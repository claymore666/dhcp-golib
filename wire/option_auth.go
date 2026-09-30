// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package wire

import (
	"errors"
	"fmt"
)

// The DHCPv4 Authentication option (90) in the one shape this library reads:
// RFC 6704 section 3.1.2's Forcerenew Nonce Authentication, which reuses RFC
// 3118 section 2's option layout with protocol 3, algorithm 1 and RDM 0
// (claymore666/docker-net-dhcp#1119). The fixed fields and the three constants
// are the DHCPv6 file's: RFC 6704 takes them from RFC 3315's RKAP unchanged.

// The Type octet of the authentication information, RFC 6704 section 3.1.2:
// "1 Forcerenew nonce Value (used in ACK message)", "2 HMAC-MD5 digest of the
// message (Forcerenew message)" (claymore666/docker-net-dhcp#1119).
const (
	ForcerenewTypeNonce  uint8 = 1
	ForcerenewTypeDigest uint8 = 2
)

// ForcerenewNonceLen is section 3.1.3's "The Forcerenew nonce is 128 bits
// long", and the digest is an MD5 output of the same size (claymore666/docker-net-dhcp#1119).
const ForcerenewNonceLen = md5DigestSize

// hopsOff and giaddrOff are RFC 2131 figure 1's offsets of the two header
// fields a relay agent rewrites (claymore666/docker-net-dhcp#1119).
const (
	hopsOff   = 3
	giaddrOff = 24
)

// forcerenewInfoLen is the Type octet and the 16-octet Value (claymore666/docker-net-dhcp#1119).
const forcerenewInfoLen = 1 + ForcerenewNonceLen

// ErrForcerenewAuth is an Authentication option that is not the Forcerenew
// Nonce shape (claymore666/docker-net-dhcp#1119).
var ErrForcerenewAuth = errors.New("wire: DHCPv4 Authentication option is not the Forcerenew Nonce shape RFC 6704 section 3.1.2 defines")

// ErrForcerenewNonce is a nonce that is not 128 bits. An empty one matters
// most: HMAC with an empty key is defined, so anybody can compute it (claymore666/docker-net-dhcp#1119).
var ErrForcerenewNonce = errors.New("wire: forcerenew nonce is not 16 octets")

// ErrForcerenewDigest is a FORCERENEW whose HMAC-MD5 does not match (claymore666/docker-net-dhcp#1119).
var ErrForcerenewDigest = errors.New("wire: FORCERENEW fails Forcerenew Nonce authentication")

// ForcerenewAuth is a decoded option 90 of the Forcerenew Nonce shape (claymore666/docker-net-dhcp#1119).
type ForcerenewAuth struct {
	// Type is ForcerenewTypeNonce in an ACK, ForcerenewTypeDigest in a FORCERENEW (claymore666/docker-net-dhcp#1119).
	Type uint8
	// Replay is the RDM 0 counter, RFC 3118 section 2: "a monotonically
	// increasing counter". This type carries it and judges nothing (claymore666/docker-net-dhcp#1119).
	Replay uint64
	// Value is the nonce, or the digest, per Type (claymore666/docker-net-dhcp#1119).
	Value [ForcerenewNonceLen]byte
}

// decodeForcerenewAuth parses one option 90 value and refuses everything that
// is not RFC 6704 section 3.1.2's shape, each field on its own line so a
// caller counting refusals can see which one failed (claymore666/docker-net-dhcp#1119).
func decodeForcerenewAuth(v []byte) (ForcerenewAuth, error) {
	if len(v) < AuthFixedLen {
		return ForcerenewAuth{}, fmt.Errorf("%w: %d octet(s), RFC 3118 section 2 fixes %d before the authentication information",
			ErrForcerenewAuth, len(v), AuthFixedLen)
	}
	switch {
	case v[0] != AuthProtocolRKAP:
		return ForcerenewAuth{}, fmt.Errorf("%w: protocol %d, section 3.1.2 fixes %d", ErrForcerenewAuth, v[0], AuthProtocolRKAP)
	case v[1] != AuthAlgorithmHMAC:
		return ForcerenewAuth{}, fmt.Errorf("%w: algorithm %d, section 3.1.2 fixes %d", ErrForcerenewAuth, v[1], AuthAlgorithmHMAC)
	case v[2] != AuthRDMMonotonic:
		return ForcerenewAuth{}, fmt.Errorf("%w: RDM %d, section 3.1.2 fixes %d", ErrForcerenewAuth, v[2], AuthRDMMonotonic)
	case len(v)-AuthFixedLen != forcerenewInfoLen:
		return ForcerenewAuth{}, fmt.Errorf("%w: authentication information is %d octet(s), section 3.1.2 gives a 1-octet Type and a %d-octet Value",
			ErrForcerenewAuth, len(v)-AuthFixedLen, ForcerenewNonceLen)
	case v[AuthFixedLen] != ForcerenewTypeNonce && v[AuthFixedLen] != ForcerenewTypeDigest:
		return ForcerenewAuth{}, fmt.Errorf("%w: type %d, section 3.1.2 defines %d and %d",
			ErrForcerenewAuth, v[AuthFixedLen], ForcerenewTypeNonce, ForcerenewTypeDigest)
	}
	a := ForcerenewAuth{Type: v[AuthFixedLen], Replay: ube64(v[3:11])}
	copy(a.Value[:], v[AuthFixedLen+1:])
	return a, nil
}

// ForcerenewAuth returns the Authentication option of this message, decoded.
//
// The second return separates absent from present-and-unusable, because RFC
// 6704 section 3.1.4 discards an ACK that "omits a valid DHCP authentication
// option" and a caller that could not tell the two apart would count a wrong
// protocol as a missing option (claymore666/docker-net-dhcp#1119).
func (o Options) ForcerenewAuth() (ForcerenewAuth, bool, error) {
	v, ok := o[OptAuthentication]
	if !ok {
		return ForcerenewAuth{}, false, nil
	}
	a, err := decodeForcerenewAuth(v)
	if err != nil {
		return ForcerenewAuth{}, true, err
	}
	return a, true, nil
}

// EncodeForcerenewAuth renders an option 90 value of the Forcerenew Nonce
// shape, for a server fixture and this package's tests
// (claymore666/docker-net-dhcp#1119).
func EncodeForcerenewAuth(typ uint8, value []byte, replay uint64) ([]byte, error) {
	if len(value) != ForcerenewNonceLen {
		return nil, fmt.Errorf("%w: %d octet(s), section 3.1.2 gives %d", ErrForcerenewNonce, len(value), ForcerenewNonceLen)
	}
	if typ != ForcerenewTypeNonce && typ != ForcerenewTypeDigest {
		return nil, fmt.Errorf("%w: type %d, section 3.1.2 defines %d and %d",
			ErrForcerenewAuth, typ, ForcerenewTypeNonce, ForcerenewTypeDigest)
	}
	out := make([]byte, AuthFixedLen, AuthFixedLen+forcerenewInfoLen)
	out[0], out[1], out[2] = AuthProtocolRKAP, AuthAlgorithmHMAC, AuthRDMMonotonic
	be64(out[3:11], replay)
	out = append(out, typ)
	return append(out, value...), nil
}

// forcerenewSpan returns the offset in raw of the 16-octet Value of the one
// option 90 the message carries.
//
// It walks the octets that arrived, options area first and then `file` and
// `sname` when option 52 says they hold options, in the order Decode reads
// them (RFC 2131 section 4.1), because the offset is used to overwrite bytes in
// raw and Decode CONCATENATES repeated options: two instances read as one
// 56-octet value, and zeroing the first would let a second one carry the digest
// (claymore666/docker-net-dhcp#1119).
func forcerenewSpan(raw []byte) (int, error) {
	if len(raw) < HeaderLen {
		return 0, fmt.Errorf("%w: %d octets", ErrShort, len(raw))
	}
	if [4]byte(raw[fixedLen:HeaderLen]) != magicCookie {
		return 0, ErrBadCookie
	}
	type instance struct{ start, n int }
	var auth []instance
	var overload []byte
	walk := func(off, end int) error {
		for i := off; i < end; {
			c := OptionCode(raw[i])
			if c == OptPad {
				i++
				continue
			}
			if c == OptEnd {
				return nil
			}
			if i+1 >= end {
				return fmt.Errorf("%w: %s has no length octet", ErrTruncatedOption, c)
			}
			n := int(raw[i+1])
			if i+2+n > end {
				return fmt.Errorf("%w: %s claims %d octets, %d remain", ErrOptionOverrun, c, n, end-i-2)
			}
			switch c {
			case OptAuthentication:
				auth = append(auth, instance{i + 2, n})
			case OptOverload:
				overload = append(overload, raw[i+2:i+2+n]...)
			}
			i += 2 + n
		}
		return nil
	}
	if err := walk(HeaderLen, len(raw)); err != nil {
		return 0, err
	}
	ov := byte(0)
	if len(overload) == 1 {
		ov = overload[0]
	}
	if ov&1 != 0 {
		if err := walk(fileOff, fileOff+fileLen); err != nil {
			return 0, err
		}
	}
	if ov&2 != 0 {
		if err := walk(snameOff, snameOff+snameLen); err != nil {
			return 0, err
		}
	}
	switch len(auth) {
	case 0:
		return 0, fmt.Errorf("%w: no Authentication option", ErrForcerenewAuth)
	case 1:
	default:
		return 0, fmt.Errorf("%w: %d Authentication options", ErrForcerenewAuth, len(auth))
	}
	a, err := decodeForcerenewAuth(raw[auth[0].start : auth[0].start+auth[0].n])
	if err != nil {
		return 0, err
	}
	if a.Type != ForcerenewTypeDigest {
		return 0, fmt.Errorf("%w: type %d carries a nonce and cannot authenticate a message, section 3.1.2 gives %d",
			ErrForcerenewAuth, a.Type, ForcerenewTypeDigest)
	}
	// The Type octet is not zeroed: RFC 6704 section 3.1.3 zeroes "the
	// HMAC-MD5 field", which is the Value alone (the DHCPv6 file does the same) (claymore666/docker-net-dhcp#1119).
	return auth[0].start + AuthFixedLen + 1, nil
}

// VerifyForcerenew is RFC 6704 section 3.1.4 applied to the octets a FORCERENEW
// arrived as: HMAC-MD5 "over the DHCP Forcerenew message (after setting the
// HMAC-MD5 field in the Authentication option to zero)", keyed with the nonce
// (claymore666/docker-net-dhcp#1119). RFC 3118 section 3 also zeroes hops and
// giaddr for any hash over the header, because a relay agent may alter them.
// The digest covers the received octets, padding after END included, with the
// 16 Value octets, hops and giaddr zeroed in a copy; one over a re-encoding
// would refuse a server whose option order differs from Encode's. The nonce
// length is checked before anything is computed.
func VerifyForcerenew(raw, nonce []byte) error {
	if len(nonce) != ForcerenewNonceLen {
		return fmt.Errorf("%w: %d octet(s), section 3.1.3 gives 128 bits", ErrForcerenewNonce, len(nonce))
	}
	start, err := forcerenewSpan(raw)
	if err != nil {
		return err
	}
	masked := append([]byte(nil), raw...)
	masked[hopsOff] = 0
	clear(masked[giaddrOff : giaddrOff+4])
	if !zeroedHMACMatches(nonce, masked, start, start+ForcerenewNonceLen) {
		return ErrForcerenewDigest
	}
	return nil
}
