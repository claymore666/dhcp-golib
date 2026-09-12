// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package wire

import (
	"errors"
	"fmt"
)

// The three options a server-initiated Reconfigure needs, RFC 9915 §21.11,
// §21.19 and §21.20, and the Reconfiguration Key Authentication Protocol of
// §20.4 that makes one safe to obey.
//
// WHY MD5 IS HERE. §20.4.1 fixes the algorithm: "protocol: 3", "algorithm: 1",
// "RDM: 0", and §20.4.2 names the primitive — "the server ... computes an
// HMAC-MD5 of the Reconfigure message using the reconfigure key for the
// client." RKAP is the only authentication RFC 9915 defines for a Reconfigure
// (§16.11: "does not include authentication (such as RKAP; see Section 20.4)"),
// so a client that wants to accept one at all computes HMAC-MD5 or accepts
// nothing. The choice is the standard's; this package neither offers MD5 for
// anything else nor exports a general digest.
//
// WHAT THE SPAN IS, AND WHY IT IS TAKEN OFF THE RECEIVED OCTETS. §20.4.3: "To
// authenticate a Reconfigure message, the client computes an HMAC-MD5 over the
// Reconfigure message, with zeroes substituted for the HMAC-MD5 field, using
// the reconfigure key received from the server." The message is the octets
// that ARRIVED, header included, and RKAPVerify hashes exactly those with the
// 16 octets of §20.4.1's Value field overwritten in a copy. A digest taken over
// a re-encoding of the decoded message would be a digest of this library's
// canonical form: a server whose option order, unknown options or trailing
// bytes differ from what EncodeOptionsV6 produces would be refused although it
// signed correctly, and two distinct messages that re-encode alike would share
// a digest.

// The option codes §21.11, §21.19 and §21.20 define.
const (
	// OptV6Auth is OPTION_AUTH (11), §21.11.
	OptV6Auth OptionCodeV6 = 11
	// OptV6ReconfMsg is OPTION_RECONF_MSG (19), §21.19.
	OptV6ReconfMsg OptionCodeV6 = 19
	// OptV6ReconfAccept is OPTION_RECONF_ACCEPT (20), §21.20.
	OptV6ReconfAccept OptionCodeV6 = 20
)

// AuthFixedLen is §21.11's "option-len: 11 + length of authentication
// information field": protocol, algorithm and RDM one octet each, then the
// 64-bit replay detection field.
const AuthFixedLen = 11

// The values §20.4.1 fixes for RKAP: "protocol: 3", "algorithm: 1", "RDM: 0".
const (
	AuthProtocolRKAP  uint8 = 3
	AuthAlgorithmHMAC uint8 = 1
	AuthRDMMonotonic  uint8 = 0
)

// The two Type octets of §20.4.1's authentication information: "1 Reconfigure
// key value (used in the Reply message)", "2 HMAC-MD5 digest of the message
// (used in the Reconfigure message)".
const (
	RKAPTypeKey    uint8 = 1
	RKAPTypeDigest uint8 = 2
)

// RKAPValueLen is §20.4.1's "Value: Data as defined by the Type field. A
// 16-octet field", which is also §20.4.2's "The reconfigure key is 128 bits
// long".
//
// It is exact in BOTH directions and neither padded nor truncated. A key
// shorter than this, accepted and zero-extended, would be a key two different
// servers could share a prefix of; one longer, truncated, would be a key whose
// tail nothing authenticates. §11's rule for a DUID — compare, never
// interpret — is the same shape and this field takes the same answer.
const RKAPValueLen = md5DigestSize

// rkapInfoLen is the authentication information field of an RKAP option: the
// Type octet and the Value.
const rkapInfoLen = 1 + RKAPValueLen

// The refusals this file adds. Each is separate because a caller counts them
// apart: an option that is not RKAP at all is a server speaking another
// authentication protocol, and a digest that does not match is an attacker or
// a key that has moved.
var (
	// ErrV6Auth is an Authentication option that is not the RKAP shape
	// §20.4.1 defines.
	ErrV6Auth = errors.New("wire: DHCPv6 Authentication option is not the RKAP shape RFC 9915 section 20.4.1 defines")
	// ErrRKAPKey is a reconfigure key that is not §20.4.2's 128 bits.
	ErrRKAPKey = errors.New("wire: reconfigure key is not 16 octets")
	// ErrRKAPDigest is a Reconfigure whose HMAC-MD5 does not match.
	ErrRKAPDigest = errors.New("wire: Reconfigure fails RKAP authentication")
)

// Auth is a decoded Authentication option, §21.11.
type Auth struct {
	Protocol  uint8
	Algorithm uint8
	RDM       uint8
	// Replay is §21.11's "replay detection: The replay detection information
	// for the RDM. A 64-bit (8-octet) field." Under RDM 0 it is §20.3's
	// "strictly monotonically increasing 64-bit unsigned integer (modulo
	// 2^64)"; this type carries it and judges nothing.
	Replay uint64
	// Info is the authentication information field, "as specified by the
	// protocol and algorithm used in this Authentication option".
	Info []byte
}

// DecodeAuth parses one Authentication option value.
func DecodeAuth(v []byte) (Auth, error) {
	if len(v) < AuthFixedLen {
		return Auth{}, fmt.Errorf("%w: %d octet(s), §21.11 fixes %d before the authentication information",
			ErrV6BadOption, len(v), AuthFixedLen)
	}
	return Auth{
		Protocol:  v[0],
		Algorithm: v[1],
		RDM:       v[2],
		Replay:    ube64(v[3:11]),
		Info:      append([]byte(nil), v[AuthFixedLen:]...),
	}, nil
}

// EncodeAuth renders one Authentication option value.
func EncodeAuth(a Auth) []byte {
	out := make([]byte, AuthFixedLen, AuthFixedLen+len(a.Info))
	out[0], out[1], out[2] = a.Protocol, a.Algorithm, a.RDM
	be64(out[3:11], a.Replay)
	return append(out, a.Info...)
}

// Auth returns the Authentication option of this options area, decoded.
//
// The third return separates absent from present-and-malformed, for the reason
// Status() gives: §16.11 drops a Reconfigure that "does not include
// authentication" and one that "fails authentication validation", and a caller
// that could not tell the two apart would report an attacker as a server that
// does not speak RKAP.
//
// MORE THAN ONE IS A REFUSAL RATHER THAN A CHOICE. §21: "Options that are
// allowed to appear only once are called 'singleton options'. The only
// non-singleton options defined in this document are the IA_NA ..., Vendor
// Class ..., Vendor-specific Information ..., and IA_PD ... options." Two
// Authentication options make "which one is the message's authentication"
// ambiguous, and picking one lets an attacker append a second that the
// verifier reads and the zeroing does not — or the reverse.
func (o OptionsV6) Auth() (Auth, bool, error) {
	switch n := o.Count(OptV6Auth); {
	case n == 0:
		return Auth{}, false, nil
	case n > 1:
		return Auth{}, true, fmt.Errorf("%w: %d Authentication options, §21 makes it a singleton", ErrV6Auth, n)
	}
	v, _ := o.First(OptV6Auth)
	a, err := DecodeAuth(v)
	if err != nil {
		return Auth{}, true, err
	}
	return a, true, nil
}

// RKAP reports the §20.4.1 authentication information of an Authentication
// option: the Type octet and the 16-octet Value.
//
// Every field §20.4.1 fixes is checked here rather than at the caller, because
// each of them is a way for a message to be authenticated under something
// other than RKAP while looking like RKAP to a reader who only compared the
// digest.
func (a Auth) RKAP() (typ uint8, value []byte, err error) {
	switch {
	case a.Protocol != AuthProtocolRKAP:
		return 0, nil, fmt.Errorf("%w: protocol %d, §20.4.1 fixes %d", ErrV6Auth, a.Protocol, AuthProtocolRKAP)
	case a.Algorithm != AuthAlgorithmHMAC:
		return 0, nil, fmt.Errorf("%w: algorithm %d, §20.4.1 fixes %d", ErrV6Auth, a.Algorithm, AuthAlgorithmHMAC)
	case a.RDM != AuthRDMMonotonic:
		return 0, nil, fmt.Errorf("%w: RDM %d, §20.4.1 fixes %d", ErrV6Auth, a.RDM, AuthRDMMonotonic)
	case len(a.Info) != rkapInfoLen:
		return 0, nil, fmt.Errorf("%w: authentication information is %d octet(s), §20.4.1 gives a 1-octet Type and a %d-octet Value",
			ErrV6Auth, len(a.Info), RKAPValueLen)
	}
	return a.Info[0], a.Info[1:], nil
}

// EncodeRKAPAuth builds an Authentication option value carrying §20.4.1's
// authentication information, for the two senders that need one: a server
// fixture, and this package's own tests.
func EncodeRKAPAuth(typ uint8, value []byte, replay uint64) ([]byte, error) {
	if len(value) != RKAPValueLen {
		return nil, fmt.Errorf("%w: %d octet(s), §20.4.1 gives %d", ErrRKAPKey, len(value), RKAPValueLen)
	}
	info := make([]byte, 0, rkapInfoLen)
	info = append(info, typ)
	info = append(info, value...)
	return EncodeAuth(Auth{
		Protocol:  AuthProtocolRKAP,
		Algorithm: AuthAlgorithmHMAC,
		RDM:       AuthRDMMonotonic,
		Replay:    replay,
		Info:      info,
	}), nil
}

// rkapDigestSpan locates the 16 octets of §20.4.1's Value inside the octets a
// message ARRIVED as, walking the option area the way ParseOptionsV6 does but
// keeping the offsets.
//
// It walks raw rather than trusting a decoded message's option order, because
// the span it returns is used to overwrite bytes in raw: an offset derived from
// a re-encoding would point at whatever the re-encoding put there.
func rkapDigestSpan(raw []byte) (start, end int, err error) {
	if len(raw) < V6HeaderLen {
		return 0, 0, fmt.Errorf("%w: %d octet(s)", ErrV6Short, len(raw))
	}
	found := 0
	for i := V6HeaderLen; i < len(raw); {
		if len(raw)-i < 4 {
			return 0, 0, fmt.Errorf("%w: %d octet(s) left at offset %d", ErrV6TruncatedOption, len(raw)-i, i)
		}
		code := OptionCodeV6(ube16(raw[i : i+2]))
		n := int(ube16(raw[i+2 : i+4]))
		i += 4
		if n > len(raw)-i {
			return 0, 0, fmt.Errorf("%w: option %s declares %d octet(s), %d remain", ErrV6OptionOverrun, code, n, len(raw)-i)
		}
		if code == OptV6Auth {
			found++
			if found > 1 {
				return 0, 0, fmt.Errorf("%w: %d Authentication options, §21 makes it a singleton", ErrV6Auth, found)
			}
			a, derr := DecodeAuth(raw[i : i+n])
			if derr != nil {
				return 0, 0, derr
			}
			if _, _, rerr := a.RKAP(); rerr != nil {
				return 0, 0, rerr
			}
			// The Value follows the fixed fields and the Type octet. The Type
			// octet is NOT zeroed: §20.4.1 puts it inside the authentication
			// information and §20.4.3 zeroes "the HMAC-MD5 field", which is
			// the Value alone.
			start = i + AuthFixedLen + 1
			end = start + RKAPValueLen
		}
		i += n
	}
	if found == 0 {
		return 0, 0, fmt.Errorf("%w: no Authentication option", ErrV6Auth)
	}
	return start, end, nil
}

// RKAPVerify is §20.4.3, applied to the octets a Reconfigure arrived as.
//
// §20.4.3: "To authenticate a Reconfigure message, the client computes an
// HMAC-MD5 over the Reconfigure message, with zeroes substituted for the
// HMAC-MD5 field, using the reconfigure key received from the server. If this
// computed HMAC-MD5 matches the value in the Authentication option, the client
// accepts the Reconfigure message."
//
// The comparison is equalConstantTime and not bytes.Equal: the value it
// compares is supplied by whoever sent the packet, and an early-exit compare
// answers "how many leading octets did I guess right" to anybody willing to
// send enough packets.
func RKAPVerify(raw, key []byte) error {
	if len(key) != RKAPValueLen {
		return fmt.Errorf("%w: %d octet(s), §20.4.2 gives 128 bits", ErrRKAPKey, len(key))
	}
	start, end, err := rkapDigestSpan(raw)
	if err != nil {
		return err
	}
	sent := append([]byte(nil), raw[start:end]...)
	buf := append([]byte(nil), raw...)
	for i := start; i < end; i++ {
		buf[i] = 0
	}
	if !equalConstantTime(sent, hmacMD5(key, buf)) {
		return ErrRKAPDigest
	}
	return nil
}

// ReconfigureMessage returns §21.19's msg-type and whether the option was
// there.
//
// THE THREE RETURNS ARE §16.11's THREE SEPARATE BULLETS: "the message does not
// include a Reconfigure Message option", and "the Reconfigure Message option
// msg-type is not a valid value" are two drop rules, and an accessor that
// folded them would leave a client unable to say which one fired.
//
// §21.19: "msg-type: 5 for Renew message, 6 for Rebind message, 11 for
// Information-request message. A 1-octet unsigned integer." and "option-len:
// 1". A length other than one is refused rather than read from the first
// octet, for Preference()'s reason: it is not this option.
func (o OptionsV6) ReconfigureMessage() (MessageTypeV6, bool, error) {
	switch n := o.Count(OptV6ReconfMsg); {
	case n == 0:
		return 0, false, nil
	case n > 1:
		return 0, true, fmt.Errorf("%w: %d Reconfigure Message options, §21 makes it a singleton", ErrV6BadOption, n)
	}
	v, _ := o.First(OptV6ReconfMsg)
	if len(v) != 1 {
		return 0, true, fmt.Errorf("%w: Reconfigure Message is %d octet(s), §21.19 says 1", ErrV6BadOption, len(v))
	}
	t := MessageTypeV6(v[0])
	if !t.ReconfigurableBy() {
		return t, true, fmt.Errorf("%w: Reconfigure Message msg-type %d, §21.19 gives 5, 6 and 11", ErrV6BadOption, v[0])
	}
	return t, true, nil
}

// ReconfigurableBy reports §21.19's valid msg-type set: the three exchanges a
// Reconfigure can ask a client to start.
//
// ALL THREE, and the third is the one a partial implementation drops: §21.19
// gives "5 for Renew message, 6 for Rebind message, 11 for Information-request
// message", so refusing 6 is failing a MUST-accept rather than enforcing a
// MUST-drop.
func (m MessageTypeV6) ReconfigurableBy() bool {
	return m == MsgRenew || m == MsgRebind || m == MsgInformationRequest
}

// EncodeReconfigureMessage renders §21.19's one-octet value.
func EncodeReconfigureMessage(t MessageTypeV6) ([]byte, error) {
	if !t.ReconfigurableBy() {
		return nil, fmt.Errorf("%w: %s is not one of §21.19's 5, 6 and 11", ErrV6Encode, t)
	}
	return []byte{byte(t)}, nil
}

// ReconfigureAccept reports whether §21.20's option is present, and whether
// what is present is the option §21.20 defines.
//
// §21.20: "option-len: 0." A non-empty one is DISCARD-THE-OPTION and not
// discard-the-message, which is §16's rule for this codec: the boolean says
// the announcement was made and the error says the octets were not the
// announcement's.
func (o OptionsV6) ReconfigureAccept() (bool, error) {
	v, ok := o.First(OptV6ReconfAccept)
	if !ok {
		return false, nil
	}
	if len(v) != 0 {
		return true, fmt.Errorf("%w: Reconfigure Accept is %d octet(s), §21.20 says 0", ErrV6BadOption, len(v))
	}
	return true, nil
}
