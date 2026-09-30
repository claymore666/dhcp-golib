// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package wire

import (
	"errors"
	"fmt"
	"sort"
)

// OptionCode is a DHCP option tag (RFC 2132).
type OptionCode uint8

// The option codes this milestone names. Everything else round-trips as raw
// bytes under its numeric code — the map is the authority, not this list.
const (
	OptPad                OptionCode = 0
	OptSubnetMask         OptionCode = 1
	OptTimeOffset         OptionCode = 2 // RFC 2132 section 3.4
	OptRouter             OptionCode = 3
	OptDNSServer          OptionCode = 6
	OptHostName           OptionCode = 12
	OptDomainName         OptionCode = 15
	OptInterfaceMTU       OptionCode = 26
	OptBroadcastAddress   OptionCode = 28
	OptStaticRoute        OptionCode = 33 // RFC 2132 section 5.8
	OptNTPServer          OptionCode = 42 // RFC 2132 section 8.3
	OptRequestedIP        OptionCode = 50
	OptLeaseTime          OptionCode = 51
	OptOverload           OptionCode = 52
	OptMessageType        OptionCode = 53
	OptServerID           OptionCode = 54
	OptParameterList      OptionCode = 55
	OptMessage            OptionCode = 56
	OptMaxMessageSize     OptionCode = 57
	OptRenewalTime        OptionCode = 58 // T1
	OptRebindingTime      OptionCode = 59 // T2
	OptVendorClassID      OptionCode = 60
	OptClientID           OptionCode = 61
	OptTFTPServer         OptionCode = 66  // RFC 2132 section 9.4
	OptBootfileName       OptionCode = 67  // RFC 2132 section 9.5
	OptUserClass          OptionCode = 77  // RFC 3004, claymore666/docker-net-dhcp#1120
	OptRapidCommit        OptionCode = 80  // RFC 4039, claymore666/docker-net-dhcp#1031
	OptFQDN               OptionCode = 81  // RFC 4702
	OptAuthentication     OptionCode = 90  // RFC 3118, claymore666/docker-net-dhcp#1119
	OptPosixTimezone      OptionCode = 100 // RFC 4833, PCode
	OptTZDatabase         OptionCode = 101 // RFC 4833, TCode
	OptIPv6OnlyPreferred  OptionCode = 108 // RFC 8925, claymore666/docker-net-dhcp#1027
	OptDomainSearch       OptionCode = 119 // RFC 3397
	OptClasslessStaticRte OptionCode = 121 // RFC 3442
	OptForcerenewNonce    OptionCode = 145 // RFC 6704 FORCERENEW_NONCE_CAPABLE, claymore666/docker-net-dhcp#1119
	// OptWPAD is the de-facto Web Proxy Auto-Discovery option. It sits in
	// RFC 2132's site-specific range and NO standards document defines it;
	// the name is what deployments call it, not what an RFC calls it. It is
	// named here so a decoded message reports "wpad" rather than
	// "option(252)", and this library gives it no meaning beyond the bytes.
	OptWPAD OptionCode = 252
	OptEnd  OptionCode = 255
)

func (c OptionCode) String() string {
	if n, ok := optionNames[c]; ok {
		return n
	}
	return fmt.Sprintf("option(%d)", uint8(c))
}

var optionNames = map[OptionCode]string{
	OptPad:                "pad",
	OptSubnetMask:         "subnet-mask",
	OptTimeOffset:         "time-offset",
	OptRouter:             "router",
	OptDNSServer:          "dns-server",
	OptHostName:           "host-name",
	OptDomainName:         "domain-name",
	OptInterfaceMTU:       "interface-mtu",
	OptBroadcastAddress:   "broadcast-address",
	OptStaticRoute:        "static-route",
	OptNTPServer:          "ntp-server",
	OptRequestedIP:        "requested-ip",
	OptLeaseTime:          "lease-time",
	OptOverload:           "overload",
	OptMessageType:        "message-type",
	OptServerID:           "server-id",
	OptParameterList:      "parameter-list",
	OptMessage:            "message",
	OptMaxMessageSize:     "max-message-size",
	OptRenewalTime:        "renewal-time",
	OptRebindingTime:      "rebinding-time",
	OptVendorClassID:      "vendor-class-id",
	OptClientID:           "client-id",
	OptTFTPServer:         "tftp-server",
	OptBootfileName:       "bootfile-name",
	OptUserClass:          "user-class",
	OptRapidCommit:        "rapid-commit",
	OptFQDN:               "fqdn",
	OptAuthentication:     "authentication",
	OptPosixTimezone:      "posix-timezone",
	OptTZDatabase:         "tz-database",
	OptIPv6OnlyPreferred:  "ipv6-only-preferred",
	OptDomainSearch:       "domain-search",
	OptClasslessStaticRte: "classless-static-route",
	OptForcerenewNonce:    "forcerenew-nonce-capable",
	OptWPAD:               "wpad",
	OptEnd:                "end",
}

// Options holds every option in a message, keyed by code, values unparsed.
//
// Unparsed on purpose. The v1.x baseline exists because this project has
// already lost a field nobody wrote down; a pass-through map means a forgotten
// option is recoverable rather than gone (requirements section 9, choice 1).
type Options map[OptionCode][]byte

// Clone returns a deep copy. The codec hands decoded messages to ring 1, which
// is pure and must not be able to observe a later mutation of a slice the
// caller still holds.
func (o Options) Clone() Options {
	if o == nil {
		return nil
	}
	out := make(Options, len(o))
	for k, v := range o {
		out[k] = append([]byte(nil), v...)
	}
	return out
}

// Codes returns the option codes present, in ascending order.
//
// Sorted because encoding must be deterministic: Go map iteration is
// randomised, and a codec whose output depends on map order cannot have a
// golden-bytes test and cannot be replayed bit-exactly.
func (o Options) Codes() []OptionCode {
	out := make([]OptionCode, 0, len(o))
	for k := range o {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ErrBadOptionValue is a DHCPv4 option whose value is not the shape its RFC
// defines. Each accessor below returns it beside present=true, so a caller can
// tell "the server sent nothing" from "the server sent something unusable"
// (claymore666/docker-net-dhcp#1120, #1027, #1031, #1119).
var ErrBadOptionValue = errors.New("wire: DHCPv4 option value is not the shape its RFC defines")

// maxUserClassInstance is the largest instance RFC 3004 section 4 can carry:
// the option length is one octet and holds "UC_Len_1 + ... + UC_Len_m + m", so
// one instance is at most 255 - 1 (claymore666/docker-net-dhcp#1120).
const maxUserClassInstance = 254

// EncodeUserClass renders option 77's value: each class behind its length
// octet, RFC 3004 section 4 (claymore666/docker-net-dhcp#1120).
//
// A class is opaque data of 1 to 254 octets and the whole value at most 255,
// because the option's own length octet cannot count more. Refused, never
// truncated or wrapped: a wrapped length is a valid option that names other
// classes.
func EncodeUserClass(classes ...[]byte) ([]byte, error) {
	if len(classes) == 0 {
		return nil, fmt.Errorf("%w: no user class, RFC 3004 section 4 gives a minimum Len of two", ErrBadOptionValue)
	}
	total := 0
	for i, c := range classes {
		if len(c) == 0 || len(c) > maxUserClassInstance {
			return nil, fmt.Errorf("%w: user class %d is %d octet(s), RFC 3004 section 4 allows 1 to %d",
				ErrBadOptionValue, i, len(c), maxUserClassInstance)
		}
		total += 1 + len(c)
	}
	if total > 255 {
		return nil, fmt.Errorf("%w: user classes need a %d-octet option, one octet of length carries 255",
			ErrBadOptionValue, total)
	}
	out := make([]byte, 0, total)
	for _, c := range classes {
		out = append(out, byte(len(c)))
		out = append(out, c...)
	}
	return out, nil
}

// UserClass returns the classes of option 77, RFC 3004 section 4
// (claymore666/docker-net-dhcp#1120). The second return is whether the option
// was there; a present option that is not a whole list of non-empty instances
// returns ErrBadOptionValue, never the instances that fit.
func (o Options) UserClass() ([][]byte, bool, error) {
	v, ok := o[OptUserClass]
	if !ok {
		return nil, false, nil
	}
	if len(v) == 0 {
		return nil, true, fmt.Errorf("%w: empty user class option, RFC 3004 section 4 gives a minimum Len of two", ErrBadOptionValue)
	}
	var out [][]byte
	for i := 0; i < len(v); {
		n := int(v[i])
		i++
		if n == 0 {
			return nil, true, fmt.Errorf("%w: zero-length user class at offset %d, RFC 3004 section 4 says UC_Len MUST be non-zero",
				ErrBadOptionValue, i-1)
		}
		if n > len(v)-i {
			return nil, true, fmt.Errorf("%w: user class at offset %d claims %d octet(s), %d remain",
				ErrBadOptionValue, i-1, n, len(v)-i)
		}
		out = append(out, append([]byte(nil), v[i:i+n]...))
		i += n
	}
	return out, true, nil
}

// EncodeRapidCommit renders option 80's value, which is empty: RFC 4039
// section 4, "Code 80, Len 0" (claymore666/docker-net-dhcp#1031).
func EncodeRapidCommit() []byte { return []byte{} }

// RapidCommit reports whether option 80 is present. A value of any length
// but zero returns ErrBadOptionValue with present false: RFC 4039 section 4
// fixes Len at 0, so the octets are not that option
// (claymore666/docker-net-dhcp#1031).
func (o Options) RapidCommit() (bool, error) {
	v, ok := o[OptRapidCommit]
	if !ok {
		return false, nil
	}
	if len(v) != 0 {
		return false, fmt.Errorf("%w: rapid commit is %d octet(s), RFC 4039 section 4 says 0", ErrBadOptionValue, len(v))
	}
	return true, nil
}

// EncodeIPv6OnlyPreferred renders option 108's value, the V6ONLY_WAIT seconds
// as a 32-bit unsigned integer, RFC 8925 section 3.1
// (claymore666/docker-net-dhcp#1027).
func EncodeIPv6OnlyPreferred(seconds uint32) []byte {
	out := make([]byte, 4)
	be32(out, seconds)
	return out
}

// IPv6OnlyPreferred returns option 108's seconds. A length other than four
// returns ErrBadOptionValue beside present=true: RFC 8925 section 3.1 says the
// client "MUST ignore the IPv6-Only Preferred option if the length field value
// is not 4", and the generic Uint32 reader answers that case exactly as it
// answers an absent option (claymore666/docker-net-dhcp#1027).
func (o Options) IPv6OnlyPreferred() (uint32, bool, error) {
	v, ok := o[OptIPv6OnlyPreferred]
	if !ok {
		return 0, false, nil
	}
	if len(v) != 4 {
		return 0, true, fmt.Errorf("%w: IPv6-Only Preferred is %d octet(s), RFC 8925 section 3.1 says 4", ErrBadOptionValue, len(v))
	}
	return ube32(v), true, nil
}

// ForcerenewAlgorithmHMACMD5 is the one algorithm RFC 6704 section 3.1.1
// defines for FORCERENEW_NONCE_CAPABLE: "algorithm equal to 1"
// (claymore666/docker-net-dhcp#1119).
const ForcerenewAlgorithmHMACMD5 uint8 = 1

// EncodeForcerenewNonceCapable renders option 145 as a client sends it: the
// one algorithm this library implements (claymore666/docker-net-dhcp#1119).
func EncodeForcerenewNonceCapable() []byte { return []byte{ForcerenewAlgorithmHMACMD5} }

// ForcerenewNonceAlgorithms returns the algorithms option 145 lists.
//
// RFC 6704 section 3.1.1 Figure 1 makes the value "a sequence of algorithms",
// so a server that lists two is read as listing two and never by its first
// octet; an empty list is ErrBadOptionValue, since it names nothing
// (claymore666/docker-net-dhcp#1119).
func (o Options) ForcerenewNonceAlgorithms() ([]uint8, bool, error) {
	v, ok := o[OptForcerenewNonce]
	if !ok {
		return nil, false, nil
	}
	if len(v) == 0 {
		return nil, true, fmt.Errorf("%w: forcerenew nonce capable lists no algorithm, RFC 6704 section 3.1.1", ErrBadOptionValue)
	}
	return append([]uint8(nil), v...), true, nil
}
