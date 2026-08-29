package wire

import (
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
	OptRouter             OptionCode = 3
	OptDNSServer          OptionCode = 6
	OptHostName           OptionCode = 12
	OptDomainName         OptionCode = 15
	OptInterfaceMTU       OptionCode = 26
	OptBroadcastAddress   OptionCode = 28
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
	OptDomainSearch       OptionCode = 119
	OptClasslessStaticRte OptionCode = 121
	OptEnd                OptionCode = 255
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
	OptRouter:             "router",
	OptDNSServer:          "dns-server",
	OptHostName:           "host-name",
	OptDomainName:         "domain-name",
	OptInterfaceMTU:       "interface-mtu",
	OptBroadcastAddress:   "broadcast-address",
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
	OptDomainSearch:       "domain-search",
	OptClasslessStaticRte: "classless-static-route",
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
