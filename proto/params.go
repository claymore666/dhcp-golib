package proto

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/claymore666/dhcp-golib/wire"
)

// Params is everything the machine needs that is not an event.
//
// A value, copied into the Machine at New and never mutated, so that a replay
// constructs the same Machine from the same Params and nothing outside can
// change the configuration between two Steps.
type Params struct {
	// CHAddr is the client hardware address. Required: RFC 2131 section 4.4.1
	// makes it a MUST when it is needed for reply delivery, which it always is
	// on a broadcast segment.
	CHAddr []byte

	// ClientID is option 61. Empty means the option is not sent.
	//
	// M1 sends whatever it is handed. Design decision D10 — whether this
	// becomes an RFC 4361 type-255 IAID+DUID — is the caller's to make and is
	// still open; the machine deliberately does not derive an identifier of
	// its own, so it cannot freeze D10 by accident.
	ClientID []byte

	// Hostname is option 12. Empty means the option is not sent.
	Hostname string

	// VendorClass is option 60. Empty means the option is not sent.
	VendorClass string

	// ParameterList is option 55. Empty means DefaultParameterList is sent.
	//
	// RFC 2131 section 4.4.1: "If the client included a list of requested
	// parameters in a DHCPDISCOVER message, it MUST include that list in all
	// subsequent messages." The machine holds one list and sends it in both,
	// so that MUST cannot be violated by editing one call site.
	ParameterList []wire.OptionCode

	// RequestedIP is a hint placed in option 50 of the DISCOVER. RFC 2131
	// section 4.4.1 makes it a MAY there. It is NOT what drives the REQUEST:
	// that carries the OFFER's yiaddr, which is a MUST.
	RequestedIP netip.Addr

	// RequestedLease is option 51 in the DISCOVER and REQUEST. Zero means the
	// option is not sent and the server chooses.
	RequestedLease Duration

	// Broadcast sets the BROADCAST flag (RFC 2131 section 2), asking the
	// server to broadcast its replies.
	//
	// TRUE in DefaultParams. The flag exists for "a client that cannot receive
	// unicast IP datagrams until its protocol software has been configured
	// with an IP address" (RFC 2131 section 4.1), which is exactly a raw
	// AF_PACKET socket on an unconfigured interface. Clearing it while ring 3
	// is a raw socket produces a client that works against servers ignoring
	// the flag and hangs against those honouring it.
	Broadcast bool

	// Discover and Request are the retransmission schedules for the two
	// transactions. See Backoff.
	Discover Backoff
	Request  Backoff

	// DesyncMin and DesyncMax bound the startup delay of RFC 2131 section
	// 4.4.1: "The client SHOULD wait a random time between one and ten seconds
	// to desynchronize the use of DHCP at startup."
	//
	// Both zero disables it — a configuration, not an opt-out: the delay
	// desynchronises a fleet of hosts booting together, and a single container
	// acquiring one lease has nothing to desynchronise from. The RFC defaults
	// are pinned by TestDesyncWindowIsWithinTheRFC.
	DesyncMin Duration
	DesyncMax Duration

	// MaxSendFailures is how many consecutive failed sends are tolerated
	// before the machine gives up on the transport and reports
	// ReasonTransport.
	//
	// R2's visible consequence: without it, a machine whose every send fails
	// sits in SELECTING re-arming a timer forever, reporting nothing, looking
	// exactly like one waiting for a slow server.
	MaxSendFailures int
}

// DefaultParameterList is option 55's default contents: the options this
// library can actually turn into a lease, plus the two the plugin's resolver
// handling needs.
func DefaultParameterList() []wire.OptionCode {
	return []wire.OptionCode{
		wire.OptSubnetMask,
		wire.OptRouter,
		wire.OptDNSServer,
		wire.OptDomainName,
		wire.OptInterfaceMTU,
		wire.OptBroadcastAddress,
		wire.OptDomainSearch,
		wire.OptClasslessStaticRte,
	}
}

// DefaultParams returns the RFC's schedules and delays for a client with the
// given hardware address. Everything a caller must decide is left zero.
func DefaultParams(chaddr []byte) Params {
	return Params{
		CHAddr:          append([]byte(nil), chaddr...),
		ParameterList:   DefaultParameterList(),
		Broadcast:       true,
		Discover:        DefaultBackoff(),
		Request:         DefaultBackoff(),
		DesyncMin:       1 * Second,
		DesyncMax:       10 * Second,
		MaxSendFailures: 5,
	}
}

// ErrNoCHAddr is returned by New when the hardware address is missing.
var ErrNoCHAddr = errors.New("proto: Params.CHAddr is required")

// ErrCHAddrTooLong is returned by New when the hardware address cannot fit the
// BOOTP field.
var ErrCHAddrTooLong = errors.New("proto: Params.CHAddr is longer than 16 octets")

// ErrBadDesync is returned by New when the desync window is inverted.
var ErrBadDesync = errors.New("proto: Params.DesyncMin is greater than Params.DesyncMax")

func (p Params) validate() error {
	if len(p.CHAddr) == 0 {
		return ErrNoCHAddr
	}
	if len(p.CHAddr) > 16 {
		return fmt.Errorf("%w: %d", ErrCHAddrTooLong, len(p.CHAddr))
	}
	if p.DesyncMin < 0 || p.DesyncMax < 0 || p.DesyncMin > p.DesyncMax {
		return fmt.Errorf("%w: [%s, %s]", ErrBadDesync, p.DesyncMin, p.DesyncMax)
	}
	return nil
}

// desync returns the startup delay for this entropy value.
func (p Params) desync(rnd uint64) Duration {
	span := p.DesyncMax - p.DesyncMin
	if span <= 0 {
		return p.DesyncMin
	}
	return p.DesyncMin + Duration(rnd%uint64(span+1))
}

func (p Params) parameterList() []wire.OptionCode {
	if len(p.ParameterList) == 0 {
		return DefaultParameterList()
	}
	return p.ParameterList
}
