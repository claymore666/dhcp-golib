package proto

import (
	"fmt"
	"net/netip"

	"github.com/claymore666/dhcp-golib/wire"
)

// Lease is what the machine derived from an ACK.
//
// Every deadline is an Instant on the monotonic clock: the only clock ring 1
// has, and RFC 2131 section 3.3 requires intervals to be measured on a clock
// that does not step. Turning these into a persistable wall-clock expiry is
// ring 2's job — a monotonic reading means nothing to the next process, and
// mixing the two in the pure ring is how a lease survives a restart with the
// wrong deadline.
type Lease struct {
	// Addr is the address with the mask the server gave, so a caller has the
	// prefix in one value. When the server sends no subnet mask the prefix is
	// the address with a /32 — stated rather than guessed at, because
	// inventing a classful mask is how a client ends up with a route it was
	// never given.
	Addr netip.Prefix

	ServerID netip.Addr
	Router   []netip.Addr
	DNS      []netip.Addr
	Domain   string
	MTU      int

	// Start is the Instant at which the REQUEST that produced this lease was
	// SENT, not the Instant its ACK arrived.
	//
	// RFC 2131 section 4.4.5: "the client computes the lease expiration time
	// as the sum of the time at which the client sent the DHCPREQUEST message
	// and the duration of the lease in the DHCPACK message." Using the ACK
	// arrival is a systematic half-round-trip error in the direction of
	// holding the lease slightly too long, and it is invisible on a fixture
	// where the round trip is microseconds.
	Start Instant

	// LeaseTime, T1 and T2 as the server supplied them. T1 and T2 are zero
	// when the server sent neither, and are NOT defaulted here — see
	// Deadlines, which applies RFC 2131 section 4.4.5's 0.5/0.875 defaults
	// where they belong, at the point of use.
	LeaseTime Duration
	T1        Duration
	T2        Duration

	// Options is every option from the ACK, unparsed. See the requirements
	// document, section 9 choice 1: a forgotten option is recoverable rather
	// than gone.
	Options wire.Options
}

// Expire is the Instant the lease runs out, and whether it has one at all.
func (l Lease) Expire() (Instant, bool) {
	if l.LeaseTime.IsInfinite() {
		return 0, false
	}
	return l.Start.Add(l.LeaseTime), true
}

// RenewAt and RebindAt apply RFC 2131 section 4.4.5's defaults: "T1 defaults
// to (0.5 * duration_of_lease). T2 defaults to (0.875 * duration_of_lease)."
//
// M1 arms neither timer — there is no RENEWING state to enter — but the values
// are computed and carried, because ring 2 reports them outward and because
// the next milestone must not have to rediscover where the defaults live.
func (l Lease) RenewAt() (Instant, bool) {
	d := l.T1
	if d <= 0 {
		if l.LeaseTime.IsInfinite() {
			return 0, false
		}
		d = l.LeaseTime / 2
	}
	if d <= 0 {
		return 0, false
	}
	return l.Start.Add(d), true
}

// RebindAt returns T2. See RenewAt.
func (l Lease) RebindAt() (Instant, bool) {
	d := l.T2
	if d <= 0 {
		if l.LeaseTime.IsInfinite() {
			return 0, false
		}
		// 0.875 == 7/8. Computed as (d/8)*7 rather than (d*7)/8 to keep the
		// intermediate away from the top of int64 for a near-infinite lease.
		d = (l.LeaseTime / 8) * 7
	}
	if d <= 0 {
		return 0, false
	}
	return l.Start.Add(d), true
}

// Equal reports whether two leases would configure an interface identically.
//
// Start is NOT compared: a renewal of the same address produces a new Start
// and an identical configuration, and a caller that reapplied the address on
// every renewal would churn the interface for nothing. Nor is Options, the
// pass-through bag: a server reordering an option nobody reads is not a
// changed lease.
func (l Lease) Equal(o Lease) bool {
	if l.Addr != o.Addr || l.ServerID != o.ServerID || l.Domain != o.Domain || l.MTU != o.MTU {
		return false
	}
	return addrsEqual(l.Router, o.Router) && addrsEqual(l.DNS, o.DNS)
}

func addrsEqual(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (l Lease) String() string {
	return fmt.Sprintf("%s from %s for %s", l.Addr, l.ServerID, l.LeaseTime)
}

// leaseFromAck builds a Lease from an ACK and the Instant the REQUEST was sent.
//
// It returns ok=false when the message cannot describe a lease at all: no
// yiaddr, or no lease time. Both are the server's obligation and a message
// missing either is not something to half-apply.
//
// The middle return is a note for the journal, empty when nothing was
// anomalous. The one anomaly tolerated here — a non-contiguous subnet mask —
// changes the lease handed back, and a silent change is the kind diagnosed as
// "the plugin used the wrong prefix" months later.
func leaseFromAck(m *wire.Message, sentAt Instant) (Lease, string, bool) {
	if !m.YIAddr.Is4() || m.YIAddr.IsUnspecified() {
		return Lease{}, "", false
	}
	secs, ok := m.Uint32(wire.OptLeaseTime)
	if !ok {
		return Lease{}, "", false
	}
	note := ""
	bits := 32
	if mask, ok := m.Addr4(wire.OptSubnetMask); ok {
		if n, ok := maskBits(mask); ok {
			bits = n
		} else {
			// A non-contiguous mask is not a prefix. Refusing the whole lease
			// over it would be worse than using a host route, so the address
			// is kept at /32 and the anomaly is journalled. Silently rounding
			// it to the nearest prefix is the option not taken.
			bits = 32
			note = "subnet mask " + mask.String() + " is not contiguous: address kept at /32"
		}
	}
	l := Lease{
		Addr:      netip.PrefixFrom(m.YIAddr, bits),
		Start:     sentAt,
		LeaseTime: SecondsToDuration(secs),
		Options:   m.Options.Clone(),
	}
	if sid, ok := m.Addr4(wire.OptServerID); ok {
		l.ServerID = sid
	}
	if r, ok := m.Addrs4(wire.OptRouter); ok {
		l.Router = r
	}
	if d, ok := m.Addrs4(wire.OptDNSServer); ok {
		l.DNS = d
	}
	if s, ok := m.Text(wire.OptDomainName); ok {
		l.Domain = s
	}
	if mtu, ok := m.Uint16(wire.OptInterfaceMTU); ok {
		l.MTU = int(mtu)
	}
	if t1, ok := m.Uint32(wire.OptRenewalTime); ok {
		l.T1 = SecondsToDuration(t1)
	}
	if t2, ok := m.Uint32(wire.OptRebindingTime); ok {
		l.T2 = SecondsToDuration(t2)
	}
	return l, note, true
}

// maskBits converts a dotted subnet mask to a prefix length, refusing a
// non-contiguous mask rather than silently accepting it.
func maskBits(mask netip.Addr) (int, bool) {
	if !mask.Is4() {
		return 0, false
	}
	v := mask.As4()
	u := uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
	n := 0
	for n < 32 && u&(1<<uint(31-n)) != 0 {
		n++
	}
	// Everything below the run of ones must be zero.
	if n < 32 && u<<uint(n) != 0 {
		return 0, false
	}
	return n, true
}
