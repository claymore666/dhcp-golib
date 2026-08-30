package lease

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

// Lease is what a caller gets. It is about the LEASE, not about the protocol
// (requirement U3): no state names, no message types, and absolute wall-clock
// deadlines rather than the monotonic Instants ring 1 works in.
type Lease struct {
	Addr     netip.Prefix
	Gateway  netip.Addr
	DNS      []netip.Addr
	Domain   string
	MTU      int
	ServerID netip.Addr

	// Acquired is when the REQUEST that produced this lease was sent, not
	// when its ACK arrived — RFC 2131 section 4.4.5. Renew and Rebind are T1
	// and T2, defaulted to 0.5 and 0.875 of the lease when the server sent
	// neither.
	//
	// A zero Expire means an infinite lease. That is the protocol's
	// 0xFFFFFFFF, and it is represented as a zero Time rather than as a huge
	// one so that "no expiry" is a value a caller can test rather than a
	// threshold it has to guess.
	Acquired time.Time
	Renew    time.Time
	Rebind   time.Time
	Expire   time.Time

	// Options is every option from the ACK, unparsed.
	Options wire.Options
}

func (l Lease) String() string {
	return fmt.Sprintf("%s via %s until %s", l.Addr, l.Gateway, l.Expire.Format(time.RFC3339))
}

// EventKind is what happened to the lease.
type EventKind uint8

// The outward events.
const (
	// Acquired: a lease the caller did not have.
	Acquired EventKind = iota
	// Changed: a lease whose contents differ from the one the caller had.
	Changed
	// Lost: the lease is gone. Reason says why.
	Lost
	// Failed: acquisition failed. Reason says why; the client keeps trying
	// unless the reason is terminal. This is the "notify the user that the
	// initialization process has failed and is restarting" of RFC 2131
	// section 3.1(5).
	Failed
)

func (k EventKind) String() string {
	switch k {
	case Acquired:
		return "acquired"
	case Changed:
		return "changed"
	case Lost:
		return "lost"
	case Failed:
		return "failed"
	default:
		return fmt.Sprintf("eventkind(%d)", uint8(k))
	}
}

// Event is one lease event.
//
// Reason is proto.Reason, a typed value — requirement U5 is that a caller can
// branch on the cause without string matching. Note is for humans and for the
// journal, and is never the thing to switch on.
type Event struct {
	Kind   EventKind
	Lease  Lease
	Reason proto.Reason
	Note   string
}

func (e Event) String() string {
	switch e.Kind {
	case Acquired, Changed:
		return fmt.Sprintf("%s %s", e.Kind, e.Lease)
	default:
		return fmt.Sprintf("%s %s: %s", e.Kind, e.Reason, e.Note)
	}
}

// clockBridge converts a monotonic Instant to wall-clock time.
//
// It is built from one PAIR of readings taken at the same moment, and it is
// the only place in the library where the two clocks meet. Taking the two
// readings separately at each conversion would let a wall-clock step land
// between them, which is precisely the error the monotonic clock exists to
// avoid.
type clockBridge struct {
	mono proto.Instant
	wall time.Time
}

func bridge(c Clock) clockBridge {
	// Order matters only in that the gap between the two calls is the error
	// bound. Both are cheap vDSO reads.
	return clockBridge{mono: c.Mono(), wall: c.Wall()}
}

func (b clockBridge) at(i proto.Instant) time.Time {
	return b.wall.Add(time.Duration(i.Sub(b.mono)))
}

// toLease converts ring 1's Lease into the outward one.
func toLease(l proto.Lease, b clockBridge) Lease {
	out := Lease{
		Addr:     l.Addr,
		DNS:      append([]netip.Addr(nil), l.DNS...),
		Domain:   l.Domain,
		MTU:      l.MTU,
		ServerID: l.ServerID,
		Acquired: b.at(l.Start),
		Options:  l.Options.Clone(),
	}
	if len(l.Router) > 0 {
		out.Gateway = l.Router[0]
	}
	if t, ok := l.Expire(); ok {
		out.Expire = b.at(t)
	}
	if t, ok := l.RenewAt(); ok {
		out.Renew = b.at(t)
	}
	if t, ok := l.RebindAt(); ok {
		out.Rebind = b.at(t)
	}
	return out
}
