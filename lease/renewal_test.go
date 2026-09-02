package lease

import (
	"net/netip"
	"testing"

	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

// TestManagerAnnouncesRenewal is seam gap G-3 at the manager's edge: the ACK
// that extends a lease reaches the caller as Renewed, and as Renewed ALONE
// when nothing in the lease changed.
//
// The renewal here changes nothing at all — the fake server answers the
// renewal DHCPREQUEST with the same lease it gave at acquisition — which is
// the case a Changed-only design cannot report and a chassis has to log.
func TestManagerAnnouncesRenewal(t *testing.T) {
	r := newRig(t, testParams(), answerNormally, Fault{})

	if ev := r.nextEvent(t); ev.Kind != Acquired {
		t.Fatalf("first event is %s, want acquired", ev)
	}
	if !r.timers.waitArmed(proto.TimerRenew) {
		t.Fatal("no renewal timer was armed after acquisition")
	}
	first, _ := r.mgr.Lease()

	// Move the clock to T1 before firing it. The deadline the renewal earns
	// is measured from the moment its DHCPREQUEST is sent (RFC 2131 4.4.5),
	// so a renewal at a clock that never moved earns the same deadline it
	// already had — and the assertion below, which is the only one that can
	// tell a renewal from a no-op, would be unfalsifiable.
	renewAt, ok := r.timers.armedAt(proto.TimerRenew)
	if !ok {
		t.Fatal("the renewal timer is not armed")
	}
	r.clock.advance(renewAt)

	r.timers.fire(proto.TimerRenew)
	ev := r.nextEvent(t)
	if ev.Kind != Renewed {
		t.Fatalf("event after T1 is %s, want renewed", ev)
	}
	if ev.Lease.Addr != first.Addr {
		t.Fatalf("renewed onto %s, want the same address %s", ev.Lease.Addr, first.Addr)
	}
	if !ev.Lease.Expire.After(first.Expire) {
		t.Fatalf("the renewed lease expires at %s, no later than the old %s; a renewal that does not move the deadline is not one",
			ev.Lease.Expire, first.Expire)
	}

	// Lease() returns the renewed one, not the one it replaced.
	held, ok := r.mgr.Lease()
	if !ok || !held.Expire.Equal(ev.Lease.Expire) {
		t.Fatalf("Lease() = %v, %v; want the renewed lease", held, ok)
	}

	s := r.mgr.Stats()
	if s.RenewalsSent == 0 {
		t.Fatal("Stats.RenewalsSent did not move")
	}
	if s.RenewalsCompleted != 1 {
		t.Fatalf("Stats.RenewalsCompleted = %d, want 1", s.RenewalsCompleted)
	}
	if s.LeasesAcquired != 1 {
		t.Fatalf("Stats.LeasesAcquired = %d; a renewal is not an acquisition", s.LeasesAcquired)
	}
	if s.LeasesLost != 0 {
		t.Fatalf("Stats.LeasesLost = %d; nothing was lost", s.LeasesLost)
	}
}

// TestRenewalsSentCountsRenewalsOnly is the control on the counter above: the
// DHCPREQUEST of an acquisition must not be counted as a renewal. The two are
// told apart by 'ciaddr' (RFC 2131 Table 5), so this drives the acquisition
// alone and asserts the counter stayed at zero.
func TestRenewalsSentCountsRenewalsOnly(t *testing.T) {
	r := newRig(t, testParams(), answerNormally, Fault{})
	if ev := r.nextEvent(t); ev.Kind != Acquired {
		t.Fatalf("first event is %s, want acquired", ev)
	}
	if s := r.mgr.Stats(); s.RenewalsSent != 0 {
		t.Fatalf("Stats.RenewalsSent = %d after an acquisition that sent one DHCPREQUEST in SELECTING", s.RenewalsSent)
	}
}

// TestNakCountersSeparateTheWireFromTheMachine is seam gap G-9's NAK half.
//
// Two counters, because their DIFFERENCE is the diagnostic: a DHCPNAK
// discarded for a stale xid is invisible in either number alone, and on a LAN
// with two DHCP servers it is the number that explains the behaviour.
func TestNakCountersSeparateTheWireFromTheMachine(t *testing.T) {
	r := newRig(t, testParams(), answerNormally, Fault{})
	if ev := r.nextEvent(t); ev.Kind != Acquired {
		t.Fatalf("first event is %s, want acquired", ev)
	}

	// A DHCPNAK for a transaction this client never had.
	stale := nakFor(&wire.Message{XID: 0xDEADBEEF, CHAddr: testCHAddr})
	raw, err := wire.Encode(stale)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	go r.server.injectRaw(raw)
	r.packets.waitRecorded(t, "the stale DHCPNAK", func(c CapturedPacket) bool {
		return c.Dir == DirIn && c.Msg != nil && c.Msg.XID == 0xDEADBEEF
	})

	s := r.mgr.Stats()
	if s.NaksSeen != 1 {
		t.Fatalf("Stats.NaksSeen = %d, want 1: the NAK was on the wire whatever the machine did with it", s.NaksSeen)
	}
	if s.NaksAccepted != 0 {
		t.Fatalf("Stats.NaksAccepted = %d, want 0: a NAK for a foreign transaction cost this client nothing", s.NaksAccepted)
	}
	if _, ok := r.mgr.Lease(); !ok {
		t.Fatal("a DHCPNAK with a foreign xid ended the lease")
	}
}

// TestManagerLeaseCarriesTheRouteAndSearchList is P-5 at the manager's edge:
// what a server sends in options 121 and 119 reaches the caller, and the
// gateway is the one RFC 3442 says to use.
func TestManagerLeaseCarriesTheRouteAndSearchList(t *testing.T) {
	behaviour := func(req *wire.Message, n int) []*wire.Message {
		out := answerNormally(req, n)
		for _, m := range out {
			if t, ok := m.Type(); !ok || t != wire.MsgAck {
				continue
			}
			// Option 3 says one gateway, option 121 says another. RFC 3442
			// makes ignoring option 3 a MUST, so the caller must see 121's.
			m.Options[wire.OptRouter] = addr4("192.168.99.254")
			m.Options[wire.OptClasslessStaticRte] = append(
				append([]byte{0}, addr4("192.168.99.1")...),
				append([]byte{24, 10, 0, 0}, addr4("192.168.99.2")...)...)
			m.Options[wire.OptDomainSearch] = []byte{
				3, 'e', 'n', 'g', 3, 'l', 'a', 'n', 0, 0xC0, 0x04,
			}
		}
		return out
	}
	r := newRig(t, testParams(), behaviour, Fault{})
	ev := r.nextEvent(t)
	if ev.Kind != Acquired {
		t.Fatalf("first event is %s, want acquired", ev)
	}
	if ev.Lease.Gateway != netip.MustParseAddr("192.168.99.1") {
		t.Fatalf("gateway = %s, want option 121's default route and not option 3's 192.168.99.254", ev.Lease.Gateway)
	}
	if len(ev.Lease.Routes) != 2 {
		t.Fatalf("routes = %v, want two", ev.Lease.Routes)
	}
	want := []string{"eng.lan", "lan"}
	if len(ev.Lease.DomainSearch) != 2 || ev.Lease.DomainSearch[0] != want[0] || ev.Lease.DomainSearch[1] != want[1] {
		t.Fatalf("domain search = %q, want %q", ev.Lease.DomainSearch, want)
	}
}

// TestRenewedEventKindRendersItself: EventKind.String is what a chassis logs,
// and an unnamed kind renders as a number nobody can grep for.
func TestRenewedEventKindRendersItself(t *testing.T) {
	if got := Renewed.String(); got != "renewed" {
		t.Fatalf("Renewed.String() = %q", got)
	}
	e := Event{Kind: Renewed, Lease: Lease{Addr: netip.MustParsePrefix("192.168.99.50/24")}}
	if got := e.String(); got == "" || got[:7] != "renewed" {
		t.Fatalf("Event.String() = %q, want it to begin with the kind", got)
	}
}

// TestNakDuringRenewalEndsTheHeldLease is where the netns test's question
// about a DHCPNAK is answered deterministically: at the moment the manager
// announces the loss, it holds nothing.
//
// The netns test cannot ask this. Its event channel is eight deep, so the
// client is free to complete the post-NAK re-acquisition before the reader
// gets to the next line, and a Lease() read there answers a question about
// NOW rather than about what the DHCPNAK cost. Here the server goes silent
// after the refusal, so nothing can re-acquire behind the assertion.
func TestNakDuringRenewalEndsTheHeldLease(t *testing.T) {
	r := newRig(t, testParams(), nakTheRenewalThenGoSilent, Fault{})

	if ev := r.nextEvent(t); ev.Kind != Acquired {
		t.Fatalf("first event is %s, want acquired", ev)
	}
	held, ok := r.mgr.Lease()
	if !ok {
		t.Fatal("nothing held after the acquisition")
	}
	if !r.timers.waitArmed(proto.TimerRenew) {
		t.Fatal("no renewal timer was armed after acquisition")
	}
	renewAt, ok := r.timers.armedAt(proto.TimerRenew)
	if !ok {
		t.Fatal("the renewal timer is not armed")
	}
	r.clock.advance(renewAt)
	r.timers.fire(proto.TimerRenew)

	lost := r.nextEvent(t)
	if lost.Kind != Lost || lost.Reason != proto.ReasonNak {
		t.Fatalf("event after the DHCPNAK is %s, want lost/nak", lost)
	}
	if lost.Lease.Addr != held.Addr {
		t.Fatalf("the lost lease names %s, want the address that was held, %s", lost.Lease.Addr, held.Addr)
	}
	if l, ok := r.mgr.Lease(); ok {
		t.Fatalf("the manager still reports holding %s while announcing that it lost it", l.Addr)
	}

	s := r.mgr.Stats()
	if s.NaksSeen != 1 || s.NaksAccepted != 1 {
		t.Fatalf("NAK counters = %d seen / %d accepted, want 1 and 1: this NAK was on the wire AND cost the lease",
			s.NaksSeen, s.NaksAccepted)
	}
	if s.LeasesLost != 1 {
		t.Fatalf("Stats.LeasesLost = %d, want 1", s.LeasesLost)
	}
}
