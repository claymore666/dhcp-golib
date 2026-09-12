// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// The machine half of RFC 4862 §5.5.3 and §5.5.4, and the Params6 mode switch.
// Every test here reads the ACTION LIST or the built lease; the counters are
// asserted beside that evidence and never instead of it.

// TestAModeThatFormsAddressesNeverSolicitsAServer is defeat row R-12, both
// halves: the new modes must not Solicit, and the mode a caller does not set
// must behave exactly as it does today.
//
// THE PRESERVATION HALF IS THE POINT. Mode6DHCP is the zero value, so a caller
// that never heard of this field gets DHCPv6, and a zero value meaning "off"
// would be a behaviour inversion no test naming the new symbol could see.
func TestAModeThatFormsAddressesNeverSolicitsAServer(t *testing.T) {
	t.Run("a caller that sets no Mode still solicits", func(t *testing.T) {
		p := testParams6()
		if p.Mode != Mode6DHCP {
			t.Fatalf("DefaultParams6 has Mode %s; the zero value must be the DHCPv6 one", p.Mode)
		}
		m := newMachine6(t, p)
		s, acts := m.Step(at(0), 0, Simple(EvStart))
		if s != State6Init {
			t.Fatalf("EvStart left the machine in %s, want %s", s, State6Init)
		}
		if _, ok := timerSet(acts, Timer6Delay); !ok {
			t.Fatal("no first-message delay was armed: the DHCPv6 path has changed shape")
		}
		s, acts = m.Step(at(1), capXIDSolicit, TimerFired(Timer6Delay))
		if s != State6Selecting {
			t.Fatalf("the delay expiring left the machine in %s, want %s", s, State6Selecting)
		}
		mustSendV6(t, acts, wire.MsgSolicit)
	})

	for _, mode := range []Mode6{Mode6SLAAC, Mode6Auto} {
		t.Run(mode.String()+" waits for an advertisement", func(t *testing.T) {
			p := testParams6SLAAC()
			p.Mode = mode
			m := newMachine6(t, p)
			s, acts := m.Step(at(0), 0, Simple(EvStart))
			if s != State6Discovering {
				t.Fatalf("EvStart in %s left the machine in %s, want %s", mode, s, State6Discovering)
			}
			for _, k := range []wire.MessageTypeV6{wire.MsgSolicit, wire.MsgConfirm, wire.MsgRequest6, wire.MsgInformationRequest} {
				if hasSendV6(acts, k) {
					t.Errorf("%s sent a %s before any router had spoken", mode, k)
				}
			}
			if _, ok := timerSet(acts, Timer6Delay); ok {
				t.Error("a first-message delay was armed for an exchange that is not going to happen")
			}
			// And a Router Solicitation IS sent: RFC 4861 §6.3.7's "To obtain
			// Router Advertisements quickly, a host on a multicast-capable
			// link SHOULD transmit up to MAX_RTR_SOLICITATIONS Router
			// Solicitation messages".
			if _, ok := find(acts, ActSendRouterSolicit); !ok {
				t.Errorf("%s waits for an advertisement and asked for none.%s", mode, journalLines(acts))
			}
		})
	}
}

// TestNewSixRefusesAParamsItCannotRun is defeat rows R-15, R-34, R-35 and
// R-37's refusal half.
//
// A machine built in a mode that forms addresses with no link address would
// form one from a zero identifier — ::ff:fe00:0 on every endpoint of the link
// — so every container would collide with every other. Refusing to build it
// is the loud shape.
func TestNewSixRefusesAParamsItCannotRun(t *testing.T) {
	t.Run("no link address in a mode that forms addresses", func(t *testing.T) {
		for _, mode := range []Mode6{Mode6SLAAC, Mode6Auto} {
			p := testParams6()
			p.Mode = mode
			if _, err := New6(p); err == nil {
				t.Errorf("%s with no link address built a machine", mode)
			} else if !strings.Contains(err.Error(), "LinkAddr") {
				t.Errorf("%s was refused with %q, which does not name the missing field", mode, err)
			}
		}
	})

	t.Run("a link address of a length RFC 4291 Appendix A does not cover", func(t *testing.T) {
		for _, n := range []int{1, 4, 5, 7, 9, 16} {
			p := testParams6()
			p.Mode = Mode6SLAAC
			p.LinkAddr = make(net.HardwareAddr, n)
			if _, err := New6(p); err == nil {
				t.Errorf("a link address of %d octet(s) built a machine", n)
			}
		}
	})

	t.Run("off is declared and refused", func(t *testing.T) {
		p := testParams6SLAAC()
		p.Mode = Mode6Off
		if _, err := New6(p); err == nil {
			t.Fatal("Mode6Off built a machine; a machine with nothing to do is better refused than proved inert")
		}
	})

	t.Run("a mode outside the declared set is refused and never defaulted", func(t *testing.T) {
		p := testParams6SLAAC()
		p.Mode = Mode6(99)
		if _, err := New6(p); err == nil {
			t.Fatal("Mode6(99) built a machine")
		}
	})

	t.Run("the preservation control: DHCPv6 needs no link address", func(t *testing.T) {
		p := testParams6()
		if p.LinkAddr != nil {
			t.Fatal("the fixture already carries a link address, so this control proves nothing")
		}
		if _, err := New6(p); err != nil {
			t.Fatalf("the mode every caller gets today was refused: %v", err)
		}
	})

	t.Run("every declared mode is named and enumerated", func(t *testing.T) {
		seen := map[Mode6]int{}
		for _, mode := range AllModes6() {
			seen[mode]++
			if s := mode.String(); s == "" || strings.HasPrefix(s, "mode6(") {
				t.Errorf("mode %d has no name of its own: %q", mode, s)
			}
		}
		for i := 0; i < 256; i++ {
			mode := Mode6(i)
			named := !strings.HasPrefix(mode.String(), "mode6(")
			if named && seen[mode] != 1 {
				t.Errorf("%s is a declared mode and appears %d time(s) in AllModes6()", mode, seen[mode])
			}
			if !named && seen[mode] != 0 {
				t.Errorf("AllModes6() carries %d, which Mode6.String() does not name", i)
			}
		}
	})
}

// TestANewlyFormedAddressGoesThroughDuplicateAddressDetection is defeat row
// R-10's first half: RFC 4862 §5.4 runs on every address before the caller is
// told about it, and an address announced without it is D22 broken.
func TestANewlyFormedAddressGoesThroughDuplicateAddressDetection(t *testing.T) {
	m := newMachine6(t, testParams6SLAAC())
	m.Step(at(0), 0, Simple(EvStart))
	s, acts := m.Step(at(1), 0, raEvent6(t, ra6(false, false, pio(testSLAACPrefix, 64, true, 86400, 14400))))
	if s != State6DAD {
		t.Fatalf("an autonomous prefix left the machine in %s, want %s.%s", s, State6DAD, journalLines(acts))
	}
	dad, ok := find(acts, ActStartDAD)
	if !ok {
		t.Fatalf("no duplicate address detection was started for the formed address.%s", journalLines(acts))
	}
	if dad.Target != netip.MustParseAddr(testSLAACAddr) {
		t.Errorf("duplicate address detection runs on %s, want %s", dad.Target, testSLAACAddr)
	}
	for _, k := range []ActionKind{ActLeaseAcquired, ActLeaseChanged, ActLeaseRenewed} {
		if _, ok := find(acts, k); ok {
			t.Errorf("%s reached the caller before duplicate address detection answered", k)
		}
	}
	if _, ok := timerSet(acts, Timer6SLAAC); ok {
		t.Error("the lifetime timer was armed for an address nothing has checked")
	}

	s, acts = m.Step(at(2), 0, DADResult(netip.MustParseAddr(testSLAACAddr), false))
	if s != State6Bound {
		t.Fatalf("a clean result left the machine in %s, want %s", s, State6Bound)
	}
	acq, ok := find(acts, ActLeaseAcquired)
	if !ok {
		t.Fatalf("the caller was never told about the address.%s", journalLines(acts))
	}
	if !acq.Lease6.SLAAC {
		t.Error("the announced lease does not say it was formed rather than granted")
	}
	if len(acq.Lease6.Addrs) != 1 || acq.Lease6.Addrs[0].Addr != netip.MustParseAddr(testSLAACAddr) {
		t.Fatalf("the announced lease carries %v", acq.Lease6.Addrs)
	}
	// THE TIMER IS ARMED BEFORE THE ANNOUNCEMENT, which is what stops a
	// caller acting on a preferred address no moment will ever deprecate.
	if !armedBefore(acts, Timer6SLAAC, ActLeaseAcquired) {
		t.Errorf("the lifetime timer was armed after the lease was announced.%s", journalLines(acts))
	}
	if got := m.SLAACCounters().Formed; got != 1 {
		t.Errorf("the formation counter is %d, want 1", got)
	}
}

// TestAPureLifetimeRefreshDoesNotRestartDuplicateAddressDetection is defeat
// row R-10's second half and R-29. A router repeats its advertisement every
// few seconds (RFC 4861 §6.2.1); a client that ran §5.4 on every repeat would
// arm a deadline nothing answers and end in ReasonDADIncomplete.
func TestAPureLifetimeRefreshDoesNotRestartDuplicateAddressDetection(t *testing.T) {
	m := slaacBound6(t, testParams6SLAAC(), 86400, 14400)
	raw := ra6(false, false, pio(testSLAACPrefix, 64, true, 86400, 14400))
	for _, tick := range []int64{5, 10, 15} {
		s, acts := m.Step(at(tick), 0, raEvent6(t, raw))
		if s != State6Bound {
			t.Fatalf("a repeated advertisement at t+%d left the machine in %s", tick, s)
		}
		if _, ok := find(acts, ActStartDAD); ok {
			t.Fatalf("a repeated advertisement at t+%d restarted duplicate address detection", tick)
		}
		if _, ok := timerSet(acts, Timer6DAD); ok {
			t.Fatalf("a repeated advertisement at t+%d armed a duplicate address detection deadline", tick)
		}
		if _, ok := find(acts, ActLeaseChanged); ok {
			t.Fatalf("a repeated advertisement at t+%d was reported as a change; only the lifetimes moved", tick)
		}
	}
	if got := m.SLAACCounters().Formed; got != 1 {
		t.Errorf("three repeats formed %d addresses, want 1", got)
	}
	if len(m.SLAACAddrs()) != 1 {
		t.Errorf("the machine holds %v", m.SLAACAddrs())
	}
}

// TestASLAACLeaseArmsNoRenewalTimers is defeat row R-11.
//
// MEASURED before the Lease6.SLAAC field existed: Deadlines' §21.4 fallback
// computed T1 and T2 from the preferred lifetime of a formed address, so the
// machine armed Timer6Renew, entered RENEWING6 with no ServerDUID to renew
// with, fell through to REBINDING6 and put a Rebind on a link where nothing
// had ever been solicited.
func TestASLAACLeaseArmsNoRenewalTimers(t *testing.T) {
	m := newMachine6(t, testParams6SLAAC())
	m.Step(at(0), 0, Simple(EvStart))
	m.Step(at(1), 0, raEvent6(t, ra6(false, false, pio(testSLAACPrefix, 64, true, 86400, 14400))))
	_, acts := m.Step(at(2), 0, DADResult(netip.MustParseAddr(testSLAACAddr), false))

	for _, id := range []TimerID{Timer6Renew, Timer6Rebind, Timer6Expire} {
		if d, ok := timerSet(acts, id); ok {
			t.Errorf("%s was armed for %s on a lease no server granted", id, d)
		}
		if !timerCancelled(acts, id) {
			t.Errorf("%s was not cancelled when the formed lease was installed", id)
		}
	}
	d, ok := timerSet(acts, Timer6SLAAC)
	if !ok {
		t.Fatalf("no lifetime timer was armed.%s", journalLines(acts))
	}
	// The earliest moment §5.5.4 has anything to say about: the preferred
	// lifetime, 14400 seconds from the instant the prefix was heard.
	if want := 14400*Second - Duration(at(2)-at(1)); d != want {
		t.Errorf("the lifetime timer was armed for %s, want %s", d, want)
	}
	l, held := m.Lease()
	if !held || !l.SLAAC {
		t.Fatalf("the machine holds %v (SLAAC=%v)", held, l.SLAAC)
	}
	// And Deadlines itself refuses to compute the renewal schedule, which is
	// what makes the cancels above a rule and not a coincidence.
	dl := l.Deadlines()
	if dl.HasRenew || dl.HasRebind {
		t.Errorf("Deadlines produced renew=%v (%v) rebind=%v (%v) for a formed lease", dl.Renew, dl.HasRenew, dl.Rebind, dl.HasRebind)
	}
	if !dl.HasExpire {
		t.Error("Deadlines produced no expiry for a formed lease; its addresses still run out")
	}
}

// TestASecondPrefixFormsASecondAddress is defeat row R-4 at the machine, in
// BOTH directions: two Prefix Information options in one advertisement, and a
// second prefix arriving in a later one while the machine is bound.
//
// Design decision Q2 is "one address per EVERY advertised autonomous prefix",
// so first-wins is the shape this closes, and it hides in a suite that drives
// one prefix.
func TestASecondPrefixFormsASecondAddress(t *testing.T) {
	t.Run("two prefixes in one advertisement", func(t *testing.T) {
		m := newMachine6(t, testParams6SLAAC())
		m.Step(at(0), 0, Simple(EvStart))
		s, acts := m.Step(at(1), 0, raEvent6(t, ra6(false, false,
			pio("2001:db8:1::", 64, true, 86400, 14400),
			pio("2001:db8:2::", 64, true, 86400, 14400),
		)))
		if s != State6DAD {
			t.Fatalf("two prefixes left the machine in %s.%s", s, journalLines(acts))
		}
		if got := count(acts, ActStartDAD); got != 2 {
			t.Fatalf("%d address(es) were checked, want 2", got)
		}
		m.Step(at(2), 0, DADResult(netip.MustParseAddr("2001:db8:1::42:acff:fe11:2"), false))
		_, acts = m.Step(at(2), 0, DADResult(netip.MustParseAddr("2001:db8:2::42:acff:fe11:2"), false))
		acq, ok := find(acts, ActLeaseAcquired)
		if !ok {
			t.Fatalf("the caller was never told.%s", journalLines(acts))
		}
		if len(acq.Lease6.Addrs) != 2 {
			t.Fatalf("the announced lease carries %v, want two addresses", acq.Lease6.Addrs)
		}
	})

	t.Run("a second prefix in a later advertisement while bound", func(t *testing.T) {
		m := slaacBound6(t, testParams6SLAAC(), 86400, 14400)
		s, acts := m.Step(at(10), 0, raEvent6(t, ra6(false, false,
			pio(testSLAACPrefix, 64, true, 86400, 14400),
			pio("2001:db8:2::", 64, true, 86400, 14400),
		)))
		if s != State6DAD {
			t.Fatalf("a new prefix while bound left the machine in %s.%s", s, journalLines(acts))
		}
		dad, ok := find(acts, ActStartDAD)
		if !ok {
			t.Fatalf("the new address was not checked.%s", journalLines(acts))
		}
		if dad.Target != netip.MustParseAddr("2001:db8:2::42:acff:fe11:2") {
			t.Errorf("the check ran on %s", dad.Target)
		}
		if got := count(acts, ActStartDAD); got != 1 {
			t.Errorf("%d addresses were checked; the one already held must not be checked again", got)
		}
		_, acts = m.Step(at(11), 0, DADResult(netip.MustParseAddr("2001:db8:2::42:acff:fe11:2"), false))
		ch, ok := find(acts, ActLeaseChanged)
		if !ok {
			t.Fatalf("a new address in the set was not reported as a change.%s", journalLines(acts))
		}
		if len(ch.Lease6.Addrs) != 2 {
			t.Fatalf("the reported lease carries %v, want two addresses", ch.Lease6.Addrs)
		}
	})
}

// TestDeprecationKeepsTheAddressAndReportsAChange is defeat rows R-8, R-26 and
// R-27.
//
// §5.5.4: "A preferred address becomes deprecated when its preferred lifetime
// expires. A deprecated address SHOULD continue to be used as a source address
// in existing communications, but SHOULD NOT be used to initiate new
// communications". So the address is KEPT, its preferred lifetime is reported
// at zero, and the caller hears about it — that last part is what sets
// PreferedLft on the interface, and its absence is the silent half.
//
// Design note M-1 phase 2b measured Linux doing exactly this: an address
// re-advertised with a preferred lifetime of 0 went to "deprecated" and stayed
// on the interface.
func TestDeprecationKeepsTheAddressAndReportsAChange(t *testing.T) {
	m := slaacBound6(t, testParams6SLAAC(), 86400, 100)

	s, acts := m.Step(at(101), 0, TimerFired(Timer6SLAAC))
	if s != State6Bound {
		t.Fatalf("the preferred lifetime running out left the machine in %s, want %s", s, State6Bound)
	}
	ch, ok := find(acts, ActLeaseChanged)
	if !ok {
		t.Fatalf("the caller was never told the address was deprecated.%s", journalLines(acts))
	}
	if len(ch.Lease6.Addrs) != 1 {
		t.Fatalf("the reported lease carries %v, want the address still there", ch.Lease6.Addrs)
	}
	if got := ch.Lease6.Addrs[0].Preferred; got != 0 {
		t.Errorf("the reported preferred lifetime is %s, want 0", got)
	}
	if got := ch.Lease6.Addrs[0].Valid; got <= 0 {
		t.Errorf("the reported valid lifetime is %s: a deprecated address is still valid", got)
	}
	if _, held := m.Lease(); !held {
		t.Fatal("the machine dropped a deprecated address; §5.5.4 keeps it until its valid lifetime runs out")
	}
	if got := m.SLAACCounters().Deprecated; got != 1 {
		t.Errorf("the deprecation counter is %d, want 1", got)
	}
	// AND THE NEXT MOMENT IS RE-ARMED. §5.5.4 has a second thing to say about
	// this address — its valid lifetime — and a machine that armed the timer
	// once at acquisition would never reach it.
	d, ok := timerSet(acts, Timer6SLAAC)
	if !ok {
		t.Fatalf("the lifetime timer was not re-armed after it fired.%s", journalLines(acts))
	}
	if want := 86401*Second - Duration(at(101)-at(0)); d != want {
		t.Errorf("the lifetime timer was re-armed for %s, want the valid deadline at %s", d, want)
	}

	// R-27: deprecation is REVERSIBLE. §5.5.3 e's closing note resets the
	// preferred lifetime on every advertisement, so a router that starts
	// advertising the prefix as preferred again lifts the address out of the
	// deprecated phase — and that is a change too.
	_, acts = m.Step(at(200), 0, raEvent6(t, ra6(false, false, pio(testSLAACPrefix, 64, true, 86400, 14400))))
	ch, ok = find(acts, ActLeaseChanged)
	if !ok {
		t.Fatalf("an address lifted out of the deprecated phase was not reported as a change.%s", journalLines(acts))
	}
	if got := ch.Lease6.Addrs[0].Preferred; got != 14400*Second {
		t.Errorf("the reported preferred lifetime is %s, want 14400s", got)
	}

	// And the control: a refresh that moves neither the set nor any phase is
	// a renewal and NOT a change, which is what stops every repeat of a
	// router's advertisement reaching the caller as one.
	_, acts = m.Step(at(210), 0, raEvent6(t, ra6(false, false, pio(testSLAACPrefix, 64, true, 90000, 14400))))
	if _, ok := find(acts, ActLeaseChanged); ok {
		t.Error("a pure lifetime refresh was reported as a change")
	}
	if _, ok := find(acts, ActLeaseRenewed); !ok {
		t.Errorf("a pure lifetime refresh was not reported at all.%s", journalLines(acts))
	}
}

// TestOneAddressExpiringIsNotTheLeaseExpiring is defeat row R-9, both halves.
//
// §5.5.4: "An address (and its association with an interface) becomes invalid
// when its valid lifetime expires. An invalid address MUST NOT be used as a
// source address in outgoing communications". So the LAST address running out
// must reach the caller as a loss and not as a change carrying an empty list,
// which would leave an invalid address installed.
func TestOneAddressExpiringIsNotTheLeaseExpiring(t *testing.T) {
	m := newMachine6(t, testParams6SLAAC())
	m.Step(at(0), 0, Simple(EvStart))
	m.Step(at(1), 0, raEvent6(t, ra6(false, false,
		pio("2001:db8:1::", 64, true, 100, 100),
		pio("2001:db8:2::", 64, true, 500, 500),
		pio("2001:db8:3::", 64, true, 900, 900),
	)))
	for _, a := range []string{"2001:db8:1::42:acff:fe11:2", "2001:db8:2::42:acff:fe11:2", "2001:db8:3::42:acff:fe11:2"} {
		m.Step(at(2), 0, DADResult(netip.MustParseAddr(a), false))
	}
	if _, held := m.Lease(); !held {
		t.Fatal("the fixture never acquired")
	}

	s, acts := m.Step(at(102), 0, TimerFired(Timer6SLAAC))
	if s != State6Bound {
		t.Fatalf("one address of three expiring left the machine in %s", s)
	}
	if _, ok := find(acts, ActLeaseLost); ok {
		t.Error("one address of three expiring ended the whole lease")
	}
	ch, ok := find(acts, ActLeaseChanged)
	if !ok {
		t.Fatalf("the caller was never told one address had gone.%s", journalLines(acts))
	}
	if len(ch.Lease6.Addrs) != 2 {
		t.Fatalf("the reported lease carries %v, want the two that are left", ch.Lease6.Addrs)
	}
	// The next moment belongs to the SECOND address, and it is armed here or
	// the two that are left never expire at all.
	d, ok := timerSet(acts, Timer6SLAAC)
	if !ok {
		t.Fatalf("the lifetime timer was not re-armed after one address expired.%s", journalLines(acts))
	}
	if want := 501*Second - Duration(at(102)-at(0)); d != want {
		t.Errorf("the lifetime timer was re-armed for %s, want the second address's deadline at %s", d, want)
	}

	m.Step(at(502), 0, TimerFired(Timer6SLAAC))
	s, acts = m.Step(at(902), 0, TimerFired(Timer6SLAAC))
	lost, ok := find(acts, ActLeaseLost)
	if !ok {
		t.Fatalf("the last address running out was not reported as a loss.%s", journalLines(acts))
	}
	if lost.Reason != ReasonExpired {
		t.Errorf("the loss was reported with reason %s, want %s", lost.Reason, ReasonExpired)
	}
	if ch, ok := find(acts, ActLeaseChanged); ok && len(ch.Lease6.Addrs) == 0 {
		t.Error("the last address was reported as a change carrying an empty list; a caller acting on that keeps an invalid address")
	}
	if s != State6Discovering {
		t.Errorf("a machine with no address left is in %s, want %s: it goes back to waiting for a prefix", s, State6Discovering)
	}
	if _, held := m.Lease(); held {
		t.Error("the machine still holds a lease whose every address is invalid")
	}
	if got := m.SLAACCounters().Expired; got != 3 {
		t.Errorf("the expiry counter is %d, want 3", got)
	}
}

// TestADuplicateCostsOneAddressAndNotTheSet is defeat row R-28.
//
// The IA_NA arm declines a whole IA because §18.2.8's retained bindings would
// mean two exchanges in flight. There is no exchange here at all — a formed
// address is granted by nobody, so there is nobody to decline to — and §5.5.3
// forms one address per prefix independently. Dropping the others would hand a
// container's whole IPv6 configuration to whichever node answered for one
// prefix.
func TestADuplicateCostsOneAddressAndNotTheSet(t *testing.T) {
	m := newMachine6(t, testParams6SLAAC())
	m.Step(at(0), 0, Simple(EvStart))
	m.Step(at(1), 0, raEvent6(t, ra6(false, false,
		pio("2001:db8:1::", 64, true, 86400, 14400),
		pio("2001:db8:2::", 64, true, 86400, 14400),
	)))
	m.Step(at(2), 0, DADResult(netip.MustParseAddr("2001:db8:1::42:acff:fe11:2"), true))
	s, acts := m.Step(at(2), 0, DADResult(netip.MustParseAddr("2001:db8:2::42:acff:fe11:2"), false))

	if s != State6Bound {
		t.Fatalf("one duplicate of two left the machine in %s, want %s.%s", s, State6Bound, journalLines(acts))
	}
	acq, ok := find(acts, ActLeaseAcquired)
	if !ok {
		t.Fatalf("the surviving address never reached the caller.%s", journalLines(acts))
	}
	if len(acq.Lease6.Addrs) != 1 || acq.Lease6.Addrs[0].Addr != netip.MustParseAddr("2001:db8:2::42:acff:fe11:2") {
		t.Fatalf("the announced lease carries %v, want the address that is not in use", acq.Lease6.Addrs)
	}
	// NO DECLINE IS SENT. §18.2.8's Decline names a server in its Server
	// Identifier option and a formed address has none.
	if hasSendV6(acts, wire.MsgDecline6) {
		t.Error("a Decline was sent for an address no server granted")
	}
	if got := m.SLAACCounters().Conflicts; got != 1 {
		t.Errorf("the conflict counter is %d, want 1", got)
	}

	// The discriminator: BOTH in use ends the acquisition rather than
	// announcing an empty set.
	m2 := newMachine6(t, testParams6SLAAC())
	m2.Step(at(0), 0, Simple(EvStart))
	m2.Step(at(1), 0, raEvent6(t, ra6(false, false,
		pio("2001:db8:1::", 64, true, 86400, 14400),
		pio("2001:db8:2::", 64, true, 86400, 14400),
	)))
	m2.Step(at(2), 0, DADResult(netip.MustParseAddr("2001:db8:1::42:acff:fe11:2"), true))
	s, acts = m2.Step(at(2), 0, DADResult(netip.MustParseAddr("2001:db8:2::42:acff:fe11:2"), true))
	if _, ok := find(acts, ActLeaseAcquired); ok {
		t.Error("every formed address was in use and a lease was announced anyway")
	}
	f, ok := find(acts, ActFailed)
	if !ok {
		t.Fatalf("every formed address was in use and the caller was never told.%s", journalLines(acts))
	}
	if f.Reason != ReasonConflict {
		t.Errorf("the failure was reported as %s, want %s", f.Reason, ReasonConflict)
	}
	if s != State6Discovering {
		t.Errorf("the machine is in %s, want %s", s, State6Discovering)
	}
}

// TestAPrefixArrivingDuringDuplicateAddressDetectionIsCheckedToo is the race
// the per-address settle exists for: a router repeats its advertisement every
// few seconds, so a NEW prefix can arrive while a check is running. Settling
// everything tentative at the end of that check would announce an address
// nothing had checked.
func TestAPrefixArrivingDuringDuplicateAddressDetectionIsCheckedToo(t *testing.T) {
	m := newMachine6(t, testParams6SLAAC())
	m.Step(at(0), 0, Simple(EvStart))
	m.Step(at(1), 0, raEvent6(t, ra6(false, false, pio("2001:db8:1::", 64, true, 86400, 14400))))
	// A second prefix arrives mid-check.
	s, acts := m.Step(at(2), 0, raEvent6(t, ra6(false, false,
		pio("2001:db8:1::", 64, true, 86400, 14400),
		pio("2001:db8:2::", 64, true, 86400, 14400),
	)))
	if s != State6DAD {
		t.Fatalf("a prefix arriving mid-check left the machine in %s", s)
	}
	if _, ok := find(acts, ActStartDAD); ok {
		t.Error("the check already running was restarted, which rearms its deadline for ever")
	}
	// The first round ends. The second address must be checked, not announced.
	s, acts = m.Step(at(3), 0, DADResult(netip.MustParseAddr("2001:db8:1::42:acff:fe11:2"), false))
	if s != State6DAD {
		t.Fatalf("the machine left duplicate address detection in %s with an unchecked address in hand.%s", s, journalLines(acts))
	}
	dad, ok := find(acts, ActStartDAD)
	if !ok {
		t.Fatalf("the address formed mid-check was never checked.%s", journalLines(acts))
	}
	if dad.Target != netip.MustParseAddr("2001:db8:2::42:acff:fe11:2") {
		t.Errorf("the second round checks %s", dad.Target)
	}
	if _, ok := find(acts, ActLeaseAcquired); ok {
		t.Error("the lease was announced with an address nothing had checked")
	}
	_, acts = m.Step(at(4), 0, DADResult(netip.MustParseAddr("2001:db8:2::42:acff:fe11:2"), false))
	acq, ok := find(acts, ActLeaseAcquired)
	if !ok || len(acq.Lease6.Addrs) != 2 {
		t.Fatalf("the announced lease is %v (%v), want both addresses", acq.Lease6.Addrs, ok)
	}
}

// TestAResumedFormedLeaseIsNotFormedASecondTime is defeat row R-16.
//
// §5.5.3 d forms an address only for a prefix "not equal to the prefix of an
// address already in the list". After a restart the list is empty unless it is
// rebuilt from the addresses ring 2 remembered, so the FIRST advertisement
// after a restart would form a second copy of every address the machine
// already holds.
func TestAResumedFormedLeaseIsNotFormedASecondTime(t *testing.T) {
	p := testParams6SLAAC()
	p.Resume = &Resume6{Addrs: []Addr6{
		{Addr: netip.MustParseAddr("2001:db8:1::42:acff:fe11:2"), Preferred: 10000 * Second, Valid: 20000 * Second},
		{Addr: netip.MustParseAddr("2001:db8:2::42:acff:fe11:2"), Preferred: 10000 * Second, Valid: 20000 * Second},
	}}
	m := newMachine6(t, p)
	s, acts := m.Step(at(0), 0, Simple(EvStart))
	if s != State6DAD {
		t.Fatalf("a restart with remembered addresses left the machine in %s.%s", s, journalLines(acts))
	}
	if got := count(acts, ActStartDAD); got != 2 {
		t.Fatalf("%d remembered address(es) were checked, want 2", got)
	}
	for _, a := range []string{"2001:db8:1::42:acff:fe11:2", "2001:db8:2::42:acff:fe11:2"} {
		m.Step(at(1), 0, DADResult(netip.MustParseAddr(a), false))
	}

	// The advertisement that formed them arrives again.
	s, acts = m.Step(at(2), 0, raEvent6(t, ra6(false, false,
		pio("2001:db8:1::", 64, true, 86400, 14400),
		pio("2001:db8:2::", 64, true, 86400, 14400),
	)))
	if s != State6Bound {
		t.Fatalf("the advertisement that formed the remembered addresses left the machine in %s", s)
	}
	if _, ok := find(acts, ActStartDAD); ok {
		t.Error("an address the machine already holds was checked again")
	}
	if got := len(m.SLAACAddrs()); got != 2 {
		t.Fatalf("the machine holds %d address(es): %v", got, m.SLAACAddrs())
	}
	if got := m.SLAACCounters().Formed; got != 0 {
		t.Errorf("the formation counter is %d; every address came from the restart, not from this advertisement", got)
	}
	// And the lifetimes the advertisement carried were taken, so the resumed
	// entries are real entries and not placeholders.
	l, _ := m.Lease()
	for _, a := range l.Addrs {
		if a.Valid != 86400*Second {
			t.Errorf("%s has %s left, want the advertised 86400s", a.Addr, a.Valid)
		}
	}
}

// TestTheAutoModeDecisionIsTakenOnceOnTheFirstAdvertisement is defeat rows
// R-13 and R-33.
//
// RFC 4861 §4.2 gives the M flag its meaning: "When set, it indicates that
// addresses are available via Dynamic Host Configuration Protocol [DHCPv6]".
// A client that re-read it on every advertisement would abandon an address it
// holds because a router's configuration changed, which is worse than either
// choice.
func TestTheAutoModeDecisionIsTakenOnceOnTheFirstAdvertisement(t *testing.T) {
	t.Run("M=0 first, and a later M=1 does not undo it", func(t *testing.T) {
		m := slaacBound6(t, testParams6Auto(), 86400, 14400)
		l, _ := m.Lease()
		_, acts := m.Step(at(10), 0, raEvent6(t, ra6(true, false, pio(testSLAACPrefix, 64, true, 86400, 14400))))

		// THE ADDRESS IS NOT REVISITED. A Solicit here would abandon an
		// address the machine holds because a router's configuration changed.
		if hasSendV6(acts, wire.MsgSolicit) {
			t.Error("a later M=1 started a Solicit under a held formed address")
		}
		after, held := m.Lease()
		if !held || !after.SLAAC || len(after.Addrs) != 1 || after.Addrs[0].Addr != l.Addrs[0].Addr {
			t.Errorf("the held address changed: %v -> %v", l, after)
		}
		// What M=1 DOES buy in a mode that forms addresses is the same thing
		// O=1 buys: RFC 9915 §18.2.6's exchange, which carries no address at
		// all. It is asked once and it carries no IA.
		msg := mustSendV6(t, acts, wire.MsgInformationRequest)
		if _, ok := msg.Options.First(wire.OptV6IANA); ok {
			t.Error("the stateless exchange carries an IA_NA; §18.2.6's message asks for no address")
		}
		_, acts = m.Step(at(20), 0, raEvent6(t, ra6(true, false, pio(testSLAACPrefix, 64, true, 86400, 14400))))
		if hasSendV6(acts, wire.MsgInformationRequest) {
			t.Error("a second M=1 advertisement asked for the same configuration again")
		}
	})

	t.Run("M=1 first, and a later M=0 does not undo it", func(t *testing.T) {
		m := newMachine6(t, testParams6Auto())
		m.Step(at(0), 0, Simple(EvStart))
		s, acts := m.Step(at(1), 0, raEvent6(t, ra6(true, false, pio(testSLAACPrefix, 64, true, 86400, 14400))))
		if s != State6Init {
			t.Fatalf("M=1 left the machine in %s, want %s.%s", s, State6Init, journalLines(acts))
		}
		// §18.2.1's delay, and the reason it is here: one advertisement is one
		// multicast frame every host on the link receives at once.
		if _, ok := timerSet(acts, Timer6Delay); !ok {
			t.Errorf("the Solicit that an advertisement triggered was not delayed.%s", journalLines(acts))
		}
		if hasSendV6(acts, wire.MsgSolicit) {
			t.Error("the Solicit went out in the same instant as the advertisement that triggered it")
		}
		// The prefixes of the advertisement that TAKES the decision are
		// accounted in that same Step and not only from the next one on.
		if got := m.SLAACCounters().Ignored[SLAACIgnoreModeDHCP]; got != 1 {
			t.Errorf("the deciding advertisement's autonomous prefix is charged %d time(s), want 1", got)
		}
		s, acts = m.Step(at(2), 0, TimerFired(Timer6Delay))
		if s != State6Selecting {
			t.Fatalf("the delay left the machine in %s, want %s.%s", s, State6Selecting, journalLines(acts))
		}
		mustSendV6(t, acts, wire.MsgSolicit)
		if got := m.SLAACCounters().Formed; got != 0 {
			t.Errorf("%d address(es) were formed on a link whose router said DHCPv6", got)
		}
		// A later M=0 is observed and forms nothing: the machine is committed.
		s, acts = m.Step(at(3), 0, raEvent6(t, ra6(false, false, pio(testSLAACPrefix, 64, true, 86400, 14400))))
		if s != State6Selecting {
			t.Fatalf("a later M=0 left the machine in %s", s)
		}
		if got := m.SLAACCounters().Formed; got != 0 {
			t.Errorf("a later M=0 formed %d address(es) under an exchange in flight", got)
		}
		if got := m.SLAACCounters().Ignored[SLAACIgnoreModeDHCP]; got != 2 {
			t.Errorf("the unused autonomous prefixes are charged %d time(s), want 2 (one per advertisement)", got)
		}
	})
}

// TestTheAutoFallbackFiresOnlyWhenItMust is defeat rows R-14, R-30, R-31 and
// R-32, driven in every direction the row names.
//
// Design decision Q3: auto with M=1 and a silent server falls back to forming
// an address after half the router discovery window by default, configurable,
// with a counter and a journal line, and a strict setting that never falls
// back.
func TestTheAutoFallbackFiresOnlyWhenItMust(t *testing.T) {
	prefix := pio(testSLAACPrefix, 64, true, 86400, 14400)

	t.Run("it fires on a silent server with a prefix to form from", func(t *testing.T) {
		m := newMachine6(t, testParams6Auto())
		m.Step(at(0), 0, Simple(EvStart))
		_, acts := m.Step(at(1), 0, raEvent6(t, ra6(true, false, prefix)))
		d, ok := timerSet(acts, Timer6AutoFallback)
		if !ok {
			t.Fatalf("no fallback deadline was armed.%s", journalLines(acts))
		}
		// R-30: the window is measured from the instant auto COMMITS to
		// DHCPv6, which is the instant the Solicit begins, so router
		// discovery never eats it.
		if want := DefaultAutoFallback; d != want {
			t.Errorf("the fallback deadline is %s, want %s", d, want)
		}
		s, acts := m.Step(at(1).Add(d), 0, TimerFired(Timer6AutoFallback))
		if s != State6DAD {
			t.Fatalf("the fallback left the machine in %s, want %s.%s", s, State6DAD, journalLines(acts))
		}
		if _, ok := find(acts, ActStartDAD); !ok {
			t.Fatal("the fallback formed no address")
		}
		if got := m.SLAACCounters().Fallbacks; got != 1 {
			t.Errorf("the fallback counter is %d, want 1", got)
		}
		if !journalContains(acts, "no server answered") {
			t.Errorf("the fallback left no journal line naming it.%s", journalLines(acts))
		}

		// R-31: after the fallback the DHCPv6 exchange is over for this
		// machine's life, so a late Reply is refused by the state it arrives
		// in rather than installing a second address.
		m.Step(at(1).Add(d), 0, DADResult(netip.MustParseAddr(testSLAACAddr), false))
		before, _ := m.Lease()
		_, acts = m.Step(at(1).Add(d)+Instant(Second), 0, reply(t, uint32(capXIDRequest), "fd00:99::5"))
		after, held := m.Lease()
		if !held || !after.Equal(before) {
			t.Errorf("a late Reply changed the formed lease: %v -> %v", before, after)
		}
	})

	t.Run("it does not fire when the setting is strict", func(t *testing.T) {
		p := testParams6Auto()
		p.AutoFallback = -1
		m := newMachine6(t, p)
		m.Step(at(0), 0, Simple(EvStart))
		_, acts := m.Step(at(1), 0, raEvent6(t, ra6(true, false, prefix)))
		if d, ok := timerSet(acts, Timer6AutoFallback); ok {
			t.Errorf("a strict setting armed a fallback deadline of %s", d)
		}
		_, acts2 := m.Step(at(2), 0, TimerFired(Timer6Delay))
		mustSendV6(t, acts2, wire.MsgSolicit)
		if !journalContains(acts, "no fallback is configured") {
			t.Errorf("a strict setting left no journal line saying so.%s", journalLines(acts))
		}
	})

	t.Run("it does not fire after a Reply", func(t *testing.T) {
		p := testParams6Auto()
		m := newMachine6(t, p)
		m.Step(at(0), 0, Simple(EvStart))
		m.Step(at(1), 0, raEvent6(t, ra6(true, false, prefix)))
		_, acts := m.Step(at(2), 0, TimerFired(Timer6Delay))
		sol := mustSendV6(t, acts, wire.MsgSolicit)
		m.Step(at(3), capXIDRequest, advertise(t, sol.XID, 255))
		_, acts = m.Step(at(4), 0, reply(t, uint32(capXIDRequest), "fd00:99::184"))
		m.Step(at(5), 0, DADResult(netip.MustParseAddr("fd00:99::184"), false))
		if _, held := m.Lease(); !held {
			t.Fatalf("the DHCPv6 path did not acquire.%s", journalLines(acts))
		}
		s, acts := m.Step(at(1).Add(DefaultAutoFallback), 0, TimerFired(Timer6AutoFallback))
		if s != State6Bound {
			t.Fatalf("the fallback deadline moved a bound machine to %s", s)
		}
		if got := m.SLAACCounters().Fallbacks; got != 0 {
			t.Errorf("the fallback counter is %d with a lease in hand", got)
		}
		if got := m.SLAACCounters().Formed; got != 0 {
			t.Errorf("%d address(es) were formed with a DHCPv6 lease in hand", got)
		}
		if _, ok := find(acts, ActStartDAD); ok {
			t.Error("the fallback checked an address it had no reason to form")
		}
	})

	t.Run("it counts effect and not intent with no prefix to form from", func(t *testing.T) {
		m := newMachine6(t, testParams6Auto())
		m.Step(at(0), 0, Simple(EvStart))
		_, acts := m.Step(at(1), 0, raEvent6(t, ra6(true, false, pio(testSLAACPrefix, 64, false, 86400, 14400))))
		d, ok := timerSet(acts, Timer6AutoFallback)
		if !ok {
			t.Fatal("no fallback deadline was armed")
		}
		_, acts = m.Step(at(1).Add(d), 0, TimerFired(Timer6AutoFallback))
		f, ok := find(acts, ActFailed)
		if !ok {
			t.Fatalf("a fallback with nothing to form from told the caller nothing.%s", journalLines(acts))
		}
		if f.Reason != ReasonNoPrefix {
			t.Errorf("the failure was reported as %s, want %s", f.Reason, ReasonNoPrefix)
		}
		if got := m.SLAACCounters().Fallbacks; got != 0 {
			t.Errorf("the fallback counter is %d; nothing was fallen back to", got)
		}
	})

	t.Run("it is never armed in slaac or in dhcp mode", func(t *testing.T) {
		for _, p := range []Params6{testParams6SLAAC(), testParams6()} {
			m := newMachine6(t, p)
			m.Step(at(0), 0, Simple(EvStart))
			_, acts := m.Step(at(1), 0, raEvent6(t, ra6(true, false, prefix)))
			if d, ok := timerSet(acts, Timer6AutoFallback); ok {
				t.Errorf("%s armed a fallback deadline of %s", p.Mode, d)
			}
		}
	})
}

// TestRouterDiscoveryEndsWithItsOwnReason is defeat row R-36.
//
// RFC 4861 §6.3.7: "If a host sends MAX_RTR_SOLICITATIONS solicitations, and
// receives no Router Advertisements after having waited
// MAX_RTR_SOLICITATION_DELAY seconds after sending the last solicitation, the
// host concludes that there are no routers on the link for the purpose of
// [ADDRCONF]." A link with no router and a router that advertises nothing this
// client can use are the same silence to a caller unless they are told apart.
func TestRouterDiscoveryEndsWithItsOwnReason(t *testing.T) {
	t.Run("no advertisement at all", func(t *testing.T) {
		m := newMachine6(t, testParams6SLAAC())
		_, acts := m.Step(at(0), 0, Simple(EvStart))
		n := 1
		for i := 0; ; i++ {
			d, ok := timerSet(acts, Timer6RouterSolicit)
			if !ok {
				t.Fatalf("the schedule stopped after %d solicitation(s) with no verdict.%s", n, journalLines(acts))
			}
			var s State6
			s, acts = m.Step(at(0).Add(Duration(i+1)*d), 0, TimerFired(Timer6RouterSolicit))
			if f, ok := find(acts, ActFailed); ok {
				if f.Reason != ReasonNoRouter {
					t.Errorf("the verdict is %s, want %s", f.Reason, ReasonNoRouter)
				}
				// §6.3.7: "the host continues to receive and process Router
				// Advertisements messages in the event that routers appear on
				// the link", so the machine does not halt.
				if s != State6Discovering {
					t.Errorf("the verdict left the machine in %s, want %s", s, State6Discovering)
				}
				return
			}
			n++
			if i > 20 {
				t.Fatal("the schedule never reached a verdict")
			}
		}
	})

	t.Run("a router that advertises nothing this client can form from", func(t *testing.T) {
		m := newMachine6(t, testParams6SLAAC())
		_, acts := m.Step(at(0), 0, Simple(EvStart))
		// An advertisement with one prefix refused by rule a.
		m.Step(at(1), 0, raEvent6(t, ra6(false, false, pio(testSLAACPrefix, 64, false, 86400, 14400))))
		for i := 0; i < 20; i++ {
			d, ok := timerSet(acts, Timer6RouterSolicit)
			if !ok {
				d = Second
			}
			var s State6
			s, acts = m.Step(at(2).Add(Duration(i+1)*d), 0, TimerFired(Timer6RouterSolicit))
			if f, ok := find(acts, ActFailed); ok {
				if f.Reason != ReasonNoPrefix {
					t.Errorf("the verdict is %s, want %s", f.Reason, ReasonNoPrefix)
				}
				if !strings.Contains(f.Note, "refused") {
					t.Errorf("the verdict says %q and does not say how many options were refused", f.Note)
				}
				if s != State6Discovering {
					t.Errorf("the verdict left the machine in %s, want %s", s, State6Discovering)
				}
				return
			}
		}
		t.Fatal("a router advertising nothing usable never reached a verdict")
	})
}

// TestAHeldPrefixReadvertisedWithoutTheAutonomousFlagChangesNothing is defeat
// row R-39, and it is an ABSENCE the design note never states.
//
// §5.5.3 a is "If the Autonomous flag is not set, silently ignore the Prefix
// Information option" — the whole option, not its lifetimes. A client that
// treated A=0 as a withdrawal would drop an address a router merely stopped
// offering for autoconfiguration, which is what a router does the moment an
// operator turns on DHCPv6 beside it.
func TestAHeldPrefixReadvertisedWithoutTheAutonomousFlagChangesNothing(t *testing.T) {
	m := slaacBound6(t, testParams6SLAAC(), 86400, 14400)
	before, _ := m.Lease()

	s, acts := m.Step(at(10), 0, raEvent6(t, ra6(false, false, pio(testSLAACPrefix, 64, false, 0, 0))))
	if s != State6Bound {
		t.Fatalf("an A=0 advertisement of a held prefix left the machine in %s", s)
	}
	for _, k := range []ActionKind{ActLeaseLost, ActLeaseChanged, ActLeaseRenewed} {
		if _, ok := find(acts, k); ok {
			t.Errorf("an A=0 advertisement produced %s", k)
		}
	}
	after, held := m.Lease()
	if !held {
		t.Fatal("an A=0 advertisement took the address away")
	}
	// The lifetimes are the ones the earlier advertisement set, counted down
	// by the eight seconds that have passed and nothing else.
	if got, want := after.Addrs[0].Valid, before.Addrs[0].Valid; got != want {
		t.Errorf("the valid lifetime is %s, want %s: the stored lifetime must not move", got, want)
	}
	if got := m.SLAACCounters().Ignored[SLAACIgnoreNotAutonomous]; got != 1 {
		t.Errorf("the rule-a counter is %d, want 1", got)
	}
}

// TestADHCPv6LeaseIsNeverTouchedByAPrefixInformationOption is defeat row R-24.
//
// §5.5.3 e is scoped to "an address configured by stateless autoconfiguration
// in the list". A DHCPv6 address is not in that list, so an advertisement of
// the very prefix it sits in changes nothing about it — and the prefix is
// accounted rather than passed over in silence, because "your router offers an
// autonomous prefix you are not using" is a configuration worth seeing.
func TestADHCPv6LeaseIsNeverTouchedByAPrefixInformationOption(t *testing.T) {
	m := bind6(t, testParams6(), "fd00:99::184")
	before, _ := m.Lease()

	s, acts := m.Step(at(10), 0, raEvent6(t, ra6(false, false, pio("fd00:99::", 64, true, 60, 60))))
	if s != State6Bound {
		t.Fatalf("an autonomous prefix left a DHCPv6 machine in %s", s)
	}
	after, held := m.Lease()
	if !held {
		t.Fatal("an autonomous prefix ended a DHCPv6 lease")
	}
	if !after.Equal(before) {
		t.Errorf("the DHCPv6 lease changed: %v -> %v", before, after)
	}
	if got := m.SLAACCounters().Formed; got != 0 {
		t.Errorf("%d address(es) were formed in DHCPv6 mode", got)
	}
	if got := m.SLAACCounters().Ignored[SLAACIgnoreModeDHCP]; got != 1 {
		t.Errorf("the unused-prefix counter is %d, want 1", got)
	}
	if _, ok := find(acts, ActStartDAD); ok {
		t.Error("a DHCPv6 machine checked an address it never formed")
	}
}

// TestTheFailureIsStampedBeforeTheDecline is defeat row R-19, the inherited
// finding this change closes.
//
// MEASURED as a flake in the runtime suite's
// TestADuplicateAddressOnTheLinkIsDeclined: ring 2 bumps its conflict counters
// in the arm that drains ActFailed and drains the actions in the order ring 1
// listed them. With the Decline listed first, the DHCPDECLINE reached the
// server's log — the only outside evidence a Decline leaves — while the
// counter had not moved, so an observer that waited on the log line and then
// read the counter was racing a ring boundary.
//
// THE FIX IS AN ORDER AND THE TEST IS AN ORDER. Making the observer wait
// longer would be weakening; the previous order is a mutant that must die.
func TestTheFailureIsStampedBeforeTheDecline(t *testing.T) {
	for _, origin := range leaseOrigins6() {
		t.Run(origin.name, func(t *testing.T) {
			m := origin.dad(t, testParams6())
			_, acts := m.Step(at(10), 3, DADResult(netip.MustParseAddr(dnsmasqLeasedAddr), true))

			failed, ok := indexOf(acts, ActFailed)
			if !ok {
				t.Fatalf("a duplicate told the caller nothing.%s", journalLines(acts))
			}
			sent, ok := indexOfSendV6(acts, wire.MsgDecline6)
			if !ok {
				t.Fatalf("no Decline was sent for a duplicate.%s", journalLines(acts))
			}
			if failed > sent {
				t.Fatalf("the Decline is action %d and the failure is action %d: an observer that waits on the Decline reads the counter before it moved", sent, failed)
			}
		})
	}
}

// -------------------------------------------------------------- helpers --

// armedBefore reports whether the timer was armed before the first action of
// the given kind was stamped.
func armedBefore(acts []Action, id TimerID, k ActionKind) bool {
	for _, a := range acts {
		if a.Kind == k {
			return false
		}
		if a.Kind == ActSetTimer && a.Timer == id {
			return true
		}
	}
	return false
}

// indexOf is find's position, because an order is what some rows assert.
func indexOf(acts []Action, k ActionKind) (int, bool) {
	for i, a := range acts {
		if a.Kind == k {
			return i, true
		}
	}
	return 0, false
}

func indexOfSendV6(acts []Action, want wire.MessageTypeV6) (int, bool) {
	for i, a := range acts {
		if a.Kind == ActSendV6 && a.MsgV6 != nil && a.MsgV6.Type == want {
			return i, true
		}
	}
	return 0, false
}

func journalContains(acts []Action, sub string) bool {
	for _, a := range acts {
		if a.Kind == ActJournal && strings.Contains(a.Note, sub) {
			return true
		}
	}
	return false
}

// TestAMomentThatArrivesDuringDuplicateAddressDetectionStillArmsTheNextOne is
// defeat row R-46.
//
// §5.5.4's moments belong to the address, not to the state the machine happens
// to be in. A held address can reach its preferred lifetime while a SECOND
// address formed from a later advertisement is still being checked, and the
// tick that reports the deprecation has nothing to announce yet. It must still
// arm the next moment, or every remaining lifetime of every held address is
// lost for as long as the check runs.
//
// The mutant this test exists for deletes the armSLAAC call on that path.
func TestAMomentThatArrivesDuringDuplicateAddressDetectionStillArmsTheNextOne(t *testing.T) {
	m := newMachine6(t, testParams6SLAAC())
	m.Step(at(0), 0, Simple(EvStart))
	m.Step(at(1), 0, raEvent6(t, ra6(false, false, pio("2001:db8:1::", 64, true, 86400, 200))))
	m.Step(at(2), 0, DADResult(netip.MustParseAddr("2001:db8:1::42:acff:fe11:2"), false))

	// A second prefix arrives and its address goes into the check.
	_, acts := m.Step(at(3), 0, raEvent6(t, ra6(false, false,
		pio("2001:db8:1::", 64, true, 86400, 200),
		pio("2001:db8:2::", 64, true, 86400, 86400),
	)))
	if _, ok := find(acts, ActStartDAD); !ok {
		t.Fatalf("the second address was never checked.%s", journalLines(acts))
	}

	// The first address's preferred lifetime runs out while that check runs.
	_, acts = m.Step(at(203), 0, TimerFired(Timer6SLAAC))
	if !journalContains(acts, "deprecated") {
		t.Fatalf("the deprecation was not reported.%s", journalLines(acts))
	}
	if _, ok := find(acts, ActLeaseRenewed); ok {
		t.Error("a lease was announced with an address nothing had checked")
	}
	d, ok := timerSet(acts, Timer6SLAAC)
	if !ok {
		t.Fatalf("the next moment was not armed while a check was running.%s", journalLines(acts))
	}
	// The next moment is the first address's valid lifetime. Its origin is the
	// advertisement at at(3), which §5.5.3's closing note reset it from.
	if want := 86400*Second - Duration(at(203)-at(3)); d != want {
		t.Errorf("the next moment was armed for %s, want %s", d, want)
	}
	if got := m.SLAACCounters().Deprecated; got != 1 {
		t.Fatalf("the deprecation counter is %d after one deprecation, want 1", got)
	}
	// AND A SECOND TICK WHILE THE CHECK IS STILL RUNNING CHARGES NOTHING. The
	// counter leaves this ring through Stats, so an arm that reported a
	// deprecation and forgot to write the phase record would charge the same
	// address once per tick for as long as the check ran.
	_, acts = m.Step(at(204), 0, TimerFired(Timer6SLAAC))
	if got := m.SLAACCounters().Deprecated; got != 1 {
		t.Errorf("a second tick charged the same address again: %d.%s", got, journalLines(acts))
	}
	if journalContains(acts, "deprecated") {
		t.Errorf("a second tick reported the same deprecation again.%s", journalLines(acts))
	}

	// AND THE CALLER IS STILL TOLD, once there is something to tell it. The
	// record of what the machine has CHARGED and the record of what the CALLER
	// was told are two records: a machine that used one for both would reach
	// this announcement with the deprecation already "reported" and hand the
	// caller a plain renewal, so the chassis would install no second address
	// and deprecate nothing. Both assertions stand in one test for that
	// reason.
	_, acts = m.Step(at(205), 0, DADResult(netip.MustParseAddr("2001:db8:2::42:acff:fe11:2"), false))
	ch, ok := find(acts, ActLeaseChanged)
	if !ok {
		t.Fatalf("the set gained an address and one member deprecated, and neither reached the caller.%s", journalLines(acts))
	}
	if len(ch.Lease6.Addrs) != 2 {
		t.Fatalf("the reported lease carries %v, want both addresses", ch.Lease6.Addrs)
	}
	for _, a := range ch.Lease6.Addrs {
		if a.Addr == netip.MustParseAddr("2001:db8:1::42:acff:fe11:2") && a.Preferred != 0 {
			t.Errorf("the deprecated address is reported preferred for %s, want 0 (RFC 4862 §5.5.4)", a.Preferred)
		}
	}
	if got := m.SLAACCounters().Deprecated; got != 1 {
		t.Errorf("the announcement charged the deprecation a second time: %d", got)
	}
}

// TestAutoDoesNotFallBackIntoFormingAfterItCommittedToDHCPv6 is defeat row
// R-47.
//
// Mode6Auto's decision is taken once (R-29). Every path that restarts server
// discovery goes through begin(), and begin() routes on the mode, so a
// committed machine whose lease ran out would re-enter the forming branch and
// wait in DISCOVERING6 for a router that already said its addresses come from
// DHCPv6 (RFC 4861 §4.2). The committed flag is the second half of that
// routing decision.
func TestAutoDoesNotFallBackIntoFormingAfterItCommittedToDHCPv6(t *testing.T) {
	m := newMachine6(t, testParams6Auto())
	m.Step(at(0), 0, Simple(EvStart))

	// M=1 with an autonomous prefix present: the prefix is what the mutant
	// would form from, and it stays unused.
	m.Step(at(1), 0, raEvent6(t, ra6(true, false,
		pio(testSLAACPrefix, 64, true, 86400, 14400))))
	_, acts := m.Step(at(2), 0, TimerFired(Timer6Delay))
	sol := mustSendV6(t, acts, wire.MsgSolicit)
	m.Step(at(2), capXIDRequest, advertise(t, sol.XID, 255))
	if s, _ := m.Step(at(3), 0, reply(t, uint32(capXIDRequest), dnsmasqLeasedAddr)); s != State6DAD {
		t.Fatalf("the Reply to a committed auto machine left it in %s", s)
	}
	if s, _ := m.Step(at(4), 0, DADResult(addr6(dnsmasqLeasedAddr), false)); s != State6Bound {
		t.Fatalf("the checked address did not bind: %s", s)
	}

	// The granted lease runs out. Discovery restarts.
	s, acts := m.Step(at(400), 0, TimerFired(Timer6Expire))
	if s == State6Discovering {
		t.Fatalf("the restart went back to waiting for a router, which already said DHCPv6.%s", journalLines(acts))
	}
	if _, ok := find(acts, ActStartDAD); ok {
		t.Errorf("the restart formed an address on a link that says DHCPv6.%s", journalLines(acts))
	}
	if got := m.SLAACCounters().Formed; got != 0 {
		t.Errorf("%d address(es) were formed on a committed link, want 0", got)
	}
	// It solicits, here or after §18.2.1's delay.
	if s == State6Init {
		s, acts = m.Step(at(401), 0, TimerFired(Timer6Delay))
	}
	if s != State6Selecting {
		t.Fatalf("the restart left the machine in %s, want %s.%s", s, State6Selecting, journalLines(acts))
	}
	if !hasSendV6(acts, wire.MsgSolicit) {
		t.Errorf("the restart sent no Solicit.%s", journalLines(acts))
	}
}

// TestAnAdvertisementWithNothingToFormFromDoesNotEndTheSolicitationSchedule is
// defeat row R-48.
//
// RFC 4861 §6.3.7 runs the schedule "To obtain Router Advertisements quickly",
// and one that arrived answers that question only for a client that got what
// it was asking for. A client with no address yet has been told nothing it
// needed, and a schedule cancelled here would never reach §6.3.7's conclusion:
// the machine would wait for a second advertisement that may never come, with
// no verdict either way.
//
// Both halves are driven: a first advertisement reaching a client with no
// address keeps the schedule, and one reaching a client that already holds an
// address ends it.
func TestAnAdvertisementWithNothingToFormFromDoesNotEndTheSolicitationSchedule(t *testing.T) {
	t.Run("nothing to form from keeps the schedule", func(t *testing.T) {
		m := newMachine6(t, testParams6SLAAC())
		_, acts := m.Step(at(0), 0, Simple(EvStart))
		if _, ok := timerSet(acts, Timer6RouterSolicit); !ok {
			t.Fatalf("no solicitation schedule was armed.%s", journalLines(acts))
		}
		// A=0: §5.5.3 a refuses it, so this client still has no address.
		_, acts = m.Step(at(1), 0, raEvent6(t, ra6(false, false,
			pio(testSLAACPrefix, 64, false, 86400, 14400))))
		if _, ok := find(acts, ActStartDAD); ok {
			t.Fatal("a prefix with A=0 formed an address")
		}
		if timerCancelled(acts, Timer6RouterSolicit) {
			t.Errorf("the schedule was cancelled by an advertisement that left this client with no address.%s", journalLines(acts))
		}
	})

	t.Run("a client that already has an address ends the schedule", func(t *testing.T) {
		p := testParams6SLAAC()
		p.Resume = &Resume6{Addrs: []Addr6{
			{Addr: netip.MustParseAddr(testSLAACAddr), Preferred: 10000 * Second, Valid: 20000 * Second},
		}}
		m := newMachine6(t, p)
		m.Step(at(0), 0, Simple(EvStart))
		if s, _ := m.Step(at(1), 0, DADResult(netip.MustParseAddr(testSLAACAddr), false)); s != State6Bound {
			t.Fatalf("the remembered address did not bind: %s", s)
		}
		_, acts := m.Step(at(2), 0, raEvent6(t, ra6(false, false,
			pio(testSLAACPrefix, 64, true, 86400, 14400))))
		if !timerCancelled(acts, Timer6RouterSolicit) {
			t.Errorf("the schedule outlived the answer it was asking for.%s", journalLines(acts))
		}
	})
}

// TestAStatelessLinkWithNoUsablePrefixStillAsksForItsConfiguration is defeat
// row R-50.
//
// RFC 4861 §4.2: "When set, it indicates that other configuration information
// is available via DHCPv6." A link whose router says M=0 O=1 and advertises no
// prefix this client can form an address from has offered something, and the
// design's mode table calls that row "no PIO but O=1: configured without an
// address". Ending RFC 4861 §6.3.7's schedule with a fatal verdict there would
// leave that configuration unasked for.
//
// The question is asked at the END of the schedule and not on the
// advertisement, because the machine runs one exchange at a time: an
// Information-request started while a prefix might still arrive would take the
// state the advertisement's address needs.
func TestAStatelessLinkWithNoUsablePrefixStillAsksForItsConfiguration(t *testing.T) {
	p := testParams6Auto()
	m := newMachine6(t, p)
	m.Step(at(0), 0, Simple(EvStart))

	// M=0, O=1, and the one prefix is not autonomous: §5.5.3 a refuses it.
	at1 := at(1)
	s, acts := m.Step(at1, 0, raEvent6(t, ra6(false, true,
		pio(testSLAACPrefix, 64, false, 86400, 14400))))
	if s != State6Discovering {
		t.Fatalf("the advertisement left the machine in %s, want %s.%s", s, State6Discovering, journalLines(acts))
	}
	if hasSendV6(acts, wire.MsgInformationRequest) {
		t.Error("the stateless exchange started while a prefix could still arrive")
	}

	// Run the schedule out. EvStart already sent the first solicitation, so
	// the remaining transmissions and the tick that ends the schedule are
	// MaxRtrSolicitations ticks.
	var last []Action
	for i := 0; i < MaxRtrSolicitations; i++ {
		s, last = m.Step(at(int64(10+i)), 0, TimerFired(Timer6RouterSolicit))
	}
	if _, ok := find(last, ActFailed); ok {
		t.Errorf("a link that offered configuration ended fatal.%s", journalLines(last))
	}
	if s != State6InfoRequesting {
		t.Fatalf("the schedule ended in %s, want %s.%s", s, State6InfoRequesting, journalLines(last))
	}
	msg := mustSendV6(t, last, wire.MsgInformationRequest)
	if _, ok := msg.Options.First(wire.OptV6IANA); ok {
		t.Error("the stateless exchange carries an IA_NA; §18.2.6's message asks for no address")
	}

	// AND IT IS ASKED ONCE. The exchange completes, and a solicitation timer
	// that had already fired when the schedule ended is still on its way here;
	// it must not start §18.2.6 a second time.
	m.Step(at(20), 0, receivedV6(t, wire.MsgReply, msg.XID,
		optClientID(capDUID), optServerID(testServerDUID)))
	_, acts = m.Step(at(21), 0, TimerFired(Timer6RouterSolicit))
	if hasSendV6(acts, wire.MsgInformationRequest) {
		t.Errorf("a stale solicitation tick asked for the same configuration again.%s", journalLines(acts))
	}

	// AND THE SAME LINK IN slaac IS FATAL. The design's mode table gives that
	// row no O=1 exception: a client told to form its own address and given
	// none has failed, and ReasonNoPrefix is one of the two verdicts #816
	// exists to tell apart. The two modes are driven in one test because it is
	// the DIFFERENCE between the rows that the arm is keyed on.
	sm := newMachine6(t, testParams6SLAAC())
	sm.Step(at(0), 0, Simple(EvStart))
	sm.Step(at(1), 0, raEvent6(t, ra6(false, true,
		pio(testSLAACPrefix, 64, false, 86400, 14400))))
	var slast []Action
	for i := 0; i < MaxRtrSolicitations; i++ {
		_, slast = sm.Step(at(int64(10+i)), 0, TimerFired(Timer6RouterSolicit))
	}
	f, ok := find(slast, ActFailed)
	if !ok {
		t.Fatalf("a slaac link that formed no address did not fail.%s", journalLines(slast))
	}
	if f.Reason != ReasonNoPrefix {
		t.Errorf("the slaac verdict is %s, want %s", f.Reason, ReasonNoPrefix)
	}
	if hasSendV6(slast, wire.MsgInformationRequest) {
		t.Errorf("a slaac machine asked a DHCPv6 server for configuration.%s", journalLines(slast))
	}
}

// TestTheFallbackWindowIsHalfOfTheScheduleThisMachineWillRun is defeat row
// R-51: decision Q3 is "half the window", and the window is RFC 4861 §6.3.7's
// schedule as this machine is configured to run it, not as the constants
// describe it. A caller that lengthens router discovery and sets no fallback
// was otherwise given half of a window it had replaced.
func TestTheFallbackWindowIsHalfOfTheScheduleThisMachineWillRun(t *testing.T) {
	for _, tc := range []struct {
		name     string
		solicits int
		interval Duration
		want     Duration
	}{
		{"the defaults", 0, 0, DefaultAutoFallback},
		{"a longer schedule", 6, 10 * Second, 30 * Second},
		{"more solicitations only", 8, 0, 16 * Second},
		{"a longer interval only", 0, 20 * Second, 30 * Second},
		// HALF OF NOTHING IS NOT A BUDGET. A negative value is this field's
		// documented "no solicitations at all", and a fallback of zero would
		// fire before the first Solicit ever left.
		{"router solicitation turned off", -1, 0, DefaultAutoFallback},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := testParams6Auto()
			p.RouterSolicitations = tc.solicits
			p.RouterSolicitInterval = tc.interval
			m := newMachine6(t, p)
			m.Step(at(0), 0, Simple(EvStart))
			// A non-zero draw, so the §18.2.1 delay is visible and the window
			// can be told apart from the window plus the delay.
			_, acts := m.Step(at(1), 7, raEvent6(t, ra6(true, false,
				pio(testSLAACPrefix, 64, true, 86400, 14400))))
			d, ok := timerSet(acts, Timer6AutoFallback)
			if !ok {
				t.Fatalf("no fallback deadline was armed.%s", journalLines(acts))
			}
			// THE WINDOW IS THE SERVER'S AND IS MEASURED FROM THE SOLICIT. The
			// deadline is armed in the Step that commits and the Solicit
			// leaves one delay later, so the delay is added to the window and
			// not taken out of it.
			sd, ok := timerSet(acts, Timer6Delay)
			if !ok {
				t.Fatalf("the Solicit was not delayed.%s", journalLines(acts))
			}
			if sd <= 0 {
				t.Fatalf("the delay drawn is %s; this row cannot tell the two shapes apart", sd)
			}
			if d != sd+tc.want {
				t.Errorf("the fallback deadline is %s, want %s (the %s window after the %s delay)", d, sd+tc.want, tc.want, sd)
			}
			// And the Solicit really does go out first.
			s, acts := m.Step(at(1).Add(sd), 0, TimerFired(Timer6Delay))
			if s != State6Selecting || !hasSendV6(acts, wire.MsgSolicit) {
				t.Fatalf("the fallback window opened in %s with no Solicit.%s", s, journalLines(acts))
			}
			if got := m.SLAACCounters().Fallbacks; got != 0 {
				t.Errorf("the fallback fired before the Solicit: %d", got)
			}
		})
	}
}

// TestAnAddressTheLinkAlreadyHoldsIsNotFormedAgainOnEveryAdvertisement is
// defeat row R-52.
//
// RFC 4861 §6.2.1 has a router advertise unsolicited "at least every
// MaxRtrAdvInterval", and RFC 4862 §5.5.3 d forms an address from the prefix
// and this link's own hardware address, which is the same address every time.
// A machine that only dropped the duplicate would form it, check it and fail
// again once per advertisement, for as long as the other node held it, and
// every one of those is an ActFailed the caller acts on.
func TestAnAddressTheLinkAlreadyHoldsIsNotFormedAgainOnEveryAdvertisement(t *testing.T) {
	prefix := pio(testSLAACPrefix, 64, true, 86400, 14400)
	m := newMachine6(t, testParams6SLAAC())
	m.Step(at(0), 0, Simple(EvStart))
	m.Step(at(1), 0, raEvent6(t, ra6(false, false, prefix)))
	_, acts := m.Step(at(2), 0, DADResult(netip.MustParseAddr(testSLAACAddr), true))
	if _, ok := find(acts, ActFailed); !ok {
		t.Fatalf("the duplicate produced no failure.%s", journalLines(acts))
	}
	if got := m.SLAACCounters().Conflicts; got != 1 {
		t.Fatalf("the conflict counter is %d, want 1", got)
	}

	// The router repeats the same advertisement. Nothing is formed and nothing
	// is checked a second time.
	s, acts := m.Step(at(3), 0, raEvent6(t, ra6(false, false, prefix)))
	if _, ok := find(acts, ActStartDAD); ok {
		t.Errorf("the repeat started a second check for an address already found in use.%s", journalLines(acts))
	}
	if _, ok := find(acts, ActFailed); ok {
		t.Errorf("the repeat produced a second failure for one duplicate.%s", journalLines(acts))
	}
	if s != State6Discovering {
		t.Errorf("the repeat left the machine in %s, want %s", s, State6Discovering)
	}
	if got := m.SLAACCounters().Formed; got != 1 {
		t.Errorf("%d address(es) were formed, want the one the duplicate cost", got)
	}
	if got := m.SLAACCounters().Conflicts; got != 1 {
		t.Errorf("the conflict counter is %d after one duplicate and two advertisements, want 1", got)
	}
	// The refusal is charged under its own reason, so an operator can see why
	// this link produced no address.
	if got := m.SLAACCounters().Ignored[SLAACIgnoreDuplicate]; got != 1 {
		t.Errorf("the repeated prefix is charged %d time(s) to the duplicate reason, want 1", got)
	}

	// A stop and a start is the only event that can mean the other node let it
	// go, and it tries once more.
	m.Step(at(4), 0, Simple(EvStop))
	m.Step(at(5), 0, Simple(EvStart))
	_, acts = m.Step(at(6), 0, raEvent6(t, ra6(false, false, prefix)))
	if _, ok := find(acts, ActStartDAD); !ok {
		t.Errorf("a restarted machine did not try the address again.%s", journalLines(acts))
	}
}

// TestAnAddressMadePreferredAgainCanDeprecateAgain is defeat row R-54.
//
// RFC 4862 §5.5.3 e's closing note: "the preferred lifetime of the
// corresponding address is always reset to the Preferred Lifetime in the
// received Prefix Information option". An address the router makes preferred
// again is preferred again, so the next time its preferred lifetime runs out
// is a second change of phase, and the record of what has been charged must
// let go of it. A record that never cleared would silence every deprecation
// of that address for the life of the machine.
func TestAnAddressMadePreferredAgainCanDeprecateAgain(t *testing.T) {
	addr := netip.MustParseAddr(testSLAACAddr)
	m := newMachine6(t, testParams6SLAAC())
	m.Step(at(0), 0, Simple(EvStart))
	m.Step(at(1), 0, raEvent6(t, ra6(false, false, pio(testSLAACPrefix, 64, true, 86400, 100))))
	m.Step(at(2), 0, DADResult(addr, false))

	_, acts := m.Step(at(101), 0, TimerFired(Timer6SLAAC))
	if got := m.SLAACCounters().Deprecated; got != 1 {
		t.Fatalf("the deprecation counter is %d after the first deprecation, want 1.%s", got, journalLines(acts))
	}

	// The router makes it preferred again.
	_, acts = m.Step(at(102), 0, raEvent6(t, ra6(false, false, pio(testSLAACPrefix, 64, true, 86400, 200))))
	ch, ok := find(acts, ActLeaseChanged)
	if !ok {
		t.Fatalf("an address that became preferred again was reported as a plain renewal.%s", journalLines(acts))
	}
	if len(ch.Lease6.Addrs) != 1 || ch.Lease6.Addrs[0].Preferred <= 0 {
		t.Fatalf("the reported lease is %v, want the address preferred again", ch.Lease6.Addrs)
	}

	// And it deprecates again when the new preferred lifetime runs out.
	_, acts = m.Step(at(302), 0, TimerFired(Timer6SLAAC))
	if got := m.SLAACCounters().Deprecated; got != 2 {
		t.Errorf("the second deprecation of the same address is charged %d time(s) in total, want 2.%s", got, journalLines(acts))
	}
	if !journalContains(acts, "deprecated") {
		t.Errorf("the second deprecation was not reported.%s", journalLines(acts))
	}
}

// journalCount is how many journal lines carry sub, because "it was reported"
// and "it was reported once per time it happened" are different assertions and
// only the second one can see a change of phase that is charged once.
func journalCount(acts []Action, sub string) int {
	n := 0
	for _, a := range acts {
		if a.Kind == ActJournal && strings.Contains(a.Note, sub) {
			n++
		}
	}
	return n
}

// TestASecondDeprecationIsChargedWhenTheRepeatArrivesLate is defeat row R-55,
// and it is R-54 with the one distance that makes the defect visible.
//
// R-54's repeat advertisement arrives while the NEW preferred lifetime, counted
// from the OLD origin, still has time to run, so the question "is this address
// deprecated" answers correctly there by accident. A router that repeats its
// advertisement later than that — which is every router on its own unsolicited
// schedule, RFC 4861 §6.2.1 — answers it against the lifetime that just ended.
// The address is then preferred again for the caller and deprecates again in
// fact, and neither the counter nor the journal says so.
func TestASecondDeprecationIsChargedWhenTheRepeatArrivesLate(t *testing.T) {
	addr := netip.MustParseAddr(testSLAACAddr)
	m := newMachine6(t, testParams6SLAAC())
	m.Step(at(0), 0, Simple(EvStart))
	m.Step(at(1), 0, raEvent6(t, ra6(false, false, pio(testSLAACPrefix, 64, true, 86400, 100))))
	m.Step(at(2), 0, DADResult(addr, false))

	var seen []Action
	_, acts := m.Step(at(101), 0, TimerFired(Timer6SLAAC))
	seen = append(seen, acts...)
	if got := m.SLAACCounters().Deprecated; got != 1 {
		t.Fatalf("the first deprecation is charged %d time(s), want 1.%s", got, journalLines(acts))
	}

	// THE REPEAT IS LATE: at(1000) is past at(1) plus the 200 seconds this
	// advertisement grants, which is exactly the arithmetic the defect used.
	_, acts = m.Step(at(1000), 0, raEvent6(t, ra6(false, false, pio(testSLAACPrefix, 64, true, 86400, 200))))
	seen = append(seen, acts...)
	ch, ok := find(acts, ActLeaseChanged)
	if !ok {
		t.Fatalf("a late repeat that makes the address preferred again was reported as a plain renewal.%s", journalLines(acts))
	}
	if len(ch.Lease6.Addrs) != 1 || ch.Lease6.Addrs[0].Preferred <= 0 {
		t.Fatalf("the reported lease is %v, want the address preferred again", ch.Lease6.Addrs)
	}

	_, acts = m.Step(at(1200), 0, TimerFired(Timer6SLAAC))
	seen = append(seen, acts...)
	if got := m.SLAACCounters().Deprecated; got != 2 {
		t.Errorf("two deprecations of the same address are charged %d time(s), want 2.%s", got, journalLines(acts))
	}
	if got := journalCount(seen, "is deprecated"); got != 2 {
		t.Errorf("two deprecations left %d journal line(s), want 2.%s", got, journalLines(seen))
	}
}

// TestARepeatThatLeavesTheAddressDeprecatedIsNotASecondDeprecation is defeat
// row R-56, and it is R-55's opposite direction.
//
// §5.5.3 e's note resets the preferred lifetime to what the option carries, and
// an option carrying zero resets it to zero: the address stays deprecated, and
// nothing has changed phase. A charge that cleared on every advertisement would
// report one deprecation again for every advertisement a router repeats, which
// is the failure the charge exists to prevent.
func TestARepeatThatLeavesTheAddressDeprecatedIsNotASecondDeprecation(t *testing.T) {
	addr := netip.MustParseAddr(testSLAACAddr)
	m := newMachine6(t, testParams6SLAAC())
	m.Step(at(0), 0, Simple(EvStart))
	m.Step(at(1), 0, raEvent6(t, ra6(false, false, pio(testSLAACPrefix, 64, true, 86400, 100))))
	m.Step(at(2), 0, DADResult(addr, false))

	var seen []Action
	_, acts := m.Step(at(101), 0, TimerFired(Timer6SLAAC))
	seen = append(seen, acts...)

	// The router repeats the prefix with a preferred lifetime of zero: still
	// valid, still deprecated, and the valid lifetime is untouched.
	_, acts = m.Step(at(1000), 0, raEvent6(t, ra6(false, false, pio(testSLAACPrefix, 64, true, 86400, 0))))
	seen = append(seen, acts...)
	_, acts = m.Step(at(1200), 0, TimerFired(Timer6SLAAC))
	seen = append(seen, acts...)

	if got := m.SLAACCounters().Deprecated; got != 1 {
		t.Errorf("one deprecation is charged %d time(s), want 1.%s", got, journalLines(seen))
	}
	if got := journalCount(seen, "is deprecated"); got != 1 {
		t.Errorf("one deprecation left %d journal line(s), want 1.%s", got, journalLines(seen))
	}
	l, held := m.Lease()
	if !held || len(l.Addrs) != 1 || l.Addrs[0].Preferred != 0 {
		t.Errorf("the lease is %v held=%v, want one address with no preferred lifetime left", l.Addrs, held)
	}
}

// TestAPrefixAdvertisedOnceIsStillFormedFromAtTheFallback is defeat row R-57.
//
// RFC 4861 §6.3.4: "Hosts accept the union of all received information; the
// receipt of a Router Advertisement MUST NOT invalidate all information
// received in a previous advertisement or from another source." A router may
// carry its Prefix Information options in one advertisement and leave them out
// of the next, so a fallback that reads only the most recent advertisement
// refuses to form from a prefix the router has already granted, and reports the
// link as having no prefix at all.
func TestAPrefixAdvertisedOnceIsStillFormedFromAtTheFallback(t *testing.T) {
	m := newMachine6(t, testParams6Auto())
	m.Step(at(0), 0, Simple(EvStart))

	// RA 1: M=1 with an autonomous prefix. The machine commits to DHCPv6.
	_, acts := m.Step(at(1), 0, raEvent6(t, ra6(true, false, pio(testSLAACPrefix, 64, true, 86400, 14400))))
	d, ok := timerSet(acts, Timer6AutoFallback)
	if !ok {
		t.Fatalf("no fallback deadline was armed.%s", journalLines(acts))
	}
	_, acts = m.Step(at(2), 0, TimerFired(Timer6Delay))
	mustSendV6(t, acts, wire.MsgSolicit)

	// RA 2: the same router, no Prefix Information option at all.
	if s, acts := m.Step(at(3), 0, raEvent6(t, ra6(true, false))); s == State6DAD {
		t.Fatalf("an advertisement with no prefix started address formation.%s", journalLines(acts))
	}

	// No server answers.
	s, acts := m.Step(at(1).Add(d), 0, TimerFired(Timer6AutoFallback))
	if f, failed := find(acts, ActFailed); failed {
		t.Fatalf("the fallback refused to form: %s %q.%s", f.Reason, f.Note, journalLines(acts))
	}
	if s != State6DAD {
		t.Fatalf("the fallback left the machine in %s, want %s.%s", s, State6DAD, journalLines(acts))
	}
	dad, ok := find(acts, ActStartDAD)
	if !ok {
		t.Fatalf("the fallback formed no address.%s", journalLines(acts))
	}
	if want := netip.MustParseAddr(testSLAACAddr); dad.Target != want {
		t.Errorf("the fallback formed %s, want %s: the prefix is the one RA 1 carried", dad.Target, want)
	}
	if got := m.SLAACCounters().Fallbacks; got != 1 {
		t.Errorf("the fallback counter is %d, want 1", got)
	}

	// THE LIFETIMES ARE COUNTED FROM THE ADVERTISEMENT THAT GRANTED THEM, not
	// from the fallback. The wait for a silent server is the client's, and a
	// client that restarted the clock here would hold the address longer than
	// the router allowed.
	m.Step(at(1).Add(d), 0, DADResult(netip.MustParseAddr(testSLAACAddr), false))
	l, held := m.Lease()
	if !held || len(l.Addrs) != 1 {
		t.Fatalf("the formed lease is %v held=%v, want one address", l.Addrs, held)
	}
	if got, want := l.Addrs[0].Valid, 86400*Second-Duration(d); got != want {
		t.Errorf("the valid lifetime is %s, want %s: it runs from RA 1 and not from the fallback", got, want)
	}
}

// TestTheMostRecentOptionForAPrefixIsTheOneTheFallbackForms is defeat row R-59.
//
// RFC 4861 §6.3.4: "when received information for a specific parameter (e.g.,
// Link MTU) or option (e.g., Lifetime on a specific Prefix) differs from
// information received earlier, and the parameter/option can only have one
// value, the most recently received information is considered authoritative."
// A union that kept the first option it saw would form from a lifetime the
// router has since replaced.
func TestTheMostRecentOptionForAPrefixIsTheOneTheFallbackForms(t *testing.T) {
	m := newMachine6(t, testParams6Auto())
	m.Step(at(0), 0, Simple(EvStart))
	_, acts := m.Step(at(1), 0, raEvent6(t, ra6(true, false, pio(testSLAACPrefix, 64, true, 86400, 14400))))
	d, ok := timerSet(acts, Timer6AutoFallback)
	if !ok {
		t.Fatalf("no fallback deadline was armed.%s", journalLines(acts))
	}
	m.Step(at(2), 0, TimerFired(Timer6Delay))
	// The same prefix again, with a longer valid lifetime, one second later.
	m.Step(at(3), 0, raEvent6(t, ra6(true, false, pio(testSLAACPrefix, 64, true, 172800, 14400))))

	s, acts := m.Step(at(1).Add(d), 0, TimerFired(Timer6AutoFallback))
	if s != State6DAD {
		t.Fatalf("the fallback left the machine in %s, want %s.%s", s, State6DAD, journalLines(acts))
	}
	m.Step(at(1).Add(d), 0, DADResult(netip.MustParseAddr(testSLAACAddr), false))
	l, held := m.Lease()
	if !held || len(l.Addrs) != 1 {
		t.Fatalf("the formed lease is %v held=%v, want one address", l.Addrs, held)
	}
	// Counted from the SECOND advertisement, at(3), and not from the first.
	if got, want := l.Addrs[0].Valid, 172800*Second-Duration(at(1).Add(d)-at(3)); got != want {
		t.Errorf("the valid lifetime is %s, want %s: the newer option is the authoritative one", got, want)
	}
}

// TestAPrefixThatArrivesAfterTheDecisionIsFormedFromAtTheFallback is defeat row
// R-60, and it is R-57's other half: the union accumulates FORWARD as well.
//
// The advertisement that decides the mode may carry no prefix at all — §6.3.4's
// union is what makes that legal — and a later advertisement from the same
// router may carry one while this client is still waiting for a server. The
// fallback forms from it, or the split costs the client its address.
func TestAPrefixThatArrivesAfterTheDecisionIsFormedFromAtTheFallback(t *testing.T) {
	m := newMachine6(t, testParams6Auto())
	m.Step(at(0), 0, Simple(EvStart))
	_, acts := m.Step(at(1), 0, raEvent6(t, ra6(true, false)))
	d, ok := timerSet(acts, Timer6AutoFallback)
	if !ok {
		t.Fatalf("no fallback deadline was armed.%s", journalLines(acts))
	}
	m.Step(at(2), 0, TimerFired(Timer6Delay))
	m.Step(at(3), 0, raEvent6(t, ra6(true, false, pio(testSLAACPrefix, 64, true, 86400, 14400))))

	s, acts := m.Step(at(1).Add(d), 0, TimerFired(Timer6AutoFallback))
	if f, failed := find(acts, ActFailed); failed {
		t.Fatalf("the fallback refused to form: %s %q.%s", f.Reason, f.Note, journalLines(acts))
	}
	if s != State6DAD {
		t.Fatalf("the fallback left the machine in %s, want %s.%s", s, State6DAD, journalLines(acts))
	}
	dad, ok := find(acts, ActStartDAD)
	if !ok {
		t.Fatalf("the fallback formed no address.%s", journalLines(acts))
	}
	if want := netip.MustParseAddr(testSLAACAddr); dad.Target != want {
		t.Errorf("the fallback formed %s, want %s", dad.Target, want)
	}
}

// TestAPrefixThatRanOutWhileWaitingFormsNothingAtTheFallback is defeat row
// R-58, and it is R-57's other direction: the union is replayed with each
// option's OWN origin, so an option that expired while this client waited for a
// server has nothing left to give.
//
// RFC 4862 §5.5.3 d forms an address "if the Valid Lifetime is not 0", and the
// valid lifetime of a deferred option is what is left of it at the moment the
// address would be formed. Replaying with the fallback's own instant as the
// origin would grant the client a lifetime the router never advertised.
func TestAPrefixThatRanOutWhileWaitingFormsNothingAtTheFallback(t *testing.T) {
	p := testParams6Auto()
	m := newMachine6(t, p)
	m.Step(at(0), 0, Simple(EvStart))

	// The valid lifetime is one second and the fallback budget is longer, so
	// the option is dead before the deadline it is waiting on.
	_, acts := m.Step(at(1), 0, raEvent6(t, ra6(true, false, pio(testSLAACPrefix, 64, true, 1, 1))))
	d, ok := timerSet(acts, Timer6AutoFallback)
	if !ok {
		t.Fatalf("no fallback deadline was armed.%s", journalLines(acts))
	}
	if d <= Second {
		t.Fatalf("the fallback budget is %s, which is not longer than the advertised valid lifetime", d)
	}
	m.Step(at(2), 0, TimerFired(Timer6Delay))

	before := m.SLAACCounters().Ignored[SLAACIgnoreValidZero]
	s, acts := m.Step(at(1).Add(d), 0, TimerFired(Timer6AutoFallback))
	if _, ok := find(acts, ActStartDAD); ok {
		t.Fatalf("an option whose valid lifetime had run out formed an address.%s", journalLines(acts))
	}
	f, failed := find(acts, ActFailed)
	if !failed || f.Reason != ReasonNoPrefix {
		t.Fatalf("the fallback ended with %v, want a %s verdict.%s", f.Reason, ReasonNoPrefix, journalLines(acts))
	}
	if s != State6Discovering {
		t.Errorf("the verdict left the machine in %s, want %s", s, State6Discovering)
	}
	if got := m.SLAACCounters().Ignored[SLAACIgnoreValidZero] - before; got != 1 {
		t.Errorf("rule d's zero-valid counter rose by %d, want 1.%s", got, journalLines(acts))
	}
	if got := m.SLAACCounters().Fallbacks; got != 0 {
		t.Errorf("the fallback counter is %d, want 0: nothing was formed", got)
	}
}

// TestTheDeferredUnionDoesNotSurviveAStop is defeat row R-61.
//
// A stop throws away the decision the union was kept for, and RFC 4861 §6.3.4's
// union is information a router gave to THIS run of the machine. The lifetimes
// in it have been running since the advertisement that carried them, so a
// machine that kept the set across a stop would, on the next link's fallback,
// form from an option nothing has re-advertised since.
func TestTheDeferredUnionDoesNotSurviveAStop(t *testing.T) {
	m := newMachine6(t, testParams6Auto())
	m.Step(at(0), 0, Simple(EvStart))
	m.Step(at(1), 0, raEvent6(t, ra6(true, false, pio(testSLAACPrefix, 64, true, 86400, 14400))))
	m.Step(at(2), 0, TimerFired(Timer6Delay))

	if s, _ := m.Step(at(3), 0, Simple(EvStop)); s != State6Stopped {
		t.Fatalf("EvStop left the machine in %s, want %s", s, State6Stopped)
	}
	m.Step(at(4), 0, Simple(EvStart))

	// The new run's router says DHCPv6 and advertises no prefix at all.
	_, acts := m.Step(at(5), 0, raEvent6(t, ra6(true, false)))
	d, ok := timerSet(acts, Timer6AutoFallback)
	if !ok {
		t.Fatalf("no fallback deadline was armed in the second run.%s", journalLines(acts))
	}
	s, acts := m.Step(at(5).Add(d), 0, TimerFired(Timer6AutoFallback))
	if _, ok := find(acts, ActStartDAD); ok {
		t.Fatalf("the second run formed an address from a prefix the first run was told about.%s", journalLines(acts))
	}
	f, failed := find(acts, ActFailed)
	if !failed || f.Reason != ReasonNoPrefix {
		t.Fatalf("the fallback ended with %v, want a %s verdict.%s", f.Reason, ReasonNoPrefix, journalLines(acts))
	}
	if s != State6Discovering {
		t.Errorf("the verdict left the machine in %s, want %s", s, State6Discovering)
	}
}

// TestTheDeferredUnionsSlotsBelongToPrefixesThatCanFormAnAddress is defeat row
// R-62.
//
// The union is bounded, and what it is bounded BY is the number of addresses
// this client can hold. RFC 4862 §5.5.3 a is "If the Autonomous flag is not
// set, silently ignore the Prefix Information option", so an option with A=0
// can never become an address and must never take a slot from one that can. A
// router advertising a page of on-link-only prefixes is ordinary.
func TestTheDeferredUnionsSlotsBelongToPrefixesThatCanFormAnAddress(t *testing.T) {
	opts := [][]byte{}
	for i := 0; i < MaxSLAACAddresses; i++ {
		opts = append(opts, pio(fmt.Sprintf("fd00:%d::", i+1), 64, false, 86400, 14400))
	}
	opts = append(opts, pio(testSLAACPrefix, 64, true, 86400, 14400))

	m := newMachine6(t, testParams6Auto())
	m.Step(at(0), 0, Simple(EvStart))
	_, acts := m.Step(at(1), 0, raEvent6(t, ra6(true, false, opts...)))
	d, ok := timerSet(acts, Timer6AutoFallback)
	if !ok {
		t.Fatalf("no fallback deadline was armed.%s", journalLines(acts))
	}
	m.Step(at(2), 0, TimerFired(Timer6Delay))

	s, acts := m.Step(at(1).Add(d), 0, TimerFired(Timer6AutoFallback))
	if f, failed := find(acts, ActFailed); failed {
		t.Fatalf("a page of A=0 prefixes crowded out the one that forms: %s %q.%s", f.Reason, f.Note, journalLines(acts))
	}
	if s != State6DAD {
		t.Fatalf("the fallback left the machine in %s, want %s.%s", s, State6DAD, journalLines(acts))
	}
	dad, ok := find(acts, ActStartDAD)
	if !ok {
		t.Fatalf("the fallback formed no address.%s", journalLines(acts))
	}
	if want := netip.MustParseAddr(testSLAACAddr); dad.Target != want {
		t.Errorf("the fallback formed %s, want %s", dad.Target, want)
	}
}
