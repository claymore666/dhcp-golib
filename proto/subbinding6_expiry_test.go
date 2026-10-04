// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"net/netip"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

const sub6Second = "fd00:99::1b7"

// sub6Bound takes a fresh machine to BOUND6 on a server that offers and grants iana and extra, and returns it with the actions of the bind at at(4).
func sub6Bound(t *testing.T, p Params6, iana wire.OptionV6, extra ...wire.OptionV6) (*Machine6, []Action) {
	t.Helper()
	opts := append([]wire.OptionV6{optClientID(capDUID), optServerID(testServerDUID), iana}, extra...)
	adv := append(append([]wire.OptionV6(nil), opts...), optPreference(255))
	m, sol := solicit6(t, p)
	_, acts := m.Step(at(2), capXIDRequest, receivedV6(t, wire.MsgAdvertise, sol.XID, adv...))
	req := mustSendV6(t, acts, wire.MsgRequest6)
	_, acts = m.Step(at(3), 0, receivedV6(t, wire.MsgReply, req.XID, opts...))
	var bind []Action
	for _, a := range pd6Targets(acts) {
		_, bind = m.Step(at(4), 0, DADResult(a, false))
	}
	if m.State() != State6Bound {
		t.Fatalf("the exchange left the machine in %s, want %s", m.State(), State6Bound)
	}
	return m, bind
}

// sub6Expiry is the instant the actions armed Timer6Expire for, counted from from.
func sub6Expiry(t *testing.T, from Instant, acts []Action) Instant {
	t.Helper()
	d, ok := timerSet(acts, Timer6Expire)
	if !ok {
		t.Fatalf("Timer6Expire was not armed.%s", journalLines(acts))
	}
	return from.Add(d)
}

func sub6IANA(t *testing.T, addrs ...iaAddrSpec) wire.OptionV6 {
	t.Helper()
	return optIANA(t, capIAID, 150, 240, addrs)
}

// sub6Left fires Timer6Expire at when and checks the lease stays held, one Changed carries it, and the expiry is armed again for next.
func sub6Left(t *testing.T, m *Machine6, when, next Instant) Lease6 {
	t.Helper()
	s, acts := m.Step(when, 0, TimerFired(Timer6Expire))
	if _, ok := find(acts, ActLeaseLost); ok {
		t.Fatalf("the lease was lost at %s.%s", when, journalLines(acts))
	}
	if n := count(acts, ActLeaseChanged); n != 1 {
		t.Fatalf("%d Changed actions at %s, want 1.%s", n, when, journalLines(acts))
	}
	if s != State6Bound {
		t.Errorf("the fire left the machine in %s, want %s", s, State6Bound)
	}
	if got := sub6Expiry(t, when, acts); got != next {
		t.Errorf("Timer6Expire armed again for %s, want %s", got, next)
	}
	ia := -1
	for i, a := range acts {
		if a.Kind == ActSetTimer && a.Timer == Timer6Expire {
			ia = i
		}
	}
	if ch, _ := indexOf(acts, ActLeaseChanged); ia > ch {
		t.Errorf("the Changed came before the expiry was armed again: %v", acts)
	}
	l, held := m.Lease()
	if !held {
		t.Fatal("the machine holds no lease")
	}
	if ch, _ := find(acts, ActLeaseChanged); !ch.Lease6.Equal(l) {
		t.Errorf("the Changed carries %+v, the machine holds %+v", ch.Lease6, l)
	}
	return l
}

func sub6Ends(l Lease6, d uint32) Instant { return l.Start.Add(Duration(d) * Second) }

func TestAPrefixWhoseValidLifetimeEndsWhileBoundLeavesTheLeaseAtThatInstant(t *testing.T) {
	m, bind := sub6Bound(t, pd6Params(64), sub6IANA(t, iaAddrSpec{pd6Addr, 300, 300}),
		optIAPD(t, capIAID, 120, 200, []pd6Spec{{pd6First, 100, 200}}))
	l0, _ := m.Lease()
	if got, want := sub6Expiry(t, at(4), bind), sub6Ends(l0, 200); got != want {
		t.Fatalf("Timer6Expire armed for %s, want the prefix's end %s", got, want)
	}
	l := sub6Left(t, m, sub6Ends(l0, 200), sub6Ends(l0, 300))
	if len(l.Prefixes) != 0 || len(l.Addrs) != 1 {
		t.Errorf("the lease holds prefixes %v and addresses %v, want none and one", l.Prefixes, l.Addrs)
	}
	pd6Counters(t, m, Prefix6Counters{Granted: 1, Changed: 1})
}

func TestATemporaryAddressWhoseValidLifetimeEndsWhileBoundLeavesTheLeaseAtThatInstant(t *testing.T) {
	m, bind := sub6Bound(t, ta6Params(true), sub6IANA(t, iaAddrSpec{ta6Stable, 300, 300}),
		optIATA(t, capIAID, []iaAddrSpec{{ta6Temp, 50, 100}}))
	l0, _ := m.Lease()
	if got, want := sub6Expiry(t, at(4), bind), sub6Ends(l0, 100); got != want {
		t.Fatalf("Timer6Expire armed for %s, want the temporary address's end %s", got, want)
	}
	l := sub6Left(t, m, sub6Ends(l0, 100), sub6Ends(l0, 300))
	if len(l.TempAddrs) != 0 || len(l.Addrs) != 1 {
		t.Errorf("the lease holds temporary %v and addresses %v, want none and one", l.TempAddrs, l.Addrs)
	}
	pd6Counters(t, m, Prefix6Counters{})
}

func TestAnAddressOfSeveralWhoseValidLifetimeEndsWhileBoundLeavesTheLeaseAtThatInstant(t *testing.T) {
	m, bind := sub6Bound(t, testParams6(), sub6IANA(t, iaAddrSpec{pd6Addr, 300, 300}, iaAddrSpec{sub6Second, 100, 150}))
	l0, _ := m.Lease()
	if got, want := sub6Expiry(t, at(4), bind), sub6Ends(l0, 150); got != want {
		t.Fatalf("Timer6Expire armed for %s, want the second address's end %s", got, want)
	}
	l := sub6Left(t, m, sub6Ends(l0, 150), sub6Ends(l0, 300))
	if len(l.Addrs) != 1 || l.Addrs[0].Addr != addr6(pd6Addr) {
		t.Errorf("the lease holds %v, want %s alone", l.Addrs, pd6Addr)
	}
}

func TestBindingsEndingAtOneInstantLeaveInOneChanged(t *testing.T) {
	p := pd6Params(64)
	p.Temporary = true
	m, _ := sub6Bound(t, p, sub6IANA(t, iaAddrSpec{pd6Addr, 300, 300}, iaAddrSpec{sub6Second, 100, 200}),
		optIATA(t, capIAID, []iaAddrSpec{{ta6Temp, 100, 200}}),
		optIAPD(t, capIAID, 120, 200, []pd6Spec{{pd6First, 100, 200}}))
	l0, _ := m.Lease()
	l := sub6Left(t, m, sub6Ends(l0, 200), sub6Ends(l0, 300))
	if len(l.Addrs) != 1 || len(l.TempAddrs) != 0 || len(l.Prefixes) != 0 {
		t.Errorf("the lease holds %v, %v and %v, want one address alone", l.Addrs, l.TempAddrs, l.Prefixes)
	}
}

func TestABindingEndedBeforeTheBindLeavesTheLeaseAtOnce(t *testing.T) {
	m, bind := sub6Bound(t, pd6Params(64), sub6IANA(t, iaAddrSpec{pd6Addr, 300, 300}),
		optIAPD(t, capIAID, 120, 200, []pd6Spec{{pd6First, 1, 1}}))
	l0, _ := m.Lease()
	if d, _ := timerSet(bind, Timer6Expire); d != 0 || sub6Ends(l0, 1).After(at(4)) {
		t.Fatalf("Timer6Expire armed for %s at the bind, the prefix ending at %s, want 0", d, sub6Ends(l0, 1))
	}
	if a, ok := find(bind, ActLeaseAcquired); !ok || len(a.Lease6.Prefixes) != 1 {
		t.Fatalf("the bind did not announce the prefix it holds: %v", bind)
	}
	l := sub6Left(t, m, sub6Expiry(t, at(4), bind), sub6Ends(l0, 300))
	if len(l.Prefixes) != 0 {
		t.Errorf("the lease still holds %v", l.Prefixes)
	}
}

func TestTheLastAddressEndingAfterAnEarlierOneEndsTheLeaseWithItsPrefix(t *testing.T) {
	m, _ := sub6Bound(t, pd6Params(64), sub6IANA(t, iaAddrSpec{pd6Addr, 300, 300}, iaAddrSpec{sub6Second, 100, 150}),
		optIAPD(t, capIAID, 120, 200, []pd6Spec{{pd6First, 300, 600}}))
	l0, _ := m.Lease()
	sub6Left(t, m, sub6Ends(l0, 150), sub6Ends(l0, 300))
	s, acts := m.Step(sub6Ends(l0, 300), 0, TimerFired(Timer6Expire))
	lost, ok := find(acts, ActLeaseLost)
	if !ok || lost.Reason != ReasonExpired {
		t.Fatalf("the last address ended without the lease expiring.%s", journalLines(acts))
	}
	if len(lost.Lease6.Prefixes) != 1 || len(lost.Lease6.Addrs) != 1 {
		t.Errorf("the lost lease is %+v, want the last address and the prefix", lost.Lease6)
	}
	if count(acts, ActLeaseChanged) != 0 {
		t.Errorf("the expiry also announced a Changed: %v", acts)
	}
	if _, held := m.Lease(); held || s == State6Bound {
		t.Errorf("the machine still holds a lease in %s", s)
	}
}

func TestAnExpiryFireBeforeAnyEndKeepsTheLeaseAndArmsAgain(t *testing.T) {
	m, _ := sub6Bound(t, pd6Params(64), sub6IANA(t, iaAddrSpec{pd6Addr, 300, 300}),
		optIAPD(t, capIAID, 120, 200, []pd6Spec{{pd6First, 100, 200}}))
	l0, _ := m.Lease()
	early := sub6Ends(l0, 199)
	s, acts := m.Step(early, 0, TimerFired(Timer6Expire))
	if _, ok := find(acts, ActLeaseLost); ok || s != State6Bound {
		t.Fatalf("an early fire ended the lease, now %s.%s", s, journalLines(acts))
	}
	if n := count(acts, ActLeaseChanged); n != 0 {
		t.Errorf("an early fire announced %d Changed", n)
	}
	if got, want := sub6Expiry(t, early, acts), sub6Ends(l0, 200); got != want {
		t.Errorf("Timer6Expire armed again for %s, want %s", got, want)
	}
	if l, _ := m.Lease(); !l.Equal(l0) {
		t.Errorf("an early fire changed the lease to %+v", l)
	}
	pd6Counters(t, m, Prefix6Counters{Granted: 1})
}

func TestAPrefixEndingDuringTheRenewStillTakesTheReplysPrefix(t *testing.T) {
	m, _ := sub6Bound(t, pd6Params(64), sub6IANA(t, iaAddrSpec{pd6Addr, 300, 300}),
		optIAPD(t, capIAID, 120, 200, []pd6Spec{{pd6First, 100, 200}}))
	l0, _ := m.Lease()
	_, acts := m.Step(sub6Ends(l0, 120), 7, TimerFired(Timer6Renew))
	ren := mustSendV6(t, acts, wire.MsgRenew)
	if ren.Options.Count(wire.OptV6IAPD) != 1 {
		t.Fatalf("the Renew carries no IA_PD")
	}
	_, acts = m.Step(sub6Ends(l0, 200), 0, TimerFired(Timer6Expire))
	if _, ok := find(acts, ActLeaseLost); ok {
		t.Fatalf("the prefix's end lost the lease during the Renew.%s", journalLines(acts))
	}
	if l, _ := m.Lease(); len(l.Prefixes) != 0 {
		t.Fatalf("the prefix outlived its valid lifetime: %v", l.Prefixes)
	}
	_, acts = m.Step(sub6Ends(l0, 201), 0, receivedV6(t, wire.MsgReply, ren.XID,
		optClientID(capDUID), optServerID(testServerDUID), sub6IANA(t, iaAddrSpec{pd6Addr, 300, 300}),
		optIAPD(t, capIAID, 120, 200, []pd6Spec{{pd6First, 300, 600}})))
	l, held := m.Lease()
	if !held || len(l.Prefixes) != 1 || l.Prefixes[0].Prefix != netip.MustParsePrefix(pd6First) {
		t.Errorf("the Reply's prefix was not taken: %+v.%s", l.Prefixes, journalLines(acts))
	}
}

func TestARenewAfterThePrefixEndedIgnoresAnUnaskedIAPD(t *testing.T) {
	m, _ := sub6Bound(t, pd6Params(64), sub6IANA(t, iaAddrSpec{pd6Addr, 300, 300}),
		optIAPD(t, capIAID, 150, 240, []pd6Spec{{pd6First, 50, 100}}))
	l0, _ := m.Lease()
	sub6Left(t, m, sub6Ends(l0, 100), sub6Ends(l0, 300))
	_, acts := m.Step(sub6Ends(l0, 150), 7, TimerFired(Timer6Renew))
	ren := mustSendV6(t, acts, wire.MsgRenew)
	if n := ren.Options.Count(wire.OptV6IAPD); n != 0 {
		t.Fatalf("the Renew after the prefix ended carries %d IA_PD", n)
	}
	_, acts = m.Step(sub6Ends(l0, 151), 0, receivedV6(t, wire.MsgReply, ren.XID,
		optClientID(capDUID), optServerID(testServerDUID), sub6IANA(t, iaAddrSpec{pd6Addr, 300, 300}),
		optIAPD(t, capIAID, 150, 240, []pd6Spec{{pd6First, 300, 600}})))
	if l, held := m.Lease(); !held || len(l.Prefixes) != 0 {
		t.Errorf("the Reply's IA_PD the Renew did not ask for was taken: %+v.%s", l.Prefixes, journalLines(acts))
	}
}

func TestARenewRetransmittedWithoutTheEndedPrefixStillTakesTheReplysPrefix(t *testing.T) {
	m, _ := sub6Bound(t, pd6Params(64), sub6IANA(t, iaAddrSpec{pd6Addr, 300, 300}),
		optIAPD(t, capIAID, 120, 200, []pd6Spec{{pd6First, 100, 200}}))
	l0, _ := m.Lease()
	_, acts := m.Step(sub6Ends(l0, 120), 7, TimerFired(Timer6Renew))
	ren := mustSendV6(t, acts, wire.MsgRenew)
	if ren.Options.Count(wire.OptV6IAPD) != 1 {
		t.Fatalf("the first Renew carries no IA_PD")
	}
	_, acts = m.Step(sub6Ends(l0, 200), 0, TimerFired(Timer6Expire))
	if l, held := m.Lease(); !held || count(acts, ActLeaseChanged) != 1 || len(l.Prefixes) != 0 {
		t.Fatalf("the prefix's end during the Renew: held %v, %d Changed, prefixes %v, want held, 1 and none.%s",
			held, count(acts, ActLeaseChanged), l.Prefixes, journalLines(acts))
	}
	_, acts = m.Step(sub6Ends(l0, 201), 3, TimerFired(Timer6Retransmit))
	again := mustSendV6(t, acts, wire.MsgRenew)
	if again.XID != ren.XID || again.Options.Count(wire.OptV6IAPD) != 0 {
		t.Fatalf("the retransmitted Renew has XID %#x and %d IA_PD, want %#x and none",
			again.XID, again.Options.Count(wire.OptV6IAPD), ren.XID)
	}
	_, acts = m.Step(sub6Ends(l0, 202), 0, receivedV6(t, wire.MsgReply, ren.XID,
		optClientID(capDUID), optServerID(testServerDUID), sub6IANA(t, iaAddrSpec{pd6Addr, 300, 300}),
		optIAPD(t, capIAID, 120, 200, []pd6Spec{{pd6First, 300, 600}})))
	l, held := m.Lease()
	if !held || len(l.Prefixes) != 1 || l.Prefixes[0].Prefix != netip.MustParsePrefix(pd6First) {
		t.Errorf("the Reply's prefix was not taken after a retransmit without it: %+v.%s", l.Prefixes, journalLines(acts))
	}
}

func TestASLAACLeaseGetsNoExpiryTimerFromAStaleFire(t *testing.T) {
	m := newMachine6(t, testParams6SLAAC())
	m.Step(at(0), 0, Simple(EvStart))
	m.Step(at(1), 0, raEvent6(t, ra6(false, false, pio(testSLAACPrefix, 64, true, 86400, 14400))))
	m.Step(at(2), 0, DADResult(netip.MustParseAddr(testSLAACAddr), false))
	if l, held := m.Lease(); !held || !l.SLAAC {
		t.Fatalf("no SLAAC lease formed: %+v", l)
	}
	_, acts := m.Step(at(3), 0, TimerFired(Timer6Expire))
	if d, ok := timerSet(acts, Timer6Expire); ok {
		t.Errorf("a stale fire armed Timer6Expire for %s on a lease Timer6SLAAC owns", d)
	}
	if count(acts, ActLeaseChanged) != 0 {
		t.Errorf("a stale fire announced a Changed on a SLAAC lease: %v", acts)
	}
}

func TestADropLeavesTheBindsAnnouncementAsItWas(t *testing.T) {
	p := pd6Params(64)
	p.Temporary = true
	m, bind := sub6Bound(t, p, sub6IANA(t, iaAddrSpec{sub6Second, 100, 150}, iaAddrSpec{pd6Addr, 300, 300}),
		optIATA(t, capIAID, []iaAddrSpec{{ta6Temp, 100, 150}, {ta6Temp2, 300, 300}}),
		optIAPD(t, capIAID, 120, 200, []pd6Spec{{pd6First, 100, 150}, {pd6Other, 300, 300}}))
	acq, _ := find(bind, ActLeaseAcquired)
	before := acq.Lease6
	want := Lease6{Start: before.Start,
		Addrs:     append([]Addr6(nil), before.Addrs...),
		TempAddrs: append([]Addr6(nil), before.TempAddrs...),
		Prefixes:  append([]Prefix6(nil), before.Prefixes...)}
	l0, _ := m.Lease()
	l := sub6Left(t, m, sub6Ends(l0, 150), sub6Ends(l0, 300))
	if len(l.Addrs) != 1 || len(l.TempAddrs) != 1 || len(l.Prefixes) != 1 {
		t.Fatalf("the lease is %+v, want one of each left", l)
	}
	for i := range want.Addrs {
		if before.Addrs[i] != want.Addrs[i] || before.TempAddrs[i] != want.TempAddrs[i] || before.Prefixes[i] != want.Prefixes[i] {
			t.Errorf("the drop rewrote the bind's announcement at %d: %+v", i, before)
		}
	}
}

func TestAPrefixEndingUnderAnAddressWithNoEndLeavesTheLease(t *testing.T) {
	m, bind := sub6Bound(t, pd6Params(64), sub6IANA(t, iaAddrSpec{pd6Addr, InfiniteSeconds, InfiniteSeconds}),
		optIAPD(t, capIAID, 120, 200, []pd6Spec{{pd6First, 100, 200}}))
	l0, _ := m.Lease()
	when := sub6Expiry(t, at(4), bind)
	if when != sub6Ends(l0, 200) {
		t.Fatalf("Timer6Expire armed for %s, want the prefix's end %s", when, sub6Ends(l0, 200))
	}
	s, acts := m.Step(when, 0, TimerFired(Timer6Expire))
	if _, ok := find(acts, ActLeaseLost); ok || s != State6Bound || count(acts, ActLeaseChanged) != 1 {
		t.Fatalf("the prefix's end left %s.%s", s, journalLines(acts))
	}
	if _, ok := timerSet(acts, Timer6Expire); ok || !timerCancelled(acts, Timer6Expire) {
		t.Errorf("a lease with nothing left to end kept an expiry timer: %v", acts)
	}
	if l, _ := m.Lease(); len(l.Addrs) != 1 || len(l.Prefixes) != 0 {
		t.Errorf("the lease holds %v and %v, want the address alone", l.Addrs, l.Prefixes)
	}
}
