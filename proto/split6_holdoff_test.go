// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"bytes"
	"net/netip"
	"sort"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// split6Sent is one message a split6Run put on the wire.
type split6Sent struct {
	at       Instant
	typ      wire.MessageTypeV6
	sid      []byte
	nas, pds int
}

// split6Run drives m on a fake clock from now until until. B (testServerDUID)
// answers every Renew or Rebind that names it or no server, with na() when the
// message carries an IA_NA and nothing else; A is silent. It returns what was
// sent and how many times the lease was lost.
func split6Run(t *testing.T, m *Machine6, now Instant, acts []Action, until Instant, na func() wire.OptionV6) ([]split6Sent, int) {
	t.Helper()
	return split6RunWith(t, m, now, acts, until, na, nil)
}

// split6RunWith is split6Run with A (pr6Server) answering a message that names
// it with a's options when a reports true.
func split6RunWith(t *testing.T, m *Machine6, now Instant, acts []Action, until Instant, na func() wire.OptionV6,
	a func(*wire.MessageV6) ([]wire.OptionV6, bool)) ([]split6Sent, int) {
	t.Helper()
	timers := map[TimerID]Instant{}
	var sent []split6Sent
	lost := 0
	var apply func(acts []Action) []*wire.MessageV6
	apply = func(acts []Action) []*wire.MessageV6 {
		var out []*wire.MessageV6
		for _, a := range acts {
			switch a.Kind {
			case ActSetTimer:
				timers[a.Timer] = now.Add(a.After)
			case ActCancelTimer:
				delete(timers, a.Timer)
			case ActSendV6:
				out = append(out, a.MsgV6)
			case ActLeaseLost:
				lost++
			case ActStartDAD:
				_, more := m.Step(now, 0, DADResult(a.Target, false))
				out = append(out, apply(more)...)
			}
		}
		return out
	}
	pending := apply(acts)
	for steps := 0; steps < 10000; steps++ {
		for len(pending) > 0 {
			msg := pending[0]
			pending = pending[1:]
			sid, nas, pds := split6IAs(t, msg)
			sent = append(sent, split6Sent{now, msg.Type, sid, nas, pds})
			if a != nil && bytes.Equal(sid, pr6Server) {
				if opts, ok := a(msg); ok {
					_, x := m.Step(now, 0, split6Reply(t, msg.XID, pr6Server, opts...))
					pending = append(pending, apply(x)...)
				}
				continue
			}
			if msg.Type != wire.MsgRenew && msg.Type != wire.MsgRebind {
				continue
			}
			if len(sid) != 0 && !bytes.Equal(sid, testServerDUID) {
				continue
			}
			var opts []wire.OptionV6
			if nas > 0 {
				opts = append(opts, na())
			}
			_, a := m.Step(now, 0, split6Reply(t, msg.XID, testServerDUID, opts...))
			pending = append(pending, apply(a)...)
		}
		ids := make([]TimerID, 0, len(timers))
		for id := range timers {
			ids = append(ids, id)
		}
		if len(ids) == 0 {
			break
		}
		sort.Slice(ids, func(i, j int) bool {
			return timers[ids[i]] < timers[ids[j]] || timers[ids[i]] == timers[ids[j]] && ids[i] < ids[j]
		})
		next, nextAt := ids[0], timers[ids[0]]
		if nextAt > until {
			break
		}
		if nextAt > now {
			now = nextAt
		}
		delete(timers, next)
		_, a := m.Step(now, 1, TimerFired(next))
		pending = append(pending, apply(a)...)
	}
	return sent, lost
}

// split6NAGaps fails t when two messages carrying the IA_NA, or the last one
// and until, are further apart than t2.
func split6NAGaps(t *testing.T, sent []split6Sent, from, until Instant, t2 Duration) {
	t.Helper()
	prev := from
	for _, s := range sent {
		if s.nas == 0 {
			continue
		}
		if s.at.Sub(prev) > t2 {
			t.Errorf("no message carried the IA_NA from %v to %v, longer than its T2 %v", prev, s.at, t2)
		}
		prev = s.at
	}
	if until.Sub(prev) > t2 {
		t.Errorf("no message carried the IA_NA from %v to the end of the drive at %v, longer than its T2 %v", prev, until, t2)
	}
}

// One server: the IA_PD (T1 120, T2 200, valid 3000) is due, and every Reply
// names the IA_NA (T1 150, T2 240, valid 300) and leaves the IA_PD out.
func TestAServerThatNeverNamesTheIAPDStillRenewsTheIANABeforeItsT2(t *testing.T) {
	m := keepBound(t, optIAPD(t, capIAID, 120, 200, []pd6Spec{{pd6First, 2000, 3000}}))
	l, _ := m.Lease()
	d := l.Deadlines()
	acts := []Action{
		{Kind: ActSetTimer, Timer: Timer6Renew, After: d.Renew.Sub(at(4))},
		{Kind: ActSetTimer, Timer: Timer6Rebind, After: d.Rebind.Sub(at(4))},
		{Kind: ActSetTimer, Timer: Timer6Expire, After: d.Expire.Sub(at(4))},
	}
	na := func() wire.OptionV6 { return optIANA(t, capIAID, 150, 240, []iaAddrSpec{{pd6Addr, 300, 300}}) }
	sent, lost := split6Run(t, m, at(4), acts, at(2900), na)
	if lost != 0 {
		t.Errorf("the lease was lost %d time(s) while the server renewed the IA_NA on every Reply", lost)
	}
	split6NAGaps(t, sent, at(2), at(2900), 240*Second)
	if !hasSent(sent, wire.MsgRenew) {
		t.Fatalf("nothing renewed in the drive: %v", sent)
	}
}

// Two servers, scenario of claymore666/dhcp-golib#70: A delegated the prefix
// (valid 3000) and is silent; B answers every Rebind and every Renew to it with
// the IA_NA alone (T1 54, T2 99, valid 120).
func split6SilentA(t *testing.T) ([]split6Sent, int) {
	t.Helper()
	p := split6Params()
	p.Resume.Prefixes[0].Preferred, p.Resume.Prefixes[0].Valid = 2000*Second, 3000*Second
	m, reb, _ := pr6Rebinding(t, p)
	m.Step(at(20), 3, split6Reply(t, reb.XID, testServerDUID, split6NA(t)))
	_, acts := m.Step(at(20), 0, DADResult(netip.MustParseAddr(pr6Addr), false))
	return split6Run(t, m, at(20), acts, at(2000), func() wire.OptionV6 { return split6NA(t) })
}

func TestAnIANAOnlyServerKeepsTheIANAWhileTheDelegatingServerIsSilent(t *testing.T) {
	sent, lost := split6SilentA(t)
	if lost != 0 {
		t.Errorf("the lease was lost %d time(s) while B renewed the IA_NA on every Reply", lost)
	}
	split6NAGaps(t, sent, at(20), at(2000), 99*Second)
}

// A held-off IA_PD whose T2 has passed is rebound, not renewed and then at
// once abandoned for a Rebind.
func TestAHeldOffIAPDPutsOneMessageOnTheWireAtATime(t *testing.T) {
	sent, _ := split6SilentA(t)
	for i := 1; i < len(sent); i++ {
		if sent[i].at == sent[i-1].at {
			t.Errorf("%v and %v both went out at %v", sent[i-1].typ, sent[i].typ, sent[i].at)
		}
	}
	for _, s := range sent {
		if s.typ == wire.MsgRenew && bytes.Equal(s.sid, pr6Server) {
			t.Errorf("a Renew went to A at %v after A's T2 had passed", s.at)
		}
	}
}

func hasSent(sent []split6Sent, typ wire.MessageTypeV6) bool {
	for _, s := range sent {
		if s.typ == typ {
			return true
		}
	}
	return false
}

// split6NoBindingFromA is A's NoBinding for the IA_PD in its Reply at 111 to
// the IA_PD-only Renew at 110, and the Request that follows.
func split6NoBindingFromA(t *testing.T, p Params6) (*Machine6, *wire.MessageV6, []Action) {
	t.Helper()
	m := split6PDOnlyWith(t, p, 100, 160)
	split6RenewNA(t, m, 55, 56)
	_, acts := m.Step(at(110), 7, TimerFired(Timer6Renew))
	ren := mustSendV6(t, acts, wire.MsgRenew)
	nb := optIAPD(t, capIAID, 0, 0, nil, optStatus(wire.StatusNoBinding))
	_, acts = m.Step(at(111), 0, split6Reply(t, ren.XID, pr6Server, nb))
	return m, mustSendV6(t, acts, wire.MsgRequest6), acts
}

func TestANoBindingForTheIAPDRequestsTheIAPDAloneFromItsServer(t *testing.T) {
	p := split6Params()
	p.Temporary = true
	if _, req, _ := split6NoBindingFromA(t, p); req.Options.Count(wire.OptV6IATA) != 0 {
		t.Errorf("the Request for A's IA_PD carries an IA_TA: the temporary addresses are not A's (RFC 8415 section 18.2.4)")
	}
	m, req, _ := split6NoBindingFromA(t, split6Params())
	if sid, nas, pds := split6IAs(t, req); !bytes.Equal(sid, pr6Server) || nas != 0 || pds != 1 || req.Options.Count(wire.OptV6IATA) != 0 {
		t.Fatalf("the Request names %x with %d IA_NA and %d IA_PD, want A with the IA_PD alone: B holds the IA_NA (RFC 8415 section 18.2.4)", sid, nas, pds)
	}
	naNo := optIANA(t, capIAID, 0, 0, nil, optStatus(wire.StatusNoAddrsAvail))
	_, acts := m.Step(at(112), 0, split6Reply(t, req.XID, pr6Server, naNo, split6PD(t, 100, 160)))
	if hasSendV6(acts, wire.MsgSolicit) || m.State() != State6Bound {
		t.Fatalf("A's Reply to the IA_PD Request left the machine in %s (Solicit sent %v), want %s with B's IA_NA kept", m.State(), hasSendV6(acts, wire.MsgSolicit), State6Bound)
	}
	l, _ := m.Lease()
	if len(l.Addrs) != 1 || l.Addrs[0].Addr != netip.MustParseAddr(pr6Addr) || !bytes.Equal(l.ServerDUID, testServerDUID) ||
		len(l.Prefixes) != 1 || !bytes.Equal(l.PrefixServerDUID, pr6Server) || l.Start.Add(l.Prefixes[0].Valid) != at(411) {
		t.Errorf("the lease holds %v from %x and %v from %x ending %v, want B's address and A's prefix valid to 411",
			l.Addrs, l.ServerDUID, l.Prefixes, l.PrefixServerDUID, l.Start.Add(l.Prefixes[0].Valid))
	}
}

func TestAnUnansweredRequestForTheIAPDKeepsTheSplitLease(t *testing.T) {
	m, req, _ := split6NoBindingFromA(t, split6Params())
	m.refreshOwed = true
	now := at(112)
	var acts []Action
	for i := 0; i < 20 && m.State() == State6Requesting; i++ {
		_, acts = m.Step(now, 0, TimerFired(Timer6Retransmit))
		now = now.Add(30 * Second)
	}
	if m.State() != State6Bound || hasSendV6(acts, wire.MsgSolicit) || hasSendV6(acts, wire.MsgRequest6) {
		t.Fatalf("after REQ_MAX_RC the machine is in %s, want %s with the held lease (Request %x)", m.State(), State6Bound, req.XID)
	}
	if _, ok := timerSet(acts, Timer6Renew); !ok {
		t.Errorf("no Renew armed on the return to %s", State6Bound)
	}
	if _, ok := timerSet(acts, Timer6Expire); !ok || !timerCancelled(acts, Timer6Retransmit) {
		t.Errorf("on the return to %s the expiry is armed %v and the retransmission cancelled %v, want both", State6Bound, ok, timerCancelled(acts, Timer6Retransmit))
	}
	if _, ok := timerSet(acts, Timer6Delay); !ok {
		t.Errorf("the Information-request owed from before the Renew is not armed again on the return to %s", State6Bound)
	}
	_, late := m.Step(now, 0, split6Reply(t, req.XID, pr6Server, split6PD(t, 300, 480)))
	if m.State() != State6Bound || hasLeaseEvent(late) || !journalHas(late, "no exchange in flight") {
		t.Errorf("a Reply to the abandoned Request moved the machine to %s with %v", m.State(), late)
	}
	l, _ := m.Lease()
	if len(l.Addrs) != 1 || len(l.Prefixes) != 1 || !bytes.Equal(l.PrefixServerDUID, pr6Server) {
		t.Errorf("the lease holds %v and %v from %x, want B's address and A's prefix", l.Addrs, l.Prefixes, l.PrefixServerDUID)
	}
	m.reconf = map[string]*reconfServer{string(testServerDUID): {key: testReconfKey}}
	if s, rc := m.Step(now, 7, goodReconfigure(t, wire.MsgRenew, 1)); s != State6Renewing {
		t.Errorf("B's Reconfigure after the return left the machine in %s, want %s: no exchange is in flight%s", s, State6Renewing, journalLines(rc))
	}
	for _, a := range acts {
		if a.Kind == ActLeaseRenewed || a.Kind == ActLeaseChanged {
			t.Errorf("%v on a return to %s that renewed nothing", a.Kind, State6Bound)
		}
	}
}

func TestANoBindingForTheIANARequestsTheIANAAloneAndKeepsThePrefix(t *testing.T) {
	m := split6PDOnly(t, 100, 160)
	_, acts := m.Step(at(55), 7, TimerFired(Timer6Renew))
	ren := mustSendV6(t, acts, wire.MsgRenew)
	nb := optIANA(t, capIAID, 0, 0, nil, optStatus(wire.StatusNoBinding))
	_, acts = m.Step(at(56), 0, split6Reply(t, ren.XID, testServerDUID, nb))
	req := mustSendV6(t, acts, wire.MsgRequest6)
	if sid, nas, pds := split6IAs(t, req); !bytes.Equal(sid, testServerDUID) || nas != 1 || pds != 0 {
		t.Fatalf("the Request names %x with %d IA_NA and %d IA_PD, want B with the IA_NA alone: A holds the IA_PD", sid, nas, pds)
	}
	m.Step(at(57), 0, split6Reply(t, req.XID, testServerDUID, optIANA(t, capIAID, 200, 300, []iaAddrSpec{{pr6Addr, 400, 400}})))
	l, ok := m.Lease()
	if !ok || m.State() != State6Bound || len(l.Prefixes) != 1 || !bytes.Equal(l.PrefixServerDUID, pr6Server) || l.Start.Add(l.Prefixes[0].Valid) != at(310) {
		t.Errorf("state %s, the lease holds %v from %x, want %s with A's prefix valid to 310", m.State(), l.Prefixes, l.PrefixServerDUID, State6Bound)
	}
}

func TestEqualSeesAPrefixTimedByItsOwnReplyAgainstOneReplysTimes(t *testing.T) {
	p1 := split6Prefix(pr6First, 310*Second, 410*Second)
	own := split6Lease(100*Second, 160*Second, p1)
	one := split6Lease(120*Second, 200*Second, p1)
	one.pdTimed = false
	if own.Equal(one) || one.Equal(own) {
		t.Errorf("Equal holds between the prefix T1 and T2 at 110 and 170 from its own Reply and at 120 and 200 from one Reply's times")
	}
}

func hasLeaseEvent(acts []Action) bool {
	for _, a := range acts {
		if a.Kind == ActLeaseRenewed || a.Kind == ActLeaseChanged || a.Kind == ActLeaseAcquired {
			return true
		}
	}
	return false
}

func TestAnUnansweredRequestForTheIANAStillRestartsDiscovery(t *testing.T) {
	m := split6PDOnly(t, 100, 160)
	_, acts := m.Step(at(55), 7, TimerFired(Timer6Renew))
	ren := mustSendV6(t, acts, wire.MsgRenew)
	nb := optIANA(t, capIAID, 0, 0, nil, optStatus(wire.StatusNoBinding))
	m.Step(at(56), 0, split6Reply(t, ren.XID, testServerDUID, nb))
	now := at(57)
	for i := 0; i < 20 && m.State() == State6Requesting; i++ {
		m.Step(now, 0, TimerFired(Timer6Retransmit))
		now = now.Add(30 * Second)
	}
	if s := m.State(); s == State6Bound || s == State6Requesting {
		t.Errorf("after REQ_MAX_RC on the Request for the IA_NA the machine is in %s, want discovery restarted", s)
	}
}

// A's Reply at 111 leaves out the due IA_PD; B's NoBinding at 114 and the
// Request for the IA_NA alone must not lift the hold-off on A.
func TestARequestForTheIANALeavesTheIAPDHoldOffStanding(t *testing.T) {
	m := split6PDOnly(t, 100, 160)
	_, acts := m.Step(at(55), 7, TimerFired(Timer6Renew))
	ren := mustSendV6(t, acts, wire.MsgRenew)
	m.Step(at(56), 0, split6Reply(t, ren.XID, testServerDUID, optIANA(t, capIAID, 58, 300, []iaAddrSpec{{pr6Addr, 400, 400}})))
	_, acts = m.Step(at(110), 7, TimerFired(Timer6Renew))
	ren = mustSendV6(t, acts, wire.MsgRenew)
	if sid, nas, pds := split6IAs(t, ren); !bytes.Equal(sid, pr6Server) || nas != 0 || pds != 1 {
		t.Fatalf("the Renew at 110 names %x with %d IA_NA and %d IA_PD, want A with the IA_PD alone", sid, nas, pds)
	}
	_, acts = m.Step(at(111), 0, split6Reply(t, ren.XID, pr6Server))
	hold, ok := timerSet(acts, Timer6Renew)
	if !ok || hold != 2*Second {
		t.Fatalf("Renew armed for %v (set %v) after A left out the IA_PD, want B's T1 at 113", hold, ok)
	}
	_, acts = m.Step(at(113), 7, TimerFired(Timer6Renew))
	ren = mustSendV6(t, acts, wire.MsgRenew)
	nb := optIANA(t, capIAID, 0, 0, nil, optStatus(wire.StatusNoBinding))
	_, acts = m.Step(at(114), 0, split6Reply(t, ren.XID, testServerDUID, nb))
	req := mustSendV6(t, acts, wire.MsgRequest6)
	_, acts = m.Step(at(115), 0, split6Reply(t, req.XID, testServerDUID, optIANA(t, capIAID, 200, 300, []iaAddrSpec{{pr6Addr, 400, 400}})))
	if d, ok := timerSet(acts, Timer6Renew); m.State() != State6Bound || !ok || d < 5*Second {
		t.Errorf("state %s, Renew armed for %v (set %v) after B's Reply to the Request for the IA_NA, want A's hold-off to stand, not a Renew at once (RFC 8415 section 18.2.10.1)", m.State(), d, ok)
	}
}

// split6LongPrefix is a split lease: B's IA_NA from its Reply at 2, and A's
// prefix (T1 100, T2 1500, valid 3000) from its Reply at 11 to the Renew at 10.
func split6LongPrefix(t *testing.T) (*Machine6, []Action) {
	t.Helper()
	m, _ := split6Bound(t)
	_, acts := m.Step(at(10), 7, TimerFired(Timer6Renew))
	ren := mustSendV6(t, acts, wire.MsgRenew)
	_, acts = m.Step(at(11), 0, split6Reply(t, ren.XID, pr6Server, optIAPD(t, capIAID, 100, 1500, []pd6Spec{{pr6First, 2000, 3000}})))
	return m, acts
}

// A answers the IA_PD Renew at 110 with NoBinding and is silent to the Request
// that follows; B's IA_NA (T1 54, T2 99, valid 120, renewed at 109) is rebound
// at its T2 while that Request runs.
func TestARequestForTheIAPDGivesWayToTheIANAsRebind(t *testing.T) {
	m, acts := split6LongPrefix(t)
	a := func(msg *wire.MessageV6) ([]wire.OptionV6, bool) {
		if msg.Type != wire.MsgRenew {
			return nil, false
		}
		return []wire.OptionV6{optIAPD(t, capIAID, 0, 0, nil, optStatus(wire.StatusNoBinding))}, true
	}
	sent, lost := split6RunWith(t, m, at(11), acts, at(1500), func() wire.OptionV6 { return split6NA(t) }, a)
	if lost != 0 {
		t.Errorf("the lease was lost %d time(s) while B answered every message that named the IA_NA", lost)
	}
	split6NAGaps(t, sent, at(11), at(1500), 99*Second)
	if !hasSent(sent, wire.MsgRequest6) {
		t.Fatalf("no Request followed A's NoBinding: %v", sent)
	}
	l, ok := m.Lease()
	if !ok || len(l.Addrs) != 1 || len(l.Prefixes) != 1 || !bytes.Equal(l.PrefixServerDUID, pr6Server) {
		t.Errorf("at the end of the drive the machine is in %s holding %v (held %v) and %v from %x, want B's address and A's prefix", m.State(), l.Addrs, ok, l.Prefixes, l.PrefixServerDUID)
	}
}

// The lease ends while the Request for the IA_PD runs: discovery restarts,
// so no later REQ_MAX_RC returns to BOUND6 with nothing held.
func TestALeaseThatEndsDuringTheRequestForTheIAPDRestartsDiscovery(t *testing.T) {
	m, _, _ := split6NoBindingFromA(t, split6Params())
	l, _ := m.Lease()
	s, acts := m.Step(l.Deadlines().Expire, 0, TimerFired(Timer6Expire))
	if _, ok := m.Lease(); ok || s != State6Init || !timerCancelled(acts, Timer6Rebind) {
		t.Errorf("the lease ended during the Request for the IA_PD and the machine is in %s (lease held %v, Rebind cancelled %v), want discovery restarted", s, ok, timerCancelled(acts, Timer6Rebind))
	}
}

// A is silent after delegating the prefix; B answers with the IA_NA alone. A
// Rebind Reply after the prefix T1 at 111 and before its T2 at 1511 holds the
// Renew to A off, and the hold-off never outgrows the retransmission bound.
func TestARebindReplyThatLeavesOutAPrefixDueForItsRenewHoldsTheRenewOff(t *testing.T) {
	m, acts := split6LongPrefix(t)
	sent, lost := split6Run(t, m, at(11), acts, at(3000), func() wire.OptionV6 { return split6NA(t) })
	if lost != 0 {
		t.Errorf("the lease was lost %d time(s) while B answered every message that named the IA_NA", lost)
	}
	split6NAGaps(t, sent, at(11), at(3000), 99*Second)
	for i := 1; i < len(sent); i++ {
		if sent[i].at == sent[i-1].at {
			t.Errorf("%v and %v both went out at %v: a Reply that left out the due IA_PD was not rate-limited (RFC 8415 section 18.2.10.1)", sent[i-1].typ, sent[i].typ, sent[i].at)
		}
	}
	bound := m.params.RenMaxRT + m.params.RenMaxRT/10
	if m.params.RebMaxRT > m.params.RenMaxRT {
		bound = m.params.RebMaxRT + m.params.RebMaxRT/10
	}
	prev := at(11)
	for _, s := range sent {
		if s.pds == 0 {
			continue
		}
		if s.at.Sub(prev) > bound {
			t.Errorf("no message carried the IA_PD from %v to %v, longer than the retransmission bound %v", prev, s.at, bound)
		}
		prev = s.at
	}
	if at(3000).Sub(prev) > bound {
		t.Errorf("no message carried the IA_PD from %v to the end of the drive", prev)
	}
}

// One server: a Request after its NoBinding names every IA and runs through
// T2 and the lease's end as before claymore666/dhcp-golib#70.
func TestARequestAfterAOneServerNoBindingRunsThroughT2AndTheExpiry(t *testing.T) {
	m := keepBound(t, optIAPD(t, capIAID, 120, 200, []pd6Spec{{pd6First, 2000, 3000}}))
	l, _ := m.Lease()
	d := l.Deadlines()
	_, acts := m.Step(d.Renew, 7, TimerFired(Timer6Renew))
	ren := mustSendV6(t, acts, wire.MsgRenew)
	nb := optIANA(t, capIAID, 0, 0, nil, optStatus(wire.StatusNoBinding))
	_, acts = m.Step(d.Renew, 0, receivedV6(t, wire.MsgReply, ren.XID, optClientID(capDUID), optServerID(testServerDUID), nb))
	if _, nas, pds := split6IAs(t, mustSendV6(t, acts, wire.MsgRequest6)); nas != 1 || pds != 1 {
		t.Fatalf("the Request after the NoBinding names %d IA_NA and %d IA_PD, want both", nas, pds)
	}
	if s, acts := m.Step(d.Rebind, 0, TimerFired(Timer6Rebind)); s != State6Requesting || hasSendV6(acts, wire.MsgRebind) {
		t.Errorf("T2 during the one-server Request left the machine in %s (Rebind sent %v), want the Request running", s, hasSendV6(acts, wire.MsgRebind))
	}
	if s, _ := m.Step(d.Expire, 0, TimerFired(Timer6Expire)); s != State6Requesting {
		t.Errorf("the lease's end during the one-server Request left the machine in %s, want the Request running", s)
	}
}

// split6NoBindingFromB is split6LongPrefix to B's NoBinding for the IA_NA at
// its T1 and the Request for the IA_NA alone that follows; B stays silent.
func split6NoBindingFromB(t *testing.T) (*Machine6, Deadlines) {
	t.Helper()
	m, _ := split6LongPrefix(t)
	l, _ := m.Lease()
	d := l.Deadlines()
	_, acts := m.Step(d.Renew, 7, TimerFired(Timer6Renew))
	ren := mustSendV6(t, acts, wire.MsgRenew)
	nb := optIANA(t, capIAID, 0, 0, nil, optStatus(wire.StatusNoBinding))
	_, acts = m.Step(d.Renew, 0, split6Reply(t, ren.XID, testServerDUID, nb))
	if sid, nas, pds := split6IAs(t, mustSendV6(t, acts, wire.MsgRequest6)); !bytes.Equal(sid, testServerDUID) || nas != 1 || pds != 0 {
		t.Fatalf("the Request after B's NoBinding names %x with %d IA_NA and %d IA_PD, want B with the IA_NA alone", sid, nas, pds)
	}
	return m, d
}

// The Request for the IA_NA alone gives way at the lease's T2 to a Rebind
// that carries both IAs, as the Request for the IA_PD does.
func TestARequestForTheIANAGivesWayToARebindOfBothIAs(t *testing.T) {
	m, d := split6NoBindingFromB(t)
	s, acts := m.Step(d.Rebind, 0, TimerFired(Timer6Rebind))
	if s != State6Rebinding || !hasSendV6(acts, wire.MsgRebind) {
		t.Fatalf("T2 during the Request for the IA_NA left the machine in %s (Rebind sent %v), want a Rebind", s, hasSendV6(acts, wire.MsgRebind))
	}
	if sid, nas, pds := split6IAs(t, mustSendV6(t, acts, wire.MsgRebind)); len(sid) != 0 || nas != 1 || pds != 1 {
		t.Errorf("the Rebind names server %x with %d IA_NA and %d IA_PD, want no server and both IAs", sid, nas, pds)
	}
}

// The lease ends while the Request for the IA_NA alone runs: discovery
// restarts and a Solicit goes out.
func TestALeaseThatEndsDuringTheRequestForTheIANASolicits(t *testing.T) {
	m, _ := split6NoBindingFromB(t)
	l, _ := m.Lease()
	now := l.Deadlines().Expire
	s, acts := m.Step(now, 0, TimerFired(Timer6Expire))
	if _, ok := m.Lease(); ok || s != State6Init {
		t.Fatalf("the lease ended during the Request for the IA_NA and the machine is in %s (lease held %v), want discovery restarted", s, ok)
	}
	d, ok := timerSet(acts, Timer6Delay)
	if !ok {
		t.Fatalf("discovery restarted with no first Solicit armed: %v", acts)
	}
	_, acts = m.Step(now.Add(d), 0, TimerFired(Timer6Delay))
	mustSendV6(t, acts, wire.MsgSolicit)
}
