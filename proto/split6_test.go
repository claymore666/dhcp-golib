// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// Two servers on one link, after claymore666/dhcp-golib#70: A (pr6Server)
// delegated the prefix, B (testServerDUID) delegates none and answers the
// resumed Rebind first with the IA_NA alone.

func split6Params() Params6 {
	p := pr6Params()
	p.Resume.T1, p.Resume.T2 = 10*Second, 16*Second
	p.Resume.Prefixes[0].Preferred, p.Resume.Prefixes[0].Valid = 40*Second, 60*Second
	return p
}

func split6Reply(t *testing.T, xid uint32, server []byte, opts ...wire.OptionV6) Event {
	t.Helper()
	return receivedV6(t, wire.MsgReply, xid,
		append([]wire.OptionV6{optClientID(capDUID), optServerID(server)}, opts...)...)
}

func split6NA(t *testing.T) wire.OptionV6 {
	t.Helper()
	return optIANA(t, capIAID, 54, 99, []iaAddrSpec{{pr6Addr, 120, 120}})
}

func split6PD(t *testing.T, t1, t2 uint32) wire.OptionV6 {
	t.Helper()
	return optIAPD(t, capIAID, t1, t2, []pd6Spec{{pr6First, 200, 300}})
}

// split6Bound runs the resumed Rebind (EvStart at 0, Rebind at 1) to B's
// IA_NA-only Reply at 2 and the clean DAD at 3.
func split6Bound(t *testing.T) (*Machine6, []Action) {
	t.Helper()
	return split6BoundWith(t, split6Params())
}

func split6BoundWith(t *testing.T, p Params6) (*Machine6, []Action) {
	t.Helper()
	m, reb, _ := pr6Rebinding(t, p)
	m.Step(at(2), 3, split6Reply(t, reb.XID, testServerDUID, split6NA(t)))
	s, acts := m.Step(at(3), 0, DADResult(netip.MustParseAddr(pr6Addr), false))
	if s != State6Bound {
		t.Fatalf("the clean DAD result left the machine in %s, want %s", s, State6Bound)
	}
	return m, acts
}

// split6IAs is the server, IA_NA count and IA_PD count of a sent message.
func split6IAs(t *testing.T, msg *wire.MessageV6) ([]byte, int, int) {
	t.Helper()
	sid, _ := pd6OnTheWire(t, msg).Options.First(wire.OptV6ServerID)
	nas, pds := pd6IAs(t, msg)
	return sid, len(nas), len(pds)
}

func TestAnIANAOnlyReplyLeavesThePrefixRenewalAtTheDelegatingServersT1(t *testing.T) {
	m, acts := split6Bound(t)
	if d, ok := timerSet(acts, Timer6Renew); !ok || d != 7*Second {
		t.Fatalf("Renew armed for %v (set %v), want 7 s: A's T1 at 10 s, not B's 54 s (RFC 8415 section 18.2.10.1)", d, ok)
	}
	l, _ := m.Lease()
	if d := l.Deadlines(); !d.HasRenew || d.Renew != at(10) {
		t.Errorf("Deadlines().Renew = %v, want at(10)", d.Renew)
	}
}

func TestTheRenewAtThePrefixT1GoesToTheDelegatingServerWithTheIAPDAlone(t *testing.T) {
	m, _ := split6Bound(t)
	_, acts := m.Step(at(10), 7, TimerFired(Timer6Renew))
	sid, nas, pds := split6IAs(t, mustSendV6(t, acts, wire.MsgRenew))
	if !bytes.Equal(sid, pr6Server) || nas != 0 || pds != 1 {
		t.Errorf("the Renew names server %x with %d IA_NA and %d IA_PD, want A with the IA_PD alone (RFC 8415 section 18.2.4)", sid, nas, pds)
	}
}

func TestAPrefixOnlyRenewReplyKeepsTheIANA(t *testing.T) {
	m, _ := split6Bound(t)
	_, acts := m.Step(at(10), 7, TimerFired(Timer6Renew))
	ren := mustSendV6(t, acts, wire.MsgRenew)
	s, acts := m.Step(at(11), 0, split6Reply(t, ren.XID, pr6Server, split6PD(t, 100, 160)))
	if s != State6Bound {
		t.Fatalf("A's Reply left the machine in %s, want %s", s, State6Bound)
	}
	l, _ := m.Lease()
	if len(l.Addrs) != 1 || l.Addrs[0].Addr != netip.MustParseAddr(pr6Addr) || !bytes.Equal(l.ServerDUID, testServerDUID) {
		t.Errorf("the lease is %v from %x, want B's address kept", l.Addrs, l.ServerDUID)
	}
	if len(l.Prefixes) != 1 || l.Start.Add(l.Prefixes[0].Valid) != at(310) {
		t.Errorf("the prefixes are %v from %v, want A's 300 s counted from the Renew at 10", l.Prefixes, l.Start)
	}
	if d, ok := timerSet(acts, Timer6Renew); !ok || d != 44*Second {
		t.Errorf("Renew armed for %v (set %v), want 44 s: B's T1 at 55", d, ok)
	}
	_, acts = m.Step(at(55), 7, TimerFired(Timer6Renew))
	sid, nas, pds := split6IAs(t, mustSendV6(t, acts, wire.MsgRenew))
	if !bytes.Equal(sid, testServerDUID) || nas != 1 || pds != 0 {
		t.Errorf("the Renew at B's T1 names server %x with %d IA_NA and %d IA_PD, want B with the IA_NA alone", sid, nas, pds)
	}
}

func TestASplitLeaseReportsTheServerThatDelegatedThePrefix(t *testing.T) {
	m, acts := split6Bound(t)
	a, ok := find(acts, ActLeaseAcquired)
	if !ok || !bytes.Equal(a.Lease6.ServerDUID, testServerDUID) || !bytes.Equal(a.Lease6.PrefixServerDUID, pr6Server) {
		t.Fatalf("Acquired names %x and prefix server %x, want B and A", a.Lease6.ServerDUID, a.Lease6.PrefixServerDUID)
	}
	_, acts = m.Step(at(10), 7, TimerFired(Timer6Renew))
	ren := mustSendV6(t, acts, wire.MsgRenew)
	_, acts = m.Step(at(11), 0, split6Reply(t, ren.XID, testServerDUID, split6PD(t, 100, 160)))
	if count(acts, ActLeaseChanged) != 1 {
		t.Errorf("%d Changed when the prefix moved from A to B, want 1", count(acts, ActLeaseChanged))
	}
	if l, _ := m.Lease(); len(l.PrefixServerDUID) != 0 {
		t.Errorf("PrefixServerDUID = %x once both IAs name B, want empty", l.PrefixServerDUID)
	}
}

func TestASplitLeaseReleasesEachIAWithItsOwnServer(t *testing.T) {
	for _, answered := range []bool{true, false} {
		m, _ := split6Bound(t)
		_, acts := m.Step(at(5), 0, Simple(EvRelease))
		sid, nas, pds := split6IAs(t, mustSendV6(t, acts, wire.MsgRelease6))
		if !bytes.Equal(sid, testServerDUID) || nas != 1 || pds != 0 {
			t.Errorf("answered=%v: the first Release names %x with %d IA_NA, %d IA_PD, want B with the IA_NA alone", answered, sid, nas, pds)
		}
		rel := mustSendV6(t, acts, wire.MsgRelease6)
		if answered {
			_, acts = m.Step(at(6), 0, split6Reply(t, rel.XID, testServerDUID))
		} else {
			for i := int64(6); i < 60 && !hasSendV6(acts, wire.MsgRelease6) || i == 6; i++ {
				_, acts = m.Step(at(i), 1, TimerFired(Timer6Retransmit))
				if r, ok := find(acts, ActSendV6); ok && r.MsgV6.XID != rel.XID {
					break
				}
				acts = nil
			}
		}
		snd, ok := find(acts, ActSendV6)
		if !ok || snd.MsgV6.Type != wire.MsgRelease6 {
			t.Fatalf("answered=%v: no second Release: %v", answered, acts)
		}
		sid, nas, pds = split6IAs(t, snd.MsgV6)
		if !bytes.Equal(sid, pr6Server) || nas != 0 || pds != 1 {
			t.Errorf("answered=%v: the second Release names %x with %d IA_NA, %d IA_PD, want A with the IA_PD alone (RFC 8415 section 18.2.7)", answered, sid, nas, pds)
		}
		if answered {
			if _, acts = m.Step(at(7), 0, split6Reply(t, snd.MsgV6.XID, pr6Server)); hasSendV6(acts, wire.MsgRelease6) {
				t.Errorf("a third Release after A answered the second: %v", acts)
			}
		}
	}
}

func TestTheDelegatingReplyFirstEndsTheRebindAndALaterReplyIsDiscarded(t *testing.T) {
	m, reb, _ := pr6Rebinding(t, split6Params())
	m.Step(at(2), 3, split6Reply(t, reb.XID, pr6Server, split6NA(t), split6PD(t, 20, 32)))
	m.Step(at(3), 0, DADResult(netip.MustParseAddr(pr6Addr), false))
	before, _ := m.Lease()
	_, acts := m.Step(at(4), 0, split6Reply(t, reb.XID, testServerDUID, split6NA(t)))
	after, _ := m.Lease()
	if !after.Equal(before) || !bytes.Equal(after.ServerDUID, pr6Server) || count(acts, ActLeaseChanged) != 0 {
		t.Errorf("B's late Reply changed the lease from %v to %v", before, after)
	}
	if d := after.Deadlines(); d.Renew != at(21) {
		t.Errorf("Renew at %v, want at(21): the earlier T1 of A's one Reply", d.Renew)
	}
}

func TestAResumedSplitRecordRenewsThePrefixWithTheServerThatDelegatedIt(t *testing.T) {
	for _, silent := range []bool{false, true} {
		p := split6Params()
		p.Resume.ServerDUID, p.Resume.PrefixServerDUID = append([]byte(nil), testServerDUID...), append([]byte(nil), pr6Server...)
		p.Resume.T1, p.Resume.T2 = 50*Second, 80*Second
		m, reb, _ := pr6Rebinding(t, p)
		now := int64(2)
		if silent {
			var acts []Action
			for ; now < 40 && count(acts, ActStartDAD) == 0; now++ {
				_, acts = m.Step(at(now), 1, TimerFired(Timer6Retransmit))
			}
			_, acts = m.Step(at(now), 0, DADResult(netip.MustParseAddr(pr6Addr), false))
			reb = mustSendV6(t, acts, wire.MsgRebind)
			now++
		}
		m.Step(at(now), 3, split6Reply(t, reb.XID, testServerDUID, split6NA(t)))
		if !silent {
			m.Step(at(now), 0, DADResult(netip.MustParseAddr(pr6Addr), false))
		}
		_, acts := m.Step(at(now+1), 7, TimerFired(Timer6Renew))
		sid, nas, pds := split6IAs(t, mustSendV6(t, acts, wire.MsgRenew))
		if !bytes.Equal(sid, pr6Server) || nas != 0 || pds != 1 {
			t.Errorf("silent=%v: the Renew names %x with %d IA_NA and %d IA_PD, want A, the record's PrefixServerDUID, with the IA_PD alone", silent, sid, nas, pds)
		}
	}
}

// joint6Bound is one server, A, granting the IA_NA (T1 150) and the IA_PD (T1
// 120, T2 200, the prefix 300/600) in one Reply sent at 2.
func joint6Bound(t *testing.T) *Machine6 {
	t.Helper()
	return keepBound(t, optIAPD(t, capIAID, 120, 200, []pd6Spec{{pd6First, 300, 600}}))
}

func TestARenewReplyThatLeavesOutADueIAPDIsRateLimited(t *testing.T) {
	m := joint6Bound(t)
	_, acts := pd6Renew(t, m, 122, 123)
	first, ok := timerSet(acts, Timer6Renew)
	if !ok || first < 9*Second || first > 11*Second {
		t.Fatalf("Renew armed for %v (set %v) after a Reply that left out the due IA_PD, want one retransmission time, 9 to 11 s (RFC 8415 section 18.2.10.1)", first, ok)
	}
	now, d, sends := int64(123), first, 1
	var gaps []Duration
	for sends <= 20 {
		now += int64((d + Second - 1) / Second)
		if now >= 123+120 {
			break
		}
		_, acts = pd6Renew(t, m, now, now)
		sends++
		prev, ok := d, false
		if d, ok = timerSet(acts, Timer6Renew); !ok {
			// the IA_PD's T2 has passed: the Rebind is next, held off as well
			if reb, rok := timerSet(acts, Timer6Rebind); !rok || reb < prev*19/10 {
				t.Errorf("Rebind armed for %v (set %v) after a %v hold-off, want it held off longer", reb, rok, prev)
			}
			break
		}
		gaps = append(gaps, d)
	}
	if sends > 4 {
		t.Errorf("%d Renews in the 120 s after the first partial Reply (hold-offs %v), want at most 4: 10, 20, 40, 80 s", sends, gaps)
	}
	if len(gaps) > 0 && gaps[0] < first*19/10 {
		t.Errorf("the second hold-off is %v after %v, want it to grow as section 15's RT does", gaps[0], first)
	}
}

func TestAReplyThatNamesTheIAPDAgainClearsTheHoldOff(t *testing.T) {
	m := joint6Bound(t)
	pd6Renew(t, m, 122, 123)
	_, acts := pd6Renew(t, m, 133, 134, optIAPD(t, capIAID, 120, 200, []pd6Spec{{pd6First, 300, 600}}))
	if d, ok := timerSet(acts, Timer6Renew); !ok || d != 119*Second {
		t.Fatalf("Renew armed for %v (set %v), want 119 s: the earlier T1 of a Reply that named both IAs", d, ok)
	}
	_, acts = pd6Renew(t, m, 253, 254)
	if d, ok := timerSet(acts, Timer6Renew); !ok || d < 9*Second || d > 11*Second {
		t.Errorf("Renew armed for %v (set %v) after the next partial Reply, want one retransmission time again, 9 to 11 s", d, ok)
	}
}

func TestAJointLeaseKeepsOneRenewAndOneReleaseWithBothIAs(t *testing.T) {
	m := joint6Bound(t)
	l, _ := m.Lease()
	if d := l.Deadlines(); d.Renew != at(122) || d.Rebind != at(202) || l.T1 != 120*Second || len(l.PrefixServerDUID) != 0 {
		t.Fatalf("Renew %v Rebind %v T1 %v prefix server %x, want at(122), at(202), the merged 120 s, none", d.Renew, d.Rebind, l.T1, l.PrefixServerDUID)
	}
	_, acts := m.Step(at(122), 7, TimerFired(Timer6Renew))
	if sid, nas, pds := split6IAs(t, mustSendV6(t, acts, wire.MsgRenew)); !bytes.Equal(sid, testServerDUID) || nas != 1 || pds != 1 {
		t.Errorf("the Renew names %x with %d IA_NA and %d IA_PD, want A with both", sid, nas, pds)
	}
	m = joint6Bound(t)
	_, acts = m.Step(at(5), 0, Simple(EvRelease))
	rel := mustSendV6(t, acts, wire.MsgRelease6)
	if sid, nas, pds := split6IAs(t, rel); !bytes.Equal(sid, testServerDUID) || nas != 1 || pds != 1 {
		t.Errorf("the Release names %x with %d IA_NA and %d IA_PD, want A with both", sid, nas, pds)
	}
	if _, acts = m.Step(at(6), 0, split6Reply(t, rel.XID, testServerDUID)); hasSendV6(acts, wire.MsgRelease6) {
		t.Errorf("a second Release followed the Reply to a joint lease's Release")
	}
}

// split6PDOnly is split6Bound plus A's IA_PD-only Reply at 11 to the Renew at
// 10, the prefix T1 t1 and T2 t2 counted from 10.
func split6PDOnly(t *testing.T, t1, t2 uint32) *Machine6 {
	t.Helper()
	return split6PDOnlyWith(t, split6Params(), t1, t2)
}

func split6PDOnlyWith(t *testing.T, p Params6, t1, t2 uint32) *Machine6 {
	t.Helper()
	m, _ := split6BoundWith(t, p)
	_, acts := m.Step(at(10), 7, TimerFired(Timer6Renew))
	ren := mustSendV6(t, acts, wire.MsgRenew)
	m.Step(at(11), 0, split6Reply(t, ren.XID, pr6Server, split6PD(t, t1, t2)))
	return m
}

// split6RenewNA is B's Reply at reply to the IA_NA-only Renew that fires at
// renew, with T1 200 and T2 300.
func split6RenewNA(t *testing.T, m *Machine6, renew, reply int64) []Action {
	t.Helper()
	_, acts := m.Step(at(renew), 7, TimerFired(Timer6Renew))
	sid, nas, pds := split6IAs(t, mustSendV6(t, acts, wire.MsgRenew))
	if !bytes.Equal(sid, testServerDUID) || nas != 1 || pds != 0 {
		t.Fatalf("the Renew at %d names %x with %d IA_NA and %d IA_PD, want B with the IA_NA alone", renew, sid, nas, pds)
	}
	ren := mustSendV6(t, acts, wire.MsgRenew)
	_, acts = m.Step(at(reply), 0, split6Reply(t, ren.XID, testServerDUID,
		optIANA(t, capIAID, 200, 300, []iaAddrSpec{{pr6Addr, 400, 400}})))
	return acts
}

func TestBsReplyToTheIANARenewKeepsThePrefixAtItsOwnT1(t *testing.T) {
	m := split6PDOnly(t, 100, 160)
	acts := split6RenewNA(t, m, 55, 56)
	l, _ := m.Lease()
	if len(l.Prefixes) != 1 || l.Start.Add(l.Prefixes[0].Valid) != at(310) || !bytes.Equal(l.PrefixServerDUID, pr6Server) {
		t.Fatalf("the prefixes are %v from %v with server %x, want A's, valid to 310", l.Prefixes, l.Start, l.PrefixServerDUID)
	}
	if d, ok := timerSet(acts, Timer6Renew); !ok || d != 54*Second {
		t.Errorf("Renew armed for %v (set %v), want 54 s: A's T1 100 counted from its Renew at 10, not from B's Reply (RFC 8415 section 18.2.10.1)", d, ok)
	}
	_, acts = m.Step(at(110), 7, TimerFired(Timer6Renew))
	if sid, nas, pds := split6IAs(t, mustSendV6(t, acts, wire.MsgRenew)); !bytes.Equal(sid, pr6Server) || nas != 0 || pds != 1 {
		t.Errorf("the Renew at 110 names %x with %d IA_NA and %d IA_PD, want A with the IA_PD alone", sid, nas, pds)
	}
}

// Both T1s fall at 55: B's Renew goes first, and its Reply, which could not
// name the IA_PD, sends the overdue prefix Renew to A at once.
func TestAnIANAReplyThatCouldNotNameTheIAPDHoldsNothingOff(t *testing.T) {
	m := split6PDOnly(t, 45, 160)
	acts := split6RenewNA(t, m, 55, 56)
	if d, ok := timerSet(acts, Timer6Renew); !ok || d > Second {
		t.Fatalf("Renew armed for %v (set %v), want now: A's T1 at 55 has passed and its Renew never went out", d, ok)
	}
	_, acts = m.Step(at(56), 7, TimerFired(Timer6Renew))
	if sid, nas, pds := split6IAs(t, mustSendV6(t, acts, wire.MsgRenew)); !bytes.Equal(sid, pr6Server) || nas != 0 || pds != 1 {
		t.Errorf("the Renew at 56 names %x with %d IA_NA and %d IA_PD, want A with the IA_PD alone", sid, nas, pds)
	}
}

func TestTheRebindAfterAnUnansweredPrefixRenewCarriesBothIAs(t *testing.T) {
	m, _ := split6Bound(t)
	m.Step(at(10), 7, TimerFired(Timer6Renew))
	l, _ := m.Lease()
	d := l.Deadlines()
	_, acts := m.Step(d.Rebind, 7, TimerFired(Timer6Rebind))
	sid, nas, pds := split6IAs(t, mustSendV6(t, acts, wire.MsgRebind))
	if len(sid) != 0 || nas != 1 || pds != 1 {
		t.Errorf("the Rebind names %x with %d IA_NA and %d IA_PD, want no server with both (RFC 8415 section 18.2.5)", sid, nas, pds)
	}
}

func TestARebindReplyThatLeavesOutADueIAPDIsRateLimited(t *testing.T) {
	m := joint6Bound(t)
	l, _ := m.Lease()
	d := l.Deadlines()
	m.Step(d.Renew, 7, TimerFired(Timer6Renew))
	_, acts := m.Step(d.Rebind, 7, TimerFired(Timer6Rebind))
	reb := mustSendV6(t, acts, wire.MsgRebind)
	now := d.Rebind.Add(Second)
	_, acts = m.Step(now, 0, pd6Reply(t, reb.XID))
	rt, ok := timerSet(acts, Timer6Rebind)
	if !ok || rt < 9*Second {
		t.Errorf("rebind6 armed for %v (set %v) after a Rebind Reply that left out the due IA_PD, want one retransmission time (RFC 8415 section 18.2.10.1)", rt, ok)
	}
	if ren, ok := timerSet(acts, Timer6Renew); ok && ren <= rt {
		t.Errorf("renew6 armed for %v beside rebind6 for %v: the IA_PD's T2 has passed, so the Rebind alone goes out (RFC 8415 section 18.2.5)", ren, rt)
	}
}

func TestAPrefixOnlyReplyIgnoresAnIATA(t *testing.T) {
	m, _ := split6Bound(t)
	_, acts := m.Step(at(10), 7, TimerFired(Timer6Renew))
	ren := mustSendV6(t, acts, wire.MsgRenew)
	_, acts = m.Step(at(11), 0, split6Reply(t, ren.XID, pr6Server, split6PD(t, 100, 160),
		optIATA(t, capIAID, []iaAddrSpec{{"fd00:99::77", 200, 1000}})))
	if l, _ := m.Lease(); len(l.TempAddrs) != 0 || !pr6Note(acts, "IA_TA option(s) in a message that answers none we sent") {
		t.Errorf("temporary addresses %v after a Reply to a Renew that sent no IA_TA, want none and the ignore noted (claymore666/docker-net-dhcp#927)", l.TempAddrs)
	}
}

func TestAResumeStartedLateCountsThePrefixTimesFromItsRebind(t *testing.T) {
	m := newMachine6(t, split6Params())
	m.Step(at(100), 0, Simple(EvStart))
	_, acts := m.Step(at(101), capXIDSolicit, TimerFired(Timer6Delay))
	reb := mustSendV6(t, acts, wire.MsgRebind)
	m.Step(at(102), 3, split6Reply(t, reb.XID, testServerDUID, split6NA(t)))
	_, acts = m.Step(at(103), 0, DADResult(netip.MustParseAddr(pr6Addr), false))
	if d, ok := timerSet(acts, Timer6Renew); !ok || d < 5*Second {
		t.Errorf("Renew armed for %v (set %v), want A's T1 10 counted from the Rebind at 101, not from 0", d, ok)
	}
}

// The record's T1 10 s holds for the prefix after B's IA_NA-only Reply, not
// the client's own half of the preferred lifetime (RFC 8415 section 18.2.12).
func TestAResumedSplitRecordKeepsItsT1ForThePrefix(t *testing.T) {
	p := split6Params()
	p.Resume.ServerDUID, p.Resume.PrefixServerDUID = append([]byte(nil), testServerDUID...), append([]byte(nil), pr6Server...)
	m, _, _ := pr6Rebinding(t, p)
	var acts []Action
	now := int64(2)
	for ; now < 40 && count(acts, ActStartDAD) == 0; now++ {
		_, acts = m.Step(at(now), 1, TimerFired(Timer6Retransmit))
	}
	_, acts = m.Step(at(now), 0, DADResult(netip.MustParseAddr(pr6Addr), false))
	reb := mustSendV6(t, acts, wire.MsgRebind)
	_, acts = m.Step(at(now+1), 3, split6Reply(t, reb.XID, testServerDUID, split6NA(t)))
	if d, ok := timerSet(acts, Timer6Renew); !ok || d != 8*Second {
		t.Errorf("Renew armed for %v (set %v), want 8 s: the record's T1 10 s from the Rebind B answered", d, ok)
	}
}

// A Start while the split Release is out abandons it; the next lease, one
// server's, is released once.
func TestARestartDuringASplitReleaseLeavesNoPrefixReleaseBehind(t *testing.T) {
	m, _ := split6Bound(t)
	m.Step(at(5), 0, Simple(EvRelease))
	m.Step(at(6), 0, Simple(EvStart))
	_, acts := m.Step(at(7), capXIDSolicit, TimerFired(Timer6Delay))
	sol := mustSendV6(t, acts, wire.MsgSolicit)
	iapd := optIAPD(t, capIAID, 120, 200, []pd6Spec{{pd6First, 300, 600}})
	_, acts = m.Step(at(8), capXIDRequest, pd6Advert(t, sol.XID, iapd))
	_, acts = m.Step(at(8), 0, pd6Reply(t, mustSendV6(t, acts, wire.MsgRequest6).XID, iapd))
	for _, a := range pd6Targets(acts) {
		m.Step(at(9), 0, DADResult(a, false))
	}
	if m.State() != State6Bound {
		t.Fatalf("the restart left the machine in %s, want %s", m.State(), State6Bound)
	}
	_, acts = m.Step(at(10), 0, Simple(EvRelease))
	rel := mustSendV6(t, acts, wire.MsgRelease6)
	if sid, nas, pds := split6IAs(t, rel); !bytes.Equal(sid, testServerDUID) || nas != 1 || pds != 1 {
		t.Fatalf("the Release names %x with %d IA_NA and %d IA_PD, want B with both", sid, nas, pds)
	}
	_, acts = m.Step(at(11), 0, split6Reply(t, rel.XID, testServerDUID))
	if hasSendV6(acts, wire.MsgRelease6) {
		t.Errorf("a second Release went out after the one-server lease's Release was answered: %v", acts)
	}
}

func TestAPrefixThatEndsTakesItsServerOutOfTheLease(t *testing.T) {
	m, _ := split6Bound(t)
	m.Step(at(10), 7, TimerFired(Timer6Renew))
	m.Step(at(16), 7, TimerFired(Timer6Rebind))
	_, acts := m.Step(at(61), 0, TimerFired(Timer6Expire))
	c, ok := find(acts, ActLeaseChanged)
	if !ok || len(c.Lease6.Prefixes) != 0 || len(c.Lease6.PrefixServerDUID) != 0 {
		t.Fatalf("the prefix's valid end reports %v with prefix server %x (changed %v), want neither", c.Lease6.Prefixes, c.Lease6.PrefixServerDUID, ok)
	}
	l, _ := m.Lease()
	bare := l
	bare.PrefixServerDUID, bare.pdT1, bare.pdT2, bare.pdStart, bare.pdTimed = nil, 0, 0, 0, false
	if !l.Equal(bare) {
		t.Errorf("the lease after its prefix ended still differs from one that never had a prefix: %+v", l)
	}
}

// split6Lease is B's address (T1 200, T2 400, 450/500) from 0 and A's prefix
// timed from A's Reply at 10; the prefix lifetimes count from 0.
func split6Lease(pdT1, pdT2 Duration, ps ...Prefix6) Lease6 {
	return Lease6{
		Addrs:      []Addr6{{Addr: netip.MustParseAddr(pr6Addr), Preferred: 450 * Second, Valid: 500 * Second}},
		Prefixes:   ps,
		ServerDUID: testServerDUID, PrefixServerDUID: pr6Server,
		T1: 200 * Second, T2: 400 * Second,
		pdT1: pdT1, pdT2: pdT2, pdStart: at(10), pdTimed: true,
	}
}

func split6Prefix(s string, pref, valid Duration) Prefix6 {
	return Prefix6{Prefix: netip.MustParsePrefix(s), Preferred: pref, Valid: valid}
}

func TestASplitLeaseTimesThePrefixFromItsOwnReply(t *testing.T) {
	p1 := split6Prefix(pr6First, 310*Second, 410*Second)
	longT2 := split6Lease(100*Second, 160*Second, p1)
	longT2.T2 = 600 * Second
	cases := []struct {
		name           string
		l              Lease6
		renew, rebind  Instant
		noteMentionsT2 bool
	}{
		{"the prefix T2 is the earlier Rebind", split6Lease(20*Second, 30*Second, p1), at(30), at(40), false},
		{"no T1 or T2 takes the shortest preferred lifetime from A's Reply",
			split6Lease(0, 0, split6Prefix(pr6First, 110*Second, 210*Second), split6Prefix("2001:db8:1:200::/64", 210*Second, 310*Second)), at(60), at(90), false},
		{"an infinite valid lifetime takes no clamp",
			split6Lease(50*Second, 300*Second, split6Prefix(pr6First, 210*Second, Infinite)), at(60), at(310), false},
		{"an infinite preferred lifetime gives no prefix T2",
			split6Lease(50*Second, 0, split6Prefix(pr6First, Infinite, Infinite)), at(60), at(400), false},
		{"the address group's note survives", longT2, at(110), at(170), true},
	}
	for _, c := range cases {
		d := c.l.Deadlines()
		if !d.HasRenew || d.Renew != c.renew || !d.HasRebind || d.Rebind != c.rebind || c.noteMentionsT2 != bytes.Contains([]byte(d.Note), []byte("T2 (")) {
			t.Errorf("%s: Renew %v Rebind %v note %q, want %v and %v", c.name, d.Renew, d.Rebind, d.Note, c.renew, c.rebind)
		}
	}
}

func TestEqualSeesThePrefixServerAndItsTimes(t *testing.T) {
	p1 := split6Prefix(pr6First, 310*Second, 410*Second)
	a := split6Lease(100*Second, 160*Second, p1)
	same := split6Lease(90*Second, 150*Second, p1)
	same.pdStart = at(20)
	shorter := split6Lease(50*Second, 160*Second, p1)
	joint := split6Lease(100*Second, 160*Second, p1)
	joint.PrefixServerDUID = nil
	for _, c := range []struct {
		name string
		o    Lease6
		want bool
	}{
		{"the same instants from a later Reply", same, true},
		{"an earlier prefix T1", shorter, false},
		{"the prefix from the address server", joint, false},
	} {
		if got := a.Equal(c.o); got != c.want {
			t.Errorf("%s: Equal = %v, want %v", c.name, got, c.want)
		}
	}
}

// B answers the resumed Rebind at 12, after the prefix T1 at 10 and before
// its T2 at 16: the prefix Renew goes to A at once, nothing is held off.
func TestAReplyAfterThePrefixT1ButBeforeItsT2RenewsThePrefixAtOnce(t *testing.T) {
	m, reb, _ := pr6Rebinding(t, split6Params())
	m.Step(at(12), 3, split6Reply(t, reb.XID, testServerDUID, split6NA(t)))
	_, acts := m.Step(at(12), 0, DADResult(netip.MustParseAddr(pr6Addr), false))
	if d, ok := timerSet(acts, Timer6Renew); !ok || d > Second {
		t.Fatalf("Renew armed for %v (set %v), want now: the IA_PD's Rebind is not due, so nothing is rate-limited", d, ok)
	}
	_, acts = m.Step(at(12), 7, TimerFired(Timer6Renew))
	if sid, nas, pds := split6IAs(t, mustSendV6(t, acts, wire.MsgRenew)); !bytes.Equal(sid, pr6Server) || nas != 0 || pds != 1 {
		t.Errorf("the Renew names %x with %d IA_NA and %d IA_PD, want A with the IA_PD alone", sid, nas, pds)
	}
}
