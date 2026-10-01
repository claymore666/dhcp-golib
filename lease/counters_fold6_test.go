// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package lease

import (
	"net/netip"
	"testing"

	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

// The DHCPv6 counters the feature lanes of v1.2.0 kept in ring 1, read at this
// ring (claymore666/docker-net-dhcp#926, #927, #214, #1027). Each drive ends
// at a barrier the machine's own Step passed, so the mirror these read was
// taken inside it, and the evidence is what the fake server decoded and the
// events the manager emitted.

const test6Temp = "fd00:99::1a5"

// foldTwoManagers6 is foldTwoManagers for a v6 rig.
func foldTwoManagers6(t *testing.T, s Stats) WireCounters { return foldTwoManagers(t, s) }

// extra6 is answerNormally6 whose Advertise and Reply each carry the options
// the function returns for their kind.
func extra6(t *testing.T, adv, rep func() []wire.OptionV6) server6Behaviour {
	t.Helper()
	base := answerNormally6(t)
	return func(req *wire.MessageV6, n int) []*wire.MessageV6 {
		out := base(req, n)
		for _, m := range out {
			switch m.Type {
			case wire.MsgAdvertise:
				if adv != nil {
					m.Options = append(m.Options, adv()...)
				}
			case wire.MsgReply:
				if rep != nil {
					m.Options = append(m.Options, rep()...)
				}
			}
		}
		return out
	}
}

// iaTA6 is an IA_TA with the fixture's IAID that carries the addresses.
func iaTA6(t *testing.T, addrs ...string) wire.OptionV6 {
	t.Helper()
	ia := &wire.IATA{IAID: test6IAID}
	for _, a := range addrs {
		v, err := wire.EncodeIAAddr(&wire.IAAddr{Addr: netip.MustParseAddr(a), PreferredLifetime: 300, ValidLifetime: 300})
		if err != nil {
			t.Fatalf("EncodeIAAddr: %v", err)
		}
		ia.Options = append(ia.Options, optV6(wire.OptV6IAAddr, v))
	}
	b, err := wire.EncodeIATA(ia)
	if err != nil {
		t.Fatalf("EncodeIATA: %v", err)
	}
	return optV6(wire.OptV6IATA, b)
}

// emptyIAPD6 is an IA_PD with our IAID that gives no prefix.
func emptyIAPD6(t *testing.T) wire.OptionV6 {
	t.Helper()
	b, err := wire.EncodeIAPD(&wire.IAPD{IAID: test6IAID, T1: 120, T2: 200})
	if err != nil {
		t.Fatalf("EncodeIAPD: %v", err)
	}
	return optV6(wire.OptV6IAPD, b)
}

func one6(o wire.OptionV6) func() []wire.OptionV6 {
	return func() []wire.OptionV6 { return []wire.OptionV6{o} }
}

// waitReceived6 blocks until the machine has stepped the n-th message that
// arrived, which is the barrier for a drive that ends in no event.
func waitReceived6(t *testing.T, r *rig6, n int) {
	t.Helper()
	seen := 0
	r.journal.waitAppended(t, "the Step on a received message", func(e proto.JournalEntry6) bool {
		if e.Kind == proto.EvReceived {
			seen++
		}
		return seen >= n
	})
}

func solicits6(r *rig6) (n int) {
	for _, m := range r.server.sentMessages() {
		if m.Type == wire.MsgSolicit {
			n++
		}
	}
	return n
}

func requests6(r *rig6) (n int) {
	for _, m := range r.server.sentMessages() {
		if m.Type == wire.MsgRequest6 {
			n++
		}
	}
	return n
}

func rapidParams6() proto.Params6 {
	p := testParams6()
	p.RapidCommit = true
	return p
}

// rapidReply6 answers a Solicit with a Reply that carries option 14 as given
// and no Request ever follows, so every Step the counters ride on is on the
// Solicit's answer.
func rapidReply6(t *testing.T, opt14 []byte) server6Behaviour {
	t.Helper()
	return func(req *wire.MessageV6, _ int) []*wire.MessageV6 {
		if req.Type != wire.MsgSolicit {
			return nil
		}
		rep := replyFor(t, req)
		rep.Options = append(rep.Options, optV6(wire.OptV6RapidCommit, opt14))
		return []*wire.MessageV6{rep}
	}
}

// TestADhcpv6RapidCommitReplyReachesStatsAsAccepted: the lease is taken from
// the Reply to the Solicit and no Request leaves the host (RFC 9915 section
// 18.2.1). The v4 accessor of the pair stays at zero on this manager.
func TestADhcpv6RapidCommitReplyReachesStatsAsAccepted(t *testing.T) {
	r := newRig6(t, rapidParams6(), rapidReply6(t, nil))
	if ev := r.acquire6(t); ev.Kind != Acquired {
		t.Fatalf("the first event is %s, want acquired", ev)
	}
	if got := requests6(r); got != 0 {
		t.Fatalf("the server saw %d Request(s) after a rapid commit Reply", got)
	}
	st := r.mgr.Stats()
	if st.RapidCommitsAccepted != 1 || st.RapidCommitsRefused != 0 {
		t.Errorf("Stats reports %d accepted and %d refused, want 1 and 0", st.RapidCommitsAccepted, st.RapidCommitsRefused)
	}
	if c := r.mgr.RapidCommit6Counters(); c.Accepted != 1 || c.Refused != 0 {
		t.Errorf("RapidCommit6Counters is %+v, want 1 accepted", c)
	}
	if c := r.mgr.RapidCommitCounters(); c != (proto.RapidCommitCounters{}) {
		t.Errorf("a v6 manager's RapidCommitCounters is %+v, want the zero value", c)
	}
	if w := foldTwoManagers6(t, st); w.RapidCommitsAccepted != 2 || w.RapidCommitsRefused != 0 {
		t.Errorf("two managers folded to %d accepted %d refused, want 2 0", w.RapidCommitsAccepted, w.RapidCommitsRefused)
	}
}

// TestAMalformedDhcpv6RapidCommitReplyReachesStatsAsRefused: a Reply whose
// option 14 has a value is turned down and starts no lease, which produces no
// action, so only a derivation after the Step sees it.
func TestAMalformedDhcpv6RapidCommitReplyReachesStatsAsRefused(t *testing.T) {
	r := newRig6(t, rapidParams6(), rapidReply6(t, []byte{1}))
	waitReceived6(t, r, 1)
	r.settle(t)
	select {
	case ev := <-r.mgr.Events():
		t.Fatalf("a refused rapid commit Reply gave an event: %s", ev)
	default:
	}
	if got := requests6(r); got != 0 || solicits6(r) != 1 {
		t.Fatalf("the server saw %d Request(s) and %d Solicit(s), want 0 and 1", got, solicits6(r))
	}
	st := r.mgr.Stats()
	if st.RapidCommitsRefused != 1 || st.RapidCommitsAccepted != 0 {
		t.Errorf("Stats reports %d refused and %d accepted, want 1 and 0", st.RapidCommitsRefused, st.RapidCommitsAccepted)
	}
	if c := r.mgr.RapidCommit6Counters(); c.Refused != 1 || c.Accepted != 0 {
		t.Errorf("RapidCommit6Counters is %+v, want 1 refused", c)
	}
	if w := foldTwoManagers6(t, st); w.RapidCommitsRefused != 2 {
		t.Errorf("two managers folded to %d refused, want 2", w.RapidCommitsRefused)
	}
}

func tempParams6() proto.Params6 {
	p := testParams6()
	p.Temporary = true
	return p
}

func requireTemp(t *testing.T, r *rig6, want proto.Temporary6Counters) {
	t.Helper()
	st := r.mgr.Stats()
	got := proto.Temporary6Counters{Granted: st.TemporaryAddressesGranted, Refused: st.TemporaryAddressesRefused,
		Absent: st.TemporaryAddressesAbsent, Conflicted: st.TemporaryAddressesConflicted}
	if got != want {
		t.Errorf("Stats reports %+v, want %+v", got, want)
	}
	if c := r.mgr.TemporaryCounters(); c != want {
		t.Errorf("TemporaryCounters is %+v, want %+v", c, want)
	}
	if c := r.mgr.PrefixCounters(); c != (proto.Prefix6Counters{}) {
		t.Errorf("a client that asked for no prefix reports PrefixCounters %+v", c)
	}
}

// TestAReplyWithNoIATAReachesStatsAsAbsent: a client that asked for temporary
// addresses and was answered with none counts the Advertise and the Reply,
// and its stable lease stands (RFC 9915 section 18.2.10.1).
func TestAReplyWithNoIATAReachesStatsAsAbsent(t *testing.T) {
	r := newRig6(t, tempParams6(), answerNormally6(t))
	ev := r.acquire6(t)
	if len(ev.Lease.TempAddrs) != 0 || len(ev.Lease.Addrs) != 1 {
		t.Fatalf("the lease holds %v and %v, want the stable address alone", ev.Lease.Addrs, ev.Lease.TempAddrs)
	}
	requireTemp(t, r, proto.Temporary6Counters{Absent: 2})
	if w := foldTwoManagers6(t, r.mgr.Stats()); w.TemporaryAddressesAbsent != 4 {
		t.Errorf("two managers folded to %d absent, want 4", w.TemporaryAddressesAbsent)
	}
}

// TestAnIATAWithNoAddressReachesStatsAsRefused: the IA_TA is there and gives
// nothing, which is a different answer from no IA_TA.
func TestAnIATAWithNoAddressReachesStatsAsRefused(t *testing.T) {
	r := newRig6(t, tempParams6(), extra6(t, one6(iaTA6(t)), one6(iaTA6(t))))
	ev := r.acquire6(t)
	if len(ev.Lease.TempAddrs) != 0 {
		t.Fatalf("the lease holds temporary addresses %v from an empty IA_TA", ev.Lease.TempAddrs)
	}
	requireTemp(t, r, proto.Temporary6Counters{Refused: 2})
	if w := foldTwoManagers6(t, r.mgr.Stats()); w.TemporaryAddressesRefused != 4 {
		t.Errorf("two managers folded to %d refused, want 4", w.TemporaryAddressesRefused)
	}
}

// TestAnIATAWithAnAddressReachesStatsAsGranted: the Reply's IA_TA gives an
// address, it is probed, and the lease the caller is told of holds it.
func TestAnIATAWithAnAddressReachesStatsAsGranted(t *testing.T) {
	r := newRig6(t, tempParams6(), extra6(t, one6(iaTA6(t, test6Temp)), one6(iaTA6(t, test6Temp))), withDAD(&fakeDAD{}))
	ev := r.nextEvent(t)
	if ev.Kind != Acquired || len(ev.Lease.TempAddrs) != 1 || ev.Lease.TempAddrs[0].Addr.Addr() != netip.MustParseAddr(test6Temp) {
		t.Fatalf("the first event is %s with temporary addresses %v, want acquired holding %s", ev, ev.Lease.TempAddrs, test6Temp)
	}
	requireTemp(t, r, proto.Temporary6Counters{Granted: 1})
	if w := foldTwoManagers6(t, r.mgr.Stats()); w.TemporaryAddressesGranted != 2 {
		t.Errorf("two managers folded to %d granted, want 2", w.TemporaryAddressesGranted)
	}
}

// dupOne is a DADRunner that reports one address as a duplicate and every
// other as free, each from its own goroutine as the port requires.
type dupOne struct{ dup netip.Addr }

func (d dupOne) Start(addr netip.Addr, report func(netip.Addr, bool)) {
	go report(addr, addr == d.dup)
}

// TestADuplicateTemporaryAddressReachesStatsAsConflicted: the probe finds the
// temporary address in use, the client declines it alone, and the server's
// record shows a Decline that names that address (RFC 9915 section 18.2.8).
func TestADuplicateTemporaryAddressReachesStatsAsConflicted(t *testing.T) {
	r := newRig6(t, tempParams6(), extra6(t, one6(iaTA6(t, test6Temp)), one6(iaTA6(t, test6Temp))),
		withDAD(dupOne{dup: netip.MustParseAddr(test6Temp)}))
	r.waitSent(t, wire.MsgDecline6)
	var dec *wire.MessageV6
	for _, m := range r.server.sentMessages() {
		if m.Type == wire.MsgDecline6 {
			dec = m
		}
	}
	if dec == nil {
		t.Fatal("no Decline reached the server")
	}
	if got := r.mgr.Stats().TemporaryAddressesConflicted; got != 1 {
		t.Errorf("Stats reports %d conflicted after the Decline left, want 1", got)
	}
	if got := r.mgr.TemporaryCounters().Conflicted; got != 1 {
		t.Errorf("TemporaryCounters reports %d conflicted, want 1", got)
	}
	if w := foldTwoManagers6(t, r.mgr.Stats()); w.TemporaryAddressesConflicted != 2 {
		t.Errorf("two managers folded to %d conflicted, want 2", w.TemporaryAddressesConflicted)
	}
}

func prefixParams6() proto.Params6 {
	p := testParams6()
	p.PrefixHint = 64
	return p
}

func requirePrefix(t *testing.T, r *rig6, want proto.Prefix6Counters) {
	t.Helper()
	st := r.mgr.Stats()
	got := proto.Prefix6Counters{Granted: st.PrefixesGranted, Refused: st.PrefixesRefused, Absent: st.PrefixesAbsent, Changed: st.PrefixesChanged}
	if got != want {
		t.Errorf("Stats reports %+v, want %+v", got, want)
	}
	if c := r.mgr.PrefixCounters(); c != want {
		t.Errorf("PrefixCounters is %+v, want %+v", c, want)
	}
	if c := r.mgr.TemporaryCounters(); c != (proto.Temporary6Counters{}) {
		t.Errorf("a client that asked for no temporary addresses reports TemporaryCounters %+v", c)
	}
}

// TestADelegatedPrefixReachesStatsAsGranted: the Reply to the Request gives a
// prefix and the lease the caller is told of holds it. Only the Reply grants;
// the Advertise before it counts nothing.
func TestADelegatedPrefixReachesStatsAsGranted(t *testing.T) {
	pd := one6(pfxIAPD(t, pfxFirst, 700, 900))
	r := newRig6(t, prefixParams6(), extra6(t, pd, pd))
	ev := r.acquire6(t)
	if len(ev.Lease.Prefixes) != 1 || ev.Lease.Prefixes[0].Addr != netip.MustParsePrefix(pfxFirst) {
		t.Fatalf("the lease holds prefixes %v, want %s", ev.Lease.Prefixes, pfxFirst)
	}
	requirePrefix(t, r, proto.Prefix6Counters{Granted: 1})
	if w := foldTwoManagers6(t, r.mgr.Stats()); w.PrefixesGranted != 2 {
		t.Errorf("two managers folded to %d granted, want 2", w.PrefixesGranted)
	}
}

// TestAnAnswerWithNoIAPDReachesStatsAsAbsent: a client that asked for a prefix
// and was answered with none counts the Advertise and the Reply, and its
// address lease stands.
func TestAnAnswerWithNoIAPDReachesStatsAsAbsent(t *testing.T) {
	r := newRig6(t, prefixParams6(), answerNormally6(t))
	ev := r.acquire6(t)
	if len(ev.Lease.Prefixes) != 0 {
		t.Fatalf("the lease holds prefixes %v although the server gave none", ev.Lease.Prefixes)
	}
	requirePrefix(t, r, proto.Prefix6Counters{Absent: 2})
	if w := foldTwoManagers6(t, r.mgr.Stats()); w.PrefixesAbsent != 4 {
		t.Errorf("two managers folded to %d absent, want 4", w.PrefixesAbsent)
	}
}

// TestAnIAPDWithNoPrefixReachesStatsAsRefused: the IA_PD is there and gives
// nothing, which is a different answer from no IA_PD.
func TestAnIAPDWithNoPrefixReachesStatsAsRefused(t *testing.T) {
	r := newRig6(t, prefixParams6(), extra6(t, one6(emptyIAPD6(t)), one6(emptyIAPD6(t))))
	ev := r.acquire6(t)
	if len(ev.Lease.Prefixes) != 0 {
		t.Fatalf("the lease holds prefixes %v from an empty IA_PD", ev.Lease.Prefixes)
	}
	requirePrefix(t, r, proto.Prefix6Counters{Refused: 2})
	if w := foldTwoManagers6(t, r.mgr.Stats()); w.PrefixesRefused != 4 {
		t.Errorf("two managers folded to %d refused, want 4", w.PrefixesRefused)
	}
}

// TestARenewalThatChangesThePrefixReachesStatsAsChanged: the Reply to the
// Renew names another prefix than the one held, and the event the caller gets
// carries the new one.
func TestARenewalThatChangesThePrefixReachesStatsAsChanged(t *testing.T) {
	const second = "2001:db8:1:200::/64"
	base := answerNormally6(t)
	b := func(req *wire.MessageV6, n int) []*wire.MessageV6 {
		out := base(req, n)
		for _, m := range out {
			if m.Type != wire.MsgAdvertise && m.Type != wire.MsgReply {
				continue
			}
			p := pfxFirst
			if req.Type == wire.MsgRenew {
				p = second
			}
			m.Options = append(m.Options, pfxIAPD(t, p, 700, 900))
		}
		return out
	}
	r := newRig6(t, prefixParams6(), b)
	r.acquire6(t)
	requirePrefix(t, r, proto.Prefix6Counters{Granted: 1})

	renewAt, ok := r.timers.armedAt(proto.Timer6Renew)
	if !ok {
		t.Fatal("no renewal timer is armed on a held v6 lease")
	}
	r.clock.advance(renewAt)
	r.timers.fire(proto.Timer6Renew)
	ev := r.nextEvent(t)
	if ev.Kind != Renewed || len(ev.Lease.Prefixes) != 1 || ev.Lease.Prefixes[0].Addr != netip.MustParsePrefix(second) {
		t.Fatalf("the event after T1 is %s with prefixes %v, want renewed holding %s", ev, ev.Lease.Prefixes, second)
	}
	requirePrefix(t, r, proto.Prefix6Counters{Granted: 1, Changed: 1})
	if w := foldTwoManagers6(t, r.mgr.Stats()); w.PrefixesChanged != 2 || w.PrefixesGranted != 2 {
		t.Errorf("two managers folded to changed %d granted %d, want 2 2", w.PrefixesChanged, w.PrefixesGranted)
	}
}

// TestAV6ManagerReportsNoV4Counters is the preservation half for the v4 types:
// a v6 manager that ran an exchange reports their zero values.
func TestAV6ManagerReportsNoV4Counters(t *testing.T) {
	r := newRig6(t, testParams6(), answerNormally6(t))
	r.acquire6(t)
	st := r.mgr.Stats()
	if st.IPv6OnlyWaited+st.IPv6OnlyIgnored+st.IPv6OnlyMalformed+st.ForcerenewsRenewed+st.ForcerenewsAlreadyRenewing+
		st.ForcerenewsAckRefused+st.ForcerenewsRefused != 0 {
		t.Errorf("a v6 manager reports v4 counters: %+v", st)
	}
	if c := r.mgr.IPv6OnlyCounters(); c != (proto.IPv6OnlyCounters{}) {
		t.Errorf("IPv6OnlyCounters is %+v on a v6 manager", c)
	}
	if c := r.mgr.ForcerenewCounters(); c != (proto.ForcerenewCounters{}) {
		t.Errorf("ForcerenewCounters is %+v on a v6 manager", c)
	}
	if c := r.mgr.RapidCommitCounters(); c != (proto.RapidCommitCounters{}) {
		t.Errorf("RapidCommitCounters is %+v on a v6 manager", c)
	}
}

// The tests above read their counters after the exchange has finished, and a
// later Step would hide a mirror taken one Step late. These read at the barrier
// of the Step that raised the count, before anything else can run: the
// journal entry that carries the duplicate-address request is appended after
// the mirror and nothing is posted until the test does
// (claymore666/docker-net-dhcp#926, #927, #1027).

// TestADhcpv6RapidCommitCountIsCurrentAtTheStepThatRaisedIt: the Reply Step
// asks for the address probe, and Stats and the accessor already say accepted.
func TestADhcpv6RapidCommitCountIsCurrentAtTheStepThatRaisedIt(t *testing.T) {
	r := newRig6(t, rapidParams6(), rapidReply6(t, nil))
	r.waitDADRequested(t, test6Addr)
	if got := r.mgr.Stats().RapidCommitsAccepted; got != 1 {
		t.Errorf("Stats reports %d accepted at the Step that took the Reply, want 1", got)
	}
	if got := r.mgr.RapidCommit6Counters().Accepted; got != 1 {
		t.Errorf("RapidCommit6Counters reports %d accepted at that Step, want 1", got)
	}
}

// TestARefusedDhcpv6RapidCommitCountIsCurrentAtTheStepThatRaisedIt: nothing
// follows a refused Reply, so the read is the one the barrier allows before
// the marker timer is dispatched.
func TestARefusedDhcpv6RapidCommitCountIsCurrentAtTheStepThatRaisedIt(t *testing.T) {
	r := newRig6(t, rapidParams6(), rapidReply6(t, []byte{1}))
	waitReceived6(t, r, 1)
	if got := r.mgr.Stats().RapidCommitsRefused; got != 1 {
		t.Errorf("Stats reports %d refused at the Step that took the Reply, want 1", got)
	}
	if got := r.mgr.RapidCommit6Counters().Refused; got != 1 {
		t.Errorf("RapidCommit6Counters reports %d refused at that Step, want 1", got)
	}
}

// TestATemporaryAddressCountIsCurrentAtTheStepThatRaisedIt: the Reply Step is
// the one that asks for the probe, and the count it raised is already read.
func TestATemporaryAddressCountIsCurrentAtTheStepThatRaisedIt(t *testing.T) {
	granted := one6(iaTA6(t, test6Temp))
	empty := one6(iaTA6(t))
	for _, c := range []struct {
		name string
		beh  server6Behaviour
		want proto.Temporary6Counters
	}{
		{"absent", answerNormally6(t), proto.Temporary6Counters{Absent: 2}},
		{"refused", extra6(t, empty, empty), proto.Temporary6Counters{Refused: 2}},
		{"granted", extra6(t, granted, granted), proto.Temporary6Counters{Granted: 1}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig6(t, tempParams6(), c.beh)
			r.waitDADRequested(t, test6Addr)
			st := r.mgr.Stats()
			got := proto.Temporary6Counters{Granted: st.TemporaryAddressesGranted, Refused: st.TemporaryAddressesRefused,
				Absent: st.TemporaryAddressesAbsent, Conflicted: st.TemporaryAddressesConflicted}
			if got != c.want {
				t.Errorf("Stats reports %+v at the Step that took the Reply, want %+v", got, c.want)
			}
			if acc := r.mgr.TemporaryCounters(); acc != c.want {
				t.Errorf("TemporaryCounters reports %+v at that Step, want %+v", acc, c.want)
			}
		})
	}
}
