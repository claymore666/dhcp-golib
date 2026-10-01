// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package lease

import (
	"net/netip"
	"testing"

	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

// The DHCPv4 counters the feature lanes of v1.2.0 kept in ring 1, read at this
// ring: ring 1 counts and this ring mirrors, so a mirror that never ran leaves
// Stats at zero while the machine counts (claymore666/docker-net-dhcp#1027,
// #1031, #1119). The evidence in each test is what the fake server decoded and
// the events the manager emitted; the counters ride on it.

// foldTwoManagers folds one Stats snapshot as two manager instances of one
// record and returns the wire half, so a counter that was assigned and not
// added shows as the snapshot's value and not twice it.
func foldTwoManagers(t *testing.T, s Stats) WireCounters {
	t.Helper()
	rec := recordAt(t, PhaseJoined)
	for _, manager := range []string{"mgr-1", "mgr-2"} {
		snap := s
		next, err := Fold(rec, RecordEvent{
			ID: "rec-1", Seq: rec.Seq + 1, Op: OpStats,
			Instance: "plugin-1", Manager: manager, Stats: &snap,
		})
		if err != nil {
			t.Fatalf("folding the snapshot of %s: %v", manager, err)
		}
		rec = next
	}
	return rec.Counters.Wire
}

// receivedKind4 is true for a journalled Step that consumed a message of this
// type.
func receivedKind4(e proto.JournalEntry, want wire.MessageType) bool {
	if e.Kind != proto.EvReceived || len(e.Raw) == 0 {
		return false
	}
	m, err := wire.Decode(e.Raw)
	if err != nil {
		return false
	}
	mt, _ := m.Type()
	return mt == want
}

// waitReceived4 blocks until the n-th journalled Step on a message of this
// type: the journal entry is appended after the Step, and the mirror is taken
// inside the Step's lock, so the counters read afterwards are the Step's.
func waitReceived4(t *testing.T, r *rig, want wire.MessageType, n int) {
	t.Helper()
	seen := 0
	r.journal.waitAppended(t, "the Step on the "+want.String(), func(e proto.JournalEntry) bool {
		if receivedKind4(e, want) {
			seen++
		}
		return seen >= n
	})
}

// noEventQueued4 fails when the manager has an outward event waiting.
func noEventQueued4(t *testing.T, r *rig, what string) {
	t.Helper()
	select {
	case ev := <-r.mgr.Events():
		t.Fatalf("%s, but the manager emitted %s", what, ev)
	default:
	}
}

// offerWith and ackWith are answerNormally whose OFFER or ACK carries one more
// option.
func offerWith(code wire.OptionCode, v []byte) serverBehaviour {
	return func(req *wire.Message, n int) []*wire.Message {
		out := answerNormally(req, n)
		for _, m := range out {
			if mt, _ := m.Type(); mt == wire.MsgOffer {
				m.Options[code] = v
			}
		}
		return out
	}
}

func ackWith(code wire.OptionCode, v []byte) serverBehaviour {
	return func(req *wire.Message, n int) []*wire.Message {
		out := answerNormally(req, n)
		for _, m := range out {
			if mt, _ := m.Type(); mt == wire.MsgAck {
				m.Options[code] = v
			}
		}
		return out
	}
}

func v6OnlyParams() proto.Params {
	p := testParams()
	p.IPv6OnlyPreferred = true
	return p
}

func requireIPv6Only(t *testing.T, r *rig, want proto.IPv6OnlyCounters) {
	t.Helper()
	st := r.mgr.Stats()
	if st.IPv6OnlyWaited != want.Waited || st.IPv6OnlyIgnored != want.Ignored || st.IPv6OnlyMalformed != want.Malformed {
		t.Errorf("Stats reports waited %d ignored %d malformed %d, want %+v", st.IPv6OnlyWaited, st.IPv6OnlyIgnored, st.IPv6OnlyMalformed, want)
	}
	if got := r.mgr.IPv6OnlyCounters(); got != want {
		t.Errorf("IPv6OnlyCounters is %+v, want %+v", got, want)
	}
}

// TestAnOfferWithOption108ReachesStatsAsAWait: an OFFER carrying option 108
// pauses DHCPv4, and the number says so (RFC 8925 section 3.2). The server's
// record shows no REQUEST went out.
func TestAnOfferWithOption108ReachesStatsAsAWait(t *testing.T) {
	r := newRig(t, v6OnlyParams(), offerWith(wire.OptIPv6OnlyPreferred, wire.EncodeIPv6OnlyPreferred(600)), Fault{})
	ev := r.nextEvent(t)
	if ev.Kind != Failed || ev.Reason != proto.ReasonIPv6OnlyPreferred {
		t.Fatalf("the first event is %s, want failed with the IPv6-only reason", ev)
	}
	if got := frRequests(r); got != 0 {
		t.Fatalf("the server saw %d REQUEST(s) from a client paused by option 108", got)
	}
	requireIPv6Only(t, r, proto.IPv6OnlyCounters{Waited: 1})
	if w := foldTwoManagers(t, r.mgr.Stats()); w.IPv6OnlyWaited != 2 || w.IPv6OnlyIgnored != 0 || w.IPv6OnlyMalformed != 0 {
		t.Errorf("two managers folded to waited %d ignored %d malformed %d, want 2 0 0", w.IPv6OnlyWaited, w.IPv6OnlyIgnored, w.IPv6OnlyMalformed)
	}
}

// TestAnAckWithOption108ReachesStatsAsIgnored: an ACK carrying 108 keeps its
// lease (RFC 8925 section 3.2), so the client holds the address the server
// gave and the counter says the option was seen.
func TestAnAckWithOption108ReachesStatsAsIgnored(t *testing.T) {
	r := newRig(t, v6OnlyParams(), ackWith(wire.OptIPv6OnlyPreferred, wire.EncodeIPv6OnlyPreferred(600)), Fault{})
	ev := r.nextEvent(t)
	if ev.Kind != Acquired || ev.Lease.Addr.Addr() != netip.MustParseAddr(testYIAddr) {
		t.Fatalf("the first event is %s, want acquired with %s", ev, testYIAddr)
	}
	requireIPv6Only(t, r, proto.IPv6OnlyCounters{Ignored: 1})
	if w := foldTwoManagers(t, r.mgr.Stats()); w.IPv6OnlyIgnored != 2 || w.IPv6OnlyWaited != 0 {
		t.Errorf("two managers folded to ignored %d waited %d, want 2 0", w.IPv6OnlyIgnored, w.IPv6OnlyWaited)
	}
}

// TestAMalformedOption108ReachesStatsAndTheLeaseStillForms: a 108 whose length
// is not 4 is read as absent, so the exchange completes and only the number
// shows it happened.
func TestAMalformedOption108ReachesStatsAndTheLeaseStillForms(t *testing.T) {
	r := newRig(t, v6OnlyParams(), offerWith(wire.OptIPv6OnlyPreferred, []byte{0, 1}), Fault{})
	if ev := r.nextEvent(t); ev.Kind != Acquired {
		t.Fatalf("the first event is %s, want acquired: a malformed 108 is read as absent", ev)
	}
	if got := frRequests(r); got != 1 {
		t.Fatalf("the server saw %d REQUEST(s), want 1", got)
	}
	requireIPv6Only(t, r, proto.IPv6OnlyCounters{Malformed: 1})
	if w := foldTwoManagers(t, r.mgr.Stats()); w.IPv6OnlyMalformed != 2 {
		t.Errorf("two managers folded to malformed %d, want 2", w.IPv6OnlyMalformed)
	}
}

func rapidParams() proto.Params {
	p := testParams()
	p.RapidCommit = true
	return p
}

// rapidServer answers a DISCOVER with an ACK carrying option 80 whose value is
// the argument, and a REQUEST with an ordinary ACK.
func rapidServer(opt80 []byte) serverBehaviour {
	return func(req *wire.Message, n int) []*wire.Message {
		if mt, _ := req.Type(); mt == wire.MsgDiscover {
			a := ackFor(req, 3600)
			a.Options[wire.OptRapidCommit] = opt80
			return []*wire.Message{a}
		}
		return answerNormally(req, n)
	}
}

// TestARapidCommitAckReachesStatsAsAccepted: the lease is taken from the ACK
// to the DISCOVER and no REQUEST leaves the host (RFC 4039 section 3.1).
func TestARapidCommitAckReachesStatsAsAccepted(t *testing.T) {
	r := newRig(t, rapidParams(), rapidServer(wire.EncodeRapidCommit()), Fault{})
	if ev := r.nextEvent(t); ev.Kind != Acquired {
		t.Fatalf("the first event is %s, want acquired", ev)
	}
	if got := frRequests(r); got != 0 {
		t.Fatalf("the server saw %d REQUEST(s) after a rapid commit", got)
	}
	st := r.mgr.Stats()
	if st.RapidCommitsAccepted != 1 || st.RapidCommitsRefused != 0 {
		t.Errorf("Stats reports %d accepted and %d refused, want 1 and 0", st.RapidCommitsAccepted, st.RapidCommitsRefused)
	}
	if c := r.mgr.RapidCommitCounters(); c.Accepted != 1 || c.Refused != 0 {
		t.Errorf("RapidCommitCounters is %+v, want 1 accepted", c)
	}
	if c := r.mgr.RapidCommit6Counters(); c != (proto.RapidCommit6Counters{}) {
		t.Errorf("a v4 manager's RapidCommit6Counters is %+v, want the zero value", c)
	}
	if w := foldTwoManagers(t, st); w.RapidCommitsAccepted != 2 || w.RapidCommitsRefused != 0 {
		t.Errorf("two managers folded to %d accepted %d refused, want 2 0", w.RapidCommitsAccepted, w.RapidCommitsRefused)
	}
}

// TestARefusedRapidCommitAckReachesStatsAndStartsNoLease: an ACK whose option
// 80 is malformed is turned down, which produces no action at all, so a
// number derived in an action arm would stay at zero.
func TestARefusedRapidCommitAckReachesStatsAndStartsNoLease(t *testing.T) {
	r := newRig(t, rapidParams(), rapidServer([]byte{1}), Fault{})
	waitReceived4(t, r, wire.MsgAck, 1)
	noEventQueued4(t, r, "a refused rapid commit ACK gives no lease")
	if got := frRequests(r); got != 0 {
		t.Fatalf("the server saw %d REQUEST(s) after a refused rapid commit", got)
	}
	st := r.mgr.Stats()
	if st.RapidCommitsRefused != 1 || st.RapidCommitsAccepted != 0 {
		t.Errorf("Stats reports %d refused and %d accepted, want 1 and 0", st.RapidCommitsRefused, st.RapidCommitsAccepted)
	}
	if c := r.mgr.RapidCommitCounters(); c.Refused != 1 || c.Accepted != 0 {
		t.Errorf("RapidCommitCounters is %+v, want 1 refused", c)
	}
	if w := foldTwoManagers(t, st); w.RapidCommitsRefused != 2 {
		t.Errorf("two managers folded to %d refused, want 2", w.RapidCommitsRefused)
	}
}

// frSilentAfterTheLease is answerWithANonce for the DISCOVER and the first
// REQUEST only, so the renewal a FORCERENEW starts goes unanswered and the
// client stays in RENEWING.
func frSilentAfterTheLease(t *testing.T) serverBehaviour {
	t.Helper()
	b := answerWithANonce(t)
	return func(req *wire.Message, n int) []*wire.Message {
		if n > 2 {
			return nil
		}
		return b(req, n)
	}
}

// frCountingBarrier blocks until the n-th journalled FORCERENEW Step after
// the previous barrier: the journal's channel is consumed as it is read.
func frCountingBarrier(t *testing.T, r *rig, n int) {
	t.Helper()
	seen := 0
	r.journal.waitAppended(t, "the Step on a FORCERENEW", func(e proto.JournalEntry) bool {
		if isForcerenewEntry(e) {
			seen++
		}
		return seen >= n
	})
}

// TestAForcerenewReachesStatsAsRenewedThenAsAlreadyRenewing: the first
// authentic FORCERENEW starts a renewal, the second finds one running and
// sends nothing (RFC 3203 section 2.2). The REQUEST count on the server is the
// evidence, the numbers ride on it.
func TestAForcerenewReachesStatsAsRenewedThenAsAlreadyRenewing(t *testing.T) {
	r := newRig(t, testParams(), frSilentAfterTheLease(t), Fault{})
	if ev := r.nextEvent(t); ev.Kind != Acquired {
		t.Fatalf("first event is %s, want acquired", ev)
	}
	addr := netip.MustParseAddr(testYIAddr)

	r.server.injectTo(signedForcerenew(t, 5), addr)
	frCountingBarrier(t, r, 1)
	r.server.injectTo(signedForcerenew(t, 6), addr)
	frCountingBarrier(t, r, 1)

	if got := frRequests(r); got != 2 {
		t.Fatalf("the server saw %d REQUESTs, want 2: the acquisition and the one renewal the first frame started", got)
	}
	st := r.mgr.Stats()
	if st.ForcerenewsRenewed != 1 || st.ForcerenewsAlreadyRenewing != 1 || st.ForcerenewsRefused != 0 || st.ForcerenewsAckRefused != 0 {
		t.Errorf("Stats reports renewed %d already %d refused %d ack-refused %d, want 1 1 0 0",
			st.ForcerenewsRenewed, st.ForcerenewsAlreadyRenewing, st.ForcerenewsRefused, st.ForcerenewsAckRefused)
	}
	c := r.mgr.ForcerenewCounters()
	if c.Renewed != 1 || c.AlreadyRenewing != 1 || c.RefusedTotal() != 0 {
		t.Errorf("ForcerenewCounters is %+v, want 1 renewed and 1 already renewing", c)
	}
	w := foldTwoManagers(t, st)
	if w.ForcerenewsRenewed != 2 || w.ForcerenewsAlreadyRenewing != 2 {
		t.Errorf("two managers folded to renewed %d already %d, want 2 2", w.ForcerenewsRenewed, w.ForcerenewsAlreadyRenewing)
	}
}

// TestARefusedForcerenewReachesStatsWithTheRuleThatRefusedIt: a frame with no
// destination is refused and produces no action, so the total can only come
// from the machine's own view after the Step. The split is the accessor's.
func TestARefusedForcerenewReachesStatsWithTheRuleThatRefusedIt(t *testing.T) {
	r := newRig(t, testParams(), frSilentAfterTheLease(t), Fault{})
	if ev := r.nextEvent(t); ev.Kind != Acquired {
		t.Fatalf("first event is %s, want acquired", ev)
	}
	r.server.injectRaw(signedForcerenew(t, 5))
	frCountingBarrier(t, r, 1)

	if got := frRequests(r); got != 1 {
		t.Fatalf("the server saw %d REQUESTs, want 1: a refused frame starts nothing", got)
	}
	st := r.mgr.Stats()
	if st.ForcerenewsRefused != 1 || st.ForcerenewsRenewed != 0 {
		t.Errorf("Stats reports %d refused and %d renewed, want 1 and 0", st.ForcerenewsRefused, st.ForcerenewsRenewed)
	}
	c := r.mgr.ForcerenewCounters()
	if got := c.Refused[proto.ForcerenewRefusalNotUnicast]; got != 1 || c.RefusedTotal() != 1 {
		t.Errorf("ForcerenewCounters.Refused[%v] is %d and the total %d, want 1 and 1: the total cannot say which rule refused", proto.ForcerenewRefusalNotUnicast, got, c.RefusedTotal())
	}
	if w := foldTwoManagers(t, st); w.ForcerenewsRefused != 2 {
		t.Errorf("two managers folded to %d refused, want 2", w.ForcerenewsRefused)
	}
}

// TestAForcerenewAccessorHandsOutACopy: the array in the returned value is the
// caller's, so scribbling on it does not reach the manager's mirror.
func TestAForcerenewAccessorHandsOutACopy(t *testing.T) {
	r := newRig(t, testParams(), frSilentAfterTheLease(t), Fault{})
	if ev := r.nextEvent(t); ev.Kind != Acquired {
		t.Fatalf("first event is %s, want acquired", ev)
	}
	r.server.injectRaw(signedForcerenew(t, 5))
	frCountingBarrier(t, r, 1)

	c := r.mgr.ForcerenewCounters()
	c.Refused[proto.ForcerenewRefusalNotUnicast] = 99
	c.Renewed = 99
	if got := r.mgr.ForcerenewCounters(); got.Renewed != 0 || got.Refused[proto.ForcerenewRefusalNotUnicast] != 1 {
		t.Errorf("a caller's write reached the mirror: %+v", got)
	}
}

// TestAnAckThatLacksTheNonceReachesStatsAsAckRefused: an OFFER that listed
// option 145 and an ACK with no valid option 90 is discarded (RFC 6704 section
// 3.1.4), which is not one of the FORCERENEW refusals and stays out of that
// total. The server answers the DISCOVER and the first REQUEST only, so the
// client's retry has nothing to count and the numbers hold still.
func TestAnAckThatLacksTheNonceReachesStatsAsAckRefused(t *testing.T) {
	capable := offerWith(wire.OptForcerenewNonce, wire.EncodeForcerenewNonceCapable())
	once := func(req *wire.Message, n int) []*wire.Message {
		if n > 2 {
			return nil
		}
		return capable(req, n)
	}
	r := newRig(t, testParams(), once, Fault{})
	waitReceived4(t, r, wire.MsgAck, 1)
	for len(r.mgr.Events()) > 0 {
		if ev := <-r.mgr.Events(); ev.Kind == Acquired {
			t.Fatalf("the manager acquired a lease from an ACK RFC 6704 section 3.1.4 has discarded: %s", ev)
		}
	}
	st := r.mgr.Stats()
	if st.ForcerenewsAckRefused != 1 || st.ForcerenewsRefused != 0 {
		t.Errorf("Stats reports %d ack-refused and %d refused, want 1 and 0", st.ForcerenewsAckRefused, st.ForcerenewsRefused)
	}
	if c := r.mgr.ForcerenewCounters(); c.AckRefused != 1 || c.RefusedTotal() != 0 {
		t.Errorf("ForcerenewCounters is %+v, want 1 ack-refused and no refusal", c)
	}
	if w := foldTwoManagers(t, st); w.ForcerenewsAckRefused != 2 {
		t.Errorf("two managers folded to %d ack-refused, want 2", w.ForcerenewsAckRefused)
	}
}

// TestAV4ManagerReportsNoV6Counters is the preservation half for the v6
// types: a v4 manager that ran an exchange reports their zero values and reads
// no machine it does not have.
func TestAV4ManagerReportsNoV6Counters(t *testing.T) {
	r := newRig(t, testParams(), answerNormally, Fault{})
	if ev := r.nextEvent(t); ev.Kind != Acquired {
		t.Fatalf("the first event is %s, want acquired", ev)
	}
	st := r.mgr.Stats()
	if st.TemporaryAddressesGranted+st.TemporaryAddressesRefused+st.TemporaryAddressesAbsent+st.TemporaryAddressesConflicted != 0 ||
		st.PrefixesGranted+st.PrefixesRefused+st.PrefixesAbsent+st.PrefixesChanged != 0 {
		t.Errorf("a v4 manager reports v6 counters: %+v", st)
	}
	if c := r.mgr.TemporaryCounters(); c != (proto.Temporary6Counters{}) {
		t.Errorf("TemporaryCounters is %+v on a v4 manager", c)
	}
	if c := r.mgr.PrefixCounters(); c != (proto.Prefix6Counters{}) {
		t.Errorf("PrefixCounters is %+v on a v4 manager", c)
	}
	if c := r.mgr.RapidCommit6Counters(); c != (proto.RapidCommit6Counters{}) {
		t.Errorf("RapidCommit6Counters is %+v on a v4 manager", c)
	}
}
