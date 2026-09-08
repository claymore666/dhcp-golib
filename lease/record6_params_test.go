// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package lease

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

// v6ParamsRecord folds a created v6 record carrying p as its snapshot, which
// is the write the caller makes once per manager instance. The declined set is
// the OTHER half a caller persists and it rides on the event beside the
// parameters, never inside them — see Record.Declined6.
func v6ParamsRecord(t *testing.T, p proto.Params6, declined ...netip.Addr) Record {
	t.Helper()
	rec, err := Fold(Record{}, RecordEvent{
		ID: "rec-6", Seq: 1, Op: OpCreate, Scope: "net-a",
		Family: FamilyV6, Identity: testIdentity6, Params6: &p,
		Declined6: declined,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return rec
}

// rebuiltFrom6 is the parameters a caller hands the NEXT client: the record's
// snapshot with the record's declined set put back into it. The two are stored
// apart so a run's own journal replays against its own snapshot, and this is
// the one place they are joined again.
func rebuiltFrom6(rec Record) proto.Params6 {
	p := *rec.Params6
	p.Declined = append([]netip.Addr(nil), rec.Declined6...)
	return p
}

// TestAV6RecordCarriesTheParametersItsReplayNeeds is the v6 half of the
// record's whole reason for holding a parameter snapshot.
//
// A step journal is a list of transitions and the messages that caused them.
// It is not a configuration: proto.Replay6 builds a fresh Machine6 from a
// Params6 and re-runs the journal against it, so a journal without the Params6
// that produced it replays into a machine that ran a different client. The v4
// side has held proto.Params in Record since the record existed; the v6 side
// carried a journal it could not replay, which is a durable log that stops
// meaning anything at the restart it exists for.
//
// THE OBSERVER IS THE RECORD'S OWN COPY. The test replays from
// *rec.Params6 — the value that came back out of Fold — and never from the
// local variable it handed in, because a record that stored nothing and a
// record that stored the right thing are indistinguishable to a test that
// replays from its own copy.
func TestAV6RecordCarriesTheParametersItsReplayNeeds(t *testing.T) {
	p := testParams6()
	r := newRig6(t, p, answerNormally6(t))
	r.acquire6(t)
	_ = r.stop()

	entries := r.mgr.Journal6()
	if len(entries) == 0 {
		t.Fatal("the journal is empty")
	}

	rec := v6ParamsRecord(t, p)
	if rec.Params6 == nil {
		t.Fatal("the record kept no v6 parameters, so its journal replays from nothing")
	}

	res, err := proto.Replay6(*rec.Params6, entries)
	if err != nil {
		t.Fatalf("the journal does not replay from the record's own snapshot: %v", err)
	}
	notes := 0
	for _, e := range entries {
		if e.Note {
			notes++
		}
	}
	if res.Steps != len(entries)-notes {
		t.Fatalf("replayed %d of %d entries (%d notes)", res.Steps, len(entries), notes)
	}
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].Note {
			continue
		}
		if res.State != entries[i].To {
			t.Errorf("the replay ended in %s, the journal in %s", res.State, entries[i].To)
		}
		break
	}

	// Replaying TO THE BIND is the assertion that carries the lease: the
	// journal above ends after the stop, and a replay that only reproduced a
	// final state with no lease in it would agree with a machine that never
	// leased.
	var upto []proto.JournalEntry6
	for _, e := range entries {
		upto = append(upto, e)
		if !e.Note && e.To == proto.State6Bound {
			break
		}
	}
	if len(upto) == len(entries) {
		t.Fatal("the journal never reached BOUND6")
	}
	bound, err := proto.Replay6(*rec.Params6, upto)
	if err != nil {
		t.Fatalf("replay to BOUND6 from the record's snapshot: %v", err)
	}
	if !bound.Held {
		t.Fatal("the replay reached BOUND6 with no lease")
	}
	if got := bound.Lease.Addrs[0].Addr.String(); got != test6Addr {
		t.Errorf("the replayed lease is %s, want %s", got, test6Addr)
	}

	// THE SNAPSHOT IS LOAD-BEARING, and these two are what say so. Without
	// them the test above would pass against a record that carried the field
	// and a replay that ignored it, because any Params6 at all would do.
	t.Run("a reader with no snapshot cannot replay at all", func(t *testing.T) {
		if _, err := proto.Replay6(proto.DefaultParams6(), entries); err == nil {
			t.Fatal("a journal replayed with no client identity of any kind")
		}
	})
	t.Run("a replay from the wrong parameters diverges", func(t *testing.T) {
		other := testParams6()
		// One field, and it is one the caller is free to change between runs:
		// a client that remembers a binding confirms it (§18.2.3) where a
		// client that does not solicits. Same journal, different second Step.
		other.Resume = &proto.Resume6{
			Addrs:      []proto.Addr6{{Addr: netip.MustParseAddr(test6Addr), Preferred: 300 * proto.Second, Valid: 300 * proto.Second}},
			ServerDUID: append([]byte(nil), test6ServerDUID...),
			T1:         150 * proto.Second,
			T2:         240 * proto.Second,
		}
		_, err := proto.Replay6(other, entries)
		if !errors.Is(err, proto.ErrReplayDiverged) {
			t.Fatalf("replaying with parameters the manager never ran with gave %v, want a divergence", err)
		}
	})
}

// TestTheV6ParamsSnapshotIsNotAliased is TestParamsAreSnapshotNotAliased for
// the second family, and it has one more level to reach than the v4 row did:
// Resume6 now carries RFC 3646's two lists, so the record can alias the
// caller's resolver as well as its identity.
func TestTheV6ParamsSnapshotIsNotAliased(t *testing.T) {
	p := testParams6()
	p.ORO = []wire.OptionCodeV6{wire.OptV6DNSServers, wire.OptV6DomainList}
	p.Resume = &proto.Resume6{
		Addrs:      []proto.Addr6{{Addr: netip.MustParseAddr(test6Addr), Preferred: 300 * proto.Second, Valid: 300 * proto.Second}},
		ServerDUID: append([]byte(nil), test6ServerDUID...),
		T1:         150 * proto.Second,
		T2:         240 * proto.Second,
		DNS:        []netip.Addr{netip.MustParseAddr(test6DNS)},
		Search:     []string{test6Search},
	}

	rec := v6ParamsRecord(t, p)

	if rec.Params6.Resume == p.Resume {
		t.Fatal("the record shares the caller's Resume6 pointer")
	}
	p.DUID[0] = 0xff
	p.ORO[0] = wire.OptV6ClientID
	p.Resume.Addrs[0].Addr = netip.MustParseAddr("fd00:99::dead")
	p.Resume.ServerDUID[0] = 0xff
	p.Resume.DNS[0] = netip.MustParseAddr("fd00:99::dead")
	p.Resume.Search[0] = "moved.invalid"

	if rec.Params6.DUID[0] != test6DUID[0] {
		t.Error("DUID aliases the caller's slice")
	}
	if rec.Params6.ORO[0] != wire.OptV6DNSServers {
		t.Error("ORO aliases the caller's slice")
	}
	if got := rec.Params6.Resume.Addrs[0].Addr.String(); got != test6Addr {
		t.Errorf("Resume.Addrs aliases the caller's slice: %s", got)
	}
	if rec.Params6.Resume.ServerDUID[0] != test6ServerDUID[0] {
		t.Error("Resume.ServerDUID aliases the caller's slice")
	}
	if got := rec.Params6.Resume.DNS[0].String(); got != test6DNS {
		t.Errorf("Resume.DNS aliases the caller's slice: %s", got)
	}
	if rec.Params6.Resume.Search[0] != test6Search {
		t.Errorf("Resume.Search aliases the caller's slice: %s", rec.Params6.Resume.Search[0])
	}

	// A nil Resume stays nil rather than becoming a pointer to a zero value,
	// which would make every snapshotted Params6 look like it had one and send
	// a replayed client to CONFIRMING with nothing to confirm.
	if got := SnapshotParams6(testParams6()); got.Resume != nil {
		t.Fatalf("SnapshotParams6 invented a Resume: %+v", *got.Resume)
	}
}

// TestARecordRefusesTheOtherFamilysParameterSnapshot is the write-once family
// rule reaching the two new fields.
//
// The two snapshots are read by different functions — proto.Replay takes
// proto.Params, proto.Replay6 takes proto.Params6 — so a record holding the
// wrong one holds a journal nothing can replay, and the reader finds out at
// the restart the record existed for. Refused at the fold, where every other
// write-once fact is refused.
//
// BOTH DIRECTIONS AND THE PAIR, so that no one of the three is the tested one,
// and each case carries its own preservation control: the same event with the
// matching snapshot must be accepted.
func TestARecordRefusesTheOtherFamilysParameterSnapshot(t *testing.T) {
	p4 := proto.DefaultParams(testMAC)
	p6 := testParams6()

	refuses := func(t *testing.T, prior Record, ev RecordEvent, want string) {
		t.Helper()
		got, err := Fold(prior, ev)
		var rj *Reject
		if !errors.As(err, &rj) || rj.Reason != RejectFamily {
			t.Fatalf("Fold = %v, want a RejectFamily", err)
		}
		if !strings.Contains(rj.Note, want) {
			t.Errorf("the refusal says %q, which does not name %q", rj.Note, want)
		}
		// The refusal leaves the record as it was: Fold returns the prior
		// record with its refusal counted, so the assertion is that NOTHING
		// the refused event carried reached it.
		if got.Params != prior.Params || got.Params6 != prior.Params6 {
			t.Error("the refused event's parameter snapshot reached the record anyway")
		}
		if got.Counters.Rejects != prior.Counters.Rejects+1 {
			t.Errorf("the record counted %d refusals, want %d", got.Counters.Rejects, prior.Counters.Rejects+1)
		}
	}

	t.Run("a v4 snapshot on a v6 record", func(t *testing.T) {
		ev := RecordEvent{ID: "rec-6", Seq: 1, Op: OpCreate, Scope: "net-a", Family: FamilyV6, Identity: testIdentity6, Params: &p4}
		refuses(t, Record{}, ev, "proto.Replay6 takes proto.Params6")

		ev.Params, ev.Params6 = nil, &p6
		ok, err := Fold(Record{}, ev)
		if err != nil {
			t.Fatalf("the same event with the v6 snapshot was refused: %v", err)
		}
		if ok.Params6 == nil {
			t.Error("the accepted event stored no v6 snapshot")
		}
	})

	t.Run("a v6 snapshot on a v4 record", func(t *testing.T) {
		ev := RecordEvent{ID: "rec-4", Seq: 1, Op: OpCreate, Scope: "net-a", Family: FamilyV4, CHAddr: testMAC, Params6: &p6}
		refuses(t, Record{}, ev, "proto.Replay takes proto.Params")

		ev.Params6, ev.Params = nil, &p4
		ok, err := Fold(Record{}, ev)
		if err != nil {
			t.Fatalf("the same event with the v4 snapshot was refused: %v", err)
		}
		if ok.Params == nil {
			t.Error("the accepted event stored no v4 snapshot")
		}
	})

	t.Run("a later event on an established record", func(t *testing.T) {
		// The family the event lands in is the RECORD's when the event does
		// not name one, which is the case a check keyed on ev.Family alone
		// would wave through: every event after the create carries no family.
		rec := v6ParamsRecord(t, p6)
		refuses(t, rec, RecordEvent{ID: "rec-6", Seq: 2, Op: OpBind, Params: &p4}, "proto.Replay6 takes proto.Params6")

		// Preservation control at the same sequence number.
		ok, err := Fold(rec, RecordEvent{ID: "rec-6", Seq: 2, Op: OpBind, Params6: &p6})
		if err != nil {
			t.Fatalf("a v6 snapshot on a v6 record was refused: %v", err)
		}
		if ok.Params6 == nil {
			t.Error("the accepted event stored no v6 snapshot")
		}
	})

	t.Run("both snapshots on one event", func(t *testing.T) {
		// No family named anywhere: this is the one the two rules above cannot
		// see, and it is a caller who has not decided which machine it ran.
		refuses(t, Record{}, RecordEvent{ID: "rec-x", Seq: 1, Op: OpCreate, Scope: "net-a", CHAddr: testMAC, Params: &p4, Params6: &p6},
			"a record runs one family")
	})
}

// hintedV6Params is the fixture's parameters with the address the fake server
// hands out asked for as a hint, which is the shape the plugin's persistent
// client runs in (#213): the caller wants the endpoint to keep the address it
// had.
func hintedV6Params() proto.Params6 {
	p := testParams6()
	p.Hint = netip.MustParseAddr(test6Addr)
	return p
}

// mustSolicit6 is the FIRST Solicit the fake server decoded, which is the one
// a restart is judged on: a client that re-hints a declined address does it on
// the message it sends before anything has answered.
func mustSolicit6(t *testing.T, r *rig6) *wire.MessageV6 {
	t.Helper()
	msg := findSent6(r, wire.MsgSolicit)
	if msg == nil {
		t.Fatal("no Solicit left the host")
	}
	return msg
}

// solicitedAddrs is the addresses a Solicit asked for, read out of the bytes
// the fake server decoded.
func solicitedAddrs(t *testing.T, msg *wire.MessageV6) []netip.Addr {
	t.Helper()
	ias, err := msg.Options.IANAs()
	if err != nil || len(ias) != 1 {
		t.Fatalf("the Solicit's IA_NA: %v %v", ias, err)
	}
	as, err := ias[0].Options.Addrs()
	if err != nil {
		t.Fatalf("the Solicit's IA Address options: %v", err)
	}
	out := make([]netip.Addr, 0, len(as))
	for _, a := range as {
		out = append(out, a.Addr)
	}
	return out
}

// TestADeclinedAddressReachesTheRecordAndTheClientRebuiltFromIt is the whole
// chain the restart runs through: decline, snapshot, record, rebuild, and the
// first Solicit the rebuilt client sends.
//
// It is one test and not four because the joints are where it broke. The
// declined set lived on proto.Machine6 and died with the process, while
// Params6.Hint — the field a caller persists, and the field SnapshotParams6
// copies into Record.Params6 — survived. A client that declined its hint and
// came back from its own record asked for that address again on its first
// message, on a link where the other node is still answering for it.
//
// EVERY VALUE COMES OUT OF THE PREVIOUS STAGE. The parameters are the
// manager's, the record's are the fold's, and the rebuilt client is built from
// the record's copy — a test that carried its own Params6 forward would pass
// against a chain in which every stage dropped the field.
func TestADeclinedAddressReachesTheRecordAndTheClientRebuiltFromIt(t *testing.T) {
	declined := netip.MustParseAddr(test6Addr)

	r := newRig6(t, hintedV6Params(), answerNormally6(t))
	r.waitSent(t, wire.MsgSolicit)
	first := mustSolicit6(t, r)
	if got := solicitedAddrs(t, first); len(got) != 1 || got[0] != declined {
		t.Fatalf("the first client's Solicit asked for %v, want the hinted %s; the fixture is not driving the case this test is about", got, test6Addr)
	}
	r.settleDAD(t, test6Addr, true)
	r.settle(t)
	_ = r.stop()

	saved, ok := r.mgr.Params6()
	if !ok {
		t.Fatal("a v6 manager reports no v6 parameters")
	}
	run, ok := r.mgr.Declined6()
	if !ok {
		t.Fatal("a v6 manager reports no declined set")
	}
	if !slices.Contains(run, declined) {
		t.Fatalf("the manager reports Declined6()=%v after declining %s; a caller has nothing to persist", run, test6Addr)
	}
	if len(saved.Declined) != 0 {
		t.Fatalf("Params6() reports Declined=%v; those are the parameters the run RAN WITH, and its own journal replays against them", saved.Declined)
	}

	rec := v6ParamsRecord(t, saved, run...)
	if rec.Params6 == nil {
		t.Fatal("the record kept no v6 parameters")
	}
	if !slices.Contains(rec.Declined6, declined) {
		t.Fatalf("the record reports Declined6=%v; the set does not survive the write it exists for", rec.Declined6)
	}
	if rec.Params6.Hint != declined {
		t.Fatalf("the record's Hint is %v, want %s: the caller's preference is kept and it is the DECLINED set that overrides it", rec.Params6.Hint, test6Addr)
	}

	r2 := newRig6(t, rebuiltFrom6(rec), answerNormally6(t))
	defer func() { _ = r2.stop() }()
	r2.waitSent(t, wire.MsgSolicit)
	if got := solicitedAddrs(t, mustSolicit6(t, r2)); len(got) != 0 {
		t.Fatalf("the client rebuilt from the record asks for %v on its first Solicit, the address the previous run declined: "+
			"the server offers it, the other node is still there, and the loop starts again one restart later", got)
	}
}

// TestARebuiltClientWithNothingDeclinedStillHints is the preservation control
// for the case above, and it is the reason the fix is a SET and not a cleared
// Hint: the ordinary restart is the one where the hint comes back.
func TestARebuiltClientWithNothingDeclinedStillHints(t *testing.T) {
	r := newRig6(t, hintedV6Params(), answerNormally6(t))
	r.acquire6(t)
	_ = r.stop()

	saved, ok := r.mgr.Params6()
	if !ok {
		t.Fatal("a v6 manager reports no v6 parameters")
	}
	run, ok := r.mgr.Declined6()
	if !ok {
		t.Fatal("a v6 manager reports no declined set")
	}
	if len(run) != 0 || len(saved.Declined) != 0 {
		t.Fatalf("a client that declined nothing reports Declined6()=%v, Params6().Declined=%v", run, saved.Declined)
	}

	rec := v6ParamsRecord(t, saved, run...)
	r2 := newRig6(t, rebuiltFrom6(rec), answerNormally6(t))
	defer func() { _ = r2.stop() }()
	r2.waitSent(t, wire.MsgSolicit)
	got := solicitedAddrs(t, mustSolicit6(t, r2))
	if len(got) != 1 || got[0] != netip.MustParseAddr(test6Addr) {
		t.Fatalf("the rebuilt client asks for %v, want the caller's hint %s back (§18.2.1)", got, test6Addr)
	}
}

// TestTheV6SnapshotDoesNotAliasTheDeclinedSet is the aliasing control for the
// one field a caller reads out of a running manager and then keeps.
func TestTheV6SnapshotDoesNotAliasTheDeclinedSet(t *testing.T) {
	p := testParams6()
	p.Declined = []netip.Addr{netip.MustParseAddr(test6Addr)}

	rec := v6ParamsRecord(t, p)
	p.Declined[0] = netip.MustParseAddr("fd00:99::dead")

	if len(rec.Params6.Declined) != 1 || rec.Params6.Declined[0].String() != test6Addr {
		t.Fatalf("the record's declined set is %v after the caller wrote into its own slice", rec.Params6.Declined)
	}
}

// TestARunsOwnJournalReplaysAgainstItsOwnSnapshot is the case that says which
// of the two contracts Record.Params6 holds, and it is here because round 1
// made the record hold both of them at once.
//
// A record carries a parameter snapshot for exactly one reason (design §4.3):
// proto.Replay6 rebuilds a Machine6 from it and re-runs the journal recorded
// beside it, comparing states and rendered actions. That only works if the
// snapshot is the parameters the run STARTED with. The declined set is the
// opposite: it is what the run ENDED with, and a restart needs it.
//
// Round 1 put both in one field and the two disagree on precisely the run this
// milestone is about. wire.Summary began naming the address a Solicit asks for,
// so the recorded action of the first Solicit reads "ia-na(fd00:99::183)"; the
// snapshot began carrying the address that run went on to decline, so a machine
// rebuilt from it refuses the hint and renders "ia-na". MEASURED by review at
// 067d5ee: the divergence is at entry 1, action 0. A run whose journal cannot
// be replayed against its own snapshot has a durable log that stops meaning
// anything at the restart it exists for — and the failure lands on the operator
// with a duplicate address, which is the run most worth replaying.
//
// SO THE RECORD HOLDS THE REPLAY CONTRACT AND Declined6 HOLDS THE OTHER, and
// this case asserts all three halves of that: the replay is clean, the set is
// in the record, and a client rebuilt from the pair still does not re-hint. The
// third is what stops the "fix" of simply dropping the set.
func TestARunsOwnJournalReplaysAgainstItsOwnSnapshot(t *testing.T) {
	declined := netip.MustParseAddr(test6Addr)

	r := newRig6(t, hintedV6Params(), answerNormally6(t))
	r.waitSent(t, wire.MsgSolicit)
	if got := solicitedAddrs(t, mustSolicit6(t, r)); len(got) != 1 || got[0] != declined {
		t.Fatalf("the first Solicit asked for %v, want the hinted %s; the fixture is not driving the case this test is about", got, test6Addr)
	}
	r.settleDAD(t, test6Addr, true)
	r.settle(t)
	_ = r.stop()

	entries := r.mgr.Journal6()
	if len(entries) == 0 {
		t.Fatal("the journal is empty")
	}
	saved, ok := r.mgr.Params6()
	if !ok {
		t.Fatal("a v6 manager reports no v6 parameters")
	}
	run, ok := r.mgr.Declined6()
	if !ok {
		t.Fatal("a v6 manager reports no declined set")
	}
	if !slices.Contains(run, declined) {
		t.Fatalf("this run declined %v, not %s; the fixture never reached the Decline", run, test6Addr)
	}

	// The premise: the journal DOES carry the hinted address in a rendered
	// action, so a snapshot that refused the hint really would diverge. A
	// renderer that stopped naming addresses would make this test vacuous.
	hinted := false
	for _, e := range entries {
		for _, a := range e.Actions {
			if strings.Contains(a, "SOLICIT") && strings.Contains(a, test6Addr) {
				hinted = true
			}
		}
	}
	if !hinted {
		t.Fatalf("no recorded Solicit action names %s; this case cannot detect what it is for", test6Addr)
	}

	rec := v6ParamsRecord(t, saved, run...)
	if rec.Params6 == nil {
		t.Fatal("the record kept no v6 parameters")
	}

	// One: the record's own journal against the record's own snapshot.
	if _, err := proto.Replay6(*rec.Params6, entries); err != nil {
		t.Fatalf("a run's own journal does not replay against its own snapshot: %v", err)
	}

	// Two: the set the restart needs is in the record, beside the snapshot.
	if !slices.Contains(rec.Declined6, declined) {
		t.Fatalf("the record reports Declined6=%v, want %s: dropping the set makes the replay clean and the restart wrong", rec.Declined6, test6Addr)
	}

	// Three: joined again, the pair is still a restart that does not walk
	// back into the address the previous run gave back.
	r2 := newRig6(t, rebuiltFrom6(rec), answerNormally6(t))
	defer func() { _ = r2.stop() }()
	r2.waitSent(t, wire.MsgSolicit)
	if got := solicitedAddrs(t, mustSolicit6(t, r2)); len(got) != 0 {
		t.Fatalf("the client rebuilt from the record's snapshot and its declined set asks for %v on its first Solicit", got)
	}
}

// TestTheRecordsDeclinedSetIsNotAliased is the aliasing control for the field
// the case above adds: an event's slice belongs to the caller, and a record
// that kept it would say something different after the caller's next write.
func TestTheRecordsDeclinedSetIsNotAliased(t *testing.T) {
	mine := []netip.Addr{netip.MustParseAddr(test6Addr)}
	rec := v6ParamsRecord(t, testParams6(), mine...)
	mine[0] = netip.MustParseAddr("fd00:99::dead")

	if len(rec.Declined6) != 1 || rec.Declined6[0].String() != test6Addr {
		t.Fatalf("the record's declined set is %v after the caller wrote into its own slice", rec.Declined6)
	}
}

// TestAServersSolMaxRTReachesTheManagersParameters is the observer the
// params6 mirror owes.
//
// Params6 is what the machine RAN WITH, and the manager holds a copy taken
// once at construction rather than deep-copying four slices and a Resume6 out
// of the machine on every Step. That is only correct while SOL_MAX_RT and
// INF_MAX_RT are the ONLY fields that move after New6 (§21.24, §21.25:
// "MUST process an included SOL_MAX_RT option"), and the mirror carries them
// across by copying two integers.
//
// So this case drives a server that sets both and asserts the manager's answer
// changed. Without it the mirror is a copy that silently stops tracking, and
// a caller persisting the parameters would write down a retransmission ceiling
// the run never used — the one on the wire in a Solicit storm.
//
// THE BOUND IS NAMED IN THE FAILURE, because it is the thing this case cannot
// see: a third mutable field added to Machine6 would need a line here and in
// proto.Machine6.MaxRT, and nothing would redden if it did not get one.
func TestAServersSolMaxRTReachesTheManagersParameters(t *testing.T) {
	const (
		sol = 900
		inf = 1800
	)
	base := testParams6()
	if base.SolMaxRT == sol*proto.Second || base.InfMaxRT == inf*proto.Second {
		t.Fatalf("the defaults are already %s/%s; this case cannot see a change", base.SolMaxRT, base.InfMaxRT)
	}

	r := newRig6(t, base, func(req *wire.MessageV6, n int) []*wire.MessageV6 {
		msgs := answerNormally6(t)(req, n)
		for _, m := range msgs {
			if m.Type == wire.MsgAdvertise {
				m.Options = append(m.Options,
					optV6(wire.OptV6SolMaxRTCode, u32(sol)),
					optV6(wire.OptV6InfMaxRTCode, u32(inf)))
			}
		}
		return msgs
	})
	r.acquire6(t)
	defer func() { _ = r.stop() }()

	got, ok := r.mgr.Params6()
	if !ok {
		t.Fatal("a v6 manager reports no v6 parameters")
	}
	if got.SolMaxRT != sol*proto.Second {
		t.Errorf("the manager reports SOL_MAX_RT %s after a server set %ds; the mirror is not tracking "+
			"proto.Machine6.MaxRT, and any third mutable field would fail the same way", got.SolMaxRT, sol)
	}
	if got.InfMaxRT != inf*proto.Second {
		t.Errorf("the manager reports INF_MAX_RT %s after a server set %ds", got.InfMaxRT, inf)
	}

	// The preservation half: the mirror carries the two that move and nothing
	// else drifted with them.
	if got.IAID != base.IAID || !slices.Equal(got.DUID, base.DUID) {
		t.Errorf("the manager reports IAID %d / DUID %x, want the configured %d / %x", got.IAID, got.DUID, base.IAID, base.DUID)
	}
}
