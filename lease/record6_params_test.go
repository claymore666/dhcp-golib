package lease

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

// v6ParamsRecord folds a created v6 record carrying p as its snapshot, which
// is the write the caller makes once per manager instance.
func v6ParamsRecord(t *testing.T, p proto.Params6) Record {
	t.Helper()
	rec, err := Fold(Record{}, RecordEvent{
		ID: "rec-6", Seq: 1, Op: OpCreate, Scope: "net-a",
		Family: FamilyV6, Identity: testIdentity6, Params6: &p,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return rec
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
