// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package lease

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

// The tests here are the caller's half of claymore666/dhcp-golib#28: the DHCPv6
// Reconfigure key and replay floor ride the durable form, reach the machine
// again through Config.Resume6, and a restarted client then answers a
// Reconfigure the way the one that never stopped would.

var recKey6 = mustHex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf")

func recLease6(key []byte, replay uint64, seen bool) Lease {
	l := testRecordLease6()
	l.ReconfigureKey = append([]byte(nil), key...)
	l.ReconfigureReplay = replay
	l.ReconfigureReplaySeen = seen
	return l
}

// TestTheReconfigureFieldsSurviveTheJSONForm: the record is the only thing that
// outlives the process, and a floor of 0 that was seen must be written, because
// omitting it is how "seen" would turn into "not yet".
func TestTheReconfigureFieldsSurviveTheJSONForm(t *testing.T) {
	for _, tc := range []struct {
		name   string
		replay uint64
		seen   bool
	}{{"floor and flag", 0x0102030405060708, true}, {"flag at zero", 0, true}, {"no value seen", 0, false}} {
		t.Run(tc.name, func(t *testing.T) {
			l := recLease6(recKey6, tc.replay, tc.seen)
			line, err := json.Marshal(RecordEvent{ID: "rec-1", Seq: 3, Op: OpLease, Kind: Acquired, Lease: &l})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if !strings.Contains(string(line), `"reconfigure_key"`) {
				t.Fatalf("the record has no reconfigure_key: %s", line)
			}
			if got := strings.Contains(string(line), `"reconfigure_replay_seen"`); got != tc.seen {
				t.Fatalf("reconfigure_replay_seen present=%v, want %v: %s", got, tc.seen, line)
			}
			var back RecordEvent
			if err := json.Unmarshal(line, &back); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			b := back.Lease
			if b == nil || !bytes.Equal(b.ReconfigureKey, recKey6) || b.ReconfigureReplay != tc.replay || b.ReconfigureReplaySeen != tc.seen {
				t.Fatalf("read back %+v, want key %x floor %d seen=%v", b, recKey6, tc.replay, tc.seen)
			}
		})
	}
}

// TestARecordWrittenBeforeTheReconfigureFieldsResumesKeyless: a record from
// before the fields has none of the three keys, decodes without complaint, and
// a lease with no key writes none, so a downgrade reads the same bytes.
func TestARecordWrittenBeforeTheReconfigureFieldsResumesKeyless(t *testing.T) {
	l := testRecordLease6()
	line, err := json.Marshal(RecordEvent{ID: "rec-1", Seq: 3, Op: OpLease, Kind: Acquired, Lease: &l})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(line), "reconfigure") {
		t.Fatalf("a keyless lease wrote a reconfigure key: %s", line)
	}
	var back RecordEvent
	if err := json.Unmarshal(line, &back); err != nil {
		t.Fatalf("a record with none of the keys was refused: %v", err)
	}
	b := back.Lease
	if b == nil || b.ReconfigureKey != nil || b.ReconfigureReplay != 0 || b.ReconfigureReplaySeen {
		t.Fatalf("read back %+v, want no key, floor 0, unseen", b)
	}
	if b.Addr != l.Addr {
		t.Fatalf("the rest of the lease changed: %v, want %v", b.Addr, l.Addr)
	}
}

// TestAReaderThatDoesNotKnowTheReconfigureFieldsIgnoresThem is the other
// direction: an older reader meeting a record that carries them reads the
// lease it knows.
func TestAReaderThatDoesNotKnowTheReconfigureFieldsIgnoresThem(t *testing.T) {
	l := recLease6(recKey6, 9, true)
	line, err := json.Marshal(l)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var older struct {
		Addr string `json:"addr"`
	}
	if err := json.Unmarshal(line, &older); err != nil {
		t.Fatalf("a reader that does not know the fields refused the record: %v", err)
	}
	if older.Addr == "" {
		t.Fatalf("the reader found no address in %s", line)
	}
}

// TestTheReconfigureKeyIsNotSharedAcrossTheCopies: CloneLease, the fold and the
// outward conversion each own their bytes.
func TestTheReconfigureKeyIsNotSharedAcrossTheCopies(t *testing.T) {
	l := recLease6(recKey6, 12, true)
	c := CloneLease(l)
	c.ReconfigureKey[0] ^= 0xff
	if l.ReconfigureKey[0] != recKey6[0] {
		t.Fatal("CloneLease shares the key with its source")
	}

	rec, err := Fold(Record{}, RecordEvent{ID: "rec-1", Seq: 1, Op: OpCreate, Scope: "net-a", Family: FamilyV6, Identity: testIdentity6})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	rec, err = Fold(rec, RecordEvent{ID: "rec-1", Seq: 2, Op: OpLease, Kind: Acquired, Lease: &l})
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	l.ReconfigureKey[1] ^= 0xff
	if !bytes.Equal(rec.Lease.ReconfigureKey, recKey6) {
		t.Fatal("the folded record shares the key with the caller's lease")
	}
	if rec.Lease.ReconfigureReplay != 12 || !rec.Lease.ReconfigureReplaySeen {
		t.Fatalf("the fold lost the floor: %d seen=%v", rec.Lease.ReconfigureReplay, rec.Lease.ReconfigureReplaySeen)
	}

	in := proto.Lease6{ReconfigureKey: []byte{9, 8, 7}, ReconfigureReplay: 55, ReconfigureReplaySeen: true}
	out := toLease6(in, clockBridge{})
	if !bytes.Equal(out.ReconfigureKey, []byte{9, 8, 7}) || out.ReconfigureReplay != 55 || !out.ReconfigureReplaySeen {
		t.Fatalf("toLease6 gave key %x floor %d seen=%v", out.ReconfigureKey, out.ReconfigureReplay, out.ReconfigureReplaySeen)
	}
	out.ReconfigureKey[0] = 0
	if in.ReconfigureKey[0] != 9 {
		t.Fatal("toLease6 shares the key with ring 1's lease")
	}
	if got := toLease6(proto.Lease6{}, clockBridge{}).ReconfigureKey; len(got) != 0 {
		t.Fatalf("a lease with no key came out with %x", got)
	}
}

// resumed6 builds the client of a restart: a rig whose Config.Resume6 is the
// record a caller persisted, answering the Confirm the machine opens with.
func resumed6(t *testing.T, key []byte, replay uint64, seen bool) (*rig6, Event) {
	t.Helper()
	clk := newFakeClock()
	remembered := recLease6(key, replay, seen)
	now := clk.Wall()
	remembered.Preferred, remembered.Valid, remembered.Expire = now.Add(240e9), now.Add(240e9), now.Add(240e9)
	remembered.Renew, remembered.Rebind = now.Add(60e9), now.Add(180e9)
	confirming := func(req *wire.MessageV6, _ int) []*wire.MessageV6 {
		switch req.Type {
		case wire.MsgConfirm:
			return []*wire.MessageV6{{
				Type: wire.MsgReply, XID: req.XID,
				Options: wire.OptionsV6{
					optV6(wire.OptV6ClientID, test6DUID),
					optV6(wire.OptV6ServerID, test6ServerDUID),
					optV6(wire.OptV6StatusCode, wire.EncodeStatus(wire.Status{Code: wire.StatusSuccess})),
				},
			}}
		case wire.MsgRenew:
			return []*wire.MessageV6{replyFor(t, req)}
		}
		return nil
	}
	r := newRig6On(t, clk, testParams6(), confirming, withResume6(remembered))
	return r, r.acquire6(t)
}

// TestAResumedClientAnswersAReconfigureSignedWithTheRecordedKey is the whole
// feature through the manager. THE OBSERVER IS THE RENEW ON THE WIRE, which is
// what the server sees, and not Stats or the lease the caller supplied.
func TestAResumedClientAnswersAReconfigureSignedWithTheRecordedKey(t *testing.T) {
	r, ev := resumed6(t, recKey6, 40, true)
	l := ev.Lease
	if !bytes.Equal(l.ReconfigureKey, recKey6) || l.ReconfigureReplay != 40 || !l.ReconfigureReplaySeen {
		t.Fatalf("the Acquired lease holds key %x floor %d seen=%v, want the recorded ones",
			l.ReconfigureKey, l.ReconfigureReplay, l.ReconfigureReplaySeen)
	}
	r.server.injectTo(reconfigureRaw(t, wire.MsgRenew, recKey6, 41), clientUnicast6)
	r.waitSent(t, wire.MsgRenew)
	r.settle(t)
	if c := r.mgr.ReconfigureCounters(); c.Accepted != 1 || c.RefusedTotal() != 0 {
		t.Errorf("counters after one accepted Reconfigure: %+v", c)
	}
}

// TestAResumedClientRefusesAReplayAtTheRecordedFloor: the same client, the
// value the server already used. No Renew leaves, and the counter names the
// rule.
func TestAResumedClientRefusesAReplayAtTheRecordedFloor(t *testing.T) {
	r, _ := resumed6(t, recKey6, 40, true)
	r.server.injectTo(reconfigureRaw(t, wire.MsgRenew, recKey6, 40), clientUnicast6)
	r.journal.waitAppended(t, "the Step on the refused Reconfigure",
		func(e proto.JournalEntry6) bool {
			return e.Kind == proto.EvReceived && len(e.Raw) > 0 && e.Raw[0] == byte(wire.MsgReconfigure)
		})
	r.settle(t)
	c := r.mgr.ReconfigureCounters()
	if got := c.Refused[proto.ReconfigureRefusalReplay]; got != 1 || c.Accepted != 0 {
		t.Fatalf("counters %+v, want one Replay refusal and nothing accepted", c)
	}
	for _, m := range r.server.sentMessages() {
		if m.Type == wire.MsgRenew {
			t.Fatal("a Renew left for a Reconfigure the floor refused")
		}
	}
}

// TestAResumedClientRefusesAZeroAtARecordedZeroFloor is the flag crossing the
// manager: a floor of 0 that was seen is not "no value seen yet", and the
// number alone cannot tell the two apart.
func TestAResumedClientRefusesAZeroAtARecordedZeroFloor(t *testing.T) {
	r, _ := resumed6(t, recKey6, 0, true)
	r.server.injectTo(reconfigureRaw(t, wire.MsgRenew, recKey6, 0), clientUnicast6)
	r.journal.waitAppended(t, "the Step on the refused Reconfigure",
		func(e proto.JournalEntry6) bool {
			return e.Kind == proto.EvReceived && len(e.Raw) > 0 && e.Raw[0] == byte(wire.MsgReconfigure)
		})
	r.settle(t)
	if got := r.mgr.ReconfigureCounters().Refused[proto.ReconfigureRefusalReplay]; got != 1 {
		t.Fatalf("Replay refusals: %d, want 1: a floor of 0 that was seen came back unseen", got)
	}
}

// TestAResumedClientWithNoRecordedKeyRefusesForWantOfOne is today's behaviour
// for a record from before the fields.
func TestAResumedClientWithNoRecordedKeyRefusesForWantOfOne(t *testing.T) {
	r, ev := resumed6(t, nil, 0, false)
	if len(ev.Lease.ReconfigureKey) != 0 {
		t.Fatalf("a keyless record came back with key %x", ev.Lease.ReconfigureKey)
	}
	r.server.injectTo(reconfigureRaw(t, wire.MsgRenew, recKey6, 1), clientUnicast6)
	r.journal.waitAppended(t, "the Step on the refused Reconfigure",
		func(e proto.JournalEntry6) bool {
			return e.Kind == proto.EvReceived && len(e.Raw) > 0 && e.Raw[0] == byte(wire.MsgReconfigure)
		})
	r.settle(t)
	if got := r.mgr.ReconfigureCounters().Refused[proto.ReconfigureRefusalNoKey]; got != 1 {
		t.Fatalf("NoKey refusals: %d, want 1", got)
	}
}

// TestTheRenewedLeaseCarriesTheFloorAnAcceptedReconfigureMoved: a client that
// has been running emits the floor at the Reply its Renew brings, which is
// what a caller persisting events then writes down.
func TestTheRenewedLeaseCarriesTheFloorAnAcceptedReconfigureMoved(t *testing.T) {
	r := newRig6(t, testParams6(), keyedServer6(t))
	first := r.acquire6(t)
	if !bytes.Equal(first.Lease.ReconfigureKey, reconfKey6) || first.Lease.ReconfigureReplaySeen {
		t.Fatalf("the first lease holds key %x seen=%v, want the Reply's key and no floor",
			first.Lease.ReconfigureKey, first.Lease.ReconfigureReplaySeen)
	}
	r.server.injectTo(reconfigureRaw(t, wire.MsgRenew, reconfKey6, 5), clientUnicast6)
	r.waitSent(t, wire.MsgRenew)
	// The server's Reply travels through a goroutine, so settle alone can
	// return before the machine has seen it: wait for the Step that renewed.
	r.journal.waitAppended(t, "the Step that renewed the lease", func(e proto.JournalEntry6) bool {
		for _, a := range e.Actions {
			if strings.Contains(a, "LeaseRenewed") {
				return true
			}
		}
		return false
	})
	r.settle(t)
	for {
		e := r.takeEvent(t)
		if e.Kind != Renewed {
			continue
		}
		if e.Lease.ReconfigureReplay != 5 || !e.Lease.ReconfigureReplaySeen || !bytes.Equal(e.Lease.ReconfigureKey, reconfKey6) {
			t.Fatalf("the Renewed lease holds key %x floor %d seen=%v, want the key and 5",
				e.Lease.ReconfigureKey, e.Lease.ReconfigureReplay, e.Lease.ReconfigureReplaySeen)
		}
		return
	}
}
