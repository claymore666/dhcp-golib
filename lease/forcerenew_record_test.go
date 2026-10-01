// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package lease

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/claymore666/dhcp-golib/proto"
)

// The tests here are claymore666/docker-net-dhcp#1119's record half: the two
// FORCERENEW fields ride the durable form, and a record written before them
// reads back as a lease with no nonce.

func frRecordLease() Lease {
	l := testRecordLease("192.168.99.100/24")
	l.ForcerenewNonce = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	l.ForcerenewReplay = 0x0102030405060708
	return l
}

// TestTheForcerenewFieldsSurviveTheJSONForm. The record is the only thing that
// outlives the process; a field that does not encode is gone after a restart.
func TestTheForcerenewFieldsSurviveTheJSONForm(t *testing.T) {
	l := frRecordLease()
	line, err := json.Marshal(RecordEvent{ID: "rec-1", Seq: 3, Op: OpLease, Kind: Acquired, Lease: &l})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{`"forcerenew_nonce"`, `"forcerenew_replay"`} {
		if !strings.Contains(string(line), key) {
			t.Fatalf("the record has no %s key: %s", key, line)
		}
	}
	var back RecordEvent
	if err := json.Unmarshal(line, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Lease == nil || !bytes.Equal(back.Lease.ForcerenewNonce, l.ForcerenewNonce) ||
		back.Lease.ForcerenewReplay != l.ForcerenewReplay {
		t.Fatalf("read back %+v, want nonce %x and floor %d", back.Lease, l.ForcerenewNonce, l.ForcerenewReplay)
	}
}

// TestARecordWrittenBeforeTheFieldsReadsBackWithNoNonce. A v1.1.0 record has
// neither key, and it must decode to "no nonce, floor zero" and not fail. A
// lease with none writes neither key, so a downgrade reads the same bytes.
func TestARecordWrittenBeforeTheFieldsReadsBackWithNoNonce(t *testing.T) {
	l := testRecordLease("192.168.99.100/24")
	line, err := json.Marshal(RecordEvent{ID: "rec-1", Seq: 3, Op: OpLease, Kind: Acquired, Lease: &l})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(line), "forcerenew") {
		t.Fatalf("a lease with no nonce wrote a forcerenew key: %s", line)
	}
	var back RecordEvent
	if err := json.Unmarshal(line, &back); err != nil {
		t.Fatalf("a record with neither key was refused: %v", err)
	}
	if back.Lease == nil || back.Lease.ForcerenewNonce != nil || back.Lease.ForcerenewReplay != 0 {
		t.Fatalf("read back %+v, want no nonce and floor 0", back.Lease)
	}
	if back.Lease.Addr != l.Addr {
		t.Fatalf("the rest of the lease changed: %v, want %v", back.Lease.Addr, l.Addr)
	}
}

// TestAReaderThatDoesNotKnowTheFieldsIgnoresThem is the other direction: a
// v1.1.0 reader meeting a record that carries them reads the lease it knows.
func TestAReaderThatDoesNotKnowTheFieldsIgnoresThem(t *testing.T) {
	l := frRecordLease()
	line, err := json.Marshal(l)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var old struct {
		Addr     netip.Prefix
		ServerID netip.Addr
	}
	if err := json.Unmarshal(line, &old); err != nil {
		t.Fatalf("a reader of the earlier shape refused the new keys: %v", err)
	}
	if old.Addr != l.Addr || old.ServerID != l.ServerID {
		t.Fatalf("the earlier shape read %+v, want %v from %v", old, l.Addr, l.ServerID)
	}
}

// TestTheNonceIsNotSharedAcrossTheCopies. CloneLease and toLease both hand a
// lease to a reader; a reader that scribbles on the nonce must not reach the
// record's copy or ring 1's.
func TestTheNonceIsNotSharedAcrossTheCopies(t *testing.T) {
	l := frRecordLease()
	c := CloneLease(l)
	c.ForcerenewNonce[0] = 0xEE
	if l.ForcerenewNonce[0] != 1 {
		t.Fatal("CloneLease shares the nonce with its source")
	}

	rec, err := Fold(Record{}, RecordEvent{ID: "rec-1", Seq: 1, Op: OpCreate, Scope: "net-a", Family: FamilyV4})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	rec, err = Fold(rec, RecordEvent{ID: "rec-1", Seq: 2, Op: OpLease, Kind: Acquired, Lease: &l})
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	l.ForcerenewNonce[1] = 0xEE
	if rec.Lease.ForcerenewNonce[1] != 2 {
		t.Fatal("the folded record shares the nonce with the caller's lease")
	}
	if rec.Lease.ForcerenewReplay != l.ForcerenewReplay {
		t.Fatalf("the floor was not kept: %d", rec.Lease.ForcerenewReplay)
	}
}

// TestTheOutwardLeaseTakesTheNonceByCopy is toLease's half of the same row.
func TestTheOutwardLeaseTakesTheNonceByCopy(t *testing.T) {
	in := proto.Lease{ForcerenewNonce: []byte{9, 8, 7}, ForcerenewReplay: 55}
	out := toLease(in, clockBridge{})
	if !bytes.Equal(out.ForcerenewNonce, []byte{9, 8, 7}) || out.ForcerenewReplay != 55 {
		t.Fatalf("toLease gave nonce %x and floor %d", out.ForcerenewNonce, out.ForcerenewReplay)
	}
	out.ForcerenewNonce[0] = 0
	if in.ForcerenewNonce[0] != 9 {
		t.Fatal("toLease shares the nonce with ring 1's lease")
	}
	if got := toLease(proto.Lease{}, clockBridge{}).ForcerenewNonce; got != nil && len(got) != 0 {
		t.Fatalf("a lease with no nonce came out with %x", got)
	}
}
