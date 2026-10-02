// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package runtime

import (
	"bytes"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/claymore666/dhcp-golib/lease"
	"github.com/claymore666/dhcp-golib/wire"
)

// TestTheReplyOptionsSurviveTheRecordFile: a v6 lease carrying options 17, 41
// and 56 is appended, the file is reopened, and the folded record holds the
// same codes and bytes in the same order (dhcp-golib#53). The file is the only
// thing that outlives the process.
func TestTheReplyOptionsSurviveTheRecordFile(t *testing.T) {
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	want := wire.OptionsV6{
		{Code: 17, Data: []byte{0, 0, 0x0d, 0xe9, 0, 1, 0, 2, 0xaa, 0xbb}},
		{Code: 41, Data: []byte("CET-1CEST,M3.5.0,M10.5.0/3")},
		{Code: 56, Data: []byte{0, 1, 0, 16, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x7b}},
	}
	l := lease.Lease{
		Addr:       netip.MustParsePrefix("2001:db8::7b/128"),
		ServerDUID: []byte{0, 3, 0, 1, 2, 0, 0, 0, 0, 9},
		IAID:       7,
		Acquired:   at,
		Expire:     at.Add(5 * time.Minute),
		OptionsV6:  want,
	}
	events := []lease.RecordEvent{
		{ID: "rec-6", Seq: 1, At: at, Op: lease.OpCreate, Scope: "net-a", Family: lease.FamilyV6, Identity: []byte{1, 2, 3}},
		{ID: "rec-6", Seq: 2, At: at, Op: lease.OpBind},
		{ID: "rec-6", Seq: 3, At: at, Op: lease.OpLease, Kind: lease.Acquired, Lease: &l},
	}
	path := filepath.Join(t.TempDir(), "records.jsonl")
	s, err := OpenRecordStore(path)
	if err != nil {
		t.Fatalf("OpenRecordStore: %v", err)
	}
	for _, ev := range events {
		if err := s.Append(ev); err != nil {
			t.Fatalf("Append(%s): %v", ev.Op, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	reopened, err := OpenRecordStore(path)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	got, err := reopened.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	recs := lease.Rebuild(got).Records
	if len(recs) != 1 || !recs[0].Held {
		t.Fatalf("the file folds to %+v, want one held record", recs)
	}
	have := recs[0].Lease.OptionsV6
	if len(have) != len(want) {
		t.Fatalf("%d option(s) came back, %d went in: %v", len(have), len(want), have)
	}
	for i := range want {
		if have[i].Code != want[i].Code || !bytes.Equal(have[i].Data, want[i].Data) {
			t.Errorf("option %d came back as %d:%x, want %d:%x", i, have[i].Code, have[i].Data, want[i].Code, want[i].Data)
		}
	}
}
