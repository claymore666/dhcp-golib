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

// The tests here are dhcp-golib#53: the outward lease carries the options of
// the DHCPv6 Reply it came from (claymore666/docker-net-dhcp#1033).

var (
	opts6Vendor = []byte{0, 0, 0x0d, 0xe9, 0, 1, 0, 2, 0xaa, 0xbb}
	opts6TZ     = []byte("CET-1CEST,M3.5.0,M10.5.0/3")
	opts6NTP    = []byte{0, 1, 0, 16, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x7b}
)

func opts6Wire() wire.OptionsV6 {
	return wire.OptionsV6{
		{Code: wire.OptV6VendorOpts, Data: append([]byte(nil), opts6Vendor...)},
		{Code: wire.OptV6PosixTimezone, Data: append([]byte(nil), opts6TZ...)},
		{Code: wire.OptV6NTPServer, Data: append([]byte(nil), opts6NTP...)},
	}
}

func opts6Want(t *testing.T, got wire.OptionsV6) {
	t.Helper()
	want := map[wire.OptionCodeV6][]byte{17: opts6Vendor, 41: opts6TZ, 56: opts6NTP}
	if len(got) != len(want) {
		t.Fatalf("%d option(s), want %d: %v", len(got), len(want), got)
	}
	for code, data := range want {
		d, ok := got.First(code)
		if !ok || !bytes.Equal(d, data) {
			t.Errorf("option %d is %x (present %v), want %x", code, d, ok, data)
		}
	}
}

// TestToLease6CarriesTheReplyOptions: options 17, 41 and 56 of the Reply reach
// the outward lease by code and bytes, and a later edit of the source reaches
// neither the slice nor the bytes inside it (dhcp-golib#53).
func TestToLease6CarriesTheReplyOptions(t *testing.T) {
	in := proto.Lease6{IAID: 7, Options: opts6Wire()}
	out := toLease6(in, clockBridge{})
	opts6Want(t, out.OptionsV6)
	if srv, err := out.OptionsV6.NTPServers(); err != nil || len(srv) != 1 {
		t.Fatalf("NTPServers through the field: %v, %v", srv, err)
	}

	in.Options[0].Data[0] = 0xEE
	in.Options[1] = wire.OptionV6{Code: 99}
	opts6Want(t, out.OptionsV6)

	out.OptionsV6[2].Data[0] = 0xEE
	if in.Options[2].Data[0] == 0xEE {
		t.Fatal("toLease6 shares a byte slice with ring 1's lease")
	}
}

// TestToLease6OfAReplyWithNoOptionsHasNone: nil in, nil out, so a caller can
// tell "no options" from "an empty list" no worse than ring 1 can (dhcp-golib#53).
func TestToLease6OfAReplyWithNoOptionsHasNone(t *testing.T) {
	if got := toLease6(proto.Lease6{}, clockBridge{}).OptionsV6; got != nil {
		t.Fatalf("a Reply with no options came out as %v", got)
	}
}

// TestAV4LeaseCarriesNoV6Options: toLease leaves the field nil, and a v4 lease
// writes no options_v6 key (dhcp-golib#53).
func TestAV4LeaseCarriesNoV6Options(t *testing.T) {
	out := toLease(proto.Lease{Options: wire.Options{53: {5}}}, clockBridge{})
	if out.OptionsV6 != nil {
		t.Fatalf("a v4 lease has v6 options %v", out.OptionsV6)
	}
	line, err := json.Marshal(testRecordLease("192.168.99.100/24"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(line), "options_v6") {
		t.Fatalf("a v4 lease wrote the v6 key: %s", line)
	}
	var back Lease
	if err := json.Unmarshal(line, &back); err != nil || back.OptionsV6 != nil {
		t.Fatalf("read back %v, %v", back.OptionsV6, err)
	}
}

// TestCloneLeaseDoesNotShareTheReplyOptions: the clone a record holds is not
// changed by the caller's later edit of the slice or of a byte inside it (dhcp-golib#53).
func TestCloneLeaseDoesNotShareTheReplyOptions(t *testing.T) {
	l := testRecordLease6()
	l.OptionsV6 = opts6Wire()
	c := CloneLease(l)
	opts6Want(t, c.OptionsV6)
	l.OptionsV6[0].Data[0] = 0xEE
	l.OptionsV6[1] = wire.OptionV6{Code: 99}
	opts6Want(t, c.OptionsV6)
	if got := CloneLease(testRecordLease6()).OptionsV6; got != nil {
		t.Fatalf("a lease with no options cloned to %v", got)
	}
}

// TestTheReplyOptionsKeyIsItsOwn: a lease holding both families' options
// writes two keys and reads each back alone, so neither field overwrites the
// other under the decoder's case-folded matching (dhcp-golib#53).
func TestTheReplyOptionsKeyIsItsOwn(t *testing.T) {
	l := testRecordLease("192.168.99.100/24")
	l.OptionsV6 = opts6Wire()
	line, err := json.Marshal(l)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(line), `"options_v6"`) || !strings.Contains(string(line), `"Options"`) {
		t.Fatalf("a key is missing: %s", line)
	}
	var back Lease
	if err := json.Unmarshal(line, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	opts6Want(t, back.OptionsV6)
	if len(back.Options) != len(l.Options) || !bytes.Equal(back.Options[53], []byte{5}) {
		t.Fatalf("the v4 options changed: %v", back.Options)
	}
	l.OptionsV6 = wire.OptionsV6{}
	line, _ = json.Marshal(l)
	if strings.Contains(string(line), "options_v6") {
		t.Fatalf("an empty list wrote a key: %s", line)
	}
}

// TestFoldKeepsTheReplyOptions: the record a Fold builds holds a copy, not the
// caller's slice (dhcp-golib#53).
func TestFoldKeepsTheReplyOptions(t *testing.T) {
	l := testRecordLease6()
	l.OptionsV6 = opts6Wire()
	rec, err := Fold(Record{}, RecordEvent{ID: "rec-6", Seq: 1, Op: OpCreate, Scope: "net-a", Family: FamilyV6, Identity: []byte{1}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if rec, err = Fold(rec, RecordEvent{ID: "rec-6", Seq: 2, Op: OpBind}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if rec, err = Fold(rec, RecordEvent{ID: "rec-6", Seq: 3, Op: OpLease, Kind: Acquired, Lease: &l}); err != nil {
		t.Fatalf("lease: %v", err)
	}
	l.OptionsV6[0].Data[0] = 0xEE
	opts6Want(t, rec.Lease.OptionsV6)
}
