// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package lease

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

// This file builds from fakes6_test.go and fakes_test.go and from nothing else
// in the package's tests, so a run with the other test files switched off
// still compiles it (claymore666/docker-net-dhcp#214).

const pfxFirst = "2001:db8:1:100::/64"

var pfxIdentity = append(append([]byte(nil), test6DUID...), 0x0a, 0x0b, 0x0c, 0x0d)

func pfxLease() Lease {
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	return Lease{
		Addr:       netip.MustParsePrefix(test6Addr + "/128"),
		IAID:       test6IAID,
		ServerDUID: append([]byte(nil), test6ServerDUID...),
		Acquired:   t0,
		Expire:     t0.Add(300 * time.Second),
		Preferred:  t0.Add(150 * time.Second),
		Valid:      t0.Add(300 * time.Second),
		Renew:      t0.Add(120 * time.Second),
		Rebind:     t0.Add(240 * time.Second),
		Addrs: []Addr6{{
			Addr:      netip.MustParsePrefix(test6Addr + "/128"),
			Preferred: t0.Add(150 * time.Second), Valid: t0.Add(300 * time.Second),
		}},
		Prefixes: []Addr6{{
			Addr:      netip.MustParsePrefix(pfxFirst),
			Preferred: t0.Add(200 * time.Second), Valid: t0.Add(1000 * time.Second),
		}},
	}
}

// TestPrefixesAreWrittenUnderTheirOwnKey: a journal line carries the delegated
// prefixes under "prefixes", reads back whole, and a lease with none writes the
// bytes it always did (claymore666/docker-net-dhcp#214).
func TestPrefixesAreWrittenUnderTheirOwnKey(t *testing.T) {
	l := pfxLease()
	raw, err := json.Marshal(RecordEvent{ID: "ctr", Op: OpLease, Seq: 3, At: l.Acquired, Lease: &l})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"prefixes":[`)) {
		t.Fatalf("the record does not carry prefixes: %s", raw)
	}
	var back RecordEvent
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.Lease == nil || len(back.Lease.Prefixes) != 1 || back.Lease.Prefixes[0].Addr != l.Prefixes[0].Addr ||
		!back.Lease.Prefixes[0].Valid.Equal(l.Prefixes[0].Valid) || len(back.Lease.Addrs) != 1 {
		t.Errorf("the line read back as %+v", back.Lease)
	}

	l.Prefixes = nil
	raw, err = json.Marshal(RecordEvent{ID: "ctr", Op: OpLease, At: l.Acquired, Lease: &l})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if bytes.Contains(raw, []byte("prefixes")) {
		t.Errorf("an empty Prefixes was written: %s", raw)
	}
}

// TestToLease6CarriesThePrefixes: the outward lease holds the prefix with the
// length the server gave it, each lifetime counted from the same Start, and no
// deadline for an infinite one (claymore666/docker-net-dhcp#214).
func TestToLease6CarriesThePrefixes(t *testing.T) {
	wall := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	b := clockBridge{mono: 0, wall: wall}
	start := proto.Instant(0).Add(10 * proto.Second)
	l := proto.Lease6{
		IAID: 7, Start: start,
		Addrs: []proto.Addr6{{Addr: netip.MustParseAddr(test6Addr), Preferred: 100 * proto.Second, Valid: 300 * proto.Second}},
		Prefixes: []proto.Prefix6{
			{Prefix: netip.MustParsePrefix(pfxFirst), Preferred: 50 * proto.Second, Valid: 400 * proto.Second},
			{Prefix: netip.MustParsePrefix("2001:db8:1:200::/56"), Preferred: proto.Infinite, Valid: proto.Infinite},
		},
	}
	out := toLease6(l, b)
	if len(out.Addrs) != 1 || out.Addrs[0].Addr != netip.PrefixFrom(netip.MustParseAddr(test6Addr), 128) {
		t.Fatalf("Addrs %v: a prefix reached the address list", out.Addrs)
	}
	if len(out.Prefixes) != 2 || out.Prefixes[0].Addr != netip.MustParsePrefix(pfxFirst) || out.Prefixes[1].Addr.Bits() != 56 {
		t.Fatalf("Prefixes %v", out.Prefixes)
	}
	if want := wall.Add(410 * time.Second); !out.Prefixes[0].Valid.Equal(want) {
		t.Errorf("prefix Valid %v, want %v", out.Prefixes[0].Valid, want)
	}
	if want := wall.Add(60 * time.Second); !out.Prefixes[0].Preferred.Equal(want) {
		t.Errorf("prefix Preferred %v, want %v", out.Prefixes[0].Preferred, want)
	}
	if !out.Prefixes[1].Valid.IsZero() || !out.Prefixes[1].Preferred.IsZero() {
		t.Errorf("an infinite prefix has deadlines %v", out.Prefixes[1])
	}
	// No prefix lifetime moves the lease's own expiry (claymore666/docker-net-dhcp#214).
	if want := wall.Add(310 * time.Second); !out.Expire.Equal(want) {
		t.Errorf("Expire %v, want %v", out.Expire, want)
	}
}

// TestCloneLeaseDoesNotSharePrefixes: the clone a record holds is not changed
// by the caller's later edit (claymore666/docker-net-dhcp#214).
func TestCloneLeaseDoesNotSharePrefixes(t *testing.T) {
	l := pfxLease()
	c := CloneLease(l)
	l.Prefixes[0].Addr = netip.MustParsePrefix("2001:db8:ffff::/48")
	if c.Prefixes[0].Addr.String() != pfxFirst {
		t.Errorf("the clone follows the original: %v", c.Prefixes)
	}
}

// TestARecordCarriesThePrefixesToTheResume: a folded record's Resume and the
// params snapshot both hold the prefix, and neither shares the slice
// (claymore666/docker-net-dhcp#214).
func TestARecordCarriesThePrefixesToTheResume(t *testing.T) {
	l := pfxLease()
	rec, err := Fold(Record{}, RecordEvent{ID: "rec-6", Seq: 1, Op: OpCreate, Scope: "net-a", Family: FamilyV6, Identity: pfxIdentity})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if rec, err = Fold(rec, RecordEvent{ID: "rec-6", Seq: 2, Op: OpBind}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if rec, err = Fold(rec, RecordEvent{ID: "rec-6", Seq: 3, Op: OpLease, Kind: Acquired, Lease: &l, DAD: proto.DADPassed}); err != nil {
		t.Fatalf("acquired: %v", err)
	}
	got, ok := rec.Resume(l.Acquired.Add(10 * time.Second))
	if !ok || len(got.Prefixes) != 1 || got.Prefixes[0].Addr != netip.MustParsePrefix(pfxFirst) {
		t.Fatalf("Resume = %+v, %t, want the prefix", got.Prefixes, ok)
	}
	got.Prefixes[0].Addr = netip.MustParsePrefix("2001:db8:ffff::/48")
	if again, _ := rec.Resume(l.Acquired.Add(10 * time.Second)); again.Prefixes[0].Addr.String() != pfxFirst {
		t.Errorf("a change of the resumed lease reached the record: %v", again.Prefixes)
	}

	p := testParams6()
	p.Resume = &proto.Resume6{
		Addrs:    []proto.Addr6{{Addr: netip.MustParseAddr(test6Addr), Valid: 300 * proto.Second}},
		Prefixes: []proto.Prefix6{{Prefix: netip.MustParsePrefix(pfxFirst), Valid: 600 * proto.Second}},
	}
	snap := SnapshotParams6(p)
	p.Resume.Prefixes[0].Valid = 1
	if len(snap.Resume.Prefixes) != 1 || snap.Resume.Prefixes[0].Valid != 600*proto.Second {
		t.Errorf("the snapshot holds %v, want the prefix as it was", snap.Resume.Prefixes)
	}
}

func pfxIAPD(t *testing.T, prefix string, pref, valid uint32) wire.OptionV6 {
	t.Helper()
	v, err := wire.EncodeIAPrefix(&wire.IAPrefix{PreferredLifetime: pref, ValidLifetime: valid, Prefix: netip.MustParsePrefix(prefix)})
	if err != nil {
		t.Fatalf("EncodeIAPrefix: %v", err)
	}
	b, err := wire.EncodeIAPD(&wire.IAPD{IAID: test6IAID, T1: 120, T2: 200, Options: wire.OptionsV6{optV6(wire.OptV6IAPrefix, v)}})
	if err != nil {
		t.Fatalf("EncodeIAPD: %v", err)
	}
	return optV6(wire.OptV6IAPD, b)
}

// TestAResumedLeaseWithAPrefixRebindsThroughTheManager: the record's prefix
// crosses the seam, the first message to leave the host is a Rebind that names
// it, no Confirm goes out, and the lease the caller is told of carries the
// prefix the server answered with (RFC 8415 section 18.2.12;
// claymore666/docker-net-dhcp#214).
func TestAResumedLeaseWithAPrefixRebindsThroughTheManager(t *testing.T) {
	clk := newFakeClock()
	now := clk.Wall()
	remembered := Lease{
		Addr:       netip.MustParsePrefix(test6Addr + "/128"),
		ServerDUID: append([]byte(nil), test6ServerDUID...),
		IAID:       test6IAID,
		Preferred:  now.Add(120e9),
		Valid:      now.Add(240e9),
		Expire:     now.Add(240e9),
		Renew:      now.Add(60e9),
		Rebind:     now.Add(180e9),
		Prefixes:   []Addr6{{Addr: netip.MustParsePrefix(pfxFirst), Preferred: now.Add(100e9), Valid: now.Add(500e9)}},
	}
	p := testParams6()
	p.PrefixHint = 64
	rebinding := func(req *wire.MessageV6, _ int) []*wire.MessageV6 {
		if req.Type != wire.MsgRebind {
			return nil
		}
		return []*wire.MessageV6{{
			Type: wire.MsgReply, XID: req.XID,
			Options: wire.OptionsV6{
				optV6(wire.OptV6ClientID, test6DUID),
				optV6(wire.OptV6ServerID, test6ServerDUID),
				ianaOption(t, test6IAID, 150, 240, test6Addr, 300),
				pfxIAPD(t, pfxFirst, 700, 900),
			},
		}}
	}
	r := newRig6On(t, clk, p, rebinding, withResume6(remembered))

	r.waitSent(t, wire.MsgRebind)
	var reb *wire.MessageV6
	for _, m := range r.server.sentMessages() {
		if m.Type == wire.MsgConfirm || m.Type == wire.MsgSolicit {
			t.Fatalf("a %v left the host before the Rebind", m.Type)
		}
		if m.Type == wire.MsgRebind && reb == nil {
			reb = m
		}
	}
	pds, err := reb.Options.IAPDs()
	if err != nil || len(pds) != 1 {
		t.Fatalf("the Rebind's IA_PD: %v %v", pds, err)
	}
	ps, err := pds[0].Options.Prefixes()
	if err != nil || len(ps) != 1 || ps[0].Prefix != netip.MustParsePrefix(pfxFirst) {
		t.Fatalf("the Rebind names %v, want the remembered %s", ps, pfxFirst)
	}

	ev := r.acquire6(t)
	if len(ev.Lease.Prefixes) != 1 || ev.Lease.Prefixes[0].Addr != netip.MustParsePrefix(pfxFirst) {
		t.Fatalf("the Acquired lease carries %v, want %s", ev.Lease.Prefixes, pfxFirst)
	}
	if ev.Lease.Prefixes[0].Valid.IsZero() || !ev.Lease.Prefixes[0].Valid.After(ev.Lease.Prefixes[0].Preferred) {
		t.Errorf("the prefix deadlines are %v and %v, want the Reply's 900 s after its 700 s",
			ev.Lease.Prefixes[0].Preferred, ev.Lease.Prefixes[0].Valid)
	}
	if len(ev.Lease.Addrs) != 1 {
		t.Errorf("Addrs %v: the prefix is not an address", ev.Lease.Addrs)
	}
}
