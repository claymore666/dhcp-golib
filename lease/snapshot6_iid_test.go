// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package lease

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"

	"github.com/claymore666/dhcp-golib/proto"
)

// A record keeps what the run was configured with, so a caller writing its
// own slices afterwards must not reach the snapshot (dhcp-golib#54).
func TestASnapshotKeepsTheIdentifierInputsTheCallerChangesAfterwards(t *testing.T) {
	p := testParams6()
	p.Mode = proto.Mode6SLAAC
	p.IID = proto.IIDModeStablePrivacy
	p.LinkAddr = []byte{0x02, 0x42, 0xac, 0x11, 0x00, 0x02}
	p.IIDSecret = bytes.Repeat([]byte{0x5a}, proto.MinIIDSecretLen)
	p.IIDNetIface = []byte("eth0")
	p.IIDNetworkID = []byte("lan")
	snap := SnapshotParams6(p)

	for _, b := range [][]byte{p.LinkAddr, p.IIDSecret, p.IIDNetIface, p.IIDNetworkID} {
		b[0] ^= 0xff
	}
	want := map[string][2][]byte{
		"LinkAddr":     {snap.LinkAddr, {0x02, 0x42, 0xac, 0x11, 0x00, 0x02}},
		"IIDSecret":    {snap.IIDSecret, bytes.Repeat([]byte{0x5a}, proto.MinIIDSecretLen)},
		"IIDNetIface":  {snap.IIDNetIface, []byte("eth0")},
		"IIDNetworkID": {snap.IIDNetworkID, []byte("lan")},
	}
	for name, w := range want {
		if !bytes.Equal(w[0], w[1]) {
			t.Errorf("the snapshot's %s is %x after the caller's write, want %x", name, w[0], w[1])
		}
	}
	if snap.IID != proto.IIDModeStablePrivacy {
		t.Errorf("the snapshot's identifier mode is %s", snap.IID)
	}

	// the secret is persisted with the record (dhcp-golib#54),
	// because a replay re-forms the run's addresses only from it.
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var back proto.Params6
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back.IIDSecret, snap.IIDSecret) || !bytes.Equal(back.IIDNetIface, snap.IIDNetIface) || back.IID != snap.IID {
		t.Errorf("the identifier inputs did not survive the record's encoding: %+v", back)
	}
}

// A stable-privacy run's journal replays from its record, encoded as the
// store encodes it, to the address its retries reached; another secret
// diverges (dhcp-golib#54).
func TestAStablePrivacyRunReplaysFromItsEncodedRecordToTheRetriedAddress(t *testing.T) {
	p := testParams6()
	p.Mode = proto.Mode6SLAAC
	p.IID = proto.IIDModeStablePrivacy
	p.IIDSecret = bytes.Repeat([]byte{0x5a}, proto.MinIIDSecretLen)
	p.IIDNetIface = []byte("eth0")
	p.IIDNetworkID = []byte("lan")
	formed := func(counter uint8) string {
		prefix := netip.MustParsePrefix(slaacRAPrefix + "/64")
		iid := proto.StablePrivacyIID(prefix, p.IIDNetIface, p.IIDNetworkID, counter, p.IIDSecret)
		b := prefix.Addr().As16()
		copy(b[8:], iid[:])
		return netip.AddrFrom16(b).String()
	}

	r := newRig6(t, p, silent6)
	r.nd.injectFrom(raWithAutonomousPrefix(86400, 14400), raRouter)
	// The retry's StartDAD rides in the verdict's own journal entry, so each
	// duplicate is followed by the next request and not by waitDADStepped
	// (dhcp-golib#54).
	for c := uint8(0); c < 2; c++ {
		r.waitDADRequested(t, formed(c))
		r.mgr.ReportDADResult(netip.MustParseAddr(formed(c)), true)
	}
	r.settleDAD(t, formed(2), false)
	e := r.takeEvent(t)
	if e.Kind != Acquired || len(e.Lease.Addrs) != 1 || e.Lease.Addrs[0].Addr.Addr().String() != formed(2) {
		t.Fatalf("the run reported %s with %v, want acquired with %s", e.Kind, e.Lease.Addrs, formed(2))
	}
	_ = r.stop()

	entries := r.mgr.Journal6()
	saved, ok := r.mgr.Params6()
	if !ok {
		t.Fatal("a v6 manager reports no v6 parameters")
	}
	raw, err := json.Marshal(v6ParamsRecord(t, saved))
	if err != nil {
		t.Fatal(err)
	}
	var rec Record
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Params6 == nil {
		t.Fatal("the decoded record kept no v6 parameters")
	}

	// Replayed to the bind, as record6_params_test.go does: the journal ends
	// after the stop, which holds no lease (dhcp-golib#54).
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
	res, err := proto.Replay6(*rec.Params6, upto)
	if err != nil {
		t.Fatalf("the run's journal does not replay from its decoded record: %v", err)
	}
	if !res.Held || len(res.Lease.Addrs) != 1 || res.Lease.Addrs[0].Addr.String() != formed(2) {
		t.Errorf("the replay holds %v, want %s", res.Lease.Addrs, formed(2))
	}

	other := *rec.Params6
	other.IIDSecret = bytes.Repeat([]byte{0xa5}, proto.MinIIDSecretLen)
	if _, err := proto.Replay6(other, upto); !errors.Is(err, proto.ErrReplayDiverged) {
		t.Errorf("replaying with another secret gave %v, want a divergence", err)
	}
}
