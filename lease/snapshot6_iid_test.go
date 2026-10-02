// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package lease

import (
	"bytes"
	"encoding/json"
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
