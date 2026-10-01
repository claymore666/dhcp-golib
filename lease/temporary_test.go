// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE (claymore666/docker-net-dhcp#927).

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

// lease110 is the Lease a v1.1.0 reader decodes into: every field of the type
// as it stood before TempAddrs, copied here so that the test names the shape
// a rolled-back process has and not whatever the type is today
// (claymore666/docker-net-dhcp#927).
type lease110 struct {
	Addr         netip.Prefix
	Gateway      netip.Addr
	DNS          []netip.Addr
	Domain       string
	MTU          int
	ServerID     netip.Addr
	ServerDUID   []byte
	IAID         uint32
	Preferred    time.Time
	Valid        time.Time
	Routes       []wire.Route
	DomainSearch []string
	Acquired     time.Time
	Renew        time.Time
	Rebind       time.Time
	Expire       time.Time
	Options      wire.Options
	Addrs        []Addr6
	SLAAC        bool
	FQDN         wire.ClientFQDN
	HasFQDN      bool
}

// record110 is the part of a journal line a v1.1.0 reader keeps of a RecordEvent
// that carries a lease (claymore666/docker-net-dhcp#927).
type record110 struct {
	ID    string    `json:"id"`
	Seq   uint64    `json:"seq"`
	At    time.Time `json:"at"`
	Lease *lease110 `json:"lease,omitempty"`
}

func tempTestLease() Lease {
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	return Lease{
		Addr:       netip.MustParsePrefix("fd00:99::183/128"),
		IAID:       7,
		ServerDUID: []byte{0, 1, 2, 3},
		Acquired:   t0,
		Expire:     t0.Add(300 * time.Second),
		Addrs: []Addr6{{
			Addr:      netip.MustParsePrefix("fd00:99::183/128"),
			Preferred: t0.Add(150 * time.Second), Valid: t0.Add(300 * time.Second),
		}},
		TempAddrs: []Addr6{{
			Addr:      netip.MustParsePrefix("fd00:99::2a1/128"),
			Preferred: t0.Add(200 * time.Second), Valid: t0.Add(1000 * time.Second),
		}},
	}
}

// TestTempAddrsRollBack: a journal line written with temporary addresses is
// read by the v1.1.0 shape of the type as the lease it always was, stable
// addresses and all, and the new key is the only thing it does not know
// (claymore666/docker-net-dhcp#927).
func TestTempAddrsRollBack(t *testing.T) {
	l := tempTestLease()
	ev := RecordEvent{ID: "ctr", Op: OpLease, Seq: 3, At: l.Acquired, Lease: &l}
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"temp_addrs":[`)) {
		t.Fatalf("the record does not carry temp_addrs: %s", raw)
	}

	var old record110
	if err := json.Unmarshal(raw, &old); err != nil {
		t.Fatalf("a v1.1.0 reader could not decode the line: %v", err)
	}
	if old.Lease == nil || old.ID != "ctr" || old.Seq != 3 {
		t.Fatalf("the v1.1.0 reader got %+v", old)
	}
	if len(old.Lease.Addrs) != 1 || old.Lease.Addrs[0].Addr != l.Addrs[0].Addr || !old.Lease.Addrs[0].Valid.Equal(l.Addrs[0].Valid) {
		t.Errorf("the v1.1.0 reader lost the stable address: %+v", old.Lease.Addrs)
	}
	if old.Lease.Addr != l.Addr || old.Lease.IAID != 7 || !old.Lease.Expire.Equal(l.Expire) {
		t.Errorf("the v1.1.0 reader got the lease %+v", old.Lease)
	}

	// The new reader reads its own line back whole (claymore666/docker-net-dhcp#927).
	var back RecordEvent
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.Lease == nil || len(back.Lease.TempAddrs) != 1 || back.Lease.TempAddrs[0].Addr != l.TempAddrs[0].Addr ||
		!back.Lease.TempAddrs[0].Valid.Equal(l.TempAddrs[0].Valid) {
		t.Errorf("the line read back as %+v", back.Lease)
	}

	// And a line written by v1.1.0 carries no temp_addrs, which this reader
	// takes as no temporary addresses (claymore666/docker-net-dhcp#927).
	oldRaw, err := json.Marshal(record110{ID: "ctr", Lease: &lease110{Addr: l.Addr, Addrs: l.Addrs}})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var fromOld RecordEvent
	if err := json.Unmarshal(oldRaw, &fromOld); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if fromOld.Lease == nil || len(fromOld.Lease.TempAddrs) != 0 || len(fromOld.Lease.Addrs) != 1 {
		t.Errorf("a v1.1.0 line read as %+v", fromOld.Lease)
	}
}

// TestALeaseWithoutTempAddrsWritesTheBytesItAlwaysDid: with Params6.Temporary
// off the key is absent, so a record of a lease that never asked is the same
// line it was before the field existed (claymore666/docker-net-dhcp#927).
func TestALeaseWithoutTempAddrsWritesTheBytesItAlwaysDid(t *testing.T) {
	l := tempTestLease()
	l.TempAddrs = nil
	newRaw, err := json.Marshal(RecordEvent{ID: "ctr", Op: OpLease, At: l.Acquired, Lease: &l})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if bytes.Contains(newRaw, []byte("temp_addrs")) {
		t.Fatalf("an empty TempAddrs was written: %s", newRaw)
	}
	var old lease110
	oldBytes, _ := json.Marshal(l)
	if err := json.Unmarshal(oldBytes, &old); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	again, err := json.Marshal(old)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Equal(oldBytes, again) {
		t.Errorf("the lease marshals differently through the v1.1.0 shape:\n new %s\n old %s", oldBytes, again)
	}
}

// TestToLease6SeparatesTheTwoSlices: the outward lease carries the temporary
// addresses beside the stable ones, each counted from the same Start, with a
// host prefix and no deadline for an infinite lifetime (claymore666/docker-net-dhcp#927).
func TestToLease6SeparatesTheTwoSlices(t *testing.T) {
	wall := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	b := clockBridge{mono: 0, wall: wall}
	start := proto.Instant(0).Add(10 * proto.Second)
	temp := netip.MustParseAddr("fd00:99::2a1")
	stable := netip.MustParseAddr("fd00:99::183")
	l := proto.Lease6{
		IAID: 7, Start: start,
		Addrs:     []proto.Addr6{{Addr: stable, Preferred: 100 * proto.Second, Valid: 300 * proto.Second}},
		TempAddrs: []proto.Addr6{{Addr: temp, Preferred: 50 * proto.Second, Valid: 400 * proto.Second}, {Addr: netip.MustParseAddr("fd00:99::2a2"), Preferred: proto.Infinite, Valid: proto.Infinite}},
	}
	out := toLease6(l, b)
	if len(out.Addrs) != 1 || out.Addrs[0].Addr != netip.PrefixFrom(stable, 128) {
		t.Fatalf("Addrs %v", out.Addrs)
	}
	if len(out.TempAddrs) != 2 || out.TempAddrs[0].Addr != netip.PrefixFrom(temp, 128) {
		t.Fatalf("TempAddrs %v", out.TempAddrs)
	}
	if want := wall.Add(410 * time.Second); !out.TempAddrs[0].Valid.Equal(want) {
		t.Errorf("temp Valid %v, want %v", out.TempAddrs[0].Valid, want)
	}
	if want := wall.Add(60 * time.Second); !out.TempAddrs[0].Preferred.Equal(want) {
		t.Errorf("temp Preferred %v, want %v", out.TempAddrs[0].Preferred, want)
	}
	if !out.TempAddrs[1].Valid.IsZero() || !out.TempAddrs[1].Preferred.IsZero() {
		t.Errorf("an infinite temporary address has deadlines %v", out.TempAddrs[1])
	}
	// The lease's own expiry is the stable one's: no temporary lifetime moves it (claymore666/docker-net-dhcp#927).
	if want := wall.Add(310 * time.Second); !out.Expire.Equal(want) {
		t.Errorf("Expire %v, want %v", out.Expire, want)
	}
}

// TestCloneLeaseDoesNotShareTempAddrs: the clone a record holds is not
// changed by the caller's later edit of the lease (claymore666/docker-net-dhcp#927).
func TestCloneLeaseDoesNotShareTempAddrs(t *testing.T) {
	l := tempTestLease()
	c := CloneLease(l)
	l.TempAddrs[0].Addr = netip.MustParsePrefix("fd00:99::ffff/128")
	l.Addrs[0].Addr = netip.MustParsePrefix("fd00:99::eeee/128")
	if c.TempAddrs[0].Addr.String() != "fd00:99::2a1/128" || c.Addrs[0].Addr.String() != "fd00:99::183/128" {
		t.Errorf("the clone follows the original: %v %v", c.TempAddrs, c.Addrs)
	}
}
