// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package lease

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

// Server A delegated the prefix, server B delegates none and answers the
// resumed Rebind first with the IA_NA alone (claymore666/dhcp-golib#70).
var splitServerB = mustHex("0001000132556cf15861326b4588")

func splitRemembered(now time.Time, server, prefixServer []byte) Lease {
	return Lease{
		Addr:       netip.MustParsePrefix(test6Addr + "/128"),
		ServerDUID: server, PrefixServerDUID: prefixServer,
		IAID:      test6IAID,
		Preferred: now.Add(40e9), Valid: now.Add(60e9), Expire: now.Add(60e9),
		Renew: now.Add(10e9), Rebind: now.Add(16e9),
		Prefixes: []Addr6{{Addr: netip.MustParsePrefix(pfxFirst), Preferred: now.Add(40e9), Valid: now.Add(60e9)}},
	}
}

// splitRig answers a Rebind from B with the IA_NA alone.
func splitRig(t *testing.T, remembered Lease) *rig6 {
	t.Helper()
	p := testParams6()
	p.PrefixHint = 64
	b := func(req *wire.MessageV6, _ int) []*wire.MessageV6 {
		if req.Type == wire.MsgRebind {
			return []*wire.MessageV6{{Type: wire.MsgReply, XID: req.XID, Options: wire.OptionsV6{
				optV6(wire.OptV6ClientID, test6DUID), optV6(wire.OptV6ServerID, splitServerB),
				ianaOption(t, test6IAID, 54, 99, test6Addr, 120)}}}
		}
		return nil
	}
	clk := newFakeClock()
	return newRig6On(t, clk, p, b, withResume6(remembered))
}

func TestAPrefixThatBLeftOutStaysWithTheServerThatDelegatedIt(t *testing.T) {
	now := newFakeClock().Wall()
	r := splitRig(t, splitRemembered(now, test6ServerDUID, nil))
	ev := r.acquire6(t)
	if len(ev.Lease.Prefixes) != 1 || !bytes.Equal(ev.Lease.ServerDUID, splitServerB) {
		t.Fatalf("Acquired carries %v from %x, want the remembered %s and B's IA_NA", ev.Lease.Prefixes, ev.Lease.ServerDUID, pfxFirst)
	}
	if !bytes.Equal(ev.Lease.PrefixServerDUID, test6ServerDUID) {
		t.Errorf("PrefixServerDUID = %x, want A, which delegated the prefix (RFC 8415 section 18.2.10.1)", ev.Lease.PrefixServerDUID)
	}
	if ev.Lease.Renew.After(now.Add(10e9)) {
		t.Errorf("the lease renews at +%v, past A's T1 at +10s (RFC 8415 section 18.2.4)", ev.Lease.Renew.Sub(now))
	}
}

func TestAResumedSplitRecordRenewsThePrefixWithItsOwnServer(t *testing.T) {
	now := newFakeClock().Wall()
	r := splitRig(t, splitRemembered(now, splitServerB, test6ServerDUID))
	r.acquire6(t)
	at, ok := r.timers.armedAt(proto.Timer6Renew)
	if !ok {
		t.Fatal("no renewal timer is armed")
	}
	r.clock.advance(at)
	r.timers.fire(proto.Timer6Renew)
	r.waitSent(t, wire.MsgRenew)
	var sid []byte
	for _, msg := range r.server.sentMessages() {
		if msg.Type == wire.MsgRenew {
			sid, _ = msg.Options.First(wire.OptV6ServerID)
		}
	}
	if !bytes.Equal(sid, test6ServerDUID) {
		t.Errorf("the Renew names %x, want A, the record's PrefixServerDUID", sid)
	}
}

func splitRecord6() Record {
	rec := relRecord6()
	rec.Lease.Prefixes = relPrefixes()
	rec.Lease.PrefixServerDUID = []byte{0x00, 0x01, 0x00, 0x01, 0x2b, 0x00, 0x00, 0x02, 0xcc, 0xdd}
	return rec
}

func TestASplitRecordReleasesEachIAWithItsOwnServer(t *testing.T) {
	rec := splitRecord6()
	grams, err := BuildReleases(rec, 0x00AABBCC)
	if err != nil || len(grams) != 2 {
		t.Fatalf("BuildReleases = %d datagram(s), %v; want two, one per server (RFC 8415 section 18.2.7)", len(grams), err)
	}
	one, _ := mustBuild(t, rec, 0x00AABBCC)
	if !bytes.Equal(grams[0].Payload, one) {
		t.Errorf("the first datagram is not BuildRelease's")
	}
	want := []struct {
		server   []byte
		xid      uint32
		nas, pds int
	}{{relServerDUID, 0x00AABBCC, 1, 0}, {rec.Lease.PrefixServerDUID, 0x00AABBCD, 0, 1}}
	for i, w := range want {
		msg, err := wire.DecodeV6(grams[i].Payload)
		if err != nil {
			t.Fatalf("datagram %d: %v", i, err)
		}
		sid, _ := msg.Options.First(wire.OptV6ServerID)
		cid, _ := msg.Options.First(wire.OptV6ClientID)
		if !bytes.Equal(sid, w.server) || msg.XID != w.xid || !bytes.Equal(cid, relDUID) ||
			msg.Options.Count(wire.OptV6IANA) != w.nas || msg.Options.Count(wire.OptV6IAPD) != w.pds ||
			msg.Options.Count(wire.OptV6ElapsedTime) != 1 || grams[i].Dest != grams[0].Dest {
			t.Errorf("datagram %d names %x xid %x client %x with %d IA_NA, %d IA_PD; want %x xid %x with %d, %d",
				i, sid, msg.XID, cid, msg.Options.Count(wire.OptV6IANA), msg.Options.Count(wire.OptV6IAPD), w.server, w.xid, w.nas, w.pds)
		}
	}
}

// A v1.4.2 journal record holding two prefixes, as that release wrote it, and
// the Release v1.4.2 built for it at xid 0x00AABBCC.
const (
	splitV142JSON = `{"ID":"rec-6","Scope":"net-a","Family":6,"CHAddr":null,"Identity":"AAMAAQJCwKhjVAoLDA0=","Params":null,"Params6":null,"Declined6":null,"Lease":{"Addr":"fd00:99::53/128","Gateway":"","DNS":null,"Domain":"","MTU":0,"ServerID":"","ServerDUID":"AAEAASsAAAGquw==","IAID":168496141,"Preferred":"0001-01-01T00:00:00Z","Valid":"0001-01-01T00:00:00Z","Routes":null,"DomainSearch":null,"Acquired":"0001-01-01T00:00:00Z","Renew":"0001-01-01T00:00:00Z","Rebind":"0001-01-01T00:00:00Z","Expire":"0001-01-01T00:00:00Z","Options":null,"Addrs":null,"prefixes":[{"Addr":"2001:db8:1:2::/64","Preferred":"0001-01-01T00:00:00Z","Valid":"0001-01-01T00:00:00Z"},{"Addr":"2001:db8:5::/56","Preferred":"0001-01-01T00:00:00Z","Valid":"0001-01-01T00:00:00Z"}],"SLAAC":false,"FQDN":{"Flags":0,"Name":""},"HasFQDN":false},"Held":true,"Phase":0,"ACD":0,"DAD":0,"Config":{"DNS":null,"Search":null,"Refresh":"0001-01-01T00:00:00Z"},"Deadline":"0001-01-01T00:00:00Z","StepsRef":"","Counters":{},"Extra":null,"Seq":0,"Instance":"","LastReject":0}`
	splitV142Hex  = "08aabbcc0001000a000300010242c0a863540002000a000100012b000001aabb000300280a0b0c0d000000000000000000050018fd000099000000000000000000000053000000000000000000" +
		"1900460a0b0c0d0000000000000000001a001900000000000000004020010db8000100020000000000000000001a001900000000000000003820010db8000500000000000000000000000800020000"
)

func TestAV142JournalRecordLoadsAsOneServerWithTheSameRelease(t *testing.T) {
	var rec Record
	if err := json.Unmarshal([]byte(splitV142JSON), &rec); err != nil {
		t.Fatalf("a v1.4.2 record does not load: %v", err)
	}
	if len(rec.Lease.PrefixServerDUID) != 0 || len(rec.Lease.Prefixes) != 2 {
		t.Fatalf("the record loads with prefix server %x and %d prefixes, want none and 2", rec.Lease.PrefixServerDUID, len(rec.Lease.Prefixes))
	}
	grams, err := BuildReleases(rec, 0x00AABBCC)
	if err != nil || len(grams) != 1 || hex.EncodeToString(grams[0].Payload) != splitV142Hex {
		t.Errorf("the v1.4.2 record releases as %d datagram(s), %v; want v1.4.2's one", len(grams), err)
	}
	b, err := json.Marshal(rec)
	if err != nil || bytes.Contains(b, []byte("prefix_server_duid")) {
		t.Errorf("a one-server record writes %s, want no prefix_server_duid", b)
	}
}

func TestCloneLeaseCopiesThePrefixServer(t *testing.T) {
	l := splitRecord6().Lease
	c := CloneLease(l)
	c.PrefixServerDUID[0] = 0xff
	if l.PrefixServerDUID[0] == 0xff || len(c.PrefixServerDUID) != len(l.PrefixServerDUID) {
		t.Errorf("CloneLease shares PrefixServerDUID with its source")
	}
}

func TestBuildReleasesSendsOneReleaseUnlessThePrefixHasItsOwnServer(t *testing.T) {
	v4 := relRecord4()
	v4.Lease.PrefixServerDUID, v4.Lease.Prefixes = splitRecord6().Lease.PrefixServerDUID, relPrefixes()
	same := splitRecord6()
	same.Lease.PrefixServerDUID = append([]byte(nil), relServerDUID...)
	invalid := splitRecord6()
	invalid.Lease.Prefixes = []Addr6{{}}
	for _, c := range []struct {
		name string
		rec  Record
		pds  int
	}{
		{"a v4 record", v4, -1},
		{"a v6 record whose prefix server is the address server", same, 1},
		{"a split record with no prefix to name", invalid, 0},
	} {
		grams, err := BuildReleases(c.rec, 0x00AABBCC)
		if err != nil || len(grams) != 1 {
			t.Errorf("%s: %d datagram(s), %v; want one", c.name, len(grams), err)
			continue
		}
		if c.pds < 0 {
			continue
		}
		msg, err := wire.DecodeV6(grams[0].Payload)
		if err != nil || msg.Options.Count(wire.OptV6IAPD) != c.pds {
			t.Errorf("%s: the Release carries %d IA_PD (%v), want %d", c.name, msg.Options.Count(wire.OptV6IAPD), err, c.pds)
		}
	}
	grams, err := BuildReleases(splitRecord6(), wire.MaxXID6-1)
	if err != nil || len(grams) != 2 {
		t.Fatalf("BuildReleases = %d datagram(s), %v", len(grams), err)
	}
	if msg, err := wire.DecodeV6(grams[1].Payload); err != nil || msg.XID != 0 {
		t.Errorf("the second Release after xid %x carries xid %x (%v), want 0: three octets (RFC 8415 section 8)", wire.MaxXID6-1, msg.XID, err)
	}
}
