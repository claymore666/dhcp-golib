// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package lease

import (
	"net/netip"
	"testing"
	"time"

	"github.com/claymore666/dhcp-golib/wire"
)

// TestARebindReplyWithoutIAPDKeepsTheRememberedPrefix: a server without prefix
// delegation answers the resumed Rebind with the IA_NA alone; the Acquired lease
// keeps the remembered prefix with the record's valid end (RFC 8415 section
// 18.2.10.1; claymore666/dhcp-golib#64).
func TestARebindReplyWithoutIAPDKeepsTheRememberedPrefix(t *testing.T) {
	clk := newFakeClock()
	now := clk.Wall()
	remembered := Lease{
		Addr:       netip.MustParsePrefix(test6Addr + "/128"),
		ServerDUID: append([]byte(nil), test6ServerDUID...),
		IAID:       test6IAID,
		Preferred:  now.Add(120e9), Valid: now.Add(240e9), Expire: now.Add(240e9),
		Renew: now.Add(60e9), Rebind: now.Add(180e9),
		Prefixes: []Addr6{{Addr: netip.MustParsePrefix(pfxFirst), Preferred: now.Add(100e9), Valid: now.Add(500e9)}},
	}
	p := testParams6()
	p.PrefixHint = 64
	naOnly := func(req *wire.MessageV6, _ int) []*wire.MessageV6 {
		if req.Type != wire.MsgRebind {
			return nil
		}
		base := wire.OptionsV6{optV6(wire.OptV6ClientID, test6DUID), optV6(wire.OptV6ServerID, test6ServerDUID),
			ianaOption(t, test6IAID, 54, 99, test6Addr, 120)}
		return []*wire.MessageV6{{Type: wire.MsgReply, XID: req.XID, Options: base}}
	}
	r := newRig6On(t, clk, p, naOnly, withResume6(remembered))
	ev := r.acquire6(t)
	if len(ev.Lease.Prefixes) != 1 || ev.Lease.Prefixes[0].Addr != netip.MustParsePrefix(pfxFirst) {
		t.Fatalf("Acquired carries %v, want the remembered %s", ev.Lease.Prefixes, pfxFirst)
	}
	// The record's 500 s count from the manager's start, the lease's from the
	// Rebind's, which is later by at most the exchange's initial delay.
	if v := ev.Lease.Prefixes[0].Valid; v.Before(now.Add(500e9)) || v.After(now.Add(501*time.Second)) {
		t.Errorf("the prefix ends at %v, want the record's %v", v, now.Add(500e9))
	}
}
