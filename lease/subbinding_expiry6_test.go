// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package lease

import (
	"testing"

	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

func TestAPrefixEndingWhileBoundReachesTheCallerAsChanged(t *testing.T) {
	pd := func() []wire.OptionV6 { return []wire.OptionV6{pfxIAPD(t, pfxFirst, 100, 200)} }
	r := newRig6(t, prefixParams6(), extra6(t, pd, pd))
	if ev := r.acquire6(t); len(ev.Lease.Prefixes) != 1 {
		t.Fatalf("the Acquired lease carries %v, want %s", ev.Lease.Prefixes, pfxFirst)
	}
	d, ok := r.timers.armedAt(proto.Timer6Expire)
	if !ok {
		t.Fatal("no expiry timer is armed on a held v6 lease")
	}
	r.clock.advance(d)
	r.timers.fire(proto.Timer6Expire)
	ev := r.nextEvent(t)
	if ev.Kind != Changed || len(ev.Lease.Prefixes) != 0 || len(ev.Lease.Addrs) != 1 {
		t.Fatalf("the event at the prefix's end is %s with prefixes %v and addresses %v, want changed with the address alone",
			ev, ev.Lease.Prefixes, ev.Lease.Addrs)
	}
	if l, held := r.mgr.Lease(); !held || len(l.Prefixes) != 0 {
		t.Errorf("the manager holds %v (held %v), want the lease without its prefix", l.Prefixes, held)
	}
	requirePrefix(t, r, proto.Prefix6Counters{Granted: 1, Changed: 1})
}
