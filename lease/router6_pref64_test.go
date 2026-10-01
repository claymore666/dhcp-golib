// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package lease

import (
	"net/netip"
	"testing"

	"github.com/claymore666/dhcp-golib/proto"
)

// raPREF64 is a bare advertisement from a router that says it is a default
// router for 1800 s, followed by the given NAT64 Prefix options, each built from
// RFC 8781 §4's diagram (claymore666/docker-net-dhcp#1028).
func raPREF64(options ...[]byte) []byte {
	out := raWithRouterLifetime(1800)
	for _, o := range options {
		out = append(out, o...)
	}
	return out
}

// pref64Option is Type 38, Length 2, "Scaled Lifetime (13) | PLC (3)" and the
// first twelve octets of the prefix (claymore666/docker-net-dhcp#1028).
func pref64Option(scaled uint16, plc uint8, prefix string) []byte {
	field := scaled<<3 | uint16(plc)
	a := netip.MustParseAddr(prefix).As16()
	return append([]byte{38, 2, byte(field >> 8), byte(field)}, a[:12]...)
}

func prefixStrings(in []netip.Prefix) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		out = append(out, p.String())
	}
	return out
}

func TestTheManagersRouterViewCarriesThePREF64AndItsLifetimeEndsOnTheManagersClock(t *testing.T) {
	const otherRouter = "fe80::dcba"
	r := newRig6(t, testParams6(), answerNormally6(t))
	r.acquire6(t)

	// Scaled Lifetime 10 is 80 s (RFC 8781 §4.1), less than the 1800 s of the
	// router that sent it (claymore666/docker-net-dhcp#1028).
	r.nd.injectFrom(raPREF64(pref64Option(10, 0, "64:ff9b::")), raRouter)
	obs := awaitRAStep(t, r, 1)
	if got := prefixStrings(obs.PREF64); len(got) != 1 || got[0] != "64:ff9b::/96" {
		t.Fatalf("Router().PREF64 is %v, want 64:ff9b::/96", got)
	}

	// Past the lifetime with no Step: the view is a snapshot of the last Step,
	// the same bound the router list states (claymore666/docker-net-dhcp#1028).
	r.clock.advance(81 * proto.Second)
	if got := r.mgr.Router().PREF64; len(got) != 1 {
		t.Errorf("Router().PREF64 is %v with no Step since the lifetime ran out", prefixStrings(got))
	}

	// The next Step, an advertisement of another router that carries no
	// PREF64 at all, drops the expired prefix and keeps the first router
	// (claymore666/docker-net-dhcp#1028).
	r.nd.injectFrom(raWithRouterLifetime(1800), otherRouter)
	obs = awaitRAStep(t, r, 2)
	if len(obs.PREF64) != 0 {
		t.Errorf("Router().PREF64 is %v after a Step past the lifetime", prefixStrings(obs.PREF64))
	}
	if len(obs.Routers) != 2 {
		t.Errorf("the prefix's expiry changed the default routers: %v", obs.Routers)
	}
}

func TestAPrefixLengthCodeOfSixOrSevenIsCountedAsAnIgnoredOptionAndItsSiblingIsKept(t *testing.T) {
	r := newRig6(t, testParams6(), answerNormally6(t))
	r.acquire6(t)
	before := r.mgr.Stats()

	r.nd.injectFrom(raPREF64(
		pref64Option(10, 6, "64:ff9b::"),
		pref64Option(10, 1, "2001:db8:5::"),
		pref64Option(10, 7, "2001:db8:6::"),
	), raRouter)
	obs := awaitRAStep(t, r, 1)
	after := r.mgr.Stats()

	if got := prefixStrings(obs.PREF64); len(got) != 1 || got[0] != "2001:db8:5::/64" {
		t.Errorf("Router().PREF64 is %v, want only the /64 beside the two refused options", got)
	}
	if got := after.RouterAdvertOptionsIgnored - before.RouterAdvertOptionsIgnored; got != 2 {
		t.Errorf("RouterAdvertOptionsIgnored moved by %d, want 2: one per refused option", got)
	}
	if got := after.RouterAdvertsRefused - before.RouterAdvertsRefused; got != 0 {
		t.Errorf("RouterAdvertsRefused moved by %d; a bad option is not a bad message", got)
	}
	if got := after.RouterTableEntriesDropped - before.RouterTableEntriesDropped; got != 0 {
		t.Errorf("RouterTableEntriesDropped moved by %d: a refused option is not a full list", got)
	}
	if len(obs.Routers) != 1 || obs.Routers[0].String() != raRouter {
		t.Errorf("the default routers are %v, want the router that sent the frame", obs.Routers)
	}
}
