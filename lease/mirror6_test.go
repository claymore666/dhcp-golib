// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package lease

import (
	"net/netip"
	"testing"

	"github.com/claymore666/dhcp-golib/proto"
)

// The seven counters below were mirrored from ring 1 into Stats and nothing at
// this ring read them. MEASURED while the Reconfigure counters were being
// built: discarding each assignment in Manager.dispatch's mirror block one at
// a time killed SLAACAddressesFormed and SLAACPrefixesIgnored and left these
// seven alive, because every test that named one asserted it had NOT moved.
// A zero is what a discarded assignment produces too.
//
// EACH TEST BELOW DRIVES ONE COUNTER OFF ZERO AND READS IT THROUGH Stats.
// One counter each, so a mutant that discards one assignment fails one test
// and names it.

// raManagedWithAutonomousPrefix is raWithAutonomousPrefix with RFC 4861 §4.2's
// M flag set: "When set, it indicates that addresses are available via Dynamic
// Host Configuration Protocol". It is the advertisement Mode6Auto commits to
// DHCPv6 on, and it carries a prefix the fallback can form from.
func raManagedWithAutonomousPrefix(valid, preferred uint32) []byte {
	ra := raWithAutonomousPrefix(valid, preferred)
	ra[5] |= 0x80
	return ra
}

// raWithResolver is a Router Advertisement carrying one RFC 8106 §5.1 RDNSS
// option naming one resolver, which is what fills the DNS Server List one
// entry at a time.
func raWithResolver(addr string, lifetime uint32) []byte {
	out := []byte{
		134, 0, 0, 0,
		64, 0x00, 0x07, 0x08,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
	o := make([]byte, 24)
	o[0], o[1] = 25, 3
	o[4], o[5], o[6], o[7] = byte(lifetime>>24), byte(lifetime>>16), byte(lifetime>>8), byte(lifetime)
	copy(o[8:], netip.MustParseAddr(addr).AsSlice())
	return append(out, o...)
}

// slaacRig forms one address from one autonomous prefix and returns the rig
// with the acquisition already taken, which is where the five lifetime and
// duplicate counters below start.
func slaacRig(t *testing.T, clk *fakeClock, valid, preferred uint32) *rig6 {
	t.Helper()
	p := testParams6()
	p.Mode = proto.Mode6SLAAC
	p.LinkAddr = mustHex("ea494ee531ed")
	r := newRig6On(t, clk, p, silent6)
	r.nd.injectFrom(raWithAutonomousPrefix(valid, preferred), raRouter)
	r.settleDAD(t, slaacRAAddr, false)
	if e := r.takeEvent(t); e.Kind != Acquired {
		t.Fatalf("the first event is %s, want acquired", e.Kind)
	}
	return r
}

// TestARepeatedAdvertisementRefreshesAnAddressWhereTheCallerCanSeeIt is
// RFC 4862 §5.5.3 e — a Prefix Information option for an address already held
// "resets the preferred lifetime" and the valid lifetime with it — read at the
// ring the caller asks. A router repeats its advertisement every few seconds
// (RFC 4861 §6.2.1), so this is the ordinary case and not an unusual one.
func TestARepeatedAdvertisementRefreshesAnAddressWhereTheCallerCanSeeIt(t *testing.T) {
	r := slaacRig(t, newFakeClock(), 86400, 14400)
	if got := r.mgr.Stats().SLAACAddressesRefreshed; got != 0 {
		t.Fatalf("Stats.SLAACAddressesRefreshed is %d before the prefix was advertised twice", got)
	}

	r.nd.injectFrom(raWithAutonomousPrefix(86400, 14400), raRouter)
	waitRA(t, r, "the advertisement repeating the prefix that formed the address")
	r.settle(t)

	st := r.mgr.Stats()
	if st.SLAACAddressesRefreshed != 1 {
		t.Errorf("Stats.SLAACAddressesRefreshed is %d, want 1", st.SLAACAddressesRefreshed)
	}
	// THE OTHER DIRECTION: a repeat is not a second address.
	if st.SLAACAddressesFormed != 1 {
		t.Errorf("Stats.SLAACAddressesFormed is %d, want 1: the repeat formed nothing", st.SLAACAddressesFormed)
	}
}

// TestAPreferredLifetimeRunningOutReachesTheCaller is RFC 4862 §5.5.4's first
// phase change: "A preferred address becomes deprecated when its preferred
// lifetime expires." The address is KEPT, so nothing else the caller reads
// moves, and the count is the only way to know it happened.
func TestAPreferredLifetimeRunningOutReachesTheCaller(t *testing.T) {
	clk := newFakeClock()
	r := slaacRig(t, clk, 86400, 60)
	if !r.timers.waitArmed(proto.Timer6SLAAC) {
		t.Fatal("no lifetime timer was armed for the formed address")
	}

	clk.advance(61 * proto.Second)
	r.timers.fire(proto.Timer6SLAAC)
	r.settle(t)

	st := r.mgr.Stats()
	if st.SLAACAddressesDeprecated != 1 {
		t.Errorf("Stats.SLAACAddressesDeprecated is %d, want 1", st.SLAACAddressesDeprecated)
	}
	// A DEPRECATED ADDRESS IS STILL HELD, §5.5.4: "SHOULD continue to be used
	// as a source address in existing communications". The valid lifetime has
	// 86340 seconds left on it.
	if st.SLAACAddressesExpired != 0 {
		t.Errorf("Stats.SLAACAddressesExpired is %d: the valid lifetime had not run out", st.SLAACAddressesExpired)
	}
	if _, ok := r.mgr.Lease(); !ok {
		t.Error("the deprecated address was given up; §5.5.4 keeps it until the valid lifetime runs out")
	}
}

// TestAValidLifetimeRunningOutReachesTheCaller is §5.5.4's second phase
// change: "An address (and its association with an interface) becomes invalid
// when its valid lifetime expires." The address is dropped, and the count is
// what separates an address this client gave up from one it never formed.
func TestAValidLifetimeRunningOutReachesTheCaller(t *testing.T) {
	clk := newFakeClock()
	r := slaacRig(t, clk, 120, 60)
	if !r.timers.waitArmed(proto.Timer6SLAAC) {
		t.Fatal("no lifetime timer was armed for the formed address")
	}

	clk.advance(121 * proto.Second)
	r.timers.fire(proto.Timer6SLAAC)
	r.settle(t)

	if got := r.mgr.Stats().SLAACAddressesExpired; got != 1 {
		t.Errorf("Stats.SLAACAddressesExpired is %d, want 1", got)
	}
}

// TestAFormedAddressAnotherNodeHoldsReachesTheCaller is RFC 4862 §5.4.5 at
// this ring: "If the address is a link-local address formed from an interface
// identifier based on the hardware address ... IP operation on the interface
// SHOULD be disabled" — this library drops the address and remembers it as
// refused. The count is what tells an operator the link has a collision on it
// from an acquisition that simply produced nothing.
func TestAFormedAddressAnotherNodeHoldsReachesTheCaller(t *testing.T) {
	p := testParams6()
	p.Mode = proto.Mode6SLAAC
	p.LinkAddr = mustHex("ea494ee531ed")
	r := newRig6On(t, newFakeClock(), p, silent6)

	r.nd.injectFrom(raWithAutonomousPrefix(86400, 14400), raRouter)
	r.settleDAD(t, slaacRAAddr, true)
	r.settle(t)

	st := r.mgr.Stats()
	if st.SLAACAddressesConflicted != 1 {
		t.Errorf("Stats.SLAACAddressesConflicted is %d, want 1", st.SLAACAddressesConflicted)
	}
	// THE OTHER DIRECTION: a duplicate is not a formed address held.
	if _, ok := r.mgr.Lease(); ok {
		t.Error("a lease is held on an address another node answered for")
	}
}

// TestFallingBackToTheRoutersPrefixReachesTheCaller is Mode6Auto's recovery
// counted where a caller reads it: the router said DHCPv6 (RFC 4861 §4.2's M
// flag), no server answered within the budget, and the address came off the
// router's autonomous prefix instead. Nothing else in Stats says that the
// address the caller holds is not the one it asked a server for.
func TestFallingBackToTheRoutersPrefixReachesTheCaller(t *testing.T) {
	p := testParams6()
	p.Mode = proto.Mode6Auto
	p.LinkAddr = mustHex("ea494ee531ed")
	r := newRig6On(t, newFakeClock(), p, silent6)

	r.nd.injectFrom(raManagedWithAutonomousPrefix(86400, 14400), raRouter)
	if !r.timers.waitArmed(proto.Timer6AutoFallback) {
		t.Fatal("M=1 armed no fallback deadline")
	}
	if got := r.mgr.Stats().SLAACFallbacks; got != 0 {
		t.Fatalf("Stats.SLAACFallbacks is %d before the deadline passed", got)
	}

	r.timers.fire(proto.Timer6AutoFallback)
	r.settleDAD(t, slaacRAAddr, false)
	r.settle(t)

	if got := r.mgr.Stats().SLAACFallbacks; got != 1 {
		t.Errorf("Stats.SLAACFallbacks is %d, want 1", got)
	}
}

// TestARouterAFullListCannotTakeReachesTheCaller drives the arrival half of
// RFC 4861 §6.3.4's bounded Default Router List. The comment on maxRouters
// prices the cap: a table full of routers that advertised a long lifetime and
// went quiet refuses a router that is real and advertising now, and this count
// is the only thing on the caller's side that says so.
func TestARouterAFullListCannotTakeReachesTheCaller(t *testing.T) {
	r := newRig6On(t, newFakeClock(), testParams6(), silent6)

	// Eight fill RFC 4861 §6.3.4's list; the ninth is the one it cannot take.
	routers := []string{
		"fe80::1", "fe80::2", "fe80::3", "fe80::4",
		"fe80::5", "fe80::6", "fe80::7", "fe80::8", "fe80::9",
	}
	for i, addr := range routers {
		r.nd.injectFrom(raWithRouterLifetime(600), addr)
		awaitRAStep(t, r, i+1)
	}
	r.settle(t)

	st := r.mgr.Stats()
	if st.RouterTableEntriesDropped != 1 {
		t.Errorf("Stats.RouterTableEntriesDropped is %d, want 1: nine routers advertised into a list of eight", st.RouterTableEntriesDropped)
	}
	// THE OTHER DIRECTION, and it is the half the pair exists for: a refused
	// arrival is not an entry thrown out. Nothing the table held was given up.
	if st.RouterTableEntriesEvicted != 0 {
		t.Errorf("Stats.RouterTableEntriesEvicted is %d: a full list refuses, it does not evict", st.RouterTableEntriesEvicted)
	}
	if got := len(r.mgr.Router().Routers); got != 8 {
		t.Errorf("the table holds %d routers, want the cap of 8", got)
	}
}

// TestAResolverAFullListThrowsOutReachesTheCaller drives the eviction half of
// the pair. RFC 8106 §6.2 step (d) is explicit that a full DNS Server List
// makes room — "the host SHOULD delete the entry with the shortest expiration
// time" — so an entry a caller was told about stops being true, and this is
// the count that says how often.
func TestAResolverAFullListThrowsOutReachesTheCaller(t *testing.T) {
	r := newRig6On(t, newFakeClock(), testParams6(), silent6)

	resolvers := []string{
		"fd00:99::1", "fd00:99::2", "fd00:99::3", "fd00:99::4",
		"fd00:99::5", "fd00:99::6", "fd00:99::7", "fd00:99::8", "fd00:99::9",
	}
	for i, addr := range resolvers {
		// THE LIFETIMES DESCEND, so §6.2 (d)'s "shortest expiration time" has
		// one answer and the ninth arrival is the one that has to make room.
		r.nd.injectFrom(raWithResolver(addr, uint32(900-i)), raRouter)
		awaitRAStep(t, r, i+1)
	}
	r.settle(t)

	st := r.mgr.Stats()
	if st.RouterTableEntriesEvicted != 1 {
		t.Errorf("Stats.RouterTableEntriesEvicted is %d, want 1: nine resolvers arrived into a list of eight", st.RouterTableEntriesEvicted)
	}
	// THE OTHER DIRECTION: the arrivals were all taken, none refused.
	if st.RouterTableEntriesDropped != 0 {
		t.Errorf("Stats.RouterTableEntriesDropped is %d: every advertisement came from one router", st.RouterTableEntriesDropped)
	}
	if got := len(r.mgr.Router().DNS); got != 8 {
		t.Errorf("the DNS Server List holds %d entries, want the cap of 8", got)
	}
}
