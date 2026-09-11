// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// advert builds a decoded advertisement the way ring 2 hands one over: the
// router's address already filled in from the frame's source, because the
// decoder cannot know it.
func advert(from string, routerLifetime uint16) *wire.RouterAdvert {
	return &wire.RouterAdvert{
		Managed:        true,
		RouterLifetime: routerLifetime,
		Router:         netip.MustParseAddr(from),
	}
}

func observation(t *testing.T, tab *routerTable, now Instant) RouterObservation {
	t.Helper()
	var out RouterObservation
	tab.fill(now, &out)
	return out
}

func addrTexts(in []netip.Addr) []string {
	out := make([]string, 0, len(in))
	for _, a := range in {
		out = append(out, a.String())
	}
	return out
}

func routesOf(in []wire.Route) []string {
	out := make([]string, 0, len(in))
	for _, r := range in {
		out = append(out, r.Dest.String()+" via "+r.Router.String())
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestTheTableTakesTheUnionOfWhatTwoRoutersSaid is RFC 4861 §6.3.4: "Hosts
// accept the union of all received information; the receipt of a Router
// Advertisement MUST NOT invalidate all information received in a previous
// advertisement or from another source."
//
// A TABLE THAT OVERWRITES PASSES EVERY SINGLE-ROUTER TEST. That is why this is
// two routers with disjoint contributions and an assertion on both halves
// after the second advertisement: the second router's arrival is the moment a
// snapshot-shaped table loses the first router's resolver.
func TestTheTableTakesTheUnionOfWhatTwoRoutersSaid(t *testing.T) {
	var tab routerTable

	first := advert("fe80::1", 1800)
	first.RDNSS = []wire.RDNSS{{Lifetime: 600, Addrs: []netip.Addr{netip.MustParseAddr("fd00::53")}}}
	first.DNSSL = []wire.DNSSL{{Lifetime: 600, Names: []string{"one.example"}}}
	first.Routes = []wire.RouteInfo{{Prefix: netip.MustParsePrefix("2001:db8:1::/48"), Lifetime: 600}}
	first.MTU = 1500
	if !tab.observe(at(0), first) {
		t.Fatal("the first advertisement contributed nothing")
	}

	second := advert("fe80::2", 1800)
	second.RDNSS = []wire.RDNSS{{Lifetime: 600, Addrs: []netip.Addr{netip.MustParseAddr("fd00::54")}}}
	second.DNSSL = []wire.DNSSL{{Lifetime: 600, Names: []string{"two.example"}}}
	second.Routes = []wire.RouteInfo{{Prefix: netip.MustParsePrefix("2001:db8:2::/48"), Lifetime: 600}}
	if !tab.observe(at(1), second) {
		t.Fatal("the second advertisement contributed nothing")
	}

	obs := observation(t, &tab, at(2))
	if want := []string{"fe80::1", "fe80::2"}; !equalStrings(addrTexts(obs.Routers), want) {
		t.Errorf("default routers %v, want %v in the order they were first heard", addrTexts(obs.Routers), want)
	}
	if want := []string{"fd00::53", "fd00::54"}; !equalStrings(addrTexts(obs.DNS), want) {
		t.Errorf("resolvers %v, want %v", addrTexts(obs.DNS), want)
	}
	if want := []string{"one.example", "two.example"}; !equalStrings(obs.Search, want) {
		t.Errorf("search list %v, want %v", obs.Search, want)
	}
	if want := []string{"2001:db8:1::/48 via fe80::1", "2001:db8:2::/48 via fe80::2"}; !equalStrings(routesOf(obs.Routes), want) {
		t.Errorf("routes %v, want %v", routesOf(obs.Routes), want)
	}
	// §6.3.4's other half: the MTU the first router set is not cleared by a
	// second advertisement that carries none. "In such cases, the parameter
	// should be ignored and the host should continue using whatever value it
	// is already using."
	if obs.MTU != 1500 {
		t.Errorf("MTU %d after an advertisement carrying no MTU option, want the one still in use", obs.MTU)
	}
}

// TestTheSamePrefixFromTwoRoutersIsTwoRoutes drives RFC 4191 §2.3's own reason
// for the preference field — "when multiple identical prefixes (for different
// routers) have been received" — and the withdrawal that tells a table keyed on
// the prefix alone from one keyed on the router and the prefix.
func TestTheSamePrefixFromTwoRoutersIsTwoRoutes(t *testing.T) {
	pfx := netip.MustParsePrefix("2001:db8:aa::/48")
	for _, tc := range []struct {
		name       string
		withdrawer string
		survivor   string
	}{
		{"the first router withdraws", "fe80::1", "fe80::2"},
		{"the second router withdraws", "fe80::2", "fe80::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var tab routerTable
			one := advert("fe80::1", 1800)
			one.Routes = []wire.RouteInfo{{Prefix: pfx, Pref: wire.RoutePrefLow, Lifetime: 600}}
			tab.observe(at(0), one)
			two := advert("fe80::2", 1800)
			two.Routes = []wire.RouteInfo{{Prefix: pfx, Pref: wire.RoutePrefHigh, Lifetime: 600}}
			tab.observe(at(1), two)

			if obs := observation(t, &tab, at(2)); len(obs.Routes) != 2 {
				t.Fatalf("%v; one prefix from two routers is two routes", routesOf(obs.Routes))
			}

			gone := advert(tc.withdrawer, 1800)
			gone.Routes = []wire.RouteInfo{{Prefix: pfx, Lifetime: 0}}
			tab.observe(at(3), gone)

			obs := observation(t, &tab, at(4))
			if want := []string{pfx.String() + " via " + tc.survivor}; !equalStrings(routesOf(obs.Routes), want) {
				t.Errorf("routes %v, want %v", routesOf(obs.Routes), want)
			}
		})
	}
}

// TestTheRoutesAreOrderedMostPreferredFirst is what the signed preference is
// for. The fixture advertises them in the wrong order on purpose, and the
// medium pair pins the tie-break so the result does not depend on the sort
// being stable by accident.
func TestTheRoutesAreOrderedMostPreferredFirst(t *testing.T) {
	var tab routerTable
	ra := advert("fe80::1", 1800)
	ra.Routes = []wire.RouteInfo{
		{Prefix: netip.MustParsePrefix("2001:db8:10::/48"), Pref: wire.RoutePrefLow, Lifetime: 600},
		{Prefix: netip.MustParsePrefix("2001:db8:20::/48"), Pref: wire.RoutePrefMedium, Lifetime: 600},
		{Prefix: netip.MustParsePrefix("2001:db8:30::/48"), Pref: wire.RoutePrefHigh, Lifetime: 600},
		{Prefix: netip.MustParsePrefix("2001:db8:40::/48"), Pref: wire.RoutePrefMedium, Lifetime: 600},
	}
	tab.observe(at(0), ra)
	obs := observation(t, &tab, at(1))
	want := []string{
		"2001:db8:30::/48 via fe80::1",
		"2001:db8:20::/48 via fe80::1",
		"2001:db8:40::/48 via fe80::1",
		"2001:db8:10::/48 via fe80::1",
	}
	if !equalStrings(routesOf(obs.Routes), want) {
		t.Errorf("routes %v, want %v", routesOf(obs.Routes), want)
	}
}

// TestAZeroLifetimeWithdrawsTheEntryItNames drives the three withdrawals,
// each quoted where it is implemented: RFC 8106 §5.1 "A value of zero means
// that the RDNSS addresses MUST no longer be used", §5.2's same semantics for
// the search list, and RFC 4861 §6.3.4 "If the address is already present in
// the host's Default Router List and the received Router Lifetime value is
// zero, immediately time-out the entry".
//
// EACH ARM ASSERTS ITS SIBLINGS SURVIVED. A table that dropped everything on a
// zero lifetime would pass every one of them read alone.
func TestAZeroLifetimeWithdrawsTheEntryItNames(t *testing.T) {
	build := func() *routerTable {
		var tab routerTable
		ra := advert("fe80::1", 1800)
		ra.RDNSS = []wire.RDNSS{{Lifetime: 600, Addrs: []netip.Addr{netip.MustParseAddr("fd00::53")}}}
		ra.DNSSL = []wire.DNSSL{{Lifetime: 600, Names: []string{"lan"}}}
		ra.Routes = []wire.RouteInfo{{Prefix: netip.MustParsePrefix("2001:db8::/48"), Lifetime: 600}}
		ra.MTU = 1400
		tab.observe(at(0), ra)
		return &tab
	}

	t.Run("the resolver", func(t *testing.T) {
		tab := build()
		ra := advert("fe80::1", 1800)
		ra.RDNSS = []wire.RDNSS{{Lifetime: 0, Addrs: []netip.Addr{netip.MustParseAddr("fd00::53")}}}
		tab.observe(at(1), ra)
		obs := observation(t, tab, at(2))
		if len(obs.DNS) != 0 {
			t.Errorf("resolvers %v after a zero-lifetime RDNSS naming the only one", addrTexts(obs.DNS))
		}
		if len(obs.Routers) != 1 || len(obs.Search) != 1 || len(obs.Routes) != 1 || obs.MTU != 1400 {
			t.Errorf("the withdrawal took its siblings with it: %s", obs)
		}
	})

	t.Run("the search domain", func(t *testing.T) {
		tab := build()
		ra := advert("fe80::1", 1800)
		ra.DNSSL = []wire.DNSSL{{Lifetime: 0, Names: []string{"lan"}}}
		tab.observe(at(1), ra)
		obs := observation(t, tab, at(2))
		if len(obs.Search) != 0 {
			t.Errorf("search list %v after a zero-lifetime DNSSL naming the only name", obs.Search)
		}
		if len(obs.Routers) != 1 || len(obs.DNS) != 1 || len(obs.Routes) != 1 {
			t.Errorf("the withdrawal took its siblings with it: %s", obs)
		}
	})

	t.Run("the route", func(t *testing.T) {
		tab := build()
		ra := advert("fe80::1", 1800)
		ra.Routes = []wire.RouteInfo{{Prefix: netip.MustParsePrefix("2001:db8::/48"), Lifetime: 0}}
		tab.observe(at(1), ra)
		obs := observation(t, tab, at(2))
		if len(obs.Routes) != 0 {
			t.Errorf("routes %v after a zero-lifetime Route Information Option naming the only one", routesOf(obs.Routes))
		}
		if len(obs.Routers) != 1 || len(obs.DNS) != 1 || len(obs.Search) != 1 {
			t.Errorf("the withdrawal took its siblings with it: %s", obs)
		}
	})

	t.Run("the default router, which keeps its options", func(t *testing.T) {
		tab := build()
		tab.observe(at(1), advert("fe80::1", 0))
		obs := observation(t, tab, at(2))
		if len(obs.Routers) != 0 {
			t.Errorf("default routers %v after Router Lifetime zero", addrTexts(obs.Routers))
		}
		// RFC 4861 §4.2: "The Router Lifetime applies only to the router's
		// usefulness as a default router; it does not apply to information
		// contained in other message fields or options."
		if len(obs.DNS) != 1 || len(obs.Search) != 1 || len(obs.Routes) != 1 || obs.MTU != 1400 {
			t.Errorf("a router that stopped being a default router took its own options with it: %s", obs)
		}
	})
}

// TestARouterNeverSeenBeforeWithLifetimeZeroIsNotADefaultRouter is §6.3.4's
// first bullet read for what it does NOT say to do: "If the address is not
// already present in the host's Default Router List, and the advertisement's
// Router Lifetime is non-zero, create a new entry in the list". The options of
// such an advertisement are still the link's.
func TestARouterNeverSeenBeforeWithLifetimeZeroIsNotADefaultRouter(t *testing.T) {
	var tab routerTable
	ra := advert("fe80::9", 0)
	ra.MTU = 1400
	ra.RDNSS = []wire.RDNSS{{Lifetime: 1800, Addrs: []netip.Addr{netip.MustParseAddr("fd00::53")}}}
	ra.Routes = []wire.RouteInfo{{Prefix: netip.MustParsePrefix("2001:db8::/48"), Lifetime: 1800}}
	tab.observe(at(0), ra)

	obs := observation(t, &tab, at(1))
	if len(obs.Routers) != 0 {
		t.Errorf("default routers %v from an advertisement with Router Lifetime zero", addrTexts(obs.Routers))
	}
	if obs.MTU != 1400 || len(obs.DNS) != 1 || len(obs.Routes) != 1 {
		t.Errorf("the options of a non-default router were dropped: %s", obs)
	}
}

// TestEachEntryExpiresOnItsOwnLifetime is the pair that tells a per-entry timer
// from one timer over the whole table, and it is driven in both directions for
// that reason. RFC 4861 §4.2: "The Router Lifetime applies only to the router's
// usefulness as a default router ... Options that need time limits for their
// information include their own lifetime fields." RFC 8106 §6.1: "Note that the
// DNS information for the RDNSS and DNSSL options need not be dropped if the
// expiry of the RA router lifetime happens."
func TestEachEntryExpiresOnItsOwnLifetime(t *testing.T) {
	t.Run("a short resolver under a long router", func(t *testing.T) {
		var tab routerTable
		ra := advert("fe80::1", 1800)
		ra.RDNSS = []wire.RDNSS{{Lifetime: 30, Addrs: []netip.Addr{netip.MustParseAddr("fd00::53")}}}
		ra.DNSSL = []wire.DNSSL{{Lifetime: 1800, Names: []string{"lan"}}}
		tab.observe(at(0), ra)

		if obs := observation(t, &tab, at(29)); len(obs.DNS) != 1 {
			t.Fatalf("the resolver was gone at t+29 with a lifetime of 30: %s", obs)
		}
		obs := observation(t, &tab, at(31))
		if len(obs.DNS) != 0 {
			t.Errorf("resolvers %v at t+31 with a lifetime of 30", addrTexts(obs.DNS))
		}
		if len(obs.Routers) != 1 || len(obs.Search) != 1 {
			t.Errorf("the resolver's expiry took the gateway or the search list with it: %s", obs)
		}
	})

	t.Run("a short router under a long resolver", func(t *testing.T) {
		var tab routerTable
		ra := advert("fe80::1", 30)
		ra.RDNSS = []wire.RDNSS{{Lifetime: 1800, Addrs: []netip.Addr{netip.MustParseAddr("fd00::53")}}}
		tab.observe(at(0), ra)

		if obs := observation(t, &tab, at(29)); len(obs.Routers) != 1 {
			t.Fatalf("the router was gone at t+29 with a lifetime of 30: %s", obs)
		}
		obs := observation(t, &tab, at(31))
		if len(obs.Routers) != 0 {
			t.Errorf("default routers %v at t+31 with a Router Lifetime of 30", addrTexts(obs.Routers))
		}
		if len(obs.DNS) != 1 {
			t.Errorf("the router's expiry took the resolver with it: %s", obs)
		}
	})
}

// TestTheRouterLifetimeIsSixteenBitsAndHasNoInfinity is RFC 4861 §4.2's
// "Router Lifetime 16-bit unsigned integer. ... The field can contain values up
// to 65535 and receivers should handle any value", set against the 32-bit
// options where "A value of all one bits (0xffffffff) represents infinity". The
// boundary pair is the assertion: 65535 is eighteen hours and not eternity.
func TestTheRouterLifetimeIsSixteenBitsAndHasNoInfinity(t *testing.T) {
	var tab routerTable
	ra := advert("fe80::1", 65535)
	ra.RDNSS = []wire.RDNSS{{Lifetime: 0xFFFFFFFF, Addrs: []netip.Addr{netip.MustParseAddr("fd00::53")}}}
	ra.Routes = []wire.RouteInfo{{Prefix: netip.MustParsePrefix("2001:db8::/48"), Lifetime: 0xFFFFFFFF}}
	tab.observe(at(0), ra)

	if obs := observation(t, &tab, at(65534)); len(obs.Routers) != 1 {
		t.Fatalf("the default router was gone one second before its lifetime ran out: %s", obs)
	}
	obs := observation(t, &tab, at(65535))
	if len(obs.Routers) != 0 {
		t.Errorf("the default router survived its whole 16-bit lifetime: %s", obs)
	}
	// The two entries that DO carry an infinity outlive it by definition.
	if len(obs.DNS) != 1 || len(obs.Routes) != 1 {
		t.Errorf("an infinite RDNSS or route lifetime expired: %s", obs)
	}
	// AND AT AN INSTANT PAST 0xffffffff SECONDS, which is what tells an
	// infinite entry from one whose deadline is now plus that number: 1<<33
	// seconds is about two hundred and seventy years, and 0xffffffff is about
	// a hundred and thirty-six. It is also the largest power of two this
	// clock can carry — an Instant is nanoseconds in an int64, so at(1<<40)
	// overflows and the comparison it feeds means nothing. MEASURED: with
	// at(1<<40) here, the mutant that reads 0xffffffff as an ordinary
	// lifetime SURVIVED.
	if obs := observation(t, &tab, at(1<<33)); len(obs.DNS) != 1 || len(obs.Routes) != 1 {
		t.Errorf("an infinite lifetime expired eventually, which is not what infinity is: %s", obs)
	}
}

// TestTheMTUIsBoundedBelowByTheMinimumLinkMTU drives RFC 4861 §6.3.4's "hosts
// SHOULD copy the option's value into LinkMTU so long as the value is greater
// than or equal to the minimum link MTU [IPv6]", whose value is RFC 8200 §5's,
// and the surface bound above it. The 1279/1280 pair is the boundary; 1280
// alone passes against a table with no lower bound at all.
func TestTheMTUIsBoundedBelowByTheMinimumLinkMTU(t *testing.T) {
	for _, tc := range []struct {
		mtu  uint32
		want uint32
	}{
		{0, 0},
		{1, 0},
		{1279, 0},
		{1280, 1280},
		{1500, 1500},
		{9000, 9000},
		{0xFFFFFFFF, 0},
	} {
		t.Run(fmt.Sprint(tc.mtu), func(t *testing.T) {
			var tab routerTable
			ra := advert("fe80::1", 1800)
			ra.MTU = tc.mtu
			tab.observe(at(0), ra)
			obs := observation(t, &tab, at(1))
			if obs.MTU != tc.want {
				t.Errorf("an advertised MTU of %d was reported as %d, want %d", tc.mtu, obs.MTU, tc.want)
			}
			if int(obs.MTU) < 0 {
				t.Errorf("the reported MTU is negative as an int: %d", int(obs.MTU))
			}
		})
	}
}

// TestAnAdvertisementWithNoSourceAddressNamesNoRouter pins the key the whole
// table is built on, RFC 4861 §6.3.4: "On receipt of a valid Router
// Advertisement, a host extracts the source address of the packet". An
// advertisement that reaches ring 1 without one is a caller that did not fill
// it in; taking the zero address would merge every such advertisement into one
// router that does not exist.
func TestAnAdvertisementWithNoSourceAddressNamesNoRouter(t *testing.T) {
	var tab routerTable
	ra := &wire.RouterAdvert{Managed: true, RouterLifetime: 1800}
	ra.RDNSS = []wire.RDNSS{{Lifetime: 600, Addrs: []netip.Addr{netip.MustParseAddr("fd00::53")}}}
	if tab.observe(at(0), ra) {
		t.Fatal("an advertisement with no source address was accepted into the table")
	}
	if tab.observe(at(0), nil) {
		t.Fatal("a nil advertisement was accepted into the table")
	}
	obs := observation(t, &tab, at(1))
	if len(obs.Routers) != 0 || len(obs.DNS) != 0 {
		t.Errorf("the table holds %s from an advertisement that named no router", obs)
	}
}

// TestTheTableCapsHoldAtLeastWhatTheStandardsRequire is the floor under the
// caps, derived from the standards rather than from today's values: RFC 4861
// §6.3.4 "a host MUST retain at least two router addresses and SHOULD retain
// more" and RFC 8106 §5.3.1 "the ability to store a total of at least three
// RDNSS addresses (or DNSSL domain names) from the multiple sources is
// RECOMMENDED".
func TestTheTableCapsHoldAtLeastWhatTheStandardsRequire(t *testing.T) {
	if maxRouters < minRoutersFloor {
		t.Errorf("maxRouters is %d, under RFC 4861 §6.3.4's floor of %d", maxRouters, minRoutersFloor)
	}
	if maxRouterDNS < minDNSFloor {
		t.Errorf("maxRouterDNS is %d, under RFC 8106 §5.3.1's floor of %d", maxRouterDNS, minDNSFloor)
	}
	if maxRouterSearch < minSearchFloor {
		t.Errorf("maxRouterSearch is %d, under RFC 8106 §5.3.1's floor of %d", maxRouterSearch, minSearchFloor)
	}
	if maxRouterRoutes < 1 {
		t.Errorf("maxRouterRoutes is %d", maxRouterRoutes)
	}
}

// TestTheTableIsBoundedAndSaysSoWhenItRefuses floods the table from more
// sources than a link has and asserts the three things a bound has to have:
// a size that stops, the entries that survive, and a count of what was refused.
//
// THE FLOOD IS REPEATED, which is the arm that tells a table keyed on the
// source address from one that appends: the second pass adds nothing at all,
// and a table without a key would double.
func TestTheTableIsBoundedAndSaysSoWhenItRefuses(t *testing.T) {
	var tab routerTable
	flood := func(base int64) {
		for i := range 500 {
			ra := advert(fmt.Sprintf("fe80::%x", i+1), 1800)
			ra.RDNSS = []wire.RDNSS{{Lifetime: 600, Addrs: []netip.Addr{netip.MustParseAddr(fmt.Sprintf("fd00::%x", i+1))}}}
			ra.DNSSL = []wire.DNSSL{{Lifetime: 600, Names: []string{fmt.Sprintf("n%d.example", i)}}}
			ra.Routes = []wire.RouteInfo{{Prefix: netip.MustParsePrefix(fmt.Sprintf("2001:db8:%x::/48", i+1)), Lifetime: 600}}
			tab.observe(at(base+int64(i)), ra)
		}
	}
	flood(0)
	afterOne := observation(t, &tab, at(500))
	switch {
	case len(afterOne.Routers) != maxRouters:
		t.Fatalf("%d default routers after 500 advertisements, want the cap %d", len(afterOne.Routers), maxRouters)
	case len(afterOne.DNS) != maxRouterDNS:
		t.Fatalf("%d resolvers, want the cap %d", len(afterOne.DNS), maxRouterDNS)
	case len(afterOne.Search) != maxRouterSearch:
		t.Fatalf("%d search domains, want the cap %d", len(afterOne.Search), maxRouterSearch)
	case len(afterOne.Routes) != maxRouterRoutes:
		t.Fatalf("%d routes, want the cap %d", len(afterOne.Routes), maxRouterRoutes)
	}
	// What survives is what arrived FIRST, and the join order is what decides
	// whether that is the router the client wants: on a link the client was
	// already on, its own router is in the table before the flood starts; on a
	// link that was already flooding when the client joined, the flood is what
	// arrived first and the real router is the entry refused. Neither policy
	// wins that link — RA-Guard and SEND are what do, and neither is this
	// library's — so what is asserted here is the order, not a defence.
	if afterOne.Routers[0] != netip.MustParseAddr("fe80::1") {
		t.Errorf("the first router heard is not the first one held: %v", addrTexts(afterOne.Routers))
	}
	if tab.dropped == 0 {
		t.Error("500 advertisements filled every list and nothing was counted as refused")
	}

	dropped := tab.dropped
	flood(500)
	afterTwo := observation(t, &tab, at(1000))
	if len(afterTwo.Routers) != len(afterOne.Routers) || len(afterTwo.Routes) != len(afterOne.Routes) {
		t.Errorf("the same 500 advertisements a second time changed the table size from %d/%d to %d/%d",
			len(afterOne.Routers), len(afterOne.Routes), len(afterTwo.Routers), len(afterTwo.Routes))
	}
	if !equalStrings(addrTexts(afterTwo.Routers), addrTexts(afterOne.Routers)) {
		t.Errorf("the second pass replaced the routers held: %v then %v", addrTexts(afterOne.Routers), addrTexts(afterTwo.Routers))
	}
	if tab.dropped <= dropped {
		t.Error("the second flood was refused silently")
	}
}

// TestAnExpiredEntryMakesRoomForANewOne is the other direction of the cap: it
// bounds what is HELD, not how many advertisements a link may ever send.
func TestAnExpiredEntryMakesRoomForANewOne(t *testing.T) {
	var tab routerTable
	for i := range maxRouters {
		tab.observe(at(0), advert(fmt.Sprintf("fe80::%x", i+1), 30))
	}
	if obs := observation(t, &tab, at(1)); len(obs.Routers) != maxRouters {
		t.Fatalf("%d default routers, want the cap %d", len(obs.Routers), maxRouters)
	}
	// Every one of them has gone, so the table is empty and the next router is
	// taken rather than refused.
	tab.observe(at(31), advert("fe80::ffff", 1800))
	obs := observation(t, &tab, at(32))
	if want := []string{"fe80::ffff"}; !equalStrings(addrTexts(obs.Routers), want) {
		t.Errorf("default routers %v after every earlier entry expired, want %v", addrTexts(obs.Routers), want)
	}
}

// TestTheObservationHoldsNoSliceOfTheAdvertisement is the aliasing rule at the
// ring boundary: the same *wire.RouterAdvert reaches ring 2's capture ring, so
// a machine holding its slices would share them with whatever reads that ring.
func TestTheObservationHoldsNoSliceOfTheAdvertisement(t *testing.T) {
	m := newMachine6(t, testParams6())
	ra := advert("fe80::1", 1800)
	ra.Prefixes = []wire.PrefixInfo{{PrefixLen: 64, Prefix: netip.MustParseAddr("fd00:98::"), Autonomous: true}}
	m.Step(at(0), 1, RouterAdvert(ra))

	ra.Prefixes[0].Prefix = netip.MustParseAddr("2001:db8::")
	ra.Prefixes[0].Autonomous = false

	got := m.Router()
	if len(got.Prefixes) != 1 {
		t.Fatalf("%d prefix(es) in the observation", len(got.Prefixes))
	}
	if got.Prefixes[0].Prefix != netip.MustParseAddr("fd00:98::") || !got.Prefixes[0].Autonomous {
		t.Errorf("the observation followed a later edit of the advertisement it was built from: %s", got.Prefixes[0])
	}
}

// TestTheObservationIsAgedByAnyStepAndNotOnlyByAnAdvertisement is the bound
// RouterObservation states, driven rather than asserted in prose: the table is
// pruned from the now every Step is handed, so a link whose router has gone
// quiet stops reporting the gateway that timed out.
func TestTheObservationIsAgedByAnyStepAndNotOnlyByAnAdvertisement(t *testing.T) {
	m := newMachine6(t, testParams6())
	ra := advert("fe80::1", 30)
	ra.RDNSS = []wire.RDNSS{{Lifetime: 1800, Addrs: []netip.Addr{netip.MustParseAddr("fd00::53")}}}
	m.Step(at(0), 1, RouterAdvert(ra))
	if got := m.Router(); len(got.Routers) != 1 {
		t.Fatalf("the advertisement named no default router: %s", got)
	}

	// Any event at all, with no further advertisement.
	m.Step(at(31), 2, TimerFired(Timer6Retransmit))
	got := m.Router()
	if len(got.Routers) != 0 {
		t.Errorf("the gateway of a router whose lifetime ran out is still reported: %s", got)
	}
	if !got.Seen || got.Router != netip.MustParseAddr("fe80::1") {
		t.Errorf("ageing the table forgot that a router was ever seen: %s", got)
	}
	if len(got.DNS) != 1 {
		t.Errorf("ageing took the resolver, whose own lifetime has not run out: %s", got)
	}
}

// raWithOptions is raManaged followed by one RDNSS option and one Route
// Information option, built from RFC 8106 §5.1's and RFC 4191 §2.3's field
// diagrams so a journal test drives real bytes rather than a struct literal
// the decoder never saw.
func raWithOptions(resolver string, prefix netip.Prefix) []byte {
	out := append([]byte(nil), raManaged...)
	rdnss := make([]byte, 24)
	rdnss[0], rdnss[1] = 25, 3
	rdnss[4], rdnss[5], rdnss[6], rdnss[7] = 0, 0, 2, 88 // lifetime 600
	copy(rdnss[8:], netip.MustParseAddr(resolver).AsSlice())
	rio := make([]byte, 24)
	rio[0], rio[1], rio[2] = 24, 3, uint8(prefix.Bits())
	rio[4], rio[5], rio[6], rio[7] = 0, 0, 2, 88
	copy(rio[8:], prefix.Addr().AsSlice())
	return append(append(out, rdnss...), rio...)
}

// TestAReplayedAdvertisementKeepsTheRouterItCameFrom is defeat row D-8 and the
// M7a carried-row shape: the source address is NOT in the ICMPv6 bytes, so a
// journal that stores only the bytes replays every advertisement as coming
// from nowhere and the replayed table is not the table that ran.
//
// THE TWO ROUTERS ARE THE ASSERTION. A replay that dropped the address would
// still reproduce one router's resolvers; it is the union, keyed on two
// different sources, that a zero-address replay collapses.
func TestAReplayedAdvertisementKeepsTheRouterItCameFrom(t *testing.T) {
	p := testParams6()
	r := newRecord6(t, p)
	r.step(at(0), 0, Simple(EvStart))

	for i, from := range []string{"fe80::1", "fe80::2"} {
		raw := raWithOptions(
			fmt.Sprintf("fd00::5%d", i+3),
			netip.MustParsePrefix(fmt.Sprintf("2001:db8:%d::/48", i+1)),
		)
		ra := mustRA(t, raw)
		ra.Router = netip.MustParseAddr(from)
		r.step(at(int64(i+1)), 0, RouterAdvertRaw(ra, raw))
	}

	live := r.m.Router()
	if len(live.Routers) != 2 || len(live.DNS) != 2 || len(live.Routes) != 2 {
		t.Fatalf("the recorded run did not build the table it was supposed to: %s", live)
	}

	if _, err := Replay6(p, r.entries); err != nil {
		t.Fatalf("Replay6: %v", err)
	}

	// Replay6 compares states and actions; the table is not part of either, so
	// it is rebuilt here from the journal's own reconstructed events and
	// compared against the run that produced them.
	again := newMachine6(t, p)
	for _, e := range r.entries {
		ev, err := e.Event()
		if err != nil {
			t.Fatalf("entry %d: %v", e.Seq, err)
		}
		again.Step(e.Now, e.Rnd, ev)
	}
	replayed := again.Router()
	if replayed.String() != live.String() {
		t.Errorf("the replayed observation is\n  %s\nand the recorded one is\n  %s", replayed, live)
	}
	if !equalStrings(addrTexts(replayed.Routers), []string{"fe80::1", "fe80::2"}) {
		t.Errorf("the replayed default routers are %v", addrTexts(replayed.Routers))
	}
	if !equalStrings(routesOf(replayed.Routes), []string{"2001:db8:1::/48 via fe80::1", "2001:db8:2::/48 via fe80::2"}) {
		t.Errorf("the replayed routes are %v", routesOf(replayed.Routes))
	}
}

// TestARouterThatWentAwayKeepsItsSeatUntilItsLifetimeRunsOut is the cost of the
// refuse-the-new policy, driven rather than left for a caller to find.
//
// THE PRUNE REMOVES WHAT HAS EXPIRED, NOT WHAT HAS GONE QUIET. A router that
// advertised the sending rules' maximum of 9000 seconds and then vanished holds
// its seat for two and a half hours, and a table full of those refuses a router
// that is real and is advertising now. It is the same bound from the other
// side as TestAnExpiredEntryMakesRoomForANewOne: room is made by time running
// out and by nothing else.
func TestARouterThatWentAwayKeepsItsSeatUntilItsLifetimeRunsOut(t *testing.T) {
	var tab routerTable
	for i := range maxRouters {
		tab.observe(at(0), advert(fmt.Sprintf("fe80::%x", i+1), 9000))
	}
	dropped := tab.dropped

	// Every one of the eight has been silent since, and every one of them is
	// still inside the lifetime it advertised.
	tab.observe(at(8000), advert("fe80::ffff", 1800))
	obs := observation(t, &tab, at(8001))
	if len(obs.Routers) != maxRouters {
		t.Fatalf("%d default routers, want the cap %d", len(obs.Routers), maxRouters)
	}
	for _, a := range obs.Routers {
		if a.String() == "fe80::ffff" {
			t.Fatalf("the ninth router was taken: %v", addrTexts(obs.Routers))
		}
	}
	if tab.dropped <= dropped {
		t.Error("the router the table refused was not counted")
	}

	// Past their lifetimes it is taken, which is what says the refusal above
	// was the cap and not the address.
	tab.observe(at(9001), advert("fe80::ffff", 1800))
	after := observation(t, &tab, at(9002))
	if want := []string{"fe80::ffff"}; !equalStrings(addrTexts(after.Routers), want) {
		t.Errorf("default routers %v once every seat expired, want %v", addrTexts(after.Routers), want)
	}
}
