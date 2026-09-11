// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package lease

import (
	"net/netip"
	"runtime"
	"testing"

	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

// The addresses the advertisement fixtures below carry. They are outside the
// fixture server's own ranges so a lease field filled from the advertisement
// cannot be mistaken for one filled from DHCPv6.
const (
	raRouter   = "fe80::abcd"
	raResolver = "fd00:99::53"
	raSearch   = "ra.invalid"
	raPrefix   = "2001:db8:beef::/48"
	raMTU      = 1492
)

// raWithEveryOption is a Router Advertisement with M and O set carrying one of
// each option this library reads, in the order dnsmasq emits them: MTU (5),
// Route Information (24), RDNSS (25), DNSSL (31). It is built from the RFC
// field diagrams rather than by the encoder, because there is no encoder: this
// library never sends an advertisement.
func raWithEveryOption() []byte {
	out := []byte{
		134, 0, 0, 0,
		64, 0xC0, 0x07, 0x08,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
	// RFC 4861 §4.6.4: Type 5, Length 1, two reserved octets, MTU.
	out = append(out, 5, 1, 0, 0, 0, 0, byte(raMTU>>8), byte(raMTU&0xFF))
	// RFC 4191 §2.3: Type 24, Length 3, Prefix Length, Prf in bits 3-4,
	// Route Lifetime, then the prefix.
	pfx := netip.MustParsePrefix(raPrefix)
	rio := make([]byte, 24)
	rio[0], rio[1], rio[2], rio[3] = 24, 3, byte(pfx.Bits()), 0x08 // Prf high
	rio[4], rio[5], rio[6], rio[7] = 0, 0, 0x02, 0x58              // 600
	copy(rio[8:], pfx.Addr().AsSlice())
	out = append(out, rio...)
	// RFC 8106 §5.1: Type 25, Length 3, two reserved octets, Lifetime, one
	// address.
	rdnss := make([]byte, 24)
	rdnss[0], rdnss[1] = 25, 3
	rdnss[4], rdnss[5], rdnss[6], rdnss[7] = 0, 0, 0x02, 0x58
	copy(rdnss[8:], netip.MustParseAddr(raResolver).AsSlice())
	out = append(out, rdnss...)
	// RFC 8106 §5.2: Type 31, Length 2, two reserved octets, Lifetime, then
	// the domain in RFC 1035 §3.1 label form, zero-padded to the length.
	dnssl := make([]byte, 24)
	dnssl[0], dnssl[1] = 31, 3
	dnssl[4], dnssl[5], dnssl[6], dnssl[7] = 0, 0, 0x02, 0x58
	dnssl[8], dnssl[9], dnssl[10] = 2, 'r', 'a'
	dnssl[11] = 7
	copy(dnssl[12:], "invalid")
	out = append(out, dnssl...)
	return out
}

// waitRA blocks until the machine has stepped a Router Advertisement.
func waitRA(t *testing.T, r *rig6, what string) {
	t.Helper()
	r.journal.waitAppended(t, what, func(e proto.JournalEntry6) bool {
		return e.Kind == proto.EvRouterAdvert
	})
}

// TestTheAddressTheSocketReadIsTheRouterTheTableKeysOn is defeat row D-7 at the
// ring that owns the fact: RFC 4861 §6.3.4 keys everything on "the source
// address of the packet", which is not in the ICMPv6 body at all. The port
// carries it beside the frame and this ring stamps it on.
//
// THE SECOND HALF IS THE ONE THAT BITES. A frame arriving with no source is a
// port that lost it, and taking the zero address would merge every such frame
// into one router that does not exist — so the assertion is that the table
// does NOT grow.
func TestTheAddressTheSocketReadIsTheRouterTheTableKeysOn(t *testing.T) {
	r := newRig6(t, testParams6(), answerNormally6(t))
	r.acquire6(t)

	r.nd.injectFrom(raWithEveryOption(), raRouter)
	waitRA(t, r, "the Router Advertisement")

	obs := r.mgr.Router()
	if obs.Router.String() != raRouter {
		t.Errorf("the observation names router %s, want %s", obs.Router, raRouter)
	}
	if len(obs.Routers) != 1 || obs.Routers[0].String() != raRouter {
		t.Errorf("the default router list is %v, want the one address the socket read", obs.Routers)
	}
	if len(obs.Routes) != 1 || obs.Routes[0].Router.String() != raRouter {
		t.Errorf("the advertised route is %v, want it via %s", obs.Routes, raRouter)
	}

	r.nd.inject(raWithEveryOption())
	waitRA(t, r, "the advertisement with no source address")
	after := r.mgr.Router()
	if len(after.Routers) != 1 {
		t.Errorf("the default router list is %v after a frame that named no source", after.Routers)
	}
	for _, rt := range after.Routes {
		if !rt.Router.IsValid() || rt.Router.IsUnspecified() {
			t.Errorf("a route is held via %s, which is no router", rt.Router)
		}
	}
}

// TestABrokenAdvertisementIsNotTheSameAsNoAdvertisement is defeat row D-10 and
// the second of the reviewer's base-tree measurements: before this change a
// refused advertisement bumped NDSeen and NDIgnored, the same pair a Neighbor
// Advertisement bumps, so a link whose router sends advertisements this
// decoder refuses read as a link with no router at all. The ICMPv6 type octet
// is what separates them, and it is in the frame the caller still has.
func TestABrokenAdvertisementIsNotTheSameAsNoAdvertisement(t *testing.T) {
	r := newRig6(t, testParams6(), answerNormally6(t))
	r.acquire6(t)
	before := r.mgr.Stats()

	// A Router Advertisement with an option whose length octet is zero: RFC
	// 4861 §4.6 "Nodes MUST silently discard an ND packet that contains an
	// option with length zero."
	broken := append(raWithEveryOption()[:16], 5, 0, 0, 0, 0, 0, 5, 0xDC)
	r.nd.inject(broken)
	// A Neighbor Advertisement, which is not this ring's to read at all.
	r.nd.inject([]byte{136, 0, 0, 0, 0, 0, 0, 0})
	r.nd.injectFrom(raWithEveryOption(), raRouter)
	waitRA(t, r, "the advertisement after the two refusals")
	after := r.mgr.Stats()

	if got := after.RouterAdvertsRefused - before.RouterAdvertsRefused; got != 1 {
		t.Errorf("RouterAdvertsRefused moved by %d over a broken advertisement and a Neighbor Advertisement, want 1", got)
	}
	if got := after.NDIgnored - before.NDIgnored; got != 2 {
		t.Errorf("NDIgnored moved by %d, want 2: both frames were dropped", got)
	}
	if got := after.RouterAdvertsSeen - before.RouterAdvertsSeen; got != 1 {
		t.Errorf("RouterAdvertsSeen moved by %d, want 1: only the last frame decoded", got)
	}
}

// TestAnOptionThisLibraryRefusesIsCountedAndItsSiblingsAreNot drives the other
// refusal level end to end, RFC 8106 §5.3.1's "the host MUST discard the
// options" and RFC 4191 §2.3's "the Route Information Option MUST be ignored":
// a recognised option that is invalid by its own document costs that option
// and nothing else, and the count says so.
func TestAnOptionThisLibraryRefusesIsCountedAndItsSiblingsAreNot(t *testing.T) {
	r := newRig6(t, testParams6(), answerNormally6(t))
	r.acquire6(t)
	before := r.mgr.Stats()

	// An MTU option whose length is 2 units, which RFC 4861 §4.6.4 fixes at 1.
	bad := append(raWithEveryOption(), 5, 2, 0, 0, 0, 0, 5, 0xDC, 0, 0, 0, 0, 0, 0, 0, 0)
	r.nd.injectFrom(bad, raRouter)
	waitRA(t, r, "the advertisement carrying one bad option")
	after := r.mgr.Stats()

	if got := after.RouterAdvertOptionsIgnored - before.RouterAdvertOptionsIgnored; got != 1 {
		t.Errorf("RouterAdvertOptionsIgnored moved by %d, want exactly 1", got)
	}
	if got := after.RouterAdvertsRefused - before.RouterAdvertsRefused; got != 0 {
		t.Errorf("RouterAdvertsRefused moved by %d; one bad option is not a bad message", got)
	}
	obs := r.mgr.Router()
	if obs.MTU != raMTU {
		t.Errorf("the observation reports MTU %d, want the good option's %d", obs.MTU, raMTU)
	}
	if len(obs.DNS) != 1 || len(obs.Search) != 1 || len(obs.Routes) != 1 {
		t.Errorf("one refused option took its siblings with it: %s", obs)
	}
}

// awaitRouterSeen spins until the manager has STEPPED an advertisement.
//
// IT DOES NOT READ THE JOURNAL, and that is the whole reason it exists. The
// journal barrier is a channel every waiter CONSUMES from, so a wait for the
// advertisement throws away whatever else was queued behind it — and on this
// rig the exchange that ends in a duplicate-address request is queued behind
// it. MEASURED: the first shape of the test below waited for the
// advertisement's journal entry and then hung for its whole timeout in
// waitDADRequested, because the entry naming the request had already been read
// and discarded by that wait.
func awaitRouterSeen(t *testing.T, r *rig6) proto.RouterObservation {
	t.Helper()
	for {
		if obs := r.mgr.Router(); obs.Seen {
			return obs
		}
		runtime.Gosched()
	}
}

// TestTheV6LeaseCarriesWhatTheRouterAdvertised is the surface #814 asks for:
// the caller reads the gateway, the link MTU, the resolvers, the search list
// and the routes off the lease it already has, without knowing that some of
// them arrived on a different protocol.
//
// THE ORDER OF THE RESOLVERS IS THE ASSERTION, not their presence. RFC 8106
// §5.3.1: "the DNS information from DHCP takes precedence over that from RAs",
// so the fixture makes both sources non-empty and reads the positions.
//
// IT IS READ OFF Lease() AND NOT OFF THE Acquired EVENT, because the two
// protocols have no ordering between them: an advertisement that arrives after
// the Reply cannot appear in an event already emitted, and this library emits
// no event of its own when the router's view changes. The event path is driven
// by the renewal below, where the ordering IS fixed.
func TestTheV6LeaseCarriesWhatTheRouterAdvertised(t *testing.T) {
	r := newRig6(t, testParams6(), answerNormally6(t))
	acquired := r.acquire6(t)
	if len(acquired.Lease.DNS) != 1 {
		t.Fatalf("the acquired lease carries DNS %v; the fixture sends exactly one", acquired.Lease.DNS)
	}

	r.nd.injectFrom(raWithEveryOption(), raRouter)
	awaitRouterSeen(t, r)

	l, held := r.mgr.Lease()
	if !held {
		t.Fatal("the manager holds no lease")
	}
	if l.Gateway.String() != raRouter {
		t.Errorf("the lease names gateway %s, want %s: DHCPv6 has no gateway option at all", l.Gateway, raRouter)
	}
	if l.MTU != raMTU {
		t.Errorf("the lease names MTU %d, want %d", l.MTU, raMTU)
	}
	if len(l.DNS) != 2 || l.DNS[0].String() != test6DNS || l.DNS[1].String() != raResolver {
		t.Errorf("the lease carries DNS %v, want DHCP's %s first and the advertisement's %s after it", l.DNS, test6DNS, raResolver)
	}
	if len(l.DomainSearch) != 2 || l.DomainSearch[0] != test6Search || l.DomainSearch[1] != raSearch {
		t.Errorf("the lease carries the search list %v, want DHCP's %s first", l.DomainSearch, test6Search)
	}
	if len(l.Routes) != 1 || l.Routes[0].Dest.String() != raPrefix || l.Routes[0].Router.String() != raRouter {
		t.Errorf("the lease carries routes %v, want %s via %s", l.Routes, raPrefix, raRouter)
	}

	// READ IT TWICE. withRouterAdvert appends to the lease's own lists, and a
	// lease whose slice had spare capacity would grow one entry per reader.
	again, _ := r.mgr.Lease()
	if len(again.DNS) != len(l.DNS) || len(again.DomainSearch) != len(l.DomainSearch) || len(again.Routes) != len(l.Routes) {
		t.Errorf("reading the lease twice changed it: %d/%d/%d then %d/%d/%d",
			len(l.DNS), len(l.DomainSearch), len(l.Routes),
			len(again.DNS), len(again.DomainSearch), len(again.Routes))
	}

	// ------------------------------------------------- the event path --
	//
	// The next event the caller is told about carries the same view, and by
	// here the ordering is settled: the advertisement has been stepped and
	// the renewal has not happened yet.
	renewAt, ok := r.timers.armedAt(proto.Timer6Renew)
	if !ok {
		t.Fatal("no renewal timer is armed on a held v6 lease")
	}
	r.clock.advance(renewAt)
	r.timers.fire(proto.Timer6Renew)
	ev := r.nextEvent(t)
	if ev.Kind != Renewed {
		t.Fatalf("the event after T1 is %s, want renewed", ev.Kind)
	}
	if ev.Lease.Gateway.String() != raRouter || ev.Lease.MTU != raMTU {
		t.Errorf("the renewed event carries gateway %s and MTU %d, want %s and %d", ev.Lease.Gateway, ev.Lease.MTU, raRouter, raMTU)
	}
	if len(ev.Lease.DNS) != 2 || ev.Lease.DNS[1].String() != raResolver {
		t.Errorf("the renewed event carries DNS %v", ev.Lease.DNS)
	}
	if !ev.Router.Seen || ev.Router.Router.String() != raRouter {
		t.Errorf("the renewed event reports the router as %s", ev.Router)
	}
}

// TestTheAdvertisedViewFillsOnlyWhatTheLeaseDoesNotHave drives the precedence
// rules withRouterAdvert states, at the function rather than through a rig,
// because the case each rule is FOR cannot be built on this link: DHCPv6 has
// no gateway option and no MTU option, so a v6 lease that already carries one
// is a lease from a source this library does not have yet.
//
// A RULE WITH NO OBSERVER IS A SENTENCE. RFC 8106 §5.3.1 is the reason the
// single-valued fields are filled only when absent — "the DNS information from
// DHCP takes precedence over that from RAs" read for a field that can hold one
// value — and a fill that overwrote would be invisible until the day something
// else sets them.
func TestTheAdvertisedViewFillsOnlyWhatTheLeaseDoesNotHave(t *testing.T) {
	obs := proto.RouterObservation{
		Seen:    true,
		Router:  netip.MustParseAddr(raRouter),
		Routers: []netip.Addr{netip.MustParseAddr(raRouter)},
		MTU:     raMTU,
	}

	t.Run("a lease that carries neither", func(t *testing.T) {
		got := withRouterAdvert(Lease{}, obs)
		if got.Gateway.String() != raRouter || got.MTU != raMTU {
			t.Errorf("the advertised gateway and MTU did not reach an empty lease: %s / %d", got.Gateway, got.MTU)
		}
	})

	t.Run("a lease that carries both", func(t *testing.T) {
		held := Lease{Gateway: netip.MustParseAddr("fe80::dead"), MTU: 9000}
		got := withRouterAdvert(held, obs)
		if got.Gateway != held.Gateway {
			t.Errorf("the advertisement replaced the gateway %s with %s", held.Gateway, got.Gateway)
		}
		if got.MTU != held.MTU {
			t.Errorf("the advertisement replaced the MTU %d with %d", held.MTU, got.MTU)
		}
	})
}

// TestTheAdvertisedViewNeverWritesIntoTheLeaseItWasGiven is the aliasing rule,
// and it is driven with SPARE CAPACITY because that is the only shape in which
// it can fail: appending to a slice whose backing array has room writes into
// the array the caller still holds, which here is the manager's stored lease.
// A fixture built by a decoder gives its slices exact capacity and would pass
// against either version.
func TestTheAdvertisedViewNeverWritesIntoTheLeaseItWasGiven(t *testing.T) {
	search := make([]string, 1, 4)
	search[0] = test6Search
	dns := make([]netip.Addr, 1, 4)
	dns[0] = netip.MustParseAddr(test6DNS)
	routes := make([]wire.Route, 0, 4)

	held := Lease{DNS: dns, DomainSearch: search, Routes: routes}
	obs := proto.RouterObservation{
		Seen:   true,
		Router: netip.MustParseAddr(raRouter),
		DNS:    []netip.Addr{netip.MustParseAddr(raResolver)},
		Search: []string{raSearch},
		Routes: []wire.Route{{Dest: netip.MustParsePrefix(raPrefix), Router: netip.MustParseAddr(raRouter)}},
	}

	merged := withRouterAdvert(held, obs)
	if len(merged.DomainSearch) != 2 || len(merged.DNS) != 2 || len(merged.Routes) != 1 {
		t.Fatalf("the merge did not happen: %v / %v / %v", merged.DomainSearch, merged.DNS, merged.Routes)
	}

	// The caller's own slices, read through their full capacity: nothing the
	// merge appended may appear in them.
	if got := search[:cap(search)][1]; got != "" {
		t.Errorf("the merge wrote %q into the lease's own search-list array", got)
	}
	if got := dns[:cap(dns)][1]; got.IsValid() {
		t.Errorf("the merge wrote %s into the lease's own DNS array", got)
	}
	if got := routes[:cap(routes)][0]; got.Dest.IsValid() {
		t.Errorf("the merge wrote %s into the lease's own route array", got.Dest)
	}
	if len(held.DomainSearch) != 1 || len(held.DNS) != 1 || len(held.Routes) != 0 {
		t.Errorf("the lease passed in grew: %v / %v / %v", held.DomainSearch, held.DNS, held.Routes)
	}
}
