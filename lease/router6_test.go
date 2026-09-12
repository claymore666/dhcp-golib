// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package lease

import (
	"net/netip"
	"runtime"
	"strings"
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

// TestAnUnusableMTUReachesTheOperatorAsAnIgnoredOptionAndNotACapInForce is the
// ring-2 half: the same advertisement read through Stats and through the
// record's own field, which is where an operator actually meets these numbers.
//
// THE LINK IS QUIET AND NOTHING IS FULL. One router, one MTU option below RFC
// 8200 §5's minimum link MTU, no routes, resolvers or search domains. Stats
// documents RouterTableEntriesDropped as an arrival a full list would not take
// and says either it or its eviction pair above zero means the caps are in
// force, so on this link both must stay where they were and the option count
// must move by one. The record's serialised field is asserted beside them,
// because that is the copy that outlives the process.
func TestAnUnusableMTUReachesTheOperatorAsAnIgnoredOptionAndNotACapInForce(t *testing.T) {
	r := newRig6(t, testParams6(), answerNormally6(t))
	r.acquire6(t)
	before := r.mgr.Stats()

	ra := []byte{
		134, 0, 0, 0,
		64, 0x40, 0x07, 0x08,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
	// RFC 4861 §4.6.4: Type 5, Length 1, two reserved octets, then the MTU.
	ra = append(ra, 5, 1, 0, 0, 0, 0, 0x03, 0xE8) // 1000
	r.nd.injectFrom(ra, raRouter)
	waitRA(t, r, "the advertisement carrying one unusable MTU")
	after := r.mgr.Stats()

	if got := after.RouterAdvertOptionsIgnored - before.RouterAdvertOptionsIgnored; got != 1 {
		t.Errorf("RouterAdvertOptionsIgnored moved by %d, want 1: the MTU was walked past", got)
	}
	if got := after.RouterTableEntriesDropped - before.RouterTableEntriesDropped; got != 0 {
		t.Errorf("RouterTableEntriesDropped moved by %d: no list was full", got)
	}
	if got := after.RouterTableEntriesEvicted - before.RouterTableEntriesEvicted; got != 0 {
		t.Errorf("RouterTableEntriesEvicted moved by %d: nothing held was thrown out", got)
	}
	if got := after.RouterAdvertsRefused - before.RouterAdvertsRefused; got != 0 {
		t.Errorf("RouterAdvertsRefused moved by %d: the message decoded", got)
	}
	if obs := r.mgr.Router(); obs.MTU != 0 {
		t.Errorf("an MTU of 1000 was reported as %d, want 0", obs.MTU)
	}

	w := statsIntoWire(after)
	b := statsIntoWire(before)
	if got := w.RouterAdvertOptionsIgnored - b.RouterAdvertOptionsIgnored; got != 1 {
		t.Errorf("the record carries %d ignored option(s), want 1", got)
	}
	if got := w.RouterTableEntriesDropped - b.RouterTableEntriesDropped; got != 0 {
		t.Errorf("the record serialises %d table drop(s) for one bad MTU", got)
	}
	if got := w.RouterTableEntriesEvicted - b.RouterTableEntriesEvicted; got != 0 {
		t.Errorf("the record serialises %d eviction(s) for one bad MTU", got)
	}
}

// TestTheDecodersIgnoredOptionsAndRingOnesAreOneNumber is the control on the
// sum: the field has TWO producers now, and a version that dropped either half
// or counted one of them twice is what this drives. One advertisement carries
// an option the DECODER refuses by its own standard's length rule and an MTU
// RING ONE refuses by its value, so the operator's number must move by exactly
// two.
func TestTheDecodersIgnoredOptionsAndRingOnesAreOneNumber(t *testing.T) {
	r := newRig6(t, testParams6(), answerNormally6(t))
	r.acquire6(t)
	before := r.mgr.Stats()

	ra := []byte{
		134, 0, 0, 0,
		64, 0x40, 0x07, 0x08,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
	// An MTU option whose length is 2 units, which RFC 4861 §4.6.4 fixes at 1:
	// the decoder's half.
	ra = append(ra, 5, 2, 0, 0, 0, 0, 5, 0xDC, 0, 0, 0, 0, 0, 0, 0, 0)
	// And a well-formed MTU option whose value this ring may not copy.
	ra = append(ra, 5, 1, 0, 0, 0, 0, 0x03, 0xE8) // 1000
	r.nd.injectFrom(ra, raRouter)
	waitRA(t, r, "the advertisement carrying one of each refusal")
	after := r.mgr.Stats()

	if got := after.RouterAdvertOptionsIgnored - before.RouterAdvertOptionsIgnored; got != 2 {
		t.Errorf("RouterAdvertOptionsIgnored moved by %d, want 2: one option per ring", got)
	}
	if got := after.RouterTableEntriesDropped - before.RouterTableEntriesDropped; got != 0 {
		t.Errorf("RouterTableEntriesDropped moved by %d: no list was full", got)
	}

	// AND THE SECOND ADVERTISEMENT ADDS ONE, NOT ITS PREDECESSOR AGAIN. Ring
	// one's counter is a cumulative TOTAL and this field is an accumulator, so
	// a version that added the total at every Step would read three after two
	// advertisements: one, then one plus two. One advertisement can never see
	// that, which is why a second one is here.
	r.nd.injectFrom(ra, raRouter)
	waitRA(t, r, "the second advertisement carrying the same two refusals")
	third := r.mgr.Stats()
	if got := third.RouterAdvertOptionsIgnored - after.RouterAdvertOptionsIgnored; got != 2 {
		t.Errorf("the second advertisement moved RouterAdvertOptionsIgnored by %d, want 2: "+
			"ring one's total is cumulative and only the new part is added", got)
	}
	if got := third.RouterAdvertOptionsIgnored - before.RouterAdvertOptionsIgnored; got != 4 {
		t.Errorf("two advertisements of two refused options each came to %d, want 4", got)
	}
}

// awaitRAStep blocks until the machine has finished with the nth Router
// Advertisement injected into the port, whatever it decided: either Step
// recorded it in the journal, or the port refused the frame before Step ever
// saw it. It returns the manager's router view as of that moment.
//
// IT IS KEYED ON THE EVENT AND NOT ON THE ANSWER, which is the whole point. A
// barrier that spins until the view says what the test expects turns every
// mutant that changes the view into a HANG, and a hang is a third verdict: the
// mutation harness banks it as a refusal rather than as a kill, so the property
// reads as unobserved when it is observed. MEASURED on this file: the "the
// router's source address is not stamped on the advertisement" mutant failed
// three tests at 0.00s and then held the package to its timeout on a fourth.
//
// THE REFUSAL COUNTER IS THE SECOND EXIT because a frame this library discards
// never reaches Step and so is never journalled; without it a barrier waiting
// on the journal hangs on exactly the mutants that refuse more than they should
// — which is the previous version of the Prefix Information rule, row D-9.
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
func awaitRAStep(t *testing.T, r *rig6, nth int) proto.RouterObservation {
	t.Helper()
	for {
		if raSteps(r.journal)+int(r.mgr.Stats().RouterAdvertsRefused) >= nth {
			return r.mgr.Router()
		}
		runtime.Gosched()
	}
}

// raSteps counts the Router Advertisements the journal has recorded. It reads
// Entries rather than waitAppended because that consumes a shared buffered
// channel, so using it as a barrier throws away whatever was queued behind the
// entry waited for.
func raSteps(j *journalRecorder6) int {
	n := 0
	for _, e := range j.Entries() {
		if e.Kind == proto.EvRouterAdvert {
			n++
		}
	}
	return n
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
	awaitRAStep(t, r, 1)

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

// raWithRouterLifetime is a bare advertisement — M and O clear, no options at
// all — from a router that says it is a default router for the given number of
// seconds. RFC 4861 §4.2's Router Lifetime is the two octets after the flags.
func raWithRouterLifetime(secs uint16) []byte {
	return []byte{
		134, 0, 0, 0,
		64, 0x00, byte(secs >> 8), byte(secs),
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
}

// awaitRouterIs waits for the nth advertisement to be disposed of and then
// asserts which router the table keyed on. The wait and the assertion are
// separate for the reason awaitRAStep states: waiting UNTIL the answer is the
// expected one cannot fail, it can only hang.
func awaitRouterIs(t *testing.T, r *rig6, nth int, addr string) proto.RouterObservation {
	t.Helper()
	obs := awaitRAStep(t, r, nth)
	if obs.Router.String() != addr {
		t.Fatalf("after advertisement %d the table's router is %q, want %s", nth, obs.Router, addr)
	}
	return obs
}

// TestTheRouterViewOnTheLeaseIsAsOfTheLastStep drives the bound that both
// surfaces state in prose, because a bound nothing drives is a sentence.
//
// THE MIDDLE ARM ASSERTS THE STALE ANSWER, DELIBERATELY. This client arms no
// timer for a router's expiry — that is the L1/L2 line, and #821's chassis half
// is where it closes — so the table is pruned from the now each Step is handed
// and from nothing else. A caller that reads Lease() long after the last Step
// is told what the last Step left behind. Asserting it here is what stops the
// window from being discovered by a caller instead.
//
// THE THIRD ARM IS WHAT MAKES THE SECOND MEAN ANYTHING. Without it the test
// has one possible verdict and would pass just as well against a table whose
// entries never expire at all: the next Step, here a second router's
// advertisement, drops the entry the first arm put in and the gateway moves.
func TestTheRouterViewOnTheLeaseIsAsOfTheLastStep(t *testing.T) {
	const (
		shortLifetime = 30
		otherRouter   = "fe80::dcba"
	)

	r := newRig6(t, testParams6(), answerNormally6(t))
	r.acquire6(t)

	r.nd.injectFrom(raWithRouterLifetime(shortLifetime), raRouter)
	awaitRouterIs(t, r, 1, raRouter)

	// Inside the lifetime: the router is a default router because it is one.
	r.clock.advance(proto.Duration(shortLifetime-1) * proto.Second)
	l, held := r.mgr.Lease()
	if !held {
		t.Fatal("the manager holds no lease")
	}
	if l.Gateway.String() != raRouter {
		t.Fatalf("one second before its lifetime ran out the lease names gateway %q, want %s", l.Gateway, raRouter)
	}

	// Past the lifetime, with no Step of any kind in between.
	r.clock.advance(2 * proto.Second)
	l, _ = r.mgr.Lease()
	if l.Gateway.String() != raRouter {
		t.Errorf("the lease names gateway %q after the lifetime ran out; the view is a snapshot as of the last Step, not as of the read, and nothing stepped", l.Gateway)
	}

	// The next Step corrects it. The second advertisement is stepped at a now
	// past the first router's lifetime, and observe prunes before it inserts.
	r.nd.injectFrom(raWithRouterLifetime(1800), otherRouter)
	obs := awaitRouterIs(t, r, 2, otherRouter)
	if len(obs.Routers) != 1 || obs.Routers[0].String() != otherRouter {
		t.Fatalf("the default router list is %v after the next Step, want only %s", obs.Routers, otherRouter)
	}
	l, _ = r.mgr.Lease()
	if l.Gateway.String() != otherRouter {
		t.Errorf("the lease names gateway %q after a Step past the first router's lifetime, want %s", l.Gateway, otherRouter)
	}
}

// raWithAMalformedPrefixBesideAGoodOne is the frame the address-formation row
// met on a real link: M and O set, a usable prefix, a second Prefix
// Information option whose Length is 3 where RFC 4861 §4.6.2 gives 4, and a
// resolver behind it.
func raWithAMalformedPrefixBesideAGoodOne() []byte {
	out := []byte{
		134, 0, 0, 0,
		64, 0xC0, 0x07, 0x08,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
	good := make([]byte, 32)
	good[0], good[1], good[2], good[3] = 3, 4, 64, 0xC0 // L and A
	good[7] = 0x3C                                      // valid lifetime 60
	good[11] = 0x1E                                     // preferred lifetime 30
	copy(good[16:32], netip.MustParseAddr(raGoodPrefixAddr).AsSlice())
	out = append(out, good...)

	bad := make([]byte, 24)
	bad[0], bad[1], bad[2] = 3, 3, 64
	out = append(out, bad...)

	rdnss := make([]byte, 24)
	rdnss[0], rdnss[1] = 25, 3
	rdnss[6], rdnss[7] = 0x02, 0x58
	copy(rdnss[8:], netip.MustParseAddr(raResolver).AsSlice())
	return append(out, rdnss...)
}

const raGoodPrefixAddr = "2001:db8:1::"

// TestOneMalformedPrefixDoesNotHideTheRouterThatSentIt is row D-9 closed at the
// ring where it was costing something.
//
// THE OLD VERDICT WAS THE WHOLE MESSAGE. A Prefix Information option of the
// wrong length refused the frame, so this advertisement — a router with a
// lifetime, a usable prefix, M, O and a resolver — reached the caller as
// nothing at all, which is the same answer a link with no router on it gives.
// MEASURED one row up: an endpoint in SLAAC mode then waited out its whole
// discovery window and failed, on a link that was advertising the prefix it
// needed. What is asserted here is everything except the bad option: the
// router is in the table, the good prefix is on the observation, the resolver
// reaches the lease, the frame is NOT counted as refused, and exactly one
// option is counted as ignored.
func TestOneMalformedPrefixDoesNotHideTheRouterThatSentIt(t *testing.T) {
	r := newRig6(t, testParams6(), answerNormally6(t))
	r.acquire6(t)
	before := r.mgr.Stats()

	r.nd.injectFrom(raWithAMalformedPrefixBesideAGoodOne(), raRouter)
	obs := awaitRAStep(t, r, 1)

	if !obs.Managed || !obs.Other {
		t.Errorf("M=%t O=%t: the flags are in the header, and one bad option took them", obs.Managed, obs.Other)
	}
	if len(obs.Routers) != 1 || obs.Routers[0].String() != raRouter {
		t.Errorf("the default router list is %v, want the router that sent the frame", obs.Routers)
	}
	if len(obs.Prefixes) != 1 {
		t.Fatalf("%d prefix(es) on the observation, want the one that is well formed: %v", len(obs.Prefixes), obs.Prefixes)
	}
	if obs.Prefixes[0].Prefix.String() != raGoodPrefixAddr || obs.Prefixes[0].PrefixLen != 64 {
		t.Errorf("the surviving prefix is %s, want %s/64", obs.Prefixes[0], raGoodPrefixAddr)
	}
	if len(obs.DNS) != 1 || obs.DNS[0].String() != raResolver {
		t.Errorf("the resolver behind the bad option is %v", obs.DNS)
	}

	l, held := r.mgr.Lease()
	if !held {
		t.Fatal("the manager holds no lease")
	}
	if l.Gateway.String() != raRouter {
		t.Errorf("the lease names gateway %q, want %s", l.Gateway, raRouter)
	}
	if len(l.DNS) != 2 || l.DNS[1].String() != raResolver {
		t.Errorf("the lease carries DNS %v, want DHCP's first and the advertisement's after it", l.DNS)
	}

	after := r.mgr.Stats()
	if got := after.RouterAdvertsRefused - before.RouterAdvertsRefused; got != 0 {
		t.Errorf("RouterAdvertsRefused moved by %d; one bad option is not a bad message", got)
	}
	if got := after.RouterAdvertOptionsIgnored - before.RouterAdvertOptionsIgnored; got != 1 {
		t.Errorf("RouterAdvertOptionsIgnored moved by %d, want exactly the one option that was refused", got)
	}
	if got := after.RouterAdvertsSeen - before.RouterAdvertsSeen; got != 1 {
		t.Errorf("RouterAdvertsSeen moved by %d, want 1", got)
	}
}

// raFromTheSameBoxAsTheServer is the link the round-1 read named: the DHCPv6
// server and the router are one box, so the resolver and the search domain it
// hands out over DHCP are the same two values it advertises over ND. It also
// carries one of its own of each, so a merge that dropped the whole list would
// be visible as well as one that duplicated it.
func raFromTheSameBoxAsTheServer() []byte {
	out := []byte{
		134, 0, 0, 0,
		64, 0xC0, 0x07, 0x08,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
	// RFC 8106 §5.1: one option, two addresses — the server's own and a
	// second the advertisement alone carries.
	rdnss := make([]byte, 40)
	rdnss[0], rdnss[1] = 25, 5
	rdnss[6], rdnss[7] = 0x02, 0x58
	copy(rdnss[8:24], netip.MustParseAddr(test6DNS).AsSlice())
	copy(rdnss[24:40], netip.MustParseAddr(raResolver).AsSlice())
	out = append(out, rdnss...)

	// RFC 8106 §5.2: "fixture.invalid" and "ra.invalid" in label form, padded
	// to the option length.
	dnssl := make([]byte, 40)
	dnssl[0], dnssl[1] = 31, 5
	dnssl[6], dnssl[7] = 0x02, 0x58
	n := 8
	for _, name := range []string{test6Search, raSearch} {
		for _, label := range strings.Split(name, ".") {
			dnssl[n] = byte(len(label))
			n++
			n += copy(dnssl[n:], label)
		}
		n++ // the root label, already zero
	}
	return append(out, dnssl...)
}

// TestWhatBothProtocolsSentAppearsOnceAndDHCPsCopyIsFirst is the guard the
// round-1 read found unobserved: every fixture until now picked advertisement
// values OUTSIDE the DHCP fixture's ranges, so nothing overlapped and the
// three duplicate checks in withRouterAdvert could each be deleted with the
// suite still green.
//
// THE OVERLAP IS THE NORMAL CASE AND NOT THE EXOTIC ONE. A home gateway is the
// DHCPv6 server and the router, and it hands out its own address as the
// resolver on both protocols; a lease that carried it twice would have a
// caller write it twice into resolv.conf. RFC 8106 §5.3.1 decides the ORDER
// and this decides the COUNT: "the DNS information from DHCP takes precedence
// over that from RAs", so DHCP's copy is the one that keeps its place and the
// advertisement's duplicate is the one that is not added.
func TestWhatBothProtocolsSentAppearsOnceAndDHCPsCopyIsFirst(t *testing.T) {
	r := newRig6(t, testParams6(), answerNormally6(t))
	acquired := r.acquire6(t)
	if len(acquired.Lease.DNS) != 1 || acquired.Lease.DNS[0].String() != test6DNS {
		t.Fatalf("the acquired lease carries DNS %v; the fixture sends exactly %s", acquired.Lease.DNS, test6DNS)
	}
	if len(acquired.Lease.DomainSearch) != 1 || acquired.Lease.DomainSearch[0] != test6Search {
		t.Fatalf("the acquired lease carries the search list %v", acquired.Lease.DomainSearch)
	}

	r.nd.injectFrom(raFromTheSameBoxAsTheServer(), raRouter)
	obs := awaitRAStep(t, r, 1)
	if len(obs.DNS) != 2 || len(obs.Search) != 2 {
		t.Fatalf("the advertisement decoded as %v / %v, want two of each", obs.DNS, obs.Search)
	}

	l, held := r.mgr.Lease()
	if !held {
		t.Fatal("the manager holds no lease")
	}
	wantDNS := []string{test6DNS, raResolver}
	if got := addrStrings(l.DNS); !equalStringSlices(got, wantDNS) {
		t.Errorf("the lease carries DNS %v, want %v: the resolver both protocols sent appears once, DHCP's copy first", got, wantDNS)
	}
	wantSearch := []string{test6Search, raSearch}
	if !equalStringSlices(l.DomainSearch, wantSearch) {
		t.Errorf("the lease carries the search list %v, want %v", l.DomainSearch, wantSearch)
	}

	// Read it twice: the merge runs per read, so a guard that only held the
	// first time would show here.
	again, _ := r.mgr.Lease()
	if got := addrStrings(again.DNS); !equalStringSlices(got, wantDNS) {
		t.Errorf("a second read of the lease carries DNS %v, want %v", got, wantDNS)
	}
}

// TestARouteBothSourcesCarryIsNotAddedTwice is the third of the three guards.
// It is driven at withRouterAdvert and not through the rig because DHCPv6 has
// no route option at all (RFC 9915 defines none), so a v6 lease that already
// carries a route is one from a source this library does not have yet — and a
// guard whose case cannot be built on this link is exactly the guard that
// rots.
func TestARouteBothSourcesCarryIsNotAddedTwice(t *testing.T) {
	shared := wire.Route{
		Dest:   netip.MustParsePrefix(raPrefix),
		Router: netip.MustParseAddr(raRouter),
	}
	other := wire.Route{
		Dest:   netip.MustParsePrefix("2001:db8:dead::/48"),
		Router: netip.MustParseAddr(raRouter),
	}
	held := Lease{Routes: []wire.Route{shared}}
	obs := proto.RouterObservation{
		Seen:   true,
		Router: netip.MustParseAddr(raRouter),
		Routes: []wire.Route{shared, other},
	}

	got := withRouterAdvert(held, obs)
	if len(got.Routes) != 2 {
		t.Fatalf("the lease carries %d route(s), want 2: the shared one once and the new one: %v", len(got.Routes), got.Routes)
	}
	if got.Routes[0] != shared {
		t.Errorf("the first route is %v, want the one the lease already had", got.Routes[0])
	}
	if got.Routes[1] != other {
		t.Errorf("the second route is %v, want %v", got.Routes[1], other)
	}
}

// TestTheLeaseNamesTheRouterThatAdvertisedTheHigherPreference is RFC 4191
// §2.2 seen from the caller: Lease.Gateway is the first entry of the default
// router list, so before this round the gateway was whichever router was heard
// first and a backup that booted first kept it.
func TestTheLeaseNamesTheRouterThatAdvertisedTheHigherPreference(t *testing.T) {
	const (
		backup = "fe80::b"
		real6  = "fe80::a"
	)
	// Two advertisements differing only in the preference bits of the flags
	// octet: 0x00 is §2.1's Medium, 0x08 its High.
	ra := func(prf byte) []byte {
		return []byte{
			134, 0, 0, 0,
			64, prf, 0x07, 0x08,
			0, 0, 0, 0,
			0, 0, 0, 0,
		}
	}

	r := newRig6(t, testParams6(), answerNormally6(t))
	r.acquire6(t)

	r.nd.injectFrom(ra(0x00), backup)
	awaitRouterIs(t, r, 1, backup)
	l, _ := r.mgr.Lease()
	if l.Gateway.String() != backup {
		t.Fatalf("the lease names gateway %q with only the backup heard, want %s", l.Gateway, backup)
	}

	r.nd.injectFrom(ra(0x08), real6)
	awaitRouterIs(t, r, 2, real6)

	l, _ = r.mgr.Lease()
	if l.Gateway.String() != real6 {
		t.Errorf("the lease names gateway %q, want %s: High outranks Medium and the backup was only heard first", l.Gateway, real6)
	}
	obs := r.mgr.Router()
	if len(obs.Routers) != 2 || obs.Routers[0].String() != real6 || obs.Routers[1].String() != backup {
		t.Errorf("the default router list is %v, want the High one first and the Medium one still in it", obs.Routers)
	}
}

func addrStrings(in []netip.Addr) []string {
	out := make([]string, 0, len(in))
	for _, a := range in {
		out = append(out, a.String())
	}
	return out
}

func equalStringSlices(a, b []string) bool {
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
