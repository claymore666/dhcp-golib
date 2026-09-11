// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"math"
	"net/netip"
	"sort"

	"github.com/claymore666/dhcp-golib/wire"
)

// The router table: what this client has been told by the routers on its link,
// and until when.
//
// IT IS A UNION AND NOT A LAST-ADVERTISEMENT SNAPSHOT, RFC 4861 §6.3.4: "When
// multiple routers are present, the information advertised collectively by all
// routers may be a superset of the information contained in a single Router
// Advertisement. Moreover, information may also be obtained through other
// dynamic means like DHCPv6. Hosts accept the union of all received
// information; the receipt of a Router Advertisement MUST NOT invalidate all
// information received in a previous advertisement or from another source.
// However, when received information for a specific parameter (e.g., Link MTU)
// or option (e.g., Lifetime on a specific Prefix) differs from information
// received earlier, and the parameter/option can only have one value, the most
// recently received information is considered authoritative."
//
// EVERY LIST EXPIRES PER ENTRY AND NOT PER ROUTER, which is the sentence that
// decides the shape. RFC 4861 §4.2: "The Router Lifetime applies only to the
// router's usefulness as a default router; it does not apply to information
// contained in other message fields or options. Options that need time limits
// for their information include their own lifetime fields." RFC 8106 §6.1 says
// the same from the DNS side: "Note that the DNS information for the RDNSS and
// DNSSL options need not be dropped if the expiry of the RA router lifetime
// happens. This is because these options have their own lifetime values." So a
// router that stops being a default router leaves its resolver and its routes
// behind until their own lifetimes run out, and a table holding one timer per
// router would drop them with it.
//
// THERE IS NO TIMER HERE AND THAT IS DELIBERATE FOR L1. Expiry is applied from
// the now every Step is handed, and from nothing else: nothing is scheduled, so
// there is no action, no event and no wake-up of a client that is otherwise
// quiet.
//
// WHICH MEANS THE TABLE IS CORRECT AS OF THE LAST Step AND NOT AS OF THE READ.
// Every read of it — Machine6.Router, and through that lease.Manager.Lease —
// is a read of what the last Step left behind, so an entry whose lifetime ran
// out while the machine took no Step is still reported, and the report is
// corrected by the next Step rather than by a wake-up. On a link with a router
// that is advertising, the next advertisement is the next Step; on a link that
// has gone quiet, the stale window is as long as the caller's own silence. The
// bound is stated at both surfaces a caller can reach — RouterObservation's doc
// and Manager.Lease's — and driven by
// lease.TestTheRouterViewOnTheLeaseIsAsOfTheLastStep. Closing it needs a timer
// and an event, which is the chassis's half of #821.

// The caps, and the RFC floor each one may not fall below.
//
// A TABLE WITH NO CAP IS A LINK'S WORTH OF MEMORY A STRANGER CHOOSES. Every
// entry here is created by a frame this host did not ask for, and the manager
// already filters Neighbor Discovery for the same reason one ring down — an
// unfiltered feed wraps the bounded journal between one acquisition and the
// next. The floors are the standards' own: RFC 4861 §6.3.4 "To limit the
// storage needed for the Default Router List, a host MAY choose not to store
// all of the router addresses discovered via advertisements. However, a host
// MUST retain at least two router addresses and SHOULD retain more.", and RFC
// 8106 §5.3.1 "the ability to store a total of at least three RDNSS addresses
// (or DNSSL domain names) from the multiple sources is RECOMMENDED".
//
// A FULL LIST REFUSES THE NEW ENTRY RATHER THAN EVICTING AN OLD ONE, so what a
// full table holds is what it heard FIRST. Both policies lose to a router
// flood — that is what RA-Guard and SEND are for, and neither is this
// library's — and which one loses the router the client has been using all
// along is decided by the join order, not by the policy: a client already on
// the link has its own router in the table before the flood starts, and a
// client joining a link that is already flooding does not.
//
// THE PRICE IS PAID BY A LINK WITH NO ATTACKER ON IT TOO. The table is pruned
// of what has EXPIRED, not of what has gone quiet, so routers that advertised
// a long lifetime and then vanished hold their seats for as long as they said
// — up to §6.2.1's 9000 seconds — and a full table of those refuses a router
// that is real and advertising now. Driven both ways:
// TestARouterThatWentAwayKeepsItsSeatUntilItsLifetimeRunsOut and
// TestAnExpiredEntryMakesRoomForANewOne. The refusals are counted; see
// routerTable.dropped.
const (
	maxRouters      = 8
	maxRouterDNS    = 8
	maxRouterSearch = 8
	maxRouterRoutes = 16

	// The floors the caps above are checked against, quoted in the comment.
	minRoutersFloor = 2
	minDNSFloor     = 3
	minSearchFloor  = 3
)

// minLinkMTU is RFC 8200 §5's minimum IPv6 link MTU, which is the bound RFC
// 4861 §6.3.4 names when it says what a host may copy out of an MTU option:
// "If the MTU option is present, hosts SHOULD copy the option's value into
// LinkMTU so long as the value is greater than or equal to the minimum link
// MTU [IPv6] and does not exceed the maximum LinkMTU value specified in the
// link-type-specific document (e.g., [IPv6-ETHER])."
//
// THE UPPER HALF OF THAT CONDITION IS NOT APPLIED HERE, and the reason is the
// same one that makes this library apply nothing to the link: the maximum is
// the link TYPE's, and ring 1 has no link, no interface and no link type. A
// caller that knows its interface refuses a value above its own maximum; what
// is refused here is only a value that cannot be reported at all, see
// RouterObservation.MTU.
const minLinkMTU = 1280

// maxReportableMTU is the largest value the table copies, and its bound is the
// SURFACE rather than any link: the observation and lease.Lease both carry the
// MTU as an int, which is 32 bits wide on a 32-bit build. A value above this is
// not an MTU reported wrongly, it is one that cannot be reported at all, and
// silently truncating 0xffffffff into a negative int is the shape this refuses.
const maxReportableMTU = math.MaxInt32

// timedEntry is what every list in the table is made of: a value that is valid
// until an Instant, or forever.
//
// FOREVER IS A FLAG AND NOT A LARGE Instant. Three of the four lifetimes here
// encode infinity as 0xffffffff (RFC 4191 §2.3 and RFC 8106 §5.1 both say "A
// value of all one bits (0xffffffff) represents infinity") and Duration's
// Infinite is already a sentinel rather than a magnitude; an Instant far in the
// future would make "is this still valid" a comparison against an arbitrary
// number, which is exactly what proto.Infinite exists to avoid.
type timedEntry struct {
	until   Instant
	forever bool
}

func entryUntil(now Instant, secs uint32) timedEntry {
	if d := SecondsToDuration(secs); d.IsInfinite() {
		return timedEntry{forever: true}
	}
	return timedEntry{until: now.Add(Duration(secs) * Second)}
}

// routerLifetimeUntil converts RFC 4861 §4.2's Router Lifetime, which is
// SIXTEEN bits and has no infinity: "Router Lifetime 16-bit unsigned integer.
// The lifetime associated with the default router in units of seconds. The
// field can contain values up to 65535 and receivers should handle any value,
// while the sending rules in Section 6 limit the lifetime to 9000 seconds."
//
// IT IS A SEPARATE FUNCTION FROM entryUntil FOR EXACTLY THAT REASON. 65535 is a
// finite eighteen hours here and 0xffffffff is forever there; one conversion
// serving both would either turn the largest router lifetime into eternity or
// make the DNS option's own infinity finite.
func routerLifetimeUntil(now Instant, secs uint16) timedEntry {
	return timedEntry{until: now.Add(Duration(secs) * Second)}
}

func (e timedEntry) live(now Instant) bool { return e.forever || now.Before(e.until) }

type routerEntry struct {
	addr netip.Addr
	// deflt is the Default Router List membership of §6.3.4. A router that
	// advertised Router Lifetime zero is still a router whose options are
	// held; it is not a default router.
	deflt   timedEntry
	isDeflt bool
	seq     int
}

type dnsEntry struct {
	addr netip.Addr
	life timedEntry
	seq  int
}

type searchEntry struct {
	name string
	life timedEntry
	seq  int
}

type routeEntry struct {
	prefix netip.Prefix
	via    netip.Addr
	pref   wire.RoutePreference
	life   timedEntry
	seq    int
}

// routerTable is the union above, per machine.
type routerTable struct {
	routers []routerEntry
	dns     []dnsEntry
	search  []searchEntry
	routes  []routeEntry

	// mtu is single-valued, so §6.3.4's "the most recently received
	// information is considered authoritative" decides it and there is no
	// lifetime to hold: an MTU option carries none. An advertisement that
	// carries no MTU option leaves it alone, §6.3.4: "In such cases, the
	// parameter should be ignored and the host should continue using whatever
	// value it is already using. In particular, a host MUST NOT interpret the
	// unspecified value as meaning change back to the default value that was
	// in use before the first Router Advertisement was received."
	mtu uint32

	// dropped counts entries a full list refused. It only ever rises.
	dropped uint64

	seq int
}

// observe applies one advertisement, RFC 4861 §6.3.4 and RFC 8106 §6.2.
//
// AN ADVERTISEMENT WITH NO SOURCE ADDRESS CONTRIBUTES NOTHING, and it is
// refused here rather than keyed on the zero address: §6.3.4's first step is
// "a host extracts the source address of the packet", every list below records
// which router said it, and a table that accepted the zero address would merge
// every such advertisement into one router that does not exist. The caller is
// told by the false return so it can journal it; the M and O flags of the same
// frame are still read, because those are the message's and not the router's.
func (t *routerTable) observe(now Instant, ra *wire.RouterAdvert) bool {
	if ra == nil || !ra.Router.IsValid() {
		return false
	}
	// PRUNED BEFORE ANYTHING IS ADDED, because the caps below bound what the
	// table HOLDS and not how many advertisements a link may send. A table
	// still carrying eight routers that all timed out would refuse the ninth
	// that replaced them, which is a link that can never recover from its
	// routers being renumbered.
	t.prune(now)
	t.observeRouterLifetime(now, ra)
	t.observeMTU(ra)
	for _, r := range ra.RDNSS {
		t.observeRDNSS(now, r)
	}
	for _, d := range ra.DNSSL {
		t.observeDNSSL(now, d)
	}
	for _, rt := range ra.Routes {
		t.observeRoute(now, ra.Router, rt)
	}
	t.prune(now)
	return true
}

// observeRouterLifetime is §6.3.4's three bullets on the Default Router List:
// "If the address is not already present in the host's Default Router List,
// and the advertisement's Router Lifetime is non-zero, create a new entry in
// the list, and initialize its invalidation timer value from the
// advertisement's Router Lifetime field.", "If the address is already present
// in the host's Default Router List as a result of a previously received
// advertisement, reset its invalidation timer to the Router Lifetime value in
// the newly received advertisement.", "If the address is already present in
// the host's Default Router List and the received Router Lifetime value is
// zero, immediately time-out the entry as specified in Section 6.3.5."
func (t *routerTable) observeRouterLifetime(now Instant, ra *wire.RouterAdvert) {
	for i := range t.routers {
		if t.routers[i].addr != ra.Router {
			continue
		}
		if ra.RouterLifetime == 0 {
			t.routers[i].isDeflt = false
			return
		}
		t.routers[i].isDeflt = true
		t.routers[i].deflt = routerLifetimeUntil(now, ra.RouterLifetime)
		return
	}
	if len(t.routers) >= maxRouters {
		t.dropped++
		return
	}
	t.seq++
	e := routerEntry{addr: ra.Router, seq: t.seq}
	if ra.RouterLifetime != 0 {
		e.isDeflt = true
		e.deflt = routerLifetimeUntil(now, ra.RouterLifetime)
	}
	t.routers = append(t.routers, e)
}

func (t *routerTable) observeMTU(ra *wire.RouterAdvert) {
	if ra.MTU == 0 {
		return
	}
	if ra.MTU < minLinkMTU || ra.MTU > maxReportableMTU {
		t.dropped++
		return
	}
	t.mtu = ra.MTU
}

// observeRDNSS is RFC 8106 §6.2's steps (b) and (c): "For each RDNSS address,
// check the following: If the RDNSS address already exists in the DNS Server
// List and the RDNSS option's Lifetime field is set to zero, delete the
// corresponding RDNSS entry from both the DNS Server List and the Resolver
// Repository" and, otherwise, the entry's "Expiration-time is set to the value
// of the Lifetime field of the RDNSS option or DNSSL option plus the current
// time. Whenever a new RDNSS option with the same address ... is received on
// the same interface as a previous RDNSS option ..., this field is updated to
// have a new Expiration-time." (§6.1)
func (t *routerTable) observeRDNSS(now Instant, r wire.RDNSS) {
	for _, a := range r.Addrs {
		idx := -1
		for i := range t.dns {
			if t.dns[i].addr == a {
				idx = i
				break
			}
		}
		if r.Lifetime == 0 {
			if idx >= 0 {
				t.dns = append(t.dns[:idx], t.dns[idx+1:]...)
			}
			continue
		}
		if idx >= 0 {
			t.dns[idx].life = entryUntil(now, r.Lifetime)
			continue
		}
		if len(t.dns) >= maxRouterDNS {
			t.dropped++
			continue
		}
		t.seq++
		t.dns = append(t.dns, dnsEntry{addr: a, life: entryUntil(now, r.Lifetime), seq: t.seq})
	}
}

// observeDNSSL is the same three rules for the search list, §5.2: the DNSSL
// "Lifetime value has the same semantics as the semantics for the RDNSS
// option".
func (t *routerTable) observeDNSSL(now Instant, d wire.DNSSL) {
	for _, n := range d.Names {
		idx := -1
		for i := range t.search {
			if t.search[i].name == n {
				idx = i
				break
			}
		}
		if d.Lifetime == 0 {
			if idx >= 0 {
				t.search = append(t.search[:idx], t.search[idx+1:]...)
			}
			continue
		}
		if idx >= 0 {
			t.search[idx].life = entryUntil(now, d.Lifetime)
			continue
		}
		if len(t.search) >= maxRouterSearch {
			t.dropped++
			continue
		}
		t.seq++
		t.search = append(t.search, searchEntry{name: n, life: entryUntil(now, d.Lifetime), seq: t.seq})
	}
}

// observeRoute keys a Route Information option on the ROUTER AND the prefix,
// which is RFC 4191 §2.3's own model: the preference exists "when multiple
// identical prefixes (for different routers) have been received", so the same
// prefix from two routers is two routes and not one that overwrites the other.
// §2.3 forbids a repeat inside one advertisement — "Routers MUST NOT include
// two Route Information Options with the same Prefix and Prefix Length in the
// same Router Advertisement" — and says nothing about two routers, which is
// the case this key exists for. A zero Route Lifetime deletes the entry, §3.1:
// the lifetime is "the length of time ... that the prefix is valid for route
// determination".
func (t *routerTable) observeRoute(now Instant, via netip.Addr, ri wire.RouteInfo) {
	idx := -1
	for i := range t.routes {
		if t.routes[i].via == via && t.routes[i].prefix == ri.Prefix {
			idx = i
			break
		}
	}
	if ri.Lifetime == 0 {
		if idx >= 0 {
			t.routes = append(t.routes[:idx], t.routes[idx+1:]...)
		}
		return
	}
	if idx >= 0 {
		t.routes[idx].pref = ri.Pref
		t.routes[idx].life = entryUntil(now, ri.Lifetime)
		return
	}
	if len(t.routes) >= maxRouterRoutes {
		t.dropped++
		return
	}
	t.seq++
	t.routes = append(t.routes, routeEntry{
		prefix: ri.Prefix, via: via, pref: ri.Pref,
		life: entryUntil(now, ri.Lifetime), seq: t.seq,
	})
}

// prune drops what has expired as of now.
//
// A ROUTER ENTRY OUTLIVES ITS DEFAULT-ROUTER STATUS and is removed only when it
// carries nothing: §4.2's "The Router Lifetime applies only to the router's
// usefulness as a default router" is what makes those two different facts, and
// MEASURED kernel behaviour agrees (a router lifetime of zero removes the
// default route and leaves the addresses).
func (t *routerTable) prune(now Instant) {
	for i := range t.routers {
		if t.routers[i].isDeflt && !t.routers[i].deflt.live(now) {
			t.routers[i].isDeflt = false
		}
	}
	dns := t.dns[:0]
	for _, e := range t.dns {
		if e.life.live(now) {
			dns = append(dns, e)
		}
	}
	t.dns = dns
	search := t.search[:0]
	for _, e := range t.search {
		if e.life.live(now) {
			search = append(search, e)
		}
	}
	t.search = search
	routes := t.routes[:0]
	for _, e := range t.routes {
		if e.life.live(now) {
			routes = append(routes, e)
		}
	}
	t.routes = routes
	routers := t.routers[:0]
	for _, e := range t.routers {
		if e.isDeflt || t.holdsSomethingOf(e.addr) {
			routers = append(routers, e)
		}
	}
	t.routers = routers
}

// holdsSomethingOf reports whether any live route still names this router as
// its next hop. The DNS and search lists are not consulted: RFC 8106 §6.1
// keeps them per interface and not per router — "Note that the DNS information
// for the RDNSS and DNSSL options need not be dropped if the expiry of the RA
// router lifetime happens" — so an entry there belongs to the link and outlives
// whichever router announced it.
func (t *routerTable) holdsSomethingOf(addr netip.Addr) bool {
	for _, r := range t.routes {
		if r.via == addr {
			return true
		}
	}
	return false
}

// fill writes the table's live view into an observation.
func (t *routerTable) fill(now Instant, out *RouterObservation) {
	t.prune(now)
	out.Routers = nil
	for _, r := range t.routers {
		if r.isDeflt {
			out.Routers = append(out.Routers, r.addr)
		}
	}
	out.MTU = t.mtu
	out.DNS = nil
	for _, e := range t.dns {
		out.DNS = append(out.DNS, e.addr)
	}
	out.Search = nil
	for _, e := range t.search {
		out.Search = append(out.Search, e.name)
	}
	// SORTED BY PREFERENCE, WHICH IS THE WHOLE OF WHAT THE PREFERENCE IS FOR.
	// RFC 4191 §2.3: the Prf "indicates whether to prefer the router
	// associated with this prefix over others, when multiple identical
	// prefixes (for different routers) have been received." A consumer reads
	// this list in order; carrying the number instead and asking every
	// consumer to sort would be the ordering derived once per consumer.
	// Arrival order breaks the tie, so the result does not depend on the sort.
	live := append([]routeEntry(nil), t.routes...)
	sort.SliceStable(live, func(i, j int) bool {
		if live[i].pref != live[j].pref {
			return live[i].pref > live[j].pref
		}
		return live[i].seq < live[j].seq
	})
	out.Routes = nil
	for _, e := range live {
		out.Routes = append(out.Routes, wire.Route{Dest: e.prefix, Router: e.via})
	}
}
