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
// A FULL LIST IS TWO POLICIES, AND WHICH ONE APPLIES IS DECIDED BY WHETHER A
// STANDARD SAYS. RFC 8106 §6.2 step (d) speaks to a full DNS Server List: "In
// the case where the data structure for the DNS Server List is full of RDNSS
// entries (that is, has more RDNSSes than the sufficient number discussed in
// Section 5.3.1), delete from the DNS Server List the entry with the shortest
// Expiration-time (i.e., the entry that will expire first)", and §6.3 says the
// DNSSL option is processed the same way, so the resolver list and the search
// list EVICT, and which entry goes is settled by evictShortest. Nothing in RFC
// 4861 or RFC 4191 says what a full Default Router
// List or a full route table does — §6.3.4's sentence above is about how many
// a host must be able to store and not about what it does when it will not
// store another — so those two REFUSE, and the boundary is that this library
// does not extend one standard's rule over a list another standard owns.
//
// THE TWO LOSE DIFFERENTLY. A refusal holds what it heard FIRST, so a flood
// that was already running when this client joined the link keeps the real
// router out for as long as it keeps the table full. An eviction holds what
// expires LAST, so a flood displaces the real resolver, and the real resolver
// comes back on its router's next advertisement. Neither is a defence — that
// is what RA-Guard and SEND are for, and neither is this library's — and on a
// link with no flood on it the two differ only in which entry is lost when
// more arrive than fit. They are counted apart, because "an entry was lost"
// with no cause beside it does not say which of the two a reader is looking
// at.
//
// THE PRICE IS PAID BY A LINK WITH NO ATTACKER ON IT TOO. The table is pruned
// of what has EXPIRED, not of what has gone quiet, so routers that advertised
// a long lifetime and then vanished hold their seats for as long as they said
// — up to §6.2.1's 9000 seconds — and a full table of those refuses a router
// that is real and advertising now. Driven both ways:
// TestARouterThatWentAwayKeepsItsSeatUntilItsLifetimeRunsOut and
// TestAnExpiredEntryMakesRoomForANewOne. The refusals and the evictions are
// counted separately; see routerTable.refused and routerTable.evicted.
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

// expiresBefore orders two deadlines, with no deadline last.
//
// AN ENTRY THAT NEVER EXPIRES IS NEVER THE ONE THAT EXPIRES FIRST. The zero
// value of timedEntry.until belongs to the forever case as much as to an
// entry whose deadline has passed, so a comparison on until alone would make
// the one entry a router said to keep forever the first one evicted.
func expiresBefore(a, b timedEntry) bool {
	if a.forever {
		return false
	}
	if b.forever {
		return true
	}
	return a.until < b.until
}

// evictShortest is RFC 8106 §6.2 step (d) applied to a full list: "delete from
// the DNS Server List the entry with the shortest Expiration-time (i.e., the
// entry that will expire first)". It is written once and called from both
// lists because §6.3 makes it one rule: "The processing of DNSSL option(s) is
// the same as the processing of RDNSS option(s) as described in Section 6.2."
//
// IT IS NOT A COMPARISON WITH THE ENTRY THAT IS ARRIVING. The text deletes the
// entry that will expire first and registers the new one whatever lifetime the
// new one carries, so an arrival with a second to live displaces an entry with
// an hour. That is the rule as written, and the alternative — taking the
// arrival only when it outlives the entry it would replace — is a rule this
// library would be inventing.
//
// THE TIE IS THIS LIBRARY'S TO DECIDE AND IT GOES TO THE ENTRY HEARD LAST.
// §6.2 (d) orders entries by Expiration-time and says nothing about two that
// share one, which is not a corner: every entry a single advertisement carries
// with one lifetime shares a deadline, and a list of entries advertised
// 0xffffffff shares the absence of one. On a tie the newest entry goes, so a
// link's own resolvers keep their seats and a flood of equals costs one seat
// in total. Evicting the oldest instead would empty the list of everything it
// had before the flood, entry by entry, which is the outcome the caps comment
// says the eviction policy avoids. Driven by
// TestAFullListOfEqualsEvictsTheOneHeardLast.
//
// THE KEY IS THE ENTRY'S seq AND NOT ITS POSITION, AND ON EVERY STATE THIS
// TABLE REACHES THOSE ARE THE SAME ORDER. seq is handed out only where an
// entry is appended and rises at each, every removal here is an
// order-preserving splice, and the two sorts in this file are on copies. So a
// version of this loop keyed on the slice index is a NO-OP that no fixture can
// tell from this one, and a mutant spelling it that way survives for that
// reason and not for want of an observer. It is written on seq because seq is
// the entry's own and the index is the container's: the day anything reorders
// a stored list, this rule still says what it means.
func evictShortest[T any](in []T, key func(T) (timedEntry, int)) []T {
	idx := 0
	for i := range in {
		li, si := key(in[i])
		lb, sb := key(in[idx])
		if expiresBefore(lb, li) {
			continue
		}
		if expiresBefore(li, lb) || si > sb {
			idx = i
		}
	}
	return append(in[:idx], in[idx+1:]...)
}

func (e timedEntry) live(now Instant) bool { return e.forever || now.Before(e.until) }

type routerEntry struct {
	addr netip.Addr
	// deflt is the Default Router List membership of §6.3.4. A router that
	// advertised Router Lifetime zero is still a router whose options are
	// held; it is not a default router.
	deflt   timedEntry
	isDeflt bool
	// pref is RFC 4191 §2.2's Default Router Preference, and it is written
	// only on the arms where the Router Lifetime is non-zero. §2.2 says the
	// value "MUST be ignored by the receiver" when the lifetime is zero, and
	// the decoder already returns Medium for that case; not writing it here is
	// how the rule stays derived in ONE place instead of two that can differ.
	pref wire.RoutePreference
	seq  int
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

	// refused counts arrivals a full list would not take, evicted the entries
	// a full list threw out to take one. Both only ever rise.
	//
	// THEY ARE TWO FACTS AND NOT ONE NUMBER. An operator reading one total
	// cannot tell which of the two happened, and the two ask for different
	// next steps: a refusal says this client is holding what it heard first
	// and something newer could not get in, an eviction says something held
	// was thrown out for an arrival. It is the same split as the refused
	// advertisement and the ignored option one ring up, and it is the reason
	// the withdrawal tests can assert a cause instead of a total.
	refused uint64
	evicted uint64

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
		t.routers[i].pref = ra.Preference
		return
	}
	if len(t.routers) >= maxRouters {
		t.refused++
		return
	}
	t.seq++
	e := routerEntry{addr: ra.Router, seq: t.seq}
	if ra.RouterLifetime != 0 {
		e.isDeflt = true
		e.deflt = routerLifetimeUntil(now, ra.RouterLifetime)
		e.pref = ra.Preference
	}
	t.routers = append(t.routers, e)
}

func (t *routerTable) observeMTU(ra *wire.RouterAdvert) {
	if ra.MTU == 0 {
		return
	}
	if ra.MTU < minLinkMTU || ra.MTU > maxReportableMTU {
		t.refused++
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
// have a new Expiration-time." (§6.1) A full list is step (d)'s case and is
// handled by evictShortest.
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
			t.dns = evictShortest(t.dns, func(e dnsEntry) (timedEntry, int) { return e.life, e.seq })
			t.evicted++
		}
		t.seq++
		t.dns = append(t.dns, dnsEntry{addr: a, life: entryUntil(now, r.Lifetime), seq: t.seq})
	}
}

// observeDNSSL is the same rules for the search list. §5.2: the DNSSL
// "Lifetime value has the same semantics as the semantics for the RDNSS
// option". §6.3: "The processing of DNSSL option(s) is the same as the
// processing of RDNSS option(s) as described in Section 6.2."
//
// IT IS THE SAME SHAPE AS observeRDNSS AND THAT IS A HAZARD, because a
// difference between the two is invisible unless a test drives the search list
// through the case it appears in. The withdrawal is driven by
// TestAWithdrawnSearchDomainFreesItsSlotInTheSameAdvertisement and the full
// list by TestAFullListEvictsTheEntryThatExpiresFirst, each one the twin of
// the resolver test beside it.
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
			t.search = evictShortest(t.search, func(e searchEntry) (timedEntry, int) { return e.life, e.seq })
			t.evicted++
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
		t.refused++
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
	// THE DEFAULT ROUTER LIST IS ORDERED BY RFC 4191 §2.2's PREFERENCE, which
	// is the only thing that preference is for and the reason a caller may
	// take the first entry and stop reading. §3.2, for a type B host doing
	// next-hop determination against its Default Router List: "it primarily
	// prefers reachable routers over
	// non-reachable routers and secondarily uses the router preference values.
	// If the host has no information about the router's reachability, then the
	// host assumes the router is reachable." This library runs no Neighbor
	// Unreachability Detection and so has no information about any router's
	// reachability — by that sentence every router here is assumed reachable,
	// the first clause decides nothing, and the preference decides everything.
	// Arrival order breaks the tie, so two routers at the same preference come
	// back in the order §6.3.4 heard them and the result does not depend on
	// the sort being stable by accident.
	deflts := make([]routerEntry, 0, len(t.routers))
	for _, r := range t.routers {
		if r.isDeflt {
			deflts = append(deflts, r)
		}
	}
	sort.SliceStable(deflts, func(i, j int) bool {
		if deflts[i].pref != deflts[j].pref {
			return deflts[i].pref > deflts[j].pref
		}
		return deflts[i].seq < deflts[j].seq
	})
	out.Routers = nil
	for _, r := range deflts {
		out.Routers = append(out.Routers, r.addr)
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
