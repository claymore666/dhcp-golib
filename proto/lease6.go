// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/claymore666/dhcp-golib/wire"
)

// Addr6 is one address of an IA_NA with the two lifetimes §21.6 gives it.
//
// The lifetimes are Durations relative to Lease6.Start and not Instants,
// because that is what the wire carries and what a Renew must send back:
// §18.2.4 has the client include "an IA Address option for each address
// assigned to the IA", and §21.4 says the T1/T2 values "are the number of
// seconds until T1 and T2 and are calculated since reception of the message".
type Addr6 struct {
	Addr      netip.Addr
	Preferred Duration
	Valid     Duration

	// PrefixLen is the ON-LINK PREFIX LENGTH this address was formed against,
	// and ZERO MEANS THERE IS NONE. RFC 9915 gives an IA Address option no
	// prefix length, so a granted address leaves this at zero and a caller
	// installs it as a host address. RFC 4862 §5.5.3 d's Prefix Information
	// option DOES carry one, and it is the only thing on the link that says
	// which addresses are reachable without a router, so dropping it here
	// would leave a caller re-deriving it from the router observation, which
	// is the same fact taken a second way.
	PrefixLen int
}

func (a Addr6) String() string {
	if a.PrefixLen > 0 {
		return fmt.Sprintf("%s/%d pref=%s valid=%s", a.Addr, a.PrefixLen, a.Preferred, a.Valid)
	}
	return fmt.Sprintf("%s pref=%s valid=%s", a.Addr, a.Preferred, a.Valid)
}

// Lease6 is what Machine6 derived from a Reply.
//
// It is Lease's counterpart and it holds a SET of addresses where Lease holds
// one prefix, because an IA_NA is a set. Every deadline is derived from Start,
// which is an Instant on the monotonic clock, for the reason Lease says: ring
// 1 has no other clock, and turning these into a persistable wall-clock expiry
// is ring 2's job.
type Lease6 struct {
	// IAID is the identity association this lease belongs to: the value the
	// client sent, echoed by the server.
	IAID uint32

	// Addrs is the addresses the server assigned, in the order they appeared
	// in the IA_NA. Addresses with a valid lifetime of 0 are NOT here:
	// §18.2.10.1 says the client "Discard[s] any leases from the IA, as
	// recorded by the client, that have a valid lifetime of 0 in the IA
	// Address or IA Prefix option."
	Addrs []Addr6

	// TempAddrs is the addresses of the IA_TA, in the order they appeared,
	// beside Addrs and never inside it: Addr, Prefix, the deadlines, the
	// Renew, the Release and the Decline all read Addrs alone. The same
	// lifetime rules apply, and they are never renewed (RFC 8415 section 13.2:
	// "it is NOT RECOMMENDED for a client to renew temporary addresses"), so a
	// renewed lease carries them forward with their original expiry and drops
	// the ones that ran out (claymore666/docker-net-dhcp#927).
	TempAddrs []Addr6

	// Prefixes is the delegated prefixes of the IA_PD, in the order they
	// appeared, beside Addrs and TempAddrs and never inside either: a prefix is
	// not an address, so Addr, Prefix, the duplicate address detection, the
	// outward address list and the longest valid lifetime all read Addrs alone.
	// The library reports the prefix and installs nothing (RFC 3633 section
	// 12.1; claymore666/docker-net-dhcp#214).
	Prefixes []Prefix6

	// ServerDUID is the Server Identifier option's contents, as sent. It is
	// the v6 counterpart of Lease.ServerID and the reason lease.Lease carries
	// both: a v6 server is named by opaque bytes, not by an address.
	ServerDUID []byte

	// PrefixServerDUID names the server that delegated Prefixes when it is not
	// ServerDUID and is empty otherwise, since a Reply that omits an IA leaves
	// that IA's leases unchanged, RFC 8415 section 18.2.10.1
	// (claymore666/dhcp-golib#70).
	PrefixServerDUID []byte

	// pdT1 and pdT2 are the IA_PD's own times, counted from pdStart when
	// pdTimed and from Start otherwise; pdTimed is set once the IA_PD and the
	// IA_NA come from different Replies (claymore666/dhcp-golib#70).
	pdT1, pdT2 Duration
	pdStart    Instant
	pdTimed    bool

	// T1 and T2 as the server supplied them, zero when it supplied none.
	// They are NOT defaulted here — see Deadlines, which applies §21.4's
	// recommendation where it belongs, at the point of use.
	T1, T2 Duration

	// Start is the Instant the message that produced this lease was SENT —
	// the FIRST transmission of the exchange, the same instant §21.9's
	// Elapsed Time counts from, not the last retransmission.
	//
	// THIS IS A DELIBERATE DEVIATION, and it is stated here rather than
	// discovered later. RFC 9915 measures from the other end, twice and
	// unambiguously: §4.2 defines T1 as "interpreted as a time interval since
	// the message's reception", and §18.2.10.1 tells the client to "Calculate
	// T1 and T2 times (based on T1 and T2 values sent in the message and the
	// message reception time)".
	//
	// WHAT IT COSTS, stated as a bound rather than as a reassurance: the
	// client's timers fire EARLY by the whole elapsed time of the exchange —
	// from the first Request transmission to the Reply's arrival — which is
	// one round trip when nothing is lost and as much as the §15
	// retransmission ran when something was. It is never late, so the client
	// never renews after the server considers T1 passed; it renews sooner
	// than it had to, and a §15 exchange that ran long makes it renew sooner
	// still. Both directions of that trade are visible in
	// TestTheGoldenPathIsDrivenByDnsmasqsOwnBytes, which pins the send origin
	// with an exchange that took two seconds.
	//
	// WHY DEVIATE AT ALL: D30 — v6 takes v4's shape. RFC 2131 §4.4.5 makes
	// the send instant normative for v4 ("the client computes the lease
	// expiration time as the sum of the time at which the client sent the
	// DHCPREQUEST message and the duration of the lease in the DHCPACK
	// message"), Lease.Start records it, and Deadlines is one helper shared
	// by both families. Two origins behind one field would make that helper
	// mean two things depending on who filled it in.
	Start Instant

	// DNS and Search are RFC 3646's two lists.
	DNS    []netip.Addr
	Search []string

	// Options is every top-level option of the Reply, unparsed, for the
	// reason Lease.Options exists: a forgotten option is recoverable rather
	// than gone.
	Options wire.OptionsV6

	// FQDN is the server's option 39 from the Reply and HasFQDN whether it
	// sent one: its flags byte as received, O and any reserved bits included,
	// and the name (RFC 4704 section 6). Reported, never acted on. Equal ignores both, since they
	// configure nothing on the interface.
	FQDN    wire.ClientFQDN
	HasFQDN bool

	// SLAAC says this lease was formed from Router Advertisements under RFC
	// 4862 §5.5.3 and not granted by a server.
	//
	// IT IS A FIELD AND NOT A DERIVATION. "IAID is zero and ServerDUID is
	// nil" describes a SLAAC lease today and also describes a DHCPv6 lease
	// from a server that used IAID 0 and a record rebuilt without its DUID,
	// and the two want opposite things from the machine: one has T1 and T2
	// and a server to renew with, the other has neither and is refreshed only
	// by the next advertisement. Deadlines reads this field for that reason,
	// and Equal compares it so a resumed record cannot change family in
	// silence.
	SLAAC bool

	// ReconfigureKey is the RKAP key this lease's server sent (RFC 9915
	// §20.4.3), ReconfigureReplay the last replay detection value accepted
	// from that server and ReconfigureReplaySeen whether any was (§20.3: the
	// first value is recorded without a check, so "none yet" and "zero" differ).
	// Equal ignores all three, as Lease ignores its nonce
	// (claymore666/dhcp-golib#28).
	ReconfigureKey        []byte
	ReconfigureReplay     uint64
	ReconfigureReplaySeen bool
}

// Addr is the first address of the IA, which is the one a single-address
// caller wants, and whether there is one.
func (l Lease6) Addr() (netip.Addr, bool) {
	if len(l.Addrs) == 0 {
		return netip.Addr{}, false
	}
	return l.Addrs[0].Addr, true
}

// Prefix is the first address with the length it was assigned under.
//
// A GRANTED ADDRESS IS A /128 AND §18.2.10.1 SAYS SO: "Addresses obtained from
// an IA Address option MUST NOT be used to form an implicit prefix with a
// length other than 128." The constant is written here once so no caller has
// to remember it.
//
// THAT SENTENCE BINDS AN IA ADDRESS OPTION AND A FORMED ADDRESS IS NOT ONE. An
// IA Address option carries no prefix length, which is why an implicit one
// would be invented; RFC 4862 §5.5.3 d's Prefix Information option carries the
// length explicitly, and that is the length here. A caller that took 128 for
// both would install a formed address with no on-link prefix and re-derive the
// prefix from the router observation, which is the same fact taken a second
// way.
func (l Lease6) Prefix() (netip.Prefix, bool) {
	a, ok := l.Addr()
	if !ok {
		return netip.Prefix{}, false
	}
	if n := l.Addrs[0].PrefixLen; n > 0 {
		return netip.PrefixFrom(a, n), true
	}
	return netip.PrefixFrom(a, 128), true
}

// shortestPreferred and longestValid are the two aggregates §21.4 and §18.2.5
// name. Infinite absorbs: an IA with one infinite lifetime does not expire.
func (l Lease6) shortestPreferred() Duration {
	out := Duration(0)
	first := true
	for _, a := range l.Addrs {
		if a.Preferred.IsInfinite() {
			continue
		}
		if first || a.Preferred < out {
			out, first = a.Preferred, false
		}
	}
	if first {
		if len(l.Addrs) == 0 {
			return 0
		}
		return Infinite
	}
	return out
}

// renewPreferred is the shortest preferred lifetime among the addresses the
// server is still willing to extend, which is what §21.4's 0.5 and 0.8 are
// fractions of: an address with preferred lifetime 0 is deprecated and is not
// one of them (dhcp-golib#78). It is Infinite when only infinite ones remain
// and 0 when none is left. shortestPreferred keeps counting a deprecated address,
// because PreferredUntil reports when the first one deprecates.
func (l Lease6) renewPreferred() Duration {
	out, live, inf := Duration(0), false, false
	for _, a := range l.Addrs {
		switch {
		case a.Preferred.IsInfinite():
			inf = true
		case a.Preferred > 0 && (!live || a.Preferred < out):
			out, live = a.Preferred, true
		}
	}
	switch {
	case live:
		return out
	case inf:
		return Infinite
	}
	return 0
}

func (l Lease6) longestValid() Duration {
	out := Duration(0)
	for _, a := range l.Addrs {
		if a.Valid.IsInfinite() {
			return Infinite
		}
		if a.Valid > out {
			out = a.Valid
		}
	}
	return out
}

// nextEnd is the earliest finite valid end of any address, temporary address or prefix in l (dhcp-golib#65).
func (l Lease6) nextEnd() (Instant, bool) {
	var at Instant
	found := false
	take := func(d Duration) {
		if e, ok := expiry(l.Start, d); ok && (!found || e.Before(at)) {
			at, found = e, true
		}
	}
	for _, a := range l.Addrs {
		take(a.Valid)
	}
	for _, a := range l.TempAddrs {
		take(a.Valid)
	}
	for _, p := range l.Prefixes {
		take(p.Valid)
	}
	return at, found
}

// withoutEnded is l less every binding whose valid lifetime has run out at now, in new slices, and how many left (dhcp-golib#65).
func (l Lease6) withoutEnded(now Instant) (Lease6, int) {
	ended := func(d Duration) bool {
		e, ok := expiry(l.Start, d)
		return ok && !now.Before(e)
	}
	n := 0
	keep := func(as []Addr6) []Addr6 {
		var out []Addr6
		for _, a := range as {
			if ended(a.Valid) {
				n++
				continue
			}
			out = append(out, a)
		}
		return out
	}
	l.Addrs, l.TempAddrs = keep(l.Addrs), keep(l.TempAddrs)
	var ps []Prefix6
	for _, p := range l.Prefixes {
		if ended(p.Valid) {
			n++
			continue
		}
		ps = append(ps, p)
	}
	l.Prefixes = ps
	return l, n
}

// PreferredUntil is when the shortest preferred lifetime in the IA runs out,
// and reports false for an infinite one or an empty IA.
//
// It is a FOURTH moment beside Deadlines' three, and it is separate because
// nothing in ring 1 arms a timer for it: RFC 9915 §7.1's preferred lifetime is
// "the length of time that a valid address is preferred", after which RFC 4862
// §5.5.4 makes the address deprecated — "A deprecated address SHOULD continue
// to be used as a source address in existing communications, but SHOULD NOT be
// used to initiate new communications if an alternate (non-deprecated) address
// of sufficient scope can easily be used instead" — which is a rule for
// whoever opens sockets
// and not for the DHCP client. Ring 2 reports it; ring 3 acts on it.
func (l Lease6) PreferredUntil() (Instant, bool) {
	if len(l.Addrs) == 0 {
		return 0, false
	}
	p := l.shortestPreferred()
	if p.IsInfinite() || p <= 0 {
		return 0, false
	}
	return l.Start.Add(p), true
}

// Deadlines are the three moments Machine6 arms timers for, in the same shape
// the v4 machine uses (D30) and through the same type.
//
// §21.4's recommendation is applied HERE and not at decode, for the reason
// Lease.Deadlines applies RFC 2131's 0.5/0.875 here: one derivation, so a
// caller reading the three cannot get an answer the machine's timers disagree
// with.
//
// THE 0.5/0.8 FIGURES ARE A RECOMMENDATION TO THE SERVER, NOT A CLIENT
// DEFAULT, and the difference is stated because a citation is a claim.
// §21.4: "The server selects the T1 and T2 values to allow the client to
// extend the lifetimes of any addresses in the IA_NA before the lifetimes
// expire, even if the server is unavailable for some short period of time.
// Recommended values for T1 and T2 are 0.5 and 0.8 times the shortest
// preferred lifetime of the addresses in the IA that the server is willing to
// extend, respectively." What the CLIENT is obliged to do when the server
// sends zero is §14.2: "When T1 and/or T2 values are set to 0, the client MUST
// choose a time to avoid message storms. In particular, it MUST NOT transmit
// immediately." So this client chooses the server's own recommended fractions
// as its choice — a value the server would have considered reasonable, and one
// that is not immediate — and says here that it is a choice.
func (l Lease6) Deadlines() Deadlines {
	var d Deadlines
	valid := l.longestValid()
	if !valid.IsInfinite() {
		d.Expire, d.HasExpire = l.Start.Add(valid), true
	}
	if len(l.Addrs) == 0 || (!valid.IsInfinite() && valid <= 0) {
		return d
	}
	if l.SLAAC {
		// A SLAAC lease HAS NO RENEWAL, and the alternative is not a
		// harmless extra timer. §21.4's T1 and T2 are the moments a client
		// contacts the server that granted the lease; this lease was granted
		// by nobody, so T1 would enter RENEWING, find no Server Identifier,
		// fall through to REBINDING and put a Rebind on a link where nothing
		// was ever solicited. The lifetimes are the whole schedule, and
		// Machine6 arms Timer6SLAAC for them per address rather than this
		// aggregate expiry.
		return d
	}

	if l.pdTimed && len(l.Prefixes) > 0 {
		na, pd := l.groupDeadlines()
		d.Note = na.Note
		d.Renew, d.HasRenew = earliestDeadline(na.Renew, na.HasRenew, pd.Renew, pd.HasRenew)
		d.Rebind, d.HasRebind = earliestDeadline(na.Rebind, na.HasRebind, pd.Rebind, pd.HasRebind)
		return d
	}
	r := renewTimes(l.T1, l.T2, l.Start, l.renewPreferred(), valid)
	d.Renew, d.HasRenew, d.Rebind, d.HasRebind, d.Note = r.Renew, r.HasRenew, r.Rebind, r.HasRebind, r.Note
	return d
}

// chosenTime is base/den*num for a time the client picks (§14.2), and Infinite
// when base is: §21.4 recommends 0xffffffff for an infinite shortest preferred
// lifetime.
func chosenTime(base, den, num Duration) Duration {
	if base.IsInfinite() {
		return Infinite
	}
	return base / den * num
}

// renewTimes is §21.4's T1 and T2 for one group of IAs, counted from start.
func renewTimes(t1, t2 Duration, start Instant, pref, valid Duration) Deadlines {
	var d Deadlines
	renew, rebind := t1, t2
	// base is what the client's own choice is a fraction of: the shortest
	// preferred lifetime still being extended, or the valid lifetime when
	// every address is deprecated, because §14.2's "the client MUST choose a
	// time" leaves no third answer (dhcp-golib#78).
	base := pref
	if !base.IsInfinite() && base <= 0 {
		base = valid
	}
	// §21.4: "the client MUST use the values in the T1 and T2 fields for the
	// T1 and T2 times, unless values in those fields are 0", and 0xffffffff is
	// "infinity": Infinite is -1 here and is the server's answer, not zero.
	if renew == 0 || renew < 0 && !renew.IsInfinite() {
		renew = chosenTime(base, 2, 1)
	}
	if rebind == 0 || rebind < 0 && !rebind.IsInfinite() {
		rebind = chosenTime(base, 5, 4)
	}

	// §18.2.5 puts the Rebind exchange's end at the expiry: "The message
	// exchange is terminated when the valid lifetimes of all leases across all
	// IAs have expired". A T2 at or after that is a T2 the machine could never
	// act on, so it is clamped to the recommendation and the clamp is
	// journalled — the same trade Lease.Deadlines makes, for the same reason:
	// refusing the Reply hands back a working lease over a server's typo.
	if !rebind.IsInfinite() && !valid.IsInfinite() && rebind >= valid {
		was := rebind
		if base.IsInfinite() {
			rebind = valid
		} else {
			rebind = (base / 5) * 4
		}
		d.Note = "T2 (" + was.String() + ") is not earlier than the longest valid lifetime (" +
			valid.String() + "): using §21.4's 0.8 of the shortest preferred lifetime, " + rebind.String()
	}
	if !renew.IsInfinite() && !rebind.IsInfinite() && renew >= rebind {
		// §21.4 makes this the SERVER's error and names the remedy for a
		// well-formed one at option level: "If a client receives an IA_NA with
		// T1 greater than T2 and both T1 and T2 are greater than 0, the client
		// discards the IA_NA option". That discard happens in
		// leaseFromReply, where the option is; by the time a lease exists the
		// two values came from different places (one from the server, one from
		// the fallback above) and half of T2 is the answer that keeps the
		// ordering without inventing a renewal after the rebind.
		was := renew
		renew = rebind / 2
		note := "T1 (" + was.String() + ") is not earlier than T2 (" + rebind.String() +
			"): using half of T2, " + renew.String()
		if d.Note == "" {
			d.Note = note
		} else {
			d.Note += "; " + note
		}
	}

	if renew > 0 {
		d.Renew, d.HasRenew = start.Add(renew), true
	}
	if rebind > 0 {
		d.Rebind, d.HasRebind = start.Add(rebind), true
	}
	return d
}

// groupDeadlines is the renewal times of the IA_NA (with the IA_TA) and of the
// IA_PD apart: one group's times are never another's (RFC 8415 section
// 18.2.10.1; claymore666/dhcp-golib#70).
func (l Lease6) groupDeadlines() (na, pd Deadlines) {
	valid := l.longestValid()
	if !l.pdTimed {
		d := renewTimes(l.T1, l.T2, l.Start, l.renewPreferred(), valid)
		return d, d
	}
	na = renewTimes(l.T1, l.T2, l.Start, l.renewPreferred(), valid)
	pref, pvalid, live := Duration(0), Duration(0), false
	for _, p := range l.Prefixes {
		// a prefix already deprecated at pdStart is not one the server is
		// willing to extend, as for an address (dhcp-golib#78)
		if e, ok := expiry(l.Start, p.Preferred); ok && e.Sub(l.pdStart) > 0 && (!live || e.Sub(l.pdStart) < pref) {
			pref, live = e.Sub(l.pdStart), true
		}
		if e, ok := expiry(l.Start, p.Valid); !ok {
			pvalid = Infinite
		} else if !pvalid.IsInfinite() && e.Sub(l.pdStart) > pvalid {
			pvalid = e.Sub(l.pdStart)
		}
	}
	if !live && l.prefixesPreferForever() {
		pref = Infinite
	}
	pd = renewTimes(l.pdT1, l.pdT2, l.pdStart, pref, pvalid)
	return na, pd
}

// prefixesPreferForever is whether no prefix has a finite preferred lifetime,
// which is also the answer for no prefix at all.
func (l Lease6) prefixesPreferForever() bool {
	for _, p := range l.Prefixes {
		if _, ok := expiry(l.Start, p.Preferred); ok {
			return false
		}
	}
	return true
}

func earliestDeadline(a Instant, hasA bool, b Instant, hasB bool) (Instant, bool) {
	if !hasA || hasB && b.Before(a) {
		return b, hasB
	}
	return a, true
}

// prefixServer is the DUID of the server that delegated Prefixes.
func (l Lease6) prefixServer() []byte {
	if len(l.PrefixServerDUID) > 0 {
		return l.PrefixServerDUID
	}
	return l.ServerDUID
}

// split reports whether the IA_PD names a different server from the IA_NA:
// canonPD leaves PrefixServerDUID set only then (claymore666/dhcp-golib#70).
func (l Lease6) split() bool {
	return len(l.PrefixServerDUID) > 0
}

// canonPD clears the IA_PD's own server and times when they say nothing more
// than ServerDUID and T1/T2 would (claymore666/dhcp-golib#70).
func (l *Lease6) canonPD() {
	if len(l.Prefixes) == 0 {
		l.PrefixServerDUID, l.pdT1, l.pdT2, l.pdStart, l.pdTimed = nil, 0, 0, 0, false
		return
	}
	if sameDUID(l.PrefixServerDUID, l.ServerDUID) {
		l.PrefixServerDUID = nil
	}
}

// pdOrigin is the instant pdT1 and pdT2 count from.
func (l Lease6) pdOrigin() Instant {
	if l.pdTimed {
		return l.pdStart
	}
	return l.Start
}

// sameT is two renewal times equal as durations or ending at the same instant.
func sameT(s1 Instant, a Duration, s2 Instant, b Duration) bool {
	if a == b {
		return true
	}
	return a > 0 && b > 0 && s1.Add(a) == s2.Add(b)
}

// Equal reports whether two leases would configure the interface identically.
// Start is NOT compared: a renewal that changes nothing but the expiry is
// ActLeaseRenewed and not ActLeaseChanged, which is the distinction this
// predicate exists to draw.
func (l Lease6) Equal(o Lease6) bool {
	if l.IAID != o.IAID || len(l.Addrs) != len(o.Addrs) || l.SLAAC != o.SLAAC {
		return false
	}
	for i := range l.Addrs {
		x, y := l.Addrs[i], o.Addrs[i]
		if x.Addr != y.Addr || x.PrefixLen != y.PrefixLen || !sameLifetimes(l.Start, x.Preferred, x.Valid, o.Start, y.Preferred, y.Valid) {
			return false
		}
	}
	// The temporary addresses compare as the stable ones do, lifetimes
	// included, but counted from the clock and not from Start: a renewal
	// carries them forward with the expiry they were granted, which is no
	// change (claymore666/docker-net-dhcp#927).
	if !tempEqual(l, o) {
		return false
	}
	// A delegated prefix compares like an address, lifetimes included, so a
	// Renew that moves, shortens or drops it is ActLeaseChanged
	// (claymore666/docker-net-dhcp#214).
	if len(l.Prefixes) != len(o.Prefixes) {
		return false
	}
	for i := range l.Prefixes {
		x, y := l.Prefixes[i], o.Prefixes[i]
		if x.Prefix != y.Prefix || !sameLifetimes(l.Start, x.Preferred, x.Valid, o.Start, y.Preferred, y.Valid) {
			return false
		}
	}
	if !sameDUID(l.ServerDUID, o.ServerDUID) || !sameDUID(l.prefixServer(), o.prefixServer()) {
		return false
	}
	if (l.pdTimed || o.pdTimed) && !(sameT(l.pdOrigin(), l.pdT1, o.pdOrigin(), o.pdT1) && sameT(l.pdOrigin(), l.pdT2, o.pdOrigin(), o.pdT2)) {
		return false
	}
	return l.T1 == o.T1 && l.T2 == o.T2 &&
		addrsEqual(l.DNS, o.DNS) && stringsEqual(l.Search, o.Search)
}

// sameLifetimes is two lifetime pairs that are equal as durations or end at the
// same instants: a lease a Reply left unnamed is carried with its own expiry
// rebased onto the new Start, which is no change (claymore666/dhcp-golib#64).
func sameLifetimes(s1 Instant, p1, v1 Duration, s2 Instant, p2, v2 Duration) bool {
	if p1 == p2 && v1 == v2 {
		return true
	}
	return sameEnd(s1, v1, s2, v2) && samePreferred(s1, p1, s2, p2)
}

// String is the diagnostic rendering. It builds through fmt.Sprintf and
// strings.Builder rather than fmt.Fprintf, because gate T1 refuses the
// Fprint family in a pure ring: Fprintf takes an io.Writer, and a ring-1
// file that can name it can hold a stream. MEASURED 2026-09-06: the first
// draft of this function used fmt.Fprintf(&b, ...) and ./verify.sh's t1 row
// named both lines. strings.Builder is not a stream the gate can see, but
// the gate keys on the identifier, not on what it was handed, and that is
// the right direction for a gate to fail in.
func (l Lease6) String() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("iaid=%d", l.IAID))
	for _, a := range l.Addrs {
		b.WriteString(" ")
		b.WriteString(a.String())
	}
	for _, a := range l.TempAddrs {
		b.WriteString(" temp ")
		b.WriteString(a.String())
	}
	for _, p := range l.Prefixes {
		b.WriteString(" pd ")
		b.WriteString(p.String())
	}
	b.WriteString(fmt.Sprintf(" t1=%s t2=%s", l.T1, l.T2))
	if len(l.DNS) > 0 {
		b.WriteString(" dns=" + addrsText(l.DNS))
	}
	if len(l.Search) > 0 {
		b.WriteString(" search=" + strings.Join(l.Search, ","))
	}
	return b.String()
}

// iaResult is what one IA_NA in a Reply produced, and why, so every discard
// arm has a journal line rather than a silence.
type iaResult struct {
	addrs []Addr6
	t1    Duration
	t2    Duration
	// status is the Status Code scoped to this IA, or Success when there was
	// none. §21.4: "The status of any operations involving this IA_NA is
	// indicated in a Status Code option".
	status wire.StatusCode
	found  bool
	// zeroed is the addresses the IA names with a valid lifetime of 0.
	zeroed []netip.Addr
}

// leaseFromReply builds a Lease6 from a Reply's IA_NA for iaid.
//
// It returns the addresses the IA_NA names with a valid lifetime of 0, the
// notes for the journal and whether a usable lease came out.
// EVERY REFUSAL IS A NOTE: sequencing §2.6's rule is that a discard is
// invisible in a passing test, so a message that yields nothing must say which
// of the six reasons applied.
func leaseFromReply(m *wire.MessageV6, iaid uint32, sentAt Instant) (Lease6, []netip.Addr, []string, wire.StatusCode, bool) {
	var notes []string
	l := Lease6{IAID: iaid, Start: sentAt, Options: append(wire.OptionsV6(nil), m.Options...)}
	if sid, ok := m.Options.First(wire.OptV6ServerID); ok {
		l.ServerDUID = append([]byte(nil), sid...)
	}

	// §21.6's option is "only specified to be encapsulated within an IA_NA",
	// so one at the top level is a misplaced option. §16 forbids discarding
	// the message over it — "Clients and servers MAY choose to either (1)
	// extract information from such a message if the information is of use to
	// the recipient or (2) ignore such a message completely and just discard
	// it" — and an address with no IAID is one nothing can renew, rebind or
	// release, so the OPTION is dropped and the drop is named.
	if n := m.Options.Count(wire.OptV6IAAddr); n > 0 {
		notes = append(notes, fmt.Sprintf("%d IA Address option(s) at the top level, outside any IA_NA: ignored, §21.6 encapsulates them within IA_NA", n))
	}

	res, ns := readIA(m.Options, iaid)
	notes = append(notes, ns...)
	if !res.found {
		return Lease6{}, nil, notes, wire.StatusSuccess, false
	}
	if res.status == wire.StatusNoAddrsAvail && len(res.addrs) > 0 {
		// §18.2.10.1: "The client uses the addresses, delegated prefixes, and
		// other information from any IAs that do not contain a Status Code
		// option with the NoAddrsAvail or NoPrefixAvail status code." An IA
		// that says it has none has nothing to give, whatever else is inside
		// it — and a client that read the address anyway would report a
		// refusal and bind an address in the same Step.
		notes = append(notes, fmt.Sprintf("the IA_NA says NoAddrsAvail and carries %d address(es): they are not ours to use (§18.2.10.1)", len(res.addrs)))
		res.addrs = nil
	}
	l.T1, l.T2, l.Addrs = res.t1, res.t2, res.addrs
	if dns, err := m.Options.DNSServers(); err != nil {
		notes = append(notes, "DNS Recursive Name Server option: "+err.Error())
	} else {
		l.DNS = dns
	}
	if s, err := m.Options.DomainSearch(); err != nil {
		notes = append(notes, "Domain Search List option: "+err.Error())
	} else {
		l.Search = s
	}
	f, ok, note := serverFQDN(m.Options)
	l.FQDN, l.HasFQDN = f, ok
	if note != "" {
		notes = append(notes, note)
	}
	return l, res.zeroed, notes, res.status, len(l.Addrs) > 0
}

// renewedAddrs is the IA_NA address set a Reply to a Renew or a Rebind leaves,
// built as renewedPrefixes builds the prefix set: a held address the Reply does
// not name keeps its own expiry, one named with a valid lifetime of 0 leaves,
// and a new one is appended. §18.2.10.1: "Leave unchanged any information about
// leases the client has recorded in the IA but that were not included in the IA
// from the server" (claymore666/dhcp-golib#64).
func renewedAddrs(held []Addr6, heldStart Instant, got []Addr6, zeroed []netip.Addr, newStart, now Instant) []Addr6 {
	var out []Addr6
	for _, h := range held {
		if i := addrIndex(got, h.Addr); i >= 0 {
			out = append(out, got[i])
			continue
		}
		if containsAddr(zeroed, h.Addr) {
			continue
		}
		c := h
		var ok bool
		if c.Preferred, c.Valid, ok = carryLifetimes(h.Preferred, h.Valid, heldStart, newStart, now); ok {
			out = append(out, c)
		}
	}
	for _, a := range got {
		if addrIndex(held, a.Addr) < 0 {
			out = append(out, a)
		}
	}
	return out
}

func addrIndex(as []Addr6, a netip.Addr) int {
	for i := range as {
		if as[i].Addr == a {
			return i
		}
	}
	return -1
}

// readIA finds the IA_NA whose IAID is ours and reads it.
func readIA(o wire.OptionsV6, iaid uint32) (iaResult, []string) {
	var notes []string
	var out iaResult
	ias, err := o.IANAs()
	if err != nil {
		return out, append(notes, "IA_NA option: "+err.Error())
	}
	for _, ia := range ias {
		if ia.IAID != iaid {
			// §18.2.10 has the client update "the information it has recorded
			// about IAs from the IA options contained in the Reply message" —
			// its own IAs. An IA the client never asked for belongs to some
			// other identity association, so it is skipped rather than
			// treated as an error: the rest of the message is still ours.
			notes = append(notes, fmt.Sprintf("IA_NA with IAID %d is not ours (%d): ignored", ia.IAID, iaid))
			continue
		}
		if out.found {
			notes = append(notes, fmt.Sprintf("a second IA_NA with IAID %d: ignored, this client sends one", iaid))
			continue
		}
		t1, t2 := SecondsToDuration(ia.T1), SecondsToDuration(ia.T2)
		// §21.4, verbatim: "If a client receives an IA_NA with T1 greater than
		// T2 and both T1 and T2 are greater than 0, the client discards the
		// IA_NA option and processes the remainder of the message as though
		// the server had not included the invalid IA_NA option."
		// The test is on the WIRE values and not on the Durations, because
		// SecondsToDuration maps 0xffffffff to the Infinite sentinel, which is
		// negative: an infinite T1 beside a finite T2 would compare as
		// less-than and slip past the rule the RFC states over the encoded
		// numbers.
		if ia.T1 > 0 && ia.T2 > 0 && ia.T1 > ia.T2 {
			notes = append(notes, fmt.Sprintf("IA_NA T1 %s is greater than T2 %s, both non-zero: IA_NA discarded (§21.4)", t1, t2))
			continue
		}
		out.found, out.t1, out.t2 = true, t1, t2
		st, ok, err := ia.Options.Status()
		switch {
		case err != nil:
			// The malformed Status Code value is checked BEFORE the value is
			// read, which is what wire.StatusMalformed exists to make
			// unnecessary to remember. Both are done: the error decides, the
			// sentinel makes forgetting it visible instead of silent.
			notes = append(notes, "IA_NA Status Code option: "+err.Error())
			out.status = wire.StatusMalformed
		case ok:
			out.status = st.Code
		default:
			out.status = wire.StatusSuccess
		}
		addrs, zs, ans := iaAddrs(ia.Options, "IA Address option")
		notes = append(notes, ans...)
		out.addrs = append(out.addrs, addrs...)
		out.zeroed = append(out.zeroed, zs...)
	}
	if !out.found && len(ias) > 0 {
		notes = append(notes, fmt.Sprintf("no IA_NA with our IAID %d in the message", iaid))
	}
	return out, notes
}

// iaAddrs reads the IA Address options of one IA, applies the discard rules
// both IA types share and returns the addresses named with a valid lifetime of
// 0 apart. what names the option in the notes (claymore666/docker-net-dhcp#927).
func iaAddrs(o wire.OptionsV6, what string) ([]Addr6, []netip.Addr, []string) {
	var notes []string
	var out []Addr6
	var zeroed []netip.Addr
	addrs, err := o.Addrs()
	if err != nil {
		return nil, nil, append(notes, what+": "+err.Error())
	}
	for _, a := range addrs {
		// §21.6: "The client MUST discard any addresses for which the
		// preferred lifetime is greater than the valid lifetime."
		// wire.IAAddr.Valid is the predicate; the discard is here,
		// because ring 0 holds no policy and an address dropped by the
		// decoder could not be counted or journalled (claymore666/docker-net-dhcp#927).
		if !a.Valid() {
			notes = append(notes, fmt.Sprintf("IA Address %s has preferred %d greater than valid %d: discarded (§21.6)",
				a.Addr, a.PreferredLifetime, a.ValidLifetime))
			continue
		}
		if a.ValidLifetime == 0 {
			notes = append(notes, fmt.Sprintf("IA Address %s has a valid lifetime of 0: discarded (§18.2.10.1)", a.Addr))
			zeroed = append(zeroed, a.Addr)
			continue
		}
		if !a.Addr.Is6() || a.Addr.Is4In6() || a.Addr.IsUnspecified() {
			notes = append(notes, fmt.Sprintf("IA Address %s is not a usable IPv6 address: discarded", a.Addr))
			continue
		}
		out = append(out, Addr6{
			Addr:      a.Addr,
			Preferred: SecondsToDuration(a.PreferredLifetime),
			Valid:     SecondsToDuration(a.ValidLifetime),
		})
	}
	return out, zeroed, notes
}

// serverFQDN reads a server's option 39 and the journal line that reports it.
// A malformed one is a note and not a refusal: the name is information about
// the server's DNS work, and the lease stands without it.
func serverFQDN(o wire.OptionsV6) (wire.ClientFQDN, bool, string) {
	f, ok, err := o.ClientFQDN()
	switch {
	case err != nil:
		return wire.ClientFQDN{}, false, "Client FQDN option: " + err.Error() + "; ignored"
	case !ok:
		return wire.ClientFQDN{}, false, ""
	}
	bit := func(b uint8) int {
		if f.Flags&b != 0 {
			return 1
		}
		return 0
	}
	return f, true, fmt.Sprintf("the server's Client FQDN option: S=%d O=%d N=%d name %q (RFC 4704 section 6)",
		bit(wire.ClientFQDNFlagS), bit(wire.ClientFQDNFlagO), bit(wire.ClientFQDNFlagN), f.Name)
}
