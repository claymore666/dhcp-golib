// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"fmt"
	"net/netip"

	"github.com/claymore666/dhcp-golib/wire"
)

// Machine6's stateless half: what a Router Advertisement does in a mode that
// forms addresses, and what the lifetimes it carried do afterwards.
//
// slaac6.go holds the rules and the table; this file holds the machine's use
// of them — which state the client waits in, when duplicate address detection
// runs, which action kind a change produces, and where Mode6Auto's decision is
// taken.

// awaitingAddress reports that this machine's address can still only come from
// a Router Advertisement and it has not got one.
//
// It is the predicate RFC 4861 §6.3.7's conclusion is keyed on — "the host
// concludes that there are no routers on the link for the purpose of
// [ADDRCONF]" — and it is false in Mode6DHCP, where a client with no router
// still has a server to talk to, and false once Mode6Auto has committed to
// DHCPv6, where the Solicit's own schedule is what bounds the attempt.
func (m *Machine6) awaitingAddress() bool {
	if !m.params.Mode.formsAddresses() || m.dhcpCommitted {
		return false
	}
	return !m.haveLse && len(m.slaac.entries) == 0
}

// startRouterDiscovery begins RFC 4861 §6.3.7's schedule, unless an
// advertisement has already answered the question it asks.
func (m *Machine6) startRouterDiscovery(out *actions) {
	if m.router.Seen && !m.awaitingAddress() {
		return
	}
	m.solicitRouter(out)
}

// beginSLAAC is begin() for a machine whose address comes from an
// advertisement: there is no first message to delay, so there is no INIT6.
func (m *Machine6) beginSLAAC(now Instant, rnd uint64, out *actions) {
	m.adverts, m.windowDone, m.tried = nil, false, nil
	m.sendFailures = 0
	m.rsCount = 0
	m.state = State6Discovering
	if r := m.resume; r.live() {
		// A restart with addresses still installed. §5.5.3's list is rebuilt
		// from them BEFORE the first advertisement arrives, which is the whole
		// point: without it the advertisement that formed them would find no
		// equal prefix and form every one of them a second time.
		m.seedFromResume(now, r, out)
		m.resume = nil
		out.journal(m, fmt.Sprintf("continuing with %d remembered address(es) and their last known lifetimes", len(m.slaac.entries)))
		m.startRouterDiscovery(out)
		m.reportSLAAC(now, rnd, out)
		return
	}
	out.journal(m, "waiting for a Router Advertisement carrying a prefix this client can form an address from (RFC 4862 §5.5.3)")
	m.startRouterDiscovery(out)
}

// seedFromResume rebuilds the §5.5.3 list from a remembered binding.
//
// THE PREFIX IS DERIVED FROM THE ADDRESS AND NOT REMEMBERED BESIDE IT, and
// that is sound for exactly this library: every address in this table was
// formed by SLAACAddress, which forms only where the prefix length plus
// IIDBits is 128, so the prefix is the address's first 128-IIDBits bits and
// there is no second possibility to guess between.
func (m *Machine6) seedFromResume(now Instant, r *Resume6, out *actions) {
	for _, a := range r.Addrs {
		if !a.Addr.Is6() || a.Addr.Is4In6() || a.Addr.IsUnspecified() {
			continue
		}
		if len(m.slaac.entries) >= MaxSLAACAddresses {
			m.slaac.counts.Ignored[SLAACIgnoreCapReached]++
			continue
		}
		p := netip.PrefixFrom(a.Addr, 128-IIDBits).Masked()
		if m.slaac.find(p) >= 0 {
			continue
		}
		m.slaac.entries = append(m.slaac.entries, slaacEntry{
			prefix:    p,
			addr:      a.Addr,
			start:     now,
			preferred: a.Preferred,
			valid:     a.Valid,
			// TENTATIVE, because nothing on THIS link has answered for the
			// address since the restart. It is lead ruling 2 and the reason
			// continueFromResume runs duplicate address detection on a
			// confirmed binding: a Confirm says the addresses belong to this
			// link and says nothing about who has taken one since.
			tentative: true,
		})
		out.journal(m, "remembered "+a.String())
	}
}

// observeSLAAC is a Router Advertisement in a mode that forms addresses.
func (m *Machine6) observeSLAAC(now Instant, rnd uint64, ra *wire.RouterAdvert, out *actions) {
	changed := m.applyAdvert(now, ra, out)

	if ra.Managed || ra.Other {
		// RFC 4861 §4.2 for both flags: addresses (M) or "other configuration
		// information" (O) are available via DHCPv6. This client's address
		// does not come from there in this mode, so the M flag buys the same
		// thing the O flag does — RFC 9915 §18.2.6's exchange, which carries
		// no address at all — and it is asked for once.
		m.wantConfig = true
	}
	if !changed {
		m.maybeInfoRequest(now, rnd, out)
		return
	}
	m.reportSLAAC(now, rnd, out)
	m.maybeInfoRequest(now, rnd, out)
}

// maybeInfoRequest sends RFC 9915 §18.2.6's exchange once, when a router has
// said there is other configuration to be had and this machine is not in the
// middle of something else.
//
// IT WAITS FOR THE ADDRESS, and BOUND6 is the only state it goes out from.
// The machine runs one exchange at a time, so an Information-request started
// while an address was still being waited for or checked would take the state
// the answer has to come back to, and the advertisement that finally carries a
// usable prefix would then abandon it. The flag is remembered instead, and
// enterBoundSLAAC asks the question once there is an address to ask it from.
func (m *Machine6) maybeInfoRequest(now Instant, rnd uint64, out *actions) {
	if !m.wantConfig || m.askedConfig || m.msgType != 0 {
		return
	}
	if m.state != State6Bound {
		return
	}
	m.askedConfig = true
	out.journal(m, "the router offers other configuration over DHCPv6: Information-request (§18.2.6)")
	m.startExchange(now, rnd, wire.MsgInformationRequest, out)
}

// applyAdvert runs RFC 4862 §5.5.3 over every Prefix Information option of one
// advertisement and reports whether anything a caller can see moved.
func (m *Machine6) applyAdvert(now Instant, ra *wire.RouterAdvert, out *actions) bool {
	changed := false
	for _, pi := range ra.Prefixes {
		formed, moved, why := m.slaac.applyPIO(now, pi, m.params.LinkAddr)
		if why != SLAACIgnoreNone {
			m.slaac.counts.Ignored[why]++
			out.journal(m, fmt.Sprintf("Prefix Information option %s formed nothing: %s", pi, why))
			continue
		}
		if formed {
			out.journal(m, fmt.Sprintf("formed %s from %s (RFC 4862 §5.5.3 d)", m.slaac.entries[len(m.slaac.entries)-1].addr, pi))
		}
		changed = changed || moved
	}
	return changed
}

// reportSLAAC turns the table into what the caller is told, through duplicate
// address detection when there is a new address to check.
func (m *Machine6) reportSLAAC(now Instant, rnd uint64, out *actions) {
	fresh := m.slaac.tentativeAddrs()
	if len(fresh) == 0 {
		m.enterBoundSLAAC(now, rnd, out)
		return
	}
	if m.state == State6DAD {
		// A router repeats its advertisement every few seconds (RFC 4861
		// §6.2.1). Restarting the check that is already running would rearm
		// its deadline for ever, so anything formed in the meantime waits for
		// the round in flight to end; finishSLAACDAD picks it up.
		out.journal(m, "duplicate address detection is already running: the new address(es) are checked when it ends")
		return
	}
	m.pending = m.slaac.lease(now, m.params.IAID)
	m.havePending, m.pendingRenewal = true, false
	m.startDAD(fresh, out)
}

// finishSLAACDAD is takeDADResult's SLAAC arm: every address this machine
// asked about has an answer.
//
// A DUPLICATE COSTS ONE ADDRESS AND NOT THE SET. The v6 IA_NA arm above
// declines the whole IA because §18.2.8's retained bindings would mean two
// exchanges in flight; there is no exchange here at all — a SLAAC address is
// granted by nobody, so there is nobody to decline to — and §5.5.3 forms one
// address per prefix independently. Dropping the others would hand a
// container's whole IPv6 configuration to whichever node happened to answer
// for one of its prefixes.
//
// AND THERE IS NO RETRY. RFC 4862 §5.4 ends at "the address is not unique";
// the identifier is this link's own hardware address, so §5.5.3 offers no
// second candidate to form. The address is dropped and it is REMEMBERED as
// refused, so the router's next advertisement of the same prefix is charged to
// SLAACIgnoreDuplicate and forms nothing. A machine that is stopped and
// started again has a new table and tries once more, which is the only event
// that can mean the other node let the address go.
func (m *Machine6) finishSLAACDAD(now Instant, rnd uint64, out *actions) {
	out.cancel(m, Timer6DAD)
	bad := append([]netip.Addr(nil), m.dadBad...)
	for _, a := range bad {
		if m.slaac.drop(a) {
			m.slaac.counts.Conflicts++
		}
		// AND IT IS NOT FORMED AGAIN. The prefix that formed it is
		// re-advertised every few seconds (RFC 4861 §6.2.1) and would form the
		// same address from the same link hardware address every time, so
		// without this the machine repeats the whole formation, check and
		// failure once per advertisement interval, for as long as the other
		// node holds the address. The repeat is charged to
		// SLAACIgnoreDuplicate instead, and router discovery reaches its own
		// verdict.
		m.slaac.refuse(a)
	}
	// ONLY THE ADDRESSES THIS ROUND ASKED ABOUT ARE SETTLED. A router repeats
	// its advertisement while a check is running and a NEW prefix can arrive
	// in one of those repeats; settling everything tentative would announce an
	// address nothing had checked, which is D22's rule broken by a race rather
	// than by a decision.
	asked := m.pending.Addrs
	m.dropPending()
	for _, a := range asked {
		m.slaac.settle(a.Addr)
	}
	if rest := m.slaac.tentativeAddrs(); len(rest) > 0 {
		out.journal(m, fmt.Sprintf("a prefix arrived while duplicate address detection was running: checking %v as well", rest))
		m.pending = m.slaac.lease(now, m.params.IAID)
		m.havePending, m.pendingRenewal = true, false
		m.startDAD(rest, out)
		return
	}

	if len(m.slaac.entries) > 0 {
		if len(bad) > 0 {
			out.journal(m, fmt.Sprintf("duplicate address detection found %v in use: dropped, %d address(es) remain", bad, len(m.slaac.entries)))
		}
		m.enterBoundSLAAC(now, rnd, out)
		return
	}

	note := fmt.Sprintf("duplicate address detection found every formed address in use: %v (RFC 4862 §5.4.5)", bad)
	out.journal(m, note)
	held := m.haveLse
	if held {
		m.loseLease(out, ReasonConflict)
	} else {
		out.failed(m, ReasonConflict, note)
	}
	out.cancel(m, Timer6SLAAC)
	m.slaacPhases = nil
	m.beginSLAAC(now, rnd, out)
}

// enterBoundSLAAC installs the formed set as the lease.
//
// THE TIMER IS ARMED BEFORE THE LEASE IS ANNOUNCED. It is the rule the DHCPv6
// side states — ring 1 announces a lease only once the deadline that ends it
// is armed — and it matters more here, because the moment being armed is not
// only an expiry: a caller that acted on this lease before the deprecation
// moment was armed would advertise an address as preferred for as long as
// nothing else happened to wake the machine.
//
// WHICH ACTION KIND IS KEYED ON A PROPERTY AND NOT ON WHAT HAPPENED. The set
// of addresses and each address's RFC 4862 §5.5.4 phase are what a chassis
// must act on — install, uninstall, set PreferedLft to zero — so a change in
// either is ActLeaseChanged and a pure movement of lifetimes is
// ActLeaseRenewed. Keying it on "an advertisement arrived" instead would have
// made every repeat of a router's advertisement a change.
func (m *Machine6) enterBoundSLAAC(now Instant, rnd uint64, out *actions) {
	if len(m.slaac.entries) == 0 {
		return
	}
	l := m.slaac.lease(now, m.params.IAID)
	phases := m.slaac.phases(now)
	had, was := m.haveLse, m.slaacPhases

	m.msgType = 0
	m.sendFailures = 0
	m.lease, m.haveLse = l, true
	m.state = State6Bound
	m.resume = nil
	m.dhcpCommitted = false
	out.cancel(m, Timer6Retransmit)
	// The DHCPv6 schedule belongs to a lease a server granted. Deadlines
	// refuses to compute it for this lease; these three cancels are what makes
	// a machine that HAD such a lease and now holds a formed one agree with
	// that refusal.
	out.cancel(m, Timer6Renew)
	out.cancel(m, Timer6Rebind)
	out.cancel(m, Timer6Expire)
	out.cancel(m, Timer6AutoFallback)
	m.armSLAAC(now, out)

	switch {
	case !had:
		out.stamp(m, Action{Kind: ActLeaseAcquired, Lease6: l})
	default:
		out.stamp(m, Action{Kind: ActLeaseRenewed, Lease6: l})
		if phasesDiffer(was, phases) {
			out.stamp(m, Action{Kind: ActLeaseChanged, Lease6: l})
		}
	}
	m.slaacPhases = phases
	m.maybeInfoRequest(now, rnd, out)
}

// armSLAAC arms Timer6SLAAC for the earliest moment RFC 4862 §5.5.4 has
// anything to say about any held address, or cancels it when there is none —
// which is a table of nothing but infinite lifetimes.
func (m *Machine6) armSLAAC(now Instant, out *actions) {
	ts, ok := m.slaac.next(now)
	if !ok {
		out.cancel(m, Timer6SLAAC)
		return
	}
	d := ts.Sub(now)
	if d < 0 {
		d = 0
	}
	out.set(m, Timer6SLAAC, d)
}

// slaacTick is Timer6SLAAC firing: a preferred lifetime has run out, or a
// valid one, or both on different addresses.
//
// §5.5.4 gives the two phases their consequences: "A preferred address becomes
// deprecated when its preferred lifetime expires. A deprecated address SHOULD
// continue to be used as a source address in existing communications, but
// SHOULD NOT be used to initiate new communications" — so a deprecated address
// is KEPT and reported with its preferred lifetime at zero — and "An address
// (and its association with an interface) becomes invalid when its valid
// lifetime expires. An invalid address MUST NOT be used as a source address in
// outgoing communications" — so an expired one is dropped.
func (m *Machine6) slaacTick(now Instant, rnd uint64, out *actions) {
	for _, a := range m.slaac.expire(now) {
		out.journal(m, "the valid lifetime of "+a.String()+" has run out: the address is invalid (RFC 4862 §5.5.4)")
	}
	for i := range m.slaac.entries {
		e := &m.slaac.entries[i]
		if e.deprecated(now) && !e.deprecationCharged {
			e.deprecationCharged = true
			m.slaac.counts.Deprecated++
			out.journal(m, "the preferred lifetime of "+e.addr.String()+" has run out: the address is deprecated (RFC 4862 §5.5.4)")
		}
	}

	if len(m.slaac.entries) == 0 {
		out.cancel(m, Timer6SLAAC)
		m.slaacPhases = nil
		if m.haveLse {
			m.loseLease(out, ReasonExpired)
		}
		m.beginSLAAC(now, rnd, out)
		return
	}
	if len(m.slaac.tentativeAddrs()) > 0 {
		// Duplicate address detection is still running on at least one of
		// them, so there is nothing to announce yet. The moments that have not
		// arrived are still moments.
		//
		// AND slaacPhases IS NOT WRITTEN HERE. It is what the CALLER was last
		// told, and nothing was told on this path; writing it would make the
		// announcement that finally comes look like a plain renewal and
		// swallow both the deprecation and the address that arrived with it.
		// What the machine has already charged is the entry's own
		// deprecationCharged, which the loop above keeps.
		m.armSLAAC(now, out)
		return
	}
	if !m.haveLse {
		m.armSLAAC(now, out)
		return
	}
	m.enterBoundSLAAC(now, rnd, out)
}

// observeAuto is Mode6Auto: the router decides, once.
//
// THE DECISION IS TAKEN ON THE FIRST ADVERTISEMENT AND IS NOT REVISITED. RFC
// 4861 §4.2 gives the M flag its meaning — "When set, it indicates that
// addresses are available via Dynamic Host Configuration Protocol [DHCPv6]" —
// and a client that re-read it on every advertisement would abandon an address
// it holds because a router's configuration changed, which is a worse outcome
// than either choice. Later advertisements are still observed, still update
// the lifetimes of what was formed, and still change nothing about where the
// address comes from.
func (m *Machine6) observeAuto(now Instant, rnd uint64, ra *wire.RouterAdvert, out *actions) {
	if !m.autoDecided {
		m.autoDecided = true
		if ra.Managed {
			m.dhcpCommitted = true
			d, ok := m.params.autoFallback()
			out.journal(m, "Router Advertisement M=1: this link's addresses come from DHCPv6 (RFC 4861 §4.2), soliciting")
			out.cancel(m, Timer6RouterSolicit)
			// THE SOLICIT IS DELAYED, and this trigger is the one §18.2.1
			// names: "The first Solicit message from the client on the
			// interface SHOULD be delayed by a random amount of time between 0
			// and SOL_MAX_DELAY. This random delay helps desynchronize clients
			// that start a DHCP session at the same time, such as after
			// recovery from a power failure or after a router outage after
			// seeing that DHCP is available in Router Advertisement messages".
			// One advertisement is one multicast frame every host on the link
			// receives at once, so sending here would be the synchronised case
			// the delay exists for.
			m.pendingType = wire.MsgSolicit
			m.state = State6Init
			sd := randomDelay(m.params.SolMaxDelay, rnd)
			out.journal(m, "first Solicit after "+sd.String()+" (§18.2.1)")
			out.set(m, Timer6Delay, sd)
			// The prefixes of the advertisement that TAKES the decision are
			// accounted like every other advertisement's. Returning here
			// without them made the one advertisement that decides the one
			// advertisement nothing counts.
			m.countUnusedPrefixes(ra, out)
			if ok {
				// THE WINDOW IS THE SERVER'S, MEASURED FROM THE SOLICIT. The
				// deadline is armed here, in the Step that commits, and the
				// first Solicit leaves one delay later, so the delay is added
				// rather than taken out of the window. R-30's rule is that
				// nothing before the exchange eats the server's time; the
				// delay is one of those things.
				out.journal(m, "if no server answers within "+d.String()+" of the first Solicit this client will form an address from an autonomous prefix instead")
				out.set(m, Timer6AutoFallback, sd+d)
			} else {
				out.journal(m, "no fallback is configured: a silent server ends this acquisition")
			}
			return
		}
		out.journal(m, "Router Advertisement M=0: this link's addresses come from the advertisement itself (RFC 4862 §5.5.3)")
	}
	if m.dhcpCommitted {
		// Committed to DHCPv6. The advertisement is still observed — L1's
		// router table has already taken it — and its prefixes form nothing.
		m.countUnusedPrefixes(ra, out)
		return
	}
	m.observeSLAAC(now, rnd, ra, out)
}

// autoFallbackFired is Timer6AutoFallback: Mode6Auto said DHCPv6 and no server
// answered.
//
// THE COUNTER COUNTS EFFECT AND NOT INTENT. A fallback with no prefix to form
// from has not fallen back to anything, so it ends the acquisition with the
// reason that names what is missing and leaves the counter where it was. A
// counter that rose here would report a recovery that did not happen.
func (m *Machine6) autoFallbackFired(now Instant, rnd uint64, out *actions) {
	out.cancel(m, Timer6AutoFallback)
	if m.haveLse {
		out.journal(m, "the DHCPv6 fallback deadline passed with a lease in hand: nothing to do")
		return
	}
	m.dhcpCommitted = false
	// Re-read every prefix this machine has already seen: the advertisements
	// that carried them were observed while the machine was committed to
	// DHCPv6, and their Prefix Information options formed nothing then.
	changed := false
	for _, pi := range m.router.Prefixes {
		formed, moved, why := m.slaac.applyPIO(now, pi, m.params.LinkAddr)
		if why != SLAACIgnoreNone {
			m.slaac.counts.Ignored[why]++
			continue
		}
		changed = changed || formed || moved
	}
	if !changed || len(m.slaac.entries) == 0 {
		note := "no server answered and the router advertises no prefix this client can form an address from (RFC 4862 §5.5.3)"
		out.journal(m, note)
		out.failed(m, ReasonNoPrefix, note)
		m.endExchange(out)
		m.state = State6Discovering
		return
	}
	m.slaac.counts.Fallbacks++
	out.journal(m, "no server answered within the DHCPv6 budget: forming an address from the router's autonomous prefix instead")
	m.endExchange(out)
	m.adverts, m.windowDone = nil, false
	m.reportSLAAC(now, rnd, out)
}

// countUnusedPrefixes accounts the Prefix Information options of a link whose
// addresses do not come from them, so that "this router advertises an
// autonomous prefix and you are not using it" is a number rather than a
// silence.
func (m *Machine6) countUnusedPrefixes(ra *wire.RouterAdvert, out *actions) {
	n := 0
	for _, pi := range ra.Prefixes {
		if pi.Autonomous {
			n++
			m.slaac.counts.Ignored[SLAACIgnoreModeDHCP]++
		}
	}
	if n > 0 {
		out.journal(m, fmt.Sprintf("the advertisement carries %d autonomous prefix(es) and this client's address comes from DHCPv6: %s", n, SLAACIgnoreModeDHCP))
	}
}
