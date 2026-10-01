// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"fmt"
	"net/netip"

	"github.com/claymore666/dhcp-golib/wire"
)

// Temporary6Counters is what this machine did with the IA_TA of the messages
// that answered a Params6.Temporary client. Granted is a Reply that gave at
// least one temporary address. Refused is an Advertise or a Reply whose IA_TA
// gave none, with or without a status. Absent is an Advertise or a Reply that
// carried no IA_TA with our IAID, so one exchange can count Absent twice, once
// for each message. Conflicted is a temporary address declined after duplicate
// address detection found it in use. Every one also writes a journal line
// (claymore666/docker-net-dhcp#927).
type Temporary6Counters struct {
	Granted    uint64
	Refused    uint64
	Absent     uint64
	Conflicted uint64
}

// TemporaryCounters returns the counters as a copy
// (claymore666/docker-net-dhcp#927).
func (m *Machine6) TemporaryCounters() Temporary6Counters { return m.tempCounts }

// taResult is what the IA_TA of one message with our IAID produced.
type taResult struct {
	found  bool
	status wire.StatusCode
	addrs  []Addr6
}

// readIATA finds the IA_TA whose IAID is ours and reads it. The IAID is the
// one the IA_NA uses: RFC 8415 section 12 gives each IA type its own IAID
// number space, so the same number names two different associations and a
// client needs no second one (claymore666/docker-net-dhcp#927).
func readIATA(o wire.OptionsV6, iaid uint32) (taResult, []string) {
	var notes []string
	var out taResult
	ias, err := o.IATAs()
	if err != nil {
		return out, append(notes, "IA_TA option: "+err.Error())
	}
	for _, ia := range ias {
		if ia.IAID != iaid {
			notes = append(notes, fmt.Sprintf("IA_TA with IAID %d is not ours (%d): ignored", ia.IAID, iaid))
			continue
		}
		if out.found {
			notes = append(notes, fmt.Sprintf("a second IA_TA with IAID %d: ignored, this client sends one", iaid))
			continue
		}
		out.found = true
		st, ok, err := ia.Options.Status()
		switch {
		case err != nil:
			notes = append(notes, "IA_TA Status Code option: "+err.Error())
			out.status = wire.StatusMalformed
		case ok:
			out.status = st.Code
		default:
			out.status = wire.StatusSuccess
		}
		addrs, ans := iaAddrs(ia.Options, "IA_TA Address option")
		notes = append(notes, ans...)
		out.addrs = append(out.addrs, addrs...)
	}
	if len(ias) > 0 && !out.found {
		notes = append(notes, fmt.Sprintf("no IA_TA with our IAID %d in the message", iaid))
	}
	if out.status != wire.StatusSuccess && len(out.addrs) > 0 {
		// RFC 8415 section 18.2.10.1: the client uses the addresses "from any
		// IAs that do not contain a Status Code option with the NoAddrsAvail
		// or NoPrefixAvail status code"; any other failure is no grant either.
		notes = append(notes, fmt.Sprintf("the IA_TA says %s and carries %d address(es): they are not ours to use (§18.2.10.1)", out.status, len(out.addrs)))
		out.addrs = nil
	}
	return out, notes
}

// dropStable removes from temp every address the stable IA_NA also holds: one
// address in two IAs would be installed once and released twice
// (claymore666/docker-net-dhcp#927).
func dropStable(temp, stable []Addr6) ([]Addr6, []string) {
	var keep []Addr6
	var notes []string
	for _, t := range temp {
		dup := false
		for _, s := range stable {
			if s.Addr == t.Addr {
				dup = true
				break
			}
		}
		if dup {
			notes = append(notes, fmt.Sprintf("IA_TA address %s is also in the IA_NA: kept as the stable address only", t.Addr))
			continue
		}
		keep = append(keep, t)
	}
	return keep, notes
}

// readTemporary reads the IA_TA of a Reply or an Advertise for a client that
// asked for one, and folds it into the counters. It reports the addresses to
// keep; a message that carried no IA_TA, or an empty one, keeps none and the
// IA_NA lease stands whole (claymore666/docker-net-dhcp#927).
func (m *Machine6) readTemporary(o wire.OptionsV6, stable []Addr6, reply bool, out *actions) []Addr6 {
	res, notes := readIATA(o, m.params.IAID)
	for _, n := range notes {
		out.journal(m, n)
	}
	kept, ns := dropStable(res.addrs, stable)
	for _, n := range ns {
		out.journal(m, n)
	}
	switch {
	case !res.found:
		m.tempCounts.Absent++
		out.journal(m, "no IA_TA in the message that answered a temporary-address request: the IA_NA lease stands")
	case len(kept) == 0:
		m.tempCounts.Refused++
		out.journal(m, fmt.Sprintf("the IA_TA gave no address (status %s): the IA_NA lease stands (§18.2.10.1)", res.status))
	case reply:
		m.tempCounts.Granted++
		out.journal(m, fmt.Sprintf("the IA_TA gave %d temporary address(es)", len(kept)))
	}
	return kept
}

// ignoreTemporary says in the journal that an IA_TA nobody asked for is not
// read: this client sends none in a Renew or Rebind and, unless Params6.Temporary
// is set, in no message at all (claymore666/docker-net-dhcp#927).
func (m *Machine6) ignoreTemporary(o wire.OptionsV6, out *actions) {
	if n := o.Count(wire.OptV6IATA); n > 0 {
		out.journal(m, fmt.Sprintf("%d IA_TA option(s) in a message that answers none we sent: ignored", n))
	}
}

// expiry is the instant an address's valid lifetime ends, counted from the
// lease's Start, and false for an infinite lifetime.
func expiry(start Instant, d Duration) (Instant, bool) {
	if d.IsInfinite() {
		return 0, false
	}
	return start.Add(d), true
}

// carryTemp is the temporary addresses of prev that a Reply to a Renew or a
// Rebind keeps. That Reply carries no IA_TA because the message carried none,
// and RFC 8415 section 13.2 makes renewing temporary addresses NOT RECOMMENDED,
// so each one keeps its own expiry: the lifetimes are rebased onto the new
// Start and one whose valid lifetime has passed at now is dropped
// (claymore666/docker-net-dhcp#927).
func carryTemp(prev []Addr6, prevStart, newStart, now Instant) []Addr6 {
	var out []Addr6
	for _, a := range prev {
		c := a
		if end, finite := expiry(prevStart, a.Valid); finite {
			if !end.After(now) {
				continue
			}
			c.Valid = end.Sub(newStart)
		}
		if pend, finite := expiry(prevStart, a.Preferred); finite {
			c.Preferred = pend.Sub(newStart)
			if c.Preferred < 0 {
				c.Preferred = 0
			}
		}
		out = append(out, c)
	}
	return out
}

// tempEqual compares two temporary-address slices as Lease6.Equal compares the
// stable ones, in the frame of a clock: the same address ending at the same
// instant is one grant, however many renewals have moved Start since
// (claymore666/docker-net-dhcp#927).
func tempEqual(a Lease6, b Lease6) bool {
	if len(a.TempAddrs) != len(b.TempAddrs) {
		return false
	}
	for i := range a.TempAddrs {
		x, y := a.TempAddrs[i], b.TempAddrs[i]
		if x.Addr != y.Addr || x.PrefixLen != y.PrefixLen {
			return false
		}
		if !sameEnd(a.Start, x.Valid, b.Start, y.Valid) || !samePreferred(a.Start, x.Preferred, b.Start, y.Preferred) {
			return false
		}
	}
	return true
}

// samePreferred is sameEnd for the preferred lifetime, except that two ends
// which both lie before the later of the two Starts are equal: carryTemp clamps
// a passed preferred time to its new Start, so without this every renewal after
// the address was deprecated would read as a change (claymore666/docker-net-dhcp#927).
func samePreferred(s1 Instant, d1 Duration, s2 Instant, d2 Duration) bool {
	e1, f1 := expiry(s1, d1)
	e2, f2 := expiry(s2, d2)
	if f1 != f2 {
		return false
	}
	if f1 {
		later := s1
		if s2.After(later) {
			later = s2
		}
		if !e1.After(later) && !e2.After(later) {
			return true
		}
	}
	return e1 == e2
}

func sameEnd(s1 Instant, d1 Duration, s2 Instant, d2 Duration) bool {
	e1, f1 := expiry(s1, d1)
	e2, f2 := expiry(s2, d2)
	return f1 == f2 && e1 == e2
}

// withoutTemp is l with the temporary addresses in drop taken out.
func withoutTemp(l Lease6, drop []netip.Addr) Lease6 {
	var keep []Addr6
	for _, a := range l.TempAddrs {
		if !containsAddr(drop, a.Addr) {
			keep = append(keep, a)
		}
	}
	l.TempAddrs = keep
	return l
}

// freshTemp is the temporary addresses of l that no lease held so far
// carries: the ones this machine has no duplicate address detection result for
// (claymore666/docker-net-dhcp#927).
func (m *Machine6) freshTemp(l Lease6) []netip.Addr {
	var fresh []netip.Addr
	for _, a := range l.TempAddrs {
		held := false
		for _, h := range m.lease.TempAddrs {
			if h.Addr == a.Addr {
				held = true
				break
			}
		}
		if !held {
			fresh = append(fresh, a.Addr)
		}
	}
	return fresh
}

// isTemp reports whether a is one of l's temporary addresses.
func isTemp(l Lease6, a netip.Addr) bool {
	for _, t := range l.TempAddrs {
		if t.Addr == a {
			return true
		}
	}
	return false
}

// buildTA renders the IA_TA a Solicit, a Request or a Decline carries. A
// Solicit and a Request carry the client's IAID and, in the Request, the
// addresses the Advertise offered (RFC 8415 section 18.2.2: an IA with no
// address makes dnsmasq take the Request for a rapid Solicit and allocate
// another one); a Decline carries the temporary addresses it declines, with
// lifetimes zero. A Renew, a Rebind, a Release and a Confirm carry none
// (claymore666/docker-net-dhcp#927).
func (m *Machine6) buildTA(addrs []Addr6, zeroLifetimes bool) (wire.OptionV6, error) {
	ia := &wire.IATA{IAID: m.params.IAID}
	for _, a := range addrs {
		if !a.Addr.Is6() || a.Addr.Is4In6() || a.Addr.IsUnspecified() {
			continue
		}
		e := &wire.IAAddr{Addr: a.Addr}
		if !zeroLifetimes {
			e.PreferredLifetime = durationToSeconds(a.Preferred)
			e.ValidLifetime = durationToSeconds(a.Valid)
		}
		v, err := wire.EncodeIAAddr(e)
		if err != nil {
			return wire.OptionV6{}, err
		}
		ia.Options = append(ia.Options, wire.OptionV6{Code: wire.OptV6IAAddr, Data: v})
	}
	v, err := wire.EncodeIATA(ia)
	if err != nil {
		return wire.OptionV6{}, err
	}
	return wire.OptionV6{Code: wire.OptV6IATA, Data: v}, nil
}
