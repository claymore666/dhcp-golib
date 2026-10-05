// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"fmt"
	"net/netip"

	"github.com/claymore666/dhcp-golib/wire"
)

// Prefix6 is one delegated prefix of an IA_PD with the two lifetimes §21.22
// gives it, counted from Lease6.Start like Addr6's. The prefix is the one the
// IA Prefix option carries, masked to its own length, and its length is the
// server's and not the hint's (claymore666/docker-net-dhcp#214).
type Prefix6 struct {
	Prefix    netip.Prefix
	Preferred Duration
	Valid     Duration
}

func (p Prefix6) String() string {
	return fmt.Sprintf("%s pref=%s valid=%s", p.Prefix, p.Preferred, p.Valid)
}

// Prefix6Counters is what this machine did with the IA_PD of the messages that
// answered a client that asked for or holds a prefix. Granted is a Reply to a
// Solicit or a Request that gave at least one prefix. Refused is an Advertise
// or a Reply whose IA_PD gave none, with or without a status; Absent is one
// that carried no IA_PD with our IAID, and on a renewal the held prefixes stand.
// Changed is a Reply to a Renew or a Rebind whose prefixes differ from the ones
// held, a prefix that reached its valid lifetime included, or a held prefix
// whose valid lifetime ran out while no Reply was due (dhcp-golib#65).
// One exchange can count Refused or Absent twice, once for each message. Every
// one also writes a journal line (claymore666/docker-net-dhcp#214).
type Prefix6Counters struct {
	Granted uint64
	Refused uint64
	Absent  uint64
	Changed uint64
}

// PrefixCounters returns the counters as a copy (claymore666/docker-net-dhcp#214).
func (m *Machine6) PrefixCounters() Prefix6Counters { return m.pdCounts }

// pdResult is what the IA_PD of one message with our IAID produced.
type pdResult struct {
	found    bool
	status   wire.StatusCode
	t1, t2   Duration
	prefixes []Prefix6
	// zeroed is the prefixes the IA_PD names with a valid lifetime of 0.
	zeroed []netip.Prefix
}

// readIAPD finds the IA_PD whose IAID is ours and reads it. The IAID is the
// IA_NA's: RFC 8415 section 12 gives each IA type its own number space
// (claymore666/docker-net-dhcp#214).
func readIAPD(o wire.OptionsV6, iaid uint32) (pdResult, []string) {
	var notes []string
	var out pdResult
	ias, err := o.IAPDs()
	if err != nil {
		// A truncated IA_PD costs the IA_PD and nothing else: the IA_NA of the
		// same message is read on its own.
		return out, append(notes, "IA_PD option: "+err.Error())
	}
	for _, ia := range ias {
		if ia.IAID != iaid {
			notes = append(notes, fmt.Sprintf("IA_PD with IAID %d is not ours (%d): ignored", ia.IAID, iaid))
			continue
		}
		if out.found {
			notes = append(notes, fmt.Sprintf("a second IA_PD with IAID %d: ignored, this client sends one", iaid))
			continue
		}
		// §21.21 states the same T1/T2 rule as §21.4 for the IA_PD.
		if ia.T1 > 0 && ia.T2 > 0 && ia.T1 > ia.T2 {
			notes = append(notes, fmt.Sprintf("IA_PD T1 %s is greater than T2 %s, both non-zero: IA_PD discarded (§21.21)",
				SecondsToDuration(ia.T1), SecondsToDuration(ia.T2)))
			continue
		}
		out.found = true
		out.t1, out.t2 = SecondsToDuration(ia.T1), SecondsToDuration(ia.T2)
		st, ok, err := ia.Options.Status()
		switch {
		case err != nil:
			notes = append(notes, "IA_PD Status Code option: "+err.Error())
			out.status = wire.StatusMalformed
		case ok:
			out.status = st.Code
		default:
			out.status = wire.StatusSuccess
		}
		ps, zs, pn := iaPrefixes(ia.Options)
		notes = append(notes, pn...)
		out.prefixes = append(out.prefixes, ps...)
		out.zeroed = append(out.zeroed, zs...)
	}
	if len(ias) > 0 && !out.found {
		notes = append(notes, fmt.Sprintf("no usable IA_PD with our IAID %d in the message", iaid))
	}
	if out.status != wire.StatusSuccess && len(out.prefixes) > 0 {
		// §18.2.10.1: the client uses the delegated prefixes "from any IAs that
		// do not contain a Status Code option with the NoAddrsAvail or
		// NoPrefixAvail status code"; any other failure is no grant either.
		notes = append(notes, fmt.Sprintf("the IA_PD says %s and carries %d prefix(es): they are not ours to use (§18.2.10.1)", out.status, len(out.prefixes)))
		out.prefixes = nil
	}
	return out, notes
}

// iaPrefixes reads the IA Prefix options of one IA_PD, applies the discard
// rules and returns the prefixes named with a valid lifetime of 0 apart
// (claymore666/docker-net-dhcp#214).
func iaPrefixes(o wire.OptionsV6) ([]Prefix6, []netip.Prefix, []string) {
	var notes []string
	var out []Prefix6
	var zeroed []netip.Prefix
	ps, err := o.Prefixes()
	if err != nil {
		return nil, nil, append(notes, "IA Prefix option: "+err.Error())
	}
	for _, p := range ps {
		// §21.22: "The client MUST discard any prefixes for which the
		// preferred lifetime is greater than the valid lifetime."
		if !p.Valid() {
			notes = append(notes, fmt.Sprintf("IA Prefix %s has preferred %d greater than valid %d: discarded (§21.22)",
				p.Prefix, p.PreferredLifetime, p.ValidLifetime))
			continue
		}
		if p.ValidLifetime == 0 {
			notes = append(notes, fmt.Sprintf("IA Prefix %s has a valid lifetime of 0: discarded (§18.2.10.1)", p.Prefix))
			zeroed = append(zeroed, p.Prefix.Masked())
			continue
		}
		if !p.Prefix.IsValid() || !p.Prefix.Addr().Is6() || p.Prefix.Addr().Is4In6() || p.Prefix.Bits() < 1 {
			notes = append(notes, fmt.Sprintf("IA Prefix %s is not a usable IPv6 prefix: discarded", p.Prefix))
			continue
		}
		out = append(out, Prefix6{
			Prefix:    p.Prefix.Masked(),
			Preferred: SecondsToDuration(p.PreferredLifetime),
			Valid:     SecondsToDuration(p.ValidLifetime),
		})
	}
	return out, zeroed, notes
}

// readPrefixes reads the IA_PD of an Advertise or a Reply to a client that
// sent one and folds it into the counters (claymore666/docker-net-dhcp#214).
func (m *Machine6) readPrefixes(o wire.OptionsV6, grant bool, out *actions) pdResult {
	res, notes := readIAPD(o, m.params.IAID)
	m.countPrefixes(res, notes, grant, out)
	return res
}

// countPrefixes folds an IA_PD readIAPD read into the counters and the journal.
// A message with no IA_PD, or an empty one, grants none and the IA_NA lease
// stands whole (claymore666/docker-net-dhcp#214).
func (m *Machine6) countPrefixes(res pdResult, notes []string, grant bool, out *actions) {
	for _, n := range notes {
		out.journal(m, n)
	}
	switch {
	case !res.found:
		m.pdCounts.Absent++
		out.journal(m, "no IA_PD in the message that answered a prefix request: the IA_NA lease stands (§18.2.10.1)")
	case len(res.prefixes) == 0:
		m.pdCounts.Refused++
		out.journal(m, fmt.Sprintf("the IA_PD gave no prefix (status %s): the IA_NA lease stands (§18.2.10.1)", res.status))
	case grant:
		m.pdCounts.Granted++
		out.journal(m, fmt.Sprintf("the IA_PD gave %d delegated prefix(es)", len(res.prefixes)))
	}
}

// renewedPrefixes is the prefix set a Reply to a Renew or a Rebind leaves: the
// held prefixes in their order, each one the IA_PD names taken from it, then the
// new ones. A held prefix the Reply does not name keeps its own expiry, rebased
// onto newStart, and leaves once its valid lifetime has passed at now; one named
// with a valid lifetime of 0 leaves. An IA_PD with a failure status keeps none.
// §18.2.10.1: "Leave unchanged any information about leases the client has
// recorded in the IA but that were not included in the IA from the server", and
// §18.3.4 lets a server that cannot extend a prefix leave it out
// (claymore666/dhcp-golib#64).
func renewedPrefixes(held []Prefix6, heldStart Instant, res pdResult, newStart, now Instant) []Prefix6 {
	if res.found && res.status != wire.StatusSuccess {
		return res.prefixes
	}
	var out []Prefix6
	for _, h := range held {
		if i := prefixIndex(res.prefixes, h.Prefix); i >= 0 {
			out = append(out, res.prefixes[i])
			continue
		}
		if containsPrefix(res.zeroed, h.Prefix) {
			continue
		}
		pref, valid, ok := carryLifetimes(h.Preferred, h.Valid, heldStart, newStart, now)
		if !ok {
			continue
		}
		out = append(out, Prefix6{Prefix: h.Prefix, Preferred: pref, Valid: valid})
	}
	for _, p := range res.prefixes {
		if prefixIndex(held, p.Prefix) < 0 {
			out = append(out, p)
		}
	}
	return out
}

func prefixIndex(ps []Prefix6, p netip.Prefix) int {
	for i := range ps {
		if ps[i].Prefix == p {
			return i
		}
	}
	return -1
}

func containsPrefix(ps []netip.Prefix, p netip.Prefix) bool {
	for _, q := range ps {
		if q == p {
			return true
		}
	}
	return false
}

// ignorePrefixes says in the journal that an IA_PD nobody asked for is not
// read (claymore666/docker-net-dhcp#214).
func (m *Machine6) ignorePrefixes(o wire.OptionsV6, out *actions) {
	if n := o.Count(wire.OptV6IAPD); n > 0 {
		out.journal(m, fmt.Sprintf("%d IA_PD option(s) in a message that answers none we sent: ignored", n))
	}
}

// samePrefixes reports whether two prefix slices name the same delegation,
// lifetimes aside: that is "the prefix changed" for the counter and the
// journal, where Equal also weighs the lifetimes (claymore666/docker-net-dhcp#214).
func samePrefixes(a, b []Prefix6) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Prefix != b[i].Prefix {
			return false
		}
	}
	return true
}

// earliestT is the earlier of two renewal times across IAs, where zero is
// "the server left it to the client" and infinity loses to any finite time.
// RFC 8415 section 18.2.4 has the client use the earliest T1 of the IAs it
// holds (claymore666/docker-net-dhcp#214).
func earliestT(a, b Duration) Duration {
	switch {
	case a == 0:
		return b
	case b == 0:
		return a
	case a.IsInfinite():
		return b
	case b.IsInfinite():
		return a
	case b < a:
		return b
	}
	return a
}

// pdOwed reports whether the message that this Reply answers carried an IA_PD:
// every Solicit and Request of a client with a hint, and every Renew or
// Rebind that sent one (claymore666/docker-net-dhcp#214, dhcp-golib#65).
func (m *Machine6) pdOwed(renewal bool) bool {
	if !renewal && m.scope == scopeAll {
		return m.params.PrefixHint > 0 || len(m.pending.Prefixes) > 0
	}
	return m.pdSent
}

// heldPrefixes is the prefix set a Renew or Rebind carries: the lease's, or on
// the resumed Rebind the record's (claymore666/docker-net-dhcp#214).
func (m *Machine6) heldPrefixes() []Prefix6 {
	if m.haveLse {
		return m.lease.Prefixes
	}
	if m.resumeRebind && m.resume != nil {
		return m.resume.usablePrefixes()
	}
	return nil
}

// heldStart is the Instant the held prefixes' lifetimes count from: the lease's
// Start, or on the resumed Rebind this exchange's start, which is later than
// the record's base by at most the exchange's initial delay
// (claymore666/dhcp-golib#64).
func (m *Machine6) heldStart() Instant {
	if m.haveLse {
		return m.lease.Start
	}
	return m.exchangeStart
}

// heldIAs is the bindings the Request after a NoBinding names (claymore666/dhcp-golib#64).
func (m *Machine6) heldIAs() Lease6 {
	l := Lease6{IAID: m.params.IAID, Prefixes: m.heldPrefixes()}
	switch {
	case m.haveLse:
		l.Addrs, l.TempAddrs = m.lease.Addrs, m.lease.TempAddrs
	case m.resumeRebind && m.resume != nil:
		l.Addrs = m.resume.Addrs
	}
	return l
}

// usablePrefixes is the prefixes of r that can go on the wire.
func (r *Resume6) usablePrefixes() []Prefix6 {
	if r == nil {
		return nil
	}
	var out []Prefix6
	for _, p := range r.Prefixes {
		if p.Prefix.IsValid() && p.Prefix.Addr().Is6() && !p.Prefix.Addr().Is4In6() && p.Prefix.Bits() >= 1 {
			out = append(out, p)
		}
	}
	return out
}

// buildPD renders the IA_PD a message carries. The IAID is the IA_NA's. With
// no prefixes and a hint it carries one IA Prefix of the hinted length and zero
// lifetimes (RFC 8415 section 18.2.1 lets a client hint at a prefix length);
// zero makes every lifetime on the wire zero (claymore666/docker-net-dhcp#214).
func (m *Machine6) buildPD(prefixes []Prefix6, hint int, zero bool) (wire.OptionV6, error) {
	ia := &wire.IAPD{IAID: m.params.IAID}
	add := func(p netip.Prefix, pref, valid uint32) error {
		v, err := wire.EncodeIAPrefix(&wire.IAPrefix{PreferredLifetime: pref, ValidLifetime: valid, Prefix: p})
		if err != nil {
			return err
		}
		ia.Options = append(ia.Options, wire.OptionV6{Code: wire.OptV6IAPrefix, Data: v})
		return nil
	}
	for _, p := range prefixes {
		var pref, valid uint32
		if !zero {
			pref, valid = durationToSeconds(p.Preferred), durationToSeconds(p.Valid)
		}
		if err := add(p.Prefix, pref, valid); err != nil {
			return wire.OptionV6{}, err
		}
	}
	if len(prefixes) == 0 && hint > 0 {
		if err := add(netip.PrefixFrom(netip.IPv6Unspecified(), hint), 0, 0); err != nil {
			return wire.OptionV6{}, err
		}
	}
	v, err := wire.EncodeIAPD(ia)
	if err != nil {
		return wire.OptionV6{}, err
	}
	return wire.OptionV6{Code: wire.OptV6IAPD, Data: v}, nil
}

// iaScope is the IAs an exchange names (claymore666/dhcp-golib#70).
type iaScope uint8

const (
	scopeAll iaScope = iota
	scopeNA
	scopePD
)

// heldPD is the IA_PD's server and times as held before a Reply: the ones a
// Reply that leaves the IA_PD out keeps (RFC 8415 section 18.2.10.1).
func (m *Machine6) heldPD() (srv []byte, t1, t2 Duration, start Instant) {
	switch {
	case m.haveLse:
		return m.lease.prefixServer(), m.lease.pdT1, m.lease.pdT2, m.lease.pdOrigin()
	case m.resumeRebind && m.resume != nil:
		srv = m.resume.PrefixServerDUID
		if len(srv) == 0 {
			srv = m.resume.ServerDUID
		}
		return srv, m.resume.T1, m.resume.T2, m.resumeAt
	}
	return nil, 0, 0, 0
}

// rebasePrefixes moves prefix lifetimes counted from from onto to, keeping
// the instants they end at.
func rebasePrefixes(ps []Prefix6, from, to, now Instant) []Prefix6 {
	var out []Prefix6
	for _, p := range ps {
		if pref, valid, ok := carryLifetimes(p.Preferred, p.Valid, from, to, now); ok {
			out = append(out, Prefix6{Prefix: p.Prefix, Preferred: pref, Valid: valid})
		}
	}
	return out
}

// keepHeldPD gives l the IA_PD server and times it held before the Reply.
func (m *Machine6) keepHeldPD(l *Lease6) {
	srv, t1, t2, start := m.heldPD()
	l.PrefixServerDUID = append([]byte(nil), srv...)
	l.pdT1, l.pdT2, l.pdStart, l.pdTimed = t1, t2, start, true
}

// paceOmission holds the next Renew or Rebind back when the Reply left out an
// IA_PD that is already due. §18.2.10.1: "the client MUST rate-limit its
// transmissions ... and MAY just wait for the normal retransmission time (as
// if the Reply message had not been received)" (claymore666/dhcp-golib#70).
func (m *Machine6) paceOmission(now Instant, rnd uint64, found bool, l Lease6, out *actions) {
	if found || len(l.Prefixes) == 0 {
		m.holdoff, m.omitRT = 0, 0
		return
	}
	if !m.pdSent {
		// a message that named the IA_NA alone says nothing of the IA_PD
		return
	}
	_, pd := l.groupDeadlines()
	if !pd.HasRenew || pd.Renew.After(now) {
		return
	}
	if m.omitRT == 0 {
		m.omitRT = m.rt
	} else {
		m.omitRT = m.sched.Next(m.omitRT, rnd)
	}
	m.holdoff = now.Add(m.omitRT)
	out.journal(m, "the Reply left out an IA_PD that is due: the next exchange waits "+m.omitRT.String()+" (§18.2.10.1)")
}

// renewalGroups is groupDeadlines with the hold-off on the IA_PD's times
// alone, so the IA_NA renews on its own T1 and T2 (claymore666/dhcp-golib#70).
func (m *Machine6) renewalGroups() (na, pd Deadlines) {
	na, pd = m.lease.groupDeadlines()
	pd.Renew, pd.Rebind = laterOf(pd.Renew, m.holdoff), laterOf(pd.Rebind, m.holdoff)
	return na, pd
}

// armRenewal arms T1 and T2 for the lease held. With the IA_PD on its own
// times, a T1 no earlier than T2 is not armed: the Rebind names every IA
// (RFC 8415 section 18.2.5; claymore666/dhcp-golib#70).
func (m *Machine6) armRenewal(now Instant, out *actions) {
	d := m.lease.Deadlines()
	if m.lease.pdTimed {
		na, pd := m.renewalGroups()
		d.Renew, d.HasRenew = earliestDeadline(na.Renew, na.HasRenew, pd.Renew, pd.HasRenew)
		d.Rebind, d.HasRebind = earliestDeadline(na.Rebind, na.HasRebind, pd.Rebind, pd.HasRebind)
		if d.HasRebind && !d.Rebind.After(d.Renew) {
			d.HasRenew = false
		}
	}
	m.armDeadline(now, Timer6Renew, d.Renew, d.HasRenew, out)
	m.armDeadline(now, Timer6Rebind, d.Rebind, d.HasRebind, out)
}

// resumeBound returns to BOUND6 with the lease as held, after an exchange
// that changed none of it.
func (m *Machine6) resumeBound(now Instant, rnd uint64, out *actions) {
	m.msgType = 0
	out.cancel(m, Timer6Retransmit)
	m.dropPending()
	m.state = State6Bound
	m.armRenewal(now, out)
	m.armExpiry(now, out)
	m.armOwedRefresh(rnd, out)
}

// laterOf is the later of a deadline and a hold-off.
func laterOf(at, holdoff Instant) Instant {
	if holdoff.After(at) {
		return holdoff
	}
	return at
}

// releaseDelegated sends the second Release of a split lease to the server
// that delegated the prefixes, §18.2.7: "The client places the identifier of
// the server that allocated the lease(s) in a Server Identifier option"
// (claymore666/dhcp-golib#70).
func (m *Machine6) releaseDelegated(now Instant, rnd uint64, out *actions) {
	if len(m.releasePD) == 0 {
		return
	}
	m.server = m.releasePDServer
	m.releasing, m.releasingTA, m.releasingPrefixes = nil, nil, m.releasePD
	m.releasePD, m.releasePDServer = nil, nil
	out.journal(m, "releasing the delegated prefixes with the server that delegated them (§18.2.7)")
	m.startExchange(now, rnd, wire.MsgRelease6, out)
}
