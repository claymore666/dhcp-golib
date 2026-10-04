// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"net/netip"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

const pd6Third = "2001:db8:1:300::/64"

// keepBound is pd6Bound with iapd on the Advertise and the Reply.
func keepBound(t *testing.T, iapd wire.OptionV6) *Machine6 {
	t.Helper()
	m, _, acts := pd6ToDAD(t, pd6Params(64), []wire.OptionV6{iapd}, iapd)
	for _, a := range pd6Targets(acts) {
		m.Step(at(4), 0, DADResult(a, false))
	}
	if m.State() != State6Bound {
		t.Fatalf("the exchange left the machine in %s, want %s", m.State(), State6Bound)
	}
	return m
}

func keepAddrs(t *testing.T, ia *wire.IANA) []*wire.IAAddr {
	t.Helper()
	as, err := ia.Options.Addrs()
	if err != nil {
		t.Fatalf("Addrs: %v", err)
	}
	return as
}

// keepWant is one prefix a test expects: fresh lifetimes from the Reply, or
// carried with the ends it held before.
type keepWant struct {
	prefix  string
	carried bool
	pref    Duration
	valid   Duration
}

func keepCheck(t *testing.T, before, after Lease6, want []keepWant) {
	t.Helper()
	if len(after.Prefixes) != len(want) {
		t.Fatalf("the lease holds %v, want %d prefix(es)", after.Prefixes, len(want))
	}
	for i, w := range want {
		p := after.Prefixes[i]
		if p.Prefix != netip.MustParsePrefix(w.prefix) {
			t.Errorf("prefix %d is %s, want %s", i, p.Prefix, w.prefix)
			continue
		}
		if !w.carried {
			if p.Preferred != w.pref || p.Valid != w.valid {
				t.Errorf("%s has %s/%s, want the Reply's %s/%s", p.Prefix, p.Preferred, p.Valid, w.pref, w.valid)
			}
			continue
		}
		j := prefixIndex(before.Prefixes, p.Prefix)
		if j < 0 {
			t.Fatalf("%s is carried but was not held", p.Prefix)
		}
		h := before.Prefixes[j]
		if got, was := after.Start.Add(p.Valid), before.Start.Add(h.Valid); got != was {
			t.Errorf("%s ends at %v, held it ended at %v", p.Prefix, got, was)
		}
		if got, was := after.Start.Add(p.Preferred), before.Start.Add(h.Preferred); got != was {
			t.Errorf("%s is preferred until %v, held until %v", p.Prefix, got, was)
		}
	}
}

// TestPrefixRenewalWithoutIAPDKeepsThePrefix: a Reply to a Renew that carries
// the IA_NA and no IA_PD refreshes the address and leaves the held prefix with
// its own expiry, as a plain renewal (RFC 8415 section 18.2.10.1;
// claymore666/dhcp-golib#64).
func TestPrefixRenewalWithoutIAPDKeepsThePrefix(t *testing.T) {
	m := keepBound(t, optIAPD(t, capIAID, 150, 240, []pd6Spec{{pd6First, 300, 600}}))
	before, _ := m.Lease()
	_, acts := pd6Renew(t, m, 152, 153)
	after, _ := m.Lease()
	keepCheck(t, before, after, []keepWant{{prefix: pd6First, carried: true}})
	if after.Start != at(152) || len(after.Addrs) != 1 || after.Addrs[0].Valid != 300*Second {
		t.Errorf("the IA_NA was not refreshed: Start %v, Addrs %v", after.Start, after.Addrs)
	}
	if after.T1 != 150*Second || after.T2 != 240*Second {
		t.Errorf("T1/T2 = %s/%s, want the IA_NA's 150 s/240 s", after.T1, after.T2)
	}
	if count(acts, ActLeaseRenewed) != 1 || count(acts, ActLeaseChanged) != 0 {
		t.Errorf("%d Renewed, %d Changed, want a plain renewal", count(acts, ActLeaseRenewed), count(acts, ActLeaseChanged))
	}
	pd6Counters(t, m, Prefix6Counters{Granted: 1, Absent: 1})
}

// TestPrefixRenewalKeepsWhatTheReplyLeavesOut: a held prefix the IA_PD does
// not name stands with its own expiry, one named with a valid lifetime of 0
// leaves, a new one is added, and an IA_PD with a failure status or none at
// all is read as RFC 8415 sections 18.2.10.1 and 21.21 say
// (claymore666/dhcp-golib#64).
func TestPrefixRenewalKeepsWhatTheReplyLeavesOut(t *testing.T) {
	both := []pd6Spec{{pd6First, 300, 600}, {pd6Other, 300, 600}}
	cases := []struct {
		name    string
		iapd    wire.OptionV6
		want    []keepWant
		changed uint64
		counts  Prefix6Counters
	}{
		{"names one", optIAPD(t, capIAID, 150, 240, []pd6Spec{{pd6First, 400, 700}}),
			[]keepWant{{pd6First, false, 400 * Second, 700 * Second}, {prefix: pd6Other, carried: true}}, 0, Prefix6Counters{}},
		{"names one and ends the other", optIAPD(t, capIAID, 150, 240, []pd6Spec{{pd6First, 400, 700}, {pd6Other, 0, 0}}),
			[]keepWant{{pd6First, false, 400 * Second, 700 * Second}}, 1, Prefix6Counters{Changed: 1}},
		{"names a new one", optIAPD(t, capIAID, 150, 240, []pd6Spec{{pd6Third, 400, 700}}),
			[]keepWant{{prefix: pd6First, carried: true}, {prefix: pd6Other, carried: true}, {pd6Third, false, 400 * Second, 700 * Second}}, 1, Prefix6Counters{Changed: 1}},
		{"an empty IA_PD", optIAPD(t, capIAID, 150, 240, nil),
			[]keepWant{{prefix: pd6First, carried: true}, {prefix: pd6Other, carried: true}}, 0, Prefix6Counters{Refused: 1}},
		{"NoPrefixAvail", optIAPD(t, capIAID, 0, 0, nil, optStatus(wire.StatusNoPrefixAvail)),
			nil, 1, Prefix6Counters{Refused: 1, Changed: 1}},
		{"UnspecFail with a prefix in it", optIAPD(t, capIAID, 0, 0, []pd6Spec{{pd6First, 300, 600}}, optStatus(wire.StatusUnspecFail)),
			nil, 1, Prefix6Counters{Refused: 1, Changed: 1}},
		{"T1 greater than T2", optIAPD(t, capIAID, 300, 200, []pd6Spec{{pd6First, 400, 700}}),
			[]keepWant{{prefix: pd6First, carried: true}, {prefix: pd6Other, carried: true}}, 0, Prefix6Counters{Absent: 1}},
		{"another IAID", optIAPD(t, capIAID+1, 150, 240, []pd6Spec{{pd6Third, 400, 700}}),
			[]keepWant{{prefix: pd6First, carried: true}, {prefix: pd6Other, carried: true}}, 0, Prefix6Counters{Absent: 1}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := keepBound(t, optIAPD(t, capIAID, 150, 240, both))
			before, _ := m.Lease()
			_, acts := pd6Renew(t, m, 152, 153, c.iapd)
			after, _ := m.Lease()
			keepCheck(t, before, after, c.want)
			if got := m.PrefixCounters().Changed; got != c.changed {
				t.Errorf("prefix_changed is %d, want %d", got, c.changed)
			}
			c.counts.Granted = 1
			pd6Counters(t, m, c.counts)
			if c.changed == 1 && count(acts, ActLeaseChanged) != 1 {
				t.Errorf("%d Changed, want one", count(acts, ActLeaseChanged))
			}
		})
	}
}

// TestPrefixRenewalWithAnotherPrefixKeepsTheOld: a Reply that gives another
// prefix and leaves the held one out adds the new one; the held one stands
// until its valid lifetime ends, because RFC 8415 section 18.3.4 has a server
// that wants it gone send it with lifetimes of 0 (claymore666/dhcp-golib#64).
func TestPrefixRenewalWithAnotherPrefixKeepsTheOld(t *testing.T) {
	m := pd6Bound(t, pd6Params(64))
	before, _ := m.Lease()
	_, acts := pd6Renew(t, m, 152, 153, optIAPD(t, capIAID, 120, 200, []pd6Spec{{pd6Other, 300, 600}}))
	after, _ := m.Lease()
	keepCheck(t, before, after, []keepWant{{prefix: pd6First, carried: true}, {pd6Other, false, 300 * Second, 600 * Second}})
	if count(acts, ActLeaseChanged) != 1 {
		t.Errorf("%d Changed, want one", count(acts, ActLeaseChanged))
	}
	if ch := pd6Lease(t, acts, ActLeaseChanged); len(ch.Prefixes) != 2 {
		t.Errorf("Changed carries %v, want both prefixes", ch.Prefixes)
	}
	pd6Counters(t, m, Prefix6Counters{Granted: 1, Changed: 1})
}

// TestACarriedPrefixPastItsValidLifetimeLeaves: a held prefix the Reply leaves
// out whose valid lifetime has passed is gone, and that is a change
// (claymore666/dhcp-golib#64).
func TestACarriedPrefixPastItsValidLifetimeLeaves(t *testing.T) {
	m := keepBound(t, optIAPD(t, capIAID, 0, 0, []pd6Spec{{pd6First, 50, 100}}))
	_, acts := pd6Renew(t, m, 152, 153)
	if l, _ := m.Lease(); len(l.Prefixes) != 0 {
		t.Errorf("the lease holds %v after the prefix's valid lifetime", l.Prefixes)
	}
	if count(acts, ActLeaseChanged) != 1 {
		t.Errorf("%d Changed, want one", count(acts, ActLeaseChanged))
	}
	pd6Counters(t, m, Prefix6Counters{Granted: 1, Absent: 1, Changed: 1})
}

// TestALaterIAPDUpdatesACarriedPrefix: after a Reply that left the prefix out,
// the next Renew names it and the next IA_PD sets its lifetimes or ends it
// (claymore666/dhcp-golib#64).
func TestALaterIAPDUpdatesACarriedPrefix(t *testing.T) {
	for _, c := range []struct {
		name string
		spec pd6Spec
		want []keepWant
	}{
		{"new lifetimes", pd6Spec{pd6First, 400, 800}, []keepWant{{pd6First, false, 400 * Second, 800 * Second}}},
		{"valid lifetime 0", pd6Spec{pd6First, 0, 0}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := pd6Bound(t, pd6Params(64))
			pd6Renew(t, m, 152, 153)
			before, _ := m.Lease()
			ren, _ := pd6Renew(t, m, 252, 253, optIAPD(t, capIAID, 120, 200, []pd6Spec{c.spec}))
			if _, pds := pd6IAs(t, ren); len(pds) != 1 || len(pd6Prefixes(t, pds[0])) != 1 || pd6Prefixes(t, pds[0])[0].Prefix != netip.MustParsePrefix(pd6First) {
				t.Errorf("the Renew after the carry names %v, want %s", pds, pd6First)
			}
			after, _ := m.Lease()
			keepCheck(t, before, after, c.want)
		})
	}
}

// TestNoBindingInTheIAPDRequestsWithEveryIA: an IA_PD that says NoBinding in a
// Reply to a Renew is answered with a Request to that server naming the held
// address and prefix; RFC 8415 section 18.2.10.1: the client "Sends a Request
// message to the server that responded if any of the IAs in the Reply message
// contain the NoBinding status code. The client places IA options in this
// message for all IAs." (claymore666/dhcp-golib#64)
func TestNoBindingInTheIAPDRequestsWithEveryIA(t *testing.T) {
	for _, c := range []struct {
		name string
		opts func() []wire.OptionV6
	}{
		{"IA_PD", func() []wire.OptionV6 {
			return pd6Base(t, optIAPD(t, capIAID, 0, 0, nil, optStatus(wire.StatusNoBinding)))
		}},
		{"IA_NA", func() []wire.OptionV6 {
			return []wire.OptionV6{optClientID(capDUID), optServerID(testServerDUID),
				optIANA(t, capIAID, 0, 0, nil, optStatus(wire.StatusNoBinding)), pd6Good(t)}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := pd6Bound(t, pd6Params(64))
			_, acts := m.Step(at(152), 7, TimerFired(Timer6Renew))
			ren := mustSendV6(t, acts, wire.MsgRenew)
			s, acts := m.Step(at(153), 9, receivedV6(t, wire.MsgReply, ren.XID, c.opts()...))
			if s != State6Requesting {
				t.Fatalf("NoBinding in the %s left the machine in %s, want %s", c.name, s, State6Requesting)
			}
			if !pd6Says(acts, "the "+c.name+" says NoBinding") {
				t.Errorf("no journal line names the %s:%s", c.name, pd6Journal(acts))
			}
			req := mustSendV6(t, acts, wire.MsgRequest6)
			nas, pds := pd6IAs(t, req)
			if len(nas) != 1 || len(keepAddrs(t, nas[0])) == 0 {
				t.Errorf("the Request's IA_NA is %v, want the held address", nas)
			}
			if len(pds) != 1 || len(pd6Prefixes(t, pds[0])) != 1 || pd6Prefixes(t, pds[0])[0].Prefix != netip.MustParsePrefix(pd6First) {
				t.Errorf("the Request's IA_PD is %v, want the held %s", pds, pd6First)
			}
			if l, held := m.Lease(); !held || len(l.Prefixes) != 1 {
				t.Errorf("the lease went on a NoBinding: %v %v", l, held)
			}
			s, _ = m.Step(at(154), 0, pd6Reply(t, req.XID, optIAPD(t, capIAID, 120, 200, []pd6Spec{{pd6First, 400, 800}})))
			if l, _ := m.Lease(); s != State6Bound || len(l.Prefixes) != 1 || l.Prefixes[0].Valid != 800*Second {
				t.Errorf("the Reply to the Request left %s with %v, want the prefix at 800 s", s, l.Prefixes)
			}
		})
	}
}

// TestResumeRebindNoBindingInTheIAPDRequests: the resumed Rebind's Reply that
// renews the address and says NoBinding in the IA_PD is answered with a Request
// naming the remembered address and prefix (RFC 8415 section 18.2.10.1;
// claymore666/dhcp-golib#64).
func TestResumeRebindNoBindingInTheIAPDRequests(t *testing.T) {
	m, reb, _ := pr6Rebinding(t, pr6Params())
	s, acts := m.Step(at(2), 3, pr6Reply(t, reb.XID, pr6IANA(t), optIAPD(t, capIAID, 0, 0, nil, optStatus(wire.StatusNoBinding))))
	if s != State6Requesting {
		t.Fatalf("the Reply left the machine in %s, want %s", s, State6Requesting)
	}
	nas, pds := pd6IAs(t, mustSendV6(t, acts, wire.MsgRequest6))
	if len(nas) != 1 || len(keepAddrs(t, nas[0])) != 1 {
		t.Errorf("the Request's IA_NA is %v, want the remembered address", nas)
	}
	if len(pds) != 1 || len(pd6Prefixes(t, pds[0])) != 1 || pd6Prefixes(t, pds[0])[0].Prefix != netip.MustParsePrefix(pr6First) {
		t.Errorf("the Request's IA_PD is %v, want the remembered %s", pds, pr6First)
	}
}

// TestLeaseEqualReadsEndsNotDurations: an address or a prefix with the same
// ends under a later Start is the same lease, a later end is not
// (claymore666/dhcp-golib#64).
func TestLeaseEqualReadsEndsNotDurations(t *testing.T) {
	a := netip.MustParseAddr(pd6Addr)
	p := netip.MustParsePrefix(pd6First)
	l := Lease6{Start: at(0), Addrs: []Addr6{{Addr: a, Preferred: 300 * Second, Valid: 300 * Second}},
		Prefixes: []Prefix6{{Prefix: p, Preferred: 300 * Second, Valid: 600 * Second}}}
	same := Lease6{Start: at(100), Addrs: []Addr6{{Addr: a, Preferred: 200 * Second, Valid: 200 * Second}},
		Prefixes: []Prefix6{{Prefix: p, Preferred: 200 * Second, Valid: 500 * Second}}}
	if !l.Equal(same) || !same.Equal(l) {
		t.Errorf("%v and %v end at the same instants and compare unequal", l, same)
	}
	for _, c := range []struct {
		name string
		edit func(*Lease6)
	}{
		{"prefix valid", func(o *Lease6) { o.Prefixes[0].Valid++ }},
		{"prefix preferred", func(o *Lease6) { o.Prefixes[0].Preferred++ }},
		{"address valid", func(o *Lease6) { o.Addrs[0].Valid++ }},
		{"address preferred", func(o *Lease6) { o.Addrs[0].Preferred++ }},
		{"address prefix length", func(o *Lease6) { o.Addrs[0].PrefixLen = 64 }},
	} {
		o := same
		o.Addrs = append([]Addr6(nil), same.Addrs...)
		o.Prefixes = append([]Prefix6(nil), same.Prefixes...)
		c.edit(&o)
		if l.Equal(o) {
			t.Errorf("%s: a later end compares equal", c.name)
		}
	}
}

// keepTwoAddrs binds a machine without a prefix to an IA_NA of two addresses.
func keepTwoAddrs(t *testing.T) *Machine6 {
	t.Helper()
	ia := optIANA(t, capIAID, 150, 240, []iaAddrSpec{{pd6Addr, 300, 300}, {pd6Temp, 300, 300}})
	m, sol := solicit6(t, testParams6())
	_, acts := m.Step(at(2), capXIDRequest, receivedV6(t, wire.MsgAdvertise, sol.XID, optClientID(capDUID), optServerID(testServerDUID), ia, optPreference(255)))
	req := mustSendV6(t, acts, wire.MsgRequest6)
	_, acts = m.Step(at(3), 0, receivedV6(t, wire.MsgReply, req.XID, optClientID(capDUID), optServerID(testServerDUID), ia))
	for _, a := range pd6Targets(acts) {
		m.Step(at(4), 0, DADResult(a, false))
	}
	if l, _ := m.Lease(); m.State() != State6Bound || len(l.Addrs) != 2 {
		t.Fatalf("the bind left %s with %v", m.State(), l)
	}
	return m
}

// TestAddressRenewalKeepsWhatTheReplyLeavesOut: the IA_NA follows the IA_PD's
// rule: a held address the Reply does not name keeps its own expiry, one named
// with a valid lifetime of 0 leaves, and only a new one is checked (RFC 8415
// section 18.2.10.1; claymore666/dhcp-golib#64).
func TestAddressRenewalKeepsWhatTheReplyLeavesOut(t *testing.T) {
	const third = "fd00:99::3c4"
	for _, c := range []struct {
		name    string
		specs   []iaAddrSpec
		want    []string
		dad     []string
		changed int
	}{
		{"names one", []iaAddrSpec{{pd6Addr, 300, 300}}, []string{pd6Addr, pd6Temp}, nil, 0},
		{"names one and ends the other", []iaAddrSpec{{pd6Addr, 300, 300}, {pd6Temp, 0, 0}}, []string{pd6Addr}, nil, 1},
		{"names a new one", []iaAddrSpec{{third, 300, 300}}, []string{pd6Addr, pd6Temp, third}, []string{third}, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := keepTwoAddrs(t)
			before, _ := m.Lease()
			_, acts := m.Step(at(152), 7, TimerFired(Timer6Renew))
			ren := mustSendV6(t, acts, wire.MsgRenew)
			_, acts = m.Step(at(153), 0, receivedV6(t, wire.MsgReply, ren.XID, optClientID(capDUID), optServerID(testServerDUID),
				optIANA(t, capIAID, 150, 240, c.specs)))
			var dad []string
			for _, a := range pd6Targets(acts) {
				dad = append(dad, a.String())
			}
			if len(dad) != len(c.dad) || (len(dad) == 1 && dad[0] != c.dad[0]) {
				t.Fatalf("DAD ran on %v, want %v", dad, c.dad)
			}
			for _, a := range pd6Targets(acts) {
				_, acts = m.Step(at(154), 0, DADResult(a, false))
			}
			after, _ := m.Lease()
			if len(after.Addrs) != len(c.want) {
				t.Fatalf("the lease holds %v, want %v", after.Addrs, c.want)
			}
			for i, w := range c.want {
				got := after.Addrs[i]
				if got.Addr != netip.MustParseAddr(w) {
					t.Errorf("address %d is %s, want %s", i, got.Addr, w)
				}
				if got.Addr == netip.MustParseAddr(pd6Temp) && after.Start.Add(got.Valid) != before.Start.Add(before.Addrs[1].Valid) {
					t.Errorf("the carried %s ends at %v, held it ended at %v", w, after.Start.Add(got.Valid), before.Start.Add(before.Addrs[1].Valid))
				}
			}
			if c.dad == nil && count(acts, ActLeaseChanged) != c.changed {
				t.Errorf("%d Changed, want %d", count(acts, ActLeaseChanged), c.changed)
			}
		})
	}
}
