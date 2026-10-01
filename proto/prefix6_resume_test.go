// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// This file builds from fakes6_test.go and fakes_test.go and from nothing else
// in the package's tests, so a run with the other test files switched off
// still compiles it (claymore666/docker-net-dhcp#214).

const (
	pr6Addr  = "fd00:99::183"
	pr6First = "2001:db8:1:100::/64"
	pr6Other = "2001:db8:1:200::/64"
)

var pr6Server = []byte{0, 1, 0, 1, 0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66}

func pr6Resume() *Resume6 {
	return &Resume6{
		Addrs:      []Addr6{{Addr: netip.MustParseAddr(pr6Addr), Preferred: 300 * Second, Valid: 300 * Second}},
		Prefixes:   []Prefix6{{Prefix: netip.MustParsePrefix(pr6First), Preferred: 300 * Second, Valid: 600 * Second}},
		ServerDUID: append([]byte(nil), pr6Server...),
		T1:         150 * Second,
		T2:         240 * Second,
	}
}

func pr6Params() Params6 {
	p := testParams6()
	p.PrefixHint = 64
	p.Resume = pr6Resume()
	return p
}

func pr6IANA(t *testing.T, extra ...wire.OptionV6) wire.OptionV6 {
	t.Helper()
	return optIANA(t, capIAID, 150, 240, []iaAddrSpec{{pr6Addr, 300, 300}}, extra...)
}

func pr6IAPD(t *testing.T, prefix string, pref, valid uint32) wire.OptionV6 {
	t.Helper()
	v, err := wire.EncodeIAPrefix(&wire.IAPrefix{
		PreferredLifetime: pref, ValidLifetime: valid, Prefix: netip.MustParsePrefix(prefix),
	})
	if err != nil {
		t.Fatalf("EncodeIAPrefix: %v", err)
	}
	b, err := wire.EncodeIAPD(&wire.IAPD{
		IAID: capIAID, T1: 120, T2: 200,
		Options: wire.OptionsV6{{Code: wire.OptV6IAPrefix, Data: v}},
	})
	if err != nil {
		t.Fatalf("EncodeIAPD: %v", err)
	}
	return wire.OptionV6{Code: wire.OptV6IAPD, Data: b}
}

func pr6Targets(acts []Action) []netip.Addr {
	var out []netip.Addr
	for _, a := range acts {
		if a.Kind == ActStartDAD {
			out = append(out, a.Target)
		}
	}
	return out
}

// pr6Rebinding takes a machine with the record of pr6Params through EvStart and
// the delay, and returns it with the Rebind it sent.
func pr6Rebinding(t *testing.T, p Params6) (*Machine6, *wire.MessageV6, []Action) {
	t.Helper()
	m := newMachine6(t, p)
	if s, _ := m.Step(at(0), 0, Simple(EvStart)); s != State6Init {
		t.Fatalf("EvStart left the machine in %s, want %s", s, State6Init)
	}
	s, acts := m.Step(at(1), capXIDSolicit, TimerFired(Timer6Delay))
	if s != State6Rebinding {
		t.Fatalf("a resume with a prefix left the machine in %s, want %s (RFC 8415 section 18.2.12)", s, State6Rebinding)
	}
	return m, mustSendV6(t, acts, wire.MsgRebind), acts
}

func pr6Reply(t *testing.T, xid uint32, opts ...wire.OptionV6) Event {
	t.Helper()
	return receivedV6(t, wire.MsgReply, xid,
		append([]wire.OptionV6{optClientID(capDUID), optServerID(testServerDUID)}, opts...)...)
}

func pr6Note(acts []Action, sub string) bool {
	for _, a := range acts {
		if a.Kind == ActJournal && strings.Contains(a.Note, sub) {
			return true
		}
	}
	return false
}

func pr6Wire(t *testing.T, msg *wire.MessageV6) *wire.MessageV6 {
	t.Helper()
	raw, err := wire.EncodeV6(msg)
	if err != nil {
		t.Fatalf("EncodeV6: %v", err)
	}
	back, err := wire.DecodeV6(raw)
	if err != nil {
		t.Fatalf("DecodeV6: %v", err)
	}
	return back
}

// TestResumeWithAPrefixSendsARebind: a client that remembers a delegated prefix
// rebinds and does not confirm, because a Confirm names addresses alone
// (RFC 8415 section 18.2.12; claymore666/docker-net-dhcp#214). The Rebind names
// the remembered address and prefix with zero lifetimes, as a Confirm does.
func TestResumeWithAPrefixSendsARebind(t *testing.T) {
	_, reb, acts := pr6Rebinding(t, pr6Params())
	if hasSendV6(acts, wire.MsgConfirm) {
		t.Error("the resume sent a Confirm")
	}
	back := pr6Wire(t, reb)
	nas, _ := back.Options.IANAs()
	pds, _ := back.Options.IAPDs()
	if len(nas) != 1 || len(pds) != 1 || nas[0].IAID != capIAID || pds[0].IAID != capIAID {
		t.Fatalf("the Rebind carries %d IA_NA and %d IA_PD, want one each with IAID %#x", len(nas), len(pds), capIAID)
	}
	addrs, _ := nas[0].Options.Addrs()
	if len(addrs) != 1 || addrs[0].Addr != netip.MustParseAddr(pr6Addr) || addrs[0].ValidLifetime != 0 || addrs[0].PreferredLifetime != 0 {
		t.Errorf("the Rebind's IA_NA = %+v, want the remembered address with zero lifetimes", addrs)
	}
	ps, _ := pds[0].Options.Prefixes()
	if len(ps) != 1 || ps[0].Prefix != netip.MustParsePrefix(pr6First) || ps[0].ValidLifetime != 0 || ps[0].PreferredLifetime != 0 {
		t.Errorf("the Rebind's IA_PD = %+v, want the remembered prefix with zero lifetimes", ps)
	}
	if _, ok := back.Options.First(wire.OptV6ServerID); ok {
		t.Error("the Rebind carries a Server Identifier (RFC 8415 section 18.2.5)")
	}
}

// TestResumeWithoutAPrefixStillConfirms: the Rebind is for a record that holds a
// prefix and the Confirm stays what it was for one that holds none
// (claymore666/docker-net-dhcp#214).
func TestResumeWithoutAPrefixStillConfirms(t *testing.T) {
	p := pr6Params()
	p.Resume.Prefixes = nil
	_, acts := confirming6(t, p)
	if hasSendV6(acts, wire.MsgRebind) || !hasSendV6(acts, wire.MsgConfirm) {
		t.Errorf("a resume with no prefix did not send a Confirm alone")
	}
}

// TestResumeOfAPrefixAloneIsRefused: a record with no usable address is no
// resume, with or without a prefix (claymore666/docker-net-dhcp#214).
func TestResumeOfAPrefixAloneIsRefused(t *testing.T) {
	p := pr6Params()
	p.Resume.Addrs = nil
	if _, err := New6(p); !errors.Is(err, ErrBadResume6) {
		t.Errorf("New6 = %v, want ErrBadResume6", err)
	}
}

// TestResumeCloneCopiesThePrefixes: a mutation of the clone does not reach the
// original (claymore666/docker-net-dhcp#214).
func TestResumeCloneCopiesThePrefixes(t *testing.T) {
	r := pr6Resume()
	c := r.Clone()
	if len(c.Prefixes) != 1 || c.Prefixes[0] != r.Prefixes[0] {
		t.Fatalf("Clone = %v, want the prefix", c.Prefixes)
	}
	c.Prefixes[0].Valid = 1
	if r.Prefixes[0].Valid == 1 {
		t.Error("the clone shares the prefix slice")
	}
}

// TestResumeRebindSuccess: a Success Reply gives the lifetimes of the
// delegation afresh, the address goes through DAD, and the lease is announced
// with the prefix and no Confirm in the journal of it
// (claymore666/docker-net-dhcp#214).
func TestResumeRebindSuccess(t *testing.T) {
	m, reb, _ := pr6Rebinding(t, pr6Params())
	s, acts := m.Step(at(2), 3, pr6Reply(t, reb.XID, pr6IANA(t), pr6IAPD(t, pr6First, 1000, 2000)))
	if s != State6DAD {
		t.Fatalf("a Success Reply left the machine in %s, want %s", s, State6DAD)
	}
	if got := pr6Targets(acts); len(got) != 1 || got[0] != netip.MustParseAddr(pr6Addr) {
		t.Errorf("DAD asked about %v, want the remembered address alone", got)
	}
	s, acts = m.Step(at(3), 0, DADResult(netip.MustParseAddr(pr6Addr), false))
	if s != State6Bound {
		t.Fatalf("a clean DAD result left the machine in %s, want %s", s, State6Bound)
	}
	a, ok := find(acts, ActLeaseAcquired)
	if !ok || len(a.Lease6.Prefixes) != 1 {
		t.Fatalf("Acquired = %v, want the prefix", a.Lease6)
	}
	if p := a.Lease6.Prefixes[0]; p.Prefix != netip.MustParsePrefix(pr6First) || p.Preferred != 1000*Second || p.Valid != 2000*Second {
		t.Errorf("the prefix is %s, want the Reply's lifetimes 1000 s and 2000 s", p)
	}
	if got := m.PrefixCounters(); got != (Prefix6Counters{}) {
		t.Errorf("PrefixCounters = %+v, want none for a prefix that stayed", got)
	}
}

// TestResumeRebindThatDropsThePrefix: a Reply whose IA_PD is gone is a change
// and the lease is the address alone (claymore666/docker-net-dhcp#214).
func TestResumeRebindThatDropsThePrefix(t *testing.T) {
	m, reb, _ := pr6Rebinding(t, pr6Params())
	m.Step(at(2), 3, pr6Reply(t, reb.XID, pr6IANA(t)))
	_, acts := m.Step(at(3), 0, DADResult(netip.MustParseAddr(pr6Addr), false))
	a, ok := find(acts, ActLeaseAcquired)
	if !ok || len(a.Lease6.Prefixes) != 0 || len(a.Lease6.Addrs) != 1 {
		t.Fatalf("Acquired = %v, want the address alone", a.Lease6)
	}
	if got := m.PrefixCounters(); got.Changed != 1 || got.Absent != 1 {
		t.Errorf("PrefixCounters = %+v, want Changed 1 and Absent 1", got)
	}
}

// TestResumeRebindNotOnLink takes stepConfirming6's path: the remembered
// binding is dropped, discovery starts over, nothing is released and the next
// message is a Solicit (RFC 8415 section 18.2.10.3;
// claymore666/docker-net-dhcp#214).
func TestResumeRebindNotOnLink(t *testing.T) {
	m, reb, _ := pr6Rebinding(t, pr6Params())
	s, acts := m.Step(at(2), 3, pr6Reply(t, reb.XID, optStatus(wire.StatusNotOnLink)))
	if s == State6Rebinding || s == State6DAD || s == State6Bound {
		t.Fatalf("a NotOnLink Reply left the machine in %s", s)
	}
	if hasSendV6(acts, wire.MsgRelease6) {
		t.Error("a NotOnLink Reply was answered with a Release")
	}
	if _, held := m.Lease(); held {
		t.Error("a lease is held after NotOnLink")
	}
	_, acts = m.Step(at(3), capXIDSolicit, TimerFired(Timer6Delay))
	if !hasSendV6(acts, wire.MsgSolicit) || hasSendV6(acts, wire.MsgRebind) {
		t.Errorf("the restart did not begin with a Solicit: %v", acts)
	}
}

// TestResumeRebindNoBinding: a server that holds no binding for the remembered
// addresses has nothing to renew, and the client starts discovery and does not
// send a Request for addresses it never held (RFC 8415 section 18.2.10.1;
// claymore666/docker-net-dhcp#214).
func TestResumeRebindNoBinding(t *testing.T) {
	m, reb, _ := pr6Rebinding(t, pr6Params())
	s, acts := m.Step(at(2), 3, pr6Reply(t, reb.XID, optIANA(t, capIAID, 0, 0, nil, optStatus(wire.StatusNoBinding))))
	if s == State6Rebinding || s == State6Requesting || hasSendV6(acts, wire.MsgRequest6) {
		t.Fatalf("a NoBinding Reply left the machine in %s with %v", s, acts)
	}
	_, acts = m.Step(at(3), capXIDSolicit, TimerFired(Timer6Delay))
	if !hasSendV6(acts, wire.MsgSolicit) {
		t.Errorf("the restart did not begin with a Solicit")
	}
}

// TestResumeRebindUnconfirmed: no Reply within the Confirm parameters continues
// with the last known lifetimes, announces the lease with its prefix after DAD
// and goes on rebinding on the Rebind parameters, which do not end at the
// Confirm limit (RFC 8415 sections 18.2.3 and 18.2.5;
// claymore666/docker-net-dhcp#214).
func TestResumeRebindUnconfirmed(t *testing.T) {
	m, first, _ := pr6Rebinding(t, pr6Params())
	var acts []Action
	now := int64(1)
	for i := 0; i < 20 && m.State() == State6Rebinding; i++ {
		now += 2
		_, acts = m.Step(at(now), uint64(i)+5, TimerFired(Timer6Retransmit))
		if m.State() == State6Rebinding {
			if re := mustSendV6(t, acts, wire.MsgRebind); re.XID != first.XID {
				t.Fatalf("a retransmission changed the transaction id %#x to %#x", first.XID, re.XID)
			}
		}
	}
	if m.State() != State6DAD {
		t.Fatalf("the Confirm limit left the machine in %s, want %s", m.State(), State6DAD)
	}
	if now > 40 {
		t.Errorf("the Rebind went on until t+%d s: the Confirm parameters were not used", now)
	}
	if !pr6Note(acts, "unconfirmed") && !pr6Note(acts, "last known lifetimes") {
		t.Errorf("the journal does not say the lease is unconfirmed")
	}
	if got := pr6Targets(acts); len(got) != 1 || got[0] != netip.MustParseAddr(pr6Addr) {
		t.Errorf("DAD asked about %v, want the remembered address", got)
	}

	now++
	s, acts := m.Step(at(now), 9, DADResult(netip.MustParseAddr(pr6Addr), false))
	acq, ok := find(acts, ActLeaseAcquired)
	if !ok || len(acq.Lease6.Prefixes) != 1 || acq.Lease6.Prefixes[0].Prefix != netip.MustParsePrefix(pr6First) {
		t.Fatalf("Acquired = %v, want the remembered prefix", acq.Lease6)
	}
	if s != State6Rebinding {
		t.Fatalf("after the unconfirmed lease was announced the machine is in %s, want %s", s, State6Rebinding)
	}
	reb := mustSendV6(t, acts, wire.MsgRebind)
	back := pr6Wire(t, reb)
	pds, _ := back.Options.IAPDs()
	if len(pds) != 1 {
		t.Fatalf("the Rebind that follows carries %d IA_PD, want 1", len(pds))
	}
	ps, _ := pds[0].Options.Prefixes()
	if len(ps) != 1 || ps[0].ValidLifetime == 0 {
		t.Errorf("the Rebind that follows carries %+v, want the prefix with its lifetimes", ps)
	}

	// The Rebind parameters have no limit at the Confirm's 10 s: the machine is
	// still rebinding a minute later (claymore666/docker-net-dhcp#214).
	for _, dt := range []int64{20, 60, 120} {
		now += dt
		s, acts = m.Step(at(now), 11, TimerFired(Timer6Retransmit))
		if s != State6Rebinding || !hasSendV6(acts, wire.MsgRebind) {
			t.Fatalf("at t+%d s the machine is in %s, want %s resending the Rebind", now, s, State6Rebinding)
		}
	}

	// A Reply to it ends the exchange (claymore666/docker-net-dhcp#214).
	s, _ = m.Step(at(now+1), 0, pr6Reply(t, reb.XID, pr6IANA(t), pr6IAPD(t, pr6First, 1000, 2000)))
	if s == State6Rebinding {
		t.Errorf("a Reply left the machine in %s", s)
	}
}

// TestResumeRebindEndsAtTheValidLifetime: the unconfirmed lease is not kept
// forever, the address's valid lifetime ends it (claymore666/docker-net-dhcp#214).
func TestResumeRebindEndsAtTheValidLifetime(t *testing.T) {
	m, _, _ := pr6Rebinding(t, pr6Params())
	now := int64(1)
	for i := 0; i < 20 && m.State() == State6Rebinding; i++ {
		now += 2
		m.Step(at(now), uint64(i)+5, TimerFired(Timer6Retransmit))
	}
	m.Step(at(now+1), 9, DADResult(netip.MustParseAddr(pr6Addr), false))
	_, acts := m.Step(at(now+1+300), 9, TimerFired(Timer6Expire))
	if _, held := m.Lease(); held || count(acts, ActLeaseLost) != 1 {
		t.Errorf("the valid lifetime passed with the lease held %t and %d Lost", held, count(acts, ActLeaseLost))
	}
}

// TestResumeRebindDropsAnUnusablePrefix: a record that names a prefix no
// delegating router could have given (zero length, IPv4-mapped) sends the
// usable prefix alone, not nothing and not the bad one
// (claymore666/docker-net-dhcp#214).
func TestResumeRebindDropsAnUnusablePrefix(t *testing.T) {
	p := pr6Params()
	p.Resume.Prefixes = append(p.Resume.Prefixes,
		Prefix6{Prefix: netip.MustParsePrefix("::/0"), Preferred: 300 * Second, Valid: 600 * Second},
		Prefix6{Prefix: netip.MustParsePrefix("::ffff:192.0.2.0/96"), Preferred: 300 * Second, Valid: 600 * Second})
	_, reb, _ := pr6Rebinding(t, p)
	pds, _ := pr6Wire(t, reb).Options.IAPDs()
	if len(pds) != 1 {
		t.Fatalf("the Rebind carries %d IA_PD, want 1", len(pds))
	}
	ps, _ := pds[0].Options.Prefixes()
	if len(ps) != 1 || ps[0].Prefix != netip.MustParsePrefix(pr6First) {
		t.Errorf("the Rebind's IA Prefixes = %+v, want the one usable prefix", ps)
	}
}
