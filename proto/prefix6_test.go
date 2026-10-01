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
	pd6Addr  = "fd00:99::183"
	pd6Temp  = "fd00:99::2a1"
	pd6First = "2001:db8:1:100::/64"
	pd6Other = "2001:db8:1:200::/64"
)

type pd6Spec struct {
	prefix          string
	preferred, vali uint32
}

func pd6Params(hint int) Params6 {
	p := testParams6()
	p.PrefixHint = hint
	return p
}

func optIAPD(t *testing.T, iaid, t1, t2 uint32, ps []pd6Spec, extra ...wire.OptionV6) wire.OptionV6 {
	t.Helper()
	ia := &wire.IAPD{IAID: iaid, T1: t1, T2: t2}
	for _, p := range ps {
		v, err := wire.EncodeIAPrefix(&wire.IAPrefix{
			PreferredLifetime: p.preferred,
			ValidLifetime:     p.vali,
			Prefix:            netip.MustParsePrefix(p.prefix),
		})
		if err != nil {
			t.Fatalf("EncodeIAPrefix: %v", err)
		}
		ia.Options = append(ia.Options, wire.OptionV6{Code: wire.OptV6IAPrefix, Data: v})
	}
	ia.Options = append(ia.Options, extra...)
	v, err := wire.EncodeIAPD(ia)
	if err != nil {
		t.Fatalf("EncodeIAPD: %v", err)
	}
	return wire.OptionV6{Code: wire.OptV6IAPD, Data: v}
}

// pd6Good is the IA_PD a server that delegates sends: our IAID, T1 120, T2 200
// and one /64 for 300 and 600 seconds.
func pd6Good(t *testing.T) wire.OptionV6 {
	t.Helper()
	return optIAPD(t, capIAID, 120, 200, []pd6Spec{{pd6First, 300, 600}})
}

// pd6Base is the options every server message here carries: the identifiers
// and an IA_NA with the address, T1 150 and T2 240, preferred and valid 300.
func pd6Base(t *testing.T, extra ...wire.OptionV6) []wire.OptionV6 {
	t.Helper()
	return append([]wire.OptionV6{
		optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 150, 240, []iaAddrSpec{{pd6Addr, 300, 300}}),
	}, extra...)
}

func pd6Advert(t *testing.T, xid uint32, extra ...wire.OptionV6) Event {
	t.Helper()
	return receivedV6(t, wire.MsgAdvertise, xid, append(pd6Base(t, extra...), optPreference(255))...)
}

func pd6Reply(t *testing.T, xid uint32, extra ...wire.OptionV6) Event {
	t.Helper()
	return receivedV6(t, wire.MsgReply, xid, pd6Base(t, extra...)...)
}

// pd6OnTheWire is the message as a server would read it: encoded, decoded.
func pd6OnTheWire(t *testing.T, msg *wire.MessageV6) *wire.MessageV6 {
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

// pd6IAs is the IA_NAs and IA_PDs of a message as they went on the wire.
func pd6IAs(t *testing.T, msg *wire.MessageV6) ([]*wire.IANA, []*wire.IAPD) {
	t.Helper()
	back := pd6OnTheWire(t, msg)
	nas, err := back.Options.IANAs()
	if err != nil {
		t.Fatalf("IANAs: %v", err)
	}
	pds, err := back.Options.IAPDs()
	if err != nil {
		t.Fatalf("IAPDs: %v", err)
	}
	return nas, pds
}

func pd6Prefixes(t *testing.T, ia *wire.IAPD) []*wire.IAPrefix {
	t.Helper()
	ps, err := ia.Options.Prefixes()
	if err != nil {
		t.Fatalf("Prefixes: %v", err)
	}
	return ps
}

func pd6Journal(acts []Action) string {
	var b strings.Builder
	for _, a := range acts {
		if a.Kind == ActJournal {
			b.WriteString("\n\t" + a.Note)
		}
	}
	return b.String()
}

func pd6Says(acts []Action, sub string) bool { return strings.Contains(pd6Journal(acts), sub) }

func pd6Targets(acts []Action) []netip.Addr {
	var out []netip.Addr
	for _, a := range acts {
		if a.Kind == ActStartDAD {
			out = append(out, a.Target)
		}
	}
	return out
}

func pd6Lease(t *testing.T, acts []Action, kind ActionKind) Lease6 {
	t.Helper()
	a, ok := find(acts, kind)
	if !ok {
		t.Fatalf("no %s action in %v", kind, acts)
	}
	return a.Lease6
}

func pd6Counters(t *testing.T, m *Machine6, want Prefix6Counters) {
	t.Helper()
	if got := m.PrefixCounters(); got != want {
		t.Errorf("PrefixCounters = %+v, want %+v", got, want)
	}
}

// pd6ToDAD takes a fresh machine through the Solicit, the Advertise and the
// Request to the Reply, which it answers with the IA_NA and the extra options.
// advExtra rides the Advertise. It returns the machine in DAD with the Request
// and the actions of the Reply.
func pd6ToDAD(t *testing.T, p Params6, advExtra []wire.OptionV6, replyExtra ...wire.OptionV6) (*Machine6, *wire.MessageV6, []Action) {
	t.Helper()
	m, sol := solicit6(t, p)
	_, acts := m.Step(at(2), capXIDRequest, pd6Advert(t, sol.XID, advExtra...))
	req := mustSendV6(t, acts, wire.MsgRequest6)
	_, acts = m.Step(at(3), 0, pd6Reply(t, req.XID, replyExtra...))
	return m, req, acts
}

// pd6Bound is pd6ToDAD with the prefix granted and the address checked clean.
func pd6Bound(t *testing.T, p Params6) *Machine6 {
	t.Helper()
	m, _, acts := pd6ToDAD(t, p, []wire.OptionV6{pd6Good(t)}, pd6Good(t))
	for _, a := range pd6Targets(acts) {
		m.Step(at(4), 0, DADResult(a, false))
	}
	if m.State() != State6Bound {
		t.Fatalf("the exchange left the machine in %s, want %s", m.State(), State6Bound)
	}
	return m
}

// pd6Renew sends the Renew at renewAt and answers it at replyAt, and returns
// the Renew with the actions of the answer.
func pd6Renew(t *testing.T, m *Machine6, renewAt, replyAt int64, extra ...wire.OptionV6) (*wire.MessageV6, []Action) {
	t.Helper()
	_, acts := m.Step(at(renewAt), 7, TimerFired(Timer6Renew))
	ren := mustSendV6(t, acts, wire.MsgRenew)
	_, acts = m.Step(at(replyAt), 0, pd6Reply(t, ren.XID, extra...))
	return ren, acts
}

// TestPrefixHintIsOffByDefault: the parameter is 0, no message carries an
// IA_PD, and an IA_PD the server sends anyway is read as nothing
// (claymore666/docker-net-dhcp#214).
func TestPrefixHintIsOffByDefault(t *testing.T) {
	if DefaultParams6().PrefixHint != 0 {
		t.Fatal("DefaultParams6 asks for a prefix")
	}
	m, sol := solicit6(t, pd6Params(0))
	if _, pds := pd6IAs(t, sol); len(pds) != 0 {
		t.Errorf("the Solicit carries %d IA_PD", len(pds))
	}
	_, acts := m.Step(at(2), capXIDRequest, pd6Advert(t, sol.XID, pd6Good(t)))
	req := mustSendV6(t, acts, wire.MsgRequest6)
	if _, pds := pd6IAs(t, req); len(pds) != 0 {
		t.Errorf("the Request carries %d IA_PD", len(pds))
	}
	_, acts = m.Step(at(3), 0, pd6Reply(t, req.XID, pd6Good(t)))
	m.Step(at(4), 0, DADResult(addr6(pd6Addr), false))
	l, held := m.Lease()
	if !held || len(l.Addrs) != 1 || len(l.Prefixes) != 0 {
		t.Errorf("lease %v held %t, want the address and no prefix", l, held)
	}
	if !pd6Says(acts, "ignored") {
		t.Errorf("an unsolicited IA_PD left no journal line:%s", pd6Journal(acts))
	}
	pd6Counters(t, m, Prefix6Counters{})
}

// TestPrefixHintIsValidated: 0 through 128 are parameters, nothing else is
// (claymore666/docker-net-dhcp#214).
func TestPrefixHintIsValidated(t *testing.T) {
	for _, c := range []struct {
		hint int
		ok   bool
	}{{-1, false}, {0, true}, {1, true}, {56, true}, {64, true}, {128, true}, {129, false}} {
		_, err := New6(pd6Params(c.hint))
		if c.ok && err != nil {
			t.Errorf("hint %d refused: %v", c.hint, err)
		}
		if !c.ok && !errors.Is(err, ErrBadPrefixHint) {
			t.Errorf("hint %d gave %v, want ErrBadPrefixHint", c.hint, err)
		}
	}
}

// TestPrefixBytesOfEveryMessage: the IA_PD rides the Solicit, the Request, the
// Renew, the Rebind and the Release and no other message a client builds, and
// its IAID is the IA_NA's (RFC 8415 sections 18.2.1 to 18.2.7;
// claymore666/docker-net-dhcp#214).
func TestPrefixBytesOfEveryMessage(t *testing.T) {
	p := pd6Params(56)

	m, sol := solicit6(t, p)
	nas, pds := pd6IAs(t, sol)
	if len(nas) != 1 || len(pds) != 1 {
		t.Fatalf("the Solicit carries %d IA_NA and %d IA_PD, want one of each", len(nas), len(pds))
	}
	if pds[0].IAID != capIAID || nas[0].IAID != pds[0].IAID {
		t.Errorf("IA_PD IAID %#x, IA_NA IAID %#x, want both %#x", pds[0].IAID, nas[0].IAID, capIAID)
	}
	hint := pd6Prefixes(t, pds[0])
	if len(hint) != 1 || hint[0].Prefix != netip.MustParsePrefix("::/56") || hint[0].PreferredLifetime != 0 || hint[0].ValidLifetime != 0 {
		t.Errorf("the Solicit's hint = %+v, want ::/56 with zero lifetimes", hint)
	}

	// The Advertise offered a prefix: the Request repeats it with its
	// lifetimes (claymore666/docker-net-dhcp#214).
	_, acts := m.Step(at(2), capXIDRequest, pd6Advert(t, sol.XID, pd6Good(t)))
	req := mustSendV6(t, acts, wire.MsgRequest6)
	if _, pds = pd6IAs(t, req); len(pds) != 1 {
		t.Fatalf("the Request carries %d IA_PD, want 1", len(pds))
	}
	got := pd6Prefixes(t, pds[0])
	if len(got) != 1 || got[0].Prefix != netip.MustParsePrefix(pd6First) || got[0].PreferredLifetime != 300 || got[0].ValidLifetime != 600 {
		t.Errorf("the Request's IA_PD = %+v, want %s with 300 and 600", got, pd6First)
	}

	// An Advertise with no IA_PD: the Request asks again with the hint.
	m2, sol2 := solicit6(t, p)
	_, acts = m2.Step(at(2), capXIDRequest, pd6Advert(t, sol2.XID))
	req2 := mustSendV6(t, acts, wire.MsgRequest6)
	_, pds = pd6IAs(t, req2)
	if len(pds) != 1 || pds[0].IAID != capIAID {
		t.Fatalf("the Request after an Advertise with no IA_PD carries %+v, want the hint", pds)
	}
	if h := pd6Prefixes(t, pds[0]); len(h) != 1 || h[0].Prefix.Bits() != 56 || h[0].ValidLifetime != 0 {
		t.Errorf("that Request's IA_PD = %+v, want ::/56 with zero lifetimes", h)
	}

	bound := pd6Bound(t, p)
	_, acts = bound.Step(at(152), 7, TimerFired(Timer6Renew))
	ren := mustSendV6(t, acts, wire.MsgRenew)
	if nas, pds = pd6IAs(t, ren); len(pds) != 1 || len(nas) != 1 || pds[0].IAID != nas[0].IAID {
		t.Fatalf("the Renew carries %d IA_NA and %d IA_PD, want one each with one IAID", len(nas), len(pds))
	}
	if h := pd6Prefixes(t, pds[0]); len(h) != 1 || h[0].Prefix != netip.MustParsePrefix(pd6First) || h[0].ValidLifetime == 0 {
		t.Errorf("the Renew's IA_PD = %+v, want the held prefix with its lifetimes", h)
	}
	_, acts = bound.Step(at(242), 8, TimerFired(Timer6Rebind))
	reb := mustSendV6(t, acts, wire.MsgRebind)
	if _, pds = pd6IAs(t, reb); len(pds) != 1 || len(pd6Prefixes(t, pds[0])) != 1 {
		t.Errorf("the Rebind carries %+v, want the held prefix", pds)
	}

	released := pd6Bound(t, p)
	_, acts = released.Step(at(10), 9, Simple(EvRelease))
	rel := mustSendV6(t, acts, wire.MsgRelease6)
	if nas, pds = pd6IAs(t, rel); len(nas) != 1 || len(pds) != 1 {
		t.Fatalf("the Release carries %d IA_NA and %d IA_PD, want one each", len(nas), len(pds))
	}
	if h := pd6Prefixes(t, pds[0]); len(h) != 1 || h[0].Prefix != netip.MustParsePrefix(pd6First) {
		t.Errorf("the Release's IA_PD = %+v, want the held prefix", h)
	}

	_, acts = confirming6(t, p)
	conf := mustSendV6(t, acts, wire.MsgConfirm)
	if _, pds = pd6IAs(t, conf); len(pds) != 0 {
		t.Errorf("the Confirm carries %d IA_PD", len(pds))
	}

	info, _ := solicit6(t, p)
	_, acts = info.Step(at(2), capXIDRequest, raEvent6(t, ra6(false, true)))
	inf := mustSendV6(t, acts, wire.MsgInformationRequest)
	if nas, pds = pd6IAs(t, inf); len(pds) != 0 || len(nas) != 0 {
		t.Errorf("the Information-request carries %d IA_NA and %d IA_PD", len(nas), len(pds))
	}

	// A Decline of the address, with a prefix granted: the Decline names the
	// address alone (claymore666/docker-net-dhcp#214).
	m3, _, acts := pd6ToDAD(t, p, []wire.OptionV6{pd6Good(t)}, pd6Good(t))
	_, acts = m3.Step(at(4), 0, DADResult(addr6(pd6Addr), true))
	dec := mustSendV6(t, acts, wire.MsgDecline6)
	if _, pds = pd6IAs(t, dec); len(pds) != 0 {
		t.Errorf("a Decline carries %d IA_PD", len(pds))
	}
}

// TestPrefixAndTemporaryShareTheIAID: a client that asks for a prefix and for
// temporary addresses sends the IA_NA, the IA_TA and the IA_PD, one IAID on
// all three (claymore666/docker-net-dhcp#214).
func TestPrefixAndTemporaryShareTheIAID(t *testing.T) {
	p := pd6Params(60)
	p.Temporary = true
	_, sol := solicit6(t, p)
	back := pd6OnTheWire(t, sol)
	nas, _ := back.Options.IANAs()
	tas, _ := back.Options.IATAs()
	pds, _ := back.Options.IAPDs()
	if len(nas) != 1 || len(tas) != 1 || len(pds) != 1 {
		t.Fatalf("the Solicit carries %d IA_NA, %d IA_TA, %d IA_PD, want one of each", len(nas), len(tas), len(pds))
	}
	if nas[0].IAID != capIAID || tas[0].IAID != capIAID || pds[0].IAID != capIAID {
		t.Errorf("IAIDs %#x %#x %#x, want %#x on all three", nas[0].IAID, tas[0].IAID, pds[0].IAID, capIAID)
	}
}

// TestPrefixReadsAThirdSlice: the lease holds the address in Addrs and the
// prefix in Prefixes, and nothing that reads the address sees the prefix
// (claymore666/docker-net-dhcp#214).
func TestPrefixReadsAThirdSlice(t *testing.T) {
	m := pd6Bound(t, pd6Params(64))
	l, held := m.Lease()
	if !held || len(l.Addrs) != 1 || len(l.Prefixes) != 1 {
		t.Fatalf("lease %v held %t, want one address and one prefix", l, held)
	}
	if l.Addrs[0].Addr != addr6(pd6Addr) || l.Prefixes[0].Prefix != netip.MustParsePrefix(pd6First) {
		t.Errorf("Addrs %v Prefixes %v", l.Addrs, l.Prefixes)
	}
	if l.Prefixes[0].Preferred != 300*Second || l.Prefixes[0].Valid != 600*Second {
		t.Errorf("the prefix lifetimes are %s and %s, want 300 s and 600 s", l.Prefixes[0].Preferred, l.Prefixes[0].Valid)
	}
	if a, ok := l.Addr(); !ok || a != addr6(pd6Addr) {
		t.Errorf("Addr() = %v, %t, want the address", a, ok)
	}
	if want := l.Start.Add(300 * Second); l.Deadlines().Expire != want {
		t.Errorf("Expire = %v, want %v: the prefix's 600 s is not the lease's", l.Deadlines().Expire, want)
	}
	if !strings.Contains(l.String(), "pd "+pd6First) {
		t.Errorf("String() = %q does not name the prefix", l.String())
	}
}

// TestPrefixDADRunsOnTheAddressAlone: a delegated prefix is no address on this
// link and nothing asks about it (RFC 3633 section 12.1;
// claymore666/docker-net-dhcp#214).
func TestPrefixDADRunsOnTheAddressAlone(t *testing.T) {
	m, _, acts := pd6ToDAD(t, pd6Params(64), []wire.OptionV6{pd6Good(t)}, pd6Good(t))
	targets := pd6Targets(acts)
	if len(targets) != 1 || targets[0] != addr6(pd6Addr) {
		t.Fatalf("DAD asked about %v, want the address alone", targets)
	}
	_, acts = m.Step(at(4), 0, DADResult(addr6(pd6Addr), false))
	acq := pd6Lease(t, acts, ActLeaseAcquired)
	if len(acq.Prefixes) != 1 || acq.Prefixes[0].Prefix != netip.MustParsePrefix(pd6First) {
		t.Errorf("Acquired carries %v, want the prefix", acq)
	}
}

// TestPrefixStatusIsPerIA: what the IA_PD says is about the IA_PD. A refusal
// there leaves the IA_NA lease whole, and an IA_PD that is not ours, malformed,
// doubled or full of unusable prefixes gives nothing (RFC 8415 section
// 18.2.10.1; claymore666/docker-net-dhcp#214).
func TestPrefixStatusIsPerIA(t *testing.T) {
	good := pd6Spec{pd6First, 300, 600}
	trunc := wire.OptionV6{Code: wire.OptV6IAPD, Data: []byte{0, 0, 0, 1, 0}}
	shortPrefix := wire.OptionV6{Code: wire.OptV6IAPrefix, Data: make([]byte, 10)}
	cases := []struct {
		name    string
		extra   []wire.OptionV6
		want    []string
		counter Prefix6Counters
		say     string
	}{
		{"granted", []wire.OptionV6{optIAPD(t, capIAID, 0, 0, []pd6Spec{good})}, []string{pd6First},
			Prefix6Counters{Granted: 1}, "gave 1 delegated"},
		{"NoPrefixAvail", []wire.OptionV6{optIAPD(t, capIAID, 0, 0, nil, optStatus(wire.StatusNoPrefixAvail))}, nil,
			Prefix6Counters{Refused: 2}, "gave no prefix (status NoPrefixAvail)"},
		{"NoPrefixAvail with a prefix in it", []wire.OptionV6{optIAPD(t, capIAID, 0, 0, []pd6Spec{good}, optStatus(wire.StatusNoPrefixAvail))}, nil,
			Prefix6Counters{Refused: 2}, "not ours to use"},
		{"UnspecFail", []wire.OptionV6{optIAPD(t, capIAID, 0, 0, nil, optStatus(wire.StatusUnspecFail))}, nil,
			Prefix6Counters{Refused: 2}, "gave no prefix"},
		{"NoBinding with a prefix in it", []wire.OptionV6{optIAPD(t, capIAID, 0, 0, []pd6Spec{good}, optStatus(wire.StatusNoBinding))}, nil,
			Prefix6Counters{Refused: 2}, "not ours to use"},
		{"empty", []wire.OptionV6{optIAPD(t, capIAID, 0, 0, nil)}, nil,
			Prefix6Counters{Refused: 2}, "gave no prefix"},
		{"not our IAID", []wire.OptionV6{optIAPD(t, capIAID+1, 0, 0, []pd6Spec{good})}, nil,
			Prefix6Counters{Absent: 2}, "is not ours"},
		{"valid lifetime 0", []wire.OptionV6{optIAPD(t, capIAID, 0, 0, []pd6Spec{{pd6First, 0, 0}})}, nil,
			Prefix6Counters{Refused: 2}, "valid lifetime of 0"},
		{"preferred above valid", []wire.OptionV6{optIAPD(t, capIAID, 0, 0, []pd6Spec{{pd6First, 900, 100}})}, nil,
			Prefix6Counters{Refused: 2}, "greater than valid"},
		{"T1 above T2", []wire.OptionV6{optIAPD(t, capIAID, 300, 100, []pd6Spec{good})}, nil,
			Prefix6Counters{Absent: 2}, "IA_PD discarded"},
		{"two IA_PDs", []wire.OptionV6{optIAPD(t, capIAID, 0, 0, []pd6Spec{good}), optIAPD(t, capIAID, 0, 0, []pd6Spec{{pd6Other, 300, 600}})}, []string{pd6First},
			Prefix6Counters{Granted: 1}, "a second IA_PD"},
		{"a truncated IA_PD", []wire.OptionV6{trunc}, nil,
			Prefix6Counters{Absent: 2}, "IA_PD option"},
		{"a truncated IA Prefix", []wire.OptionV6{optIAPD(t, capIAID, 0, 0, nil, shortPrefix)}, nil,
			Prefix6Counters{Refused: 2}, "IA Prefix option"},
		{"none", nil, nil, Prefix6Counters{Absent: 2}, "no IA_PD in the message"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// The Advertise carries the same IA_PD as the Reply, so a case
			// that counts nothing for it is a finding (claymore666/docker-net-dhcp#214).
			m, _, acts := pd6ToDAD(t, pd6Params(64), c.extra, c.extra...)
			for _, a := range pd6Targets(acts) {
				m.Step(at(4), 0, DADResult(a, false))
			}
			l, held := m.Lease()
			if m.State() != State6Bound || !held || len(l.Addrs) != 1 || l.Addrs[0].Addr != addr6(pd6Addr) {
				t.Fatalf("state %s lease %v held %t, want BOUND with the address whole", m.State(), l, held)
			}
			var got []string
			for _, p := range l.Prefixes {
				got = append(got, p.Prefix.String())
			}
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Errorf("Prefixes %v, want %v", got, c.want)
			}
			if !pd6Says(acts, c.say) {
				t.Errorf("the journal lacks %q:%s", c.say, pd6Journal(acts))
			}
			// The Advertise and the Reply each count a refusal or an absence;
			// a grant counts at the Reply alone (claymore666/docker-net-dhcp#214).
			pd6Counters(t, m, c.counter)
		})
	}
}

// TestPrefixAdvertiseWithoutPDStillMakesALease: the IA_NA alone makes a lease
// and an Advertise whose IA_PD says NoPrefixAvail or is missing is selected
// like any other (RFC 8415 section 18.2.9; claymore666/docker-net-dhcp#214).
func TestPrefixAdvertiseWithoutPDStillMakesALease(t *testing.T) {
	for name, extra := range map[string][]wire.OptionV6{
		"NoPrefixAvail": {optIAPD(t, capIAID, 0, 0, nil, optStatus(wire.StatusNoPrefixAvail))},
		"no IA_PD":      nil,
	} {
		t.Run(name, func(t *testing.T) {
			m, sol := solicit6(t, pd6Params(64))
			s, acts := m.Step(at(2), capXIDRequest, pd6Advert(t, sol.XID, extra...))
			if s != State6Requesting {
				t.Fatalf("the Advertise left the machine in %s, want %s", s, State6Requesting)
			}
			mustSendV6(t, acts, wire.MsgRequest6)
		})
	}
}

// TestPrefixDoesNotMakeALeaseOfAnIAPDAlone: no address, no lease, whatever the
// IA_PD offers (claymore666/docker-net-dhcp#214).
func TestPrefixDoesNotMakeALeaseOfAnIAPDAlone(t *testing.T) {
	for _, name := range []string{"no IA_NA", "IA_NA NoAddrsAvail"} {
		t.Run(name, func(t *testing.T) {
			m, sol := solicit6(t, pd6Params(64))
			_, acts := m.Step(at(2), capXIDRequest, pd6Advert(t, sol.XID, pd6Good(t)))
			req := mustSendV6(t, acts, wire.MsgRequest6)
			opts := []wire.OptionV6{optClientID(capDUID), optServerID(testServerDUID), pd6Good(t)}
			if name != "no IA_NA" {
				opts = append(opts, optIANA(t, capIAID, 150, 240, nil, optStatus(wire.StatusNoAddrsAvail)))
			}
			s, acts := m.Step(at(3), 0, receivedV6(t, wire.MsgReply, req.XID, opts...))
			if s == State6Bound || s == State6DAD || len(pd6Targets(acts)) != 0 || count(acts, ActLeaseAcquired) != 0 {
				t.Errorf("a Reply with no address left the machine in %s with DAD %v", s, pd6Targets(acts))
			}
			if _, held := m.Lease(); held {
				t.Error("a lease was held")
			}
			if c := m.PrefixCounters(); c.Granted != 0 {
				t.Errorf("a Reply nobody used counted %d grants", c.Granted)
			}
		})
	}
}

// TestPrefixTakesTheEarliestRenewalTimes: with two IAs the client renews at
// the earlier T1 and rebinds at the earlier T2 (RFC 8415 section 18.2.4;
// claymore666/docker-net-dhcp#214).
func TestPrefixTakesTheEarliestRenewalTimes(t *testing.T) {
	for _, c := range []struct {
		name           string
		t1, t2         uint32
		wantT1, wantT2 Duration
	}{
		{"the IA_PD is earlier", 100, 200, 100 * Second, 200 * Second},
		{"the IA_NA is earlier", 400, 500, 150 * Second, 240 * Second},
		{"T1 earlier and T2 later", 100, 500, 100 * Second, 240 * Second},
		{"the IA_PD leaves it to the client", 0, 0, 150 * Second, 240 * Second},
	} {
		t.Run(c.name, func(t *testing.T) {
			pd := optIAPD(t, capIAID, c.t1, c.t2, []pd6Spec{{pd6First, 3000, 6000}})
			m, _, acts := pd6ToDAD(t, pd6Params(64), []wire.OptionV6{pd}, pd)
			acts2 := []Action(nil)
			for _, a := range pd6Targets(acts) {
				_, acts2 = m.Step(at(4), 0, DADResult(a, false))
			}
			l, _ := m.Lease()
			if l.T1 != c.wantT1 || l.T2 != c.wantT2 {
				t.Errorf("T1 %s T2 %s, want %s and %s", l.T1, l.T2, c.wantT1, c.wantT2)
			}
			var renewAfter Duration
			for _, a := range acts2 {
				if a.Kind == ActSetTimer && a.Timer == Timer6Renew {
					renewAfter = a.After
				}
			}
			if renewAfter == 0 || renewAfter > c.wantT1 {
				t.Errorf("the Renew timer is armed for %s, want no later than T1 %s", renewAfter, c.wantT1)
			}
		})
	}
}

// TestPrefixEqualComparesThePrefixes: a Reply that moves or drops the prefix
// differs from the lease it renews, and the same grant does not
// (claymore666/docker-net-dhcp#214).
func TestPrefixEqualComparesThePrefixes(t *testing.T) {
	a := Lease6{IAID: 1, Prefixes: []Prefix6{{Prefix: netip.MustParsePrefix(pd6First), Preferred: 3 * Second, Valid: 6 * Second}}}
	b := Lease6{IAID: 1, Prefixes: append([]Prefix6(nil), a.Prefixes...)}
	if !a.Equal(b) {
		t.Error("two leases with the same prefix differ")
	}
	for name, mut := range map[string]func(*Lease6){
		"another prefix":     func(l *Lease6) { l.Prefixes[0].Prefix = netip.MustParsePrefix(pd6Other) },
		"another valid time": func(l *Lease6) { l.Prefixes[0].Valid = 7 * Second },
		"another preferred":  func(l *Lease6) { l.Prefixes[0].Preferred = 4 * Second },
		"no prefix":          func(l *Lease6) { l.Prefixes = nil },
		"a second prefix": func(l *Lease6) {
			l.Prefixes = append(l.Prefixes, Prefix6{Prefix: netip.MustParsePrefix(pd6Other), Valid: Second})
		},
	} {
		c := Lease6{IAID: 1, Prefixes: append([]Prefix6(nil), a.Prefixes...)}
		mut(&c)
		if a.Equal(c) || c.Equal(a) {
			t.Errorf("%s: Equal did not see the difference", name)
		}
	}
}

// TestPrefixRenewalSameIsNoChange: a Reply to a Renew that carries the same
// prefix is a renewal (claymore666/docker-net-dhcp#214).
func TestPrefixRenewalSameIsNoChange(t *testing.T) {
	m := pd6Bound(t, pd6Params(64))
	_, acts := pd6Renew(t, m, 152, 153, pd6Good(t))
	if count(acts, ActLeaseRenewed) != 1 || count(acts, ActLeaseChanged) != 0 {
		t.Errorf("%d Renewed, %d Changed, want a plain renewal", count(acts, ActLeaseRenewed), count(acts, ActLeaseChanged))
	}
	pd6Counters(t, m, Prefix6Counters{Granted: 1})
}

// TestPrefixRenewalThatChangesThePrefix: a Reply that gives another prefix, no
// prefix, or the prefix with the lifetime cut is a change, and the counter and
// the journal say so (RFC 8415 section 18.2.10.1;
// claymore666/docker-net-dhcp#214).
func TestPrefixRenewalThatChangesThePrefix(t *testing.T) {
	cases := []struct {
		name  string
		extra []wire.OptionV6
		want  string
		moves uint64 // how far prefix_changed moves
	}{
		{"another prefix", []wire.OptionV6{optIAPD(t, capIAID, 120, 200, []pd6Spec{{pd6Other, 300, 600}})}, pd6Other, 1},
		{"NoBinding in the IA_PD alone", []wire.OptionV6{optIAPD(t, capIAID, 0, 0, nil, optStatus(wire.StatusNoBinding))}, "", 1},
		{"no IA_PD", nil, "", 1},
		{"zero valid lifetime", []wire.OptionV6{optIAPD(t, capIAID, 120, 200, []pd6Spec{{pd6First, 0, 0}})}, "", 1},
		{"a shorter lifetime", []wire.OptionV6{optIAPD(t, capIAID, 120, 200, []pd6Spec{{pd6First, 50, 90}})}, pd6First, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := pd6Bound(t, pd6Params(64))
			before := m.PrefixCounters().Changed
			_, acts := pd6Renew(t, m, 152, 153, c.extra...)
			l, _ := m.Lease()
			var got string
			if len(l.Prefixes) > 0 {
				got = l.Prefixes[0].Prefix.String()
			}
			if got != c.want {
				t.Errorf("the lease holds %q, want %q", got, c.want)
			}
			if count(acts, ActLeaseChanged) != 1 {
				t.Errorf("%d Changed, want one", count(acts, ActLeaseChanged))
			}
			if ch := pd6Lease(t, acts, ActLeaseChanged); len(ch.Prefixes) != len(l.Prefixes) {
				t.Errorf("Changed carries %v, the lease %v", ch.Prefixes, l.Prefixes)
			}
			// A shorter lifetime alone is the same delegation: Changed by
			// Equal, but not the counter (claymore666/docker-net-dhcp#214).
			if d := m.PrefixCounters().Changed - before; d != c.moves {
				t.Errorf("prefix_changed moved by %d, want %d", d, c.moves)
			}
		})
	}
}

// TestPrefixIsReleased: the Release carries the IA_PD of the lease the client
// held, and a release of a lease with no prefix carries none
// (claymore666/docker-net-dhcp#214).
func TestPrefixIsReleased(t *testing.T) {
	m := pd6Bound(t, pd6Params(64))
	_, acts := m.Step(at(10), 9, Simple(EvRelease))
	rel := mustSendV6(t, acts, wire.MsgRelease6)
	if _, pds := pd6IAs(t, rel); len(pds) != 1 || len(pd6Prefixes(t, pds[0])) != 1 {
		t.Errorf("the Release carries %+v", pds)
	}

	// A hint with nothing granted: the lease has no prefix, so the Release has none.
	m2, _, acts := pd6ToDAD(t, pd6Params(64), nil)
	for _, a := range pd6Targets(acts) {
		m2.Step(at(4), 0, DADResult(a, false))
	}
	_, acts = m2.Step(at(10), 9, Simple(EvRelease))
	rel = mustSendV6(t, acts, wire.MsgRelease6)
	if _, pds := pd6IAs(t, rel); len(pds) != 0 {
		t.Errorf("the Release of a lease with no prefix carries %d IA_PD", len(pds))
	}
}

// pd6Rec drives a Machine6 through a script, recording a journal as it goes.
type pd6Rec struct {
	m       *Machine6
	entries []JournalEntry6
	seq     uint64
}

func (r *pd6Rec) step(now Instant, rnd uint64, ev Event) (State6, []Action) {
	from := r.m.State()
	to, acts := r.m.Step(now, rnd, ev)
	r.entries = append(r.entries, NewJournalEntry6(r.seq, now, rnd, ev, from, to, acts))
	r.seq++
	return to, acts
}

// TestPrefixReplayRebuildsTheLease: a journal whose Reply carries an IA_PD
// replays to a lease with the prefix, offline (claymore666/docker-net-dhcp#214).
func TestPrefixReplayRebuildsTheLease(t *testing.T) {
	p := pd6Params(64)
	r := &pd6Rec{m: newMachine6(t, p)}
	r.step(at(0), 0, Simple(EvStart))
	_, acts := r.step(at(1), capXIDSolicit, TimerFired(Timer6Delay))
	sol := mustSendV6(t, acts, wire.MsgSolicit)
	_, acts = r.step(at(2), capXIDRequest, pd6Advert(t, sol.XID, pd6Good(t)))
	req := mustSendV6(t, acts, wire.MsgRequest6)
	r.step(at(3), 0, pd6Reply(t, req.XID, pd6Good(t)))
	if s, _ := r.step(at(4), 0, DADResult(addr6(pd6Addr), false)); s != State6Bound {
		t.Fatalf("the recorded run did not bind: %s", s)
	}

	res, err := Replay6(p, r.entries)
	if err != nil {
		t.Fatalf("Replay6: %v", err)
	}
	if res.State != State6Bound || !res.Held || len(res.Lease.Prefixes) != 1 ||
		res.Lease.Prefixes[0].Prefix != netip.MustParsePrefix(pd6First) {
		t.Errorf("the replay ended in %s holding %v, want BOUND with %s", res.State, res.Lease, pd6First)
	}
	if res.Steps != len(r.entries) {
		t.Errorf("the replay ran %d steps, the recording has %d", res.Steps, len(r.entries))
	}
}

// TestPrefixCountersAreJournalled: every counter has a journal line, so a
// replay of the line is the replay of the count (claymore666/docker-net-dhcp#214).
func TestPrefixCountersAreJournalled(t *testing.T) {
	m, _, acts := pd6ToDAD(t, pd6Params(64), []wire.OptionV6{pd6Good(t)}, pd6Good(t))
	if !pd6Says(acts, "gave 1 delegated prefix") {
		t.Errorf("a grant left no journal line:%s", pd6Journal(acts))
	}
	for _, a := range pd6Targets(acts) {
		m.Step(at(4), 0, DADResult(a, false))
	}
	_, acts = pd6Renew(t, m, 152, 153)
	if !pd6Says(acts, "changed the delegated prefixes") || !pd6Says(acts, "no IA_PD in the message") {
		t.Errorf("a dropped IA_PD left no journal line:%s", pd6Journal(acts))
	}
	pd6Counters(t, m, Prefix6Counters{Granted: 1, Absent: 1, Changed: 1})
}
