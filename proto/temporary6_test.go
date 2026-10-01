// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// This file builds from fakes6_test.go, fakes_test.go and captured6_test.go and
// from nothing else in the package's tests, so a run with the other test files
// switched off still compiles it (claymore666/docker-net-dhcp#927).

const (
	ta6Stable = "fd00:99::183"
	ta6Temp   = "fd00:99::2a1"
	ta6Temp2  = "fd00:99::2a2"
)

func ta6Params(on bool) Params6 {
	p := testParams6()
	p.Temporary = on
	return p
}

func optIATA(t *testing.T, iaid uint32, addrs []iaAddrSpec, extra ...wire.OptionV6) wire.OptionV6 {
	t.Helper()
	ia := &wire.IATA{IAID: iaid}
	for _, a := range addrs {
		v, err := wire.EncodeIAAddr(&wire.IAAddr{
			Addr:              netip.MustParseAddr(a.addr),
			PreferredLifetime: a.preferred,
			ValidLifetime:     a.vali,
		})
		if err != nil {
			t.Fatalf("EncodeIAAddr: %v", err)
		}
		ia.Options = append(ia.Options, wire.OptionV6{Code: wire.OptV6IAAddr, Data: v})
	}
	ia.Options = append(ia.Options, extra...)
	v, err := wire.EncodeIATA(ia)
	if err != nil {
		t.Fatalf("EncodeIATA: %v", err)
	}
	return wire.OptionV6{Code: wire.OptV6IATA, Data: v}
}

// ta6Base is the options every server message here carries: the identifiers
// and an IA_NA with the stable address, T1 150 and T2 240.
func ta6Base(t *testing.T, extra ...wire.OptionV6) []wire.OptionV6 {
	t.Helper()
	return append([]wire.OptionV6{
		optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 150, 240, []iaAddrSpec{{ta6Stable, 300, 300}}),
	}, extra...)
}

func ta6Advert(t *testing.T, xid uint32, extra ...wire.OptionV6) Event {
	t.Helper()
	return receivedV6(t, wire.MsgAdvertise, xid, append(ta6Base(t, extra...), optPreference(255))...)
}

func ta6Reply(t *testing.T, xid uint32, extra ...wire.OptionV6) Event {
	t.Helper()
	return receivedV6(t, wire.MsgReply, xid, ta6Base(t, extra...)...)
}

// ta6Temps is one IA_TA with our IAID and the given addresses, 200 and 1000.
func ta6Temps(t *testing.T, addrs ...string) wire.OptionV6 {
	t.Helper()
	var specs []iaAddrSpec
	for _, a := range addrs {
		specs = append(specs, iaAddrSpec{a, 200, 1000})
	}
	return optIATA(t, capIAID, specs)
}

// ta6OnTheWire is the message as a server would read it: encoded, decoded.
func ta6OnTheWire(t *testing.T, msg *wire.MessageV6) *wire.MessageV6 {
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

// ta6IAs is the IA_NAs and IA_TAs of a message as they went on the wire.
func ta6IAs(t *testing.T, msg *wire.MessageV6) ([]*wire.IANA, []*wire.IATA) {
	t.Helper()
	back := ta6OnTheWire(t, msg)
	nas, err := back.Options.IANAs()
	if err != nil {
		t.Fatalf("IANAs: %v", err)
	}
	tas, err := back.Options.IATAs()
	if err != nil {
		t.Fatalf("IATAs: %v", err)
	}
	return nas, tas
}

func ta6AddrsOf(t *testing.T, o wire.OptionsV6) []*wire.IAAddr {
	t.Helper()
	a, err := o.Addrs()
	if err != nil {
		t.Fatalf("Addrs: %v", err)
	}
	return a
}

func ta6Journal(acts []Action) string {
	var b strings.Builder
	for _, a := range acts {
		if a.Kind == ActJournal {
			b.WriteString("\n\t" + a.Note)
		}
	}
	return b.String()
}

func ta6Says(acts []Action, sub string) bool { return strings.Contains(ta6Journal(acts), sub) }

// ta6Targets is the addresses ring 3 was asked to check.
func ta6Targets(acts []Action) []netip.Addr {
	var out []netip.Addr
	for _, a := range acts {
		if a.Kind == ActStartDAD {
			out = append(out, a.Target)
		}
	}
	return out
}

func ta6Lease(t *testing.T, acts []Action, kind ActionKind) Lease6 {
	t.Helper()
	a, ok := find(acts, kind)
	if !ok {
		t.Fatalf("no %s action in %v", kind, acts)
	}
	return a.Lease6
}

func ta6Counters(t *testing.T, m *Machine6, want Temporary6Counters) {
	t.Helper()
	if got := m.TemporaryCounters(); got != want {
		t.Errorf("TemporaryCounters = %+v, want %+v", got, want)
	}
}

func ta6Armed(acts []Action, id TimerID) bool {
	for _, a := range acts {
		if a.Kind == ActSetTimer && a.Timer == id {
			return true
		}
	}
	return false
}

// ta6ToDAD takes a fresh machine through the Solicit, the Advertise (with an
// IA_TA when advTemp) and the Request to the Reply, which it answers with the
// IA_NA and the extra options. It returns the machine in DAD with the Request
// and the actions of the Reply.
func ta6ToDAD(t *testing.T, p Params6, advTemp bool, replyExtra ...wire.OptionV6) (*Machine6, *wire.MessageV6, []Action) {
	t.Helper()
	m, sol := solicit6(t, p)
	var adv []wire.OptionV6
	if advTemp {
		adv = append(adv, ta6Temps(t, ta6Temp))
	}
	_, acts := m.Step(at(2), capXIDRequest, ta6Advert(t, sol.XID, adv...))
	req := mustSendV6(t, acts, wire.MsgRequest6)
	_, acts = m.Step(at(3), 0, ta6Reply(t, req.XID, replyExtra...))
	return m, req, acts
}

// ta6Bound is ta6ToDAD with the temporary address granted and every address
// checked clean; temp is the temporary address's lifetimes, preferred and
// valid, in seconds.
func ta6Bound(t *testing.T, temp [2]uint32) *Machine6 {
	t.Helper()
	m, sol := solicit6(t, ta6Params(true))
	_, acts := m.Step(at(2), capXIDRequest, ta6Advert(t, sol.XID, ta6Temps(t, ta6Temp)))
	req := mustSendV6(t, acts, wire.MsgRequest6)
	_, acts = m.Step(at(3), 0, ta6Reply(t, req.XID, optIATA(t, capIAID, []iaAddrSpec{{ta6Temp, temp[0], temp[1]}})))
	for _, a := range ta6Targets(acts) {
		m.Step(at(4), 0, DADResult(a, false))
	}
	if m.State() != State6Bound {
		t.Fatalf("the exchange left the machine in %s, want %s", m.State(), State6Bound)
	}
	return m
}

// ta6Renew sends the Renew at renewAt and answers it at replyAt with the plain
// stable Reply, and returns the actions of the answer.
func ta6Renew(t *testing.T, m *Machine6, renewAt, replyAt int64, extra ...wire.OptionV6) []Action {
	t.Helper()
	_, acts := m.Step(at(renewAt), 7, TimerFired(Timer6Renew))
	ren := mustSendV6(t, acts, wire.MsgRenew)
	_, acts = m.Step(at(replyAt), 0, ta6Reply(t, ren.XID, extra...))
	return acts
}

// TestTemporaryIsOffByDefault: the parameter is false, no message carries an
// IA_TA, and an IA_TA the server sends anyway is read as nothing
// (claymore666/docker-net-dhcp#927).
func TestTemporaryIsOffByDefault(t *testing.T) {
	if DefaultParams6().Temporary {
		t.Fatal("DefaultParams6 asks for temporary addresses")
	}
	p := ta6Params(false)
	m, sol := solicit6(t, p)
	if _, tas := ta6IAs(t, sol); len(tas) != 0 {
		t.Errorf("the Solicit carries %d IA_TA", len(tas))
	}
	_, acts := m.Step(at(2), capXIDRequest, ta6Advert(t, sol.XID, ta6Temps(t, ta6Temp)))
	req := mustSendV6(t, acts, wire.MsgRequest6)
	if _, tas := ta6IAs(t, req); len(tas) != 0 {
		t.Errorf("the Request carries %d IA_TA", len(tas))
	}
	_, acts = m.Step(at(3), 0, ta6Reply(t, req.XID, ta6Temps(t, ta6Temp2)))
	if got := ta6Targets(acts); len(got) != 1 || got[0] != addr6(ta6Stable) {
		t.Errorf("DAD asked about %v, want the stable address alone", got)
	}
	m.Step(at(4), 0, DADResult(addr6(ta6Stable), false))
	l, held := m.Lease()
	if !held || len(l.Addrs) != 1 || len(l.TempAddrs) != 0 {
		t.Errorf("lease %v held %t, want the stable address and no temporary one", l, held)
	}
	if !ta6Says(acts, "ignored") {
		t.Errorf("an unsolicited IA_TA left no journal line:%s", ta6Journal(acts))
	}
	ta6Counters(t, m, Temporary6Counters{})
}

// TestTemporaryBytesOfEveryMessage: the IA_TA rides the Solicit and the
// Request and no other message a client builds, and the Decline of temporary
// addresses is the one exception (RFC 8415 sections 13.2 and 18.2.4;
// claymore666/docker-net-dhcp#927).
func TestTemporaryBytesOfEveryMessage(t *testing.T) {
	p := ta6Params(true)

	m, sol := solicit6(t, p)
	nas, tas := ta6IAs(t, sol)
	if len(nas) != 1 || len(tas) != 1 {
		t.Fatalf("the Solicit carries %d IA_NA and %d IA_TA, want one of each", len(nas), len(tas))
	}
	if tas[0].IAID != capIAID || nas[0].IAID != tas[0].IAID {
		t.Errorf("IA_TA IAID %#x, IA_NA IAID %#x, want both %#x", tas[0].IAID, nas[0].IAID, capIAID)
	}
	if len(tas[0].Options) != 0 {
		t.Errorf("the Solicit's IA_TA carries options %v, want none", tas[0].Options)
	}

	// The Advertise offered an address: the Request repeats it with its
	// lifetimes, because an empty IA makes dnsmasq draw another one.
	_, acts := m.Step(at(2), capXIDRequest, ta6Advert(t, sol.XID, ta6Temps(t, ta6Temp)))
	req := mustSendV6(t, acts, wire.MsgRequest6)
	_, tas = ta6IAs(t, req)
	if len(tas) != 1 {
		t.Fatalf("the Request carries %d IA_TA, want 1", len(tas))
	}
	got := ta6AddrsOf(t, tas[0].Options)
	if len(got) != 1 || got[0].Addr != addr6(ta6Temp) || got[0].PreferredLifetime != 200 || got[0].ValidLifetime != 1000 {
		t.Errorf("the Request's IA_TA = %+v, want %s with 200 and 1000", got, ta6Temp)
	}

	// No IA_TA in the Advertise: the Request still asks, with an empty one.
	m2, sol2 := solicit6(t, p)
	_, acts = m2.Step(at(2), capXIDRequest, ta6Advert(t, sol2.XID))
	req2 := mustSendV6(t, acts, wire.MsgRequest6)
	if _, tas = ta6IAs(t, req2); len(tas) != 1 || len(tas[0].Options) != 0 || tas[0].IAID != capIAID {
		t.Errorf("the Request after an Advertise with no IA_TA carries %+v, want one empty IA_TA", tas)
	}

	bound := ta6Bound(t, [2]uint32{200, 1000})
	_, acts = bound.Step(at(152), 7, TimerFired(Timer6Renew))
	ren := mustSendV6(t, acts, wire.MsgRenew)
	if _, tas = ta6IAs(t, ren); len(tas) != 0 {
		t.Errorf("the Renew carries %d IA_TA", len(tas))
	}
	_, acts = bound.Step(at(242), 8, TimerFired(Timer6Rebind))
	reb := mustSendV6(t, acts, wire.MsgRebind)
	if _, tas = ta6IAs(t, reb); len(tas) != 0 {
		t.Errorf("the Rebind carries %d IA_TA", len(tas))
	}

	released := ta6Bound(t, [2]uint32{200, 1000})
	_, acts = released.Step(at(10), 9, Simple(EvRelease))
	rel := mustSendV6(t, acts, wire.MsgRelease6)
	if nas, tas = ta6IAs(t, rel); len(tas) != 0 || len(nas) != 1 || len(ta6AddrsOf(t, nasOptions(nas[0]))) != 1 {
		t.Errorf("the Release carries %d IA_NA and %d IA_TA, want the stable binding alone", len(nas), len(tas))
	}

	_, acts = confirming6(t, p)
	conf := mustSendV6(t, acts, wire.MsgConfirm)
	if _, tas = ta6IAs(t, conf); len(tas) != 0 {
		t.Errorf("the Confirm carries %d IA_TA", len(tas))
	}

	info, _ := solicit6(t, p)
	_, acts = info.Step(at(2), capXIDRequest, raEvent6(t, ra6(false, true)))
	inf := mustSendV6(t, acts, wire.MsgInformationRequest)
	if nas, tas = ta6IAs(t, inf); len(tas) != 0 || len(nas) != 0 {
		t.Errorf("the Information-request carries %d IA_NA and %d IA_TA", len(nas), len(tas))
	}

	// A Decline of a stable address with no temporary one granted: no IA_TA.
	m3, _, acts := ta6ToDAD(t, p, false)
	_, acts = m3.Step(at(4), 0, DADResult(addr6(ta6Stable), true))
	dec := mustSendV6(t, acts, wire.MsgDecline6)
	if _, tas = ta6IAs(t, dec); len(tas) != 0 {
		t.Errorf("a Decline with no temporary address granted carries %d IA_TA", len(tas))
	}
}

func nasOptions(ia *wire.IANA) wire.OptionsV6 { return ia.Options }

// TestTemporaryReadsTwoSlices: the lease holds the stable address in Addrs and
// the temporary one in TempAddrs, and nothing that reads the stable binding
// sees the temporary one (claymore666/docker-net-dhcp#927).
func TestTemporaryReadsTwoSlices(t *testing.T) {
	m := ta6Bound(t, [2]uint32{200, 10000})
	l, held := m.Lease()
	if !held || len(l.Addrs) != 1 || len(l.TempAddrs) != 1 {
		t.Fatalf("lease %v held %t, want one address in each slice", l, held)
	}
	if l.Addrs[0].Addr != addr6(ta6Stable) || l.TempAddrs[0].Addr != addr6(ta6Temp) {
		t.Errorf("Addrs %v TempAddrs %v", l.Addrs, l.TempAddrs)
	}
	if a, ok := l.Addr(); !ok || a != addr6(ta6Stable) {
		t.Errorf("Addr() = %v, %t, want the stable address", a, ok)
	}
	d := l.Deadlines()
	if want := l.Start.Add(300 * Second); !d.HasExpire || d.Expire != want {
		t.Errorf("Expire = %v (has %t), want %v: the temporary lifetime of 10000 s is not the lease's", d.Expire, d.HasExpire, want)
	}
	if !strings.Contains(l.String(), "temp "+ta6Temp) {
		t.Errorf("String() = %q does not name the temporary address", l.String())
	}
}

// TestTemporaryDADRunsOnTheTemporaryAddress: both addresses are checked before
// anything is bound (RFC 8415 section 18.2.10.1; claymore666/docker-net-dhcp#927).
func TestTemporaryDADRunsOnTheTemporaryAddress(t *testing.T) {
	m, _, acts := ta6ToDAD(t, ta6Params(true), true, ta6Temps(t, ta6Temp))
	targets := ta6Targets(acts)
	if len(targets) != 2 || !containsAddr(targets, addr6(ta6Stable)) || !containsAddr(targets, addr6(ta6Temp)) {
		t.Fatalf("DAD asked about %v, want both addresses", targets)
	}
	if s, acts := m.Step(at(4), 0, DADResult(addr6(ta6Stable), false)); s != State6DAD || count(acts, ActLeaseAcquired) != 0 {
		t.Fatalf("one result of two left the machine in %s with %d Acquired", s, count(acts, ActLeaseAcquired))
	}
	s, acts := m.Step(at(5), 0, DADResult(addr6(ta6Temp), false))
	if s != State6Bound || count(acts, ActLeaseAcquired) != 1 {
		t.Fatalf("both results left the machine in %s with %d Acquired", s, count(acts, ActLeaseAcquired))
	}
	if l := ta6Lease(t, acts, ActLeaseAcquired); len(l.TempAddrs) != 1 || len(l.Addrs) != 1 {
		t.Errorf("Acquired carries %v", l)
	}
}

// TestTemporaryStatusIsPerIA: what the IA_TA says is about the IA_TA. A refusal
// there leaves the IA_NA lease whole; a refusal in the IA_NA is what it is
// without a temporary address; and an IA_TA that is not ours, malformed or
// doubled gives nothing (RFC 8415 section 18.2.10.1;
// claymore666/docker-net-dhcp#927).
func TestTemporaryStatusIsPerIA(t *testing.T) {
	good := iaAddrSpec{ta6Temp, 200, 1000}
	cases := []struct {
		name    string
		extra   []wire.OptionV6
		want    []string
		counter Temporary6Counters
		say     string
	}{
		{"granted", []wire.OptionV6{optIATA(t, capIAID, []iaAddrSpec{good})}, []string{ta6Temp},
			Temporary6Counters{Granted: 1, Absent: 1}, "gave 1 temporary"},
		{"NoAddrsAvail", []wire.OptionV6{optIATA(t, capIAID, nil, optStatus(wire.StatusNoAddrsAvail))}, nil,
			Temporary6Counters{Refused: 1, Absent: 1}, "gave no address"},
		{"NoAddrsAvail with an address in it", []wire.OptionV6{optIATA(t, capIAID, []iaAddrSpec{good}, optStatus(wire.StatusNoAddrsAvail))}, nil,
			Temporary6Counters{Refused: 1, Absent: 1}, "not ours to use"},
		{"UnspecFail", []wire.OptionV6{optIATA(t, capIAID, nil, optStatus(wire.StatusUnspecFail))}, nil,
			Temporary6Counters{Refused: 1, Absent: 1}, "gave no address"},
		{"NoBinding with an address in it", []wire.OptionV6{optIATA(t, capIAID, []iaAddrSpec{good}, optStatus(wire.StatusNoBinding))}, nil,
			Temporary6Counters{Refused: 1, Absent: 1}, "not ours to use"},
		{"empty", []wire.OptionV6{optIATA(t, capIAID, nil)}, nil,
			Temporary6Counters{Refused: 1, Absent: 1}, "gave no address"},
		{"not our IAID", []wire.OptionV6{optIATA(t, capIAID+1, []iaAddrSpec{good})}, nil,
			Temporary6Counters{Absent: 2}, "is not ours"},
		{"valid lifetime 0", []wire.OptionV6{optIATA(t, capIAID, []iaAddrSpec{{ta6Temp, 0, 0}})}, nil,
			Temporary6Counters{Refused: 1, Absent: 1}, "valid lifetime of 0"},
		{"preferred above valid", []wire.OptionV6{optIATA(t, capIAID, []iaAddrSpec{{ta6Temp, 500, 100}})}, nil,
			Temporary6Counters{Refused: 1, Absent: 1}, "greater than valid"},
		{"the stable address again", []wire.OptionV6{optIATA(t, capIAID, []iaAddrSpec{{ta6Stable, 200, 1000}})}, nil,
			Temporary6Counters{Refused: 1, Absent: 1}, "also in the IA_NA"},
		{"two IA_TAs", []wire.OptionV6{optIATA(t, capIAID, []iaAddrSpec{good}), optIATA(t, capIAID, []iaAddrSpec{{ta6Temp2, 200, 1000}})}, []string{ta6Temp},
			Temporary6Counters{Granted: 1, Absent: 1}, "a second IA_TA"},
		{"none", nil, nil, Temporary6Counters{Absent: 2}, "no IA_TA in the message"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, _, acts := ta6ToDAD(t, ta6Params(true), false, c.extra...)
			for _, a := range ta6Targets(acts) {
				m.Step(at(4), 0, DADResult(a, false))
			}
			l, held := m.Lease()
			if m.State() != State6Bound || !held || len(l.Addrs) != 1 || l.Addrs[0].Addr != addr6(ta6Stable) {
				t.Fatalf("state %s lease %v held %t, want BOUND with the stable address whole", m.State(), l, held)
			}
			var got []string
			for _, a := range l.TempAddrs {
				got = append(got, a.Addr.String())
			}
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Errorf("TempAddrs %v, want %v", got, c.want)
			}
			if !ta6Says(acts, c.say) {
				t.Errorf("the journal lacks %q:%s", c.say, ta6Journal(acts))
			}
			ta6Counters(t, m, c.counter)
		})
	}
}

// TestTemporaryDoesNotMakeALeaseOfAnIATAAlone: no stable address, no lease,
// whatever the IA_TA offers, and the refused IA_NA is the failure it is today
// (claymore666/docker-net-dhcp#927).
func TestTemporaryDoesNotMakeALeaseOfAnIATAAlone(t *testing.T) {
	for _, name := range []string{"no IA_NA", "IA_NA NoAddrsAvail"} {
		t.Run(name, func(t *testing.T) {
			m, sol := solicit6(t, ta6Params(true))
			_, acts := m.Step(at(2), capXIDRequest, ta6Advert(t, sol.XID, ta6Temps(t, ta6Temp)))
			req := mustSendV6(t, acts, wire.MsgRequest6)
			opts := []wire.OptionV6{optClientID(capDUID), optServerID(testServerDUID), ta6Temps(t, ta6Temp)}
			if name != "no IA_NA" {
				opts = append(opts, optIANA(t, capIAID, 150, 240, nil, optStatus(wire.StatusNoAddrsAvail)))
			}
			s, acts := m.Step(at(3), 0, receivedV6(t, wire.MsgReply, req.XID, opts...))
			if s == State6Bound || s == State6DAD || len(ta6Targets(acts)) != 0 || count(acts, ActLeaseAcquired) != 0 {
				t.Errorf("a Reply with no stable address left the machine in %s with DAD %v", s, ta6Targets(acts))
			}
			if _, held := m.Lease(); held {
				t.Error("a lease was held")
			}
			if c := m.TemporaryCounters(); c.Granted != 0 {
				t.Errorf("a Reply nobody used counted %d grants", c.Granted)
			}
		})
	}
}

// TestTemporaryRenewalKeepsTheAddressAndItsExpiry: a Reply to a Renew or a
// Rebind has no IA_TA, and the temporary address is carried forward with the
// expiry it was granted, which is a renewal and not a change
// (RFC 8415 section 13.2; claymore666/docker-net-dhcp#927).
func TestTemporaryRenewalKeepsTheAddressAndItsExpiry(t *testing.T) {
	// Granted at start t+2 s for 1000 s: it ends at t+1002 s.
	end := at(1002)
	m := ta6Bound(t, [2]uint32{200, 1000})
	for i, hop := range []struct{ renewAt, replyAt int64 }{{152, 153}, {303, 304}} {
		acts := ta6Renew(t, m, hop.renewAt, hop.replyAt)
		l, held := m.Lease()
		if m.State() != State6Bound || !held || len(l.TempAddrs) != 1 || l.TempAddrs[0].Addr != addr6(ta6Temp) {
			t.Fatalf("renewal %d: state %s lease %v", i, m.State(), l)
		}
		if got := l.Start.Add(l.TempAddrs[0].Valid); got != end {
			t.Errorf("renewal %d moved the temporary expiry to %v, want %v", i, got, end)
		}
		// Preferred ends at t+202 s; once that has passed it is clamped to the Start.
		wantPref := at(202)
		if l.Start.After(wantPref) {
			wantPref = l.Start
		}
		if got := l.Start.Add(l.TempAddrs[0].Preferred); got != wantPref {
			t.Errorf("renewal %d: the temporary preferred time is %v, want %v", i, got, wantPref)
		}
		if count(acts, ActLeaseRenewed) != 1 || count(acts, ActLeaseChanged) != 0 || len(ta6Targets(acts)) != 0 {
			t.Errorf("renewal %d: %d Renewed, %d Changed, DAD %v; want a plain renewal", i, count(acts, ActLeaseRenewed), count(acts, ActLeaseChanged), ta6Targets(acts))
		}
	}

	// A rebind Reply reads the same way.
	_, acts := m.Step(at(500), 7, TimerFired(Timer6Renew))
	mustSendV6(t, acts, wire.MsgRenew)
	_, acts = m.Step(at(600), 8, TimerFired(Timer6Rebind))
	reb := mustSendV6(t, acts, wire.MsgRebind)
	_, acts = m.Step(at(601), 0, ta6Reply(t, reb.XID))
	if l, _ := m.Lease(); len(l.TempAddrs) != 1 || l.Start.Add(l.TempAddrs[0].Valid) != end || count(acts, ActLeaseChanged) != 0 {
		t.Errorf("after a rebind: lease %v, %d Changed", l, count(acts, ActLeaseChanged))
	}
}

// TestTemporaryRenewalIgnoresAnIATAInTheReply: this client sent none, so one in
// the Reply is not a grant (claymore666/docker-net-dhcp#927).
func TestTemporaryRenewalIgnoresAnIATAInTheReply(t *testing.T) {
	m := ta6Bound(t, [2]uint32{200, 1000})
	acts := ta6Renew(t, m, 152, 153, ta6Temps(t, ta6Temp2))
	l, _ := m.Lease()
	if len(l.TempAddrs) != 1 || l.TempAddrs[0].Addr != addr6(ta6Temp) {
		t.Errorf("TempAddrs %v, want the one carried forward", l.TempAddrs)
	}
	if !ta6Says(acts, "answers none we sent") {
		t.Errorf("no journal line for the unsolicited IA_TA:%s", ta6Journal(acts))
	}
	ta6Counters(t, m, Temporary6Counters{Granted: 1})
}

// TestTemporaryAddressLeavesWhenItsValidLifetimePasses: no temporary address is
// ever renewed, so one whose valid lifetime has passed is gone from the lease
// the next Reply builds, and the lease event is Changed because the set
// differs. At the instant itself it has passed (claymore666/docker-net-dhcp#927).
func TestTemporaryAddressLeavesWhenItsValidLifetimePasses(t *testing.T) {
	// The temporary address ends at t+402 s.
	for _, c := range []struct {
		replyAt int64
		kept    bool
	}{{401, true}, {402, false}, {410, false}} {
		m := ta6Bound(t, [2]uint32{200, 400})
		ta6Renew(t, m, 152, 153)
		acts := ta6Renew(t, m, 303, c.replyAt)
		l, _ := m.Lease()
		if (len(l.TempAddrs) == 1) != c.kept {
			t.Errorf("a Reply at t+%d s leaves %v, kept want %t", c.replyAt, l.TempAddrs, c.kept)
		}
		if changed := count(acts, ActLeaseChanged); (changed == 1) == c.kept {
			t.Errorf("a Reply at t+%d s emitted %d Changed, kept %t", c.replyAt, changed, c.kept)
		}
		if !c.kept && !ta6Says(acts, "left the lease") {
			t.Errorf("the drop left no journal line:%s", ta6Journal(acts))
		}
	}
}

// TestTemporaryInfiniteLifetimeSurvivesRenewals: the all-ones valid lifetime is
// infinity and carrying it forward keeps it infinite
// (claymore666/docker-net-dhcp#927).
func TestTemporaryInfiniteLifetimeSurvivesRenewals(t *testing.T) {
	m := ta6Bound(t, [2]uint32{0xFFFFFFFF, 0xFFFFFFFF})
	acts := ta6Renew(t, m, 152, 153)
	l, _ := m.Lease()
	if len(l.TempAddrs) != 1 || l.TempAddrs[0].Valid != Infinite || l.TempAddrs[0].Preferred != Infinite {
		t.Errorf("TempAddrs %v, want infinite lifetimes", l.TempAddrs)
	}
	if count(acts, ActLeaseChanged) != 0 {
		t.Error("an infinite temporary address made the renewal a change")
	}
}

// TestTemporaryEqualComparesTheTemporaryAddresses: a Reply that changes only
// the temporary address is a change; the same grant seen from a later Start is
// not (claymore666/docker-net-dhcp#927).
func TestTemporaryEqualComparesTheTemporaryAddresses(t *testing.T) {
	base := Lease6{IAID: 1, Start: at(0),
		Addrs:     []Addr6{{Addr: addr6(ta6Stable), Preferred: 100 * Second, Valid: 100 * Second}},
		TempAddrs: []Addr6{{Addr: addr6(ta6Temp), Preferred: 50 * Second, Valid: 100 * Second}}}
	with := func(f func(l *Lease6)) Lease6 {
		l := base
		l.TempAddrs = append([]Addr6(nil), base.TempAddrs...)
		f(&l)
		return l
	}
	for _, c := range []struct {
		name  string
		other Lease6
		equal bool
	}{
		{"same", with(func(*Lease6) {}), true},
		{"the same grant from a later start", with(func(l *Lease6) {
			l.Start = at(10)
			l.TempAddrs[0].Preferred, l.TempAddrs[0].Valid = 40*Second, 90*Second
		}), true},
		{"preferred time already passed at the later start", with(func(l *Lease6) {
			l.Start = at(70)
			l.TempAddrs[0].Preferred, l.TempAddrs[0].Valid = 0, 30*Second
		}), true},
		{"another address", with(func(l *Lease6) { l.TempAddrs[0].Addr = addr6(ta6Temp2) }), false},
		{"a longer valid lifetime", with(func(l *Lease6) { l.TempAddrs[0].Valid = 200 * Second }), false},
		{"a longer preferred lifetime", with(func(l *Lease6) { l.TempAddrs[0].Preferred = 60 * Second }), false},
		{"the same lifetimes from a later start", with(func(l *Lease6) { l.Start = at(10) }), false},
		{"none", with(func(l *Lease6) { l.TempAddrs = nil }), false},
		{"infinite instead of finite", with(func(l *Lease6) { l.TempAddrs[0].Valid = Infinite }), false},
		{"one more", with(func(l *Lease6) {
			l.TempAddrs = append(l.TempAddrs, Addr6{Addr: addr6(ta6Temp2), Preferred: 50 * Second, Valid: 100 * Second})
		}), false},
	} {
		if got := base.Equal(c.other); got != c.equal {
			t.Errorf("%s: Equal = %t, want %t", c.name, got, c.equal)
		}
		if got := c.other.Equal(base); got != c.equal {
			t.Errorf("%s reversed: Equal = %t, want %t", c.name, got, c.equal)
		}
	}
	inf := with(func(l *Lease6) { l.TempAddrs[0].Valid, l.TempAddrs[0].Preferred = Infinite, Infinite })
	if !inf.Equal(inf) {
		t.Error("an infinite temporary address is not equal to itself")
	}
}

// TestTemporaryDADFailureIsDeclinedAlone: a temporary address found in use is
// declined in an IA_TA and nothing else; the stable lease is bound when the
// exchange ends, with that address gone (RFC 8415 section 18.2.10.1:
// "the client uses the other addresses"; claymore666/docker-net-dhcp#927).
func TestTemporaryDADFailureIsDeclinedAlone(t *testing.T) {
	for _, order := range []string{"temporary last", "temporary first"} {
		t.Run(order, func(t *testing.T) {
			m, _, acts := ta6ToDAD(t, ta6Params(true), true, ta6Temps(t, ta6Temp))
			first, second := DADResult(addr6(ta6Stable), false), DADResult(addr6(ta6Temp), true)
			if order == "temporary first" {
				first, second = second, first
			}
			m.Step(at(4), 0, first)
			s, acts := m.Step(at(5), 0, second)
			if s != State6DAD {
				t.Fatalf("the machine is in %s while the Decline is out, want %s", s, State6DAD)
			}
			dec := mustSendV6(t, acts, wire.MsgDecline6)
			nas, tas := ta6IAs(t, dec)
			if len(nas) != 0 || len(tas) != 1 || tas[0].IAID != capIAID {
				t.Fatalf("the Decline carries %d IA_NA and %d IA_TA, want the IA_TA alone", len(nas), len(tas))
			}
			got := ta6AddrsOf(t, tas[0].Options)
			if len(got) != 1 || got[0].Addr != addr6(ta6Temp) || got[0].PreferredLifetime != 0 || got[0].ValidLifetime != 0 {
				t.Errorf("the Decline's IA_TA = %+v, want %s with zero lifetimes", got, ta6Temp)
			}
			if sid, _ := dec.Options.First(wire.OptV6ServerID); string(sid) != string(testServerDUID) {
				t.Errorf("the Decline names server %x, want the one that granted the lease", sid)
			}
			if count(acts, ActLeaseAcquired) != 0 || count(acts, ActFailed) != 0 {
				t.Error("the lease was reported or failed before the Decline ended")
			}
			ta6Counters(t, m, Temporary6Counters{Granted: 1, Conflicted: 1})

			s, acts = m.Step(at(6), 0, receivedV6(t, wire.MsgReply, dec.XID, optClientID(capDUID), optServerID(testServerDUID)))
			if s != State6Bound {
				t.Fatalf("the Reply to the Decline left the machine in %s, want %s", s, State6Bound)
			}
			l := ta6Lease(t, acts, ActLeaseAcquired)
			if len(l.Addrs) != 1 || l.Addrs[0].Addr != addr6(ta6Stable) || len(l.TempAddrs) != 0 {
				t.Errorf("Acquired carries %v, want the stable address alone", l)
			}
			if hasSendV6(acts, wire.MsgSolicit) || count(acts, ActFailed) != 0 || !ta6Armed(acts, Timer6Renew) {
				t.Error("the stable lease was restarted or its renewal not armed")
			}
			if len(ta6Targets(acts)) != 0 {
				t.Error("DAD ran again")
			}
		})
	}
}

// TestTemporaryDeclineThatIsNeverAnsweredStillBindsTheStableLease: the Decline
// ends at DEC_MAX_RC and the lease minus the address is bound
// (claymore666/docker-net-dhcp#927).
func TestTemporaryDeclineThatIsNeverAnsweredStillBindsTheStableLease(t *testing.T) {
	p := ta6Params(true)
	m, _, _ := ta6ToDAD(t, p, true, ta6Temps(t, ta6Temp))
	m.Step(at(4), 0, DADResult(addr6(ta6Stable), false))
	_, acts := m.Step(at(5), 0, DADResult(addr6(ta6Temp), true))
	sent := 0
	if hasSendV6(acts, wire.MsgDecline6) {
		sent++
	}
	for i := 0; i < 3*p.DecMaxRC && m.State() == State6DAD; i++ {
		_, acts = m.Step(at(int64(10+10*i)), uint64(i), TimerFired(Timer6Retransmit))
		if hasSendV6(acts, wire.MsgDecline6) {
			sent++
		}
	}
	if m.State() != State6Bound || sent != p.DecMaxRC {
		t.Fatalf("state %s after %d Declines, want %s after %d", m.State(), sent, State6Bound, p.DecMaxRC)
	}
	if l, held := m.Lease(); !held || len(l.TempAddrs) != 0 || len(l.Addrs) != 1 {
		t.Errorf("lease %v held %t", l, held)
	}
}

// TestTemporaryStableDADFailureDeclinesTheWholeReply: a stable address in use
// is today's path, and the temporary addresses of the same Reply go into that
// Decline in their IA_TA (claymore666/docker-net-dhcp#927).
func TestTemporaryStableDADFailureDeclinesTheWholeReply(t *testing.T) {
	for _, tempDup := range []bool{false, true} {
		m, _, _ := ta6ToDAD(t, ta6Params(true), true, ta6Temps(t, ta6Temp))
		m.Step(at(4), 0, DADResult(addr6(ta6Temp), tempDup))
		s, acts := m.Step(at(5), 0, DADResult(addr6(ta6Stable), true))
		if s != State6DAD {
			t.Fatalf("temporary duplicate %t: machine in %s, want %s", tempDup, s, State6DAD)
		}
		dec := mustSendV6(t, acts, wire.MsgDecline6)
		nas, tas := ta6IAs(t, dec)
		if len(nas) != 1 || len(tas) != 1 {
			t.Fatalf("the Decline carries %d IA_NA and %d IA_TA, want one of each", len(nas), len(tas))
		}
		if na := ta6AddrsOf(t, nas[0].Options); len(na) != 1 || na[0].Addr != addr6(ta6Stable) {
			t.Errorf("the IA_NA names %+v, want the stable address", na)
		}
		if ta := ta6AddrsOf(t, tas[0].Options); len(ta) != 1 || ta[0].Addr != addr6(ta6Temp) {
			t.Errorf("the IA_TA names %+v, want the temporary address", ta)
		}
		if a, ok := find(acts, ActFailed); !ok || a.Reason != ReasonConflict {
			t.Errorf("no conflict was reported: %v", acts)
		}
		want := Temporary6Counters{Granted: 1}
		if tempDup {
			want.Conflicted = 1
		}
		ta6Counters(t, m, want)
		s, acts = m.Step(at(6), 0, receivedV6(t, wire.MsgReply, dec.XID, optClientID(capDUID), optServerID(testServerDUID)))
		if s == State6Bound || count(acts, ActLeaseAcquired) != 0 {
			t.Errorf("temporary duplicate %t: the stable lease survived its own conflict (state %s)", tempDup, s)
		}
	}
}

// TestTemporaryDeclineNamesOnlyWhatThisReplyGranted: a renewal onto a new stable
// address that fails DAD declines that address and not the temporary one it
// carried; a bound lease that loses an address declines the stable binding
// alone (claymore666/docker-net-dhcp#927).
func TestTemporaryDeclineNamesOnlyWhatThisReplyGranted(t *testing.T) {
	moved := func(t *testing.T) *Machine6 {
		m := ta6Bound(t, [2]uint32{200, 1000})
		_, acts := m.Step(at(152), 7, TimerFired(Timer6Renew))
		ren := mustSendV6(t, acts, wire.MsgRenew)
		other := "fd00:99::999"
		s, acts := m.Step(at(153), 0, receivedV6(t, wire.MsgReply, ren.XID, optClientID(capDUID), optServerID(testServerDUID),
			optIANA(t, capIAID, 150, 240, []iaAddrSpec{{other, 300, 300}})))
		if got := ta6Targets(acts); s != State6DAD || len(got) != 1 || got[0] != addr6(other) {
			t.Fatalf("state %s, DAD %v, want the new stable address alone (the carried temporary one was checked)", s, got)
		}
		return m
	}
	m := moved(t)
	_, acts := m.Step(at(154), 0, DADResult(addr6("fd00:99::999"), true))
	dec := mustSendV6(t, acts, wire.MsgDecline6)
	if nas, tas := ta6IAs(t, dec); len(nas) != 1 || len(tas) != 0 {
		t.Errorf("the Decline carries %d IA_NA and %d IA_TA, want the new stable address alone", len(nas), len(tas))
	}

	b := ta6Bound(t, [2]uint32{200, 1000})
	_, acts = b.Step(at(20), 0, Simple(EvAddressLost))
	dec = mustSendV6(t, acts, wire.MsgDecline6)
	if nas, tas := ta6IAs(t, dec); len(nas) != 1 || len(tas) != 0 {
		t.Errorf("a withdrawn address: the Decline carries %d IA_NA and %d IA_TA, want the stable binding alone", len(nas), len(tas))
	}
}

// TestTemporaryCountersAreAboutMessages: an Advertise with no IA_TA and a Reply
// that grants one are two lines, and a Reply nobody could use is none
// (claymore666/docker-net-dhcp#927).
func TestTemporaryCountersAreAboutMessages(t *testing.T) {
	m, _, _ := ta6ToDAD(t, ta6Params(true), false, ta6Temps(t, ta6Temp))
	ta6Counters(t, m, Temporary6Counters{Granted: 1, Absent: 1})

	m, _, _ = ta6ToDAD(t, ta6Params(true), true, ta6Temps(t, ta6Temp))
	ta6Counters(t, m, Temporary6Counters{Granted: 1})

	m, _, _ = ta6ToDAD(t, ta6Params(false), true, ta6Temps(t, ta6Temp))
	ta6Counters(t, m, Temporary6Counters{})
}

// TestTemporaryWithRapidCommit: a Reply with option 14 carrying both IAs gives
// the lease and the temporary address with no Request, and one without the
// IA_TA keeps the IA_NA (claymore666/docker-net-dhcp#927).
func TestTemporaryWithRapidCommit(t *testing.T) {
	p := ta6Params(true)
	p.RapidCommit = true
	for _, withTemp := range []bool{true, false} {
		m, sol := solicit6(t, p)
		if _, tas := ta6IAs(t, sol); len(tas) != 1 {
			t.Fatalf("the rapid Solicit carries %d IA_TA", len(tas))
		}
		extra := []wire.OptionV6{wire.RapidCommitOption()}
		if withTemp {
			extra = append(extra, ta6Temps(t, ta6Temp))
		}
		_, acts := m.Step(at(2), 0, ta6Reply(t, sol.XID, extra...))
		if hasSendV6(acts, wire.MsgRequest6) {
			t.Error("a Request followed a Reply with Rapid Commit")
		}
		for _, a := range ta6Targets(acts) {
			m.Step(at(3), 0, DADResult(a, false))
		}
		l, held := m.Lease()
		if m.State() != State6Bound || !held || len(l.Addrs) != 1 || (len(l.TempAddrs) == 1) != withTemp {
			t.Errorf("with IA_TA %t: state %s lease %v", withTemp, m.State(), l)
		}
		if withTemp {
			ta6Counters(t, m, Temporary6Counters{Granted: 1})
		} else {
			ta6Counters(t, m, Temporary6Counters{Absent: 1})
		}
	}
}

// TestTemporaryLeaseReplaysFromTheJournal: replay re-decodes the Reply and
// reaches the same lease, both slices included, and the same counters; a
// client that never asked does not reproduce it (claymore666/docker-net-dhcp#927).
func TestTemporaryLeaseReplaysFromTheJournal(t *testing.T) {
	p := ta6Params(true)
	m := newMachine6(t, p)
	var entries []JournalEntry6
	step := func(now Instant, rnd uint64, ev Event) (State6, []Action) {
		from := m.State()
		to, acts := m.Step(now, rnd, ev)
		entries = append(entries, NewJournalEntry6(uint64(len(entries)), now, rnd, ev, from, to, acts))
		return to, acts
	}
	step(at(0), 0, Simple(EvStart))
	step(at(1), capXIDSolicit, TimerFired(Timer6Delay))
	_, acts := step(at(2), capXIDRequest, ta6Advert(t, uint32(capXIDSolicit), ta6Temps(t, ta6Temp)))
	req := mustSendV6(t, acts, wire.MsgRequest6)
	_, acts = step(at(3), 0, ta6Reply(t, req.XID, ta6Temps(t, ta6Temp)))
	for _, a := range ta6Targets(acts) {
		step(at(4), 0, DADResult(a, false))
	}
	if m.State() != State6Bound {
		t.Fatalf("the recorded run is in %s", m.State())
	}
	live, _ := m.Lease()
	res, err := Replay6(p, entries)
	if err != nil {
		t.Fatalf("Replay6: %v", err)
	}
	if res.State != State6Bound || !res.Held || len(res.Lease.TempAddrs) != 1 || res.Lease.TempAddrs[0] != live.TempAddrs[0] ||
		len(res.Lease.Addrs) != 1 || res.Lease.Addrs[0] != live.Addrs[0] || !res.Lease.Equal(live) {
		t.Errorf("replay: state %s lease %v, recorded %v", res.State, res.Lease, live)
	}
	if _, err := Replay6(ta6Params(false), entries); err == nil {
		t.Error("the journal replayed against a client that never asked for temporary addresses")
	}
}
