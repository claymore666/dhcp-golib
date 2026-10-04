// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"encoding/hex"
	"net/netip"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// release6Plain and release6PD are the Releases a client with no temporary
// address sent at 57a2f2e, before the Release carried an IA_TA: a bound client
// with the stable address alone, and one that also holds a prefix, both from
// Step(at(10), 9, EvRelease) (dhcp-golib#60).
const (
	release6Plain = "080000090001000a00030001ea494ee531ed0002000e00010001322ecbbfea494ee531ed000300280a0b0c0d000000000000000000050018fd0000990000000000000000000001830000012c0000012c0006000c0017001800110029002a0038000800020000"
	release6PD    = "080000090001000a00030001ea494ee531ed0002000e00010001322ecbbfea494ee531ed000300280a0b0c0d000000000000000000050018fd0000990000000000000000000001830000012c0000012c001900290a0b0c0d0000000000000000001a00190000012c000002584020010db80001010000000000000000000006000c0017001800110029002a0038000800020000"
)

func release6Bytes(t *testing.T, m *Machine6) []byte {
	t.Helper()
	_, acts := m.Step(at(10), 9, Simple(EvRelease))
	raw, err := wire.EncodeV6(mustSendV6(t, acts, wire.MsgRelease6))
	if err != nil {
		t.Fatalf("EncodeV6: %v", err)
	}
	return raw
}

// release6TA drives a client with Params6.Temporary, and a prefix when pd is
// set, to BOUND holding the stable address and the given temporary ones.
func release6TA(t *testing.T, pd bool, temps ...string) *Machine6 {
	t.Helper()
	p := ta6Params(true)
	var extra []wire.OptionV6
	if pd {
		p.PrefixHint = 64
		extra = append(extra, pd6Good(t))
	}
	m, sol := solicit6(t, p)
	_, acts := m.Step(at(2), capXIDRequest, pd6Advert(t, sol.XID, append(extra, ta6Temps(t, temps...))...))
	req := mustSendV6(t, acts, wire.MsgRequest6)
	var specs []iaAddrSpec
	for _, a := range temps {
		specs = append(specs, iaAddrSpec{a, 200, 1000})
	}
	_, acts = m.Step(at(3), 0, pd6Reply(t, req.XID, append(extra, optIATA(t, capIAID, specs))...))
	for _, a := range ta6Targets(acts) {
		m.Step(at(4), 0, DADResult(a, false))
	}
	if m.State() != State6Bound {
		t.Fatalf("the exchange left the machine in %s, want %s", m.State(), State6Bound)
	}
	return m
}

// TestMachineReleaseWithNoTemporaryAddressIsTheDatagramOfBefore pins the bytes
// of a Release that holds no temporary address to the ones sent before the
// IA_TA was added (dhcp-golib#60).
func TestMachineReleaseWithNoTemporaryAddressIsTheDatagramOfBefore(t *testing.T) {
	cases := []struct {
		name string
		m    *Machine6
		want string
	}{
		{"stable address only", bind6(t, testParams6(), dnsmasqLeasedAddr), release6Plain},
		{"stable address and a prefix", pd6Bound(t, pd6Params(64)), release6PD},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hex.EncodeToString(release6Bytes(t, c.m)); got != c.want {
				t.Errorf("the Release is\n%s\nwant\n%s", got, c.want)
			}
		})
	}
	// Params6.Temporary with nothing granted holds no temporary address either.
	m := release6TA(t, false)
	_, acts := m.Step(at(10), 9, Simple(EvRelease))
	if _, tas := ta6IAs(t, mustSendV6(t, acts, wire.MsgRelease6)); len(tas) != 0 {
		t.Errorf("the Release of a client holding no temporary address carries %d IA_TA", len(tas))
	}
}

// TestMachineReleaseNamesEveryTemporaryAddressInAnIATAWithZeroLifetimes: one
// IA_TA with the client's IAID and one IA Address per temporary address held,
// preferred and valid lifetimes zero (RFC 8415 section 18.2.7, dhcp-golib#60).
func TestMachineReleaseNamesEveryTemporaryAddressInAnIATAWithZeroLifetimes(t *testing.T) {
	m := release6TA(t, false, ta6Temp, ta6Temp2)
	_, acts := m.Step(at(10), 9, Simple(EvRelease))
	nas, tas := ta6IAs(t, mustSendV6(t, acts, wire.MsgRelease6))
	if len(nas) != 1 || len(tas) != 1 {
		t.Fatalf("the Release carries %d IA_NA and %d IA_TA, want one of each", len(nas), len(tas))
	}
	if tas[0].IAID != capIAID || nas[0].IAID != capIAID {
		t.Errorf("IA_TA IAID %#x, IA_NA IAID %#x, want both %#x", tas[0].IAID, nas[0].IAID, capIAID)
	}
	got := ta6AddrsOf(t, tas[0].Options)
	if len(got) != 2 || got[0].Addr != addr6(ta6Temp) || got[1].Addr != addr6(ta6Temp2) {
		t.Fatalf("the Release's IA_TA = %+v, want %s and %s", got, ta6Temp, ta6Temp2)
	}
	for _, a := range got {
		if a.PreferredLifetime != 0 || a.ValidLifetime != 0 {
			t.Errorf("%s carries lifetimes %d and %d, want 0 and 0", a.Addr, a.PreferredLifetime, a.ValidLifetime)
		}
	}
}

// TestMachineReleaseOrdersTheIAsNAThenTAThenPD: the machine's Release puts
// the IA_TA between the IA_NA and the IA_PD, as the record path's Release does
// (dhcp-golib#60).
func TestMachineReleaseOrdersTheIAsNAThenTAThenPD(t *testing.T) {
	m := release6TA(t, true, ta6Temp)
	_, acts := m.Step(at(10), 9, Simple(EvRelease))
	rel := ta6OnTheWire(t, mustSendV6(t, acts, wire.MsgRelease6))
	var got []uint16
	for _, o := range rel.Options {
		switch o.Code {
		case wire.OptV6ClientID, wire.OptV6ServerID, wire.OptV6IANA, wire.OptV6IATA, wire.OptV6IAPD, wire.OptV6ElapsedTime:
			got = append(got, uint16(o.Code))
		}
	}
	want := []uint16{
		uint16(wire.OptV6ClientID), uint16(wire.OptV6ServerID), uint16(wire.OptV6IANA),
		uint16(wire.OptV6IATA), uint16(wire.OptV6IAPD), uint16(wire.OptV6ElapsedTime),
	}
	if len(got) != len(want) {
		t.Fatalf("option order %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("option order %v, want %v", got, want)
		}
	}
	pds, err := rel.Options.IAPDs()
	if err != nil || len(pds) != 1 {
		t.Errorf("the Release carries %d IA_PD (%v), want the prefix too", len(pds), err)
	}
}

// TestMachineReleaseLeavesOutATemporaryAddressThatCannotBeOnTheWire: an entry
// the wire cannot carry is skipped and the Release goes on, and none usable
// means no IA_TA at all, the datagram of before (dhcp-golib#60).
func TestMachineReleaseLeavesOutATemporaryAddressThatCannotBeOnTheWire(t *testing.T) {
	bad := []Addr6{
		{Addr: netip.Addr{}},
		{Addr: netip.IPv6Unspecified()},
		{Addr: netip.MustParseAddr("::ffff:192.0.2.1")},
	}
	m := release6TA(t, false)
	m.lease.TempAddrs = bad
	if got := hex.EncodeToString(release6Bytes(t, m)); got != release6Plain {
		t.Errorf("the Release of a lease holding only unusable temporary addresses is\n%s\nwant\n%s", got, release6Plain)
	}

	m = release6TA(t, false)
	m.lease.TempAddrs = append(bad, Addr6{Addr: addr6(ta6Temp)})
	_, acts := m.Step(at(10), 9, Simple(EvRelease))
	_, tas := ta6IAs(t, mustSendV6(t, acts, wire.MsgRelease6))
	if len(tas) != 1 {
		t.Fatalf("the Release carries %d IA_TA, want 1", len(tas))
	}
	if got := ta6AddrsOf(t, tas[0].Options); len(got) != 1 || got[0].Addr != addr6(ta6Temp) {
		t.Errorf("the Release's IA_TA = %+v, want %s alone", got, ta6Temp)
	}
}
