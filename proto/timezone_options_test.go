// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// TestTheOROAsksForTheTimezoneOptions reads option 6 from the encoded Solicit,
// Information-request and Renew and looks for the RFC 4833 section 3 numbers 41
// and 42 after 23, 24 and 17 (claymore666/docker-net-dhcp#1033): the
// Information-request is the message a stateless network sees.
func TestTheOROAsksForTheTimezoneOptions(t *testing.T) {
	want := []wire.OptionCodeV6{23, 24, 17, 41, 42}
	p := testParams6()
	m, sol := solicit6(t, p)
	assertOROOrder(t, sol, "Solicit", want)

	_, acts := m.Step(at(2), 3, RouterAdvertRaw(mustRA(t, raOtherOnly), raOtherOnly))
	assertOROOrder(t, mustSendV6(t, acts, wire.MsgInformationRequest), "Information-request", want)

	b := bind6(t, p, dnsmasqLeasedAddr)
	_, acts = b.Step(at(200), 7, TimerFired(Timer6Renew))
	assertOROOrder(t, mustSendV6(t, acts, wire.MsgRenew), "Renew", want)
}

func assertOROOrder(t *testing.T, msg *wire.MessageV6, what string, want []wire.OptionCodeV6) {
	t.Helper()
	assertORO(t, msg, what, want)
	v, _ := msg.Options.First(wire.OptV6ORO)
	got := decodeORO(v)
	last := -1
	for _, c := range want {
		idx := -1
		for i, g := range got {
			if g == c {
				idx = i
			}
		}
		if idx <= last {
			t.Errorf("the %s's ORO %v does not list %v in that order", what, got, want)
			return
		}
		last = idx
	}
}

// TestAV6ServerThatGatesTheTimezoneOptionsOnTheORODeliversThem is the reason
// 41 and 42 are in DefaultORO at all (claymore666/docker-net-dhcp#1033): this
// server sends each only when the Request's ORO asked for that code, so dropping
// either turns the lease's value into nothing.
func TestAV6ServerThatGatesTheTimezoneOptionsOnTheORODeliversThem(t *testing.T) {
	const posix, tzdb = "EST5EDT4,M3.2.0/02:00,M11.1.0/02:00", "Europe/Zurich"
	p := testParams6()
	m, _ := solicit6(t, p)
	_, acts := m.Step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255))
	req := mustSendV6(t, acts, wire.MsgRequest6)
	oro, _ := req.Options.First(wire.OptV6ORO)
	asked := decodeORO(oro)
	opts := []wire.OptionV6{
		optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 150, 240, []iaAddrSpec{{dnsmasqLeasedAddr, 300, 300}}),
	}
	if containsCode(asked, 41) {
		opts = append(opts, wire.OptionV6{Code: 41, Data: []byte(posix)})
	}
	if containsCode(asked, 42) {
		opts = append(opts, wire.OptionV6{Code: 42, Data: []byte(tzdb)})
	}
	m.Step(at(3), 0, receivedV6(t, wire.MsgReply, req.XID, opts...))
	m.Step(at(4), 0, DADResult(addr6(dnsmasqLeasedAddr), false))
	l, ok := m.Lease()
	if !ok {
		t.Fatalf("no lease; state %s", m.State())
	}
	if v, ok := l.Options.First(41); !ok || string(v) != posix {
		t.Errorf("the lease's option 41 = %q, %v; want %q", v, ok, posix)
	}
	if v, ok := l.Options.First(42); !ok || string(v) != tzdb {
		t.Errorf("the lease's option 42 = %q, %v; want %q", v, ok, tzdb)
	}
}
