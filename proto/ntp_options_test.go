// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// TestTheOROAsksForTheNTPServerOption reads option 6 from the encoded Solicit,
// Information-request and Renew and looks for the RFC 5908 section 4 number 56
// after 23, 24, 17, 41 and 42 (claymore666/docker-net-dhcp#859): the
// Information-request is the message a stateless network sees.
func TestTheOROAsksForTheNTPServerOption(t *testing.T) {
	want := []wire.OptionCodeV6{23, 24, 17, 41, 42, 56}
	p := testParams6()
	m, sol := solicit6(t, p)
	assertOROOrder(t, sol, "Solicit", want)

	_, acts := m.Step(at(2), 3, RouterAdvertRaw(mustRA(t, raOtherOnly), raOtherOnly))
	assertOROOrder(t, mustSendV6(t, acts, wire.MsgInformationRequest), "Information-request", want)

	b := bind6(t, p, dnsmasqLeasedAddr)
	_, acts = b.Step(at(200), 7, TimerFired(Timer6Renew))
	assertOROOrder(t, mustSendV6(t, acts, wire.MsgRenew), "Renew", want)
}

// TestAV6ServerThatGatesTheNTPOptionOnTheORODeliversTheList is the reason 56 is
// in DefaultORO at all (claymore666/docker-net-dhcp#859): this server sends its
// two instances only when the Request's ORO asked for 56, so dropping it turns
// the lease's list into nothing.
func TestAV6ServerThatGatesTheNTPOptionOnTheORODeliversTheList(t *testing.T) {
	p := testParams6()
	m, _ := solicit6(t, p)
	_, acts := m.Step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255))
	req := mustSendV6(t, acts, wire.MsgRequest6)
	oro, _ := req.Options.First(wire.OptV6ORO)
	opts := []wire.OptionV6{
		optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 150, 240, []iaAddrSpec{{dnsmasqLeasedAddr, 300, 300}}),
	}
	if containsCode(decodeORO(oro), 56) {
		opts = append(opts,
			wire.OptionV6{Code: 56, Data: ntpSub(1, []byte("\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x23"))},
			wire.OptionV6{Code: 56, Data: ntpSub(3, []byte("\x04time\x07example\x03org\x00"))},
		)
	}
	m.Step(at(3), 0, receivedV6(t, wire.MsgReply, req.XID, opts...))
	m.Step(at(4), 0, DADResult(addr6(dnsmasqLeasedAddr), false))
	l, ok := m.Lease()
	if !ok {
		t.Fatalf("no lease; state %s", m.State())
	}
	got, err := l.Options.NTPServers()
	if err != nil || len(got) != 2 || got[0].Addr.String() != "2001:db8::123" || got[1].FQDN != "time.example.org" {
		t.Errorf("the lease's NTP servers = %+v, %v; want the address and the name", got, err)
	}
}

// ntpSub is one option 56 sub-option: code, length, body
// (claymore666/docker-net-dhcp#859).
func ntpSub(code uint16, body []byte) []byte {
	return append([]byte{byte(code >> 8), byte(code), byte(len(body) >> 8), byte(len(body))}, body...)
}
