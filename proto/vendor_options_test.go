// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

func asksFor(list []byte, c wire.OptionCode) bool {
	for _, b := range list {
		if wire.OptionCode(b) == c {
			return true
		}
	}
	return false
}

// TestParameterListEndsWithTheVendorOptions reads option 55 from the ENCODED
// Discover, as the RFC 3442 order test does (claymore666/docker-net-dhcp#1034):
// 43 and 125 close the list, after the WPAD entry the list ended with before.
func TestParameterListEndsWithTheVendorOptions(t *testing.T) {
	m := newMachine(t, testParams())
	_, acts := m.Step(at(0), 1, Simple(EvStart))
	pl := mustSend(t, acts, wire.MsgDiscover).Options[wire.OptParameterList]
	if len(pl) < 3 {
		t.Fatalf("parameter request list %v is too short", pl)
	}
	tail := pl[len(pl)-3:]
	if wire.OptionCode(tail[0]) != wire.OptWPAD || wire.OptionCode(tail[1]) != wire.OptVendorSpecific || wire.OptionCode(tail[2]) != wire.OptVIVSO {
		t.Fatalf("the list ends %v, want 252, 43, 125\nlist: %v", tail, pl)
	}
}

// TestAServerThatGatesVendorOptionsOnTheRequestListDeliversThem is the reason
// 43 and 125 are in the list at all (claymore666/docker-net-dhcp#1034): this
// server sends each only when the REQUEST asked for it, so dropping a code from
// DefaultParameterList turns the lease's accessor from a block into nothing.
func TestAServerThatGatesVendorOptionsOnTheRequestListDeliversThem(t *testing.T) {
	m := newMachine(t, testParams())
	_, acts := m.Step(at(0), 1, Simple(EvStart))
	disc := mustSend(t, acts, wire.MsgDiscover)
	_, acts = m.Step(at(1), 2, received(t, offerFor(disc, testLeaseAddr, testServerID)))
	req := mustSend(t, acts, wire.MsgRequest)
	ack := ackFor(req, testLeaseAddr, testServerID, 3600)
	pl := req.Options[wire.OptParameterList]
	if asksFor(pl, wire.OptVendorSpecific) {
		ack.Options[wire.OptVendorSpecific] = []byte{0x01, 0x02}
	}
	if asksFor(pl, wire.OptVIVSO) {
		ack.Options[wire.OptVIVSO] = []byte{0, 0, 0x01, 0x7f, 2, 'o', 'k'}
	}
	if _, acts = m.Step(at(2), 3, received(t, ack)); m.State() != StateBound {
		t.Fatalf("fixture did not reach BOUND: %s\n%v", m.State(), RenderActions(acts))
	}
	opts := m.lease.Options
	if v, ok := opts.VendorSpecific(); !ok || string(v) != "\x01\x02" {
		t.Errorf("the lease's option 43 = %x, %v", v, ok)
	}
	blocks, err := opts.VendorIdentifying()
	if err != nil || len(blocks) != 1 || blocks[0].Enterprise != 383 || string(blocks[0].Data) != "ok" {
		t.Errorf("the lease's option 125 = %+v, %v", blocks, err)
	}
}

// TestTheOROAsksForTheVendorOptions reads option 6 from the encoded Solicit,
// Information-request and Renew (claymore666/docker-net-dhcp#1034): the
// machine adds Params6.ORO to every message type, and DefaultORO now carries 17.
func TestTheOROAsksForTheVendorOptions(t *testing.T) {
	p := testParams6()
	m, sol := solicit6(t, p)
	assertORO(t, sol, "Solicit", []wire.OptionCodeV6{wire.OptV6VendorOpts})

	_, acts := m.Step(at(2), 3, RouterAdvertRaw(mustRA(t, raOtherOnly), raOtherOnly))
	assertORO(t, mustSendV6(t, acts, wire.MsgInformationRequest), "Information-request", []wire.OptionCodeV6{wire.OptV6VendorOpts})

	b := bind6(t, p, dnsmasqLeasedAddr)
	_, acts = b.Step(at(200), 7, TimerFired(Timer6Renew))
	assertORO(t, mustSendV6(t, acts, wire.MsgRenew), "Renew", []wire.OptionCodeV6{wire.OptV6VendorOpts})
}

// TestAV6ServerThatGatesOptionSeventeenOnTheORODeliversIt is the v6 half of
// the gate above (claymore666/docker-net-dhcp#1034): the Reply carries option 17
// only when the Request's ORO asked for it.
func TestAV6ServerThatGatesOptionSeventeenOnTheORODeliversIt(t *testing.T) {
	p := testParams6()
	m, _ := solicit6(t, p)
	_, acts := m.Step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255))
	req := mustSendV6(t, acts, wire.MsgRequest6)
	oro, _ := req.Options.First(wire.OptV6ORO)
	opts := []wire.OptionV6{
		optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 150, 240, []iaAddrSpec{{dnsmasqLeasedAddr, 300, 300}}),
	}
	if containsCode(decodeORO(oro), wire.OptV6VendorOpts) {
		opts = append(opts, wire.OptionV6{Code: wire.OptV6VendorOpts, Data: []byte{0, 0, 0x01, 0x7f, 0xaa}})
	}
	m.Step(at(3), 0, receivedV6(t, wire.MsgReply, req.XID, opts...))
	m.Step(at(4), 0, DADResult(addr6(dnsmasqLeasedAddr), false))
	l, ok := m.Lease()
	if !ok {
		t.Fatalf("no lease; state %s", m.State())
	}
	blocks, err := l.Options.VendorOpts()
	if err != nil || len(blocks) != 1 || blocks[0].Enterprise != 383 || string(blocks[0].Data) != "\xaa" {
		t.Fatalf("the lease's option 17 = %+v, %v", blocks, err)
	}
}
