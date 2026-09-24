// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// fqdnOf is option 39 as the server would decode it, and whether the ORO
// asked for it.
func fqdnOf(t *testing.T, msg *wire.MessageV6) (wire.ClientFQDN, bool, bool) {
	t.Helper()
	f, ok, err := msg.Options.ClientFQDN()
	if err != nil {
		t.Fatalf("the %s carries an option 39 that does not decode: %v", msg.Type, err)
	}
	oro, _ := msg.Options.First(wire.OptV6ORO)
	return f, ok, containsCode(decodeORO(oro), wire.OptV6ClientFQDN)
}

// sends counts the messages among acts.
func sends(acts []Action) int {
	n := 0
	for _, a := range acts {
		if a.Kind == ActSendV6 {
			n++
		}
	}
	return n
}

func assertCarriesName(t *testing.T, msg *wire.MessageV6, name string) {
	t.Helper()
	f, ok, asked := fqdnOf(t, msg)
	if !ok || f.Name != name {
		t.Fatalf("the %s carries option 39 %v %+v, want the name %q", msg.Type, ok, f, name)
	}
	if f.Flags != wire.ClientFQDNFlagS {
		t.Fatalf("the %s sets flags %#02x, want S=1 O=0 N=0 (RFC 4704 section 5.2)", msg.Type, f.Flags)
	}
	if !asked {
		t.Fatalf("the %s sends option 39 without asking for it in the ORO (RFC 4704 section 5)", msg.Type)
	}
}

func assertCarriesNoName(t *testing.T, msg *wire.MessageV6) {
	t.Helper()
	if f, ok, asked := fqdnOf(t, msg); ok || asked {
		t.Fatalf("the %s carries option 39 %+v (present %v, in the ORO %v), want neither", msg.Type, f, ok, asked)
	}
}

// TestAV6NameAtStartRidesSolicitRequestRenewAndRebind: Params6.Hostname goes
// in the four messages RFC 4704 section 5 allows, S=1, with 39 in the ORO.
func TestAV6NameAtStartRidesSolicitRequestRenewAndRebind(t *testing.T) {
	p := testParams6()
	p.Hostname = "host.example."
	m, sol := solicit6(t, p)
	assertCarriesName(t, sol, "host.example.")
	_, acts := m.Step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255))
	req := mustSendV6(t, acts, wire.MsgRequest6)
	assertCarriesName(t, req, "host.example.")
	m.Step(at(3), 0, reply(t, req.XID, dnsmasqLeasedAddr))
	if s, acts := m.Step(at(4), 0, DADResult(addr6(dnsmasqLeasedAddr), false)); s != State6Bound || hasSendV6(acts, wire.MsgRenew) {
		t.Fatalf("the bind left %s and sent a Renew %v; the Request already carried the name", s, hasSendV6(acts, wire.MsgRenew))
	}
	_, acts = m.Step(at(150), 7, TimerFired(Timer6Renew))
	assertCarriesName(t, mustSendV6(t, acts, wire.MsgRenew), "host.example.")
	_, acts = m.Step(at(240), 8, TimerFired(Timer6Rebind))
	assertCarriesName(t, mustSendV6(t, acts, wire.MsgRebind), "host.example.")
	if m.Hostname() != "host.example." {
		t.Fatalf("Hostname() = %q", m.Hostname())
	}
}

// TestAV6ClientWithNoNameSendsNoOption39: no name, no option and no ORO entry
// in any of the four messages. An empty option 39 would ask the server to
// pick a name (RFC 4704 section 4.2), which nobody asked for.
func TestAV6ClientWithNoNameSendsNoOption39(t *testing.T) {
	m, sol := solicit6(t, testParams6())
	assertCarriesNoName(t, sol)
	_, acts := m.Step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255))
	req := mustSendV6(t, acts, wire.MsgRequest6)
	assertCarriesNoName(t, req)
	m.Step(at(3), 0, reply(t, req.XID, dnsmasqLeasedAddr))
	m.Step(at(4), 0, DADResult(addr6(dnsmasqLeasedAddr), false))
	_, acts = m.Step(at(150), 7, TimerFired(Timer6Renew))
	assertCarriesNoName(t, mustSendV6(t, acts, wire.MsgRenew))
	_, acts = m.Step(at(240), 8, TimerFired(Timer6Rebind))
	assertCarriesNoName(t, mustSendV6(t, acts, wire.MsgRebind))
}

// TestOption39StaysOutOfEveryOtherV6Message: RFC 4704 section 5, "A client
// MUST only include the Client FQDN option in SOLICIT, REQUEST, RENEW, or
// REBIND messages", so a named client's Confirm, Decline, Release and
// Information-request carry none.
func TestOption39StaysOutOfEveryOtherV6Message(t *testing.T) {
	p := testParams6()
	p.Hostname = "host"

	_, acts := confirming6(t, p)
	assertCarriesNoName(t, mustSendV6(t, acts, wire.MsgConfirm))

	m := bind6(t, p, dnsmasqLeasedAddr)
	_, acts = m.Step(at(100), 3, Simple(EvAddressLost))
	assertCarriesNoName(t, mustSendV6(t, acts, wire.MsgDecline6))

	m = bind6(t, p, dnsmasqLeasedAddr)
	_, acts = m.Step(at(100), 3, Simple(EvRelease))
	assertCarriesNoName(t, mustSendV6(t, acts, wire.MsgRelease6))

	m, _ = solicit6(t, p)
	_, acts = m.Step(at(2), 3, RouterAdvertRaw(mustRA(t, raOtherOnly), raOtherOnly))
	assertCarriesNoName(t, mustSendV6(t, acts, wire.MsgInformationRequest))
}

// TestAV6NameSetWhileBoundIsSentInAnEarlyRenew is #961's rule on v6: the name
// reaches the server in one exchange, not at T1. The same name again, and an
// empty name, send nothing; the next Renew after clearing carries no option.
func TestAV6NameSetWhileBoundIsSentInAnEarlyRenew(t *testing.T) {
	m := bind6(t, testParams6(), dnsmasqLeasedAddr)
	s, acts := m.Step(at(10), 5, SetHostname("late"))
	if s != State6Renewing {
		t.Fatalf("a name set in BOUND6 left the machine in %s, want %s", s, State6Renewing)
	}
	ren := mustSendV6(t, acts, wire.MsgRenew)
	assertCarriesName(t, ren, "late")
	if s, _ := m.Step(at(11), 0, reply(t, ren.XID, dnsmasqLeasedAddr)); s != State6Bound {
		t.Fatalf("the early Renew's Reply left the machine in %s", s)
	}
	for _, name := range []string{"late", ""} {
		s, acts := m.Step(at(12), 6, SetHostname(name))
		if s != State6Bound || sends(acts) != 0 {
			t.Fatalf("SetHostname(%q) sent %d message(s) and left %s; the server needs no message", name, sends(acts), s)
		}
		if !journalHas(acts, "no message was sent") {
			t.Fatalf("SetHostname(%q) was not journalled:%s", name, journalLines(acts))
		}
	}
	_, acts = m.Step(at(160), 7, TimerFired(Timer6Renew))
	assertCarriesNoName(t, mustSendV6(t, acts, wire.MsgRenew))
}

// TestAV6NameSetDuringARenewalStartsANewExchange: RFC 9915 section 16.1 keeps
// the transaction ID only for "retransmissions of a message", so a Renew or
// Rebind carrying a new name is a new exchange, and the old one's Reply is
// not taken.
func TestAV6NameSetDuringARenewalStartsANewExchange(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state State6
		typ   wire.MessageTypeV6
	}{
		{"renewing", State6Renewing, wire.MsgRenew},
		{"rebinding", State6Rebinding, wire.MsgRebind},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := bind6(t, testParams6(), dnsmasqLeasedAddr)
			_, acts := m.Step(at(150), 0x111111, TimerFired(Timer6Renew))
			old := mustSendV6(t, acts, wire.MsgRenew)
			if tc.state == State6Rebinding {
				_, acts = m.Step(at(240), 0x111111, TimerFired(Timer6Rebind))
				old = mustSendV6(t, acts, wire.MsgRebind)
			}
			s, acts := m.Step(at(241), 0x222222, SetHostname("mid"))
			if s != tc.state {
				t.Fatalf("the name left the machine in %s, want %s", s, tc.state)
			}
			fresh := mustSendV6(t, acts, tc.typ)
			assertCarriesName(t, fresh, "mid")
			if fresh.XID == old.XID {
				t.Fatalf("the %s with the new name reuses transaction ID %06x", tc.typ, old.XID)
			}
			if s, _ := m.Step(at(242), 0, reply(t, old.XID, dnsmasqLeasedAddr)); s != tc.state {
				t.Fatalf("a Reply to the replaced exchange left the machine in %s", s)
			}
			if s, _ := m.Step(at(243), 0, reply(t, fresh.XID, dnsmasqLeasedAddr)); s != State6Bound {
				t.Fatalf("the Reply to the new exchange left the machine in %s", s)
			}
		})
	}
}

// TestAV6NameSetBeforeTheBindReachesTheServerAtTheBind: a retransmission stays
// the message it was (RFC 9915 section 16.1); a name set while selecting rides
// the Request, and one set while requesting rides an early Renew at the bind.
func TestAV6NameSetBeforeTheBindReachesTheServerAtTheBind(t *testing.T) {
	m, _ := solicit6(t, testParams6())
	m.Step(at(1), 0, SetHostname("early"))
	_, acts := m.Step(at(2), 4, TimerFired(Timer6Retransmit))
	assertCarriesNoName(t, mustSendV6(t, acts, wire.MsgSolicit))
	_, acts = m.Step(at(3), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255))
	req := mustSendV6(t, acts, wire.MsgRequest6)
	assertCarriesName(t, req, "early")
	m.Step(at(4), 0, reply(t, req.XID, dnsmasqLeasedAddr))
	if s, acts := m.Step(at(5), 0, DADResult(addr6(dnsmasqLeasedAddr), false)); s != State6Bound || hasSendV6(acts, wire.MsgRenew) {
		t.Fatalf("the bind left %s with a Renew %v; the Request carried the name", s, hasSendV6(acts, wire.MsgRenew))
	}

	// A name replaced mid-exchange: the retransmission keeps the first one.
	p := testParams6()
	p.Hostname = "first"
	m, _ = solicit6(t, p)
	m.Step(at(1), 0, SetHostname("second"))
	_, acts = m.Step(at(2), 4, TimerFired(Timer6Retransmit))
	assertCarriesName(t, mustSendV6(t, acts, wire.MsgSolicit), "first")
	_, acts = m.Step(at(3), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255))
	assertCarriesName(t, mustSendV6(t, acts, wire.MsgRequest6), "second")

	m, _ = solicit6(t, testParams6())
	_, acts = m.Step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255))
	req = mustSendV6(t, acts, wire.MsgRequest6)
	m.Step(at(3), 0, SetHostname("late"))
	_, acts = m.Step(at(4), 4, TimerFired(Timer6Retransmit))
	assertCarriesNoName(t, mustSendV6(t, acts, wire.MsgRequest6))
	m.Step(at(5), 0, reply(t, req.XID, dnsmasqLeasedAddr))
	s, acts := m.Step(at(6), 9, DADResult(addr6(dnsmasqLeasedAddr), false))
	if s != State6Renewing {
		t.Fatalf("the bind left the machine in %s, want an early Renew", s)
	}
	if _, ok := find(acts, ActLeaseAcquired); !ok {
		t.Fatal("the bind did not report the lease before renewing")
	}
	assertCarriesName(t, mustSendV6(t, acts, wire.MsgRenew), "late")
}

// TestAResumedV6ClientSendsItsNameInOneRenewAfterTheBind: a Confirm cannot
// carry option 39, so a restarted client with a name renews once after the
// bind to send it (decision 2026-09-24, claymore666/docker-net-dhcp#1029).
func TestAResumedV6ClientSendsItsNameInOneRenewAfterTheBind(t *testing.T) {
	p := testParams6()
	p.Hostname = "host"
	m := confirmed6(t, p)
	s, acts := m.Step(at(3), 3, DADResult(addr6(dnsmasqLeasedAddr), false))
	if s != State6Renewing {
		t.Fatalf("the resumed bind left the machine in %s, want one Renew carrying the name", s)
	}
	ren := mustSendV6(t, acts, wire.MsgRenew)
	assertCarriesName(t, ren, "host")
	if s, acts := m.Step(at(4), 0, reply(t, ren.XID, dnsmasqLeasedAddr)); s != State6Bound || sends(acts) != 0 {
		t.Fatalf("the Renew's Reply left %s with %d send(s); one Renew is the whole cost", s, sends(acts))
	}
}

// TestTheServersOption39IsReportedAndAMalformedOneIsANote: RFC 4704 section 6
// has the server return the flags it applied. They are journalled from the
// Advertise and carried on the lease from the Reply, O included; a malformed
// option is a journal note and the lease stands.
func TestTheServersOption39IsReportedAndAMalformedOneIsANote(t *testing.T) {
	p := testParams6()
	p.Hostname = "host"
	m, _ := solicit6(t, p)
	srvFQDN := wire.OptionV6{Code: wire.OptV6ClientFQDN, Data: mustHexBytes("0604686f7374076578616d706c6500")}
	_, acts := m.Step(at(2), capXIDRequest, receivedV6(t, wire.MsgAdvertise, uint32(capXIDSolicit),
		optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 150, 240, []iaAddrSpec{{dnsmasqLeasedAddr, 300, 300}}),
		optPreference(255), srvFQDN))
	if !journalHas(acts, `S=0 O=1 N=1 name "host.example."`) {
		t.Fatalf("the Advertise's option 39 was not reported:%s", journalLines(acts))
	}
	req := mustSendV6(t, acts, wire.MsgRequest6)
	m.Step(at(3), 0, receivedV6(t, wire.MsgReply, req.XID,
		optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 150, 240, []iaAddrSpec{{dnsmasqLeasedAddr, 300, 300}}), srvFQDN))
	_, acts = m.Step(at(4), 0, DADResult(addr6(dnsmasqLeasedAddr), false))
	acq, ok := find(acts, ActLeaseAcquired)
	if !ok || !acq.Lease6.HasFQDN || acq.Lease6.FQDN.Flags != wire.ClientFQDNFlagN|wire.ClientFQDNFlagO || acq.Lease6.FQDN.Name != "host.example." {
		t.Fatalf("the acquired lease reports %v %+v, want the server's N|O and host.example.", acq.Lease6.HasFQDN, acq.Lease6.FQDN)
	}

	_, acts = m.Step(at(150), 7, TimerFired(Timer6Renew))
	ren := mustSendV6(t, acts, wire.MsgRenew)
	s, acts := m.Step(at(151), 0, receivedV6(t, wire.MsgReply, ren.XID,
		optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 150, 240, []iaAddrSpec{{dnsmasqLeasedAddr, 300, 300}}),
		wire.OptionV6{Code: wire.OptV6ClientFQDN, Data: mustHexBytes("01c00c")}))
	renewed, ok := find(acts, ActLeaseRenewed)
	if s != State6Bound || !ok || renewed.Lease6.HasFQDN {
		t.Fatalf("a malformed option 39 left %s, renewed %v, reported %v; want the lease kept without it", s, ok, renewed.Lease6.HasFQDN)
	}
	if !journalHas(acts, "Client FQDN option:") {
		t.Fatalf("the malformed option 39 was not noted:%s", journalLines(acts))
	}
}

// TestAV6NameTheOptionCannotCarryIsRefusedAndTheOldOneKept: the event is
// journalled and changes nothing, and New6 refuses the same name.
func TestAV6NameTheOptionCannotCarryIsRefusedAndTheOldOneKept(t *testing.T) {
	p := testParams6()
	p.Hostname = "host"
	m := bind6(t, p, dnsmasqLeasedAddr)
	bad := strings.Repeat("a", 64)
	s, acts := m.Step(at(10), 5, SetHostname(bad))
	if s != State6Bound || sends(acts) != 0 || m.Hostname() != "host" {
		t.Fatalf("a 64-octet label left %s, %d send(s), name %q", s, sends(acts), m.Hostname())
	}
	if !journalHas(acts, "hostname refused") {
		t.Fatalf("the refusal was not journalled:%s", journalLines(acts))
	}
	p.Hostname = bad
	if _, err := New6(p); err == nil {
		t.Fatal("New6 accepted a name the running client refuses")
	}
}

// TestAV6NameOnAFormedAddressSendsNothing: a formed address comes from a
// Router Advertisement (RFC 4862 section 5.5.3), not from a server, so there is
// no Renew to carry the name and it is recorded only.
func TestAV6NameOnAFormedAddressSendsNothing(t *testing.T) {
	m := slaacBound6(t, testParams6SLAAC(), 3600, 1800)
	s, acts := m.Step(at(10), 5, SetHostname("host"))
	if s != State6Bound || sends(acts) != 0 || m.Hostname() != "host" {
		t.Fatalf("a name on a formed address left %s, %d send(s), name %q", s, sends(acts), m.Hostname())
	}
}

// TestReplay6ReproducesARunWhoseNameChanged: the journal records the name
// with the event, so the replay of the stored journal sends what the run sent.
func TestReplay6ReproducesARunWhoseNameChanged(t *testing.T) {
	p := testParams6()
	r := newRecord6(t, p)
	r.step(at(0), 0, Simple(EvStart))
	r.step(at(1), capXIDSolicit, TimerFired(Timer6Delay))
	_, acts := r.step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255))
	req := mustSendV6(t, acts, wire.MsgRequest6)
	r.step(at(3), 0, reply(t, req.XID, dnsmasqLeasedAddr))
	r.step(at(4), 0, DADResult(addr6(dnsmasqLeasedAddr), false))
	if s, _ := r.step(at(5), 5, SetHostname("renamed")); s != State6Renewing {
		t.Fatalf("the recorded run did not renew for the name: %s", s)
	}
	raw, err := json.Marshal(r.entries)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back []JournalEntry6
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	res, err := Replay6(p, back)
	if err != nil {
		t.Fatalf("Replay6: %v", err)
	}
	if res.Steps != len(r.entries) || res.State != State6Renewing {
		t.Fatalf("the replay ended in %s, want %s", res.State, State6Renewing)
	}
}

// TestAV6NameSetDuringAReconfiguresInformationRequestGoesOutAtItsReply: an
// Information-request cannot carry option 39 (RFC 4704 section 5), so the
// name waits for the Reply that returns the machine to BOUND6 and then goes
// out in an early Renew.
func TestAV6NameSetDuringAReconfiguresInformationRequestGoesOutAtItsReply(t *testing.T) {
	m := bindWithKey6(t, testParams6(), dnsmasqLeasedAddr, testReconfKey)
	s, acts := m.Step(at(10), 7, goodReconfigure(t, wire.MsgInformationRequest, 1))
	if s != State6InfoRequesting {
		t.Fatalf("the Reconfigure left the machine in %s%s", s, journalLines(acts))
	}
	inf := mustSendV6(t, acts, wire.MsgInformationRequest)
	if s, acts := m.Step(at(11), 8, SetHostname("reconf")); s != State6InfoRequesting || sends(acts) != 0 {
		t.Fatalf("a name set during the Information-request left %s with %d send(s)", s, sends(acts))
	}
	s, acts = m.Step(at(12), 9, receivedV6(t, wire.MsgReply, inf.XID,
		optClientID(capDUID), optServerID(testServerDUID), optU32(wire.OptV6InfoRefresh, 3600)))
	if s != State6Renewing {
		t.Fatalf("the Information-request's Reply left the machine in %s, want an early Renew%s", s, journalLines(acts))
	}
	assertCarriesName(t, mustSendV6(t, acts, wire.MsgRenew), "reconf")
}
