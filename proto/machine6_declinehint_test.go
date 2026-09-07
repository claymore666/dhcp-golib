// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"net/netip"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// The address the caller asks to keep, and a second one the server is free to
// offer instead. Neither is dnsmasqLeasedAddr, so a fixture that quietly fell
// back to the shared one is visible in the failure text.
const (
	hintedAddr    = "fd00:99::213"
	substituteAll = "fd00:99::214"
)

// solicitHintOf reads the IA Address a Solicit asks for, or the zero Addr when
// it asks for none.
//
// IT READS THE ENCODED MESSAGE and not Machine6.solicitHint, which is the
// whole difference between this file and a test of a getter: the defect being
// pinned is a MESSAGE that carries an address, and a machine that cleared its
// field and went on building the option from somewhere else would satisfy a
// field assertion exactly.
func solicitHintOf(t *testing.T, msg *wire.MessageV6) netip.Addr {
	t.Helper()
	if msg.Type != wire.MsgSolicit {
		t.Fatalf("solicitHintOf was handed a %s", msg.Type)
	}
	ias, err := msg.Options.IANAs()
	if err != nil || len(ias) != 1 {
		t.Fatalf("the Solicit's IA_NA: %v %v", ias, err)
	}
	addrs, err := ias[0].Options.Addrs()
	if err != nil {
		t.Fatalf("the Solicit's IA Address options: %v", err)
	}
	switch len(addrs) {
	case 0:
		return netip.Addr{}
	case 1:
		return addrs[0].Addr
	default:
		t.Fatalf("the Solicit hints %d addresses; this client asks for one IA_NA with one address", len(addrs))
		return netip.Addr{}
	}
}

// declineOnce drives m from State6DAD, where addr is pending, through the
// duplicate verdict and the Decline exchange, and back to the Solicit that
// §18.2.10.1's recovery produces. It returns that Solicit.
func declineOnce(t *testing.T, m *Machine6, addr string, base int64) *wire.MessageV6 {
	t.Helper()
	s, acts := m.Step(at(base), 5, DADResult(addr6(addr), true))
	if s != State6DAD {
		t.Fatalf("a duplicate verdict left the machine in %s, want %s (the Decline runs from there)", s, State6DAD)
	}
	dec := mustSendV6(t, acts, wire.MsgDecline6)
	got := declinedAddrs(t, dec)
	if len(got) != 1 || got[0].Addr != addr6(addr) {
		t.Fatalf("the Decline named %v, want %s", got, addr)
	}
	// §18.2.8: "the client considers the Decline event completed" when the
	// Reply arrives, and the machine then restarts discovery.
	s, _ = m.Step(at(base+1), 6, receivedV6(t, wire.MsgReply, dec.XID,
		optClientID(capDUID), optServerID(testServerDUID), optStatus(wire.StatusSuccess)))
	if s != State6Init {
		t.Fatalf("the Reply to the Decline left the machine in %s, want %s (§18.2.8 restarts discovery)", s, State6Init)
	}
	_, acts = m.Step(at(base+2), capXIDSolicit, TimerFired(Timer6Delay))
	return mustSendV6(t, acts, wire.MsgSolicit)
}

// offerAndReply takes a machine in SELECTING through an Advertise and a Reply
// naming addr, leaving it in State6DAD with addr pending.
func offerAndReply(t *testing.T, m *Machine6, addr string, base int64) {
	t.Helper()
	adv := receivedV6(t, wire.MsgAdvertise, uint32(capXIDSolicit),
		optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 150, 240, []iaAddrSpec{{addr, 300, 300}}),
		optPreference(255))
	if s, _ := m.Step(at(base), capXIDRequest, adv); s != State6Requesting {
		t.Fatalf("a preference-255 Advertise left the machine in %s", s)
	}
	if s, _ := m.Step(at(base+1), 0, reply(t, uint32(capXIDRequest), addr)); s != State6DAD {
		t.Fatalf("the Reply left the machine in %s, want %s", s, State6DAD)
	}
}

// TestTheSolicitAfterADeclineDoesNotAskForTheDeclinedAddress is the library
// half of the plugin's persistent decline loop.
//
// RFC 9915 §18.2.10.1 makes the Decline a MUST and then says only "The client
// SHOULD restart the process of server discovery"; §18.2.1 makes the address
// hint a MAY and says nothing about the server refusing one. A machine that
// re-sends the hint therefore does nothing the RFC forbids and everything the
// operator does not want: dnsmasq 2.91 answers a requested IAADDR before it
// allocates anything (src/rfc3315.c's SOLICIT arm calls address6_valid,
// address6_available and add_address before address6_allocate is reached),
// and its DECLINE arm blacklists only a CONFIGURED address, so the same
// address comes back and is declined again, once a second, for as long as the
// client runs. MEASURED in the plugin's chassis at run 34058213252: sixteen
// rounds in sixteen seconds.
//
// THE ASSERTION IS ON THE SECOND SOLICIT'S BYTES. A test that read the
// machine's field would pass against a machine that cleared the field and
// built the option from Params6 anyway.
func TestTheSolicitAfterADeclineDoesNotAskForTheDeclinedAddress(t *testing.T) {
	p := testParams6()
	p.Hint = addr6(hintedAddr)

	m, first := solicit6(t, p)
	if got := solicitHintOf(t, first); got != addr6(hintedAddr) {
		t.Fatalf("the FIRST Solicit hints %v, want %s; the fixture is not driving the case this test is about (§18.2.1)", got, hintedAddr)
	}

	offerAndReply(t, m, hintedAddr, 2)
	second := declineOnce(t, m, hintedAddr, 4)

	if got := solicitHintOf(t, second); got.IsValid() {
		t.Fatalf("the Solicit that RESTARTS discovery still asks for %v, the address this machine has just declined; "+
			"a server that honours the hint re-offers it and the client declines it again, without bound", got)
	}
}

// TestASecondDeclineDoesNotBringTheHintBack drives the loop's second turn.
//
// One clearing is not a bound: what the plugin measured was a client that
// asked, declined, asked, declined. This drives that shape twice and asserts
// the third Solicit is as clean as the second.
func TestASecondDeclineDoesNotBringTheHintBack(t *testing.T) {
	p := testParams6()
	p.Hint = addr6(hintedAddr)

	m, _ := solicit6(t, p)
	offerAndReply(t, m, hintedAddr, 2)
	second := declineOnce(t, m, hintedAddr, 4)
	if got := solicitHintOf(t, second); got.IsValid() {
		t.Fatalf("the second Solicit hints %v", got)
	}

	// The server hands out the same address anyway — nothing stops it — and
	// the second node is still there.
	offerAndReply(t, m, hintedAddr, 8)
	third := declineOnce(t, m, hintedAddr, 10)
	if got := solicitHintOf(t, third); got.IsValid() {
		t.Fatalf("the third Solicit asks for %v again: the machine remembers only the LAST decline", got)
	}
}

// TestADeclineOfADIFFERENTAddressLeavesTheHintAlone is the preservation
// control, and it is the reason the machine keeps a SET rather than clearing
// Params6.Hint.
//
// The hint is what keeps an endpoint's address across a restart (#213). A
// server is free to offer something other than what was asked for, and a
// duplicate on THAT address says nothing about the address the caller wants:
// a machine that cleared the hint on any Decline would give up a preference
// no node on the link has ever answered for.
func TestADeclineOfADIFFERENTAddressLeavesTheHintAlone(t *testing.T) {
	p := testParams6()
	p.Hint = addr6(hintedAddr)

	m, first := solicit6(t, p)
	if got := solicitHintOf(t, first); got != addr6(hintedAddr) {
		t.Fatalf("the first Solicit hints %v, want %s", got, hintedAddr)
	}

	// The server substitutes its own choice, and THAT address is in use.
	offerAndReply(t, m, substituteAll, 2)
	second := declineOnce(t, m, substituteAll, 4)

	if got := solicitHintOf(t, second); got != addr6(hintedAddr) {
		t.Fatalf("after declining %s the Solicit hints %v, want the caller's %s still: "+
			"the address the caller asked to keep was never offered and was never in use",
			substituteAll, got, hintedAddr)
	}
}

// TestTheHintIsDroppedEvenAfterAnEarlierDeclineOfAnotherAddress composes the
// two cases above, and it is the one a machine that remembers only its FIRST
// decline gets wrong.
//
// A client can meet the substituted address first: the server offers its own
// choice, that one is in use, it is declined, and the caller's preference is
// correctly kept. The NEXT round is the one that matters — the server now
// offers what was asked for, and that address is in use too. A machine that
// stopped recording after the first Decline hints it again, and the loop this
// whole file is about starts one round later than the simple case.
func TestTheHintIsDroppedEvenAfterAnEarlierDeclineOfAnotherAddress(t *testing.T) {
	p := testParams6()
	p.Hint = addr6(hintedAddr)

	m, _ := solicit6(t, p)
	offerAndReply(t, m, substituteAll, 2)
	second := declineOnce(t, m, substituteAll, 4)
	if got := solicitHintOf(t, second); got != addr6(hintedAddr) {
		t.Fatalf("after declining the substitute the Solicit hints %v, want %s", got, hintedAddr)
	}

	offerAndReply(t, m, hintedAddr, 8)
	third := declineOnce(t, m, hintedAddr, 10)
	if got := solicitHintOf(t, third); got.IsValid() {
		t.Fatalf("the Solicit after the SECOND decline asks for %v; the machine recorded only the first address it declined", got)
	}
}

// TestAnAcquisitionAfterADeclineDoesNotClaimToHaveAskedForTheAddress is
// Action.Requested's half of the same fact.
//
// Action.Requested is "the address this client ASKED FOR", and a caller
// compares it with the address it got to decide whether its preference was
// honoured. After the hint has been dropped the Solicit asked for nothing, so
// a Requested naming the declined address would tell the caller its preference
// was refused by the server when in fact it was never sent.
func TestAnAcquisitionAfterADeclineDoesNotClaimToHaveAskedForTheAddress(t *testing.T) {
	p := testParams6()
	p.Hint = addr6(hintedAddr)

	m, _ := solicit6(t, p)
	offerAndReply(t, m, hintedAddr, 2)
	declineOnce(t, m, hintedAddr, 4)

	offerAndReply(t, m, substituteAll, 8)
	s, acts := m.Step(at(10), 7, DADResult(addr6(substituteAll), false))
	if s != State6Bound {
		t.Fatalf("a clean DAD verdict left the machine in %s, want %s", s, State6Bound)
	}
	for _, a := range acts {
		if a.Kind != ActLeaseAcquired {
			continue
		}
		if a.Requested.IsValid() {
			t.Fatalf("the acquisition reports having asked for %v; the Solicit that produced it carried no hint", a.Requested)
		}
		return
	}
	t.Fatalf("nothing was acquired: %v", acts)
}

// TestAMachineThatHasDeclinedNothingStillHints is the other direction of the
// preservation control: the ordinary acquisition, unchanged.
func TestAMachineThatHasDeclinedNothingStillHints(t *testing.T) {
	p := testParams6()
	p.Hint = addr6(hintedAddr)

	m, first := solicit6(t, p)
	if got := solicitHintOf(t, first); got != addr6(hintedAddr) {
		t.Fatalf("the Solicit hints %v, want %s (§18.2.1)", got, hintedAddr)
	}
	offerAndReply(t, m, hintedAddr, 2)
	s, acts := m.Step(at(4), 7, DADResult(addr6(hintedAddr), false))
	if s != State6Bound {
		t.Fatalf("a clean DAD verdict left the machine in %s", s)
	}
	for _, a := range acts {
		if a.Kind == ActLeaseAcquired {
			if a.Requested != addr6(hintedAddr) {
				t.Fatalf("the acquisition reports having asked for %v, want %s", a.Requested, hintedAddr)
			}
			return
		}
	}
	t.Fatalf("nothing was acquired: %v", acts)
}

// TestAnAddressDeclinedWithNoServerToTellIsStillNotHintedAgain is the arm
// declineAll refuses.
//
// A lease that names no server cannot carry §18.2.8's Server Identifier, so
// no Decline is sent at all — and the address is exactly as unusable as one
// that was declined properly. The recording happens before that refusal for
// this reason: otherwise the one path where the server is NOT told is the one
// path where the client keeps asking.
func TestAnAddressDeclinedWithNoServerToTellIsStillNotHintedAgain(t *testing.T) {
	p := testParams6()
	p.Hint = addr6(hintedAddr)
	// The resume path is where a lease with no server DUID comes from: a
	// caller that remembered an address and not who granted it.
	p.Resume = &Resume6{
		Addrs: []Addr6{{Addr: addr6(hintedAddr), Preferred: 300 * Second, Valid: 300 * Second}},
		T1:    150 * Second,
		T2:    240 * Second,
	}
	m := newMachine6(t, p)
	if s, _ := m.Step(at(0), 0, Simple(EvStart)); s != State6Init {
		t.Fatalf("EvStart left the machine in %s", s)
	}
	s, acts := m.Step(at(1), capXIDSolicit, TimerFired(Timer6Delay))
	if s != State6Confirming {
		t.Fatalf("a live resume left the machine in %s, want %s", s, State6Confirming)
	}
	conf := mustSendV6(t, acts, wire.MsgConfirm)
	if s, _ := m.Step(at(2), 3, receivedV6(t, wire.MsgReply, conf.XID,
		optClientID(capDUID), optServerID(testServerDUID), optStatus(wire.StatusSuccess))); s != State6DAD {
		t.Fatalf("the confirming Reply left the machine in %s", s)
	}

	s, acts = m.Step(at(3), 5, DADResult(addr6(hintedAddr), true))
	if s != State6Init {
		t.Fatalf("a duplicate on a lease with no server left the machine in %s, want %s: "+
			"no Decline can be sent, so discovery restarts at once", s, State6Init)
	}
	if hasSendV6(acts, wire.MsgDecline6) {
		t.Fatal("a Decline was sent for a lease that names no server; §18.2.8 requires a Server Identifier")
	}
	_, acts = m.Step(at(4), capXIDSolicit, TimerFired(Timer6Delay))
	if got := solicitHintOf(t, mustSendV6(t, acts, wire.MsgSolicit)); got.IsValid() {
		t.Fatalf("the restarted Solicit asks for %v, an address another node answers for", got)
	}
}
