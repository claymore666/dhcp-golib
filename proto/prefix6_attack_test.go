// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"net/netip"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// TestARenewalTakesTheLifetimesOfAnAddressTheReplyNames: a held address the
// IA_NA names gets the Reply's lifetimes, and the one it leaves out keeps its
// own expiry (RFC 8415 section 18.2.10.1: "Update lifetimes for any leases in
// the IA option that the client already has recorded in the IA";
// claymore666/dhcp-golib#64).
func TestARenewalTakesTheLifetimesOfAnAddressTheReplyNames(t *testing.T) {
	m := keepTwoAddrs(t)
	before, _ := m.Lease()
	_, acts := m.Step(at(152), 7, TimerFired(Timer6Renew))
	ren := mustSendV6(t, acts, wire.MsgRenew)
	m.Step(at(153), 0, receivedV6(t, wire.MsgReply, ren.XID, optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 150, 240, []iaAddrSpec{{pd6Addr, 400, 500}})))
	after, _ := m.Lease()
	if len(after.Addrs) != 2 {
		t.Fatalf("the lease holds %v, want both addresses", after.Addrs)
	}
	if got := after.Addrs[0]; got.Addr != netip.MustParseAddr(pd6Addr) || got.Preferred != 400*Second || got.Valid != 500*Second {
		t.Errorf("the named address is %v, want the Reply's 400 s/500 s", got)
	}
	if got, was := after.Start.Add(after.Addrs[1].Valid), before.Start.Add(before.Addrs[1].Valid); got != was {
		t.Errorf("the address the Reply left out ends at %v, held it ended at %v", got, was)
	}
}

// TestRenewedAddrsDropsACarryPastItsValidLifetime: an address the Reply leaves
// out whose valid lifetime has passed at now is not kept, one that has not is
// (claymore666/dhcp-golib#64).
func TestRenewedAddrsDropsACarryPastItsValidLifetime(t *testing.T) {
	a, b, c := netip.MustParseAddr(pd6Addr), netip.MustParseAddr(pd6Temp), netip.MustParseAddr("fd00:99::3c4")
	held := []Addr6{{Addr: a, Preferred: 50 * Second, Valid: 100 * Second}, {Addr: b, Preferred: 50 * Second, Valid: 1000 * Second}}
	got := []Addr6{{Addr: c, Preferred: 300 * Second, Valid: 300 * Second}}
	out := renewedAddrs(held, at(0), got, nil, at(150), at(150))
	if len(out) != 2 || out[0].Addr != b || out[1].Addr != c {
		t.Fatalf("renewedAddrs = %v, want the unexpired %s and the new %s", out, b, c)
	}
	if end := at(150).Add(out[0].Valid); end != at(1000) {
		t.Errorf("the carried address ends at %v, want at(1000)", end)
	}
}

// TestAnIAPDNobodyAskedForSaysNoBindingAndNothingHappens: a client that sent no
// IA_PD does not answer a NoBinding in one with a Request (RFC 8415 section
// 18.2.10.1 counts the IAs "in the Reply message", and ours is the IA_NA;
// claymore666/dhcp-golib#64).
func TestAnIAPDNobodyAskedForSaysNoBindingAndNothingHappens(t *testing.T) {
	m := keepTwoAddrs(t)
	_, acts := m.Step(at(152), 7, TimerFired(Timer6Renew))
	ren := mustSendV6(t, acts, wire.MsgRenew)
	s, acts := m.Step(at(153), 0, receivedV6(t, wire.MsgReply, ren.XID, optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 150, 240, []iaAddrSpec{{pd6Addr, 300, 300}, {pd6Temp, 300, 300}}),
		optIAPD(t, capIAID, 0, 0, nil, optStatus(wire.StatusNoBinding))))
	if s == State6Requesting || count(acts, ActSendV6) != 0 {
		t.Errorf("the Reply left the machine in %s with %d message(s) sent, want a plain renewal", s, count(acts, ActSendV6))
	}
	if count(acts, ActLeaseRenewed) != 1 {
		t.Errorf("%d Renewed, want one", count(acts, ActLeaseRenewed))
	}
}

// TestAnIAPDThatNamesNoKeptPrefixLeavesT1AndT2Alone: an IA_PD whose only prefix
// ends gives the lease no renewal time, so the carried prefix does not pull T1
// and T2 down to it (claymore666/dhcp-golib#64).
func TestAnIAPDThatNamesNoKeptPrefixLeavesT1AndT2Alone(t *testing.T) {
	m := keepBound(t, optIAPD(t, capIAID, 150, 240, []pd6Spec{{pd6First, 300, 600}, {pd6Other, 300, 600}}))
	pd6Renew(t, m, 152, 153, optIAPD(t, capIAID, 30, 60, []pd6Spec{{pd6First, 0, 0}}))
	l, _ := m.Lease()
	if len(l.Prefixes) != 1 || l.Prefixes[0].Prefix != netip.MustParsePrefix(pd6Other) {
		t.Fatalf("the lease holds %v, want %s alone", l.Prefixes, pd6Other)
	}
	if l.T1 != 150*Second || l.T2 != 240*Second {
		t.Errorf("T1/T2 = %s/%s, want the IA_NA's 150 s/240 s", l.T1, l.T2)
	}
}

// TestNoBindingRequestNamesTheHeldTemporaryAddress: the Request after a NoBinding
// "places IA options in this message for all IAs", the IA_TA with them (RFC 8415
// section 18.2.10.1; claymore666/dhcp-golib#64).
func TestNoBindingRequestNamesTheHeldTemporaryAddress(t *testing.T) {
	m := ta6Bound(t, [2]uint32{300, 600})
	_, acts := m.Step(at(152), 7, TimerFired(Timer6Renew))
	ren := mustSendV6(t, acts, wire.MsgRenew)
	s, acts := m.Step(at(153), 9, receivedV6(t, wire.MsgReply, ren.XID, optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 0, 0, nil, optStatus(wire.StatusNoBinding))))
	if s != State6Requesting {
		t.Fatalf("NoBinding left the machine in %s, want %s", s, State6Requesting)
	}
	_, tas := ta6IAs(t, mustSendV6(t, acts, wire.MsgRequest6))
	if len(tas) != 1 || len(ta6AddrsOf(t, tas[0].Options)) != 1 || ta6AddrsOf(t, tas[0].Options)[0].Addr != netip.MustParseAddr(ta6Temp) {
		t.Errorf("the Request's IA_TA is %v, want the held %s", tas, ta6Temp)
	}
}

// declineAfterRenewReply binds to pd6Addr, answers the Renew with a Reply that
// names only the given addresses, reports each of them duplicate on DAD, and
// returns the Decline the machine sent and the machine.
func declineAfterRenewReply(t *testing.T, named []iaAddrSpec) (*wire.MessageV6, *Machine6) {
	t.Helper()
	ia := optIANA(t, capIAID, 150, 240, []iaAddrSpec{{pd6Addr, 300, 300}})
	m, sol := solicit6(t, testParams6())
	_, acts := m.Step(at(2), capXIDRequest, receivedV6(t, wire.MsgAdvertise, sol.XID, optClientID(capDUID), optServerID(testServerDUID), ia, optPreference(255)))
	req := mustSendV6(t, acts, wire.MsgRequest6)
	_, acts = m.Step(at(3), 0, receivedV6(t, wire.MsgReply, req.XID, optClientID(capDUID), optServerID(testServerDUID), ia))
	for _, a := range pd6Targets(acts) {
		m.Step(at(4), 0, DADResult(a, false))
	}
	_, acts = m.Step(at(152), 7, TimerFired(Timer6Renew))
	ren := mustSendV6(t, acts, wire.MsgRenew)
	_, acts = m.Step(at(153), 0, receivedV6(t, wire.MsgReply, ren.XID, optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 150, 240, named)))
	targets := pd6Targets(acts)
	if len(targets) == 0 {
		t.Fatalf("the Reply started no DAD: %v", acts)
	}
	var dec *wire.MessageV6
	for _, a := range targets {
		_, acts = m.Step(at(154), 0, DADResult(a, true))
		if hasSendV6(acts, wire.MsgDecline6) {
			dec = mustSendV6(t, acts, wire.MsgDecline6)
		}
	}
	if dec == nil {
		t.Fatal("a duplicate address sent no Decline")
	}
	return dec, m
}

// TestADuplicateOnTheRepliesNewAddressDeclinesThatAddressAlone is the Decline
// of §18.2.8 after §18.2.10.1 keeps a held address. The Reply names only a
// new address; the held one was not received in it and nobody contested it,
// so the Decline carries the new address alone, as on the base, and the held
// one stays the lease (dhcp-golib#64).
func TestADuplicateOnTheRepliesNewAddressDeclinesThatAddressAlone(t *testing.T) {
	const third = "fd00:99::3c4"
	dec, m := declineAfterRenewReply(t, []iaAddrSpec{{third, 300, 300}})
	got := declinedAddrs(t, dec)
	if len(got) != 1 || got[0].Addr != netip.MustParseAddr(third) {
		t.Fatalf("the Decline names %v, want the contested %s alone", got, third)
	}
	if l, held := m.Lease(); !held || len(l.Addrs) != 1 || l.Addrs[0].Addr != netip.MustParseAddr(pd6Addr) {
		t.Fatalf("after the Decline the lease is %v held=%v, want %s kept", l.Addrs, held, pd6Addr)
	}
}

// TestADuplicateOnANamedAddressStillDeclinesTheWholeReply is the other side of
// the one above: a Reply that names the held address as well as a new one has
// received both, so the whole-IA Decline of the base is unchanged.
func TestADuplicateOnANamedAddressStillDeclinesTheWholeReply(t *testing.T) {
	const third = "fd00:99::3c4"
	dec, _ := declineAfterRenewReply(t, []iaAddrSpec{{pd6Addr, 300, 300}, {third, 300, 300}})
	got := declinedAddrs(t, dec)
	if len(got) != 2 {
		t.Fatalf("the Decline names %v, want both addresses the Reply named", got)
	}
}

// TestACarryFromAnEarlierRenewalDoesNotShieldAnAddressALaterReplyNames: the
// held address the first Renew's Reply left out is carried; the second Reply
// names it again, so a duplicate found on the third address declines all
// three, as the base does. The carry is the pending Reply's, not the
// machine's memory of the last one (dhcp-golib#64).
func TestACarryFromAnEarlierRenewalDoesNotShieldAnAddressALaterReplyNames(t *testing.T) {
	const second, third = "fd00:99::2b2", "fd00:99::3c4"
	ia := optIANA(t, capIAID, 150, 240, []iaAddrSpec{{pd6Addr, 300, 300}})
	m, sol := solicit6(t, testParams6())
	_, acts := m.Step(at(2), capXIDRequest, receivedV6(t, wire.MsgAdvertise, sol.XID, optClientID(capDUID), optServerID(testServerDUID), ia, optPreference(255)))
	req := mustSendV6(t, acts, wire.MsgRequest6)
	_, acts = m.Step(at(3), 0, receivedV6(t, wire.MsgReply, req.XID, optClientID(capDUID), optServerID(testServerDUID), ia))
	for _, a := range pd6Targets(acts) {
		m.Step(at(4), 0, DADResult(a, false))
	}
	_, acts = m.Step(at(152), 7, TimerFired(Timer6Renew))
	ren := mustSendV6(t, acts, wire.MsgRenew)
	_, acts = m.Step(at(153), 0, receivedV6(t, wire.MsgReply, ren.XID, optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 150, 240, []iaAddrSpec{{second, 300, 300}})))
	for _, a := range pd6Targets(acts) {
		m.Step(at(154), 0, DADResult(a, false))
	}
	if l, _ := m.Lease(); m.State() != State6Bound || len(l.Addrs) != 2 {
		t.Fatalf("the first renewal left %s with %v, want both addresses bound", m.State(), l.Addrs)
	}
	_, acts = m.Step(at(310), 7, TimerFired(Timer6Renew))
	ren = mustSendV6(t, acts, wire.MsgRenew)
	_, acts = m.Step(at(311), 0, receivedV6(t, wire.MsgReply, ren.XID, optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 150, 240, []iaAddrSpec{{pd6Addr, 300, 300}, {second, 300, 300}, {third, 300, 300}})))
	var dec *wire.MessageV6
	for _, a := range pd6Targets(acts) {
		_, acts = m.Step(at(312), 0, DADResult(a, true))
		if hasSendV6(acts, wire.MsgDecline6) {
			dec = mustSendV6(t, acts, wire.MsgDecline6)
		}
	}
	if dec == nil {
		t.Fatal("a duplicate address sent no Decline")
	}
	if got := declinedAddrs(t, dec); len(got) != 3 {
		t.Fatalf("the Decline names %v, want all three the Reply named", got)
	}
}

// TestADuplicateOnANewAddressDeclinesTheNamedHeldOneAndNotTheLeftOutOne: two
// held addresses, the Reply names one of them and adds a third, and the third
// is a duplicate. The Decline carries what the Reply named (the held one it
// renewed and the new one) and leaves out the held address it did not name,
// which stays in the lease (dhcp-golib#64).
func TestADuplicateOnANewAddressDeclinesTheNamedHeldOneAndNotTheLeftOutOne(t *testing.T) {
	const third = "fd00:99::3c4"
	m := keepTwoAddrs(t)
	_, acts := m.Step(at(152), 7, TimerFired(Timer6Renew))
	ren := mustSendV6(t, acts, wire.MsgRenew)
	_, acts = m.Step(at(153), 0, receivedV6(t, wire.MsgReply, ren.XID, optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 150, 240, []iaAddrSpec{{pd6Addr, 300, 300}, {third, 300, 300}})))
	var dec *wire.MessageV6
	for _, a := range pd6Targets(acts) {
		_, acts = m.Step(at(154), 0, DADResult(a, true))
		if hasSendV6(acts, wire.MsgDecline6) {
			dec = mustSendV6(t, acts, wire.MsgDecline6)
		}
	}
	if dec == nil {
		t.Fatal("a duplicate address sent no Decline")
	}
	got := declinedAddrs(t, dec)
	if len(got) != 2 || got[0].Addr != netip.MustParseAddr(pd6Addr) || got[1].Addr != netip.MustParseAddr(third) {
		t.Fatalf("the Decline names %v, want %s and %s", got, pd6Addr, third)
	}
	if l, held := m.Lease(); !held || len(l.Addrs) != 2 {
		t.Fatalf("after the Decline the lease is %v held=%v, want both held addresses still there", l.Addrs, held)
	}
}

// TestAHeldAddressLeftOutOfOneRenewalIsDeclinedWhenTheNextReplyNamesItAndAnotherIsADuplicate:
// the first Renew's Reply names A alone, so B is carried and no address is new,
// no duplicate check runs and the carry stays set while the lease is bound.
// The next Reply names A, B and a new C and C is a duplicate: the Decline names
// all three, as the base does, because the carry belongs to the Reply that set
// it (dhcp-golib#64).
func TestAHeldAddressLeftOutOfOneRenewalIsDeclinedWhenTheNextReplyNamesItAndAnotherIsADuplicate(t *testing.T) {
	const third = "fd00:99::3c4"
	m := keepTwoAddrs(t)
	_, acts := m.Step(at(152), 7, TimerFired(Timer6Renew))
	ren := mustSendV6(t, acts, wire.MsgRenew)
	_, acts = m.Step(at(153), 0, receivedV6(t, wire.MsgReply, ren.XID, optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 150, 240, []iaAddrSpec{{pd6Addr, 300, 300}})))
	if len(pd6Targets(acts)) != 0 || m.State() != State6Bound {
		t.Fatalf("the first renewal ran a duplicate check or left %s, want bound with none", m.State())
	}
	_, acts = m.Step(at(310), 7, TimerFired(Timer6Renew))
	ren = mustSendV6(t, acts, wire.MsgRenew)
	_, acts = m.Step(at(311), 0, receivedV6(t, wire.MsgReply, ren.XID, optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 150, 240, []iaAddrSpec{{pd6Addr, 300, 300}, {pd6Temp, 300, 300}, {third, 300, 300}})))
	var dec *wire.MessageV6
	for _, a := range pd6Targets(acts) {
		_, acts = m.Step(at(312), 0, DADResult(a, true))
		if hasSendV6(acts, wire.MsgDecline6) {
			dec = mustSendV6(t, acts, wire.MsgDecline6)
		}
	}
	if dec == nil {
		t.Fatal("a duplicate address sent no Decline")
	}
	if got := declinedAddrs(t, dec); len(got) != 3 {
		t.Fatalf("the Decline names %v, want all three the Reply named", got)
	}
}
