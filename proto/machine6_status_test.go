// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// A server that ANSWERS and says no is not a server that never answered, and
// these rows are the difference. RFC 9915 has no DHCPNAK message: a DHCPv6
// server refuses with §21.13's Status Code option inside an ordinary Advertise
// or Reply, so the refusal has to be recognised where the code sits rather
// than by a message type.
//
// §21.13, on where it can sit: "A Status Code option may appear in the
// "options" field of a DHCP message and/or in the "options" field of another
// option.  If the Status Code option does not appear in a message in which the
// option could appear, the status of the message is assumed to be Success."
//
// §18.2.10, on reporting it: "The client MAY choose to report any status code
// or message from the Status Code option in the Reply message."

// refusals is every refusal in acts: an ActFailed carrying ReasonNak.
//
// It reads the ACTIONS and not the rendered text, which is the point of the
// field. Action.String does now put the code in an ActFailed's text, and that
// is a second copy for the durable journal to compare, not an observer: the
// Note carries the code as English at every emit site, so a test that grepped
// the line would pass against a machine whose FIELD was empty.
func refusals(acts []Action) []Action {
	var out []Action
	for _, a := range acts {
		if a.Kind == ActFailed && a.Reason == ReasonNak {
			out = append(out, a)
		}
	}
	return out
}

// oneRefusal asserts exactly one refusal in acts and returns it.
func oneRefusal(t *testing.T, acts []Action) Action {
	t.Helper()
	got := refusals(acts)
	if len(got) != 1 {
		t.Fatalf("%d refusal(s), want exactly 1; the machine said:%s", len(got), journalLines(acts))
	}
	return got[0]
}

// noRefusal asserts that nothing in acts reported a refusal.
func noRefusal(t *testing.T, acts []Action, why string) {
	t.Helper()
	if got := refusals(acts); len(got) != 0 {
		t.Fatalf("%s, and the machine reported %d refusal(s) (first: %s, status %s); the machine said:%s",
			why, len(got), got[0], got[0].Status, journalLines(acts))
	}
}

// TestAReplyThatRefusesIsReportedWithTheServersOwnCode drives the four places a
// refusal can reach a Request exchange and asserts the code, not the sentence.
//
// The unnamed codes are here for the reason §21.13's table is longer than this
// client's constant block: UseMulticast (5) is obsoleted — §16: "The Server
// Unicast option (see Section 21.12) and UseMulticast status code (see
// Section 21.13) have been obsoleted; hence, clients should no longer send
// messages to a server's unicast address nor receive the UseMulticast status
// code." — and IANA keeps allocating. A client that mapped an unknown code to
// a known one would tell an operator the server said something it did not.
func TestAReplyThatRefusesIsReportedWithTheServersOwnCode(t *testing.T) {
	for _, tc := range []struct {
		name  string
		opts  []wire.OptionV6
		want  wire.StatusCode
		state State6
	}{
		{
			// §18.3.2: "If the server does not send the NotOnLink status code
			// but it cannot assign any IP addresses to an IA, the server MUST
			// return the IA option in the Reply message with no addresses in
			// the IA and a Status Code option containing status code
			// NoAddrsAvail in the IA."
			name:  "in the IA_NA, which is where §18.3.2 puts it",
			opts:  []wire.OptionV6{optIANA(t, capIAID, 0, 0, nil, optStatus(wire.StatusNoAddrsAvail))},
			want:  wire.StatusNoAddrsAvail,
			state: State6Init,
		},
		{
			name:  "at the message level",
			opts:  []wire.OptionV6{optStatus(wire.StatusNoAddrsAvail)},
			want:  wire.StatusNoAddrsAvail,
			state: State6Init,
		},
		{
			// §18.2.10: the retransmission schedule already in flight is the
			// rate limit, so the exchange stands and only the report is new.
			name:  "UnspecFail, which leaves the exchange running",
			opts:  []wire.OptionV6{optStatus(wire.StatusUnspecFail)},
			want:  wire.StatusUnspecFail,
			state: State6Requesting,
		},
		{
			name:  "NotOnLink, with no lease to lose",
			opts:  []wire.OptionV6{optStatus(wire.StatusNotOnLink)},
			want:  wire.StatusNotOnLink,
			state: State6Init,
		},
		{
			name:  "an obsoleted code this client has no constant for",
			opts:  []wire.OptionV6{optStatus(wire.StatusCode(5))},
			want:  wire.StatusCode(5),
			state: State6Init,
		},
		{
			name:  "a code IANA has not allocated yet",
			opts:  []wire.OptionV6{optStatus(wire.StatusCode(77))},
			want:  wire.StatusCode(77),
			state: State6Init,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := solicit6(t, testParams6())
			m.Step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255))
			opts := append([]wire.OptionV6{optClientID(capDUID), optServerID(testServerDUID)}, tc.opts...)
			s, acts := m.Step(at(3), 3, receivedV6(t, wire.MsgReply, uint32(capXIDRequest), opts...))

			r := oneRefusal(t, acts)
			if r.Status != tc.want {
				t.Errorf("the refusal carries %s, want %s: an operator reading it is told which refusal this was", r.Status, tc.want)
			}
			if r.Note == "" {
				t.Error("the refusal carries no note; the journal's only account of it is the reason")
			}
			if s != tc.state {
				t.Errorf("the Reply left the machine in %s, want %s: reporting the refusal must not change what the machine does about it", s, tc.state)
			}
			if _, ok := find(acts, ActLeaseAcquired); ok {
				t.Error("a refused Reply acquired a lease")
			}
		})
	}
}

// TestAReplyThatSaysSuccessIsNotARefusal is the preservation control, and it
// drives the two shapes §21.13 calls one verdict.
//
// §21.13: "If the Status Code option does not appear in a message in which the
// option could appear, the status of the message is assumed to be Success."
// So an explicit Success and an absent option mean the same thing, and a guard
// keyed on "a Status Code option was present" rather than on the CODE turns an
// ordinary lease into a refusal. Both arms are driven, or the red measures
// nothing.
func TestAReplyThatSaysSuccessIsNotARefusal(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []wire.OptionV6
	}{
		{
			name: "an explicit Success at the message level",
			opts: []wire.OptionV6{
				optStatus(wire.StatusSuccess),
				optIANA(t, capIAID, 150, 240, []iaAddrSpec{{dnsmasqLeasedAddr, 300, 300}}),
			},
		},
		{
			name: "an explicit Success inside the IA_NA",
			opts: []wire.OptionV6{
				optIANA(t, capIAID, 150, 240, []iaAddrSpec{{dnsmasqLeasedAddr, 300, 300}},
					optStatus(wire.StatusSuccess)),
			},
		},
		{
			name: "no Status Code option at all",
			opts: []wire.OptionV6{
				optIANA(t, capIAID, 150, 240, []iaAddrSpec{{dnsmasqLeasedAddr, 300, 300}}),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := solicit6(t, testParams6())
			m.Step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255))
			opts := append([]wire.OptionV6{optClientID(capDUID), optServerID(testServerDUID)}, tc.opts...)
			s, acts := m.Step(at(3), 3, receivedV6(t, wire.MsgReply, uint32(capXIDRequest), opts...))

			noRefusal(t, acts, "the server said Success and offered an address")
			if s != State6DAD {
				t.Fatalf("the Reply left the machine in %s, want %s: the address it offered was taken", s, State6DAD)
			}
			s, acts = m.Step(at(4), 0, DADResult(netip.MustParseAddr(dnsmasqLeasedAddr), false))
			if s != State6Bound {
				t.Fatalf("the checked address left the machine in %s", s)
			}
			if _, ok := find(acts, ActLeaseAcquired); !ok {
				t.Error("no lease was acquired from a Reply that said Success")
			}
		})
	}
}

// TestAReplyWithNoAddressAndNoStatusIsNotARefusal is the OTHER silent row: a
// server that answers with an empty IA and states nothing has refused nobody,
// and #816's whole point is that the two are told apart.
//
// §18.2.10.1: "If the Reply message contains any IAs but the client finds no
// usable addresses and/or delegated prefixes in any of these IAs, the client
// may either try another server (perhaps restarting the DHCP server discovery
// process) or use the Information-request message to obtain other
// configuration information only."
func TestAReplyWithNoAddressAndNoStatusIsNotARefusal(t *testing.T) {
	m, _ := solicit6(t, testParams6())
	m.Step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255))
	s, acts := m.Step(at(3), 3, receivedV6(t, wire.MsgReply, uint32(capXIDRequest),
		optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 150, 240, nil)))

	noRefusal(t, acts, "the Reply carried an empty IA_NA and no Status Code option")
	if s != State6Init {
		t.Errorf("the empty Reply left the machine in %s, want discovery restarted (§18.2.10.1)", s)
	}
}

// TestAnAdvertiseThatRefusesIsReportedAndTheScheduleStands is §18.3.9's shape
// seen from the client, and the assertion is as much about what does NOT
// happen.
//
// §18.3.9: "If the server will not assign any addresses to an IA_NA in
// subsequent Request messages from the client, the server MUST include the IA
// option in the Advertise message with no addresses in that IA and a Status
// Code option (see Section 21.13) encapsulated in the IA option containing
// status code NoAddrsAvail."
//
// §18.2.9: "The client ignoring an Advertise message MUST NOT restart the
// Solicit retransmission timer." A refusal that also halted or re-armed the
// search would turn "the pool is full right now" into "give up", which is
// #816's confusion in the other direction.
func TestAnAdvertiseThatRefusesIsReportedAndTheScheduleStands(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []wire.OptionV6
	}{
		{
			name: "encapsulated in the IA_NA, which is where §18.3.9 puts it",
			opts: []wire.OptionV6{optIANA(t, capIAID, 0, 0, nil, optStatus(wire.StatusNoAddrsAvail))},
		},
		{
			// MEASURED against dnsmasq 2.91 (src/rfc3315.c, the DHCP6SOLICIT
			// arm): when it can assign nothing it drops the IA from the
			// Advertise entirely and puts NoAddrsAvail at the message level.
			// The MUST above is not what the fixture on the runtime side
			// actually sends, so both are driven here.
			name: "at the message level, which is what dnsmasq sends",
			opts: []wire.OptionV6{optStatus(wire.StatusNoAddrsAvail)},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := solicit6(t, testParams6())
			opts := append([]wire.OptionV6{optClientID(capDUID), optServerID(testServerDUID)}, tc.opts...)
			s, acts := m.Step(at(2), 3, receivedV6(t, wire.MsgAdvertise, uint32(capXIDSolicit), opts...))

			r := oneRefusal(t, acts)
			if r.Status != wire.StatusNoAddrsAvail {
				t.Errorf("the refusal carries %s, want %s", r.Status, wire.StatusNoAddrsAvail)
			}
			if s != State6Selecting {
				t.Errorf("a refusing Advertise left the machine in %s, want it still soliciting", s)
			}
			if hasSendV6(acts, wire.MsgRequest6) {
				t.Error("a Request went to a server that said it had nothing")
			}
			for _, a := range acts {
				if a.Kind == ActSetTimer || a.Kind == ActCancelTimer {
					t.Errorf("the refusal touched timer %s (%s); §18.2.9: \"The client ignoring an Advertise message MUST NOT restart the Solicit retransmission timer.\"", a.Timer, a.Kind)
				}
			}
		})
	}
}

// TestARefusedRenewKeepsTheLeaseAndSaysWhy is §18.2.10.1's "Leave unchanged any
// information about leases the client has recorded in the IA but that were not
// included in the IA from the server", with the refusal reported beside it.
//
// The lease is what the assertion is about: a client that dropped a live
// address because the server had none to give would take an endpoint down over
// a pool that is merely full.
func TestARefusedRenewKeepsTheLeaseAndSaysWhy(t *testing.T) {
	m := bind6(t, testParams6(), dnsmasqLeasedAddr)
	_, acts := m.Step(at(200), 7, TimerFired(Timer6Renew))
	rn := mustSendV6(t, acts, wire.MsgRenew)

	_, acts = m.Step(at(201), uint64(capXIDSolicit), receivedV6(t, wire.MsgReply, rn.XID,
		optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 0, 0, nil, optStatus(wire.StatusNoAddrsAvail))))

	r := oneRefusal(t, acts)
	if r.Status != wire.StatusNoAddrsAvail {
		t.Errorf("the refused renewal carries %s, want %s", r.Status, wire.StatusNoAddrsAvail)
	}
	if _, ok := find(acts, ActLeaseLost); ok {
		t.Error("the refused renewal ended the lease; the address is valid until its own lifetime runs out (§18.2.10.1)")
	}
	if _, held := m.Lease(); !held {
		t.Error("the machine dropped the lease it still holds")
	}
}

// TestANoBindingRenewIsARecoveryAndNotARefusal is the arm the client answers
// by itself.
//
// §18.2.10.1: the client "Sends a Request message to the server that responded
// if any of the IAs in the Reply message contain the NoBinding status code."
// Nothing failed for the operator to act on, and a counter that moved here
// would report a working client as a refused one.
func TestANoBindingRenewIsARecoveryAndNotARefusal(t *testing.T) {
	m := bind6(t, testParams6(), dnsmasqLeasedAddr)
	_, acts := m.Step(at(200), 7, TimerFired(Timer6Renew))
	rn := mustSendV6(t, acts, wire.MsgRenew)

	s, acts := m.Step(at(201), uint64(capXIDSolicit), receivedV6(t, wire.MsgReply, rn.XID,
		optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 0, 0, nil, optStatus(wire.StatusNoBinding))))

	noRefusal(t, acts, "NoBinding on a renewal is answered with a Request (§18.2.10.1)")
	if s != State6Requesting {
		t.Errorf("NoBinding left the machine in %s, want a Request to the server that answered", s)
	}
	mustSendV6(t, acts, wire.MsgRequest6)
}

// TestNotOnLinkCostsTheLeaseAndIsCountedOnce holds the pair that ring 2's
// counters depend on.
//
// A refusal that costs a held lease produces ActLeaseLost and then ActFailed,
// both carrying ReasonNak — the v4 DHCPNAK shape (D30) — and the fold counts
// the NAK at the Failed only. The order is load-bearing: a caller tears the
// interface down when it sees the loss.
func TestNotOnLinkCostsTheLeaseAndIsCountedOnce(t *testing.T) {
	m := bind6(t, testParams6(), dnsmasqLeasedAddr)
	_, acts := m.Step(at(200), 7, TimerFired(Timer6Renew))
	rn := mustSendV6(t, acts, wire.MsgRenew)

	_, acts = m.Step(at(201), uint64(capXIDSolicit), receivedV6(t, wire.MsgReply, rn.XID,
		optClientID(capDUID), optServerID(testServerDUID), optStatus(wire.StatusNotOnLink)))

	r := oneRefusal(t, acts)
	if r.Status != wire.StatusNotOnLink {
		t.Errorf("the refusal carries %s, want %s", r.Status, wire.StatusNotOnLink)
	}
	lost, ok := find(acts, ActLeaseLost)
	if !ok {
		t.Fatalf("the lease survived a NotOnLink Reply:%s", journalLines(acts))
	}
	if lost.Reason != ReasonNak {
		t.Errorf("the loss says %s, want %s", lost.Reason, ReasonNak)
	}
	var lostAt, failedAt = -1, -1
	for i, a := range acts {
		switch a.Kind {
		case ActLeaseLost:
			lostAt = i
		case ActFailed:
			failedAt = i
		}
	}
	if lostAt > failedAt {
		t.Errorf("the refusal was reported before the loss (%d before %d); a caller tears the interface down at the loss", failedAt, lostAt)
	}
}

// TestAMalformedStatusCodeIsNeverReportedAsARefusal keeps wire.StatusMalformed
// off the outward surface.
//
// The sentinel is 0xFFFF and is NOT a code RFC 9915 defines: it exists so that
// a caller who forgot the error does not read Success. #816's operator sentence
// is "the server refused: <name>", and a refusal carrying "malformed" would put
// this library's own sentinel in it as though a server had sent it. The machine
// checks the decode error before the value on every one of these paths, so no
// refusal is emitted at all.
func TestAMalformedStatusCodeIsNeverReportedAsARefusal(t *testing.T) {
	bad := wire.OptionV6{Code: wire.OptV6StatusCode, Data: []byte{0x00}}

	t.Run("in a Reply", func(t *testing.T) {
		m, _ := solicit6(t, testParams6())
		m.Step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255))
		s, acts := m.Step(at(3), 3, receivedV6(t, wire.MsgReply, uint32(capXIDRequest),
			optClientID(capDUID), optServerID(testServerDUID), bad))
		noRefusal(t, acts, "the Status Code option was one octet long and says nothing")
		if s != State6Requesting {
			t.Errorf("a malformed Status Code left the machine in %s, want the exchange unchanged", s)
		}
	})

	t.Run("in an Advertise", func(t *testing.T) {
		m, _ := solicit6(t, testParams6())
		_, acts := m.Step(at(2), 3, receivedV6(t, wire.MsgAdvertise, uint32(capXIDSolicit),
			optClientID(capDUID), optServerID(testServerDUID), bad))
		noRefusal(t, acts, "the Status Code option was one octet long and says nothing")
	})

	// The sentinel's own number, arriving from the wire as an ordinary code.
	// 65535 is not allocated by IANA and no server should send it, but "should
	// not" is not a guard: this library uses that number to mean "I could not
	// decode this", so a client that passed it through would tell an operator
	// the server said something this library said about itself.
	t.Run("as a literal 0xFFFF at the message level of an Advertise", func(t *testing.T) {
		m, _ := solicit6(t, testParams6())
		s, acts := m.Step(at(2), 3, receivedV6(t, wire.MsgAdvertise, uint32(capXIDSolicit),
			optClientID(capDUID), optServerID(testServerDUID), optStatus(wire.StatusMalformed)))
		noRefusal(t, acts, "65535 is this library's sentinel and not a code a server sent")
		if s != State6Selecting {
			t.Errorf("the Advertise left the machine in %s, want it still soliciting: §18.2.9 ignores any non-Success Advertise for selection", s)
		}
		if hasSendV6(acts, wire.MsgRequest6) {
			t.Error("an address was requested from an Advertise that did not say Success")
		}
	})

	t.Run("inside the IA_NA", func(t *testing.T) {
		m, _ := solicit6(t, testParams6())
		m.Step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255))
		_, acts := m.Step(at(3), 3, receivedV6(t, wire.MsgReply, uint32(capXIDRequest),
			optClientID(capDUID), optServerID(testServerDUID),
			optIANA(t, capIAID, 0, 0, nil, bad)))
		for _, a := range refusals(acts) {
			if a.Status == wire.StatusMalformed {
				t.Errorf("a refusal reports this library's own malformed sentinel as the server's code: %s", a)
			}
		}
	})
}

// TestAStatusInsideAnIAAddressIsNotRead states a BOUND rather than a
// behaviour.
//
// §21.13 permits a Status Code option "in the "options" field of another
// option", and an IA Address option has an options field (§21.6). No server
// rule in §18.3.2 or §18.3.9 puts a refusal there — both name the IA — so this
// client reads the message level and the IA_NA level and nothing deeper. The
// escape: a server that refuses one address of several inside its IA Address
// option is read here as an ordinary address.
func TestAStatusInsideAnIAAddressIsNotRead(t *testing.T) {
	iaAddr, err := wire.EncodeIAAddr(&wire.IAAddr{
		Addr:              netip.MustParseAddr(dnsmasqLeasedAddr),
		PreferredLifetime: 300,
		ValidLifetime:     300,
		Options:           wire.OptionsV6{optStatus(wire.StatusNoAddrsAvail)},
	})
	if err != nil {
		t.Fatalf("EncodeIAAddr: %v", err)
	}
	ia, err := wire.EncodeIANA(&wire.IANA{IAID: capIAID, T1: 150, T2: 240,
		Options: wire.OptionsV6{{Code: wire.OptV6IAAddr, Data: iaAddr}}})
	if err != nil {
		t.Fatalf("EncodeIANA: %v", err)
	}

	m, _ := solicit6(t, testParams6())
	m.Step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255))
	s, acts := m.Step(at(3), 3, receivedV6(t, wire.MsgReply, uint32(capXIDRequest),
		optClientID(capDUID), optServerID(testServerDUID),
		wire.OptionV6{Code: wire.OptV6IANA, Data: ia}))

	noRefusal(t, acts, "the status sat inside the IA Address option, which this client does not read")
	if s != State6DAD {
		t.Fatalf("the Reply left the machine in %s, want the address taken: %s", s, journalLines(acts))
	}
}

// TestAnIAThatRefusesAndOffersGivesNoAddress is §18.2.10.1's selection rule,
// and it is what keeps a refusal from arriving beside an Acquired.
//
// §18.2.10.1: "The client uses the addresses, delegated prefixes, and other
// information from any IAs that do not contain a Status Code option with the
// NoAddrsAvail or NoPrefixAvail status code." So an IA that says NoAddrsAvail
// has nothing to give, whatever else is inside it — and a client that took the
// address anyway would hand the caller a refusal counter and a working
// endpoint at the same time.
func TestAnIAThatRefusesAndOffersGivesNoAddress(t *testing.T) {
	m, _ := solicit6(t, testParams6())
	m.Step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255))
	s, acts := m.Step(at(3), 3, receivedV6(t, wire.MsgReply, uint32(capXIDRequest),
		optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 150, 240, []iaAddrSpec{{dnsmasqLeasedAddr, 300, 300}},
			optStatus(wire.StatusNoAddrsAvail))))

	r := oneRefusal(t, acts)
	if r.Status != wire.StatusNoAddrsAvail {
		t.Errorf("the refusal carries %s, want %s", r.Status, wire.StatusNoAddrsAvail)
	}
	if _, ok := find(acts, ActLeaseAcquired); ok {
		t.Error("an IA that said NoAddrsAvail was read for an address anyway")
	}
	if s == State6DAD {
		t.Errorf("the machine is checking an address from an IA that said NoAddrsAvail:%s", journalLines(acts))
	}
}

// TestARefusedInformationRequestIsNotAConfiguration is the issue's stateless
// row: "other-config only", where there is no address to fail to get and the
// only thing that can go wrong is the server refusing.
//
// §18.2.10 covers a Reply "in response to a Solicit (with a Rapid Commit
// option), Request, Confirm, Renew, Rebind, or Information-request message",
// and its UnspecFail sentence is written for all of them. A refused
// Information-request reported as a configuration tells the caller its
// resolver is set up when the server declined to say anything.
func TestARefusedInformationRequestIsNotAConfiguration(t *testing.T) {
	p := testParams6()
	m, _ := solicit6(t, p)
	_, acts := m.Step(at(2), 3, RouterAdvertRaw(mustRA(t, raOtherOnly), raOtherOnly))
	inf := mustSendV6(t, acts, wire.MsgInformationRequest)

	s, acts := m.Step(at(3), 3, receivedV6(t, wire.MsgReply, inf.XID,
		optClientID(capDUID), optServerID(testServerDUID),
		optStatus(wire.StatusUnspecFail)))

	r := oneRefusal(t, acts)
	if r.Status != wire.StatusUnspecFail {
		t.Errorf("the refusal carries %s, want %s", r.Status, wire.StatusUnspecFail)
	}
	if _, ok := find(acts, ActConfigured); ok {
		t.Error("a refused Information-request was reported as a configuration")
	}
	if _, ok := timerSet(acts, Timer6Refresh); ok {
		t.Error("a refresh was armed from a Reply that carried no configuration")
	}
	if s != State6InfoRequesting {
		t.Errorf("the refusal left the machine in %s, want the exchange running (§18.2.10)", s)
	}

	// The preservation control: the same Reply saying Success still configures.
	m2, _ := solicit6(t, p)
	_, acts = m2.Step(at(2), 3, RouterAdvertRaw(mustRA(t, raOtherOnly), raOtherOnly))
	inf2 := mustSendV6(t, acts, wire.MsgInformationRequest)
	_, acts = m2.Step(at(3), 3, receivedV6(t, wire.MsgReply, inf2.XID,
		optClientID(capDUID), optServerID(testServerDUID),
		optStatus(wire.StatusSuccess),
		wire.OptionV6{Code: wire.OptV6DNSServers, Data: addr16(dnsmasqDNS)}))
	noRefusal(t, acts, "the Reply said Success")
	if _, ok := find(acts, ActConfigured); !ok {
		t.Error("a Reply saying Success configured nothing; what refused the first one was the status, not the fixture")
	}
}

// TestALaterFailureCarriesNoEarlierStatus drives the staleness this field
// invites: a code stamped once and then attached to whatever fails next.
//
// The code is stamped at the emit site and never stored on the machine, so
// there is nothing to go stale — and this is where that is measured rather than
// asserted in a comment. The second failure here is a duplicate address, which
// has a reason of its own and no status at all.
func TestALaterFailureCarriesNoEarlierStatus(t *testing.T) {
	m, _ := solicit6(t, testParams6())
	_, acts := m.Step(at(2), 3, receivedV6(t, wire.MsgAdvertise, uint32(capXIDSolicit),
		optClientID(capDUID), optServerID(testServerDUID), optStatus(wire.StatusNoAddrsAvail)))
	if r := oneRefusal(t, acts); r.Status != wire.StatusNoAddrsAvail {
		t.Fatalf("the first refusal carries %s, want %s", r.Status, wire.StatusNoAddrsAvail)
	}

	m.Step(at(3), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255))
	if s, _ := m.Step(at(4), 3, reply(t, uint32(capXIDRequest), dnsmasqLeasedAddr)); s != State6DAD {
		t.Fatalf("the second server's Reply did not reach the duplicate check")
	}
	_, acts = m.Step(at(5), 3, DADResult(netip.MustParseAddr(dnsmasqLeasedAddr), true))

	f, ok := find(acts, ActFailed)
	if !ok {
		t.Fatalf("a duplicate address produced no failure:%s", journalLines(acts))
	}
	if f.Reason != ReasonConflict {
		t.Fatalf("the duplicate was reported as %s, want %s", f.Reason, ReasonConflict)
	}
	if f.Status != wire.StatusSuccess {
		t.Errorf("a conflict carries the status %s of an earlier refusal; the zero means no server refused this client", f.Status)
	}
}

// TestAV4NakCarriesNoStatusCode states the field's other bound.
//
// RFC 2131's refusal is a DHCPNAK message and carries no code, so every v4
// Failed leaves this field at its zero. A caller that read it without checking
// the family would be told Success by a refusal — which is why the field's
// documentation says the zero means "no status code refused this client"
// rather than "the server said Success".
func TestAV4NakCarriesNoStatusCode(t *testing.T) {
	m := newMachine(t, testParams())
	_, acts := m.Step(0, 1, Simple(EvStart))
	disc := mustSend(t, acts, wire.MsgDiscover)
	_, acts = m.Step(at(1), 2, received(t, offerFor(disc, "192.168.99.50", "192.168.99.1")))
	req := mustSend(t, acts, wire.MsgRequest)
	_, acts = m.Step(at(2), 3, received(t, nakFor(req, "192.168.99.1", "lease not available")))

	f, ok := find(acts, ActFailed)
	if !ok {
		t.Fatalf("a DHCPNAK produced no failure: %v", acts)
	}
	if f.Reason != ReasonNak {
		t.Fatalf("the NAK was reported as %s", f.Reason)
	}
	if f.Status != wire.StatusSuccess {
		t.Errorf("a v4 DHCPNAK carries the DHCPv6 status code %s; RFC 2131 has no such field", f.Status)
	}
}

// TestEveryRefusingMessageIsReported states what the refusal COUNTS, in both
// directions, because the number is the caller's and not this machine's.
//
// THE POPULATION IS REFUSING MESSAGES AND NOT REFUSED ENDPOINTS. Nothing
// bounds how often a server may refuse: §18.2.1 gives the Solicit no
// retransmission limit ("the client MUST retransmit the Solicit message"
// under §15's schedule, with no MRC and no MRD in Table 1), so a server with
// nothing to give answers every retransmission and every answer is reported.
// That is v4's shape too — one report per DHCPNAK message, not per endpoint —
// and it is the reading the counters take: Stats.NaksAccepted and
// RecordCounters.Naks count messages that refused this client.
//
// A caller that wants "was this endpoint refused" reads whether any refusal
// arrived, which is a question about the stream and not about its length.
// This test exists so that a change to either reading goes red rather than
// silently redefining a published counter.
func TestEveryRefusingMessageIsReported(t *testing.T) {
	m, sol := solicit6(t, testParams6())
	xid := sol.XID

	const rounds = 3
	for i := 0; i < rounds; i++ {
		s, acts := m.Step(at(int64(2*i+2)), 3, receivedV6(t, wire.MsgAdvertise, xid,
			optClientID(capDUID), optServerID(testServerDUID), optStatus(wire.StatusNoAddrsAvail)))
		r := oneRefusal(t, acts)
		if r.Status != wire.StatusNoAddrsAvail {
			t.Fatalf("round %d: the refusal carries %s, want %s", i+1, r.Status, wire.StatusNoAddrsAvail)
		}
		if s != State6Selecting {
			t.Fatalf("round %d: the machine is in %s, want it still soliciting", i+1, s)
		}
		// The retransmission that draws the next refusal. The first firing
		// also closes §18.2.1's collection window, which changes nothing
		// here: no Advertise was collected, because every one of them refused.
		_, acts = m.Step(at(int64(2*i+3)), uint64(0x40+i), TimerFired(Timer6Retransmit))
		// §16.1: "The client MUST leave the transaction-id unchanged in
		// retransmissions of a message", so the next refusing Advertise
		// answers the same xid.
		if next := mustSendV6(t, acts, wire.MsgSolicit); next.XID != xid {
			t.Fatalf("round %d: the retransmitted Solicit changed xid %x to %x (§16.1)", i+1, xid, next.XID)
		}
		noRefusal(t, acts, "a retransmission is not a refusal")
	}
}

// TestAMessageLevelRefusalBesideAUsableAddressIsNotARefusal is the stated
// bound's control: §18.2.10.1's rule is IA-scoped, so a message-level code
// beside an IA_NA that carries a usable address does not take the address
// away and does not report a refusal.
//
// §18.2.10.1: "The client uses the addresses, delegated prefixes, and other
// information from any IAs that do not contain a Status Code option with the
// NoAddrsAvail or NoPrefixAvail status code." The IA here contains none, so
// the client uses it — and a refusal beside an Acquired is the shape the emit
// sites exist to avoid.
func TestAMessageLevelRefusalBesideAUsableAddressIsNotARefusal(t *testing.T) {
	m, _ := solicit6(t, testParams6())
	m.Step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255))
	s, acts := m.Step(at(3), 3, receivedV6(t, wire.MsgReply, uint32(capXIDRequest),
		optClientID(capDUID), optServerID(testServerDUID),
		optStatus(wire.StatusNoAddrsAvail),
		optIANA(t, capIAID, 150, 240, []iaAddrSpec{{dnsmasqLeasedAddr, 300, 300}})))

	noRefusal(t, acts, "the IA_NA carried a usable address")
	if s != State6DAD {
		t.Fatalf("the Reply left the machine in %s, want %s: the address in the IA_NA is usable", s, State6DAD)
	}
	s, acts = m.Step(at(4), 0, DADResult(netip.MustParseAddr(dnsmasqLeasedAddr), false))
	if s != State6Bound {
		t.Fatalf("the checked address left the machine in %s", s)
	}
	if _, ok := find(acts, ActLeaseAcquired); !ok {
		t.Error("no lease was acquired from a Reply whose IA_NA carried an address")
	}
}

// TestAnAdvertiseThatRefusesAndOffersIsNotSelected drives the Advertise side of
// the same rule: an IA_NA that says NoAddrsAvail has nothing to give even when
// an IA Address sits beside the status, so the Advertise is refused and not
// collected for selection.
//
// It is the ORDER of two blocks in takeAdvertise that decides this — the
// refusal arm returns before the "no addresses" arm — and the order is what
// this test pins.
func TestAnAdvertiseThatRefusesAndOffersIsNotSelected(t *testing.T) {
	m, _ := solicit6(t, testParams6())
	s, acts := m.Step(at(2), 3, receivedV6(t, wire.MsgAdvertise, uint32(capXIDSolicit),
		optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 150, 240, []iaAddrSpec{{dnsmasqLeasedAddr, 300, 300}},
			optStatus(wire.StatusNoAddrsAvail))))

	r := oneRefusal(t, acts)
	if r.Status != wire.StatusNoAddrsAvail {
		t.Errorf("the refusal carries %s, want %s", r.Status, wire.StatusNoAddrsAvail)
	}
	if s != State6Selecting {
		t.Errorf("the Advertise left the machine in %s, want it still soliciting", s)
	}
	if hasSendV6(acts, wire.MsgRequest6) {
		t.Error("an address was requested from an IA_NA that said it had none")
	}
}

// TestAConfirmRefusedForThisLinkIsReported closes the arm the Request and Renew
// arms would otherwise have left silent: a resumed client whose Confirm comes
// back NotOnLink has been refused by a server that answered.
//
// §18.2.10.3: "When the client only receives one or more Reply messages with
// the NotOnLink status in response to a Confirm message, the client performs
// DHCP server discovery as described in Section 18." The discovery restart is
// what the machine already did; the report is what the caller did not get.
func TestAConfirmRefusedForThisLinkIsReported(t *testing.T) {
	m, acts := confirming6(t, testParams6())
	conf := mustSendV6(t, acts, wire.MsgConfirm)

	s, acts := m.Step(at(2), 3, receivedV6(t, wire.MsgReply, conf.XID,
		optClientID(capDUID), optServerID(testServerDUID), optStatus(wire.StatusNotOnLink)))

	r := oneRefusal(t, acts)
	if r.Status != wire.StatusNotOnLink {
		t.Errorf("the refusal carries %s, want %s", r.Status, wire.StatusNotOnLink)
	}
	if s != State6Init {
		t.Errorf("the refused Confirm left the machine in %s, want %s: §18.2.10.3 sends it back to discovery, which starts with §18.2.1's delay", s, State6Init)
	}
	if _, ok := timerSet(acts, Timer6Delay); !ok {
		t.Error("no Solicit delay was armed after a Confirm was refused, so discovery did not restart")
	}
}

// TestAFailedActionRendersTheCodeItCarries reads the RENDERING and not the
// field, because they are two artefacts with two consumers: the field is what
// a caller branches on, and the string is what the durable journal holds and
// what Replay6 compares entry by entry.
//
// THE NOTE IS NOT AN OBSERVER OF THE CODE even though every emit site writes
// the code into it: a rendering that dropped the status would still name the
// code, in English, from the note's own text. So the notes here say nothing
// about any status, and what remains in the line is the rendering under test.
// MEASURED: with the status left out of Action.String, this test is the only
// one in the suite that goes red.
func TestAFailedActionRendersTheCodeItCarries(t *testing.T) {
	refusal := Action{Kind: ActFailed, Reason: ReasonNak, Status: wire.StatusNoAddrsAvail, Note: "the server answered and gave nothing"}
	if got := refusal.String(); !strings.Contains(got, wire.StatusNoAddrsAvail.String()) {
		t.Errorf("the journal line %q does not name the code the refusal carries (%s)", got, wire.StatusNoAddrsAvail)
	}

	// The v4 shape, and every other failure: the zero is Success, nothing
	// refused this client, and the line must not grow a code out of nothing.
	timeout := Action{Kind: ActFailed, Reason: ReasonNoServer, Note: "no server answered"}
	if got, want := timeout.String(), "Failed "+ReasonNoServer.String()+": no server answered"; got != want {
		t.Errorf("a failure with no status renders as %q, want %q", got, want)
	}
	if strings.Contains(timeout.String(), wire.StatusSuccess.String()) {
		t.Errorf("a failure with no status names %s, which no server sent", wire.StatusSuccess)
	}
}

// TestAnIAThatFailsForAnotherReasonStillHandsOverItsAddress is the other
// direction of §18.2.10.1's selection rule, and without it the rule is only
// observed where it fires.
//
// The sentence names TWO codes and not every failure: "The client uses the
// addresses, delegated prefixes, and other information from any IAs that do
// not contain a Status Code option with the NoAddrsAvail or NoPrefixAvail
// status code." NoPrefixAvail is about an IA_PD, which this client does not
// send, so NoAddrsAvail is the whole of the rule here — and an IA that says
// something else and hands over a usable address has handed over a usable
// address. A guard widened to "any code that is not Success" would throw it
// away, report a refusal on an exchange that produced a lease, and nothing in
// the suite would have noticed: every other row drives the code the rule
// names.
func TestAnIAThatFailsForAnotherReasonStillHandsOverItsAddress(t *testing.T) {
	for _, tc := range []struct {
		name string
		code wire.StatusCode
	}{
		{
			// §18.2.10 answers an UnspecFail at the MESSAGE level by leaving
			// the schedule running; §21.4 scopes this one to the IA, where no
			// sentence takes the address away.
			name: "UnspecFail, which §18.2.10.1 does not name",
			code: wire.StatusUnspecFail,
		},
		{
			// IANA keeps allocating, and a client that treated every code it
			// has no constant for as "no address here" would lose a lease to
			// a status option it did not understand.
			name: "a code IANA has not allocated yet",
			code: wire.StatusCode(77),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := solicit6(t, testParams6())
			m.Step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255))
			s, acts := m.Step(at(3), 3, receivedV6(t, wire.MsgReply, uint32(capXIDRequest),
				optClientID(capDUID), optServerID(testServerDUID),
				optIANA(t, capIAID, 150, 240, []iaAddrSpec{{dnsmasqLeasedAddr, 300, 300}},
					optStatus(tc.code))))

			noRefusal(t, acts, "the IA said "+tc.code.String()+" and handed over a usable address")
			if s != State6DAD {
				t.Fatalf("the Reply left the machine in %s, want %s: the address the IA carried is not the one §18.2.10.1 takes away:%s", s, State6DAD, journalLines(acts))
			}
			s, acts = m.Step(at(4), 0, DADResult(netip.MustParseAddr(dnsmasqLeasedAddr), false))
			if s != State6Bound {
				t.Fatalf("the checked address left the machine in %s", s)
			}
			a, ok := find(acts, ActLeaseAcquired)
			if !ok {
				t.Fatalf("no lease was acquired from an IA whose code §18.2.10.1 does not name:%s", journalLines(acts))
			}
			if got, _ := a.Lease6.Addr(); got.String() != dnsmasqLeasedAddr {
				t.Errorf("the acquired lease carries %s, want %s", got, dnsmasqLeasedAddr)
			}
		})
	}
}
