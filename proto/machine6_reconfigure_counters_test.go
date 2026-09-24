// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// What this machine did with the Reconfigure messages it was handed, arm by
// arm: claymore666/docker-net-dhcp#925's "discard anything else and count it".
//
// EVERY ARM IS DRIVEN ALONE AND READ THROUGH ITS OWN CELL. A counter raised
// from one shared place would rise for every rule and distinguish none of
// them, which is the whole reason the issue asks for a count and not for the
// journal line that was already there.

// reconfCase is one arm: a machine, an event, and the cell that must rise by
// one. The machine is built by the row because most arms are only reachable
// from a particular state.
type reconfCase struct {
	name string
	want ReconfigureRefusal
	// build returns a machine parked where this arm is reachable. Anything it
	// counts on the way is absorbed by the before/after delta.
	build func(t *testing.T) *Machine6
	ev    func(t *testing.T) Event
	// say is a fragment of the journal line, so the count and the sentence are
	// asserted against each other and neither stands in for the other.
	say string
}

// badAuthOption is an Authentication option shorter than §21.11's fixed part,
// so DecodeAuth refuses it.
func badAuthOption() wire.OptionV6 {
	return wire.OptionV6{Code: wire.OptV6Auth, Data: []byte{3, 1, 0}}
}

// notRKAPAuthOption is a well-formed §21.11 Authentication option carrying a
// protocol §20.4.1 does not define, so it decodes and is not RKAP.
func notRKAPAuthOption() wire.OptionV6 {
	a := wire.Auth{Protocol: wire.AuthProtocolRKAP + 1, Algorithm: wire.AuthAlgorithmHMAC, RDM: wire.AuthRDMMonotonic}
	a.Info = make([]byte, 1+wire.RKAPValueLen)
	a.Info[0] = wire.RKAPTypeDigest
	return wire.OptionV6{Code: wire.OptV6Auth, Data: wire.EncodeAuth(a)}
}

// duringDAD is the window §18.2.11's premise excludes while the exchange that
// carried the key is already over: a key is recorded, msgType is 0, and the
// machine holds no usable configuration. It is the only way to reach the two
// arms that authenticate and then decline to act.
func duringDAD(t *testing.T) *Machine6 {
	t.Helper()
	m, _ := solicit6(t, testParams6())
	if s, _ := m.Step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255)); s != State6Requesting {
		t.Fatalf("the Advertise did not start a Request")
	}
	if s, _ := m.Step(at(3), 0, replyWithKey(t, uint32(capXIDRequest), dnsmasqLeasedAddr, testReconfKey)); s != State6DAD {
		t.Fatalf("the Reply did not start duplicate address detection")
	}
	return m
}

// reconfCases is every refusal arm §16.11, §18.2.11, §20.3 and §20.4 give this
// machine, one row each. AllReconfigureRefusals is what the set is checked
// against, so an arm added without a row here is a failure and not a gap.
func reconfCases() []reconfCase {
	keyed := func(t *testing.T) *Machine6 {
		t.Helper()
		return bindWithKey6(t, testParams6(), dnsmasqLeasedAddr, testReconfKey)
	}
	good := func() []wire.OptionV6 {
		return []wire.OptionV6{optClientID(capDUID), optServerID(testServerDUID)}
	}
	return []reconfCase{
		{
			name: "this client announced no Reconfigure Accept option",
			want: ReconfigureRefusalUnwilling,
			build: func(t *testing.T) *Machine6 {
				p := testParams6()
				p.AcceptReconfigure = false
				return bindWithKey6(t, p, dnsmasqLeasedAddr, testReconfKey)
			},
			ev:  func(t *testing.T) Event { return goodReconfigure(t, wire.MsgRenew, 1) },
			say: "announced no Reconfigure Accept option",
		},
		{
			name: "an exchange is already in flight",
			want: ReconfigureRefusalExchangeInFlight,
			build: func(t *testing.T) *Machine6 {
				m := bindWithKey6(t, testParams6(), dnsmasqLeasedAddr, testReconfKey)
				if s, _ := m.Step(at(10), 7, goodReconfigure(t, wire.MsgRenew, 1)); s != State6Renewing {
					t.Fatalf("the first Reconfigure did not start a Renew")
				}
				return m
			},
			ev:  func(t *testing.T) Event { return goodReconfigure(t, wire.MsgRebind, 2) },
			say: "ignored until it completes",
		},
		{
			name:  "a multicast destination",
			want:  ReconfigureRefusalNotUnicast,
			build: keyed,
			ev: func(t *testing.T) Event {
				return reconfigureEvent(t, netip.MustParseAddr("ff02::1:2"), testReconfKey, 1,
					optClientID(capDUID), optServerID(testServerDUID), optReconfMsg(t, wire.MsgRenew))
			},
			say: "unicast destination",
		},
		{
			name:  "no Server Identifier option",
			want:  ReconfigureRefusalNoServerID,
			build: keyed,
			ev: func(t *testing.T) Event {
				return reconfigureEvent(t, clientUnicast, testReconfKey, 1,
					optClientID(capDUID), optReconfMsg(t, wire.MsgRenew))
			},
			say: "no Server Identifier option",
		},
		{
			name:  "two Server Identifier options",
			want:  ReconfigureRefusalAmbiguousServerID,
			build: keyed,
			ev: func(t *testing.T) Event {
				return reconfigureEvent(t, clientUnicast, testReconfKey, 1,
					optClientID(capDUID), optServerID(testServerDUID), optServerID(otherServerDUID),
					optReconfMsg(t, wire.MsgRenew))
			},
			say: "the sender is ambiguous",
		},
		{
			name:  "no Client Identifier option",
			want:  ReconfigureRefusalNoClientID,
			build: keyed,
			ev: func(t *testing.T) Event {
				return reconfigureEvent(t, clientUnicast, testReconfKey, 1,
					optServerID(testServerDUID), optReconfMsg(t, wire.MsgRenew))
			},
			say: "no Client Identifier option",
		},
		{
			name:  "another client's Client Identifier",
			want:  ReconfigureRefusalForeignClientID,
			build: keyed,
			ev: func(t *testing.T) Event {
				return reconfigureEvent(t, clientUnicast, testReconfKey, 1,
					optClientID(otherServerDUID), optServerID(testServerDUID), optReconfMsg(t, wire.MsgRenew))
			},
			say: "not ours",
		},
		{
			name:  "no Reconfigure Message option",
			want:  ReconfigureRefusalNoReconfigureMessage,
			build: keyed,
			ev: func(t *testing.T) Event {
				return reconfigureEvent(t, clientUnicast, testReconfKey, 1, good()...)
			},
			say: "no Reconfigure Message option",
		},
		{
			name:  "a msg-type §21.19 does not give",
			want:  ReconfigureRefusalBadReconfigureMessage,
			build: keyed,
			ev: func(t *testing.T) Event {
				return reconfigureEvent(t, clientUnicast, testReconfKey, 1,
					append(good(), optReconfMsgRaw(7))...)
			},
			say: "Reconfigure Message option",
		},
		{
			name:  "no Authentication option",
			want:  ReconfigureRefusalNoAuth,
			build: keyed,
			ev: func(t *testing.T) Event {
				return receivedV6To(t, clientUnicast, wire.MsgReconfigure, 0x123456,
					append(good(), optReconfMsg(t, wire.MsgRenew))...)
			},
			say: "no Authentication option",
		},
		{
			name:  "an Authentication option that will not decode",
			want:  ReconfigureRefusalUnreadableAuth,
			build: keyed,
			ev: func(t *testing.T) Event {
				return receivedV6To(t, clientUnicast, wire.MsgReconfigure, 0x123456,
					append(good(), optReconfMsg(t, wire.MsgRenew), badAuthOption())...)
			},
			say: "Authentication option",
		},
		{
			name:  "two Authentication options, which §21 makes a singleton",
			want:  ReconfigureRefusalUnreadableAuth,
			build: keyed,
			ev: func(t *testing.T) Event {
				return receivedV6To(t, clientUnicast, wire.MsgReconfigure, 0x123456,
					append(good(), optReconfMsg(t, wire.MsgRenew), notRKAPAuthOption(), notRKAPAuthOption())...)
			},
			say: "Authentication option",
		},
		{
			name:  "an Authentication option that is not RKAP",
			want:  ReconfigureRefusalNotRKAP,
			build: keyed,
			ev: func(t *testing.T) Event {
				return receivedV6To(t, clientUnicast, wire.MsgReconfigure, 0x123456,
					append(good(), optReconfMsg(t, wire.MsgRenew), notRKAPAuthOption())...)
			},
			say: "is not RKAP",
		},
		{
			name: "a server that has sent this client no key",
			want: ReconfigureRefusalNoKey,
			build: func(t *testing.T) *Machine6 {
				return bind6(t, testParams6(), dnsmasqLeasedAddr)
			},
			ev:  func(t *testing.T) Event { return goodReconfigure(t, wire.MsgRenew, 1) },
			say: "no reconfigure key",
		},
		{
			name:  "a digest computed with another key",
			want:  ReconfigureRefusalBadDigest,
			build: keyed,
			ev: func(t *testing.T) Event {
				return reconfigureEvent(t, clientUnicast, mustHexBytes("00112233445566778899aabbccddeeff"), 1,
					append(good(), optReconfMsg(t, wire.MsgRenew))...)
			},
			say: "fails RKAP authentication",
		},
		{
			name: "a replay detection value this server has already used",
			want: ReconfigureRefusalReplay,
			build: func(t *testing.T) *Machine6 {
				m := bindWithKey6(t, testParams6(), dnsmasqLeasedAddr, testReconfKey)
				if s, _ := m.Step(at(10), 7, goodReconfigure(t, wire.MsgRenew, 9)); s != State6Renewing {
					t.Fatalf("the accepted Reconfigure did not start a Renew")
				}
				replyToRenew(t, m)
				return m
			},
			ev:  func(t *testing.T) Event { return goodReconfigure(t, wire.MsgRenew, 9) },
			say: "already used",
		},
		{
			name:  "a Renew asked of a client that holds no lease",
			want:  ReconfigureRefusalNoLease,
			build: duringDAD,
			ev:    func(t *testing.T) Event { return goodReconfigure(t, wire.MsgRenew, 1) },
			say:   "holds configuration",
		},
		{
			name:  "an Information-request asked of a client that holds nothing",
			want:  ReconfigureRefusalNoConfiguration,
			build: duringDAD,
			ev:    func(t *testing.T) Event { return goodReconfigure(t, wire.MsgInformationRequest, 1) },
			say:   "holds configuration",
		},
	}
}

// TestEveryReconfigureRefusalArmRaisesItsOwnCounter drives each arm ALONE and
// reads the cell that arm names, so an arm whose raise was deleted fails its
// own row and no other, and two arms sharing one cell fail each other's.
//
// The journal line is asserted beside the cell. The count says a rule fired
// and the sentence says which; a test that read only one of them would pass
// against a machine where the other had gone.
func TestEveryReconfigureRefusalArmRaisesItsOwnCounter(t *testing.T) {
	for _, tc := range reconfCases() {
		t.Run(tc.name, func(t *testing.T) {
			m := tc.build(t)
			before := m.ReconfigureCounters()
			_, acts := m.Step(at(30), 7, tc.ev(t))
			after := m.ReconfigureCounters()

			if got := after.Refused[tc.want] - before.Refused[tc.want]; got != 1 {
				t.Errorf("Refused[%v] rose by %d, want 1%s", tc.want, got, journalLines(acts))
			}
			if got := after.RefusedTotal() - before.RefusedTotal(); got != 1 {
				t.Errorf("RefusedTotal rose by %d, want 1: another arm fired too%s", got, journalLines(acts))
			}
			if after.Accepted != before.Accepted {
				t.Errorf("Accepted rose on a refusal, from %d to %d%s", before.Accepted, after.Accepted, journalLines(acts))
			}
			if !journalHas(acts, tc.say) {
				t.Errorf("the refusal counted as %v was not journalled with %q%s", tc.want, tc.say, journalLines(acts))
			}
		})
	}
}

// TestEveryReconfigureRefusalIsDeclaredCountedAndNamed holds the enumeration,
// the array that is indexed by it, the names and the table above to each other.
//
// WITHOUT IT THE ENUMERATION IS AN UNRUN CHECKLIST: a reason can be declared,
// given a sentence and never raised anywhere, and every other test in this file
// still passes.
func TestEveryReconfigureRefusalIsDeclaredCountedAndNamed(t *testing.T) {
	all := AllReconfigureRefusals()
	if len(all) != int(numReconfigureRefusal)-1 {
		t.Fatalf("AllReconfigureRefusals lists %d reasons and the enumeration declares %d: the array and the domain have parted company",
			len(all), int(numReconfigureRefusal)-1)
	}
	seen := map[ReconfigureRefusal]bool{}
	for _, r := range all {
		if seen[r] {
			t.Errorf("%v is listed twice", r)
		}
		seen[r] = true
		if r == ReconfigureRefusalNone {
			t.Error("ReconfigureRefusalNone is not a refusal and must not be in the domain")
		}
		// The predicate is the FALLBACK's shape and not one fallback value: a
		// reason with no case of its own returns "reconfigure-refusal(N)" for
		// its own N, so comparing against any single rendering would be a
		// check with one possible verdict.
		name := r.String()
		if name == "" || strings.HasPrefix(name, "reconfigure-refusal(") {
			t.Errorf("reason %d has no sentence of its own: %q", uint8(r), name)
		}
	}

	driven := map[ReconfigureRefusal]bool{}
	for _, tc := range reconfCases() {
		driven[tc.want] = true
	}
	// The one arm no event can reach, driven directly below.
	driven[ReconfigureRefusalUndefinedMessage] = true
	for _, r := range all {
		if !driven[r] {
			t.Errorf("%v is declared and counted and nothing drives it", r)
		}
	}
}

// TestAnUndefinedReconfigureMessageTypeIsCounted drives the arm no Reconfigure
// can reach: ReconfigureMessage refuses every msg-type outside §21.19's three,
// so respondToReconfigure's default is unreachable through Step and is called
// here directly.
//
// IT IS COUNTED AND NOT LEFT AS A DECLARED-AND-DEAD CELL. Step's rule is
// that every arm has a defined result; a cell that nothing can raise is a cell
// nothing can notice going wrong when a later change makes it reachable.
func TestAnUndefinedReconfigureMessageTypeIsCounted(t *testing.T) {
	m := bindWithKey6(t, testParams6(), dnsmasqLeasedAddr, testReconfKey)
	var out actions
	before := m.ReconfigureCounters()
	if m.respondToReconfigure(at(30), 7, wire.MsgAdvertise, testServerDUID, &out) {
		t.Fatal("a msg-type §21.19 does not define was answered")
	}
	after := m.ReconfigureCounters()
	if got := after.Refused[ReconfigureRefusalUndefinedMessage] - before.Refused[ReconfigureRefusalUndefinedMessage]; got != 1 {
		t.Errorf("Refused[%v] rose by %d, want 1%s", ReconfigureRefusalUndefinedMessage, got, journalLines(out.list))
	}
	if after.Accepted != before.Accepted {
		t.Error("an undefined msg-type counted as an acceptance")
	}
}

// TestEveryReconfigureAcceptArmRaisesTheAcceptedCounter is the other half of
// the partition: §21.19's three msg-types, each answered, each counted once.
//
// THE OUTSIDE EVIDENCE IS THE MESSAGE THAT LEFT, not the counter. A machine
// that raised Accepted and sent nothing would pass a test that read the number
// alone, and that is the shape this counter is most likely to acquire.
func TestEveryReconfigureAcceptArmRaisesTheAcceptedCounter(t *testing.T) {
	for _, tc := range []struct {
		kind  wire.MessageTypeV6
		state State6
		sends wire.MessageTypeV6
	}{
		{wire.MsgRenew, State6Renewing, wire.MsgRenew},
		{wire.MsgRebind, State6Rebinding, wire.MsgRebind},
		{wire.MsgInformationRequest, State6InfoRequesting, wire.MsgInformationRequest},
	} {
		t.Run(tc.kind.String(), func(t *testing.T) {
			m := bindWithKey6(t, testParams6(), dnsmasqLeasedAddr, testReconfKey)
			s, acts := m.Step(at(30), 7, goodReconfigure(t, tc.kind, 1))
			if s != tc.state {
				t.Fatalf("a Reconfigure naming %s left the machine in %s, want %s%s", tc.kind, s, tc.state, journalLines(acts))
			}
			mustSendV6(t, acts, tc.sends)
			c := m.ReconfigureCounters()
			if c.Accepted != 1 {
				t.Errorf("Accepted = %d after one answered Reconfigure, want 1", c.Accepted)
			}
			if c.RefusedTotal() != 0 {
				t.Errorf("RefusedTotal = %d on an answered Reconfigure, want 0", c.RefusedTotal())
			}
		})
	}
}

// TestAcceptedAndRefusedPartitionEveryReconfigure is the claim
// ReconfigureCounters makes about itself: every Reconfigure that reaches this
// ring raises exactly one of the two.
//
// IT IS WHAT MAKES THE SUM READABLE. Ring 2 folds Refused into one number for
// an operator, and a message that fell through both counters would leave that
// operator subtracting two numbers that do not add up to what arrived, with
// nothing to say so.
func TestAcceptedAndRefusedPartitionEveryReconfigure(t *testing.T) {
	for _, tc := range reconfCases() {
		t.Run(tc.name, func(t *testing.T) {
			m := tc.build(t)
			before := m.ReconfigureCounters()
			m.Step(at(30), 7, tc.ev(t))
			after := m.ReconfigureCounters()
			delivered := uint64(1)
			got := (after.Accepted - before.Accepted) + (after.RefusedTotal() - before.RefusedTotal())
			if got != delivered {
				t.Errorf("one Reconfigure moved the counters by %d, want exactly %d: it is in both or in neither", got, delivered)
			}
		})
	}
	t.Run("an answered one", func(t *testing.T) {
		m := bindWithKey6(t, testParams6(), dnsmasqLeasedAddr, testReconfKey)
		m.Step(at(30), 7, goodReconfigure(t, wire.MsgRenew, 1))
		c := m.ReconfigureCounters()
		if c.Accepted+c.RefusedTotal() != 1 {
			t.Errorf("one answered Reconfigure moved the counters by %d, want 1", c.Accepted+c.RefusedTotal())
		}
	})
}

// TestAResumedClientIsKeylessUntilAReplyCarriesAKey is the bound proto/doc.go
// and Machine6.reconf state, driven by this test and not asserted in prose.
// The sentence they used to carry — "the cost is one refused Reconfigure per
// restart" — was false: a resumed client holds no key at all, and it refuses
// every Reconfigure until some Reply hands it one.
//
// RFC 9915 Appendix B, Table 5, gives the Reconfigure Accept column a mark for
// Solicit, Advertise, Request, Renew, Rebind, Reply and Information-request,
// and NO mark for Confirm — so the first message a resumed client sends cannot
// announce willingness. §20.4.2: "The server selects a reconfigure key for a
// client during the Request/Reply, Solicit/Reply, or Information-request/Reply
// message exchange." Confirm/Reply is not among them, so the resume itself
// hands over no key.
//
// WHAT ENDS THE SPAN IS A REPLY CARRYING A KEY, WHICHEVER EXCHANGE IT ANSWERS,
// and the last arm below is that arm. §20.4.2 constrains when a SERVER selects
// a key; it says nothing about what a client records, and this client records
// the key on any accepted Reply — including a Renew's, which Table 5 does mark
// for Reconfigure Accept. TestALaterReplysKeyReplacesTheOldOneAndAKeylessReplyKeepsIt
// pins that recording rule; here it is the escape from the keyless span. So
// the span is the whole life of the resumed lease only on a link whose server
// sends a key nowhere but the three exchanges §20.4.2 names.
func TestAResumedClientIsKeylessUntilAReplyCarriesAKey(t *testing.T) {
	// A machine rebuilt from the record a caller persisted after a run that
	// held this lease. The key is not in that record, by design.
	m, acts := confirming6(t, testParams6())
	sent := mustSendV6(t, acts, wire.MsgConfirm)
	if ok, err := sent.Options.ReconfigureAccept(); ok || err != nil {
		t.Errorf("the Confirm announces Reconfigure Accept (%v, %v); Appendix B Table 5 gives Confirm no mark for it", ok, err)
	}

	// The server answers and the client is bound again, holding the same
	// address it held before the restart — and no key.
	if s, acts := m.Step(at(2), 0, reply(t, sent.XID, dnsmasqLeasedAddr)); s != State6DAD {
		t.Fatalf("the Reply to the Confirm left the machine in %s, want %s%s", s, State6DAD, journalLines(acts))
	}
	if s, acts := m.Step(at(3), 0, DADResult(netip.MustParseAddr(dnsmasqLeasedAddr), false)); s != State6Bound {
		t.Fatalf("a clean DAD result left the resumed machine in %s, want %s%s", s, State6Bound, journalLines(acts))
	}

	// Every Reconfigure the server sends over that span is refused, with a
	// rising replay detection value so that §20.3 is not what answers.
	for i := uint64(1); i <= 3; i++ {
		if s, acts := m.Step(at(10+int64(i)), 7, goodReconfigure(t, wire.MsgRenew, i)); s != State6Bound {
			t.Fatalf("Reconfigure %d left the machine in %s, want it refused in %s%s", i, s, State6Bound, journalLines(acts))
		}
	}
	c := m.ReconfigureCounters()
	if c.Accepted != 0 {
		t.Errorf("a resumed client accepted %d Reconfigure(s) with no key recorded", c.Accepted)
	}
	if c.Refused[ReconfigureRefusalNoKey] != 3 {
		t.Errorf("Refused[%v] = %d after three Reconfigures, want 3: the cost is not one per restart",
			ReconfigureRefusalNoKey, c.Refused[ReconfigureRefusalNoKey])
	}

	// THE SPAN ENDS AT A RENEW'S REPLY, AND THAT IS THE POINT OF THIS ARM.
	// T1 fires, the Renew announces Reconfigure Accept the way Table 5 marks
	// it, and the Reply to it carries an Authentication option with a key.
	if s, acts := m.Step(at(20), 0, TimerFired(Timer6Renew)); s != State6Renewing {
		t.Fatalf("T1 left the resumed machine in %s, want %s%s", s, State6Renewing, journalLines(acts))
	}
	xid := lastSentV6(t, m, at(21))
	if s, acts := m.Step(at(22), 0, replyWithKey(t, xid, dnsmasqLeasedAddr, testReconfKey)); s != State6Bound {
		t.Fatalf("the Reply carrying a key left the machine in %s, want %s%s", s, State6Bound, journalLines(acts))
	}
	if s, acts := m.Step(at(30), 7, goodReconfigure(t, wire.MsgRenew, 4)); s != State6Renewing {
		t.Fatalf("a Reconfigure signed with the key that Reply carried left the machine in %s, want %s%s", s, State6Renewing, journalLines(acts))
	}
	if c := m.ReconfigureCounters(); c.Accepted != 1 {
		t.Errorf("Accepted = %d after the Reply that ended the keyless span, want 1", c.Accepted)
	}

	// The other escape, and the one §20.4.2 does name: an exchange whose
	// request carries the option in the first place.
	for _, typ := range []wire.MessageTypeV6{wire.MsgSolicit, wire.MsgRequest6, wire.MsgInformationRequest} {
		m.server = testServerDUID
		msg, err := m.build(at(100), typ)
		if err != nil {
			t.Fatalf("build(%s): %v", typ, err)
		}
		if ok, err := msg.Options.ReconfigureAccept(); !ok || err != nil {
			t.Errorf("the %s does not announce Reconfigure Accept (%v, %v); it is the way out of the keyless span", typ, ok, err)
		}
	}
}

// TestAKeyInAReplyThisClientRefusesDoesNotEndTheKeylessSpan is the other half
// of the sentence above, and the word it turns on is ACCEPTED.
//
// §20.4.3: "The client will receive a reconfigure key from the server in an
// Authentication option (see Section 21.11) in the initial Reply message from
// the server." takeReply records it where the Reply is taken, and not on every
// Reply that reaches that function: §18.2.10's UnspecFail arm, its NotOnLink
// arm, a malformed Status Code option and the no-usable-address path all
// return before the recording. A Reply carrying a key that this client does
// not act on leaves the span exactly where it was, and the next signed
// Reconfigure is still refused for want of a key.
func TestAKeyInAReplyThisClientRefusesDoesNotEndTheKeylessSpan(t *testing.T) {
	m, acts := confirming6(t, testParams6())
	sent := mustSendV6(t, acts, wire.MsgConfirm)
	if s, acts := m.Step(at(2), 0, reply(t, sent.XID, dnsmasqLeasedAddr)); s != State6DAD {
		t.Fatalf("the Reply to the Confirm left the machine in %s, want %s%s", s, State6DAD, journalLines(acts))
	}
	if s, acts := m.Step(at(3), 0, DADResult(netip.MustParseAddr(dnsmasqLeasedAddr), false)); s != State6Bound {
		t.Fatalf("a clean DAD result left the resumed machine in %s, want %s%s", s, State6Bound, journalLines(acts))
	}

	if s, acts := m.Step(at(20), 0, TimerFired(Timer6Renew)); s != State6Renewing {
		t.Fatalf("T1 left the resumed machine in %s, want %s%s", s, State6Renewing, journalLines(acts))
	}
	xid := lastSentV6(t, m, at(21))

	// §18.2.10: an UnspecFail Reply leaves the exchange running, so this Reply
	// is NOT the one the client acted on, key or no key.
	keyed := receivedV6(t, wire.MsgReply, xid,
		optClientID(capDUID), optServerID(testServerDUID),
		optStatus(wire.StatusUnspecFail), optReconfKey(t, testReconfKey))
	if s, acts := m.Step(at(22), 0, keyed); s != State6Renewing {
		t.Fatalf("an UnspecFail Reply left the machine in %s, want the Renew exchange unchanged in %s%s", s, State6Renewing, journalLines(acts))
	}

	// The exchange then ends on an ordinary Reply that carries no key at all.
	if s, acts := m.Step(at(24), 0, reply(t, xid, dnsmasqLeasedAddr)); s != State6Bound {
		t.Fatalf("the Reply that ended the Renew left the machine in %s, want %s%s", s, State6Bound, journalLines(acts))
	}

	if s, acts := m.Step(at(30), 7, goodReconfigure(t, wire.MsgRenew, 1)); s != State6Bound {
		t.Fatalf("a Reconfigure signed with the key of a REFUSED Reply left the machine in %s, want it refused in %s%s", s, State6Bound, journalLines(acts))
	}
	c := m.ReconfigureCounters()
	if c.Accepted != 0 {
		t.Errorf("Accepted = %d: the key came in a Reply this client did not act on", c.Accepted)
	}
	if c.Refused[ReconfigureRefusalNoKey] != 1 {
		t.Errorf("Refused[%v] = %d, want 1", ReconfigureRefusalNoKey, c.Refused[ReconfigureRefusalNoKey])
	}
}
