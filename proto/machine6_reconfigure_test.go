// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"net/netip"
	"strings"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// RFC 9915 §16.11 and §18.2.11 at the machine: what a Reconfigure must carry
// to be acted on, and what the client does when it is.
//
// EVERY DISCARD RULE IS DRIVEN ALONE. §16.11 lists six conditions and a
// fixture that violates two of them proves nothing about either: the rule that
// was deleted is covered by the rule that was not. Each test below starts from
// goodReconfigure — which passes every rule — and breaks exactly one.

// testReconfKey is the 128-bit reconfigure key of §20.4.1, distinct from every
// DUID in this suite so a helper that signed with the wrong buffer produces a
// digest that does not verify.
var testReconfKey = mustHexBytes("0f0e0d0c0b0a09080706050403020100")

// otherServerDUID is a second server, for §20.3's "that same server".
var otherServerDUID = mustHexBytes("00010001322ecbbfaabbccddeeff")

// clientUnicast is an address a Reconfigure can be unicast TO. §16.11's first
// bullet is about the destination the datagram carried, so the value only has
// to be a unicast address; it is the client's own in any real capture.
var clientUnicast = netip.MustParseAddr("fd00:99::183")

// ---------------------------------------------------------------- fixtures --

// optReconfMsg is §21.19's option, built through the codec so a msg-type the
// codec refuses to encode cannot appear here by accident.
func optReconfMsg(t *testing.T, typ wire.MessageTypeV6) wire.OptionV6 {
	t.Helper()
	v, err := wire.EncodeReconfigureMessage(typ)
	if err != nil {
		t.Fatalf("EncodeReconfigureMessage(%s): %v", typ, err)
	}
	return wire.OptionV6{Code: wire.OptV6ReconfMsg, Data: v}
}

// optReconfMsgRaw is §21.19's option with arbitrary contents, for the msg-type
// values the codec will not encode.
func optReconfMsgRaw(v ...byte) wire.OptionV6 {
	return wire.OptionV6{Code: wire.OptV6ReconfMsg, Data: v}
}

// optReconfKey is the Authentication option a Reply carries: §20.4.1's Type 1,
// "Reconfigure key value (used in the Reply message)".
func optReconfKey(t *testing.T, key []byte) wire.OptionV6 {
	t.Helper()
	v, err := wire.EncodeRKAPAuth(wire.RKAPTypeKey, key, 0)
	if err != nil {
		t.Fatalf("EncodeRKAPAuth: %v", err)
	}
	return wire.OptionV6{Code: wire.OptV6Auth, Data: v}
}

// digestSpanHere finds §20.4.1's 16-octet Value inside an encoded message
// WITHOUT asking the code under test where it is.
//
// wire.rkapDigestSpan is the function a Reconfigure is verified with; a
// fixture that called it would sign whatever span that function believes in,
// and a fixture and a subject that agree on a wrong answer agree silently.
// This walk is derived from §21.11's layout instead: option-code 11,
// option-len, then protocol, algorithm, RDM, the eight octets of replay
// detection, then the authentication information, whose first octet is
// §20.4.1's Type and whose next sixteen are the Value.
func digestSpanHere(t *testing.T, raw []byte) (int, int) {
	t.Helper()
	for i := 4; i+4 <= len(raw); {
		code := int(raw[i])<<8 | int(raw[i+1])
		n := int(raw[i+2])<<8 | int(raw[i+3])
		i += 4
		if n > len(raw)-i {
			t.Fatalf("option %d overruns the message", code)
		}
		if code == int(wire.OptV6Auth) {
			start := i + 1 + 1 + 1 + 8 + 1
			return start, start + md5.Size
		}
		i += n
	}
	t.Fatalf("no Authentication option in %x", raw)
	return 0, 0
}

// signReconfigure is §20.4.3 applied by the fixture: "the client computes an
// HMAC-MD5 over the Reconfigure message, with zeroes substituted for the
// HMAC-MD5 field, using the reconfigure key received from the server."
func signReconfigure(t *testing.T, raw, key []byte) []byte {
	t.Helper()
	start, end := digestSpanHere(t, raw)
	zeroed := append([]byte(nil), raw...)
	for i := start; i < end; i++ {
		zeroed[i] = 0
	}
	mac := hmac.New(md5.New, key)
	mac.Write(zeroed)
	out := append([]byte(nil), raw...)
	copy(out[start:end], mac.Sum(nil))
	return out
}

// reconfigureSigned builds a Reconfigure carrying an Authentication option
// signed with key, and hands back the octets and the decoded message.
func reconfigureSigned(t *testing.T, key []byte, replay uint64, opts ...wire.OptionV6) (*wire.MessageV6, []byte) {
	t.Helper()
	// The placeholder is not zero, so a signer that forgot to zero the field
	// signs different octets from the ones the verifier zeroes and is refused.
	auth, err := wire.EncodeRKAPAuth(wire.RKAPTypeDigest, bytes.Repeat([]byte{0xa5}, md5.Size), replay)
	if err != nil {
		t.Fatalf("EncodeRKAPAuth: %v", err)
	}
	all := append(append([]wire.OptionV6(nil), opts...), wire.OptionV6{Code: wire.OptV6Auth, Data: auth})
	raw, err := wire.EncodeV6(&wire.MessageV6{Type: wire.MsgReconfigure, XID: 0xbadbad & (wire.MaxXID6 - 1), Options: all})
	if err != nil {
		t.Fatalf("EncodeV6: %v", err)
	}
	raw = signReconfigure(t, raw, key)
	msg, err := wire.DecodeV6(raw)
	if err != nil {
		t.Fatalf("DecodeV6: %v", err)
	}
	return msg, raw
}

// reconfigureEvent is a Reconfigure delivered to dst.
func reconfigureEvent(t *testing.T, dst netip.Addr, key []byte, replay uint64, opts ...wire.OptionV6) Event {
	t.Helper()
	msg, raw := reconfigureSigned(t, key, replay, opts...)
	return ReceivedV6To(msg, raw, dst)
}

// goodReconfigure passes every §16.11 rule and names typ.
func goodReconfigure(t *testing.T, typ wire.MessageTypeV6, replay uint64) Event {
	t.Helper()
	return reconfigureEvent(t, clientUnicast, testReconfKey, replay,
		optClientID(capDUID), optServerID(testServerDUID), optReconfMsg(t, typ))
}

// replyWithKey is reply() plus §20.4.3's reconfigure key.
func replyWithKey(t *testing.T, xid uint32, addr string, key []byte) Event {
	t.Helper()
	return receivedV6(t, wire.MsgReply, xid,
		optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 150, 240, []iaAddrSpec{{addr, 300, 300}}),
		optReconfKey(t, key))
}

// bindWithKey6 is bind6 whose Reply carried a reconfigure key.
func bindWithKey6(t *testing.T, p Params6, addr string, key []byte) *Machine6 {
	t.Helper()
	m, _ := solicit6(t, p)
	if s, _ := m.Step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255)); s != State6Requesting {
		t.Fatalf("a preference-255 Advertise left the machine in %s", s)
	}
	if s, _ := m.Step(at(3), 0, replyWithKey(t, uint32(capXIDRequest), addr, key)); s != State6DAD {
		t.Fatalf("the Reply left the machine in %s, want %s", s, State6DAD)
	}
	if s, _ := m.Step(at(4), 0, DADResult(netip.MustParseAddr(addr), false)); s != State6Bound {
		t.Fatalf("a clean DAD result left the machine in %s, want %s", s, State6Bound)
	}
	return m
}

// ------------------------------------------------------------ §18.2.11 --

// TestAReconfigureNamingRenewStartsARenew is the control every discard test
// below is a single mutation of: if this one stops passing, none of them mean
// anything.
//
// §18.2.11: "Upon receipt of a valid Reconfigure message, the client responds
// with a Renew message, a Rebind message, or an Information-request message as
// indicated by the Reconfigure Message option (see Section 21.19)."
func TestAReconfigureNamingRenewStartsARenew(t *testing.T) {
	m := bindWithKey6(t, testParams6(), dnsmasqLeasedAddr, testReconfKey)
	s, acts := m.Step(at(10), 7, goodReconfigure(t, wire.MsgRenew, 1))
	if s != State6Renewing {
		t.Fatalf("an authenticated Reconfigure left the machine in %s, want %s%s", s, State6Renewing, journalLines(acts))
	}
	mustSendV6(t, acts, wire.MsgRenew)
}

// TestAReconfigureNamingRebindStartsARebind is the reviewer's point 2: §21.19
// gives "msg-type: 5 for Renew message, 6 for Rebind message, 11 for
// Information-request message. A 1-octet unsigned integer.", so msg-type 6 is
// as valid as msg-type 5 and a client that only honoured the
// Renew would silently ignore a server asking to be taken out of the loop.
func TestAReconfigureNamingRebindStartsARebind(t *testing.T) {
	m := bindWithKey6(t, testParams6(), dnsmasqLeasedAddr, testReconfKey)
	s, acts := m.Step(at(10), 7, goodReconfigure(t, wire.MsgRebind, 1))
	if s != State6Rebinding {
		t.Fatalf("a Reconfigure naming Rebind left the machine in %s, want %s%s", s, State6Rebinding, journalLines(acts))
	}
	sent := mustSendV6(t, acts, wire.MsgRebind)
	// §18.2.5: "The client does not include the Server Identifier option (see
	// Section 21.3) in the Rebind message." A Rebind that named the server
	// would be a Renew with the wrong name on it.
	if _, ok := sent.Options.First(wire.OptV6ServerID); ok {
		t.Error("the Rebind carries a Server Identifier option (§18.2.5)")
	}
}

// TestAReconfigureNamingInformationRequestKeepsTheLease drives §21.19's third
// msg-type from BOUND6 and pins what happens to the address while the
// stateless exchange runs.
//
// THE LEASE IS THE POINT. An Information-request carries no address; a client
// that answered one by leaving BOUND6 for good would have thrown its binding's
// T1 and T2 into a state that ignores them, and the lease would run to its
// valid lifetime and be withdrawn — because a server asked for a DNS update.
func TestAReconfigureNamingInformationRequestKeepsTheLease(t *testing.T) {
	m := bindWithKey6(t, testParams6(), dnsmasqLeasedAddr, testReconfKey)
	s, acts := m.Step(at(10), 7, goodReconfigure(t, wire.MsgInformationRequest, 1))
	if s != State6InfoRequesting {
		t.Fatalf("a Reconfigure naming Information-request left the machine in %s, want %s%s", s, State6InfoRequesting, journalLines(acts))
	}
	sent := mustSendV6(t, acts, wire.MsgInformationRequest)
	// §18.2.6: "When responding to a Reconfigure, the client MUST include a
	// Server Identifier option (see Section 21.3) with the identifier from the
	// Reconfigure message to which the client is responding."
	sid, ok := sent.Options.First(wire.OptV6ServerID)
	if !ok {
		t.Fatalf("the Information-request answering a Reconfigure carries no Server Identifier (§18.2.6)")
	}
	if !bytes.Equal(sid, testServerDUID) {
		t.Errorf("the Server Identifier is %x, want the Reconfigure's %x (§18.2.6)", sid, testServerDUID)
	}
	if l, ok := m.Lease(); !ok || len(l.Addrs) == 0 {
		t.Fatalf("the lease was dropped by a stateless Reconfigure: %v %v", l, ok)
	}

	s, acts = m.Step(at(11), 0, receivedV6(t, wire.MsgReply, sent.XID,
		optClientID(capDUID), optServerID(testServerDUID),
		optU32(wire.OptV6InfoRefresh, 3600)))
	if s != State6Bound {
		t.Fatalf("the Reply to the Reconfigure's Information-request left the machine in %s, want %s%s", s, State6Bound, journalLines(acts))
	}
	if l, ok := m.Lease(); !ok || len(l.Addrs) == 0 {
		t.Fatalf("the lease was dropped when the stateless exchange ended: %v %v", l, ok)
	}
}

// TestTheLeaseOutranksAReconfiguresInformationRequest drives the window the
// test above opens: T1 falls due while the machine is in the detour.
//
// §18.2.4 gives the renewal a time — "At time T1, the client initiates a
// Renew/Reply message exchange to extend the lifetimes on any leases in the
// IA." — and nothing in §18.2.11 suspends it.
func TestTheLeaseOutranksAReconfiguresInformationRequest(t *testing.T) {
	for _, tc := range []struct {
		name  string
		timer TimerID
		want  State6
		msg   wire.MessageTypeV6
	}{
		{"T1", Timer6Renew, State6Renewing, wire.MsgRenew},
		{"T2", Timer6Rebind, State6Rebinding, wire.MsgRebind},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := bindWithKey6(t, testParams6(), dnsmasqLeasedAddr, testReconfKey)
			if s, _ := m.Step(at(10), 7, goodReconfigure(t, wire.MsgInformationRequest, 1)); s != State6InfoRequesting {
				t.Fatalf("the Reconfigure left the machine in %s", s)
			}
			s, acts := m.Step(at(20), 0, TimerFired(tc.timer))
			if s != tc.want {
				t.Fatalf("%s firing during the detour left the machine in %s, want %s%s", tc.timer, s, tc.want, journalLines(acts))
			}
			mustSendV6(t, acts, tc.msg)
		})
	}
}

// TestTheRefreshTimerIsHonouredAfterTheDetour closes the other end of the
// detour: takeConfig arms §21.23's refresh time and the machine is back in
// BOUND6 when it falls due, so BOUND6 has to know what it means.
func TestTheRefreshTimerIsHonouredAfterTheDetour(t *testing.T) {
	m := bindWithKey6(t, testParams6(), dnsmasqLeasedAddr, testReconfKey)
	if s, _ := m.Step(at(10), 7, goodReconfigure(t, wire.MsgInformationRequest, 1)); s != State6InfoRequesting {
		t.Fatal("the Reconfigure did not start an Information-request")
	}
	sent := lastSentV6(t, m, at(10))
	if s, _ := m.Step(at(11), 0, receivedV6(t, wire.MsgReply, sent,
		optClientID(capDUID), optServerID(testServerDUID),
		optU32(wire.OptV6InfoRefresh, 3600))); s != State6Bound {
		t.Fatal("the detour did not return to BOUND6")
	}
	if s, acts := m.Step(at(4000), 0, TimerFired(Timer6Refresh)); s != State6Bound {
		t.Fatalf("the refresh timer left BOUND6 in %s%s", s, journalLines(acts))
	} else if !journalHas(acts, "information refresh time elapsed") {
		t.Errorf("the refresh timer was ignored in %s%s", State6Bound, journalLines(acts))
	}
	s, acts := m.Step(at(4001), 0, TimerFired(Timer6Delay))
	if s != State6InfoRequesting {
		t.Fatalf("the refresh delay left the machine in %s%s", s, journalLines(acts))
	}
	req := mustSendV6(t, acts, wire.MsgInformationRequest)
	// §18.2.6's MUST is scoped: "When responding to a Reconfigure, the client
	// MUST include a Server Identifier option (see Section 21.3) with the
	// identifier from the Reconfigure message to which the client is
	// responding." A refresh is not responding to a Reconfigure, so the
	// identifier the previous exchange carried must not still be riding along.
	if _, ok := req.Options.First(wire.OptV6ServerID); ok {
		t.Error("a refresh Information-request carries the previous Reconfigure's Server Identifier (§18.2.6)")
	}
}

// lastSentV6 returns the transaction id of the message the machine last sent,
// by making it retransmit.
func lastSentV6(t *testing.T, m *Machine6, now Instant) uint32 {
	t.Helper()
	_, acts := m.Step(now+Instant(Second), 0, TimerFired(Timer6Retransmit))
	for _, a := range acts {
		if a.Kind == ActSendV6 && a.MsgV6 != nil {
			return a.MsgV6.XID
		}
	}
	t.Fatal("the machine sent nothing when the retransmission timer fired")
	return 0
}

// --------------------------------------------------------------- §16.11 --

// TestEveryReconfigureDiscardRuleFiresOnItsOwn is §16.11's list, one row per
// bullet, each row the control fixture with exactly one thing wrong.
//
// §16.11, verbatim, bullets marked with the RFC's own asterisks: "Clients MUST
// discard any Reconfigure message that meets any of the following conditions:
// * the message was not unicast to the client. * the message does not include
// a Server Identifier option (see Section 21.3). * the message does not
// include a Client Identifier option (see Section 21.2) that contains the
// client's DUID. * the message does not include a Reconfigure Message option
// (see Section 21.19). * the Reconfigure Message option msg-type is not a
// valid value. * the message does not include authentication (such as RKAP;
// see Section 20.4) or fails authentication validation."
func TestEveryReconfigureDiscardRuleFiresOnItsOwn(t *testing.T) {
	good := []wire.OptionV6{optClientID(capDUID), optServerID(testServerDUID), optReconfMsg(t, wire.MsgRenew)}

	cases := []struct {
		name string
		ev   func(t *testing.T) Event
		say  string
	}{
		{"multicast destination", func(t *testing.T) Event {
			return reconfigureEvent(t, netip.MustParseAddr("ff02::1:2"), testReconfKey, 1, good...)
		}, "unicast"},
		{"unspecified destination", func(t *testing.T) Event {
			return reconfigureEvent(t, netip.IPv6Unspecified(), testReconfKey, 1, good...)
		}, "unicast"},
		{"no destination reported", func(t *testing.T) Event {
			msg, raw := reconfigureSigned(t, testReconfKey, 1, good...)
			return ReceivedV6(msg, raw)
		}, "unicast"},
		{"no Server Identifier", func(t *testing.T) Event {
			return reconfigureEvent(t, clientUnicast, testReconfKey, 1,
				optClientID(capDUID), optReconfMsg(t, wire.MsgRenew))
		}, "no Server Identifier"},
		{"no Client Identifier", func(t *testing.T) Event {
			return reconfigureEvent(t, clientUnicast, testReconfKey, 1,
				optServerID(testServerDUID), optReconfMsg(t, wire.MsgRenew))
		}, "no Client Identifier"},
		{"somebody else's Client Identifier", func(t *testing.T) Event {
			return reconfigureEvent(t, clientUnicast, testReconfKey, 1,
				optClientID(otherServerDUID), optServerID(testServerDUID), optReconfMsg(t, wire.MsgRenew))
		}, "not ours"},
		{"no Reconfigure Message option", func(t *testing.T) Event {
			return reconfigureEvent(t, clientUnicast, testReconfKey, 1,
				optClientID(capDUID), optServerID(testServerDUID))
		}, "no Reconfigure Message option"},
		{"msg-type that is not one of §21.19's three", func(t *testing.T) Event {
			return reconfigureEvent(t, clientUnicast, testReconfKey, 1,
				optClientID(capDUID), optServerID(testServerDUID), optReconfMsgRaw(7))
		}, "Reconfigure Message option"},
		{"no Authentication option", func(t *testing.T) Event {
			return receivedV6To(t, clientUnicast, wire.MsgReconfigure, 0x123456, good...)
		}, "no Authentication option"},
		{"a digest computed with the wrong key", func(t *testing.T) Event {
			return reconfigureEvent(t, clientUnicast, bytes.Repeat([]byte{0x11}, 16), 1, good...)
		}, "fails RKAP authentication"},
		{"a digest that does not cover the message", func(t *testing.T) Event {
			_, raw := reconfigureSigned(t, testReconfKey, 1, good...)
			// One octet changed AFTER signing: the digest is genuine and no
			// longer describes these octets. The octet is §21.11's replay
			// detection field, which is inside the span the HMAC covers and
			// outside the sixteen §20.4.3 zeroes — so no earlier §16.11 rule
			// can fire and the authentication rule is what answers.
			forged := append([]byte(nil), raw...)
			start, _ := digestSpanHere(t, forged)
			forged[start-9] ^= 0xff
			m2, err := wire.DecodeV6(forged)
			if err != nil {
				t.Fatalf("DecodeV6: %v", err)
			}
			return ReceivedV6To(m2, forged, clientUnicast)
		}, "fails RKAP authentication"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := bindWithKey6(t, testParams6(), dnsmasqLeasedAddr, testReconfKey)
			s, acts := m.Step(at(10), 7, tc.ev(t))
			if s != State6Bound {
				t.Fatalf("a Reconfigure with %q left the machine in %s, want it discarded in %s%s", tc.name, s, State6Bound, journalLines(acts))
			}
			for _, a := range acts {
				if a.Kind == ActSendV6 {
					t.Fatalf("a Reconfigure with %q made the client send a %s%s", tc.name, a.MsgV6.Type, journalLines(acts))
				}
			}
			if !journalHas(acts, tc.say) {
				t.Errorf("the discard was not journalled with %q%s", tc.say, journalLines(acts))
			}
		})
	}
}

// receivedV6To is receivedV6 with a destination.
func receivedV6To(t *testing.T, dst netip.Addr, typ wire.MessageTypeV6, xid uint32, opts ...wire.OptionV6) Event {
	t.Helper()
	msg, raw := msgV6(t, typ, xid, opts...)
	return ReceivedV6To(msg, raw, dst)
}

// TestAReconfigureFromAServerThatSentNoKeyIsDiscarded is the §16.11 bullet
// "does not include authentication ... or fails authentication validation"
// read from the other side: the message carries an Authentication option and
// the client has nothing to check it against.
//
// §20.4.3: "The client records the reconfigure key for use in authenticating
// subsequent Reconfigure messages." A client with no record for this server
// cannot authenticate, and §16.11 makes that a discard.
func TestAReconfigureFromAServerThatSentNoKeyIsDiscarded(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    func(t *testing.T) *Machine6
	}{
		{"the Reply carried no key at all", func(t *testing.T) *Machine6 {
			return bind6(t, testParams6(), dnsmasqLeasedAddr)
		}},
		{"the key belongs to a different server", func(t *testing.T) *Machine6 {
			return bindWithKey6(t, testParams6(), dnsmasqLeasedAddr, testReconfKey)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := tc.m(t)
			sid := testServerDUID
			if strings.Contains(tc.name, "different") {
				sid = otherServerDUID
			}
			ev := reconfigureEvent(t, clientUnicast, testReconfKey, 1,
				optClientID(capDUID), optServerID(sid), optReconfMsg(t, wire.MsgRenew))
			s, acts := m.Step(at(10), 7, ev)
			if s != State6Bound {
				t.Fatalf("the Reconfigure left the machine in %s, want it discarded%s", s, journalLines(acts))
			}
			if !journalHas(acts, "no reconfigure key") {
				t.Errorf("the discard was not journalled as a missing key%s", journalLines(acts))
			}
		})
	}
}

// ----------------------------------------------------------------- §20.3 --

// TestTheReplayDetectionValueIsPerServerAndMustIncrease is §20.3.
//
// §20.3: "A client that receives a message with the RDM field set to 0x00 MUST
// compare its replay detection field with the previous value sent by that same
// server (based on the Server Identifier option; see Section 21.3) and only
// accept the message if the received value is greater and record this as the
// new value. If this is the first time a client processes an Authentication
// option sent by a server, the client MUST record the replay detection value
// and skip the replay detection check."
func TestTheReplayDetectionValueIsPerServerAndMustIncrease(t *testing.T) {
	// The first value is recorded and the check is skipped, whatever it is.
	m := bindWithKey6(t, testParams6(), dnsmasqLeasedAddr, testReconfKey)
	if s, acts := m.Step(at(10), 7, goodReconfigure(t, wire.MsgRenew, 40)); s != State6Renewing {
		t.Fatalf("the first Reconfigure was refused: %s%s", s, journalLines(acts))
	}
	// Back to BOUND6 so the §18.2.11 ignore window is not what answers next.
	replyToRenew(t, m)

	for _, tc := range []struct {
		name   string
		replay uint64
		accept bool
	}{
		{"the same value again", 40, false},
		{"a lower value", 39, false},
		{"zero, the wrap §20.3 describes", 0, false},
		{"a greater value", 41, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := bindWithKey6(t, testParams6(), dnsmasqLeasedAddr, testReconfKey)
			if s, _ := m.Step(at(10), 7, goodReconfigure(t, wire.MsgRenew, 40)); s != State6Renewing {
				t.Fatal("the first Reconfigure was refused")
			}
			replyToRenew(t, m)
			s, acts := m.Step(at(20), 7, goodReconfigure(t, wire.MsgRenew, tc.replay))
			if tc.accept && s != State6Renewing {
				t.Fatalf("a Reconfigure with %s was refused: %s%s", tc.name, s, journalLines(acts))
			}
			if !tc.accept {
				if s != State6Bound {
					t.Fatalf("a Reconfigure with %s was accepted: %s%s", tc.name, s, journalLines(acts))
				}
				if !journalHas(acts, "replay detection value") {
					t.Errorf("the replay discard was not journalled%s", journalLines(acts))
				}
			}
		})
	}
}

// TestTheReplayFloorIsPerServer is §20.3's "that same server (based on the
// Server Identifier option; see Section 21.3)": one counter for the client
// would refuse a second server's first Reconfigure against the first server's
// number, and would let a server that once sent a high value raise the floor
// for everybody.
//
// THE SECOND SERVER MUST ALSO HAVE SENT A KEY, which is why the fixture
// renews against it first: §20.4.2 grants a key in a Reply, and a server this
// client has never been leased by could not sign anything it would accept.
func TestTheReplayFloorIsPerServer(t *testing.T) {
	m := bindWithKey6(t, testParams6(), dnsmasqLeasedAddr, testReconfKey)
	if s, _ := m.Step(at(10), 7, goodReconfigure(t, wire.MsgRenew, 500)); s != State6Renewing {
		t.Fatal("the first Reconfigure was refused")
	}
	// The Renew is answered by the OTHER server, which hands this client its
	// own reconfigure key. Nothing in §20.3 says the two counters are related.
	xid := lastSentV6(t, m, at(12))
	otherKey := bytes.Repeat([]byte{0x5a}, 16)
	ev := receivedV6(t, wire.MsgReply, xid,
		optClientID(capDUID), optServerID(otherServerDUID),
		optIANA(t, capIAID, 150, 240, []iaAddrSpec{{dnsmasqLeasedAddr, 300, 300}}),
		optReconfKey(t, otherKey))
	if s, acts := m.Step(at(14), 0, ev); s != State6Bound {
		t.Fatalf("the Reply from the second server left the machine in %s%s", s, journalLines(acts))
	}

	// 7 is far below the 500 the FIRST server has already used.
	second := reconfigureEvent(t, clientUnicast, otherKey, 7,
		optClientID(capDUID), optServerID(otherServerDUID), optReconfMsg(t, wire.MsgRenew))
	s, acts := m.Step(at(20), 7, second)
	if s != State6Renewing {
		t.Fatalf("the second server's first Reconfigure was refused against the first server's counter: %s%s", s, journalLines(acts))
	}
	replyToRenew(t, m)

	// And the first server's floor did not move either.
	s, acts = m.Step(at(30), 7, goodReconfigure(t, wire.MsgRenew, 7))
	if s != State6Bound {
		t.Fatalf("the first server's replayed value 7 was accepted after the second server used it: %s%s", s, journalLines(acts))
	}
	if !journalHas(acts, "replay detection value") {
		t.Errorf("the replay discard was not journalled%s", journalLines(acts))
	}
}

// TestAFailedReconfigureDoesNotRaiseTheReplayFloor is the ordering §20.3's
// "only accept the message if the received value is greater and record this as
// the new value" implies: a message that is not accepted records nothing.
//
// Recording before validating would hand anyone who can put a packet on the
// link a permanent denial of service — one forged Authentication option
// carrying the largest possible value and every genuine Reconfigure from that
// server afterwards is "a replay".
func TestAFailedReconfigureDoesNotRaiseTheReplayFloor(t *testing.T) {
	m := bindWithKey6(t, testParams6(), dnsmasqLeasedAddr, testReconfKey)
	forged := reconfigureEvent(t, clientUnicast, bytes.Repeat([]byte{0x11}, 16), ^uint64(0),
		optClientID(capDUID), optServerID(testServerDUID), optReconfMsg(t, wire.MsgRenew))
	if s, _ := m.Step(at(10), 7, forged); s != State6Bound {
		t.Fatal("the forged Reconfigure was not discarded")
	}
	s, acts := m.Step(at(11), 7, goodReconfigure(t, wire.MsgRenew, 1))
	if s != State6Renewing {
		t.Fatalf("a genuine Reconfigure after a forged one was refused: %s%s", s, journalLines(acts))
	}
}

// replyToRenew answers the Renew in flight so the machine is BOUND6 again.
func replyToRenew(t *testing.T, m *Machine6) {
	t.Helper()
	xid := lastSentV6(t, m, at(12))
	if s, acts := m.Step(at(14), 0, reply(t, xid, dnsmasqLeasedAddr)); s != State6Bound {
		t.Fatalf("the Reply to the Renew left the machine in %s%s", s, journalLines(acts))
	}
}

// -------------------------------------------------------------- §18.2.11 --

// TestAReconfigureIsIgnoredWhileTheExchangeItAskedForIsInFlight is §18.2.11:
// "the client MUST ignore any additional Reconfigure messages until the
// exchange is complete."
func TestAReconfigureIsIgnoredWhileTheExchangeItAskedForIsInFlight(t *testing.T) {
	m := bindWithKey6(t, testParams6(), dnsmasqLeasedAddr, testReconfKey)
	if s, _ := m.Step(at(10), 7, goodReconfigure(t, wire.MsgRenew, 1)); s != State6Renewing {
		t.Fatal("the first Reconfigure did not start a Renew")
	}
	s, acts := m.Step(at(11), 7, goodReconfigure(t, wire.MsgRebind, 2))
	if s != State6Renewing {
		t.Fatalf("a second Reconfigure during the exchange left the machine in %s, want it ignored in %s%s", s, State6Renewing, journalLines(acts))
	}
	if hasSendV6(acts, wire.MsgRebind) {
		t.Errorf("a second Reconfigure during the exchange started a Rebind%s", journalLines(acts))
	}
	if !journalHas(acts, "ignored until it completes") {
		t.Errorf("the ignore was not journalled%s", journalLines(acts))
	}

	// The window closes when the exchange does, and not before.
	replyToRenew(t, m)
	if s, acts := m.Step(at(20), 7, goodReconfigure(t, wire.MsgRenew, 3)); s != State6Renewing {
		t.Fatalf("a Reconfigure after the exchange completed was ignored: %s%s", s, journalLines(acts))
	}
}

// TestAReconfiguresTransactionIdIsIgnored is §18.2.11: "The client ignores the
// 'transaction-id' field in the received Reconfigure message."
//
// The transaction id of a Reconfigure is the SERVER's, and the client has no
// exchange to match it against; a client that ran it through the ordinary
// admission gate would refuse every Reconfigure ever sent.
func TestAReconfiguresTransactionIdIsIgnored(t *testing.T) {
	for _, xid := range []uint32{0, 1, 0xffffff, uint32(capXIDRequest)} {
		m := bindWithKey6(t, testParams6(), dnsmasqLeasedAddr, testReconfKey)
		msg, raw := reconfigureSigned(t, testReconfKey, 1,
			optClientID(capDUID), optServerID(testServerDUID), optReconfMsg(t, wire.MsgRenew))
		msg.XID = xid
		// The octets keep the transaction id they were signed with; only the
		// decoded view is changed, which is what the machine reads.
		s, acts := m.Step(at(10), 7, ReceivedV6To(msg, raw, clientUnicast))
		if s != State6Renewing {
			t.Fatalf("a Reconfigure with transaction id %#x was refused: %s%s", xid, s, journalLines(acts))
		}
	}
}

// TestAReconfigureIsIgnoredWhereTheClientHoldsNothing pins the states
// §18.2.11's premise excludes: "interfaces for which it has acquired
// configuration information through DHCP".
func TestAReconfigureIsIgnoredWhereTheClientHoldsNothing(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(t *testing.T) (*Machine6, State6)
	}{
		{"stopped", func(t *testing.T) (*Machine6, State6) {
			return newMachine6(t, testParams6()), State6Stopped
		}},
		{"selecting", func(t *testing.T) (*Machine6, State6) {
			m, _ := solicit6(t, testParams6())
			return m, State6Selecting
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, want := tc.build(t)
			s, acts := m.Step(at(10), 7, goodReconfigure(t, wire.MsgRenew, 1))
			if s != want {
				t.Fatalf("a Reconfigure in %s left the machine in %s%s", want, s, journalLines(acts))
			}
			for _, a := range acts {
				if a.Kind == ActSendV6 && a.MsgV6.Type == wire.MsgRenew {
					t.Fatalf("a Reconfigure in %s started a Renew%s", want, journalLines(acts))
				}
			}
		})
	}
}

// ----------------------------------------------------------------- §21.20 --

// TestTheReconfigureAcceptOptionGoesWhereTheRFCAllowsIt pins the set, in both
// directions.
//
// §18.2.1 (Solicit) and §18.2.2 (Request) each say, word for word, "The client
// includes a Reconfigure Accept option (see Section 21.20) if the client is
// willing to accept Reconfigure messages from the server." §18.2.1 also says
// "The client MUST NOT include any other options in the Solicit message,
// except as specifically allowed in the definition of individual options."
// §20.4.2 names the three exchanges in which a key can be granted at all:
// "The server selects a reconfigure key for a client during the Request/Reply,
// Solicit/Reply, or Information-request/Reply message exchange."
func TestTheReconfigureAcceptOptionGoesWhereTheRFCAllowsIt(t *testing.T) {
	want := map[wire.MessageTypeV6]bool{
		wire.MsgSolicit:            true,
		wire.MsgRequest6:           true,
		wire.MsgInformationRequest: true,
		wire.MsgConfirm:            false,
		wire.MsgRenew:              false,
		wire.MsgRebind:             false,
		wire.MsgRelease6:           false,
		wire.MsgDecline6:           false,
	}
	m := bindWithKey6(t, testParams6(), dnsmasqLeasedAddr, testReconfKey)
	m.server = testServerDUID
	for typ, expect := range want {
		msg, err := m.build(at(100), typ)
		if err != nil {
			t.Fatalf("build(%s): %v", typ, err)
		}
		got, err := msg.Options.ReconfigureAccept()
		if err != nil {
			t.Fatalf("the %s's Reconfigure Accept option: %v", typ, err)
		}
		if got != expect {
			t.Errorf("the %s carries Reconfigure Accept = %v, want %v", typ, got, expect)
		}
	}
}

// TestAcceptReconfigureOffIsOffInBothDirections is the flag's own defeat: a
// switch that only stopped the announcement would leave a client that had
// already announced accepting Reconfigures it says it will not.
//
// §21.20: "In the absence of this option, the default behavior is that the
// client is unwilling to accept Reconfigure messages."
func TestAcceptReconfigureOffIsOffInBothDirections(t *testing.T) {
	p := testParams6()
	p.AcceptReconfigure = false
	m := bindWithKey6(t, p, dnsmasqLeasedAddr, testReconfKey)
	for _, typ := range []wire.MessageTypeV6{wire.MsgSolicit, wire.MsgRequest6, wire.MsgInformationRequest} {
		m.server = testServerDUID
		msg, err := m.build(at(100), typ)
		if err != nil {
			t.Fatalf("build(%s): %v", typ, err)
		}
		if ok, err := msg.Options.ReconfigureAccept(); ok || err != nil {
			t.Errorf("with AcceptReconfigure off the %s still announces it (%v, %v)", typ, ok, err)
		}
	}
	s, acts := m.Step(at(10), 7, goodReconfigure(t, wire.MsgRenew, 1))
	if s != State6Bound {
		t.Fatalf("with AcceptReconfigure off a Reconfigure left the machine in %s%s", s, journalLines(acts))
	}
	if !journalHas(acts, "announced no Reconfigure Accept option") {
		t.Errorf("the discard was not journalled%s", journalLines(acts))
	}
}

// TestDefaultParams6AcceptsReconfigure pins the maintainer's decision of
// 2026-09-11 (Q5) as a value and not a sentence in a doc comment.
func TestDefaultParams6AcceptsReconfigure(t *testing.T) {
	if !DefaultParams6().AcceptReconfigure {
		t.Error("DefaultParams6 does not accept Reconfigure messages")
	}
}

// ------------------------------------------------------------- the key --

// TestTheReconfigureKeyNeverReachesTheJournal is the secret's own rule: this
// library hands the caller its journal, and a shared key in a log is a shared
// key.
func TestTheReconfigureKeyNeverReachesTheJournal(t *testing.T) {
	m := newMachine6(t, testParams6())
	var seen []Action
	record := func(acts []Action) { seen = append(seen, acts...) }

	_, acts := m.Step(at(0), 0, Simple(EvStart))
	record(acts)
	_, acts = m.Step(at(1), capXIDSolicit, TimerFired(Timer6Delay))
	record(acts)
	_, acts = m.Step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255))
	record(acts)
	_, acts = m.Step(at(3), 0, replyWithKey(t, uint32(capXIDRequest), dnsmasqLeasedAddr, testReconfKey))
	record(acts)
	_, acts = m.Step(at(4), 0, DADResult(netip.MustParseAddr(dnsmasqLeasedAddr), false))
	record(acts)
	_, acts = m.Step(at(10), 7, goodReconfigure(t, wire.MsgRenew, 1))
	record(acts)

	hexKey := strings.ToLower(hexOf(testReconfKey))
	for _, a := range seen {
		text := a.Note + " " + a.Reason.String()
		if strings.Contains(strings.ToLower(text), hexKey) {
			t.Fatalf("the reconfigure key appears in an action: %q", text)
		}
		for _, b := range [][]byte{testReconfKey} {
			if bytes.Contains([]byte(text), b) {
				t.Fatalf("the reconfigure key appears verbatim in an action: %q", text)
			}
		}
	}
	if !journalHas(seen, "reconfigure key: recorded") {
		t.Errorf("the arrival of the key was not journalled at all%s", journalLines(seen))
	}
}

func hexOf(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, d[c>>4], d[c&0xf])
	}
	return string(out)
}

// ---------------------------------------------------------------- replay --

// TestAReconfigureReplaysWithItsDestination is the journal's half of §16.11's
// first bullet: the destination the datagram carried is not in the payload, so
// a journal that recorded only the octets would replay a Reconfigure that had
// been acted on as one that must be discarded.
//
// The divergence would be silent: the replayed run ends BOUND6 with a journal
// line, the recorded run ended RENEWING6, and Replay6's own comparison is what
// turns that into a finding.
func TestAReconfigureReplaysWithItsDestination(t *testing.T) {
	p := testParams6()
	r := newRecord6(t, p)
	r.step(at(0), 0, Simple(EvStart))
	r.step(at(1), capXIDSolicit, TimerFired(Timer6Delay))
	r.step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255))
	r.step(at(3), 0, replyWithKey(t, uint32(capXIDRequest), dnsmasqLeasedAddr, testReconfKey))
	r.step(at(4), 0, DADResult(addr6(dnsmasqLeasedAddr), false))
	if s, _ := r.step(at(10), 7, goodReconfigure(t, wire.MsgRenew, 1)); s != State6Renewing {
		t.Fatalf("the recorded run did not act on the Reconfigure: %s", s)
	}

	res, err := Replay6(p, r.entries)
	if err != nil {
		t.Fatalf("Replay6: %v", err)
	}
	if res.State != State6Renewing {
		t.Errorf("the replay ended in %s, want %s", res.State, State6Renewing)
	}
	if res.Steps != len(r.entries) {
		t.Errorf("the replay ran %d steps, the recording has %d", res.Steps, len(r.entries))
	}

	// The control: the same recording with the destination dropped is a
	// DIVERGENCE, which is what proves the field above was read and not
	// merely carried.
	mutated := append([]JournalEntry6(nil), r.entries...)
	last := mutated[len(mutated)-1]
	last.Dst = netip.Addr{}
	mutated[len(mutated)-1] = last
	if _, err := Replay6(p, mutated); err == nil {
		t.Error("a recording whose Reconfigure lost its destination replayed without a divergence")
	}
}

// TestOnlyRKAPTypeOneIsStoredAsTheReconfigureKey is §20.4.1's two types kept
// apart: "1  Reconfigure key value (used in the Reply message)." and
// "2  HMAC-MD5 digest of the message (used in the Reconfigure message)."
//
// A DIGEST IS NOT A SECRET. It travels in the clear in every Reconfigure, so a
// client that stored one as its key would be keyed on a value anyone who saw
// one packet already knows — and would then accept that attacker's next
// Reconfigure. The Reply here carries a well-formed Authentication option of
// the wrong type, so nothing but the type check can refuse it.
func TestOnlyRKAPTypeOneIsStoredAsTheReconfigureKey(t *testing.T) {
	digest, err := wire.EncodeRKAPAuth(wire.RKAPTypeDigest, testReconfKey, 0)
	if err != nil {
		t.Fatalf("EncodeRKAPAuth: %v", err)
	}
	m, _ := solicit6(t, testParams6())
	m.Step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255))
	ev := receivedV6(t, wire.MsgReply, uint32(capXIDRequest),
		optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 150, 240, []iaAddrSpec{{dnsmasqLeasedAddr, 300, 300}}),
		wire.OptionV6{Code: wire.OptV6Auth, Data: digest})
	if s, acts := m.Step(at(3), 0, ev); s != State6DAD {
		t.Fatalf("the Reply left the machine in %s%s", s, journalLines(acts))
	}
	if s, _ := m.Step(at(4), 0, DADResult(netip.MustParseAddr(dnsmasqLeasedAddr), false)); s != State6Bound {
		t.Fatal("the machine did not bind")
	}

	// The value that arrived would verify the Reconfigure below if it had been
	// stored, which is what makes this a test of the type check and not of the
	// digest.
	s, acts := m.Step(at(10), 7, goodReconfigure(t, wire.MsgRenew, 1))
	if s != State6Bound {
		t.Fatalf("a Type-2 Authentication option in the Reply was stored as the reconfigure key: %s%s", s, journalLines(acts))
	}
	if !journalHas(acts, "no reconfigure key") {
		t.Errorf("the discard was not journalled as a missing key%s", journalLines(acts))
	}
}

// TestTheAnsweringServerIdentifierDiesWithItsExchange drives the clear that
// TestTheRefreshTimerIsHonouredAfterTheDetour cannot reach.
//
// §18.2.6 makes the Server Identifier a MUST when the Information-request is
// "responding to a Reconfigure", and names it nowhere else in that section. The ordinary end of that exchange
// is a Reply, and that path clears the identifier; this one is the other end —
// the exchange is ABANDONED, here by T1 falling due, so no Reply ever arrives
// and the clear has to happen where the next exchange starts.
func TestTheAnsweringServerIdentifierDiesWithItsExchange(t *testing.T) {
	m := bindWithKey6(t, testParams6(), dnsmasqLeasedAddr, testReconfKey)
	if s, _ := m.Step(at(10), 7, goodReconfigure(t, wire.MsgInformationRequest, 1)); s != State6InfoRequesting {
		t.Fatal("the Reconfigure did not start an Information-request")
	}
	// T1 takes the machine away from that exchange, which therefore never
	// reaches takeConfig.
	if s, _ := m.Step(at(20), 0, TimerFired(Timer6Renew)); s != State6Renewing {
		t.Fatal("T1 did not take precedence over the detour")
	}
	xid := lastSentV6(t, m, at(21))
	if s, _ := m.Step(at(23), 0, reply(t, xid, dnsmasqLeasedAddr)); s != State6Bound {
		t.Fatal("the Reply to the Renew did not bind")
	}

	// A refresh Information-request now: it answers no Reconfigure.
	if s, _ := m.Step(at(30), 0, TimerFired(Timer6Refresh)); s != State6Bound {
		t.Fatal("the refresh timer moved the machine")
	}
	s, acts := m.Step(at(31), 0, TimerFired(Timer6Delay))
	if s != State6InfoRequesting {
		t.Fatalf("the refresh delay left the machine in %s%s", s, journalLines(acts))
	}
	req := mustSendV6(t, acts, wire.MsgInformationRequest)
	if _, ok := req.Options.First(wire.OptV6ServerID); ok {
		t.Error("an Information-request that answers no Reconfigure carries the abandoned exchange's Server Identifier (§18.2.6)")
	}
}

// TestALaterReplysKeyReplacesTheOldOneAndAKeylessReplyKeepsIt reads §20.4.2
// for what it does not say.
//
// §20.4.2: "The server selects a reconfigure key for a client during the
// Request/Reply, Solicit/Reply, or Information-request/Reply message
// exchange." A Reply that carries an Authentication option has selected one,
// and it replaces whatever was stored. A Reply that carries none has selected
// nothing — so a client that erased the key there, or read the absence as an
// empty key, would stop being reconfigurable at its first renewal, which is
// the ordinary case: every server in this suite's Renew Replies sends no
// Authentication option at all.
func TestALaterReplysKeyReplacesTheOldOneAndAKeylessReplyKeepsIt(t *testing.T) {
	rotated := mustHexBytes("00112233445566778899aabbccddeeff")

	for _, tc := range []struct {
		name string
		key  []byte
		want State6
	}{
		{"the rotated key", rotated, State6Renewing},
		{"the key it replaced", testReconfKey, State6Bound},
	} {
		t.Run("a Reconfigure signed with "+tc.name, func(t *testing.T) {
			m := bindWithKey6(t, testParams6(), dnsmasqLeasedAddr, testReconfKey)
			if s, _ := m.Step(at(10), 7, goodReconfigure(t, wire.MsgRenew, 1)); s != State6Renewing {
				t.Fatal("the first Reconfigure did not start a Renew")
			}
			xid := lastSentV6(t, m, at(12))
			if s, acts := m.Step(at(14), 0, replyWithKey(t, xid, dnsmasqLeasedAddr, rotated)); s != State6Bound {
				t.Fatalf("the Reply carrying a new key left the machine in %s%s", s, journalLines(acts))
			}
			ev := reconfigureEvent(t, clientUnicast, tc.key, 2,
				optClientID(capDUID), optServerID(testServerDUID), optReconfMsg(t, wire.MsgRenew))
			if s, acts := m.Step(at(20), 7, ev); s != tc.want {
				t.Fatalf("a Reconfigure signed with %s left the machine in %s, want %s%s", tc.name, s, tc.want, journalLines(acts))
			}
		})
	}

	t.Run("a Reply that carries no Authentication option keeps the stored key", func(t *testing.T) {
		m := bindWithKey6(t, testParams6(), dnsmasqLeasedAddr, testReconfKey)
		if s, _ := m.Step(at(10), 7, goodReconfigure(t, wire.MsgRenew, 1)); s != State6Renewing {
			t.Fatal("the first Reconfigure did not start a Renew")
		}
		replyToRenew(t, m)
		if s, acts := m.Step(at(20), 7, goodReconfigure(t, wire.MsgRenew, 2)); s != State6Renewing {
			t.Fatalf("a Reconfigure under the key a keyless Reply should have left alone was refused: %s, want %s%s", s, State6Renewing, journalLines(acts))
		}
	})
}

// TestAReconfigureRefusedForStateDoesNotBurnItsReplayValue is the reviewer's
// finding 1, driven as the scenario that found it.
//
// §20.3 records the replay detection value of a message the client ACCEPTS:
// "only accept the message if the received value is greater and record this as
// the new value". A Reconfigure that authenticates while the client is still
// running duplicate address detection is turned down by §18.2.11's premise —
// "interfaces for which it has acquired configuration information through
// DHCP" — so it was not accepted, and the floor must not move.
//
// WHAT IT COSTS IF IT DOES. A server retransmits a Reconfigure it got no
// answer to, and a retransmission is the same message with the same replay
// detection value. If the refused one raised the floor, the retransmission is
// discarded as a replay at the exact moment the client could act on it, and
// the reconfiguration is lost with no error anywhere: the client is bound, the
// server has given up, and neither says so.
func TestAReconfigureRefusedForStateDoesNotBurnItsReplayValue(t *testing.T) {
	m, _ := solicit6(t, testParams6())
	if s, _ := m.Step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255)); s != State6Requesting {
		t.Fatal("the Advertise did not start a Request")
	}
	if s, _ := m.Step(at(3), 0, replyWithKey(t, uint32(capXIDRequest), dnsmasqLeasedAddr, testReconfKey)); s != State6DAD {
		t.Fatal("the Reply did not start duplicate address detection")
	}

	// The exchange is over — msgType is 0 — but the address is not usable
	// yet, so §18.2.11's premise is not met. This is the window the ignore
	// rule does not cover.
	ev := goodReconfigure(t, wire.MsgRenew, 77)
	if s, acts := m.Step(at(4), 7, ev); s != State6DAD {
		t.Fatalf("a Reconfigure during DAD left the machine in %s, want it turned down in %s%s", s, State6DAD, journalLines(acts))
	}

	if s, _ := m.Step(at(5), 0, DADResult(netip.MustParseAddr(dnsmasqLeasedAddr), false)); s != State6Bound {
		t.Fatal("a clean DAD result did not bind the machine")
	}

	// The server retransmits: the identical octets, the identical replay
	// detection value.
	s, acts := m.Step(at(6), 7, ev)
	if s != State6Renewing {
		t.Fatalf("the server's retransmission left the machine in %s, want %s%s", s, State6Renewing, journalLines(acts))
	}
	mustSendV6(t, acts, wire.MsgRenew)
}

// TestARingOneRuleCannotSeeWhoseUnicastAddressItIs pins the reviewer's finding
// 2 as a case: the §16.11 arm in this package refuses a destination that is
// multicast, unspecified or absent, and it OBEYS a Reconfigure unicast to
// somebody else.
//
// This test asserts the behaviour the library has, not the behaviour §16.11
// describes, and it is here so that the gap is a measured case rather than a
// sentence in a comment. The missing half is ring 3's:
// runtime.PacketTransportV6 drops every datagram whose IPv6 destination is not
// the address it bound, so through the shipped transport this event cannot be
// built. THAT HALF IS MEASURED TOO, and not by a sentence pointing at code:
// runtime.TestAV6ClientDiscardsAnotherClientsReplyAtTheTransport puts a second
// client on one segment and reads the transport's drop counter on the first.
// A caller with its own lease.TransportV6, or a journal replayed from
// somebody else's capture, can build it.
//
// If ring 1 ever learns the client's own addresses, this test is the one that
// has to change, and changing it is the visible half of that decision.
func TestARingOneRuleCannotSeeWhoseUnicastAddressItIs(t *testing.T) {
	someoneElse := netip.MustParseAddr("2001:db8::dead:beef")
	if someoneElse.IsMulticast() || someoneElse.IsUnspecified() {
		t.Fatal("the fixture address is not the unicast address this case needs")
	}
	m := bindWithKey6(t, testParams6(), dnsmasqLeasedAddr, testReconfKey)
	ev := reconfigureEvent(t, someoneElse, testReconfKey, 1,
		optClientID(capDUID), optServerID(testServerDUID), optReconfMsg(t, wire.MsgRenew))

	s, acts := m.Step(at(10), 7, ev)
	if s != State6Renewing {
		t.Fatalf("a Reconfigure unicast to another node left the machine in %s; if ring 1 now knows its own addresses, this case is the record of that change%s", s, journalLines(acts))
	}
	mustSendV6(t, acts, wire.MsgRenew)

	// The half this arm DOES decide, driven in the same test so the case
	// above cannot be read as "the rule is not there at all".
	for _, dst := range []netip.Addr{
		netip.MustParseAddr("ff02::1"),
		netip.IPv6Unspecified(),
		{},
	} {
		m := bindWithKey6(t, testParams6(), dnsmasqLeasedAddr, testReconfKey)
		ev := reconfigureEvent(t, dst, testReconfKey, 1,
			optClientID(capDUID), optServerID(testServerDUID), optReconfMsg(t, wire.MsgRenew))
		if s, acts := m.Step(at(10), 7, ev); s != State6Bound {
			t.Errorf("a Reconfigure addressed to %v left the machine in %s, want it discarded%s", dst, s, journalLines(acts))
		}
	}
}

// TestARenewalDuringTheRefreshDelayDoesNotLoseTheRefresh is the reviewer's
// finding 4, which was read rather than run when it was reported and is driven
// here.
//
// The detour gave BOUND6 a second clock. §21.23 asks for a delay before the
// Information-request — "the client MUST delay sending the first
// Information-request by a random amount of time between 0 and INF_MAX_DELAY"
// — and T1 can fall due inside it. The lease wins: §18.2.4's renewal is what
// keeps the address. What must not happen is the third outcome, where the
// delay timer is left pending in a state that ignores it and §21.23's SHOULD
// is dropped with nobody told.
func TestARenewalDuringTheRefreshDelayDoesNotLoseTheRefresh(t *testing.T) {
	m := bindWithKey6(t, testParams6(), dnsmasqLeasedAddr, testReconfKey)
	if s, _ := m.Step(at(10), 7, goodReconfigure(t, wire.MsgInformationRequest, 1)); s != State6InfoRequesting {
		t.Fatal("the Reconfigure did not start an Information-request")
	}
	sent := lastSentV6(t, m, at(10))
	if s, _ := m.Step(at(11), 0, receivedV6(t, wire.MsgReply, sent,
		optClientID(capDUID), optServerID(testServerDUID),
		optU32(wire.OptV6InfoRefresh, 3600))); s != State6Bound {
		t.Fatal("the detour did not return to BOUND6")
	}

	// The refresh falls due, and the delay is armed.
	if s, _ := m.Step(at(4000), 0, TimerFired(Timer6Refresh)); s != State6Bound {
		t.Fatal("the refresh timer left BOUND6")
	}
	// T1 falls due inside the delay.
	s, acts := m.Step(at(4001), 0, TimerFired(Timer6Renew))
	if s != State6Renewing {
		t.Fatalf("T1 during the refresh delay left the machine in %s, want %s%s", s, State6Renewing, journalLines(acts))
	}
	if !hasTimerAction(acts, ActCancelTimer, Timer6Delay) {
		t.Errorf("the pending refresh delay was left armed in %s, where it is ignored%s", State6Renewing, journalLines(acts))
	}

	// The renewal completes. The refresh is still owed, so it is armed again.
	xid := lastSentV6(t, m, at(4002))
	s, acts = m.Step(at(4003), 9, reply(t, xid, dnsmasqLeasedAddr))
	if s != State6Bound {
		t.Fatalf("the Reply to the Renew left the machine in %s%s", s, journalLines(acts))
	}
	if !hasTimerAction(acts, ActSetTimer, Timer6Delay) {
		t.Fatalf("the refresh §21.23 still owes was not armed again after the renewal%s", journalLines(acts))
	}
	s, acts = m.Step(at(4004), 0, TimerFired(Timer6Delay))
	if s != State6InfoRequesting {
		t.Fatalf("the re-armed refresh delay left the machine in %s, want %s%s", s, State6InfoRequesting, journalLines(acts))
	}
	req := mustSendV6(t, acts, wire.MsgInformationRequest)

	// THE DEBT IS PAID BY THE REPLY, and the next renewal must not re-arm it:
	// a machine that kept owing a refresh would send an Information-request
	// after every single renewal for the rest of the lease, which is an
	// exchange §21.23 did not ask for and nothing would ever stop. MEASURED
	// as a mutant: deleting the clear in takeConfig survives every other case
	// in this file.
	if s, acts := m.Step(at(4005), 0, receivedV6(t, wire.MsgReply, req.XID,
		optClientID(capDUID), optServerID(testServerDUID),
		optU32(wire.OptV6InfoRefresh, 3600))); s != State6Bound {
		t.Fatalf("the refresh exchange did not return to BOUND6: %s%s", s, journalLines(acts))
	}
	if s, _ := m.Step(at(5000), 0, TimerFired(Timer6Renew)); s != State6Renewing {
		t.Fatal("the second T1 did not start a Renew")
	}
	xid = lastSentV6(t, m, at(5001))
	s, acts = m.Step(at(5002), 11, reply(t, xid, dnsmasqLeasedAddr))
	if s != State6Bound {
		t.Fatalf("the second Reply left the machine in %s%s", s, journalLines(acts))
	}
	if hasTimerAction(acts, ActSetTimer, Timer6Delay) {
		t.Errorf("a renewal armed another refresh Information-request although the refresh had already been answered%s", journalLines(acts))
	}
}

// hasTimerAction reports whether acts carries kind for t. The timer actions
// are what a caller actually arms and cancels, so a test about a dropped timer
// has to read them rather than the state.
func hasTimerAction(acts []Action, kind ActionKind, t TimerID) bool {
	for _, a := range acts {
		if a.Kind == kind && a.Timer == t {
			return true
		}
	}
	return false
}
