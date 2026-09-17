// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"fmt"

	"github.com/claymore666/dhcp-golib/wire"
)

// The server-initiated exchange: RFC 9915 §16.11's discard rules, §20.3's
// replay detection, §20.4's Reconfiguration Key Authentication Protocol, and
// §18.2.11's response.
//
// WHAT A RECONFIGURE IS, AND WHY IT DOES NOT GO THROUGH admit. §18.2.11: "A
// client receives Reconfigure messages sent to UDP port 546 on interfaces for
// which it has acquired configuration information through DHCP. These messages
// may be sent at any time." It answers no outstanding transaction — §18.2.11
// again: "The client ignores the 'transaction-id' field in the received
// Reconfigure message" — so admit's first test, the transaction-id of the
// exchange in flight, is a rule §16.11 does not have and would refuse every
// Reconfigure ever sent to a bound client.
//
// EVERY DISCARD IS JOURNALLED WITH THE BULLET THAT FIRED, for admit's reason
// and one more: six rules that only ever fire together are six rules of which
// five could be missing.

// ReconfigureRefusal is why a Reconfigure changed nothing.
//
// IT IS AN ENUMERATION AND NOT A COUNT, for SLAACIgnore's reason: the rules
// ask an operator for different next steps. A server that has sent this client
// no reconfigure key is a server to configure, a digest that does not verify is
// a message to look at on the wire, and a replay detection value that did not
// rise is a server retransmitting into a client that already acted. One number
// holding all three answers none of them.
type ReconfigureRefusal uint8

// The reasons, each the rule of RFC 9915 that refused the message, in the
// order the arms are reached.
const (
	// ReconfigureRefusalNone is not a reason; it is the zero value, meaning
	// the message was acted on.
	ReconfigureRefusalNone ReconfigureRefusal = iota

	// ReconfigureRefusalUnwilling is §21.20's default: "In the absence of this
	// option, the default behavior is that the client is unwilling to accept
	// Reconfigure messages." This client announced no such option.
	ReconfigureRefusalUnwilling

	// ReconfigureRefusalExchangeInFlight is §18.2.11's window: "the client
	// MUST ignore any additional Reconfigure messages until the exchange is
	// complete".
	ReconfigureRefusalExchangeInFlight

	// ReconfigureRefusalNotUnicast is the half of §16.11's first bullet — "the
	// message was not unicast to the client" — that ring 1 can see: a
	// destination that is multicast, unspecified or absent. See takeReconfigure
	// for the half that is the transport's.
	ReconfigureRefusalNotUnicast

	// ReconfigureRefusalNoServerID is §16.11's "the message does not include a
	// Server Identifier option (see Section 21.3)".
	ReconfigureRefusalNoServerID

	// ReconfigureRefusalAmbiguousServerID is more than one of them. §16.11
	// names the absence and not the repeat; §21.3 makes the option a
	// singleton, and §20.3 keys the replay counter on which server sent this.
	ReconfigureRefusalAmbiguousServerID

	// ReconfigureRefusalNoClientID is §16.11's "the message does not include a
	// Client Identifier option (see Section 21.2) that contains the client's
	// DUID", with no option at all.
	ReconfigureRefusalNoClientID

	// ReconfigureRefusalForeignClientID is the same bullet with an option
	// holding somebody else's DUID.
	ReconfigureRefusalForeignClientID

	// ReconfigureRefusalNoReconfigureMessage is §16.11's "the message does not
	// include a Reconfigure Message option (see Section 21.19)".
	ReconfigureRefusalNoReconfigureMessage

	// ReconfigureRefusalBadReconfigureMessage is §16.11's "the Reconfigure
	// Message option msg-type is not a valid value", and an option that will
	// not decode at all.
	ReconfigureRefusalBadReconfigureMessage

	// ReconfigureRefusalNoAuth is the first half of §16.11's last bullet, "the
	// message does not include authentication (such as RKAP; see Section
	// 20.4)".
	ReconfigureRefusalNoAuth

	// ReconfigureRefusalUnreadableAuth is an Authentication option that will
	// not decode.
	ReconfigureRefusalUnreadableAuth

	// ReconfigureRefusalNotRKAP is an Authentication option that decodes and
	// is not §20.4.1's protocol 3, algorithm 1, RDM 0.
	ReconfigureRefusalNotRKAP

	// ReconfigureRefusalNoKey is a server that has sent this client no
	// reconfigure key (§20.4.3). It is the reason a client that resumed a
	// lease through a Confirm reports; see the bound on Machine6.reconf.
	ReconfigureRefusalNoKey

	// ReconfigureRefusalBadDigest is the second half of §16.11's last bullet,
	// "or fails authentication validation": the HMAC-MD5 §20.4.3 asks for does
	// not match.
	ReconfigureRefusalBadDigest

	// ReconfigureRefusalReplay is §20.3: the replay detection value is not
	// greater than the one this server has already used.
	ReconfigureRefusalReplay

	// ReconfigureRefusalNoLease is §18.2.11's premise — "interfaces for which
	// it has acquired configuration information through DHCP" — refusing a
	// Renew or a Rebind asked of a client that holds no lease to extend.
	ReconfigureRefusalNoLease

	// ReconfigureRefusalNoConfiguration is that premise refusing an
	// Information-request asked of a client in a state that holds none.
	ReconfigureRefusalNoConfiguration

	// ReconfigureRefusalUndefinedMessage is a Reconfigure Message option
	// msg-type outside §21.19's three that reached the response. Unreachable
	// through ReconfigureMessage, which refuses every other value, and counted
	// anyway for Machine6.Step's reason.
	ReconfigureRefusalUndefinedMessage

	// numReconfigureRefusal is one past the last reason, which is what sizes
	// ReconfigureCounters.Refused. It is written here, immediately after the
	// block, so that a reason added below it does not compile.
	numReconfigureRefusal
)

func (r ReconfigureRefusal) String() string {
	switch r {
	case ReconfigureRefusalNone:
		return "acted on"
	case ReconfigureRefusalUnwilling:
		return "this client announced no Reconfigure Accept option (RFC 9915 §21.20)"
	case ReconfigureRefusalExchangeInFlight:
		return "an exchange is in flight (RFC 9915 §18.2.11)"
	case ReconfigureRefusalNotUnicast:
		return "the message was not unicast to the client (RFC 9915 §16.11)"
	case ReconfigureRefusalNoServerID:
		return "no Server Identifier option (RFC 9915 §16.11)"
	case ReconfigureRefusalAmbiguousServerID:
		return "more than one Server Identifier option (RFC 9915 §16, §21.3)"
	case ReconfigureRefusalNoClientID:
		return "no Client Identifier option (RFC 9915 §16.11)"
	case ReconfigureRefusalForeignClientID:
		return "a Client Identifier option holding another client's DUID (RFC 9915 §16.11)"
	case ReconfigureRefusalNoReconfigureMessage:
		return "no Reconfigure Message option (RFC 9915 §16.11)"
	case ReconfigureRefusalBadReconfigureMessage:
		return "a Reconfigure Message option this client cannot use (RFC 9915 §16.11, §21.19)"
	case ReconfigureRefusalNoAuth:
		return "no Authentication option (RFC 9915 §16.11, §20.4)"
	case ReconfigureRefusalUnreadableAuth:
		return "an Authentication option that will not decode (RFC 9915 §16.11)"
	case ReconfigureRefusalNotRKAP:
		return "an Authentication option that is not RKAP (RFC 9915 §16.11, §20.4.1)"
	case ReconfigureRefusalNoKey:
		return "this server has sent this client no reconfigure key (RFC 9915 §16.11, §20.4.3)"
	case ReconfigureRefusalBadDigest:
		return "the message fails RKAP authentication (RFC 9915 §16.11, §20.4.3)"
	case ReconfigureRefusalReplay:
		return "the replay detection value is not greater than this server's last (RFC 9915 §20.3)"
	case ReconfigureRefusalNoLease:
		return "this client holds no lease to renew or rebind (RFC 9915 §18.2.11)"
	case ReconfigureRefusalNoConfiguration:
		return "this client holds no configuration to refresh (RFC 9915 §18.2.11)"
	case ReconfigureRefusalUndefinedMessage:
		return "a msg-type RFC 9915 §21.19 does not define"
	default:
		return fmt.Sprintf("reconfigure-refusal(%d)", uint8(r))
	}
}

// AllReconfigureRefusals is every reason a Reconfigure was refused, so the
// counters and the tests enumerate the domain from one place.
func AllReconfigureRefusals() []ReconfigureRefusal {
	return []ReconfigureRefusal{
		ReconfigureRefusalUnwilling, ReconfigureRefusalExchangeInFlight,
		ReconfigureRefusalNotUnicast, ReconfigureRefusalNoServerID,
		ReconfigureRefusalAmbiguousServerID, ReconfigureRefusalNoClientID,
		ReconfigureRefusalForeignClientID, ReconfigureRefusalNoReconfigureMessage,
		ReconfigureRefusalBadReconfigureMessage, ReconfigureRefusalNoAuth,
		ReconfigureRefusalUnreadableAuth, ReconfigureRefusalNotRKAP,
		ReconfigureRefusalNoKey, ReconfigureRefusalBadDigest,
		ReconfigureRefusalReplay, ReconfigureRefusalNoLease,
		ReconfigureRefusalNoConfiguration, ReconfigureRefusalUndefinedMessage,
	}
}

// ReconfigureCounters is what this machine did with the Reconfigure messages
// it was given. Ring 2 mirrors it at every Step, the way it mirrors the SLAAC
// counters, and folds Refused into one number for an operator.
//
// ACCEPTED AND REFUSED PARTITION WHAT REACHED THIS RING. Every Reconfigure
// that reaches takeReconfigure raises exactly one of the two, so their sum is
// how many the machine was handed and their ratio is whether the server and
// this client have a working reconfigure key between them.
//
// THE POPULATION IS WHAT RING 1 WAS HANDED, which is smaller than what the
// link carried. A datagram that would not decode never becomes an event — it
// is lease.Stats.DecodeFailures — and a datagram addressed to another node is
// dropped by the transport, which is the other half of §16.11's first bullet
// and is counted nowhere. Neither is in these numbers.
//
// IT IS A COPY OF A VALUE AND NOT A POINTER, for SLAACCounters's reason: the
// array inside is what a caller compares against an earlier reading.
type ReconfigureCounters struct {
	// Accepted counts the messages this client answered with the exchange the
	// Reconfigure Message option named, counted where §20.3's replay floor
	// moves, which is after that exchange has actually started. A message the
	// client turned down because it holds nothing to reconfigure is a refusal
	// and not an acceptance, which is the same boundary the floor uses.
	Accepted uint64

	// Refused is indexed BY ReconfigureRefusal, so a reason added to the
	// enumeration widens this array and no line here has to change.
	// numReconfigureRefusal is what makes that true and
	// TestEveryReconfigureRefusalIsDeclaredCountedAndNamed is what holds the
	// two to each other.
	Refused [numReconfigureRefusal]uint64
}

// RefusedTotal is every Reconfigure refused by any rule.
func (c ReconfigureCounters) RefusedTotal() uint64 {
	var n uint64
	for _, r := range AllReconfigureRefusals() {
		n += c.Refused[r]
	}
	return n
}

// reconfServer is one server's RKAP state: the reconfigure key it last sent
// and the replay detection value last accepted from it.
//
// IT IS PER SERVER BECAUSE §20.3 SAYS SO: "A client that receives a message
// with the RDM field set to 0x00 MUST compare its replay detection field with
// the previous value sent by that same server (based on the Server Identifier
// option; see Section 21.3)". One counter per client would refuse a second
// server's first Reconfigure against the first server's number, and would let
// a server that had sent a high value raise the floor for everybody.
//
// BOUND: one entry per distinct Server Identifier that has ever sent this
// machine a reconfigure key, for the life of the machine. On a link with one
// server that is one entry; the population is the set of DHCPv6 servers
// answering this endpoint, and nothing trims it — a set that forgot a server's
// counter would accept that server's replayed Reconfigure the next time.
type reconfServer struct {
	key []byte
	// replay is §20.3's last accepted value, and seen says whether any has
	// been: "If this is the first time a client processes an Authentication
	// option sent by a server, the client MUST record the replay detection
	// value and skip the replay detection check."
	replay uint64
	seen   bool
}

// noteReconfigureKey records the reconfigure key a Reply carried, §20.4.3:
// "The client will receive a reconfigure key from the server in an
// Authentication option (see Section 21.11) in the initial Reply message from
// the server. The client records the reconfigure key for use in authenticating
// subsequent Reconfigure messages."
//
// AN ABSENT OPTION CHANGES NOTHING, and that is the difference between "this
// Reply carried no key" and "this server has no key". §20.4.2 names three
// exchanges in which a server selects one — "the Request/Reply, Solicit/Reply,
// or Information-request/Reply message exchange" — and a Renew's Reply is not
// among them, so a client that erased the key on every keyless Reply would
// lose it at T1 and accept no Reconfigure again.
//
// NO NOTE, ACTION OR ERROR STRING CARRIES THE KEY. The value is the secret the
// whole mechanism rests on, and this library hands a caller its journal, its
// counters and its error strings. What this records is that a key arrived and
// how long it was.
//
// THE RECORDED DATAGRAM IS WHERE IT DOES APPEAR. The Reply the key arrived in
// is kept whole, in JournalEntry6.Raw because a replay needs the octets and in
// the packet capture, so the key is in both. A caller that hands either one to
// somebody else hands the key over with it, and a replay of that journal puts
// the key back into the fresh machine.
func (m *Machine6) noteReconfigureKey(msg *wire.MessageV6, out *actions) {
	a, ok, err := msg.Options.Auth()
	if !ok {
		return
	}
	if err != nil {
		out.journal(m, "the "+msg.Type.String()+"'s Authentication option: "+err.Error())
		return
	}
	typ, val, err := a.RKAP()
	if err != nil {
		out.journal(m, "the "+msg.Type.String()+"'s Authentication option: "+err.Error())
		return
	}
	if typ != wire.RKAPTypeKey {
		// §20.4.1's other Type is the digest, which belongs in a Reconfigure
		// and not in a Reply. Nothing is stored: a digest read as a key would
		// be a key an attacker who saw one Reconfigure already knows.
		out.journal(m, fmt.Sprintf("the %s carries RKAP authentication information of type %d, not §20.4.1's reconfigure key: ignored", msg.Type, typ))
		return
	}
	sid, ok := msg.Options.First(wire.OptV6ServerID)
	if !ok || len(sid) == 0 {
		out.journal(m, "a reconfigure key arrived in a "+msg.Type.String()+" with no Server Identifier: ignored, §20.3 keys the replay counter on the server")
		return
	}
	if m.reconf == nil {
		m.reconf = map[string]*reconfServer{}
	}
	s := m.reconf[string(sid)]
	if s == nil {
		s = &reconfServer{}
		m.reconf[string(sid)] = s
	}
	s.key = append([]byte(nil), val...)
	out.journal(m, fmt.Sprintf("the %s carries a %d-octet reconfigure key: recorded for this server (§20.4.3)", msg.Type, len(val)))
}

// refuseReconfigure is the ONE way a Reconfigure is turned down. The reason
// and the journal line leave together, so an arm cannot record the sentence
// without the number or the number without the sentence, and an arm added
// later has to name which rule it is.
func (m *Machine6) refuseReconfigure(out *actions, why ReconfigureRefusal, note string) {
	m.reconfCounts.Refused[why]++
	out.journal(m, note)
}

// takeReconfigure is §16.11 followed by §18.2.11, in that order, and it is
// reached from every state because §18.2.11's "These messages may be sent at
// any time" is true in every one of them.
func (m *Machine6) takeReconfigure(now Instant, rnd uint64, ev Event, out *actions) {
	msg := ev.MsgV6

	// §21.20: "In the absence of this option, the default behavior is that the
	// client is unwilling to accept Reconfigure messages." This client sent no
	// such option, so it is unwilling, so the message is not its business.
	if !m.params.AcceptReconfigure {
		m.refuseReconfigure(out, ReconfigureRefusalUnwilling, "a Reconfigure arrived and this client announced no Reconfigure Accept option: discarded (§21.20)")
		return
	}

	// §18.2.11: "Once the client has received a Reconfigure, the client
	// proceeds with the message exchange (retransmitting the Renew, Rebind, or
	// Information-request message if necessary); the client MUST ignore any
	// additional Reconfigure messages until the exchange is complete."
	//
	// THE WINDOW IS THE EXCHANGE ITSELF and not a flag beside it. msgType is
	// zero exactly when no exchange is in flight, and every way an exchange
	// can end — a Reply, a give-up, Stop, a link going down, a Release — sets
	// it back. A second field would be a second record of one fact, and the
	// way out of the window that forgot to clear it would be the one nobody
	// drove.
	if m.msgType != 0 {
		m.refuseReconfigure(out, ReconfigureRefusalExchangeInFlight, fmt.Sprintf("a Reconfigure arrived while a %s exchange is in flight: ignored until it completes (§18.2.11)", m.msgType))
		return
	}

	// §16.11, bullet by bullet, each named in the line it writes.
	//
	// THIS ARM DECIDES HALF OF THE FIRST BULLET, and the journal line says
	// which half. §16.11's bullet is "the message was not unicast to the
	// client": ring 1 can see that a destination is multicast, unspecified or
	// missing, and it cannot see whether a unicast address is THIS client's,
	// because no ring-1 input carries the client's own addresses. The other
	// half belongs to the transport, and runtime.PacketTransportV6 performs
	// it — it drops every datagram whose IPv6 destination is not the address
	// it bound. A caller that supplies its own lease.TransportV6 owes that
	// half; Event.Dst says so, and
	// TestARingOneRuleCannotSeeWhoseUnicastAddressItIs is the case that pins
	// what this arm does and does not refuse. The claim here used to be the
	// whole bullet, which a reviewer measured false.
	if !ev.Dst.IsValid() || ev.Dst.IsMulticast() || ev.Dst.IsUnspecified() {
		m.refuseReconfigure(out, ReconfigureRefusalNotUnicast, fmt.Sprintf("a Reconfigure addressed to %s: discarded, §16.11's first bullet needs a unicast destination", reconfDst(ev)))
		return
	}
	sids := msg.Options.Count(wire.OptV6ServerID)
	if sids == 0 {
		m.refuseReconfigure(out, ReconfigureRefusalNoServerID, "a Reconfigure carries no Server Identifier option: discarded (§16.11)")
		return
	}
	if sids > 1 {
		// §16.11 names the absence and not the repeat, and §21 makes the
		// option a singleton. Two of them make "which server signed this"
		// ambiguous, and §20.3 keys the replay counter on that answer.
		m.refuseReconfigure(out, ReconfigureRefusalAmbiguousServerID, fmt.Sprintf("a Reconfigure carries %d Server Identifier options: discarded, the sender is ambiguous (§16, §21.3)", sids))
		return
	}
	cid, ok := msg.Options.First(wire.OptV6ClientID)
	if !ok {
		m.refuseReconfigure(out, ReconfigureRefusalNoClientID, "a Reconfigure carries no Client Identifier option: discarded (§16.11)")
		return
	}
	if !sameDUID(cid, m.params.DUID) {
		// §16.11's bullet is "does not include a Client Identifier option
		// (see Section 21.2) that contains the client's DUID", so a present
		// one holding somebody else's DUID fails the same bullet.
		m.refuseReconfigure(out, ReconfigureRefusalForeignClientID, "a Reconfigure carries a Client Identifier that is not ours: discarded (§16.11)")
		return
	}
	kind, ok, err := msg.Options.ReconfigureMessage()
	if !ok {
		m.refuseReconfigure(out, ReconfigureRefusalNoReconfigureMessage, "a Reconfigure carries no Reconfigure Message option: discarded (§16.11)")
		return
	}
	if err != nil {
		m.refuseReconfigure(out, ReconfigureRefusalBadReconfigureMessage, "a Reconfigure's Reconfigure Message option: discarded, "+err.Error()+" (§16.11)")
		return
	}

	sid, _ := msg.Options.First(wire.OptV6ServerID)
	s, replay, ok := m.authenticateReconfigure(msg, ev.Raw, sid, out)
	if !ok {
		return
	}

	// §18.2.11: "Upon receipt of a valid Reconfigure message, the client
	// responds with a Renew message, a Rebind message, or an
	// Information-request message as indicated by the Reconfigure Message
	// option (see Section 21.19)."
	if !m.respondToReconfigure(now, rnd, kind, sid, out) {
		return
	}

	// THE REPLAY FLOOR MOVES ONLY WHERE THE CLIENT ACTED. §20.3 says to
	// "only accept the message if the received value is greater and record
	// this as the new value" — and a Reconfigure the client turned down
	// because it holds no configuration to renew was not accepted. Recording
	// it there would burn the value the server will retransmit with: the
	// server's next attempt, which is the identical message, would be refused
	// as a replay once the client CAN act on it, and the reconfiguration
	// would be lost with nothing to notice it. Found by the reviewer's
	// pre-push read, MEASURED as a case: a valid Reconfigure delivered during
	// DAD, then the same octets once the machine is BOUND6.
	if !s.seen {
		out.journal(m, "the first authenticated Reconfigure from this server: its replay detection value is recorded and the check is skipped (§20.3)")
	}
	s.replay, s.seen = replay, true
	m.reconfCounts.Accepted++
}

// reconfDst renders a destination for a journal line, including the case where
// the transport reported none.
func reconfDst(ev Event) string {
	if !ev.Dst.IsValid() {
		return "an address the transport did not report"
	}
	return ev.Dst.String()
}

// authenticateReconfigure is §16.11's last bullet — "the message does not
// include authentication (such as RKAP; see Section 20.4) or fails
// authentication validation" — and §20.3's replay check behind it.
//
// IT RECORDS NOTHING. The replay detection value is COMPARED here and written
// by the caller, after the response has actually started, and that ordering is
// the whole of defeat row D-7. §20.3 says to "only accept the message if the
// received value is greater and record this as the new value": a client that
// recorded before verifying would let anyone who can put a packet on the link
// send one Authentication option carrying 2^64-1 and permanently refuse every
// genuine Reconfigure from that server afterwards, and a client that recorded
// before responding would do the same thing to the server's own retransmission
// whenever it was not yet in a state to respond.
//
// It returns the server's entry so the caller can write the floor without
// looking it up twice, the value to write, and whether every check passed.
func (m *Machine6) authenticateReconfigure(msg *wire.MessageV6, raw, sid []byte, out *actions) (*reconfServer, uint64, bool) {
	a, ok, err := msg.Options.Auth()
	if !ok {
		m.refuseReconfigure(out, ReconfigureRefusalNoAuth, "a Reconfigure carries no Authentication option: discarded (§16.11, §20.4)")
		return nil, 0, false
	}
	if err != nil {
		// §21.11's own shape: an option too short for the fixed part, or more
		// than one of a singleton. Separate from the RKAP arm below because
		// the next step differs: this is an option nothing can read, and that
		// one is an option that reads as another authentication protocol.
		m.refuseReconfigure(out, ReconfigureRefusalUnreadableAuth,
			"a Reconfigure's Authentication option: discarded, "+err.Error()+" (§16.11)")
		return nil, 0, false
	}
	if _, _, err := a.RKAP(); err != nil {
		m.refuseReconfigure(out, ReconfigureRefusalNotRKAP,
			"a Reconfigure's Authentication option is not RKAP: discarded, "+err.Error()+" (§16.11, §20.4.1)")
		return nil, 0, false
	}
	s := m.reconf[string(sid)]
	if s == nil || len(s.key) == 0 {
		// §20.4 gives the client no way to authenticate a server that never
		// sent it a key, and §16.11 makes that a discard rather than a
		// degraded acceptance.
		m.refuseReconfigure(out, ReconfigureRefusalNoKey, "a Reconfigure arrived from a server that has sent this client no reconfigure key: discarded (§16.11, §20.4.3)")
		return nil, 0, false
	}
	if err := wire.RKAPVerify(raw, s.key); err != nil {
		m.refuseReconfigure(out, ReconfigureRefusalBadDigest, "a Reconfigure fails RKAP authentication: discarded (§16.11, §20.4.3)")
		return nil, 0, false
	}
	// §20.3: "A client that receives a message with the RDM field set to 0x00
	// MUST compare its replay detection field with the previous value sent by
	// that same server ... and only accept the message if the received value
	// is greater and record this as the new value. If this is the first time a
	// client processes an Authentication option sent by a server, the client
	// MUST record the replay detection value and skip the replay detection
	// check."
	//
	// THE WRAP §20.3 MENTIONS IS REFUSED. "(modulo 2^64)" describes how the
	// sender counts; this comparison is "greater" and nothing else, so a value
	// that has wrapped past 2^64-1 back to 0 is not greater and is discarded.
	// A client that accepted it would have no replay detection at all, because
	// every replayed value is reachable by claiming a wrap.
	if s.seen && a.Replay <= s.replay {
		m.refuseReconfigure(out, ReconfigureRefusalReplay, "a Reconfigure repeats a replay detection value this server has already used: discarded (§20.3)")
		return nil, 0, false
	}
	return s, a.Replay, true
}

// respondToReconfigure is §18.2.11's response, and the states it is willing to
// respond from. It reports whether the client actually started the exchange:
// a "not now" is not an acceptance, and §20.3's replay floor must not move on
// one, or the server's retransmission is refused as a replay.
//
// §18.2.11's premise is "interfaces for which it has acquired configuration
// information through DHCP". A Renew names the server that granted a lease
// (§18.2.4) and a Rebind extends one (§18.2.5), so both need a lease in hand;
// an Information-request needs none. Every other state either has an exchange
// in flight — which the caller has already refused — or is mid-acquisition,
// where a Renew would name a binding that does not exist.
func (m *Machine6) respondToReconfigure(now Instant, rnd uint64, kind wire.MessageTypeV6, sid []byte, out *actions) bool {
	switch kind {
	case wire.MsgRenew, wire.MsgRebind:
		if m.state != State6Bound {
			m.refuseReconfigure(out, ReconfigureRefusalNoLease, fmt.Sprintf("an authenticated Reconfigure asks for a %s in %s: ignored, §18.2.11 addresses an interface that holds configuration", kind, m.state))
			return false
		}
		if kind == wire.MsgRenew {
			// §18.2.4: "The client MUST include a Server Identifier option
			// (see Section 21.3) in the Renew message, identifying the server
			// with which the client most recently communicated." That is the
			// server the LEASE names, which enterRenewing already reads, and
			// it falls back to a Rebind when the lease names none.
			out.journal(m, "an authenticated Reconfigure asks for a Renew (§18.2.11)")
			m.enterRenewing(now, rnd, out)
			return true
		}
		out.journal(m, "an authenticated Reconfigure asks for a Rebind (§18.2.11)")
		m.enterRebinding(now, rnd, out)
		return true
	case wire.MsgInformationRequest:
		switch m.state {
		case State6Bound:
			// §18.2.11 puts no condition on msg-type 11 and §21.19 lists it
			// unconditionally, so a bound client answers it — and comes back
			// to BOUND6 when the exchange ends, because an
			// Information-request carries no address and abandoning the lease
			// in a stateless detour would be the whole endpoint.
			m.reconfDetour = true
		case State6InfoRequesting:
		default:
			m.refuseReconfigure(out, ReconfigureRefusalNoConfiguration, fmt.Sprintf("an authenticated Reconfigure asks for an Information-request in %s: ignored, §18.2.11 addresses an interface that holds configuration", m.state))
			return false
		}
		// §18.2.6: "When responding to a Reconfigure, the client MUST include
		// a Server Identifier option (see Section 21.3) with the identifier
		// from the Reconfigure message to which the client is responding."
		// That is the Reconfigure's own Server Identifier and not the lease's:
		// a stateless client has no lease to read one from.
		out.journal(m, "an authenticated Reconfigure asks for an Information-request (§18.2.11)")
		m.startExchangeAnswering(now, rnd, wire.MsgInformationRequest, sid, out)
		return true
	default:
		// Unreachable: ReconfigureMessage refuses every msg-type outside
		// §21.19's three. Handled anyway, for Step's reason.
		m.refuseReconfigure(out, ReconfigureRefusalUndefinedMessage, fmt.Sprintf("an authenticated Reconfigure names msg-type %s, which §21.19 does not define: ignored", kind))
		return false
	}
}

// endReconfigureDetour returns a bound client to BOUND6 after the
// Information-request a Reconfigure asked for.
//
// It is called from takeConfig, which is where that exchange ends.
func (m *Machine6) endReconfigureDetour(out *actions) {
	m.reconfServerID = nil
	if !m.reconfDetour {
		return
	}
	m.reconfDetour = false
	m.state = State6Bound
	out.journal(m, "the Reconfigure's Information-request exchange is complete: back to "+State6Bound.String()+" with the lease and its timers untouched (§18.2.11)")
}
