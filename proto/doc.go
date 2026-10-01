// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

// Package proto is ring 1: the state machine. It is pure.
//
// No I/O, no clock, no goroutines, no ambient anything. The whole surface is
//
//	func (m *Machine) Step(now Time, rnd uint64, ev Event) (State, []Action)
//
// with time and entropy passed in as parameters rather than read from the
// environment. That is what makes the tests instant and offline replay
// bit-exact, and it is enforced by the T1 gate rather than by this comment.
//
// # Server-initiated reconfiguration, and its two bounds
//
// The DHCPv6 machine accepts RFC 9915 §18.2.11 Reconfigure messages by
// default: Params6.AcceptReconfigure is true in DefaultParams6, so a client
// announces §21.20's Reconfigure Accept option in its Solicit, Request and
// Information-request, records the reconfigure key a Reply carries (§20.4.3),
// and answers an authenticated Reconfigure with the Renew, Rebind or
// Information-request its Reconfigure Message option names. Every §16.11
// discard rule is applied, and a message that fails RKAP authentication or
// repeats a §20.3 replay detection value is dropped with a journal line.
//
// What this does NOT do, stated here because a default that is on makes all
// of it reachable:
//
// A reconfigure key survives a restart only through Resume6. The key, the
// replay floor and whether a floor exists ride Lease6, the record and Resume6
// (claymore666/dhcp-golib#28), and the machine restores the entry of the
// lease's own server from them. Two bounds stay: every other server's entry
// is lost at a restart, and a Reconfigure accepted since the last Reply that
// carries a lease moves the floor in the machine only: the record gets it at
// that Reply, so a restart before it accepts those Reconfigures again. An
// Information-request Reconfigure emits no lease, so any number of them can
// wait there. A machine rebuilt from a
// Resume6 with no key discards every Reconfigure from its server until the
// next Solicit/Reply, Request/Reply or Information-request/Reply hands it a
// new key (§20.4.2).
//
// The keyless span of a resume with no key is not one message, and it is not
// bounded by the resume. A resumed client's first message is §18.2.3's Confirm, which Appendix B Table
// 5 does not allow the Reconfigure Accept option in, so the resume itself
// reaches no exchange §20.4.2 hands a key to, and each Reconfigure that
// arrives meanwhile is reported as ReconfigureRefusalNoKey. What ends the span
// is the first ACCEPTED Reply carrying a key, whichever exchange it answers:
// §20.4.2 binds the server's selection and not the client's record, and a key
// in the Reply to the Renew at T1 is recorded like any other. Accepted is the
// word that carries the bound. §18.2.10's UnspecFail arm, its NotOnLink arm, a
// malformed Status Code option and a Reply with no usable address all return
// before the key is recorded, so a Reply this client does not act on leaves
// the span where it was. Where a server sends a key nowhere but the three
// exchanges §20.4.2 names, the span is the whole
// life of the resumed lease.
//
// The key is in three places a caller can hand to somebody else. The lease
// record carries it as reconfigure_key, where a DHCPv4 lease's nonce already
// sits, and so does the Params6 snapshot of a run that started from a resume.
// The Reply that delivered it keeps it verbatim in JournalEntry6.Raw and in the
// packet capture, because a replay needs the octets. No note, action or error
// string carries it.
//
// Half of §16.11's first bullet is somebody else's. "the message was not
// unicast to the client" is a fact about the datagram, and this package
// refuses a destination that is multicast, unspecified or absent. Whether a
// unicast destination is THIS client's address is decided by the transport —
// runtime.PacketTransportV6 drops every datagram addressed to another node,
// which TestAV6ClientDiscardsAnotherClientsReplyAtTheTransport drives on a
// real link — so a caller that supplies its own lease.TransportV6 takes that
// half on. A
// transport that hands up other nodes' datagrams will have their Reconfigure
// messages obeyed, provided they are signed with this client's reconfigure
// key.
//
// A refused Information-request holds the Reconfigure window open. §18.2.11
// ignores further Reconfigure messages "until the exchange it started
// completes", and an Information-request the server answers with a non-Success
// Status Code is an exchange that has not completed: the client keeps
// retransmitting it, so this package keeps ignoring Reconfigure messages. A
// client with a lease escapes when T1 or T2 fires, because the renewal takes
// precedence over the detour. A STATELESS client has neither timer, so a
// server that refuses every Information-request leaves it deaf to Reconfigure
// until something else moves it. The alternative — treating the first refusal
// as the end of the exchange — would have this library declare an exchange
// over while it is still sending it.
//
// §18.2.4's conditional MUST is UNIMPLEMENTED. "A client MUST also initiate a
// Renew/Reply message exchange before time T1 if the client's link-local
// address used in previous interactions with the server is no longer valid and
// it is willing to receive Reconfigure messages" — the condition's second half
// is now true by default, and this library does not watch its own link-local
// address for that purpose, so a client whose link-local address changes
// between T0 and T1 does not renew early to tell the server where to reach it.
// What that costs is the window between the change and T1, during which a
// Reconfigure is addressed to an address the client no longer holds and never
// arrives. It costs no lease: T1 still fires and the Renew still carries the
// new source address.
package proto
