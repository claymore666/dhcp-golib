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
// Four things this does NOT do, stated here because a default that is on
// makes all of them reachable:
//
// No reconfigure key survives a restart. A key is held in the Machine6 alone:
// not in Resume6, and not in the lease record a caller persists, because it is
// a shared secret and that record is the one callers log and hand to Journal6.
// A machine rebuilt after a restart therefore discards every
// Reconfigure from its server until the next Solicit/Reply, Request/Reply or
// Information-request/Reply hands it a new key (§20.4.2). The cost is one
// refused Reconfigure per restart; the server falls back to the client's own
// T1.
//
// The recorded datagram is the exception to that, and a caller handing out a
// journal needs it: the Reply that delivered the key keeps it verbatim in
// JournalEntry6.Raw and in the packet capture, because a replay needs the
// octets. The sentence above is about what a rebuilt machine holds, and not
// about what a saved journal contains.
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
