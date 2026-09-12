// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

// Package lease is ring 2: the manager. One managed lease per
// (interface, family). It turns the actions ring 1 returns into requests on
// ring 3 and reports lease changes outward.
//
// # What ring 2 is FOR
//
// Two things ring 1 cannot do and ring 3 must not decide:
//
//  1. Serialisation. One event at a time per managed lease, with the whole
//     action list drained before the next Step. This is the trap the design
//     exists to close: actions must execute in the order returned, and a
//     packet arriving mid-drain must not interleave. It is cheap here and a
//     source of heisenbugs anywhere else.
//
//  2. The bridge between the two clocks. Ring 1 works entirely in monotonic
//     Instants, because RFC 2131 section 3.3 needs intervals on a clock that
//     does not step. A lease reported outward, or persisted, needs wall-clock
//     absolute times, because a monotonic reading means nothing to the next
//     process. Ring 2 owns the conversion and it is the only place the two
//     meet.
//
// # A refusal is an event, not a silence
//
// A caller that gets no address wants to know which of two things happened,
// and Event answers it in two fields rather than in Note's words. Failed with
// Reason ReasonNak is a server that ANSWERED and said no — RFC 2131's DHCPNAK,
// or RFC 9915 section 21.13's Status Code option, whose code is then in
// Event.Status. Nobody answering at all is ReasonNoServer on the v4 path and,
// on the v6 path, is still the caller's own deadline: this library keeps
// soliciting for as long as it is run, because RFC 9915 section 18.2.1 gives
// the Solicit no retransmission bound.
//
// The router observation is the other half of that question on a v6 link: a
// link whose Router Advertisement says M=0 has no addresses to give out and
// has refused nobody. READ IT LIVE, FROM Manager.Router, AND NOT FROM THE
// COPY ON THE EVENT IN HAND. Event.Router is a snapshot stamped when the event
// was emitted, and RFC 9915 section 18.2.1's Solicit does not wait for router
// discovery: an event from early in the exchange can carry the zero
// observation, which renders as "no router advertisement seen" and reads
// exactly like a link with no router on it.
//
// WHICH OF THE TWO A REFUSAL CARRIES IS TIMING AND NOT A FACT ABOUT THE LINK,
// and both ends of that are driven.
// TestTheRouterObservationOnARefusalIsWhatHadBeenSeenByThen refuses before any
// advertisement arrives and the refusal carries the zero; on the netns
// stateless fixture, MEASURED over four runs on 2026-09-11, the advertisement
// won the race every time and the refusals there carried M=0 O=1. So a caller
// classifying "why is there no address here" asks Manager.Router at the point
// its own deadline runs out, where the answer is the current one.
//
// # The ports
//
// Every effect is an interface declared here and implemented in ring 3. That
// is what lets the whole acquisition path be table-tested with no root, no
// namespace and no network — the fake implementations in this package's tests
// are the same shape as the real ones.
package lease
