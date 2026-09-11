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
// # The ports
//
// Every effect is an interface declared here and implemented in ring 3. That
// is what lets the whole acquisition path be table-tested with no root, no
// namespace and no network — the fake implementations in this package's tests
// are the same shape as the real ones.
//
// # Two protocols, one lease
//
// On IPv6 the configuration arrives on two protocols at once, and the lease a
// caller reads carries both. DHCPv6 has no gateway and no MTU at all; those
// come from the Router Advertisement, along with resolvers and a search list
// that DHCPv6 may also have sent. Where both sent the same kind of thing the
// DHCP entries keep their places and the advertisement's are appended after
// them, RFC 8106 section 5.3.1: "the DNS information from DHCP takes
// precedence over that from RAs". Nothing is applied to the link here either;
// a lease is a report.
package lease
