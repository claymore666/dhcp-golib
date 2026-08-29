// Package runtime is ring 3: the effects. Sockets, the real clock, netlink,
// network namespaces, persistence and metrics. This is the only ring allowed
// to make a syscall.
//
// The name shadows the standard library's runtime in prose but not in import
// paths; this package is github.com/claymore666/dhcplease/runtime.
//
// # What is here at M1, and why it is here rather than later
//
// The raw AF_PACKET transport, the two clocks, the bounded journal and the
// bounded packet ring. The build plan puts the debug primitives in this
// milestone deliberately: they are how the milestones after it get debugged,
// and a journal added once there is something to debug is a journal designed
// around the bug that was already found.
//
// # The bound this ring does not remove
//
// The design document says it plainly (section 2.3) and it is worth repeating
// where the sockets actually are: ring 1's purity makes the PROTOCOL
// exhaustively testable and does nothing at all for packet loss, socket
// errors, an interface disappearing, or a namespace going away. That is this
// package, and it is where this project's most expensive failures have
// historically lived. Ring 3 is tested against a real dnsmasq on a real veth
// pair for exactly that reason.
//
// # Portability
//
// Linux only in substance. The clock reads CLOCK_BOOTTIME and the transport is
// AF_PACKET; both have build-tagged fallbacks that keep the package compiling
// elsewhere, and the fallbacks say what they cannot do rather than pretending.
package runtime
