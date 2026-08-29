// Package runtime is ring 3: the effects. Sockets, the real clock, netlink,
// network namespaces, persistence and metrics. The only ring allowed to make a
// syscall. It shadows the standard library's runtime in prose but not in
// import paths.
//
// BOUND (design document section 2.3): ring 1's purity makes the PROTOCOL
// exhaustively testable and does nothing for packet loss, socket errors, an
// interface disappearing or a namespace going away. Those live here, which is
// why this ring is tested against a real dnsmasq on a real veth pair.
//
// Linux only in substance — CLOCK_BOOTTIME and AF_PACKET. The build-tagged
// fallbacks keep the package compiling elsewhere and say what they cannot do
// rather than pretending.
package runtime
