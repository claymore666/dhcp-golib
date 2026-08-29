// Package runtime is ring 3: the effects. Sockets, the real clock, netlink,
// network namespaces, persistence and metrics. This is the only ring allowed
// to make a syscall.
//
// The name shadows the standard library's runtime in prose but not in import
// paths; this package is github.com/claymore666/dhcplease/runtime.
//
// Empty at M0 by design.
package runtime
