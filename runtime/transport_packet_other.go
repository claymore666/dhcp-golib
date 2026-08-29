//go:build !linux

package runtime

import (
	"errors"

	"github.com/claymore666/dhcplease/lease"
	"github.com/claymore666/dhcplease/proto"
)

// ErrUnsupportedPlatform is returned by NewPacketTransport off Linux.
//
// A stub that returns an error rather than a build failure, so that the pure
// rings and their tests remain usable on a developer's non-Linux machine. It
// does not pretend to work: there is no portable way to send an IPv4 datagram
// with source 0.0.0.0 on an unconfigured interface, and a "portable" transport
// that silently used an ordinary UDP socket would fail only against a real
// server, which is the worst place to find out.
var ErrUnsupportedPlatform = errors.New("runtime: AF_PACKET transport requires Linux")

// TransportStats is what a PacketTransport has seen.
type TransportStats struct {
	Reads   uint64
	Skipped uint64
	Sends   uint64
}

// PacketTransport is not available on this platform.
type PacketTransport struct{}

// NewPacketTransport always fails off Linux.
func NewPacketTransport(string) (*PacketTransport, error) { return nil, ErrUnsupportedPlatform }

// Send always fails off Linux.
func (*PacketTransport) Send(proto.Dest, []byte) error { return ErrUnsupportedPlatform }

// Received returns a closed channel off Linux.
func (*PacketTransport) Received() <-chan lease.Inbound {
	ch := make(chan lease.Inbound)
	close(ch)
	return ch
}

// Close is a no-op off Linux.
func (*PacketTransport) Close() error { return nil }

// Stats returns zeroes off Linux.
func (*PacketTransport) Stats() TransportStats { return TransportStats{} }
