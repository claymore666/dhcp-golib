package lease

import (
	"net/netip"
	"time"

	"github.com/claymore666/dhcplease/proto"
	"github.com/claymore666/dhcplease/wire"
)

// Clock is the two clocks the design document's section 8.2 requires, and they
// are not interchangeable.
//
//   - Mono is the interval clock. Ring 1 computes every deadline on it, because
//     RFC 2131 section 3.3 requires the client's and server's clocks to be
//     stable relative to each other, which forces intervals onto a clock that
//     cannot be stepped by ntpd or by an operator.
//   - Wall is the absolute clock, and it exists for exactly one reason: a lease
//     that must survive a process restart can only be persisted as a wall-clock
//     absolute expiry, because a monotonic reading means nothing to the next
//     process.
//
// Ring 3's implementation reads CLOCK_BOOTTIME for Mono, not CLOCK_MONOTONIC.
// That choice decides the host-suspend case and is documented where it is
// made.
type Clock interface {
	Mono() proto.Instant
	Wall() time.Time
}

// Entropy is the source of the rnd parameter Step takes.
//
// It is an interface rather than an io.Reader so that a test supplies a fixed
// sequence in one line, and so that "the machine consumes exactly one value
// per Step" is a property of this package's loop rather than of whatever a
// Reader happens to return.
type Entropy interface {
	Uint64() uint64
}

// Inbound is one thing that arrived on the transport.
//
// Err and Payload are mutually exclusive. A transport reporting an error is
// not reporting an empty packet: an error folded into a value has no
// direction, and a zero-length payload that means "the socket died" is exactly
// that defect.
type Inbound struct {
	Payload []byte
	From    netip.Addr
	Err     error
}

// Transport carries DHCP payloads. It is the UDP payload only — building the
// IP and UDP headers, and getting them onto a link the kernel has no address
// on, is ring 3's problem and is invisible here.
type Transport interface {
	// Send transmits one payload. A returned error becomes an
	// EvActionFailed for the action that asked for the send, which is R2:
	// the machine never assumes an action succeeded.
	Send(dst proto.Dest, payload []byte) error
	// Received is the stream of inbound payloads. It is closed when the
	// transport is closed.
	Received() <-chan Inbound
	// Close releases the transport. It is safe to call more than once.
	Close() error
}

// Timers is the timer service. Ring 1 emits SetTimer and CancelTimer; this
// turns them into one fire on Fired.
//
// Set on an already-armed timer REPLACES it. That is the contract ring 1
// assumes — it re-arms the retransmit timer freely and never tracks what is
// armed — and a Timers that queued a second fire instead would produce a
// retransmission storm that no ring-1 test could see.
type Timers interface {
	Set(id proto.TimerID, after proto.Duration)
	Cancel(id proto.TimerID)
	Fired() <-chan proto.TimerID
	Close() error
}

// Journal records every Step. See proto.JournalEntry.
type Journal interface {
	Append(proto.JournalEntry)
	Entries() []proto.JournalEntry
}

// Direction says which way a captured packet went.
type Direction uint8

// Inbound and outbound, for the packet ring.
const (
	DirIn Direction = iota
	DirOut
)

func (d Direction) String() string {
	if d == DirOut {
		return "out"
	}
	return "in"
}

// CapturedPacket is one message in or out, stored decoded, with a timestamp —
// requirement G1.
//
// Raw is kept beside the decoded message because the pcap export (G4) needs
// the bytes and because a message that FAILED to decode is exactly the one
// worth having: Msg is nil then and DecodeErr says why.
type CapturedPacket struct {
	At        time.Time
	Dir       Direction
	Raw       []byte
	Msg       *wire.Message
	DecodeErr error
}

// PacketRing is the bounded ring of every message in and out (G1, R3).
type PacketRing interface {
	Record(CapturedPacket)
	Packets() []CapturedPacket
}
