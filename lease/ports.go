package lease

import (
	"net/netip"
	"time"

	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

// Clock is the two clocks the design document's section 8.2 requires, and they
// are not interchangeable: Mono is the interval clock every ring-1 deadline is
// computed on (RFC 2131 section 3.3), Wall is the absolute clock a lease that
// must survive a restart is persisted on. Which monotonic clock Mono reads
// decides the host-suspend case; see runtime.Clock, where that is chosen.
type Clock interface {
	Mono() proto.Instant
	Wall() time.Time
}

// Entropy is the source of the rnd parameter Step takes. An interface rather
// than an io.Reader so a test supplies a fixed sequence in one line, and so
// that "one value per Step" is a property of this package's loop rather than
// of whatever a Reader returns.
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

// Transport carries DHCP payloads — the UDP payload only. Building the IP and
// UDP headers, and getting them onto a link the kernel has no address on, is
// ring 3's problem.
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

// Timers turns ring 1's SetTimer and CancelTimer into one fire on Fired.
//
// Set on an already-armed timer REPLACES it: ring 1 re-arms the retransmit
// timer freely and never tracks what is armed, so a Timers that queued a
// second fire would produce a retransmission storm no ring-1 test could see.
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

// CapturedPacket is one message in or out, decoded, with a timestamp (G1).
//
// Raw is kept beside the decoded message because the pcap export (G4) needs
// the bytes, and because a message that FAILED to decode is the one worth
// having: Msg is nil then and DecodeErr says why.
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

// Store is the durable lease-record log: the port ring 3 implements and the
// only thing that survives the process.
//
// It is deliberately NOT a record store. What is durable is the event stream;
// the record is the fold of it (Rebuild). A port with Get and Put for records
// would make the last writer the truth and would lose the one property this
// design is built on — that a restart replays what happened rather than
// trusting a summary somebody wrote down.
//
// APPEND-ONLY AND IN ORDER. Load returns every event this store holds, in the
// order it was appended, which is what makes the fold's answer a function of
// the file. A Load that sorted, de-duplicated or reversed would satisfy any
// test that counted lines; the ordering is asserted directly, and the fold's
// own per-record sequence check refuses a reordering independently.
//
// AN IMPLEMENTATION MAY SKIP WHAT IT CANNOT READ. A process killed inside an
// Append leaves a fragment, and refusing the whole file for it would lose every
// record written before the crash. Skipping is therefore allowed and COUNTING
// what was skipped is not optional — see runtime.RecordStore, which reports a
// torn tail and an unreadable interior line as two different numbers.
type Store interface {
	// Append writes one event. It must be atomic against a concurrent Append
	// from another process on the same file: one line, one write.
	Append(RecordEvent) error
	// Load returns every event, in append order.
	Load() ([]RecordEvent, error)
}
