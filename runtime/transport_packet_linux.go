//go:build linux

package runtime

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/claymore666/dhcplease/lease"
	"github.com/claymore666/dhcplease/proto"
)

// ethPIP is ETH_P_IP in host byte order. syscall does not export it.
const ethPIP = 0x0800

// inboundBuffer is how many parsed replies may sit undelivered before the
// reader drops them. Small on purpose: a DHCP exchange is a handful of packets,
// and a manager further behind than this has a problem a bigger buffer hides.
const inboundBuffer = 16

// maxFrame is the read buffer, sized so a jumbo frame carrying something else
// cannot be truncated into a DIFFERENT valid-looking frame.
const maxFrame = 9216

// broadcastMAC is the link-layer destination for every message this milestone
// sends. RFC 2131 section 4.1: a client with no configured address must
// broadcast at the link layer too — unicasting to an address the client does
// not yet have relies on it accepting a frame for an address it does not own.
var broadcastMAC = net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

var (
	// ErrTransportClosed is returned by Send after Close.
	ErrTransportClosed = errors.New("runtime: transport closed")
	// ErrUnicastUnsupported is returned for a unicast Dest. See Send.
	ErrUnicastUnsupported = errors.New("runtime: unicast send needs a resolved link-layer address")
)

// PacketTransport is the raw AF_PACKET transport.
//
// SOCK_DGRAM rather than SOCK_RAW: the kernel supplies the Ethernet header on
// send and strips it on receive, so we need not know the link's header format.
// The IP and UDP headers are still ours to build (see ipudp.go).
//
// BOUNDS:
//
//   - No BPF filter. Every IPv4 frame on the link is read and filtered in user
//     space by ParseIPv4UDP — real wasted wakeups on a busy link, measured as
//     Stats.Skipped. An LSF program is the fix; not at M1, because a wrong
//     filter drops the packet you are debugging and is invisible when it does.
//   - No ARP, therefore no unicast: Send refuses a unicast Dest with
//     ErrUnicastUnsupported rather than broadcasting it anyway. RENEWING
//     arrives in a later milestone, where an address on the interface makes an
//     ordinary UDP socket possible.
//   - No fragment reassembly (see ParseIPv4UDP).
type PacketTransport struct {
	f       *os.File
	ifIndex int
	src     netip.Addr

	inbound chan lease.Inbound

	ident atomic.Uint32

	// Without skipped, a transport that sees nothing and one that sees
	// everything and rejects all of it are the same silence. reads is bumped
	// LAST, in deliver: see the invariant there.
	reads   atomic.Uint64
	skipped atomic.Uint64
	sends   atomic.Uint64

	// The two ways a payload reaches us unverified, counted apart because they
	// have different diagnoses: see ChecksumState.
	uncompleted atomic.Uint64
	absent      atomic.Uint64
	dropped     atomic.Uint64

	closeOnce sync.Once
	closed    atomic.Bool
	wg        sync.WaitGroup
}

// TransportStats is what a PacketTransport has seen.
type TransportStats struct {
	Reads   uint64
	Skipped uint64
	Sends   uint64
	// Uncompleted counts accepted datagrams whose UDP checksum field held the
	// pseudo-header sum (CHECKSUM_PARTIAL); Absent counts those carrying no
	// checksum at all (RFC 768's zero). Neither payload was verified — see
	// acceptUDPChecksum — and counting them is what keeps that from being
	// silent.
	//
	// Neither says WHERE the sender is. The
	// expectation runs the other way and only as an expectation: a client
	// leasing from a server on this host shows Uncompleted on every reply.
	Uncompleted uint64
	Absent      uint64
	// Dropped counts DHCP replies that parsed and were then thrown away
	// because the consumer had not drained the inbound channel. Not Skipped:
	// see the drop site.
	Dropped uint64
}

// NewPacketTransport opens an AF_PACKET socket bound to ifName.
//
// NON-BLOCKING, handed to os.NewFile so the Go runtime poller owns it: a
// blocking raw socket read cannot be interrupted by closing the fd from
// another goroutine, and working around that ends in a leaked goroutine or a
// use-after-free on an fd number the runtime has reused. With the poller,
// Close unblocks the reader.
//
// For the same reason Send never calls f.Fd(), which would put the descriptor
// back into blocking mode and remove it from the poller. SyscallConn keeps it.
func NewPacketTransport(ifName string) (*PacketTransport, error) {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("runtime: interface %q: %w", ifName, err)
	}

	fd, err := syscall.Socket(syscall.AF_PACKET,
		syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK,
		int(htons(ethPIP)))
	if err != nil {
		return nil, fmt.Errorf("runtime: socket(AF_PACKET): %w", err)
	}

	sa := &syscall.SockaddrLinklayer{
		Protocol: htons(ethPIP),
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(fd, sa); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("runtime: bind(%s): %w", ifName, err)
	}

	t := &PacketTransport{
		f:       os.NewFile(uintptr(fd), "af_packet:"+ifName),
		ifIndex: iface.Index,
		src:     netip.AddrFrom4([4]byte{0, 0, 0, 0}),
		inbound: make(chan lease.Inbound, inboundBuffer),
	}
	t.wg.Add(1)
	go t.read()
	return t, nil
}

// Send builds the IPv4/UDP framing and transmits one payload.
func (t *PacketTransport) Send(dst proto.Dest, payload []byte) error {
	if t.closed.Load() {
		return ErrTransportClosed
	}
	if !dst.Broadcast {
		return fmt.Errorf("%w: %s", ErrUnicastUnsupported, dst.Addr)
	}

	// TTL 1 rather than 64: a broadcast to 255.255.255.255 is link-local by
	// definition (RFC 919) and must not be forwarded. A relay agent that needs
	// to forward it constructs its own datagram.
	frame, err := BuildIPv4UDP(t.src, netip.AddrFrom4([4]byte{255, 255, 255, 255}),
		ClientPort, ServerPort, uint16(t.ident.Add(1)), 1, payload)
	if err != nil {
		return err
	}

	lla := &syscall.SockaddrLinklayer{
		Protocol: htons(ethPIP),
		Ifindex:  t.ifIndex,
		Halen:    uint8(len(broadcastMAC)),
	}
	copy(lla.Addr[:], broadcastMAC)

	rc, err := t.f.SyscallConn()
	if err != nil {
		return fmt.Errorf("runtime: syscallconn: %w", err)
	}
	var serr error
	cerr := rc.Write(func(fd uintptr) bool {
		serr = syscall.Sendto(int(fd), frame, 0, lla)
		// Returning false parks the goroutine on the poller and retries when
		// the socket is writable. Any other error is final.
		return serr != syscall.EAGAIN
	})
	if cerr != nil {
		return fmt.Errorf("runtime: sendto: %w", cerr)
	}
	if serr != nil {
		return fmt.Errorf("runtime: sendto: %w", serr)
	}
	t.sends.Add(1)
	return nil
}

// Received is the stream of DHCP payloads addressed to the client port.
func (t *PacketTransport) Received() <-chan lease.Inbound { return t.inbound }

// Close shuts the socket. Safe to call more than once.
func (t *PacketTransport) Close() error {
	var err error
	t.closeOnce.Do(func() {
		t.closed.Store(true)
		err = t.f.Close()
		t.wg.Wait()
		close(t.inbound)
	})
	return err
}

// Stats reports what the socket has seen.
func (t *PacketTransport) Stats() TransportStats {
	return TransportStats{
		Reads:       t.reads.Load(),
		Skipped:     t.skipped.Load(),
		Sends:       t.sends.Load(),
		Uncompleted: t.uncompleted.Load(),
		Absent:      t.absent.Load(),
		Dropped:     t.dropped.Load(),
	}
}

func (t *PacketTransport) read() {
	defer t.wg.Done()
	buf := make([]byte, maxFrame)
	for {
		n, err := t.f.Read(buf)
		if err != nil {
			if t.closed.Load() {
				return
			}
			// A read error on a live socket is reported, not swallowed: an
			// interface going away is exactly this, and it must reach the
			// machine as an event rather than as a silence.
			select {
			case t.inbound <- lease.Inbound{Err: fmt.Errorf("runtime: read: %w", err)}:
			default:
			}
			return
		}
		t.deliver(buf[:n])
	}
}

// deliver classifies one frame and, if it is a reply for us, queues it.
//
// The read counter is bumped in a DEFER, LAST, which makes Reads a barrier:
// seeing Reads reach N means those N frames have each been skipped, dropped or
// queued. Bumping it on arrival instead left the last frame classified a few
// instructions later, a race a test cannot wait out.
// TestPacketTransportDropsWhenTheConsumerStalls.
func (t *PacketTransport) deliver(frame []byte) {
	defer t.reads.Add(1)
	dg, perr := ParseIPv4UDP(frame)
	if perr != nil {
		// Not for us — on a shared link, most of what arrives — so counted
		// rather than reported.
		t.skipped.Add(1)
		return
	}
	if !dg.Checksum.Verified() {
		// Accepted, and counted: the payload was NOT verified. See
		// acceptUDPChecksum. A client leasing from a server on the same
		// host shows Uncompleted on every reply, which is normal; a client
		// on a physical link showing either state is worth a second look.
		switch dg.Checksum {
		case ChecksumUncompleted:
			t.uncompleted.Add(1)
		case ChecksumAbsent:
			t.absent.Add(1)
		}
	}
	// The payload aliases buf, which the next read overwrites.
	p := make([]byte, len(dg.Payload))
	copy(p, dg.Payload)

	select {
	case t.inbound <- lease.Inbound{Payload: p, From: dg.Src}:
	default:
		// The consumer is behind. Blocking here would stall the reader and
		// lose packets in the kernel instead, where nothing can count them.
		//
		// Counted APART from Skipped: a frame that was not for us and a DHCP
		// reply we threw away are opposite facts, and one counter holding both
		// reports the second as the first. Dropped above zero means a stalled
		// manager and a retransmission that need not have happened.
		t.dropped.Add(1)
	}
}

// htons converts to network byte order. The AF_PACKET protocol field is
// big-endian even in a struct the kernel otherwise reads natively.
func htons(v uint16) uint16 { return v<<8 | v>>8 }
