//go:build linux

package runtime

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"syscall"
	"testing"

	"github.com/claymore666/dhcplease/proto"
)

// This file tests the AF_PACKET transport against a real link, with no server
// on it. The dnsmasq test covers the exchange; this one covers the two things
// that test cannot reach — the frame this library actually puts on the wire,
// read back by an independent socket, and the refusal that keeps a message the
// transport cannot address from being silently broadcast instead.
//
// It runs in its own user and network namespace for the reasons the dnsmasq
// test's header gives.

func TestPacketTransportOnARealLink(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		transportOnARealLink(t)
		return
	}
	reexecInNamespaces(t, "TestPacketTransportOnARealLink")
}

func transportOnARealLink(t *testing.T) {
	mustRun(t, "ip", "link", "add", testClientIf, "type", "veth", "peer", "name", testServerIf)
	mustRun(t, "ip", "link", "set", testServerIf, "up")
	mustRun(t, "ip", "link", "set", testClientIf, "up")

	// The witness: an ordinary packet socket on the OTHER end of the link.
	// Asserting on the transport's own Stats would be asserting on the
	// library's opinion of what it sent.
	peer := peerSocket(t, testServerIf)

	tr, err := NewPacketTransport(testClientIf)
	if err != nil {
		t.Fatalf("NewPacketTransport: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	// A unicast destination is REFUSED, not quietly broadcast. Ring 1 does not
	// produce one before RENEWING, so nothing else in the suite reaches this
	// line; without it, a later milestone's first unicast would go to the
	// broadcast address and appear to work.
	err = tr.Send(proto.Dest{Addr: netip.MustParseAddr("192.168.99.1")}, []byte("unicast"))
	if !errors.Is(err, ErrUnicastUnsupported) {
		t.Fatalf("unicast send: err = %v, want %v", err, ErrUnicastUnsupported)
	}
	if got := tr.Stats().Sends; got != 0 {
		t.Fatalf("a refused send was counted: sends = %d", got)
	}

	payload := []byte("this is not a DHCP message, and the wire does not care")
	if err := tr.Send(proto.Dest{Broadcast: true}, payload); err != nil {
		t.Fatalf("broadcast send: %v", err)
	}

	frame := awaitFrameToServerPort(t, peer)

	// RFC 2131 section 4.1: source address 0, broadcast destination. RFC 919
	// for the address itself. These are the fields a client with no address
	// has no other way to set, and they are why this transport exists.
	if got := netip.AddrFrom4([4]byte(frame[12:16])).String(); got != "0.0.0.0" {
		t.Fatalf("source address = %s, want 0.0.0.0", got)
	}
	if got := netip.AddrFrom4([4]byte(frame[16:20])).String(); got != "255.255.255.255" {
		t.Fatalf("destination address = %s, want the broadcast address", got)
	}
	if got := frame[8]; got != 1 {
		t.Fatalf("TTL = %d, want 1: a link-local broadcast must not be forwarded", got)
	}
	if got := binary.BigEndian.Uint16(frame[20:22]); got != ClientPort {
		t.Fatalf("source port = %d, want %d", got, ClientPort)
	}
	total := int(binary.BigEndian.Uint16(frame[2:4]))
	if got := frame[28:total]; !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
	// The witness parses the checksums we computed. This is the half of
	// BuildIPv4UDP that a golden-bytes test cannot reach: those bytes were
	// checked against a table, these were checked by the kernel's own idea of
	// a well-formed IPv4 datagram plus an independent verification here.
	if got := checksum(frame[:20]); got != 0 {
		t.Fatalf("IPv4 header checksum does not verify: %#04x", got)
	}
	var s4, d4 [4]byte
	copy(s4[:], frame[12:16])
	copy(d4[:], frame[16:20])
	if got := udpChecksumVerify(s4, d4, frame[20:total]); got != 0 {
		t.Fatalf("UDP checksum does not verify: %#04x", got)
	}

	if got := tr.Stats().Sends; got != 1 {
		t.Fatalf("sends = %d, want 1", got)
	}

	// ------------------------------------------ the two counters, driven --
	//
	// Skipped and Absent are the transport's answers to "what did you throw
	// away, and what could you not check". Both survived mutation on
	// 2026-08-29 — the increments could be deleted and nothing went red —
	// because nothing in the suite had ever put a frame on a real link that
	// exercised either. A counter nobody drives is a counter nobody can trust
	// when it finally moves.
	notForUs, err := BuildIPv4UDP(
		netip.MustParseAddr("192.168.99.1"), netip.MustParseAddr("255.255.255.255"),
		ServerPort, 9999, 1, 1, []byte("someone else's traffic"))
	if err != nil {
		t.Fatalf("BuildIPv4UDP: %v", err)
	}
	noChecksum, err := BuildIPv4UDP(
		netip.MustParseAddr("192.168.99.1"), netip.MustParseAddr("255.255.255.255"),
		ServerPort, ClientPort, 2, 1, []byte("no checksum here"))
	if err != nil {
		t.Fatalf("BuildIPv4UDP: %v", err)
	}
	// RFC 768's "not computed". Zeroing the field is the whole mutation.
	binary.BigEndian.PutUint16(noChecksum[26:28], 0)

	injectFrames(t, testServerIf, notForUs, noChecksum)

	// The barrier is Reads, which the transport bumps only after a frame has
	// been fully classified. Spinning on the counters under test instead would
	// turn a broken counter into an infinite spin rather than a failed
	// assertion — MEASURED 2026-08-29: written that way, both counter mutants
	// below came back as 200-second HANGS, and a hang is not a kill.
	for tr.Stats().Reads < 2 {
		runtime.Gosched()
	}
	st := tr.Stats()
	if st.Skipped != 1 {
		t.Fatalf("skipped = %d, want exactly the one frame for another port", st.Skipped)
	}
	if st.Absent != 1 {
		t.Fatalf("absent = %d, want exactly the one frame with no checksum", st.Absent)
	}
	if st.Uncompleted != 0 {
		t.Fatalf("uncompleted = %d, want 0: every frame here was built with a completed checksum", st.Uncompleted)
	}
	if st.Dropped != 0 {
		t.Fatalf("dropped = %d, want 0: two frames do not fill the channel", st.Dropped)
	}
}

// TestPacketTransportDropsWhenTheConsumerStalls drives the one path in the
// reader that throws a valid DHCP reply away.
//
// It exists because that path shares its shape with the "not for us" path and
// used to share its counter: a stalled manager and a segment full of other
// people's traffic reported as the same number. Nothing else in the suite
// reaches it — the manager always drains — and a counter nobody drives is a
// counter nobody can trust when it finally moves.
func TestPacketTransportDropsWhenTheConsumerStalls(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		transportDropsWhenStalled(t)
		return
	}
	reexecInNamespaces(t, "TestPacketTransportDropsWhenTheConsumerStalls")
}

func transportDropsWhenStalled(t *testing.T) {
	mustRun(t, "ip", "link", "add", testClientIf, "type", "veth", "peer", "name", testServerIf)
	mustRun(t, "ip", "link", "set", testServerIf, "up")
	mustRun(t, "ip", "link", "set", testClientIf, "up")

	tr, err := NewPacketTransport(testClientIf)
	if err != nil {
		t.Fatalf("NewPacketTransport: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	// Nothing consumes tr.Received() DURING a round: this test is the stalled
	// consumer. It drains between rounds so the next round starts from an
	// empty channel.
	//
	// It runs the cycle 40 times because one cycle is one sample of a race.
	// The bumped-on-arrival mutant — the shape that produced the flake this
	// test was written after — is caught by the invariant assertion below,
	// but only when the last frame's classification loses the race.
	//
	// The count is MEASURED against that mutant, not chosen: 16 of 30 at one
	// cycle, 10 of 12 at eight, 12 of 12 at forty. Eight was picked first on
	// the arithmetic of independent trials and the arithmetic was wrong — the
	// cycles are correlated, because a warm reader wins the race more often
	// than a cold one. Forty cycles cost about a second. Detection is a rate,
	// not a guarantee: this catches the mutant, it does not prove it cannot
	// slip through.
	const sent = inboundBuffer + 8
	const rounds = 40
	var consumed uint64

	for round := 1; round <= rounds; round++ {
		injectReplies(t, testServerIf, sent)

		// The barrier is Reads, spun on rather than slept on. It is exact
		// because the transport bumps it only after the frame has been
		// classified: an earlier version of this test span on it while it was
		// bumped on ARRIVAL and read Dropped as 7 of 8, one instant too early.
		// MEASURED 2026-08-29 by the mutation harness, whose control-before
		// check caught the flake on the fourth run of a test that had passed
		// twice. If a frame never arrives the test hangs into go test's own
		// timeout instead of passing early on a guess. No duration appears in
		// this file — see the T2 gate.
		want := uint64(round) * uint64(sent)
		for tr.Stats().Reads < want {
			runtime.Gosched()
		}

		st := tr.Stats()
		if st.Reads != want {
			t.Fatalf("round %d: reads = %d, want %d", round, st.Reads, want)
		}
		// The invariant Reads bumps last in order to make true, asserted
		// rather than assumed: every frame read was skipped, dropped, queued
		// or already taken.
		if got := st.Skipped + st.Dropped + consumed + uint64(len(tr.Received())); got != st.Reads {
			t.Fatalf("round %d: %d frames accounted for, %d read", round, got, st.Reads)
		}
		if st.Skipped != 0 {
			t.Fatalf("round %d: skipped = %d, want 0: every frame was a well-formed reply to the client port",
				round, st.Skipped)
		}
		if wantDropped := uint64(round) * uint64(sent-inboundBuffer); st.Dropped != wantDropped {
			t.Fatalf("round %d: dropped = %d, want %d (%d sent per round, %d fit in the channel)",
				round, st.Dropped, wantDropped, sent, inboundBuffer)
		}
		if got := len(tr.Received()); got != inboundBuffer {
			t.Fatalf("round %d: %d replies are queued, want the channel full at %d", round, got, inboundBuffer)
		}

		// Drain, so the next round measures a fresh fill rather than a channel
		// that was already full.
		for len(tr.Received()) > 0 {
			<-tr.Received()
			consumed++
		}
	}
}

// injectReplies puts n well-formed DHCP replies on the link from ifName. They
// are built by this package's own BuildIPv4UDP, which is what makes them
// acceptable to the parser under test; what is being driven here is the
// reader's queueing, not the codec.
func injectReplies(t *testing.T, ifName string, n int) {
	t.Helper()
	frames := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		frame, err := BuildIPv4UDP(
			netip.MustParseAddr("192.168.99.1"),
			netip.MustParseAddr("255.255.255.255"),
			ServerPort, ClientPort, uint16(i), 1, []byte{byte(i)})
		if err != nil {
			t.Fatalf("BuildIPv4UDP: %v", err)
		}
		frames = append(frames, frame)
	}
	injectFrames(t, ifName, frames...)
}

// injectFrames broadcasts raw IPv4 frames from ifName.
func injectFrames(t *testing.T, ifName string, frames ...[]byte) {
	t.Helper()
	fd := peerSocket(t, ifName)
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		t.Fatalf("%s: %v", ifName, err)
	}
	lla := &syscall.SockaddrLinklayer{
		Protocol: htons(ethPIP),
		Ifindex:  iface.Index,
		Halen:    6,
	}
	copy(lla.Addr[:], []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	for i, frame := range frames {
		if err := syscall.Sendto(fd, frame, 0, lla); err != nil {
			t.Fatalf("sendto frame %d: %v", i, err)
		}
	}
}

// peerSocket opens a blocking packet socket on ifName. It is deliberately NOT
// the transport under test: a bug in the transport's own reader would
// otherwise hide a bug in its writer.
func peerSocket(t *testing.T, ifName string) int {
	t.Helper()
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		t.Fatalf("%s: %v", ifName, err)
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, int(htons(ethPIP)))
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Close(fd) })
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(ethPIP), Ifindex: iface.Index}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	return fd
}

// awaitFrameToServerPort blocks until a UDP frame addressed to the server port
// arrives. There is no deadline here on purpose: go test's own timeout is the
// backstop, and a duration in this file would be a guess that either flakes or
// hides a hang. See the T2 gate.
func awaitFrameToServerPort(t *testing.T, fd int) []byte {
	t.Helper()
	buf := make([]byte, maxFrame)
	for {
		n, err := syscall.Read(fd, buf)
		if err != nil {
			t.Fatalf("read on the witness socket: %v", err)
		}
		f := buf[:n]
		if len(f) < 28 || f[0]>>4 != ipv4Version || f[9] != protoUDP {
			continue
		}
		if binary.BigEndian.Uint16(f[22:24]) != ServerPort {
			continue
		}
		return append([]byte(nil), f...)
	}
}
