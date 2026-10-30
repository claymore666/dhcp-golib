// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

//go:build linux

package runtime

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"syscall"
	"testing"

	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

// The transport half of claymore666/dhcp-golib#94: a unicast to a server that
// is behind a relay goes to the hardware address a reply naming that server
// was heard from. The witness is the kernel on the far end of the veth, as in
// transportOnARealLink: PACKET_HOST there means the frame was addressed to the
// MAC that interface has now.

const (
	relayTestRelay  = "192.168.99.1"
	relayTestServer = "10.9.9.9"
	relayTestLeased = "192.168.99.100"
)

// relayReply is a DHCPACK-shaped payload naming server in option 54.
func relayReply(t *testing.T, op wire.OpCode, server []byte) []byte {
	t.Helper()
	m := &wire.Message{Op: op, HType: 1, CHAddr: []byte{2, 0, 0, 0, 0, 1}, Options: wire.Options{}}
	m.Options[wire.OptMessageType] = []byte{byte(wire.MsgAck)}
	if server != nil {
		m.Options[wire.OptServerID] = server
	}
	b, err := wire.Encode(m)
	if err != nil {
		t.Fatalf("wire.Encode: %v", err)
	}
	return b
}

// injectReply puts payload on the link as a datagram to the client port from
// srcIP, sent from the peer interface's CURRENT hardware address.
func injectReply(t *testing.T, srcIP string, payload []byte) {
	t.Helper()
	frame, err := BuildIPv4UDP(netip.MustParseAddr(srcIP), netip.MustParseAddr("255.255.255.255"),
		ServerPort, ClientPort, 1, 1, payload)
	if err != nil {
		t.Fatalf("BuildIPv4UDP: %v", err)
	}
	injectFrames(t, testServerIf, frame)
}

func awaitReads(tr *PacketTransport, n uint64) {
	for tr.Stats().Reads < n {
		runtime.Gosched()
	}
}

func relayLink(t *testing.T) *PacketTransport {
	t.Helper()
	mustRun(t, "ip", "link", "add", testClientIf, "type", "veth", "peer", "name", testServerIf)
	mustRun(t, "ip", "link", "set", testServerIf, "up")
	mustRun(t, "ip", "link", "set", testClientIf, "up")
	tr, err := NewPacketTransport(testClientIf)
	if err != nil {
		t.Fatalf("NewPacketTransport: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}

func toServer(addr string) proto.Dest {
	return proto.Dest{Addr: netip.MustParseAddr(addr), Src: netip.MustParseAddr(relayTestLeased)}
}

func setPeerMAC(t *testing.T, mac string) {
	t.Helper()
	mustRun(t, "ip", "link", "set", testServerIf, "down")
	mustRun(t, "ip", "link", "set", testServerIf, "address", mac)
	mustRun(t, "ip", "link", "set", testServerIf, "up")
}

func TestPacketTransportSendsToTheRelayThatDeliveredTheServersReply(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		transportSendsToTheRelay(t)
		return
	}
	reexecInNamespaces(t)
}

func transportSendsToTheRelay(t *testing.T) {
	tr := relayLink(t)
	witness := peerSocket(t, testServerIf)
	sid := []byte{10, 9, 9, 9}

	// Nothing heard about the server: refused, as before the fix.
	if err := tr.Send(toServer(relayTestServer), []byte("renew")); !errors.Is(err, ErrUnicastUnresolved) {
		t.Fatalf("unicast to an off-link server nothing was heard about: err = %v, want %v", err, ErrUnicastUnresolved)
	}

	// Replies that must NOT teach the transport a next hop for 10.9.9.9. Each
	// is read by the transport (Reads) and none may open the path.
	junk := map[string][]byte{
		"a request, not a reply":    relayReply(t, wire.BootRequest, sid),
		"no server identifier":      relayReply(t, wire.BootReply, nil),
		"a three octet identifier":  relayReply(t, wire.BootReply, []byte{10, 9, 9}),
		"an unspecified identifier": relayReply(t, wire.BootReply, []byte{0, 0, 0, 0}),
		"a broadcast identifier":    relayReply(t, wire.BootReply, []byte{255, 255, 255, 255}),
		"a multicast identifier":    relayReply(t, wire.BootReply, []byte{224, 0, 0, 1}),
		"not a DHCP message":        []byte("a reply"),
	}
	var reads uint64
	for what, payload := range junk {
		injectReply(t, relayTestRelay, payload)
		reads++
		awaitReads(tr, reads)
		if err := tr.Send(toServer(relayTestServer), []byte("renew")); !errors.Is(err, ErrUnicastUnresolved) {
			t.Fatalf("after %s: unicast to the server err = %v, want %v", what, err, ErrUnicastUnresolved)
		}
	}
	if got := tr.Stats().Sends; got != 0 {
		t.Fatalf("a refused send was counted: sends = %d", got)
	}

	// The relay forwards the server's ACK: IP source the relay, option 54 the
	// server. The renewal now reaches the relay's hardware address.
	injectReply(t, relayTestRelay, relayReply(t, wire.BootReply, sid))
	reads++
	awaitReads(tr, reads)
	renew := []byte("this stands in for the RENEW")
	if err := tr.Send(toServer(relayTestServer), renew); err != nil {
		t.Fatalf("unicast to a server behind a relay it was heard through: %v", err)
	}
	frame, class := awaitFrameToServerPort(t, witness)
	if class != syscall.PACKET_HOST {
		t.Fatalf("the frame arrived as packet class %d, want PACKET_HOST (%d): it was not addressed to the relay's hardware address", class, syscall.PACKET_HOST)
	}
	if got := netip.AddrFrom4([4]byte(frame[16:20])).String(); got != relayTestServer {
		t.Fatalf("IP destination = %s, want the server %s: RFC 2131 section 4.4.5 keeps it", got, relayTestServer)
	}
	if got := netip.AddrFrom4([4]byte(frame[12:16])).String(); got != relayTestLeased {
		t.Fatalf("IP source = %s, want the leased address %s", got, relayTestLeased)
	}
	if got := tr.Stats().Sends; got != 1 {
		t.Fatalf("sends = %d, want the one renewal", got)
	}

	// A different off-link server nothing was heard about stays refused.
	if err := tr.Send(toServer("10.9.9.8"), renew); !errors.Is(err, ErrUnicastUnresolved) {
		t.Fatalf("unicast to another server: err = %v, want %v", err, ErrUnicastUnresolved)
	}
}

func TestPacketTransportPrefersAServerHeardDirectlyToTheRelay(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		transportPrefersTheDirectEntry(t)
		return
	}
	reexecInNamespaces(t)
}

func transportPrefersTheDirectEntry(t *testing.T) {
	tr := relayLink(t)
	sid := []byte{10, 9, 9, 9}

	// First a relay vouches for the server from the interface's own MAC, then
	// the server itself is heard from another MAC. The on-link entry wins: an
	// on-link server behaves exactly as it did before the relay path existed.
	injectReply(t, relayTestRelay, relayReply(t, wire.BootReply, sid))
	awaitReads(tr, 1)
	setPeerMAC(t, "02:00:00:00:99:01")
	witness := peerSocket(t, testServerIf)
	injectReply(t, relayTestServer, relayReply(t, wire.BootReply, sid))
	awaitReads(tr, 2)

	if err := tr.Send(toServer(relayTestServer), []byte("renew")); err != nil {
		t.Fatalf("unicast to a server heard from directly: %v", err)
	}
	if _, class := awaitFrameToServerPort(t, witness); class != syscall.PACKET_HOST {
		t.Fatalf("the frame arrived as packet class %d, want PACKET_HOST (%d): the relay's older entry shadowed the server's own", class, syscall.PACKET_HOST)
	}

	// The other order: the server was heard directly, and a relay-shaped reply
	// naming it (another IP source, another hardware address) arrives later.
	// The server's own entry stands, so the renewal still goes to the MAC the
	// server was heard from, which this interface no longer has.
	setPeerMAC(t, "02:00:00:00:99:02")
	witness = peerSocket(t, testServerIf)
	injectReply(t, relayTestRelay, relayReply(t, wire.BootReply, sid))
	awaitReads(tr, 3)
	if err := tr.Send(toServer(relayTestServer), []byte("renew")); err != nil {
		t.Fatalf("unicast to a server heard from directly, after a relay-shaped reply: %v", err)
	}
	if _, class := awaitFrameToServerPort(t, witness); class == syscall.PACKET_HOST {
		t.Fatalf("the frame was addressed to the relay-shaped reply's hardware address, packet class %d: a later reply overwrote the address the server was heard from", class)
	}
}

func TestPacketTransportFollowsARelayToANewHardwareAddress(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		transportFollowsARelay(t)
		return
	}
	reexecInNamespaces(t)
}

func transportFollowsARelay(t *testing.T) {
	tr := relayLink(t)
	sid := []byte{10, 9, 9, 9}

	injectReply(t, relayTestRelay, relayReply(t, wire.BootReply, sid))
	awaitReads(tr, 1)
	setPeerMAC(t, "02:00:00:00:99:02")
	witness := peerSocket(t, testServerIf)
	injectReply(t, relayTestRelay, relayReply(t, wire.BootReply, sid))
	awaitReads(tr, 2)

	if err := tr.Send(toServer(relayTestServer), []byte("renew")); err != nil {
		t.Fatalf("unicast through the moved relay: %v", err)
	}
	if _, class := awaitFrameToServerPort(t, witness); class != syscall.PACKET_HOST {
		t.Fatalf("the frame arrived as packet class %d, want PACKET_HOST (%d): the transport kept the relay's first hardware address", class, syscall.PACKET_HOST)
	}
}

// A reply that names no server a unicast could be sent to teaches the
// transport nothing (claymore666/dhcp-golib#94), and what it does learn is a
// copy of the hardware address, not a view of the receive buffer.
func TestPacketTransportLearnsOnlyAnAddressableServerFromAReply(t *testing.T) {
	relayHW := []byte{2, 0, 0, 0, 0xaa, 1}
	src := netip.MustParseAddr(relayTestRelay)
	cases := []struct {
		name   string
		server []byte
		src    netip.Addr
		hw     []byte
	}{
		{"no hardware address", []byte{10, 9, 9, 9}, src, nil},
		{"unspecified sender", []byte{10, 9, 9, 9}, netip.IPv4Unspecified(), relayHW},
		{"no sender", []byte{10, 9, 9, 9}, netip.Addr{}, relayHW},
		{"server is the sender", []byte{192, 168, 99, 1}, src, relayHW},
		{"unspecified", []byte{0, 0, 0, 0}, src, relayHW},
		{"multicast", []byte{224, 0, 0, 1}, src, relayHW},
		{"broadcast", []byte{255, 255, 255, 255}, src, relayHW},
	}
	for _, c := range cases {
		tr := &PacketTransport{peers: map[netip.Addr]net.HardwareAddr{}, heardVia: map[netip.Addr]net.HardwareAddr{}}
		tr.learnServerVia(c.src, relayReply(t, wire.BootReply, c.server), c.hw)
		if len(tr.heardVia) != 0 || len(tr.peers) != 0 {
			t.Errorf("%s: learned %v %v from a reply that names no server to unicast to", c.name, tr.heardVia, tr.peers)
		}
	}

	tr := &PacketTransport{peers: map[netip.Addr]net.HardwareAddr{}, heardVia: map[netip.Addr]net.HardwareAddr{}}
	buf := append([]byte(nil), relayHW...)
	tr.learnServerVia(src, relayReply(t, wire.BootReply, []byte{10, 9, 9, 9}), buf)
	buf[5] = 0x77
	got, ok := tr.nextHopHardwareAddr(netip.MustParseAddr(relayTestServer))
	if !ok || !bytes.Equal(got, relayHW) {
		t.Errorf("remembered %v (%v) after the caller reused its buffer; want %v", got, ok, relayHW)
	}
}
