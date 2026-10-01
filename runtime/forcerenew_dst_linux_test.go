// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

//go:build linux

package runtime

import (
	"net/netip"
	"os"
	"testing"
)

// TestTheTransportDeliversTheDestinationOfAFrame runs the packet transport on a
// real link and reads what it hands the manager: an inbound datagram carries
// the IPv4 destination of its frame, because that is the only place a
// FORCERENEW's destination exists (claymore666/docker-net-dhcp#1119). Its
// namespace is the one the other packet-transport tests use.
func TestTheTransportDeliversTheDestinationOfAFrame(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		transportDeliversDestination(t)
		return
	}
	reexecInNamespaces(t)
}

func transportDeliversDestination(t *testing.T) {
	mustRun(t, "ip", "link", "add", testClientIf, "type", "veth", "peer", "name", testServerIf)
	mustRun(t, "ip", "link", "set", testServerIf, "up")
	mustRun(t, "ip", "link", "set", testClientIf, "up")

	tr, err := NewPacketTransport(testClientIf)
	if err != nil {
		t.Fatalf("NewPacketTransport: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	server := netip.MustParseAddr("192.168.99.1")
	var frames [][]byte
	dsts := []string{"255.255.255.255", "192.168.99.100", "224.0.0.1"}
	for i, d := range dsts {
		f, err := BuildIPv4UDP(server, netip.MustParseAddr(d), ServerPort, ClientPort,
			uint16(i+1), 64, []byte("a DHCP payload"))
		if err != nil {
			t.Fatalf("BuildIPv4UDP: %v", err)
		}
		frames = append(frames, f)
	}
	injectFrames(t, testServerIf, frames...)

	// Blocking receives, in the order sent: the link keeps frame order and
	// the transport has one reader.
	for _, d := range dsts {
		in := <-tr.Received()
		if in.To != netip.MustParseAddr(d) {
			t.Fatalf("inbound To = %s, want %s", in.To, d)
		}
		if in.From != server {
			t.Fatalf("inbound From = %s, want %s", in.From, server)
		}
	}
}
