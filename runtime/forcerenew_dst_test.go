// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package runtime

import (
	"net/netip"
	"testing"
)

// TestTheDatagramReportsTheDestinationOfItsHeader. A FORCERENEW is accepted on
// the address it was sent to and refused when it was broadcast or multicast
// (RFC 3203 section 2.2; claymore666/docker-net-dhcp#1119), and that address is
// in the IPv4 header's octets 16 to 19 only. Source and destination differ
// here so that a parse that returned one for the other is a failure.
func TestTheDatagramReportsTheDestinationOfItsHeader(t *testing.T) {
	for _, dst := range []string{"192.168.99.50", "255.255.255.255", "224.0.0.1"} {
		frame, err := BuildIPv4UDP(
			netip.MustParseAddr("192.168.99.1"), netip.MustParseAddr(dst),
			ServerPort, ClientPort, 0x1234, 64, []byte("a DHCP payload"))
		if err != nil {
			t.Fatalf("BuildIPv4UDP: %v", err)
		}
		dg, err := ParseIPv4UDP(frame)
		if err != nil {
			t.Fatalf("ParseIPv4UDP to %s: %v", dst, err)
		}
		if dg.Dst != netip.MustParseAddr(dst) {
			t.Fatalf("destination = %s, want %s", dg.Dst, dst)
		}
		if dg.Src != netip.MustParseAddr("192.168.99.1") {
			t.Fatalf("source = %s, want 192.168.99.1", dg.Src)
		}
	}
}
