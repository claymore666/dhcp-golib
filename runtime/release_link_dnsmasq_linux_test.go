// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

//go:build linux

package runtime

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/claymore666/dhcp-golib/lease"
	"github.com/claymore666/dhcp-golib/wire"
)

// linkEndpointMAC is the released lease's chaddr: a container's MAC on a
// macvlan parent, never the parent's own.
var linkEndpointMAC = net.HardwareAddr{0x02, 0x00, 0x5e, 0x12, 0x88, 0x10}

// TestAReleaseFromALinkWithNoHostAddressReachesRealDnsmasq gives a lease back
// over a client end that carries no IPv4 address, once with the server
// answering the ARP probe and once with it ignoring probes, and reads each
// outcome from dnsmasq's lease file and log.
func TestAReleaseFromALinkWithNoHostAddressReachesRealDnsmasq(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		linkReleaseAgainstDnsmasq(t)
		return
	}
	reexecInNamespaces(t)
}

func linkReleaseAgainstDnsmasq(t *testing.T) {
	started := time.Now()

	mustRun(t, "ip", "link", "add", testClientIf, "type", "veth", "peer", "name", testServerIf)
	mustRun(t, "ip", "addr", "add", testServerIP+"/24", "dev", testServerIf)
	mustRun(t, "ip", "link", "set", testServerIf, "up")
	mustRun(t, "ip", "link", "set", testClientIf, "up")
	mustRun(t, "ip", "link", "set", "lo", "up")

	srv := startDnsmasq(t)
	parent, err := net.InterfaceByName(testClientIf)
	if err != nil {
		t.Fatalf("InterfaceByName(%s): %v", testClientIf, err)
	}
	server, err := net.InterfaceByName(testServerIf)
	if err != nil {
		t.Fatalf("InterfaceByName(%s): %v", testServerIf, err)
	}

	released, _ := relAcquire(t, linkEndpointMAC, relClientID)
	control, _ := relAcquire(t, relControlMAC, nil)
	probe, _ := relAcquire(t, relProbeMAC, nil)
	addr := released.Addr.Addr()
	if control.Addr.Addr() == addr || probe.Addr.Addr() == addr || probe.Addr.Addr() == control.Addr.Addr() {
		t.Fatalf("two clients share an address: released %s, control %s, probe %s", addr, control.Addr, probe.Addr)
	}
	relWaitLease(t, srv.leasefile, addr)
	linkAssertNoIPv4(t, parent)

	rec := lease.Record{
		ID: "rec-link", Scope: "net-a", Family: lease.FamilyV4,
		CHAddr:   append([]byte(nil), linkEndpointMAC...),
		Identity: append([]byte(nil), relClientID...),
		Lease:    released,
	}

	// ------------------------------------------- the server answers the probe --
	watch := newLinkWatch(t, testServerIf)
	line := "DHCPRELEASE(" + testServerIf + ") " + addr.String()
	sent, refused := relCountLine(srv, line), relCountLine(srv, line, "unknown lease")
	if err := SendReleaseOnLink(rec, LinkReleaseConfig{Interface: testClientIf}); err != nil {
		t.Fatalf("SendReleaseOnLink: %v", err)
	}
	f := watch.release(t, addr)
	if f.pkttype != syscall.PACKET_HOST {
		t.Fatalf("the release reached %s as packet type %d, not addressed to %s's own MAC: the probe's answer was not used", testServerIf, f.pkttype, server.HardwareAddr)
	}
	linkAssertFrame(t, f, addr, parent.HardwareAddr)
	relBound(t, srv, probe)
	linkAssertActedOn(t, srv, line, sent, refused)
	relWaitGone(t, srv.leasefile, addr)
	linkAssertNotLearned(t, addr, parent.HardwareAddr)
	t.Logf("dnsmasq closed %s on a release from a client end with no address, sent to %s", addr, server.HardwareAddr)

	// ------------------------------------------ the server ignores the probe --
	again, _ := relAcquire(t, linkEndpointMAC, relClientID)
	rec.Lease = again
	addr2 := again.Addr.Addr()
	relWaitLease(t, srv.leasefile, addr2)
	linkAssertNoIPv4(t, parent)

	// arp_ignore 8: "do not reply for all local addresses" (kernel
	// Documentation/networking/ip-sysctl.rst), a router that ignores probes.
	ignore := "/proc/sys/net/ipv4/conf/" + testServerIf + "/arp_ignore"
	if err := os.WriteFile(ignore, []byte("8\n"), 0o644); err != nil {
		t.Fatalf("writing %s: %v", ignore, err)
	}
	line2 := "DHCPRELEASE(" + testServerIf + ") " + addr2.String()
	sent2, refused2 := relCountLine(srv, line2), relCountLine(srv, line2, "unknown lease")
	if err := SendReleaseOnLink(rec, LinkReleaseConfig{Interface: testClientIf}); err != nil {
		t.Fatalf("SendReleaseOnLink with the probe unanswered: %v", err)
	}
	f = watch.release(t, addr2)
	if err := os.WriteFile(ignore, []byte("0\n"), 0o644); err != nil {
		t.Fatalf("writing %s: %v", ignore, err)
	}
	if f.pkttype != syscall.PACKET_BROADCAST {
		t.Fatalf("with the probe unanswered the release reached %s as packet type %d, want the broadcast fallback", testServerIf, f.pkttype)
	}
	linkAssertFrame(t, f, addr2, parent.HardwareAddr)
	relBound(t, srv, probe)
	linkAssertActedOn(t, srv, line2, sent2, refused2)
	relWaitGone(t, srv.leasefile, addr2)
	t.Logf("dnsmasq closed %s on the broadcast fallback", addr2)

	// ------------------------------------------------- the negative control --
	if n := relCountLine(srv, "DHCPRELEASE("+testServerIf+") "+control.Addr.Addr().String()); n != 0 {
		t.Fatalf("dnsmasq logged %d DHCPRELEASE line(s) for the control lease %s", n, control.Addr.Addr())
	}
	relWaitHolds(t, srv.leasefile, control.Addr.Addr())
	relAssertLifetimeMargin(t, started, testLeaseSec)
}

// linkAssertNoIPv4 is the premise: the client end holds no IPv4 address, so
// no UDP socket could have sent this release.
func linkAssertNoIPv4(t *testing.T, ifc *net.Interface) {
	t.Helper()
	addrs, err := ifc.Addrs()
	if err != nil {
		t.Fatalf("%s's addresses: %v", ifc.Name, err)
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
			t.Fatalf("%s carries %s; the subject is a link with no IPv4 address", ifc.Name, n)
		}
	}
}

// linkAssertActedOn reads dnsmasq's own decision: one more DHCPRELEASE line
// for the address, and no "unknown lease" among them.
func linkAssertActedOn(t *testing.T, srv *dnsmasqServer, line string, sent, refused int) {
	t.Helper()
	if got := relCountLine(srv, line); got != sent+1 {
		t.Fatalf("dnsmasq holds %d line(s) %q after the bound, want %d.\nLog:\n%s", got, line, sent+1, strings.Join(srv.lines(), "\n"))
	}
	if got := relCountLine(srv, line, "unknown lease"); got != refused {
		t.Fatalf("dnsmasq refused %q as an unknown lease.\nLog:\n%s", line, strings.Join(srv.lines(), "\n"))
	}
}

// linkAssertNotLearned reads the server's neighbour table: an ARP request
// from the leased address would have left leased -> the parent's MAC there,
// and the next holder of the address unreachable from the server.
func linkAssertNotLearned(t *testing.T, addr netip.Addr, parentMAC net.HardwareAddr) {
	t.Helper()
	out, err := exec.Command("ip", "-4", "neigh", "show", "dev", testServerIf).CombinedOutput()
	if err != nil {
		t.Fatalf("ip neigh show dev %s: %v\n%s", testServerIf, err, out)
	}
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) >= 3 && f[0] == addr.String() && strings.EqualFold(f[2], parentMAC.String()) {
			t.Fatalf("the server learned %s at the parent's MAC from the release: %q", addr, l)
		}
	}
}

type linkFrame struct {
	pkttype uint8
	srcMAC  net.HardwareAddr
	src     netip.Addr
	dst     netip.Addr
}

// linkAssertFrame checks the release's IP source is the leased address
// (RFC 2131 section 4.4.4) and its link source is the parent.
func linkAssertFrame(t *testing.T, f linkFrame, addr netip.Addr, parentMAC net.HardwareAddr) {
	t.Helper()
	if f.src != addr || f.dst != netip.MustParseAddr(testServerIP) {
		t.Fatalf("the release went %s -> %s, want %s -> %s", f.src, f.dst, addr, testServerIP)
	}
	if !bytes.Equal(f.srcMAC, parentMAC) {
		t.Fatalf("the release left from %s, not the parent's %s", f.srcMAC, parentMAC)
	}
}

// linkWatch reads IPv4 frames arriving at the server end; the kernel's
// packet type says whether a frame was addressed to that end's MAC or
// broadcast. Opened before the send: nothing buffers a frame for a later
// reader.
type linkWatch struct{ f *os.File }

func newLinkWatch(t *testing.T, ifName string) *linkWatch {
	t.Helper()
	ifc, err := net.InterfaceByName(ifName)
	if err != nil {
		t.Fatalf("InterfaceByName(%s): %v", ifName, err)
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, int(htons(ethPIP)))
	if err != nil {
		t.Fatalf("socket(AF_PACKET): %v", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(ethPIP), Ifindex: ifc.Index}); err != nil {
		_ = syscall.Close(fd)
		t.Fatalf("bind(%s): %v", ifName, err)
	}
	w := &linkWatch{f: os.NewFile(uintptr(fd), "link_watch")}
	t.Cleanup(func() { _ = w.f.Close() })
	return w
}

// release returns the first incoming DHCPRELEASE for addr. The read deadline
// is on the descriptor, as assertTheSolicitLeftAsIPv6's is.
func (w *linkWatch) release(t *testing.T, addr netip.Addr) linkFrame {
	t.Helper()
	if err := w.f.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("read deadline: %v", err)
	}
	rc, err := w.f.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	buf := make([]byte, maxFrame)
	for {
		var (
			n    int
			from syscall.Sockaddr
			rerr error
		)
		if cerr := rc.Read(func(fd uintptr) bool {
			n, from, rerr = syscall.Recvfrom(int(fd), buf, 0)
			return rerr != syscall.EAGAIN
		}); cerr != nil || rerr != nil {
			t.Fatalf("no DHCPRELEASE for %s reached %s: %v %v", addr, testServerIf, cerr, rerr)
		}
		ll, ok := from.(*syscall.SockaddrLinklayer)
		if !ok || ll.Pkttype == syscall.PACKET_OUTGOING {
			continue
		}
		fr := buf[:n]
		if n < ipv4HeaderLen+udpHeaderLen || fr[0]>>4 != ipv4Version || fr[9] != protoUDP {
			continue
		}
		ihl := int(fr[0]&0x0F) * 4
		if n < ihl+udpHeaderLen || binary.BigEndian.Uint16(fr[ihl+2:ihl+4]) != ServerPort {
			continue
		}
		m, err := wire.Decode(fr[ihl+udpHeaderLen:])
		if err != nil {
			continue
		}
		if mt, _ := m.Type(); mt != wire.MsgRelease || m.CIAddr != addr {
			continue
		}
		return linkFrame{
			pkttype: ll.Pkttype,
			srcMAC:  append(net.HardwareAddr(nil), ll.Addr[:ll.Halen]...),
			src:     netip.AddrFrom4([4]byte(fr[12:16])),
			dst:     netip.AddrFrom4([4]byte(fr[16:20])),
		}
	}
}
