// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

//go:build linux

package runtime

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	gosched "runtime"
	"syscall"
	"testing"
	"time"

	"github.com/claymore666/dhcp-golib/lease"
)

// Link names for the v6 release link tests (claymore666/dhcp-golib#74).
const (
	zoneCliIf = "zcli0"
	zoneSrvIf = "zsrv0"
	zoneOldIf = "zold0"
	zoneNewIf = "znsrv0"
	zoneSrc   = "fe80::9"
)

// zoneRecord is a v6 record whose Release is well formed; no server is
// involved, the observers read the bytes off the peer link.
func zoneRecord() lease.Record {
	duid := []byte{0x00, 0x03, 0x00, 0x01, 0x02, 0x42, 0xc0, 0xa8, 0x63, 0x54}
	return lease.Record{
		ID: "rec-zone-6", Scope: "net-a", Family: lease.FamilyV6,
		Identity: binary.BigEndian.AppendUint32(duid, 7),
		Lease: lease.Lease{
			Addr:       netip.MustParsePrefix("fd00:99::53/128"),
			ServerDUID: []byte{0x00, 0x01, 0x00, 0x01, 0x2b, 0x00, 0x00, 0x01, 0xaa, 0xbb},
			IAID:       7,
		},
	}
}

// zoneLink builds a veth pair, cli holding zoneSrc, both ends up.
func zoneLink(t *testing.T, cli, srv string) {
	t.Helper()
	mustRun(t, "ip", "link", "add", cli, "type", "veth", "peer", "name", srv)
	mustRun(t, "ip", "-6", "addr", "add", zoneSrc+"/64", "dev", cli, "nodad")
	mustRun(t, "ip", "link", "set", srv, "up")
	mustRun(t, "ip", "link", "set", cli, "up")
}

func zoneIndex(t *testing.T, ifName string) int {
	t.Helper()
	ifi, err := net.InterfaceByName(ifName)
	if err != nil {
		t.Fatalf("InterfaceByName(%s): %v", ifName, err)
	}
	return ifi.Index
}

// releaseWatch is an AF_PACKET socket on one link that is not this library's,
// reading DHCPv6 Releases to port 547 as they arrive there.
type releaseWatch struct {
	f      *os.File
	ifName string
}

func newReleaseWatch(t *testing.T, ifName string) *releaseWatch {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_PACKET,
		syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK,
		int(htons(ethPIPv6)))
	if err != nil {
		t.Fatalf("the observer's socket(AF_PACKET, ETH_P_IPV6): %v", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{
		Protocol: htons(ethPIPv6), Ifindex: zoneIndex(t, ifName),
	}); err != nil {
		_ = syscall.Close(fd)
		t.Fatalf("the observer's bind(%s): %v", ifName, err)
	}
	w := &releaseWatch{f: os.NewFile(uintptr(fd), "release_watch:"+ifName), ifName: ifName}
	t.Cleanup(func() { _ = w.f.Close() })
	return w
}

// next returns the UDP payload of the first datagram to port 547 seen on the
// link within the window; the deadline is the socket's (gate T2).
func (w *releaseWatch) next(t *testing.T, within time.Duration) ([]byte, netip.Addr, bool) {
	t.Helper()
	buf := make([]byte, maxFrame)
	read := w.f.Read
	if within > 0 {
		if err := w.f.SetReadDeadline(time.Now().Add(within)); err != nil {
			t.Fatalf("the observer's read deadline: %v", err)
		}
	} else {
		// a passed deadline, this call's or an earlier one's, fails in the
		// poller before any read, so a zero window clears it and drains what
		// is queued with non-blocking reads.
		if err := w.f.SetReadDeadline(time.Time{}); err != nil {
			t.Fatalf("the observer's read deadline: %v", err)
		}
		rc, err := w.f.SyscallConn()
		if err != nil {
			t.Fatalf("the observer's raw conn: %v", err)
		}
		read = func(b []byte) (n int, err error) {
			if cerr := rc.Read(func(fd uintptr) bool {
				n, err = syscall.Read(int(fd), b)
				return true
			}); cerr != nil {
				return 0, cerr
			}
			return n, err
		}
	}
	for {
		n, err := read(buf)
		if err != nil || n <= 0 {
			return nil, netip.Addr{}, false
		}
		frame := buf[:n]
		if n < ipv6HeaderLen+8 || frame[0]>>4 != ipv6Version || frame[6] != syscall.IPPROTO_UDP {
			continue
		}
		udp := frame[ipv6HeaderLen:]
		if binary.BigEndian.Uint16(udp[2:4]) != ServerPort6 {
			continue
		}
		return append([]byte(nil), udp[8:]...), netip.AddrFrom16([16]byte(frame[8:24])), true
	}
}

// zoneSend sends the record's Release from zoneSrc over iface and returns the
// exact payload the library built for it.
func zoneSend(t *testing.T, src netip.Addr, iface string, seed uint64) ([]byte, error) {
	t.Helper()
	rec := zoneRecord()
	grams, err := lease.BuildReleases(rec, uint32(NewEntropySeeded(seed).Uint64()))
	if err != nil {
		t.Fatalf("BuildReleases: %v", err)
	}
	return grams[0].Payload, SendRelease(rec, ReleaseConfig{
		Interface: iface, Source: src, Rand: NewEntropySeeded(seed),
	})
}

// expectRelease fails unless want arrives on w from zoneSrc; wrong, when set,
// is read for the same datagram to name where it went instead.
func expectRelease(t *testing.T, what string, w, wrong *releaseWatch, want []byte) {
	t.Helper()
	for {
		got, src, ok := w.next(t, 5*time.Second)
		if !ok {
			where := "no link the test watches"
			if wrong != nil {
				if g, _, ok := wrong.next(t, 0); ok && bytes.Equal(g, want) {
					where = wrong.ifName + ", the peer of the link renamed away"
				}
			}
			t.Fatalf("%s: the Release never reached %s; it went to %s", what, w.ifName, where)
		}
		if bytes.Equal(got, want) {
			if src != netip.MustParseAddr(zoneSrc) {
				t.Errorf("%s: the Release arrived from %s, not %s", what, src, zoneSrc)
			}
			return
		}
	}
}

func TestAV6ReleaseReachesALinkRecreatedUnderTheSameName(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		releaseAfterRecreate(t)
		return
	}
	reexecInNamespaces(t)
}

func releaseAfterRecreate(t *testing.T) {
	src := netip.MustParseAddr(zoneSrc)
	zoneLink(t, zoneCliIf, zoneSrvIf)
	first := zoneIndex(t, zoneCliIf)
	w := newReleaseWatch(t, zoneSrvIf)
	want, err := zoneSend(t, src, zoneCliIf, 1)
	if err != nil {
		t.Fatalf("the Release on the first link: %v", err)
	}
	expectRelease(t, "first link", w, nil, want)

	mustRun(t, "ip", "link", "del", zoneCliIf)
	zoneLink(t, zoneCliIf, zoneSrvIf)
	if second := zoneIndex(t, zoneCliIf); second == first {
		t.Fatalf("premise: %s came back with the same index %d; the recreate changed nothing", zoneCliIf, first)
	}
	w = newReleaseWatch(t, zoneSrvIf)

	for i, s := range []netip.Addr{src, src.WithZone(zoneCliIf)} {
		want, err := zoneSend(t, s, zoneCliIf, uint64(2+i))
		if err != nil {
			t.Fatalf("the Release from %s after %s was recreated: %v", s, zoneCliIf, err)
		}
		expectRelease(t, "recreated link, source "+s.String(), w, nil, want)
	}
}

func TestAV6ReleaseLeavesByTheLinkThatNowHasTheName(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		releaseAfterRename(t)
		return
	}
	reexecInNamespaces(t)
}

func releaseAfterRename(t *testing.T) {
	src := netip.MustParseAddr(zoneSrc)
	zoneLink(t, zoneCliIf, zoneSrvIf)
	wOld := newReleaseWatch(t, zoneSrvIf)
	want, err := zoneSend(t, src, zoneCliIf, 1)
	if err != nil {
		t.Fatalf("the Release before the rename: %v", err)
	}
	expectRelease(t, "before the rename", wOld, nil, want)

	// the renamed link keeps zoneSrc, so a send steered to it binds and leaves
	// without an error: the wrong-link shape is the silent one.
	mustRun(t, "ip", "link", "set", zoneCliIf, "down")
	mustRun(t, "ip", "link", "set", zoneCliIf, "name", zoneOldIf)
	mustRun(t, "ip", "link", "set", zoneOldIf, "up")
	mustRun(t, "ip", "-6", "addr", "replace", zoneSrc+"/64", "dev", zoneOldIf, "nodad")
	zoneLink(t, zoneCliIf, zoneNewIf)
	wNew := newReleaseWatch(t, zoneNewIf)

	want, err = zoneSend(t, src, zoneCliIf, 2)
	if err != nil {
		t.Fatalf("the Release after the rename: %v", err)
	}
	expectRelease(t, "after the rename", wNew, wOld, want)
	if got, _, ok := wOld.next(t, 0); ok {
		t.Errorf("a datagram to port 547 also reached %s, the peer of the renamed %s: % x", zoneSrvIf, zoneOldIf, got)
	}
}

func TestAV6ReleaseIsNotSteeredByANameSeenInAnotherNamespace(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		releaseAcrossNamespaces(t)
		return
	}
	reexecInNamespaces(t)
}

func releaseAcrossNamespaces(t *testing.T) {
	// first, before this namespace names the link: a lookup on a thread in a
	// second namespace, the shape of a client built inside a container.
	type seen struct {
		index int
		err   error
	}
	other := make(chan seen, 1)
	go func() {
		var out seen
		defer func() { other <- out }()
		// locked and never unlocked: returning locked ends the thread, so no
		// thread of this process stays in the second namespace.
		gosched.LockOSThread()
		if err := syscall.Unshare(syscall.CLONE_NEWNET); err != nil {
			out.err = fmt.Errorf("unshare(CLONE_NEWNET): %w", err)
			return
		}
		for _, l := range []string{"zpad0", "zpad1", "zpad2", zoneCliIf} {
			if b, err := execIP("link", "add", l, "type", "dummy"); err != nil {
				out.err = fmt.Errorf("ip link add %s: %v: %s", l, err, b)
				return
			}
		}
		ifi, err := net.InterfaceByName(zoneCliIf)
		if err != nil {
			out.err = err
			return
		}
		out.index = ifi.Index
	}()
	o := <-other
	if o.err != nil {
		t.Fatalf("the second namespace: %v", o.err)
	}

	zoneLink(t, zoneCliIf, zoneSrvIf)
	here := zoneIndex(t, zoneCliIf)
	if here == o.index {
		t.Fatalf("premise: %s has index %d in both namespaces", zoneCliIf, here)
	}
	t.Logf("%s is index %d here and %d in the second namespace", zoneCliIf, here, o.index)
	w := newReleaseWatch(t, zoneSrvIf)

	want, err := zoneSend(t, netip.MustParseAddr(zoneSrc), zoneCliIf, 1)
	if err != nil {
		t.Fatalf("the Release after a lookup in another namespace: %v", err)
	}
	expectRelease(t, "after a lookup in another namespace", w, nil, want)
}

// execIP runs ip on the calling thread's namespace; the child of a fork from
// a locked thread inherits that thread's namespace.
func execIP(args ...string) ([]byte, error) {
	return exec.Command("ip", args...).CombinedOutput()
}
