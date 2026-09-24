// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

//go:build linux

package runtime

import (
	"errors"
	"net"
	"net/netip"
	"os"
	goruntime "runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// readSock is one of the four AF_PACKET sockets, seen from its consumer.
type readSock interface {
	// poll takes the next event on the socket's port, if there is one.
	poll() (data bool, err error, ok bool)
	// reader is the "created by" line a stack dump shows under the reader
	// goroutine, the one goroutine the socket's constructor starts; it is
	// there before the goroutine first runs, which its entry is not.
	reader() string
	// frame is one frame the peer end can send that this socket delivers.
	frame(t *testing.T) (proto uint16, b []byte)
	reads() uint64
	close() error
}

// readKind opens one kind of socket on an interface.
type readKind struct {
	name string
	// prepare runs on the link while it is still down.
	prepare func(t *testing.T, ifName string)
	open    func(t *testing.T, ifName string) readSock
}

var readKinds = []readKind{
	{name: "v4 transport", open: func(t *testing.T, ifName string) readSock {
		tr, err := NewPacketTransport(ifName)
		if err != nil {
			t.Fatalf("NewPacketTransport: %v", err)
		}
		return v4Sock{tr}
	}},
	{name: "v6 transport", prepare: func(t *testing.T, ifName string) {
		mustRun(t, "ip", "-6", "addr", "add", "fe80::2/64", "dev", ifName, "nodad")
	}, open: func(t *testing.T, ifName string) readSock {
		tr, err := NewPacketTransportV6(ifName)
		if err != nil {
			t.Fatalf("NewPacketTransportV6: %v", err)
		}
		return v6Sock{tr}
	}},
	{name: "arp socket", open: func(t *testing.T, ifName string) readSock {
		s, err := NewARPSocket(ifName)
		if err != nil {
			t.Fatalf("NewARPSocket: %v", err)
		}
		return arpSock{s}
	}},
	{name: "nd socket", open: func(t *testing.T, ifName string) readSock {
		s, err := NewNDSocket(ifName)
		if err != nil {
			t.Fatalf("NewNDSocket: %v", err)
		}
		return ndSock{s}
	}},
}

type v4Sock struct{ *PacketTransport }

func (s v4Sock) reader() string { return "runtime.NewPacketTransport in goroutine" }
func (s v4Sock) poll() (bool, error, bool) {
	select {
	case in := <-s.Received():
		return in.Err == nil, in.Err, true
	default:
		return false, nil, false
	}
}
func (s v4Sock) reads() uint64 { return s.Stats().Reads }
func (s v4Sock) close() error  { return s.Close() }
func (s v4Sock) frame(t *testing.T) (uint16, []byte) {
	b, err := BuildIPv4UDP(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("255.255.255.255"),
		ServerPort, ClientPort, 1, 1, []byte("after the link came up"))
	if err != nil {
		t.Fatalf("BuildIPv4UDP: %v", err)
	}
	return ethPIP, b
}

type v6Sock struct{ *PacketTransportV6 }

func (s v6Sock) reader() string { return "runtime.NewPacketTransportV6 in goroutine" }
func (s v6Sock) poll() (bool, error, bool) {
	select {
	case in := <-s.Received():
		return in.Err == nil, in.Err, true
	default:
		return false, nil, false
	}
}
func (s v6Sock) reads() uint64 { return s.Stats().Reads }
func (s v6Sock) close() error  { return s.Close() }
func (s v6Sock) frame(t *testing.T) (uint16, []byte) {
	b, err := BuildIPv6UDP(netip.MustParseAddr("fe80::1"), s.Source(),
		ServerPort6, ClientPort6, dhcpHopLimit, []byte("after the link came up"))
	if err != nil {
		t.Fatalf("BuildIPv6UDP: %v", err)
	}
	return ethPIPv6, b
}

type arpSock struct{ *ARPSocket }

func (s arpSock) reader() string { return "runtime.NewARPSocket in goroutine" }
func (s arpSock) poll() (bool, error, bool) {
	select {
	case in := <-s.Received():
		return in.Err == nil, in.Err, true
	default:
		return false, nil, false
	}
}
func (s arpSock) reads() uint64 { return s.Stats().Reads }
func (s arpSock) close() error  { return s.Close() }
func (s arpSock) frame(t *testing.T) (uint16, []byte) {
	b, err := wire.EncodeARP(&wire.ARPPacket{
		Op:       wire.ARPRequest,
		SenderHW: srvMAC,
		TargetHW: make([]byte, 6),
		SenderIP: netip.MustParseAddr("192.0.2.1"),
		TargetIP: netip.MustParseAddr("192.0.2.2"),
	})
	if err != nil {
		t.Fatalf("EncodeARP: %v", err)
	}
	return ethPARP, b
}

type ndSock struct{ *NDSocket }

func (s ndSock) reader() string { return "runtime.NewNDSocket in goroutine" }
func (s ndSock) poll() (bool, error, bool) {
	select {
	case in := <-s.Received():
		return in.Err == nil, in.Err, true
	default:
		return false, nil, false
	}
}
func (s ndSock) reads() uint64 { return s.Stats().Reads }
func (s ndSock) close() error  { return s.Close() }
func (s ndSock) frame(*testing.T) (uint16, []byte) {
	return ethPIPv6, capV6NeighborAdvert
}

// downVeth makes a fresh cli0/srv0 pair with srv0 up and cli0 down.
func downVeth(t *testing.T, k readKind) {
	t.Helper()
	if _, err := net.InterfaceByName(testClientIf); err == nil {
		mustRun(t, "ip", "link", "del", testClientIf)
	}
	mustRun(t, "ip", "link", "add", testClientIf, "type", "veth", "peer", "name", testServerIf)
	mustRun(t, "ip", "link", "set", testServerIf, "up")
	if k.prepare != nil {
		k.prepare(t, testClientIf)
	}
}

// flood sends s's frame from srv0 until the returned stop is called. A
// frame sent the instant cli0 comes up can be dropped on srv0 before its
// queue is live, so the peer keeps sending and the socket is judged on what
// it reads, never on what was sent.
func flood(t *testing.T, s readSock) (stop func()) {
	t.Helper()
	proto, b := s.frame(t)
	iface, err := net.InterfaceByName(testServerIf)
	if err != nil {
		t.Fatalf("%s: %v", testServerIf, err)
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, int(htons(proto)))
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	lla := &syscall.SockaddrLinklayer{Protocol: htons(proto), Ifindex: iface.Index, Halen: 6}
	copy(lla.Addr[:], []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	var (
		halt    atomic.Bool
		wg      sync.WaitGroup
		sendErr error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !halt.Load() {
			if err := syscall.Sendto(fd, b, 0, lla); err != nil && !errors.Is(err, syscall.ENOBUFS) {
				sendErr = err
				return
			}
			goruntime.Gosched()
		}
	}()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			halt.Store(true)
			wg.Wait()
			_ = syscall.Close(fd)
			if sendErr != nil {
				t.Errorf("the peer could not send: %v", sendErr)
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

// readerAlive reports whether s's reader goroutine still exists.
func readerAlive(s readSock) bool {
	_, ok := readerStack(s)
	return ok
}

// readerStack is the stack of s's reader goroutine, if it exists.
func readerStack(s readSock) (string, bool) {
	buf := make([]byte, 1<<16)
	for {
		n := goruntime.Stack(buf, true)
		if n < len(buf) {
			for _, g := range strings.Split(string(buf[:n]), "\n\n") {
				if strings.Contains(g, s.reader()) {
					return g, true
				}
			}
			return "", false
		}
		buf = make([]byte, 2*len(buf))
	}
}

// next spins until s has an event on its port, and fails the test if the
// reader goroutine is gone with nothing left to take. A reader queues its
// last event before it leaves, so "gone and empty" is exact, with no clock.
func next(t *testing.T, name string, s readSock, last error) (bool, error) {
	t.Helper()
	for {
		if data, err, ok := s.poll(); ok {
			return data, err
		}
		if !readerAlive(s) {
			if data, err, ok := s.poll(); ok {
				return data, err
			}
			t.Fatalf("%s: the reader stopped for good; the last error it reported was %v", name, last)
		}
		goruntime.Gosched()
	}
}

// awaitFrames spins until s delivers n frames, failing on any error.
func awaitFrames(t *testing.T, name string, s readSock, n int, last error) {
	t.Helper()
	for got := 0; got < n; {
		data, err := next(t, name, s, last)
		if err != nil {
			t.Fatalf("after %d frame(s) the reader reported %v", got, err)
		}
		if data {
			got++
		}
	}
}

// openOnADownLink opens k on a down cli0 and returns the socket and the
// error its reader reports first.
func openOnADownLink(t *testing.T, k readKind) (readSock, error) {
	t.Helper()
	downVeth(t, k)
	s := k.open(t, testClientIf)
	data, err := next(t, k.name, s, nil)
	if data || err == nil {
		t.Fatalf("%s: the first event on a link that is down was a frame", k.name)
	}
	if !errors.Is(err, syscall.ENETDOWN) {
		t.Fatalf("%s: the first error is %v, want ENETDOWN", k.name, err)
	}
	return s, err
}

// readsOnAfterTheLinkComesUp is the case #23 and
// claymore666/docker-net-dhcp#1089 report: the socket is opened on a link
// that is down, the link comes up, and frames from the peer must arrive on
// the same socket.
func readsOnAfterTheLinkComesUp(t *testing.T, k readKind) {
	s, first := openOnADownLink(t, k)
	defer func() {
		if err := s.close(); err != nil {
			t.Errorf("%s: close: %v", k.name, err)
		}
	}()
	announceWait(k.name+": 3 frames after the link came up", []string{"the reader reported: " + first.Error()})
	mustRun(t, "ip", "link", "set", testClientIf, "up")
	stop := flood(t, s)
	awaitFrames(t, k.name, s, 3, first)
	stop()
	if got := s.reads(); got < 3 {
		t.Fatalf("%s: Reads = %d after 3 frames were delivered", k.name, got)
	}
}

func TestTheV4TransportReadsOnAfterTheLinkComesUp(t *testing.T) {
	if os.Getenv(nsChildEnv) != "1" {
		reexecInNamespaces(t)
		return
	}
	readsOnAfterTheLinkComesUp(t, readKinds[0])
}

func TestTheV6TransportReadsOnAfterTheLinkComesUp(t *testing.T) {
	if os.Getenv(nsChildEnv) != "1" {
		reexecInNamespaces(t)
		return
	}
	readsOnAfterTheLinkComesUp(t, readKinds[1])
}

func TestTheARPSocketReadsOnAfterTheLinkComesUp(t *testing.T) {
	if os.Getenv(nsChildEnv) != "1" {
		reexecInNamespaces(t)
		return
	}
	readsOnAfterTheLinkComesUp(t, readKinds[2])
}

func TestTheNDSocketReadsOnAfterTheLinkComesUp(t *testing.T) {
	if os.Getenv(nsChildEnv) != "1" {
		reexecInNamespaces(t)
		return
	}
	readsOnAfterTheLinkComesUp(t, readKinds[3])
}
