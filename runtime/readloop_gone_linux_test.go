// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

//go:build linux

package runtime

import (
	"errors"
	"net"
	"os"
	goruntime "runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// readErrorsOf is the ReadErrors counter of whichever socket s is.
func readErrorsOf(t *testing.T, s readSock) uint64 {
	t.Helper()
	switch v := s.(type) {
	case v4Sock:
		return v.Stats().ReadErrors
	case v6Sock:
		return v.Stats().ReadErrors
	case arpSock:
		return v.Stats().ReadErrors
	case ndSock:
		return v.Stats().ReadErrors
	}
	t.Fatalf("no ReadErrors for a %T", s)
	return 0
}

// awaitGone drains s until it reports ErrLinkGone, waits for its reader to
// leave on its own, and returns that error and how many errors came before
// it. Every one of those must be ENETDOWN: Linux sends NETDEV_DOWN before
// NETDEV_UNREGISTER on a delete, and a reader that looks between the two sees
// a link that is down, not yet gone.
func awaitGone(t *testing.T, name string, s readSock) (error, uint64) {
	t.Helper()
	var (
		before uint64
		last   error
	)
	for {
		_, err := next(t, name, s, last)
		switch {
		case err == nil:
		case errors.Is(err, ErrLinkGone):
			for readerAlive(s) {
				if _, more, ok := s.poll(); ok {
					t.Fatalf("%s: the reader went on after ErrLinkGone and reported %v", name, more)
				}
				goruntime.Gosched()
			}
			return err, before
		case errors.Is(err, syscall.ENETDOWN):
			before++
			last = err
		default:
			t.Fatalf("%s: %v on the way to ErrLinkGone", name, err)
		}
	}
}

// queuedBeforeADown leaves k's socket on a down link after it has read a
// frame that was queued before that down, which Linux delivers after the
// down's error. The reader is held on a full port while the frames queue.
func queuedBeforeADown(t *testing.T, k readKind) readSock {
	t.Helper()
	downVeth(t, k)
	mustRun(t, "ip", "link", "set", testClientIf, "up")
	s := k.open(t, testClientIf)
	stop := flood(t, s)
	for !portFull(t, s) {
		goruntime.Gosched()
	}
	stop()
	mustRun(t, "ip", "link", "set", testClientIf, "down")
	for readErrorsOf(t, s) == 0 {
		goruntime.Gosched()
	}
	if !strings.Contains(parkedReader(t, s), ").fail(") {
		t.Fatalf("%s: the reader did not wait for room on the port to report its error, so the error was dropped", k.name)
	}
	mustRun(t, "ip", "link", "set", testClientIf, "up")
	stop = flood(t, s)
	for !queuedOnClient(t) {
		goruntime.Gosched()
	}
	stop()
	mustRun(t, "ip", "link", "set", testClientIf, "down")
	var (
		errs uint64
		last error
	)
	for {
		data, err := next(t, k.name, s, last)
		switch {
		case err != nil && !errors.Is(err, syscall.ENETDOWN):
			t.Fatalf("%s: %v before the queued frames", k.name, err)
		case err != nil:
			errs++
			last = err
		case data && errs == 1:
			// Linux returns the second down's error before any frame queued
			// ahead of it (measured 2026-09-24, kernel 6.12, #23), so a frame
			// here means the first error never reached the port.
			t.Fatalf("%s: a frame between the two downs' errors; the first error was dropped", k.name)
		case data && errs == 2:
			return s
		}
	}
}

// parkedReader spins until s's reader goroutine is parked and returns its
// stack.
func parkedReader(t *testing.T, s readSock) string {
	t.Helper()
	for {
		g, ok := readerStack(s)
		if !ok {
			t.Fatal("the reader is gone")
		}
		state, _, _ := strings.Cut(g[strings.Index(g, "[")+1:], "]")
		if !strings.HasPrefix(state, "runnable") && !strings.HasPrefix(state, "running") && !strings.HasPrefix(state, "syscall") {
			return g
		}
		goruntime.Gosched()
	}
}

// queuedOnClient reports whether a packet socket bound to cli0 holds a
// received frame, from /proc/net/packet's Iface and Rmem columns.
func queuedOnClient(t *testing.T) bool {
	t.Helper()
	iface, err := net.InterfaceByName(testClientIf)
	if err != nil {
		t.Fatalf("%s: %v", testClientIf, err)
	}
	b, err := os.ReadFile("/proc/net/packet")
	if err != nil {
		t.Fatalf("read /proc/net/packet: %v", err)
	}
	for _, line := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) > 6 && f[4] == strconv.Itoa(iface.Index) && f[6] != "0" {
			return true
		}
	}
	return false
}

// TestALinkThatGoesAwayStillReachesEachSocketAsAnError holds the promise the
// retry must not break: a deleted link reaches the consumer as an error that
// wraps ErrLinkGone, in each of the four ways it can go, and the reader then
// stops. Linux sends no error at all when a link that is already down is
// deleted, so that row is the one a retry alone would turn into a silence
// (#23).
func TestALinkThatGoesAwayStillReachesEachSocketAsAnError(t *testing.T) {
	if os.Getenv(nsChildEnv) != "1" {
		reexecInNamespaces(t)
		return
	}
	for _, k := range readKinds {
		// Deleted while up, with no error before it.
		downVeth(t, k)
		mustRun(t, "ip", "link", "set", testClientIf, "up")
		s := k.open(t, testClientIf)
		announceWait(k.name+": ErrLinkGone for a link deleted while up", nil)
		mustRun(t, "ip", "link", "del", testClientIf)
		_, n := awaitGone(t, k.name, s)
		closeCounted(t, k, s, n+1)

		// Down at open, up, frames, then deleted while the peer's frames
		// fill the port, so the last error has to wait for room.
		s, _ = openOnADownLink(t, k)
		mustRun(t, "ip", "link", "set", testClientIf, "up")
		stop := flood(t, s)
		awaitFrames(t, k.name, s, 1, nil)
		stop()
		announceWait(k.name+": ErrLinkGone for a link deleted after it came up", nil)
		mustRun(t, "ip", "link", "del", testClientIf)
		_, n = awaitGone(t, k.name, s)
		closeCounted(t, k, s, n+2)

		// Frames queued before a second down arrive after its error, and the
		// link is then deleted while down.
		s = queuedBeforeADown(t, k)
		announceWait(k.name+": ErrLinkGone for a link deleted while down, after frames queued before the down", nil)
		mustRun(t, "ip", "link", "del", testClientIf)
		_, n = awaitGone(t, k.name, s)
		closeCounted(t, k, s, n+3)

		// Down at open and deleted while still down.
		s, _ = openOnADownLink(t, k)
		announceWait(k.name+": ErrLinkGone for a link deleted while down", nil)
		mustRun(t, "ip", "link", "del", testClientIf)
		_, n = awaitGone(t, k.name, s)
		closeCounted(t, k, s, n+2)
	}
}

// TestClosingASocketThatWaitsOnADownLinkReportsNothingMore drives Close
// against a reader that has reported a transient error and is backing off.
func TestClosingASocketThatWaitsOnADownLinkReportsNothingMore(t *testing.T) {
	if os.Getenv(nsChildEnv) != "1" {
		reexecInNamespaces(t)
		return
	}
	for _, k := range readKinds {
		s, _ := openOnADownLink(t, k)
		closeCounted(t, k, s, 1)
	}
}

// portFull reports whether s's port holds as many events as it can.
func portFull(t *testing.T, s readSock) bool {
	t.Helper()
	switch v := s.(type) {
	case v4Sock:
		return len(v.Received()) == cap(v.Received())
	case v6Sock:
		return len(v.Received()) == cap(v.Received())
	case arpSock:
		return len(v.Received()) == cap(v.Received())
	case ndSock:
		return len(v.Received()) == cap(v.Received())
	}
	t.Fatalf("no port for a %T", s)
	return false
}

// TestCloseReturnsWhileAReaderWaitsToReportAnError drives the one place a
// reader now blocks: an error waits for room on a full port, and Close must
// still get the reader out.
func TestCloseReturnsWhileAReaderWaitsToReportAnError(t *testing.T) {
	if os.Getenv(nsChildEnv) != "1" {
		reexecInNamespaces(t)
		return
	}
	for _, k := range readKinds {
		downVeth(t, k)
		mustRun(t, "ip", "link", "set", testClientIf, "up")
		s := k.open(t, testClientIf)
		stop := flood(t, s)
		for !portFull(t, s) {
			goruntime.Gosched()
		}
		stop()
		mustRun(t, "ip", "link", "set", testClientIf, "down")
		// ReadErrors moves just before the reader starts to wait for room.
		for readErrorsOf(t, s) == 0 {
			goruntime.Gosched()
		}
		closeCounted(t, k, s, 1)
	}
}

// closeCounted closes s and checks that ReadErrors counted exactly the
// errors its consumer saw.
func closeCounted(t *testing.T, k readKind, s readSock, want uint64) {
	t.Helper()
	if err := s.close(); err != nil {
		t.Errorf("%s: close: %v", k.name, err)
	}
	if got := readErrorsOf(t, s); got != want {
		t.Fatalf("%s: ReadErrors = %d, want %d, one per error reported", k.name, got, want)
	}
}

func TestTheReadBackoffDoublesFromItsFloorToItsCap(t *testing.T) {
	want := []time.Duration{
		20 * time.Millisecond, 40 * time.Millisecond, 80 * time.Millisecond,
		160 * time.Millisecond, 320 * time.Millisecond, 640 * time.Millisecond,
		time.Second, time.Second,
	}
	var d time.Duration
	for i, w := range want {
		d = nextReadBackoff(d)
		if d != w {
			t.Fatalf("step %d: %s, want %s", i, d, w)
		}
	}
}

func TestOnlyAReadErrorThatCanPassIsRetried(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{syscall.ENETDOWN, true},
		{&os.SyscallError{Syscall: "recvfrom", Err: syscall.ENETDOWN}, true},
		{syscall.EINTR, true},
		{syscall.ENOBUFS, true},
		{syscall.ENOMEM, true},
		{syscall.EBADF, false},
		{syscall.EINVAL, false},
		{syscall.ENODEV, false},
		{os.ErrClosed, false},
		{os.ErrDeadlineExceeded, false},
	} {
		if got := retryableReadErr(c.err); got != c.want {
			t.Errorf("retryableReadErr(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

// TestAReaderWaitingOutABackoffLeavesWhenTheSocketCloses: a wait that did not
// watch done would hold Close for the whole backoff, here an hour.
func TestAReaderWaitingOutABackoffLeavesWhenTheSocketCloses(t *testing.T) {
	done := make(chan struct{})
	close(done)
	if (readLoop{done: done}).wait(time.Hour) {
		t.Fatal("a reader waiting out a backoff went on reading after its socket closed")
	}
}

// TestALookThatFailsBecauseTheSocketClosedIsNotAGoneLink: Close can land
// between the reader's closed check and its look at the binding, which then
// fails on the closed file.
func TestALookThatFailsBecauseTheSocketClosedIsNotAGoneLink(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pw.Close()
	rc, err := pr.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var closed atomic.Bool
	r := readLoop{f: pr, ifIndex: 1, closed: &closed}
	if err := pr.Close(); err != nil {
		t.Fatal(err)
	}
	if !r.linkGone(rc) {
		t.Fatal("a look that failed on a socket nobody closed did not read as a gone link")
	}
	closed.Store(true)
	if r.linkGone(rc) {
		t.Fatal("a look that failed because the socket closed read as a gone link")
	}
}
