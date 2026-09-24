// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

//go:build linux

package runtime

import (
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
	"time"
)

// ErrLinkGone is wrapped in the last error a raw socket reports when the link it is bound to was deleted or left the namespace.
var ErrLinkGone = errors.New("runtime: the bound link is gone")

// The backoff after a read error that can pass, and the period of the reader's
// look at its binding: each doubles from readBackoffMin to readBackoffMax, and
// the backoff resets on the next frame (#23).
const (
	readBackoffMin = 20 * time.Millisecond
	readBackoffMax = time.Second
)

// readLoop is the receive loop the four AF_PACKET sockets share.
type readLoop struct {
	f       *os.File
	ifIndex int
	closed  *atomic.Bool
	done    <-chan struct{}
	errs    *atomic.Uint64
	what    string
	report  func(error)
	deliver func(frame []byte, from syscall.Sockaddr)
}

func (r readLoop) run() {
	buf := make([]byte, maxFrame)
	rc, err := r.f.SyscallConn()
	if err != nil {
		r.fail(fmt.Errorf("runtime: syscallconn: %w", err))
		return
	}
	var backoff, look time.Duration
	for {
		var (
			n    int
			from syscall.Sockaddr
			rerr error
		)
		cerr := rc.Read(func(fd uintptr) bool {
			n, from, rerr = syscall.Recvfrom(int(fd), buf, 0)
			return rerr != syscall.EAGAIN
		})
		err := firstErr(cerr, rerr)
		if err == nil {
			backoff = 0
			r.deliver(buf[:n], from)
			continue
		}
		if r.closed.Load() {
			return
		}
		// Linux reports ENETDOWN once both when the link goes down and when it
		// is deleted, nothing at all when a link already down is deleted, and
		// frames queued before a down after its error (measured 2026-09-24,
		// kernel 6.12). So a frame does not show the link is back: from its first
		// error on, the reader looks at the socket's own binding after every
		// error and at least once a second, and a link going away still reaches
		// the machine as an event (#23, claymore666/docker-net-dhcp#1089).
		tick := errors.Is(err, os.ErrDeadlineExceeded)
		if !tick && !retryableReadErr(err) {
			r.fail(fmt.Errorf("runtime: %s: %w", r.what, err))
			return
		}
		if r.linkGone(rc) {
			gone := fmt.Errorf("%w: %s", ErrLinkGone, r.what)
			if !tick {
				gone = fmt.Errorf("%w: %w", gone, err)
			}
			r.fail(gone)
			return
		}
		if tick {
			look = nextReadBackoff(look)
		} else {
			backoff = nextReadBackoff(backoff)
			r.fail(fmt.Errorf("runtime: %s: %w", r.what, err))
			if !r.wait(backoff) {
				return
			}
			look = backoff
		}
		_ = r.f.SetReadDeadline(time.Now().Add(look))
	}
}

// fail counts one error and reports it on the socket's port.
func (r readLoop) fail(err error) {
	r.errs.Add(1)
	r.report(err)
}

// wait sleeps for d and reports false if the socket was closed first.
func (r readLoop) wait(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-r.done:
		return false
	}
}

// nextReadBackoff is the wait after one more error or empty deadline.
func nextReadBackoff(d time.Duration) time.Duration {
	switch {
	case d < readBackoffMin:
		return readBackoffMin
	case d >= readBackoffMax/2:
		return readBackoffMax
	default:
		return 2 * d
	}
}

// retryableReadErr reports whether a read error can pass; on any other the
// reader leaves as it did before #23.
func retryableReadErr(err error) bool {
	for _, e := range []syscall.Errno{syscall.ENETDOWN, syscall.EINTR, syscall.ENOBUFS, syscall.ENOMEM} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// linkGone reports whether the socket is no longer bound to its link.
func (r readLoop) linkGone(rc syscall.RawConn) bool {
	// getsockname answers from the socket's own namespace, which the reader
	// goroutine's thread need not be in. Linux sets the bound index to -1 on
	// NETDEV_UNREGISTER, which a delete and a move to another namespace both
	// send (net/packet/af_packet.c, packet_notifier).
	var (
		sa   syscall.Sockaddr
		gerr error
	)
	if err := rc.Control(func(fd uintptr) { sa, gerr = syscall.Getsockname(int(fd)) }); err != nil || gerr != nil {
		// Close sets closed before it closes the file, so a look that fails
		// because Close ran first is not a gone link (#23).
		return !r.closed.Load()
	}
	ll, ok := sa.(*syscall.SockaddrLinklayer)
	return !ok || ll.Ifindex != r.ifIndex
}
