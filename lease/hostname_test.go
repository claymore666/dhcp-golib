// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package lease

import (
	"errors"
	"testing"

	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

// TestSetHostnameOnARunningManagerReachesTheServer is the manager's half of
// docker-net-dhcp#961: a client that started with no name is given one and the
// server sees it, in a DHCPREQUEST, without the caller waiting for T1.
//
// The assertion is on what the fake SERVER decoded off the wire, not on the
// manager's counters — the manager agreeing with itself is what this project
// has learned not to accept.
func TestSetHostnameOnARunningManagerReachesTheServer(t *testing.T) {
	r := newRig(t, testParams(), answerNormally, Fault{})

	if ev := r.nextEvent(t); ev.Kind != Acquired {
		t.Fatalf("first event is %s, want Acquired", ev.Kind)
	}
	if got := r.mgr.Hostname(); got != "" {
		t.Fatalf("a client started with no name reports %q", got)
	}
	acq := lastSent(t, r, wire.MsgRequest)
	if _, ok := acq.Options[wire.OptHostName]; ok {
		t.Fatal("the acquisition's DHCPREQUEST already carries option 12; this test would measure nothing")
	}

	if err := r.mgr.SetHostname("named-after-start"); err != nil {
		t.Fatalf("SetHostname: %v", err)
	}

	// The barrier is the outward event the early renewal's DHCPACK produces.
	// No duration appears here: a renewal that never happened hangs until go
	// test's own timeout, which is louder than a wait that was too short.
	for {
		ev := r.nextEvent(t)
		if ev.Kind == Renewed {
			break
		}
		if ev.Kind == Lost || ev.Kind == Failed {
			t.Fatalf("the early renewal ended in %s", ev)
		}
	}

	req := lastSent(t, r, wire.MsgRequest)
	if got := string(req.Options[wire.OptHostName]); got != "named-after-start" {
		t.Fatalf("the server saw option 12 %q, want %q", got, "named-after-start")
	}
	if req.CIAddr.IsUnspecified() {
		t.Fatal("the message the server saw has no ciaddr; it is not the RENEWING DHCPREQUEST of RFC 2131 4.3.2")
	}
	if got := r.mgr.Hostname(); got != "named-after-start" {
		t.Fatalf("Manager.Hostname() = %q after the step", got)
	}
}

// newIdleManager builds a Manager that is NOT running, which is the only way
// to see the request queue full: Run is what drains it.
func newIdleManager(t *testing.T, p proto.Params) *Manager {
	t.Helper()
	srv := newFakeServer(answerNormally)
	ft := NewFaultTransport(srv, Fault{})
	tm := newFakeTimers()
	t.Cleanup(func() {
		_ = ft.Close()
		_ = tm.Close()
	})
	mgr, err := NewManager(Config{
		Params:    p,
		Transport: ft,
		Clock:     newFakeClock(),
		Timers:    tm,
		Entropy:   &fakeEntropy{},
		Journal:   newJournalRecorder(),
		Packets:   newPacketRecorder(),
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return mgr
}

// TestSetHostnameReportsAFullRequestQueue is defeat row E. Stats.RequestsDropped
// cannot answer "did MY call land" — it is one counter over every request kind
// and every goroutine, as Release's own doc says — and for a call whose whole
// point is that something reaches the server, no answer is not an answer.
func TestSetHostnameReportsAFullRequestQueue(t *testing.T) {
	mgr := newIdleManager(t, testParams())

	// Nothing is draining, so the queue fills and then refuses. The count is
	// not written here: it is filled until a call is refused, and the refusal
	// is the subject.
	accepted := 0
	var err error
	for i := 0; i < 64; i++ {
		if err = mgr.SetHostname("name"); err != nil {
			break
		}
		accepted++
	}
	if err == nil {
		t.Fatalf("64 calls were all accepted by a manager that is not running; the queue reports nothing")
	}
	if !errors.Is(err, ErrRequestQueueFull) {
		t.Fatalf("a full queue returned %v, want ErrRequestQueueFull", err)
	}
	if accepted == 0 {
		t.Fatal("the first call was already refused; the queue has no capacity at all")
	}
	if mgr.Stats().RequestsDropped == 0 {
		t.Fatal("a refused call did not raise Stats.RequestsDropped")
	}
}

// TestSetHostnameRefusesWhatCannotBeSent is defeat rows D, H and I: the three
// clients that have no option 12 to put a name in, and the names that would not
// fit one. Each refusal is a value the caller can act on rather than a silence.
func TestSetHostnameRefusesWhatCannotBeSent(t *testing.T) {
	t.Run("a name option 12 cannot carry", func(t *testing.T) {
		mgr := newIdleManager(t, testParams())
		err := mgr.SetHostname("has a space")
		if !errors.Is(err, proto.ErrBadHostname) {
			t.Fatalf("SetHostname returned %v, want proto.ErrBadHostname — the same rule proto.New applies", err)
		}
		if _, nerr := proto.New(func() proto.Params {
			p := testParams()
			p.Hostname = "has a space"
			return p
		}()); nerr == nil {
			t.Fatal("proto.New accepts a name the setter refuses; the two are not one rule")
		}
	})

	t.Run("a client that sends option 81", func(t *testing.T) {
		p := testParams()
		p.FQDN = proto.FQDN{Name: "host.example.test."}
		mgr := newIdleManager(t, p)
		if err := mgr.SetHostname("ignored"); !errors.Is(err, ErrHostnameFQDN) {
			t.Fatalf("SetHostname on an FQDN client returned %v, want ErrHostnameFQDN (RFC 4702 3.1)", err)
		}
	})

	t.Run("a DHCPv6 manager", func(t *testing.T) {
		r := newRig6(t, testParams6(), answerNormally6(t))
		if err := r.mgr.SetHostname("ignored"); !errors.Is(err, ErrHostnameV6) {
			t.Fatalf("SetHostname on a v6 manager returned %v, want ErrHostnameV6", err)
		}
		if got := r.mgr.Hostname(); got != "" {
			t.Fatalf("a v6 manager reports the name %q", got)
		}
	})
}
