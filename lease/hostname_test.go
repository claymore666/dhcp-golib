// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package lease

import (
	"errors"
	"strings"
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

	// Since claymore666/docker-net-dhcp#1029 a v6 manager sends option 39,
	// so its refusal is the name option 39 cannot carry.
	t.Run("a name option 39 cannot carry, on a DHCPv6 manager", func(t *testing.T) {
		r := newRig6(t, testParams6(), answerNormally6(t))
		for _, name := range []string{"has a space", strings.Repeat("a", 64) + ".example."} {
			if err := r.mgr.SetHostname(name); !errors.Is(err, proto.ErrBadHostname6) {
				t.Fatalf("SetHostname(%q) on a v6 manager returned %v, want proto.ErrBadHostname6", name, err)
			}
		}
		if got := r.mgr.Hostname(); got != "" {
			t.Fatalf("a v6 manager reports the refused name %q", got)
		}
		if _, err := proto.New6(func() proto.Params6 {
			p := testParams6()
			p.Hostname = "has a space"
			return p
		}()); !errors.Is(err, proto.ErrBadHostname6) {
			t.Fatalf("proto.New6 returned %v for a name the setter refuses; the two are not one rule", err)
		}
	})
}

// TestSetHostnameOnARunningV6ManagerReachesTheServer is #961's shape on v6
// (claymore666/docker-net-dhcp#1029): a name set after the bind reaches the
// fake server in option 39 of an early Renew, with 39 in the ORO (RFC 4704
// section 5), and the server's option 39 is reported on the Renewed lease.
// The assertions read what the server decoded off the wire.
func TestSetHostnameOnARunningV6ManagerReachesTheServer(t *testing.T) {
	// The server answers N=1 O=1: it will do no DNS update and overrode S.
	answer := answerNormally6(t)
	fqdnServer := func(req *wire.MessageV6, n int) []*wire.MessageV6 {
		out := answer(req, n)
		if f, ok, _ := req.Options.ClientFQDN(); ok {
			for _, m := range out {
				v, err := wire.EncodeClientFQDN(0, f.Name+".example.test.")
				if err != nil {
					t.Errorf("EncodeClientFQDN: %v", err)
					continue
				}
				v[0] = wire.ClientFQDNFlagN | wire.ClientFQDNFlagO
				m.Options = append(m.Options, optV6(wire.OptV6ClientFQDN, v))
			}
		}
		return out
	}
	r := newRig6(t, testParams6(), fqdnServer)
	if ev := r.acquire6(t); ev.Lease.HasFQDN {
		t.Fatalf("a client that sent no name was told of a server name %+v", ev.Lease.FQDN)
	}
	for _, m := range r.server.sentMessages() {
		if _, ok := m.Options.First(wire.OptV6ClientFQDN); ok {
			t.Fatalf("a %s carried option 39 before any name was set", m.Type)
		}
	}

	if err := r.mgr.SetHostname("named-after-start"); err != nil {
		t.Fatalf("SetHostname: %v", err)
	}
	var ev Event
	for {
		if ev = r.nextEvent(t); ev.Kind == Renewed {
			break
		}
		if ev.Kind == Lost || ev.Kind == Failed {
			t.Fatalf("the early Renew ended in %s", ev)
		}
	}

	sent := r.server.sentMessages()
	renew := sent[len(sent)-1]
	if renew.Type != wire.MsgRenew {
		t.Fatalf("the last message the server saw is %s, want a Renew", renew.Type)
	}
	f, ok, err := renew.Options.ClientFQDN()
	if err != nil || !ok || f.Flags != wire.ClientFQDNFlagS || f.Name != "named-after-start" {
		t.Fatalf("the Renew's option 39 = %+v, %v, %v; want S=1 O=0 N=0 and the partial name", f, ok, err)
	}
	oro, _ := renew.Options.First(wire.OptV6ORO)
	asked := false
	for i := 0; i+1 < len(oro); i += 2 {
		asked = asked || wire.OptionCodeV6(oro[i])<<8|wire.OptionCodeV6(oro[i+1]) == wire.OptV6ClientFQDN
	}
	if !asked {
		t.Fatalf("the Renew's ORO %x does not request option 39, which RFC 4704 section 5 requires", oro)
	}
	if !ev.Lease.HasFQDN || ev.Lease.FQDN.Flags != wire.ClientFQDNFlagN|wire.ClientFQDNFlagO ||
		ev.Lease.FQDN.Name != "named-after-start.example.test." {
		t.Fatalf("the Renewed lease reports %v %+v; want the server's N|O and its full name", ev.Lease.HasFQDN, ev.Lease.FQDN)
	}
	if got := r.mgr.Hostname(); got != "named-after-start" {
		t.Fatalf("Manager.Hostname() = %q after the step", got)
	}
}
