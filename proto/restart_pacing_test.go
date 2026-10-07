// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"fmt"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// v4Server answers one client message, given the state the machine was in
// when it sent it; nil is silence.
type v4Server func(st State, req *wire.Message) *wire.Message

// paceRun drives m against srv on a simulated clock: a reply is delivered at
// the instant its message left, and when nothing is in flight the earliest
// armed timer fires. It returns, for every DHCPDISCOVER after the first, the
// time between the restart's cause (TimerExpire fired, or a reply that sent the
// machine back to acquiring) and the DHCPDISCOVER.
type paceRun struct {
	t      *testing.T
	m      *Machine
	srv    v4Server
	now    Instant
	rnd    uint64
	timers map[TimerID]Instant
	waits  []Duration
	cause  Instant
	caused bool
}

func newPaceRun(t *testing.T, m *Machine, srv v4Server) *paceRun {
	return &paceRun{t: t, m: m, srv: srv, timers: map[TimerID]Instant{}}
}

func (r *paceRun) step(ev Event) []Action {
	r.rnd++
	if ev.Kind == EvTimerFired && ev.Timer == TimerExpire {
		r.cause, r.caused = r.now, true
	}
	pre := r.m.State()
	post, acts := r.m.Step(r.now, r.rnd, ev)
	if ev.Kind == EvReceived && pre != StateInit && pre != StateSelecting && (post == StateInit || post == StateSelecting) {
		r.cause, r.caused = r.now, true
	}
	for _, a := range acts {
		switch a.Kind {
		case ActSetTimer:
			r.timers[a.Timer] = r.now.Add(a.After)
		case ActCancelTimer:
			delete(r.timers, a.Timer)
		case ActSend:
			if t, _ := a.Msg.Type(); t == wire.MsgDiscover && r.caused {
				r.waits = append(r.waits, r.now.Sub(r.cause))
				r.caused = false
			}
		}
	}
	return acts
}

// until runs until restarts DHCPDISCOVERs have followed a cause, or the
// simulated clock passes an hour.
func (r *paceRun) until(acts []Action, restarts int) {
	r.t.Helper()
	for i := 0; i < 2000 && len(r.waits) < restarts; i++ {
		var reply *wire.Message
		for _, a := range acts {
			if a.Kind == ActSend {
				reply = r.srv(r.m.State(), a.Msg)
			}
		}
		if reply != nil {
			acts = r.step(received(r.t, reply))
			continue
		}
		id, when, ok := TimerID(0), Instant(0), false
		for k, v := range r.timers {
			if !ok || v < when || (v == when && k < id) {
				id, when, ok = k, v, true
			}
		}
		if !ok || when > at(3600) {
			break
		}
		delete(r.timers, id)
		r.now = when
		acts = r.step(TimerFired(id))
	}
	if len(r.waits) < restarts {
		r.t.Fatalf("only %d restarts within the run, want %d (state %s)", len(r.waits), restarts, r.m.State())
	}
}

// checkWaits holds each restart's wait to its window: 0 means in the cause's
// own Step, a positive lo means the RFC 2131 section 4.1 delay with the
// default one-second jitter, [lo, lo+2s].
func checkWaits(t *testing.T, got []Duration, want []Duration) {
	t.Helper()
	for i, lo := range want {
		g := got[i]
		if lo == 0 && g != 0 {
			t.Fatalf("restart %d waited %s, want none (all waits %v)", i+1, g, got)
		}
		if lo > 0 && (g < lo || g > lo+2*Second) {
			t.Fatalf("restart %d waited %s, want within [%s, %s] (all waits %v)", i+1, g, lo, lo+2*Second, got)
		}
	}
}

func secs(n int64) Duration { return Duration(n) * Second }

// pacedFromTheSecond is the schedule for consecutive server-caused restarts
// with DefaultBackoff: the first at once, then 4, 8, 16, 32 and 64 s, +/-1 s.
var pacedFromTheSecond = []Duration{0, secs(3), secs(7), secs(15), secs(31), secs(63), secs(63)}

func offerNakServer(st State, req *wire.Message) *wire.Message {
	if t, _ := req.Type(); t == wire.MsgDiscover {
		return offerFor(req, "192.168.99.50", "192.168.99.1")
	}
	return nakFor(req, "192.168.99.1", "wrong network")
}

func TestRepeatedNaksInRequestingArePaced(t *testing.T) {
	m := newMachine(t, testParams())
	r := newPaceRun(t, m, offerNakServer)
	r.until(r.step(Simple(EvStart)), len(pacedFromTheSecond))
	checkWaits(t, r.waits, pacedFromTheSecond)
}

func TestNakInRebootingStartsTheSameCount(t *testing.T) {
	m := newMachine(t, resumeParams("192.168.99.77", at(3600), true))
	r := newPaceRun(t, m, offerNakServer)
	acts := r.step(Simple(EvStart))
	if _, ok := find(acts, ActSend); !ok || m.State() != StateRebooting {
		t.Fatalf("Start with a live Resume left the machine in %s, want REBOOTING", m.State())
	}
	r.until(acts, 4)
	checkWaits(t, r.waits, pacedFromTheSecond[:4])
}

// TestAZeroLeaseLoopIsPaced: a server granting zero seconds every time. The
// lease expires as it is bound, in every Conflict mode. A rapid-commit ACK of
// zero seconds is refused before it is a lease (takeRapidAck).
func TestAZeroLeaseLoopIsPaced(t *testing.T) {
	zero := func(st State, req *wire.Message) *wire.Message {
		if t, _ := req.Type(); t == wire.MsgDiscover {
			o := offerFor(req, "192.168.99.50", "192.168.99.1")
			o.Options[wire.OptLeaseTime] = u32(0)
			return o
		}
		return ackFor(req, "192.168.99.50", "192.168.99.1", 0)
	}
	cases := []struct {
		name string
		p    Params
		srv  v4Server
	}{
		{"ConflictOff", testParams(), zero},
		{"ConflictAsync", acdParams(ConflictAsync), zero},
		{"ConflictWait", acdParams(ConflictWait), zero},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := newMachine(t, c.p)
			r := newPaceRun(t, m, c.srv)
			r.until(r.step(Simple(EvStart)), len(pacedFromTheSecond))
			checkWaits(t, r.waits, pacedFromTheSecond)
		})
	}
}

// TestAnAckRefusedForOption90IsPacedLikeANak: the RFC 6704 section 3.1.4
// restart, against a server that offers option 145 and never sends option 90.
func TestAnAckRefusedForOption90IsPacedLikeANak(t *testing.T) {
	srv := func(st State, req *wire.Message) *wire.Message {
		if t, _ := req.Type(); t == wire.MsgDiscover {
			o := offerFor(req, "192.168.99.50", "192.168.99.1")
			o.Options[wire.OptForcerenewNonce] = wire.EncodeForcerenewNonceCapable()
			return o
		}
		return ackFor(req, "192.168.99.50", "192.168.99.1", 3600)
	}
	m := newMachine(t, testParams())
	r := newPaceRun(t, m, srv)
	r.until(r.step(Simple(EvStart)), 4)
	checkWaits(t, r.waits, pacedFromTheSecond[:4])
	if c := m.ForcerenewCounters(); c.AckRefused < 4 {
		t.Fatalf("AckRefused = %d: the run did not take the option 90 path", c.AckRefused)
	}
}

// heldThen grants a 100 s lease to the first DHCPREQUEST and hands every
// later message to then.
func heldThen(then v4Server) v4Server {
	acked := false
	return func(st State, req *wire.Message) *wire.Message {
		t, _ := req.Type()
		switch {
		case t == wire.MsgDiscover && !acked:
			return offerFor(req, "192.168.99.50", "192.168.99.1")
		case t == wire.MsgRequest && !acked:
			acked = true
			return ackFor(req, "192.168.99.50", "192.168.99.1", 100)
		}
		return then(st, req)
	}
}

// TestRestartsAfterAHeldLeaseArePacedFromTheSecond: a lease that held resets
// the count, so the first restart after it leaves at once, and every way a
// held lease ends starts the count for what follows.
func TestRestartsAfterAHeldLeaseArePacedFromTheSecond(t *testing.T) {
	silentWhile := func(states ...State) func(v4Server) v4Server {
		return func(next v4Server) v4Server {
			return func(st State, req *wire.Message) *wire.Message {
				for _, s := range states {
					if st == s {
						return nil
					}
				}
				return next(st, req)
			}
		}
	}
	zeroAck := func(st State, req *wire.Message) *wire.Message {
		if t, _ := req.Type(); t == wire.MsgDiscover {
			return offerFor(req, "192.168.99.50", "192.168.99.1")
		}
		return ackFor(req, "192.168.99.50", "192.168.99.1", 0)
	}
	cases := []struct {
		name string
		srv  v4Server
	}{
		{"NAK in RENEWING", heldThen(offerNakServer)},
		{"NAK in REBINDING", heldThen(silentWhile(StateRenewing)(offerNakServer))},
		{"expiry in REBINDING", heldThen(silentWhile(StateRenewing, StateRebinding)(offerNakServer))},
		{"renewal answered with a zero lease", heldThen(zeroAck)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := newMachine(t, testParams())
			r := newPaceRun(t, m, c.srv)
			r.until(r.step(Simple(EvStart)), 4)
			checkWaits(t, r.waits, pacedFromTheSecond[:4])
		})
	}
}

// TestAHeldLeaseResetsThePacing: three refusals, then a lease that holds, then
// a refusal of its renewal. The restart after the lease leaves at once.
func TestAHeldLeaseResetsThePacing(t *testing.T) {
	naks := 0
	srv := func(st State, req *wire.Message) *wire.Message {
		t, _ := req.Type()
		if t == wire.MsgDiscover {
			return offerFor(req, "192.168.99.50", "192.168.99.1")
		}
		naks++
		if naks == 4 {
			return ackFor(req, "192.168.99.50", "192.168.99.1", 100)
		}
		return nakFor(req, "192.168.99.1", "no")
	}
	m := newMachine(t, testParams())
	r := newPaceRun(t, m, srv)
	r.until(r.step(Simple(EvStart)), 5)
	checkWaits(t, r.waits, []Duration{0, secs(3), secs(7), 0, secs(3)})
}

// TestStopAndStartResetThePacing: a fresh Start is not a consecutive restart.
func TestStopAndStartResetThePacing(t *testing.T) {
	m := newMachine(t, testParams())
	r := newPaceRun(t, m, offerNakServer)
	r.until(r.step(Simple(EvStart)), 3)
	r.step(Simple(EvStop))
	r.timers = map[TimerID]Instant{}
	r.waits = nil
	r.until(r.step(Simple(EvStart)), 2)
	checkWaits(t, r.waits, pacedFromTheSecond[:2])
}

// TestTheFirstRestartAfterANakLeavesInTheSameStep is the ordinary path a
// pacing must not slow: one DHCPNAK, and the DHCPDISCOVER in the same action
// list, on a fresh transaction.
func TestTheFirstRestartAfterANakLeavesInTheSameStep(t *testing.T) {
	m := newMachine(t, testParams())
	_, acts := m.Step(at(0), 1, Simple(EvStart))
	disc := mustSend(t, acts, wire.MsgDiscover)
	_, acts = m.Step(at(0), 2, received(t, offerFor(disc, "192.168.99.50", "192.168.99.1")))
	req := mustSend(t, acts, wire.MsgRequest)
	_, acts = m.Step(at(0), 3, received(t, nakFor(req, "192.168.99.1", "no")))
	again := mustSend(t, acts, wire.MsgDiscover)
	if again.XID == disc.XID {
		t.Fatalf("the restart reused xid %#x", disc.XID)
	}
	if _, ok := timerSet(acts, TimerRestart); ok {
		t.Fatalf("the first restart armed TimerRestart: %s", RenderActions(acts))
	}
}

// TestNewRefusesABackoffThatCanResendAtOnce: a delay of zero is a
// retransmission storm, for either schedule (#77).
func TestNewRefusesABackoffThatCanResendAtOnce(t *testing.T) {
	bad := map[string]Backoff{
		"zero":            {},
		"no Initial":      {Max: 64 * Second, MaxRetransmissions: 4},
		"negative":        {Initial: -Second, Max: 64 * Second},
		"no Max":          {Initial: 4 * Second, Jitter: Second},
		"Max below":       {Initial: 4 * Second, Max: 2 * Second},
		"jitter reaches":  {Initial: 4 * Second, Max: 64 * Second, Jitter: 4 * Second},
		"negative jitter": {Initial: 4 * Second, Max: 64 * Second, Jitter: -Second},
	}
	for name, b := range bad {
		for _, which := range []string{"Discover", "Request"} {
			t.Run(fmt.Sprintf("%s %s", which, name), func(t *testing.T) {
				p := testParams()
				if which == "Discover" {
					p.Discover = b
				} else {
					p.Request = b
				}
				if _, err := New(p); err == nil {
					t.Fatalf("New accepted %s %+v", which, b)
				}
			})
		}
	}
	p := testParams()
	p.Discover = Backoff{Initial: Second, Max: Second, Jitter: Second - 1}
	p.Request = p.Discover
	if _, err := New(p); err != nil {
		t.Fatalf("New refused the narrowest usable schedule: %v", err)
	}
}
