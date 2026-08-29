package proto

import (
	"fmt"

	"github.com/claymore666/dhcplease/wire"
)

// Machine is the DHCPv4 client state machine. It is pure.
//
// The whole surface is Step: no clock, no scheduler, no goroutine, no I/O,
// enforced by the T1 gate rather than by this comment. Determinism is
// therefore a property of the type — the same Machine fed the same (now, rnd,
// event) sequence produces the same actions — which is what makes Replay exact
// and the acquisition path testable with no root and no network.
type Machine struct {
	params Params

	state State

	// nextAction is the ActionID counter. It is machine state rather than a
	// package global so two machines in one process do not interleave ids and
	// so a replay reproduces the ids exactly.
	nextAction ActionID

	// startedAt is the Instant of the Start that began the current
	// acquisition. It is what the 'secs' field counts from (RFC 2131 section
	// 2: "seconds elapsed since client began address acquisition or renewal
	// process").
	startedAt Instant
	started   bool

	// xid is the transaction id of the transaction in flight. A new one is
	// drawn for each DISCOVER cycle and REUSED for the REQUEST, because RFC
	// 2131 section 4.4.1's table says the REQUEST carries "'xid' from server
	// DHCPOFFER message" — which is the DISCOVER's xid echoed back.
	xid uint32

	// retransmits counts retransmissions of the message in flight. It is NOT
	// incremented by a send that failed locally: a message that never left the
	// host is not a retransmission, and counting it burns the budget for an
	// event the server never saw.
	retransmits int

	// sendFailures counts consecutive failed sends. Reset by any successful
	// transition that sends.
	sendFailures int

	// offer is the OFFER being requested, held so REQUEST can carry its
	// yiaddr and server identifier.
	offer *wire.Message

	// requestSentAt is the Instant the REQUEST in flight was first sent. RFC
	// 2131 section 4.4.5 computes the lease expiry from the time the REQUEST
	// was SENT, not from the ACK's arrival.
	//
	// It is set on the FIRST send of a REQUEST and re-set on each
	// retransmission, because a retransmitted REQUEST is the one the server
	// answered. Holding the first send's time would over-state the lease by
	// the whole retransmission interval.
	requestSentAt Instant

	// lease is the lease held in BOUND.
	lease   Lease
	haveLse bool
}

// New builds a Machine in StateStopped.
func New(p Params) (*Machine, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	p.CHAddr = append([]byte(nil), p.CHAddr...)
	p.ClientID = append([]byte(nil), p.ClientID...)
	p.ParameterList = append([]wire.OptionCode(nil), p.parameterList()...)
	return &Machine{params: p, state: StateStopped}, nil
}

// State returns the current state.
func (m *Machine) State() State { return m.state }

// Lease returns the held lease, if any.
func (m *Machine) Lease() (Lease, bool) { return m.lease, m.haveLse }

// Params returns the machine's configuration.
func (m *Machine) Params() Params { return m.params }

// Step is total: every (state, event) pair yields a defined result and no
// reachable panic. R1 tests that over the whole product of AllStates and
// AllEventKinds rather than sampling it.
//
// now and rnd are parameters, not ambients: rnd is journalled beside the event
// so a replay is bit-exact, where a PRNG inside the machine would make replay
// depend on a persisted seed AND a call count.
func (m *Machine) Step(now Instant, rnd uint64, ev Event) (State, []Action) {
	var out actions
	switch m.state {
	case StateStopped:
		m.stepStopped(now, rnd, ev, &out)
	case StateInit:
		m.stepInit(now, rnd, ev, &out)
	case StateSelecting:
		m.stepSelecting(now, rnd, ev, &out)
	case StateRequesting:
		m.stepRequesting(now, rnd, ev, &out)
	case StateBound:
		m.stepBound(now, rnd, ev, &out)
	default:
		// Unreachable through the exported API — State is not settable from
		// outside — and handled anyway, because "unreachable" is a claim about
		// today's code and a panic here takes the plugin down with it.
		out.journal(m, fmt.Sprintf("event %s in unknown state %s: ignored", ev.Kind, m.state))
	}
	return m.state, out.list
}

// ---------------------------------------------------------------- states --

func (m *Machine) stepStopped(now Instant, rnd uint64, ev Event, out *actions) {
	switch ev.Kind {
	case EvStart:
		m.beginAcquisition(now, rnd, out, true)
	case EvStop:
		out.journal(m, "already stopped")
	default:
		out.journal(m, fmt.Sprintf("%s ignored in STOPPED", ev.Kind))
	}
}

func (m *Machine) stepInit(now Instant, rnd uint64, ev Event, out *actions) {
	switch ev.Kind {
	case EvStart:
		// Idempotent: a second Start while INIT restarts the desync wait
		// rather than stacking a second acquisition. Two DISCOVER cycles with
		// two xids on one interface is the shape that produced two server
		// bindings in the v1.x IPv6 path.
		m.beginAcquisition(now, rnd, out, true)
	case EvStop:
		m.stop(out)
	case EvTimerFired:
		if ev.Timer == TimerDesync {
			m.sendDiscover(now, rnd, out)
			return
		}
		out.journal(m, fmt.Sprintf("timer %s fired in INIT: ignored", ev.Timer))
	case EvLinkUp:
		// The link came back after a LinkDown dropped us here. Start again.
		m.beginAcquisition(now, rnd, out, true)
	case EvActionFailed:
		m.noteActionFailed(rnd, ev, out)
	default:
		out.journal(m, fmt.Sprintf("%s ignored in INIT", ev.Kind))
	}
}

func (m *Machine) stepSelecting(now Instant, rnd uint64, ev Event, out *actions) {
	switch ev.Kind {
	case EvStop:
		m.stop(out)
	case EvReceived:
		msg, ok := m.acceptable(ev.Msg, out)
		if !ok {
			return
		}
		t, _ := msg.Type()
		switch t {
		case wire.MsgOffer:
			sid, hasSID := msg.Addr4(wire.OptServerID)
			if !msg.YIAddr.Is4() || msg.YIAddr.IsUnspecified() || !hasSID || sid.IsUnspecified() {
				// RFC 2131 section 4.4.1 has the client extract the server
				// address from the OFFER's server-identifier option, and the
				// REQUEST that follows MUST carry it. An OFFER without one, or
				// without a yiaddr, cannot produce a conformant REQUEST, so it
				// is discarded rather than half-used.
				out.journal(m, "DHCPOFFER without a usable yiaddr and server identifier: discarded")
				return
			}
			m.offer = msg.Clone()
			m.retransmits = 0
			m.sendRequest(now, rnd, out)
		case wire.MsgAck, wire.MsgNak:
			// RFC 2131 section 4.4.1: "Any arriving DHCPACK messages must be
			// silently discarded." Silent to the wire, not to the operator.
			out.journal(m, fmt.Sprintf("%s in SELECTING: discarded", t))
		default:
			out.journal(m, fmt.Sprintf("%s in SELECTING: discarded", t))
		}
	case EvTimerFired:
		if ev.Timer != TimerRetransmit {
			out.journal(m, fmt.Sprintf("timer %s fired in SELECTING: ignored", ev.Timer))
			return
		}
		if m.params.Discover.Exhausted(m.retransmits) {
			// RFC 2131 section 3.1(5): after the retransmission algorithm is
			// exhausted "the client reverts to INIT state and restarts the
			// initialization process. The client SHOULD notify the user that
			// the initialization process has failed and is restarting."
			// ActFailed is that notification, typed so U5 can branch on it.
			out.failed(m, ReasonNoServer, "no DHCPOFFER after the retransmission budget; restarting")
			m.beginAcquisition(now, split(rnd, 1), out, false)
			return
		}
		m.retransmits++
		m.sendDiscover(now, rnd, out)
	case EvLinkDown:
		m.linkDown(out)
	case EvActionFailed:
		m.noteActionFailed(rnd, ev, out)
	default:
		out.journal(m, fmt.Sprintf("%s ignored in SELECTING", ev.Kind))
	}
}

func (m *Machine) stepRequesting(now Instant, rnd uint64, ev Event, out *actions) {
	switch ev.Kind {
	case EvStop:
		m.stop(out)
	case EvReceived:
		msg, ok := m.acceptable(ev.Msg, out)
		if !ok {
			return
		}
		t, _ := msg.Type()
		switch t {
		case wire.MsgAck:
			lse, note, ok := leaseFromAck(msg, m.requestSentAt)
			if !ok {
				// An ACK with no yiaddr or no lease time cannot be applied.
				// The retransmission timer is still armed, so this is not a
				// dead end: the machine keeps asking.
				out.journal(m, "DHCPACK without a usable yiaddr and lease time: discarded")
				return
			}
			if note != "" {
				out.journal(m, note)
			}
			m.enterBound(now, lse, out)
		case wire.MsgNak:
			// RFC 2131 section 3.1(5): "If the client receives a DHCPNAK
			// message, the client restarts the configuration process."
			out.cancel(m, TimerRetransmit)
			out.failed(m, ReasonNak, m.nakText(msg))
			m.beginAcquisition(now, split(rnd, 1), out, false)
		case wire.MsgOffer:
			// A second server's OFFER arriving late. We have already selected.
			out.journal(m, "DHCPOFFER in REQUESTING: discarded")
		default:
			out.journal(m, fmt.Sprintf("%s in REQUESTING: discarded", t))
		}
	case EvTimerFired:
		if ev.Timer != TimerRetransmit {
			out.journal(m, fmt.Sprintf("timer %s fired in REQUESTING: ignored", ev.Timer))
			return
		}
		if m.params.Request.Exhausted(m.retransmits) {
			out.failed(m, ReasonNoServer, "no DHCPACK after the retransmission budget; restarting")
			m.beginAcquisition(now, split(rnd, 1), out, false)
			return
		}
		m.retransmits++
		m.sendRequest(now, rnd, out)
	case EvLinkDown:
		m.linkDown(out)
	case EvActionFailed:
		m.noteActionFailed(rnd, ev, out)
	default:
		out.journal(m, fmt.Sprintf("%s ignored in REQUESTING", ev.Kind))
	}
}

func (m *Machine) stepBound(now Instant, rnd uint64, ev Event, out *actions) {
	switch ev.Kind {
	case EvStop:
		m.stop(out)
	case EvTimerFired:
		if ev.Timer != TimerExpire {
			out.journal(m, fmt.Sprintf("timer %s fired in BOUND: ignored", ev.Timer))
			return
		}
		// RFC 2131 section 4.4.5: "If the lease expires ... the client moves
		// to INIT state, MUST immediately stop any other network processing
		// and requests network initialization parameters as if the client
		// were uninitialized." LeaseLost is how the caller is told to stop.
		m.dropLease(out, ReasonExpired)
		// No desync wait here. Section 4.4.1's one-to-ten-second delay is
		// about desynchronising hosts BOOTING together; a lease that has just
		// expired needs re-acquiring now, and adding the delay would extend
		// every outage by up to ten seconds for no benefit.
		m.beginAcquisition(now, rnd, out, false)
	case EvLinkDown:
		m.dropLease(out, ReasonLinkDown)
		m.toInitIdle(out)
	case EvAddressLost:
		m.dropLease(out, ReasonAddressLost)
		m.beginAcquisition(now, rnd, out, false)
	case EvConflictDetected:
		// M4 sends a DHCPDECLINE here — RFC 2131 section 3.1(5) makes it a
		// MUST once a conflict is detected, and the v1.x plugin's failure to
		// send one is design decision D6. M1 detects nothing and sends
		// nothing; the lease is dropped and re-acquired, which is the honest
		// behaviour for a machine that cannot yet decline.
		m.dropLease(out, ReasonConflict)
		m.beginAcquisition(now, rnd, out, false)
	case EvStart:
		out.journal(m, "Start in BOUND: already running")
	case EvReceived:
		// M1 has no transaction open in BOUND — there is no RENEWING state
		// yet — so anything arriving here is unsolicited.
		out.journal(m, "message in BOUND with no transaction open: discarded")
	case EvActionFailed:
		m.noteActionFailed(rnd, ev, out)
	default:
		out.journal(m, fmt.Sprintf("%s ignored in BOUND", ev.Kind))
	}
}

// ----------------------------------------------------------- transitions --

// beginAcquisition starts a fresh DISCOVER cycle: new xid, counters reset.
//
// withDesync applies RFC 2131 section 4.4.1's startup delay. It is false on the
// paths that are already reacting to something (an expiry, a NAK, a budget
// exhaustion) because there is nothing to desynchronise from there.
func (m *Machine) beginAcquisition(now Instant, rnd uint64, out *actions, withDesync bool) {
	m.startedAt = now
	m.started = true
	m.retransmits = 0
	m.sendFailures = 0
	m.offer = nil
	m.xid = uint32(split(rnd, 0))
	m.state = StateInit
	out.cancel(m, TimerRetransmit)
	out.cancel(m, TimerDesync)
	out.cancel(m, TimerExpire)

	d := Duration(0)
	if withDesync {
		d = m.params.desync(split(rnd, 2))
	}
	if d <= 0 {
		m.sendDiscover(now, split(rnd, 3), out)
		return
	}
	out.set(m, TimerDesync, d)
	out.journal(m, fmt.Sprintf("INIT: waiting %s to desynchronise (RFC 2131 4.4.1)", d))
}

// toInitIdle parks in INIT with nothing armed, waiting for a LinkUp or Start.
func (m *Machine) toInitIdle(out *actions) {
	m.state = StateInit
	m.offer = nil
	m.retransmits = 0
	out.cancel(m, TimerRetransmit)
	out.cancel(m, TimerDesync)
	out.cancel(m, TimerExpire)
}

func (m *Machine) linkDown(out *actions) {
	out.journal(m, "link down during acquisition: parked in INIT")
	m.toInitIdle(out)
}

func (m *Machine) stop(out *actions) {
	m.dropLease(out, ReasonStopped)
	out.cancel(m, TimerRetransmit)
	out.cancel(m, TimerDesync)
	out.cancel(m, TimerExpire)
	m.state = StateStopped
	m.started = false
	m.offer = nil
	m.retransmits = 0
	m.sendFailures = 0
}

// enterBound installs the lease and arms the expiry timer.
//
// Armed for exp-now, NOT for the lease duration: the lease clock starts when
// the REQUEST was sent (RFC 2131 section 4.4.5), so by the time the ACK is in
// hand some of it is spent. Arming for the full duration holds the address
// past its expiry by the round-trip time — invisible on a fixture, real on a
// slow or retransmitting link.
func (m *Machine) enterBound(now Instant, l Lease, out *actions) {
	out.cancel(m, TimerRetransmit)
	m.lease = l
	m.haveLse = true
	m.state = StateBound
	m.offer = nil
	m.retransmits = 0
	m.sendFailures = 0
	out.stamp(m, Action{Kind: ActLeaseAcquired, Lease: l})
	exp, ok := l.Expire()
	if !ok {
		out.journal(m, "lease is infinite: no expiry timer armed")
		return
	}
	d := exp.Sub(now)
	if d < 0 {
		// The ACK arrived after the lease it grants had already run out. Arm
		// for zero rather than for a negative delay, so ring 3 fires it at
		// once and the machine reports the loss, instead of a negative
		// duration meaning whatever the timer implementation happens to do
		// with one.
		d = 0
		out.journal(m, "DHCPACK grants a lease that has already expired")
	}
	out.set(m, TimerExpire, d)
}

func (m *Machine) dropLease(out *actions, r Reason) {
	if !m.haveLse {
		return
	}
	m.haveLse = false
	m.lease = Lease{}
	out.cancel(m, TimerExpire)
	// stamp, not add: every action carries a unique id so an EvActionFailed
	// can name exactly which one did not happen (R2). An unstamped action
	// carries id 0, which collides with the first stamped action of the
	// machine's life — and the collision is silent.
	out.stamp(m, Action{Kind: ActLeaseLost, Reason: r})
}

// noteActionFailed is R2: an action the machine emitted did not happen.
//
// A failed Send is the case that matters. The retransmission counter is NOT
// advanced — the server never saw anything — and the retransmit timer is
// re-armed at the current attempt's delay. After MaxSendFailures consecutive
// failures the transport is reported broken with a typed reason, instead of
// the machine sitting in SELECTING looking healthy.
func (m *Machine) noteActionFailed(rnd uint64, ev Event, out *actions) {
	m.sendFailures++
	out.journal(m, fmt.Sprintf("%s failed (%s), consecutive failures %d",
		ev.Action, ev.Reason, m.sendFailures))
	if m.params.MaxSendFailures > 0 && m.sendFailures >= m.params.MaxSendFailures {
		out.failed(m, ReasonTransport, fmt.Sprintf("%d consecutive send failures: %s",
			m.sendFailures, ev.Reason))
		m.dropLease(out, ReasonTransport)
		m.toInitIdle(out)
		return
	}
	switch m.state {
	case StateSelecting:
		out.set(m, TimerRetransmit, m.params.Discover.Delay(m.retransmits, rnd))
	case StateRequesting:
		out.set(m, TimerRetransmit, m.params.Request.Delay(m.retransmits, rnd))
	}
}

// -------------------------------------------------------------- messages --

func (m *Machine) sendDiscover(now Instant, rnd uint64, out *actions) {
	msg := m.base(now, wire.MsgDiscover)
	if m.params.RequestedIP.Is4() && !m.params.RequestedIP.IsUnspecified() {
		v := m.params.RequestedIP.As4()
		msg.Options[wire.OptRequestedIP] = v[:]
	}
	m.state = StateSelecting
	out.cancel(m, TimerDesync)
	out.send(m, msg, Dest{Broadcast: true})
	out.set(m, TimerRetransmit, m.params.Discover.Delay(m.retransmits, rnd))
}

func (m *Machine) sendRequest(now Instant, rnd uint64, out *actions) {
	if m.offer == nil {
		// Cannot happen through the state machine — REQUESTING is only
		// entered from an OFFER — and handled rather than asserted, because a
		// nil dereference in ring 1 is a plugin crash.
		out.journal(m, "REQUEST with no offer held: restarting")
		m.toInitIdle(out)
		return
	}
	msg := m.base(now, wire.MsgRequest)
	// RFC 2131 section 4.4.1's table: in SELECTING the REQUEST carries the
	// 'requested IP address' (MUST) and the 'server identifier' (MUST), and
	// 'ciaddr' is zero.
	yi := m.offer.YIAddr.As4()
	msg.Options[wire.OptRequestedIP] = yi[:]
	if sid, ok := m.offer.Addr4(wire.OptServerID); ok {
		v := sid.As4()
		msg.Options[wire.OptServerID] = v[:]
	}
	m.state = StateRequesting
	m.requestSentAt = now
	out.send(m, msg, Dest{Broadcast: true})
	out.set(m, TimerRetransmit, m.params.Request.Delay(m.retransmits, rnd))
}

// base builds the common part of a client message.
func (m *Machine) base(now Instant, t wire.MessageType) *wire.Message {
	msg := &wire.Message{
		Op:      wire.BootRequest,
		HType:   wire.HTypeEthernet,
		XID:     m.xid,
		Secs:    m.secs(now),
		CHAddr:  append([]byte(nil), m.params.CHAddr...),
		Options: wire.Options{},
	}
	if m.params.Broadcast {
		msg.Flags |= wire.FlagBroadcast
	}
	msg.SetType(t)
	if len(m.params.ClientID) > 0 {
		msg.Options[wire.OptClientID] = append([]byte(nil), m.params.ClientID...)
	}
	if m.params.Hostname != "" {
		msg.Options[wire.OptHostName] = []byte(m.params.Hostname)
	}
	if m.params.VendorClass != "" {
		msg.Options[wire.OptVendorClassID] = []byte(m.params.VendorClass)
	}
	if pl := m.params.parameterList(); len(pl) > 0 {
		b := make([]byte, 0, len(pl))
		for _, c := range pl {
			b = append(b, byte(c))
		}
		msg.Options[wire.OptParameterList] = b
	}
	if m.params.RequestedLease > 0 && !m.params.RequestedLease.IsInfinite() {
		secs := uint32(m.params.RequestedLease.Seconds())
		msg.Options[wire.OptLeaseTime] = []byte{
			byte(secs >> 24), byte(secs >> 16), byte(secs >> 8), byte(secs),
		}
	}
	return msg
}

// secs is RFC 2131 section 2's 'secs': "Filled in by client, seconds elapsed
// since client began address acquisition or renewal process."
//
// It saturates at 65535 rather than wrapping. A wrap makes a client that has
// been trying for eighteen hours look like one that just started, which is the
// opposite of what a relay agent reads the field for.
func (m *Machine) secs(now Instant) uint16 {
	if !m.started {
		return 0
	}
	d := now.Sub(m.startedAt)
	if d <= 0 {
		return 0
	}
	s := d.Seconds()
	if s > 65535 {
		return 65535
	}
	return uint16(s)
}

// acceptable applies the filtering RFC 2131 requires before a message is
// looked at: it must be a reply, it must carry a message type, and its xid
// must match the transaction in flight.
//
// This lives in ring 1 and not in the transport on purpose. "If the 'xid' of
// an arriving DHCPOFFER message does not match the 'xid' of the most recent
// DHCPDISCOVER message, the DHCPOFFER message must be silently discarded"
// (RFC 2131 section 4.4.1) is a protocol rule, and a protocol rule enforced in
// ring 3 is a protocol rule with no fast test.
func (m *Machine) acceptable(msg *wire.Message, out *actions) (*wire.Message, bool) {
	if msg == nil {
		out.journal(m, "nil message: discarded")
		return nil, false
	}
	if msg.Op != wire.BootReply {
		out.journal(m, fmt.Sprintf("%s is not a BOOTREPLY: discarded", msg.Op))
		return nil, false
	}
	if _, ok := msg.Type(); !ok {
		out.journal(m, "message carries no DHCP message type: discarded")
		return nil, false
	}
	if msg.XID != m.xid {
		out.journal(m, fmt.Sprintf("xid %#08x does not match %#08x: discarded", msg.XID, m.xid))
		return nil, false
	}
	if !m.chaddrMatches(msg) {
		// Not required by RFC 2131 in so many words, and cheap: a reply whose
		// chaddr is somebody else's is either a relay bug or a collision, and
		// accepting it configures this host with another host's address.
		out.journal(m, "chaddr does not match: discarded")
		return nil, false
	}
	return msg, true
}

func (m *Machine) chaddrMatches(msg *wire.Message) bool {
	if len(msg.CHAddr) != len(m.params.CHAddr) {
		return false
	}
	for i := range msg.CHAddr {
		if msg.CHAddr[i] != m.params.CHAddr[i] {
			return false
		}
	}
	return true
}

func (m *Machine) nakText(msg *wire.Message) string {
	if s, ok := msg.Text(wire.OptMessage); ok && s != "" {
		return "DHCPNAK: " + s
	}
	return "DHCPNAK"
}

// ---------------------------------------------------------------- output --

// actions accumulates the action list, stamping each with the machine's next
// ActionID so a failure can name exactly which one did not happen.
type actions struct{ list []Action }

func (a *actions) stamp(m *Machine, x Action) {
	x.ID = m.nextAction
	m.nextAction++
	a.list = append(a.list, x)
}

func (a *actions) send(m *Machine, msg *wire.Message, d Dest) {
	a.stamp(m, Action{Kind: ActSend, Msg: msg, Dest: d})
}

func (a *actions) set(m *Machine, t TimerID, d Duration) {
	a.stamp(m, Action{Kind: ActSetTimer, Timer: t, After: d})
}

func (a *actions) cancel(m *Machine, t TimerID) {
	a.stamp(m, Action{Kind: ActCancelTimer, Timer: t})
}

func (a *actions) journal(m *Machine, note string) {
	a.stamp(m, Action{Kind: ActJournal, Note: note})
}

func (a *actions) failed(m *Machine, r Reason, note string) {
	a.stamp(m, Action{Kind: ActFailed, Reason: r, Note: note})
}
