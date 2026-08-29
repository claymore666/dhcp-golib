package proto

import (
	"net/netip"
	"testing"

	"github.com/claymore666/dhcplease/wire"
)

var testCHAddr = []byte{0x02, 0x42, 0xAC, 0x11, 0x00, 0x02}

// at builds an Instant n seconds after the machine's zero. Instant and
// Duration are distinct types on purpose — a point in time and a length of
// time are not interchangeable, and the compiler enforcing that is the reason
// this helper exists rather than a plain multiplication at every call site.
func at(sec int64) Instant { return Instant(sec) * Instant(Second) }

// testParams is the parameter set the acquisition tests use. Desync is
// disabled so the DISCOVER leaves on the Start step: the delay is exercised by
// TestDesyncDelay on its own, and leaving it on here would make every other
// test carry a timer fire that has nothing to do with what it asserts.
func testParams() Params {
	p := DefaultParams(testCHAddr)
	p.DesyncMin = 0
	p.DesyncMax = 0
	return p
}

func newMachine(t *testing.T, p Params) *Machine {
	t.Helper()
	m, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

// find returns the first action of the given kind.
func find(acts []Action, k ActionKind) (Action, bool) {
	for _, a := range acts {
		if a.Kind == k {
			return a, true
		}
	}
	return Action{}, false
}

func count(acts []Action, k ActionKind) int {
	n := 0
	for _, a := range acts {
		if a.Kind == k {
			n++
		}
	}
	return n
}

func mustSend(t *testing.T, acts []Action, want wire.MessageType) *wire.Message {
	t.Helper()
	a, ok := find(acts, ActSend)
	if !ok {
		t.Fatalf("no ActSend in %v", RenderActions(acts))
	}
	got, ok := a.Msg.Type()
	if !ok {
		t.Fatalf("sent message carries no DHCP message type")
	}
	if got != want {
		t.Fatalf("sent %s, want %s", got, want)
	}
	return a.Msg
}

// offerFor builds a DHCPOFFER answering the given request.
func offerFor(req *wire.Message, yiaddr, serverID string) *wire.Message {
	m := &wire.Message{
		Op:     wire.BootReply,
		HType:  wire.HTypeEthernet,
		XID:    req.XID,
		YIAddr: netip.MustParseAddr(yiaddr),
		CHAddr: append([]byte(nil), req.CHAddr...),
		Options: wire.Options{
			wire.OptMessageType: {byte(wire.MsgOffer)},
			wire.OptServerID:    addr4(serverID),
			wire.OptSubnetMask:  {255, 255, 255, 0},
			wire.OptRouter:      addr4("192.168.99.1"),
			wire.OptDNSServer:   addr4("192.168.99.1"),
			wire.OptLeaseTime:   u32(3600),
		},
	}
	return m
}

func ackFor(req *wire.Message, yiaddr, serverID string, lease uint32) *wire.Message {
	m := offerFor(req, yiaddr, serverID)
	m.Options[wire.OptMessageType] = []byte{byte(wire.MsgAck)}
	m.Options[wire.OptLeaseTime] = u32(lease)
	m.Options[wire.OptDomainName] = []byte("example.test")
	m.Options[wire.OptInterfaceMTU] = []byte{0x05, 0xDC}
	return m
}

func nakFor(req *wire.Message, serverID, text string) *wire.Message {
	return &wire.Message{
		Op: wire.BootReply, HType: wire.HTypeEthernet, XID: req.XID,
		CHAddr: append([]byte(nil), req.CHAddr...),
		Options: wire.Options{
			wire.OptMessageType: {byte(wire.MsgNak)},
			wire.OptServerID:    addr4(serverID),
			wire.OptMessage:     []byte(text),
		},
	}
}

func addr4(s string) []byte {
	a := netip.MustParseAddr(s).As4()
	return a[:]
}

func u32(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

// received wraps a message as an EvReceived carrying its wire form, the way
// ring 2 does. Encoding it is not ceremony: the journal replays from Raw, so a
// test that fed a hand-built struct would exercise a path replay never takes.
func received(t *testing.T, m *wire.Message) Event {
	t.Helper()
	raw, err := wire.Encode(m)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	dec, err := wire.Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	return Received(dec, raw)
}

// -------------------------------------------------------------- totality --

// TestStepIsTotal is requirement R1 over the whole product, not a sample.
//
// It also drives EVERY state, including StateStopped, and every event kind
// including ones no state handles. The failure it exists to catch is a nil
// dereference or an index panic in ring 1, which in the plugin is not a
// returned error — it is the network driver going down with the daemon.
func TestStepIsTotal(t *testing.T) {
	states := AllStates()
	kinds := AllEventKinds()
	if len(states) == 0 || len(kinds) == 0 {
		t.Fatal("AllStates or AllEventKinds is empty; this test would measure nothing")
	}

	// The event payloads are deliberately hostile: a nil message, a message
	// with no type, a timer id outside the set. A totality test built only
	// from well-formed events measures the happy path twice.
	payloads := []struct {
		name string
		ev   func(*Machine) Event
	}{
		{"bare", func(*Machine) Event { return Event{} }},
		{"nil message", func(*Machine) Event { return Event{Msg: nil} }},
		{"typeless message", func(*Machine) Event {
			return Event{Msg: &wire.Message{Op: wire.BootReply, CHAddr: testCHAddr}}
		}},
		{"matching ack", func(m *Machine) Event {
			req := &wire.Message{XID: m.xid, CHAddr: testCHAddr}
			return Event{Msg: ackFor(req, "192.168.99.50", "192.168.99.1", 3600)}
		}},
		{"out-of-range timer", func(*Machine) Event { return Event{Timer: TimerID(200)} }},
	}

	for _, st := range states {
		for _, k := range kinds {
			for _, pl := range payloads {
				name := st.String() + "/" + k.String() + "/" + pl.name
				t.Run(name, func(t *testing.T) {
					m := machineIn(t, st)
					if m.State() != st {
						t.Fatalf("fixture is in %s, not %s", m.State(), st)
					}
					ev := pl.ev(m)
					ev.Kind = k
					next, acts := m.Step(at(1000), 0x1234_5678_9ABC_DEF0, ev)
					if !validState(next) {
						t.Fatalf("Step returned undefined state %d", next)
					}
					for i, a := range acts {
						if a.Kind == ActSend && a.Msg == nil {
							t.Fatalf("action %d is a Send with no message", i)
						}
					}
				})
			}
		}
	}
}

func validState(s State) bool {
	for _, x := range AllStates() {
		if x == s {
			return true
		}
	}
	return false
}

// machineIn returns a machine sitting in the named state, reached by real
// transitions. Constructing one by assignment would prove nothing: the states
// a test can build by hand include ones the machine cannot reach.
func machineIn(t *testing.T, s State) *Machine {
	t.Helper()
	m := newMachine(t, testParams())
	switch s {
	case StateStopped:
		return m
	case StateInit:
		// INIT with nothing armed: start, then drop the link.
		m.Step(0, 1, Simple(EvStart))
		m.Step(at(1), 1, Simple(EvLinkDown))
	case StateSelecting:
		m.Step(0, 1, Simple(EvStart))
	case StateRequesting:
		_, acts := m.Step(0, 1, Simple(EvStart))
		req := mustSend(t, acts, wire.MsgDiscover)
		m.Step(at(1), 2, received(t, offerFor(req, "192.168.99.50", "192.168.99.1")))
	case StateBound:
		_, acts := m.Step(0, 1, Simple(EvStart))
		disc := mustSend(t, acts, wire.MsgDiscover)
		_, acts = m.Step(at(1), 2, received(t, offerFor(disc, "192.168.99.50", "192.168.99.1")))
		req := mustSend(t, acts, wire.MsgRequest)
		m.Step(at(2), 3, received(t, ackFor(req, "192.168.99.50", "192.168.99.1", 3600)))
	default:
		t.Fatalf("machineIn does not know how to reach %s — a new state was added without extending the totality fixture", s)
	}
	if m.State() != s {
		t.Fatalf("fixture reached %s, want %s", m.State(), s)
	}
	return m
}

// ------------------------------------------------------------ acquisition --

// TestAcquisition is done-condition (c): the whole INIT-to-BOUND path, table
// driven, with no root, no namespace, no network and no clock.
func TestAcquisition(t *testing.T) {
	m := newMachine(t, testParams())

	// Start: no desync configured, so the DISCOVER goes out at once.
	st, acts := m.Step(0, 0xAAAA, Simple(EvStart))
	if st != StateSelecting {
		t.Fatalf("after Start: %s, want SELECTING", st)
	}
	disc := mustSend(t, acts, wire.MsgDiscover)
	if disc.Op != wire.BootRequest {
		t.Fatalf("DISCOVER op = %s, want BOOTREQUEST", disc.Op)
	}
	if disc.Flags&wire.FlagBroadcast == 0 {
		t.Fatal("DISCOVER does not set the BROADCAST flag; a raw-socket client cannot receive the unicast reply")
	}
	if !disc.CIAddr.IsUnspecified() && disc.CIAddr.IsValid() {
		t.Fatalf("DISCOVER ciaddr = %s, want unset (RFC 2131 4.4.1)", disc.CIAddr)
	}
	if _, ok := disc.Options[wire.OptParameterList]; !ok {
		t.Fatal("DISCOVER carries no parameter request list")
	}
	if a, ok := find(acts, ActSetTimer); !ok || a.Timer != TimerRetransmit {
		t.Fatalf("no retransmit timer armed after DISCOVER: %v", RenderActions(acts))
	}

	// OFFER.
	st, acts = m.Step(at(1), 0xBBBB, received(t, offerFor(disc, "192.168.99.50", "192.168.99.1")))
	if st != StateRequesting {
		t.Fatalf("after OFFER: %s, want REQUESTING", st)
	}
	req := mustSend(t, acts, wire.MsgRequest)

	// RFC 2131 section 4.4.1's table for a REQUEST sent from SELECTING.
	if got, ok := req.Addr4(wire.OptRequestedIP); !ok || got.String() != "192.168.99.50" {
		t.Fatalf("REQUEST requested-IP = %v/%v, want the OFFER's yiaddr (MUST)", got, ok)
	}
	if got, ok := req.Addr4(wire.OptServerID); !ok || got.String() != "192.168.99.1" {
		t.Fatalf("REQUEST server-identifier = %v/%v, want the OFFER's (MUST)", got, ok)
	}
	if req.CIAddr.IsValid() && !req.CIAddr.IsUnspecified() {
		t.Fatalf("REQUEST ciaddr = %s, want zero when sent from SELECTING (MUST)", req.CIAddr)
	}
	if req.XID != disc.XID {
		t.Fatalf("REQUEST xid %#x != DISCOVER xid %#x; they are one transaction", req.XID, disc.XID)
	}
	if !bytesEqual(req.Options[wire.OptParameterList], disc.Options[wire.OptParameterList]) {
		t.Fatal("REQUEST parameter list differs from the DISCOVER's (RFC 2131 4.4.1 MUST)")
	}

	// ACK.
	st, acts = m.Step(at(2), 0xCCCC, received(t, ackFor(req, "192.168.99.50", "192.168.99.1", 3600)))
	if st != StateBound {
		t.Fatalf("after ACK: %s, want BOUND", st)
	}
	got, ok := find(acts, ActLeaseAcquired)
	if !ok {
		t.Fatalf("no LeaseAcquired: %v", RenderActions(acts))
	}
	l := got.Lease
	if l.Addr.String() != "192.168.99.50/24" {
		t.Fatalf("lease addr = %s, want 192.168.99.50/24", l.Addr)
	}
	if l.ServerID.String() != "192.168.99.1" {
		t.Fatalf("server id = %s", l.ServerID)
	}
	if l.Domain != "example.test" {
		t.Fatalf("domain = %q", l.Domain)
	}
	if l.MTU != 1500 {
		t.Fatalf("mtu = %d, want 1500", l.MTU)
	}

	// RFC 2131 section 4.4.5: the lease clock starts when the REQUEST was
	// SENT, not when the ACK arrived. The REQUEST left at t=1s, so the lease
	// runs out at 3601s, not 3602s. One second is invisible on a fixture and
	// is exactly the error that makes a client hold an address past expiry.
	if l.Start != at(1) {
		t.Fatalf("lease Start = %s, want the REQUEST send time 1s (RFC 2131 4.4.5)", Duration(l.Start))
	}
	exp, ok := l.Expire()
	if !ok || exp != at(3601) {
		t.Fatalf("expiry = %v/%v, want 3601s", exp, ok)
	}

	// And the expiry timer is armed for the REMAINING time, not the full lease.
	var armed Action
	for _, a := range acts {
		if a.Kind == ActSetTimer && a.Timer == TimerExpire {
			armed = a
		}
	}
	if armed.Kind != ActSetTimer {
		t.Fatalf("no expiry timer armed: %v", RenderActions(acts))
	}
	if armed.After != 3599*Second {
		t.Fatalf("expiry armed for %s at t=2s, want 3599s (expiry minus now), not the lease duration", armed.After)
	}

	// The retransmit timer is cancelled on entering BOUND: a live retransmit
	// timer in BOUND resends a REQUEST for a lease we already hold.
	var cancelled bool
	for _, a := range acts {
		if a.Kind == ActCancelTimer && a.Timer == TimerRetransmit {
			cancelled = true
		}
	}
	if !cancelled {
		t.Fatalf("retransmit timer not cancelled on entering BOUND: %v", RenderActions(acts))
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestExpiryDropsTheLeaseAndReacquires(t *testing.T) {
	// RFC 2131 section 4.4.5: on expiry the client "moves to INIT state, MUST
	// immediately stop any other network processing and requests network
	// initialization parameters as if the client were uninitialized".
	m := machineIn(t, StateBound)
	st, acts := m.Step(at(4000), 7, TimerFired(TimerExpire))

	lost, ok := find(acts, ActLeaseLost)
	if !ok {
		t.Fatalf("no LeaseLost on expiry: %v", RenderActions(acts))
	}
	if lost.Reason != ReasonExpired {
		t.Fatalf("LeaseLost reason = %s, want expired", lost.Reason)
	}
	// The order matters: the caller must be told to stop using the address
	// BEFORE the client starts asking for a new one.
	lostAt, sendAt := -1, -1
	for i, a := range acts {
		if a.Kind == ActLeaseLost && lostAt < 0 {
			lostAt = i
		}
		if a.Kind == ActSend && sendAt < 0 {
			sendAt = i
		}
	}
	if sendAt >= 0 && lostAt > sendAt {
		t.Fatalf("LeaseLost is emitted after the new DISCOVER: %v", RenderActions(acts))
	}
	if st != StateSelecting {
		t.Fatalf("after expiry: %s, want SELECTING (re-acquiring)", st)
	}
	if _, held := m.Lease(); held {
		t.Fatal("machine still holds the expired lease")
	}
	mustSend(t, acts, wire.MsgDiscover)
}

func TestNakRestarts(t *testing.T) {
	// RFC 2131 section 3.1(5): "If the client receives a DHCPNAK message, the
	// client restarts the configuration process."
	m := newMachine(t, testParams())
	_, acts := m.Step(0, 1, Simple(EvStart))
	disc := mustSend(t, acts, wire.MsgDiscover)
	_, acts = m.Step(at(1), 2, received(t, offerFor(disc, "192.168.99.50", "192.168.99.1")))
	req := mustSend(t, acts, wire.MsgRequest)

	st, acts := m.Step(at(2), 3, received(t, nakFor(req, "192.168.99.1", "lease not available")))
	if st != StateSelecting {
		t.Fatalf("after NAK: %s, want SELECTING", st)
	}
	f, ok := find(acts, ActFailed)
	if !ok {
		t.Fatalf("no Failed action on NAK: %v", RenderActions(acts))
	}
	if f.Reason != ReasonNak {
		t.Fatalf("Failed reason = %s, want nak", f.Reason)
	}
	if f.Note == "" {
		t.Fatal("NAK note is empty; the server's message is the only diagnosis a user gets")
	}
	newDisc := mustSend(t, acts, wire.MsgDiscover)
	if newDisc.XID == disc.XID {
		t.Fatal("restart reused the xid; a restart is a new transaction (RFC 2131 4.4.1)")
	}
}

func TestOfferWithoutServerIDIsDiscarded(t *testing.T) {
	// The REQUEST that follows MUST carry the server identifier. An OFFER
	// without one cannot produce a conformant REQUEST, so it is refused rather
	// than half-used.
	m := newMachine(t, testParams())
	_, acts := m.Step(0, 1, Simple(EvStart))
	disc := mustSend(t, acts, wire.MsgDiscover)

	bad := offerFor(disc, "192.168.99.50", "192.168.99.1")
	delete(bad.Options, wire.OptServerID)

	st, acts := m.Step(at(1), 2, received(t, bad))
	if st != StateSelecting {
		t.Fatalf("state = %s, want to stay in SELECTING", st)
	}
	if count(acts, ActSend) != 0 {
		t.Fatalf("a REQUEST was sent for an OFFER with no server identifier: %v", RenderActions(acts))
	}
}

func TestOfferWithoutYiaddrIsDiscarded(t *testing.T) {
	m := newMachine(t, testParams())
	_, acts := m.Step(0, 1, Simple(EvStart))
	disc := mustSend(t, acts, wire.MsgDiscover)

	bad := offerFor(disc, "192.168.99.50", "192.168.99.1")
	bad.YIAddr = netip.Addr{}

	st, acts := m.Step(at(1), 2, received(t, bad))
	if st != StateSelecting || count(acts, ActSend) != 0 {
		t.Fatalf("OFFER with no yiaddr was acted on: state %s, %v", st, RenderActions(acts))
	}
}

func TestAckInSelectingIsDiscarded(t *testing.T) {
	// RFC 2131 section 4.4.1: "Any arriving DHCPACK messages must be silently
	// discarded." A client that took it would be BOUND to an address it never
	// requested.
	m := newMachine(t, testParams())
	_, acts := m.Step(0, 1, Simple(EvStart))
	disc := mustSend(t, acts, wire.MsgDiscover)

	st, acts := m.Step(at(1), 2, received(t, ackFor(disc, "192.168.99.50", "192.168.99.1", 3600)))
	if st != StateSelecting {
		t.Fatalf("state = %s after an unsolicited ACK, want SELECTING", st)
	}
	if _, ok := find(acts, ActLeaseAcquired); ok {
		t.Fatalf("an ACK in SELECTING produced a lease: %v", RenderActions(acts))
	}
}

func TestXidMismatchIsDiscarded(t *testing.T) {
	// RFC 2131 section 4.4.1: "If the 'xid' of an arriving DHCPOFFER message
	// does not match the 'xid' of the most recent DHCPDISCOVER message, the
	// DHCPOFFER message must be silently discarded."
	m := newMachine(t, testParams())
	_, acts := m.Step(0, 1, Simple(EvStart))
	disc := mustSend(t, acts, wire.MsgDiscover)

	other := offerFor(disc, "192.168.99.50", "192.168.99.1")
	other.XID = disc.XID ^ 0xFFFF

	st, acts := m.Step(at(1), 2, received(t, other))
	if st != StateSelecting || count(acts, ActSend) != 0 {
		t.Fatalf("a foreign xid was accepted: state %s, %v", st, RenderActions(acts))
	}
}

func TestChaddrMismatchIsDiscarded(t *testing.T) {
	m := newMachine(t, testParams())
	_, acts := m.Step(0, 1, Simple(EvStart))
	disc := mustSend(t, acts, wire.MsgDiscover)

	other := offerFor(disc, "192.168.99.50", "192.168.99.1")
	other.CHAddr = []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}

	st, acts := m.Step(at(1), 2, received(t, other))
	if st != StateSelecting || count(acts, ActSend) != 0 {
		t.Fatalf("another host's chaddr was accepted: state %s, %v", st, RenderActions(acts))
	}
}

func TestBootRequestReplyIsDiscarded(t *testing.T) {
	// Our own broadcast DISCOVER comes back on a raw socket bound to the same
	// link. A machine that accepted a BOOTREQUEST would answer itself.
	m := newMachine(t, testParams())
	_, acts := m.Step(0, 1, Simple(EvStart))
	disc := mustSend(t, acts, wire.MsgDiscover)

	echo := disc.Clone()
	st, acts := m.Step(at(1), 2, received(t, echo))
	if st != StateSelecting || count(acts, ActSend) != 0 {
		t.Fatalf("the client acted on its own DISCOVER: state %s, %v", st, RenderActions(acts))
	}
}

// ---------------------------------------------------------- retransmission --

func TestRetransmissionBudgetThenRestart(t *testing.T) {
	// RFC 2131 section 3.1(5) again: the retransmission algorithm is bounded,
	// and when it is exhausted the client "reverts to INIT state and restarts
	// the initialization process", notifying the user.
	m := newMachine(t, testParams())
	_, acts := m.Step(0, 1, Simple(EvStart))
	first := mustSend(t, acts, wire.MsgDiscover)

	budget := testParams().Discover.MaxRetransmissions
	now := Instant(0)
	for i := 0; i < budget; i++ {
		now = now.Add(10 * Second)
		st, acts := m.Step(now, uint64(100+i), TimerFired(TimerRetransmit))
		if st != StateSelecting {
			t.Fatalf("retransmission %d left SELECTING: %s", i+1, st)
		}
		again := mustSend(t, acts, wire.MsgDiscover)
		if again.XID != first.XID {
			t.Fatalf("retransmission %d used a new xid; a retransmission is the SAME transaction", i+1)
		}
		if again.Secs == 0 {
			t.Fatalf("retransmission %d has secs=0; the field counts from the start of acquisition", i+1)
		}
	}

	now = now.Add(10 * Second)
	st, acts := m.Step(now, 999, TimerFired(TimerRetransmit))
	f, ok := find(acts, ActFailed)
	if !ok {
		t.Fatalf("budget exhausted with no Failed notification: %v", RenderActions(acts))
	}
	if f.Reason != ReasonNoServer {
		t.Fatalf("Failed reason = %s, want no-server", f.Reason)
	}
	if st != StateSelecting {
		t.Fatalf("state = %s, want a restarted acquisition", st)
	}
	restart := mustSend(t, acts, wire.MsgDiscover)
	if restart.XID == first.XID {
		t.Fatal("the restart reused the xid; it is a new transaction")
	}
}

func TestSecsSaturates(t *testing.T) {
	// A wrap makes a client that has been trying for eighteen hours look like
	// one that just started, which is the opposite of what a relay reads the
	// field for.
	m := newMachine(t, testParams())
	m.Step(0, 1, Simple(EvStart))
	_, acts := m.Step(at(200000), 2, TimerFired(TimerRetransmit))
	msg := mustSend(t, acts, wire.MsgDiscover)
	if msg.Secs != 65535 {
		t.Fatalf("secs = %d after 200000s, want it saturated at 65535", msg.Secs)
	}
}

func TestDesyncDelay(t *testing.T) {
	// RFC 2131 section 4.4.1: "The client SHOULD wait a random time between
	// one and ten seconds to desynchronize the use of DHCP at startup."
	p := DefaultParams(testCHAddr)
	if p.DesyncMin != 1*Second || p.DesyncMax != 10*Second {
		t.Fatalf("default desync window is %s..%s, want 1s..10s", p.DesyncMin, p.DesyncMax)
	}
	for i := 0; i < 500; i++ {
		m := newMachine(t, p)
		st, acts := m.Step(0, uint64(i)*0x9E3779B97F4A7C15, Simple(EvStart))
		if st != StateInit {
			t.Fatalf("Start with desync configured went straight to %s; the delay was skipped", st)
		}
		if count(acts, ActSend) != 0 {
			t.Fatalf("a DISCOVER was sent before the desync delay elapsed: %v", RenderActions(acts))
		}
		var armed Action
		for _, a := range acts {
			if a.Kind == ActSetTimer && a.Timer == TimerDesync {
				armed = a
			}
		}
		if armed.Kind != ActSetTimer {
			t.Fatalf("no desync timer armed: %v", RenderActions(acts))
		}
		if armed.After < 1*Second || armed.After > 10*Second {
			t.Fatalf("desync delay %s is outside the RFC's 1..10s window", armed.After)
		}
	}

	// And the delay firing is what sends the DISCOVER.
	m := newMachine(t, p)
	m.Step(0, 42, Simple(EvStart))
	st, acts := m.Step(at(5), 43, TimerFired(TimerDesync))
	if st != StateSelecting {
		t.Fatalf("desync fire left the machine in %s", st)
	}
	mustSend(t, acts, wire.MsgDiscover)
}

// -------------------------------------------------------------------- R2 --

func TestFailedSendDoesNotAdvanceTheRetransmitCounter(t *testing.T) {
	// R2. The server never saw the message, so "one attempt used" would be a
	// lie the budget then pays for: with the counter advanced, a transport
	// that fails every send burns the whole retransmission budget without a
	// single packet reaching the wire.
	m := newMachine(t, testParams())
	_, acts := m.Step(0, 1, Simple(EvStart))
	send, ok := find(acts, ActSend)
	if !ok {
		t.Fatal("no send to fail")
	}

	before := m.retransmits
	_, acts = m.Step(at(1), 2, ActionFailed(send.ID, "network is down"))
	if m.retransmits != before {
		t.Fatalf("retransmit counter moved %d -> %d on a send that never left", before, m.retransmits)
	}
	// The retransmit timer is re-armed, so the machine tries again rather than
	// sitting idle.
	var rearmed bool
	for _, a := range acts {
		if a.Kind == ActSetTimer && a.Timer == TimerRetransmit {
			rearmed = true
		}
	}
	if !rearmed {
		t.Fatalf("no retransmit timer re-armed after a failed send: %v", RenderActions(acts))
	}
}

func TestMaxSendFailuresReportsTheTransport(t *testing.T) {
	// Without this bound, a machine whose every send fails sits in SELECTING
	// re-arming a timer forever and looks exactly like one waiting for a slow
	// server.
	p := testParams()
	p.MaxSendFailures = 3
	m := newMachine(t, p)
	_, acts := m.Step(0, 1, Simple(EvStart))
	send, _ := find(acts, ActSend)

	var last []Action
	for i := 0; i < p.MaxSendFailures; i++ {
		_, last = m.Step(at(int64(i+1)), uint64(i), ActionFailed(send.ID, "ENETDOWN"))
	}
	f, ok := find(last, ActFailed)
	if !ok {
		t.Fatalf("no Failed action after %d consecutive send failures: %v", p.MaxSendFailures, RenderActions(last))
	}
	if f.Reason != ReasonTransport {
		t.Fatalf("Failed reason = %s, want transport", f.Reason)
	}
	if m.State() != StateInit {
		t.Fatalf("state = %s, want INIT (parked, not spinning)", m.State())
	}
}

func TestBoundSendFailureDropsTheLease(t *testing.T) {
	// The preservation control's opposite direction: a transport that has
	// broken while we hold a lease must surface the LOSS, not just a Failed.
	// A caller left holding an address on a dead link is the v1.x failure this
	// library exists to stop repeating.
	p := testParams()
	p.MaxSendFailures = 1
	m := newMachine(t, p)
	// Reach BOUND with these params.
	_, acts := m.Step(0, 1, Simple(EvStart))
	disc := mustSend(t, acts, wire.MsgDiscover)
	_, acts = m.Step(at(1), 2, received(t, offerFor(disc, "192.168.99.50", "192.168.99.1")))
	req := mustSend(t, acts, wire.MsgRequest)
	_, acts = m.Step(at(2), 3, received(t, ackFor(req, "192.168.99.50", "192.168.99.1", 3600)))
	if m.State() != StateBound {
		t.Fatalf("fixture is in %s, not BOUND", m.State())
	}
	acq, _ := find(acts, ActLeaseAcquired)

	_, acts = m.Step(at(3), 4, ActionFailed(acq.ID, "ENETDOWN"))
	lost, ok := find(acts, ActLeaseLost)
	if !ok {
		t.Fatalf("a broken transport in BOUND did not report the lease lost: %v", RenderActions(acts))
	}
	if lost.Reason != ReasonTransport {
		t.Fatalf("LeaseLost reason = %s, want transport", lost.Reason)
	}
}

func TestLinkDownInBoundDropsTheLease(t *testing.T) {
	m := machineIn(t, StateBound)
	st, acts := m.Step(at(10), 1, Simple(EvLinkDown))
	lost, ok := find(acts, ActLeaseLost)
	if !ok || lost.Reason != ReasonLinkDown {
		t.Fatalf("link down did not drop the lease with a link-down reason: %v", RenderActions(acts))
	}
	if st != StateInit {
		t.Fatalf("state = %s, want INIT parked (nothing to send on a dead link)", st)
	}
	if count(acts, ActSend) != 0 {
		t.Fatalf("the machine sent on a link it was just told is down: %v", RenderActions(acts))
	}
}

func TestStopDropsTheLeaseAndCancelsEverything(t *testing.T) {
	m := machineIn(t, StateBound)
	st, acts := m.Step(at(10), 1, Simple(EvStop))
	if st != StateStopped {
		t.Fatalf("state = %s, want STOPPED", st)
	}
	lost, ok := find(acts, ActLeaseLost)
	if !ok || lost.Reason != ReasonStopped {
		t.Fatalf("Stop did not report the lease lost: %v", RenderActions(acts))
	}
	for _, id := range AllTimerIDs() {
		found := false
		for _, a := range acts {
			if a.Kind == ActCancelTimer && a.Timer == id {
				found = true
			}
		}
		if !found {
			t.Fatalf("Stop left timer %s armed: %v", id, RenderActions(acts))
		}
	}
}

func TestStopWithNoLeaseReportsNoLoss(t *testing.T) {
	// The preservation control for the test above: LeaseLost must mean a lease
	// was actually lost. A Stop from SELECTING has nothing to lose, and a
	// spurious Lost event would make the plugin tear down an address it never
	// installed.
	m := machineIn(t, StateSelecting)
	_, acts := m.Step(at(10), 1, Simple(EvStop))
	if _, ok := find(acts, ActLeaseLost); ok {
		t.Fatalf("Stop with no lease emitted LeaseLost: %v", RenderActions(acts))
	}
}

func TestAckWithoutLeaseTimeIsDiscarded(t *testing.T) {
	m := machineIn(t, StateRequesting)
	// Rebuild the REQUEST the fixture sent so the ACK matches its xid.
	req := &wire.Message{XID: m.xid, CHAddr: testCHAddr}
	bad := ackFor(req, "192.168.99.50", "192.168.99.1", 3600)
	delete(bad.Options, wire.OptLeaseTime)

	st, acts := m.Step(at(5), 1, received(t, bad))
	if st != StateRequesting {
		t.Fatalf("state = %s, want to stay in REQUESTING", st)
	}
	if _, ok := find(acts, ActLeaseAcquired); ok {
		t.Fatalf("an ACK with no lease time produced a lease: %v", RenderActions(acts))
	}
}

func TestInfiniteLeaseArmsNoExpiry(t *testing.T) {
	m := machineIn(t, StateRequesting)
	req := &wire.Message{XID: m.xid, CHAddr: testCHAddr}
	ack := ackFor(req, "192.168.99.50", "192.168.99.1", InfiniteSeconds)

	st, acts := m.Step(at(5), 1, received(t, ack))
	if st != StateBound {
		t.Fatalf("state = %s, want BOUND", st)
	}
	for _, a := range acts {
		if a.Kind == ActSetTimer && a.Timer == TimerExpire {
			t.Fatalf("an expiry timer was armed for an infinite lease: %s", a)
		}
	}
	l, ok := m.Lease()
	if !ok {
		t.Fatal("no lease held")
	}
	if _, has := l.Expire(); has {
		t.Fatal("an infinite lease reports an expiry")
	}
}

func TestAckForAnAlreadyExpiredLeaseArmsZero(t *testing.T) {
	// The ACK grants a lease whose clock started at the REQUEST send and has
	// already run out. Arming a negative delay leaves the behaviour to
	// whatever the timer implementation does with one; arming zero makes ring
	// 3 fire it at once and the machine report the loss.
	m := newMachine(t, testParams())
	_, acts := m.Step(0, 1, Simple(EvStart))
	disc := mustSend(t, acts, wire.MsgDiscover)
	_, acts = m.Step(at(1), 2, received(t, offerFor(disc, "192.168.99.50", "192.168.99.1")))
	req := mustSend(t, acts, wire.MsgRequest)

	// The REQUEST went out at t=1s with a 2-second lease; the ACK arrives at
	// t=100s.
	_, acts = m.Step(at(100), 3, received(t, ackFor(req, "192.168.99.50", "192.168.99.1", 2)))
	var armed *Action
	for i := range acts {
		if acts[i].Kind == ActSetTimer && acts[i].Timer == TimerExpire {
			armed = &acts[i]
		}
	}
	if armed == nil {
		t.Fatalf("no expiry timer armed: %v", RenderActions(acts))
	}
	if armed.After != 0 {
		t.Fatalf("expiry armed for %s, want 0 for a lease that has already run out", armed.After)
	}
}

func TestEveryActionCarriesAUniqueID(t *testing.T) {
	// R2 needs a failure to name exactly which action did not happen. Two
	// actions sharing an id, or an id of zero on everything, makes
	// EvActionFailed ambiguous — and the machine's response to it wrong for
	// every action but one.
	m := newMachine(t, testParams())
	seen := map[ActionID]string{}
	steps := []Event{
		Simple(EvStart),
		TimerFired(TimerRetransmit),
		Simple(EvLinkDown),
		Simple(EvLinkUp),
		Simple(EvStop),
	}
	for i, ev := range steps {
		_, acts := m.Step(at(int64(i+1)), uint64(i), ev)
		for _, a := range acts {
			if prev, dup := seen[a.ID]; dup {
				t.Fatalf("action id %s reused: %q then %q", a.ID, prev, a.String())
			}
			seen[a.ID] = a.String()
		}
	}
	if len(seen) < 5 {
		t.Fatalf("only %d stamped actions were produced; this test measured almost nothing", len(seen))
	}
}
