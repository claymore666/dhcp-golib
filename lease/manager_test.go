package lease

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/claymore666/dhcplease/proto"
	"github.com/claymore666/dhcplease/wire"
)

var testCHAddr = []byte{0x02, 0x42, 0xAC, 0x11, 0x00, 0x02}

func testParams() proto.Params {
	p := proto.DefaultParams(testCHAddr)
	// Desync off: the delay is ring 1's and is tested there. Leaving it on
	// would make every manager test start by firing a timer that has nothing
	// to do with what it asserts.
	p.DesyncMin, p.DesyncMax = 0, 0
	return p
}

// journalRecorder is a Journal that keeps everything, so a test can replay it.
//
// Locked, because the manager appends from its own goroutine while the test
// reads. An unlocked recorder is a data race, and -race reports it against
// whichever test happens to be running.
type journalRecorder struct {
	mu      sync.Mutex
	entries []proto.JournalEntry
}

func (j *journalRecorder) Append(e proto.JournalEntry) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.entries = append(j.entries, e)
}

func (j *journalRecorder) Entries() []proto.JournalEntry {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]proto.JournalEntry(nil), j.entries...)
}

// packetRecorder is a PacketRing that also announces what it recorded.
//
// The announcement is the barrier the inbound tests need, and it is not a
// convenience. The manager selects over TWO channels — inbound packets and
// timer fires — so "push a packet, then fire a timer" does not order the two:
// the manager may take the timer first. A test that ordered them that way
// passes alone and fails in a suite, which is exactly how this one was found.
type packetRecorder struct {
	mu       sync.Mutex
	packets  []CapturedPacket
	recorded chan CapturedPacket
}

func newPacketRecorder() *packetRecorder {
	return &packetRecorder{recorded: make(chan CapturedPacket, 64)}
}

func (p *packetRecorder) Record(c CapturedPacket) {
	p.mu.Lock()
	p.packets = append(p.packets, c)
	p.mu.Unlock()
	select {
	case p.recorded <- c:
	default:
	}
}

func (p *packetRecorder) Packets() []CapturedPacket {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]CapturedPacket(nil), p.packets...)
}

// waitRecorded blocks until a captured packet satisfies want.
func (p *packetRecorder) waitRecorded(t *testing.T, what string, want func(CapturedPacket) bool) {
	t.Helper()
	for c := range p.recorded {
		if want(c) {
			return
		}
	}
	t.Fatalf("the packet ring closed before %s was recorded", what)
}

type rig struct {
	mgr     *Manager
	server  *fakeServer
	fault   *FaultTransport
	timers  *fakeTimers
	clock   *fakeClock
	journal *journalRecorder
	packets *packetRecorder
	cancel  context.CancelFunc
	done    chan error

	// Run's result is read exactly once, through wait, and cached. A test
	// that stops the manager itself AND a Cleanup that stops it again is the
	// ordinary case, and a second receive on a one-shot channel is a deadlock
	// that presents as a whole-package timeout with no failing assertion.
	waitOnce sync.Once
	runErr   error
}

// wait returns Run's result, reading it from the channel at most once.
func (r *rig) wait() error {
	r.waitOnce.Do(func() { r.runErr = <-r.done })
	return r.runErr
}

// stop cancels the context and waits for Run to return.
func (r *rig) stop() error {
	r.cancel()
	return r.wait()
}

// newRig assembles a manager over the fakes and starts Run.
func newRig(t *testing.T, p proto.Params, behaviour serverBehaviour, plan Fault) *rig {
	t.Helper()

	srv := newFakeServer(behaviour)
	// The fault transport is ALWAYS in the path, even with an empty plan.
	// R2 says the failure path is not a special mode, and a wrapper only
	// present in the fault tests is a wrapper the happy-path tests never
	// exercise.
	ft := NewFaultTransport(srv, plan)

	r := &rig{
		server:  srv,
		fault:   ft,
		timers:  newFakeTimers(),
		clock:   newFakeClock(),
		journal: &journalRecorder{},
		packets: newPacketRecorder(),
		done:    make(chan error, 1),
	}

	mgr, err := NewManager(Config{
		Params:      p,
		Transport:   ft,
		Clock:       r.clock,
		Timers:      r.timers,
		Entropy:     &fakeEntropy{},
		Journal:     r.journal,
		Packets:     r.packets,
		EventBuffer: 16,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	r.mgr = mgr

	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go func() { r.done <- mgr.Run(ctx) }()

	t.Cleanup(func() {
		_ = r.stop()
		_ = ft.Close()
		_ = r.timers.Close()
	})
	return r
}

// nextEvent reads one outward event. It blocks on the channel, which is the
// barrier the whole suite is built on — no duration appears anywhere.
func (r *rig) nextEvent(t *testing.T) Event {
	t.Helper()
	e, ok := <-r.mgr.Events()
	if !ok {
		t.Fatal("the event channel closed before the expected event arrived")
	}
	return e
}

// ------------------------------------------------------------ acquisition --

func TestManagerAcquires(t *testing.T) {
	r := newRig(t, testParams(), answerNormally, Fault{})

	ev := r.nextEvent(t)
	if ev.Kind != Acquired {
		t.Fatalf("first event is %s, want acquired", ev)
	}
	if ev.Lease.Addr.String() != testYIAddr+"/24" {
		t.Fatalf("addr = %s", ev.Lease.Addr)
	}
	if ev.Lease.Gateway.String() != testServerID {
		t.Fatalf("gateway = %s", ev.Lease.Gateway)
	}
	if ev.Lease.Domain != "example.test" || ev.Lease.MTU != 1500 {
		t.Fatalf("domain/mtu = %q/%d", ev.Lease.Domain, ev.Lease.MTU)
	}

	// The outward lease reports WALL-CLOCK deadlines: a monotonic reading
	// means nothing to a caller and nothing to a file.
	if ev.Lease.Expire.IsZero() {
		t.Fatal("expiry is zero for a finite lease")
	}
	if !ev.Lease.Expire.After(ev.Lease.Acquired) {
		t.Fatalf("expiry %s is not after acquisition %s", ev.Lease.Expire, ev.Lease.Acquired)
	}
	if got := ev.Lease.Expire.Sub(ev.Lease.Acquired); got.Seconds() != 3600 {
		t.Fatalf("lease runs for %s, want 3600s", got)
	}
	// T1 and T2 defaults, converted for the caller (RFC 2131 section 4.4.5).
	if got := ev.Lease.Renew.Sub(ev.Lease.Acquired); got.Seconds() != 1800 {
		t.Fatalf("renew at +%s, want +1800s", got)
	}
	if got := ev.Lease.Rebind.Sub(ev.Lease.Acquired); got.Seconds() != 3150 {
		t.Fatalf("rebind at +%s, want +3150s", got)
	}

	// Two messages out, in order.
	sent := r.server.sentMessages()
	if len(sent) != 2 {
		t.Fatalf("sent %d messages, want DISCOVER then REQUEST", len(sent))
	}
	if got, _ := sent[0].Type(); got != wire.MsgDiscover {
		t.Fatalf("first message is %s", got)
	}
	if got, _ := sent[1].Type(); got != wire.MsgRequest {
		t.Fatalf("second message is %s", got)
	}

	// Four packets captured: two out, two in (G1).
	if n := len(r.packets.Packets()); n != 4 {
		t.Fatalf("captured %d packets, want 4", n)
	}
	dirs := ""
	for _, p := range r.packets.Packets() {
		dirs += p.Dir.String()[:1]
		if len(p.Raw) == 0 {
			t.Fatalf("a captured packet has no raw bytes: %+v", p)
		}
		if p.At.IsZero() {
			t.Fatal("a captured packet has no timestamp")
		}
	}
	if dirs != "oioi" {
		t.Fatalf("packet directions %q, want out,in,out,in", dirs)
	}

	if got, ok := r.mgr.Lease(); !ok || got.Addr != ev.Lease.Addr {
		t.Fatalf("Lease() = %v/%v, want the acquired lease", got, ok)
	}
	s := r.mgr.Stats()
	if s.Sent != 2 || s.Received != 2 || s.LeasesAcquired != 1 {
		t.Fatalf("stats = %+v", s)
	}
	if s.DecodeFailures != 0 || s.SendFailures != 0 {
		t.Fatalf("clean run reports failures: %+v", s)
	}
}

// TestManagerJournalReplays is done-condition (b) through the REAL manager:
// the journal it produced, replayed offline through ring 1, yields the same
// lease. The ring-3 test does this again with a real server's packets.
func TestManagerJournalReplays(t *testing.T) {
	r := newRig(t, testParams(), answerNormally, Fault{})
	ev := r.nextEvent(t)
	if ev.Kind != Acquired {
		t.Fatalf("first event is %s", ev)
	}

	// Stop the manager so the journal is complete and not being appended to
	// while it is read.
	_ = r.stop()

	entries := r.mgr.Journal()
	if len(entries) == 0 {
		t.Fatal("the journal is empty")
	}
	res, err := proto.Replay(testParams(), entries)
	if err != nil {
		t.Fatalf("the manager's own journal does not replay: %v", err)
	}
	if res.Steps != len(entries) {
		t.Fatalf("replayed %d of %d entries", res.Steps, len(entries))
	}
	// The run ended with a Stop, so the replayed machine ends stopped and
	// holding nothing — the lease is checked at the entry that acquired it.
	if res.State != proto.StateStopped {
		t.Fatalf("replay ended in %s, want STOPPED", res.State)
	}

	// Replay up to the ACK instead, and the lease must match what the caller
	// was told. This is the assertion that matters: a replay that only
	// reproduced the final state would agree with a machine that never leased.
	var upto []proto.JournalEntry
	for _, e := range entries {
		upto = append(upto, e)
		if e.To == proto.StateBound {
			break
		}
	}
	res, err = proto.Replay(testParams(), upto)
	if err != nil {
		t.Fatalf("replay to BOUND: %v", err)
	}
	if !res.Held {
		t.Fatal("replay to BOUND produced no lease")
	}
	if res.Lease.Addr.String() != testYIAddr+"/24" {
		t.Fatalf("replayed lease %s, want %s/24", res.Lease.Addr, testYIAddr)
	}
}

func TestManagerReportsExpiry(t *testing.T) {
	// RFC 2131 section 4.4.5: on expiry the client must stop using the
	// address. The caller learns that from a Lost event, and it must arrive
	// before the client's next DISCOVER goes out.
	r := newRig(t, testParams(), answerNormally, Fault{})
	if ev := r.nextEvent(t); ev.Kind != Acquired {
		t.Fatalf("first event is %s", ev)
	}

	d, ok := r.timers.armedAt(proto.TimerExpire)
	if !ok {
		t.Fatal("no expiry timer armed after acquisition")
	}
	if d.Seconds() != 3600 {
		t.Fatalf("expiry armed for %s, want ~3600s (the clock does not move in this rig)", d)
	}

	r.clock.advance(3600 * proto.Second)
	r.timers.fire(proto.TimerExpire)

	ev := r.nextEvent(t)
	if ev.Kind != Lost {
		t.Fatalf("event after expiry is %s, want lost", ev)
	}
	if ev.Reason != proto.ReasonExpired {
		t.Fatalf("reason = %s, want expired", ev.Reason)
	}

	// And it re-acquires: the second acquisition is the proof that expiry is
	// a restart and not a dead end.
	ev = r.nextEvent(t)
	if ev.Kind != Acquired {
		t.Fatalf("event after the loss is %s, want a fresh acquisition", ev)
	}
	if r.mgr.Stats().LeasesLost != 1 {
		t.Fatalf("stats = %+v", r.mgr.Stats())
	}
}

func TestManagerReportsNak(t *testing.T) {
	nakOnce := func(req *wire.Message, n int) []*wire.Message {
		t, _ := req.Type()
		switch {
		case t == wire.MsgDiscover:
			return []*wire.Message{offerFor(req)}
		case t == wire.MsgRequest && n == 2:
			return []*wire.Message{nakFor(req)}
		case t == wire.MsgRequest:
			return []*wire.Message{ackFor(req, 3600)}
		}
		return nil
	}
	r := newRig(t, testParams(), nakOnce, Fault{})

	ev := r.nextEvent(t)
	if ev.Kind != Failed || ev.Reason != proto.ReasonNak {
		t.Fatalf("first event is %s, want a nak failure", ev)
	}
	if ev.Note == "" {
		t.Fatal("the NAK note is empty; the server's text is the only diagnosis the user gets")
	}
	// RFC 2131 section 3.1(5): the client restarts. It must reach a lease.
	if ev = r.nextEvent(t); ev.Kind != Acquired {
		t.Fatalf("after the NAK restart: %s, want acquired", ev)
	}
	if r.mgr.Stats().AcquireFailures != 1 {
		t.Fatalf("stats = %+v", r.mgr.Stats())
	}
}

// ---------------------------------------------------------------- R2 tests --

func TestFailedSendIsRetriedNotCounted(t *testing.T) {
	// R2 end to end: the first send fails at the transport, the machine is
	// told, and the retransmit timer is re-armed WITHOUT spending a
	// retransmission. Firing that timer then gets the DISCOVER out.
	r := newRig(t, testParams(), answerNormally, Fault{FailSends: []int{1}})

	if !r.timers.waitArmed(proto.TimerRetransmit) {
		t.Fatal("the retransmit timer was never re-armed")
	}
	r.timers.fire(proto.TimerRetransmit)

	ev := r.nextEvent(t)
	if ev.Kind != Acquired {
		t.Fatalf("event = %s, want the retry to acquire", ev)
	}

	sends, _ := r.fault.Counts()
	if sends != 3 {
		t.Fatalf("the transport saw %d sends, want 3 (one failed DISCOVER, one retry, one REQUEST)", sends)
	}
	s := r.mgr.Stats()
	if s.SendFailures != 1 {
		t.Fatalf("SendFailures = %d, want exactly the one injected", s.SendFailures)
	}
	if s.ActionsFailedFed != 1 {
		t.Fatalf("ActionsFailedFed = %d, want the failure to have re-entered the machine", s.ActionsFailedFed)
	}
}

func TestBrokenTransportIsReported(t *testing.T) {
	// Every send fails. Without a bound the machine would sit re-arming a
	// timer forever and look exactly like one waiting for a slow server.
	p := testParams()
	p.MaxSendFailures = 3
	r := newRig(t, p, answerNormally, Fault{FailEvery: 1})

	// The first send failed during Start. Drive the re-arm/fire cycle until
	// the machine gives up; the event channel is the barrier.
	go func() {
		for i := 0; i < p.MaxSendFailures+2; i++ {
			if !r.timers.waitArmed(proto.TimerRetransmit) {
				return
			}
			r.timers.fire(proto.TimerRetransmit)
		}
	}()

	ev := r.nextEvent(t)
	if ev.Kind != Failed {
		t.Fatalf("event = %s, want a failure", ev)
	}
	if ev.Reason != proto.ReasonTransport {
		t.Fatalf("reason = %s, want transport", ev.Reason)
	}
	if _, held := r.mgr.Lease(); held {
		t.Fatal("a client that never sent anything reports holding a lease")
	}
}

func TestDuplicateReplyProducesOneLease(t *testing.T) {
	// A duplicated ACK — a retransmitting server, or a link that mirrors
	// frames — must not produce two Acquired events. The second one would make
	// the plugin reconfigure an interface that did not change.
	r := newRig(t, testParams(), answerNormally, Fault{DuplicateInbound: []int{2}})

	ev := r.nextEvent(t)
	if ev.Kind != Acquired {
		t.Fatalf("first event is %s", ev)
	}

	// Force a second, independent barrier: expire the lease. If the duplicate
	// ACK had produced an event, it would arrive before this one.
	r.clock.advance(3600 * proto.Second)
	r.timers.fire(proto.TimerExpire)
	if ev = r.nextEvent(t); ev.Kind != Lost {
		t.Fatalf("second event is %s, want the expiry — a duplicate ACK produced an extra event", ev)
	}

	_, inbounds := r.fault.Counts()
	if inbounds < 2 {
		t.Fatalf("the fault plan named inbound 2 but only %d arrived; nothing was injected", inbounds)
	}
	if got := r.mgr.Stats().LeasesAcquired; got != 1 {
		t.Fatalf("LeasesAcquired = %d after a duplicated ACK, want 1", got)
	}
}

func TestCorruptReplyIsCountedAndDiscarded(t *testing.T) {
	// CorruptInbound flips the first payload byte, which is 'op'. The message
	// still DECODES and then fails ring 1's BOOTREPLY check — a
	// hostile-but-well-formed input rather than a codec error.
	r := newRig(t, testParams(), answerNormally, Fault{CorruptInbound: []int{1}})

	// The corrupted OFFER is discarded, so nothing moves until the retransmit
	// timer fires and a second DISCOVER goes out.
	if !r.timers.waitArmed(proto.TimerRetransmit) {
		t.Fatal("the retransmit timer was never re-armed")
	}
	r.timers.fire(proto.TimerRetransmit)

	ev := r.nextEvent(t)
	if ev.Kind != Acquired {
		t.Fatalf("event = %s, want the retry to acquire", ev)
	}
	if got := r.mgr.Stats().Received; got < 3 {
		t.Fatalf("Received = %d, want the corrupted packet counted too", got)
	}
	// It reached the packet ring, which is the point of capturing separately
	// from the journal: a packet ring 1 refused leaves no journal entry.
	if len(r.packets.Packets()) < 5 {
		t.Fatalf("captured %d packets, want the discarded one among them", len(r.packets.Packets()))
	}
}

func TestUndecodablePacketIsCountedNotFatal(t *testing.T) {
	r := newRig(t, testParams(), answerNormally, Fault{})
	if ev := r.nextEvent(t); ev.Kind != Acquired {
		t.Fatalf("first event is %s", ev)
	}

	// Garbage on the wire. A raw socket sees everything on the segment.
	go r.server.injectRaw([]byte{1, 2, 3, 4})
	r.packets.waitRecorded(t, "the undecodable packet", func(c CapturedPacket) bool {
		return c.DecodeErr != nil && len(c.Raw) == 4
	})

	// And the loop is still alive afterwards: expire the lease and read the
	// Lost. Garbage on the wire must not stall or kill the manager.
	r.clock.advance(3600 * proto.Second)
	r.timers.fire(proto.TimerExpire)
	if ev := r.nextEvent(t); ev.Kind != Lost {
		t.Fatalf("event = %s, want the expiry after garbage was ignored", ev)
	}
	if got := r.mgr.Stats().DecodeFailures; got != 1 {
		t.Fatalf("DecodeFailures = %d, want 1", got)
	}
	// The undecodable bytes are in the packet ring WITH the decode error, which
	// is the only place the evidence exists.
	found := false
	for _, p := range r.packets.Packets() {
		if p.DecodeErr != nil && p.Msg == nil && len(p.Raw) == 4 {
			found = true
		}
	}
	if !found {
		t.Fatal("the undecodable packet was not captured with its decode error")
	}
}

func TestTransportErrorIsCounted(t *testing.T) {
	r := newRig(t, testParams(), answerNormally, Fault{})
	if ev := r.nextEvent(t); ev.Kind != Acquired {
		t.Fatalf("first event is %s", ev)
	}

	go r.server.injectErr(errors.New("ENETDOWN"))
	r.packets.waitRecorded(t, "the transport error", func(c CapturedPacket) bool {
		return c.DecodeErr != nil && c.Raw == nil
	})

	r.clock.advance(3600 * proto.Second)
	r.timers.fire(proto.TimerExpire)
	if ev := r.nextEvent(t); ev.Kind != Lost {
		t.Fatalf("event = %s, want the expiry", ev)
	}
	if got := r.mgr.Stats().TransportErrors; got != 1 {
		t.Fatalf("TransportErrors = %d, want 1", got)
	}
}

// ------------------------------------------------------------- lifecycle --

func TestCancelReportsTheLeaseLostAndClosesTheStream(t *testing.T) {
	// A caller ranging over Events must see the final Lost and then a clean
	// close. A channel that simply stops leaves the caller holding an address
	// nobody is maintaining.
	r := newRig(t, testParams(), answerNormally, Fault{})
	if ev := r.nextEvent(t); ev.Kind != Acquired {
		t.Fatalf("first event is %s", ev)
	}

	if err := r.stop(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v, want context.Canceled", err)
	}

	ev, ok := <-r.mgr.Events()
	if !ok {
		t.Fatal("the event channel closed without reporting the lease lost")
	}
	if ev.Kind != Lost || ev.Reason != proto.ReasonStopped {
		t.Fatalf("final event is %s, want lost/stopped", ev)
	}
	if _, ok := <-r.mgr.Events(); ok {
		t.Fatal("the event channel did not close after the final event")
	}
}

func TestTransportClosingIsNotACleanStop(t *testing.T) {
	// Something took the socket away. That is an error, not an orderly exit:
	// reporting nil would let a supervisor treat a vanished interface as a
	// completed job.
	r := newRig(t, testParams(), answerNormally, Fault{})
	if ev := r.nextEvent(t); ev.Kind != Acquired {
		t.Fatalf("first event is %s", ev)
	}
	_ = r.fault.Close()

	err := r.wait()
	if err == nil {
		t.Fatal("Run returned nil after the transport closed under it")
	}
	if errors.Is(err, context.Canceled) {
		t.Fatalf("Run reported %v, want a transport error", err)
	}
}

func TestNewManagerRefusesAMissingPort(t *testing.T) {
	// Every port is required, and the refusal names which one. A nil port
	// would otherwise surface as a nil dereference inside Run, on a goroutine,
	// with no indication of what was not wired.
	base := func() Config {
		return Config{
			Params:    testParams(),
			Transport: newFakeServer(answerNormally),
			Clock:     newFakeClock(),
			Timers:    newFakeTimers(),
			Entropy:   &fakeEntropy{},
		}
	}
	cases := []struct {
		name string
		mut  func(*Config)
		want error
	}{
		{"transport", func(c *Config) { c.Transport = nil }, ErrNoTransport},
		{"clock", func(c *Config) { c.Clock = nil }, ErrNoClock},
		{"timers", func(c *Config) { c.Timers = nil }, ErrNoTimers},
		{"entropy", func(c *Config) { c.Entropy = nil }, ErrNoEntropy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.mut(&cfg)
			if _, err := NewManager(cfg); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}

	// The preservation control: the same config with nothing removed must
	// build. Four refusals prove nothing if the constructor refuses always.
	if _, err := NewManager(base()); err != nil {
		t.Fatalf("a complete config was refused: %v", err)
	}
}

func TestNilJournalAndPacketsAreDiscarding(t *testing.T) {
	// Both are optional and must default to a discarding implementation, not
	// to a nil dereference on the first step.
	cfg := Config{
		Params:    testParams(),
		Transport: newFakeServer(answerNormally),
		Clock:     newFakeClock(),
		Timers:    newFakeTimers(),
		Entropy:   &fakeEntropy{},
	}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if got := mgr.Journal(); got != nil {
		t.Fatalf("Journal() = %v, want nil from the discarding default", got)
	}
	if got := mgr.Packets(); got != nil {
		t.Fatalf("Packets() = %v, want nil from the discarding default", got)
	}
}
