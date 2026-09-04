//go:build linux

package runtime

import (
	"context"
	"net"
	"net/netip"
	"os"
	goruntime "runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/claymore666/dhcp-golib/lease"
	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

// M6's outside evidence: RFC 5227 against a real dnsmasq, with a real squatter
// on the other end of a real veth pair.
//
// WHAT MAKES THIS PROOF RATHER THAN A DEMONSTRATION. Every assertion below is
// on something the client under test did not write:
//
//   - dnsmasq's own log — the DHCPDECLINE line, and the DHCPOFFER of a
//     DIFFERENT address that follows it. The client cannot make a server it
//     does not control write those.
//   - a SECOND packet socket, on the server's end of the wire, which sees the
//     Probes as frames. Its record of them is not the library's packet ring;
//     it is what an observer with tcpdump would have seen, built from the same
//     AF_PACKET the kernel offers everyone. That is where the all-zero sender
//     IP is checked, and where the acquisition delay is timed.
//
// The library's own counters appear only as a cross-check, never as the
// assertion.
//
// The three runs the milestone asks for are four tests, because the squatter
// case is run in BOTH conflict modes (D23) and the modes differ in exactly
// what the caller is told and when:
//
//	TestASquatterInTheProbeWindowMakesAWaitingClientDecline   section 2.1, wait
//	TestASquatterInTheProbeWindowMakesAnAsyncClientDecline    section 2.1, async
//	TestASquatterAfterBoundTakesSection24sPath                section 2.4
//	TestTheDelayBeforeAnAcquisitionIsRFC5227sArithmetic       no squatter

// squatterMode is what the fixture on the server's end of the wire does with
// what it hears.
type squatterMode int

const (
	// squatterObserve records every ARP frame and answers nothing. It is the
	// wire observer for the timing run, and it is what makes "no squatter"
	// a measured claim rather than an absence.
	squatterObserve squatterMode = iota
	// squatterDefendFirstProbed answers the first address it sees probed, and
	// only that one. RFC 5227 section 2.1.1's first conflict rule is about the
	// SENDER IP of the answer, so an ARP Reply carrying the probed address is
	// the minimum a squatter has to emit to be seen.
	//
	// ONLY THE FIRST. After the DECLINE the server offers a different address
	// and the client probes that one; a squatter that answered everything
	// would loop the client forever and the test would measure a livelock
	// instead of a recovery.
	squatterDefendFirstProbed
	// squatterAnnounceOnCue sends one gratuitous ARP for an address it is
	// handed, after the client already holds it: section 2.4's predicate,
	// which is about a packet whose sender IP is ours and whose sender
	// hardware address is not.
	squatterAnnounceOnCue
)

// squatter is another host on the link, built out of the same ARP socket the
// client uses.
//
// It runs in the test process because the namespace has one process in it, and
// that costs nothing here: it holds its own socket, on its own interface, with
// its own hardware address. The client has no reference to it and cannot tell
// it from a machine that was plugged in.
type squatter struct {
	sock *ARPSocket
	hw   net.HardwareAddr

	mu       sync.Mutex
	seen     []squatterSighting
	defended netip.Addr

	announce chan netip.Addr
	// heard is pinged after every frame is recorded, so a test waits on a
	// channel instead of spinning a core: this file has no sleep in it and a
	// bare polling loop is the shape that invites one.
	heard   chan struct{}
	done    chan struct{}
	stopped sync.Once
}

// squatterSighting is one frame, with the wall-clock time it was read off the
// wire. The time is the point: the timing run's arithmetic is over these.
type squatterSighting struct {
	at time.Time
	p  *wire.ARPPacket
}

func newSquatter(t *testing.T, ifName string, mode squatterMode) *squatter {
	t.Helper()
	sock, err := NewARPSocket(ifName)
	if err != nil {
		t.Fatalf("the squatter could not open an ARP socket on %s: %v", ifName, err)
	}
	s := &squatter{
		sock:     sock,
		hw:       sock.HardwareAddr(),
		announce: make(chan netip.Addr, 1),
		heard:    make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
	go s.run(t, mode)
	t.Cleanup(s.stop)
	return s
}

func (s *squatter) stop() {
	s.stopped.Do(func() {
		close(s.done)
		_ = s.sock.Close()
	})
}

func (s *squatter) run(t *testing.T, mode squatterMode) {
	in := s.sock.Received()
	for {
		select {
		case <-s.done:
			return
		case addr := <-s.announce:
			s.send(&wire.ARPPacket{
				Op:       wire.ARPRequest,
				SenderHW: s.hw,
				SenderIP: addr,
				TargetIP: addr,
			})
		case f, ok := <-in:
			if !ok {
				return
			}
			if f.Err != nil {
				return
			}
			p, err := wire.DecodeARP(f.Frame)
			if err != nil {
				continue
			}
			at := time.Now()
			// Frames the squatter itself sent come back on its own socket —
			// AF_PACKET echoes this host's outgoing frames — and recording
			// them would put the squatter's own answer into the evidence it
			// is providing about the client.
			if hwEqual(p.SenderHW, s.hw) {
				continue
			}
			s.mu.Lock()
			s.seen = append(s.seen, squatterSighting{at: at, p: p})
			s.mu.Unlock()
			select {
			case s.heard <- struct{}{}:
			default:
			}

			if mode != squatterDefendFirstProbed || !p.IsProbe() {
				continue
			}
			s.mu.Lock()
			if !s.defended.IsValid() {
				s.defended = p.TargetIP
				t.Logf("the squatter is taking %s", s.defended)
			}
			mine := s.defended == p.TargetIP
			addr := s.defended
			s.mu.Unlock()
			if mine {
				s.send(&wire.ARPPacket{
					Op:       wire.ARPReply,
					SenderHW: s.hw,
					SenderIP: addr,
					TargetHW: p.SenderHW,
					TargetIP: addr,
				})
			}
		}
	}
}

func (s *squatter) send(p *wire.ARPPacket) {
	raw, err := wire.EncodeARP(p)
	if err != nil {
		panic("runtime: the squatter built an unencodable ARP packet: " + err.Error())
	}
	_ = s.sock.Send(raw)
}

func (s *squatter) sightings() []squatterSighting {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]squatterSighting(nil), s.seen...)
}

// isProbeFor and isAnnouncementFor are the two frame classes this file waits
// on and counts. They are spelled once so that a wait and the count taken
// afterwards cannot describe different sets of frames.
//
// A Probe is RFC 5227 section 2.1.1's: an ARP Request with an all-zero sender
// IP. An Announcement is section 2.3's: an ARP Request with sender and target
// IP both the address being claimed.
func isProbeFor(addr netip.Addr) func(*wire.ARPPacket) bool {
	return func(p *wire.ARPPacket) bool { return p.IsProbe() && p.TargetIP == addr }
}

func isAnnouncementFor(addr netip.Addr) func(*wire.ARPPacket) bool {
	return func(p *wire.ARPPacket) bool {
		return p.Op == wire.ARPRequest && p.SenderIP == addr && p.TargetIP == addr
	}
}

// matching returns, in the order they crossed the wire, the frames the
// squatter has read so far that pred accepts. It does not wait: every caller
// below first waits on a LATER frame, so that what it then counts is complete.
func (s *squatter) matching(pred func(*wire.ARPPacket) bool) []squatterSighting {
	var out []squatterSighting
	for _, g := range s.sightings() {
		if pred(g.p) {
			out = append(out, g)
		}
	}
	return out
}

// waitForSighting blocks until pred has matched a frame the squatter read.
//
// It carries no duration of its own: a frame that never comes hangs the test
// until go test's own timeout, which says more than a deadline chosen here.
func (s *squatter) waitForSighting(pred func(*wire.ARPPacket) bool) squatterSighting {
	for {
		for _, g := range s.sightings() {
			if pred(g.p) {
				return g
			}
		}
		<-s.heard
	}
}

// waitForCount blocks until pred has matched at least n of the frames read.
func (s *squatter) waitForCount(pred func(*wire.ARPPacket) bool, n int) []squatterSighting {
	for {
		if out := s.matching(pred); len(out) >= n {
			return out
		}
		<-s.heard
	}
}

func hwEqual(a, b []byte) bool {
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

// conflictFixture is the wiring every test in this file starts from.
type conflictFixture struct {
	srv       *dnsmasqServer
	client    *Client
	clientMAC string
	cancel    context.CancelFunc
	runErr    chan error
}

// briskACD is RFC 5227 section 1.1's table with its DURATIONS scaled down and
// its COUNTS untouched.
//
// The three conflict runs use it and the timing run does not. What those three
// are about is a verdict — a real squatter on a real wire makes a real dnsmasq
// log a DHCPDECLINE and hand out a different address — and that verdict does
// not depend on how long the gaps were. Paying the RFC's own four to seven
// seconds three more times would add twenty seconds to a suite with a
// sixty-second ceiling and measure nothing the fourth test does not measure
// properly.
//
// PROBE_NUM and ANNOUNCE_NUM keep the RFC's values, because those are counts
// of packets and every one of them is asserted on the wire. The durations are
// pinned at their RFC values in proto's TestACDConstantsAreTheRFCValues and
// MEASURED against a real wire in
// TestTheDelayBeforeAnAcquisitionIsRFC5227sArithmetic; nothing here can reach
// either.
func briskACD() proto.ACDParams {
	d := proto.DefaultACDParams()
	d.ProbeWait = 50 * proto.Millisecond
	d.ProbeMin = 50 * proto.Millisecond
	d.ProbeMax = 100 * proto.Millisecond
	d.AnnounceWait = 100 * proto.Millisecond
	d.AnnounceInterval = 100 * proto.Millisecond
	return d
}

// newConflictClient wires the veth pair, starts dnsmasq and BUILDS a client
// with conflict detection in the given mode and the given ACD table. It does
// not run it: conflictFixture.start does, and takes the observer.
func newConflictClient(t *testing.T, mode proto.ConflictMode, acd proto.ACDParams, hostname string) *conflictFixture {
	t.Helper()

	mustRun(t, "ip", "link", "add", testClientIf, "type", "veth", "peer", "name", testServerIf)
	mustRun(t, "ip", "addr", "add", testServerIP+"/24", "dev", testServerIf)
	mustRun(t, "ip", "link", "set", testServerIf, "up")
	mustRun(t, "ip", "link", "set", testClientIf, "up")

	srv := startDnsmasq(t)

	iface, err := net.InterfaceByName(testClientIf)
	if err != nil {
		t.Fatalf("InterfaceByName(%s): %v", testClientIf, err)
	}

	params := proto.DefaultParams(iface.HardwareAddr)
	params.DesyncMin, params.DesyncMax = 0, 0
	// The RFC minimum is ten seconds and this fixture waits one, on the same
	// terms TestDeclineAndReleaseReachRealDnsmasq took it: the subject here is
	// what a real server does with a real DECLINE, and ten seconds of nothing
	// in the middle measures the timer instead. proto's
	// TestRestartDelayMeetsTheRFCMinimum pins the default at the RFC floor,
	// and this line cannot reach it.
	params.RestartDelay = 1 * proto.Second
	params.Conflict = mode
	params.ACD = acd
	params.Hostname = hostname

	c, err := NewClient(ClientConfig{Interface: testClientIf, Params: params, EventBuffer: 8})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return &conflictFixture{
		srv:       srv,
		client:    c,
		clientMAC: iface.HardwareAddr.String(),
	}
}

// start runs the client, and takes the observer that must already be watching
// the wire.
//
// The squatter is a parameter so that arming the observer LATE is a compile
// error rather than a rare red. The first ARP Probe leaves within
// U(0, PROBE_WAIT) of the DHCPACK — 50ms under briskACD — so an observer whose
// socket is bound after the client has started can miss it, and a missing
// probe 1 reads exactly like a client that sent PROBE_NUM-1 probes.
//
// MEASURED 2026-09-04, with the client started first: "the wire carried 2
// probe(s) for 192.168.99.129, want PROBE_NUM = 3", the two frames seen being
// probes 2 and 3 — their gaps, 1.477s and 2.148s, are PROBE_MIN..PROBE_MAX
// and ANNOUNCE_WAIT, not two inter-probe gaps.
func (f *conflictFixture) start(t *testing.T, sq *squatter) {
	t.Helper()
	if sq == nil {
		t.Fatal("the observer must be on the wire before the client starts")
	}
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- f.client.Run(ctx) }()
	f.cancel, f.runErr = cancel, runErr
	t.Cleanup(func() {
		cancel()
		<-runErr
	})
}

// offers returns the addresses dnsmasq has logged a DHCPOFFER for, in order.
func (f *conflictFixture) offers() []string {
	var out []string
	for _, l := range f.srv.lines() {
		if a, ok := addrInLog(l, "DHCPOFFER("+f.srv.iface+")"); ok {
			out = append(out, a)
		}
	}
	return out
}

// addrInLog pulls the address out of a dnsmasq log line of the shape
// "<prefix> <address> <mac> ...".
func addrInLog(line, prefix string) (string, bool) {
	i := strings.Index(line, prefix)
	if i < 0 {
		return "", false
	}
	fields := strings.Fields(line[i+len(prefix):])
	if len(fields) == 0 {
		return "", false
	}
	if net.ParseIP(fields[0]).To4() == nil {
		return "", false
	}
	return fields[0], true
}

// quote renders the log lines this milestone reports verbatim, so the excerpt
// in the handover is the test's own output and not a transcription.
func (f *conflictFixture) quote(t *testing.T, what string) {
	t.Helper()
	// The transaction lines only. dnsmasq's --log-dhcp prose ("available DHCP
	// range", "requested options", "sent size") is what makes this log
	// unreadable in a report, and every one of those lines contains the string
	// DHCP.
	var keep []string
	for _, l := range f.srv.lines() {
		for _, kind := range []string{
			"DHCPDISCOVER(", "DHCPOFFER(", "DHCPREQUEST(", "DHCPACK(",
			"DHCPNAK(", "DHCPDECLINE(", "DHCPRELEASE(", "DHCPINFORM(",
		} {
			if strings.Contains(l, kind) {
				keep = append(keep, l)
				break
			}
		}
	}
	t.Logf("dnsmasq log excerpt (%s):\n%s", what, strings.Join(keep, "\n"))
}

// ------------------------------------------- section 2.1: the probe window --

func TestASquatterInTheProbeWindowMakesAWaitingClientDecline(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		squatterInProbeWindow(t, proto.ConflictWait)
		return
	}
	reexecInNamespaces(t)
}

func TestASquatterInTheProbeWindowMakesAnAsyncClientDecline(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		squatterInProbeWindow(t, proto.ConflictAsync)
		return
	}
	reexecInNamespaces(t)
}

// squatterInProbeWindow is the milestone's first and second runs.
//
// A second host on the link already holds the address dnsmasq offers, and says
// so when the client probes for it. RFC 2131 section 4.4.1: "If the client
// detects that the address is already in use (e.g., through the use of ARP),
// the client MUST send a DHCPDECLINE message to the server and restarts the
// configuration process."
//
// THE TWO MODES DIFFER IN ONE OBSERVABLE AND ONLY ONE. In ConflictWait no
// Acquired for the squatted address ever reaches the caller, because section
// 2.1's check has not passed; in ConflictAsync the caller is told Acquired
// first and Lost{ReasonConflict} afterwards. dnsmasq's log is identical either
// way, which is the point: the mode is a promise to the CALLER about when it
// may use the address, not a change to the protocol on the wire.
func squatterInProbeWindow(t *testing.T, mode proto.ConflictMode) {
	f := newConflictClient(t, mode, briskACD(), "m6-client")
	sq := newSquatter(t, testServerIf, squatterDefendFirstProbed)
	f.start(t, sq)

	// The first address the server hands out. Read from the SERVER's log, not
	// from the client: the whole question is whether the client gave back the
	// address the server thinks it gave.
	f.srv.waitCount(t, "DHCPACK("+f.srv.iface+")", 1, "the first acquisition never reached DHCPACK")
	first := f.offers()
	if len(first) == 0 {
		t.Fatalf("dnsmasq logged no DHCPOFFER.\nLog:\n%s", strings.Join(f.srv.lines(), "\n"))
	}
	squatted := first[0]

	if mode == proto.ConflictAsync {
		// D23: usable at once. This event arrives before the probing that
		// will take the address away, and it says so.
		ev := awaitAcquired(t, f.client)
		if got := ev.Lease.Addr.Addr().String(); got != squatted {
			t.Fatalf("async client acquired %s, the server offered %s", got, squatted)
		}
		if ev.ACD != proto.ACDProbing {
			t.Fatalf("async Acquired carries ACD phase %s, want probing: a chassis that restarts here would skip the check", ev.ACD)
		}
	}

	// ---------------------------------------------------- the wire itself --
	//
	// The Probe as another host sees it. Sender IP all zeroes is what makes
	// the frame a Probe (RFC 5227 section 1.1) and is the whole difference
	// from the datagram trick 1.x used, which poisons the ARP cache of every
	// host that hears it.
	target := netip.MustParseAddr(squatted)
	g := sq.waitForSighting(func(p *wire.ARPPacket) bool { return p.IsProbe() && p.TargetIP == target })
	if !g.p.SenderIP.IsUnspecified() {
		t.Fatalf("the probe carried sender IP %s, want RFC 5227 1.1's all-zero", g.p.SenderIP)
	}
	if got := net.HardwareAddr(g.p.SenderHW).String(); got != f.clientMAC {
		t.Fatalf("the probe carried sender hardware address %s, want the client's %s (section 2.1.1 makes it a MUST)", got, f.clientMAC)
	}

	// ----------------------------------------------- the server's own log --
	f.srv.waitFor(t, "DHCPDECLINE("+f.srv.iface+") "+squatted+" "+f.clientMAC)
	f.srv.waitCount(t, "DHCPDISCOVER("+f.srv.iface+")", 2, "the client did not restart the configuration process after the DECLINE")
	f.srv.waitCount(t, "DHCPOFFER("+f.srv.iface+")", 2, "the server never offered a second address")

	offers := f.offers()
	if offers[len(offers)-1] == squatted {
		t.Fatalf("the server re-offered the declined address %s; the log is\n%s", squatted, strings.Join(f.srv.lines(), "\n"))
	}
	f.quote(t, mode.String()+" mode, squatter in the probe window")

	if mode == proto.ConflictAsync {
		// D23's other half: the caller WAS told it held this address, so the
		// conflict has to be reported as a loss of it. Seam row G-5.
		lost := awaitEvent(t, f.client, lease.Lost)
		if lost.Reason != proto.ReasonConflict {
			t.Fatalf("Lost carries reason %s, want conflict", lost.Reason)
		}
		if got := lost.Lease.Addr.Addr().String(); got != squatted {
			t.Fatalf("Lost names %s, the client was told it held %s", got, squatted)
		}
	}

	// The second address is probed too. A client that declined and then took
	// the replacement on faith would pass every assertion above.
	// Two of them, not one, and the second is the BARRIER for the counter
	// assertion at the end of this function. ProbesSent is bumped after the
	// send returns, so the wire runs one frame ahead of it; waiting for a
	// LATER frame -- one the assertion is not about -- puts the earlier
	// bumps behind us without spinning on the number under test, which is
	// how a broken counter stays a red rather than becoming a hang.
	second := netip.MustParseAddr(offers[len(offers)-1])
	sq.waitForCount(isProbeFor(second), 2)

	// The caller's side of it, which differs by mode and is the reason D23
	// exists at all.
	if mode == proto.ConflictWait {
		ev, failures := awaitAcquiredThroughAConflict(t, f.client)
		if got := ev.Lease.Addr.Addr().String(); got == squatted {
			t.Fatalf("the waiting client announced the squatted address %s", got)
		}
		if ev.ACD == proto.ACDProbing {
			t.Fatalf("a waiting client was told Acquired while still probing (%s)", ev.ACD)
		}
		// WHAT THE CHASSIS COUNTS WHEN NOTHING WAS ACQUIRED. Lost is the
		// confirmation that a held lease was given back, and in this mode the
		// caller was never told it held one, so a Lost here would name an
		// address the caller had never seen. Failed{conflict} is what carries
		// it instead, and this is the assertion that says so.
		if len(failures) != 1 {
			t.Fatalf("the waiting client emitted %d Failed event(s) before acquiring, want exactly the one conflict", len(failures))
		}
		if failures[0].Reason != proto.ReasonConflict {
			t.Fatalf("Failed carries reason %s, want conflict", failures[0].Reason)
		}
		if !strings.Contains(failures[0].Note, squatted) {
			t.Fatalf("Failed says %q and does not name the squatted address %s", failures[0].Note, squatted)
		}
	}

	// Counters, as a cross-check on the evidence above and never as the
	// evidence: exactly one conflict, and the probes that were sent were sent.
	st := f.client.Stats()
	if st.ConflictsDetected != 1 {
		t.Errorf("ConflictsDetected = %d, want 1", st.ConflictsDetected)
	}
	if st.ProbesSent < 2 {
		t.Errorf("ProbesSent = %d, want at least one for each of the two addresses", st.ProbesSent)
	}
	t.Logf("client stats: %d conflict(s), %d probe(s), %d announcement(s), %d ARP frames seen, %d ignored",
		st.ConflictsDetected, st.ProbesSent, st.AnnouncementsSent, st.ARPSeen, st.ARPIgnored)
}

// awaitAcquiredThroughAConflict reads events until an Acquired, keeping the
// Failed events it passed on the way.
//
// The shared awaitAcquired treats any Failed as fatal, which is right
// everywhere else and wrong here: in ConflictWait a conflict found during
// section 2.1's probing IS a Failed, because nothing was ever acquired for
// there to be a Lost about. See the assertion at the call site.
func awaitAcquiredThroughAConflict(t *testing.T, c *Client) (lease.Event, []lease.Event) {
	t.Helper()
	var failures []lease.Event
	for ev := range c.Events() {
		t.Logf("client event: %s", ev)
		switch ev.Kind {
		case lease.Acquired:
			return ev, failures
		case lease.Failed:
			if ev.Reason != proto.ReasonConflict {
				t.Fatalf("the client failed for a reason this test did not arrange: %s", ev)
			}
			failures = append(failures, ev)
		}
	}
	t.Fatal("the event stream ended before a lease was acquired")
	return lease.Event{}, nil
}

// ------------------------------------ section 2.4: after the lease is held --

func TestASquatterAfterBoundTakesSection24sPath(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		squatterAfterBound(t)
		return
	}
	reexecInNamespaces(t)
}

// squatterAfterBound is the milestone's third run.
//
// Nothing answers the probes, the client binds, and only then does another
// host start claiming the address — RFC 5227 section 2.4, whose predicate is
// an ARP packet "where the 'sender IP address' is the address being defended
// and the 'sender hardware address' does not match" this host's.
//
// Arm (a) is what a DHCP client takes: "Upon receiving a conflicting ARP
// packet, a host MAY immediately cease using the address, and signal an error
// to the configuring agent". The configuring agent is the DHCP server and the
// signal is DHCPDECLINE. The address is never defended, because it was never
// this host's to defend.
func squatterAfterBound(t *testing.T) {
	f := newConflictClient(t, proto.ConflictWait, briskACD(), "m6-client")
	sq := newSquatter(t, testServerIf, squatterAnnounceOnCue)
	f.start(t, sq)

	ev := awaitAcquired(t, f.client)
	held := ev.Lease.Addr.Addr()
	if ev.ACD == proto.ACDProbing {
		t.Fatalf("a waiting client reached Acquired while still probing (%s); D22 says the address is not used until the check passes", ev.ACD)
	}
	f.srv.waitCount(t, "DHCPACK("+f.srv.iface+") "+held.String(), 1, "the server never acknowledged the address the client says it holds")

	// The listener is still open, which is the half of section 2.4 that is
	// easiest to lose: the probing is over and its socket is not.
	cue := time.Now()
	sq.announce <- held

	lost := awaitEvent(t, f.client, lease.Lost)
	if lost.Reason != proto.ReasonConflict {
		t.Fatalf("Lost carries reason %s, want conflict (plugin seam row G-5)", lost.Reason)
	}
	if lost.Lease.Addr.Addr() != held {
		t.Fatalf("Lost names %s, the client held %s", lost.Lease.Addr, held)
	}

	f.srv.waitFor(t, "DHCPDECLINE("+f.srv.iface+") "+held.String()+" "+f.clientMAC)
	f.srv.waitCount(t, "DHCPDISCOVER("+f.srv.iface+")", 2, "the client did not restart after the section 2.4 conflict")
	f.quote(t, "squatter after BOUND, RFC 5227 section 2.4")

	// The client never answered. Arm (a) is "cease using", not "defend", and
	// the way to see the absence is to look for what a defender would have
	// sent: an ARP Reply, or a fresh Announcement, for the address after the
	// squatter claimed it.
	for _, g := range sq.sightings() {
		if g.at.Before(cue) {
			continue
		}
		if g.p.Op == wire.ARPReply && g.p.SenderIP == held {
			t.Fatalf("the client defended %s with %s; arm (a) never answers", held, g.p)
		}
	}

	st := f.client.Stats()
	if st.ConflictsDetected != 1 {
		t.Errorf("ConflictsDetected = %d, want 1", st.ConflictsDetected)
	}
}

// -------------------------------------- no squatter: the schedule, MEASURED --

func TestTheDelayBeforeAnAcquisitionIsRFC5227sArithmetic(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		measureTheProbeDelay(t)
		return
	}
	reexecInNamespaces(t)
}

// measureTheProbeDelay is the milestone's fourth run: the price of D22, timed
// on the wire.
//
// THE ARITHMETIC, from RFC 5227 section 2.1. The host "SHOULD then wait for a
// random time interval selected uniformly in the range zero to PROBE_WAIT
// seconds, and should then send PROBE_NUM probe packets, each of these probe
// packets spaced randomly and uniformly, PROBE_MIN to PROBE_MAX seconds
// apart"; then, "if, by ANNOUNCE_WAIT seconds after the transmission of the
// last ARP Probe no conflicting ARP Reply or ARP Probe has been received",
// the address is free. Section 2.3 then says the host "may begin legitimately
// using the IP address immediately after sending the first of the two ARP
// Announcements".
//
// So, with section 1.1's constants (PROBE_WAIT 1s, PROBE_NUM 3, PROBE_MIN 1s,
// PROBE_MAX 2s, ANNOUNCE_WAIT 2s), the delay from the DHCPACK to the first
// Announcement is
//
//	U(0,1) + U(1,2) + U(1,2) + 2   =  4.0 s at best, 5.5 s on average, 7.0 s
//	                                  at worst.
//
// The brief that commissioned this milestone said "≈3 s (worst ≈5 s)". That
// is low, and the difference is not an implementation choice: it is the two
// inter-probe gaps, which the RFC makes PROBE_MIN..PROBE_MAX and not zero.
// The MEASURED number below is what a container will actually wait, and it is
// the reason D23's async mode exists.
func measureTheProbeDelay(t *testing.T) {
	f := newConflictClient(t, proto.ConflictWait, proto.DefaultACDParams(), "m6-client")
	sq := newSquatter(t, testServerIf, squatterObserve)
	f.start(t, sq)

	ev := awaitAcquired(t, f.client)
	held := ev.Lease.Addr.Addr()

	d := proto.DefaultACDParams()

	// THE ANNOUNCEMENT IS THE BARRIER, and it is waited for rather than
	// sampled. Acquired is emitted from the manager's own goroutine the
	// instant the first Announcement is handed to the socket; the squatter is
	// a second process reading a second socket, and it has not necessarily
	// stamped that frame yet. Section 2.3 puts the Announcement after the
	// whole probe schedule, so once one has been read no Probe is still to
	// come.
	//
	// That closes the LATE edge of the window. The EARLY edge is closed by
	// conflictFixture.start, which will not run the client until the observer
	// holds a bound socket — read its comment, because a probe sent before
	// the observer existed is invisible here and looks like a probe never
	// sent.
	//
	// MEASURED 2026-09-04: sampled instead of waited for, this test failed
	// under load with "the wire carried no ARP Announcement" on both a loaded
	// and a concurrent verify run, having timed nothing.
	anns := sq.waitForCount(isAnnouncementFor(held), 1)
	probes := sq.matching(isProbeFor(held))
	if len(probes) != d.ProbeNum {
		t.Fatalf("the wire carried %d probe(s) for %s, want PROBE_NUM = %d.\nsightings: %v",
			len(probes), held, d.ProbeNum, sq.sightings())
	}

	// The DHCPACK's own moment, taken from the packet ring: the frame the
	// server sent, timestamped when the client read it off the socket.
	var ackAt time.Time
	for _, p := range f.client.Packets() {
		if p.Dir != lease.DirIn || p.Msg == nil {
			continue
		}
		if mt, ok := p.Msg.Type(); ok && mt == wire.MsgAck {
			ackAt = p.At
		}
	}
	if ackAt.IsZero() {
		t.Fatal("the packet ring holds no DHCPACK, so there is nothing to measure from")
	}

	// MEASURED, all of it. Nothing below is a constant this file chose.
	toFirstProbe := probes[0].at.Sub(ackAt)
	gap1 := probes[1].at.Sub(probes[0].at)
	gap2 := probes[2].at.Sub(probes[1].at)
	toAnnounce := anns[0].at.Sub(probes[len(probes)-1].at)
	total := anns[0].at.Sub(ackAt)

	t.Logf("MEASURED on the wire, %s:\n"+
		"  DHCPACK -> probe 1      %8.3fs   RFC: U(0, PROBE_WAIT=%s)\n"+
		"  probe 1 -> probe 2      %8.3fs   RFC: U(PROBE_MIN=%s, PROBE_MAX=%s)\n"+
		"  probe 2 -> probe 3      %8.3fs   RFC: U(PROBE_MIN=%s, PROBE_MAX=%s)\n"+
		"  probe 3 -> announce 1   %8.3fs   RFC: ANNOUNCE_WAIT=%s\n"+
		"  DHCPACK -> announce 1   %8.3fs   RFC: 4.000s..7.000s, mean 5.500s",
		held,
		toFirstProbe.Seconds(), d.ProbeWait,
		gap1.Seconds(), d.ProbeMin, d.ProbeMax,
		gap2.Seconds(), d.ProbeMin, d.ProbeMax,
		toAnnounce.Seconds(), d.AnnounceWait,
		total.Seconds())

	// The tolerance is one-sided in principle — a timer cannot fire early —
	// and two-sided in practice by this much, because reading a frame off a
	// socket and stamping it happens after the send. It is not a fudge
	// factor for the schedule: shrinking PROBE_NUM or ANNOUNCE_WAIT moves
	// these by seconds, not milliseconds.
	const slack = 500 * time.Millisecond
	within := func(what string, got, lo, hi time.Duration) {
		t.Helper()
		if got < lo-slack || got > hi+slack {
			t.Errorf("%s took %s, RFC 5227 says %s..%s", what, got, lo, hi)
		}
	}
	within("the wait before the first probe", toFirstProbe, 0, dur(d.ProbeWait))
	within("the first inter-probe gap", gap1, dur(d.ProbeMin), dur(d.ProbeMax))
	within("the second inter-probe gap", gap2, dur(d.ProbeMin), dur(d.ProbeMax))
	within("the wait after the last probe", toAnnounce, dur(d.AnnounceWait), dur(d.AnnounceWait))
	within("the whole delay from DHCPACK to first announcement", total,
		dur(d.AnnounceWait)+2*dur(d.ProbeMin),
		dur(d.ProbeWait)+2*dur(d.ProbeMax)+dur(d.AnnounceWait))

	// ORDERING, which is the assertion D22 actually makes: the caller is told
	// Acquired only after the probing is over.
	//
	// The phase at Acquired is ANNOUNCING and not DEFENDING, and that is the
	// RFC rather than an off-by-one. Section 2.3: the host "may begin
	// legitimately using the IP address immediately after sending the first of
	// the two ARP Announcements". The second is still owed at this moment.
	// What D22 promises is that this is not PROBING.
	if ev.ACD != proto.ACDAnnouncing {
		t.Errorf("Acquired carries ACD phase %s, want announcing (section 2.3's first announcement is sent, the second is not)", ev.ACD)
	}
	if !probes[len(probes)-1].at.Before(anns[0].at) {
		t.Errorf("the announcement did not follow the last probe")
	}
	if f.srv.count("DHCPDECLINE") != 0 {
		t.Errorf("dnsmasq logged a DECLINE on a link with nothing on it:\n%s", strings.Join(f.srv.lines(), "\n"))
	}
	f.quote(t, "no squatter, the clean acquisition")

	// The announcements are not the probes. A run where the "probes" were
	// really announcements would satisfy the timing above and would have
	// polluted every ARP cache on the link.
	for i, p := range probes {
		if !p.p.SenderIP.IsUnspecified() {
			t.Errorf("probe %d carried sender IP %s, want all-zero", i+1, p.p.SenderIP)
		}
		if p.p.TargetIP != held {
			t.Errorf("probe %d targeted %s, want the leased %s", i+1, p.p.TargetIP, held)
		}
	}
	if anns[0].p.SenderIP != held || anns[0].p.TargetIP != held {
		t.Errorf("the announcement is %s, want sender and target both %s (section 2.3)", anns[0].p, held)
	}

	// ANNOUNCE_NUM is two and the second one is owed ANNOUNCE_INTERVAL after
	// the first, so it is waited for on the wire rather than read out of the
	// counter at a moment the RFC says it has not been sent yet.
	anns = sq.waitForCount(isAnnouncementFor(held), d.AnnounceNum)
	if gap := anns[1].at.Sub(anns[0].at); gap < dur(d.AnnounceInterval)-slack || gap > dur(d.AnnounceInterval)+slack {
		t.Errorf("the two announcements are %s apart, RFC 5227 says ANNOUNCE_INTERVAL = %s", gap, d.AnnounceInterval)
	}

	// THE BARRIER IS THE PACKET RING, not the counters this then asserts on.
	//
	// A send bumps its counter and only then records the frame in the ring,
	// so a ring that holds ANNOUNCE_NUM outgoing Announcements is proof that
	// every bump owed for them has already happened. The obvious shortcut --
	// spinning until the counters reach the expected number -- would make a
	// counter that never counts an infinite spin instead of a failed
	// assertion, and the tree has MEASURED that once already: written that
	// way in transport_packet_linux_test.go, two counter mutants came back as
	// 200-second hangs, and a hang is not a kill.
	for countOutgoing(f.client, isAnnouncementFor(held)) < d.AnnounceNum {
		goruntime.Gosched()
	}
	st := f.client.Stats()
	if st.ProbesSent != uint64(d.ProbeNum) || st.AnnouncementsSent != uint64(d.AnnounceNum) {
		t.Errorf("the client counted %d probe(s) and %d announcement(s), want %d and %d",
			st.ProbesSent, st.AnnouncementsSent, d.ProbeNum, d.AnnounceNum)
	}
}

// countOutgoing counts the ARP frames the client's own packet ring says it
// sent and pred accepts. It is a barrier, never evidence: what the client
// believes it sent is exactly the thing the squatter's socket is here to
// check independently.
func countOutgoing(c *Client, pred func(*wire.ARPPacket) bool) int {
	n := 0
	for _, p := range c.Packets() {
		if p.Dir == lease.DirOut && p.ARP != nil && pred(p.ARP) {
			n++
		}
	}
	return n
}

// dur converts ring 1's Duration to the one testing prints.
func dur(d proto.Duration) time.Duration { return time.Duration(d) }
