//go:build linux

package runtime

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/claymore666/dhcplease/lease"
	"github.com/claymore666/dhcplease/proto"
)

// This file is done-condition (a): a lease acquired from a REAL dnsmasq over a
// real AF_PACKET socket, asserted against THE SERVER'S OWN LOG rather than
// against the library's opinion of what happened.
//
// The distinction is the whole point and it is a lesson this project already
// paid for: every place its suite checked a counter alone, something shipped
// broken; every place it checked the server, it stayed sound. A client that
// invented a lease out of nothing would satisfy every assertion about its own
// state. It cannot make dnsmasq write DHCPACK into a log.
//
// # Why this runs without root, and what that costs
//
// The test re-executes itself into a new USER and NETWORK namespace. Inside
// the user namespace the process is uid 0 and holds CAP_NET_ADMIN and
// CAP_NET_RAW over its own network namespace, which is exactly what creating a
// veth pair, binding AF_PACKET and binding UDP port 67 need. No password, no
// setuid binary, no capability granted on the host.
//
// It also means requirement T7 holds by construction rather than by care:
// every interface, address and socket here lives in a namespace that ceases to
// exist when the process does. The test cannot mutate host state because it
// cannot see host state.
//
// # It FAILS rather than skips when it cannot run
//
// A skip here would be indistinguishable from a pass in every summary anyone
// reads, on the one test that talks to a real server. If unprivileged user
// namespaces are disabled, or dnsmasq is absent, that is a fact about the
// machine that must be visible, and the fix is to install the one and enable
// the other.

const nsChildEnv = "DHCPLEASE_NETNS_CHILD"

const (
	testClientIf = "cli0"
	testServerIf = "srv0"
	testServerIP = "192.168.99.1"
	testSubnet   = "255.255.255.0"
	testRangeLo  = "192.168.99.100"
	testRangeHi  = "192.168.99.150"
	testDomain   = "dhcp.test"
	testMTU      = 1400
	testLeaseSec = 120
)

func TestAcquiresFromRealDnsmasq(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		runAgainstDnsmasq(t)
		return
	}
	reexecInNamespaces(t, "TestAcquiresFromRealDnsmasq")
}

// reexecInNamespaces runs this test binary again, for the named test only,
// inside a fresh user and network namespace.
func reexecInNamespaces(t *testing.T, name string) {
	t.Helper()

	if _, err := os.Stat("/proc/self/ns/user"); err != nil {
		t.Fatalf("this kernel has no user namespaces (%v); done-condition (a) cannot be measured here", err)
	}
	if _, err := findDnsmasq(); err != nil {
		t.Fatalf("%v — install dnsmasq; this test is the only one that talks to a real server", err)
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Fatalf("the ip command is not on PATH (%v); the namespace cannot be wired up", err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^"+name+"$", "-test.v=true", "-test.count=1")
	cmd.Env = append(os.Environ(), nsChildEnv+"=1", "LC_ALL=C", "LANG=C")
	// uid 0 inside the namespace, and it has to be 0: capabilities are
	// recalculated at execve, and a process that is not root in its user
	// namespace and carries no file capabilities comes out of exec with an
	// empty set. MEASURED 2026-08-29 by mapping the caller's own id instead —
	// `ip link add` then fails with EPERM, because CAP_NET_ADMIN was dropped
	// by the exec rather than never granted.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
		// setgroups must be denied before an unprivileged process may write a
		// gid map; the kernel refuses the mapping otherwise.
		GidMappingsEnableSetgroups: false,
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the namespaced run failed (%v). Its output follows.\n%s", err, out)
	}
	t.Logf("namespaced run output:\n%s", out)
}

func findDnsmasq() (string, error) {
	if p, err := exec.LookPath("dnsmasq"); err == nil {
		return p, nil
	}
	// dnsmasq installs into sbin, which is usually absent from a non-root
	// PATH. Looking there is not a workaround: the binary is world-executable
	// and needs no privilege to run inside our own namespace.
	for _, p := range []string{"/usr/sbin/dnsmasq", "/sbin/dnsmasq", "/usr/local/sbin/dnsmasq"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("dnsmasq was not found on PATH or in the usual sbin directories")
}

// runAgainstDnsmasq is the body, executed inside the namespaces.
func runAgainstDnsmasq(t *testing.T) {
	mustRun(t, "ip", "link", "add", testClientIf, "type", "veth", "peer", "name", testServerIf)
	mustRun(t, "ip", "addr", "add", testServerIP+"/24", "dev", testServerIf)
	mustRun(t, "ip", "link", "set", testServerIf, "up")
	mustRun(t, "ip", "link", "set", testClientIf, "up")

	srv := startDnsmasq(t)

	iface, err := net.InterfaceByName(testClientIf)
	if err != nil {
		t.Fatalf("InterfaceByName(%s): %v", testClientIf, err)
	}
	clientMAC := iface.HardwareAddr.String()
	t.Logf("client interface %s has hardware address %s", testClientIf, clientMAC)

	params := proto.DefaultParams(iface.HardwareAddr)
	// The desync delay would add up to ten seconds of nothing to a test whose
	// subject is the exchange. Ring 1 pins the RFC default separately.
	params.DesyncMin, params.DesyncMax = 0, 0
	params.Hostname = "m1-client"

	c, err := NewClient(ClientConfig{Interface: testClientIf, Params: params, EventBuffer: 8})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- c.Run(ctx) }()

	// Barrier: the Acquired event. No duration appears anywhere in this file —
	// if the exchange never completes, the test hangs until go test's own
	// timeout, which is a louder and more honest failure than a sleep that
	// was too short.
	var acquired lease.Event
	for ev := range c.Events() {
		t.Logf("client event: %s", ev)
		if ev.Kind == lease.Acquired {
			acquired = ev
			break
		}
		if ev.Kind == lease.Failed {
			t.Fatalf("acquisition failed: %s", ev)
		}
	}
	if acquired.Kind != lease.Acquired {
		t.Fatal("the event stream ended before a lease was acquired")
	}

	leased := acquired.Lease.Addr.Addr().String()
	t.Logf("client acquired %s", acquired.Lease)

	// ------------------------------------------------- the server's own log --
	//
	// This is the assertion that matters. Everything above is the client
	// describing itself.
	want := []string{
		"DHCPDISCOVER(" + testServerIf + ") " + clientMAC,
		"DHCPOFFER(" + testServerIf + ") " + leased + " " + clientMAC,
		"DHCPREQUEST(" + testServerIf + ") " + leased + " " + clientMAC,
		"DHCPACK(" + testServerIf + ") " + leased + " " + clientMAC,
	}
	srv.waitFor(t, want[len(want)-1])
	log := srv.lines()
	for _, w := range want {
		if !containsLine(log, w) {
			t.Fatalf("the server's log has no line containing %q.\nServer log:\n%s", w, strings.Join(log, "\n"))
		}
	}

	// The server's log is also the check on the lease CONTENTS: the address
	// the client reports is the address dnsmasq says it handed out, and it is
	// inside the range dnsmasq was configured with.
	if !inRange(leased, testRangeLo, testRangeHi) {
		t.Fatalf("the client leased %s, outside the configured range %s..%s", leased, testRangeLo, testRangeHi)
	}
	if got := acquired.Lease.Addr.Bits(); got != 24 {
		t.Fatalf("prefix = /%d, want /24 from subnet mask %s", got, testSubnet)
	}
	if got := acquired.Lease.Gateway.String(); got != testServerIP {
		t.Fatalf("gateway = %s, want %s", got, testServerIP)
	}
	if got := acquired.Lease.Domain; got != testDomain {
		t.Fatalf("domain = %q, want %q", got, testDomain)
	}
	if got := acquired.Lease.MTU; got != testMTU {
		t.Fatalf("mtu = %d, want %d", got, testMTU)
	}
	if got := acquired.Lease.Expire.Sub(acquired.Lease.Acquired); int(got.Seconds()) != testLeaseSec {
		t.Fatalf("lease runs for %s, want %ds", got, testLeaseSec)
	}

	// ----------------------------------------- done-condition (b), for real --
	//
	// The exchange that just happened, replayed offline through ring 1, must
	// produce the identical lease. This is the unit replay test again with the
	// one thing a fixture cannot supply: packets a real server actually sent.
	cancel()
	<-runErr

	if dropped := c.JournalDropped(); dropped != 0 {
		t.Fatalf("the journal dropped %d entries, so it is not replayable", dropped)
	}
	entries := c.Journal()
	if len(entries) == 0 {
		t.Fatal("the journal is empty")
	}
	var toBound []proto.JournalEntry
	for _, e := range entries {
		toBound = append(toBound, e)
		if e.To == proto.StateBound {
			break
		}
	}
	if toBound[len(toBound)-1].To != proto.StateBound {
		t.Fatal("the journal never records reaching BOUND")
	}
	res, err := proto.Replay(params, toBound)
	if err != nil {
		t.Fatalf("the real exchange does not replay: %v", err)
	}
	if !res.Held {
		t.Fatal("the replay produced no lease")
	}
	if res.Lease.Addr != acquired.Lease.Addr {
		t.Fatalf("replayed %s, the live client got %s", res.Lease.Addr, acquired.Lease.Addr)
	}
	if res.Lease.Domain != acquired.Lease.Domain || res.Lease.MTU != acquired.Lease.MTU {
		t.Fatalf("replayed lease differs: %+v", res.Lease)
	}

	// The packet ring holds the real exchange, decoded (G1). Four packets:
	// DISCOVER, OFFER, REQUEST, ACK.
	pkts := c.Packets()
	if len(pkts) < 4 {
		t.Fatalf("the packet ring holds %d packets, want at least the four of an acquisition", len(pkts))
	}
	ts := c.TransportStats()
	t.Logf("transport: %d reads, %d skipped as not-for-us, %d sends, %d uncompleted checksums, %d absent",
		ts.Reads, ts.Skipped, ts.Sends, ts.Uncompleted, ts.Absent)
	// MEASURED 2026-08-29 on this path: every reply arrives with its UDP
	// checksum UNCOMPLETED. The sending kernel writes the pseudo-header sum
	// and leaves the rest to hardware that a veth pair does not have, so the
	// count equals the number of replies read.
	//
	// This is asserted rather than logged because an uncounted counter is the
	// failure this project keeps paying for: the first run of this test hung
	// for two minutes on exactly these frames being discarded, and a count
	// nobody checks would let that return silently. It is also the one
	// assertion here that could go red for a HEALTHY reason — a kernel that
	// completes the sum on a local delivery path would drive it to zero — so
	// the message says so, and ipudp_test.go pins the parsing behaviour
	// against captured bytes where no environment can move it.
	if ts.Uncompleted != ts.Reads {
		t.Fatalf("%d of %d replies had an uncompleted checksum, want all of them. "+
			"If this host's kernel now completes the UDP checksum on a local "+
			"delivery path, the right answer is 0 and this assertion is what "+
			"needs revisiting -- not the parser.", ts.Uncompleted, ts.Reads)
	}
	if ts.Reads == 0 {
		t.Fatal("the transport read nothing, so the count above is vacuous")
	}
	if ts.Sends < 2 {
		t.Fatalf("the transport sent %d frames, want at least the DISCOVER and the REQUEST", ts.Sends)
	}
}

func inRange(addr, lo, hi string) bool {
	a := net.ParseIP(addr).To4()
	l := net.ParseIP(lo).To4()
	h := net.ParseIP(hi).To4()
	if a == nil || l == nil || h == nil {
		return false
	}
	return string(a) >= string(l) && string(a) <= string(h)
}

func containsLine(lines []string, want string) bool {
	for _, l := range lines {
		if strings.Contains(l, want) {
			return true
		}
	}
	return false
}

func mustRun(t *testing.T, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

// dnsmasqServer is a running dnsmasq whose log is being read line by line.
//
// Reading the log as a STREAM is what lets this file contain no duration at
// all: "the server is ready" and "the server logged the ACK" are both channel
// receives, so the test is as fast as the exchange and never faster than the
// truth.
type dnsmasqServer struct {
	cmd *exec.Cmd

	mu  sync.Mutex
	buf []string

	arrived chan string
}

func startDnsmasq(t *testing.T) *dnsmasqServer {
	t.Helper()

	bin, err := findDnsmasq()
	if err != nil {
		t.Fatalf("%v", err)
	}
	dir := t.TempDir()

	cmd := exec.Command(bin,
		"--conf-file=/dev/null",
		// --no-daemon, not --keep-in-foreground, and the difference decides
		// whether this test can run at all. Both stay in the foreground; only
		// --no-daemon also skips dnsmasq's privilege drop.
		//
		// MEASURED 2026-08-29: as uid 0 with --keep-in-foreground, dnsmasq
		// calls setgroups(0, ...) to shed supplementary groups and exits with
		// "failed to change group-id to root: Operation not permitted",
		// because an unprivileged user namespace must DENY setgroups before it
		// is allowed to write a gid map. The two requirements are in direct
		// conflict and no combination of --user and --group resolves it.
		"--no-daemon",
		// "-" is stderr. The log is the ORACLE for this test, so it is read
		// directly rather than through syslog, which this namespace has no
		// route to anyway.
		"--log-facility=-",
		"--log-dhcp",
		"--port=0", // DNS off: this test is about DHCP.
		"--interface="+testServerIf,
		"--bind-interfaces",
		"--except-interface=lo",
		"--dhcp-range="+testRangeLo+","+testRangeHi+","+testSubnet+","+fmt.Sprint(testLeaseSec),
		"--dhcp-option=3,"+testServerIP,
		"--dhcp-option=6,"+testServerIP,
		"--dhcp-option=15,"+testDomain,
		"--dhcp-option=26,"+fmt.Sprint(testMTU),
		"--dhcp-authoritative",
		"--dhcp-leasefile="+filepath.Join(dir, "leases"),
		"--pid-file="+filepath.Join(dir, "pid"),
		"--no-resolv",
		"--no-hosts",
	)
	// C locale: dnsmasq translates its startup messages, and a German or
	// French box would otherwise fail this test on a string nobody changed.
	// The DHCP transaction lines are protocol keywords and are not
	// translated, but the readiness line is.
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")

	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("StderrPipe: %v", err)
	}
	cmd.Stdout = io.Discard

	if err := cmd.Start(); err != nil {
		t.Fatalf("starting dnsmasq: %v", err)
	}

	s := &dnsmasqServer{cmd: cmd, arrived: make(chan string, 256)}
	go s.read(stderr)

	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Logf("dnsmasq log:\n%s", strings.Join(s.lines(), "\n"))
	})

	// Readiness, as a line rather than as a wait: dnsmasq announces the range
	// once its DHCP socket is up.
	s.waitFor(t, "DHCP, IP range "+testRangeLo)
	return s
}

func (s *dnsmasqServer) read(r io.Reader) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		s.mu.Lock()
		s.buf = append(s.buf, line)
		s.mu.Unlock()
		select {
		case s.arrived <- line:
		default:
		}
	}
	close(s.arrived)
}

func (s *dnsmasqServer) lines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.buf...)
}

// waitFor blocks until a log line contains want.
func (s *dnsmasqServer) waitFor(t *testing.T, want string) {
	t.Helper()
	// Anything already read counts: the line may have arrived before this
	// call, and a watcher that only looks at future lines misses exactly the
	// events that happen quickly.
	if containsLine(s.lines(), want) {
		return
	}
	for line := range s.arrived {
		if strings.Contains(line, want) {
			return
		}
	}
	t.Fatalf("dnsmasq exited before logging a line containing %q.\nLog:\n%s",
		want, strings.Join(s.lines(), "\n"))
}
