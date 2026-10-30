// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

//go:build linux

package runtime

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/claymore666/dhcp-golib/lease"
	"github.com/claymore666/dhcp-golib/proto"
)

// The relay fixture of claymore666/dhcp-golib#94: the client, a router running
// dnsmasq as the relay agent, and a dnsmasq server one hop further, each in
// its own network namespace inside the test's user namespace.
//
//	client (cli0) 10.0.1.0/24 (rl0) router (rs0) 10.0.2.0/24 (sv0) server
const (
	relayClientNet = "10.0.1."
	relayRouterIP  = "10.0.1.1"
	relayRouterUp  = "10.0.2.1"
	relayServerIP  = "10.0.2.2"
	relayLoAddr    = "10.0.1.100"
	relayHiAddr    = "10.0.1.102"
)

// TestRenewalBehindADnsmasqRelayIsUnicastAtT1 holds the RENEW of RFC 2131
// section 4.4.5 to leave the client at T1 when the server is behind a relay.
//
// The evidence is outside the library: the relay's own log must not see the
// renewal (a unicast to the server is routed past it, a REBIND broadcast is
// relayed), the server's log must show it, and the renewed lease must have
// been requested before T2.
func TestRenewalBehindADnsmasqRelayIsUnicastAtT1(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		renewalBehindARelay(t)
		return
	}
	reexecInNamespaces(t)
}

// netnsHolder is a process whose only job is to own a network namespace.
type netnsHolder struct {
	pid   int
	stdin io.WriteCloser
	cmd   *exec.Cmd
}

func startNetnsHolder(t *testing.T) *netnsHolder {
	t.Helper()
	cmd := exec.Command("unshare", "-n", "sh", "-c", "echo $$; exec cat")
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting a namespace holder: %v", err)
	}
	h := &netnsHolder{stdin: in, cmd: cmd}
	t.Cleanup(func() {
		_ = h.stdin.Close()
		_ = h.cmd.Process.Kill()
		_ = h.cmd.Wait()
	})
	// The first line is the pid of the process that is inside the new
	// namespace: cmd.Process.Pid is unshare's, which execs sh, and the pid is
	// kept across exec, so both are the same process.
	if _, err := fmt.Fscan(bufio.NewReader(out), &h.pid); err != nil {
		t.Fatalf("reading the holder's pid: %v", err)
	}
	return h
}

func (h *netnsHolder) run(t *testing.T, name string, args ...string) {
	t.Helper()
	mustRun(t, "nsenter", append([]string{"-t", fmt.Sprint(h.pid), "-n", name}, args...)...)
}

// startDnsmasqRelay runs dnsmasq as a relay agent in h's namespace.
func startDnsmasqRelay(t *testing.T, h *netnsHolder) *dnsmasqServer {
	t.Helper()
	bin, err := findDnsmasq()
	if err != nil {
		t.Fatalf("%v", err)
	}
	dir := t.TempDir()
	cmd := exec.Command("nsenter", "-t", fmt.Sprint(h.pid), "-n", bin,
		"--conf-file=/dev/null", "--no-daemon", "--log-facility=-", "--log-dhcp", "--port=0",
		"--interface=rl0", "--interface=rs0", "--bind-interfaces", "--except-interface=lo",
		"--dhcp-relay="+relayRouterIP+","+relayServerIP,
		"--pid-file="+filepath.Join(dir, "pid"), "--no-resolv", "--no-hosts")
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("StderrPipe: %v", err)
	}
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the relay: %v", err)
	}
	s := &dnsmasqServer{cmd: cmd, arrived: make(chan string, 256), iface: "rl0"}
	go s.read(stderr)
	t.Cleanup(func() {
		s.stop()
		t.Logf("relay log:\n%s", strings.Join(s.lines(), "\n"))
	})
	s.waitFor(t, "started, version")
	return s
}

func renewalBehindARelay(t *testing.T) {
	router := startNetnsHolder(t)
	server := startNetnsHolder(t)

	mustRun(t, "ip", "link", "add", testClientIf, "type", "veth", "peer", "name", "rl0", "netns", fmt.Sprint(router.pid))
	router.run(t, "ip", "link", "add", "rs0", "type", "veth", "peer", "name", "sv0", "netns", fmt.Sprint(server.pid))
	router.run(t, "ip", "addr", "add", relayRouterIP+"/24", "dev", "rl0")
	router.run(t, "ip", "addr", "add", relayRouterUp+"/24", "dev", "rs0")
	for _, l := range []string{"lo", "rl0", "rs0"} {
		router.run(t, "ip", "link", "set", l, "up")
	}
	router.run(t, "sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward")
	server.run(t, "ip", "addr", "add", relayServerIP+"/24", "dev", "sv0")
	server.run(t, "ip", "link", "set", "sv0", "up")
	server.run(t, "ip", "route", "add", "default", "via", relayRouterUp)
	mustRun(t, "ip", "link", "set", testClientIf, "up")

	iface := hardwareAddrOf(t, testClientIf)
	clientMAC := iface.String()
	// The client owns no kernel address on cli0, so the router's ARP for the
	// leased address would go unanswered and the DHCPACK would be dropped; the
	// same reason as renewalAgainstDnsmasq's neighbour entries.
	for _, a := range addrRange(t, relayLoAddr, relayHiAddr) {
		router.run(t, "ip", "neigh", "replace", a, "lladdr", clientMAC, "dev", "rl0", "nud", "permanent")
	}

	relay := startDnsmasqRelay(t, router)
	srv := startDnsmasqCfg(t, dnsmasqConfig{
		rangeLo: relayLoAddr, rangeHi: relayHiAddr,
		iface: "sv0", router: relayRouterIP, nsPid: server.pid,
		// T1 at 3 s and T2 at 15 s: a renewal that waits for T2 arrives
		// twelve seconds late and the assertion below sees it.
		extra: []string{"--dhcp-option=58," + fmt.Sprint(testRenewSec), "--dhcp-option=59,15"},
	})

	params := proto.DefaultParams(iface)
	params.DesyncMin, params.DesyncMax = 0, 0
	params.Conflict = proto.ConflictAsync
	params.ACD = briskACD()
	params.Hostname = "relay-client"

	c, err := NewClient(ClientConfig{Interface: testClientIf, Params: params, EventBuffer: 8})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()

	acquired := awaitAcquired(t, c)
	leased := acquired.Lease.Addr.Addr().String()
	if !strings.HasPrefix(leased, relayClientNet) {
		t.Fatalf("leased %s, outside the relayed subnet %s0/24", leased, relayClientNet)
	}
	if acquired.Lease.ServerID.String() != relayServerIP {
		t.Fatalf("server identifier %s, want %s: the server is not behind the relay", acquired.Lease.ServerID, relayServerIP)
	}
	if got := acquired.Lease.Rebind.Sub(acquired.Lease.Acquired); int(got.Seconds()) != 15 {
		t.Fatalf("T2 is %s after the lease began, want 15s from option 59", got)
	}

	// "DHCP relay at" is the relay's line for each client packet it forwards.
	// The acquisition's DISCOVER and REQUEST are two, so a zero here would
	// make the comparison below a comparison of nothing with nothing.
	relayed := relay.count("DHCP relay at")
	if relayed < 2 {
		t.Fatalf("the relay forwarded %d client packet(s) during the acquisition, want at least the DISCOVER and the REQUEST.\nRelay log:\n%s",
			relayed, strings.Join(relay.lines(), "\n"))
	}
	serverRequests := srv.count("DHCPREQUEST(sv0) " + leased)
	watch := watchSendFailures(t, c)

	renewed := awaitEvent(t, c, lease.Renewed)
	watch("renewal DHCPREQUEST")

	if !renewed.Lease.Acquired.Before(acquired.Lease.Rebind) {
		t.Fatalf("the renewal was requested at %s, not before T2 at %s: it was a REBIND, not a unicast RENEW at T1",
			renewed.Lease.Acquired, acquired.Lease.Rebind)
	}
	srv.waitCount(t, "DHCPREQUEST(sv0) "+leased, serverRequests+1, "the renewal never reached the server")
	if got := relay.count("DHCP relay at"); got != relayed {
		t.Fatalf("the relay forwarded %d client packets, %d before the renewal: the renewal was broadcast to it and not routed past it.\nRelay log:\n%s",
			got, relayed, strings.Join(relay.lines(), "\n"))
	}
}
