// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

//go:build linux

package runtime

import (
	"context"
	"net"
	"os"
	goruntime "runtime"
	"testing"

	"github.com/claymore666/dhcp-golib/lease"
	"github.com/claymore666/dhcp-golib/proto"
)

// This file is the library half of docker-net-dhcp#961, measured where the
// issue states it: "the name appears in the DHCP server's table".
//
// THE SERVER'S LEASE FILE IS THE ASSERTION. Every other thing this test could
// compare against — the client's Hostname, the journal, the counter — is the
// client agreeing with itself, and a client that stored the name and sent
// nothing satisfies all of them. It cannot make dnsmasq write a name into
// --dhcp-leasefile.

const hostnameLateName = "named-after-start"

// TestAHostnameSetAfterStartReachesTheServersLeaseFile starts a client with NO
// name, gives it one while it is running, and reads the server's own table.
//
// The before-picture is part of it: dnsmasq writes "*" for a lease whose client
// sent no option 12, so the test knows the name it finds afterwards is the one
// this call put there and not one the fixture supplied.
func TestAHostnameSetAfterStartReachesTheServersLeaseFile(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		runLateHostnameAgainstDnsmasq(t)
		return
	}
	reexecInNamespaces(t)
}

func runLateHostnameAgainstDnsmasq(t *testing.T) {
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
	// Async with the brisk table, for the reason dnsmasq_linux_test.go gives:
	// the subject here is the DHCP exchange, and RFC 5227's real schedule would
	// put five seconds of section 1.1 arithmetic in front of every assertion.
	// The probe and the section 2.4 listener are still in the path.
	params.Conflict = proto.ConflictAsync
	params.ACD = briskACD()
	// AND NO Hostname. That is the shape of the issue: the name does not exist
	// when the interface already needs a lease.

	c, err := NewClient(ClientConfig{Interface: testClientIf, Params: params, EventBuffer: 8})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- c.Run(ctx) }()

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
	leased := acquired.Lease.Addr.Addr()
	t.Logf("client acquired %s with no name", leased)

	// The before-picture, from the server's own file.
	before := readDnsmasqLeases(t, srv.leasefile, 1)
	if before[0].hostname != "*" {
		t.Fatalf("dnsmasq already records the name %q for %s; this test would measure nothing",
			before[0].hostname, before[0].addr)
	}

	if err := c.SetHostname(hostnameLateName); err != nil {
		t.Fatalf("SetHostname: %v", err)
	}

	// The server's log first: the name travels in a DHCPREQUEST, and a second
	// DHCPACK is what says the server answered it. waitCount has no duration in
	// it — a renewal that never happens hangs until go test's own timeout.
	srv.waitCount(t, "DHCPACK("+testServerIf+")", 2,
		"the hostname was handed to a running client and no second exchange followed")

	got := waitLeaseHostname(t, srv.leasefile, hostnameLateName)
	if got.addr != leased {
		t.Fatalf("the server recorded %q against %s, but this client holds %s", hostnameLateName, got.addr, leased)
	}
	if got.mac != hexColons(iface.HardwareAddr) {
		t.Fatalf("the named lease belongs to %s, not to this client's %s", got.mac, hexColons(iface.HardwareAddr))
	}
	t.Logf("dnsmasq's lease file: %s %s %s", got.addr, got.mac, got.hostname)

	if n := c.Hostname(); n != hostnameLateName {
		t.Fatalf("the client reports the name %q", n)
	}

	// A second call with the same name is not a second exchange. Asserted
	// against the server's count, which cannot be satisfied by a counter this
	// library maintains.
	acks := srv.count("DHCPACK(" + testServerIf + ")")
	if err := c.SetHostname(hostnameLateName); err != nil {
		t.Fatalf("the second SetHostname: %v", err)
	}
	if err := c.SetHostname(hostnameLateName); err != nil {
		t.Fatalf("the third SetHostname: %v", err)
	}
	// Drain the request queue by asking for something the client does answer,
	// so the two calls above have demonstrably been stepped before the count is
	// read again. Reading it straight away would pass on a manager that had not
	// looked at them yet.
	drainBarrier(t, c)
	if now := srv.count("DHCPACK(" + testServerIf + ")"); now != acks {
		t.Fatalf("two further SetHostname calls with the same name produced %d more exchanges, want 0",
			now-acks)
	}

	cancel()
	<-runErr
}

// waitLeaseHostname spins until the server's lease file carries want.
//
// It POLLS for readDnsmasqLeases's reason: dnsmasq logs the DHCPACK from its
// reply path and writes the file from its main loop, so the log line does not
// order the write. A sleep would be a guess about that gap; a spin is the same
// guess with the guess removed, and go test's own timeout is the bound.
func waitLeaseHostname(t *testing.T, path, want string) dnsmasqLease {
	t.Helper()
	for {
		got, err := parseDnsmasqLeases(path)
		if err == nil {
			for _, l := range got {
				if l.hostname == want {
					return l
				}
			}
		}
		goruntime.Gosched()
	}
}

// drainBarrier makes the client's request queue demonstrably empty: it asks for
// a name the client is already sending, which the machine steps and answers
// with nothing, and then waits for that step to appear in the journal.
//
// The point is the ORDER. Reading the server's exchange count straight after a
// SetHostname would read it before the manager had looked at the request, so a
// client that DID send a redundant renewal would pass.
func drainBarrier(t *testing.T, c *Client) {
	t.Helper()
	before := len(c.Journal())
	if err := c.SetHostname(hostnameLateName); err != nil {
		t.Fatalf("the barrier SetHostname: %v", err)
	}
	for {
		es := c.Journal()
		if len(es) > before {
			for _, e := range es[before:] {
				if e.Kind == proto.EvSetHostname {
					return
				}
			}
			before = len(es)
		}
		goruntime.Gosched()
	}
}
