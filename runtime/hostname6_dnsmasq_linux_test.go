// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

//go:build linux

package runtime

import (
	"os"
	"strings"
	"testing"

	"github.com/claymore666/dhcp-golib/lease"
	"github.com/claymore666/dhcp-golib/proto"
)

// TestAV6HostnameSetAfterStartReachesTheServersLeaseFile is
// claymore666/docker-net-dhcp#1029 measured in the server's own table: dnsmasq
// 2.91 writes "*" in the v6 lease line's name column until a client sends
// option 39, then the name (MEASURED 2026-09-24).
func TestAV6HostnameSetAfterStartReachesTheServersLeaseFile(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		runLateHostname6AgainstDnsmasq(t)
		return
	}
	reexecInNamespaces(t)
}

func runLateHostname6AgainstDnsmasq(t *testing.T) {
	wireUpV6(t)
	srv := startDnsmasq6(t, v6Managed)

	c, _ := newV6Client(t)
	stop := runV6Client(t, c)
	defer stop()
	acq := awaitV6(t, c, lease.Acquired)
	leased := acq.Lease.Addr.Addr()

	before := relWaitLease(t, srv.leasefile, leased)
	if before.hostname != "*" {
		t.Fatalf("dnsmasq already records the name %q for %s; this test would measure nothing", before.hostname, leased)
	}

	if err := c.SetHostname(hostnameLateName); err != nil {
		t.Fatalf("SetHostname: %v", err)
	}
	renewed := awaitV6(t, c, lease.Renewed)
	srv.waitFor(t, "DHCPRENEW("+test6ServerIf+")")

	got := waitLeaseHostname(t, srv.leasefile, hostnameLateName)
	if got.addr != leased {
		t.Fatalf("the server recorded %q against %s, but this client holds %s", hostnameLateName, got.addr, leased)
	}
	// RFC 4704 section 6: the server returns option 39 with the flags it set.
	if !renewed.Lease.HasFQDN || !strings.HasPrefix(renewed.Lease.FQDN.Name, hostnameLateName) {
		t.Fatalf("the renewed lease reports %v %+v, want the server's option 39 naming %q",
			renewed.Lease.HasFQDN, renewed.Lease.FQDN, hostnameLateName)
	}
	t.Logf("dnsmasq's lease file: %s %s; its option 39: flags %#02x name %q",
		got.addr, got.hostname, renewed.Lease.FQDN.Flags, renewed.Lease.FQDN.Name)
	if n := c.Hostname(); n != hostnameLateName {
		t.Fatalf("the client reports the name %q", n)
	}

	// The same name again is no exchange, counted on the server's log after a
	// barrier the journal shows was stepped.
	renews := srv.count("DHCPRENEW(" + test6ServerIf + ")")
	for i := 0; i < 3; i++ {
		if err := c.SetHostname(hostnameLateName); err != nil {
			t.Fatalf("SetHostname again: %v", err)
		}
	}
	drainBarrier6(t, c, 3)
	if now := srv.count("DHCPRENEW(" + test6ServerIf + ")"); now != renews {
		t.Fatalf("three further SetHostname calls with the same name produced %d more Renews, want 0", now-renews)
	}
}

// drainBarrier6 waits until the journal holds n more EvSetHostname steps.
func drainBarrier6(t *testing.T, c *Client6, n int) {
	t.Helper()
	seen := 0
	start := len(c.Journal())
	for seen < n {
		es := c.Journal()
		seen = 0
		for _, e := range es[start:] {
			if e.Kind == proto.EvSetHostname {
				seen++
			}
		}
		relPoll()
	}
}
