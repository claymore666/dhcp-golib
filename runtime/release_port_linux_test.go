// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

//go:build linux

package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/claymore666/dhcp-golib/lease"
)

// holdClientPort binds addr the way a host DHCP client holds its port: with
// SO_REUSEADDR when reuse is set, and pinned to dev when dev is named
// (claymore666/dhcp-golib#89).
func holdClientPort(t *testing.T, network, addr, dev string, reuse bool) net.PacketConn {
	t.Helper()
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var opErr error
		if err := c.Control(func(fd uintptr) {
			if reuse {
				opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			}
			if opErr == nil && dev != "" {
				opErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, dev)
			}
		}); err != nil {
			return err
		}
		return opErr
	}}
	pc, err := lc.ListenPacket(context.Background(), network, addr)
	if err != nil {
		t.Fatalf("the host client's socket on %s (device %q, reuse %v): %v", addr, dev, reuse, err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc
}

func TestAReleaseLeavesWhileAHostClientHoldsTheClientPort(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		releaseBesideAHostClient(t)
		return
	}
	reexecInNamespaces(t)
}

func releaseBesideAHostClient(t *testing.T) {
	started := time.Now()

	mustRun(t, "ip", "link", "add", testClientIf, "type", "veth", "peer", "name", testServerIf)
	mustRun(t, "ip", "addr", "add", testServerIP+"/24", "dev", testServerIf)
	mustRun(t, "ip", "link", "set", testServerIf, "up")
	mustRun(t, "ip", "link", "set", testClientIf, "up")
	mustRun(t, "ip", "link", "set", "lo", "up")
	relAcceptLocal(t, testServerIf)
	mustRun(t, "ip", "addr", "add", relHostAddr4+"/24", "dev", testClientIf)

	srv := startDnsmasq(t)

	plain, _ := relAcquire(t, relNeighbourMAC, nil)
	addr := plain.Addr.Addr()
	rec := lease.Record{
		ID: "rec-port-held", Scope: "net-a", Family: lease.FamilyV4,
		CHAddr: append([]byte(nil), relNeighbourMAC...),
		Lease:  plain,
	}
	cfg := ReleaseConfig{Interface: testClientIf, Source: netip.MustParseAddr(relHostAddr4)}

	// Both shapes a host client holds port 68 in: the wildcard, and the
	// link's own address pinned to the link.
	wild := holdClientPort(t, "udp4", fmt.Sprintf("0.0.0.0:%d", ClientPort), "", true)
	own := holdClientPort(t, "udp4", fmt.Sprintf("%s:%d", relHostAddr4, ClientPort), testClientIf, true)

	if err := SendRelease(rec, cfg); err != nil {
		t.Fatalf("SendRelease beside a host client on port %d: %v", ClientPort, err)
	}
	line := "DHCPRELEASE(" + testServerIf + ") " + addr.String()
	srv.waitFor(t, line)
	if relLineHas(srv, line, "unknown lease") {
		t.Fatalf("dnsmasq refused the release of %s as an unknown lease.\nLog:\n%s",
			addr, strings.Join(srv.lines(), "\n"))
	}
	relWaitGone(t, srv.leasefile, addr)
	t.Logf("dnsmasq closed %s while two sockets of a host client held port %d", addr, ClientPort)

	// A holder that does not share the port still refuses, and the refusal
	// comes back rather than a release reported as sent.
	_ = wild.Close()
	_ = own.Close()
	holdClientPort(t, "udp4", fmt.Sprintf("%s:%d", relHostAddr4, ClientPort), testClientIf, false)
	again, _ := relAcquire(t, relNeighbourMAC, nil)
	rec.Lease = again
	if err := SendRelease(rec, cfg); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("SendRelease beside a holder that does not share port %d returned %v, want EADDRINUSE", ClientPort, err)
	}

	relAssertLifetimeMargin(t, started, testLeaseSec)
}

func TestAV6ReleaseLeavesWhileAHostClientHoldsTheClientPort(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		v6ReleaseBesideAHostClient(t)
		return
	}
	reexecInNamespaces(t)
}

func v6ReleaseBesideAHostClient(t *testing.T) {
	src := netip.MustParseAddr(zoneSrc)
	zoneLink(t, zoneCliIf, zoneSrvIf)
	w := newReleaseWatch(t, zoneSrvIf)

	holdClientPort(t, "udp6", fmt.Sprintf("[::]:%d", ClientPort6), "", true)
	holdClientPort(t, "udp6", fmt.Sprintf("[%s%%%s]:%d", zoneSrc, zoneCliIf, ClientPort6), zoneCliIf, true)

	want, err := zoneSend(t, src, zoneCliIf, 89)
	if err != nil {
		t.Fatalf("SendRelease beside a host client on port %d: %v", ClientPort6, err)
	}
	expectRelease(t, "beside a host client on port 546", w, nil, want)
}
