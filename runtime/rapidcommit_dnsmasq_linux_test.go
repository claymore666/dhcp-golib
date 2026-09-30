// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

//go:build linux

package runtime

import (
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/claymore666/dhcp-golib/lease"
	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

// Runtime half of claymore666/docker-net-dhcp#1031. The outcome is the lease the
// client reports and the order of the DHCP lines in dnsmasq's own log. dnsmasq
// 2.91 answers a DISCOVER that carries option 80 with an ACK only when started
// with --dhcp-rapid-commit, and then logs no DHCPOFFER and no DHCPREQUEST
// (rfc2131.c 1176-1185 and 1544, read 2026-09-30). The library's counters are
// not consulted.

var rapidLine = regexp.MustCompile(`DHCP(DISCOVER|OFFER|REQUEST|ACK)\(` + testServerIf + `\)`)

// rapidKinds is the order of the DHCP message kinds dnsmasq logged on the link.
func rapidKinds(lines []string) []string {
	var kinds []string
	for _, l := range lines {
		if m := rapidLine.FindStringSubmatch(l); m != nil {
			kinds = append(kinds, m[1])
		}
	}
	return kinds
}

type rapidRun struct {
	srv       *dnsmasqServer
	client    *Client
	acquired  lease.Event
	mac       string
	cancel    context.CancelFunc
	runErr    chan error
	exchanged int
}

// startRapid builds the link, a dnsmasq with extra flags, and a client with
// Params.RapidCommit set as given, and returns once the client holds a lease
// (claymore666/docker-net-dhcp#1031). Permanent neighbour entries cover the
// pool, for renewalAgainstDnsmasq's reason: the renewal ACK is unicast to an
// address nothing here owns.
func startRapid(t *testing.T, serverRapid, clientRapid bool) *rapidRun {
	t.Helper()
	mustRun(t, "ip", "link", "add", testClientIf, "type", "veth", "peer", "name", testServerIf)
	mustRun(t, "ip", "addr", "add", testServerIP+"/24", "dev", testServerIf)
	mustRun(t, "ip", "link", "set", testServerIf, "up")
	mustRun(t, "ip", "link", "set", testClientIf, "up")
	iface, err := net.InterfaceByName(testClientIf)
	if err != nil {
		t.Fatalf("InterfaceByName(%s): %v", testClientIf, err)
	}
	mac := iface.HardwareAddr.String()
	for _, a := range addrRange(t, testRenewLo, testRenewHi) {
		mustRun(t, "ip", "neigh", "replace", a, "lladdr", mac, "dev", testServerIf, "nud", "permanent")
	}
	extra := []string{"--dhcp-option=58," + fmt.Sprint(testRenewSec)}
	if serverRapid {
		extra = append(extra, "--dhcp-rapid-commit")
	}
	srv := startDnsmasqCfg(t, dnsmasqConfig{rangeLo: testRenewLo, rangeHi: testRenewHi, extra: extra})

	params := proto.DefaultParams(iface.HardwareAddr)
	params.DesyncMin, params.DesyncMax = 0, 0
	// Async and the brisk table, for dnsmasq_linux_test.go's reason: the
	// subject is the exchange, not RFC 5227's schedule
	// (claymore666/docker-net-dhcp#1031).
	params.Conflict = proto.ConflictAsync
	params.ACD = briskACD()
	params.RapidCommit = clientRapid

	c, err := NewClient(ClientConfig{Interface: testClientIf, Params: params, EventBuffer: 8})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &rapidRun{srv: srv, client: c, mac: mac, cancel: cancel, runErr: make(chan error, 1)}
	go func() { r.runErr <- c.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-r.runErr
	})
	r.acquired = awaitAcquired(t, c)
	leased := r.acquired.Lease.Addr.Addr().String()
	if !inRange(leased, testRenewLo, testRenewHi) {
		t.Fatalf("leased %s, outside the pool %s..%s", leased, testRenewLo, testRenewHi)
	}
	srv.waitFor(t, "DHCPACK("+testServerIf+") "+leased+" "+mac)
	return r
}

// sent returns the client's captured outbound DHCP messages of one type.
func (r *rapidRun) sent(mt wire.MessageType) []*wire.Message {
	var out []*wire.Message
	for _, p := range r.client.Packets() {
		if p.Dir != lease.DirOut || p.Msg == nil {
			continue
		}
		if got, ok := p.Msg.Type(); ok && got == mt {
			out = append(out, p.Msg)
		}
	}
	return out
}

func (r *rapidRun) wantKinds(t *testing.T, want ...string) {
	t.Helper()
	if got := rapidKinds(r.srv.lines()); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("dnsmasq logged the exchange %v, want %v.\nLog:\n%s", got, want, strings.Join(r.srv.lines(), "\n"))
	}
}

// TestRapidCommitTakesTheTwoMessageLeaseFromDnsmasq: dnsmasq with
// --dhcp-rapid-commit answers the DISCOVER with the ACK. The log has
// DHCPDISCOVER and DHCPACK and no DHCPREQUEST, which is the assertion a run in
// which dnsmasq answered the four-message way cannot pass
// (claymore666/docker-net-dhcp#1031).
func TestRapidCommitTakesTheTwoMessageLeaseFromDnsmasq(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		r := startRapid(t, true, true)
		r.wantKinds(t, "DISCOVER", "ACK")
		for _, k := range []string{"DHCPOFFER(", "DHCPREQUEST("} {
			if n := r.srv.count(k); n != 0 {
				t.Errorf("dnsmasq logged %d %s line(s) for a two-message lease", n, k)
			}
		}
		if n := len(r.sent(wire.MsgRequest)); n != 0 {
			t.Errorf("the client sent %d REQUEST(s) for a two-message lease", n)
		}
		discovers := r.sent(wire.MsgDiscover)
		if len(discovers) == 0 {
			t.Fatal("the client captured no DISCOVER")
		}
		if _, ok := discovers[0].Options[wire.OptRapidCommit]; !ok {
			t.Error("the client's DISCOVER carries no option 80")
		}
		l := r.acquired.Lease
		if l.Expire.Sub(l.Acquired) <= 0 || l.ServerID.String() != testServerIP {
			t.Errorf("the lease event is %+v, want a lease from %s", l, testServerIP)
		}
		return
	}
	reexecInNamespaces(t)
}

// TestADnsmasqWithoutRapidCommitAnswersAClientThatAsksInFourMessages: RFC 4039
// section 3's fallback. The client sends option 80, the server does not allow
// it and sends an OFFER, and the lease comes from the REQUEST and the ACK
// (claymore666/docker-net-dhcp#1031).
func TestADnsmasqWithoutRapidCommitAnswersAClientThatAsksInFourMessages(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		r := startRapid(t, false, true)
		r.wantKinds(t, "DISCOVER", "OFFER", "REQUEST", "ACK")
		discovers := r.sent(wire.MsgDiscover)
		if len(discovers) == 0 {
			t.Fatal("the client captured no DISCOVER")
		}
		if _, ok := discovers[0].Options[wire.OptRapidCommit]; !ok {
			t.Error("the client's DISCOVER carries no option 80, so this run is not the fallback")
		}
		for _, m := range r.sent(wire.MsgRequest) {
			if _, ok := m.Options[wire.OptRapidCommit]; ok {
				t.Error("the client's REQUEST carries option 80")
			}
		}
		return
	}
	reexecInNamespaces(t)
}

// TestAClientThatDoesNotAskGetsTheFourMessageExchangeFromARapidCommitServer is
// the control for the two-message run: the same server with --dhcp-rapid-commit
// and a client with Params.RapidCommit false. dnsmasq needs option 80 in the
// DISCOVER, so the log has all four lines and the DISCOVER has no option 80
// (claymore666/docker-net-dhcp#1031).
func TestAClientThatDoesNotAskGetsTheFourMessageExchangeFromARapidCommitServer(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		r := startRapid(t, true, false)
		r.wantKinds(t, "DISCOVER", "OFFER", "REQUEST", "ACK")
		for _, m := range r.sent(wire.MsgDiscover) {
			if _, ok := m.Options[wire.OptRapidCommit]; ok {
				t.Error("a client with RapidCommit false sent option 80")
			}
		}
		return
	}
	reexecInNamespaces(t)
}

// TestARenewalAfterARapidLeaseCarriesNoOption80: after the two-message lease
// the renewal is an ordinary REQUEST and ACK, the DISCOVER count in
// dnsmasq's log does not move, and no REQUEST the client sent carries option
// 80 (claymore666/docker-net-dhcp#1031).
func TestARenewalAfterARapidLeaseCarriesNoOption80(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		r := startRapid(t, true, true)
		r.wantKinds(t, "DISCOVER", "ACK")
		leased := r.acquired.Lease.Addr.Addr().String()
		discovers := r.srv.count("DHCPDISCOVER(")
		requests := r.srv.count("DHCPREQUEST(" + testServerIf + ") " + leased)
		acks := r.srv.count("DHCPACK(" + testServerIf + ") " + leased)

		renewed := awaitEvent(t, r.client, lease.Renewed)
		if renewed.Lease.Addr != r.acquired.Lease.Addr {
			t.Fatalf("renewed onto %s, want %s", renewed.Lease.Addr, r.acquired.Lease.Addr)
		}
		r.srv.waitCount(t, "DHCPREQUEST("+testServerIf+") "+leased, requests+1, "the renewal never reached the server")
		r.srv.waitCount(t, "DHCPACK("+testServerIf+") "+leased, acks+1, "the server never answered the renewal")
		if got := r.srv.count("DHCPDISCOVER("); got != discovers {
			t.Fatalf("the server logged %d DHCPDISCOVER lines, %d before the renewal: a re-acquisition, not a renewal.\nLog:\n%s",
				got, discovers, strings.Join(r.srv.lines(), "\n"))
		}
		reqs := r.sent(wire.MsgRequest)
		if len(reqs) == 0 {
			t.Fatal("the client captured no REQUEST, so there is nothing to read option 80 from")
		}
		for i, m := range reqs {
			if _, ok := m.Options[wire.OptRapidCommit]; ok {
				t.Errorf("REQUEST %d carries option 80", i)
			}
		}
		return
	}
	reexecInNamespaces(t)
}
