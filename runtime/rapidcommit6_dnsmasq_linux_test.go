// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

//go:build linux

package runtime

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/claymore666/dhcp-golib/lease"
	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

// Runtime half of claymore666/docker-net-dhcp#926. The outcome is the lease the
// client reports and the order of the DHCP lines in dnsmasq's own log; the
// library's counters are not consulted. dnsmasq 2.91 answers every Solicit that
// carries option 14 with a Reply and logs no DHCPADVERTISE and no DHCPREQUEST
// (rfc3315.c 644-650, read 2026-10-01). Its --dhcp-rapid-commit flag is the
// DHCPv4 switch and decides nothing on DHCPv6, so the client's own setting is
// the only thing that picks the exchange here.

const rc6RenameTo = "renamed-after-rapid"

var rc6Line = regexp.MustCompile(`DHCP(SOLICIT|ADVERTISE|REQUEST|REPLY|RENEW|REBIND|CONFIRM|RELEASE|DECLINE)\(` + test6ServerIf + `\)`)

// rc6Kinds is the order of the DHCPv6 message kinds dnsmasq logged on the link.
func rc6Kinds(lines []string) []string {
	var kinds []string
	for _, l := range lines {
		if m := rc6Line.FindStringSubmatch(l); m != nil {
			kinds = append(kinds, m[1])
		}
	}
	return kinds
}

type rc6Run struct {
	srv    *dnsmasqServer
	client *Client6
	stop   func()
	addr   string
}

// rc6Start builds the link, dnsmasq as a managed DHCPv6 server, and a client
// with Params6.RapidCommit as given, and returns once the client holds a lease
// (claymore666/docker-net-dhcp#926).
func rc6Start(t *testing.T, rapid bool) *rc6Run {
	t.Helper()
	wireUpV6(t)
	srv := startDnsmasq6(t, v6Managed)
	c, _ := newV6ClientWith(t, func(p *proto.Params6) { p.RapidCommit = rapid })
	stop := runV6Client(t, c)
	t.Cleanup(stop)
	ev := awaitV6(t, c, lease.Acquired)
	addr := ev.Lease.Addr.Addr().String()
	srv.waitFor(t, "DHCPREPLY("+test6ServerIf+") "+addr)
	return &rc6Run{srv: srv, client: c, stop: stop, addr: addr}
}

// sent returns the client's captured outbound messages of one type.
func (r *rc6Run) sent(mt wire.MessageTypeV6) []*wire.MessageV6 {
	var out []*wire.MessageV6
	for _, p := range r.client.Packets() {
		if p.Dir == lease.DirOut && p.Msg != nil && p.Msg.Type == mt {
			out = append(out, p.Msg)
		}
	}
	return out
}

func (r *rc6Run) wantKinds(t *testing.T, want ...string) {
	t.Helper()
	if got := rc6Kinds(r.srv.lines()); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("dnsmasq logged the exchange %v, want %v.\nLog:\n%s", got, want, strings.Join(r.srv.lines(), "\n"))
	}
}

// TestAV6ClientThatAsksForRapidCommitGetsTheTwoMessageLease: dnsmasq answers
// the Solicit carrying option 14 with the Reply. Its log has DHCPSOLICIT and
// DHCPREPLY and no DHCPADVERTISE and no DHCPREQUEST, the assertion a run in
// which the exchange took four messages cannot pass
// (claymore666/docker-net-dhcp#926).
func TestAV6ClientThatAsksForRapidCommitGetsTheTwoMessageLease(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		r := rc6Start(t, true)
		r.wantKinds(t, "SOLICIT", "REPLY")
		for _, k := range []string{"DHCPADVERTISE(", "DHCPREQUEST("} {
			if n := r.srv.count(k); n != 0 {
				t.Errorf("dnsmasq logged %d %s line(s) for a two-message lease", n, k)
			}
		}
		if n := len(r.sent(wire.MsgRequest6)); n != 0 {
			t.Errorf("the client sent %d Request(s) for a two-message lease", n)
		}
		solicits := r.sent(wire.MsgSolicit)
		if len(solicits) == 0 {
			t.Fatal("the client captured no Solicit")
		}
		if n := solicits[0].Options.Count(wire.OptV6RapidCommit); n != 1 {
			t.Errorf("the client's Solicit carries %d option 14, want 1", n)
		}
		if l, ok := r.client.Lease(); !ok || l.Addr.Addr().String() != r.addr {
			t.Errorf("the client reports the lease %+v (held %v), want %s", l, ok, r.addr)
		}
		return
	}
	reexecInNamespaces(t)
}

// TestAV6ClientThatDoesNotAskGetsTheFourMessageExchangeFromTheSameDnsmasq is
// the control: the same server, Params6.RapidCommit false. dnsmasq needs
// option 14 in the Solicit, so the log has all four lines and the Solicit has
// no option 14 (claymore666/docker-net-dhcp#926).
func TestAV6ClientThatDoesNotAskGetsTheFourMessageExchangeFromTheSameDnsmasq(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		r := rc6Start(t, false)
		r.wantKinds(t, "SOLICIT", "ADVERTISE", "REQUEST", "REPLY")
		for _, m := range r.sent(wire.MsgSolicit) {
			if n := m.Options.Count(wire.OptV6RapidCommit); n != 0 {
				t.Errorf("a client with RapidCommit false sent option 14 (%d)", n)
			}
		}
		return
	}
	reexecInNamespaces(t)
}

// TestARenewAfterARapidV6LeaseCarriesNoOption14: after the two-message lease a
// renewal is an ordinary Renew and Reply. The SOLICIT count in dnsmasq's log
// does not move, and no Renew the client sent carries option 14
// (claymore666/docker-net-dhcp#926).
func TestARenewAfterARapidV6LeaseCarriesNoOption14(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		r := rc6Start(t, true)
		r.wantKinds(t, "SOLICIT", "REPLY")
		solicits := r.srv.count("DHCPSOLICIT(")
		replies := r.srv.count("DHCPREPLY(")

		// A new hostname makes a bound client Renew now (RFC 4704).
		if err := r.client.SetHostname(rc6RenameTo); err != nil {
			t.Fatalf("SetHostname: %v", err)
		}
		awaitV6(t, r.client, lease.Renewed)
		r.srv.waitCount(t, "DHCPRENEW("+test6ServerIf+")", 1, "the renewal never reached the server")
		r.srv.waitCount(t, "DHCPREPLY(", replies+1, "the server never answered the renewal")
		if got := r.srv.count("DHCPSOLICIT("); got != solicits {
			t.Fatalf("the server logged %d DHCPSOLICIT lines, %d before the renewal: a re-acquisition, not a renewal.\nLog:\n%s",
				got, solicits, strings.Join(r.srv.lines(), "\n"))
		}
		r.wantKinds(t, "SOLICIT", "REPLY", "RENEW", "REPLY")
		renews := r.sent(wire.MsgRenew)
		if len(renews) == 0 {
			t.Fatal("the client captured no Renew, so there is nothing to read option 14 from")
		}
		for i, m := range renews {
			if n := m.Options.Count(wire.OptV6RapidCommit); n != 0 {
				t.Errorf("Renew %d carries %d option 14", i, n)
			}
		}
		return
	}
	reexecInNamespaces(t)
}
