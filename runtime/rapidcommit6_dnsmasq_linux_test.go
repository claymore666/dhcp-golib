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

// rc6Kinds is the order of the DHCPv6 message kinds dnsmasq logged on the link
// (claymore666/docker-net-dhcp#926).
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

// sent returns the client's captured outbound messages of one type (claymore666/docker-net-dhcp#926).
func (r *rc6Run) sent(mt wire.MessageTypeV6) []*wire.MessageV6 {
	var out []*wire.MessageV6
	for _, p := range r.client.Packets() {
		if p.Dir == lease.DirOut && p.Msg != nil && p.Msg.Type == mt {
			out = append(out, p.Msg)
		}
	}
	return out
}

// kinds is the order of the message kinds dnsmasq has logged so far
// (claymore666/docker-net-dhcp#926).
func (r *rc6Run) kinds() []string { return rc6Kinds(r.srv.lines()) }

// rc6Index is where a kind first appears in the log, or -1 (claymore666/docker-net-dhcp#926).
func rc6Index(kinds []string, kind string) int {
	for i, k := range kinds {
		if k == kind {
			return i
		}
	}
	return -1
}

// onlyKinds fails when dnsmasq logged a kind outside the allowed ones. A
// Solicit the client repeated before its first answer is allowed to repeat; a
// kind that must be absent stays absent, whatever the repeats
// (claymore666/docker-net-dhcp#926).
func (r *rc6Run) onlyKinds(t *testing.T, allowed ...string) {
	t.Helper()
	for _, k := range r.kinds() {
		if rc6Index(allowed, k) < 0 {
			t.Fatalf("dnsmasq logged a %s the exchange must not have.\nLog:\n%s", k, strings.Join(r.srv.lines(), "\n"))
		}
	}
}

// inOrder fails unless the kinds appear in the log as a subsequence, each after
// the first appearance of the one before it (claymore666/docker-net-dhcp#926).
func (r *rc6Run) inOrder(t *testing.T, want ...string) {
	t.Helper()
	got, from := r.kinds(), 0
	for _, w := range want {
		i := rc6Index(got[from:], w)
		if i < 0 {
			t.Fatalf("dnsmasq's log has no %s after %v in %v, want the order %v.\nLog:\n%s", w, want[:from], got, want, strings.Join(r.srv.lines(), "\n"))
		}
		from += i + 1
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
		// At least a Solicit and the Reply that leased; a repeated Solicit is
		// allowed, an Advertise and a Request are not (claymore666/docker-net-dhcp#926).
		r.onlyKinds(t, "SOLICIT", "REPLY")
		r.inOrder(t, "SOLICIT", "REPLY")
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
		r.onlyKinds(t, "SOLICIT", "ADVERTISE", "REQUEST", "REPLY")
		r.inOrder(t, "SOLICIT", "ADVERTISE", "REQUEST", "REPLY")
		if got := r.kinds(); rc6Index(got, "REPLY") < rc6Index(got, "REQUEST") {
			t.Errorf("dnsmasq sent a Reply before any Request: %v", got)
		}
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
		r.onlyKinds(t, "SOLICIT", "REPLY")
		r.inOrder(t, "SOLICIT", "REPLY")
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
		// The renewal is a Renew and a Reply after the lease, with no new
		// Solicit, Advertise or Request (claymore666/docker-net-dhcp#926).
		r.onlyKinds(t, "SOLICIT", "REPLY", "RENEW")
		r.inOrder(t, "SOLICIT", "REPLY", "RENEW", "REPLY")
		for _, k := range []string{"DHCPADVERTISE(", "DHCPREQUEST("} {
			if n := r.srv.count(k); n != 0 {
				t.Errorf("dnsmasq logged %d %s line(s) around a renewal", n, k)
			}
		}
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
