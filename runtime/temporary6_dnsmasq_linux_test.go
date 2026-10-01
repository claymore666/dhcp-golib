// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE (claymore666/docker-net-dhcp#927).

//go:build linux

package runtime

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/claymore666/dhcp-golib/lease"
	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

// Runtime half of claymore666/docker-net-dhcp#927. The outcome is the lease the
// client reports and the lines of dnsmasq's own log; the library's counters are
// not consulted. dnsmasq 2.91 draws a temporary address from the same range as
// the stable one, at a random start, so the fixture range is wider than 2^32
// addresses: two draws from a small range collide and a collision would read as
// a client that confused the two IAs.

const (
	ta6RangeLo = "fd00:99::1000"
	ta6RangeHi = "fd00:99::1:0:1000"
	ta6Rename  = "renamed-after-ta"
)

// ta6Wide is v6Managed with a range of 2^32 + 1 addresses
// (claymore666/docker-net-dhcp#927).
var ta6Wide = v6Mode{
	name:       "managed-wide",
	args:       []string{"--dhcp-range=" + ta6RangeLo + "," + ta6RangeHi + ",64," + fmt.Sprint(test6LeaseSec), "--enable-ra"},
	ready:      "DHCPv6, IP range " + ta6RangeLo,
	absent:     []string{"DHCPv6 stateless on"},
	advertises: true, managed: true, other: true, autonomous: false,
	serves: true,
}

type ta6Run struct {
	srv    *dnsmasqServer
	client *Client6
	ev     lease.Event
}

// ta6Start builds the link, dnsmasq with the wide range and a client with
// Params6.Temporary as given, and returns once the client holds a lease
// (claymore666/docker-net-dhcp#927).
func ta6Start(t *testing.T, temporary bool) *ta6Run {
	t.Helper()
	wireUpV6(t)
	srv := startDnsmasq6(t, ta6Wide)
	c, _ := newV6ClientWith(t, func(p *proto.Params6) { p.Temporary = temporary })
	stop := runV6Client(t, c)
	t.Cleanup(stop)
	ev := awaitV6(t, c, lease.Acquired)
	srv.waitFor(t, "DHCPREPLY("+test6ServerIf+") "+ev.Lease.Addr.Addr().String())
	return &ta6Run{srv: srv, client: c, ev: ev}
}

func (r *ta6Run) packets(dir lease.Direction, mt wire.MessageTypeV6) []*wire.MessageV6 {
	var out []*wire.MessageV6
	for _, p := range r.client.Packets() {
		if p.Dir == dir && p.Msg != nil && p.Msg.Type == mt {
			out = append(out, p.Msg)
		}
	}
	return out
}

// ta6Sent is the number of IA_TA options dnsmasq logged as sent
// (claymore666/docker-net-dhcp#927).
func (r *ta6Run) ta6Sent() int { return r.srv.count("ia-ta") }

// ta6Temp is the one temporary address of the lease the client reports, and
// fails the test when there is not exactly one (claymore666/docker-net-dhcp#927).
func ta6Temp(t *testing.T, l lease.Lease) netip.Addr {
	t.Helper()
	if len(l.TempAddrs) != 1 {
		t.Fatalf("the client reports %d temporary addresses, want 1: %+v", len(l.TempAddrs), l)
	}
	return l.TempAddrs[0].Addr.Addr()
}

// TestAV6ClientThatAsksForTemporaryAddressesGetsOneFromRealDnsmasq: the lease
// holds a stable address and, beside it, a distinct temporary one from the
// range, and dnsmasq's log shows the IA_TA it granted and the same address in
// the Reply (claymore666/docker-net-dhcp#927).
func TestAV6ClientThatAsksForTemporaryAddressesGetsOneFromRealDnsmasq(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		r := ta6Start(t, true)
		l := r.ev.Lease
		stable, temp := l.Addr.Addr(), ta6Temp(t, l)
		if stable == temp {
			t.Fatalf("the stable and the temporary address are both %s", stable)
		}
		lo, hi := netip.MustParseAddr(ta6RangeLo), netip.MustParseAddr(ta6RangeHi)
		for name, a := range map[string]netip.Addr{"stable": stable, "temporary": temp} {
			if a.Compare(lo) < 0 || a.Compare(hi) > 0 {
				t.Errorf("the %s address %s is outside the range %s to %s", name, a, lo, hi)
			}
		}
		if len(l.Addrs) != 1 || l.Addrs[0].Addr.Addr() != stable {
			t.Errorf("Addrs = %+v, want the stable address alone", l.Addrs)
		}
		if !l.TempAddrs[0].Valid.After(l.Acquired) {
			t.Errorf("the temporary address has no valid lifetime: %+v", l.TempAddrs[0])
		}

		// dnsmasq's own words: it granted an IA_TA, with the temporary address
		// in it, in the Advertise and in the Reply (claymore666/docker-net-dhcp#927).
		r.srv.waitFor(t, "iaaddr  "+temp.String())
		r.srv.waitFor(t, "DHCPREPLY("+test6ServerIf+") "+temp.String())
		if n := r.ta6Sent(); n < 2 {
			t.Errorf("dnsmasq logged %d ia-ta option(s) sent, want one in the Advertise and one in the Reply.\nLog:\n%s", n, strings.Join(r.srv.lines(), "\n"))
		}

		// The client's own messages: the Solicit asks, and the Request repeats
		// what the Advertise offered (claymore666/docker-net-dhcp#927).
		solicit := r.packets(lease.DirOut, wire.MsgSolicit)
		if len(solicit) == 0 || solicit[0].Options.Count(wire.OptV6IATA) != 1 {
			t.Fatalf("the Solicit does not carry one IA_TA: %v", solicit)
		}
		request := r.packets(lease.DirOut, wire.MsgRequest6)
		if len(request) == 0 {
			t.Fatal("the client captured no Request")
		}
		tas, err := request[0].Options.IATAs()
		if err != nil || len(tas) != 1 {
			t.Fatalf("the Request's IA_TAs = %v, %v, want one", tas, err)
		}
		if got, _ := tas[0].Options.Addrs(); len(got) != 1 || got[0].Addr != temp {
			t.Errorf("the Request's IA_TA names %v, want the advertised %s", got, temp)
		}
		return
	}
	reexecInNamespaces(t)
}

// TestAV6ClientThatDoesNotAskGetsNoTemporaryAddress is the control: the same
// server, Params6.Temporary false. The client sends no IA_TA, dnsmasq logs none
// sent, and the lease has no temporary address (claymore666/docker-net-dhcp#927).
func TestAV6ClientThatDoesNotAskGetsNoTemporaryAddress(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		r := ta6Start(t, false)
		if l := r.ev.Lease; len(l.TempAddrs) != 0 {
			t.Errorf("the client reports temporary addresses %+v it did not ask for", l.TempAddrs)
		}
		if n := r.ta6Sent(); n != 0 {
			t.Errorf("dnsmasq logged %d ia-ta option(s) sent to a client that never asked.\nLog:\n%s", n, strings.Join(r.srv.lines(), "\n"))
		}
		for _, mt := range []wire.MessageTypeV6{wire.MsgSolicit, wire.MsgRequest6} {
			for _, m := range r.packets(lease.DirOut, mt) {
				if n := m.Options.Count(wire.OptV6IATA); n != 0 {
					t.Errorf("a %v the client sent carries %d IA_TA", mt, n)
				}
			}
		}
		return
	}
	reexecInNamespaces(t)
}

// TestARenewalLeavesTheTemporaryAddressAlone: a Renew asks for no temporary
// address and dnsmasq answers with none (RFC 8415 section 13.2). The count of
// ia-ta options dnsmasq logged as sent does not move across the renewal, the
// Reply the client decoded has no IA_TA, and the lease still holds the
// temporary address it had (claymore666/docker-net-dhcp#927).
func TestARenewalLeavesTheTemporaryAddressAlone(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		r := ta6Start(t, true)
		temp := ta6Temp(t, r.ev.Lease)
		stable := r.ev.Lease.Addr.Addr()
		before, replies := r.ta6Sent(), r.srv.count("DHCPREPLY(")
		if before < 2 {
			t.Fatalf("the grant logged %d ia-ta option(s) sent, want at least 2", before)
		}

		// A new hostname makes a bound client Renew now (RFC 4704) (claymore666/docker-net-dhcp#927).
		if err := r.client.SetHostname(ta6Rename); err != nil {
			t.Fatalf("SetHostname: %v", err)
		}
		renewed := awaitV6(t, r.client, lease.Renewed)
		r.srv.waitCount(t, "DHCPRENEW("+test6ServerIf+")", 1, "the renewal never reached the server")
		r.srv.waitCount(t, "DHCPREPLY(", replies+1, "the server never answered the renewal")
		if got := r.srv.count("DHCPSOLICIT("); got != 1 {
			t.Fatalf("the server logged %d DHCPSOLICIT lines: a re-acquisition, not a renewal", got)
		}
		if after := r.ta6Sent(); after != before {
			t.Errorf("dnsmasq sent %d ia-ta option(s) after the renewal, %d before: the Renew asked for temporary addresses.\nLog:\n%s",
				after, before, strings.Join(r.srv.lines(), "\n"))
		}

		renews := r.packets(lease.DirOut, wire.MsgRenew)
		if len(renews) == 0 {
			t.Fatal("the client captured no Renew")
		}
		for i, m := range renews {
			if n := m.Options.Count(wire.OptV6IATA); n != 0 {
				t.Errorf("Renew %d carries %d IA_TA", i, n)
			}
		}
		replies6 := r.packets(lease.DirIn, wire.MsgReply)
		last := replies6[len(replies6)-1]
		if n := last.Options.Count(wire.OptV6IATA); n != 0 {
			t.Errorf("the decoded Reply to the Renew carries %d IA_TA", n)
		}
		if n := last.Options.Count(wire.OptV6IANA); n != 1 {
			t.Errorf("the decoded Reply to the Renew carries %d IA_NA, want 1", n)
		}

		// The renewal left the temporary address in place and unrenewed (claymore666/docker-net-dhcp#927).
		l, ok := r.client.Lease()
		if !ok || l.Addr.Addr() != stable || len(l.TempAddrs) != 1 || l.TempAddrs[0].Addr.Addr() != temp {
			t.Errorf("after the renewal the client reports %+v (held %v), want %s and %s", l, ok, stable, temp)
		}
		// Each event converts through its own pair of clock readings, so the
		// two wall times may differ by the microseconds between the pair; a
		// renewal that moved the expiry moves it by the lease time (claymore666/docker-net-dhcp#927).
		if d := renewed.Lease.TempAddrs[0].Valid.Sub(r.ev.Lease.TempAddrs[0].Valid); d > time.Millisecond || d < -time.Millisecond {
			t.Errorf("the renewal moved the temporary address's expiry from %v to %v",
				r.ev.Lease.TempAddrs[0].Valid, renewed.Lease.TempAddrs[0].Valid)
		}
		return
	}
	reexecInNamespaces(t)
}
