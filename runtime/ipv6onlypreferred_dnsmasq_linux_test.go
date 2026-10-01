// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

//go:build linux

package runtime

import (
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/claymore666/dhcp-golib/lease"
	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

// Runtime half of claymore666/docker-net-dhcp#1027, RFC 8925 option 108.
// dnsmasq 2.91 sends option 108 only to a client whose parameter request list
// names it (rfc2131.c 2666, read 2026-10-01), so a run in which the client
// never asked cannot show the option. The outcome is read from dnsmasq's own
// log, from the packets the client sent and received, from the client's journal
// and from the lease it reports; the library's counters are not consulted.
//
// runtime.Client runs on real timers and has no way to inject a link event, so
// these cases observe the START of the wait. Its end and the link-up cut are
// proto tests on the fake clock.

// v6oProbeMAC is the hardware address of the barrier message below. dnsmasq
// handles datagrams in arrival order, so the probe's line in its log proves
// every line the client's earlier messages would have produced is already
// there; no duration is waited on (T2) (claymore666/docker-net-dhcp#1027).
const v6oProbeMAC = "02:00:00:00:00:99"

var (
	v6oLine  = regexp.MustCompile(`DHCP(DISCOVER|OFFER|REQUEST|ACK|NAK|DECLINE|RELEASE)\(` + testServerIf + `\)(?: [0-9.]+)? ([0-9a-f:]{17})`)
	v6oTimer = regexp.MustCompile(`^SetTimer restart after (\d+)s$`)
	// v6oSent108 is dnsmasq's log line for option 108 in a message it sends;
	// the column is padded, so it reads "option:108" for three digits (claymore666/docker-net-dhcp#1027).
	v6oSent108 = regexp.MustCompile(`sent size:\s*\d+ option:\s*108 `)
)

// v6oKinds is the order of the DHCP message kinds dnsmasq logged for one
// hardware address (claymore666/docker-net-dhcp#1027).
func v6oKinds(lines []string, mac string) []string {
	var kinds []string
	for _, l := range lines {
		if m := v6oLine.FindStringSubmatch(l); m != nil && m[2] == mac {
			kinds = append(kinds, m[1])
		}
	}
	return kinds
}

func v6oCountSent108(lines []string) int {
	n := 0
	for _, l := range lines {
		if v6oSent108.MatchString(l) {
			n++
		}
	}
	return n
}

type v6oRun struct {
	srv    *dnsmasqServer
	client *Client
	mac    string
	cancel context.CancelFunc
	runErr chan error
}

// startV6Only builds the link, a dnsmasq that is configured to send option 108
// with a value of 300, and a client with Params.IPv6OnlyPreferred as given,
// and returns once the client is running (claymore666/docker-net-dhcp#1027).
// Permanent neighbour entries cover the pool, for renewalAgainstDnsmasq's
// reason.
func startV6Only(t *testing.T, flag bool) *v6oRun {
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
	srv := startDnsmasqCfg(t, dnsmasqConfig{
		rangeLo: testRenewLo, rangeHi: testRenewHi,
		extra: []string{"--dhcp-option=58," + fmt.Sprint(testRenewSec), "--dhcp-option=108,300"},
	})

	params := proto.DefaultParams(iface.HardwareAddr)
	params.DesyncMin, params.DesyncMax = 0, 0
	// Async and the brisk table, for dnsmasq_linux_test.go's reason: the
	// subject is the exchange, not RFC 5227's schedule
	// (claymore666/docker-net-dhcp#1027).
	params.Conflict = proto.ConflictAsync
	params.ACD = briskACD()
	params.IPv6OnlyPreferred = flag

	c, err := NewClient(ClientConfig{Interface: testClientIf, Params: params, EventBuffer: 8})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &v6oRun{srv: srv, client: c, mac: mac, cancel: cancel, runErr: make(chan error, 1)}
	go func() { r.runErr <- c.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-r.runErr
	})
	return r
}

// packets returns the client's captured DHCP messages of one type and
// direction (claymore666/docker-net-dhcp#1027).
func (r *v6oRun) packets(dir lease.Direction, mt wire.MessageType) []*wire.Message {
	var out []*wire.Message
	for _, p := range r.client.Packets() {
		if p.Dir != dir || p.Msg == nil {
			continue
		}
		if got, ok := p.Msg.Type(); ok && got == mt {
			out = append(out, p.Msg)
		}
	}
	return out
}

// barrier sends one DHCPDISCOVER from another hardware address, out of the
// client's own link, and returns once dnsmasq has logged it. Everything the
// client sent before the call is in the log by then (claymore666/docker-net-dhcp#1027).
func (r *v6oRun) barrier(t *testing.T) {
	t.Helper()
	hw, err := net.ParseMAC(v6oProbeMAC)
	if err != nil {
		t.Fatal(err)
	}
	msg := &wire.Message{
		Op: wire.BootRequest, HType: wire.HTypeEthernet, XID: 0x1027, CHAddr: hw,
		Flags: wire.FlagBroadcast, Options: wire.Options{},
	}
	msg.SetType(wire.MsgDiscover)
	raw, err := wire.Encode(msg)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// Both ends of the veth pair are in one namespace, so a datagram that
	// leaves by the client's link carries the server end's own address as its
	// source and Linux drops it as a martian unless accept_local is set. A
	// property of the rig, not of the subject (claymore666/docker-net-dhcp#1027).
	if err := os.WriteFile("/proc/sys/net/ipv4/conf/"+testServerIf+"/accept_local", []byte("1\n"), 0o644); err != nil {
		t.Fatalf("accept_local: %v", err)
	}
	lc := net.ListenConfig{Control: bindToDevice(testClientIf)}
	pc, err := lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:68")
	if err != nil {
		t.Fatalf("barrier socket: %v", err)
	}
	defer pc.Close()
	if _, err := pc.WriteTo(raw, &net.UDPAddr{IP: net.IPv4bcast, Port: 67}); err != nil {
		t.Fatalf("barrier send: %v", err)
	}
	r.srv.waitFor(t, "DHCPDISCOVER("+testServerIf+") "+v6oProbeMAC)
}

// TestDnsmasqSendsOption108AndAnIPv6OnlyClientWaitsInsteadOfRequesting: the
// server is configured with 108 and 300, the client asked for it. dnsmasq logs
// the DISCOVER and an OFFER whose sent options include 108, and never a
// REQUEST; the client reports no lease, sent no REQUEST, DECLINE or RELEASE,
// and its own journal has the wait armed for at least 300 s from the OFFER
// (claymore666/docker-net-dhcp#1027).
func TestDnsmasqSendsOption108AndAnIPv6OnlyClientWaitsInsteadOfRequesting(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		r := startV6Only(t, true)
		r.srv.waitFor(t, "DHCPOFFER("+testServerIf+")")
		var failed lease.Event
		for ev := range r.client.Events() {
			t.Logf("client event: %s", ev)
			if ev.Kind == lease.Acquired {
				t.Fatalf("the client took a lease from an OFFER that carried option 108: %s", ev)
			}
			if ev.Kind == lease.Failed {
				failed = ev
				break
			}
		}
		if failed.Reason != proto.ReasonIPv6OnlyPreferred {
			t.Fatalf("the client's event is %s, want a Failed with reason %s", failed, proto.ReasonIPv6OnlyPreferred)
		}
		r.barrier(t)

		log := strings.Join(r.srv.lines(), "\n")
		if got := strings.Join(v6oKinds(r.srv.lines(), r.mac), ","); got != "DISCOVER,OFFER" {
			t.Fatalf("dnsmasq logged %s for the client, want DISCOVER,OFFER.\nLog:\n%s", got, log)
		}
		if n := r.srv.count("DHCPREQUEST("); n != 0 {
			t.Errorf("dnsmasq logged %d DHCPREQUEST line(s) during the wait", n)
		}
		if n := v6oCountSent108(r.srv.lines()); n == 0 {
			t.Fatalf("dnsmasq never logged sending option 108, so this run proves nothing.\nLog:\n%s", log)
		}

		offers := r.packets(lease.DirIn, wire.MsgOffer)
		if len(offers) == 0 {
			t.Fatal("the client captured no OFFER")
		}
		secs, ok, err := offers[0].Options.IPv6OnlyPreferred()
		if err != nil || !ok || secs != 300 {
			t.Fatalf("the captured OFFER carries option 108 = %d present=%v err=%v, want 300", secs, ok, err)
		}
		discovers := r.packets(lease.DirOut, wire.MsgDiscover)
		if len(discovers) == 0 || !listsOption(discovers[0].Options[wire.OptParameterList], wire.OptIPv6OnlyPreferred) {
			t.Error("the client's DISCOVER does not list option 108")
		}
		for _, mt := range []wire.MessageType{wire.MsgRequest, wire.MsgDecline, wire.MsgRelease} {
			if n := len(r.packets(lease.DirOut, mt)); n != 0 {
				t.Errorf("the client sent %d %s message(s) during the wait", n, mt)
			}
		}
		if _, held := r.client.Lease(); held {
			t.Error("the client reports a lease during the wait")
		}

		var armed int
		for _, e := range r.client.Journal() {
			for _, a := range e.Actions {
				if m := v6oTimer.FindStringSubmatch(a); m != nil {
					armed, _ = strconv.Atoi(m[1])
				}
			}
		}
		if armed < 300 {
			t.Errorf("the journal's restart timer is %d s, want at least 300.\nJournal: %v", armed, r.client.Journal())
		}
		return
	}
	reexecInNamespaces(t)
}

// TestAClientWithoutTheFlagGetsAFourMessageLeaseAndNoOption108FromTheSameDnsmasq
// is the control: the same server configured with 108, a client with
// Params.IPv6OnlyPreferred false. dnsmasq sends 108 only to a client that asks,
// so the log has all four lines, no sent option 108, and the OFFER the client
// captured has none (claymore666/docker-net-dhcp#1027).
func TestAClientWithoutTheFlagGetsAFourMessageLeaseAndNoOption108FromTheSameDnsmasq(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		r := startV6Only(t, false)
		acquired := awaitAcquired(t, r.client)
		leased := acquired.Lease.Addr.Addr().String()
		r.srv.waitFor(t, "DHCPACK("+testServerIf+") "+leased+" "+r.mac)
		if got := strings.Join(v6oKinds(r.srv.lines(), r.mac), ","); got != "DISCOVER,OFFER,REQUEST,ACK" {
			t.Fatalf("dnsmasq logged %s, want DISCOVER,OFFER,REQUEST,ACK.\nLog:\n%s", got, strings.Join(r.srv.lines(), "\n"))
		}
		if n := v6oCountSent108(r.srv.lines()); n != 0 {
			t.Errorf("dnsmasq sent option 108 %d time(s) to a client that never asked", n)
		}
		offers := r.packets(lease.DirIn, wire.MsgOffer)
		if len(offers) == 0 {
			t.Fatal("the client captured no OFFER")
		}
		if _, ok := offers[0].Options[wire.OptIPv6OnlyPreferred]; ok {
			t.Error("the OFFER the client captured carries option 108")
		}
		for _, d := range r.packets(lease.DirOut, wire.MsgDiscover) {
			if listsOption(d.Options[wire.OptParameterList], wire.OptIPv6OnlyPreferred) {
				t.Error("a client with the flag false listed option 108 in its DISCOVER")
			}
		}
		return
	}
	reexecInNamespaces(t)
}

func listsOption(list []byte, c wire.OptionCode) bool {
	for _, b := range list {
		if b == byte(c) {
			return true
		}
	}
	return false
}
