// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package runtime

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/claymore666/dhcp-golib/lease"
	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

var (
	linkParentMAC = net.HardwareAddr{0x02, 0x00, 0x5e, 0x12, 0x88, 0x01}
	linkServerMAC = net.HardwareAddr{0x02, 0x00, 0x5e, 0x12, 0x88, 0x02}
	linkOtherMAC  = net.HardwareAddr{0x02, 0x00, 0x5e, 0x12, 0x88, 0x03}
	linkServer    = netip.MustParseAddr("192.168.99.1")
	linkLeased    = netip.MustParseAddr("192.168.99.120")
	linkGateway   = netip.MustParseAddr("192.168.99.254")
	linkRelayed   = netip.MustParseAddr("10.9.9.9")
	linkRouterMAC = net.HardwareAddr{0x02, 0x00, 0x5e, 0x12, 0x88, 0x04}
)

type fakeLinkARP struct {
	sent       [][]byte
	in         chan lease.ARPInbound
	sendErr    error
	closeErr   error
	closed     int
	hwOverride net.HardwareAddr
}

func (f *fakeLinkARP) HardwareAddr() net.HardwareAddr {
	if f.hwOverride != nil {
		return f.hwOverride
	}
	return linkParentMAC
}
func (f *fakeLinkARP) Send(b []byte) error {
	f.sent = append(f.sent, append([]byte(nil), b...))
	return f.sendErr
}
func (f *fakeLinkARP) Received() <-chan lease.ARPInbound { return f.in }
func (f *fakeLinkARP) Close() error                      { f.closed++; return f.closeErr }

type fakeLinkIP struct {
	dst      []proto.Dest
	hw       []net.HardwareAddr
	payload  [][]byte
	sendErr  error
	closeErr error
	closed   int
}

func (f *fakeLinkIP) sendUnicastTo(dst proto.Dest, hw net.HardwareAddr, p []byte) error {
	f.dst = append(f.dst, dst)
	f.hw = append(f.hw, hw)
	f.payload = append(f.payload, p)
	return f.sendErr
}
func (f *fakeLinkIP) Close() error { f.closed++; return f.closeErr }

type linkRig struct {
	arp      *fakeLinkARP
	ip       *fakeLinkIP
	opened   []string
	arpErr   error
	ipErr    error
	deadline chan time.Time
}

// newLinkRig hands the probe these frames and then closes the ARP socket, so a
// probe for a hop nothing answers fails at once rather than waiting on a
// deadline the rig never fires (claymore666/docker-net-dhcp#1288).
func newLinkRig(frames ...[]byte) *linkRig {
	r := openLinkRig(frames...)
	close(r.arp.in)
	return r
}

// newSilentLinkRig hands the probe these frames and then lets the bound run out.
func newSilentLinkRig(frames ...[]byte) *linkRig {
	r := openLinkRig(frames...)
	r.deadline = make(chan time.Time)
	close(r.deadline)
	return r
}

func openLinkRig(frames ...[]byte) *linkRig {
	r := &linkRig{
		arp: &fakeLinkARP{in: make(chan lease.ARPInbound, len(frames)+1)},
		ip:  &fakeLinkIP{},
	}
	for _, f := range frames {
		r.arp.in <- lease.ARPInbound{Frame: f}
	}
	return r
}

func (r *linkRig) ports() linkPorts {
	return linkPorts{
		openARP: func(iface string) (linkARP, error) {
			r.opened = append(r.opened, "arp:"+iface)
			if r.arpErr != nil {
				return nil, r.arpErr
			}
			return r.arp, nil
		},
		openIP: func(iface string) (linkIP, error) {
			r.opened = append(r.opened, "ip:"+iface)
			if r.ipErr != nil {
				return nil, r.ipErr
			}
			return r.ip, nil
		},
		after: func(d time.Duration) <-chan time.Time {
			if d != linkResolveBound {
				panic("the probe is bounded by something other than linkResolveBound")
			}
			return r.deadline
		},
	}
}

func linkRecord() lease.Record {
	return lease.Record{
		ID: "rec-link", Scope: "net-a", Family: lease.FamilyV4,
		CHAddr:   net.HardwareAddr{0x02, 0x42, 0xac, 0x11, 0x00, 0x09},
		Identity: []byte{0x01, 0x02, 0x42, 0xac, 0x11, 0x00, 0x09},
		Lease:    lease.Lease{Addr: netip.PrefixFrom(linkLeased, 24), ServerID: linkServer, Gateway: linkGateway},
	}
}

func linkCfg() LinkReleaseConfig {
	return LinkReleaseConfig{Interface: "eth9", Rand: NewEntropySeeded(1288)}
}

func arpFrameFor(t *testing.T, op wire.ARPOp, sha net.HardwareAddr, spa netip.Addr) []byte {
	t.Helper()
	b, err := wire.EncodeARP(&wire.ARPPacket{Op: op, SenderHW: sha, SenderIP: spa, TargetIP: netip.IPv4Unspecified()})
	if err != nil {
		t.Fatalf("EncodeARP: %v", err)
	}
	return b
}

func TestLinkReleaseRefusesBeforeOpeningASocket(t *testing.T) {
	v6 := linkRecord()
	v6.Family = lease.FamilyV6
	noID := linkRecord()
	noID.CHAddr, noID.Identity = nil, nil
	noServer := linkRecord()
	noServer.Lease.ServerID = netip.Addr{}

	for _, c := range []struct {
		name string
		rec  lease.Record
		cfg  LinkReleaseConfig
		want error
	}{
		{"a v6 record", v6, linkCfg(), ErrLinkReleaseFamily},
		{"no interface", linkRecord(), LinkReleaseConfig{Rand: NewEntropySeeded(1)}, ErrLinkReleaseNoInterface},
		{"no chaddr and no client identifier", noID, linkCfg(), lease.ErrReleaseNoIdentity},
		{"no server identifier", noServer, linkCfg(), lease.ErrReleaseNoServer},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newLinkRig()
			err := sendReleaseOnLinkWith(c.rec, c.cfg, r.ports())
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if len(r.opened) != 0 {
				t.Fatalf("a refused release opened %v", r.opened)
			}
		})
	}
}

func TestLinkReleaseProbesWithAZeroSenderAndSendsToTheMACThatAnswered(t *testing.T) {
	ownProbe, err := wire.EncodeARP(&wire.ARPPacket{Op: wire.ARPRequest, SenderHW: linkParentMAC,
		SenderIP: netip.IPv4Unspecified(), TargetIP: linkServer})
	if err != nil {
		t.Fatal(err)
	}
	r := newLinkRig(
		ownProbe,
		arpFrameFor(t, wire.ARPReply, linkOtherMAC, netip.MustParseAddr("192.168.99.7")),
		arpFrameFor(t, wire.ARPRequest, linkOtherMAC, linkServer),
		arpFrameFor(t, wire.ARPReply, linkServerMAC, linkServer),
	)

	if err := sendReleaseOnLinkWith(linkRecord(), linkCfg(), r.ports()); err != nil {
		t.Fatalf("sendReleaseOnLinkWith: %v", err)
	}

	if len(r.arp.sent) != 1 {
		t.Fatalf("sent %d ARP frame(s), want one probe", len(r.arp.sent))
	}
	p, err := wire.DecodeARP(r.arp.sent[0])
	if err != nil {
		t.Fatalf("the probe does not decode: %v", err)
	}
	if !p.IsProbe() || p.TargetIP != linkServer || !bytes.Equal(p.SenderHW, linkParentMAC) {
		t.Fatalf("the probe is %s, want an RFC 5227 probe for %s from %s", p, linkServer, linkParentMAC)
	}

	if len(r.ip.dst) != 1 {
		t.Fatalf("sent %d release(s), want one", len(r.ip.dst))
	}
	if !bytes.Equal(r.ip.hw[0], linkServerMAC) {
		t.Fatalf("the release went to %s, want the MAC the server answered from, %s", r.ip.hw[0], linkServerMAC)
	}
	if got := r.ip.dst[0]; got.Broadcast || got.Addr != linkServer || got.Src != linkLeased {
		t.Fatalf("the release is addressed %+v, want unicast %s from the leased %s", got, linkServer, linkLeased)
	}
	m, err := wire.Decode(r.ip.payload[0])
	if err != nil {
		t.Fatalf("the payload does not decode: %v", err)
	}
	if mt, _ := m.Type(); mt != wire.MsgRelease || m.CIAddr != linkLeased {
		t.Fatalf("the payload is %v with ciaddr %s, want a DHCPRELEASE for %s", mt, m.CIAddr, linkLeased)
	}
	if r.arp.closed != 1 || r.ip.closed != 1 {
		t.Fatalf("closed the ARP socket %d and the IP socket %d time(s), want one each", r.arp.closed, r.ip.closed)
	}
}

func TestLinkReleaseBroadcastsTheFrameWhenNothingAnswersTheProbe(t *testing.T) {
	r := newSilentLinkRig(arpFrameFor(t, wire.ARPReply, linkOtherMAC, netip.MustParseAddr("192.168.99.7")))

	if err := sendReleaseOnLinkWith(linkRecord(), linkCfg(), r.ports()); err != nil {
		t.Fatalf("sendReleaseOnLinkWith: %v", err)
	}
	if len(r.ip.hw) != 1 || !bytes.Equal(r.ip.hw[0], broadcastMAC) {
		t.Fatalf("the release went to %v, want one frame to the broadcast MAC", r.ip.hw)
	}
	if got := r.ip.dst[0]; got.Broadcast || got.Addr != linkServer || got.Src != linkLeased {
		t.Fatalf("the fallback is addressed %+v, want unicast IP %s from %s", got, linkServer, linkLeased)
	}
}

func TestLinkReleaseIgnoresAReplyWithNoUsableHardwareAddress(t *testing.T) {
	for _, hw := range []net.HardwareAddr{make(net.HardwareAddr, 6), broadcastMAC} {
		if got := replyFrom(arpFrameFor(t, wire.ARPReply, hw, linkServer), linkServer); got != nil {
			t.Errorf("a reply from %s resolved to %s", hw, got)
		}
	}
	if got := replyFrom([]byte{1, 2, 3}, linkServer); got != nil {
		t.Errorf("a frame that does not decode resolved to %s", got)
	}
}

func TestLinkReleaseReturnsEveryFailure(t *testing.T) {
	boom := errors.New("boom")
	answered := func(t *testing.T) *linkRig {
		return newLinkRig(arpFrameFor(t, wire.ARPReply, linkServerMAC, linkServer))
	}
	for _, c := range []struct {
		name  string
		setup func(*linkRig)
		sends int
	}{
		{"the IP socket does not open", func(r *linkRig) { r.ipErr = boom }, 0},
		{"the ARP socket does not open", func(r *linkRig) { r.arpErr = boom }, 0},
		{"the probe is not sent", func(r *linkRig) { r.arp.sendErr = boom }, 0},
		{"the ARP read fails", func(r *linkRig) {
			r.arp.in = make(chan lease.ARPInbound, 1)
			r.arp.in <- lease.ARPInbound{Err: boom}
		}, 0},
		{"the ARP socket does not close", func(r *linkRig) { r.arp.closeErr = boom }, 0},
		{"the release is not sent", func(r *linkRig) { r.ip.sendErr = boom }, 1},
		{"the IP socket does not close", func(r *linkRig) { r.ip.closeErr = boom }, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := answered(t)
			c.setup(r)
			err := sendReleaseOnLinkWith(linkRecord(), linkCfg(), r.ports())
			if !errors.Is(err, boom) {
				t.Fatalf("got %v, want the failure back", err)
			}
			if len(r.ip.dst) != c.sends {
				t.Fatalf("sent %d release(s), want %d", len(r.ip.dst), c.sends)
			}
		})
	}

	r2 := newLinkRig()
	if err := sendReleaseOnLinkWith(linkRecord(), linkCfg(), r2.ports()); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("an ARP socket that closed under the wait gave %v", err)
	}
	if len(r2.ip.dst) != 0 {
		t.Fatal("a release was sent after the ARP socket closed under the wait")
	}
}

func relayedRecord() lease.Record {
	rec := linkRecord()
	rec.Lease.ServerID = linkRelayed
	return rec
}

func probedFor(t *testing.T, frame []byte) netip.Addr {
	t.Helper()
	p, err := wire.DecodeARP(frame)
	if err != nil {
		t.Fatalf("the probe does not decode: %v", err)
	}
	if !p.IsProbe() {
		t.Fatalf("%s is not an RFC 5227 probe", p)
	}
	return p.TargetIP
}

func TestLinkReleaseToAServerOffTheSubnetGoesThroughTheGateway(t *testing.T) {
	r := newLinkRig(
		arpFrameFor(t, wire.ARPReply, linkServerMAC, linkServer),
		arpFrameFor(t, wire.ARPReply, linkRouterMAC, linkGateway),
	)
	if err := sendReleaseOnLinkWith(relayedRecord(), linkCfg(), r.ports()); err != nil {
		t.Fatalf("sendReleaseOnLinkWith: %v", err)
	}
	if len(r.arp.sent) != 1 || probedFor(t, r.arp.sent[0]) != linkGateway {
		t.Fatalf("sent %d ARP frame(s), want one probe for the gateway %s", len(r.arp.sent), linkGateway)
	}
	if len(r.ip.dst) != 1 || !bytes.Equal(r.ip.hw[0], linkRouterMAC) {
		t.Fatalf("the release went to %v, want one frame to the gateway's %s", r.ip.hw, linkRouterMAC)
	}
	if got := r.ip.dst[0]; got.Broadcast || got.Addr != linkRelayed || got.Src != linkLeased {
		t.Fatalf("the release is addressed %+v, want unicast IP to the server %s from %s", got, linkRelayed, linkLeased)
	}
}

func TestLinkReleaseToAServerOffTheSubnetWithNoGatewayOpensNothing(t *testing.T) {
	rec := relayedRecord()
	rec.Lease.Gateway = netip.Addr{}
	r := newLinkRig()
	if err := sendReleaseOnLinkWith(rec, linkCfg(), r.ports()); !errors.Is(err, ErrLinkReleaseNoRoute) {
		t.Fatalf("got %v, want %v", err, ErrLinkReleaseNoRoute)
	}
	if len(r.opened) != 0 {
		t.Fatalf("a release with no way to the server opened %v", r.opened)
	}
}

func TestLinkReleaseNeverBroadcastsToAServerOffTheSubnet(t *testing.T) {
	r := newSilentLinkRig(arpFrameFor(t, wire.ARPReply, linkServerMAC, linkRelayed))
	if err := sendReleaseOnLinkWith(relayedRecord(), linkCfg(), r.ports()); !errors.Is(err, ErrLinkReleaseHopSilent) {
		t.Fatalf("got %v, want %v", err, ErrLinkReleaseHopSilent)
	}
	if len(r.ip.dst) != 0 {
		t.Fatalf("sent %v when the gateway did not answer, want nothing: a router drops a broadcast frame", r.ip.hw)
	}
}

func TestLinkReleaseOnASlash32LeaseKeepsTheOnLinkPath(t *testing.T) {
	rec := linkRecord()
	rec.Lease.Addr = netip.PrefixFrom(linkLeased, 32)
	r := newLinkRig(arpFrameFor(t, wire.ARPReply, linkServerMAC, linkServer))
	if err := sendReleaseOnLinkWith(rec, linkCfg(), r.ports()); err != nil {
		t.Fatalf("sendReleaseOnLinkWith: %v", err)
	}
	if len(r.arp.sent) != 1 || probedFor(t, r.arp.sent[0]) != linkServer || !bytes.Equal(r.ip.hw[0], linkServerMAC) {
		t.Fatalf("a lease with no subnet mask probed %d time(s) and sent to %v, want the server's %s",
			len(r.arp.sent), r.ip.hw, linkServerMAC)
	}
}

func TestLinkReleaseSharesOneProbePerHopAcrossASweep(t *testing.T) {
	for _, c := range []struct {
		name   string
		frames func(t *testing.T) [][]byte
		silent bool
		want   net.HardwareAddr
	}{
		{"an answered hop", func(t *testing.T) [][]byte {
			return [][]byte{arpFrameFor(t, wire.ARPReply, linkServerMAC, linkServer)}
		}, false, linkServerMAC},
		{"a silent hop", func(*testing.T) [][]byte { return nil }, true, broadcastMAC},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newLinkRig(c.frames(t)...)
			if c.silent {
				r = newSilentLinkRig(c.frames(t)...)
			}
			cfg := linkCfg()
			cfg.Resolved = NewLinkResolveCache()
			second := linkRecord()
			second.ID, second.Lease.Addr = "rec-link-2", netip.PrefixFrom(netip.MustParseAddr("192.168.99.121"), 24)
			for _, rec := range []lease.Record{linkRecord(), second} {
				if err := sendReleaseOnLinkWith(rec, cfg, r.ports()); err != nil {
					t.Fatalf("sendReleaseOnLinkWith %s: %v", rec.ID, err)
				}
			}
			if len(r.arp.sent) != 1 {
				t.Fatalf("two releases behind one hop sent %d probe(s), want one", len(r.arp.sent))
			}
			if len(r.ip.hw) != 2 || !bytes.Equal(r.ip.hw[0], c.want) || !bytes.Equal(r.ip.hw[1], c.want) {
				t.Fatalf("the releases went to %v, want both to %s", r.ip.hw, c.want)
			}
		})
	}
}

func TestLinkReleaseRemembersASilentGatewayAndStillSendsNothing(t *testing.T) {
	r := newSilentLinkRig()
	cfg := linkCfg()
	cfg.Resolved = NewLinkResolveCache()
	second := relayedRecord()
	second.ID, second.Lease.Addr = "rec-link-2", netip.PrefixFrom(netip.MustParseAddr("192.168.99.121"), 24)
	for _, rec := range []lease.Record{relayedRecord(), second} {
		if err := sendReleaseOnLinkWith(rec, cfg, r.ports()); !errors.Is(err, ErrLinkReleaseHopSilent) {
			t.Fatalf("%s: got %v, want %v", rec.ID, err, ErrLinkReleaseHopSilent)
		}
	}
	if len(r.arp.sent) != 1 || len(r.ip.dst) != 0 {
		t.Fatalf("two releases behind a silent gateway sent %d probe(s) and %v, want one probe and nothing else",
			len(r.arp.sent), r.ip.hw)
	}
}

func TestLinkReleaseRemembersEachHopApart(t *testing.T) {
	r := newLinkRig(
		arpFrameFor(t, wire.ARPReply, linkServerMAC, linkServer),
		arpFrameFor(t, wire.ARPReply, linkRouterMAC, linkGateway),
	)
	cfg := linkCfg()
	cfg.Resolved = NewLinkResolveCache()
	for _, rec := range []lease.Record{linkRecord(), relayedRecord()} {
		if err := sendReleaseOnLinkWith(rec, cfg, r.ports()); err != nil {
			t.Fatalf("sendReleaseOnLinkWith %s: %v", rec.Lease.ServerID, err)
		}
	}
	if len(r.arp.sent) != 2 || probedFor(t, r.arp.sent[1]) != linkGateway {
		t.Fatalf("sent %d probe(s), want a second one for the gateway", len(r.arp.sent))
	}
	if len(r.ip.hw) != 2 || !bytes.Equal(r.ip.hw[1], linkRouterMAC) {
		t.Fatalf("the relayed release went to %v, want the gateway's %s", r.ip.hw, linkRouterMAC)
	}
}
