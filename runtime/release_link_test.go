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

func newLinkRig(frames ...[]byte) *linkRig {
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
		Lease:    lease.Lease{Addr: netip.PrefixFrom(linkLeased, 24), ServerID: linkServer},
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
	r := newLinkRig(arpFrameFor(t, wire.ARPReply, linkOtherMAC, netip.MustParseAddr("192.168.99.7")))
	r.deadline = make(chan time.Time)
	close(r.deadline)

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
			<-r.arp.in
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
	close(r2.arp.in)
	if err := sendReleaseOnLinkWith(linkRecord(), linkCfg(), r2.ports()); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("an ARP socket that closed under the wait gave %v", err)
	}
	if len(r2.ip.dst) != 0 {
		t.Fatal("a release was sent after the ARP socket closed under the wait")
	}
}
