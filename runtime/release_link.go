// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package runtime

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/claymore666/dhcp-golib/lease"
	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

// LinkReleaseConfig is what SendReleaseOnLink needs beside the record.
type LinkReleaseConfig struct {
	// Interface is the link the release leaves by. Required.
	Interface string

	// Rand is the source of the transaction id. Nil means a fresh
	// crypto/rand-seeded one.
	Rand *Entropy
}

// The refusals SendReleaseOnLink returns before it opens a socket.
var (
	// ErrLinkReleaseFamily is a record that is not DHCPv4. A v6 release needs
	// a link-local source, which SendRelease takes.
	ErrLinkReleaseFamily = errors.New("runtime: a release on the link is DHCPv4 only")

	// ErrLinkReleaseNoInterface is a LinkReleaseConfig with no interface.
	ErrLinkReleaseNoInterface = errors.New("runtime: LinkReleaseConfig.Interface is required")
)

// linkResolveBound is how long SendReleaseOnLink waits for the server to
// answer its ARP probe before it broadcasts the frame instead.
const linkResolveBound = time.Second

// SendReleaseOnLink gives a v4 record's lease back from a link the host holds
// no address on: one DHCPRELEASE from the leased address to the server id,
// sent once over AF_PACKET. Every failure comes back as an error.
func SendReleaseOnLink(rec lease.Record, cfg LinkReleaseConfig) error {
	return sendReleaseOnLinkWith(rec, cfg, linkPorts{
		openARP: func(iface string) (linkARP, error) { return NewARPSocket(iface) },
		openIP:  func(iface string) (linkIP, error) { return NewPacketTransport(iface) },
		after:   time.After,
	})
}

// linkARP and linkIP are the two sockets, as the unit cases drive them.
type linkARP interface {
	HardwareAddr() net.HardwareAddr
	Send(frame []byte) error
	Received() <-chan lease.ARPInbound
	Close() error
}

type linkIP interface {
	sendUnicastTo(dst proto.Dest, hw net.HardwareAddr, payload []byte) error
	Close() error
}

type linkPorts struct {
	openARP func(iface string) (linkARP, error)
	openIP  func(iface string) (linkIP, error)
	after   func(time.Duration) <-chan time.Time
}

func sendReleaseOnLinkWith(rec lease.Record, cfg LinkReleaseConfig, ports linkPorts) (err error) {
	if rec.Family != lease.FamilyV4 {
		return fmt.Errorf("%w: the record is %s", ErrLinkReleaseFamily, rec.Family)
	}
	if cfg.Interface == "" {
		return ErrLinkReleaseNoInterface
	}
	rnd := cfg.Rand
	if rnd == nil {
		e, eerr := NewEntropy()
		if eerr != nil {
			return fmt.Errorf("runtime: seeding the release transaction id: %w", eerr)
		}
		rnd = e
	}
	payload, dst, err := lease.BuildRelease(rec, uint32(rnd.Uint64()))
	if err != nil {
		return err
	}
	server := dst.Addr()

	ip, err := ports.openIP(cfg.Interface)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, ip.Close()) }()

	arp, err := ports.openARP(cfg.Interface)
	if err != nil {
		return err
	}
	hw, rerr := resolveByProbe(arp, server, ports.after(linkResolveBound))
	if cerr := arp.Close(); rerr == nil {
		rerr = cerr
	}
	if rerr != nil {
		return rerr
	}
	// No answer: a router may ignore probes (claymore666/docker-net-dhcp#1288).
	// Broadcast at the link layer, unicast at IP: the server's kernel takes a
	// unicast IP datagram in a broadcast frame, and another server drops the
	// release for its option 54 (RFC 2131 section 4.3.2 names the server by it).
	if hw == nil {
		hw = broadcastMAC
	}
	// IP source is the leased address: RFC 2131 section 4.4.4 releases from it,
	// and the host has no address of its own on this link.
	return ip.sendUnicastTo(proto.Dest{Addr: server, Src: rec.Lease.Addr.Addr()}, hw, payload)
}

// resolveByProbe asks for server's hardware address with an RFC 5227 section
// 1.1 ARP Probe (sender IP 0.0.0.0), so no receiver learns a mapping from it;
// an ARP request from the leased address would teach the server leased
// address -> this parent's MAC and strand the address's next holder
// (claymore666/docker-net-dhcp#1288). It returns nil, nil when no reply from
// server arrives before deadline.
func resolveByProbe(arp linkARP, server netip.Addr, deadline <-chan time.Time) (net.HardwareAddr, error) {
	probe, err := wire.EncodeARP(&wire.ARPPacket{
		Op:       wire.ARPRequest,
		SenderHW: arp.HardwareAddr(),
		SenderIP: netip.IPv4Unspecified(),
		TargetIP: server,
	})
	if err != nil {
		return nil, err
	}
	if err := arp.Send(probe); err != nil {
		return nil, err
	}
	for {
		select {
		case in, ok := <-arp.Received():
			if !ok {
				return nil, fmt.Errorf("runtime: the ARP socket closed while waiting for %s to answer the probe", server)
			}
			if in.Err != nil {
				return nil, fmt.Errorf("runtime: reading the reply to the ARP probe for %s: %w", server, in.Err)
			}
			if hw := replyFrom(in.Frame, server); hw != nil {
				return hw, nil
			}
		case <-deadline:
			return nil, nil
		}
	}
}

// replyFrom is the sender hardware address of an ARP Reply from server, or
// nil for anything else: this host's own probe, another host's traffic.
func replyFrom(frame []byte, server netip.Addr) net.HardwareAddr {
	p, err := wire.DecodeARP(frame)
	if err != nil || p.Op != wire.ARPReply || p.SenderIP != server {
		return nil
	}
	hw := net.HardwareAddr(p.SenderHW)
	if len(hw) != int(wire.ARPHLenEthernet) || isZeroOrBroadcast(hw) {
		return nil
	}
	return append(net.HardwareAddr(nil), hw...)
}

func isZeroOrBroadcast(hw net.HardwareAddr) bool {
	zero, bcast := true, true
	for _, b := range hw {
		zero = zero && b == 0
		bcast = bcast && b == 0xFF
	}
	return zero || bcast
}
