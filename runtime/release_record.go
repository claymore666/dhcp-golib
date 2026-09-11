// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package runtime

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/claymore666/dhcp-golib/lease"
)

// ReleaseConfig is what the caller supplies beside the record.
//
// There is no zero value that works, and that is deliberate. Every field a
// wrong default could fill is one of the two things a release-by-record can
// get silently wrong: which address it comes from, and which link it leaves
// by. A default of "the first address on the parent" would pick the released
// address itself on a host that still carries it, which RFC 9915 section
// 18.2.7 forbids — so there is no default.
type ReleaseConfig struct {
	// Interface is the link the datagram leaves by.
	//
	// Required for a v6 release: the source is a link-local address and the
	// destination is link-scoped multicast, and neither means anything without
	// a zone. Optional for v4, where it binds the socket to the device so that
	// the datagram leaves by the parent rather than by whatever the host's
	// route table prefers.
	Interface string

	// Source is the address the datagram comes from. Required, and the
	// unspecified address is not a value for it: binding the wildcard hands
	// the choice to the route table, which is the default this field exists
	// to remove.
	//
	// IT MUST BE AN ADDRESS THE HOST REALLY HOLDS ON THE SENDING LINK. The
	// socket is bound to it, so one the host does not hold fails at the bind
	// and comes back as an error. A parent the host has no address on leaves
	// nothing to pass, and this path cannot be used there.
	//
	// It is the caller's and this package never picks it. For v6 it MUST NOT
	// be the address being released — RFC 9915 section 18.2.7: "The client
	// MUST NOT use any of the addresses it is releasing as the source address
	// in the Release message or in any subsequently transmitted message." —
	// and SendRelease refuses that rather than trusting the caller, because a
	// server accepts the datagram either way and no outside evidence would
	// ever show the violation.
	Source netip.Addr

	// SourcePort is the port to send from. Zero means the family's client
	// port, 68 or 546, which is what RFC 2131 section 4.1 and RFC 9915 section
	// 7.2 give a client.
	//
	// It is settable because a host that already runs a DHCP client of its own
	// cannot bind the client port a second time, and a release that cannot be
	// sent at all is worse than one sent from an ephemeral port. MEASURED
	// against dnsmasq 2.91: a release from an ephemeral port closes the lease.
	// That is a fact about dnsmasq and not about every server.
	SourcePort uint16

	// Rand is the source of the transaction id. Nil means a fresh
	// crypto/rand-seeded one.
	Rand *Entropy
}

// The refusals SendRelease returns before it opens a socket.
var (
	// ErrReleaseNoSource is a ReleaseConfig with no source address, or with
	// the unspecified one, which is the same thing wearing a value: a socket
	// bound to 0.0.0.0 or :: lets the route table pick, and what it picks on
	// a host that still carries the released address is the address being
	// released. There is no default: see ReleaseConfig.
	ErrReleaseNoSource = errors.New("runtime: ReleaseConfig.Source is required and cannot be the unspecified address")

	// ErrReleaseSourceFamily is a source address in the other family from the
	// record's.
	ErrReleaseSourceFamily = errors.New("runtime: ReleaseConfig.Source is in the other address family from the record")

	// ErrReleaseNoInterface is a v6 release with no interface. A link-local
	// source and a link-scoped multicast destination both need the zone.
	ErrReleaseNoInterface = errors.New("runtime: ReleaseConfig.Interface is required for a v6 release")

	// ErrReleaseSourceIsReleased is RFC 9915 section 18.2.7's second MUST NOT,
	// refused rather than trusted.
	//
	// IT IS A v6 REFUSAL AND NOT A GENERAL ONE. RFC 2131 has no counterpart,
	// and proto.Machine's own release depends on the opposite: it sends FROM
	// the address it is giving back, because that datagram is built by ring 3
	// from a client that still holds the address. A guard that refused both
	// families would refuse a legal message.
	ErrReleaseSourceIsReleased = errors.New("runtime: the source address is the address being released (RFC 9915 section 18.2.7)")
)

// SendRelease gives a record's lease back: one datagram, sent once,
// synchronously, from a source the caller chose.
//
// IT NEEDS NO CLIENT, NO MACHINE AND NO NAMESPACE. That is what it is for. A
// container that has been removed took its link and its socket with it; what
// is left is the record, and this turns the record into the one message that
// tells the server the address is free. proto.Machine's release is the other
// path and is unchanged: it releases a lease it is still holding, from the
// address it is holding.
//
// FIRE AND FORGET IS THE ARM THE RFC OFFERS, taken deliberately. RFC 9915
// section 18.2.7: "Implementations SHOULD retransmit one or more times but MAY
// choose to terminate the retransmission procedure early." Nothing here reads
// a reply, so a Reply with status NoBinding cannot be misread as an error, and
// nothing here retransmits. RFC 2131 section 4.4.6 states the consequence
// plainly for the other family: "Note that the correct operation of DHCP does
// not depend on the transmission of DHCPRELEASE messages."
//
// EVERY FAILURE COMES BACK. Forget refers to the reply, never to the error: a
// swallowed write error would tell the caller an address was given back while
// it stays leased until its lifetime runs out, and the caller would close the
// record on it.
func SendRelease(rec lease.Record, cfg ReleaseConfig) error {
	return sendReleaseWith(rec, cfg, sendOneDatagram)
}

// releaseSender is the seam the refusal cases count calls on. A refusal that
// returns an error is not the same claim as a refusal that sends nothing, and
// only the second one is what a server sees.
type releaseSender func(src, dst netip.AddrPort, iface string, payload []byte) error

func sendReleaseWith(rec lease.Record, cfg ReleaseConfig, send releaseSender) error {
	if !cfg.Source.IsValid() || cfg.Source.IsUnspecified() {
		return ErrReleaseNoSource
	}

	rnd := cfg.Rand
	if rnd == nil {
		e, err := NewEntropy()
		if err != nil {
			return fmt.Errorf("runtime: seeding the release transaction id: %w", err)
		}
		rnd = e
	}

	payload, dst, err := lease.BuildRelease(rec, uint32(rnd.Uint64()))
	if err != nil {
		return err
	}

	if (cfg.Source.Is4() || cfg.Source.Is4In6()) != dst.Addr().Is4() {
		return fmt.Errorf("%w: %s", ErrReleaseSourceFamily, cfg.Source)
	}
	port := cfg.SourcePort
	if dst.Addr().Is4() {
		if port == 0 {
			port = ClientPort
		}
	} else {
		if cfg.Interface == "" {
			return ErrReleaseNoInterface
		}
		if port == 0 {
			port = ClientPort6
		}
		if cfg.Source.WithZone("") == rec.Lease.Addr.Addr().WithZone("") {
			return fmt.Errorf("%w: %s", ErrReleaseSourceIsReleased, cfg.Source)
		}
	}

	return send(netip.AddrPortFrom(cfg.Source, port), dst, cfg.Interface, payload)
}

// sendOneDatagram is the real transport: an ordinary UDP socket, bound to the
// caller's address and closed again.
//
// A UDP SOCKET AND NOT AF_PACKET, which is the opposite of every other send in
// this package, so the reason is worth stating. The packet transports exist
// because a client's first messages leave from 0.0.0.0 to a destination that
// is not routable and no socket API will produce that datagram. This one is
// the other case entirely: the source is an address the host really holds, the
// destination is a server the host can really reach, and the link-layer
// address of that server is something the kernel already knows and this
// process does not — there is no DHCPACK frame in hand to learn it from, and
// ARPing for it here would be this library installing state on a link it has
// promised not to touch.
func sendOneDatagram(src, dst netip.AddrPort, iface string, payload []byte) error {
	network := "udp4"
	if !dst.Addr().Is4() {
		network = "udp6"
	}

	la := net.UDPAddrFromAddrPort(src)
	ra := net.UDPAddrFromAddrPort(dst)
	if network == "udp6" {
		la.Zone, ra.Zone = iface, iface
	}

	d := net.Dialer{LocalAddr: la}
	if iface != "" {
		d.Control = bindToDevice(iface)
	}
	conn, err := d.Dial(network, ra.String())
	if err != nil {
		return fmt.Errorf("runtime: opening the release socket %s -> %s: %w", la, ra, err)
	}
	defer conn.Close()

	n, err := conn.Write(payload)
	if err != nil {
		return fmt.Errorf("runtime: sending the release to %s: %w", ra, err)
	}
	// UNREACHABLE ON THIS SOCKET, and kept anyway. A connected datagram socket
	// writes the whole message or returns an error, so nothing in this package
	// can drive this branch and no test claims to. io.Writer's contract is the
	// reason it is here: a short write would be a truncated DHCP message, a
	// server discards one without a word, and the caller would be told the
	// address was given back. It is named as an unobserved line rather than
	// counted as a tested one.
	if n != len(payload) {
		return fmt.Errorf("runtime: the release to %s went out as %d of %d octets", ra, n, len(payload))
	}
	return nil
}
