// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/claymore666/dhcp-golib/wire"
)

// DHCPFORCERENEW (RFC 3203) authenticated by Forcerenew Nonce Authentication
// (RFC 6704), the DHCPv4 twin of the v6 Reconfigure in machine6_reconfigure.go
// (claymore666/docker-net-dhcp#1119).

// ForcerenewRefusal is why a DHCPFORCERENEW changed nothing. An enumeration
// and not a count, for ReconfigureRefusal's reason: a frame that fails its
// digest is a message to look at on the wire, one with no nonce is a server to
// configure, and a replay is a server retransmitting.
type ForcerenewRefusal uint8

// The reasons, in the order the checks are reached.
const (
	// ForcerenewRefusalNone is the zero value: the frame was acted on.
	ForcerenewRefusalNone ForcerenewRefusal = iota
	// ForcerenewRefusalWrongState is a frame outside BOUND, RENEWING and
	// REBINDING, where this client holds no lease to renew.
	ForcerenewRefusalWrongState
	// ForcerenewRefusalNoRaw is an event with no wire octets, which cannot be
	// authenticated: the digest covers the octets that arrived.
	ForcerenewRefusalNoRaw
	// ForcerenewRefusalNotUnicast is a destination that is absent,
	// unspecified, multicast or a broadcast: RFC 3203 section 2.2 has such a
	// frame "silently discarded".
	ForcerenewRefusalNotUnicast
	// ForcerenewRefusalNotOurAddress is a unicast to some other host. The
	// packet socket reads every frame on the link and this ring knows the
	// leased address.
	ForcerenewRefusalNotOurAddress
	// ForcerenewRefusalNotThisClient is a frame that is not a BOOTREPLY for
	// this chaddr and this leased ciaddr.
	ForcerenewRefusalNotThisClient
	// ForcerenewRefusalNoNonce is a lease whose ACKs gave no nonce, or none
	// that survived a restart.
	ForcerenewRefusalNoNonce
	// ForcerenewRefusalNoAuth is a frame with no option 90.
	ForcerenewRefusalNoAuth
	// ForcerenewRefusalMalformedAuth is an option 90 that is not a
	// Forcerenew digest: a wrong protocol, algorithm, RDM or length, a nonce
	// where a digest belongs, or two instances.
	ForcerenewRefusalMalformedAuth
	// ForcerenewRefusalReplay is a replay value not above the floor (RFC 3118
	// section 5.3 has the receiver check it first).
	ForcerenewRefusalReplay
	// ForcerenewRefusalBadDigest is an HMAC-MD5 that does not match.
	ForcerenewRefusalBadDigest
	// ForcerenewRefusalNoServer is an authentic frame in BOUND with a lease
	// that names no server to renew from, so the client could not act on it.
	ForcerenewRefusalNoServer

	// numForcerenewRefusal sizes ForcerenewCounters.Refused; a reason added
	// below it does not compile.
	numForcerenewRefusal
)

func (r ForcerenewRefusal) String() string {
	switch r {
	case ForcerenewRefusalNone:
		return "acted on"
	case ForcerenewRefusalWrongState:
		return "this client holds no lease it could renew in this state"
	case ForcerenewRefusalNoRaw:
		return "no wire octets to authenticate"
	case ForcerenewRefusalNotUnicast:
		return "not unicast to the client (RFC 3203 section 2.2)"
	case ForcerenewRefusalNotOurAddress:
		return "unicast to an address that is not this lease's"
	case ForcerenewRefusalNotThisClient:
		return "not a BOOTREPLY for this chaddr and leased address"
	case ForcerenewRefusalNoNonce:
		return "the lease holds no forcerenew nonce (RFC 6704 section 3.1.3)"
	case ForcerenewRefusalNoAuth:
		return "no Authentication option (RFC 6704 section 3.1.4)"
	case ForcerenewRefusalMalformedAuth:
		return "an Authentication option that is not a Forcerenew digest (RFC 6704 section 3.1.2)"
	case ForcerenewRefusalReplay:
		return "the replay detection value is not above the floor (RFC 3118 section 5.3)"
	case ForcerenewRefusalBadDigest:
		return "the message fails Forcerenew Nonce authentication (RFC 6704 section 3.1.4)"
	case ForcerenewRefusalNoServer:
		return "the lease names no server to renew from"
	default:
		return fmt.Sprintf("forcerenew-refusal(%d)", uint8(r))
	}
}

// AllForcerenewRefusals is every reason a FORCERENEW was refused, so the
// counters and the tests enumerate the domain from one place.
func AllForcerenewRefusals() []ForcerenewRefusal {
	return []ForcerenewRefusal{
		ForcerenewRefusalWrongState, ForcerenewRefusalNoRaw,
		ForcerenewRefusalNotUnicast, ForcerenewRefusalNotOurAddress,
		ForcerenewRefusalNotThisClient, ForcerenewRefusalNoNonce,
		ForcerenewRefusalNoAuth, ForcerenewRefusalMalformedAuth,
		ForcerenewRefusalReplay, ForcerenewRefusalBadDigest,
		ForcerenewRefusalNoServer,
	}
}

// ForcerenewCounters is what this machine did with option 90 and type 9.
//
// Renewed and AlreadyRenewing are the two ways a frame is obeyed and are kept
// apart so an observer can tell "renewed because of it" from "was already
// renewing". Refused is indexed by ForcerenewRefusal. AckRefused is the ACKs
// RFC 6704 section 3.1.4 discards (an OFFER carried option 145 and the ACK
// lacked a valid option 90); it is not a FORCERENEW refusal and stays out of
// Refused (claymore666/docker-net-dhcp#1119).
type ForcerenewCounters struct {
	Renewed         uint64
	AlreadyRenewing uint64
	AckRefused      uint64
	Refused         [numForcerenewRefusal]uint64
}

// RefusedTotal is every FORCERENEW refused by any rule.
func (c ForcerenewCounters) RefusedTotal() uint64 {
	var n uint64
	for _, r := range AllForcerenewRefusals() {
		n += c.Refused[r]
	}
	return n
}

// ForcerenewCounters returns the counters as a copy.
func (m *Machine) ForcerenewCounters() ForcerenewCounters { return m.frCounts }

// forcerenewKey is what authenticates a FORCERENEW: the nonce and the replay
// floor of the lease in hand. A fixed-size array and not the lease's slice, so
// a caller mutating a Lease it was handed cannot change the verifying key
// (claymore666/docker-net-dhcp#1119).
type forcerenewKey struct {
	have  bool
	nonce [wire.ForcerenewNonceLen]byte
	floor uint64
}

// validForcerenewNonce is the option 90 an ACK needs to carry for RFC 6704
// section 3.1.4: present, the Forcerenew Nonce shape, and of the ACK's type 1.
func validForcerenewNonce(m *wire.Message) (wire.ForcerenewAuth, bool) {
	a, present, err := m.Options.ForcerenewAuth()
	if !present || err != nil || a.Type != wire.ForcerenewTypeNonce {
		return wire.ForcerenewAuth{}, false
	}
	return a, true
}

// offerCarried145 reports whether the OFFER being requested listed option 145.
// m.offer is the chosen OFFER and is cleared with every new acquisition, so
// the answer cannot come from another exchange (claymore666/docker-net-dhcp#1119).
func (m *Machine) offerCarried145() bool {
	if m.offer == nil {
		return false
	}
	_, present, err := m.offer.Options.ForcerenewNonceAlgorithms()
	return present && err == nil
}

// refusesAckWithoutNonce is RFC 6704 section 3.1.4: "if the DHCPOFFER carried
// FORCERENEW_NONCE_CAPABLE and the DHCPACK omits a valid DHCP authentication
// option, the client MUST discard the message and return to the INIT state".
// It is asked in REQUESTING only: a rapid-commit or INIT-REBOOT ACK has no
// OFFER whose capability could be held against it (claymore666/docker-net-dhcp#1119).
func (m *Machine) refusesAckWithoutNonce(msg *wire.Message) bool {
	if !m.offerCarried145() {
		return false
	}
	_, ok := validForcerenewNonce(msg)
	return !ok
}

// settleForcerenew decides which nonce and floor the lease being entered
// carries, and holds them for the machine. An ACK's own nonce wins. Without
// one a RENEWING ACK from the same server keeps what was held, because
// section 3.1.3 has the server leave it out of a renewal's ACK; any other ACK
// leaves the lease with none. The floor never falls under a floor already held
// for the same nonce: a lower value in a later ACK would reopen frames already
// used (claymore666/docker-net-dhcp#1119).
func (m *Machine) settleForcerenew(l *Lease, renewal bool) {
	if len(l.ForcerenewNonce) == wire.ForcerenewNonceLen {
		same := renewal && m.fr.have && m.fr.nonce == [wire.ForcerenewNonceLen]byte(l.ForcerenewNonce)
		if same && m.fr.floor > l.ForcerenewReplay {
			l.ForcerenewReplay = m.fr.floor
		}
		m.fr = forcerenewKey{have: true, nonce: [wire.ForcerenewNonceLen]byte(l.ForcerenewNonce), floor: l.ForcerenewReplay}
		return
	}
	if renewal && m.fr.have && l.ServerID == m.lease.ServerID {
		l.ForcerenewNonce = append([]byte(nil), m.fr.nonce[:]...)
		l.ForcerenewReplay = m.fr.floor
		return
	}
	m.fr = forcerenewKey{}
	l.ForcerenewNonce, l.ForcerenewReplay = nil, 0
}

func (m *Machine) refuseForcerenew(out *actions, why ForcerenewRefusal) {
	m.frCounts.Refused[why]++
	out.journal(m, "DHCPFORCERENEW refused: "+why.String())
}

// takeForcerenew applies RFC 3203 and RFC 6704 to one type 9 frame, cheapest
// check first, and the digest last.
//
// It is routed from Step before any state's handler, and past the xid gate on
// purpose: a FORCERENEW is server-initiated and answers no transaction of this
// client, so its xid means nothing. It is matched to this client by chaddr, by
// ciaddr being the leased address, by the destination, and by the digest
// (claymore666/docker-net-dhcp#1119).
func (m *Machine) takeForcerenew(now Instant, rnd uint64, ev Event, out *actions) {
	if m.state != StateBound && m.state != StateRenewing && m.state != StateRebinding {
		m.refuseForcerenew(out, ForcerenewRefusalWrongState)
		return
	}
	msg := ev.Msg
	if len(ev.Raw) == 0 {
		m.refuseForcerenew(out, ForcerenewRefusalNoRaw)
		return
	}
	if !m.forcerenewDestinationIsUnicast(ev.Dst) {
		m.refuseForcerenew(out, ForcerenewRefusalNotUnicast)
		return
	}
	own := m.lease.Addr.Addr()
	if ev.Dst.Unmap() != own {
		m.refuseForcerenew(out, ForcerenewRefusalNotOurAddress)
		return
	}
	if msg.Op != wire.BootReply || !m.chaddrMatches(msg) || msg.CIAddr != own {
		m.refuseForcerenew(out, ForcerenewRefusalNotThisClient)
		return
	}
	if !m.fr.have {
		m.refuseForcerenew(out, ForcerenewRefusalNoNonce)
		return
	}
	a, present, err := msg.Options.ForcerenewAuth()
	switch {
	case !present:
		m.refuseForcerenew(out, ForcerenewRefusalNoAuth)
		return
	case err != nil || a.Type != wire.ForcerenewTypeDigest:
		m.refuseForcerenew(out, ForcerenewRefusalMalformedAuth)
		return
	}
	// VerifyForcerenew judges the digest and not the replay value, so the
	// floor is compared here, and before it: RFC 3118 section 5.3.
	if a.Replay <= m.fr.floor {
		m.refuseForcerenew(out, ForcerenewRefusalReplay)
		return
	}
	if err := wire.VerifyForcerenew(ev.Raw, m.fr.nonce[:]); err != nil {
		if errors.Is(err, wire.ErrForcerenewDigest) {
			m.refuseForcerenew(out, ForcerenewRefusalBadDigest)
		} else {
			m.refuseForcerenew(out, ForcerenewRefusalMalformedAuth)
		}
		return
	}
	if m.state != StateBound {
		// RENEWING already asks the server and REBINDING is past it. The
		// frame is authentic, so its value is used up, and nothing is sent:
		// restarting the request would let any run of fresh values hold the
		// retransmission timer back for ever.
		m.fr.floor = a.Replay
		m.frCounts.AlreadyRenewing++
		out.journal(m, "DHCPFORCERENEW accepted in "+m.state.String()+": already renewing")
		return
	}
	if sid := m.lease.ServerID; !sid.Is4() || sid.IsUnspecified() {
		m.refuseForcerenew(out, ForcerenewRefusalNoServer)
		return
	}
	m.fr.floor = a.Replay
	m.frCounts.Renewed++
	out.journal(m, "DHCPFORCERENEW accepted: renewing now (RFC 3203 section 2.2)")
	m.enterRenewing(now, rnd, out)
}

// forcerenewDestinationIsUnicast is false for a destination that is absent,
// unspecified, multicast, the limited broadcast, or the broadcast of the
// leased prefix (claymore666/docker-net-dhcp#1119).
func (m *Machine) forcerenewDestinationIsUnicast(dst netip.Addr) bool {
	d := dst.Unmap()
	if !d.Is4() || d.IsUnspecified() || d.IsMulticast() || d == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return false
	}
	p := m.lease.Addr.Masked()
	if bits := p.Bits(); bits < 31 {
		last := p.Addr().As4()
		for i := bits; i < 32; i++ {
			last[i/8] |= 1 << (7 - uint(i%8))
		}
		if d == netip.AddrFrom4(last) {
			return false
		}
	}
	return true
}
