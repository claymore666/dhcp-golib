// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"fmt"

	"github.com/claymore666/dhcp-golib/wire"
)

// RapidCommitCounters is what this machine did with DHCPACKs carrying option
// 80. Accepted is a lease taken with no DHCPREQUEST; Refused is an ACK+80 turned
// down by any rule below, each of which also writes its own journal line
// (claymore666/docker-net-dhcp#1031).
type RapidCommitCounters struct {
	Accepted uint64
	Refused  uint64
}

// RapidCommitCounters returns the counters as a copy.
func (m *Machine) RapidCommitCounters() RapidCommitCounters { return m.rapidCounts }

// hasRapidOption reports whether the message carries option 80 in any form,
// malformed included: an ACK with the option is never treated as a plain one
// (claymore666/docker-net-dhcp#1031).
func hasRapidOption(msg *wire.Message) bool {
	if msg == nil {
		return false
	}
	_, ok := msg.Options[wire.OptRapidCommit]
	return ok
}

func (m *Machine) refuseRapid(out *actions, state State, why string) {
	m.rapidCounts.Refused++
	out.journal(m, fmt.Sprintf("DHCPACK with Rapid Commit in %s: refused, %s", state, why))
}

// takeRapidAck handles a DHCPACK carrying option 80 in SELECTING. RFC 4039
// section 3.1 step 3 lets the client take it as the lease with no DHCPREQUEST,
// and section 3 has the client use the option only when configured to
// (claymore666/docker-net-dhcp#1031).
//
// acceptable has already passed it: xid, chaddr and Params.Servers. What is
// left is this client's own choice, a server identifier to renew against, and
// a lease that outlives its own acquisition.
func (m *Machine) takeRapidAck(now Instant, rnd uint64, msg *wire.Message, out *actions) {
	if _, err := msg.Options.RapidCommit(); err != nil {
		m.refuseRapid(out, StateSelecting, "option 80 is malformed")
		return
	}
	if !m.params.RapidCommit {
		m.refuseRapid(out, StateSelecting, "the DHCPDISCOVER did not ask for it")
		return
	}
	if sid, ok := msg.Addr4(wire.OptServerID); !ok || sid.IsUnspecified() {
		m.refuseRapid(out, StateSelecting, "no usable server identifier")
		return
	}
	lse, note, ok := leaseFromAck(msg, m.requestSentAt)
	if !ok {
		m.refuseRapid(out, StateSelecting, "no usable yiaddr and lease time")
		return
	}
	if lse.LeaseTime <= 0 && !lse.LeaseTime.IsInfinite() {
		m.refuseRapid(out, StateSelecting, "lease time is 0")
		return
	}
	m.rapidCounts.Accepted++
	out.journal(m, fmt.Sprintf("DHCPACK with Rapid Commit for %s from %s: lease taken, no DHCPREQUEST sent", lse.Addr.Addr(), lse.ServerID))
	if note != "" {
		out.journal(m, note)
	}
	// A Rapid Commit ACK has committed the binding, and RFC 8925 section 3.2
	// has a client in any state but an OFFER's or INIT-REBOOT's keep its
	// address (claymore666/docker-net-dhcp#1027).
	m.noteV6OnlyKept(msg, StateSelecting, out)
	m.afterAck(now, rnd, lse, out)
}

// refusesRapidInRequesting reports whether an ACK carrying option 80 must not
// be taken in REQUESTING. A client that sent option 80 and got a plain OFFER
// is here; an ACK+80 from another server, or for another address, is that
// server's rapid commit of the DISCOVER, not the answer to this REQUEST
// (claymore666/docker-net-dhcp#1031). One from the server asked, for the
// address asked, is the ordinary answer and is taken.
func (m *Machine) refusesRapidInRequesting(msg *wire.Message, out *actions) bool {
	if !m.params.RapidCommit || !hasRapidOption(msg) || m.offer == nil {
		return false
	}
	offered, _ := m.offer.Addr4(wire.OptServerID)
	sid, _ := msg.Addr4(wire.OptServerID)
	if _, err := msg.Options.RapidCommit(); err == nil && sid == offered && msg.YIAddr == m.offer.YIAddr {
		return false
	}
	m.refuseRapid(out, StateRequesting, "it does not answer the offer being requested")
	return true
}
