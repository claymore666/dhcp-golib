// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"fmt"

	"github.com/claymore666/dhcp-golib/wire"
)

// Hostname is the name option 39 carries now: Params6.Hostname until an
// EvSetHostname changes it. A restart persists this, not Params().Hostname.
func (m *Machine6) Hostname() string { return m.hostname }

// takeHostname6 applies a name set on a running client and tells the server,
// as takeHostname does for v4 (#961). An invalid name is journalled and the
// current one is kept.
func (m *Machine6) takeHostname6(now Instant, rnd uint64, ev Event, out *actions) {
	if err := ValidateHostname6(ev.Hostname); err != nil {
		out.journal(m, "hostname refused: "+err.Error())
		return
	}
	m.hostname = ev.Hostname
	if m.announceHostname6(now, rnd, out) {
		return
	}
	out.journal(m, fmt.Sprintf("hostname %q recorded in %s: option 39 last carried %q and no message was sent", m.hostname, m.state, m.nameOnWire))
}

// announceHostname6 sends a name the server has not been told and reports
// whether a message went out. Decision 2026-09-24: from BOUND6 it is an early
// Renew. RFC 4704 section 5.4 says a client whose name changes "MAY send the
// new name data in a Client FQDN option when it communicates with the server
// again"; it does not say when, and RFC 9915 names no early Renew for this.
// A name held open until T1 would leave the server's table stale for T1.
// In a Renew or Rebind the name goes in a new exchange: RFC 9915 section 16.1
// keeps the transaction ID only for "retransmissions of a message". An empty
// name sends nothing, as in v4: no DHCPv6 message withdraws a name.
func (m *Machine6) announceHostname6(now Instant, rnd uint64, out *actions) bool {
	if m.hostname == "" || m.hostname == m.nameOnWire {
		return false
	}
	switch m.state {
	case State6Bound:
		if !m.haveLse || m.lease.SLAAC {
			return false
		}
		out.journal(m, "a new name: renewing before T1 to carry it")
		m.enterRenewing(now, rnd, out)
	case State6Renewing:
		out.journal(m, "a new name: the Renew restarts as a new exchange carrying it")
		m.startExchange(now, rnd, wire.MsgRenew, out)
	case State6Rebinding:
		out.journal(m, "a new name: the Rebind restarts as a new exchange carrying it")
		m.startExchange(now, rnd, wire.MsgRebind, out)
	default:
		// No exchange that may carry option 39 is open. The next Solicit or
		// Request carries the name and enterBound checks again.
		return false
	}
	return m.nameOnWire == m.hostname
}

// fqdnOption is option 39's value for a message of type t, or nil. RFC 4704
// section 5: "A client MUST only include the Client FQDN option in SOLICIT,
// REQUEST, RENEW, or REBIND messages." S=1, O=N=0 asks the server to update
// the AAAA record (section 5.2 of the same RFC). It also records nameOnWire.
func (m *Machine6) fqdnOption(t wire.MessageTypeV6) ([]byte, error) {
	switch t {
	case wire.MsgSolicit, wire.MsgRequest6, wire.MsgRenew, wire.MsgRebind:
	default:
		return nil, nil
	}
	m.nameOnWire = m.exchangeName
	if m.exchangeName == "" {
		return nil, nil
	}
	return wire.EncodeClientFQDN(wire.ClientFQDNFlagS, m.exchangeName)
}
