// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import "fmt"

// takeHostname applies a name supplied after the client started.
//
// THE NAME IS ALSO A MESSAGE. A caller that hands a running client a name has
// not configured anything: it is asking for the server's table to carry that
// name, and a value stored until the next renewal is that request unanswered
// for up to half a lease. So this records the name AND tells the server, and
// announceHostname is where "tells the server" is decided.
func (m *Machine) takeHostname(now Instant, rnd uint64, ev Event, out *actions) {
	if !m.sendsHostname() {
		out.journal(m, "hostname ignored: this client sends option 81, which RFC 4702 section 3.1 forbids the Host Name option beside")
		return
	}
	if err := ValidateHostname(ev.Hostname); err != nil {
		out.journal(m, "hostname refused: "+err.Error())
		return
	}
	m.hostname = ev.Hostname
	if m.announceHostname(now, rnd, out) {
		return
	}
	out.journal(m, fmt.Sprintf("hostname %q recorded in %s: option 12 carries %q and no message was sent", m.hostname, m.state, m.nameOnWire))
}

// announceHostname sends the current name to the server when the server has
// not been told it, and reports whether a message went out.
//
// THE MESSAGE IS RFC 2131 SECTION 4.4.5'S RENEWAL, SENT EARLY. The section
// permits it in as many words — "A client MAY choose to renew or extend its
// lease prior to T1" — and section 4.3.2's DHCPREQUEST-generated-during-
// RENEWING bullet says what it must look like: "'server identifier' MUST NOT
// be filled in, 'requested IP address' option MUST NOT be filled in, 'ciaddr'
// MUST be filled in with client's IP address". That is sendRenewal and nothing
// else, which is why this reaches it through enterRenewing rather than
// building a message of its own.
//
// THE STATE MOVES WITH THE MESSAGE, and that is the load-bearing half. A
// DHCPREQUEST sent while the machine stayed in BOUND would have its DHCPACK
// discarded — stepBound answers a message arriving with no transaction open by
// throwing it away — so the name would reach the server and the lease timers
// would never move. There is no way to send this message and not change state.
//
// It costs what an early renewal costs: from RENEWING a DHCPNAK drops the
// address, where a client sitting in BOUND would have kept it until T1. That
// is the server repudiating the binding, heard now rather than half a lease
// later, and TestAHostnameRenewalThatIsNAKedLosesTheLease pins it.
//
// A LEASE WITH NO SERVER IDENTIFIER STAYS IN BOUND. enterRenewing refuses to
// unicast to a server it cannot name and says so in the journal; the name then
// goes out in the broadcast DHCPREQUEST at T2. Reported as "not sent" here,
// because it was not, and TestAHostnameOnALeaseWithNoServerIdentifierWaitsForT2
// drives it.
//
// CLEARING THE NAME SENDS NOTHING. An empty name takes option 12 off the next
// message this machine builds, and that is all it can do: DHCP has no message
// that withdraws a name, so the server keeps what it already holds either way.
// An early renewal whose only difference is an absent option would spend a
// DHCPREQUEST, and the DHCPNAK risk above, to change nothing at the server.
// The name a caller SETS is a request the server can answer; the name it
// clears is not.
func (m *Machine) announceHostname(now Instant, rnd uint64, out *actions) bool {
	if !m.sendsHostname() || m.hostname == m.nameOnWire || m.hostname == "" {
		return false
	}
	switch m.state {
	case StateBound:
		m.enterRenewing(now, rnd, out)
		return m.state == StateRenewing
	case StateRenewing, StateRebinding:
		// A transaction is already open and its DHCPREQUEST carried the old
		// name. This is a retransmission of that transaction rather than a new
		// one: section 4.4.5 measures the lease from the moment the request
		// was sent and sendRenewal re-stamps that on every attempt, so the
		// answer to whichever copy the server sees is the same answer.
		m.sendRenewal(now, out)
		return true
	default:
		// Nothing is held and nothing is in flight, so there is no message
		// this name belongs in. The next one this machine builds carries it,
		// and enterBound checks again the moment there is a lease — which is
		// what makes a name that arrives before the lease reach the server at
		// the bind instead of at T1.
		//
		// The states are all six that are not BOUND, RENEWING or REBINDING,
		// and each has its own observer rather than an entry in a list here:
		// STOPPED and INIT (the first DHCPDISCOVER, one of them through RFC
		// 2131 section 4.4.1's desync wait), SELECTING and REQUESTING (the
		// bind), REBOOTING (the retransmitted DHCPREQUEST of section 3.2) and
		// PROBING (the announcement after RFC 5227 section 2.1's check).
		return false
	}
}

// sendsHostname reports whether option 12 is this client's to send at all.
//
// RFC 4702 section 3.1: a client sending option 81 "MUST NOT also send the
// Host Name option", and base() honours that by never reaching the option-12
// arm. So for an FQDN client a recorded name is one this machine can never
// send — stored, silent and indistinguishable from working — and an announcing
// DHCPREQUEST would be a renewal that changed nothing.
//
// ONE PREDICATE FOR BOTH HALVES. takeHostname refuses to record and says so;
// announceHostname refuses to send, and it is reached from enterBound as well,
// where nothing else would have asked. Written twice, the enterBound path is
// the one that renews the lease on every acquisition of an FQDN client that was
// also handed a Hostname — which is what TestFqdnReplacesTheHostNameOption
// measured when this was a single check inside takeHostname.
func (m *Machine) sendsHostname() bool { return len(m.params.fqdn) == 0 }
