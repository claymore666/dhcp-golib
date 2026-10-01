// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"fmt"

	"github.com/claymore666/dhcp-golib/wire"
)

// MinV6OnlyWait is RFC 8925 section 3.4's MIN_V6ONLY_WAIT, the shortest pause
// a server's option 108 can buy (claymore666/docker-net-dhcp#1027).
const MinV6OnlyWait = 300 * Second

// IPv6OnlyCounters is what this machine did with option 108 while
// Params.IPv6OnlyPreferred was set. Waited is a DHCPv4 pause started by an
// OFFER or an INIT-REBOOT ACK; Ignored is an ACK carrying 108 where RFC 8925
// section 3.2 has the client keep its address; Malformed is a 108 whose length
// is not 4, treated as absent (claymore666/docker-net-dhcp#1027).
type IPv6OnlyCounters struct {
	Waited    uint64
	Ignored   uint64
	Malformed uint64
}

// IPv6OnlyCounters returns the counters as a copy (claymore666/docker-net-dhcp#1027).
func (m *Machine) IPv6OnlyCounters() IPv6OnlyCounters { return m.v6OnlyCounts }

// v6OnlyWait is V6ONLY_WAIT for a server's option value: RFC 8925 section 3.2
// "If the value is less than MIN_V6ONLY_WAIT, the client SHOULD set the
// V6ONLY_WAIT timer to MIN_V6ONLY_WAIT" (claymore666/docker-net-dhcp#1027).
func v6OnlyWait(secs uint32) Duration {
	d := Duration(secs) * Second
	if d < MinV6OnlyWait {
		return MinV6OnlyWait
	}
	return d
}

// v6OnlyValue reads option 108 from a message for a client that asked for it.
// A client that did not "MUST ignore" it (RFC 8925 section 3.2), and a length
// other than 4 is counted and read as absent
// (claymore666/docker-net-dhcp#1027).
func (m *Machine) v6OnlyValue(msg *wire.Message, out *actions) (uint32, bool) {
	if !m.params.IPv6OnlyPreferred || msg == nil {
		return 0, false
	}
	secs, present, err := msg.Options.IPv6OnlyPreferred()
	if !present {
		return 0, false
	}
	if err != nil {
		m.v6OnlyCounts.Malformed++
		out.journal(m, fmt.Sprintf("option 108 ignored: %v", err))
		return 0, false
	}
	return secs, true
}

// waitForIPv6 pauses DHCPv4 for V6ONLY_WAIT: no REQUEST, DECLINE or RELEASE,
// everything cancelled by toInitIdle, then the restart timer that
// declineAndRestart also uses. The timer's expiry is a fresh DISCOVER and a
// LinkUp in INIT is another, which is section 3.2's "or until a network
// attachment event" (claymore666/docker-net-dhcp#1027).
func (m *Machine) waitForIPv6(now Instant, out *actions, from State, secs uint32) {
	m.v6OnlyCounts.Waited++
	d := v6OnlyWait(secs)
	m.toInitIdle(out)
	out.failed(m, ReasonIPv6OnlyPreferred, fmt.Sprintf("option 108 in %s: DHCPv4 paused for %s", from, d))
	out.set(m, TimerRestart, d)
	out.journal(m, fmt.Sprintf("INIT: IPv6-only preferred, waiting %s before restarting (RFC 8925 3.2)", d))
}

// noteV6OnlyKept counts a DHCPACK carrying 108 in a state where RFC 8925
// section 3.2 has the client "continue to use the assigned IPv4 address"; the
// ACK itself is handled as any other (claymore666/docker-net-dhcp#1027).
func (m *Machine) noteV6OnlyKept(msg *wire.Message, state State, out *actions) {
	if msg == nil {
		return
	}
	if t, _ := msg.Type(); t != wire.MsgAck {
		return
	}
	if _, ok := m.v6OnlyValue(msg, out); ok {
		m.v6OnlyCounts.Ignored++
		out.journal(m, fmt.Sprintf("DHCPACK with option 108 in %s: lease kept", state))
	}
}

// listsCode reports whether a parameter request list names the code (claymore666/docker-net-dhcp#1027).
func listsCode(list []byte, c wire.OptionCode) bool {
	for _, b := range list {
		if b == byte(c) {
			return true
		}
	}
	return false
}
