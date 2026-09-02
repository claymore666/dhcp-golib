package proto

import "fmt"

// State is a DHCPv4 client state, named as RFC 2131 section 4.4 names them.
type State uint8

// The states this machine implements, plus Stopped. INIT-REBOOT and REBOOTING
// are still absent: naming them without their transitions would put
// unreachable values into the exhaustive totality test and make it look like
// more was covered than is.
//
// CONSEQUENCE: a client restarted with a remembered address re-acquires from
// INIT rather than verifying the address it had, so the address can change
// across a restart. RFC 2131 section 4.3.2's INIT-REBOOT DHCPREQUEST is what
// closes that, and it needs somewhere to remember the address from.
const (
	// StateStopped is the state before Start and after Stop. It is not an RFC
	// state; it exists so that Step is total over "events that arrive when we
	// are not running", which is otherwise the gap a real client falls into
	// during teardown.
	StateStopped State = iota
	// StateInit is RFC 2131's INIT. Nothing has been sent.
	StateInit
	// StateSelecting is RFC 2131's SELECTING: DISCOVER sent, collecting OFFERs.
	StateSelecting
	// StateRequesting is RFC 2131's REQUESTING: REQUEST sent, awaiting ACK/NAK.
	StateRequesting
	// StateBound is RFC 2131's BOUND: the lease is held.
	StateBound
	// StateRenewing is RFC 2131's RENEWING, entered at T1: the lease is still
	// held and a DHCPREQUEST is in flight, unicast to the server that issued
	// it (section 4.4.5).
	StateRenewing
	// StateRebinding is RFC 2131's REBINDING, entered at T2: the lease is
	// still held and the DHCPREQUEST is broadcast, so that ANY server may
	// answer (section 4.4.5).
	StateRebinding
)

func (s State) String() string {
	switch s {
	case StateStopped:
		return "STOPPED"
	case StateInit:
		return "INIT"
	case StateSelecting:
		return "SELECTING"
	case StateRequesting:
		return "REQUESTING"
	case StateBound:
		return "BOUND"
	case StateRenewing:
		return "RENEWING"
	case StateRebinding:
		return "REBINDING"
	default:
		return fmt.Sprintf("state(%d)", uint8(s))
	}
}

// AllStates is every State this machine can be in, so that the totality test
// (R1) enumerates the domain from one place: a test that hand-lists the states
// drifts the day one is added, in the direction that reports a smaller domain
// as fully covered.
func AllStates() []State {
	return []State{
		StateStopped, StateInit, StateSelecting, StateRequesting, StateBound,
		StateRenewing, StateRebinding,
	}
}
