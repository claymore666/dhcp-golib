package proto

import "fmt"

// State is a DHCPv4 client state, named as RFC 2131 section 4.4 names them.
type State uint8

// The states this milestone implements, plus Stopped.
//
// RENEWING, REBINDING and INIT-REBOOT are deliberately absent. M1's scope is
// INIT to BOUND; the states that maintain a BOUND lease are the next
// milestone's, and adding their names here without their transitions would put
// three unreachable values into the exhaustive totality test and make it look
// like more was covered than is.
//
// The consequence is written down rather than left implicit: a lease acquired
// by this machine is NOT renewed. At expiry the machine returns to INIT and
// re-acquires from scratch. RFC 2131 section 4.4.5 requires exactly that on
// expiry ("the client moves to INIT state, MUST immediately stop any other
// network processing"), so this is conformant — but it fails the PRODUCT bar,
// because the address can change at every lease expiry. Nothing depends on
// this library until M7.
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
	default:
		return fmt.Sprintf("state(%d)", uint8(s))
	}
}

// AllStates is every State this machine can be in.
//
// It exists so the totality test (R1) enumerates the domain from one place. A
// test that hand-lists the states drifts from the type the day one is added,
// and drifts in the direction that reports a smaller domain as fully covered.
func AllStates() []State {
	return []State{StateStopped, StateInit, StateSelecting, StateRequesting, StateBound}
}
