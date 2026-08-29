// Package rings is the single source of truth for the ring layout and for the
// policies the T1 and T2 gates enforce. Both gates read it; neither restates
// it. An enumeration re-typed per consumer is an unrun checklist.
package rings

// Module is the module path this repository declares. It is hardcoded on
// purpose rather than read from go.mod: a gate that derives its parameter from
// its subject cannot refuse the subject. CheckModulePath compares the two and
// refuses on a mismatch, so a rename fails loudly instead of reclassifying
// every internal import as third-party.
const Module = "github.com/claymore666/dhcplease"

// The ring roots, relative to the module root. Directories, not import paths.
//
// These are hardcoded for the same reason Module is. Deriving the ring set
// from whatever directories happen to exist would let a rename empty the
// gate's domain silently, which is this project's most repeated gate defect.
// Both gates require every root below to exist and to hold at least one .go
// file, and refuse otherwise.
var (
	Ring0 = []string{"wire"}    // codec
	Ring1 = []string{"proto"}   // the state machine, pure
	Ring2 = []string{"lease"}   // the manager
	Ring3 = []string{"runtime"} // effects: sockets, clock, netlink, netns
)

// Pure returns the ring roots subject to the purity policy: ring 1, plus
// ring 0 because ring 1 imports it and an impure ring 0 makes ring 1 impure.
func Pure() []string {
	out := make([]string, 0, len(Ring0)+len(Ring1))
	out = append(out, Ring1...)
	out = append(out, Ring0...)
	return out
}

// Impure returns the ring roots that are allowed to do I/O. Ring 1 must not
// reach any of these, transitively or otherwise.
func Impure() []string {
	out := make([]string, 0, len(Ring2)+len(Ring3))
	out = append(out, Ring2...)
	out = append(out, Ring3...)
	return out
}

// PureStdlib is the complete set of standard-library packages a pure ring may
// import. It is an ALLOWLIST, not a denylist of {net, time, os, context,
// syscall}, and the difference is the whole point: a denylist is keyed on
// today's spelling and admits every package nobody thought to name. This set
// admits nothing by default, so a new import is a refusal until somebody
// decides it belongs here.
//
// Two consequences worth stating rather than discovering:
//
//   - "net/netip" is admitted and "net" is not. netip is value types with no
//     resolver, no socket and no ambient state; net is the opposite. A
//     denylist written as == "net" would have admitted net/http, and one
//     written as a "net" prefix would have banned netip.
//   - "fmt" is admitted because Errorf and Sprintf are unavoidable, and it is
//     the one admitted package that can perform I/O. FmtAllowed below closes
//     that, by restricting which fmt identifiers a pure ring may name.
var PureStdlib = map[string]bool{
	"bytes":           true,
	"cmp":             true,
	"encoding/binary": true,
	"encoding/hex":    true,
	"errors":          true,
	"fmt":             true,
	"iter":            true,
	"math":            true,
	"math/bits":       true,
	"net/netip":       true,
	"slices":          true,
	"sort":            true,
	"strconv":         true,
	"strings":         true,
	"unicode/utf8":    true,
}

// FmtAllowed is the set of fmt identifiers a pure ring may reference. Every
// entry returns a value; none writes anywhere. Print, Println, Printf,
// Fprintf, Scan and friends are absent, which is what stops an admitted "fmt"
// from being a hole in the purity claim.
var FmtAllowed = map[string]bool{
	"Append":     true,
	"Appendf":    true,
	"Appendln":   true,
	"Errorf":     true,
	"Formatter":  true,
	"GoStringer": true,
	"Sprint":     true,
	"Sprintf":    true,
	"Sprintln":   true,
	"Sscan":      true,
	"Sscanf":     true,
	"Sscanln":    true,
	"State":      true,
	"Stringer":   true,
}

// PureIdents restricts, per import path, which identifiers a pure ring file
// may name. A package absent from this map is unrestricted once it is on
// PureStdlib.
var PureIdents = map[string]map[string]bool{
	"fmt": FmtAllowed,
}

// TestIdents restricts, per import path, which identifiers a _test.go file may
// name. This is T2: no test waits on wall-clock time.
//
// Allowlists again, for the same reason. time.Sleep, time.After, time.Tick,
// time.NewTimer, time.NewTicker and time.AfterFunc are absent, and so is
// anything the standard library adds later, until somebody adds it here.
//
// time.Now, time.Since and time.Until ARE allowed. They read the clock, they
// do not wait on it, and T2's subject is waiting. That is a deliberate bound,
// not an oversight.
var TestIdents = map[string]map[string]bool{
	"time": {
		"ANSIC": true, "DateOnly": true, "DateTime": true, "Kitchen": true,
		"Layout": true, "RFC1123": true, "RFC1123Z": true, "RFC3339": true,
		"RFC3339Nano": true, "RFC822": true, "RFC822Z": true, "RFC850": true,
		"RubyDate": true, "Stamp": true, "StampMicro": true, "StampMilli": true,
		"StampNano": true, "TimeOnly": true, "UnixDate": true,

		"Nanosecond": true, "Microsecond": true, "Millisecond": true,
		"Second": true, "Minute": true, "Hour": true,

		"January": true, "February": true, "March": true, "April": true,
		"May": true, "June": true, "July": true, "August": true,
		"September": true, "October": true, "November": true, "December": true,
		"Sunday": true, "Monday": true, "Tuesday": true, "Wednesday": true,
		"Thursday": true, "Friday": true, "Saturday": true,

		"Duration": true, "Location": true, "Month": true, "ParseError": true,
		"Time": true, "Weekday": true,

		"Date": true, "FixedZone": true, "LoadLocation": true,
		"LoadLocationFromTZData": true, "Local": true, "Now": true,
		"Parse": true, "ParseDuration": true, "ParseInLocation": true,
		"Since": true, "UTC": true, "Unix": true, "UnixMicro": true,
		"UnixMilli": true, "Until": true,
	},
	// A deadline on a context is a wall-clock wait wearing a different name:
	// whatever blocks on ctx.Done() is waiting for a timer to fire.
	"context": {
		// AfterFunc is deliberately absent: fail-closed by omission.
		"Background": true, "CancelCauseFunc": true,
		"CancelFunc": true, "Canceled": true, "Cause": true, "Context": true,
		"DeadlineExceeded": true, "TODO": true, "WithCancel": true,
		"WithCancelCause": true, "WithValue": true, "WithoutCancel": true,
	},
}
