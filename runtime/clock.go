package runtime

import (
	"time"

	"github.com/claymore666/dhcplease/proto"
)

// Clock is the two-clock implementation the design document's section 8.2
// requires.
//
// Mono is CLOCK_BOOTTIME, not CLOCK_MONOTONIC, and that is the whole reason
// this type exists rather than a wrapper around time.Now. The two differ in
// exactly one respect and it is the one that matters here: CLOCK_MONOTONIC
// does not advance across a host suspend, CLOCK_BOOTTIME does. A container
// host that suspends for an hour with CLOCK_MONOTONIC driving the lease timers
// wakes up believing an hour of lease time is still unspent, holds an address
// the server has already reissued, and nothing anywhere logs a word about it.
//
// Wall is the ordinary wall clock, and it is used for exactly one thing: the
// absolute times reported outward and (from the next milestone) persisted. A
// monotonic reading means nothing to the next process, so an expiry that must
// survive a restart can only be stored as wall-clock absolute.
//
// Neither is a substitute for the other, which is why the interface has both
// rather than one with a comment.
type Clock struct{}

// Mono returns a reading of CLOCK_BOOTTIME.
func (Clock) Mono() proto.Instant { return monoNow() }

// Wall returns the wall-clock time.
func (Clock) Wall() time.Time { return time.Now() }

// FixedClock is a Clock a test drives by hand. It is here rather than in a
// _test.go file because ring-3 tests in other packages need it too, and
// because the alternative — a test-only build tag — is the shape that lets a
// fake leak into production code without anything noticing.
type FixedClock struct {
	MonoAt proto.Instant
	WallAt time.Time
}

// Mono returns the fixed monotonic reading.
func (c *FixedClock) Mono() proto.Instant { return c.MonoAt }

// Wall returns the fixed wall reading.
func (c *FixedClock) Wall() time.Time { return c.WallAt }

// Advance moves both clocks forward by the same amount.
func (c *FixedClock) Advance(d proto.Duration) {
	c.MonoAt = c.MonoAt.Add(d)
	c.WallAt = c.WallAt.Add(time.Duration(d))
}
