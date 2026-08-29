//go:build !linux

package runtime

import (
	"time"

	"github.com/claymore666/dhcplease/proto"
)

// processStart anchors the fallback monotonic clock.
var processStart = time.Now()

// monoNow is the non-Linux fallback, and it is NOT equivalent to the Linux
// implementation.
//
// Go's monotonic reading is CLOCK_MONOTONIC, which does not advance across a
// host suspend. On this build a suspend therefore under-counts elapsed lease
// time and the client holds an address longer than it was granted. That is
// stated rather than hidden because the library's target is Linux containers
// and this file exists to keep the package compiling, not to claim parity.
func monoNow() proto.Instant {
	return proto.Instant(time.Since(processStart))
}
