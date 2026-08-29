package runtime

import (
	"sync"

	"github.com/claymore666/dhcplease/proto"
)

// Journal is the bounded in-memory journal (requirements G2, R3).
//
// Bounded because R3 says every buffer in this library has a fixed maximum: a
// long-lived client renews for months, and an unbounded journal is a memory
// leak with a respectable name. When the ring wraps, the OLDEST entries are
// discarded and Dropped counts them.
//
// Dropped is not decoration. Replay (proto.Replay) needs a CONTIGUOUS run of
// entries starting at the machine's start; a wrapped journal cannot supply one,
// and Entries() would otherwise hand back a plausible-looking prefix-less
// sequence that replays into a divergence nobody could explain. A caller that
// wants replayability checks Dropped is zero, and the divergence it would
// otherwise chase is named at its source.
type Journal struct {
	mu      sync.Mutex
	buf     []proto.JournalEntry
	next    int
	full    bool
	dropped int
}

// DefaultJournalSize is the number of entries a Journal keeps.
//
// 4096 entries covers an acquisition and a long run of renewals with room to
// spare, and costs a few hundred kilobytes. It is a default, not a limit: a
// caller that wants the whole life of a process journalled asks for it.
const DefaultJournalSize = 4096

// NewJournal returns a journal holding at most size entries. A size below 1 is
// raised to 1 rather than producing a journal that silently records nothing —
// a zero-capacity recorder and a working one are indistinguishable from the
// outside, which is the shape this project keeps paying for.
func NewJournal(size int) *Journal {
	if size < 1 {
		size = 1
	}
	return &Journal{buf: make([]proto.JournalEntry, size)}
}

// Append records one entry, discarding the oldest if the ring is full.
func (j *Journal) Append(e proto.JournalEntry) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.full {
		j.dropped++
	}
	j.buf[j.next] = e
	j.next = (j.next + 1) % len(j.buf)
	if j.next == 0 {
		j.full = true
	}
}

// Entries returns the retained entries oldest-first.
func (j *Journal) Entries() []proto.JournalEntry {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]proto.JournalEntry, 0, len(j.buf))
	if j.full {
		out = append(out, j.buf[j.next:]...)
	}
	out = append(out, j.buf[:j.next]...)
	return out
}

// Dropped is how many entries the ring has discarded. Non-zero means Entries()
// is not replayable — see the type comment.
func (j *Journal) Dropped() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.dropped
}
