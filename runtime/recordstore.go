package runtime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/claymore666/dhcp-golib/lease"
)

// RecordStore is lease.Store over one append-only JSONL file.
//
// One event per line, opened O_APPEND, one write per Append. O_APPEND is what
// makes two processes on one file safe: the kernel takes the offset and the
// write together, so two lines interleave as two lines rather than as one
// corrupted one. That is a property of the OPEN FLAG and of writing the line in
// a single call — a formatter that wrote the object and then the newline
// separately would give it up.
//
// The file is the whole store. Rotation, compaction and any retention policy
// are the caller's, and deliberately not here: what may be dropped from a lease
// history is a privacy decision, and this package has no way to make it.
type RecordStore struct {
	path string

	mu   sync.Mutex
	f    *os.File
	torn RecordStoreDamage
}

// RecordStoreDamage is what a Load could not read. Both numbers are reported
// rather than folded into one, because they mean different things: a torn tail
// is a crash, and an unreadable line anywhere else is two writers or a damaged
// file.
type RecordStoreDamage struct {
	// TornTail is 1 when the file's last line has no terminating newline, or
	// has one and still does not parse — the shape a process killed inside
	// Append leaves.
	TornTail int
	// Skipped counts unreadable lines that are NOT the last one.
	Skipped int
}

// Any reports whether anything was skipped.
func (d RecordStoreDamage) Any() bool { return d.TornTail > 0 || d.Skipped > 0 }

func (d RecordStoreDamage) String() string {
	return fmt.Sprintf("%d torn tail, %d skipped", d.TornTail, d.Skipped)
}

// OpenRecordStore opens or creates the file at path.
//
// 0600, because the contents are a history of which machine held which address
// and when.
func OpenRecordStore(path string) (*RecordStore, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("runtime: lease record store %s: %w", path, err)
	}
	return &RecordStore{path: path, f: f}, nil
}

// Close closes the file. Safe to call more than once.
func (s *RecordStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}

// Append writes one event as one line.
//
// SYNC POLICY, per event kind. Creation, the first lease and the closing
// transitions are fsynced; renewals and counter snapshots are not. The
// asymmetry is deliberate and the direction is what makes it safe: a lost
// renewal line costs an INIT-REBOOT that asks for an address the record already
// held, which the server answers; a lost creation line costs the identity, and
// nothing can answer that.
func (s *RecordStore) Append(ev lease.RecordEvent) error {
	line, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("runtime: encoding record event: %w", err)
	}
	if bytes.ContainsRune(line, '\n') {
		return fmt.Errorf("runtime: encoded record event contains a newline, which would split one event across two lines")
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return fmt.Errorf("runtime: lease record store %s is closed", s.path)
	}
	if _, err := s.f.Write(line); err != nil {
		return fmt.Errorf("runtime: appending to %s: %w", s.path, err)
	}
	if durableWrite(ev) {
		if err := syncRecordFile(s.f); err != nil {
			return fmt.Errorf("runtime: syncing %s: %w", s.path, err)
		}
	}
	return nil
}

// syncRecordFile is the fsync itself, indirected for ONE reason: an fsync has
// no effect a same-process test can observe, so without this the policy below
// can be pinned exhaustively while the line that consults it is wired to
// nothing. TestTheSyncPolicyIsAppliedToEveryAppend swaps it and reads back
// which events were synced.
var syncRecordFile = (*os.File).Sync

// durableWrite decides whether this event is fsynced.
//
// The rule is what the line cannot be reconstructed from. The ops that bring a
// record into existence carry the identity and the address, and nothing later
// can re-derive either; the first lease of a manager instance carries the
// binding itself. Everything else — renewals, tombstone transitions, the close,
// counter snapshots — is either re-derivable from a later exchange or costs
// only an earlier INIT-REBOOT, which is the safe direction.
//
// TestTheSyncPolicyIsClassifiedForEveryOperation walks lease.AllOps so a new
// operation cannot arrive unclassified.
func durableWrite(ev lease.RecordEvent) bool {
	switch ev.Op {
	case lease.OpReserve, lease.OpCreate, lease.OpRebind, lease.OpAdopt, lease.OpBind:
		return true
	case lease.OpLease:
		return ev.Kind == lease.Acquired
	default:
		return false
	}
}

// Load reads every event in append order.
//
// It reads the file rather than the handle it writes through, so a Load is
// valid on a store another process is appending to.
func (s *RecordStore) Load() ([]lease.RecordEvent, error) {
	b, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("runtime: reading %s: %w", s.path, err)
	}
	evs, damage := parseRecordLines(b)
	s.mu.Lock()
	s.torn = damage
	s.mu.Unlock()
	return evs, nil
}

// Damage reports what the last Load could not read. It is a COUNT and not a
// log line: a store that quietly drops a record is the failure this exists
// against, and a number nobody reads is the same failure with extra steps.
func (s *RecordStore) Damage() RecordStoreDamage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.torn
}

// parseRecordLines is Load's body as a pure function of the bytes, so that
// every torn shape is drivable without a filesystem.
//
// THE LAST LINE IS SPECIAL, and only the last one. A file that does not end in
// a newline has a fragment at the end, which is exactly what a process killed
// inside Append leaves; an unreadable one there is TornTail. An unreadable line
// anywhere else cannot be a crash — the writer had already written the newline
// after it — so it is a different number.
//
// A final line with no newline that DOES parse is kept, and that is not
// leniency. Append writes the object and its newline in one call, so a
// truncation lands inside the object far more often than exactly after it; and
// a JSON object is not prefix-valid — cut anywhere before the closing brace it
// does not parse. So a tail that parses is a whole event whose newline did not
// make it to disk, and dropping it would lose a record for the sake of a
// symmetry.
func parseRecordLines(b []byte) ([]lease.RecordEvent, RecordStoreDamage) {
	var (
		out    []lease.RecordEvent
		damage RecordStoreDamage
	)
	if len(b) == 0 {
		return nil, damage
	}
	lines := bytes.Split(b, []byte("\n"))
	// tailIdx is the ONLY carrier of "which line is the fragment", and it
	// names no line at all when the file ends in a newline: there is then
	// nothing half-written, and the empty final element Split leaves is
	// skipped below like any other blank.
	tailIdx := -1
	if !bytes.HasSuffix(b, []byte("\n")) {
		tailIdx = len(lines) - 1
	}
	for i, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var ev lease.RecordEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			if i == tailIdx {
				damage.TornTail++
			} else {
				damage.Skipped++
			}
			continue
		}
		out = append(out, ev)
	}
	return out, damage
}

// The port this implements. A compile error is the only guard that cannot be
// forgotten.
var _ lease.Store = (*RecordStore)(nil)
