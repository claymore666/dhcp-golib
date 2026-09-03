package runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	torn lease.StoreDamage
}

// OpenRecordStore opens or creates the file at path.
//
// 0600, because the contents are a history of which machine held which address
// and when.
//
// THE DIRECTORY IS FSYNCED WHEN THE FILE IS CREATED, and that is not the same
// fsync Append does. Syncing a file makes its CONTENTS durable; it says
// nothing about the directory entry that names it, so a machine that lost
// power after the first creating event could come back with the event synced
// and no file to find it in — the one case the sync policy says nothing can
// re-derive. ext4 with its default options usually saves this, which is a
// filesystem's behaviour and not a guarantee this store may make.
//
// O_EXCL is how creation is detected: O_CREATE alone cannot tell an open from
// a create, and a directory sync on every open would pay for it on every
// process start. A racing creator between the two opens is the one case the
// fallback reports as an error rather than papering over, and the winner of
// that race syncs the directory anyway.
//
// A FRAGMENT IS TERMINATED BEFORE THE FIRST APPEND. O_APPEND writes at the end
// of the FILE, not at the start of a line, so an existing file whose last byte
// is not a newline would take this process's first event onto the previous
// process's half-written one and lose both. That first event is the restart
// path's adopt — an event durableWrite fsyncs precisely because nothing can
// re-derive it — so the newline goes in at open, and the fragment is counted
// as damage at that moment: Damage and the next Load then report the SAME line
// the same way, instead of one number standing for two lost events.
//
// ORDER, and the reason for it. The terminator is written AND FSYNCED before
// any Append, not left to the first durable Append's fsync to carry. Two
// unsynced writes to one file are not ordered against each other across a
// power loss: the event's bytes could reach the disk while the newline before
// them did not, which is the defect this exists to prevent, reassembled. It
// costs one fsync on a path that by definition follows a crash. It does not
// interact with the directory sync above — that one runs only when the file
// was CREATED, and a created file has no fragment — but the rule the two share
// is the same: make the file findable and consistent BEFORE the first event
// depends on it.
//
// A second, live writer is not a hazard here. Append writes a whole line in
// one call, so a file that does not end in a newline while another writer is
// between calls is a file that writer died inside; and if one does append
// between the read below and the write, O_APPEND puts the terminator after its
// line, where it is a blank line — skipped, and not counted as damage.
func OpenRecordStore(path string) (*RecordStore, error) {
	created := true
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0o600)
	if errors.Is(err, os.ErrExist) {
		created = false
		f, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	}
	if err != nil {
		return nil, fmt.Errorf("runtime: lease record store %s: %w", path, err)
	}
	s := &RecordStore{path: path, f: f}
	if created {
		if err := syncDir(filepath.Dir(path)); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("runtime: making %s findable: %w", path, err)
		}
		return s, nil
	}
	fragment, err := endsMidLine(path)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("runtime: reading the end of %s: %w", path, err)
	}
	if fragment {
		if _, err := f.Write([]byte("\n")); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("runtime: terminating the fragment at the end of %s: %w", path, err)
		}
		if err := syncRecordFile(f); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("runtime: syncing the terminated fragment in %s: %w", path, err)
		}
		s.torn = lease.StoreDamage{Skipped: 1}
	}
	return s, nil
}

// endsMidLine reports whether the file's LAST BYTE is something other than a
// newline, which is the shape a process killed inside Append leaves.
//
// It reads one byte rather than the file: a journal is unbounded and this runs
// on every open. An empty file is not a fragment — there is nothing before the
// first event to run into.
func endsMidLine(path string) (bool, error) {
	r, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer func() { _ = r.Close() }()
	fi, err := r.Stat()
	if err != nil {
		return false, err
	}
	if fi.Size() == 0 {
		return false, nil
	}
	var last [1]byte
	if _, err := r.ReadAt(last[:], fi.Size()-1); err != nil {
		return false, err
	}
	return last[0] != '\n', nil
}

// syncDir fsyncs a directory so that an entry created in it survives a power
// loss. It goes through syncRecordFile for the same reason Append does: it is
// the only way a test can see that it happened.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return syncRecordFile(d)
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

// Damage reports the lines this store could not read: what the last Load
// skipped, or — before any Load — the fragment the open had to terminate.
//
// It is a COUNT and not a log line: a store that quietly drops a record is the
// failure this exists against, and a number nobody reads is the same failure
// with extra steps.
//
// The two sources agree rather than accumulate. A fragment terminated at open
// is one Skipped line, and the next Load reads that same line and counts it the
// same way, so the number does not move when a Load happens; a Load REPLACES
// the count rather than adding to it, because it re-reads the whole file.
func (s *RecordStore) Damage() lease.StoreDamage {
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
func parseRecordLines(b []byte) ([]lease.RecordEvent, lease.StoreDamage) {
	var (
		out    []lease.RecordEvent
		damage lease.StoreDamage
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
