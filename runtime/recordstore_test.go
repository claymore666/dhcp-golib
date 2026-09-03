package runtime

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/claymore666/dhcp-golib/lease"
	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

func storeFixtureEvents(t *testing.T) []lease.RecordEvent {
	t.Helper()
	p := proto.DefaultParams([]byte{0x02, 0, 0, 0, 0, 1})
	p.ClientID = []byte{0xff, 0xde, 0xad, 0xbe, 0xef}
	p.Hostname = "fixture"
	p.Servers.Allow = []netip.Addr{netip.MustParseAddr("192.168.99.1")}
	at := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	l := lease.Lease{
		Addr:         netip.MustParsePrefix("192.168.99.100/24"),
		Gateway:      netip.MustParseAddr("192.168.99.1"),
		DNS:          []netip.Addr{netip.MustParseAddr("192.168.99.1")},
		Domain:       "dhcp.test",
		MTU:          1400,
		ServerID:     netip.MustParseAddr("192.168.99.1"),
		Routes:       []wire.Route{{Dest: netip.MustParsePrefix("10.0.0.0/8"), Router: netip.MustParseAddr("192.168.99.1")}},
		DomainSearch: []string{"dhcp.test"},
		Acquired:     at,
		Renew:        at.Add(time.Minute),
		Rebind:       at.Add(105 * time.Second),
		Expire:       at.Add(2 * time.Minute),
		Options:      wire.Options{wire.OptionCode(53): {5}, wire.OptionCode(51): {0, 0, 0, 120}},
	}
	return []lease.RecordEvent{
		{ID: "rec-1", Seq: 1, At: at, Instance: "p1", Op: lease.OpCreate, Scope: "net-a",
			Family: lease.FamilyV4, CHAddr: []byte{0x02, 0, 0, 0, 0, 1}, Identity: []byte{0xff, 0xde, 0xad, 0xbe, 0xef}, Params: &p},
		{ID: "rec-1", Seq: 2, At: at, Instance: "p1", Op: lease.OpBind},
		{ID: "rec-1", Seq: 3, At: at, Instance: "p1", Op: lease.OpLease, Kind: lease.Acquired, Lease: &l},
		{ID: "rec-1", Seq: 4, At: at, Instance: "p1", Op: lease.OpStats, Stats: &lease.Stats{Sent: 2, Received: 2, Steps: 9}},
		{ID: "rec-1", Seq: 5, At: at, Instance: "p1", Op: lease.OpLost, Reason: proto.ReasonStopped},
	}
}

// TestARecordEventSurvivesTheJSONLRoundTrip. The durable form is the only thing
// that outlives the process, so a field that does not encode is a field that
// does not exist after a restart — silently, because the record still folds.
//
// The comparison is the whole event, not a field list: an enumeration here
// would be an unrun checklist that a new field never joins.
func TestARecordEventSurvivesTheJSONLRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.jsonl")
	s, err := OpenRecordStore(path)
	if err != nil {
		t.Fatalf("OpenRecordStore: %v", err)
	}
	want := storeFixtureEvents(t)
	for _, ev := range want {
		if err := s.Append(ev); err != nil {
			t.Fatalf("Append(%s): %v", ev.Op, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := OpenRecordStore(path)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	got, err := reopened.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if reopened.Damage().Any() {
		t.Fatalf("a file nothing damaged reports %s", reopened.Damage())
	}
	if len(got) != len(want) {
		t.Fatalf("%d event(s) came back, %d went in", len(got), len(want))
	}
	for i := range want {
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Errorf("event %d did not survive the file.\n got %+v\nwant %+v", i, got[i], want[i])
		}
	}

	// And the fold over the reloaded events is the fold over the originals.
	a, b := lease.Rebuild(want), lease.Rebuild(got)
	if !reflect.DeepEqual(a.Records, b.Records) {
		t.Fatalf("the reloaded journal folds to a different record.\n got %+v\nwant %+v", b.Records, a.Records)
	}
	if len(a.Records) != 1 || !a.Records[0].Held {
		t.Fatalf("the fixture folds to %+v; it is meant to end holding a lease", a.Records)
	}
}

// TestLoadAnswersInAppendOrder is defeat row M-9. Replay-in-order is the whole
// value of an append-only log, and a Load that sorted or de-duplicated would
// satisfy any test that only counted lines.
func TestLoadAnswersInAppendOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.jsonl")
	s, err := OpenRecordStore(path)
	if err != nil {
		t.Fatalf("OpenRecordStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Sequence numbers DESCENDING and record ids interleaved, so append order
	// is not recoverable by sorting on anything in the events.
	var want []uint64
	for i := uint64(9); i >= 1; i-- {
		id := "rec-1"
		if i%2 == 0 {
			id = "rec-2"
		}
		if err := s.Append(lease.RecordEvent{ID: id, Seq: i, Op: lease.OpBind}); err != nil {
			t.Fatalf("Append: %v", err)
		}
		want = append(want, i)
	}
	got, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("%d event(s) back, %d in", len(got), len(want))
	}
	for i := range want {
		if got[i].Seq != want[i] {
			t.Fatalf("position %d holds seq %d, was appended with %d", i, got[i].Seq, want[i])
		}
	}
}

// TestATornLineIsSkippedAndCounted is defeat row M-4.
//
// A process killed inside Append leaves a fragment at the tail. Refusing the
// whole file for it loses every record written before the crash; skipping it
// silently loses one record with no trace. Both are wrong, so it is skipped and
// COUNTED, and a torn tail is counted apart from an unreadable interior line
// because they mean different things — a crash, and two writers or a damaged
// file.
//
// The truncation is driven at every offset inside the last line rather than at
// one chosen point: a single offset measures one parse, not the property.
func TestATornLineIsSkippedAndCounted(t *testing.T) {
	whole := func(t *testing.T) []byte {
		t.Helper()
		path := filepath.Join(t.TempDir(), "records.jsonl")
		s, err := OpenRecordStore(path)
		if err != nil {
			t.Fatalf("OpenRecordStore: %v", err)
		}
		for _, ev := range storeFixtureEvents(t) {
			if err := s.Append(ev); err != nil {
				t.Fatalf("Append: %v", err)
			}
		}
		if err := s.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading back: %v", err)
		}
		return b
	}(t)

	full, damage := parseRecordLines(whole)
	if damage.Any() || len(full) != 5 {
		t.Fatalf("the undamaged fixture parsed as %d event(s) with %s; the control is broken", len(full), damage)
	}

	lastLine := 0
	for i := 0; i < len(whole)-1; i++ {
		if whole[i] == '\n' {
			lastLine = i + 1
		}
	}
	if lastLine == 0 {
		t.Fatal("the fixture is one line, so there is nothing before the tear to preserve")
	}

	tried, keptFour := 0, 0
	for cut := lastLine + 1; cut < len(whole); cut++ {
		tried++
		evs, damage := parseRecordLines(whole[:cut])
		if len(evs) < 4 {
			t.Fatalf("a tear at offset %d lost a record written before it: %d survived", cut, len(evs))
		}
		switch len(evs) {
		case 4:
			keptFour++
			if damage.TornTail != 1 {
				t.Fatalf("a tear at offset %d dropped a line and reported %s", cut, damage)
			}
		case 5:
			// The tear landed exactly after the object's closing brace: the
			// event is whole and only its newline is missing.
			if damage.Any() {
				t.Fatalf("a tear at offset %d kept the event and still reported %s", cut, damage)
			}
		}
		if damage.Skipped != 0 {
			t.Fatalf("a tear at offset %d was accounted as an interior line: %s", cut, damage)
		}
	}
	if tried == 0 || keptFour == 0 {
		t.Fatalf("%d offset(s) tried, %d of them torn; a table with no torn row measures nothing", tried, keptFour)
	}
	t.Logf("%d truncation offsets inside the last line, %d of them unreadable", tried, keptFour)
}

// TestAnUnreadableInteriorLineIsCountedApart. It cannot be a crash — the writer
// had already written the newline after it — so it is two writers or a damaged
// file, and it is a different number.
func TestAnUnreadableInteriorLineIsCountedApart(t *testing.T) {
	good, err := json.Marshal(lease.RecordEvent{ID: "rec-1", Seq: 1, Op: lease.OpCreate, Scope: "net-a"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	file := append(append([]byte(nil), good...), []byte("\n{\"id\":\"rec-1\",\"op\":\nnot json at all\n")...)
	file = append(file, good...)
	file = append(file, '\n')

	evs, damage := parseRecordLines(file)
	if damage.Skipped != 2 || damage.TornTail != 0 {
		t.Fatalf("damage = %s, want 2 skipped and no torn tail: a broken line in the middle is not a crash", damage)
	}
	if len(evs) != 2 {
		t.Fatalf("%d event(s) survived a damaged interior line, want the 2 good ones", len(evs))
	}
	if _, empty := parseRecordLines(nil); empty.Any() {
		t.Fatalf("an empty file reported damage: %s", empty)
	}
	if evs, blank := parseRecordLines([]byte("\n\n")); len(evs) != 0 || blank.Any() {
		t.Fatalf("blank lines were counted as damage: %d event(s), %s", len(evs), blank)
	}

	// THE LAST LINE OF A COMPLETE FILE. A broken line in the final position of
	// a file that ends in a newline is still not a crash: the writer got the
	// newline out after it. Only the absence of that newline makes a fragment,
	// and a check that keys on the position alone cannot tell the two apart.
	closed := append(append([]byte(nil), good...), '\n')
	closed = append(closed, []byte("{\"id\":\"rec-1\",\n")...)
	evs, damage = parseRecordLines(closed)
	if damage.Skipped != 1 || damage.TornTail != 0 {
		t.Fatalf("damage = %s on a broken LAST line of a newline-terminated file, want 1 skipped and no torn tail", damage)
	}
	if len(evs) != 1 {
		t.Fatalf("%d event(s) survived, want the 1 good one", len(evs))
	}

	// And the same bytes WITHOUT that final newline are the fragment.
	evs, damage = parseRecordLines(closed[:len(closed)-1])
	if damage.TornTail != 1 || damage.Skipped != 0 {
		t.Fatalf("damage = %s on the same file with its last newline missing, want 1 torn tail and nothing skipped", damage)
	}
	if len(evs) != 1 {
		t.Fatalf("%d event(s) survived the torn tail, want the 1 good one", len(evs))
	}
}

// TestTwoWritersAppendWholeLines is note row D-9: an old plugin process and a
// new one appending to one file during an upgrade.
//
// O_APPEND plus one write per event is what makes their lines interleave as
// lines rather than as one corrupted one. Two stores over one path here are the
// same shape as two processes: the kernel serialises the offset and the write
// together, and nothing in this package holds a lock the other would see.
func TestTwoWritersAppendWholeLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.jsonl")
	const perWriter = 200

	var wg sync.WaitGroup
	for _, who := range []string{"old-process", "new-process"} {
		s, err := OpenRecordStore(path)
		if err != nil {
			t.Fatalf("OpenRecordStore: %v", err)
		}
		defer func() { _ = s.Close() }()
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 1; i <= perWriter; i++ {
				ev := lease.RecordEvent{ID: who, Seq: uint64(i), Op: lease.OpBind, Instance: who, Note: who + " padding padding padding padding padding"}
				if err := s.Append(ev); err != nil {
					t.Errorf("Append: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	reader, err := OpenRecordStore(path)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	defer func() { _ = reader.Close() }()
	evs, err := reader.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if d := reader.Damage(); d.Any() {
		t.Fatalf("two writers on one file produced an unreadable line: %s", d)
	}
	if len(evs) != 2*perWriter {
		t.Fatalf("%d line(s) readable, want %d", len(evs), 2*perWriter)
	}
	seen := map[string]uint64{}
	for _, ev := range evs {
		if ev.Seq != seen[ev.Instance]+1 {
			t.Fatalf("%s wrote seq %d after %d; its own lines are out of order", ev.Instance, ev.Seq, seen[ev.Instance])
		}
		seen[ev.Instance] = ev.Seq
	}
	if len(seen) != 2 {
		t.Fatalf("%d writer(s) are visible in the file, want 2", len(seen))
	}
}

// TestTheSyncPolicyIsClassifiedForEveryOperation walks lease.AllOps, so an
// operation added later cannot arrive with no answer to "is this line worth an
// fsync". The rule is in durableWrite's doc: what cannot be reconstructed is
// synced, what a later exchange can re-derive is not.
func TestTheSyncPolicyIsClassifiedForEveryOperation(t *testing.T) {
	want := map[lease.RecordOp]bool{
		lease.OpReserve: true,
		lease.OpCreate:  true,
		lease.OpRebind:  true,
		lease.OpAdopt:   true,
		lease.OpBind:    true,
		lease.OpLease:   true, // only the first lease of an instance; driven below
		lease.OpLost:    false,
		lease.OpLeave:   false,
		lease.OpRetain:  false,
		lease.OpClose:   false,
		lease.OpStats:   false,
		lease.OpExtra:   false,
	}
	ops := lease.AllOps()
	if len(ops) != len(want) {
		t.Fatalf("%d operation(s) exist and %d are classified here", len(ops), len(want))
	}
	for _, op := range ops {
		w, ok := want[op]
		if !ok {
			t.Fatalf("operation %s has no sync classification", op)
		}
		ev := lease.RecordEvent{ID: "rec-1", Op: op}
		if op == lease.OpLease {
			ev.Kind = lease.Acquired
		}
		if got := durableWrite(ev); got != w {
			t.Errorf("%s is synced = %v, want %v", op, got, w)
		}
	}
	if durableWrite(lease.RecordEvent{Op: lease.OpLease, Kind: lease.Renewed}) {
		t.Error("a renewal is synced; a lost renewal line costs an earlier INIT-REBOOT, which is the safe direction")
	}
	if durableWrite(lease.RecordEvent{Op: lease.OpLease, Kind: lease.Changed}) {
		t.Error("a changed lease is synced")
	}
}

// TestAppendRefusesAnEventItCannotWriteAsOneLine. One event is one line, and a
// value that encoded a newline would split it into two — the second of which
// would be an unreadable interior line at every future Load.
func TestAppendRefusesAnEventItCannotWriteAsOneLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.jsonl")
	s, err := OpenRecordStore(path)
	if err != nil {
		t.Fatalf("OpenRecordStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	if err := s.Append(lease.RecordEvent{ID: "rec-1", Seq: 1, Op: lease.OpCreate, Note: "one\ntwo"}); err != nil {
		t.Fatalf("a newline inside a string must be ESCAPED by the encoder, not refused: %v", err)
	}
	evs, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(evs) != 1 || evs[0].Note != "one\ntwo" {
		t.Fatalf("an escaped newline did not survive: %+v", evs)
	}
	if s.Damage().Any() {
		t.Fatalf("damage after a note with a newline: %s", s.Damage())
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Append(lease.RecordEvent{ID: "rec-1", Seq: 2, Op: lease.OpBind}); err == nil {
		t.Fatal("appending to a closed store was accepted")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("a second Close returned %v", err)
	}
}

// TestTheSyncPolicyIsAppliedToEveryAppend is the CALL SITE of durableWrite.
//
// TestTheSyncPolicyIsClassifiedForEveryOperation pins the policy as a
// function, which a call site wired to a constant satisfies just as well. An
// fsync leaves no trace a same-process test can read, so the only way to see
// which appends took one is to stand in for it.
func TestTheSyncPolicyIsAppliedToEveryAppend(t *testing.T) {
	var synced []lease.RecordEvent
	failNext := false
	real := syncRecordFile
	syncRecordFile = func(f *os.File) error {
		if failNext {
			return os.ErrClosed
		}
		synced = append(synced, lease.RecordEvent{})
		return real(f)
	}
	t.Cleanup(func() { syncRecordFile = real })

	type appended struct {
		ev   lease.RecordEvent
		want bool
	}
	var plan []appended
	seq := uint64(0)
	add := func(op lease.RecordOp, kind lease.EventKind) {
		seq++
		ev := lease.RecordEvent{ID: "rec-1", Seq: seq, Op: op, Kind: kind}
		plan = append(plan, appended{ev: ev, want: durableWrite(ev)})
	}
	for _, op := range lease.AllOps() {
		add(op, 0)
	}
	// OpLease is the one op whose answer depends on the event it carries, so
	// every kind of it is appended, not just the zero one.
	for _, k := range []lease.EventKind{lease.Acquired, lease.Renewed, lease.Failed, lease.Lost} {
		add(lease.OpLease, k)
	}

	path := filepath.Join(t.TempDir(), "records.jsonl")
	s, err := OpenRecordStore(path)
	if err != nil {
		t.Fatalf("OpenRecordStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	wantSyncs := 0
	for _, p := range plan {
		before := len(synced)
		if err := s.Append(p.ev); err != nil {
			t.Fatalf("Append(%s/%s): %v", p.ev.Op, p.ev.Kind, err)
		}
		got := len(synced) > before
		if got != p.want {
			t.Errorf("%s/%s: synced = %v, durableWrite says %v", p.ev.Op, p.ev.Kind, got, p.want)
		}
		if p.want {
			wantSyncs++
		}
	}
	if wantSyncs == 0 || wantSyncs == len(plan) {
		t.Fatalf("%d of %d appends were durable: a policy that answers the same for everything makes this test blind",
			wantSyncs, len(plan))
	}

	// A failed fsync is a failed Append: a caller told the line is on disk
	// when it is not is the whole reason the policy exists.
	failNext = true
	if err := s.Append(lease.RecordEvent{ID: "rec-1", Seq: seq + 1, Op: lease.OpCreate}); err == nil {
		t.Error("Append returned nil after its fsync failed")
	}
}

// TestNoFieldOfARecordEventCanEncodeToARawNewline is the reason Append's
// newline check has never fired: encoding/json escapes a newline wherever one
// can appear. The check stays, because the failure it guards — one event split
// across two lines, every later line unreadable — is not recoverable, and the
// property it rests on belongs to a package this one does not own.
func TestNoFieldOfARecordEventCanEncodeToARawNewline(t *testing.T) {
	const nl = "one\ntwo"
	ev := lease.RecordEvent{
		ID: nl, Op: lease.OpCreate, Seq: 1,
		Instance: nl, Scope: nl, StepsRef: nl, Note: nl,
		CHAddr: []byte(nl), Identity: []byte(nl),
		Extra: map[string]uint64{nl: 1},
	}
	p := proto.DefaultParams([]byte(nl))
	p.Hostname = nl
	p.ClientID = []byte(nl)
	ev.Params = &p

	// Every string-shaped field of the event is set, so a field added later
	// without a value here is a gap this test can name.
	rv := reflect.ValueOf(ev)
	rt := rv.Type()
	for i := range rt.NumField() {
		f := rv.Field(i)
		switch f.Kind() {
		case reflect.String:
			if f.String() == "" {
				t.Errorf("%s is a string field this test leaves empty, so it drives no newline through it", rt.Field(i).Name)
			}
		case reflect.Slice:
			if f.Type().Elem().Kind() == reflect.Uint8 && f.Len() == 0 {
				t.Errorf("%s is a byte field this test leaves empty", rt.Field(i).Name)
			}
		}
	}

	line, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if i := bytes.IndexByte(line, '\n'); i >= 0 {
		t.Fatalf("the encoded event carries a raw newline at offset %d: %s", i, line)
	}
	var back lease.RecordEvent
	if err := json.Unmarshal(line, &back); err != nil {
		t.Fatalf("the escaped form does not round trip: %v", err)
	}
	if back.Note != nl || string(back.CHAddr) != nl {
		t.Fatalf("the newline did not survive escaping: note %q, chaddr %q", back.Note, back.CHAddr)
	}
}
