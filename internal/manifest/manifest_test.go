// Package manifest pins verify.manifest.sh from a second language.
//
// The manifest states what must be there. This file states it again, in Go, in
// a different directory, with no derivation shared with the shell — so
// shrinking the arbiter's population takes an edit here as well as there.
//
// Round 9's finding is why. Four rounds running, a guard derived its
// expectation from the thing it guarded, and the fix each time was another
// guard with the same property. The last one was measured by deleting the
// shellcheck gate from verify.sh: eleven rows became ten and the arbiter said
// PASS. A number written down in one file can always be lowered by editing
// that file; the only thing that changes is how many files.
//
// This test runs inside the unit suite, and the unit suite's own floor —
// MIN_DECLARED_TESTS — is in the manifest. Deleting this file therefore takes
// the declared-test count below its floor rather than removing the pin
// silently.
package manifest

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const manifestPath = "../../verify.manifest.sh"

// The pinned row set. Exact and ordered: this is the verdict table, and a row
// arriving or leaving is a change somebody should have to make twice.
var pinnedRows = []string{
	"self-check",
	"citations",
	"bounds",
	"build",
	"vet",
	"gofmt",
	"shellcheck",
	"doc-numbers",
	"gate-roster",
	"t1",
	"t2",
	"unit-suite",
	"verify-oracle",
}

var pinnedGates = []string{"t1", "t2"}

// Floors, not equalities: these populations are meant to grow without an edit
// here, and are meant to be unable to shrink without one.
//
// minDeclaredTests is a LOW-WATER MARK and is deliberately not maintained in
// step with the manifest. verify.sh holds MIN_DECLARED_TESTS to a BAND against
// the tree — below it, or more than MAX_DECLARED_MARGIN above it, is a
// failure; this number exists only so that the manifest cannot be lowered past
// a level somebody once measured.
//
// maxDeclaredMarginCap is the other direction and is a CEILING, not a floor: a
// band that may be widened at will is a floor with no upper edge, which is the
// state round 11 was sent to close. Checked below by its own comparison, not by
// the floors loop.
// MAINTENANCE, stated because the review asked how a low-water mark is kept
// from decaying: a round that ADDS to one of these populations raises the pin
// to the number it just measured, in the same change. That is the whole rule.
// It is cheap because adding a scenario is already a three-file edit, and it
// keeps the distance between the pin and the tree at zero, which is the only
// value at which the pin is at full strength.
const (
	minScenarios         = 60
	minShellScripts      = 4
	minDeclaredTests     = 169
	minOracleSeconds     = 8
	maxDeclaredMarginCap = 4
)

// The classes a scenario contract may declare, and the verdicts it may name.
var (
	rcClasses = map[string]bool{"zero": true, "nonzero": true, "static": true}
	verdicts  = map[string]bool{"PASS": true, "FAIL": true, "ABSENT": true}
)

// static means the scenario does not run the subject, so it cannot read the
// subject's table. It does NOT mean the scenario may observe nothing: the "-"
// token that once said exactly that is gone, and a static contract must still
// name something it saw. That rule, not this cap, is what closes the hole.
//
// The cap stays because a class spreads through its exemption. It was raised
// from 1 to 2 when the second member arrived, deliberately and with the count
// beside it — the pattern to refuse is a cap raised in the same edit as the
// member that broke it becoming routine.
const maxStaticContracts = 2

func readManifest(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("the manifest is unreadable, so nothing here measured anything: %v", err)
	}
	if len(b) == 0 {
		t.Fatalf("the manifest is empty; an empty expectation is satisfied by everything")
	}
	return string(b)
}

// list returns the names in a `NAME=( ... )` block. It fails the test rather
// than returning empty, because an unparsed list reads exactly like a list
// with nothing in it — which is the defect this whole file exists against.
func list(t *testing.T, src, name string) []string {
	t.Helper()
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(name) + `=\(\n((?:.*\n)*?)\)\n`)
	m := re.FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("%s is not declared as a multi-line array in %s", name, manifestPath)
	}
	var out []string
	for _, ln := range strings.Split(m[1], "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		out = append(out, ln)
	}
	if len(out) == 0 {
		t.Fatalf("%s parsed to no names", name)
	}
	return out
}

// number returns a `NAME=<int>` scalar.
func number(t *testing.T, src, name string) int {
	t.Helper()
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(name) + `=(\d+)\s*$`)
	m := re.FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("%s is not declared as an integer in %s", name, manifestPath)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("%s = %q is not a number: %v", name, m[1], err)
	}
	return n
}

func TestManifestRowsAreTheRowsPinnedHere(t *testing.T) {
	got := list(t, readManifest(t), "MANIFEST_ROWS")
	if len(got) != len(pinnedRows) {
		t.Fatalf("MANIFEST_ROWS has %d row(s), this file pins %d: %v", len(got), len(pinnedRows), got)
	}
	for i := range got {
		if got[i] != pinnedRows[i] {
			t.Errorf("row %d: manifest says %q, this file pins %q", i, got[i], pinnedRows[i])
		}
	}
}

func TestManifestGatesAreTheGatesPinnedHere(t *testing.T) {
	got := list(t, readManifest(t), "MANIFEST_GATES")
	if len(got) != len(pinnedGates) {
		t.Fatalf("MANIFEST_GATES has %d gate(s), this file pins %d: %v", len(got), len(pinnedGates), got)
	}
	for i := range got {
		if got[i] != pinnedGates[i] {
			t.Errorf("gate %d: manifest says %q, this file pins %q", i, got[i], pinnedGates[i])
		}
	}
}

// The floors. A floor of zero is not a floor: that sentence is the round's
// whole finding, and these are the numbers that stop being zero.
func TestManifestFloorsAreNotBelowTheirPins(t *testing.T) {
	src := readManifest(t)
	for _, c := range []struct {
		name string
		got  int
		min  int
	}{
		{"MANIFEST_SCENARIOS_N", number(t, src, "MANIFEST_SCENARIOS_N"), minScenarios},
		{"MANIFEST_SCENARIO_CONTRACTS_N", number(t, src, "MANIFEST_SCENARIO_CONTRACTS_N"), minScenarios},
		{"MANIFEST_SHELL_SCRIPTS_N", number(t, src, "MANIFEST_SHELL_SCRIPTS_N"), minShellScripts},
		{"MIN_DECLARED_TESTS", number(t, src, "MIN_DECLARED_TESTS"), minDeclaredTests},
		{"ORACLE_MIN_SECONDS", number(t, src, "ORACLE_MIN_SECONDS"), minOracleSeconds},
	} {
		if c.got < c.min {
			t.Errorf("%s is %d, below the %d pinned here; a population shrank and the shell alone would not have said so", c.name, c.got, c.min)
		}
	}

	// The one operand here whose danger is upward. Widening the band is the
	// cheapest way to make the declared-test row stop saying anything, and it
	// looks like maintenance while doing it.
	if m := number(t, src, "MAX_DECLARED_MARGIN"); m < 0 || m > maxDeclaredMarginCap {
		t.Errorf("MAX_DECLARED_MARGIN is %d, outside 0..%d; the band was widened rather than the floor raised", m, maxDeclaredMarginCap)
	}
}

// Layer 2, read from Go as well as from the shell. The shell's manifest_check
// runs this same comparison; if only the shell ran it, deleting manifest_check
// would delete the check with its subject, which is the shape of every finding
// in rounds 5 through 8.
func TestManifestListLengthsMatchTheirDeclaredCounts(t *testing.T) {
	src := readManifest(t)
	for _, c := range []struct{ list, count string }{
		{"MANIFEST_ROWS", "MANIFEST_ROWS_N"},
		{"MANIFEST_GATES", "MANIFEST_GATES_N"},
		{"MANIFEST_SHELL_SCRIPTS", "MANIFEST_SHELL_SCRIPTS_N"},
		{"MANIFEST_SCENARIOS", "MANIFEST_SCENARIOS_N"},
		{"MANIFEST_SCENARIO_CONTRACTS", "MANIFEST_SCENARIO_CONTRACTS_N"},
	} {
		names := list(t, src, c.list)
		if n := number(t, src, c.count); n != len(names) {
			t.Errorf("%s holds %d name(s) but %s says %d", c.list, len(names), c.count, n)
		}
		seen := map[string]bool{}
		for _, n := range names {
			if seen[n] {
				t.Errorf("%s lists %q twice; a duplicate inflates a count without adding a subject", c.list, n)
			}
			seen[n] = true
		}
	}
}

// contract is one MANIFEST_SCENARIO_CONTRACTS entry: what a scenario must have
// OBSERVED, as opposed to what it is called.
type contract struct {
	scenario string
	rcClass  string
	token    string
	row      string
	verdict  string
}

func contracts(t *testing.T, src string) []contract {
	t.Helper()
	var out []contract
	for _, raw := range list(t, src, "MANIFEST_SCENARIO_CONTRACTS") {
		e := strings.Trim(raw, `"`)
		parts := strings.Split(e, "|")
		if len(parts) != 3 {
			t.Errorf("contract %q is not name|rc-class|token", e)
			continue
		}
		c := contract{scenario: parts[0], rcClass: parts[1], token: parts[2]}
		// There is no "-" escape any more. A contract that demanded nothing
		// was one entry away from being the thing round 11 exists to forbid,
		// and it had exactly one user, which could observe something real.
		tok := strings.SplitN(parts[2], ":", 2)
		if len(tok) != 2 {
			t.Errorf("contract %q: token %q is not <subject>:<value>", e, parts[2])
			continue
		}
		c.row, c.verdict = tok[0], tok[1]
		out = append(out, c)
	}
	return out
}

// Round 11. The manifest pinned names and counts, and B14 kept every name while
// deleting what the names stood for: four scenario bodies emptied, one comment
// left in place to satisfy a grep, and the arbiter printed PASS over a live
// defect. A name is not a behaviour.
//
// This is the structural half of the answer — verify.sh compares each contract
// against what the oracle reports it observed, and this test makes sure there
// is a contract to compare, that it demands something real, and that the one
// exemption cannot spread.
func TestEveryScenarioHasAWellFormedBehaviourContract(t *testing.T) {
	src := readManifest(t)
	scenarios := list(t, src, "MANIFEST_SCENARIOS")
	cs := contracts(t, src)

	if len(cs) != len(scenarios) {
		t.Fatalf("%d scenario(s) but %d contract(s); a scenario with no contract is a name with no behaviour", len(scenarios), len(cs))
	}

	seen := map[string]bool{}
	static := 0
	for _, c := range cs {
		if seen[c.scenario] {
			t.Errorf("scenario %q has more than one contract", c.scenario)
		}
		seen[c.scenario] = true
		if !rcClasses[c.rcClass] {
			t.Errorf("scenario %q: rc-class %q is not one of zero/nonzero/static", c.scenario, c.rcClass)
		}
		if c.rcClass == "static" {
			static++
			// A static scenario still has to observe SOMETHING — it just
			// cannot be a row verdict, because it never ran the subject. This
			// is the class B14 would have hidden in: "it does not run
			// anything" was, until this round, also "it need not report
			// anything", and the two are not the same claim.
			if verdicts[c.verdict] {
				t.Errorf("scenario %q is static and names a row verdict %q; a scenario that never runs the subject cannot read its table", c.scenario, c.token)
			}
			continue
		}
		if c.row == "" {
			t.Errorf("scenario %q demands no row observation, so it is satisfied by a body that runs the subject and reads nothing", c.scenario)
		}
		if !verdicts[c.verdict] {
			t.Errorf("scenario %q: verdict %q is not PASS/FAIL/ABSENT", c.scenario, c.verdict)
		}
	}
	for _, s := range scenarios {
		if !seen[s] {
			t.Errorf("scenario %q has no contract", s)
		}
	}
	if static > maxStaticContracts {
		t.Errorf("%d static contract(s), at most %d allowed; static means the scenario never runs the subject, and an uncapped exemption empties this check without moving a single count", static, maxStaticContracts)
	}
}

// The replacement for the row-coverage check that used to live in the oracle as
// `grep -q "row $r"` over the oracle's own source. MEASURED 2026-08-30 by
// review: one comment satisfied it.
//
// A row is covered when some scenario must OBSERVE it in a named state. That
// cannot be satisfied by a comment, and it cannot be satisfied by a name.
func TestEveryRequiredRowIsTheSubjectOfAContract(t *testing.T) {
	src := readManifest(t)
	covered := map[string]bool{}
	for _, c := range contracts(t, src) {
		if c.row != "" {
			covered[c.row] = true
		}
	}
	for _, r := range list(t, src, "MANIFEST_ROWS") {
		if !covered[r] {
			t.Errorf("row %q is required by the manifest and no scenario contract requires it to be observed; nothing proves its count is derived rather than written", r)
		}
	}
}
