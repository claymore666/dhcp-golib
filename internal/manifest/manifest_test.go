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
	"gate-roster",
	"t1",
	"t2",
	"unit-suite",
	"verify-oracle",
}

var pinnedGates = []string{"t1", "t2"}

// Floors, not equalities: these populations are meant to grow without an edit
// here, and are meant to be unable to shrink without one.
const (
	minScenarios     = 53
	minShellScripts  = 3
	minDeclaredTests = 169
)

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
		{"MANIFEST_SHELL_SCRIPTS_N", number(t, src, "MANIFEST_SHELL_SCRIPTS_N"), minShellScripts},
		{"MIN_DECLARED_TESTS", number(t, src, "MIN_DECLARED_TESTS"), minDeclaredTests},
	} {
		if c.got < c.min {
			t.Errorf("%s is %d, below the %d pinned here; a population shrank and the shell alone would not have said so", c.name, c.got, c.min)
		}
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
