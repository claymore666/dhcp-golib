// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package publication

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The scan workflow, and the guard it has to run before it installs anything.
//
// WHY THIS TEST EXISTS. .github/lane/govulncheck-pin.sh compares the pinned
// scanner against the toolchain the job resolves, and refuses when the install
// would. Nothing outside the workflow ran it: the only other reference to the
// file was its MANIFEST_SHELL_SCRIPTS entry, which is a LINT domain and says
// nothing about execution. MEASURED before this test was written: deleting
// both steps from the workflow left the whole arbiter green, and
// docs/verifying.md went on saying the guard is driven in the job.
//
// A tracked-file gate cannot see its own new file, and a lint list is not an
// execution. So the property is stated over the workflow TEXT, and it is the
// ordering as well as the presence: a guard that runs after the install has
// already let the install decide.
const govulncheckWorkflowPath = workflowDir + "/govulncheck.yml"

// The guard, by the path the workflow has to name. Spelled once.
const pinGuardPath = ".github/lane/govulncheck-pin.sh"

var (
	// A `run:` line, and what it runs. A block scalar is refused rather than
	// read: this reader cannot follow one, and a shape it cannot follow must
	// not look like absence.
	runLine      = regexp.MustCompile(`^\s*-?\s*run:\s*(.*)$`)
	blockScalar  = regexp.MustCompile(`^\s*-?\s*run:\s*[|>]`)
	scannerSetup = regexp.MustCompile(`\bgo\s+install\s+golang\.org/x/vuln/cmd/govulncheck@`)
)

// commandsOf returns what every single-line `run:` in the text executes, in
// file order, with inline comments cut. It refuses by returning an error
// string, never by returning an empty list.
func commandsOf(text string) ([]string, string) {
	var out []string
	for i, line := range strings.Split(text, "\n") {
		if blockScalar.MatchString(line) {
			return nil, "line " + strconv.Itoa(i+1) + " is a block-scalar `run:`, which this reader does not follow; write it as a single-line run:"
		}
		m := runLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		cmd := m[1]
		if j := strings.Index(cmd, " #"); j >= 0 {
			cmd = cmd[:j]
		}
		out = append(out, strings.TrimSpace(cmd))
	}
	if len(out) == 0 {
		return nil, "no single-line `run:` at all, so every property over the commands would hold vacuously"
	}
	return out, ""
}

// pinGuardFindings holds one workflow text to the property: every command that
// installs the scanner is preceded, in the same file, by a command that runs
// the guard and by one that runs the guard's own cases.
//
// IT IS KEYED ON THE COMMAND, not on a step name. A step name is prose and
// renaming it is not a defect; running the install without the guard is.
func pinGuardFindings(text string) []string {
	cmds, refused := commandsOf(text)
	if refused != "" {
		return []string{"the reader refused this workflow: " + refused}
	}

	firstGuard, firstCases, firstInstall := -1, -1, -1
	for i, c := range cmds {
		switch {
		case !strings.Contains(c, pinGuardPath):
		case strings.Contains(c, "--self-test"):
			if firstCases < 0 {
				firstCases = i
			}
		default:
			if firstGuard < 0 {
				firstGuard = i
			}
		}
		if firstInstall < 0 && scannerSetup.MatchString(c) {
			firstInstall = i
		}
	}

	var out []string
	if firstInstall < 0 {
		return []string{"nothing in this workflow installs the scanner, so the module is not scanned at all"}
	}
	if firstGuard < 0 {
		out = append(out, "the scanner is installed and nothing runs "+pinGuardPath+"; the pin and the toolchain are compared by nothing")
	} else if firstGuard > firstInstall {
		out = append(out, pinGuardPath+" runs AFTER the install; the install has already decided by then")
	}
	if firstCases < 0 {
		out = append(out, "nothing runs "+pinGuardPath+" --self-test; a guard whose verdict is trusted before it has shown it can answer both ways is a guard with one possible verdict")
	} else if firstCases > firstInstall {
		out = append(out, pinGuardPath+" --self-test runs AFTER the install")
	}
	return out
}

// TestTheScanWorkflowRunsThePinGuardBeforeItInstalls is the property applied to
// the tree. docs/verifying.md states that the pin guard is driven in the job
// beside the scan; this is what holds that sentence true.
func TestTheScanWorkflowRunsThePinGuardBeforeItInstalls(t *testing.T) {
	b, err := os.ReadFile(govulncheckWorkflowPath)
	if err != nil {
		t.Fatalf("reading %s: %v", govulncheckWorkflowPath, err)
	}
	for _, f := range pinGuardFindings(string(b)) {
		t.Errorf("%s: %s", govulncheckWorkflowPath, f)
	}
}

// TestThePinGuardRowSpeaksInBothDirections drives the same function over the
// shapes a later edit would produce, so the row above is the application of
// machinery whose verdict is proved elsewhere rather than a check with one
// possible verdict.
func TestThePinGuardRowSpeaksInBothDirections(t *testing.T) {
	const install = "        run: go install golang.org/x/vuln/cmd/govulncheck@v1.7.0\n"
	const guard = "        run: .github/lane/govulncheck-pin.sh\n"
	const cases = "        run: .github/lane/govulncheck-pin.sh --self-test\n"

	for _, tc := range []struct {
		name  string
		text  string
		wants string // a substring the finding must carry; "" means no finding
	}{
		{"the shipped order", cases + guard + install, ""},
		{"guard and cases either way round", guard + cases + install, ""},
		{"both steps deleted", install, "compared by nothing"},
		{"guard deleted", cases + install, "compared by nothing"},
		{"cases deleted", guard + install, "--self-test"},
		{"guard moved after the install", cases + install + guard, "runs AFTER the install"},
		{"cases moved after the install", guard + install + cases, "--self-test runs AFTER"},
		{"the guard named only in a comment", "        # run: " + pinGuardPath + "\n" + install, "compared by nothing"},
		{"a block scalar hides the commands", "        run: |\n          " + pinGuardPath + "\n", "block-scalar"},
		{"a workflow with no run: at all", "jobs:\n  j:\n    steps:\n      - uses: actions/checkout@v4\n", "vacuously"},
		{"nothing installs the scanner", guard + cases, "not scanned at all"},
	} {
		got := pinGuardFindings(tc.text)
		switch {
		case tc.wants == "" && len(got) != 0:
			t.Errorf("%s: wanted no finding, got %v", tc.name, got)
		case tc.wants != "":
			if len(got) == 0 {
				t.Errorf("%s: wanted a finding carrying %q, got none", tc.name, tc.wants)
				continue
			}
			if !strings.Contains(strings.Join(got, " | "), tc.wants) {
				t.Errorf("%s: wanted a finding carrying %q, got %v", tc.name, tc.wants, got)
			}
		}
	}
}
