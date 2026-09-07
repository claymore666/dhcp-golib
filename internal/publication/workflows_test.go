// Package publication holds the checks a PUBLIC repository owes that no other
// gate here covers: that a job on a machine of ours cannot be started by a
// stranger, and that every file carries the licence it is offered under.
//
// It is a test-only package for the reason internal/manifest is one — it
// asserts about the repository rather than about the library — and it runs
// inside the unit suite, whose own population is floored by
// MIN_DECLARED_TESTS.
package publication

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// workflowDir is the workflow set, relative to this package.
const workflowDir = "../../.github/workflows"

// hostedRunner matches the label prefixes GitHub's own hosted images use.
//
// THE PREDICATE IS "NOT ONE OF THESE", NOT "self-hosted". A gate keyed on the
// word self-hosted refuses the one spelling that happens to be in the tree
// today and is satisfied by a bare label — `runs-on: [dhcp-golib]` is a
// self-hosted runner and says so nowhere. Keying on the complement means a
// label nobody here has seen before is treated as ours, which is the direction
// that fails closed.
var hostedRunner = regexp.MustCompile(`(?i)^(ubuntu|macos|windows)-`)

// forkTriggers are the two events a pull request from a FORK can start. A
// fork's push is a push in the fork and reaches nothing here, which is why
// `push` is not in this set.
var forkTriggers = map[string]bool{
	"pull_request":        true,
	"pull_request_target": true,
}

// secretRead matches a read of a repository secret.
var secretRead = regexp.MustCompile(`\bsecrets\.[A-Za-z_][A-Za-z0-9_]*`)

// workflow is what this file can see of one workflow file.
type workflow struct {
	name     string
	triggers []string
	runners  []string
	secrets  []string
}

// forkReachableSelfHosted reports whether this workflow puts a runner that is
// not one of GitHub's hosted images within reach of a fork's pull request, and
// names the pair that does it.
func (w workflow) forkReachableSelfHosted() (label, trigger string, bad bool) {
	for _, t := range w.triggers {
		if !forkTriggers[t] {
			continue
		}
		for _, r := range w.runners {
			if !hostedRunner.MatchString(r) {
				return r, t, true
			}
		}
	}
	return "", "", false
}

// stripComment removes a YAML comment from one line: a `#` that begins the
// line, or one preceded by whitespace. A `#` inside a quoted string with no
// space before it survives, which is the case this rule exists to keep.
func stripComment(line string) string {
	trimmed := strings.TrimLeft(line, " \t")
	if strings.HasPrefix(trimmed, "#") {
		return ""
	}
	if i := strings.Index(line, " #"); i >= 0 {
		return line[:i]
	}
	if i := strings.Index(line, "\t#"); i >= 0 {
		return line[:i]
	}
	return line
}

// indent is the number of leading spaces on a line.
func indent(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}

// scalarNames pulls the identifiers out of a YAML value written on one line:
// `push`, `[self-hosted, dhcp-golib]`, `["ubuntu-24.04"]`.
func scalarNames(v string) []string {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, "[]")
	var out []string
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, `"'`)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

var (
	onKey      = regexp.MustCompile(`^(?:on|"on"|'on'):(.*)$`)
	runsOnKey  = regexp.MustCompile(`^\s*runs-on:(.*)$`)
	mappingKey = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_-]*):`)
	seqItem    = regexp.MustCompile(`^\s*-\s*(.+)$`)
)

// scanWorkflow reads one workflow as TEXT.
//
// BOUNDS, stated here rather than discovered: it reads the file as lines, so a
// trigger or a runner label that arrives through an expression, a YAML anchor,
// a reusable workflow called with `uses:`, or a value this repository does not
// write today is outside what it can see. It is a refusal of the shape that
// can be written down, not a proof that no other shape exists. Anything it
// cannot parse is left OUT of the runner and trigger sets, so the failure
// direction of a parse it does not understand is silence — which is why the
// callers below floor both sets rather than trusting them.
func scanWorkflow(name, text string) workflow {
	w := workflow{name: name}
	lines := strings.Split(text, "\n")

	// Comments are stripped before the secret scan, so a `secrets.` written in
	// prose is not reported as a read; a comment cannot expand an expression.
	var code strings.Builder
	for _, ln := range lines {
		code.WriteString(stripComment(ln))
		code.WriteByte('\n')
	}
	for _, m := range secretRead.FindAllString(code.String(), -1) {
		w.secrets = append(w.secrets, m)
	}

	for i := 0; i < len(lines); i++ {
		line := stripComment(lines[i])

		if m := onKey.FindStringSubmatch(line); m != nil {
			if rest := strings.TrimSpace(m[1]); rest != "" {
				w.triggers = append(w.triggers, scalarNames(rest)...)
				continue
			}
			for j := i + 1; j < len(lines); j++ {
				sub := stripComment(lines[j])
				if strings.TrimSpace(sub) == "" {
					continue
				}
				if indent(sub) == 0 {
					break
				}
				if k := mappingKey.FindStringSubmatch(sub); k != nil && indent(sub) <= 2 {
					w.triggers = append(w.triggers, k[1])
					continue
				}
				if k := seqItem.FindStringSubmatch(sub); k != nil && indent(sub) <= 2 {
					w.triggers = append(w.triggers, scalarNames(k[1])...)
				}
			}
			continue
		}

		if m := runsOnKey.FindStringSubmatch(line); m != nil {
			if rest := strings.TrimSpace(m[1]); rest != "" {
				w.runners = append(w.runners, scalarNames(rest)...)
				continue
			}
			base := indent(line)
			for j := i + 1; j < len(lines); j++ {
				sub := stripComment(lines[j])
				if strings.TrimSpace(sub) == "" {
					continue
				}
				if indent(sub) <= base {
					break
				}
				if k := seqItem.FindStringSubmatch(sub); k != nil {
					w.runners = append(w.runners, scalarNames(k[1])...)
					continue
				}
				break
			}
		}
	}
	return w
}

// treeWorkflows reads every workflow in the repository, with the non-vacuity
// floors the scan needs to mean anything: a directory that has gone empty, a
// glob that stopped matching and a parse that produced no triggers all look
// like a clean run otherwise.
func treeWorkflows(t *testing.T) []workflow {
	t.Helper()
	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		t.Fatalf("reading %s: %v", workflowDir, err)
	}
	var out []workflow
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || (!strings.HasSuffix(n, ".yml") && !strings.HasSuffix(n, ".yaml")) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(workflowDir, n))
		if err != nil {
			t.Fatalf("reading %s: %v", n, err)
		}
		out = append(out, scanWorkflow(n, string(b)))
	}
	if len(out) == 0 {
		t.Fatalf("%s holds no workflow; this check would pass over an empty domain", workflowDir)
	}
	var triggers, runners int
	for _, w := range out {
		triggers += len(w.triggers)
		runners += len(w.runners)
	}
	if triggers == 0 || runners == 0 {
		t.Fatalf("scanned %d workflow(s) and found %d trigger(s) and %d runs-on label(s); a scan that reads neither cannot refuse their combination",
			len(out), triggers, runners)
	}
	return out
}

// TestNoSelfHostedJobIsReachableFromAForkPullRequest is the property that has
// to survive this repository becoming public, and it is a property of the
// WORKFLOW rather than of the runner or of who can read the repository.
//
// A pull request from a fork proposes the FORK's tree. A job that runs on a
// runner of ours and can be started by one is a stranger's code executing on
// that machine. `push` and `workflow_dispatch` are not reachable that way — a
// fork's push is a push in the fork — so a lane triggered only by those runs
// nothing on a fork's behalf.
//
// IT DOES NOT REFUSE `self-hosted`. The lane is self-hosted by decision (D36),
// so a gate that refused the label would have been red the day it was written
// and would have been deleted rather than obeyed.
func TestNoSelfHostedJobIsReachableFromAForkPullRequest(t *testing.T) {
	for _, w := range treeWorkflows(t) {
		if label, trigger, bad := w.forkReachableSelfHosted(); bad {
			t.Errorf("%s runs on %q, which is not one of GitHub's hosted images, and is triggered by %q: a fork's pull request would execute the fork's tree on that machine",
				w.name, label, trigger)
		}
	}
}

// TestNoWorkflowReadsARepositorySecret is the second half of the same
// argument. The lane needs no secret — its whole output is a verdict — and a
// lane that holds none has nothing for a job to carry off even if a job could
// be reached.
//
// BOUND: comments are stripped before the scan, so a `secrets.` written in
// prose is not a finding; and this reads text, so a secret reached through a
// composite action or a reusable workflow is outside it.
func TestNoWorkflowReadsARepositorySecret(t *testing.T) {
	for _, w := range treeWorkflows(t) {
		if len(w.secrets) != 0 {
			t.Errorf("%s reads %s; this lane is designed to hold no secret, and that is what makes the runner question a question about code execution only",
				w.name, strings.Join(w.secrets, ", "))
		}
	}
}

// TestTheWorkflowScanRefusesTheShapesItExistsToRefuse drives the checks above
// against workflows that violate them, because a check whose only verdict is
// the one the tree happens to produce is not a check. The two controls are the
// halves on their own: a hosted runner reachable from a fork is fine, and a
// self-hosted runner that no fork can reach is fine.
func TestTheWorkflowScanRefusesTheShapesItExistsToRefuse(t *testing.T) {
	const selfHostedPR = `
name: verify
on:
  push:
  pull_request:
jobs:
  verify:
    runs-on: [self-hosted, dhcp-golib]
    steps:
      - run: ./verify.sh
`
	const barelabelPRTarget = `
name: verify
on:
  pull_request_target:
jobs:
  verify:
    runs-on:
      - dhcp-golib
    steps:
      - run: ./verify.sh
`
	const inlineTriggers = `
name: verify
on: [push, pull_request]
jobs:
  verify:
    runs-on: self-hosted
    steps:
      - run: ./verify.sh
`
	const hostedPR = `
name: verify
on:
  pull_request:
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - run: ./verify.sh
`
	const selfHostedPush = `
name: verify
on:
  push:
  workflow_dispatch:
jobs:
  verify:
    runs-on: [self-hosted, dhcp-golib]
    steps:
      - run: ./verify.sh
`
	const readsASecret = `
name: verify
on:
  push:
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - run: ./verify.sh
        env:
          TOKEN: ${{ secrets.PUBLISH_TOKEN }}
`
	const secretInAComment = `
name: verify
on:
  push:
jobs:
  verify:
    # nothing here reads secrets.ANYTHING, and saying so is not a read
    runs-on: ubuntu-24.04
    steps:
      - run: ./verify.sh
`
	cases := []struct {
		name       string
		text       string
		wantFork   bool
		wantSecret bool
	}{
		{"self-hosted with a pull_request trigger", selfHostedPR, true, false},
		{"a bare label with pull_request_target", barelabelPRTarget, true, false},
		{"inline trigger list", inlineTriggers, true, false},
		{"a hosted image is reachable and that is fine", hostedPR, false, false},
		{"self-hosted with no fork trigger", selfHostedPush, false, false},
		{"a secret read", readsASecret, false, true},
		{"a secret named in a comment is not a read", secretInAComment, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := scanWorkflow(c.name, c.text)
			if len(w.triggers) == 0 || len(w.runners) == 0 {
				t.Fatalf("the scan read %d trigger(s) and %d runner(s) out of this fixture; it is agreeing by seeing nothing", len(w.triggers), len(w.runners))
			}
			if _, _, got := w.forkReachableSelfHosted(); got != c.wantFork {
				t.Errorf("fork-reachable self-hosted = %t, want %t (triggers %v, runners %v)", got, c.wantFork, w.triggers, w.runners)
			}
			if got := len(w.secrets) > 0; got != c.wantSecret {
				t.Errorf("reads a secret = %t, want %t (%v)", got, c.wantSecret, w.secrets)
			}
		})
	}
}
