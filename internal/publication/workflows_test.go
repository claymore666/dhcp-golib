// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

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
	"path"
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

// secretsInherit matches the OTHER way a workflow hands secrets on: `secrets:
// inherit` passes every secret this repository holds to a called workflow
// without naming one, so it carries no `secrets.` dot and the read above
// cannot see it. Two spellings enumerated means the check is keyed on the act
// of handing secrets over, not on one way of writing it.
var secretsInherit = regexp.MustCompile(`(?m)^[ \t]*secrets:[ \t]*inherit[ \t]*$`)

// workflowRef matches a `uses:` naming another WORKFLOW rather than an action.
// A reusable-workflow reference is a path ending `.yml`/`.yaml`, optionally
// with an `@ref`; an action reference is a directory or a repository and never
// carries that suffix. The suffix is the property, and it is the one GitHub
// itself keys on.
var workflowRef = regexp.MustCompile(`^\s*uses:\s*['"]?([^'"\s@]+\.ya?ml)(@[^'"\s]+)?['"]?\s*$`)

// workflow is what this file can see of one workflow file.
type workflow struct {
	name     string
	triggers []string
	runners  []string
	secrets  []string
	calls    []string
	// via names, per inherited trigger, the workflow the trigger came from.
	via map[string]string
}

// forkReachableSelfHosted reports whether this workflow puts a runner that is
// not one of GitHub's hosted images within reach of a fork's pull request, and
// names the pair that does it.
func (w workflow) forkReachableSelfHosted() (label, trigger, via string, bad bool) {
	for _, t := range w.triggers {
		if !forkTriggers[t] {
			continue
		}
		for _, r := range w.runners {
			if !hostedRunner.MatchString(r) {
				return r, t, w.via[t], true
			}
		}
	}
	return "", "", "", false
}

// forkTrigger names the first fork-reachable trigger this workflow has, or "".
func (w workflow) forkTrigger() string {
	for _, t := range w.triggers {
		if forkTriggers[t] {
			return t
		}
	}
	return ""
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
// `push`, `[self-hosted, dhcp-golib]`, `["ubuntu-24.04"]`, and the flow
// mapping `{push: null, pull_request: null}` — in a flow mapping the name is
// the KEY, so what follows a colon is dropped.
func scalarNames(v string) []string {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, "[]{}")
	var out []string
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if i := strings.Index(part, ":"); i >= 0 {
			part = part[:i]
		}
		part = strings.Trim(part, `"'`)
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

var (
	onKey      = regexp.MustCompile(`^(?:on|"on"|'on'):(.*)$`)
	runsOnKey  = regexp.MustCompile(`^\s*runs-on:(.*)$`)
	mappingKey = regexp.MustCompile(`^\s*['"]?([A-Za-z_][A-Za-z0-9_-]*)['"]?:`)
	seqItem    = regexp.MustCompile(`^\s*-\s*(.+)$`)
)

// scanWorkflow reads one workflow as TEXT.
//
// BOUNDS, stated here rather than discovered: it reads the file as lines, so a
// trigger or a runner label that arrives through an expression, a YAML anchor,
// or a value this repository does not write today is outside what it can see.
// It is a refusal of the shape that can be written down, not a proof that no
// other shape exists. Anything it cannot parse is left OUT of the runner and
// trigger sets, so the failure direction of a parse it does not understand is
// silence — which is why the callers below floor both sets PER FILE rather
// than trusting them, and why a `uses:` edge it cannot follow is a failure
// rather than an omission.
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
	for range secretsInherit.FindAllString(code.String(), -1) {
		w.secrets = append(w.secrets, "secrets: inherit")
	}

	for i := 0; i < len(lines); i++ {
		line := stripComment(lines[i])

		if m := onKey.FindStringSubmatch(line); m != nil {
			if rest := strings.TrimSpace(m[1]); rest != "" {
				w.triggers = append(w.triggers, scalarNames(rest)...)
				continue
			}
			// The block form. GitHub reads the DIRECT CHILDREN of `on:`,
			// whatever column they start in; YAML fixes that column at the
			// first child and every sibling shares it. So the child column is
			// MEASURED off the first child line. A `<=` against a constant
			// reads a POSITION as a property: a four-space `on:` block then
			// parses to no triggers at all, and a file that parses to nothing
			// is refused by nothing.
			child := -1
			for j := i + 1; j < len(lines); j++ {
				sub := stripComment(lines[j])
				if strings.TrimSpace(sub) == "" {
					continue
				}
				in := indent(sub)
				if child < 0 {
					if in == 0 {
						break
					}
					child = in
				}
				if in < child {
					break
				}
				if in > child {
					continue
				}
				if k := seqItem.FindStringSubmatch(sub); k != nil {
					w.triggers = append(w.triggers, scalarNames(k[1])...)
					continue
				}
				if k := mappingKey.FindStringSubmatch(sub); k != nil {
					w.triggers = append(w.triggers, k[1])
				}
			}
			continue
		}

		if m := workflowRef.FindStringSubmatch(line); m != nil {
			w.calls = append(w.calls, m[1])
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

// localWorkflowRef reports whether a `uses:` target names a workflow file in
// THIS repository, and gives its base name.
func localWorkflowRef(ref string) (string, bool) {
	if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "/") {
		return path.Base(ref), true
	}
	return "", false
}

// unresolvedCall is a `uses:` edge into a workflow this scan cannot read: one
// in another repository, or a local path naming no file in the set.
type unresolvedCall struct {
	caller  string
	ref     string
	trigger string
}

// resolveWorkflowCalls follows the `uses:` edges between the workflows in this
// repository and gives every callee the triggers of its callers.
//
// This is the second half of the property, and without it the first half is
// satisfied by splitting one workflow into two: a caller with `on:
// pull_request` whose only job is `uses: ./.github/workflows/lane.yml`, and a
// callee with `on: workflow_call` and a self-hosted `runs-on`. Neither FILE
// pairs a fork trigger with a runner of ours; the composition does, and it is
// the composition that GitHub runs. A reusable workflow's jobs take their
// runners from the CALLING repository, so the callee's labels are ours.
//
// Triggers only, never runners: a callee whose own jobs are all hosted stays
// green no matter who calls it.
func resolveWorkflowCalls(ws []workflow) ([]workflow, []unresolvedCall) {
	byName := make(map[string]int, len(ws))
	for i := range ws {
		byName[ws[i].name] = i
	}
	for changed := true; changed; {
		changed = false
		for i := range ws {
			for _, ref := range ws[i].calls {
				base, local := localWorkflowRef(ref)
				if !local {
					continue
				}
				j, known := byName[base]
				if !known || j == i {
					continue
				}
				for _, tr := range ws[i].triggers {
					if contains(ws[j].triggers, tr) {
						continue
					}
					ws[j].triggers = append(ws[j].triggers, tr)
					if ws[j].via == nil {
						ws[j].via = map[string]string{}
					}
					ws[j].via[tr] = ws[i].name
					changed = true
				}
			}
		}
	}
	var open []unresolvedCall
	for i := range ws {
		for _, ref := range ws[i].calls {
			if base, local := localWorkflowRef(ref); local {
				if _, known := byName[base]; known {
					continue
				}
			}
			open = append(open, unresolvedCall{caller: ws[i].name, ref: ref, trigger: ws[i].forkTrigger()})
		}
	}
	return ws, open
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// floorViolations names every workflow the scan read nothing usable out of.
//
// IT IS PER FILE, and that is the whole point of it. Summed over the set --
// total triggers, total runners -- the floor is satisfied by any one workflow
// that parses, so the file that parses to NOTHING is invisible while a sibling
// has triggers. A file that parses to nothing is precisely what a misread
// `on:` block produces, and it would then pass every check here by having
// nothing to combine.
//
// A workflow whose only job is a `uses:` call carries no `runs-on`, so a call
// satisfies the second half.
func floorViolations(ws []workflow) []string {
	var bad []string
	for _, w := range ws {
		switch {
		case len(w.triggers) == 0:
			bad = append(bad, w.name+": no trigger; every workflow has an `on:` block, so reading none is a scan that did not read this file")
		case len(w.runners) == 0 && len(w.calls) == 0:
			bad = append(bad, w.name+": no runs-on label and no reusable-workflow call; a workflow runs its jobs somewhere")
		}
	}
	return bad
}

// forkReachabilityFindings names every way this workflow SET puts a runner
// that is not one of GitHub's hosted images within reach of a fork's pull
// request. Two arms, and the second is the fail-closed one:
//
//   - a workflow that pairs a fork trigger with a runner of ours, whether the
//     trigger is its own or inherited from a workflow that calls it;
//   - a workflow with a fork trigger that calls a workflow this scan cannot
//     read. A called workflow's jobs take their runners from THIS repository,
//     so a self-hosted label inside one is reachable from here and invisible
//     from here. Silence about it would be the omission the whole check exists
//     to refuse.
func forkReachabilityFindings(ws []workflow, open []unresolvedCall) []string {
	var out []string
	for _, w := range ws {
		if label, trigger, via, bad := w.forkReachableSelfHosted(); bad {
			from := ""
			if via != "" {
				from = ", a trigger it inherits from " + via
			}
			out = append(out, w.name+": runs on "+label+", which is not one of GitHub's hosted images, and is triggered by "+trigger+from+"; a fork's pull request would execute the fork's tree on that machine")
		}
	}
	for _, c := range open {
		if c.trigger == "" {
			continue
		}
		out = append(out, c.caller+": is triggered by "+c.trigger+" and calls "+c.ref+", which this scan cannot read; a called workflow's jobs take their runners from this repository, so a self-hosted label in it would be reachable from a fork's pull request and nothing here could see it")
	}
	return out
}

// treeWorkflows reads every workflow in the repository, with the non-vacuity
// floors the scan needs to mean anything: a directory that has gone empty, a
// glob that stopped matching and a parse that produced no triggers all look
// like a clean run otherwise.
//
// THE FLOORS ARE PER FILE. Summed over the set they are satisfied by any one
// workflow that parses, so the file that parses to nothing — which is exactly
// what a misread `on:` block produces — is invisible while a sibling has
// triggers.
func treeWorkflows(t *testing.T) ([]workflow, []unresolvedCall) {
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
	if bad := floorViolations(out); len(bad) != 0 {
		t.Fatalf("the scan read nothing usable out of %d of %d workflow(s):\n  %s", len(bad), len(out), strings.Join(bad, "\n  "))
	}
	resolved, open := resolveWorkflowCalls(out)
	return resolved, open
}

// TestNoSelfHostedJobIsReachableFromAForkPullRequest is the property that has
// to survive this repository becoming public, and it is a property of the
// WORKFLOW SET rather than of the runner or of who can read the repository.
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
	for _, f := range forkReachabilityFindings(treeWorkflows(t)) {
		t.Error(f)
	}
}

// TestNoWorkflowReadsARepositorySecret is the second half of the same
// argument. The lane needs no secret — its whole output is a verdict — and a
// lane that holds none has nothing for a job to carry off even if a job could
// be reached.
//
// Two spellings: a `secrets.NAME` read, and `secrets: inherit`, which hands
// every secret to a called workflow without naming one.
//
// BOUND: comments are stripped before the scan, so a `secrets.` written in
// prose is not a finding; and this reads text, so a secret reached through a
// composite action is outside it.
func TestNoWorkflowReadsARepositorySecret(t *testing.T) {
	ws, _ := treeWorkflows(t)
	for _, w := range ws {
		if len(w.secrets) != 0 {
			t.Errorf("%s reads %s; this lane is designed to hold no secret, and that is what makes the runner question a question about code execution only",
				w.name, strings.Join(w.secrets, ", "))
		}
	}
}

// TestTheWorkflowScanRefusesTheShapesItExistsToRefuse drives the checks above
// against workflows that violate them, because a check whose only verdict is
// the one the tree happens to produce is not a check. The controls are the
// halves on their own: a hosted runner reachable from a fork is fine, a
// self-hosted runner that no fork can reach is fine, and a key BELOW a trigger
// is not itself a trigger.
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
	// The r1 finding, verbatim: valid YAML that GitHub honours, and the
	// `on:` block indented four spaces instead of two.
	const fourSpaceBlock = `
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
	const sixSpaceSequence = `
name: verify
on:
      - push
      - pull_request
jobs:
  verify:
    runs-on: [self-hosted, dhcp-golib]
    steps:
      - run: ./verify.sh
`
	const flowMapping = `
name: verify
on: {push: null, pull_request: null}
jobs:
  verify:
    runs-on: [self-hosted, dhcp-golib]
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
	// The preservation control for the indent rule: `branches` and `main`
	// live UNDER `push`, and a scan that measured the child column wrongly
	// would report them as triggers.
	const filteredPush = `
name: verify
on:
  push:
    branches:
      - main
      - pull_request
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
	const inheritsSecrets = `
name: caller
on:
  pull_request:
jobs:
  call:
    uses: ./.github/workflows/lane.yml
    secrets: inherit
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
	// A step `uses:` names an ACTION, never a workflow, and must produce no
	// edge — otherwise every lane in the world becomes an unreadable callee.
	const usesAnAction = `
name: verify
on:
  pull_request:
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - name: Check out the commit under verification
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
      - run: ./verify.sh
`
	cases := []struct {
		name       string
		text       string
		wantFork   bool
		wantSecret bool
		wantCalls  int
	}{
		{"self-hosted with a pull_request trigger", selfHostedPR, true, false, 0},
		{"a bare label with pull_request_target", barelabelPRTarget, true, false, 0},
		{"inline trigger list", inlineTriggers, true, false, 0},
		{"a four-space on: block", fourSpaceBlock, true, false, 0},
		{"a six-space sequence on: block", sixSpaceSequence, true, false, 0},
		{"a flow mapping on: block", flowMapping, true, false, 0},
		{"a hosted image is reachable and that is fine", hostedPR, false, false, 0},
		{"self-hosted with no fork trigger", selfHostedPush, false, false, 0},
		{"a key under a trigger is not a trigger", filteredPush, false, false, 0},
		{"a secret read", readsASecret, false, true, 0},
		{"secrets: inherit is a handover of every secret", inheritsSecrets, false, true, 1},
		{"a secret named in a comment is not a read", secretInAComment, false, false, 0},
		{"a step uses: names an action, not a workflow", usesAnAction, false, false, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := scanWorkflow(c.name, c.text)
			if len(w.triggers) == 0 || (len(w.runners) == 0 && len(w.calls) == 0) {
				t.Fatalf("the scan read %d trigger(s), %d runner(s) and %d call(s) out of this fixture; it is agreeing by seeing nothing", len(w.triggers), len(w.runners), len(w.calls))
			}
			if _, _, _, got := w.forkReachableSelfHosted(); got != c.wantFork {
				t.Errorf("fork-reachable self-hosted = %t, want %t (triggers %v, runners %v)", got, c.wantFork, w.triggers, w.runners)
			}
			if got := len(w.secrets) > 0; got != c.wantSecret {
				t.Errorf("reads a secret = %t, want %t (%v)", got, c.wantSecret, w.secrets)
			}
			if got := len(w.calls); got != c.wantCalls {
				t.Errorf("reusable-workflow call(s) = %d, want %d (%v)", got, c.wantCalls, w.calls)
			}
		})
	}

	// The floor, driven over a SET rather than over the tree, because the
	// difference between the per-file floor and a summed one cannot be seen
	// while this repository holds one workflow. `unread` is what a workflow
	// looks like to a scan that did not read it: no trigger and no runner.
	t.Run("a file the scan read nothing out of is named, even beside one it read", func(t *testing.T) {
		const unread = `
name: opaque
jobs:
  verify:
    steps:
      - run: ./verify.sh
`
		set := []workflow{
			scanWorkflow("verify.yml", selfHostedPush),
			scanWorkflow("opaque.yml", unread),
		}
		var triggers, runners int
		for _, w := range set {
			triggers += len(w.triggers)
			runners += len(w.runners)
		}
		if triggers == 0 || runners == 0 {
			t.Fatalf("this fixture does not reproduce the shape: the SUMMED floor already refuses it (%d trigger(s), %d runner(s))", triggers, runners)
		}
		bad := floorViolations(set)
		if len(bad) != 1 || !strings.HasPrefix(bad[0], "opaque.yml:") {
			t.Errorf("floorViolations = %v, want exactly one naming opaque.yml", bad)
		}
	})
}

// TestAForkTriggerReachesTheWorkflowsItCalls drives the composition the
// single-file scan cannot refuse: two files, each innocent on its own.
//
// It also drives the two directions that must NOT go red — a callee whose own
// jobs are hosted, and a caller with no fork trigger — and the fail-closed
// arm, a callee this repository does not hold.
func TestAForkTriggerReachesTheWorkflowsItCalls(t *testing.T) {
	const prCaller = `
name: caller
on:
  pull_request:
jobs:
  call:
    uses: ./.github/workflows/lane.yml
`
	const pushCaller = `
name: caller
on:
  push:
jobs:
  call:
    uses: ./.github/workflows/lane.yml
`
	const foreignCaller = `
name: caller
on:
  pull_request:
jobs:
  call:
    uses: someone/elsewhere/.github/workflows/lane.yml@main
`
	const selfHostedCallee = `
name: lane
on:
  workflow_call:
jobs:
  verify:
    runs-on: [self-hosted, dhcp-golib]
    steps:
      - run: ./verify.sh
`
	const hostedCallee = `
name: lane
on:
  workflow_call:
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - run: ./verify.sh
`
	cases := []struct {
		name       string
		caller     string
		callee     string
		wantFork   bool
		wantUnread bool
		wantVia    bool
	}{
		{"a fork PR reaches the self-hosted callee", prCaller, selfHostedCallee, true, false, true},
		{"a push caller reaches it too, and that is fine", pushCaller, selfHostedCallee, false, false, false},
		{"a hosted callee stays green whoever calls it", prCaller, hostedCallee, false, false, false},
		{"a callee this repository does not hold is a failure, not an omission", foreignCaller, selfHostedCallee, false, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ws := []workflow{
				scanWorkflow("caller.yml", c.caller),
				scanWorkflow("lane.yml", c.callee),
			}
			resolved, open := resolveWorkflowCalls(ws)
			found := forkReachabilityFindings(resolved, open)
			bad, unread := false, false
			for _, f := range found {
				if strings.Contains(f, "cannot read") {
					unread = true
					continue
				}
				bad = true
			}
			if bad != c.wantFork {
				t.Errorf("fork-reachable self-hosted anywhere in the set = %t, want %t (caller %v, callee %v via %v; findings %v)",
					bad, c.wantFork, resolved[0].triggers, resolved[1].triggers, resolved[1].via, found)
			}
			if unread != c.wantUnread {
				t.Errorf("an unreadable callee reachable from a fork trigger = %t, want %t (open %v; findings %v)", unread, c.wantUnread, open, found)
			}
			// The finding has to say WHERE the trigger came from. A callee
			// whose own `on:` is `workflow_call` and whose finding reads
			// "triggered by pull_request" sends the reader to the wrong file.
			via := false
			for _, f := range found {
				if strings.Contains(f, "inherits from caller.yml") {
					via = true
				}
			}
			if via != c.wantVia {
				t.Errorf("the finding names the workflow the trigger was inherited from = %t, want %t (%v)", via, c.wantVia, found)
			}
		})
	}
}
