// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

// Package publication holds the checks a PUBLIC repository owes that no other
// gate here covers: that a job on a machine of ours cannot be started by a
// stranger, that the word `secrets` appears nowhere under .github/, and that
// every file carries the licence it is offered under.
//
// It is a test-only package for the reason internal/manifest is one — it
// asserts about the repository rather than about the library — and it runs
// inside the unit suite, whose own population is floored by
// MIN_DECLARED_TESTS.
package publication

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// workflowDir is the workflow set, relative to this package.
const workflowDir = "../../.github/workflows"

// githubDir is the domain of the forbidden word: everything the lane reads,
// not the workflows alone.
const githubDir = "../../.github"

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

// forbiddenWord is the whole of the second rule. NOTHING HERE RECOGNISES A
// SECRET: the word itself is refused, wherever it appears under .github/.
//
// Two rounds of review took the other road and both ended the same way. A read
// was matched (`secrets.NAME`), then a second spelling was enumerated beside it
// (`secrets: inherit`), and review round 3 then produced five more that GitHub
// honours and neither pattern saw — the two index forms, the computed index,
// and `inherit` in each kind of quotes. An enumeration of spellings cannot be
// finished, and every version of it reads a spelling it does not know as an
// absence, which is the one answer this file may never give.
//
// So the domain is closed instead. This lane holds no secret and needs none —
// its whole output is a verdict, and Go modules come from the repository — so
// there is no legitimate occurrence to tell from an illegitimate one, and the
// check does not have to be able to. `\b` is an ASCII word boundary, which is
// exactly the design's own wording: `secrets` bounded by non-identifier
// characters. `secrets.X`, `secrets['X']`, `secrets["X"]`,
// `secrets[format(...)]`, `secrets: inherit`, `secrets: "inherit"`, `SECRETS`
// and a comment that merely says the word are one case, not seven.
//
// WHAT THE BOUNDARY DELIBERATELY LEAVES ALONE, and it is the one place the
// rule is not a substring match: `secretsmanager` and `my_secrets_dir` are
// other words. A workflow file reaches a repository secret in exactly two
// ways, the `secrets` context and the `secrets:` key of a reusable-workflow
// call, and both are the bare word; an identifier that merely contains those
// letters names something else, and refusing it would make this a rule about
// letters rather than about the two things GitHub honours.
//
// THE ESCAPE, stated beside the claim: the automatic token also reaches a
// workflow as `github.token`, which carries no `secrets` word at all. That one
// is bounded by `permissions:` — `contents: read` in this lane — and not by
// this rule.
var forbiddenWord = regexp.MustCompile(`(?i)\bsecrets\b`)

// forbiddenWordRefusals names every LINE of a file under .github/ that carries
// the forbidden word, in the same shape as every other refusal: the file, the
// line, what was read there and why it was refused.
//
// One implementation, two domains: scanWorkflow calls it so that the word in a
// workflow reddens the tree rows that read workflows, and the .github/ walk
// calls it so that the word in a file that is not a workflow — a linter
// configuration, an action definition, anything added later — is refused by
// the same sentence. Comments are NOT stripped first: the rule is about the
// word, and a rule that had to know what a comment is would be one more piece
// of YAML this reader would have to understand.
//
// BOUND: the line is the unit, so a line carrying the word twice is one
// refusal. It names the line, which is what a maintainer acts on.
func forbiddenWordRefusals(name, text string) []string {
	var out []string
	for i, ln := range strings.Split(text, "\n") {
		if !forbiddenWord.MatchString(ln) {
			continue
		}
		out = append(out, fmt.Sprintf("%s:%d: read %q; refused: %s", name, i+1, strings.TrimSpace(ln), forbiddenWordReason))
	}
	return out
}

// forbiddenWordReason is one sentence, written once, because it is the sentence
// a stranger meets and the sentence docs/verifying.md publishes.
const forbiddenWordReason = "the word `secrets`, in any case and as a whole word, may not appear anywhere under .github/; this lane holds no secret and has nothing to hand over, so the word is refused rather than a secret being recognised. A workflow here that one day needs a secret is a deliberate, reviewed widening of this rule and its cases, never a cleverer reader"

// workflowRef matches a `uses:` naming another WORKFLOW rather than an action.
// A reusable-workflow reference is a path ending `.yml`/`.yaml`, optionally
// with an `@ref`; an action reference is a directory or a repository and never
// carries that suffix. The suffix is the property, and it is the one GitHub
// itself keys on.
var workflowRef = regexp.MustCompile(`^\s*uses:\s*['"]?([^'"\s@]+\.ya?ml)(@[^'"\s]+)?['"]?\s*$`)

// workflow is what this file can see of one workflow file.
//
// refusals is the field that changed the shape of this check. A file the
// reader could not read is not a file with nothing in it, and until round 3
// those two were the same value.
type workflow struct {
	name     string
	triggers []string
	runners  []string
	calls    []string
	jobs     []job
	// refusals names every place this file left the subset the reader
	// understands, with the line. A refusal is RED. It is never an absence.
	refusals []string
	// via names, per inherited trigger, the workflow the trigger came from.
	via map[string]string
}

// job is one entry under `jobs:`, and the unit the non-vacuity floor is taken
// over. Taken per FILE the floor was satisfied by one job that parsed while a
// sibling's runner went unread, which is the escape round 2 shipped.
type job struct {
	name    string
	line    int
	runners []string
	calls   []string
}

// refuse records that this file left the subset, naming the line, what was
// read there and what was refused. BOTH halves, because a diagnostic that says
// only that something is missing sends the reader to the wrong question: round
// 2 reported "no runs-on label" for a file that plainly had one.
func (w *workflow) refuse(line int, read, why string) {
	w.refusals = append(w.refusals, fmt.Sprintf("%s:%d: read %q; refused: %s", w.name, line, read, why))
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
	jobsKey    = regexp.MustCompile(`^(?:jobs|"jobs"|'jobs'):(.*)$`)
)

// scanWorkflow reads one workflow as TEXT, over a STATED SUBSET of YAML, and
// REFUSES everything outside it.
//
// Two review rounds found the same defect class here: a shape this reader did
// not understand parsed to nothing, and a file that parses to nothing agrees
// with every property asserted over it. Enumerating the shapes that had been
// found is what produced the second instance. So the domain is closed instead:
// anything the reader cannot enumerate is refused by name and line, never read
// as absence. A stranger's workflow written in a form this reader does not
// support fails the gate and says which form; it is then written in the
// subset. That is what makes the universal in docs/verifying.md true by
// construction rather than by luck, and it is why the lane's own verify.yml
// being inside the subset is proved on every run rather than asserted here.
//
// THE SUBSET:
//
//  1. the file carries no carriage return, no tab in any line's indentation,
//     and not the forbidden word;
//  2. the root is a block mapping whose keys sit at column 0, and every line
//     at column 0 is one of its keys;
//  3. `on:` is a plain scalar, or a flow sequence or flow mapping CLOSED on
//     its own line, or a block whose children are indented DEEPER than the key
//     and are each a `key:` or a `- entry`;
//  4. `jobs:` is such a block, each child a job key with no inline value and a
//     body indented deeper than it;
//  5. every line at a job's key column is a `key:`; a job's `runs-on:` takes
//     the value forms of clause 3, its block form being a sequence; a
//     job-level `uses:` names a path ending `.yml` or `.yaml`;
//  6. no `${{` expression in an `on:` or `runs-on:` region, and no YAML anchor
//     or alias in a value this reader enumerates.
//
// Each clause EXCLUDES ordinary YAML, and every excluded shape is a refusal
// rather than a silence: a flow collection spread over two lines, a `|` or `>`
// block scalar in one of those positions, a tab-indented file, a CRLF file, an
// anchor, an alias, an expression, `runs-on:` written as a mapping
// (`group:`/`labels:`), a sequence written at its key's own column — which is
// the round-2 escape, ordinary YAML that GitHub honours and this reader read as
// zero runners — a `---` document marker, and a key with a space before its
// colon, which YAML permits and which review round 3 found reaching the floor
// as "no trigger" with no line named.
//
// WHAT IS STILL NOT READ, stated rather than discovered. hostedRunner reads a
// LABEL, not an owner. A top-level key other than `on:` and `jobs:` is read
// only as a key and skipped with its whole block, so an anchor DEFINED there
// is not itself refused — the alias that carries it into a value the reader
// enumerates is. And a refused file is not a scanned file: the refusal is all
// this reader says about it, which is also why a CRLF file's occurrences of
// the forbidden word are never listed. It is red for the carriage return
// instead, and both directions are driven.
func scanWorkflow(name, text string) workflow {
	w := workflow{name: name}

	// Clause 1, spelled ONCE for the file rather than once per pattern. A
	// `\r` rides at the end of every line, which is where some of the
	// patterns here anchor and where others trim it away; a reader that
	// counts columns and matches line ends has no business deciding, pattern
	// by pattern, which of its own survive it. So the file is refused whole
	// at the first one, and one refusal covers every pattern added later.
	if i := strings.IndexByte(text, '\r'); i >= 0 {
		w.refuse(1+strings.Count(text[:i], "\n"), "a carriage return", "this reader anchors on the line end, so a CRLF file is refused whole rather than read half right")
		return w
	}

	lines := strings.Split(text, "\n")
	for i, ln := range lines {
		if strings.ContainsRune(ln[:len(ln)-len(strings.TrimLeft(ln, " \t"))], '\t') {
			w.refuse(i+1, strings.TrimSpace(ln), "a tab in the indentation; every column here is counted in spaces, and a tab makes each of them a guess")
			return w
		}
	}

	// Clause 1's third half, and the whole of the other rule. A file carrying
	// the forbidden word is refused whole: nothing is read out of it, so no
	// property is asserted over a file this repository does not permit to
	// carry that word.
	if r := forbiddenWordRefusals(name, text); len(r) != 0 {
		w.refusals = append(w.refusals, r...)
		return w
	}

	// Clause 2. Only column 0 is a root key, and a top-level key that is
	// neither `on:` nor `jobs:` takes its whole block with it. Every OTHER
	// line at the left margin is refused rather than skipped: skipping it is
	// how `on :`, with the space YAML permits before the colon, reached the
	// floor as "no trigger" instead of naming its own line.
	first := -1
	root := false
	for i := 0; i < len(lines); i++ {
		line := stripComment(lines[i])
		if strings.TrimSpace(line) == "" {
			continue
		}
		if first < 0 {
			first = i
		}
		if indent(line) != 0 {
			continue
		}
		if m := onKey.FindStringSubmatch(line); m != nil {
			root = true
			w.readOn(lines, i, m[1])
			continue
		}
		if m := jobsKey.FindStringSubmatch(line); m != nil {
			root = true
			w.readJobs(lines, i, m[1])
			continue
		}
		if mappingKey.MatchString(line) {
			root = true
			continue
		}
		w.refuse(i+1, strings.TrimSpace(lines[i]), "a line at the left margin this reader cannot read as a root `key:`; the root is a block mapping, and a key written any other way — `on :` with a space before the colon, a `---` document marker, a sequence entry — is refused rather than skipped as though the file did not carry it")
		return w
	}
	if !root {
		if first < 0 {
			w.refuse(1, "", "a file with nothing in it this reader can read; a workflow with no root key is not a workflow, and reading nothing out of it is not the same as it holding nothing")
			return w
		}
		w.refuse(first+1, strings.TrimSpace(lines[first]), fmt.Sprintf("a first line at column %d; this reader reads root keys at the left margin only, so a root mapping written indented is refused rather than read as a file with no `on:` and no `jobs:`", indent(stripComment(lines[first]))))
	}
	return w
}

// enumerateValue is the whole value grammar of clause 3, and it is a WHITELIST:
// a plain scalar, or a flow collection closed on its own line. Everything else
// returns a reason. The default arm of a whitelist is a refusal, so a YAML form
// nobody here thought of fails closed instead of parsing to something
// plausible — which is the property the two escapes turned on.
//
// One function for both `on:` and `runs-on:`, so the two cannot drift into
// different subsets while one paragraph describes both — and ONE arm per
// refusal class, so removing a class is one edit here rather than a class
// still refused, by accident, through a second arm that meant something else.
func enumerateValue(v string) ([]string, string) {
	v = strings.TrimSpace(v)
	switch {
	case v == "":
		return nil, "an empty value"
	case strings.Contains(v, "${{"):
		return nil, "an expression; this reader does not evaluate one and will not guess what it expands to"
	case strings.ContainsAny(v, "&*"):
		return nil, "a YAML anchor or alias; this reader does not expand one"
	case strings.HasPrefix(v, "|"), strings.HasPrefix(v, ">"):
		return nil, "a block scalar; this reader reads a value written on its own line"
	case strings.HasPrefix(v, "["):
		if !strings.HasSuffix(v, "]") {
			return nil, "a flow sequence that does not close on its line; this reader does not join lines"
		}
	case strings.HasPrefix(v, "{"):
		if !strings.HasSuffix(v, "}") {
			return nil, "a flow mapping that does not close on its line; this reader does not join lines"
		}
	case strings.ContainsAny(v, "[]{}"):
		return nil, "a value that is neither a plain scalar nor a flow collection"
	}
	names := scalarNames(v)
	if len(names) == 0 {
		return nil, "a value no name could be read out of"
	}
	return names, ""
}

// blockRegion gives the column the direct children of the key at lines[key]
// sit in, and the index the block ends at, or the reason the block is outside
// the subset.
//
// A block's children are indented DEEPER than its key. A sequence written at
// the key's own column is ordinary YAML — `runs-on:` with `- self-hosted`
// below it in the same column is two labels to GitHub, verified against a real
// parser in the round-2 record — and this reader does not enumerate it, so it
// is REFUSED. Round 2 read it as zero runners, and one unrelated `uses:` job
// then satisfied the file's floor.
func blockRegion(lines []string, key, keyIndent int) (child, end int, read, why string) {
	first := -1
	for j := key + 1; j < len(lines); j++ {
		if strings.TrimSpace(stripComment(lines[j])) != "" {
			first = j
			break
		}
	}
	if first < 0 {
		return 0, 0, "", "a key with no value and no block under it"
	}
	child = indent(stripComment(lines[first]))
	if child <= keyIndent {
		return 0, 0, strings.TrimSpace(lines[first]), fmt.Sprintf("a block whose first line sits at column %d, not deeper than its key at column %d; this reader enumerates a block only where its children are indented deeper than the key", child, keyIndent)
	}
	end = len(lines)
	for j := first; j < len(lines); j++ {
		sub := stripComment(lines[j])
		if strings.TrimSpace(sub) == "" {
			continue
		}
		if indent(sub) <= keyIndent {
			end = j
			break
		}
	}
	return child, end, "", ""
}

// readOn gives this workflow its triggers, or refuses the `on:` it was given.
func (w *workflow) readOn(lines []string, i int, rest string) {
	if v := strings.TrimSpace(rest); v != "" {
		names, why := enumerateValue(v)
		if why != "" {
			w.refuse(i+1, v, "an `on:` value outside the subset: "+why)
			return
		}
		w.triggers = append(w.triggers, names...)
		return
	}
	child, end, read, why := blockRegion(lines, i, 0)
	if why != "" {
		w.refuse(i+1, read, "an `on:` block outside the subset: "+why)
		return
	}
	// The children of `on:` are read at whatever column the first child sets,
	// which is where GitHub reads them; a constant compared against that
	// column reads a POSITION as a property, and an `on:` block indented four
	// spaces then parsed to no triggers at all.
	for j := i + 1; j < end; j++ {
		sub := stripComment(lines[j])
		if strings.TrimSpace(sub) == "" {
			continue
		}
		if strings.Contains(sub, "${{") {
			w.refuse(j+1, strings.TrimSpace(sub), "an expression inside the `on:` block; this reader does not evaluate one and will not guess which triggers it expands to")
			return
		}
		in := indent(sub)
		if in > child {
			continue
		}
		if in < child {
			w.refuse(j+1, strings.TrimSpace(sub), fmt.Sprintf("a line at column %d inside an `on:` block whose children sit at column %d", in, child))
			return
		}
		if k := seqItem.FindStringSubmatch(sub); k != nil {
			names, why := enumerateValue(k[1])
			if why != "" {
				w.refuse(j+1, strings.TrimSpace(sub), "an `on:` sequence entry outside the subset: "+why)
				return
			}
			w.triggers = append(w.triggers, names...)
			continue
		}
		if k := mappingKey.FindStringSubmatch(sub); k != nil {
			w.triggers = append(w.triggers, k[1])
			continue
		}
		w.refuse(j+1, strings.TrimSpace(sub), "a line in an `on:` block that is neither a mapping key nor a sequence entry")
		return
	}
}

// readJobs enumerates the jobs, which is what makes the floor a PER-JOB one.
func (w *workflow) readJobs(lines []string, i int, rest string) {
	if v := strings.TrimSpace(rest); v != "" {
		w.refuse(i+1, v, "a `jobs:` carrying a value on its own line; this reader enumerates jobs as a block")
		return
	}
	child, end, read, why := blockRegion(lines, i, 0)
	if why != "" {
		w.refuse(i+1, read, "a `jobs:` block outside the subset: "+why)
		return
	}
	for j := i + 1; j < end; j++ {
		sub := stripComment(lines[j])
		if strings.TrimSpace(sub) == "" || indent(sub) > child {
			continue
		}
		if indent(sub) < child {
			w.refuse(j+1, strings.TrimSpace(sub), fmt.Sprintf("a line at column %d inside a `jobs:` block whose jobs sit at column %d", indent(sub), child))
			return
		}
		k := mappingKey.FindStringSubmatch(sub)
		if k == nil {
			w.refuse(j+1, strings.TrimSpace(sub), "a line under `jobs:` that is not a job key")
			return
		}
		if v := strings.TrimSpace(sub[strings.Index(sub, ":")+1:]); v != "" {
			w.refuse(j+1, strings.TrimSpace(sub), "a job whose key carries a value on its own line; this reader reads a job as a block, so an aliased or inlined one is refused rather than read as a job with nothing in it")
			return
		}
		if !w.readJob(lines, j, child, k[1]) {
			return
		}
	}
}

// readJob reads one job's DIRECT CHILDREN: its `runs-on:` and, at job level
// and only at job level, its `uses:`. A `uses:` deeper than that names an
// ACTION and must produce no edge, which used to rest on the `.ya?ml` suffix
// alone; the column now says it too.
func (w *workflow) readJob(lines []string, key, keyIndent int, name string) bool {
	child, end, read, why := blockRegion(lines, key, keyIndent)
	if why != "" {
		w.refuse(key+1, read, "a job outside the subset: "+why)
		return false
	}
	jb := job{name: name, line: key + 1}
	for j := key + 1; j < end; j++ {
		sub := stripComment(lines[j])
		if strings.TrimSpace(sub) == "" {
			continue
		}
		in := indent(sub)
		if in > child {
			continue
		}
		if in < child {
			w.refuse(j+1, strings.TrimSpace(sub), fmt.Sprintf("a line at column %d inside a job whose keys sit at column %d", in, child))
			return false
		}
		if m := runsOnKey.FindStringSubmatch(sub); m != nil {
			labels, ok := w.readRunsOn(lines, j, child, m[1])
			if !ok {
				return false
			}
			jb.runners = append(jb.runners, labels...)
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(sub), "uses:") {
			if m := workflowRef.FindStringSubmatch(sub); m != nil {
				jb.calls = append(jb.calls, m[1])
				continue
			}
			w.refuse(j+1, strings.TrimSpace(sub), "a job-level `uses:` this reader cannot resolve to a workflow file; a called workflow's jobs take their runners from this repository, so an unresolved one is refused rather than ignored")
			return false
		}
		if !mappingKey.MatchString(sub) {
			w.refuse(j+1, strings.TrimSpace(sub), "a line at a job's key column this reader cannot read as a `key:`; `runs-on :`, with the space YAML permits before the colon, is a runner this reader would otherwise never see, and the job would go to the floor with no line named")
			return false
		}
	}
	w.jobs = append(w.jobs, jb)
	w.runners = append(w.runners, jb.runners...)
	w.calls = append(w.calls, jb.calls...)
	return true
}

// readRunsOn reads one job's runner labels, or refuses the value it was given.
func (w *workflow) readRunsOn(lines []string, i, keyIndent int, rest string) ([]string, bool) {
	if v := strings.TrimSpace(rest); v != "" {
		names, why := enumerateValue(v)
		if why != "" {
			w.refuse(i+1, v, "a `runs-on:` value outside the subset: "+why)
			return nil, false
		}
		return names, true
	}
	child, end, read, why := blockRegion(lines, i, keyIndent)
	if why != "" {
		w.refuse(i+1, read, "a `runs-on:` block outside the subset: "+why)
		return nil, false
	}
	var out []string
	for j := i + 1; j < end; j++ {
		sub := stripComment(lines[j])
		if strings.TrimSpace(sub) == "" {
			continue
		}
		if strings.Contains(sub, "${{") {
			w.refuse(j+1, strings.TrimSpace(sub), "an expression inside a `runs-on:` block; this reader does not evaluate one and will not guess which machine it names")
			return nil, false
		}
		in := indent(sub)
		if in != child {
			w.refuse(j+1, strings.TrimSpace(sub), fmt.Sprintf("a line at column %d inside a `runs-on:` block whose entries sit at column %d", in, child))
			return nil, false
		}
		k := seqItem.FindStringSubmatch(sub)
		if k == nil {
			w.refuse(j+1, strings.TrimSpace(sub), "a `runs-on:` block entry that is not a sequence entry; the mapping form, `group:` and `labels:`, is outside this reader")
			return nil, false
		}
		names, why := enumerateValue(k[1])
		if why != "" {
			w.refuse(j+1, strings.TrimSpace(sub), "a `runs-on:` sequence entry outside the subset: "+why)
			return nil, false
		}
		out = append(out, names...)
	}
	if len(out) == 0 {
		w.refuse(i+1, "runs-on:", "a `runs-on:` block this reader read no label out of")
		return nil, false
	}
	return out, true
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

// refusalsOf names every place the SET left the subset the reader understands.
// It is taken BEFORE any floor and before any property, because a refusal is
// not a fact about the workflow — it is the reader saying it did not read it.
func refusalsOf(ws []workflow) []string {
	var out []string
	for _, w := range ws {
		out = append(out, w.refusals...)
	}
	return out
}

// floorViolations names every workflow the scan read nothing usable out of.
//
// IT IS PER JOB, and conjunctive: every job yields at least one runner label
// or exactly one callee, and every workflow yields at least one trigger. Per
// FILE the second half was a disjunction over the union — no runner ANYWHERE
// and no call ANYWHERE — so one job with a `uses:` satisfied it for a sibling
// job whose runner the reader never read. That is the shape round 2 shipped,
// and it is why the floor is now taken over the jobs rather than over the file.
//
// A file with a REFUSAL is not floored. It was not read, and answering "no
// trigger" about a file the reader refused sends the reader to the wrong
// question; the refusal is the finding, and it names the line.
func floorViolations(ws []workflow) []string {
	var bad []string
	for _, w := range ws {
		if len(w.refusals) != 0 {
			continue
		}
		if len(w.triggers) == 0 {
			bad = append(bad, w.name+": no trigger; every workflow has an `on:` block, so reading none is a scan that did not read this file")
		}
		if len(w.jobs) == 0 {
			bad = append(bad, w.name+": no job; a workflow with no job runs nothing, so reading none is a scan that did not read this file")
			continue
		}
		for _, j := range w.jobs {
			if len(j.runners) != 0 || len(j.calls) == 1 {
				continue
			}
			bad = append(bad, fmt.Sprintf("%s:%d: job %s yields no runs-on label and no single reusable-workflow call; every job runs somewhere, and a job that yields neither was not read", w.name, j.line, j.name))
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

// treeWorkflows reads every workflow in the repository, in the order the
// verdict is taken: what the reader REFUSED, then the non-vacuity floors, then
// the properties. A directory that has gone empty, a glob that stopped
// matching and a parse that produced no triggers all look like a clean run
// otherwise.
//
// The refusals come first because they answer a different question. A floor
// says a file the reader read holds nothing; a refusal says the reader did not
// read it, and names the line and the shape. Reporting the second as the first
// is what sent round 2's reader to the wrong file.
//
// THE FLOORS ARE PER JOB and per file, never summed over the set: summed, they
// are satisfied by any one workflow that parses.
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
	if bad := refusalsOf(out); len(bad) != 0 {
		t.Fatalf("the scan refused %d line(s) of %d workflow(s) as outside the subset it reads; the fix is a workflow written in that subset, and docs/verifying.md states it:\n  %s", len(bad), len(out), strings.Join(bad, "\n  "))
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

// TestTheWordSecretsAppearsNowhereUnderGithub is the second half of the same
// argument, and it is the whole of the second rule. The lane needs no secret —
// its whole output is a verdict — and a lane that holds none has nothing for a
// job to carry off even if a job could be reached.
//
// It asserts about the WORD, not about a read, and its domain is every file
// under .github/, not the workflows alone: the word has no business anywhere
// the lane reads, and the day .github/ holds a composite action or a second
// linter configuration is the day a workflow-only rule would go quiet. That
// widening also closes what the old textual scan had to declare as a bound.
//
// The domain is a DIRECTORY rather than the tree for a reason worth stating:
// the rule has to be writable in the check that carries it and in the page
// that publishes it. internal/publication and docs/verifying.md are not under
// .github/, and that is not an exemption — it is the shape of the rule.
func TestTheWordSecretsAppearsNowhereUnderGithub(t *testing.T) {
	seen := map[string]bool{}
	var refusals []string
	err := filepath.WalkDir(githubDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(githubDir, p)
		if err != nil {
			return err
		}
		seen[filepath.ToSlash(rel)] = true
		refusals = append(refusals, forbiddenWordRefusals(filepath.ToSlash(rel), string(b))...)
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", githubDir, err)
	}

	// The floor, and it is DERIVED rather than a number typed here: every
	// workflow the other rows read has to be one of the files this walk
	// read. A walk that visits nothing agrees with this rule exactly as
	// loudly as a tree that carries the word nowhere.
	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		t.Fatalf("reading %s: %v", workflowDir, err)
	}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || (!strings.HasSuffix(n, ".yml") && !strings.HasSuffix(n, ".yaml")) {
			continue
		}
		if !seen[path.Join("workflows", n)] {
			t.Errorf("the walk of %s did not read workflows/%s, which the workflow rows do read; a walk that misses a file cannot say the word is absent from it", githubDir, n)
		}
	}
	if len(seen) == 0 {
		t.Fatalf("%s holds no file; this rule would pass over an empty domain", githubDir)
	}

	for _, r := range refusals {
		t.Error(r)
	}
}

// TestTheForbiddenWordIsRefusedInEverySpellingGitHubHonours drives the five
// spellings review round 3 measured escaping the two patterns that used to
// stand here, the two spellings those patterns did catch, and the two
// directions the word rule has to get right at its boundary.
//
// The five are quoted from the review record. Each was EMPTY under the old
// check — no refusal, no floor, reported as no secret — and each is one line
// of GitHub's documented context syntax that a two-registry publish lane is
// written in. They are not five cases here. They are the same case, because
// nothing recognises a secret any more: the word is refused.
func TestTheForbiddenWordIsRefusedInEverySpellingGitHubHonours(t *testing.T) {
	// The step shape the three index spellings ride in. The word lands on
	// line eleven of each, which is what the case asserts: a refusal that
	// names the file and no line is a refusal a maintainer has to search for.
	const indexedSingleQuotes = `
name: verify
on:
  push:
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - run: ./verify.sh
        env:
          TOKEN: ${{ secrets['PUBLISH_TOKEN'] }}
`
	const indexedDoubleQuotes = `
name: verify
on:
  push:
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - run: ./verify.sh
        env:
          TOKEN: ${{ secrets["PUBLISH_TOKEN"] }}
`
	const indexedByExpression = `
name: verify
on:
  push:
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - run: ./verify.sh
        env:
          TOKEN: ${{ secrets[format("REG_{0}", matrix.reg)] }}
`
	const dottedRead = `
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
	const shoutedRead = `
name: verify
on:
  push:
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - run: ./verify.sh
        env:
          TOKEN: ${{ SECRETS.PUBLISH_TOKEN }}
`
	// The caller shape the three `inherit` spellings ride in; the word lands
	// on line eight of each.
	const inheritBare = `
name: caller
on:
  pull_request:
jobs:
  call:
    uses: ./.github/workflows/lane.yml
    secrets: inherit
`
	const inheritDoubleQuoted = `
name: caller
on:
  pull_request:
jobs:
  call:
    uses: ./.github/workflows/lane.yml
    secrets: "inherit"
`
	const inheritSingleQuoted = `
name: caller
on:
  pull_request:
jobs:
  call:
    uses: ./.github/workflows/lane.yml
    secrets: 'inherit'
`
	const inheritMixedCase = `
name: caller
on:
  pull_request:
jobs:
  call:
    uses: ./.github/workflows/lane.yml
    Secrets: inherit
`
	// A comment, which under the old check was a deliberate exemption: the
	// text was stripped before the scan so that prose could say the word. The
	// rule is now about the word, so the exemption is gone and the comment is
	// the plainest case there is.
	const wordInAComment = `
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
	// THE OTHER DIRECTION, and the rule turns on it: these are other words.
	// A rule that refused them would be a rule about letters, and the mutant
	// that makes the match a substring dies here rather than anywhere else.
	const wordAsASubstring = `
name: verify
on:
  push:
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - run: ./verify.sh
        env:
          TOOL: secretsmanager
          CACHE: /tmp/my_secrets_dir
`
	// Not a workflow at all: the linter configuration beside them. The
	// domain is the directory, so this file is read by the same sentence.
	const linterConfig = `
self-hosted-runner:
  labels:
    - dhcp-golib
# the word secrets has no business here either
`
	const linterConfigClean = `
self-hosted-runner:
  labels:
    - dhcp-golib
`
	cases := []struct {
		name string
		file string
		text string
		// wantLine is the line the refusal must name; zero means the file
		// carries no forbidden word and no refusal may be raised.
		wantLine int
	}{
		{"an index in single quotes, EMPTY under the old check", "verify.yml", indexedSingleQuotes, 11},
		{"an index in double quotes, EMPTY under the old check", "verify.yml", indexedDoubleQuotes, 11},
		{"a computed index, EMPTY under the old check", "verify.yml", indexedByExpression, 11},
		{"inherit in double quotes, EMPTY under the old check", "caller.yml", inheritDoubleQuoted, 8},
		{"inherit in single quotes, EMPTY under the old check", "caller.yml", inheritSingleQuoted, 8},
		{"a dotted read is the forbidden word, not a finding", "verify.yml", dottedRead, 11},
		{"bare inherit is the forbidden word, not a finding", "caller.yml", inheritBare, 8},
		{"the word shouted", "verify.yml", shoutedRead, 11},
		{"the word in mixed case", "caller.yml", inheritMixedCase, 8},
		{"the word in a comment", "verify.yml", wordInAComment, 7},
		{"the word in a file that is not a workflow", "actionlint.yaml", linterConfig, 5},
		{"secretsmanager and my_secrets_dir are other words", "verify.yml", wordAsASubstring, 0},
		{"the linter configuration as it stands", "actionlint.yaml", linterConfigClean, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := forbiddenWordRefusals(c.file, c.text)
			if c.wantLine == 0 {
				if len(got) != 0 {
					t.Fatalf("the word check refused a file that carries no forbidden word:\n  %s", strings.Join(got, "\n  "))
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("the word check raised %d refusal(s):\n  %s\nwant exactly one, naming line %d", len(got), strings.Join(got, "\n  "), c.wantLine)
			}
			if want := fmt.Sprintf("%s:%d: ", c.file, c.wantLine); !strings.HasPrefix(got[0], want) {
				t.Errorf("the refusal is %q; want it to begin %q — a refusal that names no line is one a maintainer has to search for", got[0], want)
			}
			if !strings.Contains(got[0], "may not appear anywhere under .github/") {
				t.Errorf("the refusal is %q; want it to say the word may not appear anywhere under .github/, which is the whole rule", got[0])
			}
		})
	}

	// The word is a refusal of the WORKFLOW SCAN too, and that is what makes
	// a word in this repository's own workflow redden the rows that read
	// workflows rather than only the walk of the directory.
	t.Run("the workflow scan refuses the word and reads nothing else", func(t *testing.T) {
		for _, text := range []string{indexedByExpression, inheritSingleQuoted} {
			w := scanWorkflow("verify.yml", text)
			if len(w.refusals) == 0 {
				t.Fatalf("the scan raised no refusal for a workflow carrying the forbidden word")
			}
			if !strings.Contains(strings.Join(w.refusals, "\n"), "may not appear anywhere under .github/") {
				t.Errorf("the scan refused for another reason:\n  %s", strings.Join(w.refusals, "\n  "))
			}
			if len(w.triggers) != 0 || len(w.runners) != 0 || len(w.calls) != 0 {
				t.Errorf("the scan read %d trigger(s), %d runner(s) and %d call(s) out of a file it refused; a refused file is not a scanned file", len(w.triggers), len(w.runners), len(w.calls))
			}
		}
	})

	// The preservation control for the boundary, driven through the scan
	// rather than through the pattern: a workflow whose environment names
	// two other words is read, and read correctly.
	t.Run("a workflow carrying the word only inside other words is read", func(t *testing.T) {
		w := scanWorkflow("verify.yml", wordAsASubstring)
		if len(w.refusals) != 0 {
			t.Fatalf("the scan refused a workflow inside the subset:\n  %s", strings.Join(w.refusals, "\n  "))
		}
		if len(w.triggers) == 0 || len(w.runners) == 0 {
			t.Fatalf("the scan read %d trigger(s) and %d runner(s); this control would agree by seeing nothing", len(w.triggers), len(w.runners))
		}
	})
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
	// THE ROUND-2 ESCAPE, verbatim: a `runs-on:` whose block sequence sits at
	// the key's own column. Ordinary YAML that GitHub honours — a real parser
	// reads two labels out of it — and outside this reader's subset, so it is
	// refused rather than read as zero runners.
	const sameIndentRunsOn = `
name: verify
on:
  pull_request:
jobs:
  verify:
    runs-on:
    - self-hosted
    - dhcp-golib
    steps:
      - run: ./verify.sh
`
	// The same shape one level up: a sequence under `on:` at column 0.
	const sameIndentOn = `
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
	// The declared escape of round 2's finding 3, which used to be a BOUND: an
	// anchor elsewhere and an alias where the triggers belong. It parsed to
	// the junk token `*t`, which satisfied a floor that counts.
	const aliasedTriggers = `
name: verify
x-triggers: &t
  pull_request:
on: *t
jobs:
  verify:
    runs-on: [self-hosted, dhcp-golib]
    steps:
      - run: ./verify.sh
`
	const anchoredOn = `
name: verify
on: &t
  pull_request:
jobs:
  verify:
    runs-on: [self-hosted, dhcp-golib]
    steps:
      - run: ./verify.sh
`
	// An expression among the triggers, which is the shape where reading one
	// costs a verdict rather than a diagnostic: `push` is not a fork trigger
	// and the expression could expand to one that is.
	const expressionOn = `
name: verify
on: [push, "${{ env.EXTRA_TRIGGERS }}"]
jobs:
  verify:
    runs-on: [self-hosted, dhcp-golib]
    steps:
      - run: ./verify.sh
`
	// Round 2's finding 4(b): this used to be READ, as a label spelled
	// `${{ matrix.os`, and reported under that name.
	const expressionRunsOn = `
name: verify
on:
  pull_request:
jobs:
  verify:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-24.04]
    steps:
      - run: ./verify.sh
`
	const openFlowRunsOn = `
name: verify
on:
  pull_request:
jobs:
  verify:
    runs-on: [self-hosted,
              dhcp-golib]
    steps:
      - run: ./verify.sh
`
	const mappingRunsOn = `
name: verify
on:
  pull_request:
jobs:
  verify:
    runs-on:
      group: ours
      labels: [dhcp-golib]
    steps:
      - run: ./verify.sh
`
	const blockScalarRunsOn = `
name: verify
on:
  pull_request:
jobs:
  verify:
    runs-on: |
      self-hosted
    steps:
      - run: ./verify.sh
`
	const inlinedJob = `
name: verify
on:
  pull_request:
jobs:
  verify: *jobbody
`
	const jobLevelAction = `
name: verify
on:
  pull_request:
jobs:
  verify:
    uses: someone/somewhere@v1
`
	// Review round 3's finding 2, all three shapes, each valid YAML the r3
	// reviewer put through a real parser and each caught until now by the
	// FLOOR, which names no line and no shape. The whole point of the subset
	// design is that a stranger is told which line to rewrite.
	const indentedRoot = `
  name: verify
  on:
    pull_request:
  jobs:
    verify:
      runs-on: [self-hosted, dhcp-golib]
      steps:
        - run: ./verify.sh
`
	const spacedOnKey = `
name: verify
on :
  pull_request:
jobs:
  verify:
    runs-on: [self-hosted, dhcp-golib]
    steps:
      - run: ./verify.sh
`
	const spacedRunsOnKey = `
name: verify
on:
  pull_request:
jobs:
  verify:
    runs-on : [self-hosted, dhcp-golib]
    steps:
      - run: ./verify.sh
`
	cases := []struct {
		name        string
		text        string
		wantRefusal string
		wantFork    bool
		wantCalls   int
	}{
		{"self-hosted with a pull_request trigger", selfHostedPR, "", true, 0},
		{"a bare label with pull_request_target", barelabelPRTarget, "", true, 0},
		{"inline trigger list", inlineTriggers, "", true, 0},
		{"a four-space on: block", fourSpaceBlock, "", true, 0},
		{"a six-space sequence on: block", sixSpaceSequence, "", true, 0},
		{"a flow mapping on: block", flowMapping, "", true, 0},
		{"a hosted image is reachable and that is fine", hostedPR, "", false, 0},
		{"self-hosted with no fork trigger", selfHostedPush, "", false, 0},
		{"a key under a trigger is not a trigger", filteredPush, "", false, 0},
		{"a step uses: names an action, not a workflow", usesAnAction, "", false, 0},

		// One row per clause of the subset. Each expects a REFUSAL naming
		// the shape, never an absence: what these fixtures have in common is
		// that every one of them used to parse to nothing, or to a token
		// nobody wrote, and pass.
		{"a runs-on sequence at its key's own column", sameIndentRunsOn, "a `runs-on:` block outside the subset", false, 0},
		{"an on: sequence at column 0", sameIndentOn, "an `on:` block outside the subset", false, 0},
		{"an alias where the triggers belong", aliasedTriggers, "an `on:` value outside the subset: a YAML anchor or alias", false, 0},
		{"an anchor on the on: value", anchoredOn, "an `on:` value outside the subset: a YAML anchor or alias", false, 0},
		{"an expression as the on: value", expressionOn, "an `on:` value outside the subset: an expression", false, 0},
		{"an expression as the runs-on value", expressionRunsOn, "a `runs-on:` value outside the subset: an expression", false, 0},
		{"a flow sequence that does not close on its line", openFlowRunsOn, "a flow sequence that does not close on its line", false, 0},
		{"the runs-on mapping form", mappingRunsOn, "not a sequence entry", false, 0},
		{"a block scalar as the runs-on value", blockScalarRunsOn, "a block scalar", false, 0},
		{"a job key carrying a value", inlinedJob, "a job whose key carries a value", false, 0},
		{"a job-level uses: that is not a workflow file", jobLevelAction, "cannot resolve to a workflow file", false, 0},
		{"a CRLF file is refused whole", strings.ReplaceAll(selfHostedPush, "\n", "\r\n"), "a carriage return", false, 0},
		{"a tab in the indentation", strings.Replace(selfHostedPush, "    runs-on:", "\truns-on:", 1), "a tab in the indentation", false, 0},

		// Review round 3's finding 2: three shapes the floor used to catch
		// with no line named. Each row asserts the refusal TEXT, so a
		// mutant that reverts one to the floor dies here rather than
		// passing on the floor's redness.
		{"an indented root mapping", indentedRoot, "a first line at column 2; this reader reads root keys at the left margin only", false, 0},
		{"on : with a space before the colon", spacedOnKey, "a line at the left margin this reader cannot read as a root `key:`", false, 0},
		{"runs-on : with a space before the colon", spacedRunsOnKey, "a line at a job's key column this reader cannot read as a `key:`", false, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := scanWorkflow(c.name, c.text)
			got := strings.Join(w.refusals, "\n  ")
			if c.wantRefusal != "" {
				// The assertion is on the TEXT, not on redness. A case that
				// only asked for red would be satisfied by the floor, and
				// the floor catching a shape the reader misread is exactly
				// the arrangement round 2 shipped.
				if !strings.Contains(got, c.wantRefusal) {
					t.Fatalf("the scan refused:\n  %s\nwant a refusal naming %q; a shape outside the subset that is read as an absence is the defect this test exists for", got, c.wantRefusal)
				}
				return
			}
			if got != "" {
				t.Fatalf("the scan refused a fixture that is inside the subset:\n  %s", got)
			}
			if len(w.triggers) == 0 || (len(w.runners) == 0 && len(w.calls) == 0) {
				t.Fatalf("the scan read %d trigger(s), %d runner(s) and %d call(s) out of this fixture; it is agreeing by seeing nothing", len(w.triggers), len(w.runners), len(w.calls))
			}
			if _, _, _, got := w.forkReachableSelfHosted(); got != c.wantFork {
				t.Errorf("fork-reachable self-hosted = %t, want %t (triggers %v, runners %v)", got, c.wantFork, w.triggers, w.runners)
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
		if len(bad) == 0 {
			t.Fatalf("floorViolations named nothing; the file the scan read nothing out of is the one it exists to name")
		}
		for _, b := range bad {
			if !strings.HasPrefix(b, "opaque.yml:") {
				t.Errorf("floorViolations named %q; only opaque.yml was unread, and a floor that names the file beside it is a floor nobody can act on", b)
			}
		}
	})

	// The preservation control the whole subset rests on: this repository's
	// own lane is INSIDE it, unchanged. The tree tests below prove the same
	// thing on every run, since treeWorkflows fatals on any refusal; this
	// says it as its own verdict so that a failure names the reason.
	t.Run("the lane's own workflows are inside the subset", func(t *testing.T) {
		entries, err := os.ReadDir(workflowDir)
		if err != nil {
			t.Fatalf("reading %s: %v", workflowDir, err)
		}
		read := 0
		for _, e := range entries {
			n := e.Name()
			if e.IsDir() || (!strings.HasSuffix(n, ".yml") && !strings.HasSuffix(n, ".yaml")) {
				continue
			}
			b, err := os.ReadFile(filepath.Join(workflowDir, n))
			if err != nil {
				t.Fatalf("reading %s: %v", n, err)
			}
			w := scanWorkflow(n, string(b))
			if len(w.refusals) != 0 {
				t.Errorf("the scan refused this repository's own %s:\n  %s", n, strings.Join(w.refusals, "\n  "))
			}
			read++
		}
		if read == 0 {
			t.Fatalf("%s holds no workflow; this control would pass over an empty domain", workflowDir)
		}
	})
}

// setVerdict gives every reason a SET is red, in the order treeWorkflows takes
// them: what the reader REFUSED, then the floors, then the property. The same
// functions, so a case here and the tree cannot disagree about what red means.
//
// The forbidden word arrives through the refusals, because that is where it
// arrives in scanWorkflow: it is not a finding about a workflow, it is the
// reader declining to read one.
func setVerdict(ws []workflow) []string {
	out := refusalsOf(ws)
	out = append(out, floorViolations(ws)...)
	resolved, open := resolveWorkflowCalls(ws)
	return append(out, forkReachabilityFindings(resolved, open)...)
}

// TestTheWorkflowScanRefusesASetItCannotRead drives review round 2's two
// escapes VERBATIM, over the set the tree test takes its verdict over. Both
// were green: one shape the reader did not understand was read as zero
// runners, and one was read as no secret at all, and in both cases a second
// file in the set held the floor up.
//
// A single file cannot show either. What made them escapes is the
// composition — an unrelated `uses:` job satisfying a floor taken over the
// file, and a caller handing its secrets to a callee.
func TestTheWorkflowScanRefusesASetItCannotRead(t *testing.T) {
	// Escape one, from the round-2 record: `pull_request:`, a `lint` job whose
	// only key is a `uses:` edge, and a `verify` job whose `runs-on:` sequence
	// sits at its key's column. A real parser reads `[self-hosted,
	// dhcp-golib]` there; the reader read nothing, the `uses:` job satisfied
	// the file's floor, and the set was green.
	const escapingCaller = `
name: verify
on:
  pull_request:
jobs:
  lint:
    uses: ./.github/workflows/lane.yml
  verify:
    runs-on:
    - self-hosted
    - dhcp-golib
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
	t.Run("a same-indent runs-on with a uses: job beside it", func(t *testing.T) {
		set := []workflow{
			scanWorkflow("verify.yml", escapingCaller),
			scanWorkflow("lane.yml", hostedCallee),
		}
		red := strings.Join(setVerdict(set), "\n  ")
		if !strings.Contains(red, "verify.yml:9") || !strings.Contains(red, "a `runs-on:` block outside the subset") {
			t.Fatalf("the set's verdict is:\n  %s\nwant a refusal at verify.yml:9 naming the `runs-on:` block it could not enumerate", red)
		}
		// The isolation, and it is the point of the case: the floor is NOT
		// what makes this red. It was not what made it red in round 2 either
		// — the `uses:` job satisfied it, and the set passed.
		if bad := floorViolations(set); len(bad) != 0 {
			t.Errorf("the floor also fired: %v; this case must turn on the refusal, or a mutant that removes the refusal dies on the floor and the property goes untested", bad)
		}
	})

	// Escape two, from the round-2 record: the same two-file set, LF against
	// CRLF, with the line ending as the only variable moved. Under LF the
	// handover used to be seen and the set was red; under CRLF `$` never
	// matched, the scan reported no secret, and everything else in the file
	// still parsed. Round 4 removed the pattern that produced both verdicts:
	// the file carries the forbidden word, so the reader refuses it and never
	// reaches the question the line ending could change the answer to.
	const inheritingCaller = `
name: caller
on:
  push:
jobs:
  call:
    uses: ./.github/workflows/lane.yml
    secrets: inherit
`
	t.Run("the forbidden word in a caller is refused under LF", func(t *testing.T) {
		set := []workflow{
			scanWorkflow("caller.yml", inheritingCaller),
			scanWorkflow("lane.yml", hostedCallee),
		}
		red := strings.Join(setVerdict(set), "\n  ")
		if !strings.Contains(red, "caller.yml:8") || !strings.Contains(red, "may not appear anywhere under .github/") {
			t.Fatalf("the set's verdict is:\n  %s\nwant a refusal at caller.yml:8 naming the forbidden word; this is the control the CRLF case is measured against", red)
		}
	})

	t.Run("the forbidden word under CRLF is refused too, for the line ending", func(t *testing.T) {
		set := []workflow{
			scanWorkflow("caller.yml", strings.ReplaceAll(inheritingCaller, "\n", "\r\n")),
			scanWorkflow("lane.yml", hostedCallee),
		}
		red := strings.Join(setVerdict(set), "\n  ")
		if !strings.Contains(red, "caller.yml:1") || !strings.Contains(red, "a carriage return") {
			t.Fatalf("the set's verdict is:\n  %s\nwant a refusal naming the carriage return; a CRLF file read as holding no secret is the round-2 defect, and the carriage return is refused before the word is looked for", red)
		}
	})

	// The floor's own escape, one level down from where round 2 left it: a job
	// the reader READ correctly and that yields nothing, beside a `uses:` job.
	// Taken per file the disjunction is false — the file has a call — and the
	// job that runs somewhere unknown is invisible.
	t.Run("a job that yields neither a runner nor a callee is named beside one that does", func(t *testing.T) {
		const twoJobs = `
name: verify
on:
  pull_request:
jobs:
  lint:
    uses: ./.github/workflows/lane.yml
  verify:
    steps:
      - run: ./verify.sh
`
		set := []workflow{
			scanWorkflow("verify.yml", twoJobs),
			scanWorkflow("lane.yml", hostedCallee),
		}
		if r := refusalsOf(set); len(r) != 0 {
			t.Fatalf("this fixture does not reproduce the shape: the reader refused it rather than reading it: %v", r)
		}
		if len(set[0].calls) == 0 || len(set[0].triggers) == 0 {
			t.Fatalf("this fixture does not reproduce the shape: a per-FILE floor would already refuse it (%d call(s), %d trigger(s))", len(set[0].calls), len(set[0].triggers))
		}
		bad := floorViolations(set)
		found := false
		for _, b := range bad {
			if strings.Contains(b, "job verify yields no runs-on label") {
				found = true
			}
		}
		if !found {
			t.Fatalf("the floor named %v; want the job that yields neither, named on its own line — a floor taken over the file is satisfied by the lint job's call", bad)
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
