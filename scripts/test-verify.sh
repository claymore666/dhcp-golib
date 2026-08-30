#!/usr/bin/env bash
#
# test-verify.sh — the oracle for verify.sh.
#
# Nothing but this script ever asks whether verify.sh still detects anything.
# Each scenario copies the tree, plants ONE defect, runs the copy's
# `./verify.sh --inner`, and asserts both that the run failed AND that the row
# which failed is the row that owns the defect — a run that fails for the wrong
# reason looks exactly like one that fails for the right reason.
#
# Usage:  scripts/test-verify.sh              run every scenario
#         scripts/test-verify.sh --scenario N run one (used by the parallel driver)
# Exit:   0 = every scenario behaved, 1 = at least one did not,
#         2 = REFUSED, the oracle could not measure its own domain.

set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"

JOBS="${ORACLE_JOBS:-4}"

# ------------------------------------------------------------------ helpers --

refuse() {
	printf 'ORACLE REFUSED: %s\n' "$*" >&2
	exit 2
}

# The scenarios are declared in verify.manifest.sh, not here.
#
# ROUND 9. They used to be a SCENARIOS array in this file, cross-checked
# against the sc_* functions in this file — an expectation and its subject in
# one place, which is the defect the whole round is about. MEASURED 2026-08-30
# by review: deleting a name and its function together was consistent, silent
# and left verify.sh green.
#
# JOBS stays here: it is a knob, not an expectation.
MANIFEST="$ROOT/verify.manifest.sh"
[ -r "$MANIFEST" ] || refuse "$MANIFEST is missing or unreadable; the oracle has no statement of what it must run"
# shellcheck source=verify.manifest.sh
. "$MANIFEST"
manifest_problem="$(manifest_check)" || refuse "$manifest_problem"
SCENARIOS=("${MANIFEST_SCENARIOS[@]}")

# copy_tree DEST — the subject, minus .git and minus the toolchain's caches.
copy_tree() {
	mkdir -p "$1"
	tar -cf - -C "$ROOT" --exclude=./.git . | tar -xf - -C "$1"
	[ -x "$1/verify.sh" ] || refuse "the copy has no executable verify.sh"
}

# edit FILE FROM TO — an edit that MUST change something. A mutation that fails
# to apply leaves a pristine copy, and a pristine copy passes.
edit() {
	local f="$1" from="$2" to="$3" before
	before="$(cat "$f")"
	python3 - "$f" "$from" "$to" <<-'PY'
		import sys
		p, a, b = sys.argv[1], sys.argv[2], sys.argv[3]
		s = open(p).read()
		if a not in s:
		    sys.exit(3)
		open(p, "w").write(s.replace(a, b, 1))
	PY
	[ "$before" != "$(cat "$f")" ] || refuse "planted edit did not change $f"
}

# run_verify DIR — sets RC and OUT. Uses --inner, so the copy does not run
# this script again.
run_verify() {
	RC=0
	OUT="$(cd "$1" && ./verify.sh --inner 2>&1)" || RC=$?
}

# run_verify_outer DIR — the copy's verify.sh with NO flag, i.e. the invocation
# a person types. Only safe when the copy's scripts/test-verify.sh has been
# replaced by a stub; otherwise this recurses without bound.
run_verify_outer() {
	RC=0
	OUT="$(cd "$1" && ./verify.sh 2>&1)" || RC=$?
}

# table — the step rows of $OUT and nothing else. Diagnostics go to stderr and
# are merged into OUT, so matching a step name anywhere in the output would let
# a diagnostic line satisfy an assertion about a row.
table() {
	printf '%s\n' "$OUT" | awk '
		/^----[ ]+------/ { in_table = 1; next }
		in_table && NF == 0 { exit }
		in_table { print }
	'
}

# row NAME — PASS, FAIL, or ABSENT. ABSENT is distinct on purpose: a step that
# stopped existing is the quietest way for a verifier to stop checking.
row() {
	table | awk -v n="$1" '$1 == n { print $2; found = 1 } END { if (!found) print "ABSENT" }'
}

# why NAME — the detail column of a row.
#
# MEASURED 2026-08-30: a preservation control fired inside a full oracle run
# and reported "the plant broke the suite: FAIL" and nothing else, so
# diagnosing it needed a second 2m42s run. A control that says only THAT it
# fired is the same defect as a count with no file:line.
why() {
	table | awk -v n="$1" '$1 == n { $1 = ""; $2 = ""; sub(/^[ \t]+/, ""); print; found = 1 } END { if (!found) print "(row absent)" }'
}

FAILS=()
note() { FAILS+=("$*"); }

# ---------------------------------------------------------------- scenarios --
#
# Each scenario prints exactly one line: RESULT <name> <PASS|FAIL> <detail>.

sc_control() {
	local d="$1"
	copy_tree "$d"
	run_verify "$d"
	[ "$RC" -eq 0 ] || note "an unmutated copy did not pass: exit $RC"
	printf '%s\n' "$OUT" | grep -q '^VERDICT: PASS' || note "no PASS verdict on a clean copy"
	# The copy must NOT have run this script again: if --inner did not take,
	# every scenario below is measuring a doubly-nested run of unknown depth.
	[ "$(row verify-oracle)" = ABSENT ] || note "--inner did not suppress the oracle; the run recursed"
}

sc_verdict_on_abort() {
	local d="$1"
	copy_tree "$d"
	# A hard abort under `set -e`, planted at a point every run reaches: the
	# promise is "any abort still prints a verdict", not "this abort does".
	edit "$d/verify.sh" '# -------------------------------------------------------------- gate roster --' \
		'oracle_planted_command_that_does_not_exist'
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "an aborted verifier exited 0"
	printf '%s\n' "$OUT" | grep -q '^VERDICT: FAIL' ||
		note "an aborted verifier printed no FAIL verdict (this is the defect the EXIT trap exists for)"
	printf '%s\n' "$OUT" | grep -q 'aborted before reaching its verdict' ||
		note "the abort verdict does not say it aborted"
}

sc_verdict_without_gomod() {
	local d="$1"
	copy_tree "$d"
	rm -f "$d/go.mod"
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "a tree with no go.mod passed"
	# MEASURED 2026-08-28 by review: this route used to exit 1 printing no
	# verdict line at all.
	printf '%s\n' "$OUT" | grep -q '^VERDICT: FAIL' || note "no FAIL verdict with go.mod deleted"
	[ "$(row gate-roster)" = FAIL ] || note "gate-roster did not report the unmeasurable roster: $(row gate-roster)"
}

sc_roster_gate_deleted() {
	local d="$1"
	copy_tree "$d"
	rm -rf "$d/internal/gates/t2"
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "deleting a required gate passed"
	[ "$(row gate-roster)" = FAIL ] || note "gate-roster missed a deleted gate: $(row gate-roster)"
}

sc_roster_gate_added() {
	local d="$1"
	copy_tree "$d"
	mkdir -p "$d/internal/gates/t3"
	printf 'package main\n\nfunc main() {}\n' >"$d/internal/gates/t3/main.go"
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "a gate present in the tree but absent from REQUIRED_GATES passed"
	[ "$(row gate-roster)" = FAIL ] || note "gate-roster missed an unlisted gate: $(row gate-roster)"
}

sc_t1_violation() {
	local d="$1"
	copy_tree "$d"
	printf 'package proto\n\nimport "os"\n\nvar Stderr = os.Stderr\n' >"$d/proto/impure.go"
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "ring 1 importing os passed"
	[ "$(row t1)" = FAIL ] || note "t1 did not report an impure ring-1 import: $(row t1)"
	[ "$(row gofmt)" = PASS ] || note "the planted impure file is unformatted; this run failed for a reason this scenario does not name"
}

sc_t2_violation() {
	local d="$1"
	copy_tree "$d"
	cat >"$d/proto/wait_test.go" <<'GO'
package proto

import (
	"testing"
	"time"
)

func TestWaits(t *testing.T) {
	time.Sleep(time.Millisecond)
}
GO
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "a test calling time.Sleep passed"
	[ "$(row t2)" = FAIL ] || note "t2 did not report a clock wait: $(row t2)"
	[ "$(row gofmt)" = PASS ] || note "the planted test file is unformatted; this run failed for a reason this scenario does not name"
}

sc_gofmt_violation() {
	local d="$1"
	copy_tree "$d"
	printf 'package proto\n\n\n\nvar   Misformatted   =   1\n' >"$d/proto/ugly.go"
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "an unformatted file passed"
	[ "$(row gofmt)" = FAIL ] || note "gofmt did not report an unformatted file: $(row gofmt)"
}

sc_vet_violation() {
	# MEASURED 2026-08-29: deleting `step "vet" go vet ./...` from verify.sh
	# left this oracle passing 18 of 18 — vet was the one step no scenario
	# drove, and a step nothing drives can be deleted silently.
	#
	# The bait is unreachable code because of attribution, not convenience: it
	# is in `go vet`'s suite but NOT in the subset `go test` runs by default
	# (atomic, bool, buildtags, directive, errorsas, ifaceassert, nilfunc,
	# printf, stringintconv, tests), so it reddens the vet row and leaves
	# unit-suite alone, which the rows below assert.
	local d="$1"
	copy_tree "$d"
	printf 'package proto\n\nfunc vetBait() int {\n\treturn 0\n\treturn 1\n}\n' >"$d/proto/vetbait.go"
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "unreachable code passed the verifier"
	[ "$(row vet)" = FAIL ] || note "vet did not report unreachable code: $(row vet)"
	[ "$(row build)" = PASS ] || note "the vet bait broke the build; it is not a vet-only defect: $(row build)"
	[ "$(row gofmt)" = PASS ] || note "the vet bait is unformatted; it is not a vet-only defect: $(row gofmt)"
	[ "$(row unit-suite)" = PASS ] || note "the vet bait reddened the unit suite; go test's own vet subset saw it: $(row unit-suite) — $(why unit-suite)"
}

sc_race_detector() {
	local d="$1"
	copy_tree "$d"
	# Without -race on the `go test` line this test passes: two goroutines
	# racing on an int is not a failure, it is a race.
	cat >"$d/proto/race_test.go" <<'GO'
package proto

import (
	"sync"
	"testing"
)

func TestConcurrentIncrement(t *testing.T) {
	n := 0
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n++
		}()
	}
	wg.Wait()
	if n < 1 {
		t.Fatal("no increment happened")
	}
}
GO
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "a data race passed; -race is not in force"
	[ "$(row unit-suite)" = FAIL ] || note "unit-suite did not report the race: $(row unit-suite) — $(why unit-suite)"
	[ "$(row gofmt)" = PASS ] || note "the planted race test is unformatted; this run failed for a reason this scenario does not name"
	[ "$(row t2)" = PASS ] || note "the planted race test tripped T2; this run failed for a reason this scenario does not name"
}

sc_test_cache() {
	local d="$1"
	copy_tree "$d"
	# Removing -count=1 lets the SECOND run be served from the test cache. The
	# first run must still pass, or the second run's failure could be anything.
	edit "$d/verify.sh" 'SUITE_ARGS=(-race -count=1 -timeout' 'SUITE_ARGS=(-race -timeout'
	run_verify "$d"
	[ "$RC" -eq 0 ] || note "the first run of the -count=1-less copy did not pass: exit $RC"
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "a cached suite result passed; nothing observes -count=1"
	[ "$(row unit-suite)" = FAIL ] || note "unit-suite did not report the cached result: $(row unit-suite) — $(why unit-suite)"
	printf '%s\n' "$OUT" | grep -q 'cached' || note "the cached-result failure does not say it was cached"
}

# ceiling_tree DEST — a copy whose suite genuinely takes a few seconds.
#
# A busy loop and not time.Sleep: T2 would refuse the sleep, and the row under
# test here is unit-suite. It is also the shape docs/gates.md names as beyond
# T2's reach, so this doubles as a live demonstration of that bound.
ceiling_tree() {
	copy_tree "$1"
	cat >"$1/proto/slow_test.go" <<'GO'
package proto

import (
	"testing"
	"time"
)

func TestBusyLoop(t *testing.T) {
	start := time.Now()
	for time.Since(start) < 3*time.Second {
	}
}
GO
}

sc_ceiling_fires() {
	local d="$1"
	ceiling_tree "$d"
	edit "$d/verify.sh" 'SUITE_CEILING_SECONDS=60' 'SUITE_CEILING_SECONDS=1'
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "a suite over the ceiling passed"
	[ "$(row unit-suite)" = FAIL ] || note "unit-suite did not report the ceiling: $(row unit-suite) — $(why unit-suite)"
	printf '%s\n' "$OUT" | grep -q 'ceiling' || note "the over-ceiling failure does not name the ceiling"
	[ "$(row t2)" = PASS ] || note "the busy loop tripped T2; the ceiling is not what failed this run"
}

sc_ceiling_control() {
	# The preservation control for the scenario above: the SAME slow test under
	# the SAME copy, with the ceiling where it ships, must PASS. Without it the
	# scenario above proves only that a busy loop breaks something.
	local d="$1"
	ceiling_tree "$d"
	run_verify "$d"
	[ "$RC" -eq 0 ] || note "a 3s suite failed under the shipped ceiling: exit $RC — the ceiling scenario is measuring something else"
	[ "$(row unit-suite)" = PASS ] || note "unit-suite did not pass a 3s suite: $(row unit-suite) — $(why unit-suite)"
}

sc_hang_bounded() {
	# A test that never returns cannot be caught by the wall-clock ceiling,
	# which is computed after `go test` returns — so without -timeout this
	# scenario would hang the oracle. The hang is a receive on a channel with
	# no sender: no time or context identifier, so T2 cannot see it either,
	# which the last row asserts.
	local d="$1"
	copy_tree "$d"
	cat >"$d/proto/hang_test.go" <<'GO'
package proto

import "testing"

func TestHangs(t *testing.T) {
	<-make(chan struct{})
}
GO
	# Only ONE variable moves: the ceiling stays where it ships, so a ceiling
	# failure cannot be what this scenario measures.
	edit "$d/verify.sh" 'SUITE_TIMEOUT_SECONDS=180' 'SUITE_TIMEOUT_SECONDS=15'
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "a suite containing a test that never returns passed"
	[ "$(row unit-suite)" = FAIL ] || note "unit-suite did not report the hang: $(row unit-suite) — $(why unit-suite)"
	printf '%s
' "$OUT" | grep -q 'test timed out' || note "the failure does not name the timeout; something else failed this run"
	[ "$(row t2)" = PASS ] || note "the planted hang tripped T2; the timeout is not what failed this run"
}

sc_bounds_ordering() {
	# Only the timeout moves, and it moves BELOW the shipped ceiling, so a
	# ceiling failure cannot be what this scenario measures.
	local d="$1"
	copy_tree "$d"
	edit "$d/verify.sh" 'SUITE_TIMEOUT_SECONDS=180' 'SUITE_TIMEOUT_SECONDS=30'
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "a hang timeout below the ceiling passed"
	[ "$(row bounds)" = FAIL ] || note "the bounds step did not catch it: $(row bounds)"
	[ "$(row unit-suite)" = PASS ] || note "the suite itself failed; this run failed for a reason this scenario does not name: $(row unit-suite) — $(why unit-suite)"
}

sc_stale_citation() {
	# A comment pointing at a test that does not exist. The plant is INDENTED
	# on purpose: a column-0 plant is satisfied by a gate that only looks at
	# column 0, and the fixture would then select the passing path. Narrowing
	# the gate's comment match to /^\/\// must kill this scenario.
	local d="$1"
	copy_tree "$d"
	edit "$d/proto/state.go" '	switch s {' '	switch s {
	// See TestThisCitationWasNeverWritten.'
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "a comment citing a test that does not exist passed"
	[ "$(row citations)" = FAIL ] || note "citations did not report the stale pointer: $(row citations)"
	[ "$(row gofmt)" = PASS ] || note "the planted comment is unformatted; this run failed for a reason this scenario does not name"
	[ "$(row unit-suite)" = PASS ] || note "the planted comment broke the suite: $(row unit-suite) — $(why unit-suite)"
}

sc_citation_trailing() {
	# A citation in a TRAILING comment. The first version of this gate matched
	# only lines that BEGIN with //, so this shape passed and two documents
	# said otherwise.
	local d="$1"
	copy_tree "$d"
	edit "$d/proto/state.go" '		return "BOUND"' '		return "BOUND" // See TestTrailingCitationNeverWritten.'
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "a trailing-comment citation of a test that does not exist passed"
	[ "$(row citations)" = FAIL ] || note "citations did not see the trailing comment: $(row citations)"
	[ "$(row gofmt)" = PASS ] || note "the plant is unformatted; this run failed for a reason this scenario does not name"
	[ "$(row unit-suite)" = PASS ] || note "the plant broke the suite: $(row unit-suite) — $(why unit-suite)"
}

sc_citation_underscore() {
	# Test_lowercase and Benchmark names. The first token pattern was
	# Test[A-Z], which saw neither — two spellings enumerated means a third
	# exists, and there were two more.
	local d="$1"
	copy_tree "$d"
	edit "$d/proto/state.go" '	switch s {' '	switch s {
	// See Test_neverWrittenAtAll and BenchmarkNeverWrittenEither.'
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "citations of a Test_ and a Benchmark that do not exist passed"
	[ "$(row citations)" = FAIL ] || note "citations did not see the underscore/Benchmark names: $(row citations)"
	[ "$(row gofmt)" = PASS ] || note "the plant is unformatted; this run failed for a reason this scenario does not name"
	printf '%s\n' "$OUT" | grep -q 'Test_neverWrittenAtAll' || note "the diagnosis does not name the Test_ token"
	printf '%s\n' "$OUT" | grep -q 'BenchmarkNeverWrittenEither' || note "the diagnosis does not name the Benchmark token"
	[ "$(row unit-suite)" = PASS ] || note "the plant broke the suite: $(row unit-suite) — $(why unit-suite)"
}

sc_citation_whitewash() {
	# A genuinely stale citation, plus the SAME token inside a Go string
	# literal in the same file. Under the first rule any occurrence on a
	# non-comment line counted as "exists", so one string literal anywhere in
	# the tree silenced every citation of that name. "Exists" is now "a line
	# DECLARES it", and a string literal declares nothing.
	local d="$1"
	copy_tree "$d"
	edit "$d/proto/state.go" 'import "fmt"' 'import "fmt"

// See TestWhitewashedByAStringLiteral.
var whitewashProbe = "TestWhitewashedByAStringLiteral"'
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "a stale citation was whitewashed by a string literal in the same file"
	[ "$(row citations)" = FAIL ] || note "citations was whitewashed: $(row citations)"
	[ "$(row gofmt)" = PASS ] || note "the plant is unformatted; this run failed for a reason this scenario does not name"
	printf '%s\n' "$OUT" | grep -q 'TestWhitewashedByAStringLiteral' || note "the diagnosis does not name the whitewashed token"
	[ "$(row unit-suite)" = PASS ] || note "the plant broke the suite: $(row unit-suite) — $(why unit-suite)"
}

sc_citation_vacuous() {
	# The citations row must not report PASS having measured nothing. The
	# token pattern is neutered so both sides of the comparison come back
	# empty; comm then reports no missing token, which is exactly the shape a
	# universal claim over an empty domain takes.
	local d="$1"
	copy_tree "$d"
	edit "$d/verify.sh" '(Test|Benchmark|Fuzz|Example)[_A-Z][A-Za-z0-9_]*/)) {' '(ZzNeverMatchesAnything)[_A-Z][A-Za-z0-9_]*/)) {'
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "a citations scan that found no domain at all passed"
	[ "$(row citations)" = FAIL ] || note "an empty citation domain did not fail the row: $(row citations)"
	printf '%s\n' "$OUT" | grep -q 'measured nothing' || note "the diagnosis does not say the scan measured nothing"
	[ "$(row unit-suite)" = PASS ] || note "the plant broke the suite: $(row unit-suite) — $(why unit-suite)"
}

sc_suite_timeout_detached() {
	# The bounds step used to compare two constants declared a hundred lines
	# above the go test line and call that a check on the invocation. This
	# hardcodes a timeout into the flags the suite runs with, leaving the
	# compared constant bound to nothing. MEASURED before the fix: this
	# survived both bounds-ordering and hang-bounded.
	local d="$1"
	copy_tree "$d"
	edit "$d/verify.sh" '-timeout "${SUITE_TIMEOUT_SECONDS}s")' '-timeout 90s)'
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "a suite whose timeout is detached from the checked constant passed"
	[ "$(row bounds)" = FAIL ] || note "bounds did not see the detached timeout: $(row bounds)"
	[ "$(row unit-suite)" = PASS ] || note "the suite itself failed; this run failed for a reason this scenario does not name: $(row unit-suite) — $(why unit-suite)"
}

sc_invoked_by_relative_path() {
	# PRESERVATION control. The bounds step reads verify.sh's own source, and
	# the obvious way to name that file — "$0" — is the path the CALLER typed,
	# which stops resolving the moment the script cd's to its own directory.
	# MEASURED 2026-08-30 before the fix: `library/verify.sh` run from the
	# parent recorded "bounds FAIL ... is not readable", on an untouched tree.
	#
	# Every other scenario invokes the copy as ./verify.sh from inside it, so
	# no other scenario can reach this.
	local d="$1" parent base
	copy_tree "$d"
	parent="$(dirname "$d")"
	base="$(basename "$d")"
	RC=0
	OUT="$(cd "$parent" && "$base/verify.sh" --inner 2>&1)" || RC=$?
	[ "$RC" -eq 0 ] || note "an untouched copy failed when invoked by a relative path from its parent: $OUT"
	[ "$(row bounds)" = PASS ] || note "bounds could not read its own source under a relative invocation: $(row bounds)"
}

sc_citation_url() {
	# PRESERVATION control, and the only scenario here that asserts a GREEN
	# run. A URL in an ordinary string literal is not a citation: taking
	# everything after the first "//" read the tail of an https:// literal as a
	# comment and failed the run over a token nobody wrote down. MEASURED
	# 2026-08-30 against the pre-fix scanner, which reported
	# "cited but never declared: TestRevCPhantomFromAURL".
	#
	# A one-directional drive would prove nothing here: the risk in the fix is
	# that it blinds the gate, which is what citation-after-url covers.
	local d="$1"
	copy_tree "$d"
	edit "$d/proto/state.go" 'import "fmt"' 'import "fmt"

var probeDocURL = "https://example.invalid/docs/TestRevCPhantomFromAURL"'
	run_verify "$d"
	[ "$RC" -eq 0 ] || note "a URL in a string literal failed the run: $OUT"
	[ "$(row citations)" = PASS ] || note "citations read a URL path segment as a citation: $(row citations)"
}

sc_citation_after_url() {
	# The other direction of the same fix. A REAL stale citation, in a real
	# comment, on a line that also holds a URL — the shape that a naive "skip
	# lines containing ://" would go blind to.
	local d="$1"
	copy_tree "$d"
	edit "$d/proto/state.go" 'import "fmt"' 'import "fmt"

var probeDocURL2 = "https://example.invalid/x" // See TestRevCPhantomAfterAURL.'
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "a stale citation following a URL on the same line passed"
	[ "$(row citations)" = FAIL ] || note "citations went blind to the comment after a URL: $(row citations)"
	printf '%s\n' "$OUT" | grep -q 'TestRevCPhantomAfterAURL' || note "the diagnosis does not name the token after the URL"
	[ "$(row gofmt)" = PASS ] || note "the plant is unformatted; this run failed for a reason this scenario does not name"
}

sc_suite_args_detached() {
	# The escape suite-timeout-detached could not reach: an invocation that
	# stops expanding SUITE_ARGS altogether. It is WIDER than a detached
	# timeout, because it takes -count=1 with it as well, so the cached-result
	# check goes with it. MEASURED before the fix: every row stayed green and
	# bounds printed that the suite runs with the checked flags.
	local d="$1"
	copy_tree "$d"
	edit "$d/verify.sh" 'go test "${SUITE_ARGS[@]}" ./...' 'go test -race -count=1 -timeout 300s ./...'
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "a suite invocation that stops reading SUITE_ARGS passed"
	[ "$(row bounds)" = FAIL ] || note "bounds did not see the detached invocation: $(row bounds)"
	printf '%s\n' "$OUT" | grep -q 'expanding SUITE_ARGS' || note "the diagnosis does not name the missing expansion"
}

# disable_tests DIR GLOB — add `ignore` to the build constraint of each
# matching test file, leaving the tree gofmt-clean. Files that already carry a
# //go:build line get it extended rather than a second line, which would be a
# gofmt failure and would attribute the run to the wrong row.
disable_tests() {
	local d="$1" glob="$2" f n=0
	while IFS= read -r f; do
		if head -1 "$f" | grep -q '^//go:build'; then
			sed -i '1s|$| \&\& ignore|' "$f"
		else
			printf '//go:build ignore\n\n' | cat - "$f" >"$f.t" && mv "$f.t" "$f"
		fi
		n=$((n + 1))
	done < <(find "$d" -path "$glob" -name '*_test.go')
	[ "$n" -gt 0 ] || refuse "disable_tests matched no file under $glob"
}

sc_suite_tests_disabled() {
	# The whole library's tests switched off. MEASURED 2026-08-30 before the
	# domain check: `go test ./...` exits 0 on a tree with no test files, so
	# this produced "VERDICT: PASS (10 steps)" with zero tests executed. t2
	# still counted 22 files, because it walks the filesystem; the ceiling
	# still passed, because it reads absent as fast.
	local d="$1"
	copy_tree "$d"
	disable_tests "$d" '*'
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "a tree in which no test can run passed"
	[ "$(row unit-suite)" = FAIL ] || note "unit-suite passed over a suite that ran nothing: $(row unit-suite) — $(why unit-suite)"
	[ "$(row gofmt)" = PASS ] || note "the plant is unformatted; this run failed for a reason this scenario does not name"
	[ "$(row t2)" = PASS ] || note "t2 changed verdict; this scenario is then not measuring unit-suite alone: $(row t2)"
}

sc_suite_one_package_disabled() {
	# The partial case, and the reason the check is keyed on the population
	# rather than on a test-count floor: one package's tests switched off
	# leaves the other eight running, so any global floor still passes.
	local d="$1"
	copy_tree "$d"
	disable_tests "$d" '*/wire/*'
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "one package's tests were switched off and the run passed"
	[ "$(row unit-suite)" = FAIL ] || note "unit-suite passed with a package's tests disabled: $(row unit-suite) — $(why unit-suite)"
	printf '%s\n' "$OUT" | grep -q 'dhcplease/wire' || note "the diagnosis does not name the package that ran no test"
	[ "$(row gofmt)" = PASS ] || note "the plant is unformatted; this run failed for a reason this scenario does not name"
}

sc_suite_domain_unmeasured_module() {
	# The unit-suite domain check compares import paths built from `go list -m`.
	# If that returns nothing the paths are wrong, no package matches, and the
	# comparison reports no problem having compared nothing — the same shape as
	# citation-vacuous. It must refuse instead.
	local d="$1"
	copy_tree "$d"
	edit "$d/verify.sh" 'module="$(go list -m 2>/dev/null || true)"' 'module="$(false 2>/dev/null || true)"'
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "unit-suite passed with its domain built from an empty module path"
	[ "$(row unit-suite)" = FAIL ] || note "an unmeasurable domain did not fail the row: $(row unit-suite) — $(why unit-suite)"
	printf '%s\n' "$OUT" | grep -q 'UNMEASURED' || note "the diagnosis does not say the domain was unmeasured"
}

sc_suite_domain_unmeasured_walk() {
	# The other half of the same refusal: the walk that finds the packages
	# holding tests. An empty walk is an empty universal.
	local d="$1"
	copy_tree "$d"
	edit "$d/verify.sh" "find . -name '*_test.go' -not -path './.git/*' -printf '%h\\n'" "find . -name 'zz_no_such_file' -not -path './.git/*' -printf '%h\\n'"
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "unit-suite passed with no package in its domain at all"
	[ "$(row unit-suite)" = FAIL ] || note "an empty domain walk did not fail the row: $(row unit-suite) — $(why unit-suite)"
	printf '%s\n' "$OUT" | grep -q 'UNMEASURED' || note "the diagnosis does not say the domain was unmeasured"
}

sc_suite_files_disabled_partial() {
	# B8, exactly as measured by review at 86cb3c5: disable ten of the
	# twenty-two test files, chosen so every package keeps at least one. The
	# package-keyed check sees nine ok lines and passes; 62% of the suite is
	# gone. The declared-function population is what sees it.
	local d="$1" f
	copy_tree "$d"
	for f in runtime/ipudp_test.go runtime/platform_parity_test.go \
		runtime/prose_test.go runtime/ring_test.go runtime/timers_test.go \
		proto/machine_test.go proto/lease_test.go proto/journal_test.go \
		lease/manager_test.go lease/fault_test.go; do
		[ -f "$d/$f" ] || refuse "the plant names $f, which this tree does not have"
	done
	disable_tests "$d" '*/runtime/ipudp_test.go'
	disable_tests "$d" '*/runtime/platform_parity_test.go'
	disable_tests "$d" '*/runtime/prose_test.go'
	disable_tests "$d" '*/runtime/ring_test.go'
	disable_tests "$d" '*/runtime/timers_test.go'
	disable_tests "$d" '*/proto/machine_test.go'
	disable_tests "$d" '*/proto/lease_test.go'
	disable_tests "$d" '*/proto/journal_test.go'
	disable_tests "$d" '*/lease/manager_test.go'
	disable_tests "$d" '*/lease/fault_test.go'
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "ten test files were switched off, every package kept one, and the run passed"
	[ "$(row unit-suite)" = FAIL ] || note "unit-suite passed with most of the suite disabled: $(row unit-suite) — $(why unit-suite)"
	printf '%s\n' "$OUT" | grep -q 'declared but never run' || note "the diagnosis does not name the declared tests that did not run"
	[ "$(row gofmt)" = PASS ] || note "the plant is unformatted; this run failed for a reason this scenario does not name"
}

sc_suite_roster_unmeasured() {
	# The declared-test walk is the instrument the row's verdict now rests on.
	# If it cannot run, the comparison is between an empty set and everything,
	# which is vacuously satisfied. It must refuse.
	local d="$1"
	copy_tree "$d"
	edit "$d/verify.sh" 'go run ./internal/tools/testroster "$ROOT"' 'go run ./internal/tools/no_such_tool "$ROOT"'
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "unit-suite passed with its declared-test roster unmeasurable"
	[ "$(row unit-suite)" = FAIL ] || note "an unmeasurable roster did not fail the row: $(row unit-suite) — $(why unit-suite)"
	printf '%s\n' "$OUT" | grep -q 'UNMEASURED' || note "the diagnosis does not say the roster was unmeasured"
}

sc_record_refuses_uncounted_pass() {
	# The round-7 choke point, driven directly: a row that records PASS without
	# saying how many things it examined must not pass. gofmt is the subject
	# because its PASS is the one that carried no evidence at all before this.
	local d="$1"
	copy_tree "$d"
	edit "$d/verify.sh" 'record "gofmt" PASS "all $go_files_n .go file(s) formatted" "$go_files_n"' 'record "gofmt" PASS "all files formatted"'
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "a row recorded PASS with no domain size and the run passed"
	[ "$(row gofmt)" = FAIL ] || note "an uncounted PASS was not rewritten to FAIL: $(row gofmt)"
	printf '%s\n' "$OUT" | grep -q 'no numeric domain size' || note "the diagnosis does not name the missing count"
}

sc_record_refuses_zero_count() {
	# The other half of the same guard, and the one that matters when a row's
	# derivation is honest but its domain is empty.
	local d="$1"
	copy_tree "$d"
	edit "$d/verify.sh" "go_files_n=\"\$(find . -name '*.go' -not -path './.git/*' -printf 'x\\n' | grep -c . || true)\"" 'go_files_n=0'
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "a row recorded PASS having examined zero items and the run passed"
	[ "$(row gofmt)" = FAIL ] || note "a zero-domain PASS was not rewritten to FAIL: $(row gofmt)"
	printf '%s\n' "$OUT" | grep -q 'examined 0 items' || note "the diagnosis does not say the domain was empty"
}

sc_row_deleted() {
	# The third instance of the round's class, MEASURED 2026-08-30 before the
	# fix: the verdict printed the number of rows and checked it against
	# nothing, so deleting a step call produced "VERDICT: PASS (10 steps)".
	local d="$1"
	copy_tree "$d"
	edit "$d/verify.sh" 'step "vet" "$go_pkgs_n" go vet ./...' 'true # row deleted'
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "a deleted row left the run passing"
	[ "$(row vet)" = ABSENT ] || note "this scenario is not measuring a deleted row: vet is $(row vet)"
	printf '%s\n' "$OUT" | grep -q 'the rows recorded are not the rows required' || note "the verdict does not name the roster mismatch"
}

sc_row_added() {
	# The other direction. A row nobody declared is as much a roster failure as
	# a missing one — it is how a check gets renamed into invisibility.
	local d="$1"
	copy_tree "$d"
	edit "$d/verify.sh" 'step "build" "$go_pkgs_n" go build ./...' 'step "build" "$go_pkgs_n" go build ./...
record "undeclared-row" PASS "invented" 1'
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "an undeclared row left the run passing"
	printf '%s\n' "$OUT" | grep -q 'the rows recorded are not the rows required' || note "the verdict does not name the roster mismatch"
}

sc_oracle_stub_total() {
	# B7. Replacing this very file with a script that exits 0 left
	# "VERDICT: PASS (11 steps)" and "verify-oracle PASS" with an empty detail
	# column, because the only thing checking the oracle was the oracle.
	#
	# run_verify_outer is safe here for the reason its comment gives: the
	# copy's oracle has been replaced by a stub, so nothing recurses.
	local d="$1" parent base
	copy_tree "$d"
	printf '#!/bin/sh\nexit 0\n' >"$d/scripts/test-verify.sh"
	chmod +x "$d/scripts/test-verify.sh"
	parent="$(dirname "$d")"
	base="$(basename "$d")"
	RC=0
	OUT="$(cd "$parent" && "$base/verify.sh" 2>&1)" || RC=$?
	[ "$RC" -ne 0 ] || note "the oracle was replaced by 'exit 0' and the arbiter still passed"
	[ "$(row verify-oracle)" = FAIL ] || note "a stubbed oracle did not fail its row: $(row verify-oracle)"
	printf '%s\n' "$OUT" | grep -q 'not the account of a run' || note "the diagnosis does not say the oracle's answer was not an answer"
}

sc_oracle_stub_partial() {
	# An oracle that accounts for every scenario BY NAME and then reports a
	# count that is not the manifest's. The count branch and the name branch
	# are different refusals; this scenario owns the count one and
	# oracle-names-fabricated owns the other.
	#
	# ATTRIBUTION, corrected: this bound is reviewer B's, stated in the round-6
	# record, not reviewer C's and not round 4's. On merits it was NARROWED and
	# not closed in round 7 — the expectation moved from the oracle's answer to
	# a grep over the oracle's source, which is still the subject — and its
	# survival is exactly what round 8 measured.
	local d="$1" parent base s
	copy_tree "$d"
	{
		printf '#!/bin/sh\n'
		for s in "${MANIFEST_SCENARIOS[@]}"; do printf 'echo "  RESULT %s PASS"\n' "$s"; done
		printf 'echo "ORACLE PASS: 3 scenarios, every planted defect was detected by the row that owns it"\nexit 0\n'
	} >"$d/scripts/test-verify.sh"
	chmod +x "$d/scripts/test-verify.sh"
	parent="$(dirname "$d")"
	base="$(basename "$d")"
	RC=0
	OUT="$(cd "$parent" && "$base/verify.sh" 2>&1)" || RC=$?
	[ "$RC" -ne 0 ] || note "an oracle claiming 3 scenarios against a manifest declaring ${#MANIFEST_SCENARIOS[@]} still passed"
	[ "$(row verify-oracle)" = FAIL ] || note "a partial stub did not fail its row: $(row verify-oracle)"
	printf '%s\n' "$OUT" | grep -q 'verify.manifest.sh declares' || note "the diagnosis does not compare reported against declared"
}

sc_oracle_names_fabricated() {
	# ROUND 9, B10. MEASURED 2026-08-30 by review: replacing this file with 45
	# empty sc_fakeN(){} definitions plus one echo produced
	# "VERDICT: PASS (11 steps)". The expected count was a grep over the file
	# being replaced, so the replacement supplied its own expectation.
	#
	# This stub reports the RIGHT number and runs nothing. It passes every
	# check round 7 added and must fail on the names, which come from the
	# manifest and are written nowhere in the file it replaced.
	local d="$1" parent base
	copy_tree "$d"
	printf '#!/bin/sh\necho "ORACLE PASS: %s scenarios, every planted defect was detected by the row that owns it"\nexit 0\n' \
		"${#MANIFEST_SCENARIOS[@]}" >"$d/scripts/test-verify.sh"
	chmod +x "$d/scripts/test-verify.sh"
	parent="$(dirname "$d")"
	base="$(basename "$d")"
	RC=0
	OUT="$(cd "$parent" && "$base/verify.sh" 2>&1)" || RC=$?
	[ "$RC" -ne 0 ] || note "an oracle that reported the right number and ran nothing still passed"
	[ "$(row verify-oracle)" = FAIL ] || note "a name-free stub did not fail its row: $(row verify-oracle)"
	printf '%s\n' "$OUT" | grep -q 'reported no passing result for scenario' ||
		note "the diagnosis does not say which declared scenarios went unaccounted for"
}

sc_go_domain_empty() {
	# ROUND 9, B12. docs/gates.md promised one scenario per row that empties
	# THAT row's domain; one row of eleven had one. This is the drive for the
	# rows whose domain is the Go source population — and build in particular,
	# which until now was named by exactly one assertion in this file, as a
	# control inside the vet scenario.
	#
	# The plant is one defect stated once: there is no Go source. Every row
	# below derives its count from that population, so every one of them must
	# go red, and a row that hard-codes its count is exposed here and nowhere
	# else.
	local d="$1" r
	copy_tree "$d"
	find "$d" -name '*.go' -delete
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "a tree holding no Go source at all passed"
	for r in build vet gofmt t1 t2; do
		[ "$(row "$r")" = FAIL ] || note "$r did not go red over an empty Go source population: $(row "$r")"
	done
}

sc_manifest_missing() {
	# The manifest is the expectation. Losing it is not a run with fewer rows,
	# and this drives that: no row may be recorded at all.
	local d="$1"
	copy_tree "$d"
	rm -f "$d/verify.manifest.sh"
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "the arbiter ran with no statement of what must be there"
	[ "$(row citations)" = ABSENT ] || note "rows were recorded without a manifest: citations is $(row citations)"
	printf '%s\n' "$OUT" | grep -q 'no statement of what must be there' ||
		note "the diagnosis does not say the expectation itself was missing"
}

sc_manifest_row_removed() {
	# B9, EXACTLY as the review measured it, against the design that answers
	# it. Delete the shellcheck gate: its step in verify.sh AND its name in the
	# roster. Before this round that produced eleven rows becoming ten, every
	# remaining row green, and "VERDICT: PASS (10 steps)".
	#
	# Nothing in the shell can catch it — the roster and the rows now agree,
	# because both moved. The Go pin in internal/manifest is the operand the
	# deleter did not also edit, and it fails inside the unit suite.
	local d="$1"
	copy_tree "$d"
	edit "$d/verify.manifest.sh" $'\tshellcheck\n\tgate-roster\n' $'\tgate-roster\n'
	edit "$d/verify.manifest.sh" 'MANIFEST_ROWS_N=12' 'MANIFEST_ROWS_N=11'
	edit "$d/verify.sh" 'step "shellcheck" "${#linted[@]}" shellcheck -S warning "${linted[@]}"' 'true # gate deleted'
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "a gate was deleted from the arbiter and from its roster together, and the run passed"
	[ "$(row shellcheck)" = ABSENT ] || note "this scenario is not measuring a deleted gate: shellcheck is $(row shellcheck)"
	[ "$(row unit-suite)" = FAIL ] || note "the Go pin did not see a row leave the manifest: unit-suite is $(row unit-suite) — $(why unit-suite)"
}

sc_manifest_count_lies() {
	# Layer 2 of the manifest, driven: a name removed without the literal count
	# beside it being edited. One edit is not enough even inside the file whose
	# whole content is the expectation.
	local d="$1"
	copy_tree "$d"
	edit "$d/verify.manifest.sh" $'\tshellcheck\n\tgate-roster\n' $'\tgate-roster\n'
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "the manifest disagreed with itself and the run passed"
	[ "$(row citations)" = ABSENT ] || note "rows were recorded over an incoherent manifest: citations is $(row citations)"
	printf '%s\n' "$OUT" | grep -q 'does not agree with itself' || note "the diagnosis does not name the disagreement"
}

sc_manifest_scenario_removed() {
	# The oracle's own roster used to live in the oracle, so deleting a
	# scenario name and its function together was consistent and silent — the
	# bound this file stated on itself in round 7. The list is in the manifest
	# now and the manifest's scenario count has a floor pinned in Go.
	#
	# --inner does not run the oracle at all, which is the point: the floor
	# fires without the deleted scenario's own file being consulted.
	local d="$1"
	copy_tree "$d"
	edit "$d/verify.manifest.sh" $'\tcitation-word-start\n' ''
	edit "$d/verify.manifest.sh" 'MANIFEST_SCENARIOS_N=53' 'MANIFEST_SCENARIOS_N=52'
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "a scenario left the manifest, count and all, and the run passed"
	[ "$(row unit-suite)" = FAIL ] || note "the Go floor did not see the scenario population shrink: unit-suite is $(row unit-suite) — $(why unit-suite)"
}

sc_self_check_guard_deleted() {
	# B11. MEASURED 2026-08-30 by review: deleting record()'s count guard
	# together with its two scenarios and the plant they edit produced
	# "VERDICT: PASS (11 steps)" — a witness that dies with its subject.
	#
	# The guard is now driven in process, on every run, by a row. Deleting it
	# reddens that row in the same run, with no oracle involved; this scenario
	# proves the row is not decorative.
	local d="$1"
	copy_tree "$d"
	edit "$d/verify.sh" $'\tif [ "$result" = PASS ]; then' $'\tif false; then'
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "record's guard was removed and the run passed"
	[ "$(row self-check)" = FAIL ] || note "the in-process probe did not notice its own guard was gone: $(row self-check)"
	printf '%s\n' "$OUT" | grep -q 'not enforcing its contract' || note "the diagnosis does not name the choke point"
}

sc_min_declared_tests_floor() {
	# Round 7 stated this bound and called it unclosable: "a test DELETED,
	# rather than disabled, leaves both sides agreeing". It was true because
	# both sides were derived from the tree, so a deletion moved both at once.
	#
	# The subject deleted here is the Go pin itself, which is the other half of
	# defeating the manifest — so this scenario drives two things at once: that
	# deleting tests is visible, and that deleting the pin is not free.
	local d="$1"
	copy_tree "$d"
	rm -rf "$d/internal/manifest"
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "a whole test package was deleted and every derived population moved with it"
	[ "$(row unit-suite)" = FAIL ] || note "the declared-test floor did not fire: unit-suite is $(row unit-suite) — $(why unit-suite)"
	printf '%s\n' "$OUT" | grep -q 'below the floor of' || note "the diagnosis does not name the floor"
}

sc_citation_embedded_identifier() {
	# PRESERVATION control for bound 8. An ordinary camelCase identifier that
	# happens to contain a test-shaped substring is not a citation. MEASURED
	# 2026-08-30 against the pre-fix scan: a comment on a function called
	# isTestFuncName failed the run over a token nobody wrote.
	local d="$1"
	copy_tree "$d"
	edit "$d/proto/state.go" 'import "fmt"' 'import "fmt"

// isTestRosterProbe is named to embed a test-shaped substring on purpose.
func isTestRosterProbe() bool { return true }'
	run_verify "$d"
	[ "$RC" -eq 0 ] || note "an identifier embedding a test-shaped substring failed the run: $OUT"
	[ "$(row citations)" = PASS ] || note "citations read part of an identifier as a citation: $(row citations)"
}

sc_citation_word_start() {
	# The other direction of the same fix: a citation that DOES start a word is
	# still caught. A word-boundary rule that blinds the scan would satisfy the
	# scenario above and defeat the gate.
	local d="$1"
	copy_tree "$d"
	edit "$d/proto/state.go" 'import "fmt"' 'import "fmt"

// See TestRevCWordStartNeverWritten for the rest.'
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "a citation at a word start was not caught"
	[ "$(row citations)" = FAIL ] || note "the word-boundary rule blinded the scan: $(row citations)"
	printf '%s\n' "$OUT" | grep -q 'TestRevCWordStartNeverWritten' || note "the diagnosis does not name the token"
}

sc_gate_panic() {
	# A panic and a deliberate REFUSE both exit 2. Both are a FAIL, so this was
	# never a correctness hole, but a crash reported as "could not measure its
	# domain" sends the reader to the wrong place.
	local d="$1"
	copy_tree "$d"
	edit "$d/internal/gates/t2/main.go" 'func main() {' 'func main() {
	panic("oracle: planted crash")'
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "a gate that panics passed"
	[ "$(row t2)" = FAIL ] || note "t2 did not report the crash: $(row t2)"
	table | grep -q 'the gate crashed' ||
		note "the crash was reported as something other than a crash: $(table | grep '^t2' || true)"
}

sc_gate_refuses() {
	# The other direction of the split above. MEASURED 2026-08-29: with only
	# the crash scenario, mutating verify.sh to report EVERY exit-2 as a crash
	# survived. Deleting a ring root is the refusing case — T1 rule D declines
	# rather than passing a universal claim about an empty set.
	local d="$1"
	copy_tree "$d"
	rm -rf "$d/proto"
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "a deleted ring root passed"
	[ "$(row t1)" = FAIL ] || note "t1 did not refuse a missing ring root: $(row t1)"
	table | grep -q 'could not measure its domain' ||
		note "the refusal was not reported as a refusal: $(table | grep '^t1' || true)"
}

sc_unlinted_script() {
	# The lint list is enumerated in verify.sh, so it is silenced by adding a
	# file nobody lists. This drives that direction.
	local d="$1"
	copy_tree "$d"
	printf '#!/bin/sh\necho unlisted\n' >"$d/scripts/extra.sh"
	chmod +x "$d/scripts/extra.sh"
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "a shell script absent from the lint list passed"
	[ "$(row shellcheck)" = FAIL ] || note "shellcheck did not report the unlisted script: $(row shellcheck)"
}

sc_unlinted_shebang_script() {
	# The half a suffix glob cannot see. MEASURED 2026-08-29 by review: the
	# roster keyed on ".sh" while its comments claimed "every executable shell
	# script" and "every tracked .sh"; a shebang script with no extension
	# satisfied none of the three and was linted by nothing.
	local d="$1"
	copy_tree "$d"
	printf '#!/bin/sh\necho unlisted\n' >"$d/scripts/preflight"
	# Deliberately NOT chmod +x: being a shell script is what makes it need
	# linting, not being executable. Driving it without the exec bit is what
	# proves the detection does not secretly depend on one.
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "an extension-less shell script absent from the lint list passed"
	[ "$(row shellcheck)" = FAIL ] || note "shellcheck did not report the shebang script: $(row shellcheck)"
}

sc_oracle_is_invoked() {
	# MEASURED 2026-08-29: replacing verify.sh's oracle step with a hardcoded
	# PASS survived every scenario here — this script IS the control for those
	# mutants, so verify.sh dropping the step was invisible from inside it.
	#
	# Checking it needs the UNFLAGGED invocation, which would normally recurse.
	# Replacing the copy's oracle with a stub bounds that: the stub answers
	# without calling verify.sh, and this scenario chooses its answer, so both
	# directions are drivable and neither runs deep.
	# Since round 9 the stub must account for every scenario the MANIFEST
	# declares, by name, and report the manifest's count. So the passing stub
	# below reproduces those names — and that is not a weakening, it is this
	# file demonstrating the bound verify.sh states on itself: a stub that
	# reads the manifest defeats the name check. Naming it here, where it is
	# executed, is worth more than claiming it cannot happen.
	#
	# The two directions this scenario drives are unchanged.
	local d="$1" stub marker s
	marker="oracle-stub-was-invoked"
	copy_tree "$d"
	stub="$d/scripts/test-verify.sh"

	{
		printf '#!/bin/sh\n'
		for s in "${MANIFEST_SCENARIOS[@]}"; do printf 'echo "  RESULT %s PASS"\n' "$s"; done
		printf 'echo "ORACLE PASS: %s scenarios, %s"\nexit 0\n' "${#MANIFEST_SCENARIOS[@]}" "$marker"
	} >"$stub"
	chmod +x "$stub"
	run_verify_outer "$d"
	[ "$RC" -eq 0 ] || note "verify.sh failed with a passing oracle: exit $RC"
	[ "$(row verify-oracle)" = PASS ] || note "no passing verify-oracle row: $(row verify-oracle)"
	table | grep -q "$marker" ||
		note "verify.sh did not run scripts/test-verify.sh; its verdict about itself came from somewhere else"

	# The other direction: a failing oracle must fail the run. Without this,
	# verify.sh could invoke the oracle and ignore its answer.
	printf '#!/bin/sh\necho "ORACLE FAIL: %s"\nexit 1\n' "$marker" >"$stub"
	chmod +x "$stub"
	run_verify_outer "$d"
	[ "$RC" -ne 0 ] || note "verify.sh passed with a FAILING oracle; the oracle's answer is not read"
	[ "$(row verify-oracle)" = FAIL ] || note "a failing oracle did not produce a FAIL row: $(row verify-oracle)"
}

sc_ceiling_band() {
	# STRUCTURAL, and weaker than the others by construction — driving the
	# ceiling's VALUE behaviourally would need a suite between the real ceiling
	# and a raised one, i.e. minutes of wall clock per run. This still kills the
	# two mutations that matter: deleting the line, and raising it beyond any
	# suite's reach.
	local v
	v="$(sed -n 's/^SUITE_CEILING_SECONDS=\([0-9][0-9]*\)$/\1/p' "$ROOT/verify.sh")"
	[ -n "$v" ] || {
		note "verify.sh declares no numeric SUITE_CEILING_SECONDS; the wall-clock ceiling is gone"
		return
	}
	[ "$v" -ge 5 ] && [ "$v" -le 120 ] ||
		note "SUITE_CEILING_SECONDS=$v is outside 5..120; a ceiling no suite can reach is not a ceiling"
}

# ------------------------------------------------------------------- driver --

run_one() {
	local name="$1" fn d
	fn="sc_$(printf '%s' "$name" | tr - _)"
	command -v "$fn" >/dev/null 2>&1 || refuse "no function $fn for scenario $name"
	d="$(mktemp -d)"
	# shellcheck disable=SC2064  # $d must expand now, not at trap time
	trap "rm -rf '$d'" EXIT
	FAILS=()
	"$fn" "$d"
	if [ "${#FAILS[@]}" -eq 0 ]; then
		printf 'RESULT %s PASS\n' "$name"
	else
		printf 'RESULT %s FAIL %s\n' "$name" "$(printf '%s; ' "${FAILS[@]}")"
	fi
}

if [ "${1:-}" = "--scenario" ]; then
	[ -n "${2:-}" ] || refuse "--scenario needs a name"
	run_one "$2"
	exit 0
fi

[ "${#SCENARIOS[@]}" -gt 0 ] || refuse "no scenarios are declared; the oracle's domain is empty"
command -v python3 >/dev/null 2>&1 || refuse "python3 is not on PATH; planted edits cannot be applied"

# The manifest's roster, cross-checked in BOTH directions against the sc_*
# functions defined here: a universal claim is satisfied by emptying its
# domain, so deleting a name from the manifest is a REFUSAL rather than a
# shorter run.
#
# This used to read "deleting a name AND its function together is consistent,
# and this cannot see it". That bound is CLOSED for the deletion direction and
# it is worth naming why, because the fix was not a better cross-check: the
# list moved OUT of this file. Deleting a scenario now means editing the
# manifest, its literal count, the Go floor in internal/manifest — and this
# file. Scenario manifest-scenario-removed.
#
# BOUND that remains: a scenario whose body asserts nothing is declared,
# defined, counted and says nothing. Nothing here can see that, and the
# row-coverage check below is a spelling check for the same reason.
declared="$(printf '%s\n' "${SCENARIOS[@]}" | tr - _ | sort)"
defined="$(declare -F | sed -n 's/^declare -f sc_//p' | sort)"
if [ "$declared" != "$defined" ]; then
	printf 'declared: %s\n' "$(printf '%s' "$declared" | tr '\n' ' ')" >&2
	printf 'defined : %s\n' "$(printf '%s' "$defined" | tr '\n' ' ')" >&2
	refuse "the SCENARIOS list and the sc_* functions in this file do not match"
fi

# Every row verify.sh requires must be asserted on by SOME scenario.
#
# Round 7's design makes a row unable to record PASS without stating how many
# things it examined, but nothing inside verify.sh can force that number to be
# DERIVED rather than written. A row with a hard-coded count is caught by
# emptying its domain and watching it go red — which only happens if a scenario
# exists. This is the check that a new row arrives with one.
#
# BOUND: it is a spelling check. A scenario that names a row and asserts
# nothing useful about it satisfies this, and its own empty case is refused
# below.
# ROUND 9: the domain used to be grepped OUT OF verify.sh, so B9's edit —
# delete the shellcheck step and its roster entry — shrank this check's domain
# in the same stroke, and the row that stopped being checked also stopped being
# required. It reads the manifest now.
unasserted=""
for r in "${MANIFEST_ROWS[@]}"; do
	grep -q "row $r" "$ROOT/scripts/test-verify.sh" || unasserted="$unasserted $r"
done
[ -z "$unasserted" ] || refuse "verify.sh requires row(s)$unasserted that no scenario in this file asserts on"

results="$(mktemp)"
trap 'rm -f "$results"' EXIT

printf '%s\n' "${SCENARIOS[@]}" | xargs -P "$JOBS" -I{} "$ROOT/scripts/test-verify.sh" --scenario {} >"$results" 2>&1 || true

lines="$(grep -c '^RESULT ' "$results" || true)"
if [ "$lines" != "${#SCENARIOS[@]}" ]; then
	sed 's/^/  /' "$results" >&2
	refuse "collected $lines result line(s) for ${#SCENARIOS[@]} scenario(s); a scenario died without reporting, and a missing result is not a pass"
fi

# The RESULT prefix is KEPT, not stripped. verify.sh requires one
# "RESULT <name> PASS" line per scenario the manifest declares, so this output
# is the account it reads — a stub that prints only a summary line no longer
# satisfies it.
sort -k2,2 "$results" | sed 's/^/  /'

bad="$(grep -c '^RESULT [^ ]* FAIL' "$results" || true)"
echo "---"
if [ "$bad" -eq 0 ]; then
	echo "ORACLE PASS: ${#SCENARIOS[@]} scenarios, every planted defect was detected by the row that owns it"
	exit 0
fi
echo "ORACLE FAIL: $bad of ${#SCENARIOS[@]} scenarios did not behave"
exit 1
