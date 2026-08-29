#!/usr/bin/env bash
#
# test-verify.sh — the oracle for verify.sh.
#
# verify.sh is the only instrument in this repository with no external arbiter:
# there is no CI (build plan §5.1), so nothing but this script ever asks
# whether the verifier still detects anything. A gate nobody drives is
# indistinguishable from a gate that passes everything.
#
# How it works, and why it does not recurse: it copies the tree, plants ONE
# defect in the copy, runs the COPY's `./verify.sh --inner`, and asserts both
# that the run failed AND that the row which failed is the row that owns the
# defect. --inner is what stops the copy from running this script again. The
# recursion obstacle is real, but it is specific to writing the oracle as a
# `go test`: verify.sh runs `go test ./...`, so a Go test that ran verify.sh
# would re-enter it with no place to put a flag. As a standalone script with
# an explicit flag on the inner invocation, there is no recursion to break.
#
# Attributing the failure to the ROW, not just to the exit status, is the same
# lesson that produced the guard in internal/gates/gatetest: a run that fails
# for the wrong reason looks exactly like a run that fails for the right one.
#
# Usage:  scripts/test-verify.sh              run every scenario
#         scripts/test-verify.sh --scenario N run one (used by the parallel driver)
# Exit:   0 = every scenario behaved, 1 = at least one did not,
#         2 = REFUSED, the oracle could not measure its own domain.

set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"

JOBS="${ORACLE_JOBS:-4}"

# Every scenario. The driver refuses if the number of result lines it collects
# is not exactly the number of names here — a scenario that dies without
# printing is otherwise a silent pass for the whole oracle.
SCENARIOS=(
	control
	verdict-on-abort
	verdict-without-gomod
	roster-gate-deleted
	roster-gate-added
	t1-violation
	t2-violation
	gofmt-violation
	vet-violation
	race-detector
	test-cache
	ceiling-fires
	ceiling-control
	ceiling-band
	gate-panic
	gate-refuses
	unlinted-script
	unlinted-shebang-script
	oracle-is-invoked
)

# ------------------------------------------------------------------ helpers --

refuse() {
	printf 'ORACLE REFUSED: %s\n' "$*" >&2
	exit 2
}

# copy_tree DEST — the subject, minus .git and minus the toolchain's caches.
copy_tree() {
	mkdir -p "$1"
	tar -cf - -C "$ROOT" --exclude=./.git . | tar -xf - -C "$1"
	[ -x "$1/verify.sh" ] || refuse "the copy has no executable verify.sh"
}

# edit FILE FROM TO — a sed that MUST change something. A mutation that
# silently fails to apply leaves a pristine copy, and a pristine copy passes,
# which is the one outcome this script must never mistake for a detection.
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

# table — the step rows of $OUT and nothing else. Diagnostics are printed to
# stderr and merged into OUT, so matching a step name anywhere in the output
# would let a diagnostic line satisfy an assertion about a row.
table() {
	printf '%s\n' "$OUT" | awk '
		/^----[ ]+------/ { in_table = 1; next }
		in_table && NF == 0 { exit }
		in_table { print }
	'
}

# row NAME — PASS, FAIL, or ABSENT. ABSENT is a distinct answer on purpose:
# an absent row is not a passing row, and a step that stopped existing is the
# quietest way for a verifier to stop checking something.
row() {
	table | awk -v n="$1" '$1 == n { print $2; found = 1 } END { if (!found) print "ABSENT" }'
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
	# A hard abort under `set -e`, planted at a point every run reaches. This
	# drives the EXIT trap directly rather than through one known-bad line:
	# the promise is "any abort still prints a verdict", not "this abort does".
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
	# left this oracle passing 18 of 18. Every other step in the file is
	# cross-checked by some scenario that plants a defect only that step can
	# see — deleting gofmt reddened 4 scenarios, shellcheck 2, the unit suite
	# refused the run outright — and vet alone had no such witness. A step
	# nothing drives is a step that can be deleted, which is the same defect
	# class as a gate that cannot see whether it is still wired in.
	#
	# The bait is unreachable code, chosen for attribution rather than
	# convenience: it is in `go vet`'s suite but NOT in the subset `go test`
	# runs by default (atomic, bool, buildtags, directive, errorsas,
	# ifaceassert, nilfunc, printf, stringintconv, tests), so it reddens the
	# vet row and leaves unit-suite alone. A printf bait would have failed
	# both rows and proved nothing about which one saw it.
	local d="$1"
	copy_tree "$d"
	printf 'package proto\n\nfunc vetBait() int {\n\treturn 0\n\treturn 1\n}\n' >"$d/proto/vetbait.go"
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "unreachable code passed the verifier"
	[ "$(row vet)" = FAIL ] || note "vet did not report unreachable code: $(row vet)"
	# Attribution, in the direction that catches a bait too blunt to localise:
	# the plant compiles and is gofmt-clean, so a FAIL in either of those rows
	# means this scenario is measuring something other than vet.
	[ "$(row build)" = PASS ] || note "the vet bait broke the build; it is not a vet-only defect: $(row build)"
	[ "$(row gofmt)" = PASS ] || note "the vet bait is unformatted; it is not a vet-only defect: $(row gofmt)"
	[ "$(row unit-suite)" = PASS ] || note "the vet bait reddened the unit suite; go test's own vet subset saw it: $(row unit-suite)"
}

sc_race_detector() {
	local d="$1"
	copy_tree "$d"
	# Drives -race behaviourally. Without it on the `go test` line this test
	# passes: two goroutines racing on an int is not a failure, it is a race.
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
	[ "$(row unit-suite)" = FAIL ] || note "unit-suite did not report the race: $(row unit-suite)"
	[ "$(row gofmt)" = PASS ] || note "the planted race test is unformatted; this run failed for a reason this scenario does not name"
	[ "$(row t2)" = PASS ] || note "the planted race test tripped T2; this run failed for a reason this scenario does not name"
}

sc_test_cache() {
	local d="$1"
	copy_tree "$d"
	# Drives -count=1. Removing it lets the SECOND run be served from the test
	# cache, and a cached PASS is a result that was not measured on this tree.
	# The first run must still pass — otherwise the second run's failure could
	# be anything.
	edit "$d/verify.sh" 'go test -race -count=1 ./...' 'go test -race ./...'
	run_verify "$d"
	[ "$RC" -eq 0 ] || note "the first run of the -count=1-less copy did not pass: exit $RC"
	run_verify "$d"
	[ "$RC" -ne 0 ] || note "a cached suite result passed; nothing observes -count=1"
	[ "$(row unit-suite)" = FAIL ] || note "unit-suite did not report the cached result: $(row unit-suite)"
	printf '%s\n' "$OUT" | grep -q 'cached' || note "the cached-result failure does not say it was cached"
}

# ceiling_tree DEST — a copy whose suite genuinely takes a few seconds.
#
# The delay is a busy loop and not time.Sleep on purpose: T2 would refuse the
# sleep, and the row under test here is unit-suite. It is also the exact shape
# docs/gates.md names as beyond T2's reach — built entirely from allowlisted
# identifiers — so this doubles as a live demonstration of that bound.
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
	[ "$(row unit-suite)" = FAIL ] || note "unit-suite did not report the ceiling: $(row unit-suite)"
	printf '%s\n' "$OUT" | grep -q 'ceiling' || note "the over-ceiling failure does not name the ceiling"
	[ "$(row t2)" = PASS ] || note "the busy loop tripped T2; the ceiling is not what failed this run"
}

sc_ceiling_control() {
	# The preservation control for the scenario above, and the reason it is a
	# measurement rather than a coincidence: the SAME slow test under the SAME
	# copy, with the ceiling left where it ships, must PASS. Without this the
	# scenario above proves only that a busy loop breaks something.
	local d="$1"
	ceiling_tree "$d"
	run_verify "$d"
	[ "$RC" -eq 0 ] || note "a 3s suite failed under the shipped ceiling: exit $RC — the ceiling scenario is measuring something else"
	[ "$(row unit-suite)" = PASS ] || note "unit-suite did not pass a 3s suite: $(row unit-suite)"
}

sc_gate_panic() {
	# A Go panic exits 2 and so does a deliberate REFUSE, so the exit code
	# alone cannot say which happened. Both are a FAIL, which is why this was
	# never a correctness hole — but a crash reported as "could not measure its
	# domain" sends the reader to the wrong place. The gates print a REFUSED
	# line; this drives verify.sh actually reading it.
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
	# The other direction of the split above, and the reason it is a split at
	# all. MEASURED 2026-08-29: with only the crash scenario, mutating
	# verify.sh to report EVERY exit-2 as a crash survived — nothing drove a
	# gate that genuinely declines to measure its domain.
	#
	# Deleting a ring root is that case: T1 rule D refuses rather than passing,
	# because a universal claim about an empty set is not a pass.
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
	# The shell scripts that get linted are enumerated in verify.sh and
	# cross-checked against the ones that exist. A list that discovers itself
	# is silenced by moving a file out of the glob; a list that is only
	# enumerated is silenced by adding a file nobody lists. This drives the
	# second direction, which is the one an enumeration cannot cover.
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
	# lint roster keyed on ".sh" while its own comments claimed "every
	# executable shell script" and "every tracked .sh". A script with a shebang
	# and no extension satisfied none of the three and was linted by nothing.
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
	# PASS survived every scenario here. It had to — this script IS the control
	# for those mutants, and mutate.sh runs it directly, so verify.sh dropping
	# the step is invisible from inside it. A gate that cannot see whether it
	# is still wired in is the defect class both blocking findings were.
	#
	# Checking it needs the UNFLAGGED invocation, which would normally recurse.
	# The recursion is bounded by replacing the copy's oracle with a stub: the
	# stub answers, does not call verify.sh, and its answer is chosen by this
	# scenario — so both directions are drivable and neither runs deep.
	local d="$1" stub marker
	marker="oracle-stub-was-invoked"
	copy_tree "$d"
	stub="$d/scripts/test-verify.sh"

	printf '#!/bin/sh\necho "ORACLE PASS: %s"\nexit 0\n' "$marker" >"$stub"
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
	# A STRUCTURAL check, and weaker than the others by construction — say so
	# rather than let the table imply otherwise. Driving the ceiling's VALUE
	# behaviourally needs a suite between the real ceiling and a raised one,
	# i.e. minutes of wall clock per run. This costs nothing and still kills
	# the two mutations that matter: deleting the line, and raising it to a
	# number no suite could ever reach.
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

# The oracle's own roster, cross-checked in BOTH directions against the sc_*
# functions this file defines — the same shape verify.sh applies to its gates,
# and for the same reason: a universal claim is satisfied by emptying its
# domain, so "every scenario passed" is worth exactly as much as the scenario
# list is hard to shorten. Deleting a name from SCENARIOS shrinks the run
# silently; this makes it a REFUSAL.
#
# Its bound, named rather than left for a reader to discover: deleting a name
# AND its function together is consistent, and this check cannot see it. What
# it buys is that the cheap edit — one line out of the array — is not the
# quiet one. The expensive edit remains available to anyone who wants it.
declared="$(printf '%s\n' "${SCENARIOS[@]}" | tr - _ | sort)"
defined="$(declare -F | sed -n 's/^declare -f sc_//p' | sort)"
if [ "$declared" != "$defined" ]; then
	printf 'declared: %s\n' "$(printf '%s' "$declared" | tr '\n' ' ')" >&2
	printf 'defined : %s\n' "$(printf '%s' "$defined" | tr '\n' ' ')" >&2
	refuse "the SCENARIOS list and the sc_* functions in this file do not match"
fi

results="$(mktemp)"
trap 'rm -f "$results"' EXIT

printf '%s\n' "${SCENARIOS[@]}" | xargs -P "$JOBS" -I{} "$ROOT/scripts/test-verify.sh" --scenario {} >"$results" 2>&1 || true

lines="$(grep -c '^RESULT ' "$results" || true)"
if [ "$lines" != "${#SCENARIOS[@]}" ]; then
	sed 's/^/  /' "$results" >&2
	refuse "collected $lines result line(s) for ${#SCENARIOS[@]} scenario(s); a scenario died without reporting, and a missing result is not a pass"
fi

sort -k2,2 "$results" | sed 's/^RESULT /  /'

bad="$(grep -c '^RESULT [^ ]* FAIL' "$results" || true)"
echo "---"
if [ "$bad" -eq 0 ]; then
	echo "ORACLE PASS: ${#SCENARIOS[@]} scenarios, every planted defect was detected by the row that owns it"
	exit 0
fi
echo "ORACLE FAIL: $bad of ${#SCENARIOS[@]} scenarios did not behave"
exit 1
