#!/usr/bin/env bash
#
# verify.sh — the one command. Runs every gate and prints one verdict.
#
# This repository has no CI and, per the build plan §5.1, will not get any:
# the self-hosted runners belong to the plugin repository and cannot serve a
# second private repo without an organisation. There is therefore no external
# arbiter, and "green" has to mean something a person can run in one line.
#
# A verifier reassembled from memory each time is not a verifier. Neither is a
# README paragraph listing what a developer "should run".
#
# Usage:  ./verify.sh            run every gate, including the verifier oracle
#         ./verify.sh --inner    same, minus the oracle (see below)
# Exit:   0 = PASS (the normal state), 1 = FAIL. Any step that cannot be
#         measured is a FAIL, never a skip.
#
# --inner exists for exactly one caller: scripts/test-verify.sh, which is the
# oracle for THIS file. It copies the tree, plants a defect, and runs the
# copy's verify.sh — so without the flag the oracle would run itself, forever.
# It is a flag and not an environment variable on purpose: an ambient variable
# silences the oracle for anyone who happens to have it set, which is the
# opt-out shape this project keeps paying for. A flag has to be typed into the
# invocation you are looking at.

set -euo pipefail

cd "$(dirname "$0")"
ROOT="$PWD"

INNER=0
for arg in "$@"; do
	case "$arg" in
	--inner) INNER=1 ;;
	*)
		echo "VERDICT: FAIL — unknown argument $arg; nothing was measured." >&2
		exit 1
		;;
	esac
done

# The wall-clock ceiling on the unit suite, in seconds. This is T2's second
# instrument: the identifier gate reads source, this reads the clock, and a
# wait the gate cannot see still costs time here.
#
# Its bound, stated rather than discovered: a count backstop only holds AT the
# threshold. A 200ms sleep does not move a 60s ceiling. It catches a suite that
# has drifted into waiting, not a single test that waits a little.
SUITE_CEILING_SECONDS=60

# The hang bound, in seconds, passed to `go test -timeout`.
#
# The ceiling above CANNOT bound a hang, and that is not a subtlety: it is
# computed from a clock read AFTER `go test` returns, so a test that never
# returns never reaches the comparison. Without this line the only bound is
# Go's own default of ten minutes per test binary — set nowhere in this
# repository, ten times the ceiling, and removable through GOFLAGS by anyone
# who never reads this file.
#
# It MUST stay strictly greater than the ceiling, and comfortably so: a suite
# that is slow but finishing should be diagnosed by the ceiling, which says
# something is waiting, rather than killed by this, which says only that it did
# not finish. Nothing enforces that ordering — both numbers are printed in the
# unit-suite row of every run, which is the whole of what checks it.
SUITE_TIMEOUT_SECONDS=180

# The gates that MUST run. Enumerated here, and cross-checked below against the
# gates that actually exist, in BOTH directions: a required gate that has been
# deleted is a FAIL, and a gate present in the tree but absent from this list
# is also a FAIL. A verifier that discovers its own checklist can be silenced
# by deleting a check.
REQUIRED_GATES=(t1 t2)

BIN="$(mktemp -d)"

declare -a NAMES=() RESULTS=() NOTES=()
FAILED=0
VERDICT_PRINTED=0
ABORT_LINE=""

# The verdict is printed by a trap, not by the last line of the script.
#
# MEASURED 2026-08-29: it used to be the last line, and a single unprotected
# assignment above it (the gate-roster `go list`) took `set -e` with it — so
# deleting go.mod made this file exit 1 having printed no verdict at all. A
# verifier whose whole promise is "one command, one verdict" was silent in the
# one case where the tree was most broken.
#
# Fixing that assignment fixes that assignment. The promise is a property of
# the file, so it is held here, where every exit path passes: any abort, from
# any line, still prints a verdict, and it prints FAIL.
on_exit() {
	local rc=$?
	rm -rf "$BIN"
	if [ "$VERDICT_PRINTED" -eq 0 ]; then
		echo
		echo "VERDICT: FAIL — the verifier aborted before reaching its verdict (exit $rc${ABORT_LINE:+, at line $ABORT_LINE})."
		echo "${#NAMES[@]} step(s) had been recorded. Everything after the abort is UNMEASURED, which is a FAIL and not a skip."
		[ "$rc" -ne 0 ] || rc=1
		exit "$rc"
	fi
}
trap on_exit EXIT
trap 'ABORT_LINE=$LINENO' ERR

record() { # name result note
	NAMES+=("$1")
	RESULTS+=("$2")
	NOTES+=("${3:-}")
	[ "$2" = PASS ] || FAILED=1
}

step() { # name -- command...
	local name="$1"
	shift
	local out rc=0
	out="$("$@" 2>&1)" || rc=$?
	if [ "$rc" -eq 0 ]; then
		record "$name" PASS "$(printf '%s' "$out" | tail -1)"
	else
		record "$name" FAIL "exit $rc"
		printf '\n--- %s FAILED (exit %s) ---\n%s\n' "$name" "$rc" "$out" >&2
	fi
}

command -v go >/dev/null 2>&1 || {
	echo "VERDICT: FAIL — the go toolchain is not on PATH; nothing was measured." >&2
	exit 1
}

# ---------------------------------------------------------------- toolchain --
step "build" go build ./...
step "vet" go vet ./...

# gofmt -l exits 0 whether or not it lists anything, so its exit code is not
# the signal — the output is. An error folded into a value has no direction.
fmt_out="$(gofmt -l . 2>&1)" || true
if [ -n "$fmt_out" ]; then
	record "gofmt" FAIL "unformatted: $(printf '%s' "$fmt_out" | tr '\n' ' ')"
else
	record "gofmt" PASS "all files formatted"
fi

# verify.sh is itself a load-bearing instrument and nothing else checks it, so
# it is linted here, and so is scripts/test-verify.sh, which is the oracle for
# this file. A missing shellcheck is a FAIL, not a skip: a step that cannot be
# measured must not report a pass.
#
# The list is enumerated AND cross-checked against the shell scripts the tree
# actually holds, in both directions. A lint list that discovers itself is
# silenced by moving a file out of the glob; one that is only enumerated is
# silenced by adding a file nobody lists.
SHELL_SCRIPTS=(verify.sh scripts/test-verify.sh)

# shell_files prints every shell script in the tree, one per line, relative to
# the root.
#
# "Shell script" is defined here as: a regular file that either ends in .sh OR
# opens with a shell shebang. Both halves are load-bearing. MEASURED 2026-08-29
# by review: this used to key on the .sh suffix alone while the comments around
# it described the domain two other ways — "every executable shell script" and
# "every tracked .sh" — so all three descriptions disagreed and none matched
# the code. A future scripts/preflight with a #!/bin/sh line would have been
# linted by nothing and would have tripped neither direction of the check.
#
# A filesystem walk and not `git ls-files`: git is unavailable inside the
# oracle's copies of the tree, and a check that silently does nothing where it
# is being tested is a check with no observer.
shell_files() {
	find . -type f -not -path './.git/*' -printf '%P\n' | while IFS= read -r f; do
		case "$f" in
		*.sh)
			printf '%s\n' "$f"
			;;
		*)
			if head -n 1 -- "$f" 2>/dev/null | grep -qE '^#!.*[ /](ba|da|k|z|a)?sh$|^#!.*[ /](ba|da|k|z|a)?sh '; then
				printf '%s\n' "$f"
			fi
			;;
		esac
	done
	return 0
}

if command -v shellcheck >/dev/null 2>&1; then
	shell_expected="$(printf '%s\n' "${SHELL_SCRIPTS[@]}" | sort | tr '\n' ' ')"
	shell_found="$(shell_files | sort | tr '\n' ' ')"
	if [ "$shell_expected" != "$shell_found" ]; then
		record "shellcheck" FAIL "the linted list [$shell_expected] is not every shell script in the tree [$shell_found]"
	else
		linted=()
		for sh in "${SHELL_SCRIPTS[@]}"; do linted+=("$ROOT/$sh"); done
		step "shellcheck" shellcheck -S warning "${linted[@]}"
	fi
else
	record "shellcheck" FAIL "shellcheck is not installed; the shell scripts were not linted"
fi

# -------------------------------------------------------------- gate roster --
# Structural, not a glob over directory names: ask the go tool which packages
# under internal/gates are commands.
# The rc is captured rather than allowed to propagate: `go list` failing is a
# measurable outcome of this step (a tree with no go.mod, say), not a reason
# for the verifier to vanish. The EXIT trap would still print a verdict, but
# "aborted at line N" is a worse diagnosis than the one this step can give.
roster_rc=0
roster_raw="$(go list -f '{{if eq .Name "main"}}{{.ImportPath}}{{end}}' ./internal/gates/... 2>&1)" || roster_rc=$?
discovered="$(printf '%s\n' "$roster_raw" | sed -n 's|^.*/||p' | sort | tr '\n' ' ' | sed 's/ $//')"
expected="$(printf '%s\n' "${REQUIRED_GATES[@]}" | sort | tr '\n' ' ' | sed 's/ $//')"
if [ "$roster_rc" -ne 0 ]; then
	record "gate-roster" FAIL "go list could not enumerate the gates (exit $roster_rc); the roster is UNMEASURED"
	printf '\n--- gate-roster could not be measured ---\n%s\n' "$roster_raw" >&2
elif [ "$discovered" = "$expected" ]; then
	record "gate-roster" PASS "gates present: $discovered"
else
	record "gate-roster" FAIL "required [$expected] but tree has [$discovered]"
	echo "--- gate-roster FAILED: the set of gate commands does not match REQUIRED_GATES in verify.sh ---" >&2
fi

# ------------------------------------------------------------------- gates --
# Built, then executed. NOT `go run`: MEASURED 2026-08-29, `go run` collapses
# every non-zero child status to 1, so a gate REFUSING (2) because it could not
# measure its domain would be indistinguishable from a gate reporting a
# violation (1). The distinction is the whole reason the codes differ.
for g in "${REQUIRED_GATES[@]}"; do
	if ! go build -o "$BIN/$g" "./internal/gates/$g" 2>"$BIN/$g.err"; then
		record "$g" FAIL "gate does not compile"
		cat "$BIN/$g.err" >&2
		continue
	fi
	rc=0
	out="$("$BIN/$g" -root "$ROOT" 2>&1)" || rc=$?
	case "$rc" in
	0) record "$g" PASS "$(printf '%s' "$out" | tail -1)" ;;
	1) record "$g" FAIL "VIOLATION" ;;
	2)
		# A Go panic also exits 2, so the code alone does not say whether the
		# gate declined to measure or died trying. Both are a FAIL — this is
		# fail-closed either way — but they are different diagnoses, and the
		# gates print a REFUSED line precisely so the two can be told apart.
		if printf '%s' "$out" | grep -q 'REFUSED'; then
			record "$g" FAIL "REFUSED — the gate could not measure its domain"
		else
			record "$g" FAIL "exit 2 with no REFUSED line — the gate crashed (a Go panic exits 2 too)"
		fi
		;;
	*) record "$g" FAIL "unexpected exit $rc" ;;
	esac
	[ "$rc" -eq 0 ] || printf '\n--- %s ---\n%s\n' "$g" "$out" >&2
done

# ------------------------------------------------------------- unit suite --
# -count=1 defeats the test cache: a cached PASS is a result that was not
# measured on this tree.
suite_start=$(date +%s)
rc=0
suite_out="$(go test -race -count=1 -timeout "${SUITE_TIMEOUT_SECONDS}s" ./... 2>&1)" || rc=$?
suite_elapsed=$(($(date +%s) - suite_start))
if [ "$rc" -ne 0 ]; then
	record "unit-suite" FAIL "exit $rc after ${suite_elapsed}s"
	printf '\n--- unit-suite FAILED ---\n%s\n' "$suite_out" >&2
elif printf '%s' "$suite_out" | grep -q '(cached)'; then
	# -count=1 is above; this is what proves it was in force. A cached PASS is
	# a result that was not measured on this tree, and it is indistinguishable
	# from a real one in the exit status alone — so the flag needs an observer
	# and not just a reader.
	record "unit-suite" FAIL "go test reported a cached result; -count=1 was not in force, so the suite was not measured on this tree"
	printf '\n--- unit-suite was served from the test cache ---\n%s\n' "$suite_out" >&2
elif [ "$suite_elapsed" -gt "$SUITE_CEILING_SECONDS" ]; then
	record "unit-suite" FAIL "passed but took ${suite_elapsed}s, over the ${SUITE_CEILING_SECONDS}s ceiling"
	echo "--- unit-suite exceeded the T2 wall-clock ceiling: something is waiting ---" >&2
else
	record "unit-suite" PASS "${suite_elapsed}s, ceiling ${SUITE_CEILING_SECONDS}s, hang timeout ${SUITE_TIMEOUT_SECONDS}s"
fi

# ------------------------------------------------------------- self-oracle --
# The verifier is the one instrument here with no external arbiter, so it has
# one of its own. See scripts/test-verify.sh for what it can and cannot see.
if [ "$INNER" -eq 0 ]; then
	if [ -x "$ROOT/scripts/test-verify.sh" ]; then
		step "verify-oracle" "$ROOT/scripts/test-verify.sh"
	else
		record "verify-oracle" FAIL "scripts/test-verify.sh is missing or not executable; verify.sh was not itself checked"
	fi
fi

# ------------------------------------------------------------------ verdict --
echo
echo "step                 result  detail"
echo "----                 ------  ------"
for i in "${!NAMES[@]}"; do
	printf '%-20s %-7s %s\n' "${NAMES[$i]}" "${RESULTS[$i]}" "${NOTES[$i]}"
done
echo

VERDICT_PRINTED=1
if [ "$FAILED" -eq 0 ]; then
	echo "VERDICT: PASS (${#NAMES[@]} steps)"
	exit 0
fi
echo "VERDICT: FAIL"
exit 1
