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
# Usage:  ./verify.sh
# Exit:   0 = PASS (the normal state), 1 = FAIL. Any step that cannot be
#         measured is a FAIL, never a skip.

set -euo pipefail

cd "$(dirname "$0")"
ROOT="$PWD"

# The wall-clock ceiling on the unit suite, in seconds. This is T2's second
# instrument: the identifier gate reads source, this reads the clock, and a
# wait the gate cannot see still costs time here.
#
# Its bound, stated rather than discovered: a count backstop only holds AT the
# threshold. A 200ms sleep does not move a 60s ceiling. It catches a suite that
# has drifted into waiting, not a single test that waits a little.
SUITE_CEILING_SECONDS=60

# The gates that MUST run. Enumerated here, and cross-checked below against the
# gates that actually exist, in BOTH directions: a required gate that has been
# deleted is a FAIL, and a gate present in the tree but absent from this list
# is also a FAIL. A verifier that discovers its own checklist can be silenced
# by deleting a check.
REQUIRED_GATES=(t1 t2)

BIN="$(mktemp -d)"
trap 'rm -rf "$BIN"' EXIT

declare -a NAMES=() RESULTS=() NOTES=()
FAILED=0

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
# it is linted here. A missing shellcheck is a FAIL, not a skip: a step that
# cannot be measured must not report a pass.
if command -v shellcheck >/dev/null 2>&1; then
	step "shellcheck" shellcheck -S warning "$ROOT/verify.sh"
else
	record "shellcheck" FAIL "shellcheck is not installed; verify.sh was not linted"
fi

# -------------------------------------------------------------- gate roster --
# Structural, not a glob over directory names: ask the go tool which packages
# under internal/gates are commands.
discovered="$(go list -f '{{if eq .Name "main"}}{{.ImportPath}}{{end}}' ./internal/gates/... 2>/dev/null |
	sed 's|.*/||' | sort | tr '\n' ' ' | sed 's/ $//')"
expected="$(printf '%s\n' "${REQUIRED_GATES[@]}" | sort | tr '\n' ' ' | sed 's/ $//')"
if [ "$discovered" = "$expected" ]; then
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
	2) record "$g" FAIL "REFUSED — the gate could not measure its domain" ;;
	*) record "$g" FAIL "unexpected exit $rc" ;;
	esac
	[ "$rc" -eq 0 ] || printf '\n--- %s ---\n%s\n' "$g" "$out" >&2
done

# ------------------------------------------------------------- unit suite --
# -count=1 defeats the test cache: a cached PASS is a result that was not
# measured on this tree.
suite_start=$(date +%s)
rc=0
suite_out="$(go test -race -count=1 ./... 2>&1)" || rc=$?
suite_elapsed=$(($(date +%s) - suite_start))
if [ "$rc" -ne 0 ]; then
	record "unit-suite" FAIL "exit $rc after ${suite_elapsed}s"
	printf '\n--- unit-suite FAILED ---\n%s\n' "$suite_out" >&2
elif [ "$suite_elapsed" -gt "$SUITE_CEILING_SECONDS" ]; then
	record "unit-suite" FAIL "passed but took ${suite_elapsed}s, over the ${SUITE_CEILING_SECONDS}s ceiling"
	echo "--- unit-suite exceeded the T2 wall-clock ceiling: something is waiting ---" >&2
else
	record "unit-suite" PASS "${suite_elapsed}s, ceiling ${SUITE_CEILING_SECONDS}s"
fi

# ------------------------------------------------------------------ verdict --
echo
echo "step                 result  detail"
echo "----                 ------  ------"
for i in "${!NAMES[@]}"; do
	printf '%-20s %-7s %s\n' "${NAMES[$i]}" "${RESULTS[$i]}" "${NOTES[$i]}"
done
echo

if [ "$FAILED" -eq 0 ]; then
	echo "VERDICT: PASS (${#NAMES[@]} steps)"
	exit 0
fi
echo "VERDICT: FAIL"
exit 1
