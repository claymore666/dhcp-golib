#!/usr/bin/env bash
#
# verify.sh — the one command. Runs every gate and prints one verdict.
#
# Usage:  ./verify.sh            run every gate, including the verifier oracle
#         ./verify.sh --inner    same, minus the oracle
# Exit:   0 = PASS, 1 = FAIL. A step that cannot be measured is a FAIL, never
#         a skip.
#
# DECISION 2026-08-29: no CI here (build plan §5.1) — the runners belong to the
# plugin repository — so this file is the only arbiter and has to be one line a
# person can type.
#
# DECISION 2026-08-29: --inner is a flag, not an environment variable. Its one
# caller is scripts/test-verify.sh, the oracle for this file, which would
# otherwise re-enter it forever; an ambient variable would silence the oracle
# for anyone who happened to have it set.

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

# The wall-clock ceiling on the unit suite, in seconds — T2's second
# instrument, reading the clock where the identifier gate reads source.
#
# BOUND: a threshold only holds AT the threshold. A 200ms sleep does not move a
# 60s ceiling, so this catches a suite that has drifted into waiting, not one
# test that waits a little.
SUITE_CEILING_SECONDS=60

# The hang bound, in seconds, passed to `go test -timeout`. The ceiling above
# cannot bound a hang: it is computed after `go test` returns (scenario
# hang-bounded). Without this line the only bound is Go's default of ten
# minutes per binary, which is set nowhere here and is removable through
# GOFLAGS.
SUITE_TIMEOUT_SECONDS=180

# The gates that MUST run: enumerated, not discovered — a verifier that finds
# its own checklist is silenced by deleting a check. Cross-checked below in
# both directions (scenarios roster-gate-deleted, roster-gate-added).
REQUIRED_GATES=(t1 t2)

BIN="$(mktemp -d)"

declare -a NAMES=() RESULTS=() NOTES=()
FAILED=0
VERDICT_PRINTED=0
ABORT_LINE=""

# The verdict is printed by a trap so that EVERY exit path prints one.
#
# MEASURED 2026-08-29: as the last line of the script instead, a single
# unprotected assignment above it took `set -e` with it, and deleting go.mod
# made this file exit 1 having printed no verdict at all. Fixing that
# assignment would fix that assignment; the promise is a property of the file.
# Scenarios verdict-on-abort, verdict-without-gomod.
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

# ------------------------------------------------------------- citations --
# A comment that shrinks a fact to "see TestFoo" is worth exactly as much as
# the pointer, and a renamed test leaves the pointer looking right. Every
# TestXxx named in a .go comment or in a .md file must be a test that exists.
#
# "Exists" is: the token appears on a non-comment line of some .go file. That
# also covers ordinary identifiers such as rings.TestIdents, which are not
# citations at all. BOUND: a token quoted inside a Go string literal counts as
# existing, and .sh files are outside the domain because the oracle plants test
# bodies into heredocs. BOUND, found by writing docs/gates.md: prose cannot use
# a PLACEHOLDER test name either, because nothing distinguishes one from a
# citation. That is the loud direction and it stays.
cite_scan() {
	find . -type f \( -name '*.go' -o -name '*.md' \) -not -path './.git/*' -print0 |
		xargs -0 awk -v want="$1" '
			function emit(s) {
				while (match(s, /Test[A-Z][A-Za-z0-9_]*/)) {
					print substr(s, RSTART, RLENGTH)
					s = substr(s, RSTART + RLENGTH)
				}
			}
			{
				comment = (FILENAME ~ /\.md$/) || ($0 ~ /^[ \t]*\/\//)
				if ((want == "cited") == comment) emit($0)
			}
		' | sort -u
}

missing="$(comm -23 <(cite_scan cited) <(cite_scan known) | tr '\n' ' ' | sed 's/ $//')"
if [ -z "$missing" ]; then
	record "citations" PASS "every cited test exists"
else
	record "citations" FAIL "cited but not defined anywhere: $missing"
	echo "--- citations FAILED: a comment or document names a test that does not exist ---" >&2
fi

# The hang timeout must exceed the ceiling, or a merely slow suite is killed by
# the timeout — which says only that it did not finish — instead of being
# diagnosed by the ceiling, which says something is waiting.
if [ "$SUITE_TIMEOUT_SECONDS" -gt "$SUITE_CEILING_SECONDS" ]; then
	record "bounds" PASS "hang timeout ${SUITE_TIMEOUT_SECONDS}s > ceiling ${SUITE_CEILING_SECONDS}s"
else
	record "bounds" FAIL "hang timeout ${SUITE_TIMEOUT_SECONDS}s does not exceed the ${SUITE_CEILING_SECONDS}s ceiling; a slow suite would be killed before the ceiling could diagnose it"
fi

# ---------------------------------------------------------------- toolchain --
step "build" go build ./...
step "vet" go vet ./...

# gofmt -l exits 0 whether or not it lists anything, so its output is the
# signal and its exit code is not.
fmt_out="$(gofmt -l . 2>&1)" || true
if [ -n "$fmt_out" ]; then
	record "gofmt" FAIL "unformatted: $(printf '%s' "$fmt_out" | tr '\n' ' ')"
else
	record "gofmt" PASS "all files formatted"
fi

# Enumerated, then cross-checked in both directions against the scripts the
# tree holds (scenarios unlinted-script, unlinted-shebang-script).
SHELL_SCRIPTS=(verify.sh scripts/test-verify.sh)

# shell_files prints every shell script in the tree, one per line, relative to
# the root: a regular file ending in .sh, OR one opening with a shell shebang.
#
# MEASURED 2026-08-29 by review: this used to key on the suffix alone while the
# comments around it described the domain two other ways, so all three
# disagreed and none matched the code; a scripts/preflight with a shebang and
# no extension was linted by nothing.
#
# DECISION 2026-08-29: a filesystem walk, not `git ls-files` — git is
# unavailable inside the oracle's copies of the tree, and a check that
# silently does nothing where it is being tested has no observer.
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
# under internal/gates are commands. The rc is captured rather than allowed to
# propagate, because `go list` failing is a measurable outcome of this step and
# "aborted at line N" is a worse diagnosis than the one it can give.
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
# Built, then executed. MEASURED 2026-08-29: `go run` collapses every non-zero
# child status to 1, which would make a gate REFUSING (2) indistinguishable
# from a gate reporting a violation (1). Scenarios gate-panic, gate-refuses.
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
		# A Go panic also exits 2. Both are a FAIL, but they are different
		# diagnoses, and the gates print a REFUSED line so the two can be told
		# apart.
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
# measured on this tree. Scenario test-cache.
suite_start=$(date +%s)
rc=0
suite_out="$(go test -race -count=1 -timeout "${SUITE_TIMEOUT_SECONDS}s" ./... 2>&1)" || rc=$?
suite_elapsed=$(($(date +%s) - suite_start))
if [ "$rc" -ne 0 ]; then
	record "unit-suite" FAIL "exit $rc after ${suite_elapsed}s"
	printf '\n--- unit-suite FAILED ---\n%s\n' "$suite_out" >&2
elif printf '%s' "$suite_out" | grep -q '(cached)'; then
	record "unit-suite" FAIL "go test reported a cached result; -count=1 was not in force, so the suite was not measured on this tree"
	printf '\n--- unit-suite was served from the test cache ---\n%s\n' "$suite_out" >&2
elif [ "$suite_elapsed" -gt "$SUITE_CEILING_SECONDS" ]; then
	record "unit-suite" FAIL "passed but took ${suite_elapsed}s, over the ${SUITE_CEILING_SECONDS}s ceiling"
	echo "--- unit-suite exceeded the T2 wall-clock ceiling: something is waiting ---" >&2
else
	record "unit-suite" PASS "${suite_elapsed}s, ceiling ${SUITE_CEILING_SECONDS}s, hang timeout ${SUITE_TIMEOUT_SECONDS}s"
fi

# ------------------------------------------------------------- self-oracle --
# See scripts/test-verify.sh for what this can and cannot see.
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
