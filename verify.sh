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

# This file's own path, resolved AFTER the cd above, because the bounds step
# reads it. "$0" is what the caller typed and is relative to the caller's
# directory, not to this one: MEASURED 2026-08-30, invoking `library/verify.sh`
# from the parent recorded `bounds FAIL … is not readable`, a false negative
# produced entirely by how the script was invoked. Scenario
# invoked-by-relative-path.
SELF="$ROOT/$(basename "$0")"

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

# The flags `go test` actually runs with, in ONE array, so the constant the
# bounds step reads is the constant the suite uses. Scenarios test-cache,
# race-detector, hang-bounded, bounds-ordering, suite-timeout-detached.
SUITE_ARGS=(-race -count=1 -timeout "${SUITE_TIMEOUT_SECONDS}s")

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
# The rule, stated as the code implements it rather than as a summary of it:
#
#   CITED  = every Test/Benchmark/Fuzz/Example token in the part of a .go line
#            that follows the first "//" NOT preceded by ":", or anywhere on a
#            line of a .md file.
#   KNOWN  = every such token that a .go line DECLARES, i.e. a line beginning
#            "func"/"var"/"const"/"type" followed by the token. That admits the
#            exported maps TestIdents and TestRefusedIdents, which are
#            identifiers rather than citations.
#   VERDICT = every CITED token must be KNOWN.
#
# BOUNDS, and there are six because two were not enough — each one is a shape
# this cannot see, not a shape it forgives:
#   1. Block comments. A /* ... */ citation is invisible; nothing in the tree
#      uses them and an awk state machine is the price of covering them.
#   2. A declaration written inside a Go raw string literal counts as a
#      declaration. internal/gates/t2 embeds test bodies that way on purpose.
#   3. .sh files are outside the domain entirely, because the oracle plants
#      test bodies into heredocs.
#   4. Prose cannot use a PLACEHOLDER name: nothing distinguishes one from a
#      citation. That is the loud direction and it stays. MEASURED three times
#      now, each time against a sentence written to DESCRIBE this check —
#      twice on 2026-08-29 and again on 2026-08-30, when the bound-7 paragraph
#      quoted an example URL ending in a test-shaped name.
#   5. Import aliasing and shadowing are not resolved; this is textual.
#   6. "No unseen shape is present in the tree" is a measurement at one head,
#      never a property. A new file reintroduces one silently.
#   7. The ":" rule covers a URL scheme and nothing else. A "//" inside an
#      ordinary string literal with no colon before it ("a//b") still reads as
#      a comment, and a token after it is still cited. That direction is a
#      FALSE POSITIVE — a build that fails for a reason that is not true — and
#      it is left visible on purpose: narrowing the comment match back toward
#      column 0 would trade it for the false negatives the widening removed.
#      Scenarios citation-url, citation-after-url.
cite_scan() {
	find . -type f \( -name '*.go' -o -name '*.md' \) -not -path './.git/*' -print0 |
		xargs -0 awk -v want="$1" '
			function emit(s) {
				while (match(s, /(Test|Benchmark|Fuzz|Example)[_A-Z][A-Za-z0-9_]*/)) {
					print substr(s, RSTART, RLENGTH)
					s = substr(s, RSTART + RLENGTH)
				}
			}
			want == "cited" {
				if (FILENAME ~ /\.md$/) { emit($0); next }
				# The first "//" that is not a URL scheme separator. Taking
				# index($0,"//") outright reads the tail of an https:// string
				# literal as a comment and fails the run on a token nobody
				# cited (bound 7).
				rest = $0; off = 0
				while (match(rest, /\/\//)) {
					pos = off + RSTART
					if (pos > 1 && substr($0, pos - 1, 1) == ":") {
						off = pos + 1
						rest = substr($0, off + 1)
						continue
					}
					emit(substr($0, pos + 2))
					break
				}
				next
			}
			FILENAME ~ /\.go$/ && match($0, /^(func|var|const|type)[ \t]+(Test|Benchmark|Fuzz|Example)[_A-Z][A-Za-z0-9_]*/) {
				tok = substr($0, RSTART, RLENGTH)
				sub(/^(func|var|const|type)[ \t]+/, "", tok)
				print tok
			}
		' | sort -u
}

cited_f="$(mktemp)"
known_f="$(mktemp)"
cite_scan cited >"$cited_f"
cite_scan known >"$known_f"
cited_n="$(wc -l <"$cited_f" | tr -d ' ')"
known_n="$(wc -l <"$known_f" | tr -d ' ')"
missing="$(comm -23 "$cited_f" "$known_f" | tr '\n' ' ' | sed 's/ $//')"
rm -f "$cited_f" "$known_f"

# Non-vacuity, both sides. A universal claim over an empty domain is a PASS
# that measured nothing, and the cited side is exactly the side this project's
# method keeps shrinking: the sweep replaced facts with pointers.
if [ "$known_n" -eq 0 ] || [ "$cited_n" -eq 0 ]; then
	record "citations" FAIL "measured nothing: $cited_n cited token(s), $known_n declared; a scan that finds no domain is not a passing scan"
elif [ -z "$missing" ]; then
	record "citations" PASS "$cited_n cited token(s), all declared among $known_n"
else
	record "citations" FAIL "cited but never declared: $missing"
	echo "--- citations FAILED: a comment or document names a test that is not declared anywhere ---" >&2
fi

# Three things, because any two of them are adjacency rather than a data
# dependency: the hang timeout must exceed the ceiling, the flags array must
# carry that timeout, AND the suite invocation must expand that array.
#
# The third matters more than it looks: an invocation that stops expanding
# SUITE_ARGS takes -count=1 with it as well, so it defeats the cached-result
# check too, and every row stays green while this one reports that the suite
# runs with the checked flags.
#
# BOUND, and it is a real one: this checks the SPELLING of the one invocation
# below. A second `go test` elsewhere in this file, or the array under another
# name, is outside it. Scenarios suite-timeout-detached, suite-args-detached.
bounds_src=""
if [ -r "$SELF" ]; then bounds_src="$(grep -c 'go test "${SUITE_ARGS\[@\]}" \./\.\.\.' "$SELF" || true)"; fi
if [ "$SUITE_TIMEOUT_SECONDS" -le "$SUITE_CEILING_SECONDS" ]; then
	record "bounds" FAIL "hang timeout ${SUITE_TIMEOUT_SECONDS}s does not exceed the ${SUITE_CEILING_SECONDS}s ceiling; a slow suite would be killed before the ceiling could diagnose it"
elif [[ " ${SUITE_ARGS[*]} " != *" -timeout ${SUITE_TIMEOUT_SECONDS}s "* ]]; then
	record "bounds" FAIL "the suite flags do not carry -timeout ${SUITE_TIMEOUT_SECONDS}s, so the checked constant is not the one in force: ${SUITE_ARGS[*]}"
elif [ -z "$bounds_src" ]; then
	# A check that reads its own source and cannot read it has not measured
	# anything, and must say so rather than fall through to the PASS.
	record "bounds" FAIL "$SELF is not readable, so whether the suite runs with these flags is UNMEASURED"
elif [ "$bounds_src" -ne 1 ]; then
	record "bounds" FAIL "found $bounds_src suite invocation(s) expanding SUITE_ARGS, expected exactly 1; the checked constants are not the ones in force"
else
	record "bounds" PASS "hang timeout ${SUITE_TIMEOUT_SECONDS}s > ceiling ${SUITE_CEILING_SECONDS}s, and the one suite invocation expands SUITE_ARGS"
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
#
# MEASURED 2026-08-30: `go test ./...` exits 0 on a tree with no test files at
# all, printing "? pkg [no test files]". So the exit status cannot tell a suite
# that passed from a suite that did not run, and adding `ignore` to the build
# constraint of all 22 _test.go files took this whole script to
# "VERDICT: PASS (10 steps)" with zero tests executed — t2 still counted 22
# files, because it walks the filesystem, and this row still said 0s, because a
# ceiling reads absent as fast. Hence the domain check below.
#
# It is keyed on the POPULATION rather than on a floor: a floor is a number
# somebody has to maintain, and it cannot see a single package's tests being
# disabled. Scenarios suite-tests-disabled, suite-one-package-disabled.
suite_start=$(date +%s)
rc=0
suite_out="$(go test "${SUITE_ARGS[@]}" ./... 2>&1)" || rc=$?
suite_elapsed=$(($(date +%s) - suite_start))
# Every directory holding a _test.go file, as the import path go test prints.
module="$(go list -m 2>/dev/null || true)"
tested_dirs="$(find . -name '*_test.go' -not -path './.git/*' -printf '%h\n' | sort -u)"
missing=""
tested_n=0
while IFS= read -r d; do
	[ -n "$d" ] || continue
	tested_n=$((tested_n + 1))
	case "$d" in
	.) ip="$module" ;;
	*) ip="$module/${d#./}" ;;
	esac
	if printf '%s\n' "$suite_out" | grep -qE "^\?[[:space:]]+${ip//./\\.}[[:space:]]+\[no test files\]"; then
		missing="$missing $ip"
	fi
done <<EOF
$tested_dirs
EOF
if [ "$rc" -ne 0 ]; then
	record "unit-suite" FAIL "exit $rc after ${suite_elapsed}s"
	printf '\n--- unit-suite FAILED ---\n%s\n' "$suite_out" >&2
elif printf '%s' "$suite_out" | grep -q '(cached)'; then
	record "unit-suite" FAIL "go test reported a cached result; -count=1 was not in force, so the suite was not measured on this tree"
	printf '\n--- unit-suite was served from the test cache ---\n%s\n' "$suite_out" >&2
elif [ "$suite_elapsed" -gt "$SUITE_CEILING_SECONDS" ]; then
	record "unit-suite" FAIL "passed but took ${suite_elapsed}s, over the ${SUITE_CEILING_SECONDS}s ceiling"
	echo "--- unit-suite exceeded the T2 wall-clock ceiling: something is waiting ---" >&2
elif [ -z "$module" ] || [ "$tested_n" -eq 0 ]; then
	# The two ways this row's own domain check can fail to be computed. Both
	# are a refusal, because a comparison against an empty population passes
	# for the same reason a suite with no tests does.
	record "unit-suite" FAIL "the suite exited 0, but its domain is UNMEASURED (module '$module', $tested_n director(ies) holding a _test.go file)"
elif ! printf '%s\n' "$suite_out" | grep -q '^ok[[:space:]]'; then
	record "unit-suite" FAIL "the suite exited 0 but reported no 'ok' package line; its output was not the account of a run"
	printf '\n--- unit-suite produced no ok line ---\n%s\n' "$suite_out" >&2
elif [ -n "$missing" ]; then
	record "unit-suite" FAIL "exited 0, but package(s)${missing} hold a _test.go file and ran no test"
	printf '\n--- unit-suite: these packages have test files that did not run ---\n%s\n%s\n' "$missing" "$suite_out" >&2
else
	record "unit-suite" PASS "${suite_elapsed}s, ceiling ${SUITE_CEILING_SECONDS}s, $tested_n package(s) with tests all ran"
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
