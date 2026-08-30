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

# ------------------------------------------------------------- manifest --
# The expectation, stated where it is not the subject of any check it
# parameterises. See verify.manifest.sh for why it is a separate file; the
# short version is that four consecutive rounds found a guard whose domain came
# from the thing it guarded, and a domain like that can always be shrunk by
# editing that thing.
#
# This is a HARD refusal, before any row exists, because a row is something the
# manifest declares. A missing manifest is not a run with fewer rows.
MANIFEST="$ROOT/verify.manifest.sh"
if [ ! -r "$MANIFEST" ]; then
	echo "VERDICT: FAIL — $MANIFEST is missing or unreadable; the arbiter has no statement of what must be there, so nothing was measured." >&2
	exit 1
fi
# shellcheck source=verify.manifest.sh
. "$MANIFEST"
if ! manifest_problem="$(manifest_check)"; then
	echo "VERDICT: FAIL — $manifest_problem" >&2
	echo "Nothing was measured: an expectation that disagrees with itself cannot say what is missing." >&2
	exit 1
fi

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
#
# Enumerated in the manifest rather than here, since round 9: a checklist that
# lives beside the code it checks is deleted by the same edit.
REQUIRED_GATES=("${MANIFEST_GATES[@]}")

# The ROWS that must appear in the verdict table, for the same reason and
# against a defect measured 2026-08-30: the verdict printed
# `VERDICT: PASS (${#NAMES[@]} steps)`, a count DESCRIBED and never CHECKED.
# Replacing `step "vet" go vet ./...` with `true` produced
# `VERDICT: PASS (10 steps)` and nothing refused.
#
# That is the same class as the two findings above it, one level up again: the
# SET OF ROWS was a population with no non-vacuity check. It composed with the
# stubbed oracle rather than sitting beside it — README stated this exact bound
# and rested it on the oracle's scenarios, and the oracle turned out to be
# deletable. Neither half was wrong when it was written; the composition was
# never measured.
#
# Cross-checked in BOTH directions at the verdict (scenarios row-deleted,
# row-added), and refusing on an empty roster, because a universal gate is
# satisfied by emptying its own domain.
#
# ROUND 9, and this is the finding rather than a refinement of it: the list
# used to be written here, so B9's defeat was to delete a row's step AND its
# name in one file. MEASURED 2026-08-30 by review — eleven rows became ten,
# every remaining row was green, and four SC2034 findings sat in the tree the
# deleted gate would have caught. The names now come from the manifest, which
# is pinned from Go (internal/manifest), so the cheap edit is no longer the
# quiet one. Scenarios manifest-row-removed, manifest-count-lies,
# manifest-missing.
REQUIRED_ROWS=("${MANIFEST_ROWS[@]}")

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

# record NAME RESULT NOTE [COUNT] — the ONE place a row is written, and the one
# place PASS is decided.
#
# A PASS must carry COUNT: how many things the row examined. Absent,
# non-numeric or zero and the row is REWRITTEN to FAIL. This is the round-7
# structural change and it exists because three separate rows passed over an
# absent subject, in three consecutive review rounds, each found only where
# somebody happened to look:
#
#   the unit suite, with every test build-tagged out  (round 5, 22 files)
#   the oracle, replaced by `exit 0`                  (round 6, B7)
#   the ROW ROSTER, with a step call deleted          (round 7, measured here)
#
# All three inherited one default: `step()` recorded PASS from rc == 0, and a
# command with nothing to do exits 0. The fix is not another guard beside
# another row — it is that the default is now FAIL, and a row has to say what
# it looked at in order to pass.
#
# BOUND, and it is the design's real residual: nothing here can force COUNT to
# be DERIVED. A row that hard-codes `1` satisfies this completely. What closes
# that is external and is where the round's evidence actually lives — one
# oracle scenario per row that empties THAT row's domain and requires the row
# to go red. See the row-drive scenarios in scripts/test-verify.sh.
record() { # name result note [count]
	local name="$1" result="$2" note="${3:-}" count="${4:-}"
	if [ "$result" = PASS ]; then
		case "$count" in
		'' | *[!0-9]*)
			result=FAIL
			note="recorded PASS with no numeric domain size (got '$count'); a row that cannot say how many things it examined has measured nothing"
			;;
		*)
			if [ "$count" -lt 1 ]; then
				result=FAIL
				note="recorded PASS having examined 0 items; an empty domain is not a passing domain"
			fi
			;;
		esac
	fi
	NAMES+=("$name")
	RESULTS+=("$result")
	NOTES+=("$note")
	[ "$result" = PASS ] || FAILED=1
}

# step NAME COUNT -- command... — the exit-status rows, which can no longer
# pass on an exit status alone: COUNT is a second operand and record refuses
# a PASS without it.
#
# The detail column falls back to the domain size when the command printed
# nothing. B7's measurement is why: a stubbed oracle produced `verify-oracle
# PASS` with an EMPTY detail column, and an empty cell is the quietest thing a
# table can contain.
step() { # name count -- command...
	local name="$1" count="$2"
	shift 2
	local out rc=0 detail
	out="$("$@" 2>&1)" || rc=$?
	if [ "$rc" -eq 0 ]; then
		detail="$(printf '%s' "$out" | tail -1)"
		[ -n "$detail" ] || detail="$count item(s) in domain"
		record "$name" PASS "$detail" "$count"
	else
		record "$name" FAIL "exit $rc"
		printf '\n--- %s FAILED (exit %s) ---\n%s\n' "$name" "$rc" "$out" >&2
	fi
}

command -v go >/dev/null 2>&1 || {
	echo "VERDICT: FAIL — the go toolchain is not on PATH; nothing was measured." >&2
	exit 1
}

# ------------------------------------------------------------ self-check --
# record()'s guard, driven IN PROCESS, on every run, before any real row.
#
# ROUND 9, B11: the guard was proven only by two oracle scenarios, and deleting
# the guard together with those two scenarios and the plant they edit left the
# arbiter reporting PASS. That is the round's whole class — a witness that dies
# with its subject — and it is why this row exists here rather than only in the
# oracle. Deleting the case block below now reddens a row in the same run,
# with no oracle involved. Scenario self-check-guard-deleted.
#
# It runs FIRST so the probe rows it records are the only rows in flight; it
# discards them and restores FAILED before recording its own verdict. Both
# directions are driven: three shapes that must be refused and one that must
# survive, because a guard that refuses everything measures nothing either.
self_check() {
	local bad="" cases=0
	[ "${#NAMES[@]}" -eq 0 ] || {
		record "self-check" FAIL "self-check ran after ${#NAMES[@]} row(s); it cannot discard its probes safely"
		return
	}

	record "__probe__" PASS "no count at all"
	cases=$((cases + 1))
	[ "${RESULTS[cases - 1]}" = FAIL ] || bad="$bad a PASS with no count survived;"

	record "__probe__" PASS "count is zero" 0
	cases=$((cases + 1))
	[ "${RESULTS[cases - 1]}" = FAIL ] || bad="$bad a PASS over an empty domain survived;"

	record "__probe__" PASS "count is not a number" 7x
	cases=$((cases + 1))
	[ "${RESULTS[cases - 1]}" = FAIL ] || bad="$bad a PASS with a non-numeric count survived;"

	# The preservation control. Without it this row is satisfied by a record()
	# that rewrites every PASS to FAIL, which would refuse the whole tree and
	# still look like a working guard from here.
	record "__probe__" PASS "an honest counted pass" 1
	cases=$((cases + 1))
	[ "${RESULTS[cases - 1]}" = PASS ] || bad="$bad a correctly counted PASS was rejected;"

	NAMES=()
	RESULTS=()
	NOTES=()
	FAILED=0

	if [ -n "$bad" ]; then
		record "self-check" FAIL "record() is not enforcing its contract:$bad"
		echo "--- self-check FAILED: the choke point that decides every PASS does not refuse an uncounted one ---" >&2
	else
		record "self-check" PASS "record() refused $((cases - 1)) uncountable PASS shape(s) and preserved a counted one" "$cases"
	fi
}
self_check

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
#   8. The token must start a word: a citation is matched only where the
#      character before it is not a letter, digit or underscore. Without that
#      an ordinary camelCase identifier mentioned in prose reads as a citation
#      of a test that does not exist. The direction it still cannot see is a
#      token that starts a word but is part of a longer WORD-BOUNDED name, and
#      that one is indistinguishable from a citation by any textual rule.
#      Scenarios citation-embedded-identifier, citation-word-start.
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
			function emit(s,   pre) {
				while (match(s, /(Test|Benchmark|Fuzz|Example)[_A-Z][A-Za-z0-9_]*/)) {
					# The token must START a word. Without this the pattern
					# matches INSIDE an identifier: MEASURED 2026-08-30, the
					# comment on isTestFuncName was read as citing a test
					# called TestFuncName, and the run failed over a token
					# nobody wrote. Bound 8.
					pre = (RSTART > 1) ? substr(s, RSTART - 1, 1) : " "
					if (pre !~ /[A-Za-z0-9_]/) {
						print substr(s, RSTART, RLENGTH)
					}
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
	record "citations" PASS "$cited_n cited token(s), all declared among $known_n" "$cited_n"
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
	record "bounds" PASS "hang timeout ${SUITE_TIMEOUT_SECONDS}s > ceiling ${SUITE_CEILING_SECONDS}s, and the one suite invocation expands SUITE_ARGS" "$bounds_src"
fi

# ---------------------------------------------------------------- toolchain --
# The Go domain, derived once and handed to the rows that examine it. MEASURED
# 2026-08-30: `go build ./...` over zero packages exits 0, so build had no
# guard of its own and was held only by its neighbours reddening — adjacency,
# not a data dependency. `go vet ./...` over zero packages exits 1, which is
# why the two behaved differently under the same caller and why grouping them
# as one adjudication in round 5 was wrong.
go_pkgs_n="$(go list ./... 2>/dev/null | grep -c . || true)"
go_files_n="$(find . -name '*.go' -not -path './.git/*' -printf 'x\n' | grep -c . || true)"

step "build" "$go_pkgs_n" go build ./...
step "vet" "$go_pkgs_n" go vet ./...

# gofmt -l exits 0 whether or not it lists anything, so its output is the
# signal and its exit code is not.
fmt_out="$(gofmt -l . 2>&1)" || true
if [ -n "$fmt_out" ]; then
	record "gofmt" FAIL "unformatted: $(printf '%s' "$fmt_out" | tr '\n' ' ')"
else
	record "gofmt" PASS "all $go_files_n .go file(s) formatted" "$go_files_n"
fi

# Enumerated in the manifest, then cross-checked in both directions against the
# scripts the tree holds (scenarios unlinted-script, unlinted-shebang-script).
SHELL_SCRIPTS=("${MANIFEST_SHELL_SCRIPTS[@]}")

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
		step "shellcheck" "${#linted[@]}" shellcheck -S warning "${linted[@]}"
	fi
else
	record "shellcheck" FAIL "shellcheck is not installed; the shell scripts were not linted"
fi

# -------------------------------------------------------------- gate roster --
# Structural, not a glob over directory names: ask the go tool which packages
# under internal/gates are commands. The rc is captured rather than allowed to
# propagate, because `go list` failing is a measurable outcome of this step and
# "aborted at line N" is a worse diagnosis than the one it can give.
#
# N6, round 8: stderr used to be merged into stdout here, so a `go` warning
# line was passed through the same sed as an import path and became a gate
# name. A diagnostic that can be read as a measurement is worse than a missing
# one. The two streams are separated, and only stdout is parsed.
roster_rc=0
roster_err="$BIN/gate-roster.err"
roster_raw="$(go list -f '{{if eq .Name "main"}}{{.ImportPath}}{{end}}' ./internal/gates/... 2>"$roster_err")" || roster_rc=$?
discovered="$(printf '%s\n' "$roster_raw" | sed -n 's|^\(.*/\)\{0,1\}\([a-zA-Z0-9_.-]\{1,\}\)$|\2|p' | sort | tr '\n' ' ' | sed 's/ $//')"
expected="$(printf '%s\n' "${REQUIRED_GATES[@]}" | sort | tr '\n' ' ' | sed 's/ $//')"
if [ "$roster_rc" -ne 0 ]; then
	record "gate-roster" FAIL "go list could not enumerate the gates (exit $roster_rc); the roster is UNMEASURED"
	printf '\n--- gate-roster could not be measured ---\n%s\n%s\n' "$roster_raw" "$(cat "$roster_err" 2>/dev/null || true)" >&2
elif [ "$discovered" = "$expected" ]; then
	record "gate-roster" PASS "gates present: $discovered" "${#REQUIRED_GATES[@]}"
else
	record "gate-roster" FAIL "required [$expected] but tree has [$discovered]"
	echo "--- gate-roster FAILED: the set of gate commands does not match MANIFEST_GATES in verify.manifest.sh ---" >&2
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
	# The gate's own domain size, read out of the line it prints. Both gates
	# already REFUSE on an empty domain (t1 rule D, t2 rule B), so this is the
	# second reading of a fact they already enforce — and that is the point of
	# a choke point: the row cannot pass without stating it, whether or not the
	# subject also checks itself.
	0)
		gate_n="$(printf '%s' "$out" | sed -n 's/.*[^0-9]\([0-9][0-9]*\) \(transitive dep(s)\|test file(s)\) checked.*/\1/p' | tail -1)"
		record "$g" PASS "$(printf '%s' "$out" | tail -1)" "$gate_n"
		;;
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

# The population that actually matters, and the one the package check above
# cannot see. MEASURED 2026-08-30 by review: with the package check in force,
# ten of twenty-two test files could be build-tagged out — keeping one file per
# package — taking the suite from 161 declared tests to 61 with every row
# green. Package granularity was exactly the boundary: including wire's only
# test file DID go red.
#
# So: every test function DECLARED in a _test.go file must appear in
# `go test -list`. internal/tools/testroster derives the declarations by
# walking the filesystem and parsing, which is what makes it independent of the
# build constraints that hid those ten files. It exits non-zero on an empty
# roster rather than printing nothing, because "every declared test ran" is
# vacuously true of no declarations at all.
#
# BOUNDS, stated rather than a completeness claim:
#   - `go test -list` honours build constraints and the walk does not, so this
#     is exact only while every _test.go builds on the host running it. The
#     tree has no platform-conditional test file that fails to build here
#     today; a _windows_test.go would read as declared-and-not-listed.
#
# ROUND 9 closes the bound this comment used to open with — "a test DELETED,
# rather than disabled, leaves both sides agreeing" — and it is worth saying
# how, because the reason it stood for two rounds was not difficulty. Both
# sides were DERIVED FROM THE TREE, so deleting a test moved both of them at
# once. MIN_DECLARED_TESTS is a literal in the manifest, derived from nothing,
# and a literal does not move when the tree does. Scenario
# min-declared-tests-floor.
roster_out=""
roster_rc2=0
roster_out="$(go run ./internal/tools/testroster "$ROOT" 2>&1)" || roster_rc2=$?
declared_n=0
undeclared=""
unlisted=""
if [ "$roster_rc2" -eq 0 ]; then
	listed_f="$(mktemp)"
	declared_f="$(mktemp)"
	printf '%s\n' "$roster_out" | LC_ALL=C sort -u >"$declared_f"
	go test -list '.*' ./... 2>/dev/null | grep -E '^(Test|Benchmark|Fuzz|Example)' | LC_ALL=C sort -u >"$listed_f" || true
	declared_n="$(grep -c . <"$declared_f" || true)"
	unlisted="$(LC_ALL=C comm -23 "$declared_f" "$listed_f" | tr '\n' ' ' | sed 's/ $//')"
	undeclared="$(LC_ALL=C comm -13 "$declared_f" "$listed_f" | tr '\n' ' ' | sed 's/ $//')"
	rm -f "$listed_f" "$declared_f"
fi

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
elif [ "$roster_rc2" -ne 0 ]; then
	record "unit-suite" FAIL "the declared-test roster is UNMEASURED (testroster exit $roster_rc2): $(printf '%s' "$roster_out" | tail -1)"
elif [ -n "$unlisted" ]; then
	record "unit-suite" FAIL "declared but never run: $unlisted"
	printf '\n--- unit-suite: these tests are declared in a _test.go file and go test did not list them ---\n%s\n' "$unlisted" >&2
elif [ -n "$undeclared" ]; then
	# The other direction, and it is an INSTRUMENT failure rather than a suite
	# failure: go test found a test the walk did not. Reported so that the
	# comparison cannot quietly become one-sided.
	record "unit-suite" FAIL "go test listed test(s) the declaration walk did not find: $undeclared"
elif [ "$declared_n" -lt "$MIN_DECLARED_TESTS" ]; then
	record "unit-suite" FAIL "$declared_n declared test(s), below the floor of $MIN_DECLARED_TESTS in verify.manifest.sh; tests were deleted, and every check above this one derives its population from the tree and so moved with them"
else
	record "unit-suite" PASS "${suite_elapsed}s, ceiling ${SUITE_CEILING_SECONDS}s, $declared_n declared test(s) all ran across $tested_n package(s)" "$declared_n"
fi

# ------------------------------------------------------------- self-oracle --
# See scripts/test-verify.sh for what this can and cannot see.
#
# The expectation is the MANIFEST'S scenario list, and the oracle has to
# account for every name in it BY NAME.
#
# The history is worth keeping because the previous two versions of this block
# were each written as the closure of the one before, and each was defeated the
# same way. Round 6: `verify-oracle PASS` on an oracle replaced by `exit 0`,
# because the only thing checking the oracle was the oracle. Round 7 answered
# that by counting `sc_` definitions HERE — which is still a count taken from
# the file being checked, so round 8 replaced the oracle with 45 empty
# `sc_fakeN(){}` stubs plus one echo and got `VERDICT: PASS (11 steps)`.
#
# A count over the subject can always be satisfied by the subject. Names from
# the manifest cannot: a stub now has to reproduce fifty-three specific
# scenario names, none of which are written in the file it replaced.
#
# N5, corrected: the comment here used to say the total stub — `#!/bin/sh` +
# `exit 0` — was closed by "no sc_ definitions → expected 0 → refused as an
# empty domain". It is not. That stub prints nothing, so the branch that fires
# is the one below testing for a missing `ORACLE PASS: <n> scenarios` line, and
# scenario oracle-stub-total asserts exactly that diagnosis. Naming the wrong
# branch is the same defect as a wrong line number: it survives because the
# scenario passes either way.
#
# BOUND, and it is real: a stub that READS THE MANIFEST and prints a correct
# RESULT line per name defeats this. That is strictly harder than the stub that
# defeated round 7 — which needed no knowledge of anything — and it is named
# here rather than argued away. What actually stops it is the same thing that
# stops any coordinated edit: somebody reading the diff.
if [ "$INNER" -eq 0 ]; then
	if [ -x "$ROOT/scripts/test-verify.sh" ]; then
		orc_rc=0
		orc_out="$("$ROOT/scripts/test-verify.sh" 2>&1)" || orc_rc=$?
		oracle_reported="$(printf '%s\n' "$orc_out" | sed -n 's/^ORACLE PASS: \([0-9][0-9]*\) scenarios.*/\1/p' | tail -1)"
		accounted=0
		unaccounted=""
		for s in "${MANIFEST_SCENARIOS[@]}"; do
			if printf '%s\n' "$orc_out" | grep -qE "^[[:space:]]*RESULT $s PASS[[:space:]]*$"; then
				accounted=$((accounted + 1))
			else
				unaccounted="$unaccounted $s"
			fi
		done
		if [ "$orc_rc" -ne 0 ]; then
			record "verify-oracle" FAIL "exit $orc_rc"
			printf '\n--- verify-oracle FAILED (exit %s) ---\n%s\n' "$orc_rc" "$orc_out" >&2
		elif [ -z "$oracle_reported" ]; then
			record "verify-oracle" FAIL "the oracle exited 0 but printed no 'ORACLE PASS: <n> scenarios' line; its answer is not the account of a run"
			printf '\n--- verify-oracle produced no verdict line ---\n%s\n' "$orc_out" >&2
		elif [ -n "$unaccounted" ]; then
			record "verify-oracle" FAIL "the oracle reported no passing result for scenario(s)$unaccounted, which verify.manifest.sh requires; $accounted of ${#MANIFEST_SCENARIOS[@]} were accounted for by name"
			printf '\n--- verify-oracle did not account for every declared scenario ---\n%s\n' "$orc_out" >&2
		elif [ "$oracle_reported" != "${#MANIFEST_SCENARIOS[@]}" ]; then
			record "verify-oracle" FAIL "the oracle reports $oracle_reported scenario(s); verify.manifest.sh declares ${#MANIFEST_SCENARIOS[@]}"
			printf '\n--- verify-oracle ran a different set than the manifest declares ---\n%s\n' "$orc_out" >&2
		else
			record "verify-oracle" PASS "$(printf '%s\n' "$orc_out" | tail -1)" "$accounted"
		fi
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

# The roster cross-check. --inner does not run the oracle, so the expected set
# is the declared one minus verify-oracle in that mode; the row is expected
# exactly when it is meant to have run.
expected_rows=()
for r in "${REQUIRED_ROWS[@]}"; do
	if [ "$r" = verify-oracle ] && [ "$INNER" -eq 1 ]; then continue; fi
	expected_rows+=("$r")
done
rows_expected="$(printf '%s\n' "${expected_rows[@]}" | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')"
rows_present="$(printf '%s\n' "${NAMES[@]}" | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')"

if [ "${#REQUIRED_ROWS[@]}" -eq 0 ]; then
	echo "VERDICT: FAIL — MANIFEST_ROWS is empty, so the roster check measured nothing." >&2
	VERDICT_PRINTED=1
	exit 1
fi
if [ "$rows_expected" != "$rows_present" ]; then
	echo "VERDICT: FAIL — the rows recorded are not the rows required." >&2
	echo "  required: [$rows_expected]" >&2
	echo "  recorded: [$rows_present]" >&2
	VERDICT_PRINTED=1
	exit 1
fi

VERDICT_PRINTED=1
if [ "$FAILED" -eq 0 ]; then
	echo "VERDICT: PASS (${#NAMES[@]} steps)"
	exit 0
fi
echo "VERDICT: FAIL"
exit 1
