# shellcheck shell=bash
#
# verify.manifest.sh — what MUST be there. Declarations only; no logic that
# measures anything, and nothing here is derived from the files it describes.
#
# WHY THIS FILE EXISTS (round 9). Four consecutive review rounds found the same
# defect, one level up each time, and the cause was never carelessness: every
# guard derived its expectation from the thing it was guarding.
#
#   round 5  the unit suite's population came from the filesystem it checked
#   round 6  the oracle's expected count came from a grep over the oracle
#   round 7  the row roster lived in verify.sh, beside the rows
#   round 8  the row-coverage check read that roster back out of verify.sh
#
# Each had a non-vacuity floor and EVERY FLOOR WAS ZERO. Zero is the one value
# a domain cannot reach by deletion, so shrinking a population by one was
# invisible in all four. MEASURED 2026-08-30 by review: deleting the shellcheck
# gate — its step, its roster entry and its two scenarios — produced
# "VERDICT: PASS (10 steps)" with four live SC2034 findings in the tree.
#
# So the expectation is stated HERE, where it is not the subject of any check
# it parameterises, in three layers:
#
#   1. names, listed literally, sourced by verify.sh AND by the oracle;
#   2. a literal count beside each list, so removing a name without editing the
#      count beside it is a refusal — one edit is not enough even in this file;
#   3. a Go pin, internal/manifest, in another language and another directory,
#      which asserts these names and these numbers. It runs inside the unit
#      suite, whose own population is floored below.
#
# THE CLAIM, AND ITS BOUND. No edit confined to a SINGLE FILE can shrink the
# arbiter's population. That is not "cannot be shrunk": editing this file and
# the Go pin together still does it, and no mechanism in a repository can stop
# that. The regress terminates at a person reading a diff, and the whole point
# of this file is that the diff is one line, in a file whose entire content is
# the expectation, rather than eleven lines spread through the code that
# happens to implement it.

# The rows that must appear in the verdict table.
MANIFEST_ROWS=(
	self-check
	citations
	bounds
	build
	vet
	gofmt
	shellcheck
	gate-roster
	t1
	t2
	unit-suite
	verify-oracle
)
MANIFEST_ROWS_N=12

# The gate commands under internal/gates that must exist and must run.
MANIFEST_GATES=(
	t1
	t2
)
MANIFEST_GATES_N=2

# The shell scripts that must be linted. Cross-checked in both directions
# against a filesystem walk (scenarios unlinted-script, unlinted-shebang-script).
MANIFEST_SHELL_SCRIPTS=(
	verify.sh
	verify.manifest.sh
	scripts/test-verify.sh
)
MANIFEST_SHELL_SCRIPTS_N=3

# The floor under the unit suite's declared-test population.
#
# This is the operand round 7 said could not exist. Its bound then was: "a test
# DELETED, rather than disabled, leaves both sides agreeing" — true, because
# both sides were derived from the tree. A literal floor is not derived from
# anything, so a deleted test moves the measurement and not the floor.
#
# It is a FLOOR, not an equality: adding tests must not require an edit here.
MIN_DECLARED_TESTS=169

# The oracle's scenarios. The oracle no longer holds this list; it cross-checks
# its sc_* functions against this file, and verify.sh requires the oracle's
# output to account for every name here BY NAME.
MANIFEST_SCENARIOS=(
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
	hang-bounded
	bounds-ordering
	suite-timeout-detached
	stale-citation
	citation-trailing
	citation-underscore
	citation-whitewash
	citation-vacuous
	citation-url
	citation-after-url
	invoked-by-relative-path
	suite-args-detached
	suite-tests-disabled
	suite-one-package-disabled
	suite-domain-unmeasured-module
	suite-domain-unmeasured-walk
	suite-files-disabled-partial
	suite-roster-unmeasured
	record-refuses-uncounted-pass
	record-refuses-zero-count
	row-deleted
	row-added
	oracle-stub-total
	oracle-stub-partial
	citation-embedded-identifier
	citation-word-start
	go-domain-empty
	manifest-missing
	manifest-row-removed
	manifest-count-lies
	manifest-scenario-removed
	self-check-guard-deleted
	min-declared-tests-floor
	oracle-names-fabricated
)
MANIFEST_SCENARIOS_N=53

# manifest_check — layer 2, run by every reader of this file BEFORE it is
# trusted. A list that has been shortened without its count being edited, or a
# list that has been emptied, is a refusal rather than a smaller domain.
#
# It prints one line and returns non-zero on failure; it does not exit, because
# its two callers report a refusal in two different formats.
manifest_check() {
	local bad=""
	[ "${#MANIFEST_ROWS[@]}" -eq "$MANIFEST_ROWS_N" ] ||
		bad="$bad MANIFEST_ROWS has ${#MANIFEST_ROWS[@]} name(s), MANIFEST_ROWS_N says $MANIFEST_ROWS_N;"
	[ "${#MANIFEST_GATES[@]}" -eq "$MANIFEST_GATES_N" ] ||
		bad="$bad MANIFEST_GATES has ${#MANIFEST_GATES[@]} name(s), MANIFEST_GATES_N says $MANIFEST_GATES_N;"
	[ "${#MANIFEST_SHELL_SCRIPTS[@]}" -eq "$MANIFEST_SHELL_SCRIPTS_N" ] ||
		bad="$bad MANIFEST_SHELL_SCRIPTS has ${#MANIFEST_SHELL_SCRIPTS[@]} name(s), MANIFEST_SHELL_SCRIPTS_N says $MANIFEST_SHELL_SCRIPTS_N;"
	[ "${#MANIFEST_SCENARIOS[@]}" -eq "$MANIFEST_SCENARIOS_N" ] ||
		bad="$bad MANIFEST_SCENARIOS has ${#MANIFEST_SCENARIOS[@]} name(s), MANIFEST_SCENARIOS_N says $MANIFEST_SCENARIOS_N;"
	# An empty list is the shape every one of the four rounds above ended in.
	[ "$MANIFEST_ROWS_N" -ge 1 ] || bad="$bad MANIFEST_ROWS_N is not positive;"
	[ "$MANIFEST_GATES_N" -ge 1 ] || bad="$bad MANIFEST_GATES_N is not positive;"
	[ "$MANIFEST_SHELL_SCRIPTS_N" -ge 1 ] || bad="$bad MANIFEST_SHELL_SCRIPTS_N is not positive;"
	[ "$MANIFEST_SCENARIOS_N" -ge 1 ] || bad="$bad MANIFEST_SCENARIOS_N is not positive;"
	[ "$MIN_DECLARED_TESTS" -ge 1 ] || bad="$bad MIN_DECLARED_TESTS is not positive;"
	if [ -n "$bad" ]; then
		printf 'the manifest does not agree with itself:%s\n' "$bad"
		return 1
	fi
	return 0
}
