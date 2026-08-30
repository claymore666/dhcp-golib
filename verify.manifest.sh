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
	doc-numbers
	gate-roster
	t1
	t2
	unit-suite
	verify-oracle
)
MANIFEST_ROWS_N=13

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
	scripts/sweep-doc-numbers.sh
)
MANIFEST_SHELL_SCRIPTS_N=4

# The unit suite's declared-test population, stated rather than derived.
#
# This is the operand round 7 said could not exist. Its bound then was: "a test
# DELETED, rather than disabled, leaves both sides agreeing" — true, because
# both sides were derived from the tree. A literal is not derived from
# anything, so a deleted test moves the measurement and not this number.
#
# ROUND 11: it used to say "It is a FLOOR, not an equality: adding tests must
# not require an edit here." MEASURED 2026-08-30 by review: nothing in the tree
# raises it, so its protection ERODES MONOTONICALLY with every test added.
# Today's margin is zero — 169 against 169 — which is the strongest this
# operand will ever be. At 250 declared tests, 81 could be deleted with nothing
# going red and no instrument having noticed the decay. Three of the four
# manifest lists force their own maintenance; this one asked to be remembered,
# which is the property the whole design exists to remove.
#
# It is now a BAND, enforced by verify.sh in BOTH directions: below it is
# "tests were deleted", above MIN + MAX_DECLARED_MARGIN is "raise this number
# to N". Scenarios min-declared-tests-floor and min-declared-tests-margin.
#
# The Go pin holds a separate literal as a low-water mark, `>=` only. That one
# is NOT maintained in step and is not meant to be: it exists so that lowering
# the number here cannot go below a level somebody once measured.
MIN_DECLARED_TESTS=171

# How far above MIN_DECLARED_TESTS the tree may drift before the row refuses.
#
# It is not zero, and the reason is a measurement rather than a preference: an
# oracle scenario plants Go tests into its copy of the tree, so under a strict
# equality every such scenario fails the unit-suite row it is not testing.
# MEASURED 2026-08-30 over scripts/test-verify.sh: the largest number of test
# functions any one scenario plants is 1 (sc_race_detector, sc_hang_bounded,
# sc_ceiling_tree's TestBusyLoop, sc_min_declared_tests_margin).
#
# BOUND, stated rather than claimed away: erosion is CAPPED at this number, not
# eliminated. One test may be added without anyone raising MIN_DECLARED_TESTS;
# the second one fails the row and names the number to write. And a change that
# adds one test and deletes another is invisible to both edges — the band
# measures a population size, not its membership.
MAX_DECLARED_MARGIN=1

# The wall-clock floor, in seconds, under the oracle's own run.
#
# ROUND 11, and it is the only operand here that binds WORK rather than
# reporting. Everything else in this file asks "is it there" or "did you say
# so". A fake oracle that prints a correct-looking account returns instantly;
# a real one copies the tree fifty-three times and runs a race-enabled suite in
# each copy. MEASURED 2026-08-30: 2m55s on this box.
#
# BOUND, and it is weak on purpose: this is a floor against an INSTANTANEOUS
# stub, not proof of work. A fabricator that sleeps defeats it. It is here
# because the cheap edit should not be the quiet one, which is round 8's
# lesson, not because it is hard to get past.
#
# verify.sh checks it LAST, after every content check, so it can never displace
# a truer diagnosis. Scenario oracle-too-fast.
ORACLE_MIN_SECONDS=8

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
	scenario-death-is-reported
	doc-number-reintroduced
	doc-sweep-deleted
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
	oracle-too-fast
	scenario-body-emptied
	observation-recorder-stubbed
	min-declared-tests-margin
)
MANIFEST_SCENARIOS_N=60

# What each scenario must OBSERVE. One entry per scenario, same order.
#
# ROUND 11, and it is the round's whole answer. MEASURED 2026-08-30 by review:
# four scenario BODIES were emptied with their NAMES kept, record()'s guard was
# made inert, self_check() was gutted to report PASS unconditionally, and one
# comment was left in place because the row-coverage check grepped the oracle's
# own source for it. `VERDICT: PASS (12 steps)` with a live defect in the tree,
# twice, with every operand in this file satisfied IN FULL.
#
# The diagnosis is one line: A NAME IS NOT A BEHAVIOUR. Everything above
# answers "is it there"; nothing answered "does it do anything".
#
# Format:  name|rc-class|observation-token
#   rc-class    zero     the subject must have exited 0 in this scenario
#               nonzero  the subject must have exited non-zero
#               static   the scenario runs the subject not at all (see below)
#   token       <row>:<PASS|FAIL|ABSENT> — a row the scenario must have READ,
#               in that state, in the subject's verdict table.
#
# The tokens come from the helpers — `row`, `run_verify`, `run_verify_outer` —
# which are the only ways to run the subject or read its table, so a body
# cannot opt out of being observed. verify.sh compares what the oracle reports
# against what is written here; the check lives in neither the scenario nor the
# oracle.
#
# The consequence is the point: with the contract checked outside the body, a
# body's `note` calls stop being the assertion. Emptying a body no longer
# deletes the assertion, it deletes the OBSERVATION, and no observation is a
# failure.
#
# BOUNDS, stated because a completeness claim here would be this project's
# fifth in five rounds:
#   - The contract pins the OUTCOME, not the PLANT. Two scenarios that redden
#     the same row by different routes are indistinguishable here.
#   - A driver rewritten to FABRICATE these strings defeats it. To do that it
#     must read this table, i.e. reproduce the expectation it is faking. That
#     is the terminus, and it is a person reading a diff.
#   - `static` is an escape hatch and is capped at ONE by the Go pin, because
#     an uncapped exemption is how a class spreads. Its one member is
#     ceiling-band, which reads a constant out of verify.sh and runs nothing.
MANIFEST_SCENARIO_CONTRACTS=(
	"control|zero|verify-oracle:ABSENT"
	"verdict-on-abort|nonzero|gate-roster:ABSENT"
	"verdict-without-gomod|nonzero|gate-roster:FAIL"
	"roster-gate-deleted|nonzero|gate-roster:FAIL"
	"roster-gate-added|nonzero|gate-roster:FAIL"
	"t1-violation|nonzero|t1:FAIL"
	"t2-violation|nonzero|t2:FAIL"
	"gofmt-violation|nonzero|gofmt:FAIL"
	"vet-violation|nonzero|vet:FAIL"
	"race-detector|nonzero|unit-suite:FAIL"
	"test-cache|nonzero|unit-suite:FAIL"
	"ceiling-fires|nonzero|unit-suite:FAIL"
	"ceiling-control|zero|unit-suite:PASS"
	"ceiling-band|static|ceiling-seconds:60"
	"gate-panic|nonzero|t2:FAIL"
	"gate-refuses|nonzero|t1:FAIL"
	"scenario-death-is-reported|static|scenario-death:reported"
	"doc-number-reintroduced|nonzero|doc-numbers:FAIL"
	"doc-sweep-deleted|nonzero|doc-numbers:FAIL"
	"unlinted-script|nonzero|shellcheck:FAIL"
	"unlinted-shebang-script|nonzero|shellcheck:FAIL"
	"oracle-is-invoked|nonzero|verify-oracle:FAIL"
	"hang-bounded|nonzero|unit-suite:FAIL"
	"bounds-ordering|nonzero|bounds:FAIL"
	"suite-timeout-detached|nonzero|bounds:FAIL"
	"stale-citation|nonzero|citations:FAIL"
	"citation-trailing|nonzero|citations:FAIL"
	"citation-underscore|nonzero|citations:FAIL"
	"citation-whitewash|nonzero|citations:FAIL"
	"citation-vacuous|nonzero|citations:FAIL"
	"citation-url|zero|citations:PASS"
	"citation-after-url|nonzero|citations:FAIL"
	"invoked-by-relative-path|zero|bounds:PASS"
	"suite-args-detached|nonzero|bounds:FAIL"
	"suite-tests-disabled|nonzero|unit-suite:FAIL"
	"suite-one-package-disabled|nonzero|unit-suite:FAIL"
	"suite-domain-unmeasured-module|nonzero|unit-suite:FAIL"
	"suite-domain-unmeasured-walk|nonzero|unit-suite:FAIL"
	"suite-files-disabled-partial|nonzero|unit-suite:FAIL"
	"suite-roster-unmeasured|nonzero|unit-suite:FAIL"
	"record-refuses-uncounted-pass|nonzero|gofmt:FAIL"
	"record-refuses-zero-count|nonzero|gofmt:FAIL"
	"row-deleted|nonzero|vet:ABSENT"
	"row-added|nonzero|undeclared-row:PASS"
	"oracle-stub-total|nonzero|verify-oracle:FAIL"
	"oracle-stub-partial|nonzero|verify-oracle:FAIL"
	"citation-embedded-identifier|zero|citations:PASS"
	"citation-word-start|nonzero|citations:FAIL"
	"go-domain-empty|nonzero|build:FAIL"
	"manifest-missing|nonzero|citations:ABSENT"
	"manifest-row-removed|nonzero|unit-suite:FAIL"
	"manifest-count-lies|nonzero|citations:ABSENT"
	"manifest-scenario-removed|nonzero|unit-suite:FAIL"
	"self-check-guard-deleted|nonzero|self-check:FAIL"
	"min-declared-tests-floor|nonzero|unit-suite:FAIL"
	"oracle-names-fabricated|nonzero|verify-oracle:FAIL"
	"oracle-too-fast|nonzero|verify-oracle:FAIL"
	"scenario-body-emptied|nonzero|verify-oracle:FAIL"
	"observation-recorder-stubbed|nonzero|verify-oracle:FAIL"
	"min-declared-tests-margin|nonzero|unit-suite:FAIL"
)
MANIFEST_SCENARIO_CONTRACTS_N=60

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
	[ "${#MANIFEST_SCENARIO_CONTRACTS[@]}" -eq "$MANIFEST_SCENARIO_CONTRACTS_N" ] ||
		bad="$bad MANIFEST_SCENARIO_CONTRACTS has ${#MANIFEST_SCENARIO_CONTRACTS[@]} entr(ies), MANIFEST_SCENARIO_CONTRACTS_N says $MANIFEST_SCENARIO_CONTRACTS_N;"
	[ "${#MANIFEST_SCENARIO_CONTRACTS[@]}" -eq "${#MANIFEST_SCENARIOS[@]}" ] ||
		bad="$bad ${#MANIFEST_SCENARIOS[@]} scenario(s) but ${#MANIFEST_SCENARIO_CONTRACTS[@]} contract(s); a scenario with no contract is a name with no behaviour, which is exactly what round 11 closed;"
	# An empty list is the shape every one of the four rounds above ended in.
	[ "$MANIFEST_ROWS_N" -ge 1 ] || bad="$bad MANIFEST_ROWS_N is not positive;"
	[ "$MANIFEST_GATES_N" -ge 1 ] || bad="$bad MANIFEST_GATES_N is not positive;"
	[ "$MANIFEST_SHELL_SCRIPTS_N" -ge 1 ] || bad="$bad MANIFEST_SHELL_SCRIPTS_N is not positive;"
	[ "$MANIFEST_SCENARIOS_N" -ge 1 ] || bad="$bad MANIFEST_SCENARIOS_N is not positive;"
	[ "$MIN_DECLARED_TESTS" -ge 1 ] || bad="$bad MIN_DECLARED_TESTS is not positive;"
	# A margin the tree can widen at will is a floor with no upper edge, which
	# is the state round 11 was sent to fix.
	[ "$MAX_DECLARED_MARGIN" -ge 0 ] && [ "$MAX_DECLARED_MARGIN" -le 4 ] ||
		bad="$bad MAX_DECLARED_MARGIN is $MAX_DECLARED_MARGIN, outside 0..4; a wide band is a floor that has stopped saying anything;"
	[ "$ORACLE_MIN_SECONDS" -ge 1 ] || bad="$bad ORACLE_MIN_SECONDS is not positive;"
	[ "$MANIFEST_SCENARIO_CONTRACTS_N" -ge 1 ] || bad="$bad MANIFEST_SCENARIO_CONTRACTS_N is not positive;"
	if [ -n "$bad" ]; then
		printf 'the manifest does not agree with itself:%s\n' "$bad"
		return 1
	fi
	return 0
}
