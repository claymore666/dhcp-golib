#!/usr/bin/env bash
# Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

#
# oracle-contracts.sh — hold each scenario to what it must have OBSERVED.
#
# Usage:  scripts/oracle-contracts.sh OUTPUT [I/N]
#           OUTPUT  a file holding an oracle account: one `RESULT <name> <verdict>
#                   obs=<observations>` line per scenario, indented or not.
#           I/N     restrict the check to shard I of N, the same partition
#                   scripts/test-verify.sh --shard cuts. Absent means every
#                   contract the manifest declares.
# Prints three tab-separated fields, one per line, and nothing else:
#           accounted<TAB><n>
#           unaccounted<TAB><names, leading space, empty when none>
#           breached<TAB><report, leading space, empty when none>
# Exit:   0 always when it could read its operands, 2 when it could not. The
#         VERDICT is the caller's: verify.sh turns these three into the
#         verify-oracle row, and the lane turns them into a shard's exit status.
#
# DECISION 2026-09-08 (D41). This ran inside verify.sh, where it was written,
# and it still answers to verify.sh. It moved here because the lane now runs
# the oracle as a matrix of shards on machines that never see verify.sh's
# verify-oracle row: a shard has to hold its own scenarios to their contracts
# or the matrix is a count of names. Two implementations of that comparison
# would be one fact derived twice, and the looser derivation would decide.
#
# WHAT DID NOT MOVE, and it is the whole design: the CONTRACT comes from
# verify.manifest.sh, the OBSERVATION comes from the oracle, and the comparison
# happens in neither of them. This file is the third place, exactly as the loop
# inside verify.sh was — sourced by nobody, edited by an author who is changing
# a scenario for no reason at all.

set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"

refuse() {
	printf 'ORACLE CONTRACTS REFUSED: %s\n' "$*" >&2
	exit 2
}

out="${1:-}"
[ -n "$out" ] || refuse "no output file was named; a check with no subject reports no breach"
[ -r "$out" ] || refuse "$out is missing or unreadable"

MANIFEST="$ROOT/verify.manifest.sh"
[ -r "$MANIFEST" ] || refuse "$MANIFEST is missing or unreadable"
# shellcheck source=../verify.manifest.sh
. "$MANIFEST"
manifest_problem="$(manifest_check)" || refuse "$manifest_problem"

in_list() {
	local needle="$1" x
	shift
	for x in "$@"; do
		[ "$x" = "$needle" ] || continue
		return 0
	done
	return 1
}

# The shard restriction, and it is a RESTRICTION of the domain rather than a
# second domain: the members are cut out of MANIFEST_SCENARIOS by the same
# round-robin scripts/test-verify.sh --shard cuts, so a contract can only be
# checked by the shard that ran its scenario, and every contract is checked by
# exactly one shard as long as the shards cover 1..N.
shard_i=0
shard_n=0
if [ -n "${2:-}" ]; then
	case "$2" in
	[0-9]*/[0-9]*) ;;
	*) refuse "'$2' is not a shard of the form I/N" ;;
	esac
	shard_i="${2%%/*}"
	shard_n="${2##*/}"
	[ "$shard_n" -ge 1 ] || refuse "shard count $shard_n is not positive"
	[ "$shard_i" -ge 1 ] && [ "$shard_i" -le "$shard_n" ] ||
		refuse "shard $shard_i is outside 1..$shard_n"
fi

# in_shard NAME — true when this run owns that scenario's contract.
in_shard() { # NAME
	local name="$1" idx=0 s
	[ "$shard_n" -ne 0 ] || return 0
	for s in "${MANIFEST_SCENARIOS[@]}"; do
		if [ "$s" = "$name" ]; then
			[ "$((idx % shard_n))" -eq "$((shard_i - 1))" ] && return 0
			return 1
		fi
		idx=$((idx + 1))
	done
	# A contract naming a scenario the manifest does not declare is refused by
	# manifest_check above, so this is unreachable; it fails toward CHECKING.
	return 0
}

orc_out="$(cat "$out")"
accounted=0
unaccounted=""
breached=""

for contract in "${MANIFEST_SCENARIO_CONTRACTS[@]}"; do
	IFS='|' read -r sc_name want_rc want_tok want_diag <<<"$contract"
	in_shard "$sc_name" || continue
	if ! printf '%s\n' "$orc_out" | grep -qE "^[[:space:]]*RESULT $sc_name PASS obs="; then
		unaccounted="$unaccounted $sc_name"
		continue
	fi
	accounted=$((accounted + 1))
	got="$(printf '%s\n' "$orc_out" | sed -n "s/^[[:space:]]*RESULT $sc_name PASS obs=//p" | tail -1)"
	sc_ok=1
	case "$want_rc" in
	zero) printf '%s' ",$got," | grep -q ',rc:0,' || sc_ok=0 ;;
	nonzero) printf '%s' ",$got," | grep -qE ',rc:[1-9][0-9]*,' || sc_ok=0 ;;
	static) [ -n "$got" ] || sc_ok=0 ;;
	*) sc_ok=0 ;;
	esac
	# Unconditional. The "-" escape this used to carry meant "demand no
	# observation", which is one manifest entry away from the defeat this whole
	# check answers.
	printf '%s' ",$got," | grep -q ",$want_tok," || sc_ok=0
	# ROUND 13, B15. The row's own ACCOUNT of what it found, not only that it
	# went red. A scenario cut down to the lines producing its contracted
	# observation, planting whatever reaches the same row, satisfied everything
	# up to here — because a verdict names a row and nothing named the defect.
	# The note is written by the arbiter, so the scenario cannot supply it by
	# planting something else.
	case "$want_tok" in
	*:FAIL | *:PASS | *:ABSENT)
		sc_row="${want_tok%%:*}"
		# Every note recorded for that row, not the first: a scenario may run
		# the subject more than once (oracle-is-invoked runs a stub and then
		# the real thing), and the reading that carries the diagnosis is not
		# always the first one.
		sc_note="$(printf '%s' "$got" | tr ',' '\n' | sed -n "s/^why:$sc_row://p")"
		printf '%s\n' "$sc_note" | grep -qF -- "$want_diag" || {
			sc_ok=0
			want_tok="$want_tok/$want_diag"
		}
		;;
	esac
	# The SCOPE the scenario ran at, against the manifest's declaration of the
	# scope it is entitled to (item 2, 2026-09-05). The scope is set by the
	# oracle's dispatcher from that same list and recorded by the run helpers;
	# a body that scopes itself down to skip the row it exists to drive reports
	# a scope the manifest does not declare for it, and is a breach here —
	# beside the older and stronger refusal, which is that the row it scoped
	# away then reads ABSENT and fails its own contract.
	#
	# static scenarios never run verify.sh, so there is no scope to observe;
	# they are exempt by rc-class, not by name.
	if [ "$want_rc" != static ]; then
		want_scope=full
		in_list "$sc_name" "${MANIFEST_LIGHT_SCENARIOS[@]}" && want_scope=light
		printf '%s' ",$got," | grep -q ",scope:$want_scope," || {
			sc_ok=0
			want_tok="$want_tok/scope:$want_scope"
		}
	fi
	[ "$sc_ok" -eq 1 ] || breached="$breached $sc_name(wants $want_rc,$want_tok; observed [$got])"
done

printf 'accounted\t%s\n' "$accounted"
printf 'unaccounted\t%s\n' "$unaccounted"
printf 'breached\t%s\n' "$breached"
