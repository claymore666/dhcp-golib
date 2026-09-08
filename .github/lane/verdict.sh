#!/usr/bin/env bash
# Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

#
# verdict.sh — the lane's vacuity refusal.
#
# Usage:  .github/lane/verdict.sh OUTPUT JUSTIFICATION
#           OUTPUT         what ./verify.sh printed.
#           JUSTIFICATION  what .github/lane/oracle-skip.sh wrote, if anything.
# Exit:   0 the arbiter spoke, over every row the manifest declares, and the one
#         row it may decline to repeat rests on a named green oracle run;
#         1 otherwise, with one ::error:: line per thing refused.
#
# A job whose only operand is an exit status cannot tell an arbiter that passed
# from an arbiter that printed nothing, cannot tell a full verdict from one
# taken over a shrunken roster, and — since D41 — cannot tell a skip that rests
# on a run from a skip that rests on a file somebody wrote. So read the
# arbiter's own table, take every name and count in it out of the manifest at
# run time, and take the run behind the skip out of the API.
#
# IT TYPES NO NAME AND NO NUMBER OF ITS OWN. What that is NOT is a second
# manifest: it reads the same roster verify.sh reconciles against, so an edit
# that shrinks the roster and its counts together still has to get past
# manifest_check and internal/manifest, where this adds no layer and no longer
# pretends to.
#
# THE ANCHOR IS THE MARGIN, and it is worth knowing before touching a pattern
# here: a SKIPPED oracle row's own detail CONTAINS the string "ORACLE PASS:",
# because it quotes what the stamp recorded. A grep for that token anywhere in
# the output accepts a skipped oracle. Every pattern below is anchored on the
# row name and its verdict at column zero; loosening one loses the check.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"

out="${1:-}"
justification="${2:-}"
[ -n "$out" ] || {
	echo "usage: verdict.sh OUTPUT JUSTIFICATION" >&2
	exit 2
}

bad=0
err() {
	echo "::error::$*"
	bad=1
}

if [ ! -s "$out" ]; then
	echo "::error::the arbiter produced no output; a run that printed nothing is not a pass"
	exit 1
fi

# shellcheck source=../../verify.manifest.sh
. "$root/verify.manifest.sh"
n="$MANIFEST_ROWS_N"
scenarios="${#MANIFEST_SCENARIOS[@]}"

# EVERY declared row, by name. A row may be SKIPPED only if the manifest says
# that row may be, and only after the skip has been justified below; every
# other row must be a PASS and nothing else.
for r in "${MANIFEST_ROWS[@]}"; do
	skippable=0
	for s in "${MANIFEST_SKIPPABLE_ROWS[@]}"; do
		[ "$s" = "$r" ] && skippable=1
	done
	if grep -Eq "^${r} +PASS( |\$)" "$out"; then
		continue
	fi
	if [ "$skippable" -eq 1 ] && grep -Eq "^${r} +SKIPPED " "$out"; then
		continue
	fi
	err "the arbiter recorded no PASS for the declared row ${r}"
	grep -E "^${r} +" "$out" || echo "there is no ${r} row in the output at all"
done
for r in "${MANIFEST_ROWS[@]}"; do
	if grep -Eq "^${r} +FAIL( |\$)" "$out"; then
		err "the output carries a ${r} row that is not a PASS"
		grep -E "^${r} +FAIL( |\$)" "$out"
	fi
done

# The oracle row: it either RAN here, or it rests on a run that did.
rested_run=""
rested_hash=""
if grep -Eq "^verify-oracle +PASS " "$out"; then
	if ! grep -Eq "^verify-oracle +PASS +${MANIFEST_ORACLE_PASS_PREFIX} ${scenarios} scenarios" "$out"; then
		err "the verify-oracle row does not carry the oracle's own account of ${scenarios} scenarios; the row printed below says which state this actually is — an account over a different population, or a PASS whose detail is not the account"
		grep -E '^verify-oracle' "$out"
	fi
elif grep -Eq "^verify-oracle +SKIPPED " "$out"; then
	# The row's OWN hash and the row's OWN count, read out of what the arbiter
	# printed — never out of the justification, which is the thing being
	# checked. A justification that names a different hash from the one the
	# arbiter skipped at is the first fooling shape and dies here.
	row="$(grep -E '^verify-oracle +SKIPPED ' "$out" | tail -1)"
	row_hash="$(printf '%s\n' "$row" | sed -n 's/.* hash \([0-9a-f][0-9a-f]*\),.*/\1/p')"
	row_scn="$(printf '%s\n' "$row" | sed -n "s/.*${MANIFEST_ORACLE_PASS_PREFIX} \([0-9][0-9]*\) scenarios.*/\1/p")"
	if [ -z "$row_hash" ] || [ -z "$row_scn" ]; then
		err "the verify-oracle row is SKIPPED but names no hash and no scenario count; a skip that says nothing about its subject is not traceable"
		printf '%s\n' "$row"
	elif [ "$row_scn" != "$scenarios" ]; then
		err "the verify-oracle row was skipped against ${row_scn} scenario(s); verify.manifest.sh declares ${scenarios}"
		printf '%s\n' "$row"
	elif [ -z "$justification" ] || [ ! -s "$justification" ]; then
		err "the verify-oracle row is SKIPPED and no justification was written; a skip with no run behind it is not a verdict"
		printf '%s\n' "$row"
	else
		rested_run="$(sed -n 's/^run //p' "$justification" | head -1)"
		rested_hash="$(sed -n 's/^hash //p' "$justification" | head -1)"
		if [ -z "$rested_run" ] || [ -z "$rested_hash" ]; then
			err "the justification names no run and no hash; a skip that cannot name what it rests on is not traceable"
			cat "$justification"
		elif [ "${rested_hash#"$row_hash"}" = "$rested_hash" ]; then
			err "the arbiter skipped at hash ${row_hash} and the justification names a run that passed at ${rested_hash}; a skip may not rest on a run that proved a different arbiter"
			printf '%s\n' "$row"
			cat "$justification"
			rested_run=""
		else
			echo "rested-on ${rested_run} ${rested_hash}"
		fi
	fi
else
	err "the output carries no verify-oracle row that is a PASS or a SKIPPED"
	grep -E '^verify-oracle' "$out" || echo "there is no verify-oracle row in the output at all"
fi

if ! grep -Fxq "VERDICT: PASS ($n steps)" "$out"; then
	err "the arbiter did not print VERDICT: PASS ($n steps), the row count verify.manifest.sh declares"
	grep -E '^VERDICT:' "$out" || echo "there is no VERDICT line in the output at all"
	grep -E '^[a-z-]+ +FAIL ' "$out" || true
fi

# One run, one verdict. A green output with a second verdict line after it is
# not a green run, and the check above cannot see the second line.
verdicts="$(grep -cE '^VERDICT:' "$out" || true)"
if [ "$verdicts" -ne 1 ]; then
	err "the output carries ${verdicts} VERDICT lines; one run states one verdict"
	grep -E '^VERDICT:' "$out"
fi

[ "$bad" -eq 0 ] || exit 1

# LAST, and only once everything above holds: ask the API again about the run
# the arbiter's own row rests on. The first ask decided whether to write the
# stamp; this one is over the hash the arbiter PRINTED, so a stamp that came
# from anywhere else — a leftover file, a hand-written one, one carried in —
# has to survive the same three conditions.
if [ -n "$rested_run" ]; then
	"$here/oracle-run-check.sh" "$rested_run" "$rested_hash" || {
		echo "::error::the run the skipped oracle row rests on did not survive a second reading"
		exit 1
	}
	echo "the arbiter printed VERDICT: PASS ($n steps) and declined to repeat an oracle that run ${rested_run} passed over ${scenarios} scenarios."
	exit 0
fi

echo "the arbiter printed VERDICT: PASS ($n steps) and ran its own oracle over ${scenarios} scenarios."
