#!/usr/bin/env bash
# Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

#
# oracle-aggregate.sh — turn N shard accounts into ONE verdict, or refuse.
#
# Usage:  .github/lane/oracle-aggregate.sh DIR SHARD_COUNT MATRIX_RESULT
#           DIR           holds one shard-<i>.txt per shard.
#           SHARD_COUNT   how many the domain job cut, from the roster.
#           MATRIX_RESULT what GitHub says the matrix job as a whole did.
# Exit:   0 the shards, taken together, are the oracle the manifest declares;
#         1 otherwise, one ::error:: line per thing refused.
#
# WHAT A VACUOUS GREEN LOOKS LIKE HERE, which is what each refusal answers:
#
#   - a shard job that never ran, or was cancelled, and left no file. Read as
#     "nothing to disagree with", the missing shard is the quiet pass. So the
#     files are counted against SHARD_COUNT and each index is demanded by name.
#   - a shard that ran an empty share. The oracle refuses that itself; this
#     refuses it again from the outside, because the empty domain is the
#     universal's oldest defeat.
#   - the shards not adding up to the roster: a scenario in no shard at all, or
#     in two. Membership is read out of each shard's own MEMBERS line and
#     compared to MANIFEST_SCENARIOS as a SET — every name exactly once, in
#     either direction — rather than by counting to the same number twice.
#   - a shard that collected RESULT lines and held nobody to a contract. Each
#     shard's contract account is demanded and must be empty of unaccounted and
#     breached names.
#   - a shard that answered instantly. The oracle's own floor, scaled to the
#     shard's share of the roster: it is the same weak floor for the same
#     stated reason — the cheap edit must not also be the quiet one — and it is
#     not proof of work at any size.
#   - the matrix red while every file that DID arrive looks fine. GitHub's own
#     result for the matrix is an operand here, so a shard that failed after
#     writing its file cannot be aggregated away.

set -euo pipefail

dir="${1:-}"
shard_count="${2:-}"
matrix_result="${3:-}"
[ -n "$dir" ] && [ -n "$shard_count" ] && [ -n "$matrix_result" ] || {
	echo "usage: oracle-aggregate.sh DIR SHARD_COUNT MATRIX_RESULT" >&2
	exit 2
}
root="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=../../verify.manifest.sh
. "$root/verify.manifest.sh"

bad=0
err() {
	echo "::error::$*"
	bad=1
}

case "$shard_count" in
'' | *[!0-9]*) err "the shard count '$shard_count' is not a number" ;;
esac
[ "$bad" -eq 0 ] || exit 1

if [ "$matrix_result" != success ]; then
	err "the oracle matrix concluded '$matrix_result'; a shard that is red, cancelled or never started is not a shard that passed"
fi

found="$(find "$dir" -maxdepth 2 -type f -name 'shard-*.txt' | LC_ALL=C sort)"
found_n="$(printf '%s\n' "$found" | grep -c . || true)"
if [ "$found_n" -ne "$shard_count" ]; then
	err "$found_n shard account(s) arrived for $shard_count shard(s); a shard that left no account is not a shard that passed"
	printf '%s\n' "$found"
fi

seen=""
total=0
i=1
while [ "$i" -le "$shard_count" ]; do
	f="$(printf '%s\n' "$found" | grep -E "/shard-$i\.txt\$" | head -1 || true)"
	if [ -z "$f" ]; then
		err "shard $i of $shard_count left no account"
		i=$((i + 1))
		continue
	fi
	members="$(sed -n "s|^SHARD $i/$shard_count MEMBERS: ||p" "$f" | head -1)"
	if [ -z "$members" ]; then
		err "shard $i named no members; a shard that does not say what it ran cannot be checked against the roster"
		i=$((i + 1))
		continue
	fi
	m_n="$(printf '%s\n' $members | grep -c . || true)"
	exit_rc="$(sed -n 's/^SHARD EXIT: //p' "$f" | head -1)"
	elapsed="$(sed -n 's/^SHARD ELAPSED: //p' "$f" | head -1)"
	ctr_rc="$(sed -n 's/^SHARD CONTRACTS RC: //p' "$f" | head -1)"
	accounted="$(sed -n 's/^SHARD CONTRACT accounted\t//p' "$f" | head -1)"
	unaccounted="$(sed -n 's/^SHARD CONTRACT unaccounted\t//p' "$f" | head -1)"
	breached="$(sed -n 's/^SHARD CONTRACT breached\t//p' "$f" | head -1)"

	[ "$exit_rc" = 0 ] || err "shard $i exited '$exit_rc'"
	[ "$ctr_rc" = 0 ] || err "shard $i's contract check exited '$ctr_rc'; nothing in it was held to a contract"
	[ -z "$unaccounted" ] || err "shard $i reported no passing result for scenario(s)$unaccounted"
	[ -z "$breached" ] || err "shard $i carries scenario(s) that reported PASS without observing what verify.manifest.sh says they must:$breached"
	[ "$accounted" = "$m_n" ] ||
		err "shard $i ran $m_n scenario(s) and accounted for '$accounted'; a shard that holds fewer scenarios to their contracts than it ran is a count, not a check"

	# Every member reported, by name, PASS, in that shard's own account.
	for s in $members; do
		grep -qE "^[[:space:]]*RESULT $s PASS obs=" "$f" ||
			err "shard $i names $s as a member and carries no passing result for it"
		case " $seen " in
		*" $s "*) err "scenario $s is in more than one shard; the shards are not a partition" ;;
		*) seen="$seen $s" ;;
		esac
		total=$((total + 1))
	done

	grep -qE "^ORACLE SHARD $i/$shard_count PASS: " "$f" ||
		err "shard $i printed no shard verdict of its own"

	# The floor, per member, from verify.manifest.sh's own SHARD measurement.
	#
	# 2026-09-08 round 2. This used to scale ORACLE_MIN_SECONDS — a wall clock
	# of the WHOLE roster on a developer's box — down to a shard's share, which
	# came to 3s for a shard of eight against shards that measured 169s to
	# 661s. It could not fire; a fabricated `SHARD ELAPSED: 3` was accepted.
	# MEASURED by review at 0998583. The constant it reads now is derived from
	# the fastest per-scenario cost the shards themselves produced on the image
	# they run on; the derivation is beside the number.
	floor=$((ORACLE_SHARD_MIN_SECONDS_PER_SCENARIO * m_n))
	[ "$floor" -ge 1 ] || floor=1
	case "$elapsed" in
	'' | *[!0-9]*) err "shard $i recorded no elapsed time" ;;
	*) [ "$elapsed" -ge "$floor" ] ||
		err "shard $i answered in ${elapsed}s over $m_n scenario(s), under the ${floor}s floor verify.manifest.sh derives for that many (${ORACLE_SHARD_MIN_SECONDS_PER_SCENARIO}s each); it reported the right account without doing the work" ;;
	esac
	i=$((i + 1))
done

# The roster, in BOTH directions. Counting to the same number twice is what a
# shard that ran one scenario twice would satisfy.
for s in "${MANIFEST_SCENARIOS[@]}"; do
	case " $seen " in
	*" $s "*) ;;
	*) err "the manifest declares scenario $s and no shard ran it" ;;
	esac
done
for s in $seen; do
	case " ${MANIFEST_SCENARIOS[*]} " in
	*" $s "*) ;;
	*) err "a shard ran $s, which verify.manifest.sh does not declare" ;;
	esac
done
if [ "$total" -ne "${#MANIFEST_SCENARIOS[@]}" ]; then
	err "the shards ran $total scenario(s); verify.manifest.sh declares ${#MANIFEST_SCENARIOS[@]}"
fi

[ "$bad" -eq 0 ] || exit 1
printf 'ORACLE MATRIX PASS: %s scenarios over %s shards, every planted defect was detected by the row that owns it and every scenario was held to its contract\n' \
	"${#MANIFEST_SCENARIOS[@]}" "$shard_count"
