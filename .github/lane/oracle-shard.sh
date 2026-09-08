#!/usr/bin/env bash
# Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

#
# oracle-shard.sh — run one shard of the oracle and write the account of it.
#
# Usage:  .github/lane/oracle-shard.sh I/N OUTFILE
# Exit:   0 every scenario in the shard behaved AND every one of them was held
#         to the contract verify.manifest.sh declares for it; non-zero
#         otherwise. The OUTFILE is written either way — a shard that produced
#         nothing is what the aggregation must be able to see.
#
# THE CONTRACT CHECK RUNS HERE, and that is the whole reason a matrix is
# allowed to stand in for the arbiter's verify-oracle row. A shard that only
# collected RESULT lines would be a count of names, which is the defeat round
# 11 closed: a scenario body emptied of its assertions is declared, defined,
# counted and says nothing. scripts/oracle-contracts.sh is the same comparison
# verify.sh makes, over this shard's share of the roster, and the aggregation
# refuses a shard whose account of it is missing.

set -euo pipefail

shard="${1:-}"
outfile="${2:-}"
[ -n "$shard" ] && [ -n "$outfile" ] || {
	echo "usage: oracle-shard.sh I/N OUTFILE" >&2
	exit 2
}
root="$(cd "$(dirname "$0")/../.." && pwd)"

started="$(date +%s)"
rc=0
(cd "$root" && ./scripts/test-verify.sh --shard "$shard") >"$outfile" 2>&1 || rc=$?
elapsed="$(($(date +%s) - started))"

ctr_rc=0
contracts="$("$root/scripts/oracle-contracts.sh" "$outfile" "$shard" 2>&1)" || ctr_rc=$?

{
	printf 'SHARD EXIT: %s\n' "$rc"
	printf 'SHARD ELAPSED: %s\n' "$elapsed"
	printf 'SHARD CONTRACTS RC: %s\n' "$ctr_rc"
	printf '%s\n' "$contracts" | sed 's/^/SHARD CONTRACT /'
} >>"$outfile"

cat "$outfile"

if [ "$rc" -ne 0 ]; then
	echo "::error::shard $shard: a scenario did not behave; the account above names it"
	exit "$rc"
fi
if [ "$ctr_rc" -ne 0 ]; then
	echo "::error::shard $shard: the contract check refused, so no scenario in this shard was held to anything"
	exit 1
fi
unaccounted="$(printf '%s\n' "$contracts" | sed -n 's/^unaccounted\t//p')"
breached="$(printf '%s\n' "$contracts" | sed -n 's/^breached\t//p')"
if [ -n "$unaccounted" ]; then
	echo "::error::shard $shard: the oracle reported no passing result for scenario(s)$unaccounted, which verify.manifest.sh requires"
	exit 1
fi
if [ -n "$breached" ]; then
	echo "::error::shard $shard: scenario(s) reported PASS without observing what verify.manifest.sh says they must:$breached"
	exit 1
fi
