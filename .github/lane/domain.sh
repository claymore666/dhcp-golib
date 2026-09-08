#!/usr/bin/env bash
# Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

#
# domain.sh — decide whether this push has to pay for the oracle, and cut the
# matrix it would run.
#
# Usage:  .github/lane/domain.sh SHARD_SIZE ALWAYS
#           SHARD_SIZE  how many scenarios one shard job carries.
#           ALWAYS      "yes" when the event pays for the oracle whatever the
#                       tree says: a push to the release branch, or a dispatch.
#         GH_TOKEN and GH_REPO in the environment; writes to GITHUB_OUTPUT.
# Exit:   0. Deciding NOT to run the oracle is a decision, not a failure; the
#         arbiter job then has to earn its skip and goes red if it cannot.
#
# THE DOMAIN IS NOT A PATH LIST. The decision "this push touched the oracle's
# own subject" is taken from `./verify.sh --oracle-hash` — the same set, the
# same hash, the same code the skip stamp is keyed on. A `paths:` filter in the
# workflow would be that fact derived twice, and the looser derivation would
# decide which pushes are checked.
#
# It is keyed on CONTENT rather than on a diff against a ref, and that is
# stronger than "the diff touched scripts/": a push that changes verify.sh and
# a push that changes it back are the same tree, and the second one is already
# proved. A push that touches the arbiter at all reaches a hash nothing has
# published, so it runs.
#
# THE SHARD COUNT IS DERIVED, in both directions that matter: the SIZE is a
# cost decision and is the argument to this script, and the COUNT is the
# roster divided by it — so a scenario added to verify.manifest.sh lands in a
# shard with nothing else edited, and a roster that shrank cuts a shard rather
# than leaving an empty one.

set -euo pipefail

shard_size="${1:-}"
always="${2:-no}"
case "$shard_size" in
'' | *[!0-9]* | 0) echo "usage: domain.sh SHARD_SIZE ALWAYS; the size must be a positive number" >&2 && exit 2 ;;
esac
root="$(cd "$(dirname "$0")/../.." && pwd)"

domain="$(cd "$root" && ./verify.sh --oracle-hash)"
hash="$(printf '%s\n' "$domain" | sed -n 's/^hash //p')"
scenarios="$(printf '%s\n' "$domain" | sed -n 's/^scenarios //p')"
files="$(printf '%s\n' "$domain" | sed -n 's/^files //p')"
[ -n "$hash" ] && [ -n "$scenarios" ] && [ -n "$files" ] || {
	echo "::error::./verify.sh --oracle-hash did not answer" >&2
	printf '%s\n' "$domain" >&2
	exit 2
}

count=$(((scenarios + shard_size - 1) / shard_size))
[ "$count" -ge 1 ] || count=1
shards="$(seq 1 "$count" | paste -sd, -)"

published=""
if [ "$always" != yes ]; then
	repo="${GH_REPO:?GH_REPO is unset}"
	published="$(gh api -H 'Accept: application/vnd.github+json' \
		"repos/$repo/actions/artifacts?name=oracle-pass-$hash&per_page=100" \
		--jq '[.artifacts[] | select(.expired == false)] | length' 2>/dev/null || echo 0)"
fi

if [ "$always" = yes ]; then
	run_oracle=yes
	why="this event always pays for the oracle"
elif [ "${published:-0}" -gt 0 ]; then
	run_oracle=no
	why="$published green run(s) have already published this arbiter at hash ${hash:0:16}"
else
	run_oracle=yes
	why="no green run has published this arbiter at hash ${hash:0:16}, so its own subject changed"
fi

printf 'the arbiter is %s file(s), hash %s, over %s scenario(s)\n' "$files" "$hash" "$scenarios"
printf 'the oracle runs: %s — %s\n' "$run_oracle" "$why"
printf 'the matrix is %s shard(s) of up to %s scenario(s) each\n' "$count" "$shard_size"

{
	printf 'hash=%s\n' "$hash"
	printf 'scenarios=%s\n' "$scenarios"
	printf 'shard-count=%s\n' "$count"
	printf 'shards=[%s]\n' "$shards"
	printf 'run-oracle=%s\n' "$run_oracle"
} >>"${GITHUB_OUTPUT:-/dev/stdout}"
