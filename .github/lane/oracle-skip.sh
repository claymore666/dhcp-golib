#!/usr/bin/env bash
# Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

#
# oracle-skip.sh — earn the product lane's oracle skip, or refuse to.
#
# Usage:  .github/lane/oracle-skip.sh ROOT JUSTIFICATION
#           ROOT           the checked-out tree; the stamp is written there and
#                          is root-bound, so it grants nothing anywhere else.
#           JUSTIFICATION  the file this writes: the run the skip rests on, the
#                          hash it passed at, and the evidence read for it.
#         GH_TOKEN and GH_REPO in the environment.
# Exit:   0 the stamp is written and the justification names a verified run,
#         1 no run may be rested on — and then NO STAMP IS WRITTEN, so the
#           arbiter runs its own oracle rather than skipping on nothing.
#
# WHAT THE STAMP MEANS HERE, since it does not mean locally what it means in a
# job. Locally it is a per-clone cache: this tree ran this oracle, at this
# hash, and need not run it again. There is no such history on a hosted machine
# — every job starts on a fresh one — so the sentence has to be carried between
# machines, and the three ways to carry it were priced before this one was
# picked (docs/verifying.md, "In CI", carries the pricing).
#
# The one picked is the ONLY one that is checked rather than trusted: nothing
# is carried at all. The stamp is COMPUTED here, from the tree's own hash, and
# it is written only when the API says a green oracle aggregation published
# that hash. A cache or an artefact would be a file whose provenance is its own
# name; a run id is a thing the API answers about.
#
# WHERE THE WRITE SITS, because "a stamp written by a red run must be
# impossible" is a claim about a line of code: below oracle-run-check.sh, which
# reads the aggregation JOB's conclusion, and below nothing else. The other end
# of that: the aggregation publishes the hash only on its own success, so a red
# aggregation leaves no name to look up.

set -euo pipefail

root="${1:-}"
justification="${2:-}"
[ -n "$root" ] && [ -n "$justification" ] || {
	echo "usage: oracle-skip.sh ROOT JUSTIFICATION" >&2
	exit 2
}
here="$(cd "$(dirname "$0")" && pwd)"

# The domain, from the arbiter itself. The lane keeps no path list: it asks
# verify.sh which files the oracle is about and what their hash is, so the two
# cannot be one fact derived twice.
domain="$(cd "$root" && ./verify.sh --oracle-hash)"
hash="$(printf '%s\n' "$domain" | sed -n 's/^hash //p')"
scenarios="$(printf '%s\n' "$domain" | sed -n 's/^scenarios //p')"
files="$(printf '%s\n' "$domain" | sed -n 's/^files //p')"
[ -n "$hash" ] && [ -n "$scenarios" ] && [ -n "$files" ] || {
	echo "::error::./verify.sh --oracle-hash did not answer with a hash, a scenario count and a file count" >&2
	printf '%s\n' "$domain" >&2
	exit 2
}
printf 'the arbiter hashes %s file(s) to %s over %s scenario(s)\n' "$files" "$hash" "$scenarios"

# Every unexpired run that published this hash, newest first. More than one is
# ordinary — the same arbiter is proved again on every branch that reaches it —
# and the newest verified one is the one named, so a later red run cannot
# unmake an earlier green one.
repo="${GH_REPO:?GH_REPO is unset}"
candidates="$(gh api -H 'Accept: application/vnd.github+json' \
	"repos/$repo/actions/artifacts?name=oracle-pass-$hash&per_page=100" \
	--jq '[.artifacts[] | select(.expired == false)] | sort_by(.created_at) | reverse | .[].workflow_run.id' 2>/dev/null || true)"

if [ -z "$candidates" ]; then
	echo "::error::no green oracle run has published the arbiter at hash ${hash:0:16}; this tree's arbiter has not been proved, so the product lane may not skip its oracle row"
	exit 1
fi

for run_id in $candidates; do
	echo "reading run $run_id"
	if evidence="$("$here/oracle-run-check.sh" "$run_id" "$hash")"; then
		{
			printf 'run %s\n' "$run_id"
			printf 'hash %s\n' "$hash"
			printf 'scenarios %s\n' "$scenarios"
			printf 'files %s\n' "$files"
			printf '%s\n' "$evidence"
		} >"$justification"
		# THE WRITE. Below the verification and below nothing else.
		printf 'root %s\nhash %s\nscenarios %s\nfiles %s\nwritten %s\n' \
			"$root" "$hash" "$scenarios" "$files" \
			"$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >"$root/.verify-oracle-stamp"
		printf 'the oracle row rests on run %s, which passed at hash %s over %s scenarios\n' \
			"$run_id" "$hash" "$scenarios"
		exit 0
	fi
	printf '%s\n' "$evidence"
done

echo "::error::every run that published oracle-pass-${hash:0:16} was refused; the lines above say which condition each failed"
exit 1
