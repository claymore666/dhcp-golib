#!/usr/bin/env bash
# Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

#
# oracle-run-check.sh — is there a GREEN oracle behind this run id, at this hash?
#
# Usage:  .github/lane/oracle-run-check.sh RUN_ID HASH
#         GH_TOKEN and GH_REPO in the environment; `gh` on PATH.
# Prints: one `evidence <field> <value>` line per thing it read, then either
#         `verified <run-id> <hash>` or a `refused` line naming what failed.
# Exit:   0 verified, 1 refused, 2 it could not ask (no token, no `gh`, an API
#         error) — which is a refusal too, and says which one it is.
#
# THIS IS THE WHOLE OF WHAT "THE SKIP RESTS ON A RUN" MEANS, and it is asked
# twice: once before the stamp is written, and once by the vacuity step over
# the justification the arbiter actually ran with. One implementation, because
# the second ask is only worth anything if it is the same question.
#
# THREE CONDITIONS, each of which a fooling shape fails on:
#
#   1. an artifact named `oracle-pass-<hash>` exists, is not expired, and its
#      OWNING RUN is the run id named. A stamp pointed at a run that passed at
#      a different hash fails here: the artifact carries the hash in its name,
#      and the name is what is looked up.
#   2. that run holds a job named exactly the aggregation job, and its
#      conclusion is `success`. A stamp pointed at a red run fails here — and
#      the JOB is read rather than the run, because a run's own conclusion is
#      null while it is still going and can be success over a skipped oracle.
#      MEASURED rather than argued, and by accident: run 34206597940's skip
#      rests on run 34204814646, whose own conclusion is `failure` and whose
#      `the oracle verdict` job is `success`. The matrix passed over all 79
#      scenarios; a later step of a different job went red. Reading the run
#      there would have refused an honest skip.
#   3. the run belongs to THIS repository and to this workflow file. A stamp
#      naming a run in some other repository fails here.
#
# THE ESCAPE, stated beside the claim: this checks that a green aggregation job
# published that name, not that the aggregation was honest. Anybody who can
# push a branch here can also edit .github/, and .github/ is not in the set the
# hash covers — so a workflow edited to publish the name is the deliberate
# forgery this does not close, exactly as the local stamp's own comment says of
# a stamp written by hand. What is closed is the accident and the cheap one:
# a red run, a run at another hash, a run that does not exist, an expired
# artifact, and a run in another repository.

set -euo pipefail

# The aggregation job's name, spelled once. The workflow reads it from here too,
# so a rename cannot leave this looking for a job that no longer exists.
ORACLE_VERDICT_JOB="the oracle verdict"
LANE_WORKFLOW="verify.yml"

say() { printf 'evidence %s\n' "$*"; }
refuse() {
	printf 'refused %s\n' "$*"
	exit "${2:-1}"
}

run_id="${1:-}"
hash="${2:-}"
[ -n "$run_id" ] && [ -n "$hash" ] ||
	refuse "usage: oracle-run-check.sh RUN_ID HASH; a check with no operand has one possible verdict" 2
case "$run_id" in
'' | *[!0-9]*) refuse "run id '$run_id' is not a number" ;;
esac
case "$hash" in
*[!0-9a-f]* | '') refuse "hash '$hash' is not a hex digest" ;;
esac

command -v gh >/dev/null 2>&1 || refuse "gh is not on PATH; the run behind the skip cannot be read" 2
repo="${GH_REPO:-}"
[ -n "$repo" ] || refuse "GH_REPO is unset; a run id without a repository names nothing" 2

api() { gh api -H 'Accept: application/vnd.github+json' "$@"; }

# 1. the artifact, by NAME, and its owning run.
arts="$(api "repos/$repo/actions/artifacts?name=oracle-pass-$hash&per_page=100" \
	--jq '.artifacts[] | select(.expired == false) | "\(.id) \(.workflow_run.id) \(.created_at)"' 2>&1)" ||
	refuse "the artifact list for oracle-pass-$hash could not be read: $(printf '%s' "$arts" | tr '\n' ' ')" 2
[ -n "$arts" ] ||
	refuse "no unexpired artifact named oracle-pass-$hash exists in $repo; nothing has proved this arbiter"
art_id="$(printf '%s\n' "$arts" | awk -v r="$run_id" '$2 == r { print $1; exit }')"
[ -n "$art_id" ] ||
	refuse "run $run_id owns no artifact named oracle-pass-$hash; the runs that do are $(printf '%s\n' "$arts" | awk '{ printf "%s ", $2 }')"
say "artifact $art_id name oracle-pass-$hash"

# 3. the run: this repository, this workflow.
run_json="$(api "repos/$repo/actions/runs/$run_id" --jq '"\(.path) \(.status) \(.conclusion)"' 2>&1)" ||
	refuse "run $run_id could not be read in $repo: $(printf '%s' "$run_json" | tr '\n' ' ')" 2
read -r run_path run_status run_conclusion <<<"$run_json"
say "run $run_id path $run_path status $run_status conclusion $run_conclusion"
[ "$run_path" = ".github/workflows/$LANE_WORKFLOW" ] ||
	refuse "run $run_id is a run of $run_path, not of .github/workflows/$LANE_WORKFLOW"

# 2. the JOB, by name, and its conclusion.
job="$(api "repos/$repo/actions/runs/$run_id/jobs?per_page=100" \
	--jq ".jobs[] | select(.name == \"$ORACLE_VERDICT_JOB\") | \"\(.id) \(.conclusion)\"" 2>&1)" ||
	refuse "the jobs of run $run_id could not be read: $(printf '%s' "$job" | tr '\n' ' ')" 2
[ -n "$job" ] ||
	refuse "run $run_id holds no job named '$ORACLE_VERDICT_JOB'; an artifact is not a verdict"
job_id="${job%% *}"
job_conclusion="${job##* }"
say "job $job_id name $ORACLE_VERDICT_JOB conclusion $job_conclusion"
[ "$job_conclusion" = success ] ||
	refuse "the '$ORACLE_VERDICT_JOB' job of run $run_id concluded $job_conclusion; a skip may not rest on a run that did not pass"

printf 'verified %s %s\n' "$run_id" "$hash"
