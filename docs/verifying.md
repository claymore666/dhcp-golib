# Verifying dhcp-golib

    ./verify.sh

One command, one verdict. Exit 0 is PASS and is the normal state; exit 1 is
FAIL. A step that cannot be measured is a FAIL, never a skip.

It runs `go build`, `go vet`, `gofmt`, `shellcheck` over the shell scripts, the
gate roster cross-check, the T1 and T2 gates, the race-enabled pure unit suite
under a wall-clock ceiling AND a `go test -timeout` (the ceiling cannot bound a
test that never returns — it is computed after `go test` comes back), the
namespaced dnsmasq tests under a ceiling and a timeout of their own, a check
that the flags each of those runs with carry a hang timeout that exceeds its
ceiling and that each invocation expands its own flag array, a check that every
test function DECLARED in a `_test.go` file actually ran, a citation check, a
byte-for-byte comparison of every fenced block in the README's Usage section
against the Example function it names, and its own oracle.

**No row can report PASS on an exit status alone.** A row records PASS only by
also stating how many things it examined, and a count that is absent or zero is
rewritten to FAIL by the one function that writes a row. This is structural
rather than a guard per row, because three rows were found passing over an
absent subject in three consecutive review rounds — the unit suite with every
test build-tagged out, the oracle replaced by `exit 0`, and the row roster
itself with a step call deleted — and all three inherited the same default,
that a command with nothing to do exits 0.

The residual is worth naming beside the claim: nothing inside the script can
force that count to be DERIVED rather than written. What closes that is
external — a scenario that empties a row's domain and requires the row to go
red. This paragraph used to say there was one such scenario per row. There was
one, for one row of eleven; `docs/gates.md` now lists which rows have one,
which do not, and why the ones that do not cannot.

The citation check is stated here as a BOUND, because the sentence that used to
stand in its place was a completeness claim and the tree falsifies it. What it
reads is: a Test/Benchmark/Fuzz/Example token appearing after the first `//` on
a `.go` line that is not a URL scheme separator, or anywhere on a line of a
`.md` file; and it requires each one to appear in a top-level `func`, `var`,
`const` or `type` declaration. It does **not** see block comments, `.sh` files,
or a token in a `.go` line's ordinary text — there are live examples of all
three in this tree, `scripts/test-verify.sh` chief among them. The seven
enumerated escapes, including the one direction in which it produces a false
positive, are in `docs/gates.md`; they are part of the check, not a caveat
about it.

"Every check" used to be bounded by this sentence: *a check runs only if
`verify.sh` calls it, and nothing inside `verify.sh` notices a call that is no
longer there.* That bound was accurate and it rested on the oracle's scenarios
noticing instead — and on 2026-08-30 a review measured that the oracle can be
replaced by a two-line script that exits 0. **An acknowledged bound was
load-bearing on a guard that dies with its subject**, and the composition was
never measured: with the oracle stubbed AND a step call deleted, the arbiter
printed `VERDICT: PASS (10 steps)`.

**That fix was defeated too, and the sentence that used to stand here is the
reason it is worth reading the next one carefully.** It said: the row roster is
cross-checked against the rows recorded, and the oracle's expected scenario
count is derived by `verify.sh` from the oracle's own source, so a stub —
total or partial — is a mismatch rather than an answer. Both halves were true
and both were defeated in one round, the same way, because **every expectation
was derived from the thing it was checking.** MEASURED 2026-08-30 by review:
delete the `shellcheck` gate — its step, its roster entry, its two scenarios —
and eleven rows became ten with `VERDICT: PASS (10 steps)` and four live
`SC2034` findings in the tree. Replace the oracle with forty-five empty stub
functions and one `echo`, and it passes. Delete the count guard together with
the scenarios that drive it, and it passes.

Four rounds found that same shape, one level up each time, and every guard had
a non-vacuity floor. **Every floor was at zero.** Zero is the one size a
population cannot reach by deletion, so shrinking one by a single member was
invisible in all of them.

What stands now is `verify.manifest.sh`: a file that contains the expectation
and nothing else — the row names, the gate names, the scenario names, a literal
count beside each list, and a band around the declared-test population. Both
`verify.sh` and the oracle read it, so neither derives its expectation from
itself or from the other, and `internal/manifest` pins the same names and
numbers from Go, in another directory, running inside the suite.

**And that, in turn, was defeated — on a different axis, which is why it is
worth its own paragraph.** MEASURED 2026-08-30 by review: keep every name,
delete four scenario BODIES, make the arbiter's own guard inert, and the run
reports `VERDICT: PASS` with a live defect in the tree. The manifest was never
touched and every count was satisfied in full, because **a name is not a
behaviour**. Every operand answered *is it there*; none answered *does it do
anything*.

So the manifest now states, per scenario, what that scenario must be OBSERVED
to have done — the process result class, and a row verdict it read out of the
subject's own table. The oracle reports what each scenario actually observed;
`verify.sh` compares the report against the manifest. The comparison lives in
none of the three places somebody would edit to make a scenario stop working,
so an emptied body is not a passing body: it is a scenario that observed
nothing, named in the diagnosis. A scenario that dies mid-plant reports its own
death for the same reason — silence and success used to be the same output.

That bound was taken. A review built exactly the body described above — kept
only the lines producing the observation, dropped every assertion, planted a
different defect reaching the same row — composed it with the bound beside it,
and got a passing verdict over a live defect with four scenarios testing
nothing. So a contract now names the DEFECT as well as the row: its fourth
field is a fragment of the note the ARBITER wrote beside that row, and the
arbiter is not the scenario that planted anything. Reddening the right row for
the wrong reason produces a different note.

**BOUND, and it is the honest one:** the diagnosis is matched as a substring,
so two plants the arbiter describes in the same words are still
indistinguishable. And every check on the oracle's report is defeatable by a
fabricator that reproduces the report — which is why `verify.sh` also plants
seven defects for ITSELF before calling the oracle, and requires each to redden
its own row while the unplanted rows stay green. That is a lower bound on the
arbiter's liveness, not proof of it; what it buys is that blinding the arbiter
now takes an edit to `verify.sh` too.

The claim is bounded, because a completeness claim here is the sentence this
project has been wrong about four times. What holds is narrower: **the row
roster and the scenario list cannot be shrunk by an edit confined to a single
file**, because `internal/manifest` pins them a second time, in Go, and the
edit then has to be made twice, in two languages. **The escape, named rather
than left to be found:** the self-drive's own detection set is held by a length
literal in `verify.manifest.sh` and by nothing else, so deleting entries there
shrinks it and the run still passes. MEASURED; the plugin's deferred-work
record carries the reproduction.

The step deletions below were driven rather than assumed.
MEASURED 2026-08-29, deleting one step at a time from a copy and running
`scripts/test-verify.sh` against it: eight of the nine steps then present
redden at least one oracle scenario — `gofmt` 4, the gate roster 3, the two
gates 6, the unit suite refuses the run outright, `shellcheck` 2, `build` and
`vet` 1 each. Those counts were taken against the 19-scenario oracle, before
`hang-bounded`, `bounds-ordering` and `stale-citation` were added later the
same day. They are LOWER bounds now rather than equalities: a scenario can only
add a detection, never remove one, and nobody re-ran the nine deletions. The
two steps added after that sweep — the timeout-ordering check and the citation
check — were each driven by deleting the step from a copy and watching the
scenario that owns it report ABSENT.

What landed on 2026-08-30 is a different shape and is described as one: three
checks added INSIDE steps that already existed, so step deletion is not the
drive for them. Each was driven by the mutant it exists to catch — the suite
invocation detached from its flag array, one package's tests and then the whole
library's tests switched off, and a URL in a string literal, that last one in
both directions because the risk in the fix was that it would blind the check.
The oracle carries `suite-args-detached`, `suite-one-package-disabled`,
`suite-tests-disabled`, `citation-url` and `citation-after-url` for them.

`vet` had no witness until this measurement was taken; it passed 18 of the 18
scenarios that existed then with the step deleted, and the `vet-violation`
scenario exists because of that.

The oracle step is the one that cannot be closed from the inside: see below.

The sentence that stood here until 2026-09-06 said there is no CI on this
repository and there never would be. It was wrong, and this script has run on
every push since — see **In
CI** below. `verify.sh` is still the only arbiter there is, and CI is a second
place it runs rather than a second opinion. Which is why it is one command and
not a paragraph describing what a developer should run —
and why it has an oracle of its own, `scripts/test-verify.sh`, which plants a
defect in a copy of the tree and requires the row that owns that defect to be
the row that fails. `verify.sh` runs it as a step.

That loop closes only while it is wired, and it cannot close itself: a
`verify.sh` that drops its oracle step never runs the scenario that checks the
step is there. MEASURED 2026-08-29 — deleting the step is caught, but only
incidentally, by `shellcheck` objecting that `--inner`'s variable became
unused; composing past that one objection gives a clean PASS verdict with the
arbiter's own arbiter silently gone. Running
`scripts/test-verify.sh` directly is the check for that, and it is a human act,
not a wired one. The rest of what neither can see is in `docs/gates.md`.

### The rows added on 2026-09-05, and the two verdicts that came with them

**`netns-suite`, and why the unit suite got smaller.** The tests that
re-execute themselves into a user and network namespace and talk to a real
dnsmasq used to run inside the unit suite, under the same wall-clock ceiling.
That ceiling is T2's second instrument — it asks whether the suite has drifted
into waiting — and it was measuring two populations at once: a pure suite that
should never wait, and a set of runs whose whole job is to wait out real DHCP
and ARP intervals. MEASURED on the session box the day of the split: the pure
half runs in a fraction of its ceiling now, the namespaced half takes most of a
minute, and together they had left the ceiling with seconds of headroom while
M7 was about to add more namespaced runs.

The two populations are a PARTITION derived from ONE roster:
`internal/tools/testroster -netns` reports the tests that call the re-exec
helper, the pure suite is told to skip exactly those names, and the netns row
is told to run exactly those names. **A test that is excluded from both rows is
the failure this shape exists to refuse**, and it cannot happen by omission: a
test the classifier does not recognise is not skipped, so it runs in the pure
suite and its seconds land on the pure suite's ceiling. A roster that cannot be
derived at all fails BOTH rows rather than falling back to running everything.
Both rows report how many tests they examined; the netns row additionally
requires the set of names the run REPORTED to equal the roster, because a
`-run` regexp that matches nothing exits zero, and it treats a `SKIP` as a
failure, because those tests fail closed rather than skipping.

The other direction is the one the complement does not close, and it was open
until round 2: with the pure suite's `-skip` matching nothing, BOTH rows run
the namespaced tests, `go test` exits zero, and — MEASURED by review — the
combined seconds still fitted the pure suite's ceiling while the row went on
reporting how many tests were "held" for the other row. Both of those numbers
came from the roster that produced the filter, so the sentence was true of the
roster whatever the run did. The pure suite now runs with `-v` and reads the
tests it STARTED off its own output: a roster name appearing there is the
partition broken, and it is a failure with the leaked names in it. Scenario
`suite-partition-skip-inert`.

The netns row is an OUTER row: `--inner` does not have it, so the oracle's
copies of this tree do not each raise namespaces and a dnsmasq of their own.
What that leaves open is written down rather than argued away — the row is
driven inside the oracle by three scenarios, and a namespaced test failing for
a PRODUCT reason is driven by the real run and by no scenario. The three are
`netns-row-empty-domain` (the roster cannot be derived at all),
`netns-row-control` (the honest pass, both rows green with their counts) and
`netns-row-partition-broken` (the row's own `-run` narrowed to a single name,
so the run exits zero over a subset of its population and the set comparison is
the only thing that can see it).

**`readme-usage`.** README.md's Usage section prints a Go function and the
sentence under it says it is `ExampleClient` in `runtime/example_test.go`
*byte for byte*. Nothing checked that; a claim of identity between two files
was being made by prose. The row extracts both and `diff`s them verbatim — no
normalising, because the sentence says byte for byte and a row comparing a
normalised form would leave that sentence false while passing. Either side
extracting to nothing is a FAIL and not an agreement, since two empty files
diff clean. Driven in both directions: `readme-usage-drifts-in-the-readme`
takes the block out of the README, `readme-usage-drifts-in-the-example` moves
one byte of the function.

**`SKIPPED`, the third verdict, and the only one that means "not measured".**
The oracle is most of the run's wall clock and its subject is `verify.sh`
itself, the manifest and `scripts/`. When those files are byte for byte what
they were the last time the oracle passed here, `verify-oracle` records
SKIPPED, naming the hash and the file set it covers, and the verdict line still
says PASS only because every row that was not skipped passed. `./verify.sh
--oracle` runs it regardless, and that is what should be run before a merge.

The skip is keyed on the CONTENT of those files, recorded in a stamp that is
gitignored and per-clone. A `git diff` against a ref was ruled out for a
specific reason: a fresh clone at a commit that changed the arbiter has nothing
to diff against and would skip, where a stamp makes a fresh clone run the
oracle once. What binds the stamp to a real pass: it is written in one place,
after every check the row makes, and only when `record()` ACCEPTED the pass; it
names the root it was written for, so a stamp copied into another tree — every
oracle scenario copies this one — grants nothing there. Only `verify-oracle`
may record SKIPPED; `record()` rewrites a SKIPPED from any other row to FAIL.

What drives that arm, stated exactly, because the first version of this
sentence overstated it: the `self-check` row puts a skip by a row that may not
skip, and an honest one by the row that may, through `record()` on every run —
and the row also counts its probes and the refusals they earned against
`SELF_CHECK_PROBES_N` and `SELF_CHECK_REFUSALS_N` in `verify.manifest.sh`. The
count is what survives the composed edit: MEASURED by review, disabling the arm
AND deleting the probe that drives it in one edit left every row green and the
whole oracle green, because the only trace was a refusal count derived from the
case list that had just been shortened. Scenarios `self-check-guard-deleted`
(the arm disabled, the probe speaks) and `self-check-skip-arm-deleted` (both
removed together, the declared count speaks).

**Two bounds on the skip, both real.** The stamp is a LOCAL CACHE and not
evidence: it is gitignored and per-clone, and a stamp written BY HAND carrying
the hash `verify.sh` computes grants a skip, because any hand can compute what
`verify.sh` computes. So the merge rule is not "the stamp says it passed" — it
is an `--oracle` run at the head being merged, and since 2026-09-06 that run is
CI's, on a machine that has no stamp to inherit. See **In CI**.

The second bound is that the hash covers the ARBITER, so a scenario that
depends on the PRODUCT's shape can go stale without a covered byte moving.
Those scenarios are not typed out here. A typed list was, and it omitted eleven
of them; this one is DERIVED from `scripts/test-verify.sh` and quoted:

```stale-anchor-scenarios
ceiling-control
ceiling-fires
citation-after-url
citation-embedded-identifier
citation-trailing
citation-underscore
citation-url
citation-whitewash
citation-word-start
doc-number-reintroduced
gate-panic
gate-refuses
gofmt-violation
hang-bounded
min-declared-tests-floor
min-declared-tests-margin
netns-row-empty-domain
race-detector
readme-usage-drifts-in-the-example
readme-usage-drifts-in-the-readme
roster-gate-added
roster-gate-deleted
stale-citation
t1-violation
t2-violation
v6-fixture-mode-drift
v6-ra-absent
verdict-without-gomod
vet-violation
```

The rule is: a scenario names a path inside its copy of the tree that is not
`verify.sh`, not `verify.manifest.sh` and not under `scripts/` — directly, or
through a helper it calls. `TestStaleAnchorBoundNamesWhatTheOracleDerives`
performs that derivation and fails when it and this block differ, so the list
cannot go stale the way the sentence it replaces did. Its BOUND, stated rather
than argued away: the derivation is textual, so a scenario reaching the product
through a glob, a `find`, or a tool it runs inside the copy — with no path
written down — is invisible to it, and `suite-tests-disabled` and
`suite-partition-skip-inert` are both exactly that today. Which
is why this is the list a skipped run is not re-checking rather than a claim
that nothing else can go stale.

**`--light`, the scope, and why a scenario cannot hide behind it.** The oracle
plants one defect in a copy of the tree and runs the copy's `verify.sh` end to
end, once per scenario. A scenario that plants a shell or a document defect was
paying for the whole unit suite in its own copy in order to watch a lint row go
red. Those scenarios now run `--inner --light`, which omits the two expensive
rows and nothing else, and a run at that scope NAMES the rows it did not run on
its own verdict line. Which scenarios are light is declared in the manifest
beside the contract, applied by the oracle's dispatcher and by no scenario
body, and recorded as an observation that `verify.sh` compares against the
declaration. **A scenario cannot pass by scoping away the row it exists to
drive:** its contract demands a verdict from that row, an omitted row records
nothing, and a row that recorded nothing reads ABSENT. The manifest refuses the
combination outright, in the shell and again in Go, so it cannot be written
down.

### In CI

`.github/workflows/verify.yml`. Every push of every branch, and a manual
`workflow_dispatch`, produces one run. Since D41 that run is two lanes with one
arbiter between them, and every job of both runs on a GitHub-hosted
`ubuntu-24.04` image:

| job | what it runs | when |
| --- | --- | --- |
| `the oracle's domain` | `./verify.sh --oracle-hash` | always |
| `oracle shard I` | `./scripts/test-verify.sh --shard I/N` | see below |
| `the oracle verdict` | the shards, aggregated into one verdict | with the shards |
| `the arbiter` | `./verify.sh` | always |

**The rule the shape comes from.** Maintainer, D41: every check on the way into
`dev` finishes well under five minutes; `main` and a release may take longer;
there is no nightly, because the machine that would run one may be off. "If
GitHub is as fast as the hosted runner, prefer GitHub" — and for everything
except the oracle it is. `the arbiter` is the job `dev` is protected on, so it
is the job that has to meet the rule, and the oracle is the one row that cannot.

**Measured, not asserted.** Three runs of `the arbiter` at the head of the
branch that moved the lane here, each the whole arbiter with the oracle row
honestly skipped, on `ubuntu-24.04` with `nproc` 4 and 16 GB — the job prints
the core count rather than this page assuming it:

| run | job start to verdict | `verify.sh` itself | `unit-suite` | `netns-suite` |
| --- | --- | --- | --- | --- |
| 34204814646 | 4m03s | 198s | 42s | 86s |
| 34206597940 | 4m06s | 201s | 42s | 88s |
| 34207096133 | 4m20s | 200s | 41s | 87s |

So the rule is met with about forty seconds to spare, and the spare is where a
reader should look first when it stops being met: roughly half of each job is
`verify.sh` and the other half is the checkout, the toolchain and the three
packages `prepare.sh` installs. The oracle, for the same tree, is a matrix of
ten shards whose longest ran 11m34s (run 34204814646) — which is why it is not
in this table and not on the way into `dev`.

**The ceilings were re-derived on this image, by the method each states**, and
that is a thing to do on the machine that runs them rather than a formality:
`SUITE_CEILING_SECONDS` moved 102 to 84 (twice the slowest of the three figures
above, the rule unchanged; the old value came from a two-core hosted runner and
was 2.4 times what this image draws), and `NETNS_CEILING_SECONDS` stayed at 140
(the measured wall plus headroom that covers two more rounds of this row's
largest increase; 140 minus 88 leaves 52s against a floor of 32s). The
`ceiling-band` scenario's own band moved with them, 5..120 to 13..102, and its
edges are now derived from this row's figures instead of being inherited from a
ceiling two values ago.

**When the oracle runs**, stated here and enforced in the workflow rather than
the other way round:

- a push to the release branch, always;
- a `workflow_dispatch`, always;
- any push whose tree reaches an arbiter that no green run has published.

**There is no path filter, and that is the design.** "The oracle's own domain
changed" is one fact, and `verify.sh` already derives it: the file set its skip
stamp hashes, which is `verify.sh` itself, `verify.manifest.sh` and everything
under `scripts/`. `./verify.sh --oracle-hash` prints that set, its size and its
hash and measures nothing; the lane asks, and keeps no list. A `paths:` filter
in the workflow would be the same fact derived a second time, and the looser
derivation would decide which pushes are checked — so `internal/publication`
refuses a `paths:` or `paths-ignore:` key anywhere in a workflow here, and
demands that the lane still asks the question.

Keying on the CONTENT rather than on a diff against a ref is stronger than
"the diff touched `scripts/`", in the direction that matters: a change and its
revert are the same tree, and the second one is already proved; a tree nobody
has proved runs the oracle even if the push that produced it looks innocent.

**What a skip rests on, and why it is not a file.** Locally the oracle's skip
stamp is a per-clone cache: this tree ran this oracle, at this hash, and need
not run it again. A hosted machine has no such history — every job starts fresh
— so the sentence has to cross machines, and there were three ways to do it:

- **an Actions cache keyed on the hash.** Cheap and wrong: a cache entry is
  restorable by any branch that shares the key, the path is the same for every
  branch, and the entry is a file whose provenance is its own name. Nothing
  reads back who wrote it.
- **an artifact carrying the stamp.** The same objection with a longer
  download. A file that has to be trusted to be read is not evidence.
- **nothing carried at all.** The stamp is COMPUTED in the job, from the
  checked-out tree's own hash, and it is written only after the API says a
  green `the oracle verdict` job published that hash. A run id is a thing the
  API answers about; a file is not.

The third is what the lane does. `.github/lane/oracle-skip.sh` asks
`verify.sh --oracle-hash` for the hash, lists the unexpired artifacts named
`oracle-pass-<hash>`, and puts each owning run through three conditions in
`.github/lane/oracle-run-check.sh`: the artifact exists unexpired and that run
owns it; the run is a run of this repository's `verify.yml`; and it holds a job
named `the oracle verdict` whose conclusion is `success` — the JOB, because a
run's own conclusion is null while it is in flight and can be `success` over an
oracle that was skipped. Only then is the stamp written, and the write sits
below that check and below nothing else. The publication sits below the
aggregation in the same way: `the oracle verdict` uploads the name only on its
own success, so **a red run leaves no name to look up.**

The lane then runs `./verify.sh` — the arbiter, whole, with the one row the
manifest declares skippable honestly SKIPPED — and the vacuity step asks the
API *again*, over the hash the arbiter itself printed. Three fooling shapes die
there: a justification naming a run that passed at a different hash (the
arbiter's own row names the hash it skipped at, and the two are compared); a
justification naming a run whose aggregation job was red or cancelled; and a
justification naming a run that does not exist, or exists in another repository
or another workflow. With no stamp at all, `./verify.sh` simply runs the whole
oracle itself and the job hits its timeout — which is loud, and is the correct
direction: **a lane that cannot earn its skip does not get one.**

**The escapes, beside the claim.** Anybody who can push a branch here can also
edit `.github/`, and `.github/` is not in the set the hash covers — so a
workflow edited to publish the name is a deliberate forgery this does not
close, exactly as the local stamp's own comment says of a stamp written by
hand. What is closed is the accident and the cheap attempt: a red run, a run at
another hash, a run that does not exist, an expired artifact, a run in another
repository. The second escape is a deadline rather than a hole: the artifact
expires after thirty days and the lookup demands an unexpired one, so an
untouched arbiter is re-proved after thirty days rather than skipped forever.

**The oracle matrix is one verdict.** The shards are cut from
`MANIFEST_SCENARIOS` at run time — the count is the roster divided by the shard
size, the membership is a round-robin over the same list — so a scenario added
to the manifest lands in a shard with nothing in the workflow edited, and a
shard that would be empty is a refusal rather than a job that quietly runs
nothing. Each shard holds its own scenarios to the contracts
`verify.manifest.sh` declares for them, through `scripts/oracle-contracts.sh` —
the same comparison `verify.sh` makes, restricted to that shard — because a
shard that only collected `RESULT` lines would be a count of names.
`the oracle verdict` then refuses: a matrix result that is not `success`, a
shard that left no account, a shard that named no members, a non-zero shard
exit or contract status, an unaccounted or breached scenario, a shard that held
fewer scenarios to their contracts than it ran, a scenario in two shards, a
scenario in none, a shard that answered under its share of the oracle's own
time floor, and a total that is not the roster's size.

**One copy of the suite at a time inside a shard.** `ORACLE_JOBS` is pinned to
one in the matrix, and that is the point of sharding rather than a concession
to it: every ceiling in `verify.manifest.sh` is a wall clock derived with one
copy of the suite running, and a shard running four copies at once would be
measuring contention against a ceiling nothing derived under contention. The
parallelism lives across jobs, where it cannot perturb a wall clock.

**Why a job might run on a machine of ours, and what has to stay true if one
ever does.** Since D41 no job here names a self-hosted label: the standing
runner stays registered and idle, for the day something needs a machine of
ours. The rule below is therefore VACUOUS over today's tree, and it is kept and
published anyway, because it is a property of the workflow SET and not of the
runner — the day a job needs that machine, this is the only thing between the
machine and a stranger's tree, and a rule written on that day would be written
by somebody who wanted the job to run.

A pull request from a fork proposes the FORK's tree. A job that runs on a
self-hosted runner and can be started by one is a stranger's code executing on
that machine, with that machine's filesystem, network and whatever the runner's
account can reach. So the rule is not about who owns the runner and not about
who can read this repository — it is a property of the WORKFLOW:

> A job that runs on a self-hosted runner must never be reachable from a fork's
> pull request.

That property held while this repository was private and holds unchanged after
it is public. Nothing about it was ever an argument from privacy, and a reader
who finds one here should treat it as a defect in this page.

This lane satisfies it structurally rather than by configuration. Its triggers
are `push` and `workflow_dispatch`, and it has no `pull_request` or
`pull_request_target`. A fork's push is a push in the fork, and starts nothing
here — so **a fork's pull request runs nothing in this repository at all**: no
job, no step, no checkout of the proposed tree onto the runner. The lane also
holds no secret, so there is nothing for a job to carry off even if one could
be reached.

**Running a contributor's branch is therefore a deliberate act**, and that is
the cost of the arrangement rather than a gap in it: somebody who can write
here pushes the branch to this repository, or dispatches the workflow, having
read the diff first. A pull request never buys itself a run.

**The observer is `internal/publication`**, in the unit suite, and it carries
two rules. They are stated here once each, and both are true of the code as it
is written rather than of a scan that has to be right about a workflow first.

> **One.** The word `secrets` does not appear anywhere under `.github/`.

Nothing there recognises a secret. The word itself is refused — any case, as a
whole word, in a workflow or in any other file the directory holds, in a
comment as readily as in an expression — and every occurrence is red, naming
the file and the line.

The rule is the word and not a *read* of one, and that is the whole design. A
check that recognised a read would have to enumerate how one is written, and
GitHub honours several ways: the context reached by a dot, by an index in
either kind of quotes, by an index computed at run time, and the `secrets:` key
of a call to a reusable workflow, quoted or bare. A spelling such a check did
not know would be reported as no secret at all, which is the one answer this
page may never carry. Refusing the word needs no enumeration and no parser:
this lane holds no secret and needs none, so there is no innocent occurrence to
tell from a guilty one.

The boundary is a word boundary, and that is the whole of it: `secretsmanager`
and `my_secrets_dir` are other words and are not refused. A workflow file
reaches a repository secret in exactly two ways — the `secrets` context and the
`secrets:` key of a call to a reusable workflow — and both are the bare word.
Refusing an identifier that merely contains those letters would make this a
rule about letters. The escape, stated beside the claim: the automatic token
also arrives as `github.token`, which carries no such word; that one is bounded
by `permissions:`, which this lane sets to `contents: read`.

The domain is the directory rather than the repository, and that is not an
exemption for the rest of the tree — it is the shape of the rule. A rule has to
be writable in the check that carries it and on the page that publishes it, and
neither `internal/publication` nor this page is under `.github/`. Inside the
directory it is everything: the workflows, the linter configuration beside
them, and whatever is added there later. **The day a workflow here genuinely
needs a secret, the rule is widened deliberately — this paragraph, the check
and its cases moving together, with the argument for why that lane may hold
one — and never by teaching the check to tell a harmless occurrence from a
harmful one.**

> **Two.** No job on a runner of ours is reachable from a fork's pull request.

The scan reads the workflows over a STATED SUBSET of YAML rather than over
YAML. Inside the subset it fails if the workflow SET puts a runner whose label
is not one of GitHub's hosted images within reach of a `pull_request` or
`pull_request_target` trigger — in one file, or across two, because a workflow
called with `uses:` runs its jobs on the calling repository's runners and so
inherits its caller's triggers. Outside the subset it REFUSES the file, naming
the line and the shape it would not read, and a refusal is red. So the claim
this row supports is not the universal over every workflow that could be
written; it is the one the refusal makes true by construction:

> Every workflow in this repository is written in the subset the scan reads,
> and within that subset no job on a runner of ours is reachable from a fork's
> pull request.

The subset, which is what a contributor's workflow has to be written in: no
carriage return anywhere, no tab in any line's indentation, and not the
forbidden word; root keys at the left margin, and every line at the left margin
one of them; `on:` a plain scalar, a flow collection closed on its own line, or
a block whose children are indented deeper than the key; `jobs:` such a block,
each job a key with no inline value; every line at a job's key column a `key:`;
a job's `runs-on:` in those same value forms, its block form a sequence; a
job-level `uses:` naming a path ending `.yml` or `.yaml`; no `${{ }}`
expression anywhere in an `on:` or `runs-on:` block, nor in either as a value;
and no YAML anchor or alias in a value the scan enumerates. Everything else is
refused by name: a flow collection spread over two lines, a `|` or `>` block
scalar in one of those places, a tab-indented file, a CRLF file, an anchor, an
alias, an expression, a `runs-on:` written as a `group:`/`labels:` mapping, a
sequence written at its key's own column, a `---` document marker, a root
mapping written indented, and a key with a space before its colon, which YAML
permits — `on :` and `runs-on :`. Each of those is ordinary YAML and GitHub
would honour it; the refusal is the point. The direction that fails closed is
"the reader could not read this", never "there is nothing here" — a file that
parses to nothing agrees with every property asserted over it. Somebody who
meets a refusal writes the workflow in the subset, or widens the subset and its
cases together. This lane's own workflow is inside it, which the row
demonstrates on every run rather than claiming here.

**The tab refusal is wider than the property, and that is a cost this page owes
you rather than a defect.** A tab in the leading whitespace of ANY line of a
workflow file is refused, including inside a `run: |` script — a Makefile
recipe indented with a tab, say, which is valid YAML and which GitHub would run
happily. It is refused because every column in this reader is counted in spaces
and a tab makes each of them a guess, and it is deliberately not narrowed to
"outside a block scalar": deciding where a block scalar ends is the same
position-keyed reading whose mistakes this whole subset exists to refuse. What
to write instead: indent with spaces, and where something genuinely needs a
tab — a recipe, a fixture — put it in a file of its own and have the script
call it. No tracked workflow here carries a tab.

Every workflow is floored as well, and the runner half is per JOB: a workflow
the scan read no trigger out of, and a job that yields neither a runner label
nor exactly one callee, fail the suite instead of passing quietly. Neither
floor may be taken any wider than that. Summed over the set, the trigger floor
is satisfied by any one file that parses; taken over the file, the runner floor
is satisfied by any one job that does — and a job whose runner went unread,
beside a job carrying a `uses:`, is exactly what stayed invisible.

Two things it deliberately does not do: it does not refuse `self-hosted` as
such — the lane was self-hosted by decision when the scan was written, and such
a gate would have been red on that day and deleted rather than obeyed — and it
does not know who owns a runner, only that a label is not one GitHub hosts. Its
remaining bound is stated in the file: a `uses:` edge it cannot follow — a
workflow in another repository, or a local path naming no file here — is a
failure whenever the calling workflow carries a fork trigger, not an omission.

**What keeps a vacuous row from being a check with one possible verdict.** The
row applies the scan to the tree, and the tree gives it nothing to find. Its
verdict is driven elsewhere: the scan's own cases put fork-reachable
self-hosted pairs through the same functions, direct and inherited across a
`uses:` edge, and demand the finding — as they do for every shape in the subset
above, in both directions. The row is the application; the cases are the check.

**What a hosted machine closes, and what it does not.** Every job starts on a
fresh image, so the things a standing runner carried between jobs are gone:
warm Go caches nothing read back, a writable `~/.config/go/env` any job could
have edited, a stamp left in a work directory, and a queue of one job at a time
where a reviewer's own `--oracle` competed with the lane for the same cores
(run 34067850871 cost `netns-suite` 16s of its margin that way). What a hosted
machine reopens instead is a shared store that outlives a job: the Actions
cache and the artifact store are reachable by every branch, which is exactly
why the oracle skip carries nothing through either of them and asks the API
about a run instead, and why `cache: false` is set on every `setup-go` here.

**Contention is now recorded rather than inferred.** A hosted image is not a
machine with nobody else on it — it is a virtual machine whose host has other
tenants — so the arbiter job prints its core count, its memory and its load
average before AND after the arbiter, into the same artefact as the row times.
Twice, because a figure taken once cannot say whether the load arrived during
the measurement. That is what a ceiling row's first red is read against: with
no load figure, the first red of that class reads as drift in the suite.

**The job's verdict IS the arbiter's verdict.** Green means `verify.sh` printed
`VERDICT: PASS` over every row `verify.manifest.sh` declares. Anything else is
red, including a run that never reached the arbiter at all — a failed checkout,
the job's own timeout. There is no branch filter and no path filter, because an
absent run is not a green run and nothing about a commit should be able to
decide that this job does not apply to it.

**A `VERDICT: PASS` line reads the same whether the oracle ran or was
skipped**, and a job reading only the exit status, or only that line, cannot
tell those two apart — nor either of them from an arbiter that printed nothing
at all. That is what the last step is for, and since D41 it has one more thing
to tell apart: a skip that rests on a run from a skip that rests on a file
somebody wrote.

So `.github/lane/verdict.sh` refuses an empty output; requires a `PASS` row for
**every** name in `MANIFEST_ROWS`, sourced from the manifest while the job
runs, allowing SKIPPED only for a row `MANIFEST_SKIPPABLE_ROWS` declares
skippable, and refusing any declared row that recorded a FAIL; requires the
`verify-oracle` row either to carry the oracle's own account over the scenario
count the manifest declares, or, if it is SKIPPED, to name its own hash and its
own count and to have a justification whose hash is the one the arbiter printed;
requires one verdict line naming the manifest's row count; and only then asks
the API a second time about the run that skip rests on. What that step is not is
a second manifest: it types no name and no number of its own, and an edit that
shrinks the roster and the counts together still has to get past
`manifest_check` and `internal/manifest`, where CI adds no layer.

**The anchor is the margin**, and it is why every pattern in that step is
anchored on a row name at column zero: a SKIPPED oracle row's own detail
CONTAINS the string `ORACLE PASS:`, because it quotes what the stamp recorded.
A grep for that token anywhere in the output accepts a skipped oracle, which is
the check the D35 design would have shipped.

**It is a script and not a `run:` block**, and so are the lane's other
decisions — the domain, the shard, the skip, the aggregation. Two reasons that
are the same reason: the `shellcheck` row lints a script and cannot lint a step
body, and an oracle scenario can drive a script and cannot drive a step.

**The merge rule.** A green run at the head SHA being merged, plus the
reviewer's CLEAR. The reviewer no longer re-runs the oracle on their own box.
Read that rule exactly: a green run at THAT SHA, because a force-push moves a
branch and leaves its run behind, and an absent run is not among the things it
accepts. A cancelled run at that SHA is neither green nor red; it is not a
verdict, and the green run is the one to read.

**The bound, and it is back.** Two executions of one script are not one
execution: the machine the lane runs on is not the box a developer runs
`./verify.sh` on, and its differences have changed a verdict four times.
MEASURED on the hosted images of 2026-08 and 2026-09, each cause named with the
runs that show it — the list is kept because every one of these is a hosted
image again:

- **Namespaces.** The image restricted unprivileged user namespaces through
  AppArmor. Left at its default the namespaced child STARTED — the namespace
  was created — and then every netlink call inside it was refused, so `ip link
  add` answered `Operation not permitted` and the `netns-suite` row went red
  (run 33992151078). `.github/lane/prepare.sh` clears it with one sysctl on
  every hosted job, and records the fact where the knob does not exist rather
  than assuming its absence.
- **Cores, against a ceiling derived elsewhere.** The pure suite's ceiling was
  measured on a box with many times that runner's two cores. With the oracle
  running two copies at once, the root run's suite and the copies' suites all
  ran past the ceiling and nothing else was wrong with them (runs 33992151078,
  34008425787). The matrix answers it by running one copy per shard and putting
  the parallelism across jobs, and the ceilings themselves are re-derived on the
  image that runs them; `verify.sh` states each derivation beside its number
  and `verify.manifest.sh` pins the value, so moving one is an edit in two
  files.
- **Scheduling, and this is the one that found a real defect.** Two cores made
  `TestSquatterWaitReportsTheFramesThatArriveDuringIt` deadlock: the waiter it
  drives returned through its match arm without reporting the frame that ended
  the wait, so the number of reports depended on which of two goroutines the
  scheduler ran first, and the test — which takes delivery of each report —
  blocked forever on one that was never written. Bounded only by `go test
  -timeout`, so it read as a suite hang, never as a failure. MEASURED on runs
  33995090303, 33999661871 and 34003796997. Run 34008425787 carries the fix.
  This box never showed the defect at all: it takes contention, and the first
  machine to have any was the runner.
- **A namespace read on the wrong thread.** The v6 client read the link-local
  address of whichever thread the Go runtime happened to schedule it on rather
  than the one it was built in, which is a race that a two-core machine loses
  and a many-core one usually wins. It reddened runs 34012610376 and
  34024003237 and nothing on this box. Fixed on `main` at 6290220. This is the
  strongest instance of the whole paragraph, and it went unnamed here for a
  day — the fourth cause the sentence above used to undercount.

**What that bound is now.** Two machines again, which is the useful state: a
developer's box and a hosted image are different hardware, and a ceiling that
one meets and the other does not is a thing somebody has to look at rather than
a thing nobody can see. The first two causes above are handled by the lane
rather than by luck — `.github/lane/prepare.sh` clears the namespace
restriction where the knob exists and installs the three tools the arbiter
shells out to, and the shards run one copy of the suite at a time — and the
last two were real defects in the library that only a machine with contention
could show. A green run and a green local arbiter are two measurements again.


### The two gates

- **T1 — ring 1 imports nothing that does I/O.** Enforced by parsing the import
  set, not by convention.
- **T2 — no test waits on wall-clock time.** Enforced by an identifier
  allowlist over test files, plus a wall-clock ceiling on the suite.

Both are load-bearing guarantees rather than hygiene, and both are checked
against a planted violation rather than trusted. The allowlists the gates read
are checked too, and separately: a correct gate enforcing a widened table is
the failure a gate test cannot see. What each one **cannot** see
is written down in `docs/gates.md`; read that before relying on either.

### One thing that surprised us, recorded because it will surprise the next reader

A reply from a server on the SAME HOST arrives with its UDP checksum **not
computed**. Linux writes the folded pseudo-header sum into the field and leaves
completing it to hardware, so an AF_PACKET reader on the far side of a veth
pair sees `CHECKSUM_PARTIAL` bytes. MEASURED 2026-08-29 against dnsmasq 2.91:
the captured OFFER held `0x24f6` in a field whose completed value is `0xe58c`.
Both are fixtures in `runtime/ipudp_test.go`, asserted against the captured
bytes. `0x24f6` is the pseudo-header sum for that source, destination and
length and nothing else — flip a payload octet and the completed checksum
moves while the field does not, which is a test, and is exactly why the field
says nothing about the payload.

A client that verifies the checksum strictly therefore never sends a REQUEST —
which is precisely what the first run of the dnsmasq test did, for two minutes,
retransmitting DISCOVER while the server answered every one of them. The parser
recognises that exact value, reports the payload as unverified, and the
transport counts it — though the counter says only what a field held, never
where the sender was.

**The bound, both halves of it:** neither an uncompleted checksum nor RFC 768's
zero checks the payload, so a corrupt payload is accepted under both — more
cheaply under the zero. The accepting value in the uncompleted case is not a
lucky collision either: it is a pure function of source, destination and UDP
length, all read from the frame itself, so anyone who can put a frame on the
link can compute it. Closing it needs `PACKET_AUXDATA`, whose
`TP_STATUS_CSUMNOTREADY` states the deferral as a fact instead of leaving us to
infer it — new I/O, and a later milestone.
