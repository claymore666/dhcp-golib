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
`workflow_dispatch`, produces one run with one job, and the job is:

    ./verify.sh --oracle

byte for byte the command this document gives a developer, at the oracle's own
default job count.

**Where it runs, and this is TEMPORARY.** Until 2026-09-06 the job ran on a
GitHub-hosted two-core `ubuntu-24.04` image and took about ninety minutes:
twelve runs measured, the four unmutated ones at the end of that period each
between eighty-seven and ninety-one billed minutes (runs 34036002593,
34040618756, 34045474164, 34050089381). Since D36 it runs on a standing
self-hosted runner labelled
`dhcp-golib`, on the same machine every ceiling, floor and timeout in
`verify.sh` and `verify.manifest.sh` was derived on, where the same command
takes about a seventh of that. MEASURED: `./verify.sh --oracle` wall to wall in
a local copy at 8c87caf is 818s, and on the runner the branch's own green run
34065275390 recorded 831s inside a job of 13m51s, checkout to verdict. The
runner leaves that machine when a shared pool serves this repository;
`runs-on` is the only line that has to move.

**Why a job may run on a machine of ours at all, and what has to stay true.**
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
reads no repository secret, so there is nothing for a job to carry off even if
one could be reached.

**Running a contributor's branch is therefore a deliberate act**, and that is
the cost of the arrangement rather than a gap in it: somebody who can write
here pushes the branch to this repository, or dispatches the workflow, having
read the diff first. A pull request never buys itself a run.

**The observer is `internal/publication`**, in the unit suite, and it reads the
workflows over a STATED SUBSET of YAML rather than over YAML. Inside the subset
it fails if the workflow SET puts a runner whose label is not one of GitHub's
hosted images within reach of a `pull_request` or `pull_request_target`
trigger — in one file, or across two, because a workflow called with `uses:`
runs its jobs on the calling repository's runners and so inherits its caller's
triggers. It also fails if any workflow hands secrets over, whether by naming
one (`secrets.NAME`) or by `secrets: inherit`, which names none. Outside the
subset it REFUSES the file, naming the line and the shape it would not read,
and a refusal is red. So the claim this row supports is not the universal over
every workflow that could be written; it is the one the refusal makes true by
construction:

> Every workflow in this repository is written in the subset the scan reads,
> and within that subset no job on a runner of ours is reachable from a fork's
> pull request and no workflow hands a secret over.

The subset, which is what a contributor's workflow has to be written in: no
carriage return anywhere and no tab in any line's indentation; root keys at the
left margin; `on:` a plain scalar, a flow collection closed on its own line, or
a block whose children are indented deeper than the key; `jobs:` such a block,
each job a key with no inline value; a job's `runs-on:` in those same value
forms, its block form a sequence; a job-level `uses:` naming a path ending
`.yml` or `.yaml`; no `${{ }}` expression anywhere in an `on:` or `runs-on:`
block, nor in either as a value; and no YAML anchor or alias in a value the
scan enumerates. Everything else is refused by name: a flow
collection spread over two lines, a `|` or `>` block scalar in one of those
places, a tab-indented file, a CRLF file, an anchor, an alias, an expression, a
`runs-on:` written as a `group:`/`labels:` mapping, and a sequence written at
its key's own column. Each of those is ordinary YAML and GitHub would honour
it; the refusal is the point. The direction that fails closed is "the reader
could not read this", never "there is nothing here" — a file that parses to
nothing agrees with every property asserted over it. Somebody who meets a
refusal writes the workflow in the subset, or widens the subset and its cases
together. This lane's own workflow is inside it, which the row demonstrates on
every run rather than claiming here.

Every workflow is floored as well, and the runner half is per JOB: a workflow
the scan read no trigger out of, and a job that yields neither a runner label
nor exactly one callee, fail the suite instead of passing quietly. Neither
floor may be taken any wider than that. Summed over the set, the trigger floor
is satisfied by any one file that parses; taken over the file, the runner floor
is satisfied by any one job that does — and a job whose runner went unread,
beside a job carrying a `uses:`, is exactly what stayed invisible.

Two things it deliberately does not do: it does not refuse `self-hosted` as
such — this lane is self-hosted by decision and such a gate would be red on the
day it was written — and it does not know who owns a runner, only that a label
is not one GitHub hosts. Its remaining bounds are stated in the file: the
secret scan is textual, so a secret reached through a composite action is
outside both spellings; and a `uses:` edge it cannot follow — a workflow in
another repository, or a local path naming no file here — is a failure whenever
the calling workflow carries a fork trigger, not an omission.

Two consequences worth stating rather than discovering:

- **One runner is one job at a time.** GitHub queues the rest. Nothing here
  serialises anything and no bound was changed for it; `timeout-minutes`
  counts execution, not the wait for a slot.
- **The lane shares the machine with the people who read it.** A reviewer
  running `./verify.sh --oracle` on that box is competing with the job for the
  same cores, and both are timed against wall-clock ceilings. Measured, not
  assumed: run 34067850871 ran the whole lane inside a reviewer's local
  `--oracle` at the oracle's default job count, and both printed `VERDICT:
  PASS`. The lane's `netns-suite` went from 90s to 106s against its 140s
  ceiling and its `unit-suite` from 20s to 24s against 102s. Nothing broke and
  no ceiling was moved to accommodate it; if contention ever does redden a row,
  the answer is a scheduling rule, not a looser ceiling.

**The job's verdict IS the arbiter's verdict.** Green means `verify.sh` printed
`VERDICT: PASS` over every row `verify.manifest.sh` declares. Anything else is
red, including a run that never reached the arbiter at all — a failed checkout,
the job's own timeout. There is no branch filter and no path filter, because an
absent run is not a green run and nothing about a commit should be able to
decide that this job does not apply to it.

**Always `--oracle`, and the last step is why that is not enough on its own.**
The skip is a per-clone local cache. A standing runner is exactly the machine
that could carry one from a previous job, so the flag stops being a formality
here — and the checkout step's own clean removes the stamp before it can
matter. What the flag removes is the shape where a `VERDICT: PASS` line reads
the same whether the oracle ran or was skipped. A job reading only the exit
status, or only that line, cannot tell those two apart, nor either of them from
an arbiter that printed nothing at all.

So the job's last step refuses an empty output; requires a `PASS` row for
**every** name in `MANIFEST_ROWS`, sourced from the manifest while the job
runs, and refuses any row that recorded something else; requires the
`verify-oracle` row to carry the oracle's own account over the scenario count
the manifest declares; and requires one verdict line naming the manifest's row
count. What that step is not is a second manifest: it types no name and no
number of its own, and an edit that shrinks the roster and the counts together
still has to get past `manifest_check` and `internal/manifest`, where CI adds
no layer.

**The merge rule.** A green run at the head SHA being merged, plus the
reviewer's CLEAR. The reviewer no longer re-runs the oracle on their own box.
Read that rule exactly: a green run at THAT SHA, because a force-push moves a
branch and leaves its run behind, and an absent run is not among the things it
accepts. A cancelled run at that SHA is neither green nor red; it is not a
verdict, and the green run is the one to read.

**The bound, and it has changed shape.** While the lane ran on a hosted image,
the honest statement was that two executions of one script are not one
execution: the runner was not the box the ceilings, timeouts and floors were
measured on, and its differences changed a verdict **four** times. MEASURED,
and each cause named with the runs that show it:

- **Namespaces.** The image restricted unprivileged user namespaces through
  AppArmor. Left at its default the namespaced child STARTED — the namespace
  was created — and then every netlink call inside it was refused, so `ip link
  add` answered `Operation not permitted` and the `netns-suite` row went red
  (run 33992151078). The workflow cleared that with one sysctl. That step is
  gone with the image: this kernel has no such knob, and the netns rows have
  run unprivileged on this machine since 2026-08-29.
- **Cores, against a ceiling derived elsewhere.** The pure suite's ceiling was
  measured on a box with many times that runner's two cores. With the oracle
  running two copies at once, the root run's suite and the copies' suites all
  ran past the ceiling and nothing else was wrong with them (runs 33992151078,
  34008425787). So the hosted lane ran one copy at a time and pinned
  `ORACLE_JOBS`. That pin is gone too: this is the machine the ceiling was
  derived on.
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

**What that bound is now.** There is one machine. The lane's ceilings and the
lane's runs describe the same hardware, so they can no longer disagree — and
therefore can no longer warn. The two-measurement shape returns the day the
runner moves off this box, and every paragraph that rests on it (the netns
ceiling's closing bound in `verify.sh`, the suite ceiling's) says so where it
stands. A green run and a green local arbiter are now one measurement taken
twice, which is a weaker thing than what this section used to be able to claim.


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
