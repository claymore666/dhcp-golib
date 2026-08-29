# The M0 gates, and what each one cannot see

Written at M0, against an empty package, before any protocol code exists. A
gate added after the code it guards gets weakened to fit the code; these were
added first so that any inconvenience shows up now, when it is cheapest.

Nothing below is a completeness claim. Each section states a bound and names
the escape beside it.

Run everything with:

    ./verify.sh

Exit 0 is PASS and is the normal state. Exit 1 is FAIL. A step that cannot be
measured is a FAIL, never a skip.

---

## T1 — ring 1 imports nothing that does I/O

`internal/gates/t1`. Policy lives in `internal/gates/rings`.

Ring 1 (`proto/`) is the state machine and it is pure: `Step(now, rnd, ev)`
takes time and entropy as parameters instead of reading them. That is what
makes the suite instant and offline replay bit-exact. The day ring 1 can read
a clock or open a socket, both properties are gone and no test will say so —
which is why this is a gate and not a comment.

Ring 0 (`wire/`) is held to the same policy, because ring 1 imports it and an
impure ring 0 makes ring 1 impure transitively.

### Four rules

| Rule | What it does | Blind to |
|---|---|---|
| A | Transitive dependency closure via `go list -deps`; a pure ring may depend on no module-internal package outside the pure rings | Files excluded by a build constraint |
| B | Direct imports of **every** `.go` file under a pure ring root, parsed with `go/parser`, build constraints ignored | Anything transitive |
| C | Identifier-level: only allowlisted identifiers of a restricted package may be named | Indirection — a variable holding `fmt.Println` |
| D | Non-vacuity: every declared ring root must exist and hold a non-test `.go` file | A root that exists and is populated but is no longer the real ring |

**A is not an independent second instrument today and must not be described as
one.** Because B scans every file under every pure root, and a pure ring may
currently depend on nothing but another pure root, A's module-internal findings
are a subset of B's. A becomes load-bearing the day a pure ring is allowed a
dependency B does not scan — a third-party package, or a module-internal
package outside the pure roots — because B sees only the import line while A
sees what that import drags in.

**Allowlists, not denylists.** The requirement is written as "ring 1 imports no
`net`, `time`, `os`, `context` or `syscall`", and implementing that literally
would be a denylist keyed on today's spelling, admitting everything nobody
thought to name. `rings.PureStdlib` is the complete set of standard-library
packages a pure ring may import; anything else is refused by default.

Two consequences of that, worth stating rather than discovering:

- `net/netip` is admitted and `net` is not. netip is value types with no
  resolver, no socket and no ambient state. A denylist written as `== "net"`
  would have admitted `net/http`; one written as a `net` prefix would have
  banned netip.
- `fmt` is admitted, because `Errorf` and `Sprintf` are unavoidable, and it is
  the one admitted package that can perform I/O. Rule C closes that by
  restricting which `fmt` identifiers a pure ring may name — `Println` and the
  `Fprint`/`Scan` families are absent.

### What T1 cannot see

1. **Indirection.** `var p = fmt.Println` in a non-pure package, called from
   ring 1 through a function value or an interface. Rule C reads selector
   expressions, not the call graph.
2. **`unsafe`, `go:linkname` and assembly.** A `.s` file or a linkname
   directive reaches anything without an import. Not scanned at all.
3. **Impurity that is not an import.** A package-level `var` initialised from
   a global, a `func init()` with a side effect inside an allowlisted package,
   a map iterated in nondeterministic order. T1 is a claim about the import
   set; it is not a proof of determinism.
4. **Generated code, before it is written to disk.** `go:generate` output is
   checked once it exists as a file, and not before.
5. **`_test.go` files under a pure root.** Deliberate: T1 is a claim about the
   package, not about its tests. A ring-1 test reading a golden file does not
   make the state machine impure. T2 governs test files.
6. **A pure stdlib package that stops being pure.** The allowlist is a set of
   names checked against a policy decision made by a person. If a future Go
   release gives `strconv` a background goroutine, T1 will not notice.
7. **The ring layout itself.** Rule D checks that the four roots exist and are
   populated. It cannot check that `proto/` still contains the state machine.
8. **Files under `testdata/`, `vendor/` and `.git/`.** Both gates share
   `scan.GoFiles`, which skips them. For `testdata/` the reason is the same one
   T2 gives: the go tool does not compile it, so nothing there is part of any
   binary, and it is where the gates' own deliberate violations live. This was
   documented for T2 and not for T1 until 2026-08-29, although the two gates
   have always walked the tree with the same function.
9. **Its live domain at M0 is inert.** MEASURED 2026-08-29: `proto/doc.go` and
   `wire/doc.go` are doc comments with no imports, so on the real tree rules B
   and C judge zero import lines and rule A a closure of two packages — the two
   rings themselves. Rule D is what stops that from being reported as a vacuous
   pass; the rules are actually exercised in `internal/gates/t1`'s own cases,
   against planted violations. T2 states the equivalent bound as item 4 below,
   and T1 did not state it at all until this line was written.

## T2 — no test waits on wall-clock time

`internal/gates/t2`.

This library has no CI and, per the build plan, will not get any: the
self-hosted runners belong to the plugin repository and cannot serve a second
private repo without an organisation. The only thing that runs this suite is a
person running it. A suite slow enough to avoid is a suite that is not run, and
then nothing observes anything.

The older half of the reason: a test that waits gets "fixed" by waiting
longer, and a longer timeout is how a real user-facing failure hid in the v1.x
plugin for months.

### Two rules, in two different instruments

- **Identifier allowlist**, in the gate. In every `_test.go` file, a reference
  to a restricted package must name an identifier on that package's allowlist.
  `time.Sleep`, `After`, `Tick`, `NewTimer`, `NewTicker` and `AfterFunc` are
  absent from it, as is anything the standard library adds later. Aliases are
  resolved from each file's own import declarations, so `import clk "time"`
  then `clk.Sleep` is caught. `context.WithTimeout` and `WithDeadline` are
  restricted too: a deadline on a context is a wall-clock wait under another
  name, because whatever blocks on `ctx.Done()` is blocking until a timer
  fires.
- **A wall-clock ceiling on the suite**, in `verify.sh`, currently 60s. This is
  a genuinely different instrument: the gate reads source, the ceiling reads
  the clock, so a wait the gate cannot see still costs time here.

`time.Now`, `time.Since` and `time.Until` **are** allowed. They read the clock;
they do not wait on it, and T2's subject is waiting.

### What T2 cannot see

1. **A wait that names no restricted package at all.** `exec.Command("sleep")`,
   `syscall.Nanosleep`, a blocking channel receive whose sender is on a timer
   in non-test code, `runtime.Gosched` in a spin. The identifier allowlist has
   no opinion about packages it does not restrict.
2. **A wait built entirely out of ALLOWLISTED identifiers**, which is a
   different and worse case than (1), because the heading above does not cover
   it. `for time.Since(start) < 50*time.Millisecond {}` names `time.Since` and
   `time.Millisecond`, both allowed, and both *correctly* allowed: reading the
   clock is not waiting on it, right up until the read is a loop condition.
   Distinguishing the two is control-flow analysis, not an identifier check.
   MEASURED 2026-08-29: `scripts/test-verify.sh` plants exactly this loop, and
   T2 passes it — the scenario asserts that it does, because the loop is there
   to drive the wall-clock ceiling and the ceiling is only being measured if
   T2 stayed out of the way.
   This bullet and (1) used to be one bullet headed "a wait that is not a
   `time` or `context` identifier", with the busy loop listed underneath it.
   The busy loop is built from nothing but `time` identifiers, so the heading
   denied the case it was filed under.
3. **The ceiling only holds AT the threshold.** MEASURED 2026-08-29: a planted
   `time.Sleep(50 * time.Millisecond)` in a test did not move the suite from
   1s against a 60s ceiling. The ceiling catches a suite that has drifted into
   waiting; it does not catch one test that waits a little.
3a. **And the ceiling cannot bound a HANG at all.** It is computed from a clock
   read after `go test` returns, so a test that never returns never reaches the
   comparison — the check sits behind a branch the failure it would name can
   never take. That was written here as though the ceiling covered blocking
   tests; it does not, and never did. What bounds a hang is
   `SUITE_TIMEOUT_SECONDS` on the `go test` line, added 2026-08-29 and driven
   by the `hang-bounded` oracle scenario. Two bounds on the bound itself:
   running `go test` by hand outside `verify.sh` gets Go's default of ten
   minutes per test binary instead, settable from the environment; and the
   absence check for this one shows up as the ORACLE hanging rather than as a
   red row — MEASURED 2026-08-29, the scenario returns in seconds with the flag
   and had to be killed at 100s without it. Loud to a person watching, silent
   to any caller that does not impose a timeout of its own.
4. **A wait inside a helper in non-test code**, called from a test. T2's domain
   is `_test.go` files. That is deliberate — ring 3 has a real clock in it —
   and it means a test can wait by delegating.
5. **Its domain was the gates' own self-tests at M0, and is the library's
   tests from M1 on.** That bullet used to end "it will not be guarding any
   protocol test until M1"; M1 landed on 2026-08-29 and it now checks every
   test file in `wire`, `proto`, `lease` and `runtime`. Two of those tests
   BLOCK — one on a real dnsmasq's log line, one spinning on a counter with
   `runtime.Gosched` — and T2 sees neither, by bullets (1) and (4). What bounds
   them is the `go test -timeout` in `verify.sh`, per (3a). It is NOT the suite
   ceiling: this bullet said the ceiling and the ceiling is unreachable for
   exactly the tests it was claiming to cover.
6. **Files under `testdata/`.** Not walked, because the go tool does not
   compile them, so a file there is not part of any test binary. It is also
   where the gates' own deliberate violations live.
7. **Shadowing, in the loud direction.** A local variable named `time` would
   make the gate report a false positive. That direction is deliberate: a gate
   that refuses something innocent is loud, and one that misses something is
   not.
8. **A third-party dependency that sleeps.** There are none today; the gate has
   no view into module cache source.

## verify.sh

One command, every check, one verdict. Details that are not incidental:

- It **builds** the gate binaries and executes them rather than using
  `go run`. MEASURED 2026-08-29: `go run` collapses every non-zero child
  status to 1, which would make a gate REFUSING because it could not measure
  its domain indistinguishable from a gate reporting a violation. The gates
  return 0/1/2 precisely so those are different facts.
- The required gate set is enumerated in the script and cross-checked against
  the gate commands the go tool finds, **in both directions**. A required gate
  that has been deleted is a FAIL; a gate present in the tree but missing from
  the list is also a FAIL. A verifier that discovers its own checklist can be
  silenced by deleting a check.
- **The verdict is printed by an EXIT trap, not by the last line.** MEASURED
  2026-08-28 by review: one unprotected assignment took `set -e` with it, so
  deleting `go.mod` made the verifier exit 1 having printed no verdict at all —
  silent in the one case where the tree was most broken. That assignment is
  also fixed, but the promise "one command, one verdict" is a property of the
  file, so it is now held at a place every exit path passes.
- **Exit 2 is disambiguated.** A Go panic exits 2 and so does a deliberate
  REFUSE. Both are a FAIL, so this was never a correctness hole; but a crash
  reported as "could not measure its domain" sends the reader to the wrong
  place, so the gates' `REFUSED` line is read before the diagnosis is chosen.
- **`-count=1` has an observer.** A cached PASS is a result that was not
  measured on this tree and is indistinguishable from a real one in the exit
  status, so a `(cached)` marker in the suite output is itself a FAIL.

### verify.sh has an oracle

`scripts/test-verify.sh`. It copies the tree, plants ONE defect in the copy,
runs the copy's `./verify.sh --inner`, and asserts both that the run failed and
that **the row which failed is the row that owns the defect**. Attributing the
failure to the row is the same lesson as the fixture-path finding below: a run
that fails for the wrong reason looks exactly like one that fails for the right
one. `verify.sh` runs it as a step, so the verifier is checked by the command
that runs the verifier.

The scenario roster is the `SCENARIOS` list in that script, cross-checked in
both directions against the `sc_*` functions beside it. Read it there, not
here: a prose copy of a list the script already enforces is an unrun checklist,
and this paragraph was one — it enumerated the scenarios as they stood before
`hang-bounded`, `bounds-ordering` and `stale-citation` were added.

**Every step's DELETION was driven, not assumed.** MEASURED 2026-08-29 by
removing one step at a time from a copy of `verify.sh` and running the oracle
against that copy. The table covers the nine steps that existed at that
measurement; `citations` and `bounds` were added later the same day, each
driven by its own absence check at introduction — delete the step from a copy,
watch its scenario report ABSENT — rather than by a re-run of this sweep:

| step deleted from `verify.sh` | oracle scenarios that went red |
|---|---|
| `build`     | 1 (`vet-violation`, whose bait must compile) |
| `vet`       | 1 (`vet-violation`) — **0 before that scenario existed** |
| `gofmt`     | 4 |
| `shellcheck`| 2 |
| `gate-roster` | 3 |
| the `t1`/`t2` gate loop | 6 |
| `unit-suite` | REFUSED — a scenario died without reporting |
| `verify-oracle` | 4, but see the bound below |

`vet` is why this sweep is in the document rather than in a transcript. It was
the one step in the file that no scenario drove: with `step "vet" go vet ./...`
deleted, the oracle passed **18 of the 18 scenarios that existed then**. A step
nothing drives is a step that
can be deleted, which is the defect class of every finding this project has
paid for twice.

The `vet-violation` bait is unreachable code, and the choice is about
attribution rather than convenience. `go test` runs a vet subset of its own
(atomic, bool, buildtags, directive, errorsas, ifaceassert, nilfunc, printf,
stringintconv, tests), so a `printf` bait would redden the unit-suite row too
and prove nothing about which step saw it. `unreachable` is in `go vet` and not
in that subset, so the scenario can assert `build`, `gofmt` and `unit-suite`
all still PASS — the preservation control that makes the vet row's FAIL
attributable.

**The oracle also checks that `verify.sh` still runs it.** MEASURED 2026-08-29:
replacing the oracle step with a hardcoded PASS survived every other scenario,
and had to — this script is the *control* for those mutants, so `verify.sh`
dropping the step is invisible from inside it. That is the same defect class as
both blocking findings: a check that cannot see its own domain. It is now
driven by replacing the copy's oracle with a stub and running the copy's
`verify.sh` with **no** flag: the stub answers instead of recursing, this
scenario chooses its answer, and both directions are asserted — a passing stub
must produce a PASS row that quotes the stub, and a failing stub must fail the
run.

**This section used to say the opposite, and the reason it gave was wrong.** It
said verify.sh could have no automated test because the harness would run
`verify.sh` against a mutated copy and the copy would run the harness again.
That obstacle is real but specific to writing the harness as a **`go test`**:
`verify.sh` runs `go test ./...`, so a Go test that ran `verify.sh` re-enters it
with nowhere to put a flag. As a standalone script with an explicit `--inner`
on the inner invocation, there is no recursion to break. The correction is on
the record because a false justification is worse than an admitted gap: the gap
gets closed, the justification gets believed.

`--inner` is a flag and not an environment variable on purpose. An ambient
variable silences the oracle for anyone who happens to have it set; a flag has
to be typed into the invocation you are reading.

### What the oracle cannot see

0. **`verify.sh` no longer calling the oracle.** The row above says 4 scenarios
   catch it, and that number is honest but the mechanism is not what it looks
   like: the catch is `shellcheck` objecting that deleting the step left
   `--inner`'s variable unused. MEASURED 2026-08-29, composing past that single
   objection — one `disable=SC2034` and a `: "$INNER"` — the copy prints
   a PASS verdict with the arbiter's own arbiter silently gone. This
   is inherent and not fixable from inside: a `verify.sh` that drops the step
   never runs the scenario that checks the step is there. Running
   `scripts/test-verify.sh` by hand is the only check for it, and running it by
   hand is not a wired check. Recorded because an incidental catch is the
   easiest thing in this file to mistake for a designed one.
1. **A defect nobody planted.** It is a list of scenarios, not a proof. The
   scenario list is cross-checked in both directions against the `sc_*`
   functions in the file, so removing a name is a REFUSAL rather than a quiet
   shrinkage — but removing the name **and** its function together is
   consistent and invisible. The cheap edit is loud; the expensive one is not.
2. **The ceiling's VALUE, behaviourally.** Driving it needs a suite lasting
   between the shipped ceiling and a raised one, i.e. minutes of wall clock per
   run. The oracle instead drives the ceiling's *branch* (a 3s suite against a
   ceiling lowered in the copy must FAIL, and the same suite against the
   shipped ceiling must PASS — that second one is the control, without which
   the first proves only that a busy loop breaks something), and checks the
   declared value is inside 5..120. The band check is STRUCTURAL and weaker
   than the rest; it kills "delete the line" and "raise it to 6000" and nothing
   subtler.
3. **`--inner` failing to SUPPRESS the oracle.** The other half — that the
   unflagged invocation still runs it — is driven by the stub scenario above.
   Suppression is asserted (the clean-copy scenario requires the inner run to
   have no `verify-oracle` row) but not mutation-driven, because that mutant is
   unbounded recursion and running it on a shared machine is not worth the
   evidence. MEASURED 2026-08-29 by hand instead, in both directions:
   `./verify.sh` reports exactly one step more than `./verify.sh --inner`, and
   the extra row is `verify-oracle`; the inner run has no such row. The counts
   themselves are not written here — they move with every step added.
4. **Two defensive arms that are unreachable today.** The `*)` unexpected
   exit-code arm — the gates return only 0/1/2 — and the "gate does not
   compile" arm, since a gate that fails to build fails `build`, `vet` and
   `unit-suite` first. Both are correct code and no test is owed; they are
   named here so a reader does not mistake them for gaps.

### Two steps added 2026-08-29, and what each cannot see

- **`citations`** fails the run when a Test/Benchmark/Fuzz/Example token
  appearing after `//` on a `.go` line, or anywhere on a `.md` line, is not
  DECLARED by some `.go` line beginning `func`/`var`/`const`/`type`. It exists
  because converting a fact-comment into a pointer at a test is exactly how an
  invented test name gets written down and believed: one was invented during
  that conversion, and one already in the tree
  (`internal/gates/rings/policy_test.go`) named a test that had never existed.

  **This bullet described a stricter check than the code performed**, and a
  reviewer measured the gap with five planted trees: trailing comments, block
  comments, and names the token pattern did not reach — an underscore suffix,
  and benchmarks — all passed, and a genuinely
  stale citation was whitewashed whenever the same token appeared in a Go
  string literal anywhere in the tree — because "exists" meant "appears on a
  non-comment line". Four of the five are caught now, each with its own
  scenario: `citation-trailing`, `citation-underscore`, `citation-whitewash`,
  and `stale-citation`, whose plant is INDENTED so that narrowing the match
  back to column 0 kills it. `citation-vacuous` drives the other direction — a
  scan that finds no domain at all must FAIL rather than report that every
  citation resolved. The six remaining bounds are listed beside the
  implementation in `verify.sh` and not restated here; the first is block
  comments, and none of them is a completeness claim.
- **`bounds`** fails the run unless the `go test` hang timeout exceeds the
  suite ceiling AND the flags the suite actually runs with carry that timeout.
  The second half was missing, which is why this bullet is longer than its
  first version: comparing two constants declared a hundred lines above the
  `go test` line is adjacency, not a data dependency. MEASURED by a reviewer, a
  hardcoded `-timeout 90s` on the invocation survived both `bounds-ordering`
  and `hang-bounded`. The flags are one array now, the invocation expands it,
  `suite-timeout-detached` plants exactly that mutant, and the residual bound —
  an invocation that stops using the array — is stated at the check.

Every scenario named above was driven by its own absence: with the step it
guards deleted from a copy, or with the widening it drives reverted, each one
goes red. Six mutants across seven runs, MEASURED 2026-08-29 — the step
deleted, the comment match narrowed back to column 0 (two scenarios), "exists"
reverted to any non-comment line, the token pattern narrowed back to
`Test[A-Z]`, the non-vacuity branch deleted, and the flags check deleted. It is
a statement about those six and about nothing else.

The residual bound on `bounds` is MEASURED, not reasoned: replacing
`go test "${SUITE_ARGS[@]}"` with a `go test` line carrying its own literal
`-timeout 300s` leaves `bounds` PASS. The check holds the array honest; it
cannot hold an invocation that stops reading the array, and nothing else
does either.

`shellcheck -S warning` runs on `verify.sh` and on the oracle as one of
`verify.sh`'s own steps. The linted list is enumerated AND cross-checked
against the shell scripts the tree holds, for the reason the gate roster is: a
list that discovers itself is silenced by moving a file, and a list that is
only enumerated is silenced by adding one.

"Shell script" means a regular file ending in `.sh` **or** opening with a shell
shebang. MEASURED 2026-08-29 by review: the walk keyed on the suffix alone
while the surrounding comments described the domain as "every executable shell
script" and as "every tracked `.sh`" — three descriptions, none of which was
the code. A `scripts/preflight` with a `#!/bin/sh` line was linted by nothing
and tripped neither direction of the cross-check. The oracle now plants exactly
that file, deliberately WITHOUT an exec bit, since being a shell script is what
makes it need linting.

It covers shell defects and says nothing about whether the verdicts are right.

## The policy is itself under test

Everything the gates enforce is a table in `internal/gates/rings/rings.go`. A
gate can be perfect and enforce a widened table, and MEASURED 2026-08-28 by
review, that was the state: mutating the gate logic killed every mutant, and
mutating the **policy** — adding `net`, `time`, `os`, `syscall` to the ring-1
allowlist, adding `Sleep`, `After`, `Tick` to the test allowlist — was never
attempted by the author. When the reviewer tried it, 7 of 16 widenings
survived. Re-derived here at 21 widenings, 12 survived.

Two layers now stand behind those tables, and they fail differently on purpose.

**Derived (`internal/gates/rings/policy_test.go`).** These do not read a list of
names; they compute the answer from the standard library and compare.

| Check | What it derives | Killed by |
|---|---|---|
| `TestPureStdlibClosureIsClean` | `go list -deps` of every admitted package; any whose closure reaches `os`, `syscall`, `net`, `time`, `context`, … must carry an identifier restriction | admitting an impure package |
| `TestAllowlistedIdentifiersExist` | two signals per entry — `go doc pkg.Ident` resolving AND the name appearing verbatim in `go doc -all pkg` | a typo, or an identifier the stdlib removed |
| `TestAllowlistsExcludeStreamAPIs` | signatures naming `io.Writer`/`io.Reader`/…, per package, refusing when it matches nothing | admitting a stream API into a pure ring; and, via witnesses, the pattern going inert |
| `TestTimeAllowlistExcludesWaiters` | signatures returning `<-chan Time`, `*Timer`, `*Ticker` | admitting a waiting primitive into tests |
| `TestContextAllowlistExcludesDeadlines` | constructors whose signature names `time.Duration` or `time.Time` | admitting a deadline constructor into tests |

The derived layer covers identifiers nobody enumerated, which is the point: it
found a hole neither human pass did. `encoding/hex` was admitted to ring 1
unrestricted; its dependency closure reaches `os` and `syscall`, and
`hex.Dumper` takes an `io.Writer`. It now carries a restriction.

**A derived check must refuse when it cannot derive.** MEASURED 2026-08-29 by
review, and this was a blocking finding: the stream derivation guarded against
`go doc` breaking — a signature it could not read was a failure — but not
against its own pattern going inert. Neutering the regexp so it matched nothing
left the whole suite green, and a ring-1 file calling `fmt.Fprintf` into a
`bytes.Buffer` then passed the full lane with a PASS verdict. A check
with one possible verdict reports that verdict.

Two things stand behind it now, and they are different guards rather than one
guard twice. **Per-package non-vacuity:** if the pattern matches no signature
in a restricted package, the test REFUSES and says how many signatures it read,
so "the pattern is broken" is distinguishable from "the toolchain answered
nothing". **Witnesses:** `streamWitnesses` names three identifiers per
restricted package that provably take or return a stream (`fmt.Fprintf`,
`fmt.Fprintln`, `fmt.Fscanf`; `hex.Dumper`, `hex.NewEncoder`, `hex.NewDecoder`),
and the control asserts the pattern matches each one *directly* — not that the
check recorded a match, which a mutant that records everything defeats. A
second test cross-checks the witness map against the restricted packages in
both directions, so emptying it is a refusal rather than a shrinkage.

Each guard alone suffices and the composition proves it: with the pattern
neutered, deleting either guard still goes red; deleting **both** returns
exactly the original green. That is the evidence that neither is decoration.

`go doc pkg.Ident` is an existence probe and **not** an exact oracle — MEASURED
2026-08-29, `go doc time.now` exits 0, so it is case-insensitive and a
lower-cased typo resolves to the unexported original. The existence check
therefore takes a second signal: the name must also appear as a whole word in
`go doc -all pkg`, whose output is case-sensitive. Validated over all 102
allowlisted identifiers with no false miss.

**Enumerated, and driven through the real binary**
(`t1/policy_driven_test.go`, `t2/policy_driven_test.go`). `PureRefusedPkgs`,
`PureRefusedIdents` and `TestRefusedIdents` are things the tables must never
admit. Membership in a map proves nothing about behaviour, so each case is
generated into a fixture and run through the built gate: the gate must exit
VIOLATION. Widening the allowlist makes it exit PASS and the case goes red.

**Preservation controls, of two kinds, because one kind is not enough.** A
guard fails in one direction, and a policy that refuses everything passes every
refusal test.

*Generated.* `TestPureAllowlistIsAccepted` imports all 15 admitted packages and
names all 25 restricted identifiers in one ring-1 fixture and requires PASS.
`TestTestAllowlistIsAccepted` names all 77 allowlisted identifiers across `time`
and `context` in a test fixture and requires PASS. Both build their fixture from
the tables, so they cover a package ADDED to a table that nobody wrote a test
for.

*Hand-written.* `TestRealisticRing1CodeIsAccepted` and
`TestFakeClockTestIsAccepted` are ordinary code of the shape M1 will contain —
option parsing, wire encoding, address formatting; a table-driven lease
lifecycle on a `fakeClock` — written out rather than generated.

**The split is not stylistic and it was measured.** MEASURED 2026-08-29:
deleting `bytes` from the ring-1 allowlist SURVIVED the generated control, and
so did deleting `Since` from the test allowlist. A control that builds its
fixture from the table it is testing shrinks with the table: the fixture simply
stopped importing `bytes` and passed. A measurement cannot backstop itself.
With the hand-written controls in place, nine narrowings — five packages, four
identifiers — all die.

The two kinds fail in opposite directions and neither subsumes the other. The
generated ones cover ADDITIONS to a table; the hand-written ones cover
REMOVALS.

**The bound on the hand-written half is open today, not in future.** MEASURED
2026-08-29 and confirmed independently by review: **16 of the 102 allowlisted
identifiers are named in any `_test.go` file at all** — `encoding/hex` 1/11,
`fmt` 1/14, `context` 2/12, `time` 12/65 — so 86 could be removed from an
allowlist with nothing going red. Review measured 4 of 8 identifier narrowings
against today's tables SURVIVING the whole suite (`fmt.Sprintf`, `hex.Dump`,
`time.Kitchen`, `context.WithValue`) and 4 dying. PACKAGE narrowings are
covered: 4 of 4 die.

This used to read "a package admitted **later** and never written into those
fixtures", which described a present-tense escape as a future one — a
completeness claim wearing a bound's clothes. The number is printed by
`TestNarrowingCoverageIsMeasured`, which refuses rather than reporting zero
coverage when it cannot find the test files, so it is a measurement a run makes
rather than a sentence in a document.

Why it is tolerated at M0 rather than closed: a narrowing makes the gate REFUSE
honest code, loudly, at the point of use, naming the identifier — a
self-announcing failure. A widening is silent, and the widening direction is
covered. Naming all 102 identifiers in a hand-written fixture would rebuild the
generated control by hand and misrepresent what M1 needs.

### What the policy guards cannot see

1. **A widening that is genuinely correct.** They cannot tell a considered
   policy change from a careless one; they make the change loud, not illegal.
   Deleting a case remains available to anyone who means it.
2. **`time.Sleep`, from the derived side.** MEASURED 2026-08-29: the waiter
   derivation matches signatures *returning* a channel or a timer, and
   `func Sleep(d Duration)` returns nothing. It matches 5 of the 6 waiting
   primitives; `Sleep` is carried by the enumerated layer alone. The two layers
   are not redundant and neither is a superset of the other.
3. **A package it does not restrict.** The closure check demands a restriction
   for an admitted package whose closure is impure. It says nothing about which
   identifiers that restriction should hold beyond the stream-API rule.
4. **`context.AfterFunc`, and this is the one place a mutant legitimately
   survived.** It runs `f` on cancellation, not on a clock, so it is not
   obviously a T2 violation and it is deliberately NOT listed as refused —
   claiming otherwise would assert an adjudication nobody made. Its signature
   `(ctx Context, f func()) (stop func() bool)` names no `time` type, so the
   deadline derivation correctly does not match it. That left its refusal held
   by nothing but the absence of a key in a map, so it is **pinned as a case**
   (`TestContextAfterFuncIsRefusedByDefault`): today's answer is refused,
   admitting it means deleting the case and writing down why. A pin records a
   decision that has not been made; it does not make one.
5. **A narrowing of the 86 identifiers no fixture names.** MEASURED
   2026-08-29: 16 of 102 allowlisted identifiers appear in any test file, so
   the rest can be removed from an allowlist with nothing going red — the
   generated controls cannot see it, being derived from the same table, and the
   hand-written ones name only what realistic code uses. This is open now; the
   count is printed by `TestNarrowingCoverageIsMeasured` and the reasoning for
   accepting it at M0 is above.
6. **The stdlib moving under them.** `go doc` is queried at test time against
   the toolchain in use, so an identifier removed upstream turns the existence
   probe red — which is correct — but a *newly added* waiting primitive is
   simply not on the allowlist, and is refused by default rather than noticed.

## Diagnostics name positions relative to the tree root

MEASURED 2026-08-28 by review: six self-test cases asserted a rule had fired by
looking for a substring in the gate's output, and the output carried the
fixture's `t.TempDir()` path — which Go names after the subtest. A case named
`third_party` was satisfied by the words `third_party` in the temp directory,
not by the diagnosis. Every one of those assertions would have passed with the
rule deleted.

Fixed twice, on purpose. At the source: `scan.Rel` makes every position
relative to the tree root, so no diagnostic carries the caller's directory. And
at the one place every self-test passes through: `gatetest.Run` fails any case
whose gate output contains the fixture root. A source fix holds only until the
next diagnostic is written; the choke point holds after that.

`scan.RelErr` is the same fix for the other half. MEASURED 2026-08-29 by
review: the first pass at keeping roots out of diagnostics dropped the *error*
along with the path, so a refusal said the tree was unreadable without saying
why. `RelErr` relativises the message and keeps the cause. `gatetest.Run`
already covers the root half at every call site; `TestRelErr` covers the cause
half, which nothing else did.

`Rel` falls back to the **basename** for a path it cannot relativise, and a
basename satisfies the choke point perfectly well — it does not contain the
root either. MEASURED 2026-08-29: mutating `Rel` to take that fallback always
survived the whole suite. `TestT1DiagnosticsNameTheRing` now plants the same
basename in two rings and requires the diagnosis to tell them apart, and
`TestRel` pins both directions of the function itself.

**What this cannot see:** it fixes the shape of a position, not its accuracy. A
gate emitting a plausible but wrong relative path passes all of it.
