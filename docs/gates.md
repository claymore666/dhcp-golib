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

1. **A wait that is not a `time` or `context` identifier.** `exec.Command("sleep")`,
   `syscall.Nanosleep`, a blocking channel receive whose sender is on a timer
   in non-test code, a busy loop, `runtime.Gosched` in a spin. The wall-clock
   ceiling is the only instrument that covers these, and see (2).
2. **The ceiling only holds AT the threshold.** MEASURED 2026-08-29: a planted
   `time.Sleep(50 * time.Millisecond)` in a test did not move the suite from
   1s against a 60s ceiling. The ceiling catches a suite that has drifted into
   waiting; it does not catch one test that waits a little.
3. **A wait inside a helper in non-test code**, called from a test. T2's domain
   is `_test.go` files. That is deliberate — ring 3 has a real clock in it —
   and it means a test can wait by delegating.
4. **Files under `testdata/`.** Not walked, because the go tool does not
   compile them, so a file there is not part of any test binary. It is also
   where the gates' own deliberate violations live.
5. **Shadowing, in the loud direction.** A local variable named `time` would
   make the gate report a false positive. That direction is deliberate: a gate
   that refuses something innocent is loud, and one that misses something is
   not.
6. **A third-party dependency that sleeps.** There are none today; the gate has
   no view into module cache source.

## verify.sh

One command, every check, one verdict. Two details that are not incidental:

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

### What verify.sh cannot see, and one thing owed

**Its own logic has no automated test.** The roster comparison, the exit-code
mapping and the ceiling arithmetic were attacked by hand at M0 — a deleted
gate, an unregistered extra gate, a gate that does not compile, and a check
that `-allow-empty` is never passed — and all four behaved. None of that is
repeatable by a check, which is the exact shape this project distrusts.

The obstacle is real rather than an excuse: the obvious test runs `verify.sh`
against a mutated copy of the tree, and the copy's `verify.sh` would run the
test again. A non-recursive harness is owed work for M1, and until it exists
this paragraph is prose, and prose decays silently.

`shellcheck -S warning` runs on `verify.sh` as one of its own steps, which
covers shell defects and nothing about whether the verdicts are right.
