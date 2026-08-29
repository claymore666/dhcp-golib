# dhcplease — a managed-lease DHCP client for Go

**Private. Not published.** See the publication rule in the plugin's
`vision.md` §5.2 — this repo goes public the day the plugin depends on it,
and not before. That is a binary trigger, not a judgement call.

## What this is

Not a DHCP packet library — that slot is occupied (`insomniacslk/dhcp`).
This is the layer nobody has published: **lifecycle**.

> Give me a managed lease on this interface, and tell me when it changes.

Transactions, timers, the state machine, persistence, change notification.

## Design

The architecture document and the protocol conformance checklist are held
privately alongside the plugin project, not in this tree. This README states
the part a reader needs before opening any file; `docs/gates.md` states what
the two gates enforce and what they cannot see.

This paragraph used to name those documents by their exact path under the
plugin's gitignored notes directory. That path is private scaffolding, and this
repository publishes the day the plugin depends on it — so the reference would
have gone public with it.

The one thing to know before reading any code: **ring 1 is pure.** The
state machine is `Step(now, rnd, event) -> (state, []action)` with no I/O, no
clock and no goroutines inside it. Time **and entropy** are parameters —
both protocols require randomised backoff, so `rnd` has to come in from
outside or the core stops being deterministic. That is what makes
the tests instant and the replay debugger possible, and it is not
negotiable without re-reading the design doc's §2.1.

## Layout

Four rings; each depends only on the rings below it.

    ring 3  runtime/   sockets, real clock, netlink, netns, persistence, metrics
    ring 2  lease/     manager: one managed lease per (interface, family)
    ring 1  proto/     THE STATE MACHINE — pure. no I/O, no clock, no goroutines
    ring 0  wire/      codec: bytes <-> typed messages

All four are empty at M0 on purpose. The gates below were built and proven
against an empty package, because a gate added after the code it guards gets
weakened to fit the code.

## Verifying

    ./verify.sh

One command, every check, one verdict. Exit 0 is PASS and is the normal state;
exit 1 is FAIL. A step that cannot be measured is a FAIL, never a skip.

It runs `go build`, `go vet`, `gofmt`, `shellcheck` over the shell scripts, the
gate roster cross-check, the T1 and T2 gates, the race-enabled unit suite under
a wall-clock ceiling, and its own oracle.

There is no CI on this repository and there will not be: the self-hosted
runners belong to the plugin repository and cannot serve a second private repo
without an organisation. `verify.sh` is the only arbiter there is, which is why
it is one command and not a paragraph describing what a developer should run —
and why it has an oracle of its own, `scripts/test-verify.sh`, which plants a
defect in a copy of the tree and requires the row that owns that defect to be
the row that fails. `verify.sh` runs it as a step, so the arbiter is checked by
the command that runs the arbiter. What it cannot see is in `docs/gates.md`.

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
