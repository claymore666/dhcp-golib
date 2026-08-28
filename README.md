# (name undecided) — a managed-lease DHCP client for Go

**Private. Not published.** See the publication rule in the plugin's
`vision.md` §5.2 — this repo goes public the day the plugin depends on it,
and not before. That is a binary trigger, not a judgement call.

## What this is

Not a DHCP packet library — that slot is occupied (`insomniacslk/dhcp`).
This is the layer nobody has published: **lifecycle**.

> Give me a managed lease on this interface, and tell me when it changes.

Transactions, timers, the state machine, persistence, change notification.

## Design

`.claude/internal/2x-dhcp-library-design.md` in the plugin repo.
Protocol obligations: `2x-protocol-conformance.md` beside it.

The one thing to know before reading any code: **ring 1 is pure.** The
state machine is `Step(now, event) -> (state, []action)` with no I/O, no
clock and no goroutines inside it. Time is a parameter. That is what makes
the tests instant and the replay debugger possible, and it is not
negotiable without re-reading the design doc's §2.1.
