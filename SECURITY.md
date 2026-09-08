# Security policy

## Reporting a vulnerability

Report it **privately**, through this repository's advisory form:

**<https://github.com/claymore666/dhcp-golib/security/advisories/new>**

Please do not open a public issue for something you believe is exploitable.
This is a solo-maintained library: expect an initial answer within a few days,
and allow a reasonable window for a fix before disclosing — ninety days is a
fine default, and a shorter one is a conversation rather than a refusal.

**What happens next.** The report is triaged and confirmed or refuted against
the tree; a confirmed one is fixed, the fix ships in a tagged release with a
test that fails without it, and a GitHub Security Advisory is published.
**Reporters are credited** in the advisory and in the release notes unless they
ask not to be.

## Scope — what this library is, and what it is not

`dhcp-golib` is a DHCP client you embed in a Go program. It takes a lease on an
interface, keeps it renewed, and tells the caller what changed.

**What it does not do** is most of the answer to "how bad could this be":

- **it applies nothing to the link.** No address is added, no route is
  installed, no resolver file is written. The library hands the caller a lease;
  what to do with it is the caller's code and the caller's privileges;
- **it needs no root.** The packets that must be sent before an address exists
  go over an `AF_PACKET` socket, which needs `CAP_NET_RAW` — the test suite
  holds it inside an unprivileged user namespace — and the library asks for
  nothing beyond that;
- **it holds no secret, reads no configuration file, and starts no
  subprocess.** There is no `dhcpcd`, no `dhclient`, no shell.

**The attack surface is the wire.** A DHCP reply is written by whoever answers
first on the link, and the library decodes it before anything has authenticated
anybody: `wire/` parses the message and its options, `proto/` decides what to
do about it, and both are reachable by any host that can put a frame on the
interface. Findings there are the ones this project most wants to hear about:

- a message, option or ND packet that makes the decoders read, allocate or loop
  out of proportion to its size — a length field trusted, a slice taken past
  its bound, a message that never terminates a state;
- a reply from one server accepted where the state machine's own rules say it
  must not be, including across a rebind, a decline or a restart;
- an option value that reaches the caller in a form the caller cannot tell from
  something it chose itself — a hostname, a resolver address or a route that
  arrived from the wire and looks local.

A **hostile DHCP server** is only partly in scope: a client necessarily trusts
the server for addressing, so a server that hands out an address or a route
you did not want is a network-design problem and not a defect here. Handling
its bytes unsafely is a defect here.

## Supported versions

The latest tagged release. There is no backport policy.

## The checks that run on every change

`./verify.sh` is the arbiter, and `docs/verifying.md` says what each of its
rows measures and what it cannot see. Beside it, on GitHub-hosted machines:
CodeQL over the Go source and over the workflows, `govulncheck` for advisories
reachable from code this module calls, and `actionlint` over the workflows.
The workflows themselves are held to two published properties — no job on a
machine of ours is reachable from a fork's pull request, and the word
`secrets` appears nowhere under `.github/` — which the unit suite checks and
`docs/verifying.md` states.
