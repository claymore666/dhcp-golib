# Design and scope

The long form behind the README: how the library is put together, what its
tests prove today, and the words its comments use. [`docs/verifying.md`](verifying.md) covers
the arbiter. [`docs/gates.md`](gates.md) covers the two ring gates.

## The consumer, and the word for it

Comments throughout the tree call the process that drives a client **the
chassis**: whatever installs the addresses the client announces and decides
what to do when a lease changes or is lost. This library never plays that role
itself. That is why so many of its bounds are stated as what the chassis must
do.

The chassis this was written for is the
[docker-net-dhcp](https://github.com/claymore666/docker-net-dhcp) network
plugin, which leases container addresses from the LAN's own DHCP server. That
plugin carries a copy of this tree under `pkg/dhcp/`, refreshed by a script in
its repository that filters what it copies against a list it keeps privately;
it does not import this module today. The plugin is GPL-3.0 and this library
is MIT, which permits the combination.

## Purity of ring 1

Every normative claim in the code cites an RFC section, so the code can be read
against the standard itself and needs no notes about it. Beyond that there is
one thing to know: **ring 1 is pure.** The state machine is
`Step(now, rnd, event) -> (state, []action)` with no I/O, no clock and no
goroutines inside it. Time **and entropy** are parameters. Both protocols
require randomised backoff, so `rnd` has to come in from outside or the core
stops being deterministic. That is what makes the tests instant and the replay
debugger possible. The whole design rests on this one property, and nothing may
be added to the pure core that breaks it.

## Layout

Four rings; each depends only on the rings below it.

    ring 3  runtime/   sockets, real clock, netlink, netns, persistence, metrics
    ring 2  lease/     manager: one managed lease per (interface, family)
    ring 1  proto/     THE STATE MACHINE: pure. no I/O, no clock, no goroutines
    ring 0  wire/      codec: bytes <-> typed messages

All four were empty at M0 on purpose. The gates below were built and proven
against an empty package, because a gate added after the code it guards gets
weakened to fit the code. M1 filled all four.


## Milestones

The commit history and the docs name milestones M0 to M8. They are the order
the library was built in. They are not releases.

| | |
|---|---|
| M0 | The repository, the local verifier and its two gates, before any protocol code. |
| M1 | The vertical slice: the four rings from wire to runtime, one DHCPv4 lease from INIT to BOUND against a real dnsmasq in a user namespace. |
| M2 | Giving a lease back: DHCPDECLINE and DHCPRELEASE. |
| M3 | Keeping a lease: renewal at T1, rebinding at T2, expiry, and a NAK on renewal. |
| M4 | The durable lease record: a journal that survives a restart and repairs a torn tail. |
| M5 | Restart with a remembered address: INIT-REBOOT and the requested-address report. |
| M6 | Address conflict detection per RFC 5227, in three modes: wait, async, off. |
| M7 | DHCPv6: the codec, the state machine, the durable record and the runtime. On `main` here; the plugin-side wiring is M8's. |
| M8 | Integration into the docker-net-dhcp plugin. Done in the plugin's own repository. |

"Done" means the milestone's tests are in the tree and the verifier passes on
them.


## Coverage by claim, through M7

One IPv4 lease and one DHCPv6 lease, each taken and KEPT: INIT to BOUND over a
real socket, renewed at T1 and rebound at T2, given back or refused. Every
entry below is a test. The DHCPv6 half has its own list after the IPv4 one.

- **A lease from a real server.** [`runtime`](../runtime)'s test re-executes itself into a
  user and network namespace, wires a veth pair, runs dnsmasq on one end and
  this library on the other, and asserts the exchange against **dnsmasq's own
  log**: DHCPDISCOVER, DHCPOFFER, DHCPREQUEST, DHCPACK, and for the renewal a
  second DHCPREQUEST and DHCPACK with the DHCPDISCOVER count unmoved, and a
  DHCPNAK driven by restarting the server with a pool that no longer holds the
  leased address. The library's own opinion of what happened is asserted on
  nowhere. No root, no password, no host state touched.
- **A restart that keeps its address, against that same server.** The client is
  stopped and started again with the lease it held, and the server's log shows
  a DHCPREQUEST and a DHCPACK for that address with no DHCPDISCOVER between
  them. A second run, against a replacement server whose pool no longer holds
  the address, shows the refusal and then the whole acquisition the RFC
  prescribes after one; a third, whose remembered lease is past its deadline,
  shows the DHCPDISCOVER and never the DHCPREQUEST.
- **A lease record that outlives the process that wrote it.** Three managers
  lease from that same server at once over one bridge, every manager and every
  in-memory record is then thrown away, and the journal is reloaded from its
  file and checked against **dnsmasq's own lease file**: the addresses, the
  client identifiers and the expiry times the server wrote for itself
  (`TestTheRebuiltJournalMatchesTheServersLeaseFile`). A tail torn by a write
  that ran out of file is repaired before anything is appended to it, and the
  line lost to it is counted
  (`TestAShortWriteLeavesTheStoreUsableAndTheNextEventSurvives`,
  `TestReopeningAfterATornTailDoesNotLandOnTheFragment`).
- **An address probed before it is used, against a real squatter on the link.**
  RFC 5227's probe window runs on the wire: a second host answers for the
  address dnsmasq offered, and the server's log carries the DHCPDECLINE and the
  acquisition that restarts after it. Both modes are driven: the one that
  withholds the address until the window closes, and the one that reports it and
  then takes it back (`TestASquatterInTheProbeWindowMakesAWaitingClientDecline`,
  `TestASquatterInTheProbeWindowMakesAnAsyncClientDecline`). A conflict after
  BOUND takes RFC 5227 §2.4's path
  (`TestASquatterAfterBoundTakesSection24sPath`), and a client built with
  detection off puts no ARP frame on the link at all
  (`TestAnOffClientPutsNoARPOnTheWire`).
- **A socket that keeps the namespace it was opened in.** A client is built on
  a thread inside a network namespace of its own, the thread is then destroyed,
  and the client leases from a server that exists only in there. The goroutine
  running it cannot even see the interface. That is what lets one process lease
  on many containers' links at once.
- **That same exchange replayed offline.** The journal of the live run is fed
  back through ring 1 and must produce the identical lease. Ring 1 is pure, so
  the replay needs no socket, no clock and no server.
- **The whole acquisition path in milliseconds.** [`proto`](../proto) tables the path with
  no root, no namespace and no network at all.

### DHCPv6, against the same real dnsmasq

- **A lease on a managed link.** Solicit, Advertise, Request, Reply against
  dnsmasq in the netns fixture, with the address checked by RFC 4862 §5.4
  duplicate address detection on the wire before it is announced, and released
  with a Release the server logs (`TestAV6ClientAcquiresFromRealDnsmasq`,
  `TestAV6ReleaseReachesRealDnsmasq`).
- **The four other shapes a real link can have, told apart.** A stateless link
  where only the configuration comes from DHCPv6, a SLAAC-only link that says
  there is no DHCPv6 at all, a link with a server and no router, and the one
  that matters: a managed link whose server is present and answers nothing.
  That last shape differs from a link with no server at all. Each mode is
  asserted on two channels, dnsmasq's log and the Router Advertisement on the
  link.
- **A server that refuses, told apart from one that never answered.** dnsmasq
  is given a pool of one address, a first client takes it, and a second client
  on the same link is answered and not ignored: the refusal reaches the
  caller as `Failed` carrying RFC 9915 section 21.13's status code
  (`TestAV6ClientIsToldTheServerRefused`), and dnsmasq's own log carries the
  Advertise and the status option it put in it. The code is read at the message
  level and inside the IA_NA, an explicit Success and an absent option are one
  verdict, and a status this library could not decode is never reported as one
  a server sent (`proto`'s `TestAReplyThatRefusesIsReportedWithTheServersOwnCode`,
  `TestAReplyThatSaysSuccessIsNotARefusal`,
  `TestAMalformedStatusCodeIsNeverReportedAsARefusal`).
- **A duplicate address is declined and not asked for again, across a restart
  too.** A neighbour answers for the offered address; the client Declines it,
  and the next Solicit does not carry it as a hint
  (`TestADuplicateAddressOnTheLinkIsDeclined`, `TestADeclinedHintIsNotAskedForAgain`).
  That holds on every path into the Decline, including the one the plugin pins:
  a squatter that arrives after the address is already bound
  (`TestAnAddressWithdrawnUnderABoundLeaseIsNotHintedAgain`). The declined set
  is durable, so a resumed client does not ask for it either
  (`TestADeclinedAddressReachesTheRecordAndTheClientRebuiltFromIt`). It is kept
  BESIDE the parameter snapshot and not inside it. `Record.Params6` is what the
  run ran with, so a run's own journal replays against its own record, and
  `Record.Declined6` is what the run accumulated, which is what the next process
  is seeded from
  (`TestARunsOwnJournalReplaysAgainstItsOwnSnapshot`,
  `TestTheDeclinedSetSurvivesSeveralRebuilds`).
- **A restart that confirms.** A client started with a binding from a previous
  run sends RFC 9915 §18.2.3's Confirm as its first message (`TestAResumedV6LeaseConfirmsAgainstRealDnsmasq`).
- **The namespace and the thread.** The v6 client's three sockets and its
  link-local address are taken in one call, in the namespace of the thread it
  was built on, and it leases from a server only that namespace can see.
- Renewal, rebinding, expiry, Advertise selection by preference, the Status
  Code paths and the Information-request are ring 1's, driven there in
  milliseconds against [`proto`](../proto)'s tables and against captured frames replayed
  through the decoder.

