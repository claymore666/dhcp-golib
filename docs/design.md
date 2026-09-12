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
them. Work after M8 is named by its issue and by the release it ships in, not
by a milestone letter.


## Coverage by claim, through v1.0.0

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
- **A name given to a client that is already running, in the server's own
  table.** The client starts with no name, is handed one while it holds a lease,
  and dnsmasq's `--dhcp-leasefile` carries it against that client's address and
  hardware address: the field is `*` before the call and the name after it. The
  message is RFC 2131 §4.4.5's early renewal, and two further calls with the
  same name produce no further exchange
  (`TestAHostnameSetAfterStartReachesTheServersLeaseFile`).
- **A lease given back with no client and no interface left.**
  `lease.BuildRelease` renders the datagram out of a `Record` alone and
  `runtime.SendRelease` writes it, on both families, from a source address the
  caller names. What it is asserted against is dnsmasq's own lease file and
  dnsmasq's own log: the released binding is gone and its DHCPRELEASE line is
  there, a control lease taken in the same fixture and never released is still
  there at the end, a release carrying the wrong identity runs first and leaves
  the binding where it is, and the fixture's lease lifetime is measured against
  the run's own wall time so that an expiry cannot be read as a release
  (`TestAReleaseBuiltFromARecordReachesRealDnsmasq`,
  `TestAV6ReleaseBuiltFromARecordReachesRealDnsmasq`). On IPv6 the source may
  not be the address being given back, RFC 9915 §18.2.7: "The client MUST NOT
  use any of the addresses it is releasing as the source address in the Release
  message or in any subsequently transmitted message." `SendRelease` refuses
  that shape itself and does not trust the caller for it: a server accepts the
  datagram either way, so no outside evidence would ever show the violation
  (`TestAV6ReleaseRefusesToComeFromTheAddressItIsReleasing`).
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
- **What the advertisement carries, kept per router and stamped on the
  lease.** Its Prefix Information options, the link MTU (RFC 4861 §4.6.4),
  RFC 4191 §2.3's more-specific routes and RFC 8106's resolver and search-list
  options are decoded in ring 0. The four that describe the LINK are kept in
  ring 1 as a table; the prefixes describe one frame and are reported as that
  frame sent them, in wire order. The table is a union and not a snapshot of the
  last frame, RFC 4861 §6.3.4: "Hosts accept the union of all received
  information; the receipt of a Router Advertisement MUST NOT invalidate all
  information received in a previous advertisement or from another source."
  Every entry expires on its own lifetime and not on the router's, §4.2: "The
  Router Lifetime applies only to the router's usefulness as a default router;
  it does not apply to information contained in other message fields or
  options. Options that need time limits for their information include their
  own lifetime fields." The default router list is ordered by RFC 4191 §2.2's
  preference, so a caller that wants one gateway takes the first
  (`TestTheTableTakesTheUnionOfWhatTwoRoutersSaid`,
  `TestEachEntryExpiresOnItsOwnLifetime`,
  `TestTheDefaultRouterListIsOrderedByTheAdvertisedPreference`). Where DHCPv6
  sent the same kind of thing, its entries keep their places and the
  advertisement's are appended after them, RFC 8106 §5.3.1: "the DNS
  information from DHCP takes precedence over that from RAs"
  (`TestWhatBothProtocolsSentAppearsOnceAndDHCPsCopyIsFirst`). The outside
  evidence is dnsmasq's own advertisement on the link, read back off the lease:
  the gateway, which DHCPv6 has no option for at all and which can only have
  come from the frame's source address, an MTU the veth pair does not have, and
  a search domain that arrives once
  (`TestTheOptionsARealRouterAdvertisesReachTheCaller`). The table is pruned by
  the `now` every `Step` is handed and by nothing else, so what a caller reads
  is correct as of the last `Step` and not as of the read. That bound is
  driven and not only written down
  (`TestTheRouterViewOnTheLeaseIsAsOfTheLastStep`).
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
  `TestAMalformedStatusCodeIsNeverReportedAsARefusal`). An IA that says
  `NoAddrsAvail` hands over no address even when it carries one, and an IA that
  says anything else hands over the address it carries
  (`TestAnIAThatRefusesAndOffersGivesNoAddress`,
  `TestAnIAThatFailsForAnotherReasonStillHandsOverItsAddress`). The router
  observation on such an event is what had been seen when it was stamped, which
  is why a caller classifying a link reads the live one
  (`lease`'s `TestTheRouterObservationOnARefusalIsWhatHadBeenSeenByThen`).
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
- **A reconfiguration the server starts.** RFC 9915 §18.2.11: "Upon receipt of
  a valid Reconfigure message, the client responds with a Renew message, a
  Rebind message, or an Information-request message as indicated by the
  Reconfigure Message option (see Section 21.19)." A client announces §21.20's
  Reconfigure Accept option, records the reconfigure key a Reply hands it
  (§20.4.3), and answers an authenticated Reconfigure with the exchange the
  message names. dnsmasq cannot send one: the fixture's own record is a
  measurement against the 2.91 sources, two constants and no code that builds
  or sends the message. So the proof runs against a server written for it,
  which signs with RFC 2104's construction written out from the RFC and not
  with this library's own helpers
  (`TestAnAuthenticatedReconfigureMakesTheClientRenew`). A client built with
  the option off announces nothing and answers nothing
  (`TestAClientThatDoesNotAcceptReconfigureAnnouncesNothingAndAnswersNothing`).
  Every §16.11 discard rule is driven on its own, so six rules that only ever
  fire together are not six rules
  (`TestEveryReconfigureDiscardRuleFiresOnItsOwn`), the §20.3 replay floor is
  per server and rises only where the client acted
  (`TestTheReplayDetectionValueIsPerServerAndMustIncrease`,
  `TestAFailedReconfigureDoesNotRaiseTheReplayFloor`), and the key appears
  in no journal line and in no action a caller could log
  (`TestTheReconfigureKeyNeverReachesTheJournal`).
- **The namespace and the thread.** The v6 client's three sockets and its
  link-local address are taken in one call, in the namespace of the thread it
  was built on, and it leases from a server only that namespace can see.
- Renewal, rebinding, expiry, Advertise selection by preference, the Status
  Code paths and the Information-request are ring 1's, driven there in
  milliseconds against [`proto`](../proto)'s tables and against captured frames replayed
  through the decoder.

