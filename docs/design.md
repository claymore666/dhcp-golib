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


## Coverage by claim, through v1.2.0

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
- **A user class that a server's class rule acts on.** The client sends the
  User Class option in its Discover and every Request, one length-prefixed
  instance per class, and dnsmasq with `--dhcp-userclass` rules hands a
  private option in the ACK only to the client whose instance matches: not to
  one sending another class or none, and a rule that spans two instances does
  not fire where one that names either does. The class dnsmasq logs and the
  tags it sets are asserted beside the lease the client reports
  (`TestUserClassReachesTheServersClassRule`). The parameter's limits are the
  RFC's one-octet length: an instance of at least one octet and at most one
  less than the octet's range, the list within it with its length octets; a
  zero octet inside an instance reaches the bytes, which dnsmasq cannot be
  given a rule for, so that one is asserted on the encoded message
  (`TestNewValidatesTheUserClassAgainstRFC3004Section4`,
  `TestUserClassIsOnTheDiscoverAndOnEveryRequestByteForByte`). A Decline and a
  Release carry none (`TestADeclineAndAReleaseCarryNoUserClass`).
- **A two-message lease from a real server, and the four-message one when the
  server does not allow it.** A client with `RapidCommit` sends the Rapid Commit option in its
  Discover and in no other message. dnsmasq with `--dhcp-rapid-commit` answers
  with an Ack, and its log holds DHCPDISCOVER and DHCPACK with no DHCPOFFER and
  no DHCPREQUEST, beside the lease the client reports
  (`TestRapidCommitTakesTheTwoMessageLeaseFromDnsmasq`). Without the flag the same
  client gets Discover, Offer, Request, Ack
  (`TestADnsmasqWithoutRapidCommitAnswersAClientThatAsksInFourMessages`), a client
  that does not ask gets four messages from the flagged server
  (`TestAClientThatDoesNotAskGetsTheFourMessageExchangeFromARapidCommitServer`), and
  the renewal after the rapid lease is a Request and an Ack with the
  DHCPDISCOVER count unmoved and no Rapid Commit option on any Request the client sent
  (`TestARenewalAfterARapidLeaseCarriesNoOption80`). An Ack with the option is
  refused in INIT, from a server the client's policy excludes, with no server
  identifier, with a lease time of zero, and from a server other than the one
  an Offer is being requested from
  (`TestARapidAckIsRefusedWhereItAnswersNothingTheClientSent`,
  `TestARapidAckFromADeniedOrUnlistedServerIsRefused`,
  `TestARapidAckInRequestingIsTakenOnlyFromTheServerAndAddressAsked`).
- **A client that waits when the server says IPv6 only, and one that does not
  ask.** dnsmasq set to send the IPv6-Only Preferred option (RFC 8925) with a
  value of five minutes sends it only to a client whose request list names it.
  A client with `IPv6OnlyPreferred` gets an Offer whose logged options include
  it and sends no Request, Decline or Release: dnsmasq's log holds DHCPDISCOVER
  and DHCPOFFER and no DHCPREQUEST, the client reports no lease, and its journal
  shows a restart timer of at least five minutes
  (`TestDnsmasqSendsOption108AndAnIPv6OnlyClientWaitsInsteadOfRequesting`).
  The absence is read after a second client's Discover has been logged, so that
  no sleep stands in for "nothing came". The same server and a client without
  the flag exchange four messages and the Offer does not carry it
  (`TestAClientWithoutTheFlagGetsAFourMessageLeaseAndNoOption108FromTheSameDnsmasq`).
  The wait's end and a link coming up are driven on the machine's own clock in
  `proto` (`TestTheWaitEndsInAFreshDiscover`, `TestALinkUpEndsTheWaitEarly`).
- **A DHCPFORCERENEW the client obeys only when it is genuine and unicast.**
  dnsmasq is given the server's Forcerenew Nonce Capable and Authentication
  options as fixed bytes, so the client's Discover and Request carry the first,
  the Ack's nonce becomes the lease's key, and a frame signed with it renews
  the lease: dnsmasq's log holds a second DHCPREQUEST and DHCPACK with the
  DHCPDISCOVER count unmoved.
  The frame is synthetic, since dnsmasq sends none. A frame addressed to
  the broadcast address, one for another host's address that reached the link as
  a broadcast, one with a flipped digest and one that repeats a spent
  replay value each start nothing, read as an absence window on a second
  socket and as a refusal in the journal, and the same bytes sent again after
  they were obeyed are refused too
  (`TestAForcerenewIsObeyedOnlyWhenItIsAuthenticAndUnicast`). The same server
  proves only that the client sends the Forcerenew Nonce option and keeps the nonce; it is not a
  conformant FORCERENEW server. The refusals and the replay floor are driven
  on the machine's own clock in `proto`
  (`TestEveryRefusalLeavesTheMachineAsItWas`, `TestTheReplayFloorIsStrict`).
- **A two-message DHCPv6 lease from a real server, and the four-message one
  from the same server.** A client with `RapidCommit` sends the Rapid Commit option in its
  Solicit and in no other message. dnsmasq answers a Solicit that carries it with
  a Reply, whatever its `--dhcp-rapid-commit` flag, which is the DHCPv4 switch, so the
  client's setting is the only one that decides. The server's log holds
  DHCPSOLICIT and DHCPREPLY with no DHCPADVERTISE and no DHCPREQUEST, beside the
  lease the client reports
  (`TestAV6ClientThatAsksForRapidCommitGetsTheTwoMessageLease`). The same server
  and a client that does not ask gives Solicit, Advertise, Request, Reply
  (`TestAV6ClientThatDoesNotAskGetsTheFourMessageExchangeFromTheSameDnsmasq`), and
  the renewal after the rapid lease is a Renew and a Reply with the DHCPSOLICIT
  count unmoved and no Rapid Commit option in any Renew the client sent
  (`TestARenewAfterARapidV6LeaseCarriesNoOption14`). dnsmasq cannot be made to
  answer such a Solicit with a plain Advertise, so that fallback is driven in
  [`proto`](../proto) alone, with the refusals of a Reply that carries the option
  (`TestARapid6ReplyIsDiscardedWhereItAnswersNothingTheClientSent`,
  `TestAPlainAdvertise6ToARapidSolicitLeadsToRequestAndReply`).
- **A temporary address from a real server, beside the stable one.** A client
  with `Temporary` sends an IA_TA with the IA_NA's IAID in its Solicit, repeats
  the address the Advertise offered in its Request, and holds the Reply's
  address in `TempAddrs`, a second slice that nothing reading the stable lease
  looks at. The test runs dnsmasq with a range of billions of addresses, because it
  draws both addresses from one range at random starts, and asserts a stable
  and a distinct temporary address on the lease, the IA_TA and the same address
  in dnsmasq's log, and no IA_TA at all for a client that does not ask
  (`TestAV6ClientThatAsksForTemporaryAddressesGetsOneFromRealDnsmasq`,
  `TestAV6ClientThatDoesNotAskGetsNoTemporaryAddress`). A renewal asks for no
  temporary address, as RFC 8415 advises: the count of `ia-ta` options
  dnsmasq logged as sent does not move and the decoded Reply has none
  (`TestARenewalLeavesTheTemporaryAddressAlone`). A temporary address that
  fails duplicate address detection is declined alone in an IA_TA, and a stable
  one that fails takes the same Reply's temporary addresses with it; both are
  driven in [`proto`](../proto), where each address can be failed on its own.
  A lease resumed from a remembered binding has no temporary address, because
  a Confirm is not followed by a Request
  (`TestTemporaryIsNotAskedForOnAResumedLease`).
- **A delegated prefix from a real server, reported and never installed.** A client
  with `PrefixHint` set sends an IA_PD with the IA_NA's IAID and one hint IA
  Prefix of that length in its Solicit and Request, and again in every Renew,
  Rebind and Release; a zero hint puts nothing on the wire. The Reply's
  prefixes are held in `Prefixes`, a third slice that the address list, duplicate
  address detection and every reader of the stable lease never see, because
  RFC 3633 §12.1 never assigns a delegated prefix to the link it arrived on.
  The library installs nothing. dnsmasq delegates no prefix, so the tests run Kea:
  with a `pd-pools` entry its lease file carries a PD row for the client's DUID,
  a Renew appends the renewed row and a Release a row that has expired
  (`TestKeaDelegatesAPrefixAndKeepsItsRow`, `TestKeaRenewsThePrefixRow`,
  `TestKeaTakesAReleasedPrefixBack`). Kea without a pool answers NoPrefixAvail
  and still gives the address, and dnsmasq answers with no IA_PD at all; both
  leave the address bound and `Prefixes` empty
  (`TestKeaWithoutAPrefixPoolStillGivesTheAddress`,
  `TestADnsmasqThatCannotDelegateLeavesTheAddressAlone`). A lease resumed with a
  prefix sends a Rebind and no Confirm, as RFC 8415 §18.2.12 has it, and Kea's
  row is renewed (`TestKeaSeesAResumedPrefixRebind`). The refusals, the
  earliest T1 and T2 across the IAs, a prefix changed or dropped by a renewal and
  the resumed Rebind's three outcomes are driven in [`proto`](../proto), where
  the Reply can be chosen. The Kea tests run in a mount namespace so its lease
  database sits under the one directory it accepts.
- **A DHCPv6 name given to a client that is already running, in the server's
  own table.** The client holds a lease with no name and dnsmasq's lease file
  shows `*`. It is handed one, sends RFC 4704's Client FQDN option with the S
  bit set in a Renew at once, and the lease file then carries the name against
  its address. The server's own Client FQDN option is reported on the lease,
  and three further calls with the same name produce no Renew
  (`TestAV6HostnameSetAfterStartReachesTheServersLeaseFile`). The Renew before
  T1 is this library's choice: RFC 4704 §5.4 lets a client send new name data
  "when it communicates with the server again" and RFC 9915 names no early
  Renew for it (`TestAV6NameSetWhileBoundIsSentInAnEarlyRenew`). The option
  rides only Solicit, Request, Renew and Rebind (RFC 4704 §5)
  (`TestAV6NameAtStartRidesSolicitRequestRenewAndRebind`,
  `TestOption39StaysOutOfEveryOtherV6Message`).
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
  that shape itself and does not trust the caller for it: the one server the
  fixture runs accepts the datagram either way, so no outside evidence from it
  would show the violation. That is a fact about that server, not about every
  server
  (`TestAV6ReleaseRefusesToComeFromTheAddressItIsReleasing`).
- **A socket that keeps the namespace it was opened in.** A client is built on
  a thread inside a network namespace of its own, the thread is then destroyed,
  and the client leases from a server that exists only in there. The goroutine
  running it cannot even see the interface. That is what lets one process lease
  on many containers' links at once.
- **A link that is down for a while, and one that goes away.** Each of the
  four raw sockets (the IPv4 and DHCPv6 transports, ARP and Neighbor
  Discovery) is opened on a veth whose end is down, reports the one "network
  is down" Linux gives it, and reads the peer's frames on the same socket once
  the link comes up. The same sockets on a link that is deleted, while up,
  after coming up, after frames queued before a down and while still down,
  report an error wrapping `ErrLinkGone` and stop, and `ReadErrors` counts
  exactly the errors the consumer received ([#23](https://github.com/claymore666/dhcp-golib/issues/23),
  `TestTheV4TransportReadsOnAfterTheLinkComesUp`,
  `TestALinkThatGoesAwayStillReachesEachSocketAsAnError`).
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
- **The NAT64 prefix an advertisement carries, held per entry and reported
  with the router view.** The PREF64 option of RFC 8781 is decoded in the
  codec and kept in the state machine beside the resolver list: one entry per
  prefix, each with its own lifetime, which is the Scaled Lifetime times eight, §4.1. A lifetime
  of zero withdraws the prefix at once, an entry outlives a router whose
  lifetime went to zero and dies at its own expiry with no further
  advertisement, and a refresh that shortens a lifetime is taken as sent
  (`TestAPREF64PrefixLivesForItsScaledLifetimeTimesEight`,
  `TestAPREF64PrefixOutlivesARouterWhoseLifetimeWentToZero`,
  `TestARefreshThatShortensTheLifetimeIsHonoured`). The list is read from
  `Router()` on the manager, sorted by address and then length, and a journaled
  advertisement replays into the same list
  (`TestTheManagersRouterViewCarriesThePREF64AndItsLifetimeEndsOnTheManagersClock`,
  `TestAReplayedAdvertisementKeepsTheRouterItCameFrom`). The frame is synthetic:
  dnsmasq sends no such option, so no real server sits behind this entry and
  the observers are the state machine and manager tests over bytes built from
  the RFC's diagram.
- **An address formed from an advertised prefix.** RFC 4862 §5.5.3 d forms it
  by "combining the advertised prefix with an interface identifier of the
  link", and RFC 4291 Appendix A's modified EUI-64 is the identifier. The
  option is refused where the two do not fit: "If the sum of the prefix length
  and interface identifier length does not equal 128 bits, the Prefix
  Information option MUST be ignored." Every §5.5.3 rule that refuses an option
  is charged under its own name and counted
  (`TestEachIgnoreRuleIsChargedByName`,
  `TestEveryIgnoreReasonIsDeclaredCountedAndNamed`), and the formation is
  checked against RFC 4291 Appendix A's own octets
  (`TestTheFormedAddressIsRFC4291AppendixAsOwnOctets`). A link with two
  autonomous prefixes ends with two addresses, each with its own pair of
  lifetimes and its own expiry (`TestTwoAutonomousPrefixesFormTwoAddresses`,
  `TestEachAddressKeepsItsOwnLifetimeOrigin`), and §5.5.3 e's two-hour rule is
  driven at its boundary against the kernel's own numbers
  (`TestTheTwoHourRuleUsesRemainingLifetimeAndTheKernelsOwnNumbers`). A formed
  address goes through the same duplicate address detection an address from an
  IA_NA does, and a duplicate costs that one address and not the set
  (`TestANewlyFormedAddressGoesThroughDuplicateAddressDetection`,
  `TestADuplicateCostsOneAddressAndNotTheSet`). §5.5.4 gives the two phases
  their consequences: "A preferred address becomes deprecated when its
  preferred lifetime expires. A deprecated address SHOULD continue to be used
  as a source address in existing communications, but SHOULD NOT be used to
  initiate new communications if an alternate (non-deprecated) address of
  sufficient scope can easily be used instead." So a deprecated address is kept
  and reported as
  a change, and only an invalid one is dropped
  (`TestDeprecationKeepsTheAddressAndReportsAChange`,
  `TestOneAddressExpiringIsNotTheLeaseExpiring`). Which source an endpoint gets
  its address from is `Params6.Mode`: DHCPv6 alone, autoconfiguration alone, or
  the first advertisement deciding once and not again
  (`TestTheAutoModeDecisionIsTakenOnceOnTheFirstAdvertisement`,
  `TestAutoDoesNotFallBackIntoFormingAfterItCommittedToDHCPv6`). The lease a
  caller reads carries the formed set
  (`TestAnAddressFormedFromAnAdvertisementReachesTheCaller`) and a resumed
  client does not form it a second time
  (`TestAResumedFormedLeaseIsNotFormedASecondTime`).
  BOUND, and it is the one thing on this list that has it: this claim is driven
  at ring 1 and ring 2 against tables and decoded options. There is no run
  against a router advertising on a real link yet, which is the only entry here
  whose outside evidence is still owed.
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
  `TestAFailedReconfigureDoesNotRaiseTheReplayFloor`), and no action and no
  journal note carries the key: what those record is that a key arrived and
  how long it was (`TestNoActionNoteOrReasonCarriesTheReconfigureKey`). The
  boundary is the recorded datagram, MEASURED on this tree: the Reply that
  delivered the key keeps it verbatim in `proto.JournalEntry6.Raw`, where a
  replay needs the octets, and in the packet capture `Client6.Packets`
  returns. A caller that hands a journal or a capture to somebody else hands
  the key over with it. Every Reconfigure the machine is handed is COUNTED as
  well as journalled: one cell per rule in `proto.ReconfigureCounters`, and
  `lease.Stats.ReconfiguresAccepted` and `ReconfiguresRefused` beside it, which
  partition what reached the state machine
  (`TestEveryReconfigureRefusalArmRaisesItsOwnCounter`,
  `TestEveryReconfigureAcceptArmRaisesTheAcceptedCounter`,
  `TestAcceptedAndRefusedPartitionEveryReconfigure`,
  `TestEveryReconfigureRefusalIsDeclaredCountedAndNamed`,
  `TestAnAcceptedReconfigureReachesStatsAndTheCounters`,
  `TestARefusedReconfigureReachesStatsWithTheRuleThatRefusedIt`). A refusal is
  not a fault: a client that RESUMED a lease from a record with no key holds
  none and refuses its server's Reconfigures one after another, because RFC 9915
  Appendix B Table 5 gives the Reconfigure Accept option no mark for Confirm
  and §20.4.2 says "The server selects a reconfigure key for a client during
  the Request/Reply, Solicit/Reply, or Information-request/Reply message
  exchange." The span ends at the first ACCEPTED Reply that carries a key,
  whichever exchange it answers: §20.4.2 binds the server's choice, not what
  the client records, so a key in the Reply to the Renew at T1 ends it there.
  A Reply the client does not act on does not, and §18.2.10's UnspecFail and
  NotOnLink arms, an IA_NA that says NoBinding, a malformed Status Code option
  and a Reply with no usable address are among them. The rule is the two call
  sites, `takeReply` and `takeConfig` (the Reply to an Information-request),
  each recording the key where the Reply is acted on, and not this list.
  `TestAResumedClientIsKeylessUntilAReplyCarriesAKey` drives the span, the
  Renew's Reply that ends it, and the exchanges §20.4.2 does name;
  `TestAKeyInAReplyThisClientRefusesDoesNotEndTheKeylessSpan` drives the
  boundary.
  The key, the replay floor and whether a floor exists are in the lease record
  (`reconfigure_key`, `reconfigure_replay`, `reconfigure_replay_seen`) and
  restore the resumed lease's own server's entry, so a record that has them
  starts no keyless span (`TestAResumedLeaseAuthenticatesAReconfigureSignedWithItsRestoredKey`).
  A Reconfigure accepted since the last Reply that carries a lease reaches the
  record at that Reply, so a restart before it accepts those Reconfigures
  again; an Information-request Reconfigure emits no lease, so several can wait
  there. A Reconfigure key carried by an Information-request Reply reaches the
  record at the next lease Reply too, the same window as the floor; a restart
  inside it restores the earlier key, so the server's valid Reconfigures are
  refused until a Reply brings a key again
  (`TestAKeyChangedInAnInformationRequestReplyReachesTheRecordAtTheNextLeaseReply`).
  Other servers' entries are lost at a restart.
  A Reconfigure discarded before the state
  machine — a datagram that would not decode, or one the transport dropped as
  addressed to another node — is in neither counter.
- **The counters of the v1.2.0 features.** Each feature kept its counters in
  its own `proto` file, and each reaches `lease.Stats`, the record's wire half
  and a `Manager` accessor the way the Reconfigure counters do: read once after
  the Step, under the manager's lock, from the machine of the manager's own
  family, with the other family's accessor returning the zero value
  (`TestAV4ManagerReportsNoV6Counters`, `TestAV6ManagerReportsNoV4Counters`).
  All of them are WIRED and none is folded: no event in a record's own stream
  produces one (`TestEveryNewCounterIsWiredAndNoneIsFolded`), and a record
  that outlives a manager adds each manager's counts
  (`TestEveryNewCounterAccumulatesAcrossManagerInstances`). A record written
  before them decodes with all of them zero
  (`TestARecordWrittenByV110ReadsBackWithTheNewCountersZero`).
  - **IPv6-only preferred** (RFC 8925, `IPv6OnlyWaited`, `IPv6OnlyIgnored`,
    `IPv6OnlyMalformed`, `Manager.IPv6OnlyCounters`): an OFFER with the
    IPv6-only-preferred option pauses DHCPv4 and an ACK with it keeps the lease
    (`TestAnOfferWithOption108ReachesStatsAsAWait`,
    `TestAnAckWithOption108ReachesStatsAsIgnored`,
    `TestAMalformedOption108ReachesStatsAndTheLeaseStillForms`).
  - **Rapid commit** (RFC 4039 and RFC 9915's Solicit rules,
    `RapidCommitsAccepted`, `RapidCommitsRefused`,
    `Manager.RapidCommitCounters`, `Manager.RapidCommit6Counters`): one pair
    in `Stats` serves both families, because a manager runs one, and the two
    accessors stay apart
    (`TestARapidCommitAckReachesStatsAsAccepted`,
    `TestARefusedRapidCommitAckReachesStatsAndStartsNoLease`,
    `TestADhcpv6RapidCommitReplyReachesStatsAsAccepted`,
    `TestAMalformedDhcpv6RapidCommitReplyReachesStatsAsRefused`; the v6 count
    is also read at the Step that raised it, before any later Step can hide a
    mirror taken one Step late,
    `TestADhcpv6RapidCommitCountIsCurrentAtTheStepThatRaisedIt`,
    `TestARefusedDhcpv6RapidCommitCountIsCurrentAtTheStepThatRaisedIt`).
  - **FORCERENEW** (RFC 3203 and RFC 6704, `ForcerenewsRenewed`,
    `ForcerenewsAlreadyRenewing`, `ForcerenewsAckRefused`,
    `ForcerenewsRefused`, `Manager.ForcerenewCounters`): `Stats` carries the
    total of the refusals and the accessor the rule that refused each, and the
    returned array is the caller's copy
    (`TestAForcerenewReachesStatsAsRenewedThenAsAlreadyRenewing`,
    `TestARefusedForcerenewReachesStatsWithTheRuleThatRefusedIt`,
    `TestAForcerenewAccessorHandsOutACopy`,
    `TestAnAckThatLacksTheNonceReachesStatsAsAckRefused`).
  - **Temporary addresses** (RFC 9915's rules for a Reply,
    `TemporaryAddressesGranted`, `TemporaryAddressesRefused`,
    `TemporaryAddressesAbsent`, `TemporaryAddressesConflicted`,
    `Manager.TemporaryCounters`): an Advertise and a Reply each count Absent
    or Refused, so one exchange can count either twice
    (`TestAReplyWithNoIATAReachesStatsAsAbsent`,
    `TestAnIATAWithNoAddressReachesStatsAsRefused`,
    `TestAnIATAWithAnAddressReachesStatsAsGranted`,
    `TestADuplicateTemporaryAddressReachesStatsAsConflicted`; the count is also
    read at the Step that raised it,
    `TestATemporaryAddressCountIsCurrentAtTheStepThatRaisedIt`).
  - **Delegated prefixes** (RFC 9915's rules for a Reply, `PrefixesGranted`,
    `PrefixesRefused`, `PrefixesAbsent`, `PrefixesChanged`,
    `Manager.PrefixCounters`): only a Reply grants, a Renew's or Rebind's
    Reply that names other prefixes counts Changed
    (`TestADelegatedPrefixReachesStatsAsGranted`,
    `TestAnAnswerWithNoIAPDReachesStatsAsAbsent`,
    `TestAnIAPDWithNoPrefixReachesStatsAsRefused`,
    `TestARenewalThatChangesThePrefixReachesStatsAsChanged`).
- **The namespace and the thread.** The v6 client's three sockets and its
  link-local address are taken in one call, in the namespace of the thread it
  was built on, and it leases from a server only that namespace can see.
- Renewal, rebinding, expiry, Advertise selection by preference, the Status
  Code paths and the Information-request are ring 1's, driven there in
  milliseconds against [`proto`](../proto)'s tables and against captured frames replayed
  through the decoder.

