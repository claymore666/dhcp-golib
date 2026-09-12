# Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

# shellcheck shell=bash
#
# verify.manifest.sh — what MUST be there. Declarations only; no logic that
# measures anything, and nothing here is derived from the files it describes.
#
# WHY THIS FILE EXISTS (round 9). Four consecutive review rounds found the same
# defect, one level up each time, and the cause was never carelessness: every
# guard derived its expectation from the thing it was guarding.
#
#   round 5  the unit suite's population came from the filesystem it checked
#   round 6  the oracle's expected count came from a grep over the oracle
#   round 7  the row roster lived in verify.sh, beside the rows
#   round 8  the row-coverage check read that roster back out of verify.sh
#
# Each had a non-vacuity floor and EVERY FLOOR WAS ZERO. Zero is the one value
# a domain cannot reach by deletion, so shrinking a population by one was
# invisible in all four. MEASURED 2026-08-30 by review: deleting the shellcheck
# gate — its step, its roster entry and its two scenarios — produced
# "VERDICT: PASS (10 steps)" with four live SC2034 findings in the tree.
#
# So the expectation is stated HERE, where it is not the subject of any check
# it parameterises, in three layers:
#
#   1. names, listed literally, sourced by verify.sh AND by the oracle;
#   2. a literal count beside each list, so removing a name without editing the
#      count beside it is a refusal — one edit is not enough even in this file;
#   3. a Go pin, internal/manifest, in another language and another directory,
#      which asserts these names and these numbers. It runs inside the unit
#      suite, whose own population is floored below.
#
# THE CLAIM, AND ITS BOUND. No edit confined to a SINGLE FILE can shrink the
# arbiter's population. That is not "cannot be shrunk": editing this file and
# the Go pin together still does it, and no mechanism in a repository can stop
# that. The regress terminates at a person reading a diff, and the whole point
# of this file is that the diff is one line, in a file whose entire content is
# the expectation, rather than eleven lines spread through the code that
# happens to implement it.

# The rows that must appear in the verdict table.
MANIFEST_ROWS=(
	self-check
	citations
	bounds
	build
	vet
	gofmt
	shellcheck
	doc-numbers
	readme-usage
	gate-roster
	t1
	t2
	unit-suite
	netns-suite
	self-drive
	verify-oracle
)
MANIFEST_ROWS_N=16

# The rows an INNER run does not have. --inner exists so the oracle's copies do
# not re-enter the oracle; netns-suite joined the list on 2026-09-05 because
# sixty-odd copies of this tree each raising real namespaces and a real dnsmasq
# is not a cost the oracle can carry. What that leaves undriven is stated
# rather than argued away: this row is driven by OUTER scenarios only,
# and which ones is read off MANIFEST_SCENARIO_CONTRACTS rather than counted
# in a sentence here.
MANIFEST_OUTER_ROWS=(
	netns-suite
	self-drive
	verify-oracle
)
MANIFEST_OUTER_ROWS_N=3

# The rows a SCOPED run (--light) leaves out, and the entire meaning of that
# flag. Both are the expensive populations; every other row still runs, so a
# scoped run is a real run of everything cheap and says on its verdict line
# which rows it did not run.
#
# The refusal that matters is not here but in the shape of the thing: a
# scenario whose contract names a row in this list, and which declares itself
# light, has scoped away the row it exists to drive — the row records nothing,
# the contract reads ABSENT, and the scenario fails. manifest_check refuses the
# combination outright so that it cannot be written down in the first place.
MANIFEST_SCOPED_OUT_ROWS=(
	unit-suite
	netns-suite
)
MANIFEST_SCOPED_OUT_ROWS_N=2

# The rows that may record SKIPPED. Exactly one, and record() rewrites a
# SKIPPED from any other row to FAIL: a third verdict is a way for a row to
# stop measuring, and the population entitled to it is enumerated here rather
# than decided at the row.
MANIFEST_SKIPPABLE_ROWS=(
	verify-oracle
)
MANIFEST_SKIPPABLE_ROWS_N=1

# The one spelling of the oracle's own verdict line, and the reason it is here
# rather than in any of the four files that use it.
#
# 2026-09-06, D36, carried review row R1. The oracle prints this line; verify.sh
# parses it for the scenario count and puts it in the verify-oracle row's
# detail; the CI job greps that row for it. Three producers and three consumers
# of one token, with nothing tying them together: a rename in the oracle left
# the arbiter's parse and the job's grep looking for a line that no longer
# exists, and the job's diagnosis then named a state ("the oracle did not run")
# that had not occurred. The oracle's two fabricating stubs read it too, because
# a stub whose whole purpose is to print a CONVINCING account stops being the
# strongest fake the moment the real spelling moves away from it.
#
# What deliberately does NOT read it: MANIFEST_SCENARIO_CONTRACTS' diagnosis
# tokens. A contract is this file's independent statement of what a message must
# say; one that followed the token automatically would agree with any rename,
# which is the whole shape this file exists to refuse.
MANIFEST_ORACLE_PASS_PREFIX='ORACLE PASS:'

# The self-check row's own population: how many probe verdicts it puts through
# record() before any real row, and how many of those record() must REFUSE.
#
# ROUND 2, 2026-09-05. These were derived inside verify.sh — the row counted
# its own cases and reported `cases - 2` refusals — so a probe deleted together
# with the arm it drives moved the expectation with it. MEASURED by review at
# the previous head: record()'s SKIPPED arm turned into `if false` and its
# probe deleted in one edit, every row green, the full oracle green, and the
# only trace a note that said "refused 4" instead of 5.
#
# Stating them here is the same move the rest of this file is: the number is
# not in the file that can delete the thing it counts. verify.sh compares both
# against what actually ran, so a probe added without an edit here is a
# refusal too — which is the direction that keeps the pair honest.
SELF_CHECK_PROBES_N=7
SELF_CHECK_REFUSALS_N=5

# The gate commands under internal/gates that must exist and must run.
MANIFEST_GATES=(
	t1
	t2
)
MANIFEST_GATES_N=2

# The shell scripts that must be linted. Cross-checked in both directions
# against a filesystem walk (scenarios unlinted-script, unlinted-shebang-script).
#
# .github/lane/ ARRIVED 2026-09-08 WITH D41 and the reason it is shell rather
# than YAML is this list. A `run:` block inside a workflow is linted by nothing
# here and driven by nothing here; a script is linted by the row below and can
# be run by a scenario. The lane's decisions — what a shard is, when a skip may
# be earned, what makes a verdict vacuous — are therefore each a file, and the
# workflow is the wiring between them.
MANIFEST_SHELL_SCRIPTS=(
	verify.sh
	verify.manifest.sh
	scripts/test-verify.sh
	scripts/oracle-contracts.sh
	scripts/sweep-doc-numbers.sh
	.github/lane/domain.sh
	.github/lane/govulncheck-pin.sh
	.github/lane/oracle-aggregate.sh
	.github/lane/oracle-run-check.sh
	.github/lane/oracle-shard.sh
	.github/lane/oracle-skip.sh
	.github/lane/prepare.sh
	.github/lane/verdict.sh
)
MANIFEST_SHELL_SCRIPTS_N=13

# The unit suite's declared-test population, stated rather than derived.
#
# This is the operand round 7 said could not exist. Its bound then was: "a test
# DELETED, rather than disabled, leaves both sides agreeing" — true, because
# both sides were derived from the tree. A literal is not derived from
# anything, so a deleted test moves the measurement and not this number.
#
# ROUND 11: it used to say "It is a FLOOR, not an equality: adding tests must
# not require an edit here." MEASURED 2026-08-30 by review: nothing in the tree
# raises it, so its protection ERODES MONOTONICALLY with every test added.
# Today's margin is zero — 169 against 169 — which is the strongest this
# operand will ever be. At 250 declared tests, 81 could be deleted with nothing
# going red and no instrument having noticed the decay. Three of the four
# manifest lists force their own maintenance; this one asked to be remembered,
# which is the property the whole design exists to remove.
#
# It is now a BAND, enforced by verify.sh in BOTH directions: below it is
# "tests were deleted", above MIN + MAX_DECLARED_MARGIN is "raise this number
# to N". Scenarios min-declared-tests-floor and min-declared-tests-margin.
#
# The Go pin holds a separate literal as a low-water mark, `>=` only. That one
# is NOT maintained in step and is not meant to be: it exists so that lowering
# the number here cannot go below a level somebody once measured.
#
# M7c (v6 runtime): 529 -> 580, and the fifty-one are enumerated per file so
# that the number is a record of what was added rather than a number somebody
# raised until the row went green. Measured as the difference of two
# `go run ./internal/tools/testroster` outputs, at f901589 and here; no test
# was renamed or removed between them.
#
#   lease/manager6_test.go          (4)  AV6ConflictIsCountedAndReportedAsOne,
#     TheConfiguredRunnerIsAskedAndItsAnswerIsTheMachines,
#     TheConfiguredRunnersDuplicateVerdictDeclines,
#     WithoutARunnerTheCallerStillOwesTheResult
#   proto/machine6_test.go          (2)  ADuplicateOnAFreshAcquisitionIsReported
#     AndNotOnlyJournalled, ADuplicateUnderAHeldLeaseReportsTheLossAndNotAFailure
#   runtime/dad6_linux_test.go      (8)  ACancelledProbeAnswersNothing,
#     AnAddressTheCodecRefusesIsReportedTakenNotFree,
#     AVerdictDuringTheWaitWindowIsTheAnswer, OneRunReportsExactlyOnce,
#     SilenceThroughTheWindowIsNotAVerdict, StartWithNoReportDoesNothing,
#     TheDuplicateCheckSortsOneFrameTheWayRFC4862Does,
#     TheOwnFramePredicateIsLengthSafe
#   runtime/dnsmasq6_linux_test.go  (9)  AClientOnALinkWithNoRouterStillAcquires,
#     ADuplicateAddressOnTheLinkIsDeclined,
#     AManagedLinkWhoseServerIsSilentIsNotALinkWithoutOne,
#     AResumedV6LeaseConfirmsAgainstRealDnsmasq,
#     ASLAACOnlyLinkSaysThereIsNoDHCPv6, AV6ClientAcquiresFromRealDnsmasq,
#     AV6ClientOnAStatelessLinkIsConfiguredAndNotLeased,
#     AV6ReleaseReachesRealDnsmasq, TheV6ClientKeepsTheNamespaceItWasBuiltIn
#   runtime/ipudp6_test.go         (14)  ARealAdvertiseIsAcceptedAsUncompleted,
#     ARealSolicitVerifiesAgainstItsOwnAddresses,
#     AVerifiedFrameIsNotReportedUncompleted,
#     BuildIPv6ICMPPutsExactlyTheChecksumsAddressesInTheHeader,
#     BuildIPv6UDPWritesTheHeaderTheChecksumCovers,
#     BuildRefusesAnAddressItCannotSend, IPv6UpperRefusesWhatItCannotWalk,
#     ParseIPv6ICMPReadsARealRouterAdvertisement,
#     ParseIPv6ICMPRefusesWhatIsNotICMPv6, ParseIPv6UDPChecksTheClientPort,
#     ParseIPv6UDPDiscardsAZeroChecksum, ParseIPv6UDPRefusesACorruptChecksum,
#     TheKernelsPartialChecksumIsOurPseudoHeaderSum,
#     TheV6ChecksumIsBoundedByThePayloadLengthAndNotTheFrame
#   runtime/linklocal6_linux_test.go (2) InterfaceLinkLocalRefusesAn
#     AddressTheKernelIsStillChecking, InterfaceLinkLocalReportsAFileItCannotRead
#   runtime/nd_linux_test.go        (5)  TheMulticastMACIsRFC2464s,
#     TheNDSocketDropsWhenAConsumerStalls,
#     TheNDSocketMakesTheFourChecksItOwnsAndCountsEachApart,
#     TheNDSocketRefusesAUnicastDestination,
#     ThisHostsOwnFrameIsCountedAndKeptOffTheLeasePort
#   runtime/platform_parity_test.go (3)  DADStatsDeclarationsAgree,
#     NDStatsDeclarationsAgree, TransportStatsV6DeclarationsAgree
#   wire/icmpv6_test.go             (4)  NeighborSolicitReadsTheSourceLinkAddrOption,
#     NeighborSolicitRefusesWhatSection711Refuses, OurOwnDADSolicitDecodesBack,
#     TheKernelsOwnDADSolicitDecodes
#
# M7c's CARRIED ROWS: 580 -> 587, measured the same way (two testroster runs,
# at e173966 and here; nothing renamed or removed between them). Seven, per
# file, and each one is the observer for a row the review or the CI runner
# named rather than a test added to raise a number:
#
#   runtime/dad6_linux_test.go              (1)  AProbeThatCouldNotSend
#     DeclinesNothing
#   runtime/dnsmasq6_linux_test.go          (4)  AV6ClientDiscardsAnother
#     ClientsReplyAtTheTransport, AV6ClientRefusesALinkThatNeverGetsA
#     LinkLocalAddress, AV6ClientWaitsForTheKernelToAssignTheLinkLocalAddress,
#     TheFixtureReadsItsOwnDnsmasqArguments
#   runtime/transport_packet6_linux_test.go (2)  AnUncompletedChecksumIs
#     CountedOnlyForThisClient, TheV6TransportCountsEachRefusalApart
#
# M7c's THREAD ROUND: 587 -> 591, measured the same way (two testroster runs,
# at 560ea3b and here; one test was RENAMED, which moves no count —
# InterfaceLinkLocalReportsAFileItCannotRead became
# InterfaceLinkLocalReportsAKernelItCannotAsk, because there is no file any
# more). Four, per file, each the observer for a row the runner's red or this
# round's own enumeration named:
#
#   runtime/dnsmasq6_linux_test.go          (1)  TheV6ClientReadsTheLinkLocal
#     OfTheThreadItWasBuiltOn
#   runtime/linklocal6_linux_test.go        (3)  ADumpThatDoesNotParseIsNotAn
#     AbsentAddress, InterfaceLinkLocalReportsAnInterfaceThatIsNotThere,
#     TheLinkLocalDumpAsksTheKernelForIPv6Addresses
#
# M7e's LIBRARY FIXES: 591 -> 609, measured the same way (two testroster runs,
# at 8a90619 and here). One test was RENAMED, which moves no count —
# ParseIPv6UDPChecksBothPorts became ParseIPv6UDPChecksTheClientPort, because
# RFC 9915 §7.2 leaves a server's source port free and the parse no longer
# checks it; the name is corrected in the M7a list above rather than left
# naming a function that is gone. Eighteen added, per file, each the observer
# for one of the four library defects that round fixed or for a carried row:
#
#   proto/machine6_declinehint_test.go   (7)  TheSolicitAfterADeclineDoesNot
#     AskForTheDeclinedAddress, ASecondDeclineDoesNotBringTheHintBack,
#     ADeclineOfADIFFERENTAddressLeavesTheHintAlone, TheHintIsDroppedEvenAfter
#     AnEarlierDeclineOfAnotherAddress, AnAcquisitionAfterADeclineDoesNotClaim
#     ToHaveAskedForTheAddress, AMachineThatHasDeclinedNothingStillHints,
#     AnAddressDeclinedWithNoServerToTellIsStillNotHintedAgain
#   proto/machine6_resumeconfig_test.go  (4)  AConfirmedResumeKeepsThe
#     ConfigurationItWasGiven, AnUnansweredConfirmKeepsTheConfigurationToo,
#     Resume6CloneReachesTheConfigurationLists,
#     AMachineDoesNotFollowTheCallersRememberedLists
#   lease/manager6_test.go               (1)  AResumedV6LeaseKeepsThe
#     ResolverItRemembered
#   lease/record6_params_test.go         (3)  AV6RecordCarriesTheParameters
#     ItsReplayNeeds, TheV6ParamsSnapshotIsNotAliased,
#     ARecordRefusesTheOtherFamilysParameterSnapshot
#   runtime/newfile_label_test.go        (1)  NoCallerStringReachesOsNewFile
#   runtime/dnsmasq6_linux_test.go       (1)  ADeclinedHintIsNotAskedForAgain
#   runtime/ipudp6_test.go               (1)  AReplyFromAnUnusualSourcePortIs
#     Delivered
#
# THE D29 PUBLICATION SWEEP: 609 -> 615, measured the same way (two testroster
# runs, at d78c1eb and here). Six added, per file, each the observer for a
# claim this repository makes to a reader who cannot ask anybody about it:
#
#   internal/publication/workflows_test.go (3)  NoSelfHostedJobIsReachable
#     FromAForkPullRequest, NoWorkflowReadsARepositorySecret,
#     TheWorkflowScanRefusesTheShapesItExistsToRefuse
#   internal/publication/headers_test.go   (2)  EveryGoAndShellFileCarriesThe
#     LicenceHeader, TheLicenceHeaderPointsAtALicenceThatGrantsIt
#   runtime/example_test.go                (1)  ExampleClient6
#
# The "Test" prefix is left off each name above so the lines fit; every one of
# them carries it in the tree — except ExampleClient6, which carries the
# Example prefix instead and which testroster counts for the same reason
# `go test -list` reports it.
# ROUND 2 OF THE SAME SWEEP: 615 -> 616. One added, the observer for the
# escape the round-1 scan could not see — two workflows, each innocent alone,
# composed by a `uses:` edge so a fork's pull request reaches a runner of ours:
#
#   internal/publication/workflows_test.go (1)  AForkTriggerReachesThe
#     WorkflowsItCalls
# ROUND 3 OF THE SAME SWEEP: 616 -> 617. One added, and it is the SET-level
# half of the round-2 escapes: two workflows read together, where a shape the
# reader could not enumerate used to be read as an absence and a sibling file
# held the floor up:
#
#   internal/publication/workflows_test.go (1)  TheWorkflowScanRefusesASet
#     ItCannotRead
# ROUND 4 OF THE SAME SWEEP: 617 -> 618. Net one, and it is two moves: the
# secret check became a forbidden WORD, so the tree row was renamed
# (NoWorkflowReadsARepositorySecret -> TheWordSecretsAppearsNowhereUnderGithub,
# and its domain widened from the workflows to everything under .github/), and
# one test was ADDED for the word itself — the five spellings review round 3
# measured escaping the two patterns that used to stand there, plus the two
# substring controls that keep the rule a rule about a word:
#
#   internal/publication/workflows_test.go (1)  TheForbiddenWordIsRefusedIn
#     EverySpellingGitHubHonours
#
# D41 ROUND 2: 620 -> 624. Two are read-backs of a number that used to be
# stated in prose and checked by nobody, and two are the refusal that answers
# the pipe which threw a verdict away on run 34214582437:
#
#   internal/manifest/manifest_test.go (2)  TheStatedPopulationIsWhatThe
#     SweepCounts, TheStatedCeilingBandIsTheOneTheOracleChecks
#   internal/publication/workflows_test.go (2)  APipelineInAWorkflowDoesNot
#     ThrowAwayItsVERDICT, ThePipelineRefusalSpeaksInBothDirections
#
# D37, THE PUBLIC-REPO SET: 624 -> 628, measured the same way (two testroster
# runs, at a761434 and here). Four added, and they are the two rows carried out
# of the D29 sweep review — the two routes past the forbidden word that nothing
# was reading — each with the case set that drives it in both directions:
#
#   internal/publication/workflows_test.go (4)  EveryFileUnderGithubIsText
#     ThisReaderCanRead, TheTextRefusalSpeaksInBothDirections,
#     NoWorkflowGrantsAPermissionTheseChecksDoNotNeed,
#     ThePermissionRefusalSpeaksInBothDirections
#
# D37 ROUND 2: 628 -> 632, measured the same way. Two of the four close review
# round 1's finding 2 — the fork triggers are two events and one of them hands
# out this repository's own token — and two close its finding 3, holding the
# security page to the page it cites:
#
#   internal/publication/workflows_test.go (4)  NoWorkflowIsTriggeredBy
#     PullRequestTarget, ThePullRequestTargetRefusalSpeaksInBothDirections,
#     TheSecurityPageStatesTheRulesTheVerifyingPageStates,
#     TheRuleAgreementSpeaksInBothDirections
#
# The round's BLOCKING finding added no test: the permitted set became a set of
# pairs rather than a set of names, and the value half is driven by six cases
# inside ThePermissionRefusalSpeaksInBothDirections, which already existed.
# M7f, THE v6 DEFECT ROUND: 632 -> 648, measured the same way (two testroster
# runs, one over the base tree and one here). Sixteen added, in the seven files
# that carry this round's observers:
#
#   proto/machine6_declinehint_test.go  (7)  AnAddressWithdrawnUnderABound
#     LeaseIsNotHintedAgain, ADuplicateFoundUnderABoundLeaseIsNotHintedAgain,
#     AnAddressWithdrawnWhileRenewingIsNotHintedAgain, ADeclineUnderABound
#     LeaseLeavesAnUnrelatedHintAlone, AResumedMachineDoesNotAskForAnAddress
#     ItDeclined, ARestartWithNothingDeclinedStillHints, TheDeclinedSetHanded
#     OutIsNotTheMachinesOwn
#   lease/record6_params_test.go        (3)  ADeclinedAddressReachesTheRecord
#     AndTheClientRebuiltFromIt, ARebuiltClientWithNothingDeclinedStillHints,
#     TheV6SnapshotDoesNotAliasTheDeclinedSet
#   wire/dhcpv6_test.go                 (2)  ASummaryNamesTheAddressAMessage
#     AsksFor, ASummaryOfAMalformedOptionIsStillALine
#   proto/machine6_replay_test.go       (1)  Replay6TellsAHintedSolicitFrom
#     AnUnhintedOne
#   runtime/dnsmasq6_linux_test.go      (1)  AV6LinkLocalThatLostTheKernels
#     DuplicateCheckIsRefusedAsFailed
#   runtime/linklocal6_linux_test.go    (1)  TheLinkLocalWaitDoesNotNoticeAn
#     InterfaceThatWentAway
#   runtime/newfile_label_test.go       (1)  TheNewFileLabelRuleRefusesEvery
#     WayPastIt
#
# One of them is a netns test, which is why the enumeration under
# NETNS_CEILING_SECONDS in verify.sh is re-measured in the same round.
#
# M7f ROUND 2, THE FIX ROUND: 648 -> 653, measured the same way (one testroster
# run over round 1's head and one here). Five added, in three files, and each
# one is the observer a round-2 finding asked for:
#
#   lease/record6_params_test.go        (3)  ARunsOwnJournalReplaysAgainstIts
#     OwnSnapshot, TheRecordsDeclinedSetIsNotAliased, AServersSolMaxRTReaches
#     TheManagersParameters
#   proto/machine6_declinehint_test.go  (1)  TheDeclinedSetSurvivesSeveral
#     Rebuilds
#   wire/dhcpv6_test.go                 (1)  ASummaryOfAnIANATruncatedAfterOne
#     AddressIsTheBareCode
#
# None is a netns test, so the netns enumeration in verify.sh does not move in
# this round and is not re-measured.
#
# THE DOCS ROUND, ROUND 2: 653 -> 654, measured the same way, one testroster
# run over the base and one over this head, and the difference taken as a set
# rather than as two numbers. One added, in one file, and it is the observer
# the domain of the doc-numbers sweep did not have:
#
#   internal/manifest/manifest_test.go  (1)  TheStatedDomainIsTheOneTheSweep
#     Reads
#
# It is not a netns test, MEASURED with testroster -netns at 34 over the base
# and 34 here, so the netns enumeration in verify.sh does not move and is not
# re-measured.
#
# ROUND 1 OF THIS ROUND LEFT IT AT 653 AND THAT IS THE FINDING. The band was
# full: 654 declared against 653 plus a margin of 1, so every oracle scenario
# that plants a test into its own copy reached 655 and failed the unit-suite
# row it was not driving. Shard 2's ceiling-control and shard 1's
# ceiling-fires are what said so, and a local `./verify.sh --inner` cannot:
# the plant only exists inside the oracle.
#
# THE GOVULNCHECK PIN ROUND: 654 -> 656, measured the same way, one testroster
# run over the base and one over this head, the difference taken as a set. Two
# added, in one file, and they are the observer the scan workflow did not have:
# nothing outside that workflow ran the pin guard, so deleting both of its
# steps left every check green.
#
#   internal/publication/govulncheck_test.go  (2)  TheScanWorkflowRunsThePin
#     GuardBeforeItInstalls, ThePinGuardRowSpeaksInBothDirections
#
# Neither is a netns test, MEASURED with testroster -netns at 34 over the base
# and 34 here, so the netns enumeration in verify.sh does not move and is not
# re-measured.
#
# L4 OF THE v2.2.0 IPv6 BATCH, #816: 654 -> 674, measured the same way, one
# testroster run over a clean worktree at the base and one over this head, the
# difference taken as a SET and not as two numbers. Twenty added, none removed,
# in three files:
#
#   proto/machine6_status_test.go  (18)  AReplyThatRefusesIsReportedWithThe
#     ServersOwnCode, AReplyThatSaysSuccessIsNotARefusal, AReplyWithNoAddress
#     AndNoStatusIsNotARefusal, AnAdvertiseThatRefusesIsReportedAndTheSchedule
#     Stands, ARefusedRenewKeepsTheLeaseAndSaysWhy, ANoBindingRenewIsA
#     RecoveryAndNotARefusal, NotOnLinkCostsTheLeaseAndIsCountedOnce,
#     AMalformedStatusCodeIsNeverReportedAsARefusal, AStatusInsideAnIAAddress
#     IsNotRead, AnIAThatRefusesAndOffersGivesNoAddress, ARefusedInformation
#     RequestIsNotAConfiguration, ALaterFailureCarriesNoEarlierStatus,
#     AV4NakCarriesNoStatusCode, EveryRefusingMessageIsReported, AMessageLevel
#     RefusalBesideAUsableAddressIsNotARefusal, AnAdvertiseThatRefusesAndOffers
#     IsNotSelected, AConfirmRefusedForThisLinkIsReported, AFailedAction
#     RendersTheCodeItCarries
#   lease/manager6_test.go          (1)  TheCallerIsToldWhichCodeTheServer
#     RefusedWith
#   runtime/dnsmasq6_linux_test.go  (1)  AV6ClientIsToldTheServerRefused
#
# The runtime one IS a netns test, MEASURED with testroster -netns at 34 over
# the base and 35 here, so the netns enumeration in verify.sh moves in this
# round and is re-measured there as one run rather than patched with a line.
#
# #816 ROUND 2, THE REVIEW ROUND: 674 -> 676, measured the same way. Two added,
# in two files, and each is an observer a round-2 finding asked for:
#
#   proto/machine6_status_test.go   (1)  AnIAThatFailsForAnotherReasonStill
#     HandsOverItsAddress
#   lease/manager6_test.go          (1)  TheRouterObservationOnARefusalIsWhat
#     HadBeenSeenByThen
#
# The first is the PRESERVATION direction of §18.2.10.1: the rule was observed
# only where it fires, so widening it to any failure code left the suite green.
# The second pins what Event.Router carries on a refusal stamped before any
# Router Advertisement has arrived, which is the ordering the advice beside
# that field is written against.
#
# NEITHER IS A NETNS TEST, measured with testroster -netns at 35 on both sides
# of this round, so the netns enumeration in verify.sh is not re-measured here.
# NETNS_CEILING_SECONDS did move, 140 -> 160, and the derivation is in that
# block: at 108s the old headroom sat exactly on its 32s floor, and this round
# is the one the block named as having to move the number.
#
# THE BACK-MERGE OF THE PIN ROUND INTO #816: the two rounds above are disjoint
# — different files, no test renamed or removed in either — so the merge
# product carries both, 656 + 22 and 674 + 2 reaching the same number. It is
# MEASURED on the merge product and not added up: one testroster run here.
#
# L5, #925 (DHCPv6 Reconfigure), over the back-merge of #816 and the pin round:
# 678 -> 725, measured the same way — one testroster run over the merge base and
# one over the merge product, the difference taken as a set and not added up.
# Forty-seven added, in four files, none removed:
#
#   wire/dhcpv6_reconfigure_test.go     (13) TheReconfigureMessageOptionReads
#     AllThreeMsgTypes, TheReconfigureMessageOptionRefusesEveryOtherMsgType,
#     TheReconfigureAcceptOptionIsZeroLength, TheAuthenticationOptionRoundTrips,
#     TheAuthenticationOptionRefusesWhatIsNotRKAP,
#     RKAPVerifyAcceptsTheSpanRFC9915Defines, RKAPVerifyRefusesAWrongZeroedSpan,
#     RKAPVerifyCoversTheWholeMessage, RKAPVerifyReadsTheOctetsThatArrived,
#     RKAPVerifyRefusesAKeyThatIsNotOneHundredAndTwentyEightBits,
#     RKAPVerifyRefusesAMessageWithNoAuthenticationOption,
#     RKAPVerifyRefusesASecondAuthenticationOption,
#     RKAPVerifyRefusesADigestThatIsRightInItsLeadingOctets
#   wire/hmacmd5_test.go                (7)  MD5MatchesRFC1321sOwnVectors,
#     HMACMD5MatchesRFC2202sOwnVectors,
#     MD5AgreesWithTheStandardLibraryAtEveryBoundary,
#     HMACMD5AgreesWithTheStandardLibrary,
#     EqualConstantTimeAnswersTheSameQuestionBytesEqualDoes,
#     EqualConstantTimeHasNoEarlyExit, RKAPVerifyIsTheOnlyMD5InThisPackage
#   proto/machine6_reconfigure_test.go  (25) AReconfigureNamingRenewStartsARenew,
#     AReconfigureNamingRebindStartsARebind,
#     AReconfigureNamingInformationRequestKeepsTheLease,
#     TheLeaseOutranksAReconfiguresInformationRequest,
#     TheRefreshTimerIsHonouredAfterTheDetour,
#     EveryReconfigureDiscardRuleFiresOnItsOwn,
#     AReconfigureFromAServerThatSentNoKeyIsDiscarded,
#     TheReplayDetectionValueIsPerServerAndMustIncrease,
#     TheReplayFloorIsPerServer, AFailedReconfigureDoesNotRaiseTheReplayFloor,
#     AReconfigureIsIgnoredWhileTheExchangeItAskedForIsInFlight,
#     AReconfiguresTransactionIdIsIgnored,
#     AReconfigureIsIgnoredWhereTheClientHoldsNothing,
#     TheReconfigureAcceptOptionGoesWhereTheRFCAllowsIt,
#     AcceptReconfigureOffIsOffInBothDirections,
#     DefaultParams6AcceptsReconfigure, TheReconfigureKeyNeverReachesTheJournal,
#     AReconfigureReplaysWithItsDestination,
#     OnlyRKAPTypeOneIsStoredAsTheReconfigureKey,
#     TheAnsweringServerIdentifierDiesWithItsExchange,
#     ALaterReplysKeyReplacesTheOldOneAndAKeylessReplyKeepsIt,
#     AReconfigureRefusedForStateDoesNotBurnItsReplayValue,
#     ARingOneRuleCannotSeeWhoseUnicastAddressItIs,
#     ARenewalDuringTheRefreshDelayDoesNotLoseTheRefresh,
#     AReconfiguresInformationRequestRefusedKeepsTheDetourOpen
#   runtime/reconfigure6_linux_test.go  (2)  AnAuthenticatedReconfigureMakesThe
#     ClientRenew,
#     AClientThatDoesNotAcceptReconfigureAnnouncesNothingAndAnswersNothing
#
# The last two ARE netns tests, so the netns enumeration in verify.sh moves in
# this round and is re-measured there — MEASURED with testroster -netns at 35
# over the merge base and 37 over the merge product, and the whole table is one
# run on the merge product rather than #816's table with two lines inserted.
# NETNS_CEILING_SECONDS moves with it, 160 -> 170: #816's paragraph named the
# round that adds a netns test as the one that has to move the number rather
# than re-check it, this is that round, and 170 is 117s of measured wall plus
# 53s of derived headroom. The derivation is in that block.
#
# AReconfiguresInformationRequestRefusedKeepsTheDetourOpen is the one test here
# that exists because of the merge rather than because of either side: #816's
# early return on a refused Information-request sits in front of the call that
# ends this branch's Reconfigure detour, and a clean textual merge answers
# nothing about what becomes of the detour.
#
# THE HOSTNAME SETTER, #961, AND ITS BACK-MERGE INTO THIS BATCH: this branch
# moved the pin 654 -> 676 and then 678 without writing its set down, which is
# what this block repays. 725 -> 747, MEASURED here, one testroster run over
# dev at the back-merge base and one over the merge product, the difference
# taken as a SET and not added up: twenty-two added, none removed, none
# renamed, in three files:
#
#   proto/hostname_test.go                 (18)
#     AHostnameArrivingBeforeTheLeaseGoesOutAtTheBind,
#     AHostnameArrivingWhileProbingGoesOutAtTheAnnouncement,
#     AHostnameDuringARenewalResendsTheOpenTransaction,
#     AHostnameInBoundIsSentAsAnEarlyRenewal,
#     AHostnameOnALeaseWithNoServerIdentifierWaitsForT2,
#     AHostnameRenewalThatIsNAKedLosesTheLease,
#     AHostnameSetAfterStartReplaysFromTheStartParams,
#     AHostnameSetBeforeTheClientStartsGoesOutInTheFirstDiscover,
#     AHostnameSetDuringTheDesyncWaitGoesOutInTheDiscover,
#     AHostnameSetTwiceSendsOneMessage,
#     AHostnameSetWhileRebootingGoesOutInTheNextRequest,
#     AMachineRefusesAnUnsendableHostnameAtRuntime,
#     AnEmptyHostnameStopsTheOptionAndSendsNothing,
#     AnFqdnClientIgnoresAHostname, AnOrdinaryAcquisitionSendsNoExtraMessage,
#     NewRefusesAnUnsendableHostname, ParamsIsNotMovedByASetter,
#     TheRenewTimerLeftOverByAnEarlyRenewalIsIgnored
#
#   lease/hostname_test.go                 (3)
#     SetHostnameOnARunningManagerReachesTheServer,
#     SetHostnameRefusesWhatCannotBeSent, SetHostnameReportsAFullRequestQueue
#
#   runtime/hostname_dnsmasq_linux_test.go (1)
#     AHostnameSetAfterStartReachesTheServersLeaseFile
#
# No TEST file is touched by both sides, which is what makes the set a union
# with nothing to reconcile inside it. Three files did need a hand resolution
# and none of them declares a test: this pin, README.md's out-of-scope list,
# and JournalEntry6, where #925's Dst and this branch's Hostname are two new
# fields on one struct.
#
# The runtime one IS a netns test, MEASURED with testroster -netns at 37 over
# dev and 38 on the merge product, so the population the unit-suite row hands
# to the netns row moves here. It is derived at run time in verify.sh, so there
# is no second number to patch; NETNS_CEILING_SECONDS is this batch's 170 and
# is not moved by one more namespaced test.
#
# THE RELEASE-BY-RECORD ROUND, ROUND 2 OF THE READ: one more added,
# TestBindingTheReleaseSocketToALinkIsCheckedOrRefused, which drives the two
# sentences beside bindToDevice that were stated and run by nothing. It is not
# a netns test, MEASURED with testroster -netns at 41 on both sides of this
# fold, so the netns enumeration does not move here. 766 -> 767.
#
# THE RELEASE-BY-RECORD ROUND, #962: nineteen added, none removed, measured
# the same way, one testroster run over the base and one over this head with
# the difference taken as a SET. Ten read the built datagram's octets in
# lease, six read what the sender hands the transport in runtime, and three
# run a release against the dnsmasq fixture: one per family, and one that
# gives a second client exactly the identifier an invented option 61 would be.
#
# THREE OF THEM ARE NETNS TESTS, so the netns enumeration in verify.sh moves
# in this round and is re-measured there rather than patched with a line.
#
# THE BACK-MERGE OF dev INTO THIS BRANCH, three times: the rounds above are
# disjoint from this one, different files and no test renamed or removed in
# any of them, so the number below is MEASURED on the merge product with one
# testroster run here and not added up. 766 declared and 41 netns on the
# product of this branch and dev at 6a69a38, which is dev's 747 and 38 plus
# this round's nineteen and three.
MIN_DECLARED_TESTS=767

# How far above MIN_DECLARED_TESTS the tree may drift before the row refuses.
#
# It is not zero, and it is not a preference: an oracle scenario plants Go
# tests into its copy of the tree, so under a strict equality every such
# scenario would fail the unit-suite row it is not testing. The number is
# therefore exactly the largest number of test functions ANY ONE scenario
# plants, counting the helpers it calls.
#
# ROUND 13, N11. It used to be a literal sitting at that maximum as measured
# once, under a Go cap of 4 — so the band could be quadrupled one line at a
# time, and each of those edits would look exactly like the maintenance this
# file says it removes. It is now DERIVED and checked:
# TestDeclaredTestMarginIsDerivedFromWhatScenariosPlant reads the oracle,
# computes the maximum, and refuses any other value in EITHER direction. The
# 0..4 caps below and in the Go pin stay as a backstop, not as the check.
#
# BOUNDS, stated rather than claimed away: erosion is CAPPED at this number,
# not eliminated. One test may be added without anyone raising
# MIN_DECLARED_TESTS; the second one fails the row and names the number to
# write. A change that adds one test and deletes another is invisible to both
# edges — the band measures a population size, not its membership. And the
# derivation is a static read of a shell script: it cannot see a helper
# reached through a variable, and it counts a commented-out plant. Both of
# those fail closed, i.e. toward a larger derived number than the truth.
MAX_DECLARED_MARGIN=1

# The self-drive: the rows the ARBITER plants for itself, and the rows that must
# survive the same plant untouched.
#
# ROUND 13. The oracle's entire report is derivable from this file — every
# scenario name, its result class, its row verdict and now its diagnosis — so a
# script that sources this file and prints the contract table back reproduces a
# passing account without running anything. MEASURED 2026-08-30 by review at the
# previous head, and re-driven here: 24 lines, one file, clean under the lint
# gate, all sixty detections gone, whole run green in thirty seconds.
#
# Every check verify.sh could perform on the oracle's REPORT is defeatable by a
# fabricator that knows the check, because the report is the fabricator's own
# output. A replay that asks the same script again is answered by the same
# script; that construction was written this round and deleted for being
# circular. The only non-circular answer is the arbiter doing the work.
#
# So verify.sh plants these defects itself, in one copy, and runs one --inner
# pass. Blinding the arbiter now needs an edit to verify.sh as well as to the
# oracle — which is the difference between round 10's claim, that no single-file
# edit can shrink the arbiter's POPULATION, and the claim it does not make, that
# no single-file edit can BLIND it.
#
# BOUND, and it is a large one: these are seven rows of fourteen with one plant
# each, in ONE tree, chosen so no plant cascades into a row on the survivors
# list. The self-drive is a lower bound on the arbiter's liveness, not a
# substitute for the oracle's sixty-three, and it does not become one. The
# seven rows it does not plant stay blindable by an edit the oracle can no
# longer object to.
#
# MEASURED 2026-08-30, both halves, against the finished tree: fabricate the
# oracle by injection (one file, all sixty-three of its detections gone) AND
# blind the gofmt row in verify.sh AND plant a live unformatted file — the
# shape that gave VERDICT: PASS before this round — and the run ends
# VERDICT: FAIL on `gofmt=PASS (planted, did not redden)`. The fabrication is
# not what the self-drive stops; it is what the fabrication BUYS.
SELF_DRIVE_REDDENS=(
	gofmt
	shellcheck
	citations
	doc-numbers
	vet
	t1
	t2
)
SELF_DRIVE_REDDENS_N=7

# The preservation control, in the same run and against the same plant. Without
# it the self-drive is satisfied by an arbiter that reddens everything, which is
# a check with one possible verdict.
SELF_DRIVE_SURVIVES=(
	self-check
	bounds
	build
	gate-roster
	unit-suite
)
SELF_DRIVE_SURVIVES_N=5

# The wall-clock floor, in seconds, under the oracle's own run.
#
# ROUND 11, and it is the only operand here that binds WORK rather than
# reporting. Everything else in this file asks "is it there" or "did you say
# so". A fake oracle that prints a correct-looking account returns instantly;
# a real one copies the tree once per scenario and runs a race-enabled suite in
# each copy. MEASURED 2026-08-30 on this box, that tree: 262s. RE-MEASURED
# 2026-09-05 on this box, this tree, ORACLE_JOBS=4: 440s over the
# population MANIFEST_SCENARIOS_N declares, at the scopes
# MANIFEST_LIGHT_SCENARIOS declares. Round 1 wrote those two counts out here as
# "71 scenarios, 39 of them light" and both were wrong the moment the lists
# above moved; a count restated in a comment is a count nothing checks, which
# is the same lesson the DOC_NUMBER_CEILING comment carries. The number below
# is the oracle's WALL CLOCK,
# and it moves whenever the population or the scope declaration moves, so it is
# re-measured rather than carried: a floor derived from a measurement of a
# different tree is a literal wearing a derivation's clothes.
#
# BOUND, and it is weak on purpose: this is a floor against an INSTANTANEOUS
# stub, not proof of work. A fabricator that sleeps defeats it. It is here
# because the cheap edit should not be the quiet one, which is round 8's
# lesson, not because it is hard to get past.
#
# verify.sh checks it LAST, after every content check, so it can never displace
# a truer diagnosis. Scenario oracle-too-fast.
#
# ROUND 13, N12. The floor was the literal 8 standing two lines under a
# measurement of 175 — a number with no stated relationship to the thing it
# bounds, which is §0.2 with the measurement sitting right there. It is now
# DERIVED from that measurement at a stated fraction, and manifest_check
# refuses the two drifting apart.
#
# Why 5% and not more, stated as a trade rather than a preference: the floor is
# paid, in wall clock, by every scenario that reaches the floor through
# fabricating_stub, each sleeping the floor plus one second — a population that
# grows with the oracle and is not restated here, because a number in this
# comment is a number nothing checks. Raising the fraction
# raises that cost linearly, to catch a fabricator that is already free to
# sleep for as long as the floor demands. The floor buys "the cheap edit is not
# the quiet one"; it does not buy proof of work, and no fraction of a
# measurement can.
# How many lines of prose in README.md and docs/*.md may carry a bare number.
#
# ROUND 13, N13. `doc-numbers --check` used to print this count and compare it
# to nothing, so a new derived number — one no pattern in the sweep
# recognises — moved the count and was seen by nobody. MEASURED 2026-08-30 by
# review: a line carrying four live instrument-owned numbers passed.
#
# It is a CEILING, not an equality: prose that says "two" in words, a version
# pin, or a quoted sample can be added without an edit here, and the count
# falling is not a failure. Going over it prints the whole enumeration.
#
# The Go pin holds it from above (docNumberCeilingCap), because the cheap way
# to make this row stop saying anything is to raise the ceiling rather than
# delete the number.
#
# 2026-09-06, +2, and the two lines were enumerated because a bump without the
# list is a ratchet nobody earned: docs/verifying.md's "In CI" section carried
# the runner command (ORACLE_JOBS=1) and the one line that named the machine
# the runner facts were measured on (kernel, dnsmasq and Go versions).
#
# LATER THE SAME DAY, D36: both of those lines are gone — the lane no longer
# pins ORACLE_JOBS and no longer quotes an image's facts — and the section's
# numbers are now written in the "818s" form the sweep does not
# count as bare. The population MEASURED after that rewrite was 64, two under
# the number this line then carried, and the paragraph here argued the slack
# was safe because a ceiling is not an equality.
#
# 2026-09-08, D41: that argument was wrong in the direction that matters, and
# the review row it produced is what DOC_NUMBER_MARGIN below now answers. A
# ceiling two above its population is not a ceiling, it is an allowance for two
# bare numbers to arrive with nothing red — which is the whole thing this
# number exists to refuse. Both edges now name the number to write, so a
# population that FELL is a one-line edit here rather than a silent widening,
# and a population that ROSE is the same one-line edit.
#
# 2026-09-08, D41 round 2, and this is the row review MEASURED on the previous
# head: the sentence that used to end this paragraph — RE-MEASURED after this
# round's rewrite of "In CI": 64 — was the PREVIOUS round's measurement left
# standing above a ceiling this round had moved. With DOC_NUMBER_MARGIN=0 the
# two edges are an equality, so writing the paragraph's own number into the
# constant reddens the row: the prose and the number disagreed by five and
# nothing could see it, because a measurement in a comment is a claim nobody
# reads back.
#
# THE HISTORY, since the record got it wrong in the same way: 64 for most of
# the library's life; 66 on 2026-09-06 with the two lines enumerated above;
# back to 64 at d1f3964, when the "In CI" rewrite removed them; and what the
# marker below records, set here.
#
# WHAT MOVED IT IN ROUND 1: "In CI" gained the measured run table D41 asks for
# — three runs, four figures each — and every figure is a bare number in a
# prose line. The ceiling is the POPULATION and not headroom over it.
#
# WHAT MOVED IT IN ROUND 2, +1, and the line is enumerated because a bump
# without the list is a ratchet nobody earned: docs/verifying.md now says which
# pushes into `dev` wait for the oracle matrix and which do not, and cites the
# run and the two timestamps review measured it on. One line, one bare number
# that is a run id and two that are clock times.
#
# WHAT MOVED IT IN THE D37 PUBLIC-REPO ROUND: nothing, MEASURED 2026-09-08 with
# scripts/sweep-doc-numbers.sh over the head of that round. It added the three
# hosted scans to "In CI", two rules to the publication section and a
# Contributing paragraph to the README, and not one of those lines carries a
# bare number — which is the state the sweep asks for rather than a
# coincidence, and it is written down here because "the number did not move" is
# a measurement like any other.
#
# WHAT MOVED IT IN THE DOCS WORDING ROUND, 2026-09-08, +2, and the two lines
# are enumerated because a bump without the list is a ratchet nobody earned:
# docs/design.md's heading is now the noun "Purity of ring 1" and carries a
# ring number, and docs/verifying.md's ceilings paragraph re-wrapped so that
# the sentence about the old two-core figure now sits on a line of its own.
# Both are reflow. No number was added to the prose and none was deleted.
#
# THE POPULATION RULE, stated in the marker line below and nowhere else here.
# The domain is the prose pages of the repository: README.md, SECURITY.md and
# docs/*.md, which is the FILES array in scripts/sweep-doc-numbers.sh.
# SECURITY.md joined the domain in this round and contributes zero lines,
# MEASURED at the head of it, so the number below does not move for it. A URL's
# digits are blanked as a token there, the way a date and an RFC number are: an
# issue number in a link is an address, and no instrument recomputes it.
# internal/manifest's TestTheStatedDomainIsTheOneTheSweepReads holds the two
# spellings of the domain to each other, so it cannot drift from the page that
# records the count.
#
# ONE NUMBER, TWO READINGS HERE AND THE THIRD IN THE ROW. The marker on the
# next line is the ONLY place this paragraph states the measurement, and what
# it states is the POPULATION, which is the band's lower edge.
# internal/manifest's TestTheStatedPopulationIsWhatTheSweepCounts compares that
# marker to the constant under it through the margin: ceiling = marker +
# margin. It does NOT run the sweep, deliberately, because a second doc-numbers
# row made out of a unit test reddens on exactly the trees the self-drive row
# plants a bare number into, which is what took five oracle shards down on run
# 34214582437. The third leg is the doc-numbers ROW itself, which the arbiter
# runs on every run and which refuses a population under the marker or over the
# ceiling. Marker = population follows, with each leg made once. Re-measuring
# is a one-line edit to the marker, and forgetting the marker is red.
# DOC-NUMBER POPULATION MEASURED 2026-09-08 over README.md SECURITY.md docs/*.md: 72
DOC_NUMBER_CEILING=73

# How far UNDER the ceiling the population may sit before the row refuses.
#
# 2026-09-08, D41, and it closes a review row measured on the previous head:
# the ceiling stayed at 66 while the population fell to 64, so TWO bare
# numbers could enter the prose with nothing red. A ceiling above its
# population is not a ceiling, it is an allowance — and the paragraph above
# says in as many words that the slack "is named here so the next bump still
# has to justify itself", which is a rule written beside a number rather than
# an observer of it. The band is the observer. It is the mirror of
# MAX_DECLARED_MARGIN: that one caps how far a population may grow ABOVE its
# floor, this one caps how far it may fall BELOW its ceiling, and both name
# the number to write.
#
# ZERO, and the derivation is the same question MAX_DECLARED_MARGIN answers:
# how many bare-number prose lines does any one oracle scenario add to, or
# remove from, a copy whose doc-numbers row is meant to stay green. MEASURED
# 2026-09-08 over the whole roster: none. The plant the self-drive row appends
# to README.md — "22 of the 102 allowlisted identifiers" — is caught by the
# PATTERN list above it and never reaches the count, so it moves no margin.
#
# BOUND, and it is the same one the ceiling already had: this is a size and no
# membership. Deleting one bare number and adding another is invisible to both
# edges.
#
# 2026-09-08, THE DOCS WORDING ROUND, and this is where the margin stops being
# zero. At zero the band is an equality and every docs change that touches a
# line carrying a digit is red until somebody edits this file, which prices a
# wording pass at a machinery edit and puts the oracle matrix on the push. The
# brief for this round asked for a stated margin instead.
#
# ONE, and the derivation is a measurement over this repository's own history.
# MEASURED 2026-09-08 with scripts/sweep-doc-numbers.sh, replayed over the
# twenty most recent commits that touch README.md, SECURITY.md or docs/: the
# population moved by zero in eighteen of them, by one in 237536d, and by five
# in 0998583, the round that re-derived the CI ceilings and raised this ceiling
# with its lines enumerated. So one bare number is what an ordinary docs change
# adds. The margin buys exactly that one. A change that adds two is red and
# raises the ceiling with its lines named, which is the ratchet the paragraph
# above asks for, and docNumberMarginCap in internal/manifest holds this edge
# from growing.
#
# THE MARGIN IS HEADROOM IN ONE DIRECTION AND THE ROW REFUSES IN BOTH, which
# the paragraph above did not say and which a wording pass pays for. The band
# is [marker, marker + margin]. A docs change that ADDS one bare-number line
# stays green. A docs change that REMOVES one, or that reflows two of them onto
# a single line, falls under the marker and is RED, so a wording pass still
# costs a manifest edit in the falling direction. That is deliberate and it is
# not an oversight: the lower edge is the whole reason this margin exists at
# all, since a ceiling standing above its population IS an allowance, which is
# what 66 against 64 bought on the previous head. Widening the band downward by
# the margin would hand that allowance back, doubled. What the falling
# direction costs is bounded and named: one line to the marker and one to the
# ceiling, printed by scripts/sweep-doc-numbers.sh's own diagnosis as the pair
# internal/manifest accepts. MEASURED 2026-09-08 in this round: deleting one
# bare-number line from docs/design.md takes the population to 71 and the row
# red, and the pair the diagnosis then prints, marker 71 with the ceiling at
# 72, leaves the row green and internal/manifest green.
DOC_NUMBER_MARGIN=1

# RE-MEASURED 2026-09-06 at M7c, this box, this tree, ORACLE_JOBS=4, over the
# 77 scenarios MANIFEST_SCENARIOS declared then: 623s, from the verify-oracle
# row's own figure on a PASS. D36 (2026-09-06) added a 78th,
# oracle-account-not-last-line, which sleeps the floor plus one like the rest
# of the fabricating-stub family, so the true figure is now higher again and
# 623 is further under it. It is NOT raised, for the reason the paragraph
# below already gives: this is a low-water mark, understating it is the safe
# direction, and raising it feeds back into every sleeping stub. The population moved by two and the netns row
# every full-scope scenario runs moved 53s -> 78s, which is where the rest of
# the increase over the 440s above comes from.
#
# THE FEEDBACK IS STATED RATHER THAN HIDDEN, because this number pays for
# itself: raising it raises ORACLE_MIN_SECONDS from 22s to 31s, and the fifteen
# scenarios that reach the floor through fabricating_stub each sleep the floor
# plus one, so the NEXT measurement of this same tree is about 34s higher
# again (135s of sleep over four jobs). It is a low-water mark and understating
# it is the safe direction, so it is not chased upward within a round.
ORACLE_MEASURED_SECONDS=623
ORACLE_MIN_PERCENT=5
ORACLE_MIN_SECONDS=$((ORACLE_MEASURED_SECONDS * ORACLE_MIN_PERCENT / 100))

# The SHARD floor, which is a DIFFERENT measurement of a different shape and
# not a share of the one above. Added 2026-09-08 round 2, because a share of
# the one above could not fire: 31s scaled to a shard of eight is 3s, against
# shards that measured 169s to 661s, and a fabricated `SHARD ELAPSED: 3` was
# accepted by the aggregation. MEASURED by review at 0998583.
#
# The figures, run 34204814646, ten shards of eight on GitHub-hosted
# ubuntu-24.04: shard elapsed 169s to 661s, which is 21s to 83s per scenario. A
# factor of four across shards of the same size on the same image, because the
# cost is the scenario's and not the shard's.
#
# THE RULE: a quarter of the FASTEST per-scenario cost measured on the image
# the shards run on. A quarter, because four is the spread the same image
# already produces between its own shards — a floor under the whole observed
# spread cannot fire on an honest shard unless hosted becomes four times faster
# than its fastest measurement, and it refuses an account that did no work.
#
# IT IS STILL A FLOOR AND STILL NOT PROOF OF WORK. A stub that sleeps its
# share passes it, exactly as the roster floor's own paragraph says. What it
# closes is the cheap edit — an account written by hand, a shard whose job died
# after writing its file — not a deliberate forgery. Driven by scenario
# lane-aggregate-instant-shard, which is the other half of the finding: nothing
# drove this arm at all.
ORACLE_SHARD_MEASURED_SECONDS_PER_SCENARIO=21
ORACLE_SHARD_MIN_PERCENT=25
ORACLE_SHARD_MIN_SECONDS_PER_SCENARIO=$((ORACLE_SHARD_MEASURED_SECONDS_PER_SCENARIO * ORACLE_SHARD_MIN_PERCENT / 100))

# The oracle's scenarios. The oracle no longer holds this list; it cross-checks
# its sc_* functions against this file, and verify.sh requires the oracle's
# output to account for every name here BY NAME.
MANIFEST_SCENARIOS=(
	control
	verdict-on-abort
	verdict-without-gomod
	roster-gate-deleted
	roster-gate-added
	t1-violation
	t2-violation
	gofmt-violation
	vet-violation
	race-detector
	test-cache
	ceiling-fires
	ceiling-control
	ceiling-band
	gate-panic
	gate-refuses
	self-drive-blinded
	self-drive-reddens-everything
	scenario-death-is-reported
	doc-number-reintroduced
	doc-sweep-deleted
	unlinted-script
	unlinted-shebang-script
	oracle-is-invoked
	hang-bounded
	bounds-ordering
	suite-timeout-detached
	stale-citation
	citation-trailing
	citation-underscore
	citation-whitewash
	citation-vacuous
	citation-url
	citation-after-url
	invoked-by-relative-path
	suite-args-detached
	suite-tests-disabled
	suite-one-package-disabled
	suite-domain-unmeasured-module
	suite-domain-unmeasured-walk
	suite-files-disabled-partial
	suite-roster-unmeasured
	record-refuses-uncounted-pass
	record-refuses-zero-count
	row-deleted
	row-added
	oracle-stub-total
	oracle-stub-partial
	citation-embedded-identifier
	citation-word-start
	go-domain-empty
	manifest-missing
	manifest-row-removed
	manifest-count-lies
	manifest-scenario-removed
	self-check-guard-deleted
	min-declared-tests-floor
	oracle-names-fabricated
	oracle-too-fast
	scenario-body-emptied
	observation-recorder-stubbed
	min-declared-tests-margin
	silent-scenario-named
	oracle-skip-on-unchanged-arbiter
	oracle-skip-refused-when-scripts-change
	oracle-skip-needs-a-real-pass
	oracle-account-not-last-line
	contract-check-deleted
	netns-row-empty-domain
	netns-row-control
	netns-row-partition-broken
	readme-usage-drifts-in-the-readme
	readme-usage-drifts-in-the-example
	oracle-scope-fabricated
	self-check-skip-arm-deleted
	suite-partition-skip-inert
	scenario-rc-follows-the-verdict
	v6-fixture-mode-drift
	v6-ra-absent
	lane-scripts-are-in-the-oracles-domain
	lane-verdict-foreign-hash
	lane-verdict-roster-shrunk
	lane-verdict-two-verdicts
	lane-aggregate-short-count
	lane-aggregate-instant-shard
)
MANIFEST_SCENARIOS_N=85

# The scenarios that run the subject at the LIGHT scope: --inner --light, which
# is every row except the unit suite and the netns row (MANIFEST_SCOPED_OUT_ROWS).
#
# DECISION 2026-09-05 (machinery batch, item 2). The oracle ran a 56s unit
# suite inside every one of sixty-three copies of this tree in order to watch
# the lint row go red. The rule for membership, and it is a rule rather than
# a list somebody curated:
#
#   a scenario is light when its contract names a row that is not in
#   MANIFEST_SCOPED_OUT_ROWS, AND its plant is a shell, document or manifest
#   defect rather than Go source, AND its BODY reads no scoped-out row.
#
# The second clause is why the t1/t2/gofmt/vet/race scenarios are not here
# (they edit Go). The control is not here either: a control that does not run
# everything controls nothing.
#
# THE THIRD CLAUSE WAS LEARNED, MEASURED 2026-09-05: seven scenarios that plant
# a comment or a constant read the unit-suite row as their own NEGATIVE CONTROL
# — "this run failed for a reason this scenario does not name" — and a light
# run makes that row ABSENT, so all seven failed at once on the first full run
# after the split. A contract names one row; a body may read several, and the
# rule has to cover what the body reads. It is no longer curated by hand: the
# oracle REFUSES, before it runs anything, a light scenario whose function body
# names a row in MANIFEST_SCOPED_OUT_ROWS, so the list cannot drift back into
# this state without the refusal saying which scenario and which row.
#
# The scope is applied by the oracle's dispatcher from THIS list and recorded
# by the run helpers as scope:light or scope:full; verify.sh compares what each
# scenario reported against what this list declares. A body that scopes itself
# is a breach there — and, before that, a scenario that scopes away the row it
# exists to drive reads that row ABSENT and fails its own contract.
MANIFEST_LIGHT_SCENARIOS=(
	verdict-on-abort
	verdict-without-gomod
	roster-gate-deleted
	roster-gate-added
	gate-panic
	gate-refuses
	self-drive-blinded
	self-drive-reddens-everything
	doc-number-reintroduced
	doc-sweep-deleted
	unlinted-script
	unlinted-shebang-script
	oracle-is-invoked
	citation-url
	citation-after-url
	invoked-by-relative-path
	suite-args-detached
	record-refuses-uncounted-pass
	record-refuses-zero-count
	row-deleted
	row-added
	oracle-stub-total
	oracle-stub-partial
	citation-embedded-identifier
	citation-word-start
	manifest-missing
	manifest-count-lies
	self-check-guard-deleted
	oracle-names-fabricated
	oracle-too-fast
	scenario-body-emptied
	observation-recorder-stubbed
	silent-scenario-named
	oracle-skip-on-unchanged-arbiter
	oracle-skip-refused-when-scripts-change
	oracle-skip-needs-a-real-pass
	oracle-account-not-last-line
	contract-check-deleted
	readme-usage-drifts-in-the-readme
	readme-usage-drifts-in-the-example
	oracle-scope-fabricated
	self-check-skip-arm-deleted
)
MANIFEST_LIGHT_SCENARIOS_N=42

# What each scenario must OBSERVE. One entry per scenario, same order.
#
# ROUND 11, and it is the round's whole answer. MEASURED 2026-08-30 by review:
# four scenario BODIES were emptied with their NAMES kept, record()'s guard was
# made inert, self_check() was gutted to report PASS unconditionally, and one
# comment was left in place because the row-coverage check grepped the oracle's
# own source for it. `VERDICT: PASS (12 steps)` with a live defect in the tree,
# twice, with every operand in this file satisfied IN FULL.
#
# The diagnosis is one line: A NAME IS NOT A BEHAVIOUR. Everything above
# answers "is it there"; nothing answered "does it do anything".
#
# Format:  name|rc-class|observation-token|diagnosis
#   rc-class    zero     the subject must have exited 0 in this scenario
#               nonzero  the subject must have exited non-zero
#               static   the scenario runs the subject not at all (see below)
#   token       <row>:<PASS|FAIL|ABSENT> — a row the scenario must have READ,
#               in that state, in the subject's verdict table.
#   diagnosis   a substring of the NOTE the arbiter wrote beside that row,
#               squashed to letters, spaces and # (see `squash` in the
#               oracle). "no row" for a static contract, which reads none.
#
# ROUND 13, B15. The token names the row that must go red; the diagnosis names
# WHY it went red, and the arbiter — not the scenario — writes it. That is the
# whole of the round: a contract that pins the outcome and not the cause is
# satisfied by a scenario reddening the right row for the wrong reason, which
# is how four bodies were substituted in round 12 and still passed.
#
# The tokens come from the helpers — `row`, `run_verify`, `run_verify_outer` —
# which are the only ways to run the subject or read its table, so a body
# cannot opt out of being observed. verify.sh compares what the oracle reports
# against what is written here; the check lives in neither the scenario nor the
# oracle.
#
# The consequence is the point: with the contract checked outside the body, a
# body's `note` calls stop being the assertion. Emptying a body no longer
# deletes the assertion, it deletes the OBSERVATION, and no observation is a
# failure.
#
# BOUNDS, stated because a completeness claim here would be this project's
# fifth in five rounds:
#   - The contract pins the outcome AND the diagnosis, but the diagnosis is a
#     SUBSTRING of the arbiter's note. Two plants the arbiter describes with
#     the same words are still indistinguishable here — how narrow that is
#     depends on how specific the arbiter's notes are, which is why round 13
#     rewrote the generic ones (`exit $rc` alone, the roster mismatch) rather
#     than tightening the contract around them.
#   - A driver rewritten to FABRICATE these strings defeats it. To do that it
#     must read this table, i.e. reproduce the expectation it is faking. That
#     is the terminus, and it is a person reading a diff.
#   - `static` is an escape hatch, and its membership is ENUMERATED below in
#     MANIFEST_STATIC_CONTRACTS rather than described here, because an
#     uncapped exemption is how a class spreads and a described one drifts.
#     This paragraph used to read "capped at ONE, its one member
#     ceiling-band" while the Go pin said 2 and the table held two: it was
#     wrong from the moment the second member landed, and nothing could see
#     it, because it was prose. The list below is checked for set equality
#     against the contracts, so adding a static contract without declaring it
#     now fails the suite instead of falsifying a sentence.
MANIFEST_SCENARIO_CONTRACTS=(
	"control|zero|verify-oracle:ABSENT|row absent"
	"verdict-on-abort|nonzero|gate-roster:ABSENT|row absent"
	"verdict-without-gomod|nonzero|gate-roster:FAIL|go list could not enumerate the gates"
	"roster-gate-deleted|nonzero|gate-roster:FAIL|MISSING from the tree"
	"roster-gate-added|nonzero|gate-roster:FAIL|UNDECLARED in the manifest"
	"t1-violation|nonzero|t1:FAIL|VIOLATION"
	"t2-violation|nonzero|t2:FAIL|VIOLATION"
	"gofmt-violation|nonzero|gofmt:FAIL|unformatted proto ugly go"
	"vet-violation|nonzero|vet:FAIL|unreachable code"
	"race-detector|nonzero|unit-suite:FAIL|WARNING DATA RACE"
	"test-cache|nonzero|unit-suite:FAIL|go test reported a cached result"
	"ceiling-fires|nonzero|unit-suite:FAIL|passed but took"
	"ceiling-control|zero|unit-suite:PASS|started here and none of the"
	# The one token that spans TWO observations. ceiling-band emits
	# ceiling-seconds: and netns-ceiling-seconds:, run_one sorts them, and
	# they sort adjacent — so pinning them as one comma-joined token pins
	# both numbers with the single token a contract is allowed. Raising
	# EITHER ceiling in verify.sh without editing this line reddens the
	# verify-oracle row.
	"ceiling-band|static|ceiling-seconds:84,netns-ceiling-seconds:170|no row"
	"gate-panic|nonzero|t2:FAIL|with no REFUSED line the gate crashed"
	"gate-refuses|nonzero|t1:FAIL|REFUSED the gate could not measure its domain"
	"self-drive-blinded|nonzero|self-drive:FAIL|gofmt PASS planted did not redden"
	"self-drive-reddens-everything|nonzero|self-drive:FAIL|build FAIL unplanted went red"
	"scenario-death-is-reported|static|scenario-death:died before reporting and not a subject failure|no row"
	"doc-number-reintroduced|nonzero|doc-numbers:FAIL|Delete the number and name the instrument"
	"doc-sweep-deleted|nonzero|doc-numbers:FAIL|is missing or not executable"
	"unlinted-script|nonzero|shellcheck:FAIL|scripts extra sh"
	"unlinted-shebang-script|nonzero|shellcheck:FAIL|scripts preflight"
	"oracle-is-invoked|nonzero|verify-oracle:FAIL|oracle stub was invoked"
	"hang-bounded|nonzero|unit-suite:FAIL|test timed out"
	"bounds-ordering|nonzero|bounds:FAIL|does not exceed the"
	"suite-timeout-detached|nonzero|bounds:FAIL|the suite flags do not carry timeout"
	"stale-citation|nonzero|citations:FAIL|TestThisCitationWasNeverWritten"
	"citation-trailing|nonzero|citations:FAIL|TestTrailingCitationNeverWritten"
	"citation-underscore|nonzero|citations:FAIL|BenchmarkNeverWrittenEither"
	"citation-whitewash|nonzero|citations:FAIL|TestWhitewashedByAStringLiteral"
	"citation-vacuous|nonzero|citations:FAIL|a scan that finds no domain is not a passing scan"
	"citation-url|zero|citations:PASS|cited token s all declared among"
	"citation-after-url|nonzero|citations:FAIL|TestRevCPhantomAfterAURL"
	"invoked-by-relative-path|zero|bounds:PASS|each invocation expands its own flag array"
	"suite-args-detached|nonzero|bounds:FAIL|suite invocation s expanding SUITE ARGS expected exactly"
	"suite-tests-disabled|nonzero|unit-suite:FAIL|reported no ok package line"
	"suite-one-package-disabled|nonzero|unit-suite:FAIL|hold a test go file and ran no test"
	"suite-domain-unmeasured-module|nonzero|unit-suite:FAIL|its domain is UNMEASURED module ##"
	"suite-domain-unmeasured-walk|nonzero|unit-suite:FAIL|its domain is UNMEASURED module github"
	"suite-files-disabled-partial|nonzero|unit-suite:FAIL|declared but never run"
	"suite-roster-unmeasured|nonzero|unit-suite:FAIL|the declared test roster is UNMEASURED"
	"record-refuses-uncounted-pass|nonzero|gofmt:FAIL|no numeric domain size"
	"record-refuses-zero-count|nonzero|gofmt:FAIL|examined # items an empty domain"
	"row-deleted|nonzero|vet:ABSENT|row absent"
	"row-added|nonzero|undeclared-row:PASS|invented"
	"oracle-stub-total|nonzero|verify-oracle:FAIL|printed no ORACLE PASS"
	"oracle-stub-partial|nonzero|verify-oracle:FAIL|verify manifest sh declares"
	"citation-embedded-identifier|zero|citations:PASS|cited token s all declared among"
	"citation-word-start|nonzero|citations:FAIL|TestRevCWordStartNeverWritten"
	"go-domain-empty|nonzero|build:FAIL|an empty domain is not a passing domain"
	"manifest-missing|nonzero|citations:ABSENT|row absent"
	"manifest-row-removed|nonzero|unit-suite:FAIL|TestManifestRowsAreTheRowsPinnedHere"
	"manifest-count-lies|nonzero|citations:ABSENT|row absent"
	"manifest-scenario-removed|nonzero|unit-suite:FAIL|TestManifestFloorsAreNotBelowTheirPins"
	"self-check-guard-deleted|nonzero|self-check:FAIL|record is not enforcing its contract"
	"min-declared-tests-floor|nonzero|unit-suite:FAIL|below the floor of"
	"oracle-names-fabricated|nonzero|verify-oracle:FAIL|reported no passing result for scenario"
	"oracle-too-fast|nonzero|verify-oracle:FAIL|floor in verify manifest sh it reported the right account without doing the work"
	"scenario-body-emptied|nonzero|verify-oracle:FAIL|record refuses uncounted pass wants nonzero"
	"observation-recorder-stubbed|nonzero|verify-oracle:FAIL|control wants zero verify oracle ABSENT"
	"min-declared-tests-margin|nonzero|unit-suite:FAIL|tests were ADDED"
	"silent-scenario-named|nonzero|verify-oracle:FAIL|Silent control"
	"oracle-skip-on-unchanged-arbiter|zero|verify-oracle:SKIPPED|which already produced ORACLE PASS"
	"oracle-skip-refused-when-scripts-change|zero|verify-oracle:PASS|oracle ran after scripts changed"
	"oracle-skip-needs-a-real-pass|nonzero|verify-oracle:FAIL|its answer is not the account of a run"
	"oracle-account-not-last-line|zero|verify-oracle:PASS|the account is not the last line this oracle printed"
	"contract-check-deleted|nonzero|verify-oracle:FAIL|oracle contracts sh is missing or not executable"
	"netns-row-empty-domain|nonzero|netns-suite:FAIL|the netns population is UNMEASURED"
	"netns-row-control|zero|netns-suite:PASS|namespaced test s each reported its own verdict"
	"netns-row-partition-broken|nonzero|netns-suite:FAIL|reported no verdict for"
	"readme-usage-drifts-in-the-readme|nonzero|readme-usage:FAIL|has no fenced go block under Usage"
	"readme-usage-drifts-in-the-example|nonzero|readme-usage:FAIL|the README says byte for byte and they are not"
	"oracle-scope-fabricated|nonzero|verify-oracle:FAIL|ABSENT scope full"
	"self-check-skip-arm-deleted|nonzero|self-check:FAIL|a probe that dies with the arm it drives leaves the arm undriven"
	"suite-partition-skip-inert|nonzero|unit-suite:FAIL|the skip filter did not hold them back"
	"v6-fixture-mode-drift|nonzero|netns-suite:FAIL|TestASLAACOnlyLinkSaysThereIsNoDHCPv"
	"v6-ra-absent|nonzero|netns-suite:FAIL|TestAManagedLinkWhoseServerIsSilentIsNotALinkWithoutOne"
	"scenario-rc-follows-the-verdict|static|scenario-rc-fail:1|no row"
	# The lane's own decisions, round 2 of the hosted lane. Each pins the
	# refusal's DIAGNOSIS beside its control, as one comma-joined token: the
	# observations sort adjacent and the scenario emits no others between them,
	# so half a pin cannot be dropped quietly.
	"lane-scripts-are-in-the-oracles-domain|static|lane-domain:covers-the-lane,lane-domain:hash-moves-with-the-lane|no row"
	"lane-verdict-foreign-hash|static|lane-refusal:foreign-hash,lane-refusal:foreign-hash-control|no row"
	"lane-verdict-roster-shrunk|static|lane-refusal:roster-shrunk,lane-refusal:roster-shrunk-control|no row"
	"lane-verdict-two-verdicts|static|lane-refusal:two-verdicts,lane-refusal:two-verdicts-control|no row"
	"lane-aggregate-short-count|static|lane-refusal:short-count,lane-refusal:short-count-control|no row"
	"lane-aggregate-instant-shard|static|lane-refusal:instant-shard,lane-refusal:instant-shard-edges|no row"
)
MANIFEST_SCENARIO_CONTRACTS_N=85

# The `static` exemption, enumerated. A scenario is static when it does not run
# verify.sh at all, so it can read no row of the subject's table; both members
# still have to observe something derived from what they DID run.
#
#   ceiling-band                reads SUITE_CEILING_SECONDS and
#                               NETNS_CEILING_SECONDS out of verify.sh and
#                               observes both values.
#   scenario-death-is-reported  runs the ORACLE in a copy, not verify.sh, and
#                               observes the child's own death line.
#   scenario-rc-follows-the-verdict
#                               runs ONE scenario in a copy, twice, and
#                               observes the exit status it answered with.
#
# The third member arrived in round 2 and the cap moved with it, which is the
# pattern this file says to watch. What makes it the sanctioned case rather
# than the routine one: both of the new-ish members are about the ORACLE'S OWN
# PROTOCOL — how a scenario reports and what its exit status means — and a
# scenario about the oracle's protocol has no row of the subject's table to
# read, by construction rather than by convenience. A fourth member that is
# not of that kind is the one to refuse.
#
# Set equality against the contract table is pinned from Go, so this list
# cannot describe a membership the table does not have.
MANIFEST_STATIC_CONTRACTS=(
	ceiling-band
	scenario-death-is-reported
	scenario-rc-follows-the-verdict
	lane-scripts-are-in-the-oracles-domain
	lane-verdict-foreign-hash
	lane-verdict-roster-shrunk
	lane-verdict-two-verdicts
	lane-aggregate-short-count
	lane-aggregate-instant-shard
)
MANIFEST_STATIC_CONTRACTS_N=9


# manifest_check — layer 2, run by every reader of this file BEFORE it is
# trusted. A list that has been shortened without its count being edited, or a
# list that has been emptied, is a refusal rather than a smaller domain.
#
# It prints one line and returns non-zero on failure; it does not exit, because
# its two callers report a refusal in two different formats.
manifest_check() {
	local bad=""
	[ "${#MANIFEST_ROWS[@]}" -eq "$MANIFEST_ROWS_N" ] ||
		bad="$bad MANIFEST_ROWS has ${#MANIFEST_ROWS[@]} name(s), MANIFEST_ROWS_N says $MANIFEST_ROWS_N;"
	[ "${#MANIFEST_GATES[@]}" -eq "$MANIFEST_GATES_N" ] ||
		bad="$bad MANIFEST_GATES has ${#MANIFEST_GATES[@]} name(s), MANIFEST_GATES_N says $MANIFEST_GATES_N;"
	[ "${#MANIFEST_SHELL_SCRIPTS[@]}" -eq "$MANIFEST_SHELL_SCRIPTS_N" ] ||
		bad="$bad MANIFEST_SHELL_SCRIPTS has ${#MANIFEST_SHELL_SCRIPTS[@]} name(s), MANIFEST_SHELL_SCRIPTS_N says $MANIFEST_SHELL_SCRIPTS_N;"
	[ "${#MANIFEST_SCENARIOS[@]}" -eq "$MANIFEST_SCENARIOS_N" ] ||
		bad="$bad MANIFEST_SCENARIOS has ${#MANIFEST_SCENARIOS[@]} name(s), MANIFEST_SCENARIOS_N says $MANIFEST_SCENARIOS_N;"
	[ "${#MANIFEST_SCENARIO_CONTRACTS[@]}" -eq "$MANIFEST_SCENARIO_CONTRACTS_N" ] ||
		bad="$bad MANIFEST_SCENARIO_CONTRACTS has ${#MANIFEST_SCENARIO_CONTRACTS[@]} entr(ies), MANIFEST_SCENARIO_CONTRACTS_N says $MANIFEST_SCENARIO_CONTRACTS_N;"
	[ "${#MANIFEST_STATIC_CONTRACTS[@]}" -eq "$MANIFEST_STATIC_CONTRACTS_N" ] ||
		bad="$bad MANIFEST_STATIC_CONTRACTS has ${#MANIFEST_STATIC_CONTRACTS[@]} name(s), MANIFEST_STATIC_CONTRACTS_N says $MANIFEST_STATIC_CONTRACTS_N;"
	[ "${#MANIFEST_SCENARIO_CONTRACTS[@]}" -eq "${#MANIFEST_SCENARIOS[@]}" ] ||
		bad="$bad ${#MANIFEST_SCENARIOS[@]} scenario(s) but ${#MANIFEST_SCENARIO_CONTRACTS[@]} contract(s); a scenario with no contract is a name with no behaviour, which is exactly what round 11 closed;"
	# An empty list is the shape every one of the four rounds above ended in.
	[ "$MANIFEST_ROWS_N" -ge 1 ] || bad="$bad MANIFEST_ROWS_N is not positive;"
	[ "$MANIFEST_GATES_N" -ge 1 ] || bad="$bad MANIFEST_GATES_N is not positive;"
	[ "$MANIFEST_SHELL_SCRIPTS_N" -ge 1 ] || bad="$bad MANIFEST_SHELL_SCRIPTS_N is not positive;"
	[ "$MANIFEST_SCENARIOS_N" -ge 1 ] || bad="$bad MANIFEST_SCENARIOS_N is not positive;"
	[ "$MIN_DECLARED_TESTS" -ge 1 ] || bad="$bad MIN_DECLARED_TESTS is not positive;"
	# The floor and the measurement it comes from, held together. A literal
	# reinstated here in place of the derivation fails as soon as it drifts.
	[ "$ORACLE_MIN_SECONDS" -eq "$((ORACLE_MEASURED_SECONDS * ORACLE_MIN_PERCENT / 100))" ] ||
		bad="$bad ORACLE_MIN_SECONDS is $ORACLE_MIN_SECONDS but ORACLE_MEASURED_SECONDS=$ORACLE_MEASURED_SECONDS at $ORACLE_MIN_PERCENT percent is $((ORACLE_MEASURED_SECONDS * ORACLE_MIN_PERCENT / 100)); the floor no longer derives from the measurement printed beside it;"
	# A margin the tree can widen at will is a floor with no upper edge, which
	# is the state round 11 was sent to fix.
	[ "${#SELF_DRIVE_REDDENS[@]}" -eq "$SELF_DRIVE_REDDENS_N" ] ||
		bad="$bad SELF_DRIVE_REDDENS has ${#SELF_DRIVE_REDDENS[@]} name(s), SELF_DRIVE_REDDENS_N says $SELF_DRIVE_REDDENS_N;"
	[ "${#SELF_DRIVE_SURVIVES[@]}" -eq "$SELF_DRIVE_SURVIVES_N" ] ||
		bad="$bad SELF_DRIVE_SURVIVES has ${#SELF_DRIVE_SURVIVES[@]} name(s), SELF_DRIVE_SURVIVES_N says $SELF_DRIVE_SURVIVES_N;"
	[ "$SELF_DRIVE_REDDENS_N" -ge 1 ] && [ "$SELF_DRIVE_SURVIVES_N" -ge 1 ] ||
		bad="$bad a self-drive with an empty half is a check with one possible verdict;"
	[ "$MAX_DECLARED_MARGIN" -ge 0 ] && [ "$MAX_DECLARED_MARGIN" -le 4 ] ||
		bad="$bad MAX_DECLARED_MARGIN is $MAX_DECLARED_MARGIN, outside 0..4; a wide band is a floor that has stopped saying anything;"
	[ "$ORACLE_MIN_SECONDS" -ge 1 ] || bad="$bad ORACLE_MIN_SECONDS is not positive;"
	[ "$ORACLE_SHARD_MIN_SECONDS_PER_SCENARIO" -eq "$((ORACLE_SHARD_MEASURED_SECONDS_PER_SCENARIO * ORACLE_SHARD_MIN_PERCENT / 100))" ] ||
		bad="$bad ORACLE_SHARD_MIN_SECONDS_PER_SCENARIO is $ORACLE_SHARD_MIN_SECONDS_PER_SCENARIO but $ORACLE_SHARD_MEASURED_SECONDS_PER_SCENARIO at $ORACLE_SHARD_MIN_PERCENT percent is $((ORACLE_SHARD_MEASURED_SECONDS_PER_SCENARIO * ORACLE_SHARD_MIN_PERCENT / 100)); the shard floor no longer derives from the measurement printed beside it;"
	[ "$ORACLE_SHARD_MIN_SECONDS_PER_SCENARIO" -ge 1 ] || bad="$bad ORACLE_SHARD_MIN_SECONDS_PER_SCENARIO is not positive;"
	[ "$DOC_NUMBER_CEILING" -ge 1 ] || bad="$bad DOC_NUMBER_CEILING is not positive;"
	[ "$DOC_NUMBER_MARGIN" -ge 0 ] || bad="$bad DOC_NUMBER_MARGIN is negative; a band cannot open downward;"
	[ "$DOC_NUMBER_MARGIN" -lt "$DOC_NUMBER_CEILING" ] ||
		bad="$bad DOC_NUMBER_MARGIN is $DOC_NUMBER_MARGIN against a ceiling of $DOC_NUMBER_CEILING; a margin as wide as the ceiling is a row with one possible verdict;"
	# The oracle's verdict token, held to what its three consumers need of it.
	# Empty, and every anchored grep for it matches every line, which turns the
	# CI job's oracle check and this arbiter's own parse into checks with one
	# verdict. A slash, and verify.sh's `sed -n "s/^$prefix ...
	# /\1/p"` stops being the expression it reads as.
	case "$MANIFEST_ORACLE_PASS_PREFIX" in
	"") bad="$bad MANIFEST_ORACLE_PASS_PREFIX is empty; an empty token makes every grep for it match everything;" ;;
	*/*) bad="$bad MANIFEST_ORACLE_PASS_PREFIX contains a slash, which verify.sh's sed uses as its delimiter;" ;;
	esac
	# Both halves non-empty and the refusals a PROPER subset of the probes: a
	# self-check that refuses every probe it runs has no preservation control,
	# and one that refuses none of them is not a guard.
	[ "$SELF_CHECK_REFUSALS_N" -ge 1 ] && [ "$SELF_CHECK_REFUSALS_N" -lt "$SELF_CHECK_PROBES_N" ] ||
		bad="$bad SELF_CHECK_REFUSALS_N is $SELF_CHECK_REFUSALS_N against $SELF_CHECK_PROBES_N probe(s); a self-check with no refusals is not a guard and one with no survivors is a check with one possible verdict;"
	[ "$MANIFEST_SCENARIO_CONTRACTS_N" -ge 1 ] || bad="$bad MANIFEST_SCENARIO_CONTRACTS_N is not positive;"
	[ "${#MANIFEST_OUTER_ROWS[@]}" -eq "$MANIFEST_OUTER_ROWS_N" ] ||
		bad="$bad MANIFEST_OUTER_ROWS has ${#MANIFEST_OUTER_ROWS[@]} name(s), MANIFEST_OUTER_ROWS_N says $MANIFEST_OUTER_ROWS_N;"
	[ "${#MANIFEST_SCOPED_OUT_ROWS[@]}" -eq "$MANIFEST_SCOPED_OUT_ROWS_N" ] ||
		bad="$bad MANIFEST_SCOPED_OUT_ROWS has ${#MANIFEST_SCOPED_OUT_ROWS[@]} name(s), MANIFEST_SCOPED_OUT_ROWS_N says $MANIFEST_SCOPED_OUT_ROWS_N;"
	[ "${#MANIFEST_SKIPPABLE_ROWS[@]}" -eq "$MANIFEST_SKIPPABLE_ROWS_N" ] ||
		bad="$bad MANIFEST_SKIPPABLE_ROWS has ${#MANIFEST_SKIPPABLE_ROWS[@]} name(s), MANIFEST_SKIPPABLE_ROWS_N says $MANIFEST_SKIPPABLE_ROWS_N;"
	[ "${#MANIFEST_LIGHT_SCENARIOS[@]}" -eq "$MANIFEST_LIGHT_SCENARIOS_N" ] ||
		bad="$bad MANIFEST_LIGHT_SCENARIOS has ${#MANIFEST_LIGHT_SCENARIOS[@]} name(s), MANIFEST_LIGHT_SCENARIOS_N says $MANIFEST_LIGHT_SCENARIOS_N;"
	# Each of the three row lists is a NON-EMPTY PROPER subset of the rows.
	# Empty, and the flag it describes means nothing; equal to the whole, and
	# --light is a run of nothing and --inner has no rows at all.
	local r c sc_name sc_row rest
	for r in "${MANIFEST_OUTER_ROWS[@]}" "${MANIFEST_SCOPED_OUT_ROWS[@]}" "${MANIFEST_SKIPPABLE_ROWS[@]}"; do
		case " ${MANIFEST_ROWS[*]} " in
		*" $r "*) ;;
		*) bad="$bad row list names '$r', which is not a row in MANIFEST_ROWS;" ;;
		esac
	done
	[ "$MANIFEST_OUTER_ROWS_N" -ge 1 ] && [ "$MANIFEST_OUTER_ROWS_N" -lt "$MANIFEST_ROWS_N" ] ||
		bad="$bad MANIFEST_OUTER_ROWS_N is $MANIFEST_OUTER_ROWS_N against $MANIFEST_ROWS_N row(s); an inner run with no rows measures nothing;"
	[ "$MANIFEST_SCOPED_OUT_ROWS_N" -ge 1 ] && [ "$MANIFEST_SCOPED_OUT_ROWS_N" -lt "$MANIFEST_ROWS_N" ] ||
		bad="$bad MANIFEST_SCOPED_OUT_ROWS_N is $MANIFEST_SCOPED_OUT_ROWS_N against $MANIFEST_ROWS_N row(s); a scope that omits every row is a run of nothing;"
	[ "$MANIFEST_SKIPPABLE_ROWS_N" -ge 1 ] && [ "$MANIFEST_SKIPPABLE_ROWS_N" -lt "$MANIFEST_ROWS_N" ] ||
		bad="$bad MANIFEST_SKIPPABLE_ROWS_N is $MANIFEST_SKIPPABLE_ROWS_N against $MANIFEST_ROWS_N row(s); a verdict every row may give is not an exception;"
	# THE refusal item 2 turns on: a light scenario whose contract names a row
	# that a light run does not produce has scoped away the row it exists to
	# drive. It would read ABSENT and fail anyway; refusing it here means it
	# cannot be written down.
	for sc_name in "${MANIFEST_LIGHT_SCENARIOS[@]}"; do
		case " ${MANIFEST_SCENARIOS[*]} " in
		*" $sc_name "*) ;;
		*) bad="$bad MANIFEST_LIGHT_SCENARIOS names '$sc_name', which is not a scenario;" ;;
		esac
		for c in "${MANIFEST_SCENARIO_CONTRACTS[@]}"; do
			case "$c" in
			"$sc_name|"*) ;;
			*) continue ;;
			esac
			rest="${c#*|}"
			rest="${rest#*|}"
			sc_row="${rest%%:*}"
			case " ${MANIFEST_SCOPED_OUT_ROWS[*]} " in
			*" $sc_row "*)
				bad="$bad scenario '$sc_name' is declared light and its contract wants row '$sc_row', which a light run does not run;"
				;;
			esac
		done
	done
	if [ -n "$bad" ]; then
		printf 'the manifest does not agree with itself:%s\n' "$bad"
		return 1
	fi
	return 0
}
