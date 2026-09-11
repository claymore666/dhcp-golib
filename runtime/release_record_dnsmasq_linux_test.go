// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

//go:build linux

package runtime

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/claymore666/dhcp-golib/lease"
	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

// The proof standard applied to the one path in this library that has no
// client behind it.
//
// SendRelease gives back a lease whose holder is gone. Nothing answers it,
// nothing retransmits it, and no state comes back — so a release that is
// malformed, addressed wrongly or never sent produces EXACTLY the observable
// behaviour of a correct one, and every assertion this process could make
// about its own datagram is an assertion about its own opinion. dnsmasq
// removing the lease from its own file, and writing DHCPRELEASE into its own
// log, is not.
//
// FOUR OBSERVERS, AND THE LAST THREE ARE WHY THIS IS NOT A TAUTOLOGY.
//
//  1. The lease this test releases is GONE from dnsmasq's lease file.
//  2. dnsmasq's log carries its own DHCPRELEASE line for that address.
//  3. A NEGATIVE CONTROL lease, taken in the same fixture by a second client
//     and never released, is still there at the end. A lease can vanish
//     because its lifetime ran out, because the server was restarted, because
//     the range recycled or because the file was rewritten — RFC 9915 section
//     18.2.7 names the rival cause itself: "each lease assigned to the IA will
//     be reclaimed by the server when the valid lifetime of that lease
//     expires." If the control is gone too, the rig is the cause and this test
//     says so instead of passing.
//  4. A WRONG-IDENTITY release runs FIRST, in the same fixture, against the
//     same lease. It must leave the lease exactly where it is. A rig in which
//     that one also shows GONE is a rig measuring expiry, and a sender that
//     closed a binding it had not identified would be the worse defect.
//
// The lease lifetime the fixture runs with is asserted against the test's own
// wall duration at the end, with a margin, so that observer 3's meaning is
// measured rather than assumed.

// relMargin is how much of the fixture's lease lifetime must be left over when
// the test ends. A lease that expired during the run would make every
// disappearance ambiguous, and a test that merely hoped it would not is the
// natural-fixture failure: the rig selects the passing path.
const relMargin = 30 * time.Second

// relHostAddr4 is the source address the RELEASE is sent from: an address on
// the client end of the link that never held a lease and is outside the
// server's range. It stands for the host's own address on a container's
// parent interface, which is the only address a plugin has left once the
// container's namespace is gone.
const relHostAddr4 = "192.168.99.2"

// relControlMAC is the negative control client's hardware address. Fixed and
// locally administered so that its lease line can be told from the released
// one in the server's own file.
var relControlMAC = net.HardwareAddr{0x02, 0x00, 0x5e, 0x96, 0x20, 0x01}

// relClientID is the option 61 the released lease is acquired WITH.
//
// proto.DefaultParams leaves ClientID empty, so the library's own client
// acquires without one by default — and this test needs the other arm: RFC
// 2131 section 3.1(6) makes replaying the identifier a MUST only "If the
// client used a 'client identifier' when it obtained the lease", and dnsmasq
// then matches the binding on it rather than on chaddr. A release that
// replayed the wrong bytes would be refused, which is observer 4.
var relClientID = []byte{0xff, 0x96, 0x20, 0x01, 0xde, 0xad}

func TestAReleaseBuiltFromARecordReachesRealDnsmasq(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		releaseByRecordAgainstDnsmasq(t)
		return
	}
	reexecInNamespaces(t)
}

func releaseByRecordAgainstDnsmasq(t *testing.T) {
	started := time.Now()

	mustRun(t, "ip", "link", "add", testClientIf, "type", "veth", "peer", "name", testServerIf)
	mustRun(t, "ip", "addr", "add", testServerIP+"/24", "dev", testServerIf)
	mustRun(t, "ip", "link", "set", testServerIf, "up")
	mustRun(t, "ip", "link", "set", testClientIf, "up")
	mustRun(t, "ip", "link", "set", "lo", "up")
	relAcceptLocal(t, testServerIf)
	// The host's own address on the parent. Not the leased one, and never was.
	mustRun(t, "ip", "addr", "add", relHostAddr4+"/24", "dev", testClientIf)

	srv := startDnsmasq(t)

	iface, err := net.InterfaceByName(testClientIf)
	if err != nil {
		t.Fatalf("InterfaceByName(%s): %v", testClientIf, err)
	}

	// ---------------------------------------------- the lease to be released --
	released, releasedMAC := relAcquire(t, iface.HardwareAddr, relClientID)

	// OBSERVER 4'S PREMISE, READ FROM THE SERVER RATHER THAN ASSUMED. dnsmasq
	// 2.91's lease_find_by_client tries the client identifier first and then
	// falls back to the hardware address, and the fallback is taken for any
	// stored lease that HAS NO client identifier. The wrong-identity release
	// below carries this client's hardware address, so if dnsmasq had kept
	// this binding without a client identifier the fallback would match it and
	// the release would be acted on for the wrong reason. What dnsmasq wrote
	// in column five is what says it did not.
	stored := relWaitLease(t, srv.leasefile, released.Addr.Addr())
	if want := hexColons(relClientID); stored.clientID != want {
		t.Fatalf("dnsmasq stored %s under client identifier %q, want %q; a release carrying the wrong option 61 would then match this binding on the hardware address and observer 4 would be measuring nothing",
			released.Addr.Addr(), stored.clientID, want)
	}
	t.Logf("the lease to be released: %s, held by dnsmasq under client identifier %s",
		released.Addr.Addr(), stored.clientID)

	// ------------------------------------------------- the negative control --
	control, _ := relAcquire(t, relControlMAC, nil)
	if control.Addr.Addr() == released.Addr.Addr() {
		t.Fatalf("both clients leased %s; the control cannot be told from the subject", control.Addr)
	}
	t.Logf("the negative control lease, never released: %s", control.Addr.Addr())

	rec := lease.Record{
		ID: "rec-released", Scope: "net-a", Family: lease.FamilyV4,
		CHAddr:   append([]byte(nil), releasedMAC...),
		Identity: append([]byte(nil), relClientID...),
		Lease:    released,
	}
	addr := released.Addr.Addr()

	// ------------------------------------------- observer 4, and it runs FIRST --
	// Negative before positive, so that a disappearance seen afterwards cannot
	// be this one's doing.
	wrong := rec
	wrong.Identity = append([]byte(nil), relClientID...)
	wrong.Identity[0] ^= 0xFF
	before := srv.count("DHCPRELEASE(" + testServerIf + ")")
	if err := SendRelease(wrong, ReleaseConfig{
		Interface: testClientIf,
		Source:    netip.MustParseAddr(relHostAddr4),
	}); err != nil {
		t.Fatalf("the wrong-identity release was not sent: %v", err)
	}
	srv.waitCount(t, "DHCPRELEASE("+testServerIf+")", before+1,
		"dnsmasq logs a DHCPRELEASE before it decides whether it knows the binding")

	// DNSMASQ'S OWN VERDICT, AND IT IS WHAT ORDERS THIS OBSERVER. Presence in
	// the lease file cannot say the release was refused: the lease is there
	// from the acquisition until dnsmasq's main loop rewrites the file, so a
	// read taken in that window returns "still there" whether the release was
	// acted on or not. The refusal string is written on the decision itself,
	// so waiting for it fails closed and needs no ordering of its own.
	// MEASURED, dnsmasq 2.91: "DHCPRELEASE(srv0) 192.168.99.146
	// 5e:ab:73:97:bb:a9 unknown lease".
	srv.waitFor(t, "unknown lease")
	if !relLineHas(srv, "DHCPRELEASE("+testServerIf+") "+addr.String(), "unknown lease") {
		t.Fatalf("dnsmasq said \"unknown lease\" about some other datagram, not about %s.\nLog:\n%s",
			addr, strings.Join(srv.lines(), "\n"))
	}
	relWaitHolds(t, srv.leasefile, addr)
	t.Logf("dnsmasq called the wrong-identity release an unknown lease and left %s in place", addr)

	// ----------------------------------------- observers 1 and 2, default port --
	if err := SendRelease(rec, ReleaseConfig{
		Interface: testClientIf,
		Source:    netip.MustParseAddr(relHostAddr4),
	}); err != nil {
		t.Fatalf("SendRelease: %v", err)
	}
	srv.waitFor(t, "DHCPRELEASE("+testServerIf+") "+addr.String())
	relWaitGone(t, srv.leasefile, addr)
	t.Logf("dnsmasq closed %s on a release sourced from %s, which never held it", addr, relHostAddr4)

	// ------------------------------- the same thing from an EPHEMERAL source port --
	// RFC 2131 section 4.1 gives a client port 68, and a host that already runs
	// a DHCP client of its own cannot bind it twice. Whether a server still
	// acts on a release from another port is a claim about the server, so it
	// is MEASURED here rather than assumed. BOUND: measured against this
	// fixture's dnsmasq and nothing else.
	again, _ := relAcquire(t, iface.HardwareAddr, relClientID)
	rec2 := rec
	rec2.Lease = again
	addr2 := again.Addr.Addr()
	if err := SendRelease(rec2, ReleaseConfig{
		Interface:  testClientIf,
		Source:     netip.MustParseAddr(relHostAddr4),
		SourcePort: 34567,
	}); err != nil {
		t.Fatalf("SendRelease from an ephemeral source port: %v", err)
	}
	srv.waitCount(t, "DHCPRELEASE("+testServerIf+") "+addr2.String(), 1,
		"the release sent from an ephemeral source port")
	relWaitGone(t, srv.leasefile, addr2)
	t.Logf("a release from source port 34567 closed %s", addr2)

	// -------------------------------------------------------- observer 3, last --
	relWaitHolds(t, srv.leasefile, control.Addr.Addr())

	// -------------------------------------- ReleaseConfig.Interface is applied --
	// A device name that does not exist must FAIL. It is the only way to tell
	// an option that binds the socket to a link from one that is accepted and
	// ignored, which on a host with two interfaces on the parent's subnet is
	// the difference between the right link and whichever the route table
	// preferred.
	err = SendRelease(rec, ReleaseConfig{
		Interface: "no-such-link0",
		Source:    netip.MustParseAddr(relHostAddr4),
	})
	if err == nil {
		t.Error("a release naming an interface that does not exist was sent anyway")
	} else if !strings.Contains(err.Error(), "no-such-link0") {
		t.Errorf("the refusal does not name the interface: %v", err)
	}

	// ------------------------------------------------- observer 3's own premise --
	relAssertLifetimeMargin(t, started, testLeaseSec)
}

// relAcquire takes one lease with the library's own client and stops the
// client WITHOUT releasing it, which is the state this whole file is about: a
// binding the server still holds and no client is behind.
//
// proto.ConflictOff, and it is the one judgement in this fixture. The subject
// here is a release built from a record, and RFC 5227's probe is not on that
// path at all; two clients on one veth with hand-picked hardware addresses
// would otherwise spend this test inside the probe window, and the M6 record
// notes that a client whose Params.CHAddr is not the link's own address
// declines itself under the async check. conflict_dnsmasq_linux_test.go pays
// for that check with the RFC's own constants and measures it; nothing here
// can reach it.
func relAcquire(t *testing.T, chaddr net.HardwareAddr, clientID []byte) (lease.Lease, net.HardwareAddr) {
	t.Helper()

	params := proto.DefaultParams(chaddr)
	params.DesyncMin, params.DesyncMax = 0, 0
	params.Conflict = proto.ConflictOff
	params.ClientID = append([]byte(nil), clientID...)

	c, err := NewClient(ClientConfig{Interface: testClientIf, Params: params, EventBuffer: 8})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- c.Run(ctx) }()

	ev := awaitAcquired(t, c)

	// Cancelled, never Released: c.Release() would send the very datagram this
	// test exists to build somewhere else.
	cancel()
	if err := <-runErr; err != nil && err != context.Canceled {
		t.Fatalf("Run: %v", err)
	}
	return ev.Lease, chaddr
}

// relHolds reports whether dnsmasq's lease file currently names addr, as one
// read. Every caller that wants "it is still there" goes through relWaitHolds
// instead, and the reason is in that function.
func relHolds(t *testing.T, path string, addr netip.Addr) bool {
	t.Helper()
	got, err := parseDnsmasqLeases(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	for _, l := range got {
		if l.addr == addr {
			return true
		}
	}
	return false
}

// relWaitGone spins until dnsmasq's lease file no longer names addr.
//
// It SPINS rather than sleeping, and it carries no duration of its own, for
// readDnsmasqLeases's reason: dnsmasq logs from its reply path and rewrites
// the lease file from its main loop, so the log line the caller already waited
// for does not order the file write. A sleep would be a guess about that gap.
// The bound is go test's own timeout, which prints the goroutine dump and the
// server's log beside it.
func relWaitGone(t *testing.T, path string, addr netip.Addr) {
	t.Helper()
	for relHolds(t, path, addr) {
		relPoll()
	}
}

// relWaitHolds spins until dnsmasq's lease file names addr.
//
// A SINGLE READ OF THAT FILE CANNOT SAY "still there", and this is the
// measurement: dnsmasq 2.91's lease_update_file rewinds the stream, calls
// ftruncate(fd, 0), writes every lease through buffered stdio and only then
// flushes and fsyncs. Between the truncate and the flush the file on disk is
// empty or holds a prefix of itself, so a reader can find a lease missing that
// nothing touched. MEASURED as two red runs in twelve, both of them here, on
// 2026-09-12.
//
// Waiting for presence is sound where waiting for a value would not be:
// dnsmasq never puts back a binding it has removed, and the client that took
// this lease was stopped before the release under test. So an address seen
// after the rewrite settles was never released, and an address that really was
// released never appears. A release that wrongly closed this lease therefore
// ends in the child's own timeout, with the goroutine dump and the dnsmasq log
// printed beside it, which is the bound relWaitGone carries for the same
// reason.
func relWaitHolds(t *testing.T, path string, addr netip.Addr) {
	t.Helper()
	for !relHolds(t, path, addr) {
		relPoll()
	}
}

// relLineHas reports whether one dnsmasq log line carries all of want. Two
// substrings in two different lines are two events, and this observer is about
// one.
func relLineHas(srv *dnsmasqServer, want ...string) bool {
	for _, line := range srv.lines() {
		all := true
		for _, w := range want {
			if !strings.Contains(line, w) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// relWaitLease spins until dnsmasq's lease file names addr and returns the
// line, for relWaitHolds's reason and one more: it puts the file write in
// front of whatever the caller does next, so a lease that is missing later
// cannot be one that was never written.
func relWaitLease(t *testing.T, path string, addr netip.Addr) dnsmasqLease {
	t.Helper()
	for {
		got, err := parseDnsmasqLeases(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		for _, l := range got {
			if l.addr == addr {
				return l
			}
		}
		relPoll()
	}
}

// relPoll is the pause between two reads of a file another process rewrites.
//
// It is not a guess about how long that takes, which is what the waits here
// refuse to make: the loops carry no deadline and stop on the state they are
// waiting for. It is a yield with a floor, because a bare Gosched spins a core
// flat while the lane already runs several suites at once on this box.
func relPoll() {
	goruntime.Gosched()
	time.Sleep(time.Millisecond)
}

// relAssertLifetimeMargin is observer 3's premise, measured rather than
// assumed: a control lease means nothing if it could have expired.
func relAssertLifetimeMargin(t *testing.T, started time.Time, leaseSec int) {
	t.Helper()
	elapsed := time.Since(started)
	lifetime := time.Duration(leaseSec) * time.Second
	if elapsed+relMargin > lifetime {
		t.Errorf("the test ran %s against a %s lease lifetime, leaving less than the %s margin: a lease that vanished here could have expired rather than been released",
			elapsed.Round(time.Millisecond), lifetime, relMargin)
	}
	t.Logf("ran in %s against a %s lease lifetime", elapsed.Round(time.Millisecond), lifetime)
}

// relHostLLA6 is the link-local the v6 release is sent FROM: a second address
// on the client end that never acquired anything. RFC 9915 section 18.2.7's
// "The client MUST NOT use any of the addresses it is releasing as the source
// address in the Release message" is satisfied by construction here, and
// SendRelease refuses the other shape rather than relying on the fixture.
const relHostLLA6 = "fe80::9"

// relControlMAC6 is the negative control client's hardware address, and it is
// what makes that client a different client to the server: section 11 keys a
// binding on the DUID, and this client's DUID is formed from this address.
var relControlMAC6 = net.HardwareAddr{0x02, 0x00, 0x5e, 0x96, 0x20, 0x02}

func TestAV6ReleaseBuiltFromARecordReachesRealDnsmasq(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		v6ReleaseByRecordAgainstDnsmasq(t)
		return
	}
	reexecInNamespaces(t)
}

func v6ReleaseByRecordAgainstDnsmasq(t *testing.T) {
	started := time.Now()

	wireUpV6(t)
	mustRun(t, "ip", "-6", "addr", "add", relHostLLA6+"/64", "dev", test6ClientIf, "nodad")
	srv := startDnsmasq6(t, v6Managed)

	// ---------------------------------------------- the lease to be released --
	c, hw := newV6Client(t)
	stop := runV6Client(t, c)
	ev := awaitV6(t, c, lease.Acquired)
	stop()

	duid, err := wire.DUIDLL(wire.ARPHTypeEthernet, hw)
	if err != nil {
		t.Fatalf("DUIDLL: %v", err)
	}
	addr := ev.Lease.Addr.Addr()

	// The v4 half reads column five here to check observer 4's premise. RFC
	// 9915 section 11 leaves a DUID opaque and dnsmasq has no second key to
	// fall back to on the v6 side, so the read here is for the other half of
	// that call: it puts dnsmasq's lease-file write in front of the Release
	// below, and a lease missing afterwards is then one that was removed
	// rather than one that was never written.
	stored := relWaitLease(t, srv.leasefile, addr)
	t.Logf("the v6 lease to be released: %s, iaid %#x, held by dnsmasq under %s",
		addr, ev.Lease.IAID, stored.clientID)

	// ------------------------------------------------- the negative control --
	second, err := newV6ClientAs(test6ClientIf, relControlMAC6)
	if err != nil {
		t.Fatalf("building the control client: %v", err)
	}
	stopSecond := runV6Client(t, second)
	controlEv := awaitV6(t, second, lease.Acquired)
	stopSecond()
	control := controlEv.Lease.Addr.Addr()
	if control == addr {
		t.Fatalf("both clients leased %s; the control cannot be told from the subject", control)
	}
	t.Logf("the v6 negative control lease, never released: %s", control)

	rec := lease.Record{
		ID: "rec-released-6", Scope: "net-a", Family: lease.FamilyV6,
		Identity: binary.BigEndian.AppendUint32(append([]byte(nil), duid...), ev.Lease.IAID),
		Lease:    ev.Lease,
	}
	cfg := ReleaseConfig{Interface: test6ClientIf, Source: netip.MustParseAddr(relHostLLA6)}

	// ------------------------------------------- observer 4, and it runs FIRST --
	// The DUID is mutated and the IAID left alone, so the record still passes
	// BuildRelease's own consistency check and the datagram really goes out
	// naming a client the server has never bound. Section 7.1's measurement
	// says dnsmasq answers that with a per-IA status and leaves the lease.
	wrong := rec
	wrong.Identity = append([]byte(nil), rec.Identity...)
	wrong.Identity[len(wrong.Identity)-5] ^= 0xFF
	before := srv.count("DHCPRELEASE(" + test6ServerIf + ")")
	if err := SendRelease(wrong, cfg); err != nil {
		t.Fatalf("the wrong-DUID release was not sent: %v", err)
	}
	srv.waitCount(t, "DHCPRELEASE("+test6ServerIf+")", before+1,
		"dnsmasq logs a DHCPRELEASE before it decides whether it knows the binding")

	// The v4 half's reason, in this family's spelling. RFC 9915 section 21.13
	// gives the Release its per-IA Status Code and dnsmasq writes it into the
	// log. MEASURED, dnsmasq 2.91: "option: 13 status  3 no binding found"
	// against "option: 13 status  0 release received" for one it acts on.
	srv.waitFor(t, "no binding found")
	relWaitHolds(t, srv.leasefile, addr)
	t.Logf("dnsmasq found no binding for the wrong-DUID Release and left %s in place", addr)

	// ----------------------------------------------------- observers 1 and 2 --
	if err := SendRelease(rec, cfg); err != nil {
		t.Fatalf("SendRelease: %v", err)
	}
	srv.waitCount(t, "DHCPRELEASE("+test6ServerIf+")", before+2,
		"the Release that names the binding dnsmasq holds")
	relWaitGone(t, srv.leasefile, addr)
	t.Logf("dnsmasq closed %s on a Release sourced from %s, which never held it", addr, relHostLLA6)

	// -------------------------------------------------------- observer 3, last --
	relWaitHolds(t, srv.leasefile, control)

	// ------------------------------------ section 18.2.7's MUST NOT, refused --
	// The forbidden shape, driven against the real transport so that the
	// refusal is shown to happen before anything reaches a socket rather than
	// only in a table.
	forbidden := cfg
	forbidden.Source = addr
	if err := SendRelease(rec, forbidden); err == nil {
		t.Error("a Release sourced from the address it releases was sent; section 18.2.7 forbids it")
	}

	relAssertLifetimeMargin(t, started, test6LeaseSec)
}

// relAcceptLocal lets the server end of the fixture link accept a datagram
// whose source address this same host owns.
//
// IT IS A PROPERTY OF THE RIG AND NOT OF THE SUBJECT, and saying which is the
// point. Both ends of the veth pair live in ONE network namespace here, so a
// release that really goes out on the wire — which is what binding the socket
// to the sending link makes it do — arrives at the other end carrying a source
// address the receiving host holds itself, and Linux discards that as a
// martian source unless accept_local is set. In production the two ends are
// two machines and the question does not arise.
//
// MEASURED 2026-09-11 in this fixture: without it, dnsmasq logs nothing at all
// for a release sent with ReleaseConfig.Interface set, while the identical
// release sent without the device binding is logged. Setting it changes what
// this test can SEE and nothing about what SendRelease does.
func relAcceptLocal(t *testing.T, ifName string) {
	t.Helper()
	p := "/proc/sys/net/ipv4/conf/" + ifName + "/accept_local"
	if err := os.WriteFile(p, []byte("1\n"), 0o644); err != nil {
		t.Fatalf("writing %s: %v", p, err)
	}
}

// relNeighbourMAC is the client that acquires WITHOUT an option 61, and
// relIdentifiedMAC is the one whose option 61 is exactly what an invented
// identifier for the first client would be.
var (
	relNeighbourMAC  = net.HardwareAddr{0x02, 0x00, 0x5e, 0x96, 0x20, 0x03}
	relIdentifiedMAC = net.HardwareAddr{0x02, 0x00, 0x5e, 0x96, 0x20, 0x04}
)

// TestAnInventedIdentifierWouldCloseAnotherClientsLease is the outside
// evidence for the half of RFC 2131 section 3.1(6) that has none on its own.
//
// "If the client used a 'client identifier' when it obtained the lease, it
// MUST use the same 'client identifier' in the DHCPRELEASE message." The
// condition means a lease taken without one must be released without one, and
// a single-lease fixture cannot see a release that invents an identifier:
// dnsmasq falls back to the hardware address, finds the same binding and
// closes it, so the datagram's bytes are the only witness.
//
// A SECOND LEASE MAKES IT VISIBLE. The invention that a builder reaches for is
// RFC 2132 section 9.14's type-1 form, one octet of hardware type followed by
// the hardware address. So the fixture gives that exact string to somebody
// else: one client acquires with no identifier, a second acquires with
// 01 followed by the FIRST client's hardware address, and dnsmasq now keys a
// different binding on the bytes the invention would produce. Releasing the
// first client's record must close the first client's lease. A release that
// invented an identifier closes the second one instead, and both halves are
// lines in dnsmasq's own file.
func TestAnInventedIdentifierWouldCloseAnotherClientsLease(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		inventedIdentifierAgainstDnsmasq(t)
		return
	}
	reexecInNamespaces(t)
}

func inventedIdentifierAgainstDnsmasq(t *testing.T) {
	started := time.Now()

	mustRun(t, "ip", "link", "add", testClientIf, "type", "veth", "peer", "name", testServerIf)
	mustRun(t, "ip", "addr", "add", testServerIP+"/24", "dev", testServerIf)
	mustRun(t, "ip", "link", "set", testServerIf, "up")
	mustRun(t, "ip", "link", "set", testClientIf, "up")
	mustRun(t, "ip", "link", "set", "lo", "up")
	relAcceptLocal(t, testServerIf)
	mustRun(t, "ip", "addr", "add", relHostAddr4+"/24", "dev", testClientIf)

	srv := startDnsmasq(t)

	// The lease that was taken with no identifier, and the one to release.
	plain, _ := relAcquire(t, relNeighbourMAC, nil)
	plainAddr := plain.Addr.Addr()

	// The neighbour, holding the identifier an invention would produce.
	invented := append([]byte{0x01}, relNeighbourMAC...)
	other, _ := relAcquire(t, relIdentifiedMAC, invented)
	otherAddr := other.Addr.Addr()
	if plainAddr == otherAddr {
		t.Fatalf("both clients leased %s", plainAddr)
	}

	// THE FIXTURE'S PREMISE, READ FROM THE SERVER. The whole test is that
	// these two bindings are keyed on different things and that one of those
	// keys is the invention.
	if l := relWaitLease(t, srv.leasefile, plainAddr); l.clientID != "*" {
		t.Fatalf("dnsmasq stored %s under client identifier %q, want none; this fixture cannot tell a replayed absence from an invention",
			plainAddr, l.clientID)
	}
	if l := relWaitLease(t, srv.leasefile, otherAddr); l.clientID != hexColons(invented) {
		t.Fatalf("dnsmasq stored %s under client identifier %q, want %q", otherAddr, l.clientID, hexColons(invented))
	}
	t.Logf("%s is held with no identifier, %s is held under %s", plainAddr, otherAddr, hexColons(invented))

	rec := lease.Record{
		ID: "rec-no-identity", Scope: "net-a", Family: lease.FamilyV4,
		CHAddr: append([]byte(nil), relNeighbourMAC...),
		Lease:  plain,
	}
	if err := SendRelease(rec, ReleaseConfig{
		Interface: testClientIf,
		Source:    netip.MustParseAddr(relHostAddr4),
	}); err != nil {
		t.Fatalf("SendRelease: %v", err)
	}

	srv.waitFor(t, "DHCPRELEASE("+testServerIf+") "+plainAddr.String())
	relWaitGone(t, srv.leasefile, plainAddr)
	relWaitHolds(t, srv.leasefile, otherAddr)
	t.Logf("the release with no option 61 closed %s and left %s alone", plainAddr, otherAddr)

	relAssertLifetimeMargin(t, started, testLeaseSec)
}
