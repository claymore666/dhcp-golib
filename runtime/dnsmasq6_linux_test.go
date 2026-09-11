// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

//go:build linux

package runtime

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	gosched "runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/claymore666/dhcp-golib/lease"
	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

// The DHCPv6 half of the namespaced proofs.
//
// It shares this package's namespace machinery with the v4 file —
// reexecInNamespaces, childReport, announceWait, dnsmasqServer and its log
// barriers — and adds what the second family needs: a dnsmasq that speaks
// DHCPv6 and Router Advertisements, FIVE named modes of it, and the two
// vacuity observers design section A.4 requires of every v6 proof.
//
// WHY THE TWO OBSERVERS ARE NOT OPTIONAL, and why they are the first thing
// each proof runs.
//
// Trap 1: a v6 test goes green because NO ROUTER ADVERTISEMENT EVER ARRIVED
// and the client took a path that does not need one. Every positive assertion
// below still holds — the client solicits, the server answers, an address is
// acquired — and the one thing the test was written to measure never happened.
//
// Trap 2: a v6 test goes green because THE FIXTURE ANSWERED FROM A DIFFERENT
// MODE than the test named. dnsmasq's five configurations differ by two
// command-line words, three of them log a readiness line that is easy to
// mistake for another's, and a client that acquires an address under the
// stateless configuration has proved something about a fixture nobody built.
//
// So each proof calls assertMode BEFORE it constructs a client, and assertMode
// checks the mode's WHOLE signature: dnsmasq's own readiness line, whether an
// advertisement was logged, and — from a SEPARATE packet socket that is not
// this library's — the M and O flags and the prefix option's autonomous flag
// on an advertisement actually seen on the link. A fixture in the wrong mode
// is red in the fixture, with the mode it actually was named in the failure.

const (
	test6ClientIf = "v6cli0"
	test6ServerIf = "v6srv0"

	// test6ClientIf2 is a SECOND client on the SAME link: a macvlan over the
	// client end of the veth, which is what the plugin's macvlan mode builds
	// and is the cheapest honest way to put two DHCPv6 clients with two
	// different link-local addresses on one segment. See
	// TestAV6ClientDiscardsAnotherClientsReplyAtTheTransport.
	test6ClientIf2 = "v6cli1"

	test6ServerIP = "fd00:99::1"
	test6Prefix   = "fd00:99::"
	test6PrefixLn = 64
	test6RangeLo  = "fd00:99::100"
	test6RangeHi  = "fd00:99::1ff"
	test6LeaseSec = 300

	// test6OnlyAddr is the whole pool in v6Exhausted mode: one address, inside
	// the same prefix as the ordinary range and outside it, so a client that
	// was answered from the wrong fixture is visible in the address itself.
	test6OnlyAddr = "fd00:99::1ff0"

	// test6RAInterval is dnsmasq's --ra-param advertisement interval, in
	// seconds, and test6RALifetime the Router Lifetime the advertisement
	// carries. RFC 4861 section 6.2.1 requires MaxRtrAdvInterval to be no
	// greater than the Router Lifetime, and dnsmasq refuses the pair outright
	// otherwise.
	test6RAInterval = 4
	test6RALifetime = 300
)

// test6RAUnsolicitedMax is how long a link that advertises at all can stay
// silent, and it is READ OUT OF THE FIXTURE'S OWN SOURCE rather than derived
// from the interval passed on its command line.
//
// DEFEAT ROW F-4 IS WHY THIS IS NOT `2 * test6RAInterval`. That was this
// file's first shape, and it is wrong: --ra-param's interval does not govern
// the first minute. dnsmasq 2.91's src/radv.c, new_timeout(), verbatim:
//
//	if (difftime(now, context->ra_short_period_start) < 60.0)
//	  /* range 5 - 20 */
//	  context->ra_time = now + 5 + (rand16()/4400);
//	else
//	  {
//	    /* range 3/4 - 1 times MaxRtrAdvInterval */
//
// MEASURED against that, on this box, with --ra-param interval 4: successive
// RTR-ADVERT lines 9, 5, 5, 19 and 11 seconds apart — every one of them
// inside 5..20 and none of them inside 2×4. A window of eight seconds would
// therefore have passed on a link that advertises perfectly well, and passed
// FASTER the more wrong it was, which is the whole shape row F-4 names.
//
// Every namespaced proof here runs inside dnsmasq's first minute, so 20
// seconds is the bound that applies. It is spent by exactly one test.
const test6RAUnsolicitedMax = 20 * time.Second

// test6RADrain is how long a "nothing arrived" read keeps listening past now.
//
// IT IS NOT THE WINDOW. The window is the socket's buffer, which has been
// filling since before the client was built; this is only long enough for the
// runtime poller to hand over what is already queued, because a deadline
// already in the past is a read that may return before it has looked. Where
// the claim needs a window that extends into the FUTURE — "a link that
// advertises would have spoken by now" — the caller passes
// test6RAUnsolicitedMax instead, and says so.
const test6RADrain = 500 * time.Millisecond

// v6Mode is one dnsmasq configuration together with the whole of what it looks
// like from outside — design section A.4's signature, in a struct.
//
// EVERY FIELD IS AN ASSERTION AND NOT A SETTING. args builds the fixture;
// everything after it is what the fixture must then be observed to do, on two
// independent channels. A mode whose args and whose signature disagree fails
// in assertMode rather than in whichever proof happens to run first.
type v6Mode struct {
	// name is what a failure calls this mode.
	name string
	// args are the dnsmasq arguments that make this mode, appended to the
	// common set in startDnsmasq6.
	args []string
	// ready is the log line dnsmasq prints once THIS mode's configuration is
	// up, and absent are the readiness lines this mode must NOT print.
	//
	// BOTH ARE NEEDED AND ONE OF THEM ALONE IS A TRAP-2 HOLE. MEASURED on
	// this box: the managed, stateless and managed-silent modes all log
	// "router advertisement on fd00:99::", so the SLAAC-only mode's readiness
	// line is a line three other modes also print, and waiting for it would
	// confirm nothing. What separates them is the DHCPv6 line each mode does
	// or does not print beside it, so each mode names the ones that would
	// mean it is a different mode.
	ready  string
	absent []string
	// advertises says whether this mode emits Router Advertisements at all.
	advertises bool
	// managed and other are RFC 4861 section 4.2's M and O flags as this mode
	// sets them, measured against dnsmasq 2.91. They are not a transcription of
	// a capture taken once: assertMode reads both flags off a real Router
	// Advertisement on the link on every run, and fails the mode whose wire
	// disagrees with the two values declared here.
	managed, other bool
	// autonomous is section 4.6.2's A flag on the Prefix Information option.
	// It is what separates a link where SLAAC is offered from one where the
	// prefix is on-link only, and it is the field that tells the managed mode
	// from the stateless one when M and O would not.
	autonomous bool
	// serves says whether dnsmasq ANSWERS a DHCPv6 client in this mode at
	// all — an Advertise, a Reply, or the "no addresses available" Advertise
	// a stateless server sends. It is the column that separates the managed
	// mode from the managed-silent one, which agree on every other field in
	// this struct and on both channels assertMode reads: same readiness line,
	// same absent lines, same M, O and A flags.
	//
	// IT IS CHECKED TWICE, in the two places a mode can be wrong. startDnsmasq6
	// derives it from the ARGUMENTS before dnsmasq is even started, so a
	// fixture whose command line and whose claim disagree is red before any
	// proof body runs; assertMode registers a check of dnsmasq's OWN LOG at
	// the end of the test, so a fixture whose arguments were fine and whose
	// server behaved otherwise is red too. MEASURED: mis-spelling
	// --dhcp-ignore=tag:dhcpv6 as tag:dhcpv6zz — which matches no client, so
	// the silent server answers — used to leave assertMode reporting "mode
	// managed-silent confirmed on two channels", and the drift was caught
	// only by one proof's own DHCPADVERTISE count eight lines later. Both
	// checks below fail on it now.
	serves bool
}

// The six modes, and every one of them is reachable from a real network.
//
// v6Managed is a container link on a managed network — the shape this library
// exists for. v6Stateless is RFC 9915 section 18.2.6's link: addresses come
// from SLAAC and only the other configuration comes from DHCPv6. v6SLAAC is
// RFC 4861 section 4.2's "no information is available via DHCPv6", which the
// 1.9.0 plugin could not tell from a server that was down. v6NoRA is a link
// with a DHCPv6 server and no router, which is where interlock 1 must NOT
// wait. v6ManagedSilent is the one that separates "there is no server" from
// "the server is there and is not answering us", and it is the reason the
// router observation is published at all. v6Exhausted is the server that is
// there, is answering, and has nothing left to give, which is the third thing
// those two are told apart from (#816).
var (
	v6Managed = v6Mode{
		name:       "managed",
		args:       []string{"--dhcp-range=" + test6RangeLo + "," + test6RangeHi + ",64," + fmt.Sprint(test6LeaseSec), "--enable-ra"},
		ready:      "DHCPv6, IP range " + test6RangeLo,
		absent:     []string{"DHCPv6 stateless on"},
		advertises: true, managed: true, other: true, autonomous: false,
		serves: true,
	}
	v6Stateless = v6Mode{
		name: "stateless",
		// NO --enable-ra, and its absence is load-bearing information rather
		// than an omission. MEASURED 2026-09-06 against the dnsmasq 2.91
		// source: option.c sets CONTEXT_RA on the range for the ra-only,
		// slaac, ra-names, ra-advrouter and ra-stateless keywords, dnsmasq.c
		// turns doing_ra on for any context carrying it, and radv.c consults
		// --enable-ra only in the ELSE arm, for contexts that do not. So on
		// this mode and on v6SLAAC the flag decided nothing, and a plant that
		// took it away would have been a plant that changed nothing — which
		// is exactly what the first draft of the v6-ra-absent scenario was.
		// The flag is kept where it is the only thing enabling the
		// advertisement: v6Managed and v6ManagedSilent.
		args:       []string{"--dhcp-range=" + test6Prefix + ",ra-stateless,64," + fmt.Sprint(test6LeaseSec)},
		ready:      "DHCPv6 stateless on " + test6Prefix,
		absent:     []string{"DHCPv6, IP range"},
		advertises: true, managed: false, other: true, autonomous: true,
		serves: true,
	}
	v6SLAAC = v6Mode{
		name: "slaac-only",
		// No --enable-ra: ra-only sets CONTEXT_RA by itself. See v6Stateless.
		args:       []string{"--dhcp-range=" + test6Prefix + ",ra-only,64," + fmt.Sprint(test6LeaseSec)},
		ready:      "router advertisement on " + test6Prefix,
		absent:     []string{"DHCPv6, IP range", "DHCPv6 stateless on"},
		advertises: true, managed: false, other: false, autonomous: true,
		serves: false,
	}
	v6NoRA = v6Mode{
		name:       "no-ra",
		args:       []string{"--dhcp-range=" + test6RangeLo + "," + test6RangeHi + ",64," + fmt.Sprint(test6LeaseSec)},
		ready:      "DHCPv6, IP range " + test6RangeLo,
		absent:     []string{"DHCPv6 stateless on", "IPv6 router advertisement enabled"},
		advertises: false,
		serves:     true,
	}
	// v6Exhausted is v6Managed with a pool of ONE address, so that a second
	// client on the same link is refused with an address in the range and none
	// of it free. It is the only mode here whose answer depends on what
	// another client already took.
	v6Exhausted = v6Mode{
		name:       "exhausted",
		args:       []string{"--dhcp-range=" + test6OnlyAddr + "," + test6OnlyAddr + ",64," + fmt.Sprint(test6LeaseSec), "--enable-ra"},
		ready:      "DHCPv6, IP range " + test6OnlyAddr,
		absent:     []string{"DHCPv6 stateless on"},
		advertises: true, managed: true, other: true, autonomous: false,
		serves: true,
	}
	v6ManagedSilent = v6Mode{
		name: "managed-silent",
		args: []string{
			"--dhcp-range=" + test6RangeLo + "," + test6RangeHi + ",64," + fmt.Sprint(test6LeaseSec),
			"--enable-ra",
			// The server is up, is advertising itself as managed, and answers
			// nothing. dnsmasq tags every DHCPv6 client "dhcpv6"; ignoring
			// that tag is a server that hears the Solicit and stays silent,
			// which is what the log then shows.
			"--dhcp-ignore=tag:dhcpv6",
		},
		ready:      "DHCPv6, IP range " + test6RangeLo,
		absent:     []string{"DHCPv6 stateless on"},
		advertises: true, managed: true, other: true, autonomous: false,
		serves: false,
	}
)

// wireUpV6 builds the veth pair and gives the server end its address.
//
// DUPLICATE ADDRESS DETECTION IS TURNED OFF ON THE LINK, and the reason is
// worth stating because turning off a duplicate check in a file about
// duplicate checks looks exactly like the defect. What is turned off is the
// KERNEL's, for the addresses the KERNEL assigns — the link-local addresses of
// the two veth ends. RFC 4862 section 5.4 makes an address tentative until its
// own check completes, and InterfaceLinkLocal refuses a tentative address by
// design, so without this every client here would have to wait out the
// kernel's probe with a wall-clock sleep that gate T2 rightly forbids in a
// test file.
//
// What it does NOT turn off is this library's check, which is the subject:
// DADProbe runs over the packet socket and knows nothing about this sysctl.
// The refusal of a tentative address is driven separately and without a
// namespace by TestInterfaceLinkLocalRefusesAnAddressTheKernelIsStillChecking.
func wireUpV6(t *testing.T) {
	t.Helper()
	wireUpV6Link(t, v6LinkReady)
}

// v6LinkMode is the state the CLIENT end of the fixture link comes up in.
//
// The server end keeps accept_dad off, one global address and up in all four.
// What varies is whether the client end has a usable link-local address when it
// comes up, because that is what the link-local proofs are about — and, in
// v6LinkCollide alone, the server end gains a hardware address as well, because
// a duplicate needs two holders and one of them has to be the neighbour.
type v6LinkMode int

const (
	// v6LinkReady is every other proof in this file: the kernel's own
	// duplicate check is off, so the link-local is usable as soon as it
	// exists. See wireUpV6's own comment for why turning it off is not the
	// defect it looks like.
	v6LinkReady v6LinkMode = iota
	// v6LinkTentative leaves the kernel's check ON at the client end, so the
	// address the client must send from spends RFC 4862 section 5.4's
	// tentative window unusable — one to two seconds on Linux at the
	// defaults — starting the instant the link comes up.
	v6LinkTentative
	// v6LinkNoIPv6 brings the client end up with net.ipv6.conf.<if>.
	// disable_ipv6 set, so the kernel forms no link-local for it at all and
	// never will.
	v6LinkNoIPv6
	// v6LinkCollide puts the SAME link-local address on both ends of the veth
	// and leaves the kernel's own duplicate check on at the client end, so the
	// client's address really loses RFC 4862 section 5.4's procedure and the
	// kernel really sets IFA_F_DADFAILED on it.
	//
	// HOW THE COLLISION IS BUILT, and why it is built out of the MAC rather
	// than out of `ip -6 addr add`. Linux forms a link-local from the
	// interface's hardware address by RFC 4291 Appendix A's modified EUI-64
	// when addr_gen_mode is 0, so two interfaces with one MAC form one
	// address. Both ends are given that MAC and that mode BEFORE they come up.
	// The server end keeps accept_dad off, so its copy is valid the instant it
	// exists and its kernel answers the Neighbor Solicitation the client's
	// duplicate check sends; the client end keeps accept_dad on, so it sends
	// that solicitation, hears itself answered, and marks its own address
	// failed. Adding the address by hand instead would produce an address this
	// library's caller never asked for; this one is the address the kernel
	// would have picked anyway, in collision with a neighbour.
	//
	// accept_dad is 1 and not 2 at the client end deliberately: 2 makes the
	// kernel disable IPv6 on the interface outright, which is the v6LinkNoIPv6
	// shape wearing another name and loses the flag byte this mode exists to
	// produce.
	v6LinkCollide
)

// test6CollideMAC is the hardware address BOTH ends of the link wear in
// v6LinkCollide mode. Locally administered, unicast, and fixed so that the
// address the kernel forms from it is the same in every run and can be
// predicted by the proof rather than only read back.
const test6CollideMAC = "02:00:00:00:c0:11"

// wireUpV6Link is wireUpV6 with the client end's state as a parameter.
func wireUpV6Link(t *testing.T, mode v6LinkMode) {
	t.Helper()
	mustRun(t, "ip", "link", "add", test6ClientIf, "type", "veth", "peer", "name", test6ServerIf)
	dad := map[string]string{test6ServerIf: "0", test6ClientIf: "0"}
	if mode == v6LinkTentative || mode == v6LinkCollide {
		dad[test6ClientIf] = "1"
	}
	if mode == v6LinkCollide {
		// The mode is written before the MAC and both before the link comes
		// up: addr_gen_mode is read when the kernel forms the address, and it
		// forms it at the transition to up.
		for _, ifName := range []string{test6ServerIf, test6ClientIf} {
			p := "/proc/sys/net/ipv6/conf/" + ifName + "/addr_gen_mode"
			if err := os.WriteFile(p, []byte("0\n"), 0o644); err != nil {
				t.Fatalf("writing %s: %v", p, err)
			}
			mustRun(t, "ip", "link", "set", ifName, "address", test6CollideMAC)
		}
	}
	for ifName, v := range dad {
		p := "/proc/sys/net/ipv6/conf/" + ifName + "/accept_dad"
		if err := os.WriteFile(p, []byte(v+"\n"), 0o644); err != nil {
			t.Fatalf("writing %s: %v", p, err)
		}
	}
	if mode == v6LinkNoIPv6 {
		p := "/proc/sys/net/ipv6/conf/" + test6ClientIf + "/disable_ipv6"
		if err := os.WriteFile(p, []byte("1\n"), 0o644); err != nil {
			t.Fatalf("writing %s: %v", p, err)
		}
	}
	mustRun(t, "ip", "-6", "addr", "add", test6ServerIP+"/"+fmt.Sprint(test6PrefixLn), "dev", test6ServerIf)
	mustRun(t, "ip", "link", "set", test6ServerIf, "up")
	mustRun(t, "ip", "link", "set", test6ClientIf, "up")
}

// threadIfInet6Path is the kernel's IPv6 address list for the network
// namespace of the CALLING THREAD.
//
// It is NOT /proc/net/if_inet6, and the difference is this milestone's defect.
// /proc/net is a symlink to /proc/self/net, and the kernel resolves both
// against the THREAD GROUP LEADER's network namespace rather than the calling
// thread's (fs/proc/proc_net.c, get_proc_task_net, which takes pid_task on the
// tgid). Any fixture here that unshares on a locked goroutine and then reads
// /proc/net is reading the namespace it came from. MEASURED 2026-09-06 from a
// locked non-leader thread that had unshared: /proc/net/if_inet6 and
// /proc/self/net/if_inet6 listed 0 rows for the new interface and this path
// listed 1, in 3 runs of 3.
//
// /proc/thread-self exists from Linux 3.17. The tree's own re-exec needs
// unprivileged user namespaces, which are older than that, so nothing here can
// run on a kernel where this path is missing.
const threadIfInet6Path = "/proc/thread-self/net/if_inet6"

// clientLinkLocal reports the link-local address the KERNEL currently lists for
// the client interface, in the CALLING THREAD's namespace — the 32-hex-digit
// form the kernel prints, and that row's flags column.
//
// It is the fixture's own reading and NOT readLinkLocal's, and since M7c's
// thread round it is a different MECHANISM as well: this is the kernel's text
// file and InterfaceLinkLocal asks netlink. The proofs below assert what the
// kernel held at a particular moment, and an observation taken with the
// function under test would make the observer and the subject one piece of
// code: a reader that never saw the address would report the address as absent
// and agree with itself.
func clientLinkLocal(t *testing.T) (string, uint64, bool) {
	t.Helper()
	return linkLocalOf(t, test6ClientIf)
}

// linkLocalOf is clientLinkLocal with the interface as a parameter, for the one
// proof that has to read BOTH ends of the link: a duplicate address needs a
// second holder, and a proof that only ever looked at the client end could not
// tell a collision from a kernel that failed the check for its own reasons.
func linkLocalOf(t *testing.T, ifName string) (string, uint64, bool) {
	t.Helper()
	b, err := os.ReadFile(threadIfInet6Path)
	if err != nil {
		t.Fatalf("reading %s: %v", threadIfInet6Path, err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) != 6 || f[5] != ifName || !strings.HasPrefix(f[0], "fe80") {
			continue
		}
		flags, err := strconv.ParseUint(f[4], 16, 32)
		if err != nil {
			t.Fatalf("the kernel printed %q as the flags of %s on %s", f[4], f[0], ifName)
		}
		return f[0], flags, true
	}
	return "", 0, false
}

// startDnsmasq6 starts the server in one of the six modes and waits for that
// mode's own readiness line.
//
// It is a second function beside startDnsmasqCfg rather than a flag on it. The
// two command lines share four arguments out of sixteen and disagree about the
// rest; a single function with a v4/v6 switch would put both families'
// arguments in one place where an edit for one silently reaches the other, and
// ruling 9 for this milestone is that the v4 path is untouched.
func startDnsmasq6(t *testing.T, mode v6Mode) *dnsmasqServer {
	t.Helper()

	bin, err := findDnsmasq()
	if err != nil {
		t.Fatalf("%v", err)
	}
	dir := t.TempDir()
	leasefile := filepath.Join(dir, "leases")

	args := []string{
		"--conf-file=/dev/null",
		// See startDnsmasqCfg: --no-daemon skips the privilege drop an
		// unprivileged user namespace cannot survive.
		"--no-daemon",
		"--log-facility=-",
		"--log-dhcp",
		"--port=0",
		"--interface=" + test6ServerIf,
		"--bind-interfaces",
		"--except-interface=lo",
		"--dhcp-option=option6:dns-server,[" + test6ServerIP + "]",
		"--dhcp-authoritative",
		"--dhcp-leasefile=" + leasefile,
		"--pid-file=" + filepath.Join(dir, "pid"),
		"--no-resolv",
		"--no-hosts",
		// The advertisement interval, small, and the ONE place it is written.
		// Every negative assertion about advertisements derives its window
		// from test6RAInterval rather than from a number of its own.
		"--ra-param=" + test6ServerIf + "," + fmt.Sprint(test6RAInterval) + "," + fmt.Sprint(test6RALifetime),
	}
	args = append(args, mode.args...)

	// THE SERVES COLUMN AGAINST THE COMMAND LINE, before dnsmasq exists. A
	// mode that claims to answer nothing and is built out of arguments that
	// answer everything is a Trap 2 fixture, and this is the earliest moment
	// it can be caught.
	if got := modeServesDHCPv6(args); got != mode.serves {
		t.Fatalf("mode %s declares serves=%t and its arguments make dnsmasq serves=%t; the fixture and what it claims to be disagree, so every assertion in this test would be about a link nobody built.\nArguments: %s",
			mode.name, mode.serves, got, strings.Join(mode.args, " "))
	}

	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")

	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("StderrPipe: %v", err)
	}
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting dnsmasq: %v", err)
	}

	s := &dnsmasqServer{cmd: cmd, arrived: make(chan string, 256), leasefile: leasefile, iface: test6ServerIf}
	go s.read(stderr)
	t.Cleanup(func() {
		s.stop()
		t.Logf("dnsmasq log (%s mode):\n%s", mode.name, strings.Join(s.lines(), "\n"))
	})

	s.waitFor(t, mode.ready)
	return s
}

// modeServesDHCPv6 derives from a dnsmasq command line whether it will answer a
// DHCPv6 client, and it is the fixture's own reading of its own arguments.
//
// TWO ARGUMENTS DECIDE IT, and both are read as dnsmasq 2.91 reads them.
//
// A --dhcp-range carrying the ra-only keyword configures router advertisements
// and NO DHCPv6 service: src/option.c sets CONTEXT_RA on the context without
// CONTEXT_DHCP, so there is nothing listening for a Solicit. Any other
// --dhcp-range serves — including ra-stateless, which answers an
// Information-request and answers a Solicit with "no addresses available".
//
// --dhcp-ignore=tag:dhcpv6 silences it again. dnsmasq tags every DHCPv6 client
// "dhcpv6" (src/rfc3315.c), so THAT EXACT STRING is the argument that makes a
// server hear a Solicit and answer nothing. A tag that is not that one matches
// no client and changes nothing, which is why the comparison is an equality
// and not a prefix: the mis-spelling is the whole point.
func modeServesDHCPv6(args []string) bool {
	serves := false
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "--dhcp-range=") && !strings.Contains(a, ",ra-only,"):
			serves = true
		case a == "--dhcp-ignore=tag:dhcpv6":
			return false
		}
	}
	return serves
}

// TestTheFixtureReadsItsOwnDnsmasqArguments drives modeServesDHCPv6 over the
// six modes and over the mis-spelling that made this column necessary.
//
// The derivation is fixture code, so nothing else in this package can fail
// when it is wrong: a derivation that always returned the declared value would
// make the check above pass for every mode, including the broken one.
func TestTheFixtureReadsItsOwnDnsmasqArguments(t *testing.T) {
	for _, m := range []v6Mode{v6Managed, v6Stateless, v6SLAAC, v6NoRA, v6ManagedSilent, v6Exhausted} {
		if got := modeServesDHCPv6(m.args); got != m.serves {
			t.Errorf("mode %s: modeServesDHCPv6 = %t, the mode declares %t", m.name, got, m.serves)
		}
	}
	misspelt := append([]string(nil), v6ManagedSilent.args...)
	for i, a := range misspelt {
		if a == "--dhcp-ignore=tag:dhcpv6" {
			misspelt[i] = "--dhcp-ignore=tag:dhcpv6zz"
		}
	}
	if !modeServesDHCPv6(misspelt) {
		t.Errorf("modeServesDHCPv6 still reads %v as a server that answers nothing; dnsmasq tags its DHCPv6 clients \"dhcpv6\" and matches no other tag, so this command line serves", misspelt)
	}
}

// ------------------------------------------------- the second observer --

// raWatch is a packet socket that is NOT this library's, reading Router
// Advertisements off the client's link.
//
// IT IS DELIBERATELY NOT AN NDSocket. An observer built from the type under
// test cannot see a defect the two of them share: an NDSocket that dropped
// every advertisement would report a link with no router, and an NDSocket
// watching it would agree. So this opens its own AF_PACKET socket, walks the
// IPv6 header with four comparisons written here, and hands the ICMPv6 body
// to the codec. What it shares with the subject is wire.DecodeRouterAdvert,
// and that is unavoidable and also the point: the flags are what is being
// asserted, and ring 0's reading of them is checked against captured frames
// in wire's own suite.
//
// THE DEADLINE IS THE SOCKET'S, NOT A TIMER. Gate T2 refuses time.After,
// time.Sleep and context.WithTimeout in a _test.go file, and it is right to:
// a wall-clock wait in a test is a bet on how loaded the box is. os.File's
// read deadline is enforced by the runtime poller on the descriptor, so a
// window here is a property of the socket rather than a goroutine racing it.
type raWatch struct {
	f      *os.File
	ifName string
}

// newRAWatch opens the observer, and it MUST be called before the client is
// constructed.
//
// Defeat row F-2: an observer opened after the Router Solicitation has gone
// out cannot see the advertisement that answered it, and would then pass on
// the next PERIODIC advertisement — later, and having measured a different
// frame than the one the test is about. Every proof below opens this first.
func newRAWatch(t *testing.T, ifName string) *raWatch {
	t.Helper()
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		t.Fatalf("InterfaceByName(%s): %v", ifName, err)
	}
	fd, err := syscall.Socket(syscall.AF_PACKET,
		syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK,
		int(htons(ethPIPv6)))
	if err != nil {
		t.Fatalf("the observer's socket(AF_PACKET, ETH_P_IPV6): %v", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{
		Protocol: htons(ethPIPv6), Ifindex: iface.Index,
	}); err != nil {
		_ = syscall.Close(fd)
		t.Fatalf("the observer's bind(%s): %v", ifName, err)
	}
	w := &raWatch{f: os.NewFile(uintptr(fd), "ra_watch:"+ifName), ifName: ifName}
	t.Cleanup(func() { _ = w.f.Close() })
	return w
}

// next reads until a Router Advertisement arrives or the window closes.
//
// The IPv6 header is walked here, by hand, and only the four fields that
// decide whether this is an advertisement are read: version, payload length,
// next header, and the ICMPv6 type. There is no extension-header walk, because
// RFC 4861 section 4.2's advertisement carries none and a frame that did would
// not be one this fixture sent.
func (w *raWatch) next(t *testing.T, within time.Duration) (*wire.RouterAdvert, netip.Addr, bool) {
	t.Helper()
	if err := w.f.SetReadDeadline(time.Now().Add(within)); err != nil {
		t.Fatalf("the observer's read deadline: %v", err)
	}
	buf := make([]byte, maxFrame)
	for {
		n, err := w.f.Read(buf)
		if err != nil {
			return nil, netip.Addr{}, false
		}
		frame := buf[:n]
		if n < ipv6HeaderLen+4 || frame[0]>>4 != ipv6Version || frame[6] != wire.ICMPv6NextHeader {
			continue
		}
		plen := int(binary.BigEndian.Uint16(frame[4:6]))
		if plen < 4 || ipv6HeaderLen+plen > n {
			continue
		}
		body := frame[ipv6HeaderLen : ipv6HeaderLen+plen]
		if body[0] != wire.ICMPv6RouterAdvert {
			continue
		}
		src := netip.AddrFrom16([16]byte(frame[8:24]))
		ra, err := wire.DecodeRouterAdvert(body)
		if err != nil {
			t.Fatalf("the observer read a Router Advertisement it could not decode (% x): %v", body, err)
		}
		return ra, src, true
	}
}

// none asserts that NO Router Advertisement has arrived, over a window whose
// two ENDS are events rather than a duration.
//
// THE SOCKET IS THE WINDOW. It was opened before the client was constructed
// and the kernel has been buffering into it ever since, so everything the link
// carried between then and now is either already read or queued. Draining it
// answers "did an advertisement arrive in that window" without any wait at
// all, and the window's length is whatever the barriers around the call made
// it — which is what makes it a window a reader can name.
//
// within is how long to keep listening PAST now, and callers pass a bound they
// can justify: zero for a window already closed by a positive barrier,
// test6RAUnsolicitedMax where the claim is that a silent link would have
// spoken by now.
func (w *raWatch) none(t *testing.T, why string, within time.Duration) {
	t.Helper()
	if ra, src, ok := w.next(t, within); ok {
		t.Fatalf("%s: a Router Advertisement arrived from %s — %s", why, src, ra)
	}
}

// -------------------------------------------- the outgoing-frame watch --

// test6SendWindow is how long assertTheSolicitLeftAsIPv6 keeps listening.
//
// RFC 9915 section 18.2.1 delays the first Solicit "by a random amount of time
// between 0 and SOL_MAX_DELAY" — one second (proto.DefaultParams6). Five is
// that plus four seconds of slack for a loaded two-core box, and it is spent
// only by a client whose messages are not leaving.
const test6SendWindow = 5 * time.Second

// txWatch is a packet socket reading THIS HOST'S OWN transmissions.
//
// IT IS BOUND TO ETH_P_ALL AND THAT IS THE ONLY BINDING THAT WORKS, which is
// the same measurement PacketTransportV6's BOUNDS carries from the other side:
// the kernel clones an outgoing frame only to sockets bound to ETH_P_ALL, so a
// socket bound to ETH_P_IPV6 — this file's raWatch, and the client's own
// transport — reads none of this host's own frames. That is exactly why it can
// be used to check WHICH EtherType a frame left with: the answer is in the
// sockaddr the kernel hands back, not in the buffer.
type txWatch struct {
	f *os.File
}

// newTXWatch opens the observer, and like every observer in this file it must
// be opened before the client is constructed: an outgoing frame is not
// buffered anywhere a later reader can find it.
func newTXWatch(t *testing.T, ifName string) *txWatch {
	t.Helper()
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		t.Fatalf("InterfaceByName(%s): %v", ifName, err)
	}
	fd, err := syscall.Socket(syscall.AF_PACKET,
		syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK,
		int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		t.Fatalf("the send observer's socket(AF_PACKET, ETH_P_ALL): %v", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL), Ifindex: iface.Index,
	}); err != nil {
		_ = syscall.Close(fd)
		t.Fatalf("the send observer's bind(%s): %v", ifName, err)
	}
	w := &txWatch{f: os.NewFile(uintptr(fd), "tx_watch:"+ifName)}
	t.Cleanup(func() { _ = w.f.Close() })
	return w
}

// assertTheSolicitLeftAsIPv6 is defeat row F-6's observer, and it is BOUNDED
// where the acquisition it precedes is not.
//
// WHY IT EXISTS. awaitV6 has no duration in it on purpose — a client that is
// slow on a loaded box must not be reported as broken — so a transport that
// cannot reach the server at all does not fail there; it HANGS, until the
// namespaced child's own -test.timeout ends the run 45 seconds later with a
// goroutine dump for a diagnosis. MEASURED with mutate.sh: rebinding this
// transport's socket, bind and sendto to ETH_P_IP (0x0800) leaves the golden
// path in awaitV6 for 45.13s and exits 2, and this project scores a hang as a
// third verdict and explicitly not as a kill.
//
// WHAT IT ASSERTS is the one fact that separates that mutant from a slow box:
// a DHCPv6 message left this host, and it left as IPv6. The EtherType comes
// out of the sockaddr the kernel fills in, so it is the value the wire
// carried and not a re-reading of the buffer the client built. The window is a
// socket read deadline, enforced by the runtime poller — gate T2's reason for
// refusing time.After does not apply to a deadline on a descriptor.
func (w *txWatch) assertTheSolicitLeftAsIPv6(t *testing.T, within time.Duration) {
	t.Helper()
	if err := w.f.SetReadDeadline(time.Now().Add(within)); err != nil {
		t.Fatalf("the send observer's read deadline: %v", err)
	}
	buf := make([]byte, maxFrame)
	var outgoing int
	for {
		n, from, err := w.readFrom(buf)
		if err != nil {
			t.Fatalf("no DHCPv6 message left %s within %s, over %d outgoing frame(s): a client that cannot put its Solicit on the wire never acquires, and waiting for the lease instead of for the send is a %s hang with no name on it (%v)",
				test6ClientIf, within, outgoing, within, err)
		}
		lla, ok := from.(*syscall.SockaddrLinklayer)
		if !ok || lla.Pkttype != syscall.PACKET_OUTGOING {
			continue
		}
		outgoing++
		frame := buf[:n]
		// The four fields that say "this is one of ours": an IPv6 packet,
		// carrying UDP, from the DHCPv6 client port to the server port.
		// Written out here rather than handed to ParseIPv6UDP, which narrows
		// on the ports the other way round because it reads REPLIES.
		if n < ipv6HeaderLen+8 || frame[0]>>4 != ipv6Version || frame[6] != protoUDP {
			continue
		}
		u := frame[ipv6HeaderLen:]
		if binary.BigEndian.Uint16(u[0:2]) != ClientPort6 || binary.BigEndian.Uint16(u[2:4]) != ServerPort6 {
			continue
		}
		if got := htons(lla.Protocol); got != ethPIPv6 {
			t.Fatalf("this client's DHCPv6 message left %s with EtherType %#04x, not IPv6 (%#04x): the frame is on the wire and no IPv6 receiver on the link will look at it",
				test6ClientIf, got, ethPIPv6)
		}
		return
	}
}

// readFrom is Recvfrom through the runtime poller, so the deadline set above
// is the thing that ends the wait.
func (w *txWatch) readFrom(buf []byte) (int, syscall.Sockaddr, error) {
	rc, err := w.f.SyscallConn()
	if err != nil {
		return 0, nil, err
	}
	var (
		n    int
		from syscall.Sockaddr
		rerr error
	)
	cerr := rc.Read(func(fd uintptr) bool {
		n, from, rerr = syscall.Recvfrom(int(fd), buf, 0)
		return rerr != syscall.EAGAIN
	})
	if cerr != nil {
		return 0, nil, cerr
	}
	return n, from, rerr
}

// ------------------------------------------------------ the mode check --

// assertMode is design section A.4's signature check, and it runs BEFORE any
// client is built.
//
// It closes both traps at once. Trap 1 — the whole test was green because no
// advertisement arrived — is closed by requiring one on BOTH channels for
// every mode that has one. Trap 2 — the fixture was in a different mode — is
// closed by checking the flags, and the flags are what the six modes actually
// differ by: managed says M=1 O=1 with no autonomous prefix, stateless says
// M=0 O=1 WITH one, and SLAAC-only says neither flag.
//
// A MODE WITH NO ADVERTISEMENT IS CHECKED IN THE OTHER DIRECTION and not
// skipped: silence is exactly what v6NoRA is for, and a fixture that quietly
// enabled advertisements would otherwise make every assertion that follows an
// assertion about a different link.
//
// It returns the advertisement it saw, for the proofs that go on to compare it
// against what the client reported.
func assertMode(t *testing.T, s *dnsmasqServer, w *raWatch, mode v6Mode) *wire.RouterAdvert {
	t.Helper()

	// THE SERVES COLUMN ON THE SECOND CHANNEL, deferred to the end of the
	// test because it is the one part of the signature that cannot be read
	// before a client has spoken: a server that ignores its DHCPv6 clients
	// says so by staying silent, and silence is only evidence after somebody
	// has asked. dnsmasq under --log-dhcp writes one "sent size:" line per
	// option of every message it SENDS (2.91 src/rfc3315.c log6_opts), which
	// is its own record of having answered at all — and it covers the
	// stateless mode, whose Advertise carries "no addresses available" and is
	// logged under no DHCPADVERTISE line.
	//
	// THE GUARD HAS A DIRECTION. A proof that failed before its exchange ever
	// happened proves nothing about whether a serving fixture would have
	// answered, and reporting that as a second failure would bury the first
	// one about the subject. The opposite case carries no such doubt: a
	// server that answered when this mode says it answers nothing is a fact
	// about the fixture whether or not the proof also failed, and it is the
	// fact that explains the failure.
	t.Cleanup(func() {
		answered := s.count(" sent size:") > 0
		if answered == mode.serves || (mode.serves && t.Failed()) {
			return
		}
		t.Errorf("mode %s declares serves=%t and dnsmasq answered=%t over this whole test; the fixture did not behave like the mode this test named.\nLog:\n%s",
			mode.name, mode.serves, answered, strings.Join(s.lines(), "\n"))
	})

	// The readiness lines this mode must NOT have printed. startDnsmasq6 has
	// already waited for the one it must, so by here the configuration
	// summary is complete and an absent line is absent for good.
	for _, no := range mode.absent {
		if containsLine(s.lines(), no) {
			t.Fatalf("mode %s logged %q, which belongs to a different mode; the fixture is not what this test named.\nLog:\n%s",
				mode.name, no, strings.Join(s.lines(), "\n"))
		}
	}

	if !mode.advertises {
		// The wire half, and its window is the SOLICITED one. It runs from
		// before the client existed to whatever barrier the caller has
		// already passed, and the derivation is measured: on the managed
		// fixture dnsmasq logs RTR-SOLICIT and RTR-ADVERT in the SAME SECOND
		// and this observer reads the advertisement before the acquisition
		// completes, so a link with --enable-ra could not have carried this
		// client's Router Solicitation and stayed quiet through the window a
		// caller closes here.
		//
		// WHAT IT DOES NOT COVER, said rather than implied: dnsmasq's
		// UNSOLICITED schedule, which its own new_timeout puts at 5 to 20
		// seconds (see test6RAUnsolicitedMax). Waiting that out would cost
		// twenty seconds for a claim the log half already settles
		// categorically — dnsmasq without --enable-ra logs neither the
		// enabling line checked below nor any RTR- line at all, because the
		// subsystem is not running.
		if containsLine(s.lines(), "IPv6 router advertisement enabled") {
			t.Fatalf("mode %s must not advertise, but dnsmasq logged that advertisements are enabled:\n%s",
				mode.name, strings.Join(s.lines(), "\n"))
		}
		if n := s.count("RTR-ADVERT(" + test6ServerIf + ")"); n != 0 {
			t.Fatalf("mode %s must not advertise, but dnsmasq logged %d RTR-ADVERT line(s)", mode.name, n)
		}
		w.none(t, "mode "+mode.name+" must emit no Router Advertisement", test6RADrain)
		return nil
	}

	// The wire half, and it goes FIRST on purpose. The log channel has no
	// deadline of its own: waitFor blocks until a matching line arrives or
	// until dnsmasq exits, so asking the log first turns "this link is not
	// advertising at all" into a HANG that only the child's own timeout ends,
	// by which point the failure names whichever proof happened to be running
	// rather than the one whose fixture went quiet. The wire window IS
	// bounded — test6RAUnsolicitedMax — so asking it first makes a silent
	// link a failure of this mode check, in this test, inside that bound.
	// MEASURED 2026-09-06: this is what the v6-ra-absent oracle scenario
	// drives, and with the two halves the other way round it drove a timeout
	// in an unrelated proof.
	//
	// The client's Router Solicitation is answered at once — MEASURED:
	// dnsmasq logs RTR-SOLICIT and RTR-ADVERT in the same second — and an
	// unsolicited one follows inside test6RAUnsolicitedMax regardless, so a
	// link that is advertising at all cannot reach this bound silently.
	ra, src, ok := w.next(t, test6RAUnsolicitedMax)
	if !ok {
		if containsLine(s.lines(), "RTR-ADVERT("+test6ServerIf+")") {
			t.Fatalf("mode %s: dnsmasq logged a Router Advertisement and the observer on %s saw none in %s; "+
				"the log and the link disagree, so nothing below can be trusted.\nLog:\n%s",
				mode.name, test6ClientIf, test6RAUnsolicitedMax, strings.Join(s.lines(), "\n"))
		}
		t.Fatalf("mode %s: no Router Advertisement reached %s in %s and dnsmasq logged none either; "+
			"this link is not advertising, so every flag this mode names is unmeasured.\nLog:\n%s",
			mode.name, test6ClientIf, test6RAUnsolicitedMax, strings.Join(s.lines(), "\n"))
	}

	// The log half: dnsmasq's own record that it sent one. It is a second
	// channel rather than a restatement — the observer above reads the wire,
	// this reads the server — and by here it is satisfied without waiting.
	s.waitFor(t, "RTR-ADVERT("+test6ServerIf+")")

	// RFC 4861 section 6.1.2: "IP Source Address is a link-local address.
	// Routers must use their link-local address as the source for Router
	// Advertisement and Redirect messages so that hosts can uniquely identify
	// routers." Asserted on the fixture, so that NDSocket's refusal of a
	// non-link-local source is known to be refusing something this link never
	// produces rather than something it produces all the time.
	if !src.IsLinkLocalUnicast() {
		t.Errorf("mode %s: the advertisement came from %s, which is not link-local (RFC 4861 section 6.1.2)", mode.name, src)
	}

	if ra.Managed != mode.managed || ra.Other != mode.other {
		t.Fatalf("mode %s: the advertisement on the link carries M=%t O=%t, but this mode is M=%t O=%t — "+
			"the fixture is not in the mode this test named",
			mode.name, ra.Managed, ra.Other, mode.managed, mode.other)
	}
	if len(ra.Prefixes) == 0 {
		t.Fatalf("mode %s: the advertisement carries no Prefix Information option (%s)", mode.name, ra)
	}
	var auto bool
	for _, p := range ra.Prefixes {
		if p.Autonomous {
			auto = true
		}
	}
	if auto != mode.autonomous {
		t.Fatalf("mode %s: the prefix option's autonomous flag is %t, want %t — %s",
			mode.name, auto, mode.autonomous, ra)
	}
	t.Logf("mode %s confirmed on two channels: dnsmasq logged RTR-ADVERT and the observer read %s", mode.name, ra)
	return ra
}

// ------------------------------------------------------- the v6 client --

// newV6Client builds the client this file's proofs drive, on the fixture link.
func newV6Client(t *testing.T) (*Client6, net.HardwareAddr) {
	t.Helper()
	return newV6ClientWith(t, nil)
}

// newV6ClientWith is newV6Client with one hook on the parameters, for the
// tests whose subject IS a parameter.
//
// The tweak runs BEFORE NewClient6, which is the only place it can run: the
// constructor clones the Params6 into the machine, so a field set on a client
// that already exists is a field the machine never sees — a test written that
// way would pass against a library that ignored the parameter entirely.
func newV6ClientWith(t *testing.T, tweak func(*proto.Params6)) (*Client6, net.HardwareAddr) {
	t.Helper()
	iface, err := net.InterfaceByName(test6ClientIf)
	if err != nil {
		t.Fatalf("InterfaceByName(%s): %v", test6ClientIf, err)
	}
	duid, err := wire.DUIDLL(wire.ARPHTypeEthernet, iface.HardwareAddr)
	if err != nil {
		t.Fatalf("DUIDLL: %v", err)
	}
	p := proto.DefaultParams6()
	p.DUID = duid
	p.IAID = 0x0a0b0c0d
	// THE OPTION REQUEST LIST IS THE CALLER'S AND DefaultParams6 LEAVES IT
	// EMPTY, which is deliberate one ring down and is a trap here. MEASURED:
	// without this, dnsmasq answered the Information-request with a Reply
	// carrying only the information-refresh time — its log reads "requested
	// options: 83, 32:information-refresh-time" — and the stateless proof
	// asserted a DNS server the client had never asked for. A server sends an
	// Information-request client what it was asked for and nothing else.
	p.ORO = proto.DefaultORO()
	if tweak != nil {
		tweak(&p)
	}

	c, err := NewClient6(ClientConfig6{Interface: test6ClientIf, Params6: p, EventBuffer: 8})
	if err != nil {
		t.Fatalf("NewClient6: %v", err)
	}
	return c, iface.HardwareAddr
}

// runV6Client starts the client and returns a stop function.
func runV6Client(t *testing.T, c *Client6) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- c.Run(ctx) }()
	// ONCE, because the callers that stop a client early also defer this, and
	// a second read of errc would block forever on a channel nothing writes to
	// again — a hang where the test had already finished making its point.
	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			if err := <-errc; err != nil && err != context.Canceled {
				t.Errorf("Run: %v", err)
			}
		})
	}
}

// awaitV6 blocks for one event of the given kind, failing on Failed.
//
// NO DURATION APPEARS HERE, for the reason the v4 file gives: an exchange that
// never completes hangs until the CHILD's own -test.timeout, which prints a
// goroutine dump and the dnsmasq log beside it. A wall-clock wait that was too
// short would instead report a slow box as a broken client.
func awaitV6(t *testing.T, c *Client6, kind lease.EventKind) lease.Event {
	t.Helper()
	for ev := range c.Events() {
		t.Logf("client event: %s", ev)
		if ev.Kind == kind {
			return ev
		}
		if ev.Kind == lease.Failed {
			t.Fatalf("the client failed while waiting for %s: %s", kind, ev)
		}
	}
	t.Fatalf("the event stream ended before a %s event", kind)
	return lease.Event{}
}

// awaitV6PastTheAddressRefusal is awaitV6 for lease.Configured on the one link
// whose server refuses the address before it hands over the configuration.
//
// A STATELESS dnsmasq ANSWERS THE SOLICIT WITH "no addresses available", which
// the caller comment above already measures, and since #816 that answer is an
// EVENT rather than only a journal line: Failed{ReasonNak} carrying
// wire.StatusNoAddrsAvail. It is true and it is not this link failing — the
// address was never on offer here — so the proof steps over refusals of that
// exact shape and over nothing else. A refusal carrying any other status, and
// any failure for any other reason, is fatal.
//
// THE TOLERANCE IS A SHAPE AND NOT A COUNT, which is a correction and not a
// weakening. An earlier version allowed exactly one, and one is a property of
// how fast this fixture's router advertisement arrives rather than of the
// protocol: §18.2.1 puts no retransmission limit on the Solicit, so until the
// advertisement reaches the client and moves it to the Information-request,
// every retransmission draws another refusing Advertise and every one of them
// is reported. A count would make this proof fail on a slow advertisement it
// does not control. What it still refuses is any OTHER event, which is the
// property the test is here for.
//
// IT IS TOLERATED RATHER THAN ASSERTED because the Solicit and the router
// advertisement cross the other way too: a client that reads the advertisement
// first never solicits again and is never refused. Asserting the refusal would
// make this proof fail on that ordering; asserting its ABSENCE would fail on
// the first one. The refusal itself is driven, deterministically and with the
// pool as the subject, by TestAV6ClientIsToldTheServerRefused.
//
// WHAT THE REFUSAL SAYS ABOUT THE ROUTER IS READ HERE TOO, because this is the
// event the advice on lease.Event.Router is written against. That advice sends
// a caller to the LIVE observation, and the assertion here is the half of it
// that holds on every ordering: whatever the refusals carried, the client that
// has reached the stateless configuration reports a router with M clear and O
// set. Each refusal's own copy is checked for the one thing it may never say
// on this link — managed — and the ones carrying nothing are counted into the
// log line.
//
// MEASURED 2026-09-11, four runs: every refusal here carried M=0 O=1, so on
// this fixture the advertisement wins the race against the Solicit. That is
// the reason the count is logged rather than asserted in either direction:
// §18.2.1 gives the Solicit no wait for router discovery, so an event stamped
// before the first advertisement carries the zero, and which of the two a run
// produces is timing. The deterministic end of that fact is
// TestTheRouterObservationOnARefusalIsWhatHadBeenSeenByThen, one ring down,
// where no advertisement arrives at all.
func awaitV6PastTheAddressRefusal(t *testing.T, c *Client6) lease.Event {
	t.Helper()
	refused := 0
	unseen := 0
	for ev := range c.Events() {
		t.Logf("client event: %s", ev)
		if ev.Kind == lease.Configured {
			t.Logf("the stateless link reported %d address refusal(s) before it was configured, %d of them carrying no router observation", refused, unseen)
			obs := c.Router()
			if !obs.Seen || obs.Managed || !obs.Other {
				t.Fatalf("the configured client reports %s, want a router seen with M clear and O set: the live observation is what a caller asks when it has no address, and this link has a router", obs)
			}
			return ev
		}
		if ev.Kind == lease.Failed {
			refused++
			if ev.Reason != proto.ReasonNak || ev.Status != wire.StatusNoAddrsAvail {
				t.Fatalf("the client failed while waiting for the stateless configuration: %s (reason %s, status %s, failure %d)",
					ev, ev.Reason, ev.Status, refused)
			}
			if !ev.Router.Seen {
				unseen++
			}
			if ev.Router.Seen && ev.Router.Managed {
				t.Fatalf("refusal %d carries %s on a stateless link: the observation a caller reads must not say this link is managed", refused, ev.Router)
			}
		}
	}
	t.Fatalf("the event stream ended before a configured event")
	return lease.Event{}
}

// assertTheCheckActuallyRan is the DAD half of the vacuity argument, and every
// proof that acquires an address calls it.
//
// AN ACQUISITION IS NOT EVIDENCE THAT RFC 4862 SECTION 5.4 RAN. A runner that
// reported every address free without sending anything would produce exactly
// this client's observable behaviour, and so would a manager that never
// consulted a runner at all. Solicits is what separates them: it counts frames
// that left the socket, and section 5.4.2 requires DupAddrDetectTransmits of
// them per address.
//
// OwnIgnored IS ASSERTED ZERO, WHICH IS THE OPPOSITE OF WHAT THE ASSUMPTION
// WOULD HAVE WRITTEN. MEASURED in this milestone: a packet socket bound to
// ETH_P_IPV6 does not read back this host's own transmissions, so the
// loopback exclusion cannot fire here. NDSocket's BOUNDS carry the experiment;
// the exclusion is driven by
// TestTheDuplicateCheckSortsOneFrameTheWayRFC4862Does instead. A number above
// zero here would mean something on this link echoes, and that is worth being
// told about rather than tolerated.
func assertTheCheckActuallyRan(t *testing.T, c *Client6, addr netip.Addr) {
	t.Helper()
	st := c.DADStats()
	if !st.Present {
		t.Fatal("the client reports no duplicate-address runner at all")
	}
	if st.Started != 1 {
		t.Errorf("DADStats.Started = %d, want 1 (one address checked)", st.Started)
	}
	if st.Solicits < proto.DupAddrDetectTransmits {
		t.Errorf("DADStats.Solicits = %d, want at least DupAddrDetectTransmits (%d): RFC 4862 section 5.4.2 sends that many, and an address reported free after none was never checked",
			st.Solicits, proto.DupAddrDetectTransmits)
	}
	if st.Free != 1 || st.Duplicate != 0 {
		t.Errorf("DADStats Free=%d Duplicate=%d, want 1 and 0 for the acquired address %s", st.Free, st.Duplicate, addr)
	}
	if st.OwnIgnored != 0 {
		t.Errorf("DADStats.OwnIgnored = %d; this socket does not read back its own frames (see NDSocket's BOUNDS), so something on this link is echoing them", st.OwnIgnored)
	}
	if nd := c.NDStats(); nd.Sends < proto.DupAddrDetectTransmits {
		t.Errorf("NDStats.Sends = %d; the solicitations the runner counted did not reach the socket", nd.Sends)
	}
}

// ---------------------------------------------------------- the proofs --

// TestAV6ClientAcquiresFromRealDnsmasq is the golden path, and it is the row
// every other v6 assertion in this package rests on.
//
// It is a proof rather than a test because of what it exercises that nothing
// else can: the UDP checksum over RFC 8200 section 8.1's pseudo-header, which
// a round trip written by one hand agrees with itself about and every real
// receiver disagrees with; the Linux CHECKSUM_PARTIAL an inbound reply
// actually carries over a veth, which is neither a complete checksum nor the
// zero section 8.1 forbids; the link-local source the reply is addressed back
// to; and RFC 4862 section 5.4's duplicate check between the Reply and the
// Acquired event.
func TestAV6ClientAcquiresFromRealDnsmasq(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		v6AcquireAgainstDnsmasq(t)
		return
	}
	reexecInNamespaces(t)
}

func v6AcquireAgainstDnsmasq(t *testing.T) {
	wireUpV6(t)
	srv := startDnsmasq6(t, v6Managed)
	watch := newRAWatch(t, test6ClientIf)
	tx := newTXWatch(t, test6ClientIf)

	c, hw := newV6Client(t)
	t.Logf("client interface %s has hardware address %s and link-local %s", test6ClientIf, hw, c.Source())
	stop := runV6Client(t, c)
	defer stop()

	// THE SIGNATURE FIRST, and only then anything about the client. Both
	// channels must agree that this link is the managed one before a single
	// client fact is read.
	ra := assertMode(t, srv, watch, v6Managed)

	// AND THE FIRST MESSAGE LEFT THE HOST, before anything waits for a lease
	// with no deadline on it. See assertTheSolicitLeftAsIPv6: this is where
	// defeat row F-6 turns from a 45-second hang into a named failure.
	tx.assertTheSolicitLeftAsIPv6(t, test6SendWindow)

	ev := awaitV6(t, c, lease.Acquired)
	addr := ev.Lease.Addr.Addr()
	if !addr.IsValid() {
		t.Fatalf("the Acquired event carries no address: %s", ev)
	}
	if !addr.Is6() || addr.Is4In6() {
		t.Fatalf("the acquired address %s is not IPv6", addr)
	}
	lo, hi := netip.MustParseAddr(test6RangeLo), netip.MustParseAddr(test6RangeHi)
	if addr.Less(lo) || hi.Less(addr) {
		t.Errorf("the acquired address %s is outside the range dnsmasq serves, %s..%s", addr, lo, hi)
	}

	// ------------------------------------------- the server's own log --
	//
	// Everything above is the client describing itself. These lines are
	// dnsmasq's, and they are what says the exchange happened on the wire.
	srv.waitFor(t, "DHCPSOLICIT("+test6ServerIf+")")
	srv.waitFor(t, "DHCPREQUEST("+test6ServerIf+")")
	srv.waitFor(t, "DHCPREPLY("+test6ServerIf+") "+addr.String())

	// The checksum finding, as an assertion. The Advertise and the Reply
	// arrive over a veth carrying Linux's CHECKSUM_PARTIAL — the folded
	// pseudo-header sum with the completion deferred — and NOT a finished
	// checksum. A parser that treated the field as a finished checksum drops
	// every reply and this client never acquires; a parser that accepted a
	// ZERO would violate RFC 8200 section 8.1. Both counters are read, so the
	// row says which of the two states the frames were actually in.
	tr := c.TransportStats()
	if tr.Reads < 2 {
		t.Errorf("TransportStatsV6.Reads = %d; the Advertise and the Reply are two frames", tr.Reads)
	}
	if tr.BadChecksum != 0 || tr.ZeroChecksum != 0 {
		t.Errorf("the transport refused frames: BadChecksum=%d ZeroChecksum=%d — %+v", tr.BadChecksum, tr.ZeroChecksum, tr)
	}
	if tr.Uncompleted == 0 {
		t.Errorf("TransportStatsV6.Uncompleted = 0: no reply carried Linux's CHECKSUM_PARTIAL, so this run did not exercise the state that made every reply look corrupt before it was understood — %+v", tr)
	}

	assertTheCheckActuallyRan(t, c, addr)

	// The Router Solicitation went out and the advertisement came back to
	// ring 1, which is the ND port end to end. The flags the manager reports
	// are compared against the ones the INDEPENDENT observer read, so a port
	// that invented an observation fails here.
	obs := c.Router()
	if !obs.Seen {
		t.Fatalf("the manager saw no Router Advertisement although the independent observer read %s: the ND port did not carry it to ring 1", ra)
	}
	if obs.Managed != ra.Managed || obs.Other != ra.Other {
		t.Errorf("the manager reports %s and the observer read %s; the two readings of one frame disagree", obs, ra)
	}
	if got := c.Stats().RouterAdvertsSeen; got == 0 {
		t.Error("RouterAdvertsSeen = 0 although the manager holds an observation")
	}
	nd := c.NDStats()
	if nd.Sends == 0 {
		t.Error("no Neighbor Discovery frame left the host; RFC 4861 section 6.3.7's Router Solicitation is sent at start")
	}
	if nd.BadHopLimit != 0 || nd.BadChecksum != 0 || nd.BadSource != 0 {
		t.Errorf("the ND socket refused frames on this link: %+v", nd)
	}
}

// awaitRouterObservation blocks until ring 1 reports having seen a Router
// Advertisement, and returns what it reports.
//
// IT SPINS, AND THE ALTERNATIVES ARE ALL WORSE. An advertisement produces no
// outward lease.Event — by design, because design Q2 makes the observation a
// diagnostic and not a lease transition — so there is no channel to receive
// on. A sleep is what gate T2 exists to refuse. A wall-clock deadline would
// turn a loaded box into a failed test. What is left is to read the value the
// manager publishes until it is there; the manager sets it inside the Step
// that takes the frame, and the frame is already on the link by the time any
// caller reaches here, so the loop is short. If it never resolves the CHILD's
// own -test.timeout ends the run and prints the dnsmasq log and a goroutine
// dump beside it, which is the loudest failure available in this file.
func awaitRouterObservation(t *testing.T, c *Client6) proto.RouterObservation {
	t.Helper()
	for {
		if obs := c.Router(); obs.Seen {
			return obs
		}
		gosched.Gosched()
	}
}

// awaitDADVerdict blocks until the duplicate-address runner has reported its
// FIRST verdict and returns the counters as they stood then.
//
// IT EXISTS TO TURN A HANG INTO A FAILURE. MEASURED 2026-09-06 with mutate.sh:
// a runner that calls deliver(free) at the top of probe — before a single
// solicitation has left the socket — is invisible to every pure test in this
// tree, because nothing pure drives DADProbe.probe at all (it needs a real
// packet socket), and it made the duplicate proof HANG for the netns child's
// whole timeout, because the barrier that proof waited on was dnsmasq's
// DHCPDECLINE and a client that thinks the address is free never sends one.
// mutate.sh scores a hang as its own verdict and explicitly not as a kill, so
// the mutant was adjudicated by neither row. Read here, before any barrier
// that depends on the verdict, a wrong verdict FAILS: MEASURED, the same
// mutant is now KILLED in 3s.
func awaitDADVerdict(t *testing.T, c *Client6) DADStats {
	t.Helper()
	for {
		if st := c.DADStats(); st.Free+st.Duplicate > 0 {
			return st
		}
		gosched.Gosched()
	}
}

// assertJournalNoteOn waits for the journal ENTRY the machine writes for one
// event kind and then asserts the sentence inside it.
//
// TWO SEPARATE THINGS, AND THE SPLIT IS THE POINT.
//
// The wait is needed because the two facts a caller reads about one Step are
// published through DIFFERENT objects: lease/manager.go sets mg.router inside
// the lock and appends the journal entry AFTER releasing it, so Router()
// reporting Seen says nothing about the entry having landed. MEASURED
// 2026-09-06: a one-shot journal read taken right after awaitRouterObservation
// failed roughly one run in three under load.
//
// The assertion is separated from the wait because a spin that waits for the
// SENTENCE never returns when the sentence is the thing that is gone. MEASURED
// 2026-09-06 with mutate.sh: deleting proto/machine6.go's §4.2 journal line
// HUNG the control for its whole timeout, and mutate.sh scores a hang as its
// own verdict and explicitly not as a kill. Waiting for the ENTRY — which the
// machine writes for every event it steps on, note or no note — and then
// reading it makes the missing sentence a named failure in the same second.
func assertJournalNoteOn(t *testing.T, c *Client6, kind proto.EventKind, want string) {
	t.Helper()
	for {
		var seen int
		for _, e := range c.Journal() {
			if e.Kind != kind {
				continue
			}
			seen++
			if strings.Contains(e.Reason, want) {
				return
			}
			for _, a := range e.Actions {
				if strings.Contains(a, want) {
					return
				}
			}
		}
		if seen > 0 {
			t.Fatalf("the journal holds %d entr(ies) for %v and none of them carries %q; the step ran and said nothing a reader could use", seen, kind, want)
		}
		gosched.Gosched()
	}
}

// TestAV6ClientOnAStatelessLinkIsConfiguredAndNotLeased is RFC 9915 section
// 18.2.6 against a real server, and design section A.3.3's interlock 1 end to
// end.
//
// THE POINT IS THE ABSENCE OF AN ADDRESS. A client that acquired one here
// would be a client that ignored what the router said: on this link addresses
// come from the prefix's autonomous flag and the DHCPv6 server has none to
// give. The event carries a configuration and no lease, and the duplicate
// check never runs, because there is nothing to check.
func TestAV6ClientOnAStatelessLinkIsConfiguredAndNotLeased(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		v6StatelessAgainstDnsmasq(t)
		return
	}
	reexecInNamespaces(t)
}

func v6StatelessAgainstDnsmasq(t *testing.T) {
	wireUpV6(t)
	srv := startDnsmasq6(t, v6Stateless)
	watch := newRAWatch(t, test6ClientIf)

	c, _ := newV6Client(t)
	stop := runV6Client(t, c)
	defer stop()

	ra := assertMode(t, srv, watch, v6Stateless)
	if ra.Managed {
		t.Fatalf("the stateless fixture set M: %s", ra)
	}

	ev := awaitV6PastTheAddressRefusal(t, c)
	if ev.Lease.Addr.IsValid() {
		t.Errorf("the Configured event carries the address %s; section 18.2.6's exchange has none", ev.Lease.Addr)
	}
	if len(ev.Config.DNS) != 1 || ev.Config.DNS[0].String() != test6ServerIP {
		t.Errorf("the configuration carries DNS %v, want [%s] — the option the fixture was given", ev.Config.DNS, test6ServerIP)
	}
	if _, held := c.Lease(); held {
		t.Error("the client holds a lease on a link whose router advertised M=0")
	}

	// The server's own record of what it answered, and of what it was asked.
	srv.waitFor(t, "DHCPINFORMATION-REQUEST("+test6ServerIf+")")
	// AND NOT "no Solicit was ever sent", which was this row's first shape
	// and is false on a real link. MEASURED: the client's first Solicit and
	// the router's advertisement cross — section 18.2.1 delays the Solicit by
	// up to SOL_MAX_DELAY and the advertisement answers a solicitation that
	// went out at the same moment — so dnsmasq logs one Solicit, answers it
	// with "no addresses available", and the switch happens after. What
	// interlock 1 guarantees is the DESTINATION, not that nothing was sent
	// first: no address is ever taken on this link.
	if n := srv.count("DHCPADVERTISE(" + test6ServerIf + ")"); n != 0 {
		t.Errorf("dnsmasq offered %d address(es) on a stateless link", n)
	}

	// Nothing was checked for duplicates because nothing was assigned. A
	// number above zero here would mean the client ran RFC 4862 section 5.4
	// against an address it does not have.
	if st := c.DADStats(); st.Started != 0 || st.Solicits != 0 {
		t.Errorf("the duplicate check ran on a link with no address to check: %+v", st)
	}
}

// TestASLAACOnlyLinkSaysThereIsNoDHCPv6 is the distinction the 1.9.0 plugin
// could not make.
//
// RFC 4861 section 4.2: "If neither M nor O flags are set, this indicates that
// no information is available via DHCPv6." A client that has acquired nothing
// on such a link has not failed and has not hit a bug — there is nothing here
// to acquire — and the ONLY thing that says so is the router observation. A
// caller with a deadline needs to tell this apart from a server that is down,
// and TestAManagedLinkWhoseServerIsSilentIsNotALinkWithoutOne is the other
// half of that pair.
func TestASLAACOnlyLinkSaysThereIsNoDHCPv6(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		v6SLAACAgainstDnsmasq(t)
		return
	}
	reexecInNamespaces(t)
}

func v6SLAACAgainstDnsmasq(t *testing.T) {
	wireUpV6(t)
	srv := startDnsmasq6(t, v6SLAAC)
	watch := newRAWatch(t, test6ClientIf)

	c, _ := newV6Client(t)
	stop := runV6Client(t, c)
	defer stop()

	ra := assertMode(t, srv, watch, v6SLAAC)

	obs := awaitRouterObservation(t, c)
	if obs.Managed != ra.Managed || obs.Other != ra.Other {
		t.Fatalf("the manager reports %s and the independent observer read %s", obs, ra)
	}
	if obs.Managed || obs.Other {
		t.Fatalf("this fixture advertises neither flag and the client reports %s", obs)
	}

	// The journal note is what a reader of a stuck client finds, and it is
	// the sentence that turns "nothing happened" into an answer. Waited for
	// rather than read: see awaitJournalNote.
	assertJournalNoteOn(t, c, proto.EvRouterAdvert, "no information is available via DHCPv6")

	if _, held := c.Lease(); held {
		t.Error("the client holds a lease on a link with no DHCPv6 service at all")
	}
	// dnsmasq in this mode serves no DHCPv6, so it logs no exchange. The
	// count is the check that the client's Solicits reached a server that
	// simply is not one, rather than that the fixture was misconfigured into
	// answering.
	if n := srv.count("DHCPREPLY(" + test6ServerIf + ")"); n != 0 {
		t.Errorf("dnsmasq answered %d Reply/Replies on a SLAAC-only link", n)
	}
}

// TestAClientOnALinkWithNoRouterStillAcquires is interlock 1 in the direction
// that would otherwise hang forever.
//
// Design section A.3.3 makes the Router Advertisement a diagnostic and never a
// precondition, and this is the link that tells the two apart: a DHCPv6 server
// with no router beside it is an ordinary container network, and a client that
// waited for an advertisement there would never acquire anything and would
// have no way to say why.
//
// THE SILENCE CHECK RUNS AFTER THE ACQUISITION AND NOT BEFORE IT, which is the
// one place in this file where the mode signature is not the first thing
// asserted. It is deliberate and it is stronger: the observer socket is still
// opened before the client, so the window is unchanged, and closing it after
// the acquisition makes the window COVER the exchange rather than precede it.
func TestAClientOnALinkWithNoRouterStillAcquires(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		v6NoRouterAgainstDnsmasq(t)
		return
	}
	reexecInNamespaces(t)
}

func v6NoRouterAgainstDnsmasq(t *testing.T) {
	wireUpV6(t)
	srv := startDnsmasq6(t, v6NoRA)
	watch := newRAWatch(t, test6ClientIf)

	c, _ := newV6Client(t)
	stop := runV6Client(t, c)
	defer stop()

	ev := awaitV6(t, c, lease.Acquired)
	addr := ev.Lease.Addr.Addr()
	srv.waitFor(t, "DHCPREPLY("+test6ServerIf+") "+addr.String())

	// And now the signature, over a window that contains the whole exchange.
	assertMode(t, srv, watch, v6NoRA)

	if obs := c.Router(); obs.Seen {
		t.Errorf("the client reports %s on a link with no router at all", obs)
	}
	if got := c.Stats().RouterAdvertsSeen; got != 0 {
		t.Errorf("RouterAdvertsSeen = %d on a link that emitted none", got)
	}
	// The solicitation still went out — section 6.3.7 asks for one whether or
	// not anybody answers — and a client that stopped sending it because the
	// last link had no router would be a client that never discovers one.
	if nd := c.NDStats(); nd.Sends == 0 {
		t.Error("no Router Solicitation left the host; RFC 4861 section 6.3.7 asks for one regardless of what answers")
	}
	assertTheCheckActuallyRan(t, c, addr)
}

// TestAManagedLinkWhoseServerIsSilentIsNotALinkWithoutOne is the other half of
// the pair TestASLAACOnlyLinkSaysThereIsNoDHCPv6 opens.
//
// Two links, one observable client behaviour: nothing is acquired. On the
// SLAAC-only link that is correct and final; here it is a server that
// advertised itself as managed and then did not answer, which is an outage a
// caller should retry through and report differently. M=1 with no lease is the
// only thing that distinguishes them, and it is why the observation is
// published at all.
func TestAManagedLinkWhoseServerIsSilentIsNotALinkWithoutOne(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		v6SilentAgainstDnsmasq(t)
		return
	}
	reexecInNamespaces(t)
}

func v6SilentAgainstDnsmasq(t *testing.T) {
	wireUpV6(t)
	srv := startDnsmasq6(t, v6ManagedSilent)
	watch := newRAWatch(t, test6ClientIf)

	c, _ := newV6Client(t)
	stop := runV6Client(t, c)
	defer stop()

	assertMode(t, srv, watch, v6ManagedSilent)

	// The server heard the client. This is what makes the silence an ANSWER
	// rather than a wire fault: a Solicit that never arrived would produce
	// the same empty client, and the log is the only place the difference
	// shows.
	srv.waitFor(t, "DHCPSOLICIT("+test6ServerIf+")")
	if n := srv.count("DHCPADVERTISE(" + test6ServerIf + ")"); n != 0 {
		t.Fatalf("dnsmasq answered %d Advertise(s); this mode is configured to ignore DHCPv6 clients and the fixture is not silent", n)
	}

	obs := awaitRouterObservation(t, c)
	if !obs.Managed {
		t.Fatalf("the client reports %s on a link whose router advertised M=1", obs)
	}
	if _, held := c.Lease(); held {
		t.Error("the client holds a lease from a server that answered nothing")
	}

	// The client is still trying, which is the behaviour the observation is
	// meant to be read alongside: section 18.2.1's Solicit is retransmitted,
	// and a caller that gave up on the first timeout would give up on a
	// server that is merely restarting.
	//
	// COUNTED IN THE SERVER'S LOG AND NOT IN THE CLIENT'S TRANSPORT. The
	// client's own counter says a second message was handed to a socket; the
	// server's log says a second message arrived. The second is the claim
	// worth making, and it is also the only one that is a barrier: reading
	// the counter needs the retransmission to have already happened, and
	// waiting for the LINE is what makes that a wait rather than a race.
	// MEASURED: the counter version failed here at Sends=1, one second before
	// the retransmission it was asserting.
	srv.waitCount(t, "DHCPSOLICIT("+test6ServerIf+")", 2,
		"a Solicit nobody answers is retransmitted (RFC 9915 section 18.2.1)")
}

// test6SoleAddr is the whole of the range the duplicate-address proof serves.
//
// One address, so the exchange is DETERMINISTIC. dnsmasq allocates from a
// range by hashing the client's DUID, and the DUID here is built from a veth
// hardware address the kernel invents at random on every run — so a test that
// needed to know the address in advance could not, unless the range holds
// exactly one.
const test6SoleAddr = "fd00:99::100"

// TestADuplicateAddressOnTheLinkIsDeclined is RFC 4862 section 5.4 against a
// real neighbour, and it is the proof that says the whole duplicate check
// works rather than merely runs.
//
// THE SECOND HOLDER IS THE KERNEL AT THE OTHER END OF THE VETH, which is what
// makes this evidence rather than a fixture answering itself. The address
// dnsmasq is about to hand out is installed on the server end first, so that
// kernel — a real RFC 4861 section 7.2.4 implementation, not this library —
// answers the client's Neighbor Solicitation with a Neighbor Advertisement for
// the target. Section 5.4.4: "If the target address is tentative, the
// tentative address is not unique."
//
// EVERY OTHER v6 PROOF IN THIS FILE WOULD PASS WITH THE CHECK DELETED. That is
// what this one is for: on an empty link every address is free, so a runner
// that reported free without sending anything is indistinguishable from a
// correct one. Here the answer must come back Duplicate, and the client must
// then do what RFC 9915 section 18.2.10.1 makes a MUST — send a Decline, which
// dnsmasq logs.
func TestADuplicateAddressOnTheLinkIsDeclined(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		v6DuplicateAgainstDnsmasq(t)
		return
	}
	reexecInNamespaces(t)
}

func v6DuplicateAgainstDnsmasq(t *testing.T) {
	wireUpV6(t)

	// THE HOLDER, INSTALLED BEFORE THE CLIENT EXISTS. accept_dad is already
	// off on this link (see wireUpV6), so the address is usable immediately
	// and the kernel begins answering for it at once; with the kernel's own
	// check on, the address would sit tentative and — section 5.4's "a node
	// MUST NOT respond to a Neighbor Solicitation for a tentative address" —
	// answer nothing, which is the shape of a test that proves the opposite
	// of what it says.
	mustRun(t, "ip", "-6", "addr", "add", test6SoleAddr+"/"+fmt.Sprint(test6PrefixLn), "dev", test6ServerIf)

	iface, err := net.InterfaceByName(test6ClientIf)
	if err != nil {
		t.Fatalf("InterfaceByName(%s): %v", test6ClientIf, err)
	}

	// --dhcp-host, AND NOT THE RANGE ALONE, BECAUSE OF WHAT DNSMASQ DOES
	// WITH ITS OWN ADDRESSES. Measured: with only the one-address range the
	// server answered "DHCPADVERTISE(v6srv0) ... no addresses available",
	// because dnsmasq 2.91 src/dhcp6.c address6_allocate() skips the
	// address it holds itself —
	//
	//	/* eliminate addresses in use by the server. */
	//	for (d = context; d; d = d->current)
	//	  if (addr == addr6part(&d->local6))
	//	    break;
	//
	// — and the holder installed above IS on dnsmasq's interface, which is
	// the only place on a two-ended veth where a second node can hold it.
	// The configured-address path (src/rfc3315.c config_valid(), reached
	// from "Suggest configured address(es)") has no such test, so a
	// --dhcp-host offers the address anyway. The client cannot tell the two
	// paths apart: the same address arrives in the same IA_NA.
	held := v6Managed
	held.args = []string{
		"--dhcp-range=" + test6SoleAddr + "," + test6SoleAddr + ",64," + fmt.Sprint(test6LeaseSec),
		"--dhcp-host=" + iface.HardwareAddr.String() + ",[" + test6SoleAddr + "]",
		"--enable-ra",
	}
	held.ready = "DHCPv6, IP range " + test6SoleAddr
	srv := startDnsmasq6(t, held)
	watch := newRAWatch(t, test6ClientIf)

	c, _ := newV6Client(t)
	stop := runV6Client(t, c)
	defer stop()

	assertMode(t, srv, watch, held)

	// The server offered the one address it has, and the client asked for it.
	srv.waitFor(t, "DHCPREPLY("+test6ServerIf+") "+test6SoleAddr)

	// THE RUNNER'S FIRST VERDICT, read before any barrier that depends on it.
	// Every wait below — the Decline, the address line, the counters — assumes
	// the check came back "duplicate", and a runner that answered "free"
	// without waiting out RFC 4862 section 5.4.2's schedule would leave all of
	// them waiting for a message the client has no reason to send. Asserting
	// the verdict HERE is what makes that a named failure instead of a
	// timeout: see awaitDADVerdict.
	if v := awaitDADVerdict(t, c); v.Duplicate != 1 || v.Free != 0 {
		t.Fatalf("the runner's first verdict on %s was Free=%d Duplicate=%d, want a duplicate: another node on this link answers for that address, so a free verdict is one reported before the check ran",
			test6SoleAddr, v.Free, v.Duplicate)
	}

	// AND THEN DECLINED IT. This is the assertion: a Decline gets no reply,
	// is not retransmitted, and changes no state the client can read back, so
	// the server's log is the only place it is visible at all. See
	// TestDeclineAndReleaseReachRealDnsmasq for the v4 statement of the same
	// argument.
	srv.waitFor(t, "DHCPDECLINE("+test6ServerIf+")")

	// AND THE DECLINE NAMED THE ADDRESS. dnsmasq's DHCPDECLINE line carries
	// only the DUID, so on its own it would still be there if the client had
	// declined an empty IA_NA. This second line is written from the IA
	// Address option inside the message dnsmasq just parsed (2.91
	// src/rfc3315.c: "disabling DHCP static address %s for %s", reached only
	// when config_implies() matches the declined address), so it is the
	// address that travelled on the wire and not one this test supplied.
	srv.waitFor(t, "disabling DHCP static address "+test6SoleAddr)

	if l, ok := c.Lease(); ok {
		t.Errorf("the client holds %s, an address another node on this link answers for", l.Addr)
	}

	st := c.DADStats()
	if st.Duplicate != 1 {
		t.Errorf("DADStats.Duplicate = %d, want 1: %+v", st.Duplicate, st)
	}
	if st.Free != 0 {
		t.Errorf("DADStats.Free = %d; the address is held by the node at the other end of the veth", st.Free)
	}
	if st.Adverts == 0 {
		t.Errorf("DADStats.Adverts = 0: the verdict did not come from a Neighbor Advertisement, so it came from somewhere this test did not arrange — %+v", st)
	}
	if st.Solicits < proto.DupAddrDetectTransmits {
		t.Errorf("DADStats.Solicits = %d; nothing was asked (RFC 4862 section 5.4.2)", st.Solicits)
	}
	// The exclusion of this host's own frames did not fire, which is what
	// makes the duplicate above another node's answer and not our own
	// solicitation misread. See NDSocket's BOUNDS for why this is zero here.
	if st.OwnIgnored != 0 {
		t.Errorf("DADStats.OwnIgnored = %d on a link that does not echo", st.OwnIgnored)
	}
	if got := c.Stats().DADConflicts; got != 1 {
		t.Errorf("Stats.DADConflicts = %d, want 1; ring 2 did not record the conflict ring 3 found", got)
	}
}

// test6HintedAddr and test6SubstituteAddr are the two-address range the
// declined-hint proof runs on, and the first of them is the one another node
// on the link already holds.
//
// TWO ADDRESSES AND NOT ONE, because the proof is that the client ends up
// somewhere else: with a single-address range a client that had learned
// nothing from its Decline and a client that had learned everything would both
// end up with no lease, and the log would look the same either way.
const (
	test6HintedAddr     = "fd00:99::1a0"
	test6SubstituteAddr = "fd00:99::1a1"
)

// TestADeclinedHintIsNotAskedForAgain is the wire proof for the loop RFC 9915
// §18.2.10.1 forbids and §18.2.1's hint makes easy to write.
//
// §18.2.1 makes the hint a MAY: "The client MAY include addresses in the IA as
// a hint to the server about the addresses for which the client has a
// preference." Nothing there says what to do with that preference after the
// address turns out to be in use, and §18.2.10.1 says only that the client
// "MUST restart the DHCP configuration process" — so a machine that restarts
// with the same preference restarts into the same address.
//
// THIS IS MEASURED BEHAVIOUR AND NOT A READING. Plugin lane run 34058213252
// recorded 16 acquisition rounds in 16 seconds against a real server: hint,
// offer, duplicate, Decline, hint again. The middle of that loop is dnsmasq
// 2.91 and it is not a bug in it — src/rfc3315.c's SOLICIT arm honours a
// requested IAADDR through address6_valid/address6_available before it ever
// reaches address6_allocate, and its DECLINE arm blacklists only CONFIGURED
// addresses (ADDRLIST_DECLINED); for a range address it bumps addr_epoch,
// which changes where the NEXT ALLOCATION starts and has no effect at all on
// an address the client asks for by name.
//
// SO THE FIXTURE PUTS THOSE TWO PATHS ON DIFFERENT ADDRESSES. The squatted
// address sits on the SERVER's end of the veth — the only place a second node
// can hold it — which makes it dnsmasq's own local6, and dhcp6.c's
// address6_allocate skips it:
//
//	/* eliminate addresses in use by the server. */
//	for (d = context; d; d = d->current)
//	  if (addr == addr6part(&d->local6))
//	    break;
//
// address6_available has no such test. So the hinted address is reachable
// ONLY by asking for it, and every offer of it in this log is one this client
// asked for. That is what makes the decline count evidence about the client.
//
// THE COUNT IS READ ON THE WIRE, from dnsmasq's log, and the second decline is
// a NAMED FAILURE rather than a timeout: with the defect the client never
// acquires anything, so a test that only waited for the acquisition would hang
// until the child's own deadline and report "slow" where the finding is "it
// asked again".
func TestADeclinedHintIsNotAskedForAgain(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		v6DeclinedHintAgainstDnsmasq(t)
		return
	}
	reexecInNamespaces(t)
}

func v6DeclinedHintAgainstDnsmasq(t *testing.T) {
	wireUpV6(t)

	// THE SQUATTER, INSTALLED BEFORE THE CLIENT EXISTS, for the reason
	// v6DuplicateAgainstDnsmasq gives: accept_dad is already off on this link,
	// so the kernel answers for the address at once instead of leaving it
	// tentative and — RFC 4862 §5.4 — answering nothing.
	mustRun(t, "ip", "-6", "addr", "add", test6HintedAddr+"/"+fmt.Sprint(test6PrefixLn), "dev", test6ServerIf)

	twoAddrs := v6Managed
	twoAddrs.args = []string{
		"--dhcp-range=" + test6HintedAddr + "," + test6SubstituteAddr + ",64," + fmt.Sprint(test6LeaseSec),
		"--enable-ra",
	}
	twoAddrs.ready = "DHCPv6, IP range " + test6HintedAddr
	srv := startDnsmasq6(t, twoAddrs)
	watch := newRAWatch(t, test6ClientIf)

	// THE HINT IS THE SUBJECT. It is the caller's remembered preference: an
	// address this container held before, or one an operator asked for.
	c, _ := newV6ClientWith(t, func(p *proto.Params6) {
		p.Hint = netip.MustParseAddr(test6HintedAddr)
	})
	stop := runV6Client(t, c)
	defer stop()

	assertMode(t, srv, watch, twoAddrs)

	// ---------------------------------------------- the hinted pass --
	//
	// The server offered the address this client asked for by name, which is
	// the precondition of everything below: without this line the decline
	// count is a count of nothing.
	srv.waitFor(t, "DHCPREPLY("+test6ServerIf+") "+test6HintedAddr)
	if v := awaitDADVerdict(t, c); v.Duplicate != 1 || v.Free != 0 {
		t.Fatalf("the runner's first verdict on %s was Free=%d Duplicate=%d, want a duplicate: the other end of this veth holds that address",
			test6HintedAddr, v.Free, v.Duplicate)
	}
	srv.waitFor(t, "DHCPDECLINE("+test6ServerIf+")")

	// ------------------------------------------- and the pass after it --
	//
	// Whichever comes first: the substitute address being leased, or a SECOND
	// decline. The second decline is the defect, and naming it here is what
	// keeps the defect a failure instead of a deadline.
	declineLine := "DHCPDECLINE(" + test6ServerIf + ")"
	leasedSubstitute := "DHCPREPLY(" + test6ServerIf + ") " + test6SubstituteAddr
	for {
		if n := srv.count(declineLine); n > 1 {
			t.Fatalf("the client sent %d Declines: it asked for %s again after declining it, which is RFC 9915 §18.2.10.1's restart walking back into the same address.\nServer log:\n%s",
				n, test6HintedAddr, strings.Join(srv.lines(), "\n"))
		}
		if containsLine(srv.lines(), leasedSubstitute) {
			break
		}
		if _, ok := <-srv.arrived; !ok {
			t.Fatalf("dnsmasq exited before leasing %s.\nServer log:\n%s", test6SubstituteAddr, strings.Join(srv.lines(), "\n"))
		}
	}

	// The client's own view, read after the wire and never instead of it.
	//
	// NOT awaitV6, WHICH FAILS ON A Failed EVENT. This client reports one on
	// purpose — §18.2.10.1's conflict, the reason it declined — so the wait
	// here counts those instead of tripping on the first, and it still refuses
	// a Failed that is anything else. A SECOND conflict would mean the second
	// pass had found a duplicate too, which on this fixture can only be the
	// declined address coming back.
	conflicts := 0
	var ev lease.Event
	for e := range c.Events() {
		t.Logf("client event: %s", e)
		if e.Kind == lease.Failed {
			if e.Reason != proto.ReasonConflict {
				t.Fatalf("the client failed while waiting for acquired: %s", e)
			}
			conflicts++
			if conflicts > 1 {
				t.Fatalf("the client reported %d conflicts; on this fixture only %s is held, so the second pass asked for it again.\nServer log:\n%s",
					conflicts, test6HintedAddr, strings.Join(srv.lines(), "\n"))
			}
			continue
		}
		if e.Kind == lease.Acquired {
			ev = e
			break
		}
	}
	if ev.Kind != lease.Acquired {
		t.Fatalf("the event channel closed before anything was acquired.\nServer log:\n%s", strings.Join(srv.lines(), "\n"))
	}
	if conflicts != 1 {
		t.Errorf("the client reported %d conflicts, want the one it declined", conflicts)
	}
	got := ev.Lease.Addr.Addr().String()
	if got == test6HintedAddr {
		t.Fatalf("the client bound %s, the address it had just declined", got)
	}
	if got != test6SubstituteAddr {
		t.Fatalf("the client bound %s; this range holds only %s and %s", got, test6HintedAddr, test6SubstituteAddr)
	}

	// AT MOST ONE DECLINE FOR THE HINTED PASS. Read last, over the whole log,
	// so it is a statement about the run and not about the moment the loop
	// above happened to stop.
	if n := srv.count(declineLine); n != 1 {
		t.Fatalf("the server logged %d Declines, want exactly 1.\nServer log:\n%s", n, strings.Join(srv.lines(), "\n"))
	}
	if st := c.Stats(); st.DeclinesSent != 1 {
		t.Errorf("Stats.DeclinesSent = %d, want 1: %+v", st.DeclinesSent, st)
	}
	// One duplicate and one free: the second check RAN and came back clean,
	// so the substitute address was not bound past a check that never
	// happened.
	if st := c.DADStats(); st.Duplicate != 1 || st.Free != 1 {
		t.Errorf("DADStats = %+v, want one duplicate (%s) and one free (%s)", st, test6HintedAddr, test6SubstituteAddr)
	}
}

// TestAV6ReleaseReachesRealDnsmasq is RFC 9915 section 18.2.7 against a server
// that writes down what it received.
//
// A Release is answered with a Reply the client does not wait for, is not
// retransmitted past its own limit, and leaves the client's own state
// identical to a client that simply stopped. So a Release that was malformed,
// misaddressed or never sent produces exactly the observable behaviour of a
// correct one, and every assertion this library could make about it on its own
// would be an assertion about its own opinion. dnsmasq's log is not.
func TestAV6ReleaseReachesRealDnsmasq(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		v6ReleaseAgainstDnsmasq(t)
		return
	}
	reexecInNamespaces(t)
}

func v6ReleaseAgainstDnsmasq(t *testing.T) {
	wireUpV6(t)

	// ONE ADDRESS IN THE WHOLE RANGE, so that "the server took the release"
	// and "the server did not" are two DIFFERENT log lines rather than a line
	// and a silence. dnsmasq logs DHCPRELEASE with the client's DUID and no
	// address (2.91 src/rfc3315.c: log6_quiet(state, "DHCPRELEASE", NULL,
	// NULL)), so that line alone cannot say WHICH binding was given back —
	// and a Release that named the wrong address, or carried an empty IA_NA,
	// produces exactly it.
	sole := v6Managed
	sole.args = []string{
		"--dhcp-range=" + test6SoleAddr + "," + test6SoleAddr + ",64," + fmt.Sprint(test6LeaseSec),
		"--enable-ra",
	}
	sole.ready = "DHCPv6, IP range " + test6SoleAddr
	srv := startDnsmasq6(t, sole)
	watch := newRAWatch(t, test6ClientIf)

	c, _ := newV6Client(t)
	stop := runV6Client(t, c)
	defer stop()

	assertMode(t, srv, watch, sole)
	ev := awaitV6(t, c, lease.Acquired)
	addr := ev.Lease.Addr.Addr()
	if addr.String() != test6SoleAddr {
		t.Fatalf("the client leased %s from a range that holds only %s", addr, test6SoleAddr)
	}
	srv.waitFor(t, "DHCPREPLY("+test6ServerIf+") "+test6SoleAddr)

	c.Release()

	// The caller is told. A Release ends the lease, so the outward event is
	// Lost with proto.ReasonReleased — the reason is what separates it from a
	// lease that expired or was withdrawn under the caller.
	rel := awaitV6(t, c, lease.Lost)
	if rel.Reason != proto.ReasonReleased {
		t.Errorf("Lost reason = %v, want %v", rel.Reason, proto.ReasonReleased)
	}
	if _, ok := c.Lease(); ok {
		t.Error("the client still holds a lease it released")
	}

	// The server received it.
	srv.waitFor(t, "DHCPRELEASE("+test6ServerIf+")")
	stop()

	// AND UNDERSTOOD WHICH BINDING IT WAS, which is the half the DHCPRELEASE
	// line cannot carry. A SECOND client, a different DUID, the same one-
	// address range: dnsmasq can only offer that address to it if the first
	// client's binding is gone (src/dhcp6.c address6_allocate skips an address
	// lease6_find_by_addr still finds).
	second, err := newV6ClientAs(test6ClientIf, net.HardwareAddr{0x02, 0x00, 0x5e, 0x99, 0x00, 0x02})
	if err != nil {
		t.Fatalf("building the second client: %v", err)
	}
	stopSecond := runV6Client(t, second)
	defer stopSecond()

	// THE BARRIER IS THE ADVERTISE, NOT THE ADDRESS, and that is deliberate:
	// dnsmasq logs a DHCPADVERTISE either way — with the address when it has
	// one to give and with "no addresses available" when it does not — so a
	// Release the server did not act on FAILS here with the server's own
	// sentence in the message instead of hanging on a line that never comes.
	srv.waitCount(t, "DHCPADVERTISE("+test6ServerIf+")", 2,
		"the second client's Advertise, which dnsmasq logs whether or not it has an address left")

	var last string
	for _, l := range srv.lines() {
		if strings.Contains(l, "DHCPADVERTISE("+test6ServerIf+")") {
			last = l
		}
	}
	if !strings.Contains(last, test6SoleAddr) {
		t.Fatalf("dnsmasq answered the second client with %q; the only address in the range is still bound to the client that released it", last)
	}

	got := awaitV6(t, second, lease.Acquired)
	if got.Lease.Addr.Addr().String() != test6SoleAddr {
		t.Errorf("the second client leased %s, want the released %s", got.Lease.Addr, test6SoleAddr)
	}
}

// newV6ClientAs builds a client whose DUID is derived from a hardware address
// this test chose rather than from the interface's own.
//
// It is how a second identity is put on one link without a second link: RFC
// 9915 section 11 keys a binding on the DUID, and dnsmasq does the same, so a
// client built this way is a different client to the server while sharing the
// interface, the link-local source address and the namespace.
func newV6ClientAs(ifName string, hw net.HardwareAddr) (*Client6, error) {
	duid, err := wire.DUIDLL(wire.ARPHTypeEthernet, hw)
	if err != nil {
		return nil, err
	}
	p := proto.DefaultParams6()
	p.DUID = duid
	p.IAID = 0x0a0b0c0d
	p.ORO = proto.DefaultORO()
	return NewClient6(ClientConfig6{Interface: ifName, Params6: p, EventBuffer: 8})
}

// TestAResumedV6LeaseConfirmsAgainstRealDnsmasq is RFC 9915 section 18.2.3
// end to end: a client that starts holding a binding from a PREVIOUS run asks
// whether it is still on the right link, instead of soliciting a new address.
//
// THE POINT IS THE FIRST MESSAGE ON THE WIRE. A resumed client that solicited
// would get a second address while the first one is still leased to it, which
// on a container host is how a restart doubles a pool's consumption. Section
// 18.2.3's Confirm asks the question without taking anything, and the only
// place the difference is visible is the server's log — so that is what this
// reads, and it reads the ABSENCE of a Solicit beside the presence of a
// Confirm.
func TestAResumedV6LeaseConfirmsAgainstRealDnsmasq(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		v6ResumeAgainstDnsmasq(t)
		return
	}
	reexecInNamespaces(t)
}

func v6ResumeAgainstDnsmasq(t *testing.T) {
	wireUpV6(t)
	srv := startDnsmasq6(t, v6Managed)
	watch := newRAWatch(t, test6ClientIf)

	// ------------------------------------------------- the first run --
	first, _ := newV6Client(t)
	stopFirst := runV6Client(t, first)
	assertMode(t, srv, watch, v6Managed)
	ev := awaitV6(t, first, lease.Acquired)
	held := ev.Lease
	addr := held.Addr.Addr()
	srv.waitFor(t, "DHCPREPLY("+test6ServerIf+") "+addr.String())
	stopFirst()

	solicitsBefore := srv.count("DHCPSOLICIT(" + test6ServerIf + ")")

	// ------------------------------------------------ the second run --
	//
	// A new client, the SAME identity — the DUID is derived from the
	// interface's hardware address, which has not changed — carrying the
	// binding the first one held.
	iface, err := net.InterfaceByName(test6ClientIf)
	if err != nil {
		t.Fatalf("InterfaceByName(%s): %v", test6ClientIf, err)
	}
	duid, err := wire.DUIDLL(wire.ARPHTypeEthernet, iface.HardwareAddr)
	if err != nil {
		t.Fatalf("DUIDLL: %v", err)
	}
	p := proto.DefaultParams6()
	p.DUID = duid
	p.IAID = 0x0a0b0c0d
	p.ORO = proto.DefaultORO()

	second, err := NewClient6(ClientConfig6{
		Interface: test6ClientIf, Params6: p, EventBuffer: 8, Resume: &held,
	})
	if err != nil {
		t.Fatalf("NewClient6 with a resumed lease: %v", err)
	}
	stopSecond := runV6Client(t, second)
	defer stopSecond()

	srv.waitFor(t, "DHCPCONFIRM("+test6ServerIf+")")

	// THE ABSENCE, and it is the half that would still pass if Resume were
	// ignored entirely. A resumed client that solicited would show a Solicit
	// count above the one the first run left behind.
	if n := srv.count("DHCPSOLICIT(" + test6ServerIf + ")"); n != solicitsBefore {
		t.Errorf("dnsmasq logged %d Solicit(s), was %d before the resume: a resumed client asks with a Confirm (section 18.2.3) and takes nothing new",
			n, solicitsBefore)
	}

	// And the binding survives: the server says the link is the right one and
	// the client keeps the address it came with.
	got := awaitV6(t, second, lease.Acquired)
	if got.Lease.Addr.Addr() != addr {
		t.Errorf("the resumed client ended up with %s, want the address it came in holding, %s", got.Lease.Addr, addr)
	}
}

// nsBuild6 is what the locked goroutine hands back before its thread dies.
type nsBuild6 struct {
	client *Client6
	server *dnsmasqServer
	watch  *raWatch
	// tid is the thread the build actually ran on. It is carried because
	// whether it is the thread group leader used to DECIDE the outcome of
	// the proof below without appearing in it: see that test's comment.
	tid int
	err error
}

// TestTheV6ClientKeepsTheNamespaceItWasBuiltIn is NewClient6's contract, and it
// is the v6 twin of TestTheClientKeepsTheNamespaceItWasBuiltIn.
//
// IT IS A SEPARATE TEST AND NOT A PARAMETER OF THE v4 ONE, because it is a
// claim about THREE sockets rather than two. NewClient6 opens the DHCPv6
// transport, the Neighbor Discovery socket and — through it — the
// solicited-node multicast join, all in the calling goroutine's namespace, and
// the failure this guards against is the one that looks like success: a client
// whose transport is on the container's link and whose Neighbor Discovery is
// on the host's would run duplicate address detection that sees nothing, and
// would report every address free.
//
// THE CONTROL IS THE HALF THAT MATTERS. The goroutine that runs the client was
// never in the namespace and cannot see the interface; if it could, the
// acquisition below would prove nothing about where the sockets live.
//
// THIS PROOF USED TO PASS FOR A REASON IT DID NOT STATE, and the thread it
// reports below is that reason. Until M7c's thread round the client's
// link-local address came from /proc/net/if_inet6, which the kernel resolves
// against the THREAD GROUP LEADER's network namespace and not the calling
// thread's, so this test measured the sockets correctly and the address only
// when the scheduler happened to put the locked goroutine on the leader
// thread. On this box it did; on a two-core CI runner it did not, about half
// the time, and the failure read as a slow kernel. The thread is now REPORTED
// here — it is not asserted, because either value is now correct — and it is
// ASSERTED in TestTheV6ClientReadsTheLinkLocalOfTheThreadItWasBuiltOn, which
// is that half of the claim driven on purpose.
func TestTheV6ClientKeepsTheNamespaceItWasBuiltIn(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		v6NamespaceCaptureAgainstDnsmasq(t)
		return
	}
	reexecInNamespaces(t)
}

func v6NamespaceCaptureAgainstDnsmasq(t *testing.T) {
	// The outer namespace is the re-exec's own, and it is EMPTY: nothing
	// creates the link here.
	if _, err := net.InterfaceByName(test6ClientIf); err == nil {
		t.Fatalf("%s already exists in the outer namespace, so the control below cannot fail", test6ClientIf)
	}

	built := make(chan nsBuild6, 1)
	go func() {
		var out nsBuild6
		// Deferred, so a t.Fatalf inside — which unwinds this goroutine with
		// runtime.Goexit — still delivers the result and the test fails with
		// its own message rather than hanging on this channel.
		defer func() { built <- out }()

		// LOCKED AND NEVER UNLOCKED, for the reason the v4 twin gives: the
		// unshare below changes the network namespace of THIS THREAD, and
		// returning while still locked makes the runtime terminate the
		// thread, so no thread of ours is left in that namespace.
		gosched.LockOSThread()
		out.tid = syscall.Gettid()

		if err := syscall.Unshare(syscall.CLONE_NEWNET); err != nil {
			out.err = fmt.Errorf("unshare(CLONE_NEWNET): %w", err)
			return
		}

		wireUpV6(t)
		out.server = startDnsmasq6(t, v6Managed)
		out.watch = newRAWatch(t, test6ClientIf)

		c, _, err := newV6ClientErr(test6ClientIf)
		if err != nil {
			out.err = fmt.Errorf("NewClient6 inside the namespace: %w", err)
			return
		}
		out.client = c
	}()

	res := <-built
	leader := "not the thread group leader"
	if res.tid == os.Getpid() {
		leader = "the thread group leader, which is what used to decide this proof"
	}
	t.Logf("the namespaced build ran on thread %d of process %d: %s", res.tid, os.Getpid(), leader)
	if res.err != nil {
		t.Fatal(res.err)
	}
	if res.client == nil {
		t.Fatal("the namespaced build produced no client; see the failure above")
	}

	// THE CONTROL.
	if iface, err := net.InterfaceByName(test6ClientIf); err == nil {
		t.Fatalf("%s is visible from the goroutine that runs the client (index %d): the client was not built in a namespace of its own",
			test6ClientIf, iface.Index)
	} else {
		t.Logf("control: %s is invisible here (%v)", test6ClientIf, err)
	}

	// An ORDINARY goroutine: no lock, no namespace, any thread the scheduler
	// picks. The sockets are what carry the namespace.
	stop := runV6Client(t, res.client)
	defer stop()

	assertMode(t, res.server, res.watch, v6Managed)
	ev := awaitV6(t, res.client, lease.Acquired)
	addr := ev.Lease.Addr.Addr()
	res.server.waitFor(t, "DHCPREPLY("+test6ServerIf+") "+addr.String())

	// ALL THREE SOCKETS ARE IN THAT NAMESPACE, not just the one that carried
	// the lease. The Router Solicitation and the duplicate-address
	// solicitations went out of the ND socket, and dnsmasq — which lives only
	// inside the namespace — logged the first of them.
	res.server.waitFor(t, "RTR-SOLICIT("+test6ServerIf+")")
	assertTheCheckActuallyRan(t, res.client, addr)
	t.Logf("the client built inside a namespace this goroutine cannot enter leased %s", addr)
}

// newV6ClientErr is newV6Client without the *testing.T, for the one caller
// that runs on a goroutine whose failures must travel back over a channel
// rather than through t.Fatalf.
func newV6ClientErr(ifName string) (*Client6, net.HardwareAddr, error) {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return nil, nil, err
	}
	duid, err := wire.DUIDLL(wire.ARPHTypeEthernet, iface.HardwareAddr)
	if err != nil {
		return nil, nil, err
	}
	p := proto.DefaultParams6()
	p.DUID = duid
	p.IAID = 0x0a0b0c0d
	p.ORO = proto.DefaultORO()
	c, err := NewClient6(ClientConfig6{Interface: ifName, Params6: p, EventBuffer: 8})
	return c, iface.HardwareAddr, err
}

// ------------------------------------- the thread the client is built on --

// nonLeaderThreadAttempts bounds the hunt for a thread that is NOT this
// process's thread group leader.
//
// It can be small, and it is not a retry-until-lucky loop: an attempt that
// finds itself on the leader keeps that thread, locked and parked on a
// channel, so the runtime cannot hand the same thread to the next attempt —
// the Go runtime parks a locked goroutine's thread with it rather than
// running other goroutines there. MEASURED 2026-09-06 with a probe in this
// shape: attempt 0 was the leader and attempt 1 was not, in 3 runs of 3.
const nonLeaderThreadAttempts = 8

// runOnANonLeaderLockedThread runs body on a goroutine locked to a thread
// whose gettid() is not this process's pid, and returns body's error.
//
// IT FAILS RATHER THAN SKIPPING when it cannot get such a thread: a proof
// that quietly measures nothing when the scheduler does not cooperate is the
// shape this whole subject exists to remove.
//
// body may call t.Fatalf. The delivery is deferred, so the runtime.Goexit
// that t.Fatalf performs on this goroutine still hands a result back rather
// than leaving the caller on the channel until the child's own timeout.
func runOnANonLeaderLockedThread(body func(tid int) error) error {
	done := make(chan error, 1)
	release := make(chan struct{})
	defer close(release)

	var attempt func(n int)
	attempt = func(n int) {
		go func() {
			gosched.LockOSThread()
			tid := syscall.Gettid()
			if tid != os.Getpid() {
				var out error
				defer func() { done <- out }()
				out = body(tid)
				return
			}
			if n+1 >= nonLeaderThreadAttempts {
				done <- fmt.Errorf("all %d locked goroutines landed on the thread group leader (%d): this proof cannot be made on this scheduler, and it does not skip", nonLeaderThreadAttempts, tid)
				return
			}
			attempt(n + 1)
			<-release
		}()
	}
	attempt(0)
	return <-done
}

// TestTheV6ClientReadsTheLinkLocalOfTheThreadItWasBuiltOn is the defect the
// CI runner showed and the reason it is a PRODUCT defect rather than a slow
// test.
//
// WHAT IS WRONG WITH READING /proc/net. The kernel resolves /proc/net — and
// /proc/self/net, which it is a symlink to — against the THREAD GROUP
// LEADER's network namespace, not the calling thread's
// (fs/proc/proc_net.c, get_proc_task_net, which takes pid_task on the tgid).
// Every other namespace-bearing thing this package opens is a socket or a
// netlink dump on the CALLING thread. So a client built on a locked
// goroutine that has entered another namespace — which is exactly what the
// plugin's chassis does, and what TestTheV6ClientKeepsTheNamespaceItWasBuiltIn
// does one unshare deeper — read its link-local address out of a different
// namespace from the one its sockets are bound in.
//
// MEASURED 2026-09-06 on a probe in this shape: from a locked non-leader
// thread that had unshared, /proc/net/if_inet6 and /proc/self/net/if_inet6
// listed 0 rows for the new interface while /proc/thread-self/net/if_inet6
// and /proc/<pid>/task/<tid>/net/if_inet6 listed 1, flags 0xc0 settling to
// 0x80. Three runs of three, both at +100ms and at +2.4s.
//
// THE DECOY IS WHAT MAKES THIS PROOF STRONGER THAN A REFUSAL, and it is the
// shape the chassis would have met first. The leader's namespace here holds
// an interface with the SAME NAME and its own link-local address, so a read
// that lands there does not fail to find an address — it finds the wrong one
// and the client sends from it, soliciting on one link and claiming an
// address off another. The refusal shape ("0 tentative, 0 failed duplicate
// address detection") is the one the runner happened to show, because no
// interface of that name existed outside.
//
// THE FIXTURE READS THE ADDRESS BY A DIFFERENT MECHANISM FROM THE SUBJECT:
// clientLinkLocal reads the kernel's text file for the calling thread's
// namespace, and InterfaceLinkLocal asks netlink. An observation taken with
// the function under test would agree with it by construction.
func TestTheV6ClientReadsTheLinkLocalOfTheThreadItWasBuiltOn(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		v6LinkLocalComesFromTheCallingThread(t)
		return
	}
	reexecInNamespaces(t)
}

func v6LinkLocalComesFromTheCallingThread(t *testing.T) {
	wireUpV6Link(t, v6LinkReady)

	var (
		client *Client6
		inner  string
		tid    int
	)
	if err := runOnANonLeaderLockedThread(func(id int) error {
		tid = id
		if err := syscall.Unshare(syscall.CLONE_NEWNET); err != nil {
			return fmt.Errorf("unshare(CLONE_NEWNET): %w", err)
		}
		wireUpV6Link(t, v6LinkReady)
		c, _, err := newV6ClientErr(test6ClientIf)
		if err != nil {
			return fmt.Errorf("NewClient6 on thread %d: %w", id, err)
		}
		client = c
		addr, _, ok := clientLinkLocal(t)
		if !ok {
			return fmt.Errorf("the kernel lists no link-local for %s in this thread's own namespace, although the client was built with %s", test6ClientIf, c.Source())
		}
		inner = addr
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if client == nil {
		t.Fatal("the build on the non-leader thread produced no client; see the failure above")
	}

	// THE THREAD IS THE PRECONDITION, asserted after the fact because it is
	// the whole reason this proof differs from the one above it.
	if tid == os.Getpid() {
		t.Fatalf("the client was built on thread %d, which IS the thread group leader: /proc/net would have answered for the right namespace by coincidence and this proof would measure nothing", tid)
	}

	decoy, _, ok := clientLinkLocal(t)
	if !ok {
		t.Fatalf("the %s in the leader's namespace carries no link-local address; this proof needs one for a leader-namespace read to take by mistake", test6ClientIf)
	}
	if decoy == inner {
		t.Fatalf("the two namespaces' %s carry the same link-local %s, so which one the client read cannot be told apart", test6ClientIf, decoy)
	}

	got := hex.EncodeToString(client.Source().AsSlice())
	if got == decoy {
		t.Fatalf("the client built on thread %d (leader %d) sends from %s, which is the link-local of the SAME-NAMED interface in the LEADER's namespace. Its sockets are bound in its own thread's namespace, so it would solicit on one link and send from an address off another",
			tid, os.Getpid(), client.Source())
	}
	if got != inner {
		t.Fatalf("the client sends from %s; the kernel holds %s for %s in the namespace the client was built in, and %s in the leader's", got, inner, test6ClientIf, decoy)
	}
	t.Logf("built on thread %d of process %d: it took %s from its own namespace and not the leader's %s", tid, os.Getpid(), client.Source(), decoy)
}

// ------------------------------------------ the kernel's own link-local --

// TestAV6ClientWaitsForTheKernelToAssignTheLinkLocalAddress is the runner's
// defect, driven.
//
// MEASURED here, on a real link: InterfaceLinkLocal read the kernel's address
// list ONCE and nothing waited, so a client built the instant the link came up
// asked a question about an interface the kernel had not finished configuring
// and got the answer that belongs to an interface which will never have an
// address. RFC 4862 section 5.4's tentative window is one to two seconds wide
// at Linux's defaults and it is real; this proof crosses it.
//
// WHAT THIS TEST IS NOT. It was written for a CI runner's refusal — "v6cli0
// (0 tentative, 0 failed duplicate address detection)" on a two-core box while
// dnsmasq in the same namespace was already bound — and that refusal is NOT
// what this test drives. It was the OTHER namespace's address list being read,
// and it is driven by TestTheV6ClientReadsTheLinkLocalOfTheThreadItWasBuiltOn.
// The wait below still earns its place, on its own measurement rather than on
// that one.
//
// THE ADDRESS IS UNUSABLE WHEN THE CONSTRUCTOR STARTS, AND THAT IS ASSERTED
// AND NOT ASSUMED. This is the one proof in this file that leaves the kernel's
// own duplicate address detection ON at the client end, so the link-local is
// tentative for RFC 4862 section 5.4's window — one to two seconds at Linux's
// defaults, which is a thousand times the width of the race a channel handshake
// would have left. The state is read out of /proc immediately before the
// client is built and immediately after, so the proof is that the CONSTRUCTOR
// crossed the window, not that the window existed.
//
// Which of the two unusable states it starts in does not matter and both are
// accepted: tentative or not yet written. readLinkLocal refuses both the same
// way and the wait repeats the same question.
func TestAV6ClientWaitsForTheKernelToAssignTheLinkLocalAddress(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		v6LinkLocalArrivesLate(t)
		return
	}
	reexecInNamespaces(t)
}

func v6LinkLocalArrivesLate(t *testing.T) {
	wireUpV6Link(t, v6LinkTentative)

	// THE PRECONDITION. The link came up microseconds ago; the kernel has
	// either not written the address yet or has written it tentative, and a
	// settled one here would mean this proof measured nothing.
	before, flags, present := clientLinkLocal(t)
	switch {
	case !present:
		t.Logf("the kernel has not written a link-local for %s yet: the constructor starts on an interface with no address at all, which is the runner's own shape", test6ClientIf)
	case flags&ifaTentative != 0:
		t.Logf("the kernel holds %s tentative (flags %#x): the constructor starts on an address RFC 4862 section 5.4 forbids sending from", before, flags)
	default:
		t.Fatalf("the kernel had already settled %s on %s (flags %#x) before the client was built; accept_dad did not take and this proof would pass without any wait at all",
			before, test6ClientIf, flags)
	}

	start := time.Now()
	c, _, err := newV6ClientErr(test6ClientIf)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("NewClient6 was refused while the kernel was still finishing with the interface's link-local address, after %s: %v — a client built the instant a link comes up must wait for the address, not report that there is none",
			elapsed.Round(time.Millisecond), err)
	}
	stop := runV6Client(t, c)
	defer stop()

	// AND THE ADDRESS IT TOOK IS THE KERNEL'S, SETTLED. Read back out of
	// /proc by this fixture rather than derived: the whole point of waiting is
	// to send from the address the kernel will answer Neighbor Solicitations
	// for, and an address still tentative here would mean the wait returned
	// early rather than that it waited.
	after, flags, present := clientLinkLocal(t)
	if !present {
		t.Fatalf("the kernel lists no link-local for %s although the client was built with %s", test6ClientIf, c.Source())
	}
	if flags&ifaTentative != 0 {
		t.Errorf("the client was built with %s while the kernel still has it tentative (flags %#x)", c.Source(), flags)
	}
	if got := hex.EncodeToString(c.Source().AsSlice()); got != after {
		t.Errorf("the client sends from %s and the kernel holds %s; the two readings of one interface disagree", got, after)
	}
	t.Logf("the constructor waited %s for %s and took the kernel's %s", elapsed.Round(time.Millisecond), test6ClientIf, c.Source())
}

// TestAV6ClientRefusesALinkThatNeverGetsALinkLocalAddress is the other
// direction, and it is the one that says the wait is BOUNDED.
//
// A wait with no bound is the defect the wait was added to fix, wearing the
// other sign: a link that will never carry an IPv6 address — this one has IPv6
// switched off and nothing switches it back on — must be refused with the
// reason, in seconds, and not hang until the namespaced child's own
// -test.timeout ends the run 45 seconds later with a goroutine dump for an
// answer.
//
// It also asserts the SENTENCE. "This interface has no link-local address" and
// "this interface has no link-local address and I waited four seconds for one"
// send a reader to different places, and the second is the one that is true.
func TestAV6ClientRefusesALinkThatNeverGetsALinkLocalAddress(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		v6LinkLocalNeverArrives(t)
		return
	}
	reexecInNamespaces(t)
}

func v6LinkLocalNeverArrives(t *testing.T) {
	wireUpV6Link(t, v6LinkNoIPv6)
	if addr, flags, ok := clientLinkLocal(t); ok {
		t.Fatalf("%s carries the link-local %s (flags %#x) with IPv6 disabled on it; this proof needs a link that never gets one", test6ClientIf, addr, flags)
	}

	start := time.Now()
	c, _, err := newV6ClientErr(test6ClientIf)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("NewClient6 built a client on a link with IPv6 disabled; it sends from %s, which the kernel does not hold", c.Source())
	}
	if !errors.Is(err, ErrNoLinkLocal) {
		t.Fatalf("NewClient6 failed with %v, which does not wrap ErrNoLinkLocal; a caller cannot tell this apart from a socket it could not open", err)
	}
	if !strings.Contains(err.Error(), "after waiting") {
		t.Errorf("the refusal %q does not say that it waited; a reader cannot tell a bound that was spent from a read that was never repeated", err)
	}
	if elapsed < linkLocalWait {
		t.Errorf("the refusal came after %s, before linkLocalWait (%s): the address was refused rather than waited for", elapsed, linkLocalWait)
	}
	if elapsed >= 2*linkLocalWait {
		t.Errorf("the refusal came after %s, twice linkLocalWait (%s) or more: a bound that is not held is the 45-second timeout with extra steps", elapsed, linkLocalWait)
	}
	t.Logf("refused in %s: %v", elapsed.Round(time.Millisecond), err)
}

// awaitDuplicateVerdict blocks until the KERNEL has finished RFC 4862 section
// 5.4's procedure on the client's link-local address, and returns the address
// and the flag byte as they stood the moment it finished.
//
// IT SPINS, for the reason every wait in this file spins: gate T2 refuses a
// sleep in a test, the kernel publishes this through a file rather than a
// channel, and a wall-clock deadline would turn a loaded box into a failed
// test. The loop terminates on EITHER outcome — the tentative bit clearing or
// the failed bit appearing — and never on the one this proof wants, so a
// fixture that produces no collision at all comes back with a settled address
// and fails LOUDLY one line below instead of hanging until the child's own
// -test.timeout. It costs up to the kernel's own duplicate-detection window,
// which is RFC 4861 section 10's one-second random delay plus one RetransTimer.
func awaitDuplicateVerdict(t *testing.T) (string, uint64) {
	t.Helper()
	for {
		addr, flags, ok := clientLinkLocal(t)
		if ok && (flags&ifaTentative == 0 || flags&ifaDADFailed != 0) {
			return addr, flags
		}
		gosched.Gosched()
	}
}

// TestAV6LinkLocalThatLostTheKernelsDuplicateCheckIsRefusedAsFailed is the
// flag byte a REAL duplicate produces, read out of a REAL netlink dump.
//
// WHY IT IS OWED. readLinkLocal decides between "tentative" and "failed
// duplicate address detection" by testing IFA_F_DADFAILED first and
// IFA_F_TENTATIVE second, and until this proof existed the only thing that
// ever exercised the first arm was a table of dumps this repository writes
// itself. A fabricated table is written by the same understanding it checks:
// an earlier version of that table used 0x88 for a failed address — permanent
// and failed, tentative CLEARED — and every arm of the parse agreed with it,
// because the parse was reading a byte nobody had ever asked the kernel for.
//
// WHAT THE KERNEL ACTUALLY EMITS. Linux does not clear IFA_F_TENTATIVE when a
// duplicate is found; addrconf_dad_stop leaves the address tentative and adds
// IFA_F_DADFAILED to it, because an address that lost the check is not an
// address that finished the check. MEASURED here, on a real collision on a
// real link: 0xc8 — permanent, tentative AND failed, all three. So the two
// arms are not mutually exclusive on any real input, the ORDER of the switch
// is the whole behaviour, and a table that never produced both bits at once
// could not see that.
//
// AND THE COLLISION IS BUILT, NOT ASSERTED. Both ends of the veth wear one
// hardware address and Linux's default addr_gen_mode, so both form RFC 4291
// Appendix A's same modified EUI-64 link-local; the server end holds it valid
// and answers for it, the client end asks and is answered. The proof reads the
// server end too, so "the client's address failed" is backed by the neighbour
// that made it fail rather than by a kernel that refused for its own reasons.
//
// IT ALSO CHECKS THE DERIVATION AGAINST THE KERNEL, which is the one claim
// InterfaceLinkLocal's own comment makes about a netns proof: the address the
// kernel forms is compared with wire.LinkLocalFromMAC of the same MAC. That
// comparison is what keeps "the kernel's address and the derived one agree on
// an ordinary Linux host" from being an unexamined assertion.
func TestAV6LinkLocalThatLostTheKernelsDuplicateCheckIsRefusedAsFailed(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		v6LinkLocalLosesTheDuplicateCheck(t)
		return
	}
	reexecInNamespaces(t)
}

func v6LinkLocalLosesTheDuplicateCheck(t *testing.T) {
	wireUpV6Link(t, v6LinkCollide)

	mac, err := net.ParseMAC(test6CollideMAC)
	if err != nil {
		t.Fatalf("test6CollideMAC %q does not parse: %v", test6CollideMAC, err)
	}
	derived, err := wire.LinkLocalFromMAC(mac)
	if err != nil {
		t.Fatalf("LinkLocalFromMAC(%s): %v", test6CollideMAC, err)
	}
	want := hex.EncodeToString(derived.AsSlice())

	// THE NEIGHBOUR FIRST. The server end holds the address this proof is
	// about, and holds it usable; without that there is nothing to collide
	// with and the client's check would simply succeed.
	srvAddr, srvFlags, ok := linkLocalOf(t, test6ServerIf)
	if !ok {
		t.Fatalf("the kernel lists no link-local for %s; the collision this proof needs has only one side", test6ServerIf)
	}
	if srvFlags&(ifaTentative|ifaDADFailed) != 0 {
		t.Fatalf("%s holds %s with flags %#x, which is not a usable address: a neighbour that is itself tentative does not answer for the address and there is no collision", test6ServerIf, srvAddr, srvFlags)
	}
	if srvAddr != want {
		t.Fatalf("%s holds %s and the modified EUI-64 of %s is %s: the two ends did not form one address, so nothing on this link is duplicated", test6ServerIf, srvAddr, test6CollideMAC, want)
	}

	addr, flags := awaitDuplicateVerdict(t)
	if flags&ifaDADFailed == 0 {
		t.Fatalf("the kernel settled %s on %s (flags %#x) although %s already held it: the fixture produced no duplicate and this proof would measure the tentative arm instead",
			addr, test6ClientIf, flags, test6ServerIf)
	}
	if addr != want {
		t.Fatalf("the address that failed on %s is %s and the modified EUI-64 of %s is %s; the kernel did not form the address this proof predicted",
			test6ClientIf, addr, test6CollideMAC, want)
	}
	// THE BYTE ITSELF, asserted and not only logged. This is the fact a
	// fabricated table got wrong, and it is not fatal here so that the
	// behaviour under test below is still measured on whatever the kernel
	// emitted.
	if flags&ifaTentative == 0 {
		t.Errorf("the kernel reports the failed %s with flags %#x, which does NOT carry IFA_F_TENTATIVE (%#x); this tree's fabricated dumps assume a real failure carries both bits and the order of readLinkLocal's two arms is only load-bearing if it does",
			addr, flags, ifaTentative)
	}
	t.Logf("the kernel reports %s on %s with flags %#x after losing the duplicate check to %s", addr, test6ClientIf, flags, test6ServerIf)

	// AND WHAT THE LIBRARY MAKES OF IT. readLinkLocal rather than
	// InterfaceLinkLocal: the classification is the subject, the four-second
	// wait around it is not, and this address will never become usable.
	iface, err := net.InterfaceByName(test6ClientIf)
	if err != nil {
		t.Fatalf("InterfaceByName(%s): %v", test6ClientIf, err)
	}
	got, err := readLinkLocal(iface.Index, test6ClientIf)
	if err == nil {
		t.Fatalf("readLinkLocal returned %s for %s, an address the kernel has marked as having lost duplicate address detection: RFC 4862 section 5.4 forbids sending from it and the neighbour that owns it would answer for it",
			got, test6ClientIf)
	}
	if !errors.Is(err, ErrNoLinkLocal) {
		t.Fatalf("readLinkLocal failed with %v, which does not wrap ErrNoLinkLocal; a caller cannot tell this apart from a dump it could not take", err)
	}
	if !strings.Contains(err.Error(), "0 tentative, 1 failed") {
		t.Errorf("the refusal is %q; the kernel's own byte for this address is %#x and it must be counted as one that FAILED the check, not as one still taking it — an address that is still tentative is worth waiting for and this one never will be",
			err, flags)
	}
}

// ------------------------------------------ two clients, one link --

// countInbound6 is how many Steps in a v6 journal were caused by a message
// arriving, which is the unit of the cost the ring-3 destination narrowing
// removes: one decode, one Step, one slot in a bounded ring.
//
// Notes are skipped because a note is ring 2's own line and not a Step.
func countInbound6(entries []proto.JournalEntry6) int {
	n := 0
	for _, e := range entries {
		if !e.Note && e.Kind == proto.EvReceived {
			n++
		}
	}
	return n
}

// TestAV6ClientDiscardsAnotherClientsReplyAtTheTransport is the shared-segment
// row, and the fixture is the plugin's own macvlan case.
//
// WHAT REACHES THIS CLIENT THAT IS NOT FOR IT. ParseIPv6UDP narrows on the two
// UDP ports and nothing else, so a server's unicast Advertise or Reply for
// ANOTHER client on the link satisfies it completely: right ports, right
// direction, a valid checksum over its own pseudo-header. Ring 1 discards such
// a message too — a bound client on the "no exchange in flight" arm, a client
// mid-exchange on RFC 9915 section 16.3's Client Identifier — so nothing was
// ever mis-leased; the cost is a decode, a counter, a journal entry and a slot
// in a bounded ring, per foreign exchange, on a link that may carry dozens.
// Both halves are read below: TransportStats.Foreign for what the transport
// kept out, and the journal for what got past it.
//
// THE SECOND CLIENT IS A MACVLAN OVER THE FIRST CLIENT'S INTERFACE, and that
// is not an approximation of the shared segment; it is one. A macvlan has its
// own hardware address and therefore its own link-local, the lower device sees
// every frame the peer transmits, and an AF_PACKET socket on the lower device
// is tapped before the demux that would have sorted them — so this client
// reads the other's replies exactly as a container on a flooding bridge does.
//
// THE OTHER DIRECTION IS ASSERTED TOO. The macvlan is NOT promiscuous, so the
// second client does not see the first one's replies at all, and its Foreign
// counter must stay at zero. Without that half the row would pass just as well
// against a transport that counted every frame it read as foreign.
func TestAV6ClientDiscardsAnotherClientsReplyAtTheTransport(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		v6TwoClientsOnOneLink(t)
		return
	}
	reexecInNamespaces(t)
}

func v6TwoClientsOnOneLink(t *testing.T) {
	wireUpV6(t)
	srv := startDnsmasq6(t, v6Managed)
	watch := newRAWatch(t, test6ClientIf)

	first, _ := newV6Client(t)
	stopFirst := runV6Client(t, first)
	defer stopFirst()

	assertMode(t, srv, watch, v6Managed)

	evFirst := awaitV6(t, first, lease.Acquired)
	addrFirst := evFirst.Lease.Addr.Addr()
	srv.waitFor(t, "DHCPREPLY("+test6ServerIf+") "+addrFirst.String())
	base := first.TransportStats()
	if base.Foreign != 0 {
		t.Fatalf("the first client had already counted %d foreign repl(ies) on a link with nothing else on it: %+v", base.Foreign, base)
	}

	// THE COST THE NARROWING WAS MADE FOR, as a number read at ring 1 rather
	// than as a claim in a comment. Every foreign exchange that reaches the
	// machine costs a decode, a Step and a slot in a BOUNDED journal, so on a
	// busy segment one container's traffic pushes another's own history out of
	// its ring. The count of received-message Steps in this client's journal
	// is what says whether any of them arrived, and it is taken here so the
	// reading below is a DELTA over the window the second client is alive in.
	// MEASURED by the M7c review with the narrowing removed: this journal grew
	// from 10 entries to 12.
	inboundBefore := countInbound6(first.Journal())

	// The second client, on its own hardware address over the same wire.
	mustRun(t, "ip", "link", "add", test6ClientIf2, "link", test6ClientIf, "type", "macvlan", "mode", "bridge")
	p := "/proc/sys/net/ipv6/conf/" + test6ClientIf2 + "/accept_dad"
	if err := os.WriteFile(p, []byte("0\n"), 0o644); err != nil {
		t.Fatalf("writing %s: %v", p, err)
	}
	mustRun(t, "ip", "link", "set", test6ClientIf2, "up")

	second, _, err := newV6ClientErr(test6ClientIf2)
	if err != nil {
		t.Fatalf("building the second client on %s: %v", test6ClientIf2, err)
	}
	stopSecond := runV6Client(t, second)
	defer stopSecond()

	if first.Source() == second.Source() {
		t.Fatalf("both clients send from %s; two clients sharing one link-local address cannot tell each other's replies apart, and this row would measure nothing", first.Source())
	}

	evSecond := awaitV6(t, second, lease.Acquired)
	addrSecond := evSecond.Lease.Addr.Addr()
	if addrSecond == addrFirst {
		t.Fatalf("dnsmasq gave both clients %s", addrFirst)
	}
	srv.waitFor(t, "DHCPREPLY("+test6ServerIf+") "+addrSecond.String())

	// THE BARRIER IS Reads AND NOT Foreign, which is what makes the mutant a
	// failure instead of a hang: every frame moves Reads whether or not the
	// destination is checked, so a transport that does not narrow reaches this
	// point too — and then fails on the count below, by name, instead of
	// spinning until the child's own timeout.
	st := awaitTransportReads(t, first, base.Reads+2)
	if st.Foreign < 2 {
		t.Errorf("the first client counted %d foreign repl(ies) after the second client's Advertise and Reply crossed the link; a reply addressed to %s is not this client's and is not this transport's to deliver — %+v",
			st.Foreign, second.Source(), st)
	}
	if l, ok := first.Lease(); !ok || l.Addr.Addr() != addrFirst {
		t.Errorf("the first client's lease is %v (held=%v) after another client's exchange, want %s", l.Addr, ok, addrFirst)
	}

	// AND NOTHING OF IT REACHED RING 1. Foreign counts what the transport
	// discarded; this counts what got past it, which is the half the cost
	// argument is about. Ring 1 would have discarded these too — a bound
	// client on the "no exchange in flight" arm, a client mid-exchange on RFC
	// 9915 section 16.3's Client Identifier — so a message that arrives here
	// is not a mis-lease, it is a journal entry somebody else paid for.
	if got := countInbound6(first.Journal()); got != inboundBefore {
		t.Errorf("the first client's journal grew from %d received-message Step(s) to %d while another client exchanged on the same link; the narrowing that exists to keep them out of a bounded ring did not keep them out",
			inboundBefore, got)
	}

	// The control: the macvlan sees only what is addressed to it.
	if sst := second.TransportStats(); sst.Foreign != 0 {
		t.Errorf("the second client counted %d foreign repl(ies); the macvlan is not promiscuous and the first client's replies are addressed to a hardware address it does not hold — %+v", sst.Foreign, sst)
	}
	t.Logf("the first client read %d frame(s) and discarded %d of them as another client's", st.Reads, st.Foreign)
}

// awaitTransportReads blocks until the transport has read at least n frames and
// returns the counters as they stood then.
//
// IT SPINS ON THE COUNTER THAT MOVES UNCONDITIONALLY. Reads is bumped in a
// defer at the end of deliver, after every classification, so it is a barrier
// for the frame having been classified — whatever the classification was. A
// barrier on the counter under test would only ever be reached by a transport
// that already passes.
func awaitTransportReads(t *testing.T, c *Client6, n uint64) TransportStatsV6 {
	t.Helper()
	for {
		if st := c.TransportStats(); st.Reads >= n {
			return st
		}
		gosched.Gosched()
	}
}

// TestAV6ClientIsToldTheServerRefused is #816's library half against a real
// server: a pool with one address in it, one client holding that address, and
// a second client that gets an answer rather than silence.
//
// WHAT THE PROOF IS ABOUT IS THE DIFFERENCE BETWEEN TWO SILENCES. Before this,
// a client that was refused and a client nobody answered produced the same
// thing at this boundary — nothing at all — and the caller's own deadline was
// the only event either of them ever generated. The refusal is now an event
// carrying the server's own code, and the server's log is the outside evidence
// that the code came from the server rather than from this library's opinion
// of the silence.
//
// dnsmasq 2.91 puts that code at the MESSAGE level on a Solicit it cannot
// answer, and not in the IA_NA where RFC 9915 section 18.3.9 puts it
// (src/rfc3315.c, the DHCP6SOLICIT arm: the IA is dropped from the Advertise
// with save_counter and the status is added to the message). Both placements
// are driven at ring 1; this is the one a real server sends.
func TestAV6ClientIsToldTheServerRefused(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		v6RefusedByDnsmasq(t)
		return
	}
	reexecInNamespaces(t)
}

func v6RefusedByDnsmasq(t *testing.T) {
	wireUpV6(t)
	srv := startDnsmasq6(t, v6Exhausted)
	watch := newRAWatch(t, test6ClientIf)

	first, _ := newV6Client(t)
	stopFirst := runV6Client(t, first)
	defer stopFirst()

	assertMode(t, srv, watch, v6Exhausted)

	// The pool is emptied by a client taking the one address in it, not by a
	// fixture asserting that it is empty.
	held := awaitV6(t, first, lease.Acquired)
	if got := held.Lease.Addr.Addr().String(); got != test6OnlyAddr {
		t.Fatalf("the first client took %s; the pool is the single address %s", got, test6OnlyAddr)
	}
	srv.waitFor(t, "DHCPREPLY("+test6ServerIf+") "+test6OnlyAddr)

	// The second client, on its own hardware address over the same wire, so it
	// is a different DUID asking for a different binding.
	mustRun(t, "ip", "link", "add", test6ClientIf2, "link", test6ClientIf, "type", "macvlan", "mode", "bridge")
	p := "/proc/sys/net/ipv6/conf/" + test6ClientIf2 + "/accept_dad"
	if err := os.WriteFile(p, []byte("0\n"), 0o644); err != nil {
		t.Fatalf("writing %s: %v", p, err)
	}
	mustRun(t, "ip", "link", "set", test6ClientIf2, "up")

	second, _, err := newV6ClientErr(test6ClientIf2)
	if err != nil {
		t.Fatalf("building the second client on %s: %v", test6ClientIf2, err)
	}
	stopSecond := runV6Client(t, second)
	defer stopSecond()

	ev := awaitV6Refusal(t, second)
	if ev.Reason != proto.ReasonNak {
		t.Errorf("the refusal says %s, want %s: a server that answers and says no is refusing, not absent", ev.Reason, proto.ReasonNak)
	}
	if ev.Status != wire.StatusNoAddrsAvail {
		t.Errorf("the refusal carries the status %s, want %s (RFC 9915 section 21.13: \"The server has no addresses available to assign to the IA(s).\")", ev.Status, wire.StatusNoAddrsAvail)
	}
	if !strings.Contains(ev.Note, wire.StatusNoAddrsAvail.String()) {
		t.Errorf("the note %q does not name the code; it is what an operator reads", ev.Note)
	}

	// THE SERVER'S OWN ACCOUNT, which is what makes this a refusal rather than
	// this library's reading of one. dnsmasq logs the sentence it put in the
	// status message beside the message it sent.
	srv.waitFor(t, "no addresses available")

	if _, ok := second.Lease(); ok {
		t.Error("the refused client holds a lease")
	}
	if st := second.Stats(); st.NaksAccepted == 0 || st.AcquireFailures == 0 {
		t.Errorf("the refused client counted %d refusal(s) and %d acquisition failure(s): %+v", st.NaksAccepted, st.AcquireFailures, st)
	}
	if st := second.DADStats(); st.Started != 0 {
		t.Errorf("the refused client checked %d address(es) for duplicates; it was given none", st.Started)
	}

	// The preservation control on the same link and the same server: the
	// client that HAS the address is untouched by the other one's refusal.
	if l, ok := first.Lease(); !ok || l.Addr.Addr().String() != test6OnlyAddr {
		t.Errorf("the first client's lease is %v (held=%v) after the second was refused", l.Addr, ok)
	}
	if st := first.Stats(); st.NaksAccepted != 0 {
		t.Errorf("the client that holds the address counted %d refusal(s): %+v", st.NaksAccepted, st)
	}
}

// awaitV6Refusal blocks for the first refusal and fails on anything that says
// the client got somewhere instead.
//
// NO DURATION, for awaitV6's reason: a client that is never refused hangs until
// the child's own -test.timeout, which prints the goroutine dump and dnsmasq's
// log beside it, rather than reporting a slow box as a broken client.
func awaitV6Refusal(t *testing.T, c *Client6) lease.Event {
	t.Helper()
	for ev := range c.Events() {
		t.Logf("client event: %s", ev)
		switch ev.Kind {
		case lease.Failed:
			return ev
		case lease.Acquired, lease.Configured:
			t.Fatalf("the client was %s on a link whose only address is held by another client: %s", ev.Kind, ev)
		}
	}
	t.Fatalf("the event stream ended before any event")
	return lease.Event{}
}
