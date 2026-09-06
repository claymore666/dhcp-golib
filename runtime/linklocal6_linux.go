//go:build linux

package runtime

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// ErrNoLinkLocal is returned when an interface has no usable link-local
// address for this library to send from.
var ErrNoLinkLocal = errors.New("runtime: interface has no assigned IPv6 link-local address")

// ifInet6Path is Linux's list of configured IPv6 addresses with their per-
// address flags. A variable so a test can point it at a fixture file and drive
// every branch of the parser without a network namespace.
var ifInet6Path = "/proc/net/if_inet6"

// Linux's per-address flags, from include/uapi/linux/if_addr.h. Only the three
// this library acts on are named; the rest are read and ignored.
const (
	ifaDADFailed = 0x08
	ifaTentative = 0x40
)

// linkLocalWait is how long InterfaceLinkLocal keeps looking before it
// refuses, and linkLocalPoll is how often it looks.
//
// WHERE THE FOUR SECONDS COME FROM. The kernel does two things between the
// moment a link comes up and the moment its link-local address is usable, and
// RFC 4862 section 5.4.2 names both. First it waits: "If the Neighbor
// Solicitation is going to be the first message sent from an interface after
// interface (re)initialization, the node SHOULD delay joining the
// solicited-node multicast address by a random delay between 0 and
// MAX_RTR_SOLICITATION_DELAY as specified in [RFC4861]" — one second, RFC 4861
// section 10. Then it probes: "To check an address, a node sends
// DupAddrDetectTransmits Neighbor Solicitations, each separated by RetransTimer
// milliseconds" — one solicitation and one RETRANS_TIMER of listening at RFC
// 4861 section 10's defaults, another second. Linux spells those two variables
// dad_transmits and retrans_time, and the address is tentative for the whole of
// it. Two seconds is therefore the kernel's own worst case at the defaults,
// MEASURED here at 2.043s on a veth whose accept_dad was left on, and the bound
// is that doubled. The doubling is the part the measurement demanded rather
// than the protocol: on a two-core CI runner under load the address was not
// merely tentative but ABSENT — no row in the file for the interface at all —
// because addrconf had not run yet, and that latency belongs to a work queue,
// not to a timer anything here can derive.
//
// IT IS A CONSTANT AND NOT A READING OF THE TWO SYSCTLS, deliberately. The
// seam design's section 5 keeps this library off /proc/sys: a library that
// reads a host's tuning has to decide what to do when it disagrees with the
// host, and nothing here can. The cost is stated rather than hidden: on a host
// that has raised dad_transmits or retrans_time above the defaults this bound
// is too short, and the refusal says how long it actually waited so that a
// reader can tell that case from a link with no address at all.
//
// THE POLL IS A LOOP OVER /proc AND NOT A NETLINK SUBSCRIPTION. Netlink would
// give the answer on the kernel's edge instead of on a clock, and it is the
// better instrument; it is also a second socket, in a namespace this function
// is careful to say it reads from the CALLING GOROUTINE, and it would have to
// be opened before the very thing it is waiting for. Twenty milliseconds of
// granularity costs at most 200 reads of a file the kernel formats on demand,
// and it is the last thing this client does before it has a link at all.
const (
	linkLocalWait = 4 * time.Second
	linkLocalPoll = 20 * time.Millisecond
)

// InterfaceLinkLocal returns the IPv6 link-local address the KERNEL has
// assigned to ifName, refusing one that is tentative or has failed duplicate
// address detection, and WAITING up to linkLocalWait for one to appear.
//
// WHY IT WAITS, MEASURED on a two-core CI runner: a client built the instant
// after the link came up was refused with "0 tentative, 0 failed duplicate
// address detection" while a server in the same namespace was already bound to
// that link. Nothing was wrong with the link; the kernel had not got to it.
// A single read answers a question about an interface that is still being
// configured, and the answer it gives is indistinguishable from the answer for
// an interface that will never have an address — which is why the refusal now
// carries the elapsed wait, and why the wait exists at all.
//
// A READ ERROR IS NOT WAITED OUT. An unreadable /proc/net/if_inet6 is a mount
// problem, not a link that has not settled, and retrying it for four seconds
// turns a clear failure into a slow one.
//
// WHY THE KERNEL'S AND NOT ONE DERIVED FROM THE MAC. Both are one line of
// arithmetic and they agree on an ordinary Linux host, so the choice looks
// free; it is not. A DHCPv6 server's reply is UNICAST to the source address of
// the message it answers — RFC 9915 section 18.3.10: "the server unicasts the
// Advertise or Reply message directly to the client using the address in the
// source address field from the IP datagram in which the original message was
// received" — and section 5 says which address that field carries: "The client
// uses a link-local source address or addresses determined through other
// mechanisms for transmitting and receiving DHCP messages." Delivering that
// unicast means resolving the address with a Neighbor Solicitation that THIS
// LIBRARY DOES NOT ANSWER — the kernel does, and only for an address the
// kernel holds. RFC 4291 Appendix A's modified EUI-64 is what Linux forms when
// the interface's addr_gen_mode is 0, which is the default and is MEASURED for
// a veth pair in an unprivileged network namespace in this milestone; it is
// NOT what a host doing RFC 7217 stable-privacy or RFC 8981 temporary
// addressing forms, and on such a host a MAC-derived source names an address
// nothing on the link answers for. The client would then send perfectly valid
// Solicits and time out with nothing to point at.
//
// So the address is READ, and wire.LinkLocalFromMAC stays what its own comment
// says it is — the fixture's way of predicting what the kernel will do. The
// netns proof asserts the two agree there, which is what keeps this from being
// an unexamined divergence: the derivation is checked against the kernel in
// the one environment where both are available.
//
// TENTATIVE AND DAD-FAILED ADDRESSES ARE REFUSED. RFC 4862 section 5.4: "An
// address on which the Duplicate Address Detection procedure is applied is
// said to be tentative until the procedure has completed successfully. A
// tentative address is not considered 'assigned to an interface' in the
// traditional sense." Sending from one is sending from an address that is not
// assigned, which is what section 5.4's whole procedure exists to prevent, and
// the flags column of /proc/net/if_inet6 is where Linux says so — MEASURED:
// a freshly-upped veth reads flag 0xc0 (permanent | tentative) and settles to
// 0x80 about a second later. That second is why this function waits rather
// than answering at once, and REFUSING a tentative address is what makes the
// wait necessary: a reader that took the address the moment it appeared would
// need no wait and would send from an address that is not assigned.
//
// BOUND: it reads /proc, so it reports the namespace of the CALLING GOROUTINE,
// which is the same contract every socket constructor in this package carries
// and the reason NewClient6 opens all of them together.
func InterfaceLinkLocal(ifName string) (netip.Addr, error) {
	start := time.Now()
	for {
		addr, err := readLinkLocal(ifName)
		if err == nil {
			return addr, nil
		}
		if !errors.Is(err, ErrNoLinkLocal) {
			return netip.Addr{}, err
		}
		if elapsed := time.Since(start); elapsed >= linkLocalWait {
			// The elapsed wait is the ACTUAL one and not the constant: a
			// caller reading "after waiting 3.002s" knows the bound was
			// spent, and one reading a much larger number knows this
			// goroutine was not running for most of it, which on the runner
			// that found this defect is the more useful fact of the two.
			return netip.Addr{}, fmt.Errorf("%w after waiting %s", err, elapsed.Round(time.Millisecond))
		}
		time.Sleep(linkLocalPoll)
	}
}

// readLinkLocal is one pass over the file: the parse, with no wait around it.
//
// It is separate so that the parser's arms — a tentative address, one that
// failed the kernel's check, a global address, a malformed row — can be driven
// from a fabricated file without paying linkLocalWait for each refusing row,
// and so that the wait above has exactly one thing to repeat.
func readLinkLocal(ifName string) (netip.Addr, error) {
	f, err := os.Open(ifInet6Path)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("runtime: %s: %w", ifInet6Path, err)
	}
	defer func() { _ = f.Close() }()

	var (
		refusedTentative int
		refusedDADFailed int
	)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// address(32 hex) index prefixlen scope flags name
		fields := strings.Fields(sc.Text())
		if len(fields) != 6 || fields[5] != ifName {
			continue
		}
		raw, err := hex.DecodeString(fields[0])
		if err != nil || len(raw) != 16 {
			continue
		}
		addr := netip.AddrFrom16([16]byte(raw))
		if !addr.IsLinkLocalUnicast() {
			continue
		}
		flags, err := strconv.ParseUint(fields[4], 16, 32)
		if err != nil {
			continue
		}
		switch {
		case flags&ifaDADFailed != 0:
			refusedDADFailed++
		case flags&ifaTentative != 0:
			refusedTentative++
		default:
			return addr, nil
		}
	}
	if err := sc.Err(); err != nil {
		return netip.Addr{}, fmt.Errorf("runtime: %s: %w", ifInet6Path, err)
	}
	// The counts are in the message rather than dropped, because "the
	// interface has no link-local address" and "it has one and the kernel's
	// own duplicate address detection has not finished with it" are different
	// problems with different fixes, and a caller that sees only the first
	// wording waits for the wrong thing.
	return netip.Addr{}, fmt.Errorf("%w: %s (%d tentative, %d failed duplicate address detection)",
		ErrNoLinkLocal, ifName, refusedTentative, refusedDADFailed)
}
