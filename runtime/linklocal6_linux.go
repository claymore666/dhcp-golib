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

// InterfaceLinkLocal returns the IPv6 link-local address the KERNEL has
// assigned to ifName, refusing one that is tentative or has failed duplicate
// address detection.
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
// 0x80 about a second later. The refusal is therefore also the reason a caller
// may have to wait for the link before building a client, and it says which
// wait it is instead of leaving a timeout.
//
// BOUND: it reads /proc, so it reports the namespace of the CALLING GOROUTINE,
// which is the same contract every socket constructor in this package carries
// and the reason NewClient6 opens all of them together.
func InterfaceLinkLocal(ifName string) (netip.Addr, error) {
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
