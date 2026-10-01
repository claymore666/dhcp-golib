// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

//go:build linux

package runtime

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/claymore666/dhcp-golib/lease"
	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

// Runtime half of claymore666/docker-net-dhcp#1119, DHCPFORCERENEW with Forcerenew
// Nonce Authentication, against dnsmasq 2.91 as the server.
//
// WHAT THIS PROVES AND WHAT IT DOES NOT. dnsmasq has no option 145, no option
// 90 and no DHCPFORCERENEW. It sends the bytes it is given, so the server's
// options 145 and 90 are fixed bytes and the FORCERENEW frame is synthetic: a
// frame this file builds and puts on the link. Case (a) proves that the client
// offered option 145 (dnsmasq's tag fires on it and the forced options come
// back only then) and that it took the nonce out of the ACK. It does not
// prove a conformant server. Cases (b) to (e) prove how the client treats a
// frame, read from dnsmasq's log: a DHCPREQUEST that answers it, under a new
// xid and with no DHCPDISCOVER, and none from the frames that must change
// nothing.
//
// THE FIXED REPLAY VALUE is frcServerReplay, the replay detection value of the
// option 90 dnsmasq puts on every ACK, renewals included. The floor starts at
// it, so every frame sent here must exceed it: 101 and 102 do and 100 does
// not. The renewal ACK in (b) carries 100 again with the same nonce, and the
// refused replay in (c) is the proof that the floor was not lowered to it.
//
// THE XID of every frame here is a constant that is not the client's. A
// FORCERENEW is server-initiated and answers no transaction, so the machine
// does not look at it (RFC 3203 section 2.2).
//
// The library's own counters are not what is read. The journal is read once,
// after the last frame, as the account of why each earlier one did nothing:
// the final frame is processed after every earlier one, so the journal is
// complete by then.

const (
	frcServerReplay = 100
	frcServerTag    = "frcap"
	// frcQuiet is a window in which nothing is expected. It is a socket read
	// deadline, which gate T2 allows; a sleep it does not.
	frcQuiet = 300 * time.Millisecond
	// frcDrain empties the observer's queue of frames already delivered.
	frcDrain = 20 * time.Millisecond
	// frcBound is how long a frame that must be obeyed has to produce its
	// DHCPREQUEST. It is only ever spent when the client is broken.
	frcBound = 5 * time.Second
)

var frcNonce = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40}

func frcHex(b []byte) string {
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = fmt.Sprintf("%02x", c)
	}
	return strings.Join(parts, ":")
}

// frcOption90 is the 28 octets of RFC 6704 section 3.1.2's Forcerenew Nonce
// option: protocol 3, algorithm 1, RDM 0, the replay value, type 1, the nonce.
func frcOption90(nonce []byte, replay uint64) []byte {
	v := []byte{3, 1, 0}
	v = binary.BigEndian.AppendUint64(v, replay)
	v = append(v, 1)
	return append(v, nonce...)
}

// frcFrame is a DHCPFORCERENEW to the client: option 53 = 9, the server's id,
// option 90 type 2 with the HMAC-MD5 over the whole message, hops and giaddr
// zeroed and the digest field zeroed (RFC 3118 section 3, RFC 6704 section
// 3.1.2). It is signed here, with crypto/hmac, and not by the library.
func frcFrame(mac net.HardwareAddr, leased netip.Addr, nonce []byte, replay uint64) []byte {
	f := make([]byte, 300)
	f[0], f[1], f[2] = 2, 1, 6
	copy(f[4:8], []byte{0xC0, 0xFF, 0xEE, 0x01})
	ci := leased.As4()
	copy(f[12:16], ci[:])
	copy(f[28:34], mac)
	copy(f[236:240], []byte{99, 130, 83, 99})
	o := 240
	o += copy(f[o:], []byte{53, 1, 9})
	sid := netip.MustParseAddr(testServerIP).As4()
	o += copy(f[o:], append([]byte{54, 4}, sid[:]...))
	val := []byte{3, 1, 0}
	val = binary.BigEndian.AppendUint64(val, replay)
	val = append(val, 2)
	val = append(val, make([]byte, 16)...)
	f[o], f[o+1] = 90, byte(len(val))
	digestAt := o + 2 + 12
	o += 2 + copy(f[o+2:], val)
	f[o] = 255
	h := hmac.New(md5.New, nonce)
	h.Write(f)
	copy(f[digestAt:], h.Sum(nil))
	return f
}

// frcInjector puts frames on the server's side of the veth pair, to the
// client. It is not this library's transport, so it shares no defect with the
// receiver it is testing.
type frcInjector struct {
	fd    int
	index int
	mac   net.HardwareAddr
	src   netip.Addr
}

func newFrcInjector(t *testing.T, mac net.HardwareAddr) *frcInjector {
	t.Helper()
	iface, err := net.InterfaceByName(testServerIf)
	if err != nil {
		t.Fatalf("InterfaceByName(%s): %v", testServerIf, err)
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, int(htons(ethPIP)))
	if err != nil {
		t.Fatalf("the injector's socket: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Close(fd) })
	return &frcInjector{fd: fd, index: iface.Index, mac: mac, src: netip.MustParseAddr(testServerIP)}
}

// send puts payload on the link as a UDP datagram from the server's port to
// the client's, addressed at the IP layer to ipDst and at the link layer to
// hwDst.
func (j *frcInjector) send(t *testing.T, ipDst netip.Addr, hwDst net.HardwareAddr, payload []byte) {
	t.Helper()
	pkt, err := BuildIPv4UDP(j.src, ipDst, 67, 68, 1, 64, payload)
	if err != nil {
		t.Fatalf("BuildIPv4UDP: %v", err)
	}
	lla := &syscall.SockaddrLinklayer{Protocol: htons(ethPIP), Ifindex: j.index, Halen: 6}
	copy(lla.Addr[:], hwDst)
	if err := syscall.Sendto(j.fd, pkt, 0, lla); err != nil {
		t.Fatalf("injecting a frame to %s: %v", ipDst, err)
	}
}

// frcWatch reads the DHCPREQUESTs the client puts on the link, off the
// server's end, with a socket that is not this library's. Its window is the
// descriptor's read deadline.
type frcWatch struct{ f *os.File }

func newFrcWatch(t *testing.T) *frcWatch {
	t.Helper()
	iface, err := net.InterfaceByName(testServerIf)
	if err != nil {
		t.Fatalf("InterfaceByName(%s): %v", testServerIf, err)
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, int(htons(ethPIP)))
	if err != nil {
		t.Fatalf("the observer's socket: %v", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(ethPIP), Ifindex: iface.Index}); err != nil {
		_ = syscall.Close(fd)
		t.Fatalf("the observer's bind: %v", err)
	}
	w := &frcWatch{f: os.NewFile(uintptr(fd), "frc_watch")}
	t.Cleanup(func() { _ = w.f.Close() })
	return w
}

// requests counts the DHCPREQUESTs that arrive within the window.
func (w *frcWatch) requests(t *testing.T, within time.Duration) int {
	t.Helper()
	return w.count(t, within, 0)
}

// await returns as soon as one DHCPREQUEST arrives, or false when none does
// within the window. A client that ignored the frame fails the test here
// instead of leaving it blocked on a log line that never comes.
func (w *frcWatch) await(t *testing.T) bool {
	t.Helper()
	return w.count(t, frcBound, 1) == 1
}

// count reads until the window ends, or until stopAt requests when it is set.
func (w *frcWatch) count(t *testing.T, within time.Duration, stopAt int) int {
	t.Helper()
	if err := w.f.SetReadDeadline(time.Now().Add(within)); err != nil {
		t.Fatalf("the observer's read deadline: %v", err)
	}
	var n int
	buf := make([]byte, 2048)
	for {
		got, err := w.f.Read(buf)
		if err != nil {
			return n
		}
		f := buf[:got]
		if got < 28 || f[0]>>4 != 4 || f[9] != 17 {
			continue
		}
		ihl := int(f[0]&0x0f) * 4
		if got < ihl+8 || binary.BigEndian.Uint16(f[ihl+2:ihl+4]) != 67 {
			continue
		}
		m, err := wire.Decode(f[ihl+8:])
		if err != nil {
			continue
		}
		if mt, ok := m.Type(); ok && mt == wire.MsgRequest {
			n++
			if stopAt > 0 && n >= stopAt {
				return n
			}
		}
	}
}

// frcXIDs returns the xid of every dnsmasq log line for one message kind on
// the link, in order.
func frcXIDs(lines []string, kind string) []string {
	re := regexp.MustCompile(`\]: (\d+) DHCP` + kind + `\(` + testServerIf + `\)`)
	var out []string
	for _, l := range lines {
		if m := re.FindStringSubmatch(l); m != nil {
			out = append(out, m[1])
		}
	}
	return out
}

// TestAForcerenewIsObeyedOnlyWhenItIsAuthenticAndUnicast is cases (a) to (e) in
// one run, on one client and one dnsmasq so the suite pays for the fixture once.
func TestAForcerenewIsObeyedOnlyWhenItIsAuthenticAndUnicast(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		forcerenewAgainstDnsmasq(t)
		return
	}
	reexecInNamespaces(t)
}

func forcerenewAgainstDnsmasq(t *testing.T) {
	mustRun(t, "ip", "link", "add", testClientIf, "type", "veth", "peer", "name", testServerIf)
	mustRun(t, "ip", "addr", "add", testServerIP+"/24", "dev", testServerIf)
	mustRun(t, "ip", "link", "set", testServerIf, "up")
	mustRun(t, "ip", "link", "set", testClientIf, "up")
	iface, err := net.InterfaceByName(testClientIf)
	if err != nil {
		t.Fatalf("InterfaceByName(%s): %v", testClientIf, err)
	}
	mac := iface.HardwareAddr
	// Permanent neighbour entries, renewalAgainstDnsmasq's reason: the
	// renewal ACK is unicast to an address nothing here owns.
	for _, a := range addrRange(t, testRenewLo, testRenewHi) {
		mustRun(t, "ip", "neigh", "replace", a, "lladdr", mac.String(), "dev", testServerIf, "nud", "permanent")
	}
	srv := startDnsmasqCfg(t, dnsmasqConfig{rangeLo: testRenewLo, rangeHi: testRenewHi, extra: []string{
		"--dhcp-match=set:" + frcServerTag + ",145",
		"--dhcp-option-force=tag:" + frcServerTag + ",145,1",
		"--dhcp-option-force=tag:" + frcServerTag + ",90," + frcHex(frcOption90(frcNonce, frcServerReplay)),
	}})
	inject := newFrcInjector(t, mac)

	params := proto.DefaultParams(mac)
	params.DesyncMin, params.DesyncMax = 0, 0
	params.Conflict = proto.ConflictAsync
	params.ACD = briskACD()
	c, err := NewClient(ClientConfig{Interface: testClientIf, Params: params, EventBuffer: 16})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- c.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-runErr
	})

	acquired := awaitAcquired(t, c)
	leased := acquired.Lease.Addr.Addr()
	srv.waitFor(t, "DHCPACK("+testServerIf+") "+leased.String()+" "+mac.String())

	// Opened after the acquisition, so its queue holds nothing of it.
	watch := newFrcWatch(t)

	// (a) option 145 crossed and the nonce was taken.
	if !strings.Contains(strings.Join(srv.lines(), "\n"), frcServerTag) {
		t.Errorf("(a) dnsmasq's tag %q never fired, so the client's DISCOVER carried no option 145.\nLog:\n%s", frcServerTag, strings.Join(srv.lines(), "\n"))
	}
	for _, mt := range []wire.MessageType{wire.MsgDiscover, wire.MsgRequest} {
		var seen int
		for _, p := range c.Packets() {
			if p.Dir != lease.DirOut || p.Msg == nil {
				continue
			}
			if got, ok := p.Msg.Type(); ok && got == mt {
				seen++
				if v := p.Msg.Options[wire.OptForcerenewNonce]; !bytes.Equal(v, []byte{1}) {
					t.Errorf("(a) a %s carries option 145 = %x, want 01", mt, v)
				}
			}
		}
		if seen == 0 {
			t.Errorf("(a) no %s captured", mt)
		}
	}
	if got := acquired.Lease.ForcerenewNonce; !bytes.Equal(got, frcNonce) || acquired.Lease.ForcerenewReplay != frcServerReplay {
		t.Fatalf("(a) the lease the client reports carries nonce %x replay %d, want %x and %d",
			got, acquired.Lease.ForcerenewReplay, frcNonce, frcServerReplay)
	}

	discovers := srv.count("DHCPDISCOVER(")
	requests := srv.count("DHCPREQUEST(" + testServerIf + ") " + leased.String())
	acks := srv.count("DHCPACK(" + testServerIf + ") " + leased.String())
	seenXIDs := append(frcXIDs(srv.lines(), "DISCOVER"), frcXIDs(srv.lines(), "REQUEST")...)
	broadcast := netip.MustParseAddr("255.255.255.255")
	allHW := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	good := frcFrame(mac, leased, frcNonce, frcServerReplay+1)

	// (e), (d), a value equal to the server's own, and a frame for another
	// host's address that reached this link-layer broadcast: all four must
	// change nothing, and one window covers them.
	inject.send(t, broadcast, allHW, good)
	inject.send(t, leased.Next(), allHW, good)
	flipped := append([]byte(nil), good...)
	flipped[bytes.Index(flipped, []byte{90, 28})+2+12] ^= 0x01
	inject.send(t, leased, mac, flipped)
	inject.send(t, leased, mac, frcFrame(mac, leased, frcNonce, frcServerReplay))
	if n := watch.requests(t, frcQuiet); n != 0 {
		t.Fatalf("(d)(e) %d DHCPREQUEST(s) left the client after a broadcast frame, another host's frame, a flipped digest and a stale replay value", n)
	}
	if got := srv.count("DHCPREQUEST(" + testServerIf + ") " + leased.String()); got != requests {
		t.Fatalf("(d)(e) dnsmasq logged %d REQUEST line(s) for %s, was %d.\nLog:\n%s", got, leased, requests, strings.Join(srv.lines(), "\n"))
	}

	// (b) the same signed frame, unicast, is obeyed.
	inject.send(t, leased, mac, good)
	if !watch.await(t) {
		t.Fatalf("(b) no DHCPREQUEST left the client within %s of the authenticated FORCERENEW.\nLog:\n%s", frcBound, strings.Join(srv.lines(), "\n"))
	}
	srv.waitCount(t, "DHCPREQUEST("+testServerIf+") "+leased.String(), requests+1, "the authenticated FORCERENEW was not answered")
	srv.waitCount(t, "DHCPACK("+testServerIf+") "+leased.String(), acks+1, "dnsmasq did not ACK the forced renewal")
	renewed := awaitEvent(t, c, lease.Renewed)
	// await consumed the one REQUEST; a second would already be queued.
	if n := watch.requests(t, frcDrain); n != 0 {
		t.Fatalf("(b) the observer saw %d further DHCPREQUEST(s) for the authenticated frame, want exactly 1", n+1)
	}
	if got := srv.count("DHCPDISCOVER("); got != discovers {
		t.Fatalf("(b) dnsmasq logged %d DHCPDISCOVER lines, %d before the frame: a re-acquisition, not a renewal.\nLog:\n%s",
			got, discovers, strings.Join(srv.lines(), "\n"))
	}
	reqXIDs := frcXIDs(srv.lines(), "REQUEST")
	forcedXID := reqXIDs[len(reqXIDs)-1]
	for _, old := range seenXIDs {
		if forcedXID == old {
			t.Fatalf("(b) the renewal REQUEST reuses xid %s of the acquisition", forcedXID)
		}
	}
	if ackXIDs := frcXIDs(srv.lines(), "ACK"); ackXIDs[len(ackXIDs)-1] != forcedXID {
		t.Fatalf("(b) the last ACK answers xid %s, the forced REQUEST was %s", ackXIDs[len(ackXIDs)-1], forcedXID)
	}
	if !bytes.Equal(renewed.Lease.ForcerenewNonce, frcNonce) || renewed.Lease.ForcerenewReplay != frcServerReplay+1 {
		t.Fatalf("(b) after the renewal the lease carries nonce %x floor %d, want the nonce and %d (the renewal ACK's own value is %d and must not lower it)",
			renewed.Lease.ForcerenewNonce, renewed.Lease.ForcerenewReplay, frcServerReplay+1, frcServerReplay)
	}

	// (c) the same bytes again: nothing.
	inject.send(t, leased, mac, good)
	if n := watch.requests(t, frcQuiet); n != 0 {
		t.Fatalf("(c) %d DHCPREQUEST(s) left the client for a replayed frame", n)
	}
	if got := srv.count("DHCPREQUEST(" + testServerIf + ") " + leased.String()); got != requests+1 {
		t.Fatalf("(c) dnsmasq logged %d REQUEST line(s) for %s, want %d.\nLog:\n%s", got, leased, requests+1, strings.Join(srv.lines(), "\n"))
	}

	// The control and the barrier: the next value is obeyed, so the client
	// was still listening, and it is processed after every frame above.
	inject.send(t, leased, mac, frcFrame(mac, leased, frcNonce, frcServerReplay+2))
	if !watch.await(t) {
		t.Fatalf("the next FORCERENEW value drew no DHCPREQUEST within %s", frcBound)
	}
	srv.waitCount(t, "DHCPREQUEST("+testServerIf+") "+leased.String(), requests+2, "the next FORCERENEW value was not answered")
	if got := awaitEvent(t, c, lease.Renewed).Lease.ForcerenewReplay; got != frcServerReplay+2 {
		t.Fatalf("floor after the second forced renewal = %d, want %d", got, frcServerReplay+2)
	}

	// Why each frame did what it did, in order, from the machine's journal.
	var notes []string
	for _, e := range c.Journal() {
		if e.Kind != proto.EvReceived || len(e.Raw) < 243 || e.Raw[242] != byte(wire.MsgForceRenew) {
			continue
		}
		var why string
		for _, a := range e.Actions {
			if strings.Contains(a, "DHCPFORCERENEW") {
				why = a
			}
		}
		notes = append(notes, why)
	}
	want := []string{"not unicast", "not this lease", "fails Forcerenew Nonce", "not above the floor", "accepted", "not above the floor", "accepted"}
	if len(notes) != len(want) {
		t.Fatalf("the journal holds %d FORCERENEW entries, want %d: %q", len(notes), len(want), notes)
	}
	for i := range want {
		if !strings.Contains(notes[i], want[i]) {
			t.Errorf("FORCERENEW entry %d reads %q, want it to say %q", i, notes[i], want[i])
		}
	}
}
