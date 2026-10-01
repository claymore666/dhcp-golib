// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package lease

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"net/netip"
	"runtime"
	"testing"

	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

// frDispatchNonce is the key the fixture server hands out in its ACKs.
var frDispatchNonce = []byte{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50}

// answerWithANonce is answerNormally whose OFFER and ACK carry what RFC 6704
// section 3.1.3 gives: option 145 in the OFFER and option 90 type 1 in the ACK.
func answerWithANonce(t *testing.T) serverBehaviour {
	t.Helper()
	auth, err := wire.EncodeForcerenewAuth(wire.ForcerenewTypeNonce, frDispatchNonce, 3)
	if err != nil {
		t.Fatalf("EncodeForcerenewAuth: %v", err)
	}
	return func(req *wire.Message, n int) []*wire.Message {
		out := answerNormally(req, n)
		for _, m := range out {
			switch mt, _ := m.Type(); mt {
			case wire.MsgOffer:
				m.Options[wire.OptForcerenewNonce] = wire.EncodeForcerenewNonceCapable()
			case wire.MsgAck:
				m.Options[wire.OptAuthentication] = auth
			}
		}
		return out
	}
}

// signedForcerenew builds a FORCERENEW for the fixture's client and signs it
// with HMAC-MD5 over the encoded octets, found by walking the options and not
// by asking the code under test where the digest is (RFC 3118 section 5.3).
func signedForcerenew(t *testing.T, replay uint64) []byte {
	t.Helper()
	auth, err := wire.EncodeForcerenewAuth(wire.ForcerenewTypeDigest, make([]byte, md5.Size), replay)
	if err != nil {
		t.Fatalf("EncodeForcerenewAuth: %v", err)
	}
	raw, err := wire.Encode(&wire.Message{
		Op: wire.BootReply, HType: wire.HTypeEthernet, XID: 0x0BADF00D,
		CIAddr: netip.MustParseAddr(testYIAddr),
		CHAddr: testParams().CHAddr,
		Options: wire.Options{
			wire.OptMessageType:    {byte(wire.MsgForceRenew)},
			wire.OptServerID:       addr4(testServerID),
			wire.OptAuthentication: auth,
		},
	})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	at := -1
	for i := 240; i+2 <= len(raw) && raw[i] != 255; {
		if raw[i] == byte(wire.OptAuthentication) {
			at = i + 2 + 12
			break
		}
		if raw[i] == 0 {
			i++
			continue
		}
		i += 2 + int(raw[i+1])
	}
	if at < 0 {
		t.Fatal("the FORCERENEW built has no option 90")
	}
	buf := append([]byte(nil), raw...)
	clear(buf[at : at+md5.Size])
	buf[3] = 0
	clear(buf[24:28])
	h := hmac.New(md5.New, frDispatchNonce)
	h.Write(buf)
	copy(raw[at:], h.Sum(nil))
	return raw
}

// injectTo is the v4 counterpart of fakeServer6.injectTo: a datagram with the
// destination a FORCERENEW is decided on, which injectRaw does not report.
func (s *fakeServer) injectTo(raw []byte, to netip.Addr) {
	select {
	case s.inbound <- Inbound{Payload: raw, From: netip.MustParseAddr(testServerID), To: to}:
	case <-s.closed:
	}
}

// frRequests counts the DHCPREQUESTs the server has decoded.
func frRequests(r *rig) int {
	n := 0
	for _, m := range r.server.sentMessages() {
		if mt, _ := m.Type(); mt == wire.MsgRequest {
			n++
		}
	}
	return n
}

// frSettle returns once the manager has handled everything injected before
// it. The manager is one goroutine, and a payload that does not decode is
// counted by Stats and does nothing else, so its count is a barrier that holds
// whether or not the frame before it was obeyed: a failing run reports, where
// waiting for the renewal would hang.
func frSettle(t *testing.T, r *rig, undecodable uint64) {
	t.Helper()
	r.server.injectRaw([]byte{0x01})
	for r.mgr.Stats().DecodeFailures < undecodable {
		runtime.Gosched()
	}
}

// TestTheDestinationOfADatagramReachesRing1 drives the dispatch seam of
// claymore666/docker-net-dhcp#1119 at the manager: Inbound.To is the only place
// a FORCERENEW's destination exists, and a manager that dropped it would
// refuse every authentic frame as not unicast.
//
// A frame with no destination goes first and a frame to the leased address
// second, each followed by a barrier, so the REQUEST count after each says
// which one the manager acted on.
func TestTheDestinationOfADatagramReachesRing1(t *testing.T) {
	r := newRig(t, testParams(), answerWithANonce(t), Fault{})
	if ev := r.nextEvent(t); ev.Kind != Acquired {
		t.Fatalf("first event is %s, want acquired", ev)
	}
	held, _ := r.mgr.Lease()
	if !bytes.Equal(held.ForcerenewNonce, frDispatchNonce) || held.ForcerenewReplay != 3 {
		t.Fatalf("the acquired lease holds nonce %x floor %d, want the ACK's", held.ForcerenewNonce, held.ForcerenewReplay)
	}
	if got := frRequests(r); got != 1 {
		t.Fatalf("the server saw %d REQUESTs after the acquisition, want 1", got)
	}

	addr := netip.MustParseAddr(testYIAddr)
	r.server.injectRaw(signedForcerenew(t, 4))
	frSettle(t, r, 1)
	if got := frRequests(r); got != 1 {
		t.Fatalf("a frame with no destination started %d REQUEST(s) in all, want none", got-1)
	}
	if got, _ := r.mgr.Lease(); got.ForcerenewReplay != 3 {
		t.Fatalf("a refused frame moved the floor to %d", got.ForcerenewReplay)
	}

	frame := signedForcerenew(t, 5)
	r.server.injectTo(frame, addr)
	frSettle(t, r, 2)
	if got := frRequests(r); got != 2 {
		t.Fatalf("the server saw %d REQUESTs after the frame to the leased address, want 2", got)
	}
	// The renewal's ACK carries the original replay value, 3, and the floor
	// the outward lease reports after it is still 5.
	if ev := r.nextEvent(t); ev.Kind != Renewed || ev.Lease.ForcerenewReplay != 5 {
		t.Fatalf("event after the authentic FORCERENEW is %s with floor %d, want renewed with 5", ev, ev.Lease.ForcerenewReplay)
	}
	e := findEntry(t, r, "the frame to the leased address", func(e proto.JournalEntry) bool {
		return isForcerenewEntry(e) && e.Dst == addr
	})
	if !bytes.Equal(e.Raw, frame) {
		t.Fatal("the journalled octets are not the frame sent")
	}
}

// isForcerenewEntry says whether a journalled Step consumed a FORCERENEW.
func isForcerenewEntry(e proto.JournalEntry) bool {
	if e.Kind != proto.EvReceived {
		return false
	}
	m, err := wire.Decode(e.Raw)
	if err != nil {
		return false
	}
	mt, _ := m.Type()
	return mt == wire.MsgForceRenew
}
