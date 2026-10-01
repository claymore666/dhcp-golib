// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package proto

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// A restart must not cost a client its Reconfigure key or its replay floor
// (claymore666/dhcp-golib#28). These tests build only from fakes6_test.go and
// fakes_test.go: the Reconfigure is signed here with its own digest walk, so a
// fault in another test file's signer cannot make these pass or fail.

var (
	persistKey      = mustHexBytes("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
	persistOtherKey = mustHexBytes("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf")
	persistOtherSrv = mustHexBytes("00010001322ecbbf0102030405ff")
	persistDst      = netip.MustParseAddr("fd00:99::183")
)

// persistSigned is a Reconfigure naming typ, from server, signed with key and
// carrying replay, delivered to a unicast destination. RFC 9915 §20.4.3: the
// HMAC-MD5 is computed with zeroes in the digest field. The 0xa5 placeholder
// makes a signer that forgot to zero the field produce a digest nobody
// verifies.
func persistSigned(t *testing.T, server, key []byte, replay uint64, typ wire.MessageTypeV6) Event {
	t.Helper()
	msgType, err := wire.EncodeReconfigureMessage(typ)
	if err != nil {
		t.Fatalf("EncodeReconfigureMessage: %v", err)
	}
	auth, err := wire.EncodeRKAPAuth(wire.RKAPTypeDigest, bytes.Repeat([]byte{0xa5}, md5.Size), replay)
	if err != nil {
		t.Fatalf("EncodeRKAPAuth: %v", err)
	}
	raw, err := wire.EncodeV6(&wire.MessageV6{Type: wire.MsgReconfigure, XID: 0x1234, Options: wire.OptionsV6{
		optClientID(capDUID), optServerID(server),
		{Code: wire.OptV6ReconfMsg, Data: msgType},
		{Code: wire.OptV6Auth, Data: auth},
	}})
	if err != nil {
		t.Fatalf("EncodeV6: %v", err)
	}
	// §21.11: option code, length, protocol, algorithm, RDM, eight octets of
	// replay detection, the Type octet, then the sixteen-octet digest.
	start := -1
	for i := 4; i+4 <= len(raw); {
		code := int(raw[i])<<8 | int(raw[i+1])
		n := int(raw[i+2])<<8 | int(raw[i+3])
		i += 4
		if code == int(wire.OptV6Auth) {
			start = i + 1 + 1 + 1 + 8 + 1
			break
		}
		i += n
	}
	if start < 0 {
		t.Fatalf("no Authentication option in %x", raw)
	}
	zeroed := append([]byte(nil), raw...)
	for i := start; i < start+md5.Size; i++ {
		zeroed[i] = 0
	}
	mac := hmac.New(md5.New, key)
	mac.Write(zeroed)
	copy(raw[start:start+md5.Size], mac.Sum(nil))
	msg, err := wire.DecodeV6(raw)
	if err != nil {
		t.Fatalf("DecodeV6: %v", err)
	}
	return ReceivedV6To(msg, raw, persistDst)
}

// persistResume is the record a caller persisted after a run that held
// dnsmasqLeasedAddr from testServerDUID, with the key state under test.
func persistResume(key []byte, replay uint64, seen bool) *Resume6 {
	return &Resume6{
		Addrs:                 []Addr6{{Addr: addr6(dnsmasqLeasedAddr), Preferred: 300 * Second, Valid: 300 * Second}},
		ServerDUID:            append([]byte(nil), testServerDUID...),
		T1:                    150 * Second,
		T2:                    240 * Second,
		ReconfigureKey:        append([]byte(nil), key...),
		ReconfigureReplay:     replay,
		ReconfigureReplaySeen: seen,
	}
}

// persistLease is the newest lease an action list carries.
func persistLease(acts []Action) (Lease6, bool) {
	var out Lease6
	var ok bool
	for _, a := range acts {
		switch a.Kind {
		case ActLeaseAcquired, ActLeaseChanged, ActLeaseRenewed:
			if len(a.Lease6.Addrs) > 0 {
				out, ok = a.Lease6, true
			}
		}
	}
	return out, ok
}

// persistBound takes a machine built from r through the confirm and the
// duplicate address detection to BOUND6. The Confirm's Reply carries no key,
// which is RFC 9915 §20.4.2's norm: only the exchanges it names carry one. It
// returns every action emitted on the way.
func persistBound(t *testing.T, r *Resume6) (*Machine6, []Action) {
	t.Helper()
	p := testParams6()
	p.Resume = r
	m := newMachine6(t, p)
	var all []Action
	_, acts := m.Step(at(0), 0, Simple(EvStart))
	all = append(all, acts...)
	s, acts := m.Step(at(1), capXIDSolicit, TimerFired(Timer6Delay))
	all = append(all, acts...)
	if s != State6Confirming {
		t.Fatalf("a live resume left the machine in %s, want %s", s, State6Confirming)
	}
	conf := mustSendV6(t, acts, wire.MsgConfirm)
	s, acts = m.Step(at(2), 3, receivedV6(t, wire.MsgReply, conf.XID,
		optClientID(capDUID), optServerID(testServerDUID), optStatus(wire.StatusSuccess)))
	all = append(all, acts...)
	if s != State6DAD {
		t.Fatalf("the confirming Reply left the machine in %s, want %s", s, State6DAD)
	}
	s, acts = m.Step(at(4), 0, DADResult(addr6(dnsmasqLeasedAddr), false))
	all = append(all, acts...)
	if s != State6Bound {
		t.Fatalf("a clean DAD result left the machine in %s, want %s", s, State6Bound)
	}
	return m, all
}

// persistAccepts reports whether a Reconfigure at replay from server, signed
// with key, starts a Renew; it returns the Renew's actions.
func persistAccepts(t *testing.T, m *Machine6, now int64, server, key []byte, replay uint64) (bool, []Action) {
	t.Helper()
	s, acts := m.Step(at(now), 7, persistSigned(t, server, key, replay, wire.MsgRenew))
	return s == State6Renewing, acts
}

func persistRefused(m *Machine6, why ReconfigureRefusal) uint64 {
	return m.ReconfigureCounters().Refused[why]
}

// TestAResumedLeaseAuthenticatesAReconfigureSignedWithItsRestoredKey is the
// feature: a client restarted from a record that holds the key accepts the
// server's Reconfigure, and a Renew follows.
func TestAResumedLeaseAuthenticatesAReconfigureSignedWithItsRestoredKey(t *testing.T) {
	m, _ := persistBound(t, persistResume(persistKey, 40, true))
	ok, acts := persistAccepts(t, m, 10, testServerDUID, persistKey, 41)
	if !ok {
		t.Fatalf("a Reconfigure at floor+1 signed with the restored key was refused: %+v", m.ReconfigureCounters())
	}
	mustSendV6(t, acts, wire.MsgRenew)
	if c := m.ReconfigureCounters(); c.Accepted != 1 || c.RefusedTotal() != 0 {
		t.Errorf("counters after one accepted Reconfigure: %+v", c)
	}
}

// TestAResumedLeaseRefusesAReconfigureSignedWithAnotherKey keeps the test above
// honest: it would pass for a machine that accepted anything.
func TestAResumedLeaseRefusesAReconfigureSignedWithAnotherKey(t *testing.T) {
	m, _ := persistBound(t, persistResume(persistKey, 40, true))
	if ok, _ := persistAccepts(t, m, 10, testServerDUID, persistOtherKey, 41); ok {
		t.Fatal("a Reconfigure signed with a key the client never held was accepted")
	}
	if got := persistRefused(m, ReconfigureRefusalBadDigest); got != 1 {
		t.Errorf("BadDigest refusals: %d, want 1", got)
	}
}

// TestAResumedLeaseRefusesAReplayAtItsRestoredFloor is RFC 9915 §20.3 across a
// restart: a value that does not exceed the recorded floor is refused, with
// the refusal that names the rule.
func TestAResumedLeaseRefusesAReplayAtItsRestoredFloor(t *testing.T) {
	for _, tc := range []struct {
		name   string
		replay uint64
	}{{"the floor itself", 40}, {"below the floor", 39}, {"zero, the wrap", 0}} {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := persistBound(t, persistResume(persistKey, 40, true))
			if ok, _ := persistAccepts(t, m, 10, testServerDUID, persistKey, tc.replay); ok {
				t.Fatalf("a Reconfigure with %s was accepted after a restart", tc.name)
			}
			if got := persistRefused(m, ReconfigureRefusalReplay); got != 1 {
				t.Errorf("Replay refusals: %d, want 1", got)
			}
		})
	}
}

// TestAResumedFloorOfZeroIsNotAnUnseenFloor is why there are three fields: a
// floor of 0 that was seen refuses 0, and "no value seen yet" accepts the
// first value whatever it is (§20.3).
func TestAResumedFloorOfZeroIsNotAnUnseenFloor(t *testing.T) {
	t.Run("seen at zero refuses zero", func(t *testing.T) {
		m, _ := persistBound(t, persistResume(persistKey, 0, true))
		if ok, _ := persistAccepts(t, m, 10, testServerDUID, persistKey, 0); ok {
			t.Fatal("a replayed Reconfigure with value 0 was accepted although 0 was the recorded floor")
		}
		if got := persistRefused(m, ReconfigureRefusalReplay); got != 1 {
			t.Errorf("Replay refusals: %d, want 1", got)
		}
	})
	t.Run("seen at zero accepts one", func(t *testing.T) {
		m, _ := persistBound(t, persistResume(persistKey, 0, true))
		if ok, _ := persistAccepts(t, m, 10, testServerDUID, persistKey, 1); !ok {
			t.Fatal("value 1 over a recorded floor of 0 was refused")
		}
	})
	t.Run("unseen accepts zero", func(t *testing.T) {
		m, _ := persistBound(t, persistResume(persistKey, 0, false))
		if ok, _ := persistAccepts(t, m, 10, testServerDUID, persistKey, 0); !ok {
			t.Fatal("the first value was refused although no value had been seen")
		}
	})
	t.Run("a floor with the flag lost is still a floor", func(t *testing.T) {
		m, _ := persistBound(t, persistResume(persistKey, 9, false))
		if ok, _ := persistAccepts(t, m, 10, testServerDUID, persistKey, 9); ok {
			t.Fatal("a nonzero recorded floor was treated as unseen and its value accepted again")
		}
	})
}

// TestAResumeWithoutAKeyRefusesAReconfigureForWantOfAKey is today's behaviour
// kept: an empty key restores nothing, floor or no floor.
func TestAResumeWithoutAKeyRefusesAReconfigureForWantOfAKey(t *testing.T) {
	m, _ := persistBound(t, persistResume(nil, 40, true))
	if ok, _ := persistAccepts(t, m, 10, testServerDUID, persistKey, 41); ok {
		t.Fatal("a Reconfigure was accepted by a client holding no key")
	}
	if got := persistRefused(m, ReconfigureRefusalNoKey); got != 1 {
		t.Errorf("NoKey refusals: %d, want 1", got)
	}
}

// TestAFloorWithNoKeyIsNotRestored: a floor belongs to a key. A record that
// holds a value and no key restores nothing, so the key a later Reply brings
// starts from "no value seen yet" and not from a number nobody can account for.
func TestAFloorWithNoKeyIsNotRestored(t *testing.T) {
	m, _ := persistBound(t, persistResume(nil, 40, true))
	_, acts := m.Step(at(100), 0, TimerFired(Timer6Renew))
	renew := mustSendV6(t, acts, wire.MsgRenew)
	auth, err := wire.EncodeRKAPAuth(wire.RKAPTypeKey, persistKey, 0)
	if err != nil {
		t.Fatalf("EncodeRKAPAuth: %v", err)
	}
	rep := receivedV6(t, wire.MsgReply, renew.XID,
		optClientID(capDUID), optServerID(testServerDUID),
		optIANA(t, capIAID, 150, 240, []iaAddrSpec{{dnsmasqLeasedAddr, 300, 300}}),
		wire.OptionV6{Code: wire.OptV6Auth, Data: auth})
	if s, _ := m.Step(at(101), 0, rep); s != State6Bound {
		t.Fatalf("the Reply left the machine in %s", s)
	}
	if ok, _ := persistAccepts(t, m, 110, testServerDUID, persistKey, 5); !ok {
		t.Fatal("a floor recorded without its key was applied to the key a later Reply brought")
	}
}

// TestARestoredKeyBelongsToTheLeasesServerOnly: another server's Reconfigure,
// signed even with the restored key, finds no key under its own identifier.
func TestARestoredKeyBelongsToTheLeasesServerOnly(t *testing.T) {
	m, _ := persistBound(t, persistResume(persistKey, 40, true))
	if ok, _ := persistAccepts(t, m, 10, persistOtherSrv, persistKey, 41); ok {
		t.Fatal("a server other than the lease's was authenticated by the restored key")
	}
	if got := persistRefused(m, ReconfigureRefusalNoKey); got != 1 {
		t.Errorf("NoKey refusals: %d, want 1", got)
	}
}

// TestAKeylessReplyAfterResumeKeepsTheRestoredKeyAndFloor: the Reply to the
// Renew a Reconfigure started carries no key, and the next Reconfigure is still
// authenticated and still checked against the floor the first one raised.
func TestAKeylessReplyAfterResumeKeepsTheRestoredKeyAndFloor(t *testing.T) {
	m, _ := persistBound(t, persistResume(persistKey, 40, true))
	ok, acts := persistAccepts(t, m, 10, testServerDUID, persistKey, 41)
	if !ok {
		t.Fatal("the first Reconfigure was refused")
	}
	renew := mustSendV6(t, acts, wire.MsgRenew)
	if s, _ := m.Step(at(12), 0, reply(t, renew.XID, dnsmasqLeasedAddr)); s != State6Bound {
		t.Fatalf("the keyless Reply left the machine in %s", s)
	}
	if ok, _ := persistAccepts(t, m, 20, testServerDUID, persistKey, 41); ok {
		t.Fatal("the floor the accepted Reconfigure raised was lost with the keyless Reply")
	}
	if ok, _ := persistAccepts(t, m, 21, testServerDUID, persistKey, 42); !ok {
		t.Fatal("the restored key was lost with the keyless Reply")
	}
}

// TestEveryLeaseFromAReplyCarriesTheStoreEntry is what the record sees: the
// lease the machine emits holds the key and the floor, and the floor moves at
// the Reply the Renew brings, not before, because an Information-request
// Reconfigure emits no lease (claymore666/dhcp-golib#28).
func TestEveryLeaseFromAReplyCarriesTheStoreEntry(t *testing.T) {
	t.Run("a Solicit-path lease carries the key and no floor yet", func(t *testing.T) {
		m, _ := solicit6(t, testParams6())
		var all []Action
		_, a := m.Step(at(2), capXIDRequest, advertise(t, uint32(capXIDSolicit), 255))
		all = append(all, a...)
		_, a = m.Step(at(3), 0, replyWithKey(t, uint32(capXIDRequest), dnsmasqLeasedAddr, persistKey))
		all = append(all, a...)
		_, a = m.Step(at(4), 0, DADResult(addr6(dnsmasqLeasedAddr), false))
		all = append(all, a...)
		l, ok := persistLease(all)
		if !ok {
			t.Fatal("no lease was emitted")
		}
		if !bytes.Equal(l.ReconfigureKey, persistKey) {
			t.Errorf("the lease's key is %x, want %x", l.ReconfigureKey, persistKey)
		}
		if l.ReconfigureReplay != 0 || l.ReconfigureReplaySeen {
			t.Errorf("a lease before any Reconfigure holds a floor: %d seen=%v", l.ReconfigureReplay, l.ReconfigureReplaySeen)
		}
	})
	t.Run("the Reply after an accepted Reconfigure carries the moved floor", func(t *testing.T) {
		m, _ := persistBound(t, persistResume(persistKey, 0, false))
		ok, acts := persistAccepts(t, m, 10, testServerDUID, persistKey, 77)
		if !ok {
			t.Fatal("the Reconfigure was refused")
		}
		if l, has := persistLease(acts); has && l.ReconfigureReplaySeen {
			t.Error("the floor reached the lease before the Reply: the stated bound moved")
		}
		renew := mustSendV6(t, acts, wire.MsgRenew)
		_, acts = m.Step(at(12), 0, reply(t, renew.XID, dnsmasqLeasedAddr))
		l, has := persistLease(acts)
		if !has {
			t.Fatal("the Reply to the Renew emitted no lease")
		}
		if l.ReconfigureReplay != 77 || !l.ReconfigureReplaySeen {
			t.Errorf("the renewed lease holds floor %d seen=%v, want 77 true", l.ReconfigureReplay, l.ReconfigureReplaySeen)
		}
		if !bytes.Equal(l.ReconfigureKey, persistKey) {
			t.Errorf("the keyless Reply erased the key from the lease: %x", l.ReconfigureKey)
		}
	})
	t.Run("a resumed lease carries what it was restored with", func(t *testing.T) {
		_, all := persistBound(t, persistResume(persistKey, 40, true))
		l, ok := persistLease(all)
		if !ok {
			t.Fatal("the confirm path emitted no lease")
		}
		if !bytes.Equal(l.ReconfigureKey, persistKey) || l.ReconfigureReplay != 40 || !l.ReconfigureReplaySeen {
			t.Errorf("the resumed lease holds key %x floor %d seen=%v", l.ReconfigureKey, l.ReconfigureReplay, l.ReconfigureReplaySeen)
		}
	})
	t.Run("a resume without a key emits a keyless lease", func(t *testing.T) {
		_, all := persistBound(t, persistResume(nil, 40, true))
		l, ok := persistLease(all)
		if !ok {
			t.Fatal("the confirm path emitted no lease")
		}
		if len(l.ReconfigureKey) != 0 || l.ReconfigureReplay != 0 || l.ReconfigureReplaySeen {
			t.Errorf("a keyless resume emitted key %x floor %d seen=%v", l.ReconfigureKey, l.ReconfigureReplay, l.ReconfigureReplaySeen)
		}
	})
}

// TestTheMachineAndItsLeasesShareNoKeyBytes: the caller owns what it was
// handed and the machine owns its store, in both directions.
func TestTheMachineAndItsLeasesShareNoKeyBytes(t *testing.T) {
	r := persistResume(persistKey, 40, true)
	m, all := persistBound(t, r)

	// Scribbling on the caller's Resume6 after construction.
	for i := range r.ReconfigureKey {
		r.ReconfigureKey[i] ^= 0xff
	}
	// Scribbling on an emitted lease.
	l, ok := persistLease(all)
	if !ok {
		t.Fatal("no lease was emitted")
	}
	for i := range l.ReconfigureKey {
		l.ReconfigureKey[i] ^= 0xff
	}
	if ok, _ := persistAccepts(t, m, 10, testServerDUID, persistKey, 41); !ok {
		t.Fatal("the store was changed through a slice the caller or a lease held")
	}
}

// TestResume6CloneCopiesTheKey: Clone is what Params6.Clone hands the machine,
// and it must not alias the caller's slice.
func TestResume6CloneCopiesTheKey(t *testing.T) {
	r := persistResume(persistKey, 40, true)
	c := r.Clone()
	if !bytes.Equal(c.ReconfigureKey, persistKey) || c.ReconfigureReplay != 40 || !c.ReconfigureReplaySeen {
		t.Fatalf("the clone lost a field: key %x floor %d seen=%v", c.ReconfigureKey, c.ReconfigureReplay, c.ReconfigureReplaySeen)
	}
	c.ReconfigureKey[0] ^= 0xff
	if r.ReconfigureKey[0] != persistKey[0] {
		t.Error("the clone shares its key with the original")
	}
}

// TestNoActionNoteReasonOrLeaseTextCarriesTheRestoredKey: the key is in the
// record and nowhere else the machine writes (the rule noteReconfigureKey
// states). Lease6.String is checked as well, because the lease now carries it.
func TestNoActionNoteReasonOrLeaseTextCarriesTheRestoredKey(t *testing.T) {
	m, all := persistBound(t, persistResume(persistKey, 40, true))
	_, acts := persistAccepts(t, m, 10, testServerDUID, persistKey, 41)
	all = append(all, acts...)
	renew := mustSendV6(t, acts, wire.MsgRenew)
	_, acts = m.Step(at(12), 0, reply(t, renew.XID, dnsmasqLeasedAddr))
	all = append(all, acts...)
	_, acts = persistAccepts(t, m, 20, testServerDUID, persistOtherKey, 50)
	all = append(all, acts...)

	hexKey := hex.EncodeToString(persistKey)
	for _, a := range all {
		text := a.Note + " " + a.Reason.String() + " " + a.Lease6.String()
		if strings.Contains(strings.ToLower(text), hexKey) || bytes.Contains([]byte(text), persistKey) {
			t.Fatalf("the reconfigure key appears in an action's text: %q", text)
		}
	}
}

// persistReply is a Reply to the exchange xid from server, carrying key when
// there is one.
func persistReply(t *testing.T, xid uint32, server, key []byte) Event {
	t.Helper()
	opts := []wire.OptionV6{
		optClientID(capDUID), optServerID(server),
		optIANA(t, capIAID, 150, 240, []iaAddrSpec{{dnsmasqLeasedAddr, 300, 300}}),
	}
	if key != nil {
		auth, err := wire.EncodeRKAPAuth(wire.RKAPTypeKey, key, 0)
		if err != nil {
			t.Fatalf("EncodeRKAPAuth: %v", err)
		}
		opts = append(opts, wire.OptionV6{Code: wire.OptV6Auth, Data: auth})
	}
	return receivedV6(t, wire.MsgReply, xid, opts...)
}

// TestTheLeaseCarriesTheEntryOfTheServerThatAnsweredNotTheOneBefore: a Renew
// answered by another server, with a key of its own, emits a lease holding that
// server's key and no floor, and not the first server's.
func TestTheLeaseCarriesTheEntryOfTheServerThatAnsweredNotTheOneBefore(t *testing.T) {
	m, _ := persistBound(t, persistResume(persistKey, 40, true))
	_, acts := m.Step(at(100), 0, TimerFired(Timer6Renew))
	renew := mustSendV6(t, acts, wire.MsgRenew)
	s, acts := m.Step(at(101), 0, persistReply(t, renew.XID, persistOtherSrv, persistOtherKey))
	if s != State6Bound {
		t.Fatalf("the Reply from the second server left the machine in %s", s)
	}
	l, ok := persistLease(acts)
	if !ok {
		t.Fatal("no lease was emitted")
	}
	if !bytes.Equal(l.ServerDUID, persistOtherSrv) || !bytes.Equal(l.ReconfigureKey, persistOtherKey) ||
		l.ReconfigureReplay != 0 || l.ReconfigureReplaySeen {
		t.Errorf("the lease holds server %x key %x floor %d seen=%v, want the second server's entry",
			l.ServerDUID, l.ReconfigureKey, l.ReconfigureReplay, l.ReconfigureReplaySeen)
	}
}

// TestAFloorStepAloneEmitsRenewedAndNotChanged: the record sees the moved
// floor through the Renewed action every Reply emits, and an equality that
// compared it would add a Changed on every Reconfigure.
func TestAFloorStepAloneEmitsRenewedAndNotChanged(t *testing.T) {
	m, _ := persistBound(t, persistResume(persistKey, 40, true))
	_, acts := persistAccepts(t, m, 10, testServerDUID, persistKey, 41)
	renew := mustSendV6(t, acts, wire.MsgRenew)
	_, acts = m.Step(at(12), 0, persistReply(t, renew.XID, testServerDUID, nil))
	var renewed, changed int
	for _, a := range acts {
		switch a.Kind {
		case ActLeaseRenewed:
			renewed++
		case ActLeaseChanged:
			changed++
		}
	}
	if renewed != 1 || changed != 0 {
		t.Errorf("a floor step alone emitted %d Renewed and %d Changed, want 1 and 0", renewed, changed)
	}
}

// TestReplay6ReproducesARunThatStartedFromARestoredKey: the Params6 snapshot a
// journal is replayed with carries the key and the floor, so a Reconfigure the
// recorded run accepted is accepted by the replay.
func TestReplay6ReproducesARunThatStartedFromARestoredKey(t *testing.T) {
	p := testParams6()
	p.Resume = persistResume(persistKey, 40, true)
	m := newMachine6(t, p)
	var entries []JournalEntry6
	step := func(now Instant, rnd uint64, ev Event) (State6, []Action) {
		from := m.State()
		to, acts := m.Step(now, rnd, ev)
		entries = append(entries, NewJournalEntry6(uint64(len(entries)), now, rnd, ev, from, to, acts))
		return to, acts
	}
	step(at(0), 0, Simple(EvStart))
	_, acts := step(at(1), capXIDSolicit, TimerFired(Timer6Delay))
	conf := mustSendV6(t, acts, wire.MsgConfirm)
	step(at(2), 3, receivedV6(t, wire.MsgReply, conf.XID,
		optClientID(capDUID), optServerID(testServerDUID), optStatus(wire.StatusSuccess)))
	step(at(4), 0, DADResult(addr6(dnsmasqLeasedAddr), false))
	if s, _ := step(at(10), 7, persistSigned(t, testServerDUID, persistKey, 41, wire.MsgRenew)); s != State6Renewing {
		t.Fatalf("the recorded run refused its Reconfigure: %s", s)
	}

	res, err := Replay6(p, entries)
	if err != nil {
		t.Fatalf("Replay6: %v", err)
	}
	if res.State != State6Renewing || res.Steps != len(entries) {
		t.Fatalf("the replay ended in %s after %d steps, want %s after %d", res.State, res.Steps, State6Renewing, len(entries))
	}
}

// persistInfoDetour runs one Reconfigure naming an Information-request from a
// bound machine, through the Reply that ends it, and returns every action.
func persistInfoDetour(t *testing.T, m *Machine6, now int64, replay uint64) []Action {
	t.Helper()
	return persistInfoDetourKeyed(t, m, now, replay, nil)
}

// TestInformationRequestReconfiguresReachTheRecordAtTheNextLeaseReply states
// the bound the detour has: an Information-request Reconfigure moves the floor
// in the machine and emits no lease action, because ActLeaseRenewed says the
// lease was extended and nothing was. The record keeps the older floor until
// the next Reply that carries a lease, so a restart in that span accepts those
// Reconfigures a second time, and a run that goes on to the next Renew carries
// the moved floor into the record.
func TestInformationRequestReconfiguresReachTheRecordAtTheNextLeaseReply(t *testing.T) {
	m, acts := persistBound(t, persistResume(persistKey, 40, true))
	record, ok := persistLease(acts)
	if !ok || record.ReconfigureReplay != 40 || !record.ReconfigureReplaySeen {
		t.Fatalf("the record before the detours holds floor %d seen=%v, want 40 true", record.ReconfigureReplay, record.ReconfigureReplaySeen)
	}
	var detours []Action
	detours = append(detours, persistInfoDetour(t, m, 10, 50)...)
	detours = append(detours, persistInfoDetour(t, m, 20, 60)...)
	if l, ok := persistLease(detours); ok {
		t.Fatalf("an Information-request detour emitted a lease (floor %d): ActLeaseRenewed would claim an extension nothing made", l.ReconfigureReplay)
	}

	if s, _ := m.Step(at(30), 7, persistSigned(t, testServerDUID, persistKey, 50, wire.MsgRenew)); s == State6Renewing {
		t.Errorf("the running machine accepted a replay of 50 after 60")
	}

	// The restart: a machine built from the record the caller last saved.
	r, _ := persistBound(t, persistResume(persistKey, record.ReconfigureReplay, record.ReconfigureReplaySeen))
	if ok, _ := persistAccepts(t, r, 10, testServerDUID, persistKey, 50); !ok {
		t.Errorf("a restart in the span refused 50, which the stated bound says it accepts again")
	}

	// The next Reply that carries a lease writes the moved floor.
	_, acts = m.Step(at(40), 7, persistSigned(t, testServerDUID, persistKey, 61, wire.MsgRenew))
	renew := mustSendV6(t, acts, wire.MsgRenew)
	_, acts = m.Step(at(41), 0, persistReply(t, renew.XID, testServerDUID, nil))
	next, ok := persistLease(acts)
	if !ok || next.ReconfigureReplay != 61 {
		t.Errorf("the Renew's lease carries floor %d (found %v), want 61", next.ReconfigureReplay, ok)
	}
}

// persistInfoDetourKeyed is persistInfoDetour whose Reply carries key as the
// reconfigure key of RFC 9915 §20.4.1, or none when key is nil.
func persistInfoDetourKeyed(t *testing.T, m *Machine6, now int64, replay uint64, key []byte) []Action {
	t.Helper()
	s, acts := m.Step(at(now), 7, persistSigned(t, testServerDUID, persistKey, replay, wire.MsgInformationRequest))
	if s != State6InfoRequesting {
		t.Fatalf("a Reconfigure at %d naming Information-request left the machine in %s, want %s", replay, s, State6InfoRequesting)
	}
	sent := mustSendV6(t, acts, wire.MsgInformationRequest)
	all := append([]Action(nil), acts...)
	opts := []wire.OptionV6{optClientID(capDUID), optServerID(testServerDUID), optU32(wire.OptV6InfoRefresh, 3600)}
	if key != nil {
		auth, err := wire.EncodeRKAPAuth(wire.RKAPTypeKey, key, 0)
		if err != nil {
			t.Fatalf("EncodeRKAPAuth: %v", err)
		}
		opts = append(opts, wire.OptionV6{Code: wire.OptV6Auth, Data: auth})
	}
	s, acts = m.Step(at(now+1), 0, receivedV6(t, wire.MsgReply, sent.XID, opts...))
	if s != State6Bound {
		t.Fatalf("the Reply to the Information-request left the machine in %s, want %s", s, State6Bound)
	}
	return append(all, acts...)
}

// TestAKeyChangedInAnInformationRequestReplyReachesTheRecordAtTheNextLeaseReply
// is the key's window beside the floor's: a restart before the next lease Reply
// restores the earlier key and refuses Reconfigures signed with the new one
// (claymore666/dhcp-golib#28).
func TestAKeyChangedInAnInformationRequestReplyReachesTheRecordAtTheNextLeaseReply(t *testing.T) {
	m, acts := persistBound(t, persistResume(persistKey, 40, true))
	record, ok := persistLease(acts)
	if !ok || !bytes.Equal(record.ReconfigureKey, persistKey) {
		t.Fatalf("the record before the detour holds key %x (found %v), want %x", record.ReconfigureKey, ok, persistKey)
	}
	detour := persistInfoDetourKeyed(t, m, 10, 50, persistOtherKey)
	if l, ok := persistLease(detour); ok {
		t.Fatalf("an Information-request detour emitted a lease (key %x): the new key would already be in the record", l.ReconfigureKey)
	}

	// The running machine already holds the new key and no longer the old one.
	if ok, _ := persistAccepts(t, m, 20, testServerDUID, persistKey, 51); ok {
		t.Fatal("the running machine accepted a Reconfigure signed with the key the Reply replaced")
	}
	if got := persistRefused(m, ReconfigureRefusalBadDigest); got != 1 {
		t.Fatalf("BadDigest refusals in the running machine: %d, want 1", got)
	}

	// The restart: the record the caller last saved still holds the earlier
	// key, so the server's valid Reconfigure is refused until a Reply brings a key.
	r, _ := persistBound(t, persistResume(record.ReconfigureKey, record.ReconfigureReplay, record.ReconfigureReplaySeen))
	if ok, _ := persistAccepts(t, r, 10, testServerDUID, persistOtherKey, 51); ok {
		t.Fatal("a restart in the window accepted a Reconfigure signed with the new key, which the record cannot hold yet")
	}
	if got := persistRefused(r, ReconfigureRefusalBadDigest); got != 1 {
		t.Fatalf("BadDigest refusals after the restart: %d, want 1", got)
	}

	// The next Reply that carries a lease writes the new key.
	_, acts = m.Step(at(40), 7, persistSigned(t, testServerDUID, persistOtherKey, 52, wire.MsgRenew))
	renew := mustSendV6(t, acts, wire.MsgRenew)
	_, acts = m.Step(at(41), 0, persistReply(t, renew.XID, testServerDUID, nil))
	next, ok := persistLease(acts)
	if !ok || !bytes.Equal(next.ReconfigureKey, persistOtherKey) {
		t.Fatalf("the Renew's lease carries key %x (found %v), want %x", next.ReconfigureKey, ok, persistOtherKey)
	}
	r2, _ := persistBound(t, persistResume(next.ReconfigureKey, next.ReconfigureReplay, next.ReconfigureReplaySeen))
	if ok, _ := persistAccepts(t, r2, 10, testServerDUID, persistOtherKey, 53); !ok {
		t.Error("a restart from the record the lease Reply wrote refused a Reconfigure signed with the new key")
	}
}
