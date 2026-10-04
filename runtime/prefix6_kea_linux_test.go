// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

//go:build linux

package runtime

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/claymore666/dhcp-golib/lease"
	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

// Runtime half of claymore666/docker-net-dhcp#214, against a real Kea. The
// outcomes are the lease the client reports, Kea's own lease file and the
// message types a packet socket saw leave; the library's counters are not
// consulted.

const keaHint = 64

type keaRun struct {
	srv    *dnsmasqServer
	tap    *outTap
	client *Client6
	stop   func()
	duid   string
}

// keaStartClient builds the link, Kea with cfg and a client asking for a /64,
// and returns before the client has acquired anything
// (claymore666/docker-net-dhcp#214).
func keaStartClient(t *testing.T, cfg keaConfig, tweak func(*proto.Params6), resume *lease.Lease) *keaRun {
	t.Helper()
	wireUpV6(t)
	srv := keaStart(t, cfg)
	tap := newOutTap(t, test6ClientIf)
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
	if tweak != nil {
		tweak(&p)
	}
	c, err := NewClient6(ClientConfig6{Interface: test6ClientIf, Params6: p, EventBuffer: 8, PrefixHint: keaHint, Resume: resume})
	if err != nil {
		t.Fatalf("NewClient6: %v", err)
	}
	r := &keaRun{srv: srv, tap: tap, client: c, duid: duidText(duid)}
	r.stop = runV6Client(t, c)
	t.Cleanup(r.stop)
	return r
}

// pdRows is the rows of Kea's lease file for the delegated prefix p, oldest
// first (claymore666/docker-net-dhcp#214).
func (r *keaRun) pdRows(t *testing.T, p netip.Prefix) []keaRow {
	t.Helper()
	var out []keaRow
	for _, row := range keaRows(t, r.srv.leasefile) {
		if row.leaseType == keaLeasePD && row.addr == p.Addr().String() {
			out = append(out, row)
		}
	}
	return out
}

// onlyPrefix is the one delegated prefix of a lease, failing otherwise.
func onlyPrefix(t *testing.T, l lease.Lease) lease.Addr6 {
	t.Helper()
	if len(l.Prefixes) != 1 {
		t.Fatalf("the lease carries %d delegated prefixes, want 1: %+v", len(l.Prefixes), l)
	}
	return l.Prefixes[0]
}

func TestKeaDelegatesAPrefixAndKeepsItsRow(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		r := keaStartClient(t, keaConfig{pdPools: true}, nil, nil)
		ev := awaitV6(t, r.client, lease.Acquired)
		l := ev.Lease
		pfx := onlyPrefix(t, l)
		pool := netip.MustParsePrefix(fmt.Sprintf("%s/%d", keaPDPrefix, keaPDPoolLen))
		if !pool.Contains(pfx.Addr.Addr()) || pfx.Addr.Bits() != keaPDDelegated {
			t.Errorf("the delegated prefix %s is not a /%d inside %s", pfx.Addr, keaPDDelegated, pool)
		}
		if got, want := pfx.Valid.Sub(l.Acquired), time.Duration(keaValidSec)*time.Second; got > want || got < want-30*time.Second {
			t.Errorf("the prefix is valid for %v after the lease was acquired, Kea was told %v", got, want)
		}
		if got, want := pfx.Preferred.Sub(l.Acquired), time.Duration(keaPrefSec)*time.Second; got > want || got < want-30*time.Second {
			t.Errorf("the prefix is preferred for %v, Kea was told %v", got, want)
		}
		if got, want := l.Renew.Sub(l.Acquired), time.Duration(keaT1Sec)*time.Second; got > want || got < want-30*time.Second {
			t.Errorf("T1 is %v after the acquisition, Kea sent %v", got, want)
		}
		if got, want := l.Rebind.Sub(l.Acquired), time.Duration(keaT2Sec)*time.Second; got > want || got < want-30*time.Second {
			t.Errorf("T2 is %v after the acquisition, Kea sent %v", got, want)
		}
		if len(l.Addrs) != 1 || l.Addrs[0].Addr.Bits() != 128 && l.Addrs[0].Addr.Bits() != test6PrefixLn {
			t.Errorf("Addrs = %+v, want the one address and no prefix among them", l.Addrs)
		}

		rows := r.pdRows(t, pfx.Addr)
		if len(rows) == 0 {
			t.Fatalf("Kea's lease file has no PD row for %s:\n%s", pfx.Addr, strings.Join(r.srv.lines(), "\n"))
		}
		row := rows[len(rows)-1]
		if row.duid != r.duid || row.prefixLen != keaPDDelegated || row.valid != keaValidSec {
			t.Errorf("Kea's PD row is %+v, want DUID %s, /%d, valid %d", row, r.duid, keaPDDelegated, keaValidSec)
		}

		sol := r.tap.ofType(wire.MsgSolicit)
		if len(sol) == 0 {
			t.Fatal("no Solicit left the client")
		}
		assertHintIAPD(t, sol[0])
		r.tap.waitCount(t, wire.MsgRequest6, 1)
		req := r.tap.ofType(wire.MsgRequest6)[0]
		pds, err := req.Options.IAPDs()
		if err != nil || len(pds) != 1 {
			t.Fatalf("the Request's IA_PDs = %v, %v, want one", pds, err)
		}
		if got, _ := pds[0].Options.Prefixes(); len(got) != 1 || got[0].Prefix != pfx.Addr {
			t.Errorf("the Request's IA_PD names %v, want the advertised %s", got, pfx.Addr)
		}
		return
	}
	reexecInNamespaces(t)
}

// assertHintIAPD checks a message carries one IA_PD with the client's IAID and
// one IA Prefix of the hinted length and zero lifetimes
// (claymore666/docker-net-dhcp#214).
func assertHintIAPD(t *testing.T, m *wire.MessageV6) {
	t.Helper()
	pds, err := m.Options.IAPDs()
	if err != nil || len(pds) != 1 {
		t.Fatalf("the %v's IA_PDs = %v, %v, want one", m.Type, pds, err)
	}
	if pds[0].IAID != 0x0a0b0c0d {
		t.Errorf("the IA_PD's IAID is %#x, want the IA_NA's", pds[0].IAID)
	}
	got, err := pds[0].Options.Prefixes()
	if err != nil || len(got) != 1 {
		t.Fatalf("the hint IA_PD carries %v, %v, want one IA Prefix", got, err)
	}
	if got[0].Prefix.Bits() != keaHint || got[0].PreferredLifetime != 0 || got[0].ValidLifetime != 0 {
		t.Errorf("the hint is %+v, want a /%d with zero lifetimes", got[0], keaHint)
	}
}

func TestKeaRenewsThePrefixRow(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		r := keaStartClient(t, keaConfig{pdPools: true}, nil, nil)
		first := awaitV6(t, r.client, lease.Acquired).Lease
		pfx := onlyPrefix(t, first)
		before := r.pdRows(t, pfx.Addr)
		if len(before) == 0 {
			t.Fatalf("Kea's lease file has no PD row after the grant:\n%s", strings.Join(r.srv.lines(), "\n"))
		}

		if err := r.client.SetHostname("renamed-after-pd"); err != nil {
			t.Fatalf("SetHostname: %v", err)
		}
		renewed := awaitV6(t, r.client, lease.Renewed).Lease
		if got := onlyPrefix(t, renewed); got.Addr != pfx.Addr {
			t.Errorf("the renewal reports %s, the grant was %s", got.Addr, pfx.Addr)
		}
		r.tap.waitCount(t, wire.MsgRenew, 1)
		if n := r.tap.count(wire.MsgSolicit); n != 1 {
			t.Errorf("%d Solicits left the client: a re-acquisition, not a renewal", n)
		}
		renew := r.tap.ofType(wire.MsgRenew)[0]
		pds, err := renew.Options.IAPDs()
		if err != nil || len(pds) != 1 {
			t.Fatalf("the Renew's IA_PDs = %v, %v, want one", pds, err)
		}
		if got, _ := pds[0].Options.Prefixes(); len(got) != 1 || got[0].Prefix != pfx.Addr {
			t.Errorf("the Renew's IA_PD names %v, want the held %s", got, pfx.Addr)
		}

		after := r.pdRows(t, pfx.Addr)
		if len(after) <= len(before) {
			t.Fatalf("Kea's lease file holds %d row(s) for %s after the Renew, %d before it:\n%s",
				len(after), pfx.Addr, len(before), strings.Join(r.srv.lines(), "\n"))
		}
		last := after[len(after)-1]
		if last.expire < before[len(before)-1].expire || last.valid != keaValidSec || last.duid != r.duid {
			t.Errorf("the renewed PD row is %+v after %+v", last, before[len(before)-1])
		}
		return
	}
	reexecInNamespaces(t)
}

func TestKeaTakesAReleasedPrefixBack(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		r := keaStartClient(t, keaConfig{pdPools: true}, nil, nil)
		pfx := onlyPrefix(t, awaitV6(t, r.client, lease.Acquired).Lease)
		if rows := r.pdRows(t, pfx.Addr); len(rows) == 0 || rows[len(rows)-1].valid != keaValidSec {
			t.Fatalf("Kea does not hold %s before the Release: %+v", pfx.Addr, rows)
		}

		r.client.Release()
		if rel := awaitV6(t, r.client, lease.Lost); rel.Reason != proto.ReasonReleased {
			t.Errorf("Lost reason = %v, want %v", rel.Reason, proto.ReasonReleased)
		}
		r.tap.waitCount(t, wire.MsgRelease6, 1)
		rel := r.tap.ofType(wire.MsgRelease6)[0]
		pds, err := rel.Options.IAPDs()
		if err != nil || len(pds) != 1 {
			t.Fatalf("the Release's IA_PDs = %v, %v, want one", pds, err)
		}
		if got, _ := pds[0].Options.Prefixes(); len(got) != 1 || got[0].Prefix != pfx.Addr {
			t.Errorf("the Release's IA_PD names %v, want the held %s", got, pfx.Addr)
		}

		// Kea writes the row before it logs that the prefix was released, and a
		// Release has no Reply to wait for (claymore666/docker-net-dhcp#214).
		r.srv.waitFor(t, "DHCP6_RELEASE_PD_EXPIRED")
		rows := r.pdRows(t, pfx.Addr)
		last := rows[len(rows)-1]
		if last.valid != 0 || last.expire > time.Now().Unix() {
			t.Errorf("Kea's last PD row for %s is %+v after the Release, want a valid lifetime of 0 and an expiry that has passed", pfx.Addr, last)
		}
		return
	}
	reexecInNamespaces(t)
}

// TestKeaTakesAPrefixBackFromARecordRelease is dhcp-golib#60: a Release built
// from the stored record alone, by a sender that holds no client, names the
// delegated prefix, and Kea's own lease file shows the PD row expired. The
// client is stopped without a Release, so the only Release on the wire is the
// record's, and the tap's copy of it is the bytes that left the link.
func TestKeaTakesAPrefixBackFromARecordRelease(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		r := keaStartClient(t, keaConfig{pdPools: true}, nil, nil)
		held := awaitV6(t, r.client, lease.Acquired).Lease
		pfx := onlyPrefix(t, held)
		if rows := r.pdRows(t, pfx.Addr); len(rows) == 0 || rows[len(rows)-1].valid != keaValidSec {
			t.Fatalf("Kea does not hold %s before the Release: %+v", pfx.Addr, rows)
		}
		r.stop()

		duid, err := hex.DecodeString(strings.ReplaceAll(r.duid, ":", ""))
		if err != nil {
			t.Fatalf("the client DUID %q is not hex: %v", r.duid, err)
		}
		rec := lease.Record{
			ID: "rec-pd-released", Scope: "net-a", Family: lease.FamilyV6,
			Identity: binary.BigEndian.AppendUint32(duid, held.IAID),
			Lease:    held,
		}
		mustRun(t, "ip", "-6", "addr", "add", relHostLLA6+"/64", "dev", test6ClientIf, "nodad")
		cfg := ReleaseConfig{Interface: test6ClientIf, Source: netip.MustParseAddr(relHostLLA6)}
		if err := SendRelease(rec, cfg); err != nil {
			t.Fatalf("SendRelease: %v", err)
		}

		r.tap.waitCount(t, wire.MsgRelease6, 1)
		if n := r.tap.count(wire.MsgRelease6); n != 1 {
			t.Errorf("%d Releases left the link, want only the record's", n)
		}
		pds, err := r.tap.ofType(wire.MsgRelease6)[0].Options.IAPDs()
		if err != nil || len(pds) != 1 {
			t.Fatalf("the Release's IA_PDs = %v, %v, want one", pds, err)
		}
		if got, _ := pds[0].Options.Prefixes(); len(got) != 1 || got[0].Prefix != pfx.Addr {
			t.Errorf("the Release's IA_PD names %v, want the held %s", got, pfx.Addr)
		}

		// Kea writes the row before it logs that the prefix was released.
		r.srv.waitFor(t, "DHCP6_RELEASE_PD_EXPIRED")
		rows := r.pdRows(t, pfx.Addr)
		last := rows[len(rows)-1]
		if last.valid != 0 || last.expire > time.Now().Unix() {
			t.Errorf("Kea's last PD row for %s is %+v after the record's Release, want a valid lifetime of 0 and an expiry that has passed", pfx.Addr, last)
		}
		return
	}
	reexecInNamespaces(t)
}

// journalSays reports whether any journal line carries sub
// (claymore666/docker-net-dhcp#214).
func journalSays(c *Client6, sub string) bool {
	for _, e := range c.Journal() {
		if strings.Contains(e.Reason, sub) {
			return true
		}
		for _, a := range e.Actions {
			if strings.Contains(a, sub) {
				return true
			}
		}
	}
	return false
}

// inbound returns the decoded messages of one type the client received.
func inbound(c *Client6, mt wire.MessageTypeV6) []*wire.MessageV6 {
	var out []*wire.MessageV6
	for _, p := range c.Packets() {
		if p.Dir == lease.DirIn && p.Msg != nil && p.Msg.Type == mt {
			out = append(out, p.Msg)
		}
	}
	return out
}

func TestKeaWithoutAPrefixPoolStillGivesTheAddress(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		r := keaStartClient(t, keaConfig{pdPools: false}, nil, nil)
		l := awaitV6(t, r.client, lease.Acquired).Lease
		if len(l.Prefixes) != 0 {
			t.Errorf("the lease carries prefixes %+v from a server with no prefix pool", l.Prefixes)
		}
		if got := l.Addr.Addr(); !got.IsValid() || !netip.MustParsePrefix(test6Prefix+"/"+fmt.Sprint(test6PrefixLn)).Contains(got) {
			t.Errorf("the lease address %s is not Kea's", l.Addr)
		}

		// Kea's own answer: an IA_PD that carries status NoPrefixAvail and no prefix.
		adv := inbound(r.client, wire.MsgAdvertise)
		if len(adv) == 0 {
			t.Fatal("the client captured no Advertise")
		}
		pds, err := adv[0].Options.IAPDs()
		if err != nil || len(pds) != 1 {
			t.Fatalf("the Advertise's IA_PDs = %v, %v, want one", pds, err)
		}
		st, ok, err := pds[0].Options.Status()
		if err != nil || !ok || st.Code != wire.StatusNoPrefixAvail {
			t.Errorf("the Advertise's IA_PD status = %v, %v, %v, want NoPrefixAvail", st, ok, err)
		}
		if got, _ := pds[0].Options.Prefixes(); len(got) != 0 {
			t.Errorf("the refusing IA_PD carries prefixes %v", got)
		}

		if !journalSays(r.client, "the IA_PD gave no prefix (status NoPrefixAvail") {
			t.Errorf("the journal does not say the IA_PD was refused with NoPrefixAvail")
		}
		if rows := keaRows(t, r.srv.leasefile); len(rows) == 0 {
			t.Error("Kea's lease file is empty: the address was not Kea's")
		} else {
			for _, row := range rows {
				if row.leaseType == keaLeasePD {
					t.Errorf("Kea's lease file holds a PD row %+v on a server with no prefix pool", row)
				}
			}
		}
		return
	}
	reexecInNamespaces(t)
}

// TestKeaSeesAResumedPrefixRebind: a client restarted with a lease that holds a
// delegated prefix sends a Rebind, not a Confirm (RFC 8415 section 18.2.12),
// and Kea renews the PD row it already had instead of opening a second one
// (claymore666/docker-net-dhcp#214).
func TestKeaSeesAResumedPrefixRebind(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		first := keaStartClient(t, keaConfig{pdPools: true}, nil, nil)
		held := awaitV6(t, first.client, lease.Acquired).Lease
		pfx := onlyPrefix(t, held)
		before := first.pdRows(t, pfx.Addr)
		if len(before) == 0 {
			t.Fatalf("Kea has no PD row after the first run")
		}
		first.stop()

		// The second run is a new client with the same identity and the record
		// the first one left. Its messages go through the first run's observer,
		// which sees every message that leaves the interface.
		second, err := newV6ClientResumed(t, &held)
		if err != nil {
			t.Fatalf("NewClient6 with a resumed prefix: %v", err)
		}
		stop := runV6Client(t, second)
		defer stop()

		first.tap.waitCount(t, wire.MsgRebind, 1)
		got := awaitV6(t, second, lease.Acquired).Lease
		if again := onlyPrefix(t, got); again.Addr != pfx.Addr {
			t.Errorf("the resumed client holds %s, the record held %s", again.Addr, pfx.Addr)
		}
		if got.Addr != held.Addr {
			t.Errorf("the resumed client holds %s, the record held %s", got.Addr, held.Addr)
		}

		if n := first.tap.count(wire.MsgConfirm); n != 0 {
			t.Errorf("%d Confirm(s) left the client: a client that holds a prefix rebinds (section 18.2.12)", n)
		}
		if n := first.tap.count(wire.MsgSolicit); n != 1 {
			t.Errorf("%d Solicits left in all: the resumed client took a new binding instead of keeping its own", n)
		}
		rb := first.tap.ofType(wire.MsgRebind)[0]
		pds, err := rb.Options.IAPDs()
		if err != nil || len(pds) != 1 {
			t.Fatalf("the Rebind's IA_PDs = %v, %v, want one", pds, err)
		}
		if p, _ := pds[0].Options.Prefixes(); len(p) != 1 || p[0].Prefix != pfx.Addr {
			t.Errorf("the Rebind's IA_PD names %v, want the held %s", p, pfx.Addr)
		}
		nas, err := rb.Options.IANAs()
		if err != nil || len(nas) != 1 {
			t.Fatalf("the Rebind's IA_NAs = %v, %v, want one", nas, err)
		}
		if a, _ := nas[0].Options.Addrs(); len(a) != 1 || a[0].Addr != held.Addr.Addr() {
			t.Errorf("the Rebind's IA_NA names %v, want the held %s", a, held.Addr)
		}

		// Kea answered the Rebind and renewed the same row (Reply came before
		// the Acquired event, so the file is already written).
		// Kea 2.4 does not log the type of a received packet at this level, so
		// the Rebind itself is read off the wire above; Kea says it renewed the
		// prefix (claymore666/docker-net-dhcp#214).
		if !first.srv.hasLine("DHCP6_PD_LEASE_RENEW") {
			t.Errorf("Kea did not log the renewal of the prefix.\nLog:\n%s", strings.Join(first.srv.lines(), "\n"))
		}
		after := first.pdRows(t, pfx.Addr)
		if len(after) <= len(before) {
			t.Errorf("Kea's lease file holds %d row(s) for %s after the Rebind, %d before it", len(after), pfx.Addr, len(before))
		}
		if last := after[len(after)-1]; last.valid != keaValidSec || last.duid != first.duid {
			t.Errorf("the renewed PD row is %+v", last)
		}
		return
	}
	reexecInNamespaces(t)
}

// newV6ClientResumed builds the second run's client: the fixture identity, the
// hint, and a record to resume from (claymore666/docker-net-dhcp#214).
func newV6ClientResumed(t *testing.T, held *lease.Lease) (*Client6, error) {
	t.Helper()
	iface, err := net.InterfaceByName(test6ClientIf)
	if err != nil {
		return nil, err
	}
	duid, err := wire.DUIDLL(wire.ARPHTypeEthernet, iface.HardwareAddr)
	if err != nil {
		return nil, err
	}
	p := proto.DefaultParams6()
	p.DUID = duid
	p.IAID = 0x0a0b0c0d
	p.ORO = proto.DefaultORO()
	return NewClient6(ClientConfig6{Interface: test6ClientIf, Params6: p, EventBuffer: 8, PrefixHint: keaHint, Resume: held})
}

// TestADnsmasqThatCannotDelegateLeavesTheAddressAlone: dnsmasq 2.91 answers a
// Solicit that carries an IA_PD with a message-level Status Code 0 and no IA_PD
// at all, and no NoPrefixAvail. The address binds, the lease has no prefix and
// the client counts the IA_PD as absent, not refused (claymore666/docker-net-dhcp#214).
func TestADnsmasqThatCannotDelegateLeavesTheAddressAlone(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		wireUpV6(t)
		srv := startDnsmasq6(t, v6Managed)
		watch := newRAWatch(t, test6ClientIf)
		c, _ := newV6ClientWith(t, func(p *proto.Params6) { p.PrefixHint = keaHint })
		stop := runV6Client(t, c)
		defer stop()
		assertMode(t, srv, watch, v6Managed)

		l := awaitV6(t, c, lease.Acquired).Lease
		srv.waitFor(t, "DHCPREPLY("+test6ServerIf+") "+l.Addr.Addr().String())
		if len(l.Prefixes) != 0 {
			t.Errorf("the lease carries prefixes %+v from a server that cannot delegate", l.Prefixes)
		}

		// The client did ask: its Solicit carries the hint.
		var asked bool
		for _, p := range c.Packets() {
			if p.Dir == lease.DirOut && p.Msg != nil && p.Msg.Type == wire.MsgSolicit {
				assertHintIAPD(t, p.Msg)
				asked = true
			}
		}
		if !asked {
			t.Fatal("the client captured no Solicit")
		}

		// dnsmasq's answer has no IA_PD and no NoPrefixAvail anywhere; it does
		// carry a message-level Status Code 0, so that is not what is asserted.
		var answers int
		for _, mt := range []wire.MessageTypeV6{wire.MsgAdvertise, wire.MsgReply} {
			for _, m := range inbound(c, mt) {
				answers++
				if n := m.Options.Count(wire.OptV6IAPD); n != 0 {
					t.Errorf("dnsmasq's %v carries %d IA_PD", mt, n)
				}
				if st, ok, _ := m.Options.Status(); ok && st.Code == wire.StatusNoPrefixAvail {
					t.Errorf("dnsmasq's %v carries a message-level NoPrefixAvail", mt)
				}
				nas, _ := m.Options.IANAs()
				for _, na := range nas {
					if st, ok, _ := na.Options.Status(); ok && st.Code == wire.StatusNoPrefixAvail {
						t.Errorf("dnsmasq's %v carries NoPrefixAvail inside the IA_NA", mt)
					}
				}
			}
		}
		if answers == 0 {
			t.Fatal("the client captured no answer from dnsmasq")
		}
		if !journalSays(c, "no IA_PD in the message that answered a prefix request") {
			t.Error("the journal does not say the IA_PD was absent")
		}
		if journalSays(c, "the IA_PD gave no prefix (status") {
			t.Error("the journal counts a refusal where dnsmasq sent no IA_PD at all")
		}
		return
	}
	reexecInNamespaces(t)
}
