// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package runtime

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"

	"github.com/claymore666/dhcp-golib/lease"
	"github.com/claymore666/dhcp-golib/wire"
)

// A record whose IA_PD came from another server is released with each server
// for its own IAs, RFC 8415 section 18.2.7 (claymore666/dhcp-golib#70).
func TestASplitRecordIsReleasedWithBothServersEvenWhenOneWriteFails(t *testing.T) {
	prefixServer := []byte{0x00, 0x01, 0x00, 0x01, 0x2b, 0x00, 0x00, 0x02, 0xcc, 0xdd}
	rec := relRec6()
	rec.Lease.PrefixServerDUID = prefixServer
	rec.Lease.Prefixes = []lease.Addr6{{Addr: netip.MustParsePrefix("2001:db8:1:2::/64")}}
	boom := errors.New("the parent link went away")
	var servers [][]byte
	send := func(_, dst netip.AddrPort, _ string, payload []byte) error {
		msg, err := wire.DecodeV6(payload)
		if err != nil {
			t.Fatalf("datagram %d: %v", len(servers), err)
		}
		sid, _ := msg.Options.First(wire.OptV6ServerID)
		servers = append(servers, append([]byte(nil), sid...))
		if dst.Addr() != AllDHCPRelayAgentsAndServers || dst.Port() != ServerPort6 {
			t.Errorf("datagram %d goes to %s", len(servers), dst)
		}
		if len(servers) == 1 {
			return boom
		}
		return nil
	}
	err := sendReleaseWith(rec, relCfg6(), send)
	if len(servers) != 2 || !bytes.Equal(servers[0], relServerDUID) || !bytes.Equal(servers[1], prefixServer) {
		t.Fatalf("the transport saw Releases for %x, want the address server then the prefix server", servers)
	}
	if !errors.Is(err, boom) {
		t.Errorf("error = %v, want the first write's %v", err, boom)
	}
}
