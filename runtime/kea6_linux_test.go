// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

//go:build linux

package runtime

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/claymore666/dhcp-golib/wire"
)

// The Kea fixture for prefix delegation (claymore666/docker-net-dhcp#214).
//
// dnsmasq 2.91 answers an IA_PD with a message-level Status Code 0 and no
// IA_PD, so it can never delegate a prefix. Kea can, and it keeps a lease file
// of its own, which is the outside evidence for what the client holds.
//
// Kea refuses a lease file anywhere but /var/lib/kea, so a Kea test runs in a
// mount namespace of its own and binds a per-test directory over that path.
// The re-exec adds CLONE_NEWNS for any test whose name starts with
// keaTestPrefix; a Kea test without the prefix finds no mount namespace and
// fails in keaStart rather than passing on nothing.

const keaTestPrefix = "TestKea"

// keaLeaseDir is the one path Kea accepts for a memfile lease database. Each
// test checks it exists, then bind-mounts its own directory over it inside the
// test's mount namespace (claymore666/docker-net-dhcp#214).
const keaLeaseDir = "/var/lib/kea"

// keaPDPrefix and the lengths below are the pool every Kea test delegates from:
// /48 split into /64 (claymore666/docker-net-dhcp#214).
const (
	keaPDPrefix    = "fd00:98::"
	keaPDPoolLen   = 48
	keaPDDelegated = 64
	keaValidSec    = 600
	keaPrefSec     = 400
	keaT1Sec       = 300
	keaT2Sec       = 480
)

func isKeaTest(name string) bool { return strings.HasPrefix(name, keaTestPrefix) }

// keaCloneFlags is the extra namespace a Kea test is re-executed into.
func keaCloneFlags(name string) uintptr {
	if isKeaTest(name) {
		return syscall.CLONE_NEWNS
	}
	return 0
}

// keaSbinDirs are where a package installs kea-dhcp6 and a non-root PATH
// usually has no entry for.
var keaSbinDirs = []string{"/usr/sbin/kea-dhcp6", "/sbin/kea-dhcp6", "/usr/local/sbin/kea-dhcp6"}

// findKea looks for kea-dhcp6 where findDnsmasq looks for dnsmasq. A runner
// without the package fails here instead of skipping (claymore666/docker-net-dhcp#214).
func findKea() (string, error) {
	return findKeaIn(exec.LookPath, keaSbinDirs)
}

// findKeaIn is findKea with the PATH lookup and the fallback paths given, so
// the failure can be driven on a box that has Kea installed
// (claymore666/docker-net-dhcp#214).
func findKeaIn(look func(string) (string, error), fallback []string) (string, error) {
	if p, err := look("kea-dhcp6"); err == nil {
		return p, nil
	}
	for _, p := range fallback {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("kea-dhcp6 was not found on PATH or in the usual sbin directories")
}

// keaConfig is what a Kea test varies about the server.
type keaConfig struct {
	// pdPools says whether the subnet has a delegation pool. False is a server
	// that has no prefix to give (claymore666/docker-net-dhcp#214).
	pdPools bool
}

// json is the one configuration both Kea 2.4 and 2.6 accept: the lease
// database and the server id are files under keaLeaseDir, the logger key is
// output_options, and the timers are the ones the tests read back
// (claymore666/docker-net-dhcp#214).
func (k keaConfig) json() string {
	pd := ""
	if k.pdPools {
		pd = fmt.Sprintf(`,
        "pd-pools": [ { "prefix": %q, "prefix-len": %d, "delegated-len": %d } ]`,
			keaPDPrefix, keaPDPoolLen, keaPDDelegated)
	}
	return fmt.Sprintf(`{
  "Dhcp6": {
    "interfaces-config": { "interfaces": [ %q ] },
    "lease-database": { "type": "memfile", "persist": true, "name": %q, "lfc-interval": 0 },
    "valid-lifetime": %d,
    "renew-timer": %d,
    "rebind-timer": %d,
    "preferred-lifetime": %d,
    "subnet6": [
      {
        "id": 1,
        "subnet": "%s/%d",
        "interface": %q,
        "pools": [ { "pool": "%s - %s" } ]%s
      }
    ],
    "loggers": [ { "name": "kea-dhcp6", "output_options": [ { "output": "stderr" } ], "severity": "INFO", "debuglevel": 0 } ]
  }
}
`, test6ServerIf, filepath.Join(keaLeaseDir, "leases6.csv"),
		keaValidSec, keaT1Sec, keaT2Sec, keaPrefSec,
		test6Prefix, test6PrefixLn, test6ServerIf, test6RangeLo, test6RangeHi, pd)
}

// keaStart binds a per-test directory over keaLeaseDir, starts kea-dhcp6 on the
// fixture link and returns once it logs DHCP6_STARTED
// (claymore666/docker-net-dhcp#214).
func keaStart(t *testing.T, cfg keaConfig) *dnsmasqServer {
	t.Helper()
	bin, err := findKea()
	if err != nil {
		t.Fatalf("%v", err)
	}
	if _, err := os.Stat(keaLeaseDir); err != nil {
		t.Fatalf("%s is missing (%v): Kea accepts no other lease directory, so the test mounts its own over this one", keaLeaseDir, err)
	}
	dir := t.TempDir()
	if err := syscall.Mount(dir, keaLeaseDir, "", syscall.MS_BIND, ""); err != nil {
		t.Fatalf("binding %s over %s: %v. A Kea test runs in a mount namespace of its own, and only a test named %s... is given one", dir, keaLeaseDir, err, keaTestPrefix)
	}
	conf := filepath.Join(dir, "kea.json")
	if err := os.WriteFile(conf, []byte(cfg.json()), 0o600); err != nil {
		t.Fatalf("writing the Kea configuration: %v", err)
	}

	cmd := exec.Command(bin, "-c", conf)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C", "KEA_PIDFILE_DIR="+dir, "KEA_LOCKFILE_DIR="+dir)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("StderrPipe: %v", err)
	}
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting kea-dhcp6: %v", err)
	}
	s := &dnsmasqServer{cmd: cmd, arrived: make(chan string, 1024), leasefile: filepath.Join(dir, "leases6.csv"), iface: test6ServerIf, tag: "kea"}
	go s.read(stderr)
	t.Cleanup(func() {
		s.stop()
		t.Logf("kea-dhcp6 log:\n%s", strings.Join(s.lines(), "\n"))
	})
	s.waitFor(t, "DHCP6_STARTED")
	return s
}

// hasLine reports whether a log line contains want, now
// (claymore666/docker-net-dhcp#214).
func (s *dnsmasqServer) hasLine(want string) bool { return s.count(want) > 0 }

// keaRow is one line of Kea's memfile lease file
// (claymore666/docker-net-dhcp#214).
type keaRow struct {
	addr      string
	duid      string
	valid     int64
	expire    int64
	leaseType int
	prefixLen int
}

const (
	keaLeaseNA = 0
	keaLeasePD = 2
)

// keaRows reads every row of the lease file, oldest first, by column name so
// that 2.4's header and 2.6's, which has one more column, both read
// (claymore666/docker-net-dhcp#214).
func keaRows(t *testing.T, path string) []keaRow {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("opening Kea's lease file: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var col map[string]int
	var rows []keaRow
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ",")
		if col == nil {
			col = map[string]int{}
			for i, n := range fields {
				col[n] = i
			}
			continue
		}
		get := func(n string) string {
			if i, ok := col[n]; ok && i < len(fields) {
				return fields[i]
			}
			return ""
		}
		var r keaRow
		r.addr, r.duid = get("address"), strings.ToLower(get("duid"))
		fmt.Sscan(get("valid_lifetime"), &r.valid)
		fmt.Sscan(get("expire"), &r.expire)
		fmt.Sscan(get("lease_type"), &r.leaseType)
		fmt.Sscan(get("prefix_len"), &r.prefixLen)
		rows = append(rows, r)
	}
	return rows
}

// duidText is a DUID the way Kea's lease file writes it.
func duidText(d []byte) string {
	parts := make([]string, len(d))
	for i, b := range d {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}

// outTap is a packet socket reading this host's own DHCPv6 transmissions on
// one interface, in order. It is the outside evidence for which message types
// left the client; the library's own capture is its opinion of itself
// (claymore666/docker-net-dhcp#214).
type outTap struct {
	mu     sync.Mutex
	all    []*wire.MessageV6
	notify chan struct{}
	closed bool
}

func newOutTap(t *testing.T, ifName string) *outTap {
	t.Helper()
	w := newTXWatch(t, ifName)
	o := &outTap{notify: make(chan struct{}, 1)}
	go func() {
		buf := make([]byte, maxFrame)
		for {
			n, from, err := w.readFrom(buf)
			if err != nil {
				o.mu.Lock()
				o.closed = true
				o.mu.Unlock()
				select {
				case o.notify <- struct{}{}:
				default:
				}
				return
			}
			lla, ok := from.(*syscall.SockaddrLinklayer)
			if !ok || lla.Pkttype != syscall.PACKET_OUTGOING {
				continue
			}
			frame := buf[:n]
			if n < ipv6HeaderLen+8 || frame[0]>>4 != ipv6Version || frame[6] != protoUDP {
				continue
			}
			u := frame[ipv6HeaderLen:]
			if binary.BigEndian.Uint16(u[0:2]) != ClientPort6 || binary.BigEndian.Uint16(u[2:4]) != ServerPort6 {
				continue
			}
			m, err := wire.DecodeV6(append([]byte(nil), u[8:]...))
			if err != nil {
				continue
			}
			o.mu.Lock()
			o.all = append(o.all, m)
			o.mu.Unlock()
			select {
			case o.notify <- struct{}{}:
			default:
			}
		}
	}()
	return o
}

// sent returns the messages that have left so far, oldest first.
func (o *outTap) sent() []*wire.MessageV6 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]*wire.MessageV6(nil), o.all...)
}

// count is how many messages of a type have left.
func (o *outTap) count(mt wire.MessageTypeV6) int {
	n := 0
	for _, m := range o.sent() {
		if m.Type == mt {
			n++
		}
	}
	return n
}

// waitCount blocks until n messages of a type have left. Every message sent
// before the one that satisfies it has been read by then, which is what makes
// the absence of an earlier type a fact (claymore666/docker-net-dhcp#214).
func (o *outTap) waitCount(t *testing.T, mt wire.MessageTypeV6, n int) {
	t.Helper()
	for o.count(mt) < n {
		<-o.notify
		o.mu.Lock()
		closed := o.closed
		o.mu.Unlock()
		if closed && o.count(mt) < n {
			t.Fatalf("the send observer ended with %d %v message(s), want %d", o.count(mt), mt, n)
		}
	}
}

// ofType returns the sent messages of one type.
func (o *outTap) ofType(mt wire.MessageTypeV6) []*wire.MessageV6 {
	var out []*wire.MessageV6
	for _, m := range o.sent() {
		if m.Type == mt {
			out = append(out, m)
		}
	}
	return out
}
