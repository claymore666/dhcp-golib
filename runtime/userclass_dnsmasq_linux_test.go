// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

//go:build linux

package runtime

import (
	"bytes"
	"context"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/claymore666/dhcp-golib/lease"
	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/wire"
)

// Runtime half of claymore666/docker-net-dhcp#1120. The assertion is the ACK:
// the server hands a client option 224 only when its --dhcp-userclass rule
// matched, and dnsmasq's own log names the class and tags it read. dnsmasq
// 2.91 matches a rule as a substring of the whole option value with the length
// octets zeroed (rfc2131.c 475-510, read 2026-09-30), so the negative class
// shares no text with the rule and a rule spanning two instances cannot match.
const (
	ucOptVip    = 224
	ucOptJoined = 225
	ucOptFoo    = 226

	ucVip    = "vip-tier"
	ucValVip = "matched-vip"
)

// TestUserClassReachesTheServersClassRule runs one server with three class
// rules against one client per case (claymore666/docker-net-dhcp#1120).
func TestUserClassReachesTheServersClassRule(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		runUserClassAgainstDnsmasq(t)
		return
	}
	reexecInNamespaces(t)
}

func runUserClassAgainstDnsmasq(t *testing.T) {
	mustRun(t, "ip", "link", "add", testClientIf, "type", "veth", "peer", "name", testServerIf)
	mustRun(t, "ip", "addr", "add", testServerIP+"/24", "dev", testServerIf)
	mustRun(t, "ip", "link", "set", testServerIf, "up")
	mustRun(t, "ip", "link", "set", testClientIf, "up")

	srv := startDnsmasqCfg(t, dnsmasqConfig{extra: []string{
		"--dhcp-userclass=set:vip," + ucVip,
		"--dhcp-option-force=tag:vip,224," + ucValVip,
		"--dhcp-userclass=set:joined,foobar",
		"--dhcp-option-force=tag:joined,225,matched-joined",
		"--dhcp-userclass=set:foo,foo",
		"--dhcp-option-force=tag:foo,226,matched-foo",
	}})

	iface, err := net.InterfaceByName(testClientIf)
	if err != nil {
		t.Fatalf("InterfaceByName(%s): %v", testClientIf, err)
	}
	if bytes.Contains([]byte("other-class"), []byte(ucVip)) {
		t.Fatal("the negative case contains the rule text; dnsmasq matches substrings")
	}

	for _, tc := range []struct {
		name    string
		classes [][]byte
		// want maps an option to the value the ACK must carry; the other
		// two of the three must be absent (claymore666/docker-net-dhcp#1120).
		want map[wire.OptionCode]string
		// logged is the class text dnsmasq must log for the exchange, empty
		// when the client sent no option 77. Its log drops the zeroed length
		// octets, so foo and bar read "foobar" there and only the tags line
		// tells the two shapes apart (claymore666/docker-net-dhcp#1120, 2026-09-30).
		logged string
		// tags is what dnsmasq's "tags:" line lists among the three rule tags,
		// for the DISCOVER and the REQUEST (claymore666/docker-net-dhcp#1120).
		tags []string
	}{
		{"the matching instance", [][]byte{[]byte(ucVip)},
			map[wire.OptionCode]string{ucOptVip: ucValVip}, ucVip, []string{"vip"}},
		{"another instance that shares nothing with the rule", [][]byte{[]byte("other-class")},
			map[wire.OptionCode]string{}, "other-class", nil},
		{"no user class at all", nil, map[wire.OptionCode]string{}, "", nil},
		{"two instances, a rule on one of them", [][]byte{[]byte("foo"), []byte("bar")},
			map[wire.OptionCode]string{ucOptFoo: "matched-foo"}, "foobar", []string{"foo"}},
		{"one instance holding both words", [][]byte{[]byte("foobar")},
			map[wire.OptionCode]string{ucOptJoined: "matched-joined", ucOptFoo: "matched-foo"}, "foobar",
			[]string{"joined", "foo"}},
	} {
		start := len(srv.lines())
		acks := srv.count("DHCPACK(" + testServerIf + ")")
		got := acquireWithUserClass(t, iface, tc.classes)
		srv.waitCount(t, "DHCPACK("+testServerIf+")", acks+1, tc.name)
		for _, opt := range []wire.OptionCode{ucOptVip, ucOptJoined, ucOptFoo} {
			v, ok := got.Options[opt]
			want, wantOK := tc.want[opt]
			switch {
			case wantOK && (!ok || string(v) != want):
				t.Errorf("%s: option %d in the ACK = %q/%v, want %q", tc.name, opt, v, ok, want)
			case !wantOK && ok:
				t.Errorf("%s: option %d = %q is in the ACK for a client the rule does not match", tc.name, opt, v)
			}
		}
		// dnsmasq's own reading of the exchange: the class it logged and the
		// tags its rules set. This is what stops a pass in which the server
		// ignored option 77 and the tagged option arrived some other way
		// (claymore666/docker-net-dhcp#1120).
		seg := srv.lines()[start:]
		for _, kind := range []string{"DHCPDISCOVER(", "DHCPREQUEST("} {
			if !containsLine(seg, kind) {
				t.Errorf("%s: dnsmasq logged no %s", tc.name, kind)
			}
		}
		classLines := 0
		for _, l := range seg {
			if strings.Contains(l, "user class:") {
				classLines++
				if !strings.HasSuffix(l, "user class: "+tc.logged) {
					t.Errorf("%s: dnsmasq read the class as %q, want %q", tc.name, l, tc.logged)
				}
			}
		}
		if (tc.logged == "") != (classLines == 0) {
			t.Errorf("%s: dnsmasq logged %d user class line(s) for a client whose class is %q", tc.name, classLines, tc.logged)
		}
		tagLines := 0
		for _, l := range seg {
			i := strings.Index(l, " tags: ")
			if i < 0 {
				continue
			}
			tagLines++
			var rules []string
			for _, tag := range strings.Split(l[i+len(" tags: "):], ", ") {
				if tag == "vip" || tag == "joined" || tag == "foo" {
					rules = append(rules, strings.TrimSpace(tag))
				}
			}
			if strings.Join(rules, ",") != strings.Join(tc.tags, ",") {
				t.Errorf("%s: dnsmasq set the rule tags %v, want %v (%q)", tc.name, rules, tc.tags, l)
			}
		}
		if tagLines == 0 {
			t.Errorf("%s: dnsmasq logged no tags line", tc.name)
		}
		t.Logf("%s: ACK options %v", tc.name, describeUserClassOptions(got))
	}
}

// describeUserClassOptions lists the three rule options of a lease (claymore666/docker-net-dhcp#1120).
func describeUserClassOptions(l lease.Lease) map[wire.OptionCode]string {
	out := map[wire.OptionCode]string{}
	for _, o := range []wire.OptionCode{ucOptVip, ucOptJoined, ucOptFoo} {
		if v, ok := l.Options[o]; ok {
			out[o] = string(v)
		}
	}
	return out
}

// acquireWithUserClass returns the lease event of a client started with the
// given classes; its Options are the ACK's (claymore666/docker-net-dhcp#1120).
func acquireWithUserClass(t *testing.T, iface *net.Interface, classes [][]byte) lease.Lease {
	t.Helper()
	params := proto.DefaultParams(iface.HardwareAddr)
	params.DesyncMin, params.DesyncMax = 0, 0
	// Async and the brisk table, for dnsmasq_linux_test.go's reason: the
	// subject is the exchange, not RFC 5227's schedule
	// (claymore666/docker-net-dhcp#1120).
	params.Conflict = proto.ConflictAsync
	params.ACD = briskACD()
	params.UserClass = classes

	c, err := NewClient(ClientConfig{Interface: testClientIf, Params: params, EventBuffer: 8})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- c.Run(ctx) }()
	defer func() {
		cancel()
		<-runErr
	}()

	for ev := range c.Events() {
		t.Logf("client event: %s", ev)
		if ev.Kind == lease.Acquired {
			return ev.Lease
		}
		if ev.Kind == lease.Failed {
			t.Fatalf("acquisition failed: %s", ev)
		}
	}
	t.Fatal("the event stream ended before a lease was acquired")
	return lease.Lease{}
}
