// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

//go:build linux

package runtime

import (
	"errors"
	"syscall"
	"testing"
)

// TestAKeaTestIsReExecutedWithAMountNamespace: the re-exec gives CLONE_NEWNS to
// the tests whose name starts with the Kea prefix and to no other, so the
// existing netns tests keep the namespaces they were built for
// (claymore666/docker-net-dhcp#214).
func TestAKeaTestIsReExecutedWithAMountNamespace(t *testing.T) {
	if got := keaCloneFlags("TestKeaSomething"); got != syscall.CLONE_NEWNS {
		t.Errorf("a Kea test is cloned with %#x, want CLONE_NEWNS (%#x)", got, syscall.CLONE_NEWNS)
	}
	for _, name := range []string{"TestAcquiresFromRealDnsmasq", "TestAKeaThing", "Kea"} {
		if got := keaCloneFlags(name); got != 0 {
			t.Errorf("%s is cloned with extra flags %#x", name, got)
		}
		if isKeaTest(name) {
			t.Errorf("%s is taken for a Kea test", name)
		}
	}
}

// TestTheKeaFixtureFailsClosedWithoutKea: a box with no kea-dhcp6 anywhere is
// an error, never a skip, so a runner that lost the package is red
// (claymore666/docker-net-dhcp#214).
func TestTheKeaFixtureFailsClosedWithoutKea(t *testing.T) {
	none := func(string) (string, error) { return "", errors.New("not found") }
	if p, err := findKeaIn(none, []string{"/nonexistent/kea-dhcp6"}); err == nil {
		t.Errorf("findKeaIn found %q with no Kea anywhere", p)
	}
	found := func(string) (string, error) { return "/somewhere/kea-dhcp6", nil }
	if p, err := findKeaIn(found, nil); err != nil || p != "/somewhere/kea-dhcp6" {
		t.Errorf("findKeaIn = %q, %v, want the PATH hit", p, err)
	}
}
