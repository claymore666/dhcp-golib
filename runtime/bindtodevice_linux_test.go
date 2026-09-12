// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

//go:build linux

package runtime

import (
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
)

// TestBindingTheReleaseSocketToALinkIsCheckedOrRefused drives the sentences
// beside bindToDevice, which were stated and run by nothing.
//
// THE REFUSING DIRECTION. A link that does not exist must come back as an
// error on the dial. That is also the only thing that tells SO_BINDTODEVICE
// apart from an option accepted and ignored: a Control that did nothing would
// open this socket, and the release would leave by whatever link the route
// table preferred while ReleaseConfig.Interface looked like it had been
// honoured.
//
// THE PRESERVING DIRECTION, and it is the half a guard that refused everything
// would fail. An ordinary process with no capabilities binds a fresh socket to
// a real link without trouble, MEASURED here rather than assumed: the unit run
// holds an empty effective set, and this arm is what says so. A version of
// this library that treated the bind as privileged and skipped it, or one that
// returned an error for every link, would be red here and green on every
// assertion about the datagram's bytes.
func TestBindingTheReleaseSocketToALinkIsCheckedOrRefused(t *testing.T) {
	const absent = "dhcp-golib-no-link"

	d := net.Dialer{Control: bindToDevice(absent)}
	c, err := d.Dial("udp4", "127.0.0.1:9")
	if err == nil {
		_ = c.Close()
		t.Fatalf("a socket that asked for the link %q, which does not exist, was opened anyway; the release would leave by whatever link the route table picked and nothing would say so", absent)
	}
	if !errors.Is(err, syscall.ENODEV) {
		t.Errorf("a link that does not exist must come back ENODEV, got %v", err)
	}
	if !strings.Contains(err.Error(), "binding the release socket to "+absent) {
		t.Errorf("the error does not come from bindToDevice and does not name the link: %v", err)
	}

	d = net.Dialer{Control: bindToDevice("lo")}
	c, err = d.Dial("udp4", "127.0.0.1:9")
	if err != nil {
		t.Fatalf("binding a socket to lo, a link this host really has, failed: %v", err)
	}
	_ = c.Close()
}
