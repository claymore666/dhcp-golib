// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

//go:build linux

package runtime

import (
	"fmt"
	"syscall"
)

// bindToDevice returns a net.Dialer Control that pins the socket to one link.
//
// It is what makes ReleaseConfig.Interface mean something on the v4 path,
// where the destination is an ordinary unicast address and the route table
// would otherwise choose the link. A host with two interfaces on the parent's
// subnet is the case: the release reaches the server either way, and only one
// of the two ways is the link the lease was taken on.
//
// A device that does not exist is an error here and not a silent fallback,
// which is also the only way to tell this option apart from one that is
// accepted and ignored: a Control that did nothing would open the socket just
// the same, and the datagram would leave by whatever link the route table
// preferred while the caller believed it had named one.
//
// THE KERNEL REFUSES LESS THAN "THIS NEEDS ROOT", MEASURED on Linux 6.12 with
// an empty effective capability set: binding a fresh socket to an existing
// link succeeds there, and an absent link comes back ENODEV. So this is not a
// privileged path in the ordinary case, and a caller that reads it as one
// would skip the release it could have sent. What the function guarantees is
// the half that holds either way: a refusal arrives HERE, as an error on the
// dial, and never as a socket that quietly went out by the route table's
// choice. TestBindingTheReleaseSocketToALinkIsCheckedOrRefused drives both
// directions.
func bindToDevice(iface string) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var opErr error
		if err := c.Control(func(fd uintptr) {
			opErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
		}); err != nil {
			return err
		}
		if opErr != nil {
			return fmt.Errorf("runtime: binding the release socket to %s: %w", iface, opErr)
		}
		return nil
	}
}
