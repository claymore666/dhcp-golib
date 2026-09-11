// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

//go:build !linux

package runtime

import (
	"errors"
	"syscall"
)

// ErrBindToDevice says what this platform cannot do, rather than binding to
// nothing and reporting success. SO_BINDTODEVICE is Linux's; the portable
// build refuses the option instead of accepting and ignoring it.
var ErrBindToDevice = errors.New("runtime: binding a socket to one link needs Linux")

func bindToDevice(string) func(network, address string, c syscall.RawConn) error {
	return func(string, string, syscall.RawConn) error { return ErrBindToDevice }
}
