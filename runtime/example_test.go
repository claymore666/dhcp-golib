// Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

package runtime_test

import (
	"context"
	"log"
	"net"
	"os"

	"github.com/claymore666/dhcp-golib/lease"
	"github.com/claymore666/dhcp-golib/proto"
	"github.com/claymore666/dhcp-golib/runtime"
	"github.com/claymore666/dhcp-golib/wire"
)

// ExampleClient is the smallest real use of this library, and it is compiled
// rather than quoted: the README's Usage section is this function, byte for
// byte, so a reader who copies it gets code the suite builds.
//
// The interface name comes from the environment because a lease needs a link
// with a server on it. Unset — which is how every run of the suite sees it —
// the example returns before it opens anything, which is why its expected
// output is empty. A compile-only example, with no expected output at all,
// would be DECLARED and never LISTED, and the arbiter refuses that.
func ExampleClient() {
	iface := os.Getenv("DHCP_GOLIB_EXAMPLE_IFACE")
	if iface == "" {
		return
	}

	client, err := runtime.NewClient(runtime.ClientConfig{
		Interface: iface,
		Params:    proto.DefaultParams(nil),
	})
	if err != nil {
		log.Print(err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if err := client.Run(ctx); err != nil {
			log.Print(err)
		}
	}()

	for ev := range client.Events() {
		if ev.Kind != lease.Acquired {
			continue
		}
		log.Printf("%s via %s until %s", ev.Lease.Addr, ev.Lease.Gateway, ev.Lease.Expire)
		break
	}

	client.Release()
	// Output:
}

// ExampleClient6 is the same use for DHCPv6, and the README's second Usage
// block is this function, byte for byte, for the reason ExampleClient's is.
//
// TWO THINGS DIFFER FROM THE v4 EXAMPLE AND BOTH ARE THE PROTOCOL'S. The DUID
// is required and this library will not invent one (RFC 9915 section 11: a
// DUID "SHOULD NOT change over time if at all possible"), so the caller builds
// one and keeps it; and the Option Request list is the caller's, so a client
// that does not ask for DNS servers is answered without them.
func ExampleClient6() {
	iface := os.Getenv("DHCP_GOLIB_EXAMPLE_IFACE")
	if iface == "" {
		return
	}

	link, err := net.InterfaceByName(iface)
	if err != nil {
		log.Print(err)
		return
	}
	duid, err := wire.DUIDLL(wire.ARPHTypeEthernet, link.HardwareAddr)
	if err != nil {
		log.Print(err)
		return
	}

	params := proto.DefaultParams6()
	params.DUID = duid
	params.IAID = 1
	params.ORO = proto.DefaultORO()

	client, err := runtime.NewClient6(runtime.ClientConfig6{
		Interface: iface,
		Params6:   params,
	})
	if err != nil {
		log.Print(err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if err := client.Run(ctx); err != nil {
			log.Print(err)
		}
	}()

	for ev := range client.Events() {
		if ev.Kind != lease.Acquired {
			continue
		}
		log.Printf("%s preferred until %s, valid until %s", ev.Lease.Addr, ev.Lease.Preferred, ev.Lease.Valid)
		break
	}

	client.Release()
	// Output:
}
