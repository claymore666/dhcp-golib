# dhcp-golib: a managed-lease DHCP client for Go

[![verify](https://github.com/claymore666/dhcp-golib/actions/workflows/verify.yml/badge.svg?branch=dev)](https://github.com/claymore666/dhcp-golib/actions/workflows/verify.yml?query=branch%3Adev)

A DHCP client you embed. It takes a lease on an interface, keeps it renewed,
and tells you when it changes. It applies nothing to the link. Adding the
address and the routes is your job. That is what lets one process hold leases
on many interfaces at once.

DHCPv4 and DHCPv6, Linux, no dependencies outside the standard library. The
protocol runs inside your process. It shells out to no `dhcpcd` or `dhclient`,
and it needs no root.

## Feature list

| | DHCPv4 | DHCPv6 |
|---|:---:|:---:|
| Take a lease and keep it: renew at T1, rebind at T2, expire when nobody answers | yes | yes |
| Give the lease back, and cope with a server that refuses it (DHCPNAK / Status Code) | yes | yes |
| Check the address is free before announcing it, and decline a duplicate (RFC 5227 / RFC 4862) | yes | yes |
| Come back after a restart still holding the same address (INIT-REBOOT / Confirm) | yes | yes |
| A durable lease record, a torn tail repaired, the exchange replayable offline | yes | yes |
| Report the address, the DNS servers and the search list | yes | yes |
| Report the preferred and the valid lifetime as separate deadlines | n/a | yes |
| Report the gateway, the static routes and the link MTU | yes | [v1.0.0](https://github.com/claymore666/docker-net-dhcp/issues/821) |
| Serve a caller that wants the configuration and no lease (DHCPINFORM / Information-request) | unsupported | yes |
| Tell a managed, a stateless, a SLAAC-only and a silent link apart (the advertisement's M and O flags) | n/a | yes |
| Form an address from a Router Advertisement prefix (SLAAC) | n/a | [v1.0.0](https://github.com/claymore666/docker-net-dhcp/issues/818) |
| Prefix delegation (IA_PD) | n/a | [v1.0.0](https://github.com/claymore666/docker-net-dhcp/issues/214) |
| Get an address in two messages (Rapid Commit) | n/a | [planned](https://github.com/claymore666/docker-net-dhcp/issues/926) |
| Hold a temporary address beside the non-temporary one (IA_TA) | n/a | [planned](https://github.com/claymore666/docker-net-dhcp/issues/927) |
| Take a reconfiguration the server starts (DHCPFORCERENEW / Reconfigure) | unsupported | [v1.0.0](https://github.com/claymore666/docker-net-dhcp/issues/925) |
| Act as a relay agent | unsupported | unsupported |
| Apply anything to the link: an address, a route, a resolver | unsupported | unsupported |

- **yes**: in the tree today, with a test that drives it, against a real
  server or through the state machine.
- **v1.0.0**: in the tree at v1.0.0. The roadmap below names the scope.
- **planned**: intended. No release names it yet, and the linked issue holds
  the plan.
- **unsupported**: the protocol has it, this library deliberately does not.
  "Out of scope" gives the reason.
- **n/a**: the protocol has no such thing.

A mark that is a link points at the issue that holds the plan.

## Status and roadmap

IPv6 is not finished. DHCPv6 takes a lease and keeps it. The matrix says where
it stops. The Router Advertisement is read for its two flags, and nothing else
is taken from it. No address is formed from a prefix. There is no prefix
delegation. A server cannot reconfigure a client that already holds a lease.
Nothing on DHCPv4 is planned for a later release.

The library is pre-1.0 and the API is not stable. It moves without a
deprecation cycle. Releases are tagged on `main`, so a consumer pins a tag.
The API still moves between tags. One consumer is being built on it. Nothing
that uses it has shipped.

v1.0.0 is when every `v1.0.0` row above is shipped. The scope of v1.0.0 is
exactly those rows. They are this library's share of the IPv6 work on the
`docker-net-dhcp` plugin's `v2.2.0` milestone. That milestone is wider than
this matrix, and its other rows land in the plugin.

What works today, claim by claim with the test that drives each one, is
[Coverage by claim in `docs/design.md`](docs/design.md#coverage-by-claim-through-m7).

## Usage

```
go get github.com/claymore666/dhcp-golib
```

Give it an interface and a parameter set; read lease events off a channel.

```go
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
```

Every event carries the address, the gateway, the routes, the DNS servers and
the absolute deadlines, already resolved out of the options. The kinds are
`Acquired`, `Changed`, `Renewed`, `Lost`, `Failed` and `Configured`, and they
are separate because a caller that has to reconfigure an interface needs to
know which one happened. A renewal that changed nothing carries no new
address. A failure the client is still retrying leaves the lease in place.

### DHCPv6

DHCPv6 is a second client with its own type. The two share no socket, no
journal and no state enumeration. A dual-stack endpoint runs both.

```go
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
```

Both blocks are `ExampleClient` and `ExampleClient6` in
[`runtime/example_test.go`](runtime/example_test.go), byte for byte. The arbiter's `readme-usage` row
diffs them and fails if either side moves, so this section cannot go stale.
Set `DHCP_GOLIB_EXAMPLE_IFACE` to a link with a DHCP server on it to run them.

## Why another DHCP library

Go already has good DHCP **packet** libraries. `insomniacslk/dhcp` is the one
you want if you need to build and parse messages. This library is the layer
above:

> Give me a managed lease on this interface, and tell me when it changes.

The work it saves you:

- The lease is kept. Renew at T1, rebind at T2, handle the NAK, expire the
  lease when nobody answers. It is a state machine.
- The address is checked before you use it. RFC 5227 conflict detection on
  IPv4 and RFC 4862 duplicate address detection on IPv6, with the decline and
  the recovery that follow, on the wire.
- It survives a restart. The lease is journalled, so a process that comes back
  asks for the address it had. A torn tail is repaired before anything is
  appended to it.
- DHCPv6 has the same shape as DHCPv4.
- The protocol core is pure and replayable. There is no clock and no I/O
  inside the state machine, so a captured exchange replays offline and
  deterministically. That is how you debug a lease that went wrong on someone
  else's network.
- The tests run against a real DHCP server. It is dnsmasq on a veth pair in an
  unprivileged namespace, asserted against the server's own log and lease
  file. No root, no password.

It is written for and consumed by the
[docker-net-dhcp](https://github.com/claymore666/docker-net-dhcp) network
plugin. The plugin is GPL-3.0 and this library is MIT, a combination the MIT
licence permits.

## Out of scope

The bounds below are written down so that nobody has to infer them.

- Nothing is applied to the link. No address added, no route installed, no
  resolver written. The library reports and you configure.
- No address management. It asks a server for a lease and reports the result.
  It is a client.
- No relay agent. A DHCPv6 Relay-forward or a Relay-reply is refused by the
  decoder by name, before its options are parsed. Nothing here forwards
  another host's messages.
- No server-initiated reconfiguration on IPv4. A message that arrives at a
  bound client with no exchange in flight is discarded, RFC 3203's
  DHCPFORCERENEW included. DHCPv6's Reconfigure is a `v1.0.0` row above.
- No DHCPINFORM. An IPv4 caller that already has an address and wants only the
  parameters is not served. DHCPv6's Information-request is sent, and it is how
  a stateless link is served.
- A reboot that goes unanswered keeps nothing. RFC 2131 permits reusing the
  lease when neither an ACK nor a NAK arrives. This client acquires from INIT,
  so nothing reaches the link that no server has confirmed in this process's
  lifetime.
- Linux only. IPv4 unicast renewal needs the peer's hardware address, learned
  from a frame the peer sent. A unicast the client cannot address is refused.
  The client does not fall back to broadcast.

## Testing

[`./verify.sh`](verify.sh) is the only arbiter this repository has. One command, one verdict
line. No row may report PASS without also saying how many things it examined.
It needs no root and touches no host state. [`docs/verifying.md`](docs/verifying.md) covers the
measurement behind each row. [`docs/gates.md`](docs/gates.md) covers the two ring gates and
their blind spots.

## Licence

MIT. See [`LICENSE`](LICENSE). Every `.go` and `.sh` file carries a one-line copyright
notice, so a file copied out of here carries its licence with it. The unit
suite fails if one does not.

## Contributing

[`./verify.sh`](verify.sh) is the gate, and it is the same command in CI as on a desk. One
thing is worth knowing first: a pull request from a fork does not run the
arbiter. The lane is triggered by `push` and by manual dispatch, and it is the
only workflow here that produces a verdict on a tree. The scans beside it,
CodeQL, `govulncheck` and `actionlint`, do run on a fork's pull request. They
run on GitHub's own machines, hold no secret and write nothing back. Two
properties make that safe. No job on a machine of ours is reachable from a
fork's pull request. No workflow here is triggered by `pull_request_target`,
the event that would hand this repository's own token to a run beside a
proposed tree. To have a contribution arbitrated, a maintainer pushes the
branch to this repository or dispatches the workflow.
[Section **In CI** of `docs/verifying.md`](docs/verifying.md#in-ci) states both
properties and names the tests that enforce them.

## More

- [`docs/design.md`](docs/design.md): the four rings, the milestones, the proof behind each claim
- [`docs/verifying.md`](docs/verifying.md): the measurement behind every arbiter row
- [`docs/gates.md`](docs/gates.md): the two ring gates, and their blind spots
- [`SECURITY.md`](SECURITY.md): how to report a vulnerability, and the attack surface
