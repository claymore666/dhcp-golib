# dhcp-golib — a managed-lease DHCP client for Go

[![verify](https://github.com/claymore666/dhcp-golib/actions/workflows/verify.yml/badge.svg?branch=dev)](https://github.com/claymore666/dhcp-golib/actions/workflows/verify.yml?query=branch%3Adev)

A DHCP client you embed. It takes a lease on an interface, keeps it renewed,
and tells you when it changes. It applies nothing to the link — adding the
address and the routes is your job, which is what lets one process hold leases
on many interfaces at once.

DHCPv4 and DHCPv6, Linux, no dependencies outside the standard library. It
shells out to no `dhcpcd` or `dhclient` — the protocol is in the process — and
it needs no root.

## What is there, and what is not

| | DHCPv4 | DHCPv6 |
|---|:---:|:---:|
| Take a lease and keep it: renew at T1, rebind at T2, expire when nobody answers | yes | yes |
| Give the lease back, and cope with a server that refuses it (DHCPNAK / Status Code) | yes | yes |
| Check the address is free before announcing it, and decline a duplicate (RFC 5227 / RFC 4862) | yes | yes |
| Come back after a restart still holding the same address (INIT-REBOOT / Confirm) | yes | yes |
| A durable lease record, a torn tail repaired, the exchange replayable offline | yes | yes |
| Report the address, the DNS servers and the search list | yes | yes |
| Report the preferred and the valid lifetime as separate deadlines | n/a | yes |
| Report the gateway, the static routes and the link MTU | yes | planned |
| Serve a caller that wants the configuration and no lease (DHCPINFORM / Information-request) | by design | yes |
| Tell a managed, a stateless, a SLAAC-only and a silent link apart (the advertisement's M and O flags) | n/a | yes |
| Form an address from a Router Advertisement prefix (SLAAC) | n/a | planned |
| Prefix delegation (IA_PD) | n/a | planned |
| Take a reconfiguration the server starts (DHCPFORCERENEW / Reconfigure) | by design | planned |
| Act as a relay agent | by design | by design |
| Apply anything to the link: an address, a route, a resolver | by design | by design |

**yes** — in the tree today, with a test that drives it, against a real server
or through the state machine. **planned** — not there yet, and named for
v1.0.0 below. **by design** — deliberately not done, and "What it does not do"
says why. **n/a** — the protocol has no such thing.

## Status and roadmap

**IPv6 is not finished.** DHCPv6 takes a lease and keeps it, and the matrix
says where it stops: the Router Advertisement is read for its two flags and
nothing else is taken from it, no address is formed from a prefix, there is no
prefix delegation, and a server cannot reconfigure a client that already holds
a lease. The DHCPv4 column has no `planned` row.

**Pre-1.0 and the API is not stable.** It moves without a deprecation cycle,
and there is no tagged release yet, so a consumer takes a commit. One consumer
is being built on it; nothing that uses it has shipped.

**v1.0.0 is when every `planned` row above is shipped — those rows, and
nothing else.** They are this library's share of the IPv6 work on the
`docker-net-dhcp` plugin's `v2.2.0` milestone; that milestone is wider than
this matrix, and its other rows land in the plugin rather than here. A `by
design` row does not become a `planned` one by waiting.

What works today, claim by claim with the test that drives each one, is
`docs/design.md`.

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
know which one happened: a renewal that changed nothing is not a new address,
and a failure that the client is retrying is not a lost lease.

### DHCPv6

A second client rather than a mode of the first: the two share no socket, no
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
`runtime/example_test.go`, byte for byte — the arbiter's `readme-usage` row
diffs them and fails if either side moves, so this section cannot go stale.
Set `DHCP_GOLIB_EXAMPLE_IFACE` to a link with a DHCP server on it to run them.

## Why this one

Go already has good DHCP **packet** libraries — `insomniacslk/dhcp` is the one
you want if you need to build and parse messages. This is the layer above:

> Give me a managed lease on this interface, and tell me when it changes.

What that buys you, and what you would otherwise write yourself:

- **The lease is kept.** Renew at T1, rebind at T2, handle the NAK, expire the
  lease when nobody answers — as a state machine, not a retry loop.
- **The address is checked before you use it.** RFC 5227 conflict detection on
  IPv4 and RFC 4862 duplicate address detection on IPv6, with the decline and
  the recovery that follow, on the wire.
- **It survives a restart.** The lease is journalled, so a process that comes
  back asks for the address it had instead of taking a new one, and a torn
  write is repaired rather than appended to.
- **DHCPv6 has the same shape**, not a different API bolted on.
- **The protocol core is pure and replayable.** No clock and no I/O inside the
  state machine, so a captured exchange replays offline and deterministically —
  which is how you debug a lease that went wrong on someone else's network.
- **The tests run against a real DHCP server.** Not mocks: dnsmasq on a veth
  pair in an unprivileged namespace, asserted against the server's own log and
  lease file. No root, no password.

It is written for and consumed by the
[docker-net-dhcp](https://github.com/claymore666/docker-net-dhcp) network
plugin, which is GPL-3.0 while this library is MIT — a combination the MIT
licence permits.

## What it does not do

Stated because a bound nobody writes down is read as a guarantee.

- **Nothing is applied to the link.** No address added, no route installed, no
  resolver written. The library reports; you configure.
- **No address management.** It asks a server for a lease and reports what it
  got. It is a client, not an IPAM.
- **No relay agent.** This is a client: a DHCPv6 Relay-forward or a Relay-reply
  is refused by the decoder rather than parsed, and nothing here forwards
  another host's messages.
- **No server-initiated reconfiguration on IPv4.** A message that arrives at a
  bound client with no exchange in flight is discarded rather than acted on,
  RFC 3203's DHCPFORCERENEW included. DHCPv6's Reconfigure is a different case
  and is a `planned` row above.
- **No DHCPINFORM.** An IPv4 caller that already has an address and wants only
  the parameters is not served. DHCPv6's Information-request is a different
  case and is sent: it is how a stateless link is served.
- **A reboot that goes unanswered keeps nothing.** RFC 2131 permits reusing the
  lease when neither an ACK nor a NAK arrives; this client acquires from INIT
  instead, so nothing reaches the link that no server has confirmed in this
  process's lifetime.
- **Linux only**, and IPv4 unicast renewal needs the peer's hardware address
  learned from a frame it sent — a unicast it cannot address is refused rather
  than broadcast anyway.

## Testing

`./verify.sh` is the only arbiter this repository has: one command, one verdict
line, and no row may report PASS without also saying how many things it
examined. It needs no root and touches no host state. `docs/verifying.md` says
what each row measures; `docs/gates.md` says what the two ring gates enforce
and, more usefully, what they cannot see.

## Licence

MIT — see `LICENSE`. Every `.go` and `.sh` file carries a one-line copyright
notice so that a file copied out of here carries its licence with it, and the
unit suite fails if one does not.

## Contributing

`./verify.sh` is the gate, and it is the same command in CI as on a desk. One
thing is worth knowing first: **a pull request from a fork does not run the
arbiter.** The lane is triggered by `push` and by manual dispatch, and it is
the only workflow here that produces a verdict on a tree. The scans beside it —
CodeQL, `govulncheck`, `actionlint` — do run on a fork's pull request, on
GitHub's own machines, holding no secret and writing nothing back. Two
properties make that safe rather than one: no job on a machine of ours is
reachable from a fork's pull request, and no workflow here is triggered by
`pull_request_target` — the event that would hand this repository's own token
to a run beside a proposed tree. To have a contribution arbitrated, a
maintainer pushes the branch to this repository or dispatches the workflow.
`docs/verifying.md`, **In CI**, states both properties and names the tests that
enforce them.

## More

- `docs/design.md` — the four rings, what the tests prove today, the milestones
- `docs/verifying.md` — what every arbiter row measures
- `docs/gates.md` — the two ring gates, and their blind spots
- `SECURITY.md` — how to report a vulnerability, and what the attack surface is
