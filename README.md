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
| Give a lease back from its record alone, with no client and no interface left | yes | yes |
| Check the address is free before announcing it, and decline a duplicate (RFC 5227 / RFC 4862) | yes | yes |
| Come back after a restart still holding the same address (INIT-REBOOT / Confirm) | yes | yes |
| A durable lease record, a torn tail repaired, the exchange replayable offline | yes | yes |
| Report the address, the DNS servers and the search list | yes | yes |
| Give a running client a name for the server's table, and send it at once (RFC 2132's Host Name option, RFC 4704's Client FQDN option) | yes | yes |
| Report the preferred and the valid lifetime as separate deadlines | n/a | yes |
| Report the gateway, the static routes and the link MTU | yes | yes |
| Serve a caller that wants the configuration and no lease (DHCPINFORM / Information-request) | unsupported | yes |
| Tell a managed, a stateless, a SLAAC-only and a silent link apart (the advertisement's M and O flags) | n/a | yes |
| Tell a server that refused apart from one that never answered, and say which code it sent | yes | yes |
| Read what the Router Advertisement carries beyond those flags: the link MTU, the routes, the resolvers, the search list and the advertised prefixes | n/a | yes |
| Form an address from a Router Advertisement prefix (SLAAC), from the link address (modified EUI-64) or a stable, opaque identifier (RFC 7217) | n/a | yes |
| Ask for a delegated prefix and report it (IA_PD, RFC 8415; the library installs nothing) | n/a | yes |
| Get an address in two messages (Rapid Commit, RFC 4039 / RFC 8415) | yes | yes |
| Hold a temporary address beside the non-temporary one (IA_TA) | n/a | yes, not on a resumed lease |
| Take a reconfiguration the server starts (DHCPFORCERENEW / Reconfigure) | yes | yes |
| Tell the server what kind of client this is (User Class, RFC 3004) | yes | n/a |
| Learn that the network runs IPv6 only and how long to wait before asking again (IPv6-Only Preferred, RFC 8925) | yes | n/a |
| Read the NAT64 prefix a Router Advertisement carries (PREF64, RFC 8781) | n/a | yes |
| Act as a relay agent | unsupported | unsupported |
| Apply anything to the link: an address, a route, a resolver | unsupported | unsupported |

- **yes**: in the tree today, with a test that drives it, against a real
  server or through the state machine.
- **planned**: intended. No release names it yet, and the linked issue holds
  the plan.
- **unsupported**: the protocol has it, this library deliberately does not.
  "Out of scope" gives the reason.
- **n/a**: the protocol has no such thing.

A mark that is a link points at the issue that holds the plan.

## Status and roadmap

IPv6 is not finished. DHCPv6 takes a lease and keeps it. The matrix says where
it stops. The Router Advertisement is read for its flags and for its
prefixes, its routes, its link MTU, its resolvers and its search list, an
address is formed from an advertised prefix, and every one of those is reported
and none of it is applied. A client with `PrefixHint` set asks for a delegated
prefix in an IA_PD and reports what the server grants; it installs no address
and no route, as RFC 3633 §12.1 says a delegated prefix is never assigned to
the link it arrived on. A server that holds the reconfigure key it gave the
client can make it renew, rebind or ask for configuration again, and a Reconfigure that is not signed
with that key is discarded. A DHCPv6 client sends its name in RFC 4704's
Client FQDN option. A name set on a client that holds a lease goes out
straight away in a Renew, or in a Rebind when the lease names no server or the
client is already rebinding, and lands in the server's lease file
(`TestAV6HostnameSetAfterStartReachesTheServersLeaseFile`). A client bound to
a SLAAC address or holding no lease sends nothing, a client not yet bound
sends the name in its next Solicit or Request, or as above once it is bound,
and an empty name is never sent. A DHCPv6 client with `RapidCommit` set puts
the Rapid Commit option in its Solicit and in no other message, and takes a Reply that
carries it as the lease with no Request; a Reply without it is discarded, and
a plain Advertise gets the ordinary Request. On DHCPv4 a client with user classes sends
them in the User Class option in its Discover and every Request. A DHCPv4
client with `RapidCommit` set asks for a two-message lease in its Discover and
takes an Ack that carries the option as the lease, and a server that answers
with an Offer gets the ordinary Request. A DHCPv4 client with `IPv6OnlyPreferred`
set lists that option (RFC 8925) in its Discover and every Request. An Offer that carries
it gets no Request, Decline or Release: the client waits for the server's
value, never less than five minutes, or until the link comes up again, and then
starts a new Discover. An Ack that carries it in INIT-REBOOT is the same wait,
and in any other state, a two-message Ack included, the lease stands. A client
without the flag ignores the option. The wire and the client behaviour for every
option in the rows above ship. A DHCPv4 client lists the
Forcerenew Nonce option (RFC 6704) in its Discover and every Request and keeps
the nonce its Ack gives. A DHCPFORCERENEW is acted on only when it was sent to
the leased address, names this client, and
carries an HMAC-MD5 over its own octets under that nonce with a replay value
above the last one used; a client that holds a lease then renews like T1 (one
already renewing or rebinding only raises the replay floor), and anything else is
discarded and counted by reason. An Ack that follows an Offer which listed the option and
carries no valid nonce is discarded, and the client starts over. A client
restarted from its record holds no nonce and refuses every DHCPFORCERENEW until
its next Ack gives one. v1.3.0 adds four pieces to what a
client reads and asks for: the Microsoft classless static routes option as a
second source for the routes when RFC 3442's is absent
([#1030](https://github.com/claymore666/docker-net-dhcp/issues/1030)), the vendor-specific options on DHCPv4 and DHCPv6
([#1034](https://github.com/claymore666/docker-net-dhcp/issues/1034)), the DHCPv6 timezone options ([#1033](https://github.com/claymore666/docker-net-dhcp/issues/1033)) and the
DHCPv6 NTP server option, read as the whole list ([#859](https://github.com/claymore666/docker-net-dhcp/issues/859)).
v1.4.0 adds the DHCPv6 Reply's options on the lease a caller receives, as
`Lease.OptionsV6` ([#1033](https://github.com/claymore666/docker-net-dhcp/issues/1033)), and the RFC 7217 stable, opaque
interface identifier as a `Params6` choice, retried on a duplicate address
([#1032](https://github.com/claymore666/docker-net-dhcp/issues/1032)).
v1.4.1 makes a DHCPv6 Release list every address and prefix the client holds,
an IA_TA for the temporary addresses and, on the record path, an IA_PD for the
delegated prefixes ([#60](https://github.com/claymore666/dhcp-golib/issues/60)).
v1.4.2 fixes two DHCPv6 lease-keeping faults. A Renew or Rebind Reply that
leaves a held prefix or address out no longer drops it: the held binding keeps
its own expiry ([#64](https://github.com/claymore666/dhcp-golib/issues/64)). A
prefix, temporary address or address of several whose valid lifetime ends while
the lease is bound now leaves the lease at that instant, and the caller gets a
`Changed` event; the lease still ends with its last address
([#65](https://github.com/claymore666/dhcp-golib/issues/65)).

v1.0.0 is the DHCPv6 release, and every row of it is in the tree: the Router
Advertisement read for the five options the row above names, an address formed
from one of its prefixes, a refusal told apart from a silence, a
reconfiguration the server starts, and a lease given back from its record
alone.

This library is the DHCP engine of docker-net-dhcp 2.x. The API is not stable.
It moves between tags and without a deprecation cycle. Releases are tagged on
`main`, so a consumer pins a tag.

What works today, claim by claim with the test that drives each one, is
[Coverage by claim in `docs/design.md`](docs/design.md#coverage-by-claim-through-v142).

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
  file. No root, no password. The prefix delegation tests run Kea instead,
  because dnsmasq delegates nothing; they need `kea-dhcp6` on `PATH` and fail
  when it is absent.

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
- No unauthenticated DHCPFORCERENEW. RFC 3203's message is acted on only with
  the nonce authentication of RFC 6704 ([#1119](https://github.com/claymore666/docker-net-dhcp/issues/1119)); a server that gave no nonce cannot
  make an IPv4 client renew, and a frame sent to a broadcast or multicast address
  is discarded. DHCPv6's Reconfigure is served, which is a `yes` row above.
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
