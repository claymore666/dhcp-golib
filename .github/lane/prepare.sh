#!/usr/bin/env bash
# Copyright (c) 2026 Christian Kamien. MIT License, see LICENSE.

#
# prepare.sh — put a GitHub-hosted image into the state the arbiter measures in.
#
# Usage:  .github/lane/prepare.sh
# Exit:   0, or non-zero with the reason. It is a step, not a gate: nothing here
#         decides a verdict, and everything here is a fact the arbiter would
#         otherwise report as a missing tool or an unavailable namespace.
#
# ONE COPY, called by both hosted job kinds. The product lane and every oracle
# shard need exactly the same machine, and a lane that wrote these steps out
# twice is a lane where a fix reaches one of them.
#
# Each thing here was measured on the image rather than assumed:
#
#   - dnsmasq, kea-dhcp6-server, iproute2 and shellcheck. The arbiter shells
#     out to all of them (netns-suite, the namespaced tests, the shellcheck row)
#     and the image carries none of them. Without this step those rows report
#     an absent tool, which is a FAIL and not a skip. Kea serves the
#     prefix-delegation tests (claymore666/docker-net-dhcp#214).
#   - kernel.apparmor_restrict_unprivileged_userns. The image's AppArmor lets an
#     unprivileged user namespace be CREATED and then refuses every netlink call
#     inside it, so `ip link add` answers "Operation not permitted" and the
#     netns row goes red for a reason that is not the tree (run 33992151078).
#     The knob does not exist on every kernel; where it does not, this is a
#     no-op and the fact is recorded rather than assumed.

set -euo pipefail

sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
	dnsmasq-base kea-dhcp6-server iproute2 shellcheck >/dev/null

# /var/lib/kea is the unit's StateDirectory=, created at the service's first
# start; the package leaves it to systemd, so a fresh runner has none and a Kea
# test fails in 0.04 s on its os.Stat (claymore666/docker-net-dhcp#214). Create
# it the way the unit would, and print what was found so the log is the proof.
if [ ! -d /var/lib/kea ]; then
	sudo install -d -m 0750 -o _kea -g _kea /var/lib/kea
	echo "kea state directory: created"
else
	echo "kea state directory: present"
fi
ls -ld /var/lib/kea
echo "kea-dhcp6-server.service: $(systemctl is-active kea-dhcp6-server || true)"

if [ -e /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]; then
	sudo sysctl -q -w kernel.apparmor_restrict_unprivileged_userns=0
	echo "apparmor userns restriction: cleared"
else
	echo "apparmor userns restriction: the knob does not exist on this kernel"
fi
