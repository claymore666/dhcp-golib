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
#   - dnsmasq, iproute2 and shellcheck. The arbiter shells out to all three
#     (netns-suite, the namespaced tests, the shellcheck row) and the image
#     carries none of them. Without this step those rows report an absent tool,
#     which is a FAIL and not a skip.
#   - kernel.apparmor_restrict_unprivileged_userns. The image's AppArmor lets an
#     unprivileged user namespace be CREATED and then refuses every netlink call
#     inside it, so `ip link add` answers "Operation not permitted" and the
#     netns row goes red for a reason that is not the tree (run 33992151078).
#     The knob does not exist on every kernel; where it does not, this is a
#     no-op and the fact is recorded rather than assumed.

set -euo pipefail

sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
	dnsmasq-base iproute2 shellcheck >/dev/null

if [ -e /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]; then
	sudo sysctl -q -w kernel.apparmor_restrict_unprivileged_userns=0
	echo "apparmor userns restriction: cleared"
else
	echo "apparmor userns restriction: the knob does not exist on this kernel"
fi
