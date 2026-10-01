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
# Each thing here was measured on the image rather than assumed. The apt calls
# are bounded by a lock timeout, retries and a wall limit, and name the lock
# holder on failure, so a stuck runner reads as a failure and not as silence.
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

# Both apt calls are bounded and loud. A fresh runner can hold the dpkg lock
# in a background apt run or stall on a mirror, and an unbounded call then sits
# silent until the job's own timeout kills it with nothing in the log. The
# install's stdout is kept, because that is where apt says it is waiting for a
# lock (claymore666/docker-net-dhcp#214).
apt_bounded() {
	local limit=$1 rc=0
	shift
	sudo env DEBIAN_FRONTEND=noninteractive timeout -k 10 "$limit" apt-get \
		-o DPkg::Lock::Timeout=120 -o Acquire::Retries=3 \
		-o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 \
		"$@" || rc=$?
	if [ "$rc" -ne 0 ]; then
		echo "apt-get $* failed after at most ${limit}s, exit $rc; lock holders follow" >&2
		sudo fuser -v /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock >&2 || true
		ps -eo pid,etimes,cmd | awk '/[a]pt|[d]pkg|[u]nattended/' >&2 || true
		exit "$rc"
	fi
}
apt_bounded 240 update -qq
apt_bounded 600 install -y -qq dnsmasq-base kea-dhcp6-server iproute2 shellcheck

# The Kea tests stat /var/lib/kea and bind-mount a per-test directory over it.
# Print what the runner has, so the log shows it, and make it only if absent
# (claymore666/docker-net-dhcp#214).
if [ ! -d /var/lib/kea ]; then
	sudo install -d -m 0750 -o _kea -g _kea /var/lib/kea
	echo "kea state directory: created"
else
	echo "kea state directory: present"
fi
ls -ld /var/lib/kea
echo "kea-dhcp6-server.service: $(systemctl is-active kea-dhcp6-server || true)"
# Ubuntu's package ships an AppArmor profile for kea-dhcp6; the Kea tests keep
# their files inside it, so the log states whether it is loaded and its mode
# (claymore666/docker-net-dhcp#214).
sudo aa-status 2>/dev/null | grep -i kea || echo "apparmor: no kea profile"

if [ -e /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]; then
	sudo sysctl -q -w kernel.apparmor_restrict_unprivileged_userns=0
	echo "apparmor userns restriction: cleared"
else
	echo "apparmor userns restriction: the knob does not exist on this kernel"
fi
