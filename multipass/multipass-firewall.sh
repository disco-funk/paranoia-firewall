#!/usr/bin/env bash
#
# Adds the minimum nftables allowances for Multipass to the running
# paranoia-firewall ruleset. Does not touch nftables.conf.
#
# Multipass installs its own base chains (see nftables-appendix.config), but a
# packet traverses every base chain on a hook and any drop is final. Those
# chains are all policy accept, so they cannot rescue traffic from the policy
# drop in `inet filter`. These rules do.
#
#   multipass-firewall.sh           apply
#   multipass-firewall.sh remove    revert
#
# Runtime only: `nft -f /etc/nftables.conf` or a reboot wipes these. See README.

set -euo pipefail

BR="${MULTIPASS_BRIDGE:-mpqemubr0}"
ACTION="${1:-apply}"

if [[ $EUID -ne 0 ]]; then
	echo "must be root" >&2
	exit 1
fi

if ! nft list chain inet filter output >/dev/null 2>&1; then
	echo "inet filter table not loaded — is the paranoia firewall up?" >&2
	exit 1
fi

# Drop every rule in CHAIN matching PATTERN, highest handle first so earlier
# handles stay valid as we go. Makes apply idempotent and gives us `remove` for
# free.
purge() {
	local chain=$1 pattern=$2 handles
	handles=$(nft -a list chain inet filter "$chain" |
		awk -v pat="$pattern" '$0 ~ pat && match($0, /# handle [0-9]+$/) {
			print substr($0, RSTART + 9)
		}' | sort -rn)
	local h
	for h in $handles; do
		nft delete rule inet filter "$chain" handle "$h"
	done
}

purge input "$BR"
purge output "$BR"
purge forward "$BR"

if [[ $ACTION == remove ]]; then
	# The ct_base jump we add to forward names no interface, so purge above
	# leaves it. It is not in nftables.conf, so it is ours to take back.
	purge forward 'jump ct_base'
	echo "removed ${BR} rules from inet filter"
	exit 0
fi

if [[ $ACTION != apply ]]; then
	echo "usage: $0 [apply|remove]" >&2
	exit 1
fi

if ! ip link show "$BR" >/dev/null 2>&1; then
	echo "bridge ${BR} not present — start multipassd first" >&2
	exit 1
fi

# The guest reaches the dnsmasq that multipassd runs on the bridge. dnsmasq
# forwards upstream via /etc/resolv.conf -> systemd-resolved -> DoT, so no
# plain DNS leaves the host.
nft add rule inet filter input iifname "$BR" udp dport 67 counter accept
nft add rule inet filter input iifname "$BR" udp dport 53 counter accept
nft add rule inet filter input iifname "$BR" tcp dport 53 counter accept

# DHCP replies go to a broadcast address, so conntrack does not see them as a
# reply to the request and ct_base will not accept them. DNS replies it does.
nft add rule inet filter output oifname "$BR" udp sport 67 udp dport 68 counter accept

# `multipass launch` finishes by SSHing into the guest. Scoped to the bridge:
# this does not widen the github-only SSH rule.
nft add rule inet filter output oifname "$BR" tcp dport 22 counter accept

# forward has no ct_base jump of its own, so return traffic would be dropped.
nft list chain inet filter forward | grep -q 'jump ct_base' ||
	nft insert rule inet filter forward jump ct_base

nft add rule inet filter forward iifname "$BR" oifname != "$BR" tcp dport '{ 80, 443 }' counter accept

subnet=$(ip -4 -o addr show dev "$BR" | awk '{print $4}')
echo "applied ${BR} rules (${subnet:-no address})"

# multipassd owns ip filter / ip mangle / ip nat, including the masquerade.
# `flush ruleset` in nftables.conf destroys them; only a daemon restart
# rebuilds them.
if ! nft list table ip nat 2>/dev/null | grep -q masquerade; then
	echo
	echo "warning: multipass NAT rules are missing — guests will have no internet."
	echo "         run: snap restart multipass"
fi
