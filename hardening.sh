#!/bin/bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Error: this script must be run as root." >&2
    exit 1
fi

echo "→ Configuring DNS-over-TLS (Quad9)..."
mkdir -p /etc/systemd/resolved.conf.d
cat > /etc/systemd/resolved.conf.d/dot-quad9.conf << 'EOF'
[Resolve]
DNS=9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net 2620:fe::fe#dns.quad9.net 2620:fe::9#dns.quad9.net
DNSOverTLS=yes
DNSSEC=yes
FallbackDNS=
EOF

systemctl restart systemd-resolved
ln -sf /run/systemd/resolved/stub-resolv.conf /etc/resolv.conf

IFACE=$(ip route show default 2>/dev/null | awk 'NR==1 {print $5}')
if [[ -n "$IFACE" ]]; then
    echo "   Interface: $IFACE"
    resolvectl dns "$IFACE" \
        "9.9.9.9#dns.quad9.net" \
        "149.112.112.112#dns.quad9.net" \
        "2620:fe::fe#dns.quad9.net" \
        "2620:fe::9#dns.quad9.net"
    resolvectl dnsovertls "$IFACE" yes
    resolvectl dnssec "$IFACE" yes
    resolvectl status "$IFACE" | grep -E "DNS Server|DNS Over TLS|DNSSEC"
else
    echo "   No default route — per-interface config applies on first connection."
fi

echo "→ Applying sysctl hardening..."
cat > /etc/sysctl.d/99-stealth-hardening.conf << 'EOF'
net.ipv4.tcp_timestamps = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_mtu_probing = 1
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.use_tempaddr = 2
net.netfilter.nf_conntrack_max = 65536
net.netfilter.nf_conntrack_tcp_timeout_syn_sent = 10
EOF
sysctl -p /etc/sysctl.d/99-stealth-hardening.conf

echo "→ Deploying nftables ruleset..."
if [[ ! -f ./nftables.conf ]]; then
    echo "Error: nftables.conf not found in current directory." >&2
    exit 1
fi
nft -c -f ./nftables.conf
cp ./nftables.conf /etc/nftables.conf
systemctl enable nftables
systemctl restart nftables

echo "✓ Done. Verify:"
echo "  resolvectl status"
echo "  nft list ruleset"
echo "  sysctl -a | grep -E 'rp_filter|timestamps|tempaddr|conntrack_max'"
