#!/bin/bash
set -euo pipefail

(( EUID == 0 )) || exit 1

mkdir -p /etc/systemd/resolved.conf.d
cat > /etc/systemd/resolved.conf.d/dot-quad9.conf << 'EOF'
[Resolve]
DNS=9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net
DNSOverTLS=yes
DNSSEC=yes
FallbackDNS=
EOF
systemctl restart systemd-resolved
ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf

IFACE=$(ip route show default 2>/dev/null | awk 'NR==1 {print $5}')
if [[ -n "$IFACE" ]]; then
    resolvectl dns "$IFACE" "9.9.9.9#dns.quad9.net" "149.112.112.112#dns.quad9.net"
    resolvectl dnsovertls "$IFACE" yes
    resolvectl dnssec "$IFACE" yes
fi

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

[[ -f ./nftables.conf ]] || exit 1
nft -c -f ./nftables.conf
cp ./nftables.conf /etc/nftables.conf
systemctl enable nftables
systemctl restart nftables
