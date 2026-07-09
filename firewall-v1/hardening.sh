#!/bin/bash
set -euo pipefail

(( EUID == 0 )) || exit 1

DOT_SERVERS="9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net"
RD=/etc/systemd/resolved.conf.d
TD=/etc/systemd/timesyncd.conf.d

mkdir -p "$RD"
cat > "$RD/dot-quad9.conf" << EOF
[Resolve]
DNS=$DOT_SERVERS
DNSOverTLS=yes
DNSSEC=yes
FallbackDNS=
EOF
systemctl restart systemd-resolved
ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf

IFACE=$(ip route show default 2>/dev/null | awk 'NR==1 {print $5}')
if [[ -n "$IFACE" ]]; then
    resolvectl dns "$IFACE" $DOT_SERVERS
    resolvectl dnsovertls "$IFACE" yes
    resolvectl dnssec "$IFACE" yes
fi

mkdir -p "$TD"
cat > "$TD/cloudflare-ntp.conf" << 'EOF'
[Time]
NTP=162.159.200.123 162.159.200.1
FallbackNTP=
EOF
systemctl restart systemd-timesyncd

echo nf_conntrack > /etc/modules-load.d/nf_conntrack.conf
modprobe nf_conntrack
cat > /etc/sysctl.d/99-stealth-hardening.conf << 'EOF'
kernel.kptr_restrict = 2
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.default.use_tempaddr = 2
net.netfilter.nf_conntrack_max = 65536
net.netfilter.nf_conntrack_tcp_timeout_syn_sent = 1
EOF
sysctl -p /etc/sysctl.d/99-stealth-hardening.conf

[[ -f ./nftables.conf ]] || exit 1
nft -c -f ./nftables.conf
cp ./nftables.conf /etc/nftables.conf
systemctl enable nftables
systemctl restart nftables
