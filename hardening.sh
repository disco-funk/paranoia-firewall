#!/bin/bash
# hardening.sh — stealth CGNAT host setup
# Applies DNS-over-TLS, sysctl hardening, and deploys nftables ruleset.
# Must be run as root from the directory containing nftables.conf.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Error: this script must be run as root." >&2
    exit 1
fi

# ─────────────────────────────────────────────
# 1. DNS-over-TLS via systemd-resolved
# ─────────────────────────────────────────────
echo "→ Configuring DNS-over-TLS (Quad9)..."

# Drop-in avoids modifying /etc/systemd/resolved.conf directly;
# resolvectl applies the same settings to the running instance immediately.
mkdir -p /etc/systemd/resolved.conf.d
cat > /etc/systemd/resolved.conf.d/dot-quad9.conf << 'EOF'
[Resolve]
# Quad9 IPv4 and IPv6 — #hostname suffix enables strict TLS certificate validation
DNS=9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net 2620:fe::fe#dns.quad9.net 2620:fe::9#dns.quad9.net
DNSOverTLS=yes
DNSSEC=yes
# No fallback — plain DNS is not permitted
FallbackDNS=
EOF

# Restart resolved so the global drop-in takes effect without needing a live interface
systemctl restart systemd-resolved

# Ensure applications use the stub resolver (127.0.0.53)
ln -sf /run/systemd/resolved/stub-resolv.conf /etc/resolv.conf

# Apply per-interface settings live if a default route already exists.
# Belt-and-suspenders only — the restarted service already has the global config.
IFACE=$(ip route show default 2>/dev/null | awk 'NR==1 {print $5}')
if [[ -n "$IFACE" ]]; then
    echo "   Primary interface: $IFACE"
    resolvectl dns "$IFACE" \
        "9.9.9.9#dns.quad9.net" \
        "149.112.112.112#dns.quad9.net" \
        "2620:fe::fe#dns.quad9.net" \
        "2620:fe::9#dns.quad9.net"
    resolvectl dnsovertls "$IFACE" yes
    resolvectl dnssec     "$IFACE" yes
    echo "   DNS status:"
    resolvectl status "$IFACE" | grep -E "DNS Server|DNS Over TLS|DNSSEC"
else
    echo "   No default route yet — per-interface config will apply on first connection."
fi

# ─────────────────────────────────────────────
# 2. sysctl hardening
# ─────────────────────────────────────────────
echo "→ Applying sysctl hardening..."

cat > /etc/sysctl.d/99-stealth-hardening.conf << 'EOF'
# ── Fingerprinting reduction ──────────────────────────────────────────────────
# Remove TCP timestamp option — leaks host uptime to observers
net.ipv4.tcp_timestamps = 0

# ── Source address validation ─────────────────────────────────────────────────
# Strict reverse-path filtering — drop packets with spoofed source addresses
net.ipv4.conf.all.rp_filter     = 1
net.ipv4.conf.default.rp_filter = 1

# Log martian packets (impossible/spoofed source addresses) to kernel log
net.ipv4.conf.all.log_martians  = 1

# ── PMTUD resilience ──────────────────────────────────────────────────────────
# Probe for MTU when ICMP black hole detected (rate-limited ICMP mitigation)
net.ipv4.tcp_mtu_probing = 1

# ── IPv6 privacy ──────────────────────────────────────────────────────────────
# Rotate temporary addresses — reduces long-term address tracking
net.ipv6.conf.all.use_tempaddr     = 2
net.ipv6.conf.default.use_tempaddr = 2

# ── Conntrack tuning ──────────────────────────────────────────────────────────
# Cap conntrack table size
net.netfilter.nf_conntrack_max = 65536
# Reduce half-open TCP connection timeout (limits conntrack exhaustion window)
net.netfilter.nf_conntrack_tcp_timeout_syn_sent = 10
EOF

sysctl -p /etc/sysctl.d/99-stealth-hardening.conf

# ─────────────────────────────────────────────
# 3. nftables
# ─────────────────────────────────────────────
echo "→ Deploying nftables ruleset..."

if [[ ! -f ./nftables.conf ]]; then
    echo "Error: nftables.conf not found in current directory." >&2
    exit 1
fi

# Validate before deploying
nft -c -f ./nftables.conf
cp ./nftables.conf /etc/nftables.conf

systemctl enable nftables
systemctl restart nftables

echo ""
echo "✓ All done. Verify with:"
echo "  resolvectl status"
echo "  nft list ruleset"
echo "  sysctl -a | grep -E 'rp_filter|timestamps|tempaddr|conntrack_max'"
