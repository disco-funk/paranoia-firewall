#!/bin/bash
set -uo pipefail

PASS=0
FAIL=0

ok()   { echo "PASS  $1"; PASS=$(( PASS + 1 )); }
fail() { echo "FAIL  $1"; FAIL=$(( FAIL + 1 )); }

check() {
    local label="$1"; shift
    if "$@" >/dev/null 2>&1; then ok "$label"; else fail "$label"; fi
}

check_blocked() {
    local label="$1"; shift
    if "$@" >/dev/null 2>&1; then fail "$label"; else ok "$label"; fi
}

IFACE=$(ip route show default 2>/dev/null | awk 'NR==1 {print $5}')

echo "=== config ==="
check "active interface found"                          test -n "$IFACE"
check "resolved live: DoT active on $IFACE"             bash -c "resolvectl status $IFACE | grep -q '+DNSOverTLS'"
check "resolved live: DNSSEC active on $IFACE"          bash -c "resolvectl status $IFACE | grep -q 'DNSSEC=yes'"
check "resolved live: 9.9.9.9 active on $IFACE"         bash -c "resolvectl status $IFACE | grep -q '9\.9\.9\.9'"
check "resolved live: 149.112.112.112 active on $IFACE" bash -c "resolvectl status $IFACE | grep -q '149\.112\.112\.112'"
check "resolv.conf symlink to stub"       bash -c  'readlink /etc/resolv.conf | grep -q stub-resolv'
check "sysctl tcp_timestamps=0"           bash -c  '[[ $(sysctl -n net.ipv4.tcp_timestamps) == 0 ]]'
check "sysctl rp_filter=1"               bash -c  '[[ $(sysctl -n net.ipv4.conf.all.rp_filter) == 1 ]]'
check "sysctl use_tempaddr=2"            bash -c  '[[ $(sysctl -n net.ipv6.conf.all.use_tempaddr) == 2 ]]'
check "sysctl log_martians=1"            bash -c  '[[ $(sysctl -n net.ipv4.conf.all.log_martians) == 1 ]]'

echo "=== green: must reach ==="
check "stub resolves example.com"         resolvectl query example.com
check "http outbound port 80"             curl -sSo /dev/null --max-time 10 http://neverssl.com/
check "https outbound port 443"           curl -sSo /dev/null --max-time 10 https://example.com/
check "DoT 9.9.9.9:853"                  nc -z -w 5 9.9.9.9 853
check "DoT 149.112.112.112:853"          nc -z -w 5 149.112.112.112 853

echo "=== red: must be blocked ==="
check_blocked "port 53 TCP to 9.9.9.9"             timeout 5 nc -z    9.9.9.9      53
check_blocked "port 53 UDP to 9.9.9.9"             timeout 5 dig @9.9.9.9      example.com +time=3 +tries=1 +notcp
check_blocked "port 53 TCP to 8.8.8.8"             timeout 5 nc -z    8.8.8.8      53
check_blocked "port 53 UDP to 8.8.8.8"             timeout 5 dig @8.8.8.8      example.com +time=3 +tries=1 +notcp
check_blocked "DoT to 1.1.1.1:853"                 timeout 5 nc -z    1.1.1.1     853
check_blocked "DoT to 8.8.8.8:853"                 timeout 5 nc -z    8.8.8.8     853
check_blocked "DoT to Quad9 IPv6 2620:fe::fe:853"  timeout 5 nc -6 -z 2620:fe::fe 853
check_blocked "DoT to Quad9 IPv6 2620:fe::9:853"   timeout 5 nc -6 -z 2620:fe::9  853
check_blocked "port 22 outbound"                    timeout 5 nc -z    9.9.9.9      22
check_blocked "port 25 outbound"                    timeout 5 nc -z    9.9.9.9      25
check_blocked "port 8080 outbound"                  timeout 5 nc -z    9.9.9.9    8080
check_blocked "ICMP echo outbound"                  timeout 5 ping -c 1 -W 3 9.9.9.9

echo ""
echo "Results: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
