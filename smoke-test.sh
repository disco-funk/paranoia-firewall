#!/bin/bash
set -uo pipefail

usage() {
    cat >&2 <<'USAGE'
Usage: smoke-test.sh [config|network|all]

  config   Host state only: systemd-resolved DoT/DNSSEC, resolv.conf, sysctls.
           Requires a deployed host. Meaningless in a container.
  network  Egress policy only: what the firewall lets out and what it drops.
           Runs anywhere the ruleset is loaded, including a container.
  all      Both (default).

Environment:
  FIREWALL_VERSION   v1 (default) or v2. v2 permits outbound ping and
                     outbound SSH to a pinned GitHub set; v1 blocks both.
USAGE
}

SECTION="${1:-all}"
FIREWALL_VERSION="${FIREWALL_VERSION:-v1}"

case "$FIREWALL_VERSION" in
    v1|v2) ;;
    *) echo "ERROR: FIREWALL_VERSION must be v1 or v2, got '${FIREWALL_VERSION}'" >&2; exit 2 ;;
esac

PASS=0
FAIL=0
SKIP=0

ok()   { echo "PASS  $1"; PASS=$(( PASS + 1 )); }
fail() { echo "FAIL  $1"; FAIL=$(( FAIL + 1 )); }
skip() { echo "SKIP  $1 ($2)"; SKIP=$(( SKIP + 1 )); }

check() {
    local label="$1"; shift
    if "$@" >/dev/null 2>&1; then ok "$label"; else fail "$label"; fi
}

check_blocked() {
    local label="$1"; shift
    if "$@" >/dev/null 2>&1; then fail "$label"; else ok "$label"; fi
}

have_global_ipv6() {
    ip -6 addr show scope global 2>/dev/null | grep -q inet6
}

run_config() {
    local IFACE
    IFACE=$(ip route show default 2>/dev/null | awk 'NR==1 {print $5}')

    echo "=== config ==="
    check "active interface found"                          test -n "$IFACE"
    check "resolved live: DoT active on $IFACE"             bash -c "resolvectl status $IFACE | grep -q '+DNSOverTLS'"
    check "resolved live: DNSSEC active on $IFACE"          bash -c "resolvectl status $IFACE | grep -q 'DNSSEC=yes'"
    check "resolved live: 9.9.9.9 active on $IFACE"         bash -c "resolvectl status $IFACE | grep -q '9\.9\.9\.9'"
    check "resolved live: 149.112.112.112 active on $IFACE" bash -c "resolvectl status $IFACE | grep -q '149\.112\.112\.112'"
    check "resolv.conf symlink to stub"       bash -c  'readlink /etc/resolv.conf | grep -q stub-resolv'
    check "sysctl tcp_timestamps=0"          test "$(sysctl -n net.ipv4.tcp_timestamps 2>/dev/null)"      = 0
    check "sysctl rp_filter=1"               test "$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null)"  = 1
    check "sysctl use_tempaddr=2"            test "$(sysctl -n net.ipv6.conf.all.use_tempaddr 2>/dev/null)" = 2
    check "sysctl log_martians=1"            test "$(sysctl -n net.ipv4.conf.all.log_martians 2>/dev/null)" = 1

    echo "=== green: stub resolver ==="
    check "stub resolves example.com"         resolvectl query example.com
}

run_network() {
    echo "=== green: must reach (${FIREWALL_VERSION}) ==="
    check "http outbound port 80"             wget -q -O /dev/null --timeout=10 --tries=1 http://neverssl.com/
    check "https outbound port 443"           wget -q -O /dev/null --timeout=10 --tries=1 https://example.com/
    check "DoT 9.9.9.9:853"                  nc -z -w 5 9.9.9.9 853
    check "DoT 149.112.112.112:853"          nc -z -w 5 149.112.112.112 853

    echo "=== red: must be blocked (${FIREWALL_VERSION}) ==="
    check_blocked "port 53 TCP to 9.9.9.9"             timeout 5 nc -z    9.9.9.9      53
    check_blocked "port 53 UDP to 9.9.9.9"             timeout 5 dig @9.9.9.9      example.com +time=3 +tries=1 +notcp
    check_blocked "port 53 TCP to 8.8.8.8"             timeout 5 nc -z    8.8.8.8      53
    check_blocked "port 53 UDP to 8.8.8.8"             timeout 5 dig @8.8.8.8      example.com +time=3 +tries=1 +notcp
    check_blocked "DoT to 1.1.1.1:853"                 timeout 5 nc -z    1.1.1.1     853
    check_blocked "DoT to 8.8.8.8:853"                 timeout 5 nc -z    8.8.8.8     853

    # Quad9 IPv6 DoT is deliberately excluded from the ruleset. Without a global
    # IPv6 address these connects fail for lack of routing, not because the
    # firewall dropped them, so the assertion would pass vacuously.
    if have_global_ipv6; then
        check_blocked "DoT to Quad9 IPv6 2620:fe::fe:853"  timeout 5 nc -6 -z 2620:fe::fe 853
        check_blocked "DoT to Quad9 IPv6 2620:fe::9:853"   timeout 5 nc -6 -z 2620:fe::9  853
    else
        skip "DoT to Quad9 IPv6 2620:fe::fe:853" "no global IPv6 address"
        skip "DoT to Quad9 IPv6 2620:fe::9:853"  "no global IPv6 address"
    fi

    check_blocked "port 22 outbound to 9.9.9.9"         timeout 5 nc -z    9.9.9.9      22
    check_blocked "port 25 outbound"                    timeout 5 nc -z    9.9.9.9      25
    check_blocked "port 8080 outbound"                  timeout 5 nc -z    9.9.9.9    8080

    # v1 drops outbound echo-request; v2 accepts it.
    if [[ "$FIREWALL_VERSION" == "v2" ]]; then
        check         "ICMP echo outbound allowed"      timeout 5 ping -c 1 -W 3 9.9.9.9
    else
        check_blocked "ICMP echo outbound blocked"      timeout 5 ping -c 1 -W 3 9.9.9.9
    fi
}

case "$SECTION" in
    config)  run_config ;;
    network) run_network ;;
    all)     run_config; run_network ;;
    -h|--help) usage; exit 0 ;;
    *)       echo "ERROR: unknown section '${SECTION}'" >&2; usage; exit 2 ;;
esac

echo ""
echo "Results: $PASS passed, $FAIL failed, $SKIP skipped"
[[ $FAIL -eq 0 ]]
