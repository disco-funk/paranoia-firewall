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

default_gateway() {
    ip route show default 2>/dev/null | awk 'NR==1 {print $3}'
}

# A blocked-assertion against a target nothing listens on passes whether or not
# the firewall exists. SMOKE_VACUOUS_TARGETS lets a caller that has probed the
# targets beforehand (see .github/workflows/ci.yml) mark those as unprovable, so
# they are skipped rather than counted as a meaningless pass.
is_vacuous() {
    case " ${SMOKE_VACUOUS_TARGETS:-} " in
        *" $1 "*) return 0 ;;
        *)        return 1 ;;
    esac
}

blocked_tcp() {
    local label="$1" host="$2" port="$3"
    if is_vacuous "${host}:${port}"; then
        skip "$label" "nothing listens on ${host}:${port} even without the firewall"
    else
        check_blocked "$label" timeout 5 nc -z "$host" "$port"
    fi
}

# --- DNSSEC validation ---
#
# Three cases that discriminate. A resolver that simply fails every query would
# "pass" the bogus-domain check on its own, so the good-domain control is what
# gives it meaning; and a resolver that reports every failure as a DNSSEC
# failure would hide a broken NXDOMAIN path.

# dnssec-failed.org is a deliberately bogus-signed zone. It exists -- a
# non-validating resolver returns an A record -- so a validating resolver must
# reject it, and must say DNSSEC, not merely fail.
dnssec_bogus_rejected() {
    local out
    if out=$(timeout 15 resolvectl query --cache=no dnssec-failed.org 2>&1); then
        return 1
    fi
    grep -qiE 'dnssec|bogus|invalid|revoked' <<<"$out"
}

dnssec_good_resolves() {
    timeout 15 resolvectl query --cache=no cloudflare.com >/dev/null 2>&1
}

# A nonexistent name under the signed example.com zone. This must come back as
# authenticated denial of existence (NXDOMAIN), not as a validation failure --
# otherwise the bogus check above could be passing for the wrong reason.
dnssec_nxdomain_reported() {
    local out
    if out=$(timeout 15 resolvectl query --cache=no "no-such-host-${RANDOM}${RANDOM}.example.com" 2>&1); then
        return 1
    fi
    grep -qiE "not found|nxdomain|no such" <<<"$out" \
        && ! grep -qiE 'dnssec|bogus|invalid' <<<"$out"
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

    echo "=== DNSSEC validation ==="
    resolvectl flush-caches >/dev/null 2>&1 || true
    check "DNSSEC: signed domain resolves (cloudflare.com)"        dnssec_good_resolves
    check "DNSSEC: bogus zone rejected (dnssec-failed.org)"        dnssec_bogus_rejected
    check "DNSSEC: nonexistent name returns NXDOMAIN, not bogus"   dnssec_nxdomain_reported
}

run_network() {
    echo "=== green: must reach (${FIREWALL_VERSION}) ==="
    # example.com serves both 80 and 443, so one host covers both checks. It was
    # neverssl.com for port 80, which turned out to go down often enough to make
    # CI red for reasons unrelated to the firewall.
    check "http outbound port 80"             wget -q -O /dev/null --timeout=10 --tries=1 http://example.com/
    check "https outbound port 443"           wget -q -O /dev/null --timeout=10 --tries=1 https://example.com/
    check "DoT 9.9.9.9:853"                  nc -z -w 5 9.9.9.9 853
    check "DoT 149.112.112.112:853"          nc -z -w 5 149.112.112.112 853

    echo "=== red: must be blocked (${FIREWALL_VERSION}) ==="
    blocked_tcp   "port 53 TCP to 9.9.9.9"             9.9.9.9  53
    check_blocked "port 53 UDP to 9.9.9.9"             timeout 5 dig @9.9.9.9      example.com +time=3 +tries=1 +notcp
    blocked_tcp   "port 53 TCP to 8.8.8.8"             8.8.8.8  53
    check_blocked "port 53 UDP to 8.8.8.8"             timeout 5 dig @8.8.8.8      example.com +time=3 +tries=1 +notcp
    blocked_tcp   "DoT to 1.1.1.1:853"                 1.1.1.1  853
    blocked_tcp   "DoT to 8.8.8.8:853"                 8.8.8.8  853

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

    # gitlab.com actually runs sshd, so this measures the firewall rather than a
    # closed port. It is deliberately not GitHub: v2 permits 22 to the pinned
    # @github_ips set, so GitHub would be allowed there and prove nothing here.
    blocked_tcp   "port 22 outbound (gitlab.com)"      gitlab.com 22
    blocked_tcp   "port 25 outbound"                   9.9.9.9    25
    blocked_tcp   "port 8080 outbound"                 9.9.9.9    8080

    # v1 drops outbound echo-request; v2 accepts it.
    #
    # Ping the default gateway, not a public address. Many networks -- including
    # the Azure-hosted GitHub Actions runners -- drop ICMP to the internet
    # regardless of any local firewall, which would make the v1 "blocked"
    # assertion pass for the wrong reason and the v2 "allowed" one fail for the
    # wrong reason. The gateway is inside our own segment, so what is measured
    # here is the output chain and nothing else.
    local gw
    gw=$(default_gateway)
    if [[ -z "$gw" ]]; then
        skip "ICMP echo outbound" "no default gateway"
    elif [[ "$FIREWALL_VERSION" == "v2" ]]; then
        check         "ICMP echo outbound allowed (gw ${gw})"  timeout 5 ping -c 1 -W 3 "$gw"
    else
        check_blocked "ICMP echo outbound blocked (gw ${gw})"  timeout 5 ping -c 1 -W 3 "$gw"
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
