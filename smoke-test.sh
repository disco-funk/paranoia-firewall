#!/bin/bash
set -uo pipefail

usage() {
    cat >&2 <<'USAGE'
Usage: smoke-test.sh [config|network|all]

  config   Host state only: DoT/DNSSEC, resolv.conf, sysctls. Checks the DNS
           stack for the detected platform — systemd-resolved on Ubuntu,
           dnsmasq + stubby on the Pi. Requires a deployed host; no-op in a container.
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

# Platform detection mirrors firewall-v2/setup.sh: read $ID from /etc/os-release,
# treating Raspberry Pi OS (raspbian, or debian on Pi hardware) as "pi". This only
# steers the config section's DNS checks — Ubuntu resolves via systemd-resolved
# (resolvectl), the Pi via dnsmasq + stubby, which has no resolvectl at all. The
# network section is identical on both platforms and ignores this.
PLATFORM="unsupported"
if [[ -r /etc/os-release ]]; then
    # shellcheck source=/dev/null
    . /etc/os-release
fi
case "${ID:-}" in
    ubuntu)   PLATFORM="ubuntu" ;;
    raspbian) PLATFORM="pi" ;;
    debian)
        if [[ -f /proc/device-tree/model ]] && grep -qi "raspberry pi" /proc/device-tree/model 2>/dev/null; then
            PLATFORM="pi"
        fi
        ;;
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

# A nonexistent name under the signed iana.org zone. This must come back as
# authenticated denial of existence (NXDOMAIN), not as a validation failure --
# otherwise the bogus check above could be passing for the wrong reason.
#
# Not example.com: it is now hosted on Cloudflare, which does "compact denial of
# existence" (returns NOERROR/NODATA with a synthesised NSEC instead of NXDOMAIN),
# so a nonexistent name there never yields NXDOMAIN. iana.org is ICANN-operated,
# DNSSEC-signed, uses traditional NSEC, and no third party can register a name
# under it, so the answer is a stable authenticated NXDOMAIN.
dnssec_nxdomain_reported() {
    local out
    if out=$(timeout 15 resolvectl query --cache=no "no-such-host-${RANDOM}${RANDOM}.iana.org" 2>&1); then
        return 1
    fi
    grep -qiE "not found|nxdomain|no such" <<<"$out" \
        && ! grep -qiE 'dnssec|bogus|invalid' <<<"$out"
}

# --- DNSSEC validation on the Pi ---
#
# The Pi has no resolvectl. dnsmasq (127.0.0.1:53) does the DNSSEC validation and
# forwards to stubby, which carries the DoT to Quad9. dig against the local
# resolver gives the same three discriminating cases as the resolvectl path above,
# read from the response's header status rather than resolvectl's prose:
#
#   good  -> NOERROR with an address   (a resolver failing every query cannot fake this)
#   bogus -> SERVFAIL                   (dnsmasq refuses a bogus-signed zone)
#   nxdomain -> NXDOMAIN, *not* SERVFAIL (a resolver blaming DNSSEC for everything would SERVFAIL here)
#
# The NXDOMAIN-vs-SERVFAIL split is what stands in for resolvectl's explicit
# "DNSSEC" wording: it proves the SERVFAIL on the bogus zone is validation, not a
# resolver that fails or SERVFAILs indiscriminately.

# Header status (NOERROR / SERVFAIL / NXDOMAIN) for a query to the local resolver,
# or empty on transport failure/timeout — which fails the good-domain control
# rather than masquerading as a pass.
dig_status() {
    timeout 15 dig +time=3 +tries=1 "$@" @127.0.0.1 2>/dev/null \
        | awk -F'status: ' '/status:/ { split($2, s, ","); print s[1]; exit }'
}

pi_dnssec_good_resolves() {
    local out
    out=$(timeout 15 dig +time=3 +tries=1 +short A cloudflare.com @127.0.0.1 2>/dev/null)
    [[ -n "$out" ]]
}

pi_dnssec_bogus_rejected() {
    [[ "$(dig_status dnssec-failed.org)" == "SERVFAIL" ]]
}

# iana.org, not example.com: see dnssec_nxdomain_reported above — example.com is
# Cloudflare-hosted and answers nonexistent names with NOERROR/NODATA, never NXDOMAIN.
pi_dnssec_nxdomain_reported() {
    [[ "$(dig_status "no-such-host-${RANDOM}${RANDOM}.iana.org")" == "NXDOMAIN" ]]
}

# Ubuntu config DNS checks: systemd-resolved carries DoT + DNSSEC, pinned to Quad9.
config_dns_resolved() {
    local IFACE="$1"
    check "resolved live: DoT active on $IFACE"             bash -c "resolvectl status $IFACE | grep -q '+DNSOverTLS'"
    check "resolved live: DNSSEC active on $IFACE"          bash -c "resolvectl status $IFACE | grep -q 'DNSSEC=yes'"
    check "resolved live: 9.9.9.9 active on $IFACE"         bash -c "resolvectl status $IFACE | grep -q '9\.9\.9\.9'"
    check "resolved live: 149.112.112.112 active on $IFACE" bash -c "resolvectl status $IFACE | grep -q '149\.112\.112\.112'"
    check "resolv.conf symlink to stub"       bash -c  'readlink /etc/resolv.conf | grep -q stub-resolv'

    echo "=== green: stub resolver ==="
    check "stub resolves example.com"         resolvectl query example.com

    echo "=== DNSSEC validation ==="
    resolvectl flush-caches >/dev/null 2>&1 || true
    check "DNSSEC: signed domain resolves (cloudflare.com)"        dnssec_good_resolves
    check "DNSSEC: bogus zone rejected (dnssec-failed.org)"        dnssec_bogus_rejected
    check "DNSSEC: nonexistent name returns NXDOMAIN, not bogus"   dnssec_nxdomain_reported
}

# Pi config DNS checks: stubby carries DoT (127.0.0.1:5300), dnsmasq does DNSSEC
# and is the local resolver (127.0.0.1:53). No resolvectl here — assert the two
# services are up and pinned to Quad9, resolv.conf points at the local stack, and
# exercise DNSSEC through dnsmasq with dig. dig (dnsutils) may not be installed on a
# minimal Pi image, so those functional checks skip cleanly when it is absent.
config_dns_pi() {
    check "stubby active (DoT layer)"           systemctl is-active --quiet stubby
    check "dnsmasq active (DNSSEC + resolver)"  systemctl is-active --quiet dnsmasq
    check "stubby pinned to 9.9.9.9"            grep -q '9\.9\.9\.9'         /etc/stubby/stubby.yml
    check "stubby pinned to 149.112.112.112"    grep -q '149\.112\.112\.112' /etc/stubby/stubby.yml
    check "resolv.conf points to 127.0.0.1"     grep -qE '^[[:space:]]*nameserver[[:space:]]+127\.0\.0\.1' /etc/resolv.conf

    echo "=== green: local resolver (dnsmasq → stubby) ==="
    if ! command -v dig >/dev/null 2>&1; then
        skip "stub resolves example.com"                             "dig not installed (apt install dnsutils)"
        skip "DNSSEC: signed domain resolves (cloudflare.com)"       "dig not installed (apt install dnsutils)"
        skip "DNSSEC: bogus zone rejected (dnssec-failed.org)"       "dig not installed (apt install dnsutils)"
        skip "DNSSEC: nonexistent name returns NXDOMAIN, not bogus"  "dig not installed (apt install dnsutils)"
        return
    fi

    check "stub resolves example.com"  bash -c 'timeout 10 dig +time=3 +tries=1 +short example.com @127.0.0.1 | grep -q .'

    echo "=== DNSSEC validation ==="
    check "DNSSEC: signed domain resolves (cloudflare.com)"        pi_dnssec_good_resolves
    check "DNSSEC: bogus zone rejected (dnssec-failed.org)"        pi_dnssec_bogus_rejected
    check "DNSSEC: nonexistent name returns NXDOMAIN, not bogus"   pi_dnssec_nxdomain_reported
}

run_config() {
    local IFACE
    IFACE=$(ip route show default 2>/dev/null | awk 'NR==1 {print $5}')

    echo "=== config (${PLATFORM}) ==="
    check "active interface found"           test -n "$IFACE"
    check "sysctl tcp_timestamps=0"          test "$(sysctl -n net.ipv4.tcp_timestamps 2>/dev/null)"      = 0
    check "sysctl rp_filter=1"               test "$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null)"  = 1
    check "sysctl use_tempaddr=2"            test "$(sysctl -n net.ipv6.conf.all.use_tempaddr 2>/dev/null)" = 2
    check "sysctl log_martians=1"            test "$(sysctl -n net.ipv4.conf.all.log_martians 2>/dev/null)" = 1

    # DNS is the one part of the config that differs by platform. Everything above
    # is shared; the resolver stack is not.
    if [[ "$PLATFORM" == "pi" ]]; then
        config_dns_pi
    else
        config_dns_resolved "$IFACE"
    fi
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
