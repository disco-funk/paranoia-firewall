#!/bin/bash
set -uo pipefail

# Enforces the design constraints from CLAUDE.md that would otherwise rely on a
# human remembering them. Runs without root and without loading any ruleset.

V1="firewall-v1/nftables.conf"
V2="firewall-v2/config/nftables.conf"
RULESETS=("$V1" "$V2")

QUAD9_A="9.9.9.9"
QUAD9_B="149.112.112.112"
CF_A="162.159.200.123"
CF_B="162.159.200.1"

PASS=0
FAIL=0

ok()   { echo "PASS  $1"; PASS=$(( PASS + 1 )); }
bad()  { echo "FAIL  $1"; FAIL=$(( FAIL + 1 )); }

for f in "${RULESETS[@]}"; do
    [[ -f "$f" ]] || { bad "$f exists"; continue; }
    ok "$f exists"
done

echo ""
echo "=== constraint 1: default-drop on every chain ==="
for f in "${RULESETS[@]}"; do
    for hook in input forward output; do
        if grep -qE "hook ${hook} priority [a-z0-9]+; policy drop;" "$f"; then
            ok "$f: ${hook} chain is policy drop"
        else
            bad "$f: ${hook} chain is NOT policy drop"
        fi
    done
done

# Match a port as a standalone token on a dport/sport line, so that set syntax
# like `dport { 53, 80 }` is caught, while `dport 853` never matches port 53
# (the 5 is preceded by an 8, so there is no token boundary).
port_rules() {
    local file="$1" port="$2"
    awk -v p="$port" '
        /dport|sport/ && $0 ~ "(^|[^0-9])" p "([^0-9]|$)" { print FILENAME ":" FNR ": " $0 }
    ' "$file"
}

echo ""
echo "=== constraint 2: no plain DNS (port 53) anywhere ==="
for f in "${RULESETS[@]}"; do
    hits=$(port_rules "$f" 53)
    hits+=$(awk '/dport|sport/ && /domain/ { print FILENAME ":" FNR ": " $0 }' "$f")
    if [[ -n "$hits" ]]; then
        bad "$f: references port 53"
        echo "$hits"
    else
        ok "$f: no port 53 reference"
    fi
done

echo ""
echo "=== constraint 3: DoT (853) pinned to Quad9 IPv4 only ==="
for f in "${RULESETS[@]}"; do
    seen=0
    while IFS= read -r line; do
        seen=$(( seen + 1 ))

        if [[ "$line" == *"$QUAD9_A"* && "$line" == *"$QUAD9_B"* ]]; then
            ok "$f: DoT rule pins both Quad9 IPs"
        else
            bad "$f: DoT rule does not pin both Quad9 IPs -> ${line}"
        fi

        if [[ "$line" == *"ip6 daddr"* || "$line" == *"2620:fe"* ]]; then
            bad "$f: DoT rule permits IPv6 -> ${line}"
        else
            ok "$f: DoT rule is IPv4-only"
        fi
    done < <(port_rules "$f" 853)

    [[ $seen -eq 0 ]] && bad "$f: no DoT rule found at all"
done

echo ""
echo "=== constraint 7: NTP (123) pinned to Cloudflare ==="
for f in "${RULESETS[@]}"; do
    seen=0
    while IFS= read -r line; do
        seen=$(( seen + 1 ))

        if [[ "$line" == *"$CF_A"* && "$line" == *"$CF_B"* ]]; then
            ok "$f: NTP rule pins both Cloudflare IPs"
        else
            bad "$f: NTP rule does not pin both Cloudflare IPs -> ${line}"
        fi
    done < <(port_rules "$f" 123)

    [[ $seen -eq 0 ]] && bad "$f: no NTP rule found"
done

echo ""
echo "=== constraint 6: no inbound service ports ==="
for f in "${RULESETS[@]}"; do
    # An inbound accept on a TCP dport would mean a listening service is exposed.
    if awk '/hook input/,/^[[:space:]]*}/' "$f" | grep -qE 'tcp[[:space:]]+dport'; then
        bad "$f: input chain accepts a TCP dport"
    else
        ok "$f: input chain opens no TCP ports"
    fi
done

echo ""
echo "=== constraint 8: firewall-v1 carries no comments (it is retyped by hand) ==="
for f in "$V1" "firewall-v1/hardening.sh"; do
    # Line 1 is a shebang, not a comment. Any other '#' line is transcription cost.
    if [[ -n "$(tail -n +2 "$f" | grep -E '^[[:space:]]*#' || true)" ]]; then
        bad "$f: contains comment lines"
        tail -n +2 "$f" | grep -nE '^[[:space:]]*#'
    else
        ok "$f: no comment lines"
    fi
done

echo ""
echo "=== constraint 10: no sudo inside either script ==="
for f in firewall-v1/hardening.sh firewall-v2/setup.sh; do
    if grep -qE '^[[:space:]]*sudo[[:space:]]' "$f"; then
        bad "$f: calls sudo internally"
    else
        ok "$f: no internal sudo calls"
    fi
done

echo ""
echo "=== firewall-v2 layout: only setup.sh, the docs, and config/ ==="
unexpected=$(find firewall-v2 -maxdepth 1 -mindepth 1 -not -name config -not -name setup.sh -not -name 'README.md' -not -name 'CLAUDE.md')
if [[ -n "$unexpected" ]]; then
    bad "firewall-v2 has unexpected top-level entries:"
    echo "$unexpected"
else
    ok "firewall-v2 top level is clean"
fi

echo ""
echo "Invariants: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
