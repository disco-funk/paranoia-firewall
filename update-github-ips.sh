#!/bin/bash
set -euo pipefail

# Refreshes the `github_ips` set in firewall-v2/config/nftables.conf from
# GitHub's published meta API (the "git" key: the addresses that serve git over
# SSH). Run by hand on a networked dev machine, never on the target host, and
# review the diff before committing:
#
#   bash update-github-ips.sh
#
# Lives at the repo root, not in firewall-v2/, because everything in firewall-v2/
# is copied to the write-protected deployment media and this is a dev-side tool.
#
# Only IPv4 entries are kept. The set is `type ipv4_addr` and the ruleset has no
# IPv6 SSH rule, so GitHub's IPv6 ranges are dropped deliberately.
#
# Needs: curl, jq, nft. No root needed: the result is syntax-checked with
# `nft -c` inside an unprivileged user + network namespace where available.

META_URL="https://api.github.com/meta"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULESET="${REPO_DIR}/firewall-v2/config/nftables.conf"

die() { echo "ERROR: $*" >&2; exit 1; }

for cmd in curl jq nft awk; do
    command -v "$cmd" >/dev/null || die "'$cmd' is required but not installed"
done
[[ -f "$RULESET" ]] || die "ruleset not found: $RULESET"
grep -q '^[[:space:]]*set github_ips {' "$RULESET" || die "no 'set github_ips' in $RULESET"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- fetch -------------------------------------------------------------------
# HTTPS only (including on redirects), modern TLS, fail on HTTP errors.
echo "Fetching ${META_URL} ..."
curl --fail --silent --show-error --location \
     --proto '=https' --proto-redir '=https' --tlsv1.2 \
     --max-time 30 \
     -H 'Accept: application/vnd.github+json' \
     -o "${WORK}/meta.json" \
     "$META_URL"

# --- extract & validate ------------------------------------------------------
jq -e '.git | type == "array" and length > 0' "${WORK}/meta.json" >/dev/null \
    || die "response has no non-empty .git array (rate-limited or API changed?)"

# IPv4 only; strip /32 so single hosts match the existing file's style.
jq -r '.git[] | select(test(":") | not)' "${WORK}/meta.json" \
    | sed 's|/32$||' \
    | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n -u \
    > "${WORK}/new.txt"

# Every entry must be a dotted quad, optionally with a /0-32 prefix. Anything
# else means the response is not what we think it is: refuse to write it into
# a firewall config.
octet='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
cidr_re="^${octet}\.${octet}\.${octet}\.${octet}(/(3[0-2]|[12]?[0-9]))?$"
if bad=$(grep -Ev "$cidr_re" "${WORK}/new.txt"); then
    die "unexpected entries in .git:"$'\n'"$bad"
fi

count=$(wc -l < "${WORK}/new.txt")
[[ "$count" -gt 0 ]] || die "no IPv4 entries in .git"

# --- build the new elements block -------------------------------------------
# Same layout as the hand-written file: two entries per line, continuation
# lines aligned under the first entry.
awk -v n="$count" '
    {
        sep = (NR == n) ? " }" : ","
        if (NR == 1)          printf "\t\telements = { %s%s", $0, sep
        else if (NR % 2 == 1) printf "\n\t\t\t     %s%s", $0, sep
        else                  printf " %s%s", $0, sep
    }
    END { printf "\n" }
' "${WORK}/new.txt" > "${WORK}/elements.txt"

# --- splice it into the ruleset ---------------------------------------------
# Inside `set github_ips { ... }`, replace everything from the `elements = {`
# line through the line that closes it. Nothing else in the file is touched.
awk -v block="${WORK}/elements.txt" '
    /^[[:space:]]*set github_ips \{/ { in_set = 1 }
    in_set && !done && /^[[:space:]]*elements = \{/ { skipping = 1 }
    skipping {
        if (/\}/) {
            while ((getline line < block) > 0) print line
            skipping = 0; done = 1
        }
        next
    }
    in_set && /^[[:space:]]*\}/ { in_set = 0 }
    { print }
    END { if (!done) exit 1 }
' "$RULESET" > "${WORK}/nftables.conf" \
    || die "could not locate the elements block of github_ips"

# --- report ------------------------------------------------------------------
# Current entries, extracted from the old file the same way, for a readable
# added/removed summary rather than a reflowed-lines diff.
awk '
    /^[[:space:]]*set github_ips \{/ { in_set = 1 }
    in_set && /elements = \{/ { grab = 1 }
    grab { print; if (/\}/) exit }
' "$RULESET" \
    | sed 's/.*elements = {//; s/}.*//' | tr ',' '\n' | tr -d ' \t' | sed '/^$/d' \
    | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n -u > "${WORK}/old.txt"

if cmp -s "$RULESET" "${WORK}/nftables.conf"; then
    echo "github_ips is already current (${count} IPv4 entries). Nothing to do."
    exit 0
fi

echo ""
# grep -Fxv rather than comm: comm needs lexical order, these are sorted numerically.
echo "Removed:"
{ grep -Fxv -f "${WORK}/new.txt" "${WORK}/old.txt" || true; } | sed 's/^/  - /'
echo "Added:"
{ grep -Fxv -f "${WORK}/old.txt" "${WORK}/new.txt" || true; } | sed 's/^/  + /'
echo ""

# --- syntax-check before overwriting -----------------------------------------
# `nft -c` needs CAP_NET_ADMIN. An unprivileged user + net namespace provides
# that without root and without touching the host's live ruleset. This also
# catches overlapping intervals, which nft rejects in an interval set.
if unshare --user --map-root-user --net true 2>/dev/null; then
    unshare --user --map-root-user --net nft -c -f "${WORK}/nftables.conf" \
        || die "new ruleset failed 'nft -c'; $RULESET left unchanged"
    echo "nft -c: new ruleset parses."
else
    echo "WARNING: cannot create a user namespace here, so the new ruleset was" >&2
    echo "         NOT syntax-checked. Run: sudo nft -c -f $RULESET" >&2
fi

# Write in place with `cat >` so the file keeps its mode and ownership.
cat "${WORK}/nftables.conf" > "$RULESET"
echo "Updated $RULESET (${count} IPv4 entries)."
echo "Review with: git diff -- firewall-v2/config/nftables.conf"
