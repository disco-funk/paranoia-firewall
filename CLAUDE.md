# CLAUDE.md — Context for AI assistants

This file gives an AI assistant working on this repo the context needed to make good decisions without repeated explanation.

## What this project is

A minimal nftables firewall + sysctl hardening script for Debian/Ubuntu hosts that will be attached to an untrusted (potentially CGNAT) network *after* the firewall is deployed. Informally called the "paranoia firewall."

## Core design constraints — do not violate these

1. **Default-drop output.** The output chain has `policy drop`. Every outbound protocol must be explicitly whitelisted. Never add a broad "allow all established outbound" rule that would undermine this.
2. **No plain DNS.** Port 53 (UDP or TCP) must never be added to the output allowlist. The intent is that only DNS-over-TLS reaches the network, so a rogue DNS server on the LAN has no way to intercept queries.
3. **DoT pinned to Quad9 IPv4 only.** The nftables output rule for TCP 853 is restricted to `9.9.9.9` and `149.112.112.112`. IPv6 Quad9 addresses are intentionally excluded — the design assumes DNS is always reachable over IPv4. Do not broaden this to "any destination on port 853" — that would allow DoT to an attacker-controlled resolver.
4. **DNSSEC required.** `DNSSEC=yes` in systemd-resolved must not be weakened to `allow-downgrade` or removed.
5. **No FallbackDNS.** The drop-in config sets `FallbackDNS=` (empty) deliberately. A fallback would allow plain DNS if DoT fails, defeating the DNS hardening.
6. **No inbound services.** The input chain has no rules opening ports for SSH, web servers, or anything else. This is a client-only host. If the user asks to add inbound rules, ask whether this is intentional and what the threat model change is.
7. **No comments.** Both files are typed by hand on the target machine. Every comment line is extra transcription with no runtime value. Do not add any comment lines to `nftables.conf` or `hardening.sh`, including inside heredocs.

## Files

| File | Purpose |
| --- | --- |
| `nftables.conf` | nftables ruleset — loaded directly by `/sbin/nft -f` |
| `hardening.sh` | One-shot setup script: writes systemd-resolved drop-in, applies sysctl, deploys nftables |

## Deployment context

- Fresh Debian/Ubuntu install, airgapped at time of script execution
- Network connected *after* the script completes
- CGNAT upstream — host has no routable public IP
- systemd is the init system; `systemd-resolved` handles DNS stub

## What "minimal" means here

- No logging to a file (counters only — use `nft list ruleset` to inspect)
- No IDS/IPS integration
- No application-layer inspection
- No rate limiting beyond ICMP error types
- No IP allowlists (outbound HTTP/HTTPS is unrestricted by destination)

If the user asks to add any of these, they are in scope but are deliberate additions, not corrections.

## Tone / style

- Shell scripts: `set -euo pipefail`, no `sudo` inside root-required scripts (caller must be root)
- nftables: prefer `inet` tables for dual-stack; use `counter` on every terminal rule for observability
- No comments anywhere — see constraint 7 above
- No feature flags, no backwards-compat shims — this is a security config, not a library
