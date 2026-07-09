# CLAUDE.md — Context for AI assistants

This file gives an AI assistant working on this repo the context needed to make good decisions without repeated explanation.

## What this project is

nftables firewall + kernel hardening for Debian/Ubuntu (and Raspberry Pi) hosts that will be attached to an untrusted (potentially CGNAT) network *after* the firewall is deployed. Informally called the "paranoia firewall."

The repo holds **two generations** of the firewall. They are independent — neither imports from the other, and there is no migration path between them.

The split exists because of **how each one gets onto the air-gapped machine**. That delivery mechanism drives almost every design difference between them, so understand it before proposing changes.

| Directory | What it is | Delivery | Platforms |
| --- | --- | --- | --- |
| `firewall-v1/` | Minimal ruleset, deliberately short. | **Typed in by hand** at the console. | Ubuntu / Debian |
| `firewall-v2/` | Enhanced. Raspberry Pi support, encrypted-DNS bootstrap, chrony/NTP pinning, orchestrated setup. | **Carried on physically write-protected media** (e.g. a 3.5" HD floppy with the tab open). | Ubuntu + Raspberry Pi OS |

The target machine is air-gapped from first boot until the firewall is live, so the config cannot be downloaded — it has to arrive out-of-band. v1 solves this by being small enough that a human can retype it. v2 solves it by riding on read-only media, where the write-protect tab provides the integrity guarantee that a network download could not.

**Consequences that follow directly from this, and that you must respect:**

- **v1 must stay short enough to type.** Every line is transcription cost paid by a human at a console. Terseness is the feature. Do not add convenience, defensive checks, or explanatory prose to v1.
- **v1 carries no comments.** See constraint 8.
- **v2 is under no length pressure at all.** It is copied, never retyped. Clarity, comments, and multiple config files are *free*. Prefer legibility over brevity in v2.
- **v2 must run from a read-only mount.** `setup.sh` may not write into its own directory or expect its source tree to be mutable. Anything it needs to modify must be written to `/etc`, `/run`, or `/tmp`.

`firewall-v2/` has its own `CLAUDE.md` with implementation detail specific to that generation. Read it before editing anything under `firewall-v2/`.

## Which version is a change for?

Ask this before editing. It is the first question, and the answer is rarely "both."

- Fixes to the minimal hand-typed design → `firewall-v1/`
- Anything involving Raspberry Pi, stubby, dnsmasq, chrony, or `setup.sh` → `firewall-v2/`
- A change that genuinely applies to both must be made twice, deliberately. The files are not shared.

If a proposed addition to v1 makes it meaningfully longer, that is a strong signal it belongs in v2 instead — length is the whole reason the two exist.

## Core design constraints — do not violate these

These hold across **both** generations unless noted.

1. **Default-drop output.** The output chain has `policy drop`. Every outbound protocol must be explicitly whitelisted. Never add a broad "allow all established outbound" rule that would undermine this.
2. **No plain DNS.** Port 53 (UDP or TCP) must never be added to the output allowlist. The intent is that only DNS-over-TLS reaches the network, so a rogue DNS server on the LAN has no way to intercept queries.
3. **DoT pinned to Quad9 IPv4 only.** The nftables output rule for TCP 853 is restricted to `9.9.9.9` and `149.112.112.112`. IPv6 Quad9 addresses are intentionally excluded — the design assumes DNS is always reachable over IPv4. Do not broaden this to "any destination on port 853" — that would allow DoT to an attacker-controlled resolver.
4. **DNSSEC required.** `DNSSEC=yes` in systemd-resolved must not be weakened to `allow-downgrade` or removed. On the Pi path, dnsmasq performs DNSSEC validation instead.
5. **No FallbackDNS.** The systemd-resolved drop-in sets `FallbackDNS=` (empty) deliberately. A fallback would allow plain DNS if DoT fails, defeating the DNS hardening.
6. **No inbound services.** The input chain opens no ports for SSH, web servers, or anything else. This is a client-only host. If the user asks to add inbound rules, ask whether this is intentional and what the threat model change is.
7. **NTP pinned by IP.** Outbound UDP 123 is restricted to the Cloudflare time servers `162.159.200.123` and `162.159.200.1`. An untrusted LAN must not be able to steer the clock — a wrong clock breaks TLS certificate validation and DNSSEC signature checks.
8. **No comments — `firewall-v1/` only.** Both v1 files are typed by hand on the target machine, so every comment line is extra transcription with no runtime value. Do not add comment lines to `firewall-v1/nftables.conf` or `firewall-v1/hardening.sh`, including inside heredocs. **This rule does not apply to `firewall-v2/`**, which is copied from media rather than retyped; its `setup.sh` is deliberately commented and those comments should be preserved and maintained.
9. **`firewall-v2/` must run from read-only media.** `setup.sh` reads only from its own directory and writes solely to `/etc`. Never make it write into its source tree, create dotfiles or state alongside itself, or assume its directory is writable — it may be executing off a write-protected floppy. Scratch state goes in `/run` or `/tmp`.

## Where the two generations differ

Do not assume a rule present in one is present in the other.

| Behaviour | `firewall-v1/` | `firewall-v2/` |
| --- | --- | --- |
| Outbound ICMP echo (ping) | Blocked | **Allowed** |
| Inbound ICMP echo | Blocked | Allowed from `192.168.0.0/24` and `fe80::/10` |
| Outbound TCP 22 (SSH) | Blocked | **Allowed to a pinned GitHub IP set** (`@github_ips`) |
| DNS resolver | systemd-resolved | systemd-resolved (Ubuntu) / dnsmasq + stubby (Pi) |
| NTP daemon | systemd-timesyncd | chrony or systemd-timesyncd, whichever is present |
| Deployment | `hardening.sh` | `setup.sh` (auto-detects distro) |

## Testing

`smoke-test.sh` (repo root) targets **`firewall-v1/`**. It asserts that outbound ICMP echo is blocked, which `firewall-v2/` deliberately permits, so it will report a failure if run against a v2 host. It also checks only the systemd-resolved DNS path. Do not treat it as a v2 test without adapting those assertions.

## Deployment context

- Fresh Debian/Ubuntu/Raspberry Pi OS install, airgapped at time of script execution
- Network connected *after* the script completes
- CGNAT upstream — host has no routable public IP
- systemd is the init system

## What "minimal" means here

- No logging to a file (counters only — use `nft list ruleset` to inspect)
- No IDS/IPS integration
- No application-layer inspection
- No rate limiting beyond ICMP error types
- No IP allowlists on outbound HTTP/HTTPS (unrestricted by destination)

If the user asks to add any of these, they are in scope but are deliberate additions, not corrections.

## Tone / style

- Shell scripts: `set -euo pipefail`
- `firewall-v1/hardening.sh` takes no `sudo` internally — the caller must already be root. `firewall-v2/setup.sh` calls `sudo` per command by design; do not strip it.
- nftables: prefer `inet` tables for dual-stack; use `counter` on every terminal rule for observability
- v1: terse, no comments, no niceties — it is retyped by hand. v2: legible and commented — it is copied from media.
- No feature flags, no backwards-compat shims — this is a security config, not a library
