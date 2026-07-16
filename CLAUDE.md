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
9. **`firewall-v2/` must run from read-only media.** `setup.sh` reads only from `firewall-v2/config/` — resolved from its own path via `BASH_SOURCE`, never from the working directory — and writes solely to `/etc`. Never make it write into its source tree, create dotfiles or state alongside itself, or assume its directory is writable; it may be executing off a write-protected floppy. Scratch state goes in `/run` or `/tmp`. `firewall-v2/` holds only `setup.sh`, the two markdown files, and `config/`; new config files belong in `config/`.
10. **Elevate once, at the top. Never `sudo` inside a script.** Both scripts require root and assert it. Do not reintroduce per-command `sudo`, however natural it looks:
    - Both scripts block indefinitely — on a clock-confirmation prompt, and on waiting for the ethernet cable. `sudo`'s credential timestamp (`timestamp_timeout`, 15 min default) will expire across those waits, and the next `sudo` then prompts for a password *after* the cable is in, during the Pi bootstrap window with the NM connectivity check disabled. An unattended machine sits networked and half-configured.
    - A partially applied security config is the failure mode that matters most here. Elevating once removes the possibility.
    - Minimal Debian and Pi OS Lite images frequently have no `sudo` installed; inline `sudo` fails outright when you are already root.
    - Backgrounding under `sudo` captures the PID of `sudo`, not of the child. `sudo python3 dot-proxy.py & PROXY_PID=$!` is a latent bug; without `sudo` it is correct.
    - Unelevated commands (`nmcli`, `awk`, `grep`) inherit the caller's `PATH` and their output steers later privileged actions. Running the whole script under `sudo` applies `secure_path` and `env_reset` once, deterministically.

    Invoke as `sudo bash setup.sh` rather than `sudo ./setup.sh`: the intended media is FAT12 (no execute bit) and untrusted removable media should be mounted `ro,noexec`, under which `./setup.sh` fails but `bash setup.sh` works.

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

`smoke-test.sh` (repo root) runs in two independent sections:

```bash
./smoke-test.sh config    # host state: resolved DoT/DNSSEC, resolv.conf, sysctls
./smoke-test.sh network   # egress policy: what gets out, what is dropped
./smoke-test.sh           # both (default)
```

Set `FIREWALL_VERSION=v2` for a v2 host — v2 permits outbound ping, v1 drops it, and the assertion flips accordingly. The default is `v1`. The `config` section needs a real deployed host and auto-detects the platform the same way `setup.sh` does (`$ID` from `/etc/os-release`): on Ubuntu it checks systemd-resolved via `resolvectl`, on the Pi it checks the dnsmasq + stubby stack via `dig` against `127.0.0.1` (skipping the functional DNS checks if `dig`/dnsutils is absent). The `network` section runs anywhere the ruleset is loaded, including a container.

CI (`.github/workflows/ci.yml`) has two jobs:

- **`lint`** — shellcheck, `nft -c -f` on both rulesets, byte-compiles `dot-proxy.py`, and runs `.github/scripts/check-invariants.sh`.
- **`ruleset`** — loads each ruleset into a privileged container's own netns and runs `smoke-test.sh network` against the real internet, matrixed over v1 and v2.

`check-invariants.sh` mechanically enforces the constraints above: no port 53 in any form (including inside a set, and the `domain` keyword), DoT pinned to both Quad9 IPv4 addresses and no IPv6, NTP pinned to both Cloudflare addresses, default-drop on all three chains, no inbound TCP ports, no comments in `firewall-v1/`, no `sudo` inside either script, and no stray files at the `firewall-v2/` top level. **If you change a constraint, change that script too** — otherwise CI will contradict this file.

The `config` section additionally checks DNSSEC with three cases that only mean something together: a signed domain (`cloudflare.com`) must resolve, the deliberately bogus-signed `dnssec-failed.org` must be rejected *and reported as a DNSSEC failure*, and a nonexistent name under the signed `iana.org` zone must come back as NXDOMAIN rather than as a validation failure. (`iana.org`, not `example.com`: example.com is Cloudflare-hosted and uses *compact denial of existence*, answering nonexistent names with NOERROR/NODATA instead of NXDOMAIN, which would fail this case. iana.org is ICANN-operated, signed, uses traditional NSEC, and no third party can register under it.) The good-domain control is what stops a resolver that fails every query from "passing" the bogus check; the NXDOMAIN case is what stops a resolver that blames DNSSEC for everything. Do not drop any one of the three. On Ubuntu these run through `resolvectl` (which names the DNSSEC failure in its output); the Pi mirrors the same three via `dig` against dnsmasq, where the NXDOMAIN-vs-SERVFAIL split substitutes for that explicit wording. Either way they need a deployed resolver, so CI does not run them.

Several assertions are deliberately not what they look like, and should not be "simplified":

- **ICMP egress is tested against the default gateway, not a public IP.** Many networks — including the Azure-hosted GitHub runners — drop outbound ICMP to the internet regardless of local rules. Pinging `9.9.9.9` therefore makes v1's "blocked" assertion pass for the wrong reason and v2's "allowed" assertion fail for the wrong reason. The gateway is inside our own segment, so only the output chain is under test.
- **The Quad9 IPv6 DoT checks are skipped, not passed, when there is no global IPv6 address.** Without IPv6 routing those connects fail for lack of a route rather than because the firewall dropped them, which is a vacuous pass.
- **The SSH check targets `gitlab.com`, not GitHub and not `9.9.9.9`.** Nothing listens on `9.9.9.9:22`, so blocking it proves nothing; and v2 *permits* 22 to the pinned `@github_ips` set, so GitHub would be allowed. `gitlab.com` runs sshd and is outside that set, so both versions must drop it.
- **CI probes every "must be blocked" target before loading any ruleset** and exports the unreachable ones as `SMOKE_VACUOUS_TARGETS`, which the smoke test skips rather than counting as passes. It hard-fails if `9.9.9.9:53` or `8.8.8.8:853` are unreachable beforehand, since those two carry the assertions this project exists to make.

CI deliberately never runs `sysctl -p`. Three of the parameters (`kernel.kptr_restrict`, `kernel.unprivileged_bpf_disabled`, `net.core.bpf_jit_harden`) are not network-namespaced, so in a privileged container they would mutate the runner's host kernel instead of testing anything. Nor does CI run `setup.sh`: it waits for DHCP, which Docker does not provide. Those paths are only exercised on a real host.

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
- No `sudo` inside either script. Both require root and must be invoked as `sudo bash <script>`; `setup.sh` asserts `EUID -eq 0` and refuses otherwise. Elevating once is deliberate — see constraint 10.
- nftables: prefer `inet` tables for dual-stack; use `counter` on every terminal rule for observability
- v1: terse, no comments, no niceties — it is retyped by hand. v2: legible and commented — it is copied from media.
- No feature flags, no backwards-compat shims — this is a security config, not a library
