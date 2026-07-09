# CLAUDE.md

## Project overview

Shell-based firewall hardening project for Ubuntu and Raspberry Pi. No build system, no dependencies, no tests. One setup script and a set of config files deployed to system paths.

**Intended workflow:** `setup.sh` is run on a fresh install while the machine is still air-gapped (no network cable connected). The firewall is fully in place before the ethernet cable is ever plugged in, so the machine is never exposed to the internet without protection.

## File map

Everything `setup.sh` installs lives in `config/`. The directory holds exactly three things plus that folder: `setup.sh`, `README.md`, `CLAUDE.md`. Keep it that way — new config files go in `config/`, not beside the runner.

`setup.sh` resolves `config/` from its own path via `BASH_SOURCE`, never from the working directory, and aborts if it is missing. Do not reintroduce `./`-relative reads.

| File | Platform | Purpose |
| ---- | -------- | ------- |
| `setup.sh` | both | Orchestration script; run as root. The only executable entry point. |
| `config/nftables.conf` | both | Firewall ruleset |
| `config/90-custom-sysctl.conf` | both | Kernel hardening (→ `/etc/sysctl.d/90-custom.conf`) |
| `config/timesyncd-cloudflare.conf` | both | NTP pinned to Cloudflare via systemd-timesyncd (→ `/etc/systemd/timesyncd.conf.d/cloudflare.conf`) |
| `config/chrony.conf` | Ubuntu live boot | Full chrony config, NTP pinned to Cloudflare, DHCP/pool sources removed (→ `/etc/chrony/chrony.conf`) |
| `config/no-connectivity-check.conf` | both | Disables the NM connectivity probe (→ `/etc/NetworkManager/conf.d/99-no-connectivity-check.conf`) |
| `config/dns-over-tls-resolved.conf` | Ubuntu | systemd-resolved DoT + DNSSEC config |
| `config/dnsmasq-pi.conf` | Pi | dnsmasq DNSSEC + forward to 127.0.0.1:5300 |
| `config/dnsmasq-pi.service` | Pi | dnsmasq unit pinned to the config above (→ `/etc/systemd/system/dnsmasq.service`) |
| `config/stubby-pi.yml` | Pi | stubby DoT config (listens on 127.0.0.1:5300) |
| `config/dot-proxy.py` | Pi bootstrap | Temporary Python DoT proxy, same port as stubby. A script, but kept in `config/` so `setup.sh` stays the sole entry point. |

## Platform detection

`setup.sh` sources `/etc/os-release` and reads `$ID`:

- `ubuntu` → Ubuntu path
- `raspbian` → Pi path
- `debian` + `/proc/device-tree/model` contains "raspberry pi" → Pi path

## Key design decisions

- **Air-gapped first:** Run `setup.sh` before any network connection. Don't change this.
- **Root once, never inline `sudo`:** `setup.sh` asserts `EUID -eq 0` and exits otherwise. It contains no `sudo` calls. Do not add any back — the script blocks on a clock prompt and on waiting for the cable, and sudo's 15-minute credential timestamp would expire mid-run, prompting for a password after the network is up and the connectivity check is disabled. Invoke as `sudo bash setup.sh` (not `./setup.sh`: the media is FAT12 and should be mounted `ro,noexec`).
- **Runs from write-protected media:** This directory is intended to live on a physically write-protected disk (a 3.5" HD floppy with the tab open) and be executed from a read-only mount. `setup.sh` reads only from its own directory and writes solely under `/etc`. Never make it write into its source tree, drop state files beside itself, or assume its directory is writable. Scratch state belongs in `/run` or `/tmp`.
- **Length is free here, unlike v1:** `../firewall-v1/` is retyped by hand and therefore forbids comments. v2 is copied from media, so comments and extra config files cost nothing. Keep `setup.sh` legible and commented.
- **Default-deny everywhere:** INPUT, FORWARD, and OUTPUT chains all drop by default. Any new allowed traffic requires an explicit rule in `nftables.conf`.
- **Quad9 only:** DNS locked to 9.9.9.9 and 149.112.112.112. No fallback — intentional to prevent leaks.
- **No forwarding:** FORWARD chain drops everything. This machine is not a router.
- **NTP pinned to Cloudflare:** UDP 123 allowed only to 162.159.200.123 and 162.159.200.1. `setup.sh` configures whichever NTP daemon is present — chrony (Ubuntu 26.04 live boot) or systemd-timesyncd (Pi, most Ubuntu installs). The chrony path overwrites `/etc/chrony/chrony.conf` entirely, dropping the DHCP (`/run/chrony-dhcp`) and Ubuntu pool (`/etc/chrony/sources.d`) source directories so an untrusted LAN cannot steer the clock; only the two Cloudflare servers remain.
- **Port 853 allowlisted:** Both Ubuntu (systemd-resolved) and Pi (stubby/proxy) need TCP 853 outbound to Quad9. If DNS servers change, update both the DNS config and `nftables.conf`.
- **dnsmasq always forwards to :5300:** The Pi dnsmasq config points to `127.0.0.1#5300` regardless of whether the Python proxy or stubby is listening there. No config change needed when the proxy is replaced by stubby.

## Pi bootstrap sequence

When stubby is not pre-installed:

1. dnsmasq starts, forwarding to `127.0.0.1:5300` (nothing listening yet — intentional, no network yet)
2. apt timers and NM connectivity check are stopped before cable plug-in
3. Ethernet cable is plugged in; connection is cycled
4. `dot-proxy.py` starts on `127.0.0.1:5300`
5. `apt-get install stubby` runs — dnsmasq → proxy → Quad9 DoT
6. Proxy is killed; stubby takes over on the same port
7. apt timers and connectivity check are re-enabled

If stubby is pre-installed (recommended: `apt install stubby` on a trusted network before air-gapping), steps 4–6 are skipped.

## When editing firewall rules

The `nftables.conf` structure has three chains in one `inet filter` table:

1. `ct_base` — shared stateful logic (drop invalid, accept established/related)
2. `input` — inbound traffic policy
3. `output` — outbound traffic policy
4. `forward` — all-drop, no rules needed

ICMP is rate-limited to 10/second. IPv6 neighbour discovery and router advertisements are explicitly permitted in both input and output.

## Applying changes manually

```bash
# Firewall
sudo nft -f /etc/nftables.conf

# DNS (Ubuntu)
sudo systemctl restart systemd-resolved

# DNS (Pi)
sudo systemctl restart stubby dnsmasq

# Kernel params
sudo sysctl --system
```
