# Paranoia Firewall — v2

The current generation of the [paranoia firewall](../README.md). A hardened firewall with encrypted DNS for Ubuntu and Raspberry Pi, designed to be applied to a **fresh install before the machine is ever connected to the internet**. Run `setup.sh` while the machine is still air-gapped, then plug in the ethernet cable. The firewall is in place before the first packet is sent or received.

Implements a default-deny stateful packet filter via nftables, kernel parameter hardening via sysctl, and DNSSEC + DNS-over-TLS via Quad9 (9.9.9.9 / 149.112.112.112).

## How to get this onto an air-gapped machine

Carry it in on **physically write-protected media** — a 3.5" HD floppy with the write-protect tab flipped open is the intended vehicle, and is sufficient. Mount it read-only and run `setup.sh` directly from the mount.

The tab is doing real work. A machine you have not yet hardened cannot alter the config you are about to harden it with, and neither can anything already resident on it. That guarantee is mechanical rather than cryptographic, which is precisely why it holds on a host you do not yet trust.

`setup.sh` reads only from its own directory and writes solely under `/etc`, so it runs correctly from a read-only mount. **Keep it that way** — nothing here may write to its own source tree.

If you have no such media, use [`../firewall-v1/`](../firewall-v1/) instead: it is two short files with no comments, sized to be retyped by hand at the console.

## What it does

- **Firewall (nftables):** Default-drop on INPUT, FORWARD, and OUTPUT. Allows only loopback, DHCP, NTP (Cloudflare), DNS-over-TLS (Quad9), HTTP/HTTPS, ping, and SSH to a pinned set of GitHub IPs. Blocks all packet forwarding.
- **Kernel hardening (sysctl):** Disables source routing and redirects, enables reverse-path filtering, SYN cookies, BPF restrictions, and kernel pointer hiding.
- **Encrypted DNS:** DoT + DNSSEC via systemd-resolved on Ubuntu; dnsmasq + stubby on Raspberry Pi.
- **Pinned time:** NTP locked to Cloudflare via chrony or systemd-timesyncd, whichever the host runs.

## Requirements

- Ubuntu or Raspberry Pi OS (Debian-based)
- NetworkManager (`nmcli`) managing the active connection
- Root access. `setup.sh` must run as root and refuses to start otherwise; it contains no internal `sudo` calls, so it works on minimal images where `sudo` is not installed.

## Usage

From a read-only mount of the media:

```bash
sudo mount -o ro,noexec /dev/sdb /mnt/firewall
sudo bash /mnt/firewall/setup.sh
```

Or from a checkout:

```bash
sudo bash firewall-v2/setup.sh
```

`setup.sh` locates `config/` relative to itself, so the working directory does not matter and no `cd` is needed. It exits immediately if `config/` is missing beside it.

Invoke it as `sudo bash setup.sh`, not `sudo ./setup.sh`. A floppy is FAT12 and carries no execute bit, and untrusted removable media is best mounted `noexec` — under either condition `./setup.sh` fails with "permission denied" while `bash setup.sh` reads the script as data and runs it.

The script elevates once rather than calling `sudo` per command. It waits on a clock confirmation and on you plugging the cable in, and a per-command `sudo` would let its credential timestamp lapse across those waits — prompting for a password after the network is live and the connectivity check is disabled.

The script auto-detects the distro and active ethernet connection, deploys configs, and waits for the ethernet cable to be plugged in. It prints a status summary when done.

## Platform behaviour

### Ubuntu

Uses `systemd-resolved` for DNS-over-TLS and DNSSEC. No extra packages needed.

On an Ubuntu live boot, `chrony` is typically present; `setup.sh` overwrites `/etc/chrony/chrony.conf` entirely so that the DHCP-supplied (`/run/chrony-dhcp`) and Ubuntu pool (`/etc/chrony/sources.d`) source directories are dropped. Only the two Cloudflare servers remain, so an untrusted LAN cannot steer the clock. Hosts without chrony get the `systemd-timesyncd` drop-in instead.

### Raspberry Pi OS (Debian Trixie / Bookworm)

Uses `dnsmasq` (must be pre-installed) for DNSSEC + local resolution, and `stubby` for DNS-over-TLS.

**If stubby is already installed** (`apt install stubby` on a trusted network before air-gapping), it is used directly.

**If stubby is not installed**, the script bootstraps using a minimal Python DoT proxy (`dot-proxy.py`) — enough to run `apt-get install stubby` in a controlled window. Background apt services and the NM connectivity check are paused for the duration to prevent apt lock conflicts and uncontrolled network activity. Once stubby is installed, the proxy is replaced.

## Files

```text
firewall-v2/
├── README.md
├── CLAUDE.md
├── setup.sh          <- the only thing you run
└── config/           <- everything setup.sh installs
```

`setup.sh` resolves `config/` relative to its own location, not to your working directory, so it can be invoked by absolute path from anywhere.

| File | Platform | Installed to | Purpose |
| ---- | -------- | ------------ | ------- |
| `setup.sh` | both | run in place | Orchestration script; run as root |
| `config/nftables.conf` | both | `/etc/nftables.conf` | Firewall ruleset |
| `config/90-custom-sysctl.conf` | both | `/etc/sysctl.d/90-custom.conf` | Kernel hardening |
| `config/timesyncd-cloudflare.conf` | both | `/etc/systemd/timesyncd.conf.d/cloudflare.conf` | NTP pinned to Cloudflare |
| `config/chrony.conf` | Ubuntu (live boot) | `/etc/chrony/chrony.conf` | Full chrony config; NTP pinned to Cloudflare, DHCP/pool sources removed |
| `config/no-connectivity-check.conf` | both | `/etc/NetworkManager/conf.d/99-no-connectivity-check.conf` | Disables the NM connectivity probe |
| `config/dns-over-tls-resolved.conf` | Ubuntu | `/etc/systemd/resolved.conf.d/dns-over-tls.conf` | systemd-resolved DoT + DNSSEC |
| `config/dnsmasq-pi.conf` | Pi | `/etc/dnsmasq.d/dns-privacy.conf` | dnsmasq DNSSEC + forward to :5300 |
| `config/dnsmasq-pi.service` | Pi | `/etc/systemd/system/dnsmasq.service` | dnsmasq unit pinned to the config above |
| `config/stubby-pi.yml` | Pi | `/etc/stubby/stubby.yml` | stubby DoT config |
| `config/dot-proxy.py` | Pi (bootstrap) | run in place | Temporary Python DoT proxy |

`dot-proxy.py` is a script rather than a config file, but it lives in `config/` so that `setup.sh` is the single executable entry point in this directory.

## Outbound traffic allowed

| Protocol | Destination | Purpose |
| -------- | ----------- | ------- |
| TCP 853 | 9.9.9.9, 149.112.112.112 | DNS-over-TLS (Quad9) |
| UDP 67/68 | any | DHCP |
| UDP 123 | 162.159.200.123, 162.159.200.1 | NTP (Cloudflare) |
| TCP 80/443 | any | HTTP/HTTPS |
| TCP 22 | pinned `@github_ips` set | git over SSH |
| ICMP echo-request | any | Outbound ping |

All other outbound traffic is dropped.

## Inbound traffic allowed

| Protocol | Source | Purpose |
| -------- | ------ | ------- |
| UDP 68 | any (from server port 67) | DHCP replies |
| ICMP/ICMPv6 errors | any | Rate-limited to 10/s |
| ICMPv6 neighbour solicit/advert | any | IPv6 neighbour discovery |
| ICMPv6 router-advert, MLD query | `fe80::/10` | IPv6 autoconfiguration from link-local only |
| ICMP echo-request | `192.168.0.0/24` | Ping from the local LAN |
| ICMPv6 echo-request | `fe80::/10` | Ping from link-local |

No TCP or UDP service ports are open. All other inbound traffic is dropped.

## Differences from v1

| Behaviour | v1 | v2 |
| --- | --- | --- |
| Outbound ICMP echo (ping) | Blocked | Allowed |
| Inbound ICMP echo | Blocked | Allowed from `192.168.0.0/24` and `fe80::/10` |
| Outbound TCP 22 (SSH) | Blocked | Allowed to pinned `@github_ips` |
| Raspberry Pi support | No | Yes |
| NTP daemon | systemd-timesyncd | chrony or systemd-timesyncd |

The repo-root `smoke-test.sh` targets v1 and asserts outbound ping is blocked, so it will report a failure against a v2 host.
