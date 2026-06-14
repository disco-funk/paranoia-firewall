# various-firewalls

A hardened firewall with encrypted DNS for Ubuntu and Raspberry Pi, designed to be applied to a **fresh install before the machine is ever connected to the internet**. Run `setup.sh` while the machine is still air-gapped, then plug in the ethernet cable. The firewall is in place before the first packet is sent or received.

Implements a default-deny stateful packet filter via nftables, kernel parameter hardening via sysctl, and DNSSEC + DNS-over-TLS via Quad9 (9.9.9.9 / 149.112.112.112).

## What it does

- **Firewall (nftables):** Default-drop on INPUT, FORWARD, and OUTPUT. Allows only loopback, DHCP, NTP (Cloudflare), DNS-over-TLS (Quad9), and HTTP/HTTPS. Blocks all packet forwarding.
- **Kernel hardening (sysctl):** Disables source routing and redirects, enables reverse-path filtering, SYN cookies, BPF restrictions, and kernel pointer hiding.
- **Encrypted DNS:** DoT + DNSSEC via systemd-resolved on Ubuntu; dnsmasq + stubby on Raspberry Pi.

## Requirements

- Ubuntu or Raspberry Pi OS (Debian-based)
- NetworkManager (`nmcli`) managing the active connection
- `sudo` / root access

## Usage

```bash
sudo bash setup.sh
```

The script auto-detects the distro and active ethernet connection, deploys configs, and waits for the ethernet cable to be plugged in. It prints a status summary when done.

## Platform behaviour

### Ubuntu

Uses `systemd-resolved` for DNS-over-TLS and DNSSEC. No extra packages needed.

### Raspberry Pi OS (Debian Trixie / Bookworm)
Uses `dnsmasq` (must be pre-installed) for DNSSEC + local resolution, and `stubby` for DNS-over-TLS.

**If stubby is already installed** (`apt install stubby` on a trusted network before air-gapping), it is used directly.

**If stubby is not installed**, the script bootstraps using a minimal Python DoT proxy (`dot-proxy.py`) — enough to run `apt-get install stubby` in a controlled window. Background apt services and the NM connectivity check are paused for the duration to prevent apt lock conflicts and uncontrolled network activity. Once stubby is installed, the proxy is replaced.

## Files

| File | Platform | Installed to | Purpose |
| ---- | -------- | ------------ | ------- |
| `nftables.conf` | both | `/etc/nftables.conf` | Firewall ruleset |
| `90-custom-sysctl.conf` | both | `/etc/sysctl.d/90-custom.conf` | Kernel hardening |
| `dns-over-tls-resolved.conf` | Ubuntu | `/etc/systemd/resolved.conf.d/dns-over-tls.conf` | systemd-resolved DoT + DNSSEC |
| `dnsmasq-pi.conf` | Pi | `/etc/dnsmasq.d/dns-privacy.conf` | dnsmasq DNSSEC + forward to :5300 |
| `stubby-pi.yml` | Pi | `/etc/stubby/stubby.yml` | stubby DoT config |
| `dot-proxy.py` | Pi (bootstrap) | run in place | Temporary Python DoT proxy |

## Outbound traffic allowed

| Protocol | Destination | Purpose |
| -------- | ----------- | ------- |
| TCP 853 | 9.9.9.9, 149.112.112.112 | DNS-over-TLS (Quad9) |
| UDP 67/68 | any | DHCP |
| UDP 123 | 162.159.200.123, 162.159.200.1 | NTP (Cloudflare) |
| TCP 80/443 | any | HTTP/HTTPS |

All other outbound traffic is dropped.
