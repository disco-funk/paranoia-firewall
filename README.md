# various-firewalls

A hardened Ubuntu firewall with encrypted DNS, designed to be applied to a **fresh Ubuntu install before the machine is ever connected to the internet**. Run `setup.sh` while the machine is still air-gapped, then plug in the ethernet cable. The firewall is in place before the first packet is sent or received.

Implements a default-deny stateful packet filter via nftables, kernel parameter hardening via sysctl, and DNSSEC + DNS-over-TLS via systemd-resolved — all routed through Quad9 (9.9.9.9 / 149.112.112.112).

## What it does

- **Firewall (nftables):** Default-drop on INPUT, FORWARD, and OUTPUT. Allows only loopback, DHCP, NTP (Cloudflare), DNS-over-TLS (Quad9), and HTTP/HTTPS. Blocks all packet forwarding.
- **Kernel hardening (sysctl):** Disables source routing and redirects, enables reverse-path filtering, SYN cookies, BPF restrictions, and kernel pointer hiding.
- **Encrypted DNS (systemd-resolved):** Forces DNS-over-TLS and DNSSEC validation. No plaintext DNS leaks. No fallback servers.

## Requirements

- Ubuntu (tested and working)
- NetworkManager managing the active connection
- `sudo` / root access

## Usage

```bash
sudo bash setup.sh
```

The script auto-detects the active Ethernet connection, copies configs to their system locations, applies settings, and restarts the relevant services (nftables, systemd-resolved, NetworkManager). It prints a status summary at the end via `nmcli`, `resolvectl`, and `nft`.

## Files

| File | Installed to | Purpose |
| ---- | ------------ | ------- |
| `nftables.conf` | `/etc/nftables.conf` | Firewall ruleset |
| `90-custom-sysctl.conf` | `/etc/sysctl.d/90-custom.conf` | Kernel hardening parameters |
| `dns-over-tls-resolved.conf` | `/etc/systemd/resolved.conf.d/dns-over-tls.conf` | DNS-over-TLS + DNSSEC config |

## Outbound traffic allowed

| Protocol | Destination | Purpose |
| -------- | ----------- | ------- |
| TCP 853 | 9.9.9.9, 149.112.112.112 | DNS-over-TLS (Quad9) |
| UDP 67/68 | any | DHCP |
| UDP 123 | 162.159.200.123, 162.159.200.1 | NTP (Cloudflare) |
| TCP 80/443 | any | HTTP/HTTPS |

All other outbound traffic is dropped.
