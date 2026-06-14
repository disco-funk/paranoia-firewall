# CLAUDE.md

## Project overview

Shell-based Ubuntu firewall hardening project. No build system, no dependencies, no tests. Four files: one setup script and three config files that get deployed to system paths.

**Intended workflow:** `setup.sh` is run on a fresh Ubuntu install while the machine is still air-gapped (no network cable connected). The firewall is fully in place before the ethernet cable is ever plugged in, so the machine is never exposed to the internet without protection.

## File map

- `setup.sh` — orchestration script; must be run as root on the target Ubuntu system
- `nftables.conf` — nftables firewall ruleset (inet filter table, three chains)
- `90-custom-sysctl.conf` — kernel parameter hardening (deployed as `/etc/sysctl.d/90-custom.conf`)
- `dns-over-tls-resolved.conf` — systemd-resolved config enabling DNS-over-TLS + DNSSEC via Quad9

## Key design decisions

- **Air-gapped first:** The setup is designed to run before any network connection is made. Don't change this workflow.
- **Default-deny everywhere:** INPUT, FORWARD, and OUTPUT chains all drop by default. Any new allowed traffic requires an explicit rule addition to `nftables.conf`.
- **Quad9 only:** DNS is locked to 9.9.9.9 and 149.112.112.112. No fallback DNS is configured — intentional to prevent DNS leaks.
- **No forwarding:** The FORWARD chain drops everything. This machine is not a router.
- **NTP pinned to Cloudflare:** UDP 123 is only allowed to 162.159.200.123 and 162.159.200.1, not open to any destination.
- **DNS-over-TLS port 853 is explicitly allowlisted** in the firewall so systemd-resolved can reach Quad9. If DNS servers change, both `dns-over-tls-resolved.conf` and `nftables.conf` need updating.

## When editing firewall rules

The `nftables.conf` structure has three chains in one `inet filter` table:
1. `ct_base` — shared stateful logic (drop invalid, accept established/related); called via jump from input and output
2. `input` — inbound traffic policy
3. `output` — outbound traffic policy; `forward` — all-drop, no rules needed

ICMP is rate-limited to 10/second. IPv6 neighbor discovery and router advertisements are explicitly permitted in both input and output.

## Applying changes

Changes to config files don't take effect until `setup.sh` is re-run on the target system, or the relevant service is restarted manually:

```bash
# Firewall
sudo nft -f /etc/nftables.conf

# DNS
sudo systemctl restart systemd-resolved

# Kernel params
sudo sysctl --system
```

## Platform

Ubuntu only. The script uses NetworkManager (`nmcli`) for DNS and connection configuration. It will not work on systems using other network managers (e.g. netplan without NM, ifupdown).
