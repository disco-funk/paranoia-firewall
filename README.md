# Paranoia Firewall

A minimal, security-hardened nftables ruleset and network hardening script for Debian/Ubuntu hosts that will be attached to an untrusted network (including CGNAT) after deployment.

The design philosophy: assume the network is hostile. Lock everything down before the cable goes in.

## What it does

- **nftables** — dual-stack (IPv4 + IPv6) firewall with default-drop on *input*, *forward*, and *output*
- **DNS-over-TLS** — enforced via systemd-resolved, pinned to Quad9 (`9.9.9.9`, `149.112.112.112`), with DNSSEC validation; plain port-53 DNS is blocked by the output policy
- **sysctl hardening** — TCP timestamp suppression, strict reverse-path filtering, IPv6 temporary addresses, conntrack tuning

## Threat model

| Threat | Mitigation |
|---|---|
| Port scanners / unsolicited inbound | Default-drop input; no listening services exposed |
| Malware / trackers calling home | Default-drop output; only HTTPS (443), HTTP (80), and DoT (853) allowed out |
| DNS hijacking / poisoning | Port 53 silently dropped by output policy; DoT+DNSSEC mandatory |
| Source IP spoofing | `rp_filter = 1` (strict reverse-path filtering) |
| TCP fingerprinting via timestamps | `tcp_timestamps = 0` |
| IPv6 address tracking | Temporary addresses rotated (`use_tempaddr = 2`) |
| Conntrack table exhaustion | `nf_conntrack_max = 65536`; reduced SYN-sent timeout |
| ICMP flood / smurfing | Rate-limited ICMP error types; broadcast echo ignored via sysctl |

## Network assumptions

- CGNAT upstream — the host has no routable public IP; NAT traversal is not a goal
- DHCP for address assignment (broadcast and unicast renewal)
- IPv4 + IPv6 dual-stack (IPv6 NDP preserved)
- Loopback must work; loopback-spoofed traffic from external interfaces is dropped

## What is and isn't allowed outbound

| Traffic | Allowed | Notes |
|---|---|---|
| HTTPS (TCP 443) | Yes | Any destination |
| HTTP (TCP 80) | Yes | Debatable; remove if not needed |
| DNS over TLS (TCP 853) | Yes | **Only** to Quad9 IPs |
| Plain DNS (UDP/TCP 53) | **No** | Blocked by default-drop output |
| DHCP (UDP 67/68) | Yes | Broadcast and unicast renewal |
| ICMP error types | Yes | Rate-limited, outbound only |
| ICMPv6 (NDP + errors) | Yes | Required for IPv6 |
| Everything else | **No** | Default-drop output policy |

## Requirements

- Debian or Ubuntu with systemd
- `nftables` package
- `systemd-resolved` (enabled and running)
- Root privileges

## Usage

Run **before** connecting the host to the network:

```bash
sudo bash hardening.sh
```

The script will:
1. Write a systemd-resolved drop-in enabling DNS-over-TLS + DNSSEC to Quad9
2. Apply sysctl hardening parameters
3. Validate and deploy the nftables ruleset

Verify afterwards:

```bash
resolvectl status           # confirm DoT + DNSSEC active
nft list ruleset            # inspect live rules
sysctl -a | grep -E 'rp_filter|timestamps|tempaddr|conntrack_max'
```

## Design decisions

**Why default-drop output?** Most firewalls only block inbound. This one also blocks outbound by default so that software installed later can't phone home without an explicit rule being added.

**Why Quad9 only for DoT?** Pinning DoT to specific IPs means a rogue DHCP server handing out a malicious DNS IP can't intercept resolution — the firewall will simply drop the connection attempt.

**Why no port 53 at all?** Plain DNS is unencrypted and trivially hijackable. systemd-resolved talking to the stub resolver on 127.0.0.53 bypasses port 53 for applications; the nftables output policy then blocks port 53 to anything else.

**Why not also block port 80?** Kept for practical compatibility (package mirrors, captive portals). Remove the rule if your threat model requires it.

## Known issues / TODOs

- DHCP unicast renewal: the current output DHCP rule only permits broadcast (`255.255.255.255`). DHCP renewal (RENEWING state) uses unicast to the server IP, which may be blocked. See issue in `nftables.conf`.
- `hardening.sh` interface detection uses `ip route show default`, which will return nothing if run before any network connection. The per-interface `resolvectl` live commands will fail; the drop-in config is still written correctly and applies on next `systemd-resolved` restart.
