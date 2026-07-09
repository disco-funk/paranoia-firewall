# Paranoia Firewall

A minimal, security-hardened nftables ruleset and network hardening script for Debian/Ubuntu hosts that will be attached to an untrusted network (including CGNAT) after deployment.

The design philosophy: assume the network is hostile. Lock everything down before the cable goes in.

## Two generations

This repo contains two independent versions of the firewall. Pick one — they are not layered, and there is no migration path between them.

They differ mainly in **how you get the config onto a machine that has never touched a network**. That is the hard problem: you cannot download the firewall you need in order to safely download things.

| | [`firewall-v1/`](firewall-v1/) | [`firewall-v2/`](firewall-v2/) |
| --- | --- | --- |
| **How it gets there** | You type it in | Write-protected media |
| **Status** | Original, stable | Current work |
| **Platforms** | Ubuntu / Debian | Ubuntu **+ Raspberry Pi OS** |
| **Deploy with** | `sudo bash hardening.sh` | `sudo bash setup.sh` |
| **Files** | 2, short enough to transcribe | Orchestrated, copied into place |
| **DNS** | systemd-resolved (DoT + DNSSEC) | systemd-resolved, or dnsmasq + stubby on Pi |
| **NTP** | systemd-timesyncd, pinned | chrony *or* systemd-timesyncd, pinned |

**Use `firewall-v1/`** if you have nothing but a keyboard. It is deliberately short — two files, no comments, no conveniences — so that a human can retype it at the console of a freshly installed machine and get the firewall up before the cable ever goes in. Every line you don't have to type is a line that can't be mistyped.

**Use `firewall-v2/`** if you can carry it in on read-only media. Mount a physically write-protected disk — a 3.5" HD floppy with the tab flipped open does the job — and run `setup.sh` straight off it. The write-protect tab is the integrity guarantee: the media cannot be altered by the machine you are about to harden, or by anything already on it. Freed from transcription cost, v2 adds Raspberry Pi support, automated setup, encrypted-DNS bootstrap, and comments throughout. See [`firewall-v2/README.md`](firewall-v2/README.md).

It is a pleasing accident that in 2026 a USB floppy drive and a spindle of blank HD disks are close to a reliable indicator of the sort of person who ends up running a firewall like this one.

The rest of this page describes the shared design. Version-specific details live in each directory.

## What it does

- **nftables** — dual-stack (IPv4 + IPv6) firewall with default-drop on *input*, *forward*, and *output*
- **DNS-over-TLS** — pinned to Quad9 (`9.9.9.9`, `149.112.112.112`), with DNSSEC validation; plain port-53 DNS is blocked by the output policy
- **NTP** — pinned to Cloudflare (`162.159.200.123`, `162.159.200.1`) so an untrusted LAN cannot steer the clock
- **sysctl hardening** — TCP timestamp suppression, strict reverse-path filtering, IPv6 temporary addresses, conntrack tuning, ICMP redirect and source-routing rejection, BPF and kernel-pointer restrictions

## Threat model

| Threat | Mitigation |
| --- | --- |
| Port scanners / unsolicited inbound | Default-drop input; no listening services exposed |
| Malware / trackers calling home | Default-drop output; only HTTPS (443), HTTP (80), and DoT (853) allowed out |
| DNS hijacking / poisoning | Port 53 silently dropped by output policy; DoT+DNSSEC mandatory |
| Clock skew breaking TLS / DNSSEC | NTP pinned to Cloudflare IPs; LAN-supplied time sources dropped |
| Source IP spoofing | `rp_filter = 1` (strict reverse-path filtering) |
| ICMP redirect route hijacking | `accept_redirects = 0`, `send_redirects = 0` |
| TCP fingerprinting via timestamps | `tcp_timestamps = 0` |
| IPv6 address tracking | Temporary addresses rotated (`use_tempaddr = 2`) |
| Conntrack table exhaustion | `nf_conntrack_max = 65536`; reduced SYN-sent timeout; SYN cookies |
| Local privilege escalation via BPF | `unprivileged_bpf_disabled = 1`, `bpf_jit_harden = 2` |
| ICMP flood / smurfing | Rate-limited ICMP error types; broadcast echo ignored via sysctl |

## Network assumptions

- CGNAT upstream — the host has no routable public IP; NAT traversal is not a goal
- DHCP for address assignment (broadcast and unicast renewal)
- IPv4 + IPv6 dual-stack (IPv6 NDP preserved)
- Loopback must work; loopback-spoofed traffic from external interfaces is dropped

## What is and isn't allowed outbound

Shared baseline. `firewall-v2/` additionally permits outbound ping and SSH to a pinned GitHub IP set — see its README.

| Traffic | Allowed | Notes |
| --- | --- | --- |
| HTTPS (TCP 443) | Yes | Any destination |
| HTTP (TCP 80) | Yes | Debatable; remove if not needed |
| DNS over TLS (TCP 853) | Yes | **Only** to Quad9 IPs |
| Plain DNS (UDP/TCP 53) | **No** | Blocked by default-drop output |
| NTP (UDP 123) | Yes | **Only** to Cloudflare IPs |
| DHCP (UDP 67/68) | Yes | Broadcast and unicast renewal |
| ICMP error types | Yes | Rate-limited, outbound only |
| ICMPv6 (NDP + errors) | Yes | Required for IPv6 |
| Everything else | **No** | Default-drop output policy |

## Requirements

- Debian, Ubuntu, or Raspberry Pi OS with systemd
- `nftables` package
- `systemd-resolved` (enabled and running) — Ubuntu/Debian path
- Root privileges

## Usage

Run **before** connecting the host to the network:

```bash
# v1
cd firewall-v1 && sudo bash hardening.sh

# v2
cd firewall-v2 && sudo bash setup.sh
```

Verify afterwards:

```bash
resolvectl status           # confirm DoT + DNSSEC active
nft list ruleset            # inspect live rules
sysctl -a | grep -E 'rp_filter|timestamps|tempaddr|conntrack_max'
```

## Testing

`smoke-test.sh` exercises a deployed host: it asserts DoT and DNSSEC are live, the expected sysctls are set, permitted egress works, and blocked egress fails.

```bash
sudo bash smoke-test.sh
```

It targets **`firewall-v1/`**. Two of its assertions do not hold for `firewall-v2/` (which permits outbound ping, and reaches DNS via dnsmasq/stubby on the Pi), so adapt it before pointing it at a v2 host.

## Design decisions

**Why default-drop output?** Most firewalls only block inbound. This one also blocks outbound by default so that software installed later can't phone home without an explicit rule being added.

**Why Quad9 only for DoT?** Pinning DoT to specific IPs means a rogue DHCP server handing out a malicious DNS IP can't intercept resolution — the firewall will simply drop the connection attempt.

**Why no port 53 at all?** Plain DNS is unencrypted and trivially hijackable. systemd-resolved talking to the stub resolver on 127.0.0.53 bypasses port 53 for applications; the nftables output policy then blocks port 53 to anything else.

**Why not also block port 80?** Kept for practical compatibility (package mirrors, captive portals). Remove the rule if your threat model requires it.

**Why pin NTP?** TLS and DNSSEC both fail closed when the clock is wrong. Leaving time sync to a DHCP-supplied server hands an attacker on the LAN a way to disable both by drifting the clock.

## Security review

See [`docs/SECURITY.md`](docs/SECURITY.md) for a full review of `firewall-v1/`, including accepted residual risks (rogue IPv6 RA, ARP poisoning) that cannot be mitigated at the host layer.

## Known issues / TODOs

All tracked issues are currently closed. Accepted residual risks — rogue IPv6 router advertisements, ARP poisoning, and unrestricted HTTP/HTTPS egress — are documented in [`docs/SECURITY.md`](docs/SECURITY.md); they cannot be mitigated at the host layer or are deliberate tradeoffs.

`firewall-v2/` has not had a security review.
