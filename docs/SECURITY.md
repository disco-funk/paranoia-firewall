# Security Review — Paranoia Firewall

**Reviewed:** 2026-04-30
**Remediation status re-checked:** 2026-07-09
**Files reviewed:** `firewall-v1/nftables.conf`, `firewall-v1/hardening.sh`
**Scope:** `firewall-v1/` only. Host-level network hardening. Layer 2 (switch-enforced) controls are noted where relevant but are out of scope for this project.

> This review predates the split of the repo into `firewall-v1/` and `firewall-v2/`. It examines the v1 files at their current paths. **`firewall-v2/` has not been reviewed** — it permits outbound ping and outbound SSH to a pinned GitHub IP set, neither of which is assessed below.

Findings 1, 2, 3 and 6 have since been remediated in `firewall-v1/`; each is marked **Resolved** with the fix in place. They are retained rather than deleted so the reasoning stays on record. Findings 4, 5 and 7 remain open, and 4 and 5 are accepted residual risk.

---

## Posture summary

The ruleset provides a strong baseline for a client host on an untrusted or CGNAT network. Default-drop on all three chains (input, forward, output), mandatory DoT+DNSSEC pinned to specific Quad9 IPs, empty `FallbackDNS`, NTP pinned to Cloudflare, and strict reverse-path filtering together close the most common network-layer attack paths before the cable is plugged in. The remaining gaps are catalogued below in order of severity.

---

## What is well-covered

| Threat | Mechanism | Assessment |
| --- | --- | --- |
| Unsolicited inbound traffic | Default-drop input, zero open ports | Strong |
| Unauthorised egress | Default-drop output, explicit whitelist | Strong |
| DNS hijacking via port 53 | Output policy blocks UDP/TCP 53 entirely | Strong |
| DoT downgrade to plaintext | `DNSOverTLS=yes` (strict, not `allow-downgrade`) | Strong |
| DNSSEC bypass | `DNSSEC=yes` | Strong |
| Rogue DoT resolver | DoT restricted to `9.9.9.9`, `149.112.112.112` only | Strong |
| DNS fallback to untrusted resolver | `FallbackDNS=` (empty) | Strong |
| Clock manipulation via LAN time source | NTP pinned to Cloudflare IPs; `FallbackNTP=` empty | Strong |
| IP source address spoofing | `rp_filter=1` (strict reverse-path filtering) | Strong |
| ICMP redirect route hijacking | `accept_redirects=0`, `send_redirects=0` | Strong |
| IP source routing | `accept_source_route=0` (IPv4 + IPv6) | Strong |
| Local privilege escalation via BPF | `unprivileged_bpf_disabled=1`, `bpf_jit_harden=2` | Strong |
| Kernel address disclosure | `kptr_restrict=2` | Strong |
| TCP fingerprinting via timestamps | `tcp_timestamps=0` | Strong |
| IPv6 address tracking / correlation | `use_tempaddr=2` (privacy extensions) | Strong |
| Loopback spoofing from external interface | Explicit drop rules in input and output chains | Strong |
| Inbound ICMP flood | Rate-limited to 10/second; error types only, no echo-request | Adequate |
| SYN flood | `tcp_syncookies=1` | Adequate |
| Conntrack exhaustion | `nf_conntrack_max=65536`; SYN-sent timeout reduced to 10 s | Adequate |
| IPv6 router advertisement source | RA accepted only from `fe80::/10` link-local | Partial (see §4) |
| CGNAT exposure | No routable public IP; inbound new connections silently dropped | Adequate |

---

## Identified gaps and attack vectors

### 1. No time synchronisation — clock drift will break TLS and DNSSEC (HIGH) — **Resolved**

> **Resolved.** `firewall-v1/nftables.conf` now permits `udp dport 123` to `162.159.200.123` and `162.159.200.1` only, and `firewall-v1/hardening.sh` writes a `systemd-timesyncd` drop-in pinning `NTP=` to those same IPs with `FallbackNTP=` left empty. Original finding retained below.

The output chain has no rule for NTP (UDP 123). `systemd-timesyncd`, which ships enabled by default on Debian/Ubuntu, requires UDP 123 and will fail silently. As the system clock drifts past the tolerance window for TLS certificate validity or DNSSEC signature expiry, both defences become inoperable — with no attacker action required.

The fact that TCP 443 is open does not help: standard NTP and Network Time Security (NTS) do not run over TCP 443.

**Mitigation applied:** Outbound NTP is pinned to the static anycast IPs of a provider that maintains stable addresses, matching the same IP-pinning approach used for DoT:

```nft
udp dport 123 ip daddr { 162.159.200.123, 162.159.200.1 } counter accept
```

Alternatively, chrony with NTS (TCP/UDP 4460) provides authenticated time sync and is harder to spoof, at the cost of opening port 4460 to a pinned server. `firewall-v2/` uses chrony where present, with the same Cloudflare IP pinning.

---

### 2. ICMP redirects and IP source routing not disabled (MEDIUM) — **Resolved**

> **Resolved.** All ten sysctl entries listed below are now present in `firewall-v1/hardening.sh`. Original finding retained below.

Two classes of kernel-level routing manipulation are not blocked by sysctl:

**ICMP redirects.** Without `accept_redirects = 0`, a co-located attacker on the CGNAT segment can send forged ICMP Type 5 (Redirect) messages. The kernel will update its routing cache to send traffic through the attacker's host, silently intercepting connections that the output chain would otherwise permit to their legitimate destination. The nftables rules do not help here — traffic is redirected before the output chain sees the correct destination.

**Source routing.** Without `accept_source_route = 0`, IPv4 Loose/Strict Source Route options in packet headers are processed. Modern kernels default IPv4 source routing to disabled, but the setting is not explicit in the current sysctl conf and is not disabled for IPv6.

**Also missing:** `send_redirects = 0`. A client host should never send ICMP redirects; leaving this enabled leaks routing topology information.

**Additions applied to `firewall-v1/hardening.sh`:**

```text
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
```

---

### 3. Missing kernel hardening parameters (MEDIUM) — **Resolved**

> **Resolved.** All five parameters are now set in `firewall-v1/hardening.sh`. Original finding retained below.

Several kernel tunables that reduce local privilege escalation attack surface and close information-disclosure paths are absent from the current sysctl conf:

| Parameter | Value | Risk if absent |
| --- | --- | --- |
| `kernel.kptr_restrict` | `2` | Kernel symbol addresses exposed in `/proc/kallsyms` and similar; aids exploit development against the local kernel |
| `kernel.unprivileged_bpf_disabled` | `1` | Unprivileged BPF programs have been the root cause of multiple local privilege escalation CVEs; this is one of the highest-value mitigations for recent kernels |
| `net.core.bpf_jit_harden` | `2` | BPF JIT spraying attacks remain viable even with privileged-only BPF; hardening the JIT output closes a second-order path |
| `net.ipv4.tcp_syncookies` | `1` | Without SYN cookies, a sustained SYN flood can exhaust the conntrack table despite `nf_conntrack_max`; this is belt-and-suspenders protection |
| `net.ipv4.icmp_echo_ignore_broadcasts` | `1` | Smurf amplification prevention; the README threat-model table claims this is set, but it is absent from the sysctl conf |

Note on `icmp_echo_ignore_broadcasts`: modern kernels default this to `1`, so the README description is practically accurate on current Debian/Ubuntu, but it should be explicitly set so the configuration is self-documenting and does not silently rely on a kernel default that could change.

---

### 4. IPv6 rogue Router Advertisement injection (MEDIUM — partially unmitigatable at host level) — **Open, accepted**

The input chain accepts `nd-router-advert` from any link-local source (`fe80::/10`). NDP provides no authentication, so on a shared CGNAT segment a co-located attacker can broadcast forged RA packets to:

- Advertise themselves as the IPv6 default gateway, redirecting all IPv6 traffic through their host before it reaches the internet.
- Include an RDNSS option (RFC 8106) pointing to an attacker-controlled resolver. While the nftables DoT pinning would block any connection to that resolver on port 853 (since only Quad9 IPs are permitted), IPv6 routing itself could be compromised.

The host cannot distinguish a legitimate RA from a forged one because both arrive from `fe80::/10`. Full mitigation requires RA Guard enforced at the switch or access point. At the host level the only complete mitigation is disabling IPv6 (`net.ipv6.conf.all.disable_ipv6 = 1`), which eliminates the attack surface at the cost of IPv6 connectivity.

**Accepted residual risk** for dual-stack deployments on untrusted networks. Document and acknowledge.

---

### 5. ARP poisoning and DHCP spoofing (MEDIUM — unmitigatable at host layer) — **Open, accepted**

An attacker on the same L2 segment can:

- **ARP poison** the host's ARP cache to impersonate the gateway, intercepting all outbound traffic before the nftables output chain can apply rules. The nftables rules operate on routed packets; an ARP-level intercept happens below that layer.
- **DHCP spoof** by responding to DHCP Discover/Request before the legitimate DHCP server, supplying an attacker-controlled gateway IP. The systemd-resolved drop-in overrides any DHCP-supplied DNS, so DNS hijacking via this path is blocked — but the gateway itself can be poisoned.

Mitigations require Dynamic ARP Inspection (DAI) and DHCP snooping at the network switch. These are not configurable at the host. Document as accepted risk for CGNAT deployments.

---

### 6. `ct state invalid` drop ordering (LOW) — **Resolved**

> **Resolved.** The `ct_base` chain in `firewall-v1/nftables.conf` now drops invalid before accepting established/related. `firewall-v2/` expresses the same ordering via a `ct state vmap`.

In both the input and output chains, `ct state { established, related } accept` appears before `ct state invalid drop`. Conntrack states are mutually exclusive, so in practice no packet can match both rules and the behaviour is correct. However, the canonical safe ordering — drop invalid first — is the convention recommended by the nftables project and avoids any theoretical edge case in conntrack state assignment by a module loaded after the base ruleset.

**Reordering applied in `ct_base`:**

```nft
ct state invalid counter drop
ct state { established, related } counter accept
```

---

### 7. Unrestricted HTTP/HTTPS egress (LOW — accepted design tradeoff) — **Open, accepted**

`tcp dport { 80, 443 }` allows outbound connections to any destination with no restriction on the initiating process. Any software installed on the host — including malware — can use these ports for command-and-control or data exfiltration. The README acknowledges this tradeoff; HTTP in particular is noted as debatable.

**Potential mitigation (out of scope for current "minimal" design):** An outbound application-layer proxy with a destination allowlist, or a host-based firewall with per-UID/GID connmark rules to restrict which users can initiate outbound HTTP/HTTPS. Both are meaningful additions to the threat model but require ongoing maintenance.

---

## Not yet reviewed — `firewall-v2/`

`firewall-v2/` broadens the egress and ingress policy relative to v1 and has not been assessed. A future review should cover at minimum:

- **Outbound TCP 22 to `@github_ips`.** A hardcoded IP set for a third-party service. GitHub rotates these addresses; a stale set fails closed (git breaks), but the rule widens egress to a set the operator does not control.
- **Outbound ICMP echo-request to any destination.** Permits ping as a low-bandwidth exfiltration or beaconing channel.
- **Inbound ICMP echo-request from `192.168.0.0/24`.** A hardcoded RFC 1918 range that may not match the deployed LAN, and which an attacker on the segment can trivially source-spoof.
- **The Pi bootstrap window.** `firewall-v2/config/dot-proxy.py` terminates TLS to Quad9 in Python during `apt-get install stubby`, with the NM connectivity check disabled. The proxy's certificate validation behaviour should be verified.

---

## Out-of-scope / accepted design decisions

The following are documented design choices, not defects:

- **No persistent logging.** Counters via `nft list ruleset`; no SIEM or IDS/IPS integration.
- **No inbound services.** Client-only host; no SSH or management interface.
- **No rate limiting on new outbound connections.** Not in scope for current design.
- **No application-layer inspection.** Traffic content is not examined.
- **HTTP (port 80) permitted.** Retained for package mirrors and captive portal compatibility.

---

## Issue tracker

All tracked issues are closed as of 2026-07-09.

| Issue | Title | Severity | Status |
| --- | --- | --- | --- |
| [#5](https://github.com/disco-funk/paranoia-firewall/issues/5) | NTP blocked — clock drift will break TLS/DNSSEC | High | Closed |
| [#6](https://github.com/disco-funk/paranoia-firewall/issues/6) | Missing sysctl: ICMP redirects, source routing, kernel hardening | Medium | Closed |
| [#7](https://github.com/disco-funk/paranoia-firewall/issues/7) | `ct state invalid` drop should precede `established/related` accept | Low | Closed |
| [#1](https://github.com/disco-funk/paranoia-firewall/issues/1) | DHCP unicast renewal blocked by output rule | Medium | Closed |
| [#2](https://github.com/disco-funk/paranoia-firewall/issues/2) | Interface detection fails when run before network connection | Medium | Closed |
| [#3](https://github.com/disco-funk/paranoia-firewall/issues/3) | sysctl error when running hardening.sh | Low | Closed |
| [#4](https://github.com/disco-funk/paranoia-firewall/issues/4) | DNS-over-TLS lookup succeeds but cannot wget a webpage | Medium | Closed |

The remaining open risks are §4 (rogue IPv6 RA) and §5 (ARP/DHCP spoofing) — both accepted, both unmitigatable at the host layer — plus §7 (unrestricted HTTP/HTTPS egress), an accepted design tradeoff.
