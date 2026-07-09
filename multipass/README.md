# Multipass on the paranoia firewall

`multipass launch` hangs indefinitely under the default-deny ruleset. The image
downloads (HTTPS is already allowed) but the guest never comes up.

## Why

`nftables-appendix.config` is the ruleset Multipass installs on a stock host,
captured from a working Ubuntu 26.04 box. It registers base chains in
`table ip filter` at the same hook and priority as `inet filter`.

That does not help. A packet traverses *every* base chain on a hook, `accept`
only ends traversal of the chain it appears in, and any `drop` is final. Every
Multipass chain is `policy accept`, so none of them can rescue traffic from the
policy drop in `inet filter`. Three things are dropped, each enough to hang a
launch on its own:

| Chain | What breaks |
| ----- | ----------- |
| `input` | Guest DHCP request and DNS queries to the bridge dnsmasq. The guest never gets an address. |
| `output` | Multipass finishes a launch by SSHing into the guest. `tcp dport 22` is allowed only to `@github_ips`. |
| `forward` | Policy drop, and no `jump ct_base`, so guests have no internet and no return path. Cloud-init blocks on snapd seeding. |

## Use

```bash
sudo ./multipass-firewall.sh          # apply
sudo ./multipass-firewall.sh remove   # revert
```

Idempotent — apply drops any existing rule mentioning the bridge before adding
its own. Override the bridge with `MULTIPASS_BRIDGE=` if it is not `mpqemubr0`.

## What it allows

Deliberately narrower than what Multipass gives itself. Its own `FORWARD` chain
accepts guest egress on *any* port; this restricts guests to 80/443, which is
what cloud-init and snapd need and nothing more.

- `input`: UDP 67, and TCP/UDP 53, on the bridge only
- `output`: DHCP replies, and TCP 22 **scoped to the bridge** — the github-only
  SSH rule is not widened
- `forward`: `jump ct_base`, then guest egress on 80/443 only

Guest DNS goes to the dnsmasq that multipassd runs on the bridge, which forwards
upstream through `/etc/resolv.conf` → systemd-resolved → DoT to Quad9. No plain
DNS leaves the host, so the no-plain-DNS constraint holds. Worth confirming on
first run: watch the `tcp dport 853` counter move while the trailing bare
`counter` in `output` stays put.

Not allowed, because a launch does not need it: guest-to-guest traffic
(`iifname mpqemubr0 oifname mpqemubr0`), and guest NTP — cloud-init does not
block on the latter.

## NAT, and the flush problem

`nftables.conf` opens with `flush ruleset`, which destroys **every** table —
including the `ip filter`, `ip mangle` and `ip nat` that Multipass owns. The
masquerade lives in `ip nat`, so after any `nft -f /etc/nftables.conf` the
guests have no internet no matter what these rules say. Only a daemon restart
rebuilds them:

```bash
sudo snap restart multipass
sudo nft list tables          # expect ip filter, ip mangle, ip nat
```

The script warns if the masquerade is missing. At boot the ordering happens to
work out — `nftables.service` runs early, multipassd starts later and installs
its tables afterwards.

## Persistence

These rules are runtime-only and do not survive a reboot, by design:
`nftables.conf` is unchanged. To reapply automatically:

```bash
sudo install -m 755 multipass-firewall.sh /usr/local/sbin/
sudo install -m 644 multipass-firewall.service /etc/systemd/system/
sudo systemctl enable --now multipass-firewall.service
```

## If it still hangs

The trailing bare `counter` in each chain counts everything that fell through to
the policy drop. Whichever is incrementing during a launch is the chain still
eating packets:

```bash
sudo nft list chain inet filter forward
sudo nft list chain inet filter input
sudo nft list chain inet filter output
sudo nft monitor trace
```
