#!/bin/bash

set -euo pipefail

# Everything below this line needs root. Elevate once, here, rather than calling
# sudo per command: the script blocks indefinitely waiting for the clock check
# and the ethernet cable, and sudo's credential timestamp would expire in the
# middle of the Pi bootstrap window with the network already up.
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: setup.sh must run as root. Run: sudo bash setup.sh" >&2
    exit 1
fi

# Resolve config relative to this script, not the working directory, so the
# script can be invoked by absolute path from anywhere. Read-only: nothing is
# ever written back here.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${SCRIPT_DIR}/config"

if [[ ! -d "$CONFIG" ]]; then
    echo "ERROR: config directory not found at ${CONFIG}" >&2
    exit 1
fi

# --- Platform detection ---
# shellcheck source=/dev/null
source /etc/os-release

PLATFORM="unsupported"
case "${ID:-}" in
    ubuntu)   PLATFORM="ubuntu" ;;
    raspbian) PLATFORM="pi" ;;
    debian)
        if [[ -f /proc/device-tree/model ]] && grep -qi "raspberry pi" /proc/device-tree/model 2>/dev/null; then
            PLATFORM="pi"
        fi
        ;;
esac

echo "Detected platform: ${PLATFORM} (distro: ${ID:-unknown})"
if [[ "$PLATFORM" == "unsupported" ]]; then
    echo "ERROR: Unsupported distro '${ID:-unknown}'. This script supports Ubuntu and Raspberry Pi OS."
    exit 1
fi

# A wrong clock causes TLS cert validation to fail later (DoT, HTTPS).
# The Pi 4 has no RTC, and an Ubuntu live boot may also carry a bad clock —
# both run air-gapped here, so verify on every platform before anything else.
echo "System date/time: $(date)"
NTP_DISABLED=false
read -r -p "Does this look correct? [Y/n] " CLOCK_OK
if [[ "${CLOCK_OK,,}" == n* ]]; then
    # timedatectl refuses to set the clock manually while NTP synchronisation
    # is active, so switch it off first. It is turned back on further down, once
    # the network — and a real time source — is available.
    timedatectl set-ntp off
    NTP_DISABLED=true
    # Loop until timedatectl accepts the entered value, so a typo re-prompts
    # rather than aborting the whole run under 'set -e'.
    until read -r -p "Enter the correct date and time as 'YYYY-MM-DD HH:MM:SS': " NEW_DATETIME \
        && timedatectl set-time "$NEW_DATETIME"; do
        echo "Could not set the time from '${NEW_DATETIME}'. Use the format YYYY-MM-DD HH:MM:SS."
    done
    echo "Clock set. System date/time is now: $(date)"
fi

# --- Connection detection ---
# nmcli -g emits one "NAME:TYPE" line per connection; keep the NAME of every
# ethernet one. A host may have more than one (multiple NICs, or a stale
# profile), so collect them into an array rather than a single string — a
# multi-line value would be treated as one non-existent connection name and
# every later 'nmcli connection modify' would fail.
mapfile -t CONNS < <(nmcli -g NAME,TYPE connection | awk -F : '/.*ethernet.*/ { print $1 }')

if [[ ${#CONNS[@]} -eq 0 ]]; then
    echo "ERROR: No ethernet connection found via nmcli. NetworkManager must manage the interface." >&2
    exit 1
elif [[ ${#CONNS[@]} -eq 1 ]]; then
    CONN="${CONNS[0]}"
else
    # More than one ethernet connection — let the operator pick which to harden.
    echo "Multiple ethernet connections found. Choose which one to configure:"
    select CONN in "${CONNS[@]}"; do
        if [[ -n "${CONN:-}" ]]; then
            break
        fi
        echo "Invalid selection — enter a number from the list."
    done
fi
echo "Using connection: ${CONN}"

# --- Shared: kernel hardening and firewall ---
echo "Loading nf_conntrack module..."
modprobe nf_conntrack

echo "Making directories..."
mkdir -p /etc/systemd/resolved.conf.d/

echo "Copying shared configuration files..."
cp "${CONFIG}/90-custom-sysctl.conf" /etc/sysctl.d/90-custom.conf
cp "${CONFIG}/nftables.conf" /etc/nftables.conf

echo "Applying kernel parameters and firewall rules..."
sysctl -p /etc/sysctl.d/90-custom.conf
nft -f /etc/nftables.conf

# NTP daemon varies by platform: systemd-timesyncd on the Pi and most Ubuntu
# installs, but the Ubuntu 26.04 live boot ships chrony. Configure whichever is
# present — both pin to the same Cloudflare servers allowed in nftables.conf.
echo "Configuring NTP (Cloudflare time service)..."
if command -v chronyd &>/dev/null; then
    echo "chrony detected — pinning chrony to Cloudflare."
    cp "${CONFIG}/chrony.conf" /etc/chrony/chrony.conf
    systemctl restart chrony 2>/dev/null || systemctl restart chronyd
else
    echo "systemd-timesyncd path — pinning timesyncd to Cloudflare."
    mkdir -p /etc/systemd/timesyncd.conf.d/
    cp "${CONFIG}/timesyncd-cloudflare.conf" /etc/systemd/timesyncd.conf.d/cloudflare.conf
    timedatectl set-ntp true
    systemctl restart systemd-timesyncd
fi

# --- Platform-specific DNS configuration ---
HAS_STUBBY=false

if [[ "$PLATFORM" == "ubuntu" ]]; then
    echo "Configuring systemd-resolved (DNS-over-TLS + DNSSEC)..."
    cp "${CONFIG}/dns-over-tls-resolved.conf" /etc/systemd/resolved.conf.d/dns-over-tls.conf

    echo "Modifying connection..."
    nmcli connection modify "${CONN}" connection.dns-over-tls yes
    nmcli connection modify "${CONN}" ipv6.method link-local
    nmcli connection modify "${CONN}" ipv4.ignore-auto-dns yes
    nmcli connection modify "${CONN}" ipv4.dns 9.9.9.9#dns.quad9.net,149.112.112.112#dns.quad9.net

    echo "Enabling and restarting services..."
    systemctl enable nftables
    systemctl restart systemd-sysctl
    systemctl restart systemd-resolved
    systemctl restart nftables
    systemctl restart NetworkManager

else
    # --- Raspberry Pi path ---
    if command -v stubby &>/dev/null; then
        HAS_STUBBY=true
        echo "stubby found — configuring for DNS-over-TLS."
        mkdir -p /etc/stubby
        cp "${CONFIG}/stubby-pi.yml" /etc/stubby/stubby.yml
    else
        echo "stubby not found — Python DoT proxy will bootstrap the connection, then stubby will be installed."
    fi

    if ! command -v dnsmasq &>/dev/null; then
        echo "ERROR: dnsmasq (or dnsmasq-base) is not installed. Cannot configure DNS."
        exit 1
    fi

    echo "Configuring dnsmasq..."
    mkdir -p /etc/dnsmasq.d/
    cp "${CONFIG}/dnsmasq-pi.conf" /etc/dnsmasq.d/dns-privacy.conf
    cp "${CONFIG}/dnsmasq-pi.service" /etc/systemd/system/dnsmasq.service
    systemctl daemon-reload

    echo "Modifying connection..."
    nmcli connection modify "${CONN}" ipv6.method link-local
    nmcli connection modify "${CONN}" ipv4.ignore-auto-dns yes
    nmcli connection modify "${CONN}" ipv4.dns 127.0.0.1

    # Stop background services that race for the apt lock or react to network-up events.
    # These are timer-driven and will resume normally on next schedule after reboot.
    echo "Quiescing apt timers and NM connectivity check before network comes up..."
    systemctl stop apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
    systemctl stop apt-daily.service apt-daily-upgrade.service 2>/dev/null || true
    # Disable NM connectivity check via config file — more portable than
    # 'nmcli general connectivity-check set', which isn't available on all builds.
    mkdir -p /etc/NetworkManager/conf.d/
    cp "${CONFIG}/no-connectivity-check.conf" /etc/NetworkManager/conf.d/99-no-connectivity-check.conf

    echo "Enabling and restarting services..."
    systemctl enable nftables
    systemctl restart systemd-sysctl
    systemctl restart nftables
    if $HAS_STUBBY; then
        systemctl enable stubby
        systemctl restart stubby
    fi
    systemctl enable dnsmasq
    systemctl restart dnsmasq
    systemctl restart NetworkManager
fi

# --- Wait for ethernet connection ---
echo "Waiting for ${CONN} to connect — plug in the ethernet cable now..."
until nmcli -g NAME connection show --active 2>/dev/null | grep -qF "${CONN}"; do
    sleep 1
done
echo "${CONN} connected, cycling connection to apply new DNS settings..."
nmcli connection down "${CONN}"
nmcli connection up "${CONN}"
# nmcli connection up returns as soon as NM marks the link activated, before DHCP
# completes. Wait for a default route so we know an IP is actually assigned.
echo "Waiting for DHCP..."
until ip route show default 2>/dev/null | grep -q .; do
    sleep 1
done

# If we disabled NTP sync to set the clock by hand, re-enable it now that the
# network is up so the daemon can correct any residual drift against Cloudflare.
if $NTP_DISABLED; then
    echo "Re-enabling NTP synchronisation..."
    timedatectl set-ntp true
fi

# --- Pi bootstrap: use Python DoT proxy to install stubby, then replace it ---
if [[ "$PLATFORM" == "pi" ]] && ! $HAS_STUBBY; then
    # Kill any stale proxy left over from a previous failed run.
    pkill -f dot-proxy.py 2>/dev/null || true
    echo "Starting Python DoT proxy..."
    python3 "${CONFIG}/dot-proxy.py" &
    PROXY_PID=$!
    sleep 1

    echo "Refreshing package lists..."
    apt-get update
    echo "Installing stubby via proxy..."
    apt-get install -y stubby

    echo "Stubby installed. Stopping proxy and switching over..."
    kill "${PROXY_PID}" 2>/dev/null || true
    wait "${PROXY_PID}" 2>/dev/null || true

    mkdir -p /etc/stubby
    cp "${CONFIG}/stubby-pi.yml" /etc/stubby/stubby.yml
    systemctl enable stubby
    systemctl start stubby
fi

# --- Re-enable background services on Pi ---
if [[ "$PLATFORM" == "pi" ]]; then
    echo "Re-enabling background services..."
    systemctl start apt-daily.timer apt-daily-upgrade.timer
    rm -f /etc/NetworkManager/conf.d/99-no-connectivity-check.conf
    systemctl reload NetworkManager
fi

# --- Status ---
echo "Finished. Status:"
nmcli

if [[ "$PLATFORM" == "ubuntu" ]]; then
    resolvectl
else
    echo "DNS check (via local resolver):"
    nslookup quad9.net 127.0.0.1 2>/dev/null \
        || dig +short quad9.net @127.0.0.1 2>/dev/null \
        || echo "(install dnsutils for a DNS check)"
fi

nft list ruleset
