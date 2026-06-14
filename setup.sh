#!/bin/bash

set -e

# --- Platform detection ---
# shellcheck source=/dev/null
source /etc/os-release

PLATFORM="unsupported"
case "$ID" in
    ubuntu)   PLATFORM="ubuntu" ;;
    raspbian) PLATFORM="pi" ;;
    debian)
        if [[ -f /proc/device-tree/model ]] && grep -qi "raspberry pi" /proc/device-tree/model 2>/dev/null; then
            PLATFORM="pi"
        fi
        ;;
esac

echo "Detected platform: ${PLATFORM} (distro: ${ID})"
if [[ "$PLATFORM" == "unsupported" ]]; then
    echo "ERROR: Unsupported distro '${ID}'. This script supports Ubuntu and Raspberry Pi OS."
    exit 1
fi

# --- Connection detection ---
CONN=$(nmcli -g NAME,TYPE connection | awk -F : '/.*ethernet.*/ { print $1 }')
echo "Using connection: ${CONN}"

# --- Shared: kernel hardening and firewall ---
echo "Loading nf_conntrack module..."
sudo modprobe nf_conntrack

echo "Making directories..."
sudo mkdir -p /etc/systemd/resolved.conf.d/

echo "Copying shared configuration files..."
sudo cp ./90-custom-sysctl.conf /etc/sysctl.d/90-custom.conf
sudo cp ./nftables.conf /etc/nftables.conf

echo "Applying kernel parameters and firewall rules..."
sudo sysctl -p /etc/sysctl.d/90-custom.conf
sudo nft -f /etc/nftables.conf

# --- Platform-specific DNS configuration ---
HAS_STUBBY=false

if [[ "$PLATFORM" == "ubuntu" ]]; then
    echo "Configuring systemd-resolved (DNS-over-TLS + DNSSEC)..."
    sudo cp ./dns-over-tls-resolved.conf /etc/systemd/resolved.conf.d/dns-over-tls.conf

    echo "Modifying connection..."
    nmcli connection modify "${CONN}" connection.dns-over-tls yes
    nmcli connection modify "${CONN}" ipv6.method link-local
    nmcli connection modify "${CONN}" ipv4.ignore-auto-dns yes
    nmcli connection modify "${CONN}" ipv4.dns 9.9.9.9#dns.quad9.net,149.112.112.112#dns.quad9.net

    echo "Enabling and restarting services..."
    sudo systemctl enable nftables
    sudo systemctl restart systemd-sysctl
    sudo systemctl restart systemd-resolved
    sudo systemctl restart nftables
    sudo systemctl restart NetworkManager

else
    # --- Raspberry Pi path ---
    if command -v stubby &>/dev/null; then
        HAS_STUBBY=true
        echo "stubby found — configuring for DNS-over-TLS."
        sudo mkdir -p /etc/stubby
        sudo cp ./stubby-pi.yml /etc/stubby/stubby.yml
    else
        echo "stubby not found — Python DoT proxy will bootstrap the connection, then stubby will be installed."
    fi

    if ! command -v dnsmasq &>/dev/null; then
        echo "ERROR: dnsmasq (or dnsmasq-base) is not installed. Cannot configure DNS."
        exit 1
    fi

    echo "Configuring dnsmasq..."
    sudo mkdir -p /etc/dnsmasq.d/
    sudo cp ./dnsmasq-pi.conf /etc/dnsmasq.d/dns-privacy.conf

    echo "Modifying connection..."
    nmcli connection modify "${CONN}" ipv6.method link-local
    nmcli connection modify "${CONN}" ipv4.ignore-auto-dns yes
    nmcli connection modify "${CONN}" ipv4.dns 127.0.0.1

    # Stop background services that race for the apt lock or react to network-up events.
    # These are timer-driven and will resume normally on next schedule after reboot.
    echo "Quiescing apt timers and NM connectivity check before network comes up..."
    sudo systemctl stop apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
    sudo systemctl stop apt-daily.service apt-daily-upgrade.service 2>/dev/null || true
    # Disable NM connectivity check via config file — more portable than
    # 'nmcli general connectivity-check set', which isn't available on all builds.
    sudo mkdir -p /etc/NetworkManager/conf.d/
    sudo cp ./no-connectivity-check.conf /etc/NetworkManager/conf.d/99-no-connectivity-check.conf

    echo "Enabling and restarting services..."
    sudo systemctl enable nftables
    sudo systemctl restart systemd-sysctl
    sudo systemctl restart nftables
    if $HAS_STUBBY; then
        sudo systemctl enable stubby
        sudo systemctl restart stubby
    fi
    sudo systemctl enable dnsmasq
    sudo systemctl restart dnsmasq
    sudo systemctl restart NetworkManager
fi

# --- Wait for ethernet connection ---
echo "Waiting for ${CONN} to connect — plug in the ethernet cable now..."
until nmcli -g NAME connection show --active 2>/dev/null | grep -qF "${CONN}"; do
    sleep 1
done
echo "${CONN} connected, cycling connection to apply new DNS settings..."
nmcli connection down "${CONN}"
nmcli connection up "${CONN}"

# --- Pi bootstrap: use Python DoT proxy to install stubby, then replace it ---
if [[ "$PLATFORM" == "pi" ]] && ! $HAS_STUBBY; then
    echo "Starting Python DoT proxy..."
    sudo python3 ./dot-proxy.py &
    PROXY_PID=$!
    sleep 1

    echo "Installing stubby via proxy..."
    sudo apt-get install -y stubby

    echo "Stubby installed. Stopping proxy and switching over..."
    sudo kill "${PROXY_PID}" 2>/dev/null || true
    wait "${PROXY_PID}" 2>/dev/null || true

    sudo mkdir -p /etc/stubby
    sudo cp ./stubby-pi.yml /etc/stubby/stubby.yml
    sudo systemctl enable stubby
    sudo systemctl start stubby
fi

# --- Re-enable background services on Pi ---
if [[ "$PLATFORM" == "pi" ]]; then
    echo "Re-enabling background services..."
    sudo systemctl start apt-daily.timer apt-daily-upgrade.timer
    sudo rm -f /etc/NetworkManager/conf.d/99-no-connectivity-check.conf
    sudo systemctl reload NetworkManager
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

sudo nft list ruleset
