#!/bin/bash

set -e

CONN=$(nmcli -g NAME,TYPE connection | awk -F : '/.*ethernet.*/ { print $1 }')
echo "Using connection: ${CONN}"

echo "Adding nf_conntrack module..."
sudo modprobe nf_conntrack

echo "Making directories..."
sudo mkdir -p /etc/systemd/resolved.conf.d/

echo "Copying configuration files..."
sudo cp ./sysctl.conf /etc/sysctl.d/90-custom.conf
sudo cp ./default.conf /etc/systemd/resolved.conf.d/dns-over-tls.conf
sudo cp ./nftables.conf /etc/nftables.conf

echo "Making files executable..."
sudo chmod u+x /etc/nftables.conf

echo "Importing custom configurations..."
sudo sysctl -p /etc/sysctl.d/90-custom.conf
sudo /etc/nftables.conf

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

echo "Finished, command outputs as follows:"
nmcli
resolvectl
sudo nft list ruleset
