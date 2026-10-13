#!/bin/bash

# Task 13 - Firewall Baseline
# Configure UFW to allow only the required MedDefense services.

set -e

# Approved networks from the MedDefense assignment.
MGMT_NET="10.10.1.0/24"
APP_NET="10.10.2.0/24"

# Check root privileges.
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script with sudo."
    exit 1
fi

# Avoid changing firewall rules through an SSH connection.
if [ -n "${SSH_CONNECTION:-}" ] || [ -n "${SSH_CLIENT:-}" ]; then
    echo "Run this script from the VM console, not SSH."
    exit 1
fi

# Check whether UFW is installed.
echo "[*] Checking UFW..."

if ! command -v ufw > /dev/null 2>&1; then
    echo "    Installing UFW..."
    apt-get install -y ufw
else
    echo "    UFW is already installed."
fi

# Do not overwrite an existing active firewall configuration.
if ufw status | grep -q "Status: active"; then
    echo "UFW is already active."
    echo "Review the existing rules before making changes."
    exit 1
fi

# Check for rules saved from an earlier configuration.
# We do not want to erase important firewall rules.
if ufw show added | grep -q '^ufw '; then
    echo "Existing UFW rules found."
    echo "Review these rules before applying the baseline."
    ufw show added
    exit 1
fi

echo "[*] Configuring UFW..."

# Block incoming traffic unless we explicitly allow it.
ufw default deny incoming
echo "    Default incoming: deny"

# Allow outgoing traffic.
ufw default allow outgoing
echo "    Default outgoing: allow"

echo "[*] Adding allow rules..."

# SSH - only administrators on the management network.
ufw allow from "$MGMT_NET" to any port 22 proto tcp
echo "    22/tcp from $MGMT_NET [ADDED] SSH"

# HTTP - public web access.
ufw allow 80/tcp
echo "    80/tcp [ADDED] HTTP"

# HTTPS - encrypted web access.
ufw allow 443/tcp
echo "    443/tcp [ADDED] HTTPS"

# MySQL - only applications on the approved network.
ufw allow from "$APP_NET" to any port 3306 proto tcp
echo "    3306/tcp from $APP_NET [ADDED] MySQL"

# Log blocked connections for later investigation.
echo "[*] Enabling firewall logging..."

ufw logging low
echo "    Logging: on (low)"

# Activate the firewall.
echo "[*] Activating firewall..."

ufw --force enable

# Verify that UFW is running.
if ufw status | grep -q "Status: active"; then
    echo "    UFW: active"
else
    echo "    UFW failed to activate."
    exit 1
fi

# Display the active rules.
echo "[*] Verifying firewall configuration..."

ufw status verbose

echo "Firewall baseline configured."
echo "Expected allow rules: 4"
echo "Default incoming: deny"
echo "Default outgoing: allow"

