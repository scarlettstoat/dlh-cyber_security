#!/bin/bash

# Task 7 - Service Minimizer
# Disable services that are not needed on the billing server.

if [ "$EUID" -ne 0 ]; then
    echo "Please run this script with sudo."
    exit 1
fi

# Services needed by MedDefense.
# SSH is needed for remote administration.
# Apache and MySQL are needed for the billing application.
# UFW protects the network.
# Auditd and AppArmor help with security.
# Cron runs scheduled jobs.
# Rsyslog stores system logs.
# Timesyncd keeps the system clock correct.

required=(
    ssh.service
    apache2.service
    mysql.service
    ufw.service
    auditd.service
    apparmor.service
    cron.service
    rsyslog.service
    systemd-timesyncd.service
)

echo "[*] Scanning enabled services..."

# Save the list so we can compare before and after.
services=$(mktemp)

systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager | awk '{print $1}' > "$services"

before=$(wc -l < "$services")

echo "    Enabled services found: $before"
echo "[*] Comparing against MedDefense whitelist (${#required[@]} required services)..."

disabled=0

# Check every enabled service.
while read -r service; do

    # Check whether the service is on our whitelist.
    keep=no

    for allowed in "${required[@]}"; do
        if [ "$service" = "$allowed" ]; then
            keep=yes
            break
        fi
    done

    # Keep important Ubuntu system and network services.
    # Disabling these could stop the server working.
    case "$service" in
        systemd-*|dbus.service|networking.service|NetworkManager.service|polkit.service|getty@*.service)
            keep=yes
            ;;
    esac

    if [ "$keep" = "yes" ]; then
        continue
    fi

    # Stop and disable services that are not needed.
    if systemctl stop "$service" > /dev/null 2>&1; then
        echo "  $service [STOPPED]"
    else
        echo "  $service [STOP FAILED]"
    fi

    if systemctl disable "$service" > /dev/null 2>&1; then
        echo "  $service [DISABLED]"
        disabled=$((disabled + 1))
    else
        echo "  $service [DISABLE FAILED]"
    fi

done < "$services"

# Check that our required services are running.
echo "[*] Checking required services..."

for service in "${required[@]}"; do

    if systemctl is-active --quiet "$service"; then
        echo "  $service [ACTIVE]"
    else
        echo "  $service [NOT RUNNING]"
    fi

done

# Count enabled services again.
after=$(systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager | awk 'END {print NR}')

echo "Before: $before | After: $after | Disabled: $disabled"

# Remove the temporary file.
rm -f "$services"

