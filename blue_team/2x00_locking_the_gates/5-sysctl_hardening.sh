#!/bin/bash

# Task 5 - Kernel Shield
# Improve network and kernel security on the billing server.

CONFIG="/etc/sysctl.conf"
BACKUP="/etc/sysctl.conf.bak"

if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo."
    exit 1
fi

# Back up the original configuration.
echo "[*] Backing up $CONFIG"
cp -p "$CONFIG" "$BACKUP" || exit 1

echo "[*] Applying kernel hardening parameters..."

# Remove old MedDefense settings if the script runs again.
sed -i '/# START MedDefense settings/,/# END MedDefense settings/d' "$CONFIG"

# Add the security settings.
cat >> "$CONFIG" <<'EOF'

# START MedDefense settings

# Prevent IP forwarding and unwanted redirects.
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0

# Protect against suspicious network traffic.
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable IPv6.
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Improve memory and kernel protection.
kernel.randomize_va_space = 2
fs.suid_dumpable = 0
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2

# END MedDefense settings
EOF

# Apply the changes immediately.
if ! sysctl -p > /dev/null; then
    echo "Warning: Some settings could not be applied."
fi

passed=0
failed=0

# Check that each setting has the correct value.
check_setting() {
    name=$1
    expected=$2

    # Convert the setting name into a /proc/sys/ path.
    path="/proc/sys/$(echo "$name" | tr '.' '/')"
    actual=$(cat "$path" 2>/dev/null)

    if [ "$actual" = "$expected" ]; then
        echo "$name = $expected [PASS]"
        passed=$((passed + 1))
    else
        echo "$name = $expected [FAIL]"
        failed=$((failed + 1))
    fi
}

# Check all 14 settings.
check_setting net.ipv4.ip_forward 0
check_setting net.ipv4.conf.all.accept_redirects 0
check_setting net.ipv4.conf.default.accept_redirects 0
check_setting net.ipv4.conf.all.send_redirects 0
check_setting net.ipv4.conf.all.accept_source_route 0
check_setting net.ipv4.conf.all.log_martians 1
check_setting net.ipv4.tcp_syncookies 1
check_setting net.ipv4.icmp_echo_ignore_broadcasts 1
check_setting net.ipv6.conf.all.disable_ipv6 1
check_setting net.ipv6.conf.default.disable_ipv6 1
check_setting kernel.randomize_va_space 2
check_setting fs.suid_dumpable 0
check_setting kernel.dmesg_restrict 1
check_setting kernel.kptr_restrict 2

echo "Parameters applied: 14"
echo "Verified PASS: $passed"
echo "Verified FAIL: $failed"

if [ "$failed" -gt 0 ]; then
    exit 1
fi

