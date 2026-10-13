#!/bin/bash

# Task 15 - Final Security Validation
# MedDefense Health Systems
# Check whether the hardening controls are active.
# This script only checks settings. It does not change them.

set -u

PASS=0
FAIL=0

# Check root privileges.
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script with sudo."
    exit 1
fi

# Run a check and record its result.
check() {
    local description="$1"
    shift

    if "$@" > /dev/null 2>&1; then
        echo "[PASS] $description"
        PASS=$((PASS + 1))
    else
        echo "[FAIL] $description"
        FAIL=$((FAIL + 1))
    fi
}

# Check an effective SSH setting.
ssh_setting() {
    local name="$1"
    local expected="$2"

    sshd -T 2>/dev/null | awk \
        -v key="$name" -v value="$expected" \
        '$1 == key && $2 == value {found=1}
         END {exit !found}'
}

# Check an active kernel setting.
sysctl_setting() {
    local name="$1"
    local expected="$2"
    local actual

    actual=$(sysctl -n "$name" 2>/dev/null) || return 1
    [ "$actual" = "$expected" ]
}

# Check that a file belongs to root.
root_owned() {
    [ "$(stat -c '%U' "$1" 2>/dev/null)" = "root" ]
}

# Check that a file is not writable by group or others.
secure_file() {
    local mode

    mode=$(stat -c '%a' "$1" 2>/dev/null) || return 1
    [[ "$mode" =~ ^[0-7]+$ ]] || return 1

    (( (8#$mode & 0022) == 0 ))
}

# Check that a file is not accessible by other users.
no_other_access() {
    local mode

    mode=$(stat -c '%a' "$1" 2>/dev/null) || return 1
    [[ "$mode" =~ ^[0-7]+$ ]] || return 1

    (( (8#$mode & 0007) == 0 ))
}

# Check that a temporary directory has the sticky bit.
sticky_bit() {
    local mode

    mode=$(stat -c '%a' "$1" 2>/dev/null) || return 1
    [[ "$mode" =~ ^[0-7]+$ ]] || return 1

    (( (8#$mode & 01000) != 0 ))
}

# Check that an unnecessary service is stopped and disabled.
service_disabled() {
    local service="$1"

    ! systemctl is-active --quiet "$service" &&
    ! systemctl is-enabled --quiet "$service"
}

# Check whether a PAM module is configured.
pam_module() {
    local module="$1"

    grep -Eq "^[[:space:]]*(auth|account|password)[[:space:]].*pam_${module}\.so" \
        /etc/pam.d/common-auth \
        /etc/pam.d/common-account \
        /etc/pam.d/common-password 2>/dev/null
}

# Check audit rules by their configured key.
audit_key() {
    local key="$1"

    auditctl -l 2>/dev/null |
        grep -Eq "(-k[[:space:]]+${key}([[:space:]]|$)|key=${key}([[:space:]]|$))"
}

# Check that a log file has restricted permissions.
log_secure() {
    local file="$1"
    local mode owner

    mode=$(stat -c '%a' "$file" 2>/dev/null) || return 1
    owner=$(stat -c '%U' "$file" 2>/dev/null) || return 1

    [[ "$mode" =~ ^[0-7]+$ ]] || return 1
    [[ "$owner" = "root" || "$owner" = "syslog" ]] || return 1

    (( (8#$mode & 0027) == 0 ))
}

# Check the retention policy in the MedDefense rotation file.
rotation_policy() {
    local filename="$1"
    local days="$2"
    local config="/etc/logrotate.d/meddefense"

    [ -f "$config" ] || return 1

    awk -v file="/var/log/$filename" -v days="$days" '
        $1 == file && $2 == "{" {inside=1; next}
        inside && $1 == "rotate" && $2 == days {found=1}
        inside && $1 == "}" {inside=0}
        END {exit !found}
    ' "$config"
}

# Check active UFW rules.
ufw_rule() {
    ufw status 2>/dev/null | grep -Eq "$1"
}

echo "========================================"
echo " MedDefense Security Validation"
echo "========================================"

echo ""
echo "TASK 4 - SSH HARDENING"

check "SSH configuration is valid" sshd -t
check "SSH root login disabled" ssh_setting permitrootlogin no
check "SSH password authentication disabled" ssh_setting passwordauthentication no
check "SSH X11 forwarding disabled" ssh_setting x11forwarding no

echo ""
echo "TASK 5 - KERNEL HARDENING"

check "IP forwarding disabled" \
    sysctl_setting net.ipv4.ip_forward 0

check "ICMP broadcast requests ignored" \
    sysctl_setting net.ipv4.icmp_echo_ignore_broadcasts 1

check "TCP SYN cookies enabled" \
    sysctl_setting net.ipv4.tcp_syncookies 1

check "ASLR enabled" \
    sysctl_setting kernel.randomize_va_space 2

check "Core dumps from privileged programs disabled" \
    sysctl_setting fs.suid_dumpable 0

echo ""
echo "TASK 6 - FILESYSTEM HARDENING"

check "/etc/passwd owned by root" root_owned /etc/passwd
check "/etc/passwd permissions secure" secure_file /etc/passwd
check "/etc/shadow owned by root" root_owned /etc/shadow
check "/etc/shadow not accessible to others" no_other_access /etc/shadow
check "/tmp sticky bit enabled" sticky_bit /tmp
check "/var/tmp sticky bit enabled" sticky_bit /var/tmp

echo ""
echo "TASK 7 - SERVICE MINIMIZATION"

check "Avahi disabled" service_disabled avahi-daemon.service
check "CUPS disabled" service_disabled cups.service
check "Bluetooth disabled" service_disabled bluetooth.service
check "RPC bind disabled" service_disabled rpcbind.service

echo ""
echo "TASK 8 - PAM HARDENING"

check "PAM account lockout module configured" pam_module faillock
check "PAM password quality module configured" pam_module pwquality

echo ""
echo "TASK 9 - APPARMOR"

check "AppArmor enabled" aa-status --enabled

echo ""
echo "TASKS 10 AND 11 - AUDIT LOGGING"

check "Auditd service running" systemctl is-active --quiet auditd

check "Kernel auditing enabled" \
    bash -c 'auditctl -s 2>/dev/null | grep -Eq "^enabled[[:space:]]+1$"'

check "Privilege escalation audit rule loaded" audit_key priv_esc
check "Identity audit rule loaded" audit_key identity
check "SSH configuration audit rule loaded" audit_key sshd_config
check "Suspicious download audit rule loaded" audit_key suspicious_download

echo ""
echo "TASK 12 - LOG MANAGEMENT"

check "Rsyslog service running" systemctl is-active --quiet rsyslog
check "Rsyslog configuration valid" rsyslogd -N1
check "Authentication log permissions secure" log_secure /var/log/auth.log
check "System log permissions secure" log_secure /var/log/syslog
check "Authentication log retention: 90 days" rotation_policy auth.log 90
check "System log retention: 60 days" rotation_policy syslog 60

echo ""
echo "TASK 13 - FIREWALL"

check "UFW active" \
    bash -c 'ufw status | grep -Fxq "Status: active"'

check "Default incoming deny and outgoing allow" \
    bash -c 'ufw status verbose | grep -Eq "Default: deny \(incoming\), allow \(outgoing\)"'

check "SSH restricted to management network" \
    ufw_rule '^22/tcp[[:space:]]+ALLOW[[:space:]]+10\.10\.1\.0/24'

check "HTTP allowed" \
    ufw_rule '^80/tcp[[:space:]]+ALLOW[[:space:]]+Anywhere'

check "HTTPS allowed" \
    ufw_rule '^443/tcp[[:space:]]+ALLOW[[:space:]]+Anywhere'

check "MySQL restricted to application network" \
    ufw_rule '^3306/tcp[[:space:]]+ALLOW[[:space:]]+10\.10\.2\.0/24'

check "UFW logging enabled" \
    bash -c 'ufw status verbose | grep -Eq "Logging: on \(low\)"'

# Final results.
TOTAL=$((PASS + FAIL))

echo ""
echo "========================================"
echo " FINAL VALIDATION RESULTS"
echo "========================================"
echo "Total checks: $TOTAL"
echo "PASS: $PASS"
echo "FAIL: $FAIL"

if [ "$FAIL" -eq 0 ]; then
    echo "RESULT: PASS"
    echo "All checked security controls are configured."
    exit 0
else
    echo "RESULT: FAIL"
    echo "Some security controls need attention."
    exit 1
fi

