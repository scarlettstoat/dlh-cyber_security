#!/bin/bash

# Task 0 - Baseline Snapshot
# Record the current security settings before hardening billing-srv-01.

if [ "$EUID" -ne 0 ]; then
    echo "Please run this script with sudo."
    exit 1
fi

umask 077

REPORT="/var/tmp/baseline_snapshot_$(date +%Y%m%d_%H%M%S).json"
TEMP=$(mktemp -d)
trap 'rm -rf "$TEMP"' EXIT

# 1. System information
hostname > "$TEMP/hostname"
grep '^PRETTY_NAME=' /etc/os-release | cut -d= -f2- | tr -d '"' > "$TEMP/os"
uname -r > "$TEMP/kernel"
uptime -p > "$TEMP/uptime"

# 2. Running services
systemctl list-units --type=service --state=running \
    --no-legend --no-pager > "$TEMP/services" 2>/dev/null || true

# 3. Open ports and listening sockets
ss -tulnpH > "$TEMP/ports" 2>/dev/null || true

# 4. SUID and SGID binaries
find / -xdev -type f -perm -4000 -print \
    > "$TEMP/suid" 2>/dev/null

find / -xdev -type f -perm -2000 -print \
    > "$TEMP/sgid" 2>/dev/null

# 5. World-writable files
find / -xdev -type f -perm -0002 \
    ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' \
    -print > "$TEMP/world_writable" 2>/dev/null

# 6. Security-related sysctl settings
for key in \
    net.ipv4.ip_forward \
    net.ipv4.tcp_syncookies \
    net.ipv4.conf.all.accept_redirects \
    net.ipv4.conf.all.send_redirects \
    net.ipv4.conf.all.accept_source_route \
    net.ipv4.conf.all.log_martians \
    kernel.randomize_va_space \
    kernel.dmesg_restrict \
    kernel.kptr_restrict \
    fs.suid_dumpable
do
    sysctl "$key" 2>/dev/null || true
done > "$TEMP/sysctl"

# 7. SSH configuration
if [ -x /usr/sbin/sshd ]; then
    /usr/sbin/sshd -T > "$TEMP/ssh" 2>/dev/null || true
fi

if [ ! -s "$TEMP/ssh" ]; then
    grep -hEv '^[[:space:]]*(#|$)' \
        /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf \
        > "$TEMP/ssh" 2>/dev/null || true
fi

# 8. User accounts and sudo members
getent passwd | awk -F: \
    '($3 == 0 || ($3 >= 1000 && $3 < 65534)) && $7 !~ /(nologin|false)$/ {
        print $1 " UID=" $3 " Shell=" $7
    }' > "$TEMP/users"

getent group sudo | cut -d: -f4 > "$TEMP/sudo_members"

# Save the collected information as valid JSON
python3 - "$TEMP" "$REPORT" <<'PY'
import json
import sys
from pathlib import Path

folder = Path(sys.argv[1])
output = sys.argv[2]

def read(name):
    return (folder / name).read_text().splitlines()

report = {
    "hostname": read("hostname")[0],
    "os": read("os")[0],
    "kernel": read("kernel")[0],
    "uptime": read("uptime")[0],
    "running_services": read("services"),
    "listening_sockets": read("ports"),
    "suid_binaries": read("suid"),
    "sgid_binaries": read("sgid"),
    "world_writable_files": read("world_writable"),
    "sysctl": read("sysctl"),
    "ssh_configuration": read("ssh"),
    "user_accounts": read("users"),
    "sudo_members": read("sudo_members")
}

with open(output, "w") as file:
    json.dump(report, file, indent=2)

print("Hostname:", report["hostname"])
print("OS:", report["os"])
print("Running services:", len(report["running_services"]))
print("Open ports:", len(report["listening_sockets"]))
print("SUID binaries:", len(report["suid_binaries"]))
print("SGID binaries:", len(report["sgid_binaries"]))
print("World-writable files:", len(report["world_writable_files"]))
print("JSON report:", output)
PY
