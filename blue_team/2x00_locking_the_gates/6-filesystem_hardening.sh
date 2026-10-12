#!/bin/bash

# Task 6 - Permission Sweep
# Check risky file permissions and restrict access.

if [ "$EUID" -ne 0 ]; then
    echo "Please run this script with sudo."
    exit 1
fi

# Temporary folder for storing our lists.
WORK=$(mktemp -d)

# Allowed SUID programs on Ubuntu 22.04.
cat > "$WORK/suid_allow" <<'EOF'
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/su
/usr/bin/mount
/usr/bin/umount
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/fusermount3
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
EOF

# Allowed SGID programs.
cat > "$WORK/sgid_allow" <<'EOF'
/usr/bin/chage
/usr/bin/expiry
/usr/bin/wall
/usr/bin/ssh-agent
/usr/bin/crontab
/usr/bin/at
/usr/bin/bsd-write
/usr/bin/dotlockfile
/usr/bin/locate
/usr/bin/mlocate
EOF

# Find SUID and SGID files.
# Skip virtual system folders.
find / \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o -type f -perm -4000 -print 2>/dev/null > "$WORK/suid_files"

find / \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o -type f -perm -2000 -print 2>/dev/null > "$WORK/sgid_files"

# Check SUID files.
suid_found=$(wc -l < "$WORK/suid_files")
suid_ok=0
suid_fixed=0

echo "Found $suid_found SUID binaries"

while IFS= read -r file; do
    if grep -Fxq "$file" "$WORK/suid_allow"; then
        suid_ok=$((suid_ok + 1))
    elif chmod u-s "$file"; then
        echo "  $file [SUID REMOVED]"
        suid_fixed=$((suid_fixed + 1))
    else
        echo "  $file [FAILED]"
    fi
done < "$WORK/suid_files"

echo "Whitelisted: $suid_ok"
echo "Non-whitelisted: $((suid_found - suid_ok))"

# Check SGID files.
sgid_found=$(wc -l < "$WORK/sgid_files")
sgid_ok=0
sgid_fixed=0

echo "Found $sgid_found SGID binaries"

while IFS= read -r file; do
    if grep -Fxq "$file" "$WORK/sgid_allow"; then
        sgid_ok=$((sgid_ok + 1))
    elif chmod g-s "$file"; then
        echo "  $file [SGID REMOVED]"
        sgid_fixed=$((sgid_fixed + 1))
    else
        echo "  $file [FAILED]"
    fi
done < "$WORK/sgid_files"

echo "Whitelisted: $sgid_ok"
echo "Non-whitelisted: $((sgid_found - sgid_ok))"

# Find files that anyone can write to.
find / \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o -type f -perm -0002 -print 2>/dev/null > "$WORK/writable_files"

# Check writable directories without the sticky bit.
# Leave shared folders like /tmp alone.
find / \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o -type d -perm -0002 ! -perm -1000 -print 2>/dev/null > "$WORK/writable_dirs"

file_count=$(wc -l < "$WORK/writable_files")
dir_count=$(wc -l < "$WORK/writable_dirs")

echo "Found $((file_count + dir_count)) world-writable files/directories"

writable_fixed=0

for list in "$WORK/writable_files" "$WORK/writable_dirs"; do
    while IFS= read -r file; do
        if chmod o-w "$file"; then
            echo "  $file [FIXED]"
            writable_fixed=$((writable_fixed + 1))
        else
            echo "  $file [FAILED]"
        fi
    done < "$list"
done

# Check mount options for temporary directories.
check_mount() {
    dir="$1"

    if [ ! -d "$dir" ]; then
        echo "$dir: [NOT FOUND]"
        return
    fi

    options=$(findmnt -n -M "$dir" -o OPTIONS 2>/dev/null)

    if [[ "$options" == *noexec* && "$options" == *nosuid* && "$options" == *nodev* ]]; then
        echo "$dir: noexec,nosuid,nodev [OK]"
        return
    fi

    # Apply the mount options if they are missing.
    if mountpoint -q "$dir"; then
        mount -o remount,noexec,nosuid,nodev "$dir"
    else
        mount --bind "$dir" "$dir" && mount -o remount,bind,noexec,nosuid,nodev "$dir"
    fi

    # Check the options again.
    options=$(findmnt -n -M "$dir" -o OPTIONS 2>/dev/null)

    if [[ "$options" == *noexec* && "$options" == *nosuid* && "$options" == *nodev* ]]; then
        echo "$dir: noexec,nosuid,nodev [APPLIED]"
    else
        echo "$dir: [FAILED]"
    fi
}

check_mount /tmp
check_mount /var/tmp
check_mount /dev/shm

# Limit cron access to approved users.
printf 'root\nmedadmin\nsysadmin\n' > /etc/cron.allow
chmod 600 /etc/cron.allow

echo "Cron access limited to root, medadmin and sysadmin"

# Print the results.
echo "SUID remediated: $suid_fixed | SGID remediated: $sgid_fixed | World-writable fixed: $writable_fixed"

# Delete the temporary files.
rm -rf "$WORK"

