
#!/bin/bash

# Task 4 - SSH hardening
# Disable password logins and limit SSH access.

CONFIG="/etc/ssh/sshd_config"
BACKUP="/etc/ssh/sshd_config.bak"

if [ "$EUID" -ne 0 ]; then
    echo "Please run this script with sudo."
    exit 1
fi

# Make sure the allowed accounts exist before changing SSH access.
for user in medadmin sysadmin; do
    if ! id "$user" &>/dev/null; then
        echo "User $user does not exist. SSH settings not changed."
        exit 1
    fi
done

echo "[*] Backing up $CONFIG"
cp -p "$CONFIG" "$BACKUP" || exit 1

echo "[*] Applying SSH hardening settings..."

# Put our settings first so they take priority over the defaults.
# Remove the previous block if the script is run again.
{
    cat <<'EOF'
# START MedDefense settings

# Stop attackers from logging in directly as root.
PermitRootLogin no

# Prevent brute-force password attacks.
PasswordAuthentication no
KbdInteractiveAuthentication no

# Block accounts with empty passwords.
PermitEmptyPasswords no

# Disable X11 forwarding as it is not needed.
X11Forwarding no

# Limit repeated login attempts.
MaxAuthTries 3

# Close connections from unresponsive clients.
ClientAliveInterval 300
ClientAliveCountMax 2

# Only approved administrators can connect.
AllowUsers medadmin sysadmin

# SSH Protocol 2 is already enforced by modern OpenSSH.

# Limit how long users have to log in.
LoginGraceTime 60

# Show a warning before login.
Banner /etc/issue.net

# END MedDefense settings
EOF

    sed '/^# START MedDefense settings$/,/^# END MedDefense settings$/d' "$BACKUP"
} > "$CONFIG"

echo "[*] Creating SSH warning banner..."

cat > /etc/issue.net <<'EOF'
MedDefense Health Systems
Authorized access only.
Unauthorized access is prohibited.
System activity may be monitored.
EOF

chmod 644 /etc/issue.net

echo "[*] Checking SSH configuration..."

if /usr/sbin/sshd -t; then
    echo "    sshd -t: OK"
else
    echo "    Configuration failed. Restoring backup."
    cp -p "$BACKUP" "$CONFIG"
    exit 1
fi

echo "[*] Restarting SSH..."

if systemctl restart ssh; then
    echo "    ssh.service: $(systemctl is-active ssh)"
else
    echo "    SSH restart failed. Restoring backup."
    cp -p "$BACKUP" "$CONFIG"
    systemctl restart ssh
    exit 1
fi

echo "SSH hardening completed."

