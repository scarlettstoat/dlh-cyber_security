#!/bin/bash

# Task 10 - Audit Engine
# Configure auditd to monitor security events on billing-srv-01.

RULES="/etc/audit/rules.d/meddefense.rules"

# Check root privileges.
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script with sudo."
    exit 1
fi

# Check auditd is installed.
echo "[*] Checking auditd..."

if dpkg -s auditd > /dev/null 2>&1; then
    echo "    auditd is already installed."
else
    echo "    Installing auditd..."
    apt-get install -y auditd || exit 1
fi

# Enable and start auditd.
echo "[*] Enabling auditd service..."

if systemctl enable --now auditd; then
    echo "    auditd.service: $(systemctl is-active auditd)"
else
    echo "    Failed to start auditd."
    exit 1
fi

# Check that audit rules can be changed.
if auditctl -s | grep -q "enabled 2"; then
    echo "Audit rules are locked until reboot."
    exit 1
fi

# Check the files and folders we want to monitor.
for path in \
    /etc/passwd \
    /etc/shadow \
    /etc/group \
    /etc/pam.d \
    /etc/ssh/sshd_config \
    /usr/bin/sudo \
    /usr/bin/su \
    /etc/sudoers \
    /usr/bin/wget \
    /usr/bin/curl \
    /usr/bin/nc \
    /var/lib/mysql \
    /etc/apache2 \
    /etc/init.d
do
    if [ ! -e "$path" ]; then
        echo "Missing path: $path"
        exit 1
    fi
done

# Back up existing MedDefense rules, if any.
if [ -f "$RULES" ]; then
    echo "[*] Backing up existing MedDefense rules..."
    cp -p "$RULES" "$RULES.bak" || exit 1
fi

echo "[*] Deploying MedDefense audit rules..."

# Create our audit rules file.
# -w = watch a file or directory
# -p = permissions to monitor
# -k = keyword used when searching audit logs

cat > "$RULES" <<'EOF'
# MedDefense audit rules

# Monitor changes to user and group information.
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity

# Monitor authentication and SSH configuration changes.
-w /etc/pam.d/ -p wa -k pam_config
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Monitor privilege escalation.
-w /usr/bin/sudo -p x -k priv_esc
-w /usr/bin/su -p x -k priv_esc
-w /etc/sudoers -p wa -k sudoers

# Monitor execution of suspicious tools.
-w /usr/bin/wget -p x -k suspicious_download
-w /usr/bin/curl -p x -k suspicious_download
-w /usr/bin/nc -p x -k suspicious_netcat

# Monitor important MedDefense application files.
-w /var/lib/mysql/ -p wa -k meddefense_db
-w /etc/apache2/ -p wa -k meddefense_web
-w /etc/init.d/ -p wa -k startup_scripts
EOF

chmod 640 "$RULES"

# Show the rules we added.
grep '^-w' "$RULES" | while read -r rule; do
    echo "    $rule [ADDED]"
done

# Load the new rules into the running audit system.
echo "[*] Loading audit rules..."

if augenrules --load; then
    echo "    augenrules --load: OK"
else
    echo "    Failed to load audit rules."
    echo "    Check auditd configuration before retrying."
    exit 1
fi

# Check that the rules are actually active.
echo "[*] Verifying active audit rules..."

loaded=0
failed=0

# Compare our rules with the active rules.
while IFS= read -r rule; do

    if [[ "$rule" == -w* ]]; then

        if auditctl -l | grep -Fxq -- "$rule"; then
            loaded=$((loaded + 1))
        else
            echo "    Missing rule: $rule"
            failed=$((failed + 1))
        fi

    fi

done < "$RULES"

echo "    Rules verified: $loaded"
echo "    Rules missing: $failed"

if [ "$failed" -gt 0 ]; then
    echo "Some audit rules are not active."
    exit 1
fi

# Test auditing by executing sudo.
# This should trigger our priv_esc rule.
echo "[*] Testing audit event detection..."

# Run a harmless command through sudo.
# Save its process ID so we can search for that event.
sudo -n true &
test_pid=$!

if ! wait "$test_pid"; then
    echo "    Test command failed."
    exit 1
fi

# Give auditd a moment to write the event.
sleep 1

if ausearch -k priv_esc -p "$test_pid" -ts recent > /dev/null 2>&1; then
    echo "    sudo execution recorded [PASS]"
else
    echo "    Audit event not found [FAIL]"
    exit 1
fi

echo "Auditd configuration completed."
echo "MedDefense rules verified: $loaded"
echo "Test event: PASS"

