#!/bin/bash

# Task 8 - PAM Fortress
# Set password rules, account lockout and password history.
# Written for the MedDefense Ubuntu 22.04 billing server.

QUALITY="/etc/security/pwquality.conf"
FAILLOCK="/etc/security/faillock.conf"
AUTH="/etc/pam.d/common-auth"
PASSWORD="/etc/pam.d/common-password"

# PAM changes need root privileges.
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script with sudo."
    exit 1
fi

# Do not change login settings through a remote SSH session.
if [ -n "${SSH_CONNECTION:-}" ]; then
    echo "Run this from the Ubuntu VM console, not SSH."
    exit 1
fi

# Check that password quality is installed.
echo "[*] Checking libpam-pwquality..."

if dpkg -s libpam-pwquality > /dev/null 2>&1; then
    echo "    libpam-pwquality is already installed."
else
    echo "    Installing libpam-pwquality..."
    apt-get install -y libpam-pwquality || exit 1
fi

# Make sure the required PAM files exist.
for file in "$QUALITY" "$FAILLOCK" "$AUTH" "$PASSWORD"; do
    if [ ! -f "$file" ]; then
        echo "Missing file: $file"
        exit 1
    fi
done

# Check the authentication modules are available.
for module in pam_pwquality pam_faillock pam_pwhistory; do
    if [ ! -f "/lib/x86_64-linux-gnu/security/$module.so" ]; then
        echo "Missing PAM module: $module"
        exit 1
    fi
done

# Only continue if the Ubuntu PAM configuration matches
# the basic configuration we checked earlier.
if ! grep -Eq '^auth[[:space:]]+\[success=1 default=ignore\][[:space:]]+pam_unix.so' "$AUTH"; then
    echo "Unexpected authentication configuration. No changes made."
    exit 1
fi

if ! grep -Eq '^password[[:space:]]+requisite[[:space:]]+pam_pwquality.so' "$PASSWORD"; then
    echo "Password quality rule not found. No changes made."
    exit 1
fi

# Avoid adding duplicate PAM rules.
if grep -Eq '^[[:space:]]*auth.*pam_faillock.so' "$AUTH"; then
    echo "pam_faillock is already configured. Check manually."
    exit 1
fi

if grep -Eq '^[[:space:]]*password.*pam_pwhistory.so' "$PASSWORD"; then
    echo "Password history is already configured. Check manually."
    exit 1
fi

# Stop if these security settings are already customized.
if grep -Eq '^[[:space:]]*(minlen|dcredit|ucredit|lcredit|ocredit|maxrepeat|usercheck)[[:space:]]*=' "$QUALITY"; then
    echo "Existing password policy found. Check manually."
    exit 1
fi

if grep -Eq '^[[:space:]]*(deny|unlock_time|fail_interval)[[:space:]]*=' "$FAILLOCK"; then
    echo "Existing lockout policy found. Check manually."
    exit 1
fi

# Back up all configuration files before changing anything.
echo "[*] Backing up PAM configuration..."

for file in "$QUALITY" "$FAILLOCK" "$AUTH" "$PASSWORD"; do
    cp -p "$file" "$file.bak" || exit 1
done

# Restore the backups if a check fails.
restore() {
    echo "Configuration check failed. Restoring backups."

    for file in "$QUALITY" "$FAILLOCK" "$AUTH" "$PASSWORD"; do
        cp -p "$file.bak" "$file"
    done

    exit 1
}

# Password complexity settings.
echo "[*] Configuring password quality..."

cat >> "$QUALITY" <<'EOF' || restore

# MedDefense password policy
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
usercheck = 1
EOF

# Configure account lockout after 5 failed attempts.
echo "[*] Configuring account lockout..."

cat >> "$FAILLOCK" <<'EOF' || restore

# MedDefense account lockout
deny = 5
unlock_time = 900
fail_interval = 900
EOF

# Add faillock before and after password authentication.
# The order matters because PAM checks rules in sequence.
sed -i '/^auth.*pam_unix.so/i auth requisite pam_faillock.so preauth' "$AUTH" || restore

sed -i '/^auth.*pam_unix.so/a auth [default=die] pam_faillock.so authfail' "$AUTH" || restore

sed -i '/^auth.*pam_deny.so/a auth required pam_faillock.so authsucc' "$AUTH" || restore

# Successful authentication must skip the failure rules.
sed -i 's/\[success=1 default=ignore\]/[success=2 default=ignore]/' "$AUTH" || restore

# Prevent users from reusing their previous 12 passwords.
echo "[*] Configuring password history..."

sed -i '/^password.*pam_pwquality.so/a password required pam_pwhistory.so use_authtok remember=12' "$PASSWORD" || restore

# Verify the settings were saved.
echo "[*] Validating PAM configuration..."

for setting in \
    "minlen = 14" \
    "dcredit = -1" \
    "ucredit = -1" \
    "lcredit = -1" \
    "ocredit = -1" \
    "maxrepeat = 3" \
    "usercheck = 1"; do

    grep -Fxq "$setting" "$QUALITY" || restore
    echo "    $setting [SET]"
done

for setting in \
    "deny = 5" \
    "unlock_time = 900" \
    "fail_interval = 900"; do

    grep -Fxq "$setting" "$FAILLOCK" || restore
    echo "    $setting [SET]"
done

# Check the PAM modules were added.
grep -Fq 'pam_faillock.so preauth' "$AUTH" || restore
grep -Fq 'pam_faillock.so authfail' "$AUTH" || restore
grep -Fq 'pam_faillock.so authsucc' "$AUTH" || restore
grep -Fq '[success=2 default=ignore]' "$AUTH" || restore
grep -Fq 'pam_pwhistory.so use_authtok remember=12' "$PASSWORD" || restore

echo "    pam_faillock rules [SET]"
echo "    Password history: remember = 12 [SET]"

echo "Password minimum length: 14 | Lockout: 5 attempts / 15 min | History: 12"
echo "PAM configuration file checks completed."

