#!/bin/bash

# Task 8 - PAM Fortress
# Configure password quality, login lockout and password history.
# For the MedDefense Ubuntu 22.04 billing server.

set -e

QUALITY=/etc/security/pwquality.conf
FAILLOCK=/etc/security/faillock.conf
AUTH=/etc/pam.d/common-auth
PASSWORD=/etc/pam.d/common-password

# Check root access.
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script with sudo."
    exit 1
fi

# Do not change login rules during an SSH session.
if [ -n "${SSH_CONNECTION:-}" ]; then
    echo "Run this from the Ubuntu VM console, not SSH."
    exit 1
fi

# Check the required package.
echo "[*] Checking libpam-pwquality..."

if dpkg -s libpam-pwquality > /dev/null 2>&1; then
    echo "    Already installed"
else
    apt-get install -y libpam-pwquality || exit 1
fi

# Check the configuration files exist.
for file in "$QUALITY" "$FAILLOCK" "$AUTH" "$PASSWORD"; do
    if [ ! -f "$file" ]; then
        echo "Missing file: $file"
        exit 1
    fi
done

# Check the three PAM modules.
for module in pam_pwquality pam_faillock pam_pwhistory; do
    if [ ! -f "/lib/x86_64-linux-gnu/security/$module.so" ]; then
        echo "Missing module: $module"
        exit 1
    fi
done

# Check that all required settings are present.
verify() {
    grep -Fxq 'minlen = 14' "$1" &&
    grep -Fxq 'dcredit = -1' "$1" &&
    grep -Fxq 'ucredit = -1' "$1" &&
    grep -Fxq 'lcredit = -1' "$1" &&
    grep -Fxq 'ocredit = -1' "$1" &&
    grep -Fxq 'maxrepeat = 3' "$1" &&
    grep -Fxq 'usercheck = 1' "$1" &&
    grep -Fxq 'deny = 5' "$2" &&
    grep -Fxq 'unlock_time = 900' "$2" &&
    grep -Fxq 'fail_interval = 900' "$2" &&
    grep -Fxq 'auth requisite pam_faillock.so preauth silent' "$3" &&
    grep -Fxq 'auth [success=1 default=bad] pam_unix.so nullok' "$3" &&
    grep -Fxq 'auth [default=die] pam_faillock.so authfail' "$3" &&
    grep -Fxq 'auth sufficient pam_faillock.so authsucc' "$3" &&
    grep -Fxq 'password requisite pam_pwhistory.so use_authtok remember=12' "$4"
}

# If our policy is already configured, do not add it again.
if grep -Fq '# MedDefense PAM lockout' "$AUTH"; then
    if verify "$QUALITY" "$FAILLOCK" "$AUTH" "$PASSWORD"; then
        echo "PAM policy already configured. Nothing to change."
        exit 0
    fi

    echo "Existing MedDefense rules are incomplete. Check manually."
    exit 1
fi

# Avoid overwriting other existing PAM policies.
if grep -Eq '^[[:space:]]*auth[[:space:]].*pam_faillock\.so' "$AUTH" ||
   grep -Eq '^[[:space:]]*password[[:space:]].*pam_pwhistory\.so' "$PASSWORD" ||
   grep -Eq '^[[:space:]]*(minlen|dcredit|ucredit|lcredit|ocredit|maxrepeat|usercheck)[[:space:]]*=' "$QUALITY" ||
   grep -Eq '^[[:space:]]*(deny|unlock_time|fail_interval)[[:space:]]*=' "$FAILLOCK"; then

    echo "Existing PAM settings found. No changes made."
    exit 1
fi

# Check the expected Ubuntu authentication layout.
if [ "$(grep -Ec '^auth[[:space:]]+\[success=1 default=ignore\][[:space:]]+pam_unix\.so[[:space:]]+nullok[[:space:]]*$' "$AUTH")" -ne 1 ] ||
   [ "$(grep -Ec '^password[[:space:]]+requisite[[:space:]]+pam_pwquality\.so[[:space:]]+retry=3[[:space:]]*$' "$PASSWORD")" -ne 1 ]; then

    echo "Unexpected PAM configuration. No changes made."
    exit 1
fi

# Create a separate backup folder.
backup=$(mktemp -d /root/meddefense-pam-backup.XXXXXX)

echo "[*] Backing up PAM configuration to $backup"

for file in "$QUALITY" "$FAILLOCK" "$AUTH" "$PASSWORD"; do
    cp -p "$file" "$backup/$(basename "$file")" || exit 1
done

# Temporary files for preparing the changes.
quality_tmp=""
fail_tmp=""
auth_tmp=""
pass_tmp=""

cleanup() {
    rm -f "$quality_tmp" "$fail_tmp" "$auth_tmp" "$pass_tmp"
}

# Restore the original files if something fails.
rollback() {
    trap - ERR INT TERM

    echo "[!] Error detected. Restoring original PAM files..."

    cp -p "$backup/pwquality.conf" "$QUALITY" || echo "Could not restore pwquality.conf"
    cp -p "$backup/faillock.conf" "$FAILLOCK" || echo "Could not restore faillock.conf"
    cp -p "$backup/common-auth" "$AUTH" || echo "Could not restore common-auth"
    cp -p "$backup/common-password" "$PASSWORD" || echo "Could not restore common-password"

    exit 1
}

trap cleanup EXIT
trap rollback ERR INT TERM

# Prepare copies before changing the real PAM files.
quality_tmp=$(mktemp /etc/security/pwquality.conf.tmp.XXXXXX)
fail_tmp=$(mktemp /etc/security/faillock.conf.tmp.XXXXXX)
auth_tmp=$(mktemp /etc/pam.d/common-auth.tmp.XXXXXX)
pass_tmp=$(mktemp /etc/pam.d/common-password.tmp.XXXXXX)

cp -p "$QUALITY" "$quality_tmp"
cp -p "$FAILLOCK" "$fail_tmp"
cp -p "$AUTH" "$auth_tmp"
cp -p "$PASSWORD" "$pass_tmp"

# Password quality.
echo "[*] Configuring password quality..."

cat >> "$quality_tmp" <<'EOF'

# MedDefense password quality
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
usercheck = 1
EOF

# Account lockout.
echo "[*] Configuring account lockout..."

cat >> "$fail_tmp" <<'EOF'

# MedDefense account lockout
deny = 5
unlock_time = 900
fail_interval = 900
EOF

# Add faillock around the existing Ubuntu password check.
# Success skips authfail and reaches authsucc.
# Failed authentication is recorded by authfail.
awk '
/^auth[[:space:]]+\[success=1 default=ignore\][[:space:]]+pam_unix\.so[[:space:]]+nullok[[:space:]]*$/ {
    print "# MedDefense PAM lockout"
    print "auth requisite pam_faillock.so preauth silent"
    print "auth [success=1 default=bad] pam_unix.so nullok"
    print "auth [default=die] pam_faillock.so authfail"
    print "auth sufficient pam_faillock.so authsucc"
    next
}
{print}
' "$AUTH" > "$auth_tmp"

# Add password history after password quality.
echo "[*] Configuring password history..."

awk '
/^password[[:space:]]+requisite[[:space:]]+pam_pwquality\.so[[:space:]]+retry=3[[:space:]]*$/ {
    print
    print "# MedDefense password history"
    print "password requisite pam_pwhistory.so use_authtok remember=12"
    next
}
{print}
' "$PASSWORD" > "$pass_tmp"

# Check the prepared files before applying them.
echo "[*] Validating new configuration files..."

verify "$quality_tmp" "$fail_tmp" "$auth_tmp" "$pass_tmp" || rollback

# Apply the prepared files.
mv -f "$quality_tmp" "$QUALITY"
mv -f "$fail_tmp" "$FAILLOCK"
mv -f "$auth_tmp" "$AUTH"
mv -f "$pass_tmp" "$PASSWORD"

# Check the actual files once more.
verify "$QUALITY" "$FAILLOCK" "$AUTH" "$PASSWORD" || rollback

trap - ERR INT TERM

echo "    All required rules found [PASS]"
echo "Password minimum length: 14 | Lockout: 5 attempts / 15 min | History: 12"
echo "Backup saved at: $backup"
echo "Test real logins from the VM console before considering deployment complete."

