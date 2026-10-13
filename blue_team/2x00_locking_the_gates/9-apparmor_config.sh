#!/bin/bash

# Task 9 - AppArmor Enforcer
# Check profiles and protect the MedDefense billing services.

MYSQL="/etc/apparmor.d/usr.sbin.mysqld"
APACHE="/etc/apparmor.d/usr.sbin.apache2"
APP="/opt/meddefense/billing-app/app.sh"
APP_PROFILE="/etc/apparmor.d/opt.meddefense.billing-app.app.sh"

if [ "$EUID" -ne 0 ]; then
    echo "Please run this script with sudo."
    exit 1
fi

# Avoid changing security profiles during an SSH session.
if [ -n "${SSH_CONNECTION:-}" ]; then
    echo "Run this from the Ubuntu VM console, not SSH."
    exit 1
fi

echo "[*] Checking AppArmor status..."

# Check that the required tools are installed.
for tool in aa-status aa-enforce apparmor_parser ss; do
    if ! command -v "$tool" > /dev/null 2>&1; then
        echo "Missing command: $tool"
        exit 1
    fi
done

# Check whether AppArmor is enabled.
if ! aa-status --enabled > /dev/null 2>&1; then
    echo "    AppArmor module is not enabled."
    exit 1
fi

echo "    AppArmor module: loaded"

if ! systemctl is-active --quiet apparmor; then
    echo "    AppArmor service is not active."
    exit 1
fi

echo "    AppArmor service: active"

# Show the profiles already loaded.
echo "[*] Current AppArmor profiles:"
aa-status

problems=0

# Check a profile before enforcing it.
enforce_profile() {
    file="$1"
    program="$2"

    if [ ! -f "$file" ]; then
        echo "    $program [NO PROFILE]"
        problems=$((problems + 1))
        return
    fi

    # Check the profile without loading it.
    if ! apparmor_parser -Q "$file" > /dev/null 2>&1; then
        echo "    $program [INVALID PROFILE]"
        problems=$((problems + 1))
        return
    fi

    if aa-enforce "$file" > /dev/null 2>&1; then
        echo "    $program [ENFORCED PROFILE]"
    else
        echo "    $program [ENFORCEMENT FAILED]"
        problems=$((problems + 1))
    fi
}

echo "[*] Profile enforcement:"

# MySQL already has a profile on billing-srv-01.
enforce_profile "$MYSQL" "/usr/sbin/mysqld"

# Apache needs a tested profile before enforcement.
enforce_profile "$APACHE" "/usr/sbin/apache2"

# Create a custom profile for the billing application.
echo "[*] Custom MedDefense profile:"

if [ ! -x "$APP" ]; then
    echo "    $APP [NOT FOUND OR NOT EXECUTABLE]"
    problems=$((problems + 1))
else
    if [ ! -f "$APP_PROFILE" ]; then
        temp=$(mktemp)
        trap 'rm -f "$temp"' EXIT

        cat > "$temp" <<'EOF'
#include <tunables/global>

# MedDefense billing application profile.
profile /opt/meddefense/billing-app/app.sh {
    #include <abstractions/base>

    # Allow reading billing application files.
    /opt/meddefense/billing-app/** r,

    # The application is a Bash script.
    /bin/bash ix,
    /usr/bin/bash ix,
}
EOF

        # Validate before copying to the real profile directory.
        if apparmor_parser -Q "$temp" > /dev/null 2>&1; then
            if install -m 644 "$temp" "$APP_PROFILE"; then
                echo "    Custom profile created."
            else
                echo "    Could not install custom profile."
                problems=$((problems + 1))
            fi
        else
            echo "    Custom profile failed syntax check."
            problems=$((problems + 1))
        fi
    else
        echo "    Existing custom profile found."
    fi

    # Enforce only if the profile exists and passes validation.
    if [ -f "$APP_PROFILE" ]; then
        enforce_profile "$APP_PROFILE" "$APP"
    fi
fi

# Report processes listening on non-loopback addresses.
echo "[*] Unconfined network-listening processes:"

unconfined=0

pids=$(ss -H -tulpn | awk '$5 !~ /^127\./ && $5 !~ /^\[::1\]:/ && $5 !~ /^::1:/' | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -un)

for pid in $pids; do
    if [ -r "/proc/$pid/attr/current" ]; then
        status=$(cat "/proc/$pid/attr/current" 2>/dev/null)

        if [ "$status" = "unconfined" ]; then
            program=$(readlink -f "/proc/$pid/exe" 2>/dev/null)

            echo "    ${program:-unknown} (PID $pid) [UNCONFINED]"
            unconfined=$((unconfined + 1))
        fi
    fi
done

# Count the profiles using AppArmor's numeric output.
echo "[*] AppArmor summary:"

enforced=$(aa-status --enforced)
complaining=$(aa-status --complaining)

echo "Profiles in enforce: $enforced"
echo "Profiles in complain: $complaining"
echo "Unconfined network-listening processes: $unconfined"

# Report incomplete enforcement instead of claiming success.
if [ "$problems" -gt 0 ]; then
    echo "Profiles still needing attention: $problems"
    exit 1
fi

echo "AppArmor profile checks completed."
