#!/bin/bash

# Task 9 - AppArmor Enforcer
# Check AppArmor profiles and protect MedDefense services.

MYSQL="/etc/apparmor.d/usr.sbin.mysqld"
APACHE="/etc/apparmor.d/usr.sbin.apache2"
APP="/opt/meddefense/billing-app/app.sh"
APP_PROFILE="/etc/apparmor.d/opt.meddefense.billing-app.app.sh"

# Check root privileges.
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script with sudo."
    exit 1
fi

echo "[*] Checking AppArmor status..."

# Make sure AppArmor is available and running.
if ! command -v aa-status > /dev/null; then
    echo "AppArmor tools are not installed."
    exit 1
fi

if ! aa-status --enabled; then
    echo "AppArmor module is not loaded."
    exit 1
fi

echo "    AppArmor module: loaded"

if systemctl is-active --quiet apparmor; then
    echo "    AppArmor service: active"
else
    echo "    AppArmor service is not active."
    exit 1
fi

# Check that the tools needed for enforcement exist.
for tool in aa-enforce apparmor_parser ss; do
    if ! command -v "$tool" > /dev/null; then
        echo "Missing command: $tool"
        exit 1
    fi
done

# Show the current AppArmor profiles.
echo "[*] Current AppArmor profiles:"
aa-status

echo "[*] Profile enforcement:"

# MySQL already has a profile on the billing server.
if [ -f "$MYSQL" ]; then
    if aa-enforce "$MYSQL"; then
        echo "    /usr/sbin/mysqld [ENFORCED]"
    else
        echo "    /usr/sbin/mysqld [FAILED]"
    fi
else
    echo "    /usr/sbin/mysqld [NO PROFILE]"
fi

# Apache needs its own profile.
# Do not enforce an untested profile on a running web server.
if [ -f "$APACHE" ]; then
    if aa-enforce "$APACHE"; then
        echo "    /usr/sbin/apache2 [ENFORCED]"
    else
        echo "    /usr/sbin/apache2 [FAILED]"
    fi
else
    echo "    /usr/sbin/apache2 [NO PROFILE]"
    echo "    Apache needs a tested profile before enforcement."
fi

# Create a profile for the MedDefense billing application.
echo "[*] Configuring MedDefense application profile..."

if [ ! -x "$APP" ]; then
    echo "    Billing application not found or not executable."
else

    # Do not overwrite an existing profile.
    if [ ! -f "$APP_PROFILE" ]; then

        cat > "$APP_PROFILE" <<'EOF'
#include <tunables/global>

# MedDefense billing application
profile /opt/meddefense/billing-app/app.sh {

    # Basic permissions needed by the application.
    #include <abstractions/base>

    # Allow access to the billing application files.
    /opt/meddefense/billing-app/** r,

    # Allow the shell script to use Bash.
    /bin/bash ix,
    /usr/bin/bash ix,

    # Other application and patient directories
    # are not given access by this profile.
}
EOF

        echo "    Custom profile created."
    else
        echo "    Custom profile already exists."
    fi

    # Validate before loading the profile.
    if apparmor_parser -Q "$APP_PROFILE"; then
        echo "    Profile syntax: OK"

        if aa-enforce "$APP_PROFILE"; then
            echo "    $APP [ENFORCED]"
        else
            echo "    $APP [FAILED]"
        fi
    else
        echo "    Invalid AppArmor profile."
    fi
fi

# Find network-listening processes without AppArmor confinement.
echo "[*] Unconfined network-exposed processes:"

unconfined=0

pids=$(ss -tulpn | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -un)

for pid in $pids; do
    if [ -r "/proc/$pid/attr/current" ]; then

        status=$(cat "/proc/$pid/attr/current")

        if [ "$status" = "unconfined" ]; then
            program=$(readlink -f "/proc/$pid/exe")

            echo "    $program (PID $pid) [UNCONFINED]"
            unconfined=$((unconfined + 1))
        fi
    fi
done

# Print final AppArmor counts.
echo "[*] AppArmor summary:"

enforced=$(aa-status --enforced)
complaining=$(aa-status --complaining)

echo "Profiles in enforce: $enforced"
echo "Profiles in complain: $complaining"
echo "Unconfined network processes: $unconfined"

echo "AppArmor checks completed."

