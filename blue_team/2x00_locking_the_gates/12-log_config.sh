#!/bin/bash

# Task 12 - The Log Architect
# Configure security logs, rotation and file permissions.

set -e

DEFAULT="/etc/rsyslog.d/50-default.conf"
MD_CONF="/etc/rsyslog.d/40-meddefense.conf"
ROTATE="/etc/logrotate.d/rsyslog"
MD_ROTATE="/etc/logrotate.d/meddefense"

# Check root privileges.
if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo."
    exit 1
fi

# Check that the required tools are installed.
for tool in rsyslogd logrotate logger; do
    if ! command -v "$tool" > /dev/null; then
        echo "Missing tool: $tool"
        exit 1
    fi
done

# Check the existing Ubuntu configuration.
if [ ! -f "$DEFAULT" ] || [ ! -f "$ROTATE" ]; then
    echo "Expected Ubuntu logging configuration not found."
    exit 1
fi

# Do not overwrite an existing MedDefense configuration.
if [ -e "$MD_CONF" ] || [ -e "$MD_ROTATE" ]; then
    echo "MedDefense configuration already exists. Review it before rerunning."
    exit 1
fi

# Only change the default routes if they match Ubuntu's layout.
if ! grep -Eq '^[[:space:]]*auth,authpriv\.\*[[:space:]]+-?/var/log/auth\.log[[:space:]]*$' "$DEFAULT" ||
   ! grep -Eq '^[[:space:]]*\*\.\*;auth,authpriv\.none[[:space:]]+-?/var/log/syslog[[:space:]]*$' "$DEFAULT"; then
    echo "Existing rsyslog routes differ from the expected Ubuntu layout."
    exit 1
fi

# Check that the original rotation file covers both logs.
if ! grep -qx '/var/log/auth.log' "$ROTATE" ||
   ! grep -qx '/var/log/syslog' "$ROTATE"; then
    echo "Existing logrotate layout differs from the expected Ubuntu layout."
    exit 1
fi

# Back up the original configuration files.
BACKUP=$(mktemp -d /root/meddefense-log-backup.XXXXXX)

cp -p "$DEFAULT" "$BACKUP/50-default.conf"
cp -p "$ROTATE" "$BACKUP/rsyslog"

echo "[*] Backups saved to $BACKUP"

# Restore the files if an error occurs.
rollback() {
    trap - ERR INT TERM

    echo "[!] Problem found. Restoring the original logging configuration."

    cp -p "$BACKUP/50-default.conf" "$DEFAULT" || true
    cp -p "$BACKUP/rsyslog" "$ROTATE" || true

    rm -f "$MD_CONF" "$MD_ROTATE"

    systemctl restart rsyslog || true
    exit 1
}

trap rollback ERR INT TERM

echo "[*] Configuring rsyslog..."

# Replace only the default auth.log and syslog routes.
# Leave the other Ubuntu logging rules alone.
sed -i -E 's|^([[:space:]]*auth,authpriv\.\*[[:space:]]+-?/var/log/auth\.log[[:space:]]*)$|# MedDefense replacement: \1|' "$DEFAULT"

sed -i -E 's|^([[:space:]]*\*\.\*;auth,authpriv\.none[[:space:]]+-?/var/log/syslog[[:space:]]*)$|# MedDefense replacement: \1|' "$DEFAULT"

# Add structured logging with timestamps and severity.
cat > "$MD_CONF" <<'EOF'
# MedDefense structured logging
# Include timestamp, host, program, facility, severity and message.

template(name="MedDefenseFormat" type="string"
         string="%timereported:::date-rfc3339% %hostname% %syslogtag% %syslogfacility-text%.%syslogseverity-text% %msg%\n")

# Authentication and privileged access events.
if ($syslogfacility-text == "auth" or $syslogfacility-text == "authpriv") then {
    action(type="omfile" file="/var/log/auth.log" template="MedDefenseFormat"
           fileOwner="syslog" fileGroup="adm" fileCreateMode="0640")
}

# System events with info severity or higher.
if ($syslogseverity <= 6 and $syslogfacility-text != "auth" and $syslogfacility-text != "authpriv") then {
    action(type="omfile" file="/var/log/syslog" template="MedDefenseFormat"
           fileOwner="syslog" fileGroup="adm" fileCreateMode="0640")
}
EOF

# Preserve the original rotation settings for other logs.
# Remove only auth.log and syslog from that group.
sed -i '/^\/var\/log\/auth\.log$/d; /^\/var\/log\/syslog$/d' "$ROTATE"

echo "[*] Configuring daily rotation and retention..."

cat > "$MD_ROTATE" <<'EOF'
# Authentication logs - 90 days.
/var/log/auth.log {
    daily
    rotate 90
    maxage 90
    missingok
    notifempty
    dateext
    nocompress
    create 0640 syslog adm

    postrotate
        /usr/lib/rsyslog/rsyslog-rotate

        # Compress archives after seven days.
        find /var/log -maxdepth 1 -type f -name 'auth.log-*' ! -name '*.gz' -mtime +6 -exec gzip -- {} \;

        # Remove archives older than 90 days.
        find /var/log -maxdepth 1 -type f -name 'auth.log-*' -mtime +89 -delete
    endscript
}

# System logs - 60 days.
/var/log/syslog {
    daily
    rotate 60
    maxage 60
    missingok
    notifempty
    dateext
    nocompress
    create 0640 syslog adm

    postrotate
        /usr/lib/rsyslog/rsyslog-rotate

        # Compress archives after seven days.
        find /var/log -maxdepth 1 -type f -name 'syslog-*' ! -name '*.gz' -mtime +6 -exec gzip -- {} \;

        # Remove archives older than 60 days.
        find /var/log -maxdepth 1 -type f -name 'syslog-*' -mtime +59 -delete
    endscript
}
EOF

# Validate before restarting the logging service.
echo "[*] Validating configuration..."

rsyslogd -N1 > /dev/null
logrotate -d /etc/logrotate.conf > /dev/null 2>&1

echo "    rsyslog and logrotate configuration checks: OK"

# Keep permissions suitable for the rsyslog service.
chown syslog:adm /var/log/auth.log /var/log/syslog
chmod 640 /var/log/auth.log /var/log/syslog

# Restart rsyslog to apply the new configuration.
systemctl restart rsyslog
systemctl is-active --quiet rsyslog

# Send harmless test messages to both log files.
MARKER="meddefense12_$$"

logger -p authpriv.notice -t md12 "$MARKER authentication"
logger -p user.info -t md12 "$MARKER system"

# Check whether a test message reached its destination.
check_message() {
    file="$1"
    message="$2"

    for attempt in 1 2 3 4 5; do
        if grep -Fq "$message" "$file"; then
            return 0
        fi
        sleep 1
    done

    return 1
}

echo "[*] Verifying log activity..."

check_message /var/log/auth.log "$MARKER authentication"
echo "    auth.log [OK]"

check_message /var/log/syslog "$MARKER system"
echo "    syslog [OK]"

echo "[*] Securing file permissions..."

ls -l /var/log/auth.log /var/log/syslog

trap - ERR INT TERM

echo "Log sources configured: 2 | Rotation policies: 2 | Permissions: 640"
echo "Backups: $BACKUP"

