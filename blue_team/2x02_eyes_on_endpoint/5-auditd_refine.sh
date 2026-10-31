#!/bin/bash
# Name: 5-auditd_refine.sh
# Purpose: Add and validate process, network, SSH, cron, and sudo audit rules.
# Author: Suraya

set -uo pipefail

RULE_FILE="/etc/audit/rules.d/65-meddefense-detection.rules"
TEST_TAG="auditd_refine_$$"
TEMP_RULES=""
SSH_TEST_DIR=""

cleanup() {
    if [[ -n "$TEMP_RULES" && -f "$TEMP_RULES" ]]; then
        rm -f -- "$TEMP_RULES"
    fi
    if [[ -n "$SSH_TEST_DIR" ]]; then
        rm -f -- "$SSH_TEST_DIR/.${TEST_TAG}"
    fi
    rm -f -- "/etc/cron.d/.${TEST_TAG}" \
        "/var/spool/cron/.${TEST_TAG}" \
        "/etc/sudoers.d/.${TEST_TAG}"
}
trap cleanup EXIT

if (( EUID != 0 )); then
    echo "[!] Run this script as root: sudo ./5-auditd_refine.sh" >&2
    exit 1
fi

for cmd in auditctl augenrules ausearch find id touch; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "[!] Required command not found: $cmd" >&2
        exit 1
    fi
done

if [[ ! -d /etc/audit/rules.d ]]; then
    echo "[!] Missing /etc/audit/rules.d (is auditd installed?)" >&2
    exit 1
fi

# Locked audit rules cannot be changed until a reboot.
if auditctl -s 2>/dev/null | grep -Eq '^enabled[[:space:]]+2$'; then
    echo "[!] Audit rules are immutable (enabled 2). A reboot is required before changes can be loaded." >&2
    exit 1
fi

current_rules=$(auditctl -l 2>/dev/null | grep -cv '^No rules$' || true)
echo "[*] Current auditd rules: $current_rules"
echo "[*] Adding detection-focused rules..."

# auditctl does not accept wildcards in -w paths. Watch each existing SSH
# directory separately, instead of using the invalid /home/*/.ssh/ watch.
ssh_dirs=()
for dir in /home/*/.ssh; do
    [[ -d "$dir" ]] && ssh_dirs+=("$dir")
done

if (( ${#ssh_dirs[@]} == 0 )); then
    # If no SSH directories exist, create one for an existing home directory.
    for home in /home/*; do
        if [[ -d "$home" ]]; then
            ssh_dir="$home/.ssh"
            owner=$(stat -c '%u:%g' "$home")
            if [[ ! -d "$ssh_dir" ]]; then
                mkdir -p -- "$ssh_dir" || exit 1
                chown "$owner" "$ssh_dir"
                chmod 700 "$ssh_dir"
            fi
            ssh_dirs+=("$ssh_dir")
            break
        fi
    done
fi

if (( ${#ssh_dirs[@]} == 0 )); then
    # Some minimal lab machines have no /home user directory.
    mkdir -p -m 700 /root/.ssh || exit 1
    ssh_dirs+=(/root/.ssh)
    echo "    [i] No user home under /home; monitoring /root/.ssh instead"
fi

# Each watched directory must exist when augenrules loads the rules.
mkdir -p /etc/cron.d /var/spool/cron /etc/sudoers.d || exit 1

TEMP_RULES=$(mktemp /etc/audit/rules.d/.meddefense.XXXXXX) || exit 1
cat > "$TEMP_RULES" <<'RULES'
# MedDefense: additional endpoint telemetry for the SOC
-a always,exit -F arch=b64 -S execve -k process_exec
-a always,exit -F arch=b64 -S socket -S connect -k network_connect
RULES

for dir in "${ssh_dirs[@]}"; do
    if [[ "$dir" == *' '* || "$dir" == *$'\t'* ]]; then
        echo "[!] SSH directory path contains whitespace; cannot use an auditctl watch: $dir" >&2
        continue
    fi
    printf -- '-w %s -p rwa -k ssh_keys\n' "$dir" >> "$TEMP_RULES"
done

cat >> "$TEMP_RULES" <<'RULES'
-w /etc/cron.d/ -p wa -k cron_persist
-w /var/spool/cron/ -p wa -k cron_persist
-w /etc/sudoers.d/ -p wa -k sudoers
RULES

# Keep earlier 2x00 rules untouched. Re-running replaces only this task's file.
if [[ -f "$RULE_FILE" ]] && cmp -s "$TEMP_RULES" "$RULE_FILE"; then
    status="PRESENT"
else
    install -m 0640 "$TEMP_RULES" "$RULE_FILE" || exit 1
    status="ADDED"
fi

echo "    execve syscall tracking               [$status]"
echo "    socket/connect syscall tracking       [$status]"
echo "    SSH key file monitoring               [$status]"
echo "    Cron directory monitoring             [$status]"
echo "    sudoers.d monitoring                  [$status]"

echo "[*] Loading rules..."
if augenrules --load >/dev/null 2>&1; then
    echo "    augenrules --load: OK"
else
    echo "    augenrules --load: FAILED" >&2
    echo "[!] Check 'sudo augenrules --load' for details." >&2
    exit 1
fi

# Confirm all rule categories actually exist in the active kernel ruleset.
loaded_rules=$(auditctl -l 2>/dev/null)
for key in process_exec network_connect ssh_keys cron_persist sudoers; do
    if ! grep -q -- "-k $key\|-F key=$key" <<< "$loaded_rules"; then
        echo "[!] Missing loaded audit key: $key" >&2
        exit 1
    fi
done

total_rules=$(printf '%s\n' "$loaded_rules" | grep -cv '^No rules$' || true)
echo "[*] Total rules: $total_rules"
echo "[*] Validating new rules..."

# Capture start time before generating events, so older records do not pass.
start_date=$(date '+%m/%d/%Y')
start_time=$(date '+%H:%M:%S')

# Ensure test actions create new activity after rules are loaded.
/usr/bin/id >/dev/null 2>&1 || id >/dev/null 2>&1

# A refused localhost connection still exercises the socket/connect syscalls.
if command -v curl >/dev/null 2>&1; then
    curl --max-time 2 --silent --output /dev/null http://127.0.0.1:1 || true
elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import socket; s=socket.socket(); s.settimeout(1); s.connect_ex(("127.0.0.1", 1)); s.close()' >/dev/null 2>&1 || true
else
    echo "    [i] Neither curl nor python3 available for network test"
fi

SSH_TEST_DIR="${ssh_dirs[0]}"
touch -- "$SSH_TEST_DIR/.${TEST_TAG}" || true
touch -- "/etc/cron.d/.${TEST_TAG}" || true
touch -- "/var/spool/cron/.${TEST_TAG}" || true
touch -- "/etc/sudoers.d/.${TEST_TAG}" || true

# auditd can take a moment to flush the records to disk.
captured=0
validate() {
    local label="$1" key="$2" detail="$3"
    local attempt
    for attempt in 1 2 3 4 5; do
        if ausearch -k "$key" -ts "$start_date" "$start_time" --raw 2>/dev/null | grep -q 'type='; then
            printf '    %-9s %-48s [CAPTURED]\n' "$label" "$detail"
            captured=$((captured + 1))
            return 0
        fi
        sleep 1
    done
    printf '    %-9s %-48s [MISSED]\n' "$label" "$detail"
    return 1
}

validate execve process_exec 'ran /usr/bin/id -> ausearch -k process_exec' || true
validate socket network_connect 'curl localhost -> ausearch -k network_connect' || true
validate ssh_keys ssh_keys 'touch ~/.ssh/test -> ausearch -k ssh_keys' || true
validate cron cron_persist 'touch /etc/cron.d/test -> ausearch -k cron_persist' || true
validate sudoers sudoers 'touch /etc/sudoers.d/test -> ausearch -k sudoers' || true

printf 'Rules added: 5 categories | Validation: %d/5 PASS\n' "$captured"
if (( captured < 5 )); then
    exit 1
fi
