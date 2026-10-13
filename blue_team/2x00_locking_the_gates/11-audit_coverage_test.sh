#!/bin/bash

# Task 11 - Audit coverage validation
# Safely test six security events and produce a JSON report.

set -euo pipefail

REPORT="audit_validation.json"
PASSED=0
FAILED=0

# Check permissions and required tools.
if [ "$EUID" -ne 0 ]; then
    echo "Run this script with sudo."
    exit 1
fi

for tool in auditctl ausearch systemctl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing command: $tool"
        exit 1
    fi
done

if ! systemctl is-active --quiet auditd; then
    echo "auditd is not running."
    exit 1
fi

if [ "$(auditctl -s | awk '/^enabled/ {print $2}')" = "2" ]; then
    echo "Audit rules are immutable; temporary test rules cannot be added."
    exit 1
fi

# Use a temporary directory for the monitored file.
WORKDIR=$(mktemp -d /tmp/md11-audit.XXXXXX)
TEST_FILE="$WORKDIR/test-file"
touch "$TEST_FILE"

# Remember temporary audit rules for cleanup.
declare -a WATCH_PATHS=()
declare -a WATCH_PERMS=()
declare -a WATCH_KEYS=()

# Store results for the final JSON report.
declare -a NAMES=()
declare -a KEYS=()
declare -a COMMANDS=()
declare -a TIMES=()
declare -a STATUSES=()
declare -a COUNTS=()
declare -a BASELINE_KEYS=()
declare -a BASELINE_PRESENT=()

# Remove only the rules and files created by this script.
cleanup() {
    for ((i=${#WATCH_KEYS[@]}-1; i>=0; i--)); do
        auditctl -W "${WATCH_PATHS[i]}" \
            -p "${WATCH_PERMS[i]}" \
            -k "${WATCH_KEYS[i]}" >/dev/null 2>&1 || true
    done

    rm -rf -- "$WORKDIR"
}

trap cleanup EXIT

# Create a temporary audit watch.
add_watch() {
    local path="$1"
    local permission="$2"
    local key="$3"

    if ! auditctl -w "$path" -p "$permission" -k "$key" >/dev/null; then
        echo "Could not add audit watch for $path" >&2
        exit 1
    fi

    WATCH_PATHS+=("$path")
    WATCH_PERMS+=("$permission")
    WATCH_KEYS+=("$key")
}

# Count real system-call events recorded by auditd.
event_count() {
    local key="$1"
    local result

    result=$(ausearch -k "$key" -m SYSCALL --raw 2>/dev/null |
        grep -c '^type=SYSCALL' || true)

    printf '%s' "${result:-0}"
}

# Separately check whether the original Task 10 rule is loaded.
has_baseline_key() {
    local key="$1"

    auditctl -l 2>/dev/null |
        grep -Eq "(^|[[:space:],])(-k[[:space:]]+|key=)${key}([[:space:]]|$)"
}

# Run one test and record its result.
run_test() {
    local name="$1"
    local key="$2"
    local baseline="$3"
    local description="$4"
    shift 4

    local before after difference status baseline_found timestamp

    if has_baseline_key "$baseline"; then
        baseline_found=true
    else
        baseline_found=false
    fi

    before=$(event_count "$key")

    # Trigger the event without stopping the whole test if it fails.
    "$@" >/dev/null 2>&1 || true

    sleep 2
    after=$(event_count "$key")
    difference=$((after - before))

    if [ "$difference" -gt 0 ]; then
        status="CAPTURED"
        PASSED=$((PASSED + 1))
    else
        status="MISSING"
        difference=0
        FAILED=$((FAILED + 1))
    fi

    timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

    NAMES+=("$name")
    KEYS+=("$key")
    BASELINE_KEYS+=("$baseline")
    BASELINE_PRESENT+=("$baseline_found")
    COMMANDS+=("$description")
    TIMES+=("$timestamp")
    STATUSES+=("$status")
    COUNTS+=("$difference")

    printf '[%s] %s (%s events)\n' \
        "$status" "$name" "$difference"
}

# Unique test keys prevent unrelated events being counted.
KEY_PREFIX="md11_$$"

# Temporary watches for six different security events.
add_watch /usr/bin/sudo x "${KEY_PREFIX}_sudo"
add_watch /etc/shadow r "${KEY_PREFIX}_shadow"
add_watch /usr/bin/curl x "${KEY_PREFIX}_curl"
add_watch /etc/ssh/sshd_config r "${KEY_PREFIX}_ssh"
add_watch "$TEST_FILE" w "${KEY_PREFIX}_file"
add_watch /etc/crontab r "${KEY_PREFIX}_cron"

echo "Running six MedDefense audit tests..."

# 1. Execute sudo.
run_test "sudo execution" "${KEY_PREFIX}_sudo" "priv_esc" \
    "sudo true" sudo -n true

# 2. Read part of the shadow file without modifying it.
run_test "shadow file read" "${KEY_PREFIX}_shadow" "identity" \
    "read one byte of /etc/shadow" head -c 1 /etc/shadow

# 3. Execute a download utility without making a download.
run_test "download tool execution" "${KEY_PREFIX}_curl" "suspicious_download" \
    "curl --version" curl --version

# 4. Read the SSH configuration without changing permissions.
run_test "SSH configuration read" "${KEY_PREFIX}_ssh" "sshd_config" \
    "read one byte of sshd_config" head -c 1 /etc/ssh/sshd_config

# 5. Write to our own temporary monitored file.
run_test "monitored file write" "${KEY_PREFIX}_file" "startup_scripts" \
    "write temporary audit test file" \
    bash -c 'echo audit-test >> "$1"' _ "$TEST_FILE"

# 6. Read the cron configuration without changing scheduled jobs.
run_test "cron configuration read" "${KEY_PREFIX}_cron" "cron_config" \
    "read one byte of /etc/crontab" head -c 1 /etc/crontab

# Create a JSON report using Bash.
# The text fields are controlled by this script, not user input.
{
    printf '{\n'
    printf '  "generated_at": "%s",\n' \
        "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    printf '  "note": "Temporary audit watches test event capture; baseline_rule_loaded reports Task 10 rule presence separately.",\n'
    printf '  "tests_executed": 6,\n'
    printf '  "tests_captured": %d,\n' "$PASSED"
    printf '  "tests_missed": %d,\n' "$FAILED"
    printf '  "results": [\n'

    for ((i=0; i<${#NAMES[@]}; i++)); do
        [ "$i" -gt 0 ] && printf ',\n'

        printf '    {"test_name":"%s", "expected_key":"%s", ' \
            "${NAMES[i]}" "${KEYS[i]}"

        printf '"baseline_key":"%s", "baseline_rule_loaded":%s, ' \
            "${BASELINE_KEYS[i]}" "${BASELINE_PRESENT[i]}"

        printf '"command_executed":"%s", "timestamp":"%s", ' \
            "${COMMANDS[i]}" "${TIMES[i]}"

        printf '"capture_status":"%s", "event_count":%d}' \
            "${STATUSES[i]}" "${COUNTS[i]}"
    done

    printf '\n  ]\n}\n'
} > "$REPORT"

echo ""
echo "Audit coverage: $PASSED captured, $FAILED missing"
echo "Report saved to: $REPORT"

# Zero means every test recorded an actual audit event.
[ "$FAILED" -eq 0 ]

