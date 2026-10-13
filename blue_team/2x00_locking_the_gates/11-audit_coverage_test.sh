#!/bin/bash

# Task 11 - Audit Telemetry Coverage Test
# Test six security events and save the results as JSON.

OUTPUT="audit_validation.json"

if [ "$EUID" -ne 0 ]; then
    echo "Please run this script with sudo."
    exit 1
fi

# Check the tools we need.
for tool in auditctl ausearch jq; do
    if ! command -v "$tool" > /dev/null 2>&1; then
        echo "Missing tool: $tool"
        exit 1
    fi
done

# Check that auditd is running.
if ! systemctl is-active --quiet auditd; then
    echo "auditd is not running."
    exit 1
fi

# Check whether we can add temporary rules.
audit_state=$(auditctl -s | awk '/^enabled/ {print $2}')

if [ "$audit_state" != "1" ]; then
    echo "Auditing is disabled or rules are locked."
    exit 1
fi

# Check the files and commands needed for testing.
for path in /usr/bin/sudo /usr/bin/curl /etc/shadow \
            /etc/ssh/sshd_config /etc/crontab; do

    if [ ! -e "$path" ]; then
        echo "Missing path: $path"
        exit 1
    fi
done

# Create temporary files for our tests and results.
TEST_DIR=$(mktemp -d /tmp/meddefense-audit.XXXXXX)
RESULTS=$(mktemp)

# Keep a list of temporary audit rules for cleanup.
WATCHES=()

cleanup() {
    echo "[*] Cleaning test artifacts..."

    for watch in "${WATCHES[@]}"; do
        IFS='|' read -r path perm key <<< "$watch"

        if ! auditctl -W "$path" -p "$perm" -k "$key" > /dev/null 2>&1; then
            echo "    Warning: could not remove rule $key"
        fi
    done

    rm -rf -- "$TEST_DIR"
    rm -f -- "$RESULTS"
}

trap cleanup EXIT
trap 'exit 1' INT TERM

# Add a temporary audit rule.
add_watch() {
    path="$1"
    perm="$2"
    key="$3"

    if auditctl -w "$path" -p "$perm" -k "$key"; then
        WATCHES+=("$path|$perm|$key")
    else
        echo "Could not add audit rule for $path"
        exit 1
    fi
}

# Give each test a unique key for this run.
# This prevents us from counting older audit events.
K_SUDO="md11_sudo_$$"
K_SHADOW="md11_shadow_$$"
K_CURL="md11_curl_$$"
K_SSH="md11_ssh_$$"
K_FILE="md11_file_$$"
K_CRON="md11_cron_$$"

echo "[*] Adding temporary audit rules..."

add_watch /usr/bin/sudo x "$K_SUDO"
add_watch /etc/shadow r "$K_SHADOW"
add_watch /usr/bin/curl x "$K_CURL"
add_watch /etc/ssh/sshd_config r "$K_SSH"
add_watch "$TEST_DIR" wa "$K_FILE"
add_watch /etc/crontab r "$K_CRON"

captured=0
missed=0

# Run a command and look for its audit event.
run_test() {
    number="$1"
    name="$2"
    key="$3"
    description="$4"

    shift 4

    timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

    # Run the test command without displaying sensitive output.
    "$@" > /dev/null 2>&1 || true

    count=0

    # Give auditd a few seconds to record the event.
    for attempt in 1 2 3; do
        sleep 1

        count=$(ausearch -k "$key" -ts recent --raw 2>/dev/null |
                grep -c '^type=SYSCALL ')

        if [ "$count" -gt 0 ]; then
            break
        fi
    done

    if [ "$count" -gt 0 ]; then
        status="CAPTURED"
        captured=$((captured + 1))
    else
        status="MISSED"
        missed=$((missed + 1))
    fi

    printf "[%s/6] %-32s [%s]\n" "$number" "$name" "$status"

    # Save the result as one JSON object.
    jq -nc \
        --arg name "$name" \
        --arg key "$key" \
        --arg command "$description" \
        --arg time "$timestamp" \
        --arg status "$status" \
        --argjson count "$count" \
        '{
            test_name: $name,
            expected_key: $key,
            command_executed: $command,
            timestamp: $time,
            capture_status: $status,
            event_count: $count,
            rule_source: "temporary_test_rule"
        }' >> "$RESULTS"
}

echo "[*] Running audit telemetry coverage tests..."

# Test 1 - Execute a harmless command through sudo.
run_test 1 "sudo execution" "$K_SUDO" \
    "/usr/bin/sudo -n /usr/bin/true" \
    /usr/bin/sudo -n /usr/bin/true

# Test 2 - Read one byte from shadow without displaying it.
run_test 2 "shadow access" "$K_SHADOW" \
    "head -c 1 /etc/shadow" \
    head -c 1 /etc/shadow

# Test 3 - Execute curl without making a network request.
run_test 3 "suspicious download tool" "$K_CURL" \
    "/usr/bin/curl --version" \
    /usr/bin/curl --version

# Test 4 - Read one byte from the SSH configuration.
run_test 4 "sshd config read" "$K_SSH" \
    "head -c 1 /etc/ssh/sshd_config" \
    head -c 1 /etc/ssh/sshd_config

# Test 5 - Create a harmless file in our test directory.
run_test 5 "monitored test file write" "$K_FILE" \
    "touch $TEST_DIR/check.txt" \
    touch "$TEST_DIR/check.txt"

# Test 6 - Read cron configuration without creating a job.
run_test 6 "cron configuration check" "$K_CRON" \
    "head -c 1 /etc/crontab" \
    head -c 1 /etc/crontab

# Combine all six JSON results into one report.
jq -s \
    --arg time "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --argjson captured "$captured" \
    --argjson missed "$missed" \
    '{
        report_timestamp: $time,
        tests_executed: length,
        tests_captured: $captured,
        tests_missed: $missed,
        results: .
    }' "$RESULTS" > "$OUTPUT"

echo "Tests executed: 6"
echo "Captured: $captured"
echo "Missed: $missed"
echo "Report saved to: $OUTPUT"

if [ "$missed" -gt 0 ]; then
    exit 1
fi
