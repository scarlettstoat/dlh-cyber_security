#!/bin/bash
# Name: 12-linux_detection_proof.sh
# Purpose: Correlate Task 11 ground truth with Linux auditd, auth.log and syslog.
# Author: Suraya
# Project: MedDefense - Eyes on the Endpoint (2x02), Task 12
# Run: sudo ./12-linux_detection_proof.sh (on the Linux lab VM)

set -uo pipefail
export LC_TIME=C

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
GROUND_TRUTH="${1:-$SCRIPT_DIR/linux_attack_log.json}"
OUTPUT_FILE="$SCRIPT_DIR/linux_detection_matrix.json"
AUTH_LOG="${AUTH_LOG:-/var/log/auth.log}"
SYSLOG="${SYSLOG:-/var/log/syslog}"
WINDOW_SECONDS=30

if (( EUID != 0 )); then
    echo '[!] Run with sudo to read the audit and authentication logs.' >&2
    exit 1
fi

for tool in jq ausearch date awk hostname; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "[!] Missing required command: $tool" >&2
        exit 1
    fi
done
if [[ ! -r "$GROUND_TRUTH" ]]; then
    echo "[!] Ground truth file not found: $GROUND_TRUTH" >&2
    exit 1
fi
if ! jq -e 'if type == "array" then . else .actions end | type == "array"' \
    "$GROUND_TRUTH" >/dev/null 2>&1; then
    echo '[!] Ground truth must be a JSON array (or an object with an actions array).' >&2
    exit 1
fi

# Return one complete audit event per line. Related audit records have the same
# msg=audit(timestamp:serial) identifier, so inspect them together.
group_audit_events() {
    awk '
        {
            if (match($0, /msg=audit\([0-9]+\.[0-9]+:[0-9]+\)/)) {
                identifier = substr($0, RSTART, RLENGTH)
                if (!(identifier in events)) order[++count] = identifier
                events[identifier] = events[identifier] " " $0
            }
        }
        END {
            for (i = 1; i <= count; i++) print events[order[i]]
        }
    '
}

# Require an action-specific marker, rather than counting unrelated audit
# activity that happened during the same 30-second window.
audit_matches_action() {
    local number="$1" key="$2" event="$3"
    case "$number:$key" in
        1:identity|1:process_exec)
            [[ "$event" == *testattacker* && \
               ( "$event" == *useradd* || "$event" == *'type=ADD_USER'* ) ]]
            ;;
        2:sudoers)
            [[ "$event" == *'/etc/sudoers.d/backdoor'* || \
               "$event" == *'name="backdoor"'* ]]
            ;;
        3:process_exec)
            [[ "$event" == *'/tmp/suspicious_bin'* ]]
            ;;
        4:network_connect)
            # IPv4 loopback 127.0.0.1, port 4444 = 0x115c in SOCKADDR.
            [[ "$event" =~ saddr=0200115[cC]7[fF]000001 || \
               "$event" == *'127.0.0.1'* ]] || \
                [[ "$event" == *'comm="bash"'* && \
                   ( "$event" == *'type=SOCKADDR'* || "$event" == *'syscall=42'* ) ]]
            ;;
        5:cron_persist)
            [[ "$event" == *'/etc/cron.d/persistence_test'* || \
               "$event" == *'name="persistence_test"'* ]]
            ;;
        6:identity|6:process_exec)
            [[ "$event" == *'/etc/shadow'* && \
               ( "$key" == identity || "$event" == *cat* ) ]]
            ;;
        *) return 1 ;;
    esac
}

# Print a source record using jq so all JSON strings are safely escaped.
make_source_record() {
    local source="$1" key="$2" event_id="$3" detail="$4" evidence="$5"
    local text="$6" fields=() field fields_json
    for field in acct name exe comm uid auid syscall saddr proctitle argc a0 a1 \
                 success res op pid cwd terminal; do
        if [[ "$text" == *"$field="* ]]; then
            fields+=("$field")
        fi
    done
    fields_json="$(jq -cn '$ARGS.positional' --args "${fields[@]}")"
    jq -cn --arg source "$source" --arg audit_key "$key" \
        --arg event_id "$event_id" --arg detail_level "$detail" \
        --arg evidence "$evidence" --argjson key_fields_present "$fields_json" \
        '{source:$source,audit_key:(if $audit_key=="" then null else $audit_key end),
          event_id:$event_id,detail_level:$detail_level,
          key_fields_present:$key_fields_present,evidence:$evidence}'
}

# Extract targeted audit records for one key in the exact local-time range.
check_audit() {
    local action="$1" key="$2" start="$3" end="$4"
    local start_date start_clock end_date end_clock raw event serial detail evidence
    start_date="$(date -d "@$start" '+%x')"
    start_clock="$(date -d "@$start" '+%H:%M:%S')"
    end_date="$(date -d "@$end" '+%x')"
    end_clock="$(date -d "@$end" '+%H:%M:%S')"

    raw="$(ausearch -k "$key" -ts "$start_date" "$start_clock" \
        -te "$end_date" "$end_clock" --raw 2>/dev/null)" || return 0

    while IFS= read -r event; do
        [[ -n "$event" ]] || continue
        if ! audit_matches_action "$action" "$key" "$event"; then
            continue
        fi
        serial="$(sed -nE 's/.*msg=audit\([0-9]+\.[0-9]+:([0-9]+)\).*/\1/p' <<< "$event")"
        detail='full'
        case "$action:$key" in
            1:process_exec|6:process_exec) detail='partial' ;;
            4:network_connect)
                if [[ "$event" != *'type=SOCKADDR'* && \
                      "$event" != *'saddr='* ]]; then
                    detail='partial'
                fi
                ;;
        esac
        evidence="Audit event ${serial:-unknown} matched rule '$key'"
        if [[ "$event" == *'exe="'* ]]; then
            evidence+=', executable information present'
        fi
        make_source_record 'auditd' "$key" "${serial:-unknown}" "$detail" \
            "$evidence" "$event"
        break  # One well-matched event per rule is sufficient for proof.
    done < <(printf '%s\n' "$raw" | group_audit_events)
}

# Convert an auth.log / syslog timestamp to epoch seconds. Traditional syslog
# omits the year; check adjacent years for New Year boundary cases.
log_epoch() {
    local line="$1" reference_year="$2" year stamp epoch
    if [[ "$line" =~ ^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+-]+Z?) ]]; then
        date -d "${BASH_REMATCH[1]}" +%s 2>/dev/null
        return
    fi
    if [[ "$line" =~ ^([A-Z][a-z]{2}[[:space:]]+[0-9]{1,2}[[:space:]]+[0-9]{2}:[0-9]{2}:[0-9]{2}) ]]; then
        stamp="${BASH_REMATCH[1]}"
        for year in "$reference_year" "$((reference_year - 1))" "$((reference_year + 1))"; do
            epoch="$(date -d "$stamp $year" +%s 2>/dev/null)" || continue
            if (( epoch >= window_start && epoch <= window_end )); then
                printf '%s\n' "$epoch"
                return
            fi
        done
    fi
}

# Search only action-specific messages, with independent timestamp validation.
check_text_log() {
    local source="$1" logfile="$2" action="$3" start="$4" end="$5"
    local line epoch ref_year match=0 detail='partial' event_id='log-line'
    [[ -r "$logfile" ]] || return 0
    ref_year="$(date -d "@$start" +%Y)"
    window_start="$start" window_end="$end"
    while IFS= read -r line; do
        match=0
        case "$source:$action" in
            auth.log:1)
                if [[ "$line" == *useradd* && "$line" == *testattacker* ]]; then
                    match=1
                    [[ "$line" == *'new user'* || "$line" == *'name=testattacker'* ]] && detail='full'
                fi
                ;;
            auth.log:2)
                [[ "$line" == *sudo* && "$line" == *'/etc/sudoers.d/backdoor'* ]] && match=1
                ;;
            syslog:1)
                [[ "$line" == *useradd* && "$line" == *testattacker* ]] && match=1
                ;;
            syslog:5)
                [[ "$line" == *cron* && "$line" == *persistence_test* ]] && match=1
                ;;
        esac
        (( match == 1 )) || continue
        epoch="$(log_epoch "$line" "$ref_year")"
        [[ "$epoch" =~ ^[0-9]+$ ]] || continue
        (( epoch >= start && epoch <= end )) || continue
        make_source_record "$source" '' "$event_id" "$detail" \
            "${line:0:240}" "$line"
        break
    done < "$logfile"
}

action_lines="$(jq -c 'if type=="array" then . else .actions end | sort_by(.action_number)[]' \
    "$GROUND_TRUTH")" || exit 1
if [[ -z "$action_lines" ]]; then
    echo '[!] Ground truth has no actions to compare.' >&2
    exit 1
fi

count="$(printf '%s\n' "$action_lines" | wc -l | tr -d ' ')"
printf '[*] Loading ground truth (%s actions)...\n' "$count"
if [[ ! -r "$AUTH_LOG" ]]; then
    echo "[i] $AUTH_LOG is unavailable; auth.log matches will be missed."
fi
if [[ ! -r "$SYSLOG" ]]; then
    echo "[i] $SYSLOG is unavailable; syslog matches will be missed."
fi
printf '[*] Searching telemetry within +/- %ss of each action...\n' "$WINDOW_SECONDS"
printf '%-27s %-13s %-17s %-9s %s\n' 'Action' 'Source' 'Key' 'Detail' 'Status'
printf '%-27s %-13s %-17s %-9s %s\n' '------' '------' '---' '------' '------'

results=()
captured=0
multi_source=0
while IFS= read -r action_json; do
    number="$(jq -r '.action_number // .action // 0' <<< "$action_json")"
    description="$(jq -r '.description // "Unknown action"' <<< "$action_json")"
    timestamp="$(jq -r '.timestamp // .timestamp_utc // empty' <<< "$action_json")"
    ran="$(jq -r '.status // "SUCCESS"' <<< "$action_json")"

    if ! epoch="$(date -d "$timestamp" +%s 2>/dev/null)"; then
        echo "[!] Invalid timestamp for action $number: $timestamp" >&2
        exit 1
    fi
    window_start=$((epoch - WINDOW_SECONDS))
    window_end=$((epoch + WINDOW_SECONDS))
    start_iso="$(date -u -d "@$window_start" '+%Y-%m-%dT%H:%M:%SZ')"
    end_iso="$(date -u -d "@$window_end" '+%Y-%m-%dT%H:%M:%SZ')"

    sources=()
    if [[ "$ran" == 'SUCCESS' || "$ran" == 'success' ]]; then
        keys=()
        case "$number" in
            1) keys=(identity process_exec) ;;
            2) keys=(sudoers) ;;
            3) keys=(process_exec) ;;
            4) keys=(network_connect) ;;
            5) keys=(cron_persist) ;;
            6) keys=(identity process_exec) ;;
        esac
        for key in "${keys[@]}"; do
            while IFS= read -r record; do
                [[ -n "$record" ]] && sources+=("$record")
            done < <(check_audit "$number" "$key" "$window_start" "$window_end")
        done
        for source in auth.log syslog; do
            log="$AUTH_LOG"
            [[ "$source" == syslog ]] && log="$SYSLOG"
            while IFS= read -r record; do
                [[ -n "$record" ]] && sources+=("$record")
            done < <(check_text_log "$source" "$log" "$number" "$window_start" "$window_end")
        done
    fi

    if (( ${#sources[@]} > 0 )); then
        state='CAPTURED'
        captured=$((captured + 1))
        distinct_sources="$(printf '%s\n' "${sources[@]}" | jq -sr \
            '[.[].source] | unique | length')"
        if (( distinct_sources > 1 )); then
            multi_source=$((multi_source + 1))
        fi
        detail="$(printf '%s\n' "${sources[@]}" | jq -s \
            'if any(.[]; .detail_level=="full") then "full" else "partial" end')"
        for record in "${sources[@]}"; do
            src="$(jq -r '.source' <<< "$record")"
            rule="$(jq -r '.audit_key // "-"' <<< "$record")"
            rec_detail="$(jq -r '.detail_level' <<< "$record")"
            printf '%-27.27s %-13s %-17s %-9s [%s]\n' \
                "$description" "$src" "$rule" "$rec_detail" "$state"
        done
    else
        state='MISSED'
        detail='missed'
        printf '%-27.27s %-13s %-17s %-9s [%s]\n' \
            "$description" '-' '-' "$detail" "$state"
    fi

    sources_json='[]'
    if (( ${#sources[@]} > 0 )); then
        sources_json="$(printf '%s\n' "${sources[@]}" | jq -sc '.')"
    fi
    results+=("$(jq -cn --argjson number "$number" --arg description "$description" \
        --arg timestamp "$timestamp" --arg start "$start_iso" --arg end "$end_iso" \
        --arg state "$state" --arg detail "$detail" --arg execution_status "$ran" \
        --argjson sources "$sources_json" \
        '{action_number:$number,description:$description,timestamp:$timestamp,
          window_start_utc:$start,window_end_utc:$end,
          execution_status:$execution_status,status:$state,detail_level:$detail,
          sources:$sources}')")
done <<< "$action_lines"

results_json="$(printf '%s\n' "${results[@]}" | jq -sc '.')"
total="${#results[@]}"
percent=$((captured * 100 / total))
report="$(jq -cn --arg generated_at_utc "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --arg hostname "$(hostname)" --arg ground_truth "$(basename "$GROUND_TRUTH")" \
    --argjson window_seconds "$WINDOW_SECONDS" --argjson actions "$total" \
    --argjson captured "$captured" --argjson multi_source "$multi_source" \
    --argjson percentage "$percent" --argjson results "$results_json" \
    '{generated_at_utc:$generated_at_utc,hostname:$hostname,ground_truth:$ground_truth,
      window_seconds:$window_seconds,
      summary:{actions:$actions,captured:$captured,missed:($actions-$captured),
               capture_percentage:$percentage,multi_source:$multi_source},
      detection_matrix:$results}')"

# Write atomically; never leave a truncated JSON report behind.
temp_file="$(mktemp "$SCRIPT_DIR/.linux_detection_matrix.XXXXXX")" || exit 1
if ! printf '%s\n' "$report" | jq '.' > "$temp_file"; then
    rm -f -- "$temp_file"
    echo '[!] Could not create detection matrix.' >&2
    exit 1
fi
mv -f -- "$temp_file" "$OUTPUT_FILE" || exit 1
if [[ -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]]; then
    chown "$SUDO_UID:$SUDO_GID" "$OUTPUT_FILE" 2>/dev/null || true
fi

printf 'Actions: %d | Captured: %d/%d (%d%%) | Multi-source: %d\n' \
    "$total" "$captured" "$total" "$percent" "$multi_source"
printf 'Report saved to: %s\n' "$OUTPUT_FILE"
