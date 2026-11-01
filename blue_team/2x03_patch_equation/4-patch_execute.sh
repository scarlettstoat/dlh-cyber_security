#!/bin/bash
# Task 4: execute an approved patch plan with checks and an interruption-safe JSON log.
set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PLAN_FILE="$SCRIPT_DIR/patch_plan.json"
LOG_FILE="$SCRIPT_DIR/patch_execution_log.json"
LOCK_FILE=/var/lock/meddefense-patch.lock
MODE=dry-run

case "${1:---dry-run}" in
    --execute) MODE=execute ;;
    --dry-run) MODE=dry-run ;;
    *) echo "Usage: $0 [--dry-run|--execute]" >&2; exit 1 ;;
esac
if (( $# > 1 )); then
    echo "Only one option is allowed." >&2
    exit 1
fi

for command in jq flock sha256sum mktemp mv dpkg-query dpkg apt-get apt-cache systemctl cp; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "Missing required command: $command" >&2
        exit 1
    fi
done

if (( EUID != 0 )); then
    echo "Run with sudo (even for a dry-run, to collect service state)." >&2
    exit 1
fi

if [[ ! -r $PLAN_FILE ]] || ! jq -e '
    (.generated_at | type == "string") and
    (.plan | type == "array" and length > 0) and
    (all(.plan[]; (.package | type == "string" and length > 0)
                      and (.affected_services | type == "array")
                      and (.requires_restart | type == "boolean")
                      and (.requires_reboot | type == "boolean")))
' "$PLAN_FILE" >/dev/null 2>&1; then
    echo "No populated patch_plan.json found. Finish Tasks 0-3 first." >&2
    exit 1
fi

# The flock file remains in place; the kernel releases the lock on exit.
printf '[*] Acquiring lock %s... ' "$LOCK_FILE"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    echo 'BUSY'
    exit 2
fi
echo 'OK'

TMP_DIR=$(mktemp -d)
CURRENT_ENTRY=''
LOG_STARTED=false
FINISHED=false

# Update the JSON through a temporary file and rename, so readers never see
# a partially written log. Keep the running entry visible during apt-get.
replace_log() {
    local filter=$1
    shift
    jq "$@" "$filter" "$LOG_FILE" > "$TMP_DIR/new_log.json"
    mv -f -- "$TMP_DIR/new_log.json" "$LOG_FILE"
}

on_exit() {
    local exit_code=$?
    trap - EXIT INT TERM
    if [[ $LOG_STARTED == true && $FINISHED == false ]]; then
        if [[ -n $CURRENT_ENTRY ]]; then
            replace_log '.entries[-1].status = "interrupted" |
                         .entries[-1].failure_reason = "Execution interrupted before completion"' || true
        fi
        replace_log '.finished_at = $time | .status = "interrupted"' \
            --arg time "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" || true
    fi
    rm -rf -- "$TMP_DIR"
    flock -u 9 || true
    exit "$exit_code"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

plan_hash=$(sha256sum -- "$PLAN_FILE")
plan_hash=${plan_hash%% *}
mapfile -t plan_entries < <(jq -c '.plan[]' "$PLAN_FILE")
total=${#plan_entries[@]}

# Preserve earlier execution reports instead of overwriting audit history.
if [[ -f $LOG_FILE ]] && jq -e '(.started_at | type) == "string"'     "$LOG_FILE" >/dev/null 2>&1; then
    archive="$SCRIPT_DIR/patch_execution_log_$(date -u '+%Y%m%dT%H%M%SZ')_$$.json"
    cp -p -- "$LOG_FILE" "$archive"
fi

jq -n --arg start "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --arg host "$(hostname)" --arg hash "$plan_hash" --arg mode "$MODE" '
    {
        started_at: $start,
        finished_at: null,
        hostname: $host,
        plan_source_hash: $hash,
        mode: $mode,
        status: "running",
        entries: []
    }
' > "$TMP_DIR/new_log.json"
mv -f -- "$TMP_DIR/new_log.json" "$LOG_FILE"
LOG_STARTED=true

# Return JSON with a service's state; never restart pseudo-units.
service_states() {
    local service state active sub pid
    local -a services=("$@")
    local rows="$TMP_DIR/service_rows.jsonl"
    : > "$rows"
    for service in "${services[@]}"; do
        if [[ ! $service =~ ^[[:alnum:]_.@:-]+\.service$ ]]; then
            continue
        fi
        state=$(systemctl show "$service" --no-pager \
            -p ActiveState -p SubState -p MainPID 2>/dev/null || true)
        active=$(printf '%s\n' "$state" | sed -n 's/^ActiveState=//p' | head -n 1)
        sub=$(printf '%s\n' "$state" | sed -n 's/^SubState=//p' | head -n 1)
        pid=$(printf '%s\n' "$state" | sed -n 's/^MainPID=//p' | head -n 1)
        [[ $pid =~ ^[0-9]+$ ]] || pid=0
        jq -nc --arg service "$service" \
            --arg active "${active:-unknown}" --arg sub "${sub:-unknown}" \
            --argjson pid "$pid" \
            '{service:$service, ActiveState:$active, SubState:$sub, MainPID:$pid}' \
            >> "$rows"
    done
    jq -sc '.' "$rows"
}

package_version() {
    dpkg-query -W -f='${Version}' -- "$1" 2>/dev/null || true
}

# Some versions of apt produce slightly different lock errors.
lock_error() {
    grep -Eiq 'Could not get lock|Unable to acquire.*lock|is another process using it|dpkg frontend lock' "$1"
}

# Keep each log entry complete even when an individual apt command fails.
write_entry() {
    replace_log '.entries += [$entry]' --argjson entry "$1"
}
update_entry() {
    replace_log '.entries[-1] = $entry' --argjson entry "$1"
}

success=0
failed=0
skipped=0
printf '[*] Loading plan: %s (%d entries) [%s]\n' "$(basename "$PLAN_FILE")" "$total" "$MODE"

for ((index=0; index<total; index++)); do
    item=${plan_entries[$index]}
    package=$(jq -r '.package' <<< "$item")
    bucket=$(jq -r '.bucket // "scheduled"' <<< "$item")
    candidate=$(jq -r '.candidate_version // empty' <<< "$item")
    reboot=$(jq -r '.requires_reboot' <<< "$item")
    restart=$(jq -r '.requires_restart' <<< "$item")
    mapfile -t services < <(jq -r '.affected_services[] | strings' <<< "$item")

    # Reject untrusted fields before passing them to command-line tools.
    if [[ ! $package =~ ^[[:alnum:]][[:alnum:].+:\-]*$ ]]; then
        echo "Invalid package name in plan: $package" >&2
        failed=$((failed + 1))
        break
    fi

    started=$(date +%s)
    before_version=$(package_version "$package")
    before_services=$(service_states "${services[@]}")
    pre=$(jq -nc --arg version "$before_version" \
        --argjson services "$before_services" \
        '{installed_version:$version, service_states:$services}')

    entry=$(jq -nc --argjson item "$item" --argjson pre "$pre" \
        '{package:$item.package, rank:($item.rank // null), bucket:($item.bucket // null),
          requires_reboot:$item.requires_reboot, affected_services:$item.affected_services,
          pre:$pre, post:null, status:"running", duration_seconds:0,
          stdout_tail:"", stderr_tail:"", restart_results:[], failure_reason:null}')
    write_entry "$entry"
    CURRENT_ENTRY=$package
    printf '[%d/%d] %-26s %-10s ' "$((index + 1))" "$total" "$package" "$bucket"

    status=success
    reason=''
    stdout_tail=''
    stderr_tail=''
    restart_results='[]'

    # A plan must refer to an already installed package, and cannot silently
    # switch to a newly published candidate version.
    if [[ -z $before_version ]]; then
        status=failed
        reason='Package is not installed'
    elif [[ -z $candidate ]]; then
        status=failed
        reason='Plan has no candidate_version'
    elif dpkg --compare-versions "$before_version" ge "$candidate"; then
        status=skipped
        reason='Already at or above planned version'
    else
        current_candidate=$(apt-cache policy "$package" | \
            sed -n 's/^[[:space:]]*Candidate:[[:space:]]*//p' | head -n 1)
        if [[ $current_candidate != "$candidate" ]]; then
            status=failed
            reason="APT candidate differs from plan: ${current_candidate:-unavailable}"
        fi
    fi

    # Simulate each operation before attempting a real change. Refuse removals.
    if [[ $status == success ]]; then
        if DEBIAN_FRONTEND=noninteractive apt-get -s install --only-upgrade "$package" \
            > "$TMP_DIR/sim.out" 2> "$TMP_DIR/sim.err"; then
            if grep -Eq '^Remv[[:space:]]' "$TMP_DIR/sim.out"; then
                status=failed
                reason='Simulation would remove a package'
            elif ! grep -Eq '^Inst[[:space:]]' "$TMP_DIR/sim.out"; then
                status=failed
                reason='Simulation did not show any upgrades'
            fi
        else
            status=failed
            reason='APT simulation failed'
        fi
        stdout_tail=$(tail -c 4096 "$TMP_DIR/sim.out")
        stderr_tail=$(tail -c 4096 "$TMP_DIR/sim.err")
    fi

    if [[ $status == success && $MODE == dry-run ]]; then
        status=simulated
        reason='Dry-run only; nothing installed'
    elif [[ $status == success ]]; then
        elapsed=0
        delay=1
        while :; do
            # Zero-second APT lock timeout lets us implement bounded retries.
            if DEBIAN_FRONTEND=noninteractive apt-get \
                -o DPkg::Lock::Timeout=0 install --only-upgrade -y "$package" \
                > "$TMP_DIR/apt.out" 2> "$TMP_DIR/apt.err"; then
                stdout_tail=$(tail -c 4096 "$TMP_DIR/apt.out")
                stderr_tail=$(tail -c 4096 "$TMP_DIR/apt.err")
                break
            fi
            stdout_tail=$(tail -c 4096 "$TMP_DIR/apt.out")
            stderr_tail=$(tail -c 4096 "$TMP_DIR/apt.err")
            if ! lock_error "$TMP_DIR/apt.err"; then
                status=failed
                reason='APT command failed'
                break
            fi
            if (( elapsed >= 120 )); then
                status=failed
                reason='APT/dpkg lock was busy for 120 seconds'
                break
            fi
            remaining=$((120 - elapsed))
            (( delay > remaining )) && delay=$remaining
            sleep "$delay"
            elapsed=$((elapsed + delay))
            delay=$((delay * 2))
        done

        if [[ $status == success ]]; then
            after_version=$(package_version "$package")
            if ! dpkg --compare-versions "$after_version" ge "$candidate"; then
                status=failed
                reason='Installed version did not reach planned candidate'
            fi
        fi

        # Restart services only after the upgrade succeeds, and never in the
        # reboot-required case. Avoid systemctl on placeholder names.
        if [[ $status == success && $restart == true && $reboot == false ]]; then
            for service in "${services[@]}"; do
                [[ $service =~ ^[[:alnum:]_.@:-]+\.service$ ]] || continue
                if systemctl try-restart "$service" > "$TMP_DIR/restart.out" \
                    2> "$TMP_DIR/restart.err"; then
                    result=ok
                else
                    result=failed
                    status=failed
                    reason="Unable to try-restart $service"
                fi
                restart_results=$(jq -nc --argjson results "$restart_results" \
                    --arg service "$service" --arg result "$result" \
                    '$results + [{service:$service, result:$result}]')
                printf '\n    try-restart %-24s %s' "$service" "$result"
                [[ $status == failed ]] && break
            done
        fi
    fi

    after_version=$(package_version "$package")
    after_services=$(service_states "${services[@]}")
    post=$(jq -nc --arg version "$after_version" \
        --argjson services "$after_services" \
        '{installed_version:$version, service_states:$services}')
    duration=$(( $(date +%s) - started ))
    entry=$(jq -nc --argjson entry "$entry" --argjson post "$post" \
        --arg status "$status" --argjson duration "$duration" \
        --arg stdout "$stdout_tail" --arg stderr "$stderr_tail" \
        --argjson restarts "$restart_results" --arg reason "$reason" \
        '$entry + {post:$post, status:$status, duration_seconds:$duration,
                   stdout_tail:$stdout, stderr_tail:$stderr,
                   restart_results:$restarts, failure_reason:(if $reason == "" then null else $reason end)}')
    update_entry "$entry"
    CURRENT_ENTRY=''

    case $status in
        success) success=$((success + 1)); echo 'OK' ;;
        simulated) skipped=$((skipped + 1)); echo 'SIMULATED (no changes)' ;;
        skipped) skipped=$((skipped + 1)); echo 'SKIPPED (already current)' ;;
        failed) failed=$((failed + 1)); printf 'FAILED: %s\n' "$reason"; break ;;
    esac
done

finished_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
if (( failed > 0 )); then
    final_status=failed
    code=1
else
    final_status=completed
    code=0
fi
replace_log '.finished_at = $finished | .status = $status |
             .summary = {succeeded:$succeeded, failed:$failed, skipped:$skipped}' \
    --arg finished "$finished_at" --arg status "$final_status" \
    --argjson succeeded "$success" --argjson failed "$failed" --argjson skipped "$skipped"
FINISHED=true
printf '\nSucceeded: %d  Failed: %d  Skipped/dry-run: %d\n' "$success" "$failed" "$skipped"
printf 'Log saved to: %s\n' "$LOG_FILE"
exit "$code"
