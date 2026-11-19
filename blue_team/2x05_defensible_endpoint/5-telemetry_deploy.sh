#!/bin/bash
# Exit codes: 0 all actions verified, 1 verification failed, 2 missing prerequisite.
set -o pipefail
export LC_ALL=C

die() { printf '%s\n' "$2" >&2; exit "$1"; }

for tool in auditctl augenrules ausearch awk bash cmp date dirname find flock getent \
    grep hostname install jq mkdir mktemp mv python3 readlink rm sleep sort systemctl useradd userdel; do
    command -v "$tool" >/dev/null 2>&1 || die 2 "Missing dependency: $tool"
done
host=$(hostname -s) || die 2 'Cannot read hostname.'
[[ $host == hawthorne-app-01 ]] || die 2 "Expected hawthorne-app-01. Current host: $host"
(( EUID == 0 )) || die 2 'Run with sudo on the Hawthorne VM.'

root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd) || die 2 'Cannot locate the project.'
exporter="$root/../2x02_eyes_on_endpoint/7-linux_export.sh"
provided_rules=/etc/audit/rules.d/meddefense.rules
supplement=/etc/audit/rules.d/76-meddefense-task5.rules
[[ -r $root/2-target_state.sh && -r $exporter && -s $provided_rules && -d /etc/cron.d ]] ||
    die 2 'Missing the target validator, Linux exporter, project audit rules or cron directory.'
bash "$root/2-target_state.sh" --validate || exit "$?"
nologin=$(command -v nologin) || die 2 'Missing nologin.'
getent group nogroup >/dev/null || die 2 'Missing the nogroup group.'
getent passwd nobody >/dev/null || die 2 'Missing the nobody account.'

output="$root/capstone/telemetry"
mkdir -p -- "$output" || die 2 'Cannot create the telemetry directory.'
exec {lock_fd}>"$output/.linux_telemetry.lock" || die 2 'Cannot open the telemetry lock.'
flock -n "$lock_fd" || die 1 'Another telemetry run is in progress.'
stage=$(mktemp -d "$output/.linux-telemetry.XXXXXX") || die 2 'Cannot stage evidence.'
suffix=${stage##*.}
test_user="mdt-${suffix,,}"
cron_file="/etc/cron.d/$test_user"
own_user=false
own_cron=false
cleanup() {
    local rc=0
    if [[ $own_cron == true ]]; then rm -f -- "$cron_file" || rc=1; fi
    if [[ $own_user == true ]] && getent passwd "$test_user" >/dev/null; then
        userdel "$test_user" || rc=1
    fi
    return "$rc"
}
trap 'cleanup || printf "Fixture cleanup failed.\n" >&2; rm -rf -- "$stage"' EXIT
trap 'exit 1' INT TERM
if getent passwd "$test_user" >/dev/null || [[ -e $cron_file || -L $cron_file ]]; then
    die 2 'The generated test name is already in use.'
fi

# Keep the capstone rules in place. Add only the probes this task needs.
systemctl is-active --quiet auditd || systemctl start auditd || die 1 'Cannot start auditd.'
useradd_path=$(readlink -f "$(command -v useradd)") || die 2 'Cannot resolve useradd.'
userdel_path=$(readlink -f "$(command -v userdel)") || die 2 'Cannot resolve userdel.'
systemctl_path=$(readlink -f "$(command -v systemctl)") || die 2 'Cannot resolve systemctl.'
find_path=$(readlink -f "$(command -v find)") || die 2 'Cannot resolve find.'
cron_key=meddefense-cron
shared_key=
for rule_file in /etc/audit/rules.d/*.rules; do
    [[ $rule_file != "$supplement" && -r $rule_file ]] || continue
    shared_key=$(awk '
        $1 == "-w" && ($2 == "/etc/cron.d" || $2 == "/etc/cron.d/") {
            perms = key = ""
            for (i = 3; i < NF; i++) {
                if ($i == "-p") perms = $(i+1)
                if ($i == "-k") key = $(i+1)
            }
            if (perms ~ /w/ && key != "") { print key; exit }
        }
    ' "$rule_file")
    if [[ -n $shared_key ]]; then cron_key=$shared_key; break; fi
done
{
    printf '# MedDefense Task 5 telemetry\n'
    for path in "$useradd_path" "$userdel_path"; do
        printf '%s\n' "-a always,exit -F arch=b64 -F path=$path -F perm=x -F euid=0 -k meddefense-user-mgmt"
    done
    printf '%s\n' "-a always,exit -F arch=b64 -F path=$systemctl_path -F perm=x -F euid=0 -k meddefense-service"
    printf '%s\n' "-a always,exit -F arch=b64 -F path=$find_path -F perm=x -F euid=0 -k meddefense-root-find"
    if [[ -z $shared_key ]]; then
        printf '%s\n' '-w /etc/cron.d/ -p wa -k meddefense-cron'
    fi
} > "$stage/task5.rules" || die 1 'Cannot stage audit rules.'

rule_keys() {
    awk '!/^[[:space:]]*#/ {
        for (i=1;i<NF;i++) {
            if ($i=="-k") print $(i+1)
            if ($i=="-F" && $(i+1)~/^key=/) print substr($(i+1),5)
        }
    }' "$@" | sort -u
}
rules_loaded() {
    local active required key
    active=$(auditctl -l | rule_keys) || return 1
    required=$(rule_keys "$provided_rules" "$stage/task5.rules") || return 1
    while IFS= read -r key; do
        grep -Fxq -- "$key" <<< "$active" || return 1
    done <<< "$required"
    grep -Fxq -- "$cron_key" <<< "$active"
}

if ! cmp -s "$stage/task5.rules" "$supplement" || ! rules_loaded; then
    audit_status=$(auditctl -s) || die 1 'Cannot read the audit state.'
    if grep -Eq '^enabled[[:space:]]+2$' <<< "$audit_status"; then
        die 1 'Audit policy is locked and one or more Task 5 rules are missing.'
    fi
    if ! cmp -s "$stage/task5.rules" "$supplement"; then
        install -m 0640 -- "$stage/task5.rules" "$supplement" || die 1 'Cannot install Task 5 audit rules.'
    fi
    augenrules --load || die 1 'Cannot load the project audit rules.'
fi
rules_loaded || die 1 'One or more required audit keys are missing.'

read -r run_day run_time < <(date '+%m/%d/%Y %H:%M:%S')
run_action() {
    local action=$1 key=$2 alternate=$3
    local pid attempt candidate hits expected=$key serials='[]' passed=false error=''
    shift 3
    [[ -z $alternate ]] || expected="$key or $alternate"
    "$@" >"$stage/$action.log" 2>&1 &
    pid=$!
    if wait "$pid"; then
        for ((attempt=0; attempt<8; attempt++)); do
            for candidate in "$key" "$alternate"; do
                [[ -n $candidate ]] || continue
                hits=$(ausearch --input-logs -k "$candidate" -p "$pid" \
                    -ts "$run_day" "$run_time" -sv yes --raw 2>/dev/null) || continue
                serials=$(jq -Rsc '[scan("audit\\([0-9.]+:([0-9]+)\\)") | .[0]] | unique' <<<"$hits") ||
                    die 1 'Cannot read the audit serials.'
                if [[ $serials != '[]' ]]; then passed=true; break 2; fi
            done
            sleep 0.5
        done
        [[ $passed == true ]] || error='No matching successful audit event.'
    else
        error="Test action exited with code $?."
    fi
    jq -cn --arg action "$action" --arg expected "$expected, pid=$pid" \
        --argjson passed "$passed" --argjson evidence "$serials" --arg error "$error" '
        {action:$action, source:"auditd", expected:$expected, passed:$passed,
         evidence:$evidence, error:(if $error == "" then null else $error end)}
    ' >> "$stage/actions.jsonl" || die 1 'Cannot record the test result.'
    printf '%s: %s\n' "$action" "$passed"
}

own_user=true
run_action create_user meddefense-user-mgmt process_exec \
    "$useradd_path" -M -N -g nogroup -s "$nologin" -p '!' "$test_user"
run_action remove_user meddefense-user-mgmt process_exec "$userdel_path" "$test_user"
run_action inspect_service meddefense-service process_exec \
    "$systemctl_path" show --property=ActiveState auditd.service

# The disposable cron entry can only run a no-op as nobody.
printf '0 0 1 1 * nobody /usr/bin/true\n' > "$stage/cron" || die 1 'Cannot stage the cron fixture.'
own_cron=true
run_action schedule_cron "$cron_key" "" install -m 0644 -- "$stage/cron" "$cron_file"
run_action remove_cron "$cron_key" "" rm -- "$cron_file"
run_action root_find meddefense-root-find process_exec "$find_path" "$stage" -maxdepth 1 -type f -name task5.rules

cleanup_ok=false
if cleanup; then
    cleanup_ok=true
    own_user=false
    own_cron=false
fi

end_stamp=$(date +%s.%N) || die 1 'Cannot read the clock.'
end_epoch=${end_stamp%.*}
start_epoch=$((end_epoch - 1800))
start_utc=$(date -u -d "@$start_epoch.${end_stamp#*.}" '+%Y-%m-%dT%H:%M:%S.%NZ')
end_utc=$(date -u -d "@$end_stamp" '+%Y-%m-%dT%H:%M:%S.%NZ')
read -r start_day start_time < <(date -d "@$start_epoch" '+%m/%d/%Y %H:%M:%S')
read -r end_day end_time < <(date -d "@$end_epoch" '+%m/%d/%Y %H:%M:%S')

collect_events() {
    ausearch --input-logs -ts "$start_day" "$start_time" -te "$end_day" "$end_time" \
        --raw > "$stage/audit.log" || return 1
    local syslog=/var/log/syslog
    if [[ ! -r $syslog ]]; then
        command -v journalctl >/dev/null 2>&1 && command -v sed >/dev/null 2>&1 || return 1
        syslog="$stage/syslog"
        journalctl --utc --no-pager -q -o short-iso-precise \
            --since "@$start_epoch" --until "@$end_epoch" _TRANSPORT=syslog |
            sed -E 's/^([^ ]+)\+0000 /\1Z /' > "$syslog" || return 1
    fi
    : > "$stage/auth.log"
    bash "$exporter" --start "$start_utc" --end "$end_utc" --auth-log "$stage/auth.log" \
        --audit-log "$stage/audit.log" --syslog "$syslog" --output "$stage/linux_events.json" ||
        return 1
    jq -e --slurpfile actions "$stage/actions.jsonl" '
        . as $events
        | type == "array" and any(.[]; .source_type == "auditd")
          and all($actions[] | .evidence[]; . as $serial |
              any($events[]; .source_type == "auditd" and (.audit_serial | tostring) == $serial))
    ' "$stage/linux_events.json" >/dev/null
}

export_ok=false
if collect_events && mv -fT -- "$stage/linux_events.json" "$output/linux_events.json"; then
    export_ok=true
fi
jq -s --arg timestamp "$end_utc" --arg hostname "$host" \
    --argjson export_ok "$export_ok" --argjson cleanup_ok "$cleanup_ok" '
    {timestamp:$timestamp, hostname:$hostname, platform:"linux", actions:., export_ok:$export_ok,
     cleanup_ok:$cleanup_ok, all_passed:(length == 6 and all(.[]; .passed) and $export_ok and $cleanup_ok)}
' "$stage/actions.jsonl" > "$stage/linux_coverage.json" || die 1 'Cannot write Linux coverage.'
mv -fT -- "$stage/linux_coverage.json" "$output/linux_coverage.json" || die 1 'Cannot publish Linux coverage.'
jq -e '.all_passed' "$output/linux_coverage.json" >/dev/null
