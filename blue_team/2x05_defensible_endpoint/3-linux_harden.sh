#!/bin/bash
# Exit codes: 0 complete and at target, 1 execution or validation failed,
# 2 missing dependency, input, or the required lab environment.
set -o pipefail
export LC_ALL=C

die() {
    printf '%s\n' "$2" >&2
    exit "$1"
}

for cmd in awk bash cat cmp comm date dirname find findmnt flock grep hostname jq \
    lynis mkdir mktemp mv rm sha256sum sort stat systemctl; do
    command -v "$cmd" >/dev/null 2>&1 || die 2 "Missing dependency: $cmd"
done

host=$(hostname -s) || die 2 'Cannot read the hostname.'
[[ $host == hawthorne-app-01 ]] || die 2 "Run on hawthorne-app-01. Current host: $host"
(( EUID == 0 )) || die 2 'Run with sudo from the Hawthorne VM console.'
[[ -z ${SSH_CONNECTION-}${SSH_CLIENT-}${SSH_TTY-} ]] ||
    die 2 'Use the VM console because the PAM and AppArmor scripts require it.'

root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd) ||
    die 2 'Cannot locate the project directory.'
target="$root/capstone/target_state.json"
baseline="$root/capstone/baseline/baseline_linux.json"
output="$root/capstone/exec"
report="$output/linux_harden.json"
legacy=${HARDENING_STEPS_DIR:-"$root/../2x00_locking_the_gates"}
legacy=$(CDPATH='' cd -- "$legacy" && pwd) || die 2 'Cannot locate the prior hardening scripts.'

[[ -r $root/2-target_state.sh ]] || die 2 'Missing the Task 2 target-state validator.'
if bash "$root/2-target_state.sh" --validate; then
    :
else
    exit "$?"
fi

[[ -r $baseline ]] || die 2 'Run the Linux baseline snapshot on Hawthorne first.'
score='type == "number" and . >= 0 and . <= 100 and floor == .'
lynis_before=$(jq -er --arg host "$host" \
    "select((.hostname | strings | split(\".\")[0]) == \$host) | .hardening_index | select($score)" "$baseline") ||
    die 2 'The baseline must record a valid Hardening Index from hawthorne-app-01.'
required_index=$(jq -er ".linux.hardening_index | select($score)" "$target") ||
    die 1 'The target Lynis index is invalid.'

names=(ssh_hardening sysctl_hardening permission_sweep service_minimization
       pam_configuration apparmor_enforcement auditd_deployment)
pam_script=8-pam_hardening.sh
[[ -r $legacy/$pam_script ]] || pam_script=8-service_minimization.sh
scripts=(4-ssh_hardening.sh 5-sysctl_hardening.sh 6-filesystem_hardening.sh
         7-service_minimization.sh "$pam_script" 9-apparmor_config.sh 10-auditd_config.sh)

for script in "${scripts[@]}"; do
    [[ -f $legacy/$script && -r $legacy/$script ]] ||
        die 2 "Missing hardening script: $legacy/$script"
done

mkdir -p -- "$output" || die 2 'Cannot create the execution directory.'
exec {lock_fd}>"$output/.linux_harden.lock" || die 2 'Cannot open the execution lock.'
flock -n "$lock_fd" || die 1 'Another Linux hardening run is active.'

previous='[]'
if [[ -r $report ]]; then
    previous=$(jq -c --arg host "$host" 'if .hostname == $host then .steps // [] else [] end' \
        "$report" 2>/dev/null) || previous='[]'
fi
staging=$(mktemp -d "$output/.hardening.XXXXXX") || die 2 'Cannot stage execution evidence.'
trap 'rm -rf -- "$staging"' EXIT
log="$staging/linux_harden.log"
step_records="$staging/steps.jsonl"
timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ') || die 2 'Cannot read the clock.'

file_state() {
    local path
    for path in "$@"; do
        if [[ -f $path ]]; then
            stat -c '%a %u %g %n' -- "$path" && sha256sum -- "$path" || return 1
        else
            printf 'absent %s\n' "$path"
        fi
    done
}

record_state() {
    local label=$1 value digest
    shift
    if value=$("$@" 2>/dev/null); then
        digest=$(printf '%s\n' "$value" | sha256sum) || return 1
        printf '%s\t%s\n' "$label" "${digest%% *}"
    else
        printf '%s\tunknown\n' "$label"
    fi
}

ssh_setting() {
    sshd -T | awk -v key="$1" '$1 == key { print $2 }'
}

kernel_state() {
    file_state /etc/sysctl.conf || return 1
    sysctl net.ipv4.conf.{all,default}.accept_redirects net.ipv4.conf.all.send_redirects \
        net.ipv4.conf.all.{accept_source_route,log_martians} net.ipv4.tcp_syncookies \
        net.ipv4.icmp_echo_ignore_broadcasts net.ipv6.conf.{all,default}.disable_ipv6 \
        fs.suid_dumpable kernel.{dmesg_restrict,kptr_restrict}
}

permission_state() {
    local path
    find / -ignore_readdir_race \
        \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o \
        \( -type f -perm /6002 -o -type d -perm -0002 ! -perm -1000 \) \
        -printf '%m %p\0' | sort -z | sha256sum || return 1
    for path in /tmp /var/tmp /dev/shm; do
        printf '%s ' "$path"
        findmnt -n -M "$path" -o OPTIONS || printf 'unmounted\n'
    done
    file_state /etc/cron.allow
}

service_state() {
    systemctl list-unit-files --type=service --no-legend --no-pager --full |
        awk '{print $1, $2}' | sort
}

audit_rule_state() {
    file_state /etc/audit/rules.d/meddefense.rules || return 1
    auditctl -l | sort
}

snapshot() {
    case "$1" in
        ssh_hardening)
            record_state LNX-SSH-01 ssh_setting permitrootlogin
            record_state LNX-SSH-02 ssh_setting passwordauthentication
            record_state ssh_files file_state /etc/ssh/sshd_config /etc/issue.net
            ;;
        sysctl_hardening)
            record_state LNX-SYS-01 sysctl -n net.ipv4.ip_forward
            record_state LNX-SYS-02 sysctl -n kernel.randomize_va_space
            record_state sysctl_config kernel_state
            ;;
        permission_sweep)
            record_state permissions permission_state
            ;;
        service_minimization)
            record_state services service_state
            ;;
        pam_configuration)
            record_state pam file_state /etc/pam.d/common-{auth,password} \
                /etc/security/{pwquality,faillock}.conf
            ;;
        apparmor_enforcement)
            record_state LNX-MAC-01 sort /sys/kernel/security/apparmor/profiles
            record_state apparmor_files file_state /etc/apparmor.d/*
            ;;
        auditd_deployment)
            record_state LNX-AUD-01 systemctl show auditd -p ActiveState -p UnitFileState
            record_state LNX-AUD-02 audit_rule_state
            ;;
    esac
}

state_hash() {
    local result
    result=$({ sha256sum <"$1" && cat "$2"; } | sha256sum) || return 1
    printf '%s\n' "${result%% *}"
}

run_step() {
    local name=$1 script=$2 before="$staging/before" after="$staging/after"
    local before_hash after_hash cached start duration status changed touched
    snapshot "$name" >"$before" || die 1 "Cannot observe $name before execution."
    before_hash=$(state_hash "$script" "$before") || die 1 "Cannot hash $name evidence."
    cached=$(jq -r --arg name "$name" --arg path "$script" '
        [.[] | select(.name == $name and .script_path == $path and .exit_code == 0)
         | .state_sha256][0] // ""
    ' <<<"$previous") || cached=''

    printf '\n[%s] script=%s\n' "$name" "$script" >>"$log" ||
        die 1 'Cannot append to the execution log.'
    start=$SECONDS
    if [[ $before_hash == "$cached" ]] && ! grep -q $'\tunknown$' "$before"; then
        printf 'Already applied and the observed state matches the last successful run.\n' >>"$log" ||
            die 1 'Cannot append to the execution log.'
        status=0
    elif (cd -- "$legacy" && bash "$script") >>"$log" 2>&1; then
        status=0
    else
        status=$?
    fi
    duration=$((SECONDS - start))

    snapshot "$name" >"$after" || die 1 "Cannot observe $name after execution."
    after_hash=$(state_hash "$script" "$after") || die 1 "Cannot hash $name evidence."
    changed=false
    if ! cmp -s "$before" "$after"; then
        changed=true
    fi
    touched=$(comm -13 <(sort "$before") <(sort "$after") |
        jq -Rsc --slurpfile target "$target" '
            split("\n") | map(split("\t")[0]) as $labels
            | [$target[0].controls[].id | select(. as $id | $labels | index($id) != null)]
        ') || die 1 "Cannot record changed controls for $name."
    printf '[%s] exit_code=%s duration_seconds=%s changed=%s\n' \
        "$name" "$status" "$duration" "$changed" >>"$log" ||
        die 1 'Cannot append to the execution log.'
    jq -cn --arg name "$name" --arg script_path "$script" --argjson exit_code "$status" \
        --argjson duration_seconds "$duration" --argjson changed "$changed" \
        --argjson controls_touched "$touched" --arg state_sha256 "$after_hash" \
        '{name: $name, script_path: $script_path, exit_code: $exit_code,
          duration_seconds: $duration_seconds, changed: $changed,
          controls_touched: $controls_touched, state_sha256: $state_sha256}' \
        >>"$step_records" || die 1 'Cannot write step evidence.'
}

for index in "${!names[@]}"; do
    run_step "${names[index]}" "$legacy/${scripts[index]}"
done

printf '\n[lynis] post-hardening audit\n' >>"$log" || die 1 'Cannot log the post-hardening audit.'
lynis_after=null
if lynis audit system --quick --no-colors >"$staging/lynis.log" 2>&1; then
    parsed=$(awk 'tolower($0) ~ /^[[:space:]]*hardening index[[:space:]]*:/ && match($0, /[0-9]+/) {
        score = substr($0, RSTART, RLENGTH) + 0
        found = 1
    } END {
        if (!found || score > 100) exit 1
        print score
    }' "$staging/lynis.log") && lynis_after=$parsed
fi
cat "$staging/lynis.log" >>"$log" || die 1 'Cannot append the Lynis output.'
printf '[lynis] before=%s after=%s required=%s\n' \
    "$lynis_before" "$lynis_after" "$required_index" >>"$log" ||
    die 1 'Cannot record the Lynis scores.'

jq -s --arg timestamp "$timestamp" --arg hostname "$host" \
    --argjson lynis_before "$lynis_before" --argjson lynis_after "$lynis_after" \
    --argjson required_index "$required_index" '
    {
        timestamp: $timestamp, hostname: $hostname, steps: .,
        lynis_before: $lynis_before, lynis_after: $lynis_after,
        index_delta: (if $lynis_after == null then null else $lynis_after - $lynis_before end),
        controls_touched: ([.[].controls_touched[]] | unique),
        passed: ($lynis_after != null and $lynis_after >= $required_index
                 and all(.[]; .exit_code == 0))
    }
' "$step_records" >"$staging/linux_harden.json" || die 1 'Cannot build the execution report.'

mv -fT -- "$log" "$output/linux_harden.log" || die 1 'Cannot publish the execution log.'
mv -fT -- "$staging/linux_harden.json" "$report" || die 1 'Cannot publish the execution report.'
jq -e '.passed' "$report" >/dev/null || die 1 'Hardening or the Lynis threshold failed. See capstone/exec/.'
printf 'Linux hardening met the Lynis target of %s.\n' "$required_index"
