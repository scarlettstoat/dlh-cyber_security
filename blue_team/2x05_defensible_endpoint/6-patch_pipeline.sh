#!/bin/bash
# Task 6: 0 complete, 1 pipeline or policy failure, 2 missing prerequisite.
set -euo pipefail
export LC_ALL=C

die() {
    printf '%s\n' "$2" >&2
    exit "$1"
}

(( $# == 0 )) || die 2 "Usage: $0"
for tool in apt-config bash cmp cp date dirname flock hostname install jq mkdir mktemp mv \
    python3 rm sed unattended-upgrade; do
    command -v "$tool" >/dev/null 2>&1 || die 2 "Missing dependency: $tool"
done
host=$(hostname -s)
[[ $host == hawthorne-app-01 ]] || die 2 "Expected hawthorne-app-01. Current host: $host"
(( EUID == 0 )) || die 2 'Run with sudo on the Hawthorne Linux endpoint.'

root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
legacy="$root/../2x03_patch_equation"
lab=/home/analyst/MedDefense_Lab/capstone
feed="$lab/cve_feed.json"
blacklist="$lab/blacklist.json"
apt_dir=/etc/apt/apt.conf.d
apt_file="$apt_dir/99meddefense-patch-blacklist"
artifact_dir=capstone/patch
output="$root/$artifact_dir"
executor=4-patch_execute.sh
scripts=(0-vuln_inventory.sh 1-service_deps.sh 2-pre_patch_snapshot.sh
         3-patch_plan.sh "$executor" 5-post_patch_validate.sh)
reports=(vulnerability_inventory.json service_dependency_map.json pre_patch_state.json
         patch_plan.json patch_execution_log.json post_patch_validation.json)

for path in "$feed" "$blacklist" "$root/2-target_state.sh"; do
    [[ -f $path && -r $path ]] || die 2 "Missing input: $path"
done
for script in "${scripts[@]}"; do
    [[ -f $legacy/$script && -r $legacy/$script ]] ||
        die 2 "Missing previous project script: $script"
done
bash "$root/2-target_state.sh" --validate
jq -es 'length == 1 and (.[0] | type == "object" or type == "array")' "$feed" >/dev/null ||
    die 2 'The capstone CVE feed must be a single JSON object or array.'

mkdir -p -- "$output"
exec {lock_fd}>"$output/.patch_pipeline.lock"
flock -n "$lock_fd" || die 1 'Another Task 6 run is in progress.'
stage=$(mktemp -d "$root/capstone/.patch-run.XXXXXX")
work="$stage/$artifact_dir"
apt_tmp=
preserve_stage=false
trap '
    if [[ -n $apt_tmp ]]; then rm -f -- "$apt_tmp"; fi
    if [[ $preserve_stage == true ]]; then
        printf "Partial run evidence is available in %s\n" "$work" >&2
    else
        rm -rf -- "$stage"
    fi
' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# The earlier scripts resolve their output paths beside themselves or from the
# working directory. Give both a fresh capstone workspace for this run.
mkdir -p -- "$work"
for script in "${scripts[@]}"; do cp -- "$legacy/$script" "$work/$script"; done
cp -- "$feed" "$work/cve_feed.json"
for input in service_criticality.json service_probes.json; do
    for directory in "$lab" "$legacy"; do
        if [[ -f $directory/$input ]]; then
            cp -- "$directory/$input" "$work/$input"
            break
        fi
    done
done
export CAPSTONE_ARTIFACTS_DIR="$work/"

# Append the required regexes through a dedicated APT fragment.
python3 - "$blacklist" > "$stage/blacklist.conf" <<'PYTHON'
import json
import re
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as source:
        patterns = json.load(source)
    if not isinstance(patterns, list) or not patterns:
        raise ValueError("expected a non-empty JSON array")
    for pattern in patterns:
        if (not isinstance(pattern, str) or not pattern
                or any(c == '"' or ord(c) < 32 or ord(c) == 127 for c in pattern)):
            raise ValueError("each entry must be a non-empty APT-safe regular expression")
        re.compile(pattern)
except (OSError, ValueError, re.error) as error:
    sys.exit(f"Invalid unattended-upgrades blacklist: {error}")

print("Unattended-Upgrade::Package-Blacklist {")
for pattern in dict.fromkeys(patterns):
    print(f'    "{pattern}";')
print("};")
PYTHON
apt-config -c "$stage/blacklist.conf" dump >/dev/null ||
    die 1 'APT rejected the blacklist configuration.'
if ! cmp -s "$stage/blacklist.conf" "$apt_file"; then
    apt_tmp=$(mktemp "$apt_dir/.meddefense-blacklist.XXXXXX")
    install -m 0644 -- "$stage/blacklist.conf" "$apt_tmp"
    mv -fT -- "$apt_tmp" "$apt_file"
    apt_tmp=
fi
apt-config dump | jq -eRs --slurpfile required "$blacklist" '
    [split("\n")[] |
     capture("^Unattended-Upgrade::Package-Blacklist:: \"(?<pattern>.*)\";$").pattern] as $active
    | ($required[0] - $active | length) == 0
' >/dev/null || die 1 'One or more required blacklist entries are missing from active APT settings.'

log=patch_pipeline.log
: > "$work/$log"
: > "$stage/steps.jsonl"
publish=("$log")

run_previous_pipeline() {
    local index script report path code status overall=0
    local -a args=()
    for index in "${!scripts[@]}"; do
        script=${scripts[index]}
        report=${reports[index]}
        args=()
        if [[ $script == "$executor" ]]; then
            args=(--execute)
            # Let a freshly generated empty plan produce the executor's normal
            # zero-entry log. This compatibility edit is scoped to the work copy.
            if jq -e '.plan | type == "array" and length == 0' "$work/patch_plan.json" >/dev/null; then
                sed -i 's/(\.plan | type == "array" and length > 0) and/(.plan | type == "array") and/' \
                    "$work/$executor" || return 1
            fi
        fi
        printf 'Running %s\n' "$script"
        printf '\n--- %s ---\n' "$script" >> "$work/$log" || return 1
        if (cd -- "$work" && bash "./$script" "${args[@]}") >> "$work/$log" 2>&1; then
            code=0
        else
            code=$?
        fi
        printf 'Exit code: %s\n' "$code" >> "$work/$log" || return 1
        path=
        status=$code
        if [[ -s $work/$report ]] &&
            jq -es 'length == 1 and (.[0] | type == "object")' "$work/$report" >/dev/null; then
            path="$artifact_dir/$report"
            publish+=("$report")
        elif (( code == 0 )); then
            printf 'Missing or invalid artifact: %s\n' "$report" >> "$work/$log" || return 1
            status=1
        fi
        jq -cn --arg script "$script" --arg report "$report" --arg path "$path" \
            --argjson code "$code" '
            {script:$script, exit_code:$code, artifact:$report,
             artifact_path:(if $path == "" then null else $path end)}
        ' >> "$stage/steps.jsonl" || return 1

        if (( status != 0 && overall == 0 )); then overall=$status; fi
        # Still check service health if the executor failed after making changes.
        if (( status != 0 )) && [[ $script != "$executor" ]]; then break; fi
    done
    return "$overall"
}

preserve_stage=true
pipeline_exit_code=0
run_previous_pipeline || pipeline_exit_code=$?
failed_entries=null
execution_report="$work/patch_execution_log.json"
if [[ -s $execution_report ]]; then
    failed_entries=$(jq -er '
        select(.entries | type == "array")
        | [.entries[] | select((.status // .state // .result) == "failed")] | length
    ' "$execution_report") || failed_entries=null
fi

summary=patch_pipeline_summary.json
jq -s --arg timestamp "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" --arg hostname "$host" \
    --arg feed "$feed" --arg blacklist "$blacklist" --arg config "$apt_file" \
    --arg log "$artifact_dir/$log" --argjson code "$pipeline_exit_code" \
    --argjson failed "$failed_entries" '
    {timestamp:$timestamp, hostname:$hostname, cve_feed:$feed, blacklist:$blacklist,
     unattended_upgrades_config:$config, pipeline_exit_code:$code, failed_entries:$failed,
     log_path:$log, steps:., artifacts:(map(select(.artifact_path != null) |
       {key:.artifact, value:.artifact_path}) | from_entries), passed:($code == 0 and $failed == 0)}
' "$stage/steps.jsonl" > "$work/$summary"

# Keep earlier reports together so an incomplete run cannot reuse stale evidence.
previous=
for artifact in "$summary" "$log" "${reports[@]}"; do
    [[ -e $output/$artifact ]] || continue
    if [[ -z $previous ]]; then previous=$(mktemp -d "$output/.previous.XXXXXX"); fi
    mv -T -- "$output/$artifact" "$previous/$artifact"
done
for artifact in "${publish[@]}" "$summary"; do
    mv -fT -- "$work/$artifact" "$output/$artifact"
done
preserve_stage=false

printf 'Pipeline summary: %s\n' "$output/$summary"
if (( pipeline_exit_code == 0 )) && [[ $failed_entries == 0 ]]; then
    exit 0
fi
die 1 "Pipeline exit code: $pipeline_exit_code. Failed entries: $failed_entries."
