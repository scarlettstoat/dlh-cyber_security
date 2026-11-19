#!/bin/bash
# Exit codes: 0 success, 1 audit or report failure, 2 environment error.
set -o pipefail
export LC_ALL=C

fail() {
    printf '%s\n' "$2" >&2
    exit "$1"
}

for tool in lynis jq awk date hostname dirname mkdir mktemp mv rm; do
    command -v "$tool" >/dev/null 2>&1 || fail 2 "Missing dependency: $tool"
done

project_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd) ||
    fail 2 'Cannot resolve the project directory.'
output_dir="$project_dir/capstone/baseline"
log_path='capstone/baseline/lynis_baseline.log'
mkdir -p -- "$output_dir" || fail 2 'Cannot create the baseline directory.'
staging=$(mktemp -d "$output_dir/.lynis.XXXXXX") || fail 2 'Cannot stage baseline files.'
trap 'rm -rf -- "$staging"' EXIT

audit_log="$staging/lynis_baseline.log"
lynis audit system --quick --no-colors >"$audit_log" 2>&1 ||
    fail 1 'Lynis audit failed.'

metadata=$(awk '
    tolower($1) == "lynis" && $2 ~ /^[0-9]+\.[0-9]+/ && version == "" { version = $2 }
    { line = tolower($0) }
    line ~ /^[[:space:]]*hardening index[[:space:]]*:/ && match(line, /[0-9]+/) {
        score = substr(line, RSTART, RLENGTH)
    }
    line ~ /^[[:space:]]*warnings[[:space:]]*[:(][[:space:]]*[0-9]+/ && match(line, /[0-9]+/) {
        warnings = substr(line, RSTART, RLENGTH)
    }
    line ~ /^[[:space:]]*suggestions[[:space:]]*[:(][[:space:]]*[0-9]+/ && match(line, /[0-9]+/) {
        suggestions = substr(line, RSTART, RLENGTH)
    }
    END {
        if (score == "") exit 1
        if (version == "") version = "-"
        printf "%s\t%d\t%d\t%d\n", version, score, warnings, suggestions
    }
' "$audit_log") || fail 1 'No Hardening Index found in the Lynis output.'

IFS=$'\t' read -r lynis_version hardening_index warnings_count suggestions_count <<< "$metadata"
if [[ $lynis_version == '-' ]]; then
    lynis_version=$(lynis show version) || fail 1 'Cannot read the Lynis version.'
fi
[[ $lynis_version =~ ^[0-9]+\.[0-9]+ ]] || fail 1 'Invalid Lynis version.'

timestamp=$(date -u +'%Y-%m-%dT%H:%M:%SZ') || fail 1 'Cannot read the timestamp.'
host_name=$(hostname) || fail 1 'Cannot read the hostname.'
jq -n \
    --arg timestamp "$timestamp" \
    --arg hostname "$host_name" \
    --arg lynis_version "$lynis_version" \
    --argjson hardening_index "$hardening_index" \
    --argjson warnings_count "$warnings_count" \
    --argjson suggestions_count "$suggestions_count" \
    --arg log_path "$log_path" \
    '{timestamp: $timestamp, hostname: $hostname, lynis_version: $lynis_version,
      hardening_index: $hardening_index, warnings_count: $warnings_count,
      suggestions_count: $suggestions_count, log_path: $log_path}' \
    >"$staging/baseline_linux.json" || fail 1 'Cannot write the Linux baseline JSON.'

mv -f -- "$audit_log" "$staging/baseline_linux.json" "$output_dir/" ||
    fail 1 'Cannot save the Linux baseline.'
