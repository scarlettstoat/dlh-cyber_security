#!/bin/bash
# Task 5: Compare running services, listening ports and critical probes with the baseline.
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SNAPSHOT="$SCRIPT_DIR/pre_patch_state.json"
DEPENDENCIES="$SCRIPT_DIR/service_dependency_map.json"
PROBES="$SCRIPT_DIR/service_probes.json"
OUTPUT="$SCRIPT_DIR/post_patch_validation.json"

if (( EUID != 0 )); then
    echo "Run this script with sudo to inspect the full service and socket state." >&2
    exit 1
fi

for tool in jq systemctl ss timeout mktemp date hostname; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required command: $tool" >&2
        exit 1
    fi
done

if [[ ! -f $SNAPSHOT || ! -f $DEPENDENCIES ]]; then
    echo "Missing pre_patch_state.json or service_dependency_map.json." >&2
    exit 1
fi

# Reject empty templates: they do not contain an actual baseline to compare.
if ! jq -e '(.timestamp | type == "string") and
          (.services | type == "array") and
          (.listening | type == "array")' "$SNAPSHOT" >/dev/null; then
    echo "pre_patch_state.json must be a real snapshot from Task 2." >&2
    exit 1
fi
if ! jq -e '(.services | type == "array")' "$DEPENDENCIES" >/dev/null; then
    echo "Invalid service_dependency_map.json from Task 1." >&2
    exit 1
fi
if [[ -f $PROBES ]] && ! jq -e '.' "$PROBES" >/dev/null; then
    echo "Invalid service_probes.json." >&2
    exit 1
fi

work_dir=$(mktemp -d)
temp_output=""
cleanup() {
    rm -rf -- "$work_dir"
    if [[ -n $temp_output ]]; then
        rm -f -- "$temp_output"
    fi
}
trap cleanup EXIT
: > "$work_dir/checks.jsonl"

# Add one complete, machine-readable check to the report at a time.
add_check() {
    printf '%s\n' "$1" >> "$work_dir/checks.jsonl"
}

# SERVICE CHECKS: everything active before patching must still be active.
while IFS= read -r old; do
    service=$(jq -r '.service' <<< "$old")
    before=$(jq -r '.ActiveState // "unknown"' <<< "$old")
    after="unknown"
    sub_state="unknown"
    main_pid=0
    if service_info=$(systemctl show "$service" -p ActiveState -p SubState -p MainPID --no-pager 2>/dev/null); then
        after=$(sed -n 's/^ActiveState=//p' <<< "$service_info" | head -n 1)
        sub_state=$(sed -n 's/^SubState=//p' <<< "$service_info" | head -n 1)
        main_pid=$(sed -n 's/^MainPID=//p' <<< "$service_info" | head -n 1)
    fi
    [[ -n $after ]] || after="unknown"
    [[ -n $sub_state ]] || sub_state="unknown"
    [[ $main_pid =~ ^[0-9]+$ ]] || main_pid=0

    status="regression"
    if [[ $after == active ]]; then
        status="pass"
    fi
    add_check "$(jq -cn --arg check service_state --arg service "$service" \
        --arg expected "$before" --arg actual "$after" \
        --arg sub "$sub_state" --argjson pid "$main_pid" --arg status "$status" \
        '{check: $check, service: $service, expected_state: $expected,
          actual_state: $actual, sub_state: $sub, main_pid: $pid, status: $status}')"
done < <(jq -c '.services[]' "$SNAPSHOT")

# SOCKET CHECKS: compare protocol and port (rather than transient process IDs).
# Record the addresses as supporting information so interface changes are visible.
sockets_available=true
if ! ss -H -tulnp > "$work_dir/current_sockets.txt" 2> "$work_dir/ss_error.txt"; then
    sockets_available=false
fi

declare -A listening_ports=()
declare -A current_addresses=()
if [[ $sockets_available == true ]]; then
    while read -r proto _state _recv _send address _peer _process; do
        [[ $proto == tcp || $proto == udp || $proto == tcp6 || $proto == udp6 ]] || continue
        port=${address##*:}
        [[ $port =~ ^[0-9]+$ ]] || continue
        key="$proto:$port"
        listening_ports["$key"]=1
        current_addresses["$key"]+=" $address"
    done < "$work_dir/current_sockets.txt"
fi

while IFS= read -r old; do
    proto=$(jq -r '.protocol // ""' <<< "$old")
    address=$(jq -r '.local_address // ""' <<< "$old")
    port=${address##*:}
    key="$proto:$port"
    status="regression"
    reason="port is no longer listening"
    if [[ $sockets_available == false ]]; then
        reason="could not read current listening sockets"
    elif [[ $port =~ ^[0-9]+$ && -n ${listening_ports[$key]+yes} ]]; then
        status="pass"
        reason="protocol and port still listening"
    fi
    add_check "$(jq -cn --arg check listening_socket --arg proto "$proto" \
        --arg port "$port" --arg expected "$address" \
        --arg current "${current_addresses[$key]-}" --arg reason "$reason" \
        --arg status "$status" \
        '{check: $check, protocol: $proto, port: $port,
          baseline_address: $expected, current_addresses: ($current | split(" ") | map(select(length > 0))),
          reason: $reason, status: $status}')"
done < <(jq -c '.listening[]' "$SNAPSHOT")

# Read the probe for a critical service from a map, a services/probes map,
# or a list of objects with a service field. No shell evaluation is performed.
probe_definition() {
    local service=$1
    if [[ ! -f $PROBES ]]; then
        printf 'null\n'
        return
    fi
    jq -c --arg service "$service" '
        def find($value):
            if ($value | type) == "object" then $value[$service]
            elif ($value | type) == "array" then
                [$value[] | select(type == "object" and (.service == $service or .name == $service))][0]
            else null end;
        if type == "object" then
            find(.) // find(.services) // find(.probes) // null
        elif type == "array" then find(.) // null
        else null end
    ' "$PROBES"
}

# Only known, read-only liveness utilities are supported; no eval or sh -c.
# Prefer a command argument array when a probe needs quoted arguments.
run_probe() {
    local spec=$1 kind command_name url host port user detail
    local -a args=()
    probe_result="probe_failed"
    probe_detail=""

    if [[ $spec == null ]]; then
        probe_detail="no probe configured for this critical service"
        return
    fi

    kind=$(jq -r 'if type == "string" then "command"
                   else (.type // .kind //
                      (if .url then "curl" elif .command then "command" else "" end)) end' <<< "$spec")
    case "$kind" in
        http|https|curl)
            url=$(jq -r '.url // .target // empty' <<< "$spec")
            if [[ -z $url || ( $url != http://* && $url != https://* ) ]]; then
                probe_detail="curl probe needs an HTTP(S) URL"
                return
            fi
            args=(curl -fsS --connect-timeout 5 --max-time 10 -o /dev/null --url "$url")
            ;;
        mysql|mysqladmin)
            args=(mysqladmin --connect-timeout=5 ping)
            if [[ $(jq -r '.args | type' <<< "$spec") == array ]]; then
                mapfile -t args < <(jq -r '.args[]' <<< "$spec")
                args=(mysqladmin "${args[@]}")
            fi
            ;;
        ssh)
            host=$(jq -r '.host // "127.0.0.1"' <<< "$spec")
            port=$(jq -r '.port // 22 | tostring' <<< "$spec")
            user=$(jq -r '.user // empty' <<< "$spec")
            [[ $port =~ ^[0-9]+$ ]] || { probe_detail="invalid SSH port"; return; }
            if [[ -n $user ]]; then host="$user@$host"; fi
            args=(ssh -o BatchMode=yes -o ConnectTimeout=5 -p "$port" "$host" true)
            ;;
        command)
            if [[ $(jq -r 'if type == "object" then (.command | type) else type end' <<< "$spec") == array ]]; then
                mapfile -t args < <(jq -r '.command[]' <<< "$spec")
            else
                command_name=$(jq -r 'if type == "string" then . else .command // "" end' <<< "$spec")
                # Simple space-separated commands are supported; quoted arguments
                # should be supplied as a JSON argument array instead.
                read -r -a args <<< "$command_name"
            fi
            ;;
        *)
            probe_detail="unsupported probe type: $kind"
            return
            ;;
    esac

    if (( ${#args[@]} == 0 )); then
        probe_detail="probe command is empty"
        return
    fi
    command_name=${args[0]##*/}
    case "$command_name" in
        curl|mysqladmin|ssh) ;;
        *) probe_detail="unsupported probe command: $command_name"; return ;;
    esac
    if ! command -v "${args[0]}" >/dev/null 2>&1; then
        probe_detail="probe utility is not installed: $command_name"
        return
    fi

    if detail=$(timeout 12s "${args[@]}" 2>&1); then
        probe_result="pass"
        probe_detail="probe succeeded"
    else
        # A bounded output tail helps troubleshoot without bloating the JSON.
        probe_detail=$(printf '%s' "$detail" | tail -c 600)
        [[ -n $probe_detail ]] || probe_detail="probe returned a nonzero exit status"
    fi
}

# PROBE CHECKS: every critical service must have a working liveness test.
while IFS= read -r service; do
    definition=$(probe_definition "$service")
    run_probe "$definition"
    add_check "$(jq -cn --arg check critical_probe --arg service "$service" \
        --arg status "$probe_result" --arg result "$probe_detail" \
        '{check: $check, service: $service, status: $status, result: $result}')"
done < <(jq -r '[.services[] | select(.criticality == "critical") | .service] | unique[]' "$DEPENDENCIES")

# Assemble the report once, then atomically replace the old output.
temp_output=$(mktemp "$SCRIPT_DIR/.post_patch_validation.XXXXXX")
jq -s --arg generated "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --arg host "$(hostname)" '
    {generated_at: $generated, hostname: $host,
     total_checks: length,
     passed: ([.[] | select(.status == "pass")] | length),
     failed: ([.[] | select(.status != "pass")] | length),
     details: .}
' "$work_dir/checks.jsonl" > "$temp_output"
mv -- "$temp_output" "$OUTPUT"
temp_output=""

jq -r '
    def count_all($kind): [.details[] | select(.check == $kind)] | length;
    def count_pass($kind): [.details[] | select(.check == $kind and .status == "pass")] | length;
    "Service state checks:     \(count_pass("service_state"))/\(count_all("service_state"))",
    "Listening socket checks: \(count_pass("listening_socket"))/\(count_all("listening_socket"))",
    "Critical liveness probes: \(count_pass("critical_probe"))/\(count_all("critical_probe"))",
    "VERDICT: \(if .failed == 0 then "PASS" else "FAIL" end) (\(.passed)/\(.total_checks))",
    "Report saved to: post_patch_validation.json"
' "$OUTPUT"

if [[ $(jq -r '.failed' "$OUTPUT") -gt 0 ]]; then
    exit 1
fi
exit 0
