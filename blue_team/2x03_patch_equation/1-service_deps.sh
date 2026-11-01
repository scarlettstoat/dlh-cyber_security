#!/bin/bash
# Task 1 - Map running services to their executable and shared-library packages.
# This script only reads system information and writes a JSON report.
set -euo pipefail
export LC_ALL=C

OUTPUT_FILE="service_dependency_map.json"
CRITICALITY_FILE="service_criticality.json"

for tool in systemctl dpkg-query ldd apt jq awk sort readlink; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required command: $tool" >&2
        exit 1
    fi
done

# Find the package that owns a file, including on systems using merged /usr.
package_owner() {
    local path="$1" resolved result name candidate
    local -a paths=("$path")

    resolved=$(readlink -f -- "$path" 2>/dev/null || true)
    [[ -n "$resolved" ]] && paths+=("$resolved")

    if [[ "$path" == /usr/* ]]; then
        paths+=("${path#/usr}")
    elif [[ "$path" == /* ]]; then
        paths+=("/usr$path")
    fi
    if [[ "$resolved" == /usr/* ]]; then
        paths+=("${resolved#/usr}")
    elif [[ "$resolved" == /* ]]; then
        paths+=("/usr$resolved")
    fi

    for candidate in "${paths[@]}"; do
        result=$(dpkg-query -S -- "$candidate" 2>/dev/null | head -n 1 || true)
        [[ -z "$result" ]] && continue
        name=${result%%: *}
        name=${name%%,*}
        name=${name%%:*}  # Remove architecture suffix, if present.
        printf '%s\n' "$name"
        return 0
    done
    return 0  # Locally installed or generated files may not have an owner.
}

# Get ExecStart from systemd, or use the running process as a fallback.
service_executable() {
    local service="$1" details path="" pid
    details=$(systemctl show "$service" --property=ExecStart --value 2>/dev/null || true)

    if [[ "$details" =~ path=([^[:space:];]+) ]]; then
        path=${BASH_REMATCH[1]}
    elif [[ "$details" == /* ]]; then
        path=${details%% *}
    fi

    if [[ -n "$path" && -f "$path" ]]; then
        printf '%s\n' "$path"
        return 0
    fi

    pid=$(systemctl show "$service" --property=MainPID --value 2>/dev/null || true)
    if [[ "$pid" =~ ^[1-9][0-9]*$ && -e "/proc/$pid/exe" ]]; then
        readlink -f "/proc/$pid/exe" 2>/dev/null || true
    fi
}

# Accept a direct service-to-label map, or a {"services": ...} map/list.
service_criticality() {
    local service="$1" label="low"
    if [[ -f "$CRITICALITY_FILE" ]]; then
        label=$(jq -r --arg s "$service" '
            def getlabel: if type == "object" then .criticality else . end;
            if type == "object" then
                (.[$s] | getlabel) // (.services[$s]? | getlabel) //
                (if (.services | type) == "array" then
                    [.services[] | select(.service == $s or .name == $s) | .criticality][0]
                else null end) //
                (if (.critical | type) == "array" and (.critical | index($s)) then "critical"
                 elif (.high | type) == "array" and (.high | index($s)) then "high"
                 elif (.medium | type) == "array" and (.medium | index($s)) then "medium"
                 else null end) // "low"
            elif type == "array" then
                [.[] | select(.service == $s or .name == $s) | .criticality][0] // "low"
            else "low" end
        ' "$CRITICALITY_FILE" 2>/dev/null || echo low)
    fi
    case "$label" in
        critical|high|medium|low) printf '%s\n' "$label" ;;
        *) printf 'low\n' ;;
    esac
}

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

# Collect active units and pending package upgrades without changing anything.
if ! systemctl list-units --type=service --state=active --no-legend --no-pager --plain > "$tmp_dir/units"; then
    echo "Could not list active systemd services. Run on the Ubuntu endpoint." >&2
    exit 1
fi

if ! apt list --upgradable > "$tmp_dir/upgradeable" 2>/dev/null; then
    echo "Warning: Could not read APT upgrade candidates; restart flags may be incomplete." >&2
    : > "$tmp_dir/upgradeable"
fi

declare -A upgradeable=()
while IFS= read -r name; do
    [[ -n "$name" ]] && upgradeable["$name"]=1
done < <(awk '$1 ~ /\// {split($1, parts, "/"); sub(/:[^:]+$/, "", parts[1]); print parts[1]}' "$tmp_dir/upgradeable")

: > "$tmp_dir/entries"
while IFS= read -r service; do
    [[ -z "$service" ]] && continue

    executable=$(service_executable "$service")
    owning_package=""
    declare -a linked_packages=()

    if [[ -n "$executable" ]]; then
        owning_package=$(package_owner "$executable")

        # Libraries reported by ldd, including the ELF interpreter (if present).
        while IFS= read -r library_path; do
            library_package=$(package_owner "$library_path")
            [[ -n "$library_package" ]] && linked_packages+=("$library_package")
        done < <(ldd "$executable" 2>/dev/null | awk '
            /=>[[:space:]]+\// {
                for (i = 2; i <= NF; i++) {
                    if ($(i-1) == "=>" && $i ~ /^\//) print $i
                }
                next
            }
            $1 ~ /^\// {print $1}
        ' || true)
    fi

    linked_json=$(printf '%s\n' "${linked_packages[@]}" | awk 'NF' | sort -u | jq -R . | jq -s .)

    # A restart is flagged when a service's own or linked package can be upgraded.
    restart=false
    if [[ -n "$owning_package" && -n "${upgradeable[$owning_package]+yes}" ]]; then
        restart=true
    fi
    for package in "${linked_packages[@]}"; do
        if [[ -n "${upgradeable[$package]+yes}" ]]; then
            restart=true
            break
        fi
    done

    criticality=$(service_criticality "$service")
    jq -cn \
        --arg service "$service" \
        --arg executable "$executable" \
        --arg owner "$owning_package" \
        --argjson packages "$linked_json" \
        --arg criticality "$criticality" \
        --argjson restart "$restart" \
        '{service: $service, exec_path: $executable,
          owning_package: (if $owner == "" then null else $owner end),
          linked_packages: $packages, criticality: $criticality,
          restart_required_on_patch: $restart}' >> "$tmp_dir/entries"
done < <(awk '$1 ~ /\.service$/ {print $1}' "$tmp_dir/units")

# Build the complete, valid JSON document and replace the output atomically.
jq -s --arg time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg host "$(hostname)" \
    '{generated_at: $time, hostname: $host, services: .}' \
    "$tmp_dir/entries" > "$tmp_dir/report.json"

mv -- "$tmp_dir/report.json" "$OUTPUT_FILE"
echo "Dependency map saved to $OUTPUT_FILE"
jq -r '"Active services: \(.services | length) | Services with upgradeable dependencies: \([.services[] | select(.restart_required_on_patch)] | length)"' "$OUTPUT_FILE"
