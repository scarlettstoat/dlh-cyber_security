#!/bin/bash
set -euo pipefail

# Capture the system state before applying patches.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
OUTPUT="$SCRIPT_DIR/pre_patch_state.json"

if (( EUID != 0 )); then
    echo "Please run this script with sudo." >&2
    exit 1
fi

for command in dpkg-query systemctl ss sha256sum jq uname hostname date; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "Missing required command: $command" >&2
        exit 1
    fi
done

WORK_DIR=$(mktemp -d)
trap 'rm -rf -- "$WORK_DIR"' EXIT

# 1. Installed packages and their exact versions.
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' |
    while IFS=$'\t' read -r package version status; do
        if [[ $status == ii* ]]; then
            printf '%s\t%s\n' "$package" "$version"
        fi
    done > "$WORK_DIR/packages.tsv"

# 2. Services that are active at snapshot time.
systemctl list-units --type=service --state=active --all \
    --no-legend --no-pager --plain > "$WORK_DIR/active_units.txt"

: > "$WORK_DIR/services.tsv"
while read -r unit _; do
    [[ $unit == *.service ]] || continue

    active_state=""
    sub_state=""
    main_pid=0

    systemctl show "$unit" -p ActiveState -p SubState -p MainPID \
        --no-pager > "$WORK_DIR/service_details.txt"

    while IFS='=' read -r key value; do
        case $key in
            ActiveState) active_state=$value ;;
            SubState) sub_state=$value ;;
            MainPID) main_pid=$value ;;
        esac
    done < "$WORK_DIR/service_details.txt"

    [[ $main_pid =~ ^[0-9]+$ ]] || main_pid=0
    printf '%s\t%s\t%s\t%s\n' \
        "$unit" "$active_state" "$sub_state" "$main_pid" \
        >> "$WORK_DIR/services.tsv"
done < "$WORK_DIR/active_units.txt"

# 3. All TCP and UDP listening sockets, including process details.
ss -tulnp > "$WORK_DIR/ss_output.txt"
: > "$WORK_DIR/listening.tsv"
while read -r protocol state recv_q send_q local_addr peer_addr process; do
    [[ $protocol == tcp || $protocol == udp ]] || continue
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$protocol" "$state" "$recv_q" "$send_q" \
        "$local_addr" "$peer_addr" "${process:-}" \
        >> "$WORK_DIR/listening.tsv"
done < "$WORK_DIR/ss_output.txt"

# 4. Hash all package-owned files under /etc (directories excluded).
dpkg-query -S '/etc/*' > "$WORK_DIR/owned_etc.txt"
: > "$WORK_DIR/config_hashes.tsv"

while IFS= read -r path; do
    [[ -n $path ]] || continue
    if [[ -f $path ]]; then
        hash=$(sha256sum -- "$path")
        hash=${hash%% *}
        printf '%s\t%s\n' "$path" "$hash" >> "$WORK_DIR/config_hashes.tsv"
    elif [[ ! -d $path ]]; then
        # A package-owned file may have been deleted or become a broken link.
        printf '%s\t%s\n' "$path" "MISSING" >> "$WORK_DIR/config_hashes.tsv"
    fi
done < <(sed -n 's/^.*: \(\/etc\/.*\)$/\1/p' \
    "$WORK_DIR/owned_etc.txt" | LC_ALL=C sort -u)

# 5-6. Write one structured JSON snapshot atomically.
timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
host=$(hostname)
kernel=$(uname -r)
reboot_required=false
if [[ -e /var/run/reboot-required ]]; then
    reboot_required=true
fi

TEMP_OUTPUT=$(mktemp "$SCRIPT_DIR/.pre_patch_state.XXXXXX")
trap 'rm -rf -- "$WORK_DIR"; rm -f -- "$TEMP_OUTPUT"' EXIT

jq -n \
    --arg timestamp "$timestamp" \
    --arg hostname "$host" \
    --arg kernel "$kernel" \
    --argjson reboot_required "$reboot_required" \
    --rawfile package_rows "$WORK_DIR/packages.tsv" \
    --rawfile service_rows "$WORK_DIR/services.tsv" \
    --rawfile socket_rows "$WORK_DIR/listening.tsv" \
    --rawfile hash_rows "$WORK_DIR/config_hashes.tsv" '
    def rows($text): $text | split("\n") | map(select(length > 0) | split("\t"));
    {
        timestamp: $timestamp,
        hostname: $hostname,
        kernel: $kernel,
        packages: (rows($package_rows) | map({key: .[0], value: .[1]}) | from_entries),
        services: (rows($service_rows) | map({
            service: .[0],
            ActiveState: .[1],
            SubState: .[2],
            MainPID: (.[3] | tonumber)
        })),
        listening: (rows($socket_rows) | map({
            protocol: .[0],
            state: .[1],
            recv_q: (.[2] | tonumber),
            send_q: (.[3] | tonumber),
            local_address: .[4],
            peer_address: .[5],
            process: .[6]
        })),
        conffile_hashes: (rows($hash_rows) | map({
            key: .[0],
            value: (if .[1] == "MISSING" then null else .[1] end)
        }) | from_entries),
        reboot_required: $reboot_required
    }
' > "$TEMP_OUTPUT"

mv -- "$TEMP_OUTPUT" "$OUTPUT"

printf 'Snapshot: %s\n' "$(basename -- "$OUTPUT")"
printf 'Size: %s\n' "$(du -h -- "$OUTPUT" | cut -f1)"
printf 'Kernel: %s\n' "$kernel"
printf 'Reboot required: %s\n' "$reboot_required"
printf 'Packages: %s\n' "$(jq '.packages | length' "$OUTPUT")"
printf 'Services: %s\n' "$(jq '.services | length' "$OUTPUT")"
