#!/bin/bash
# Exit codes: 0 success, 1 collection failed, 2 environment error.
set -o pipefail
export LC_ALL=C

fail() {
    printf '%s\n' "$2" >&2
    exit "$1"
}

for tool in hostname uname dpkg-query jq ss systemctl sysctl find wc nft; do
    command -v "$tool" >/dev/null 2>&1 || fail 2 "Missing dependency: $tool"
done

(( EUID == 0 )) || fail 2 'Run with sudo to read the full baseline.'
[[ -r /etc/os-release ]] || fail 2 'Cannot read /etc/os-release.'
# shellcheck disable=SC1091
. /etc/os-release || fail 2 'Could not load /etc/os-release.'

host=$(hostname) || fail 1 'Could not read hostname.'
kernel_release=$(uname -r) || fail 1 'Could not read kernel release.'
kernel_build=$(uname -v) || fail 1 'Could not read kernel build.'
# dpkg-query expands these field names.
# shellcheck disable=SC2016
packages=$(dpkg-query -W -f='${db:Status-Status}\t${binary:Package}\t${Version}\n') ||
    fail 1 'Could not query installed packages.'
sockets=$(ss -tulnpH) || fail 1 'Could not read listening sockets.'
services=$(systemctl list-units --type=service --state=active \
    --no-legend --no-pager --plain --full) || fail 1 'Could not read active services.'

ssh_present=false
ssh_files='{}'
if [[ -e /etc/ssh/sshd_config ]]; then
    ssh_present=true
    [[ -r /etc/ssh/sshd_config ]] || fail 2 'Cannot read /etc/ssh/sshd_config.'
    shopt -s nullglob
    ssh_files=$(jq -Rn '
        reduce (inputs
            | capture("^\\s*(?<key>[A-Za-z][A-Za-z0-9]*)(?:\\s*=\\s*|\\s+)(?<value>\\S.*?)\\s*$")
            | .file = input_filename
        ) as $setting ({};
            ($setting.key | ascii_downcase) as $key
            | .[$setting.file] |= (
                . // {global: {}, match_blocks: []}
                | if $key == "match" then
                      .match_blocks += [{condition: $setting.value, settings: {}}]
                  elif (.match_blocks | length) > 0 then
                      .match_blocks[-1].settings[$key] += [$setting.value]
                  else
                      .global[$key] += [$setting.value]
                  end
            )
        )
    ' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf) ||
        fail 1 'Could not collect SSH configuration.'
fi

sysctl_keys=(
    kernel.randomize_va_space
    kernel.kptr_restrict
    kernel.dmesg_restrict
    kernel.yama.ptrace_scope
    fs.protected_hardlinks
    fs.protected_symlinks
    fs.protected_fifos
    fs.protected_regular
    net.ipv4.ip_forward
    net.ipv4.tcp_syncookies
    net.ipv4.conf.all.rp_filter
    net.ipv4.conf.default.rp_filter
    net.ipv4.conf.all.accept_redirects
    net.ipv4.conf.default.accept_redirects
    net.ipv4.conf.all.send_redirects
    net.ipv4.conf.default.send_redirects
    net.ipv4.conf.all.accept_source_route
    net.ipv4.conf.default.accept_source_route
    net.ipv6.conf.all.forwarding
    net.ipv6.conf.all.accept_redirects
    net.ipv6.conf.default.accept_redirects
)
sysctl_values=$(
    for key in "${sysctl_keys[@]}"; do
        value=null
        if [[ -e /proc/sys/${key//./\/} ]]; then
            value=$(sysctl -n "$key") || exit 1
        fi
        printf '%s\t%s\n' "$key" "$value"
    done
) || fail 1 'Could not read security sysctls.'

kali_smoke_test=false
desktop_prune=()
case "$#:${1-}" in
    0:) ;;
    1:--kali-smoke-test)
        kali_smoke_test=true
        desktop_prune=(-path /run/user -prune -o)
        ;;
    *) fail 2 "Usage: $0 [--kali-smoke-test]" ;;
esac

suid_sgid_count=$(find / -ignore_readdir_race "${desktop_prune[@]}" -perm /6000 -type f -printf x | wc -c) ||
    fail 1 'Could not count SUID and SGID files.'
world_writable_count=$(find / -ignore_readdir_race "${desktop_prune[@]}" \
    \( -path /proc -o -path /sys \) -prune -o \
    -perm -0002 -type f -printf x | wc -c) ||
    fail 1 'Could not count world-writable files.'
ruleset_lines=$(nft list ruleset | wc -l) || fail 1 'Could not read nftables ruleset.'

sysmon_binary=false
if command -v sysmon >/dev/null 2>&1 || [[ -x /opt/sysmon/sysmon ]]; then
    sysmon_binary=true
fi

printf '%s\n' "$packages" |
    jq -nRS \
        --arg hostname "$host" \
        --arg kernel_release "$kernel_release" \
        --arg kernel_build "$kernel_build" \
        --arg distribution "$PRETTY_NAME" \
        --arg distribution_version "$VERSION_ID" \
        --arg sockets "$sockets" \
        --arg services "$services" \
        --arg sysctl "$sysctl_values" \
        --argjson ssh_present "$ssh_present" \
        --argjson ssh_files "$ssh_files" \
        --argjson suid_sgid_count "$suid_sgid_count" \
        --argjson world_writable_count "$world_writable_count" \
        --argjson kali_smoke_test "$kali_smoke_test" \
        --argjson ruleset_lines "$ruleset_lines" \
        --argjson sysmon_binary "$sysmon_binary" \
        '
        def lines: split("\n") | map(select(length > 0));
        def running($service):
            any(.[]; [splits("\\s+")] | .[0] == $service and .[3] == "running");

        ([inputs | split("\t") | select(.[0] == "installed")
          | {key: .[1], value: .[2]}] | from_entries) as $versions
        | ($services | lines | sort) as $units
        | {
            hostname: $hostname,
            kernel_release: $kernel_release,
            distribution: $distribution,
            distribution_version: $distribution_version,
            patch_level: {
                kernel_build: $kernel_build,
                installed_package_versions: $versions
            },
            package_count: ($versions | length),
            listening_sockets: ($sockets | lines | sort),
            active_services: $units,
            sshd_config: {present: $ssh_present, files: $ssh_files},
            sysctl: ($sysctl | lines | map(split("\t")
                | {key: .[0], value: (.[1] | fromjson)}) | from_entries),
            suid_sgid_count: $suid_sgid_count,
            world_writable_count: $world_writable_count,
            filesystem_scan_exclusions: {
                suid_sgid: (if $kali_smoke_test then ["/run/user"] else [] end),
                world_writable: (["/proc", "/sys"] +
                    (if $kali_smoke_test then ["/run/user"] else [] end))
            },
            firewall: {ruleset_lines: $ruleset_lines},
            telemetry: {
                auditd_running: ($units | running("auditd.service")),
                rsyslog_running: ($units | running("rsyslog.service")),
                sysmon_present: ($sysmon_binary or
                    any($versions | keys_unsorted[]; split(":")[0] == "sysmonforlinux"))
            }
        }' || fail 1 'Could not generate the JSON baseline.'
