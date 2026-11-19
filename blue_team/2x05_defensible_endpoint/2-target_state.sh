#!/bin/bash
# Exit codes: 0 success, 1 existing or invalid target, 2 environment error.
set -o pipefail

die() {
    printf '%s\n' "$2" >&2
    exit "$1"
}

mode=generate
if (( $# > 1 )); then
    die 2 "Usage: $0 [--force | --validate]"
fi
case "${1-}" in
    '') ;;
    --force) mode=replace ;;
    --validate) mode=validate ;;
    *) die 2 "Usage: $0 [--force | --validate]" ;;
esac

for dependency in jq date dirname mkdir mktemp ln mv rm; do
    command -v "$dependency" >/dev/null 2>&1 || die 2 "Missing dependency: $dependency"
done

root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd) ||
    die 2 'Cannot locate project directory.'
target="$root/capstone/target_state.json"

validate_target() {
    jq -es '
        def text: type == "string" and length > 0;
        def valid_control:
            ([.id, .description, .check_target, .source_project] | all(.[]; text))
            and (.platform | IN("linux", "windows", "network", "both"))
            and (.family | IN("hardening", "telemetry", "patching", "network", "handoff"))
            and (.severity | IN("critical", "high", "medium", "low"))
            and (if .check_type == "file_exists" then .expected_value == true
                 elif .check_type == "command_exit_zero" then .expected_value == 0
                 elif .check_type == "json_field_gte" then (.expected_value | type == "number")
                 elif .check_type == "json_field_equals" then has("expected_value")
                 elif .check_type == "grep_match" then (.expected_value | text)
                 else false end);
        length == 1 and (.[0] |
            .schema_version == "capstone-target-v1"
            and (.generated_at | fromdateiso8601 | type == "number")
            and (.controls | type == "array" and length >= 29
                and all(.[]; valid_control)
                and ([.[].id] | length == (unique | length)))
            and (.linux.hardening_index | type == "number")
            and (.windows.pass_rate | type == "number")
        )
    ' "$1" >/dev/null
}

# Downstream scripts invoke --validate before reading the target state.
if [[ $mode == validate ]]; then
    [[ -f $target ]] || die 2 'Missing capstone/target_state.json.'
    validate_target "$target" || die 1 'Invalid capstone/target_state.json.'
    exit 0
fi
if [[ $mode == generate && ( -e $target || -L $target ) ]]; then
    die 1 'capstone/target_state.json already exists. Use --force to replace it.'
fi

mkdir -p -- "$root/capstone" || die 2 'Cannot create the capstone directory.'
staged=$(mktemp "$root/capstone/.target-state.XXXXXX") || die 2 'Cannot stage the target state.'
trap 'rm -f -- "$staged"' EXIT
generated_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ') || die 2 'Cannot read the clock.'

# JSON field checks use path:jq-filter. Command checks use PowerShell
# for the Windows platform and Bash for Linux, network and both.
jq -n --arg generated_at "$generated_at" -f /dev/stdin >"$staged" <<'JQ' || die 1 'Could not write target state.'
def group($platform; $family; $source):
    map({
        id: .[0], platform: $platform, family: $family, description: .[1],
        check_type: .[2], check_target: .[3], expected_value: .[4],
        source_project: $source, severity: .[5]
    });

def audit_rules_check:
    [
        "rules=/etc/audit/rules.d/meddefense.rules",
        "test -s \"$rules\" || exit 1",
        "keys='!/^[[:space:]]*#/ {for (i=1;i<NF;i++) {if ($i==\"-k\") print $(i+1); if ($i==\"-F\" && $(i+1)~/^key=/) print substr($(i+1),5)}}'",
        "required=$(awk \"$keys\" \"$rules\") && test -n \"$required\" || exit 1",
        "active=$(auditctl -l) || exit 1",
        "loaded=$(awk \"$keys\" <<< \"$active\") || exit 1",
        "missing=$(comm -23 <(sort <<< \"$required\") <(sort <<< \"$loaded\")) || exit 1",
        "test -z \"$missing\""
    ] | join("\n");

def windows_audit_check:
    [
        "foreach ($scope in @('/category:Account Logon','/subcategory:Logon','/category:Object Access','/category:Privilege Use')) {",
        "    $rows = @(auditpol.exe /get $scope /r | ConvertFrom-Csv)",
        "    $audited = @($rows | Where-Object { $_.'Inclusion Setting' -in @('Success','Failure','Success and Failure') })",
        "    if ($LASTEXITCODE -ne 0 -or $audited.Count -eq 0) { exit 1 }",
        "}",
        "exit 0"
    ] | join("\n");

def blacklist_check:
    [
        "command -v unattended-upgrade >/dev/null || exit 1",
        "required=$(jq -ce 'arrays | select(length > 0 and all(.[]; type == \"string\"))' /home/analyst/MedDefense_Lab/capstone/blacklist.json) || exit 1",
        "settings=$(apt-config dump) || exit 1",
        "jq -en --argjson required \"$required\" --arg settings \"$settings\" '($settings | split(\"\\n\") | map(capture(\"^Unattended-Upgrade::Package-Blacklist:: (?<entry>.*);$\").entry | fromjson)) as $configured | ($required - $configured | length) == 0'"
    ] | join("\n");

def dns_check:
    [
        "systemctl is-active --quiet dnsmasq || exit 1",
        "blocked=$(awk 'NF && $1 !~ /^#/ {print $1; exit}' /home/analyst/MedDefense_Lab/capstone/dns_blocklist.txt) || exit 1",
        "test -n \"$blocked\" && dig @127.0.0.1 +time=2 +tries=1 +short -q \"$blocked\" -t A | grep -Fx '0.0.0.0' >/dev/null"
    ] | join("\n");

{
    schema_version: "capstone-target-v1",
    generated_at: $generated_at,
    controls: (
        ([
            ["LNX-SSH-01", "SSH must refuse root login.", "command_exit_zero",
             "sshd -T | grep -Ex 'permitrootlogin no' >/dev/null", 0, "critical"],
            ["LNX-SSH-02", "SSH must refuse password authentication.", "command_exit_zero",
             "sshd -T | grep -Ex 'passwordauthentication no' >/dev/null", 0, "high"],
            ["LNX-SYS-01", "IPv4 forwarding must be disabled.", "grep_match",
             "/proc/sys/net/ipv4/ip_forward", "^0$", "high"],
            ["LNX-SYS-02", "Full ASLR must be enabled.", "grep_match",
             "/proc/sys/kernel/randomize_va_space", "^2$", "high"],
            ["LNX-AUD-01", "The auditd service must be active.", "command_exit_zero",
             "systemctl is-active --quiet auditd", 0, "high"],
            ["LNX-MAC-01", "AppArmor must have at least one enforcing profile.", "command_exit_zero",
             "aa-status --enabled && count=$(aa-status --enforced) && test \"$count\" -gt 0", 0, "high"],
            ["LNX-LYN-01", "The post-hardening Lynis index must be at least 80.", "json_field_gte",
             "capstone/exec/linux_harden.json:.lynis_after", 80, "high"]
        ] | group("linux"; "hardening"; "2x00_locking_the_gates"))
        + ([
            ["WIN-FW-01", "Windows Firewall must default-deny inbound on every profile.", "command_exit_zero",
             "$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop); if ($profiles.Count -eq 3 -and @($profiles | Where-Object { $_.Enabled -ne 'True' -or $_.DefaultInboundAction -ne 'Block' }).Count -eq 0) { exit 0 }; exit 1",
             0, "critical"],
            ["WIN-PWR-01", "PowerShell Script Block Logging must be enabled.", "command_exit_zero",
             "$state = Get-ItemPropertyValue -LiteralPath 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction Stop; if ($state -eq 1) { exit 0 }; exit 1",
             0, "high"],
            ["WIN-SYS-01", "A Windows Sysmon service must be installed and running.", "command_exit_zero",
             "if (@(Get-Service -Name Sysmon,Sysmon64 -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running').Count -gt 0) { exit 0 }; exit 1",
             0, "high"],
            ["WIN-AUD-01", "Audit policy must cover Account Logon, Logon, Object Access and Privilege Use.", "command_exit_zero",
             windows_audit_check, 0, "high"],
            ["WIN-CIS-01", "The post-hardening CIS Level 1 pass rate must be at least 85 percent.", "json_field_gte",
             "capstone/exec/windows_harden.json:(.post_pass_rate // .cis_after)", 85, "high"]
        ] | group("windows"; "hardening"; "2x01_windows_fortress"))
        + ([
            ["LNX-AUD-02", "The MedDefense auditd rules file and its loaded rule keys must be present.",
             "command_exit_zero", audit_rules_check, 0, "high"],
            ["LNX-EXP-01", "The structured Linux event export must exist.", "file_exists",
             "capstone/telemetry/linux_events.json", true, "medium"]
        ] | group("linux"; "telemetry"; "2x02_eyes_on_endpoint"))
        + ([
            ["WIN-SYS-02", "Sysmon must have recorded an event in the last 10 minutes.", "command_exit_zero",
             "$event = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=(Get-Date).AddMinutes(-10)} -MaxEvents 1 -ErrorAction SilentlyContinue; if ($null -ne $event) { exit 0 }; exit 1",
             0, "high"],
            ["WIN-SYS-03", "The PowerShell Operational channel must be enabled with positive capacity.", "command_exit_zero",
             "$channel = Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational' -ErrorAction Stop; if ($channel.IsEnabled -and $channel.MaximumSizeInBytes -gt 0) { exit 0 }; exit 1",
             0, "medium"]
        ] | group("windows"; "telemetry"; "2x02_eyes_on_endpoint"))
        + ([
            ["PAT-INV-01", "The vulnerability inventory must be present.", "file_exists",
             "capstone/patch/vulnerability_inventory.json", true, "high"],
            ["PAT-PLAN-01", "The patch plan must be present.", "file_exists",
             "capstone/patch/patch_plan.json", true, "high"],
            ["PAT-EXEC-01", "The patch execution log must exist with zero failed entries.", "json_field_equals",
             "capstone/patch/patch_execution_log.json:[.entries[] | select((.status // .state // .result // \"\") == \"failed\")] | length",
             0, "critical"],
            ["PAT-BLK-01", "Unattended upgrades must honour every mandated blacklist entry.", "command_exit_zero",
             blacklist_check, 0, "high"]
        ] | group("linux"; "patching"; "2x03_patch_equation"))
        + ([
            ["NET-NFT-01", "The loaded nftables input chain must default to drop.", "command_exit_zero",
             "nft -j list ruleset | jq -e '[.nftables[] | .chain? | select(.hook == \"input\" and .policy == \"drop\")] | any(.[]; .family == \"inet\") or (any(.[]; .family == \"ip\") and any(.[]; .family == \"ip6\"))' >/dev/null",
             0, "critical"],
            ["NET-SEG-01", "The network segmentation rules must be present.", "file_exists",
             "capstone/network/segmentation_rules.json", true, "high"],
            ["NET-SUR-01", "Suricata must load at least six custom rules.", "command_exit_zero",
             "rules=capstone/network/meddefense_custom.rules; count=$(grep -Ec '^[[:space:]]*(alert|drop|reject|pass)[[:space:]]' \"$rules\") && test \"$count\" -ge 6 && suricata -T --init-errors-fatal -c /etc/suricata/suricata.yaml -S \"$rules\"",
             0, "high"],
            ["NET-SUR-02", "Every custom Suricata rule must fire against its labelled PCAP.", "json_field_equals",
             "capstone/network/custom_rule_validation.json:(.results | arrays | length >= 6 and all(.[]; (.result | ascii_downcase | IN(\"pass\", \"passed\")) and (.alerts_detected | type == \"number\" and . > 0)))",
             true, "high"],
            ["NET-DNS-01", "The active DNS filter must return the block address for a listed domain.", "command_exit_zero",
             dns_check, 0, "high"]
        ] | group("network"; "network"; "2x04_perimeter_defense"))
        + ([
            ["HDF-CMP-01", "The compliance report must be present.", "file_exists",
             "capstone/compliance.json", true, "high"],
            ["HDF-MAN-01", "The handoff manifest must record a SHA-256 digest for each file.", "json_field_equals",
             "defensible_endpoint_package/manifest.json:(.files | arrays | length > 0 and all(.[]; (.sha256 | type == \"string\" and test(\"^[a-fA-F0-9]{64}$\"))))",
             true, "high"],
            ["HDF-TEL-01", "The telemetry handoff directory must exist with a readable tarball.", "command_exit_zero",
             "test -d capstone/telemetry_handoff && tar -tzf telemetry_handoff.tar.gz | grep '^capstone/telemetry_handoff/' >/dev/null",
             0, "medium"],
            ["HDF-RUN-01", "The handoff runbook must be present and executable.", "command_exit_zero",
             "test -f defensible_endpoint_package/runbook.sh && test -x defensible_endpoint_package/runbook.sh",
             0, "high"]
        ] | group("both"; "handoff"; "2x05_defensible_endpoint"))
    )
}
| .linux.hardening_index = (.controls[] | select(.id == "LNX-LYN-01") | .expected_value)
| .windows.pass_rate = (.controls[] | select(.id == "WIN-CIS-01") | .expected_value)
JQ
validate_target "$staged" || die 1 'Could not generate a valid target state.'

if [[ $mode == replace ]]; then
    mv -fT -- "$staged" "$target" || die 1 'Could not replace the target state.'
else
    ln -T -- "$staged" "$target" || die 1 'Could not create the target state without overwriting.'
fi
printf 'Wrote capstone/target_state.json\n'
