#!/bin/bash
# Task 3: prioritise patches using the vulnerability and service inventories.
# Read-only: this script does not install packages or restart services.
set -euo pipefail

PROJECT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
VULN_FILE="$PROJECT_DIR/vulnerability_inventory.json"
SERVICE_FILE="$PROJECT_DIR/service_dependency_map.json"
OUTPUT_FILE="$PROJECT_DIR/patch_plan.json"

# Adjustable priority weights. Higher scores are patched first.
CVSS_WEIGHT=0.50
KEV_WEIGHT=2.00
CRITICALITY_WEIGHT=0.50
EXPOSURE_WEIGHT=0.25

for cmd in jq mktemp mv; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        printf 'Missing command: %s\n' "$cmd" >&2
        exit 1
    fi
done

for file in "$VULN_FILE" "$SERVICE_FILE"; do
    if [[ ! -r "$file" ]]; then
        printf 'Missing input: %s\n' "$file" >&2
        exit 1
    fi
done

# The Task 0 and Task 1 placeholder files must be replaced by actual reports.
if ! jq -e 'type == "object" and (.packages | type == "array") and (.generated_at | type == "string")' \
    "$VULN_FILE" >/dev/null; then
    echo 'Run Task 0 first to populate vulnerability_inventory.json.' >&2
    exit 1
fi
if ! jq -e '(type == "array") or (type == "object" and (.services | type == "array"))' \
    "$SERVICE_FILE" >/dev/null; then
    echo 'Run Task 1 first to populate service_dependency_map.json.' >&2
    exit 1
fi

TMP_FILE=$(mktemp "$PROJECT_DIR/.patch_plan.XXXXXXXX")
trap 'rm -f -- "$TMP_FILE"' EXIT

jq -n \
    --slurpfile inventories "$VULN_FILE" \
    --slurpfile dependencies "$SERVICE_FILE" \
    --argjson cvss_weight "$CVSS_WEIGHT" \
    --argjson kev_weight "$KEV_WEIGHT" \
    --argjson criticality_weight "$CRITICALITY_WEIGHT" \
    --argjson exposure_weight "$EXPOSURE_WEIGHT" '
    def rank_criticality:
        if . == "critical" then 4
        elif . == "high" then 3
        elif . == "medium" then 2
        elif . == "low" then 1
        else 0 end;

    # Debian multi-arch suffixes may appear in either input.
    def base_package:
        if type == "string" then split(":")[0] else "" end;

    def is_kernel:
        test("^linux-(image|modules|generic)(-|$)");

    # T1 does not measure real network exposure. Estimate exposure from the
    # service names and the number of active services affected by this patch.
    def exposure_rank($names):
        if ($names | length) == 0 then 0
        elif any($names[]; test("(ssh|apache|nginx|http|ftp|postfix|dovecot|bind9|named|haproxy|squid|vpn)"; "i")) then 3
        elif ($names | length) > 1 then 2
        else 1 end;

    $inventories[0] as $inventory
    | (if ($dependencies[0] | type) == "array"
       then $dependencies[0]
       else $dependencies[0].services end) as $services
    | [ $inventory.packages[] as $v
        | ($v.package // "") as $pkg
        | select(($pkg | type) == "string" and ($pkg | length) > 0)
        | ($pkg | base_package) as $base
        | ($base | is_kernel) as $kernel
        | ($base == "systemd") as $systemd
        | [ $services[]
            | select((.owning_package | base_package) == $base
                     or any((.linked_packages // [])[]; base_package == $base))
          ] as $affected
        | ([ $affected[].service | strings ] | unique | sort) as $service_names
        | (if $kernel then ["(kernel-wide)"] else $service_names end) as $impacted
        | (if $kernel or $systemd then 4
           else ([$affected[].criticality | rank_criticality] | max // 0) end) as $criticality
        | (if $kernel or $systemd then 4
           else exposure_rank($service_names) end) as $exposure
        | (if ($v.max_cvss | type) == "number" then $v.max_cvss
           else ($v.max_cvss | tonumber? // 0) end) as $cvss
        | (($v.in_cisa_kev // false) == true) as $kev
        | (((($cvss_weight * $cvss)
              + (if $kev then $kev_weight else 0 end)
              + ($criticality_weight * $criticality)
              + ($exposure_weight * $exposure)) * 100 | round) / 100) as $score
        | {
            package: $pkg,
            installed_version: ($v.installed_version // null),
            candidate_version: ($v.candidate_version // null),
            source_pocket: ($v.source_pocket // null),
            cves: ($v.cves // []),
            max_cvss: ($v.max_cvss // null),
            in_cisa_kev: $kev,
            score: $score,
            bucket: (if $score >= 7 then "emergency"
                     elif $score >= 4 then "urgent" else "scheduled" end),
            affected_services: $impacted,
            requires_restart: (if $kernel then false else ($service_names | length) > 0 end),
            requires_reboot: ($kernel or $systemd),
            rollback_target_version: ($v.installed_version // null),
            criticality_rank: $criticality,
            exposure_rank: $exposure
          }
      ]
    | sort_by(-.score, .package)
    | [ to_entries[] | .value + {rank: (.key + 1)} ] as $plan
    | {
        generated_at: $inventory.generated_at,
        weights: {
            cvss_weight: $cvss_weight,
            kev_weight: $kev_weight,
            criticality_weight: $criticality_weight,
            exposure_weight: $exposure_weight
        },
        plan: $plan,
        summary: {
            total: ($plan | length),
            emergency: ([$plan[] | select(.bucket == "emergency")] | length),
            urgent: ([$plan[] | select(.bucket == "urgent")] | length),
            scheduled: ([$plan[] | select(.bucket == "scheduled")] | length),
            requires_reboot: any($plan[]; .requires_reboot)
        }
      }
' > "$TMP_FILE"

jq -e '.plan | type == "array"' "$TMP_FILE" >/dev/null
mv -- "$TMP_FILE" "$OUTPUT_FILE"
trap - EXIT

jq -r '"Emergency: \(.summary.emergency)  Urgent: \(.summary.urgent)  Scheduled: \(.summary.scheduled)",
       "Reboot required by plan: \(if .summary.requires_reboot then "yes" else "no" end)"' "$OUTPUT_FILE"
printf 'Report saved to: %s\n' "$OUTPUT_FILE"
