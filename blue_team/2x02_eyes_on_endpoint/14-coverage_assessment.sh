#!/bin/bash
# Name: 14-coverage_assessment.sh
# Purpose: Summarise cross-platform telemetry, detection coverage, gaps and quality for the SOC handoff.
# Author: Suraya
# Project: MedDefense - Eyes on the Endpoint (2x02), Task 14
# Run: ./14-coverage_assessment.sh (from anywhere; reads files beside this script)

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT="$SCRIPT_DIR/telemetry_coverage_assessment.json"
HANDOFF="$SCRIPT_DIR/telemetry_handoff"

if ! command -v jq >/dev/null 2>&1; then
    echo '[!] jq is required. Install jq before running this script.' >&2
    exit 1
fi

required_files=(
    "$HANDOFF/windows_events.json"
    "$HANDOFF/linux_events.json"
    "$HANDOFF/attack_ground_truth.json"
    "$SCRIPT_DIR/windows_detection_matrix.json"
    "$SCRIPT_DIR/linux_detection_matrix.json"
    "$SCRIPT_DIR/windows_telemetry_quality.json"
    "$SCRIPT_DIR/linux_telemetry_quality.json"
    "$SCRIPT_DIR/sysmon_coverage_matrix.json"
)

missing=0
for file in "${required_files[@]}"; do
    if [[ ! -r "$file" ]]; then
        printf '[!] Missing required input: %s\n' "${file#"$SCRIPT_DIR"/}" >&2
        missing=1
    fi
done
if (( missing )); then
    echo '[!] Run the earlier export, detection and quality tasks to generate these files.' >&2
    exit 1
fi

work_dir="$(mktemp -d)"
trap 'rm -rf -- "$work_dir"' EXIT

# Summarise each platform without copying thousands of raw events into the
# final report. Reject malformed events instead of silently counting them.
summarise_events() {
    local platform="$1" file="$2" output="$3"
    jq --arg platform "$platform" '
        def records:
            if type == "array" then .
            elif type == "object" and (.events | type) == "array" then .events
            else error("Telemetry input must be an array or contain an events array") end;
        def present($key):
            has($key) and .[$key] != null and
            (if (.[$key] | type) == "string" then (.[$key] | length) > 0 else true end);
        records as $items
        | if any($items[]; (type != "object") or
            ((present("timestamp") and present("hostname") and
              present("source_type") and present("event_category")) | not))
          then error("Event missing one or more required fields")
          else $items end
        | {
            platform: $platform,
            count: length,
            by_source_type: (group_by(.source_type) |
                map({source_type: .[0].source_type, count: length})),
            by_event_category: (group_by(.event_category) |
                map({event_category: .[0].event_category, count: length}))
          }
    ' "$file" > "$output"
}

printf '[*] Loading telemetry handoff package...\n'
summarise_events Windows "$HANDOFF/windows_events.json" "$work_dir/windows.json"
summarise_events Linux "$HANDOFF/linux_events.json" "$work_dir/linux.json"

# Consolidate smaller files. Both detection matrices produced by Tasks 10 and
# 12 are supported: Windows writes an array; Linux writes detection_matrix[].
# The ATT&CK status is derived from evidence, never from expected sources alone.
jq -n \
    --slurpfile win "$work_dir/windows.json" \
    --slurpfile lin "$work_dir/linux.json" \
    --slurpfile ground "$HANDOFF/attack_ground_truth.json" \
    --slurpfile win_matrix "$SCRIPT_DIR/windows_detection_matrix.json" \
    --slurpfile lin_matrix "$SCRIPT_DIR/linux_detection_matrix.json" \
    --slurpfile win_quality "$SCRIPT_DIR/windows_telemetry_quality.json" \
    --slurpfile lin_quality "$SCRIPT_DIR/linux_telemetry_quality.json" \
    --slurpfile sysmon "$SCRIPT_DIR/sysmon_coverage_matrix.json" \
    --arg generated "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" '
    def items($object; $name):
        if ($object | type) == "array" then $object
        elif ($object | type) == "object" and ($object[$name] | type) == "array"
            then $object[$name]
        else error("Expected an array or an object with array field " + $name) end;
    def score($q):
        ($q.overall_score // $q.quality_score // $q.score //
         $q.overall_quality_score // $q.score_percentage //
         $q.summary.overall_score // $q.summary.quality_score //
         $q.summary.score // $q.summary.total_score //
         $q.quality.overall_score // $q.quality.score //
         $q.metrics.overall_score // $q.metrics.quality_score //
         $q.metrics.overall // $q.overall.score //
         (if ($q.overall | type) == "number" then $q.overall else null end))
         as $raw
        | if $raw == null then null
          elif ($raw | type) == "number" then $raw
          elif ($raw | type) == "string" then
               (try ($raw | gsub("%"; "") | tonumber) catch null)
          else null end
        | if . == null then null elif . >= 0 and . <= 1 then (. * 100)
          else . end
        | if . != null and (. < 0 or . > 100) then null else . end;
    def evidence($entry):
        if ($entry.detections | type) == "array" then $entry.detections
        elif ($entry.sources | type) == "array" then $entry.sources
        elif ($entry.captured_by | type) == "array" then
            [$entry.captured_by[] | if type == "string" then {source: .} else . end]
        else [] end;
    def sources($entry):
        (evidence($entry) | map(if type == "string" then . else
            (.source // .source_type // .channel // empty) end) |
            map(select(type == "string" and length > 0)) | unique);
    def key_fields($entry):
        (evidence($entry) | map(.key_fields_present // .key_fields // {}) |
            map(if type == "object" then keys elif type == "array" then . else [] end) |
            add // [] | unique);
    def detail($entry):
        (($entry.detail_level // "") | ascii_downcase) as $given
        | if $given == "full" or $given == "partial" then $given
          elif any(evidence($entry)[]; ((.detail_level // "") | ascii_downcase) == "full")
              then "full"
          elif (evidence($entry) | length) > 0 then "partial"
          else "missed" end;
    def detection_status($entry):
        if $entry == null then "missed"
        elif (($entry.status // "") | ascii_downcase) == "missed" then "missed"
        elif (($entry.status // "") | ascii_downcase) == "captured" then "captured"
        elif ((evidence($entry) | length) > 0) then "captured"
        else "missed" end;
    def recommendation($platform; $number):
        if $platform == "Windows" then
            if $number == 1 or $number == 2 then
                "Enable and verify Security account/group auditing (4720/4732)."
            elif $number == 3 then
                "Verify PowerShell Script Block Logging (4104), Sysmon process creation (1), and command-line collection."
            elif $number == 4 then
                "Verify Sysmon process creation (1) and Security scheduled-task auditing (4698)."
            elif $number == 5 then
                "Review Sysmon network connection rules (3) and destination fields."
            elif $number == 6 then
                "Enable or refine Sysmon file-creation monitoring (11) for the Startup directory."
            else "Review relevant Windows audit settings, Sysmon filtering and captured fields." end
        else
            if $number == 1 or $number == 6 then
                "Verify auditd identity-file watches, relevant syscall rules and auth.log collection."
            elif $number == 2 then
                "Verify auditd watches on /etc/sudoers.d and corresponding audit keys."
            elif $number == 3 then
                "Verify execve auditing with key process_exec and capture executable/argument fields."
            elif $number == 4 then
                "Verify socket/connect auditing with key network_connect and check event filtering."
            elif $number == 5 then
                "Verify auditd cron-directory watches with key cron_persist."
            else "Review auditd rules, audit keys, auth.log and syslog ingestion." end
        end;
    def assess_sysmon($value):
        (if ($value | type) == "array" then $value
         elif ($value | type) == "object" then
             ($value.coverage_matrix // $value.matrix // $value.results //
              $value.tests // $value.events // $value.checks // [])
         else [] end) as $rows
        | ($rows | if type == "array" then . else [] end) as $checks
        | {
            checks_total: ($checks | length),
            captured_checks: ([$checks[] |
                select((.status // .result // .state // "" | tostring | ascii_downcase) |
                  IN("captured", "pass", "passed", "ok"))] | length),
            failed_checks: ([$checks[] |
                select((.status // .result // .state // "" | tostring | ascii_downcase) |
                  IN("missed", "fail", "failed", "blind"))] | length),
            failed_details: ([$checks[] |
                select((.status // .result // .state // "" | tostring | ascii_downcase) |
                    IN("missed", "fail", "failed", "blind")) |
                {event_id: (.event_id // .event_id_number // .id // null),
                 description: (.description // .name // .test // "Sysmon coverage check"),
                 reason: (.reason // .error // "Test reported FAIL or MISSED")}
            ]),
            source_summary: (if ($value | type) == "object" then
                ($value.summary // {}) else {} end)
          };

    ($win[0]) as $w | ($lin[0]) as $l |
    items($ground[0]; "actions") as $truth |
    items($win_matrix[0]; "detection_matrix") as $wm |
    items($lin_matrix[0]; "detection_matrix") as $lm |
    ($win_quality[0]) as $wq | ($lin_quality[0]) as $lq |
    (score($wq)) as $ws | (score($lq)) as $ls |
    (assess_sysmon($sysmon[0])) as $sysmon_result |

    # Join by BOTH platform and action number: Task 9 and Task 11 each use 1..6.
    ([$truth[] | . as $gt |
        ($gt.platform // "unknown") as $platform |
        ($gt.action_number // $gt.action // null) as $number |
        (if $platform == "Windows" then $wm else $lm end |
          map(select((.action_number // .action // null | tostring) == ($number | tostring))) |
          first // null) as $match |
        (($gt.status // "SUCCESS") | tostring | ascii_downcase) as $executed |
        (if ($executed | IN("success", "completed", "ok", "pass", "passed"))
            then detection_status($match) else "unassessed" end) as $status |
        {
            platform: $platform,
            action_number: $number,
            description: ($gt.description // "Unknown action"),
            mitre_attack_id: ($gt.mitre_attack_id // $gt.attack_technique_id // "UNKNOWN"),
            mitre_attack_technique: ($gt.mitre_attack_technique // "Unknown technique"),
            execution_status: ($gt.status // "SUCCESS"),
            detection_status: $status,
            detail_level: (if $status == "captured" then detail($match)
                           elif $status == "unassessed" then "unassessed"
                           else "missed" end),
            captured_sources: (if $status == "captured" then sources($match) else [] end),
            key_fields_present: (if $status == "captured" then key_fields($match) else [] end),
            expected_sources: ($gt.expected_detection_source // []),
            matrix_entry_present: ($match != null)
        }
    ]) as $actions |
    ([$actions[] | select(.detection_status == "captured")]) as $hits |
    ([$actions[] | select(.detection_status == "missed")]) as $misses |
    ([$actions[] | select(.detection_status == "unassessed")]) as $unassessed |
    ([$hits[] | select((.captured_sources | length) > 1)]) as $multi |

    ([$actions[] | select(.mitre_attack_id != "UNKNOWN")] |
       group_by(.mitre_attack_id) |
       map(. as $group |
         ([$group[] | select(.detection_status == "captured")]) as $found |
         ([$group[] | select(.detection_status == "missed")]) as $missed |
         ([$group[] | select(.detection_status == "unassessed")]) as $not_run |
         {
            technique_id: $group[0].mitre_attack_id,
            technique_name: $group[0].mitre_attack_technique,
            platforms: ([$group[].platform] | unique),
            action_count: ($group | length),
            captured_actions: ($found | length),
            missed_actions: ($missed | length),
            unassessed_actions: ($not_run | length),
            source_responsible_for_coverage: ([$found[].captured_sources[]] | unique),
            expected_sources: ([$group[].expected_sources] | flatten | unique),
            coverage: (if ($not_run | length) == ($group | length) then "unassessed"
                       elif ($found | length) == 0 and ($not_run | length) > 0
                           then "unassessed"
                       elif ($found | length) == 0 then "blind"
                       elif ($found | length) == ($group | length) and
                            all($found[]; .detail_level == "full") then "covered"
                       else "partial" end)
         })) as $techniques |
    ([$actions[] | select(.detection_status == "missed" or
                          .detection_status == "unassessed" or
                          .detail_level == "partial") |
      {
        description: (if .detection_status == "missed" then
             "No matching telemetry was confirmed for: " + .description
             elif .detection_status == "unassessed" then
             "Simulation action was not completed: " + .description
             else "Incomplete telemetry details for: " + .description end),
        impacted_platform: .platform,
        impacted_technique: .mitre_attack_id,
        action_number: .action_number,
        reason: (if .detection_status == "unassessed" then
            "Ground truth reports an unsuccessful or incomplete simulation; detection cannot be assessed."
          elif .matrix_entry_present == false then
            "No corresponding entry was found in the platform detection matrix."
          elif .detection_status == "missed" then
            "The detection matrix reports MISSED; the event may be unlogged, filtered or unavailable."
          else "A matching event was recorded, but it lacks some expected detail fields." end),
        recommended_instrumentation_improvement: recommendation(.platform; .action_number)
      }]) as $action_gaps |
    ([$sysmon_result.failed_details[] |
        (.event_id | tostring) as $event_id |
        {
          description: ("Sysmon coverage test failed: " + (.description | tostring)),
          impacted_platform: "Windows",
          impacted_technique: (if $event_id == "1" then "T1059"
                                elif $event_id == "3" then "T1071"
                                elif $event_id == "11" then "T1547.001"
                                elif $event_id == "13" then "T1112"
                                elif $event_id == "22" then "T1071.004"
                                else "UNKNOWN" end),
          action_number: null,
          reason: .reason,
          recommended_instrumentation_improvement:
            ("Review Sysmon event " + $event_id + " configuration, filtering and capture quality.")
        }
    ]) as $sysmon_gaps |
    ($action_gaps + $sysmon_gaps) as $gaps |

    # Confidence is an assessment, not an autograder score. Missing evidence is
    # shown as insufficient_data instead of assigning a made-up percentage.
    (if $w.count == 0 or $l.count == 0 or ($truth | length) == 0 or
          ($wm | length) == 0 or ($lm | length) == 0 or $ws == null or $ls == null
         then "insufficient_data"
     elif $ws >= 98 and $ls >= 98 and ($misses | length) == 0 and
          ($unassessed | length) == 0 and
          all($hits[]; .detail_level == "full") then "high"
     elif $ws >= 85 and $ls >= 85 and
          (($hits | length) / ($truth | length)) >= 0.75 then "acceptable"
     elif $ws >= 70 and $ls >= 70 then "needs_improvement"
     else "low" end) as $confidence |

    {
      report_name: "MedDefense Cross-Platform Telemetry Coverage Assessment",
      assessment_version: "1.0",
      generated_at_utc: $generated,
      status: (if $confidence == "insufficient_data" then "incomplete" else "complete" end),
      event_summary: {
        total_events: ($w.count + $l.count),
        by_platform: { Windows: $w.count, Linux: $l.count },
        by_source_type: ([$w, $l] | map(. as $p | .by_source_type[] |
            {platform: $p.platform, source_type, count})),
        by_event_category: ([$w, $l] | map(. as $p | .by_event_category[] |
            {platform: $p.platform, event_category, count}))
      },
      detection_matrix_summary: {
        total_simulated_actions: ($truth | length),
        captured_actions: ($hits | length),
        missed_actions: ($misses | length),
        unassessed_actions: ($unassessed | length),
        partial_detail_actions: ([$hits[] | select(.detail_level == "partial")] | length),
        multi_source_detections: ($multi | length),
        capture_percentage: (if ($truth | length) > 0 then
          ((($hits | length) / ($truth | length)) * 1000 | round) / 10 else null end),
        by_platform: ([$actions | group_by(.platform)[] |
            {platform: .[0].platform, actions: length,
             captured: ([.[] | select(.detection_status == "captured")] | length),
             missed: ([.[] | select(.detection_status == "missed")] | length),
             multi_source: ([.[] | select(.detection_status == "captured" and
                              (.captured_sources | length) > 1)] | length)}]),
        actions: $actions
      },
      attack_coverage: {
        covered_techniques: ([$techniques[] | select(.coverage == "covered")]),
        partially_covered_techniques: ([$techniques[] | select(.coverage == "partial")]),
        blind_techniques: ([$techniques[] | select(.coverage == "blind")]),
        unassessed_techniques: ([$techniques[] | select(.coverage == "unassessed")]),
        summary: {
          covered: ([$techniques[] | select(.coverage == "covered")] | length),
          partial: ([$techniques[] | select(.coverage == "partial")] | length),
          blind: ([$techniques[] | select(.coverage == "blind")] | length),
          unassessed: ([$techniques[] | select(.coverage == "unassessed")] | length)
        }
      },
      known_gaps: $gaps,
      sysmon_coverage_summary: $sysmon_result,
      quality_summary: {
        windows_score: $ws,
        linux_score: $ls,
        handoff_confidence_rating: $confidence,
        final_handoff_confidence_rating: $confidence,
        confidence_basis: "Based on actual telemetry availability, action detection rate, detection detail and platform quality scores; no score is inferred when missing."
      },
      input_files: [
        "telemetry_handoff/windows_events.json",
        "telemetry_handoff/linux_events.json",
        "telemetry_handoff/attack_ground_truth.json",
        "windows_detection_matrix.json", "linux_detection_matrix.json",
        "windows_telemetry_quality.json", "linux_telemetry_quality.json",
        "sysmon_coverage_matrix.json"
      ]
    }
' > "$work_dir/report.json"

jq -e '.event_summary.total_events >= 0 and .detection_matrix_summary.total_simulated_actions >= 0' \
    "$work_dir/report.json" >/dev/null
mv -f -- "$work_dir/report.json" "$OUTPUT"

windows_count="$(jq -r '.event_summary.by_platform.Windows' "$OUTPUT")"
linux_count="$(jq -r '.event_summary.by_platform.Linux' "$OUTPUT")"
actions="$(jq -r '.detection_matrix_summary.total_simulated_actions' "$OUTPUT")"
captured="$(jq -r '.detection_matrix_summary.captured_actions' "$OUTPUT")"
covered="$(jq -r '.attack_coverage.summary.covered' "$OUTPUT")"
partial="$(jq -r '.attack_coverage.summary.partial' "$OUTPUT")"
blind="$(jq -r '.attack_coverage.summary.blind' "$OUTPUT")"
win_score="$(jq -r '.quality_summary.windows_score // "unknown"' "$OUTPUT")"
lin_score="$(jq -r '.quality_summary.linux_score // "unknown"' "$OUTPUT")"
confidence="$(jq -r '.quality_summary.handoff_confidence_rating' "$OUTPUT")"

printf 'Windows events: %s\n' "$windows_count"
printf 'Linux events: %s\n' "$linux_count"
printf 'Ground truth actions: %s\n' "$actions"
printf 'Detection matrix: %s/%s captured\n' "$captured" "$actions"
printf 'ATT&CK covered: %s\n' "$covered"
printf 'ATT&CK partial: %s\n' "$partial"
printf 'ATT&CK blind: %s\n' "$blind"
printf 'Windows quality: %s\n' "$win_score"
printf 'Linux quality: %s\n' "$lin_score"
printf 'Confidence: %s\n' "$confidence"
printf 'Report saved to: %s\n' "$(basename "$OUTPUT")"
