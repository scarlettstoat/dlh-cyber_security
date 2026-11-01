#!/bin/bash
set -euo pipefail
export LC_ALL=C

# Task 0 - Read-only inventory of installed packages and security updates.
PROJECT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
FEED="$PROJECT_DIR/cve_feed.json"
OUTPUT="$PROJECT_DIR/vulnerability_inventory.json"

fail() {
    printf 'Error: %s\n' "$1" >&2
    exit 1
}

for tool in dpkg-query dpkg apt apt-cache apt-get jq awk grep sort timeout mktemp; do
    command -v "$tool" >/dev/null 2>&1 || fail "Missing command: $tool"
done
[[ -r "$FEED" ]] || fail "Cannot read $FEED (copy the supplied feed to the project directory)."

WORK_DIR=$(mktemp -d)
trap 'rm -rf -- "$WORK_DIR"' EXIT

# Accept the common array, {cves:[...]}, and CVE-keyed feed layouts.
# A missing CVE in the exercise feed is normal, not an error.
jq '
  def items:
    if type == "array" then .[]
    elif (.cves? | type) == "array" then .cves[]
    elif (.cves? | type) == "object" then
      .cves | to_entries[] | select(.key | test("^CVE-[0-9]{4}-[0-9]{4,}$"))
      | .value + {id: .key}
    elif (.vulnerabilities? | type) == "array" then .vulnerabilities[]
    elif (.vulnerabilities? | type) == "object" then
      .vulnerabilities | to_entries[] | select(.key | test("^CVE-[0-9]{4}-[0-9]{4,}$"))
      | .value + {id: .key}
    elif (.entries? | type) == "array" then .entries[]
    elif type == "object" then
      to_entries[] | select(.key | test("^CVE-[0-9]{4}-[0-9]{4,}$"))
      | .value + {id: .key}
    else empty end;
  def score_value:
    if type == "number" then .
    elif type == "string" then (tonumber? // null)
    elif type == "object" then
      (.baseScore // .base_score // .score // .cvssData.baseScore // null)
      | score_value
    else null end;
  def kev_value:
    if type == "boolean" then .
    elif type == "string" then ascii_downcase == "true"
    else . == 1 end;
  [items | . as $entry
    | (if (.cve? | type) == "object" then .cve else . end) as $data
    | ($entry.id // $entry.cve_id // $entry.cveId
       // (if ($entry.cve? | type) == "string" then $entry.cve else null end)
       // $data.id // $data.cve_id // $data.cveId // null) as $id
    | select(($id | type) == "string" and ($id | test("^CVE-[0-9]{4}-[0-9]{4,}$")))
    | {
        key: $id,
        value: {
          cvss: (($entry.cvss // $entry.cvss_score // $entry.cvss_base_score
                  // $entry.base_score // $entry.cvss_v3 // $entry.cvss_v3_1
                  // $entry.cvss_v3_score
                  // $data.cvss // $data.cvss_score // $data.cvss_base_score
                  // $data.base_score // $data.metrics.cvssMetricV31[0].cvssData.baseScore
                  // $data.metrics.cvssMetricV30[0].cvssData.baseScore // null)
                 | score_value),
          kev: (($entry.in_cisa_kev // $entry.cisa_kev // $entry.kev
                 // $entry.known_exploited // $data.in_cisa_kev
                 // $data.cisa_kev // $data.kev // false) | kev_value)
        }
      }
  ] | from_entries
' "$FEED" > "$WORK_DIR/feed_index.json" || fail "Invalid or unsupported CVE feed JSON."

# 1. Capture the complete installed-package set using the requested dpkg fields.
dpkg-query -W -f='${binary:Package} ${Version} ${Status}\n' > "$WORK_DIR/dpkg.txt"
awk '$3 == "install" && $4 == "ok" && $5 == "installed" {print $1 "\t" $2}' \
    "$WORK_DIR/dpkg.txt" > "$WORK_DIR/installed.tsv"
[[ -s "$WORK_DIR/installed.tsv" ]] || fail "No installed packages found."

# 2. APT's cached upgrade list (no apt update or package modification).
apt list --upgradable > "$WORK_DIR/upgradable.txt" 2>/dev/null \
    || fail "Unable to read APT upgrade list."

# Read the repository pocket for the *candidate version*, not an older version.
get_pocket() {
    local candidate=$1
    awk -v target="$candidate" '
      /^  \*\*\* [^ ]+ [0-9]+$/ || /^     [^ ]+ [0-9]+$/ {
        line=$0
        sub(/^[[:space:]]+/, "", line)
        sub(/^\*\*\*[[:space:]]+/, "", line)
        split(line, parts, /[[:space:]]+/)
        active=(parts[1] == target)
        next
      }
      active && match($0, /[[:alnum:]._-]+-(security|updates|backports)/) {
        pocket=substr($0, RSTART, RLENGTH)
        rank=(pocket ~ /-security$/ ? 3 : pocket ~ /-updates$/ ? 2 : 1)
        if (rank > best_rank) {best_rank=rank; best=pocket}
      }
      END {if (best_rank > 0) print best}
    ' "$WORK_DIR/policy.txt"
}

# 4. Extract CVEs only from changelog versions newer than the installed version.
# Changelog retrieval may use the network, but does not install anything.
get_changelog_cves() {
    local package=$1 installed=$2 candidate=$3 line version relevant=0
    if ! timeout 20s apt-get changelog "$package=$candidate" \
        > "$WORK_DIR/changelog.txt" 2>/dev/null; then
        return 1
    fi
    while IFS= read -r line; do
        if [[ $line =~ ^[^[:space:]]+[[:space:]]+\(([^\)]*)\) ]]; then
            version=${BASH_REMATCH[1]}
            relevant=0
            if dpkg --compare-versions "$version" gt "$installed" && \
               dpkg --compare-versions "$version" le "$candidate"; then
                relevant=1
            fi
        fi
        if (( relevant )); then
            grep -Eo 'CVE-[0-9]{4}-[0-9]{4,}' <<< "$line" || true
        fi
    done < "$WORK_DIR/changelog.txt"
}

# Conservative local USN fallback: only CVEs explicitly mapped to this package
# in readable, structured JSON files; never guess from arbitrary file contents.
get_local_usn_cves() {
    local package=$1 source_package=$2 file
    local base=/usr/share/ubuntu-advantage-tools
    [[ -d "$base" ]] || return 0
    while IFS= read -r -d '' file; do
        jq -r --arg p "$package" --arg s "$source_package" '
          .. | objects
          | select((.package? // .package_name? // .source_package? // .source? // "") as $n
                   | ($n | type) == "string" and ($n == $p or $n == $s))
          | (.cves? // .cve_ids? // [])
          | if type == "array" then .[] elif type == "string" then . else empty end
          | select(type == "string" and test("^CVE-[0-9]{4}-[0-9]{4,}$"))
        ' "$file" 2>/dev/null || true
    done < <(find "$base" -maxdepth 5 -type f -name '*.json' -print0 2>/dev/null)
}

: > "$WORK_DIR/packages.ndjson"
checked=0
security_count=0
while IFS= read -r line; do
    [[ $line == */* ]] || continue
    package=${line%%/*}
    [[ $package =~ ^[a-zA-Z0-9+.:_-]+$ ]] || continue
    checked=$((checked + 1))

    # Use the installed version captured from dpkg, not the display in apt list.
    installed=$(awk -F '\t' -v p="$package" '$1 == p {print $2; exit}' \
        "$WORK_DIR/installed.tsv")
    [[ -n "$installed" ]] || continue

    apt-cache policy "$package" > "$WORK_DIR/policy.txt"
    candidate=$(awk '/^[[:space:]]*Candidate:/ {print $2; exit}' \
        "$WORK_DIR/policy.txt")
    [[ -n "$candidate" && "$candidate" != '(none)' ]] || continue
    dpkg --compare-versions "$candidate" gt "$installed" || continue
    pocket=$(get_pocket "$candidate")
    [[ "$pocket" == *-security ]] || continue
    security_count=$((security_count + 1))

    source_package=$(dpkg-query -W -f='${source:Package}' "$package" 2>/dev/null || true)
    [[ -n "$source_package" ]] || source_package=${package%%:*}

    # A missing/unreachable changelog must not prevent a usable inventory.
    cves=$(get_changelog_cves "$package" "$installed" "$candidate" || true)
    if [[ -z "$cves" ]]; then
        cves=$(get_local_usn_cves "$package" "$source_package")
    fi
    cves_json=$(printf '%s\n' "$cves" \
        | grep -E '^CVE-[0-9]{4}-[0-9]{4,}$' \
        | sort -u | jq -Rsc 'split("\n") | map(select(length > 0))' ) || cves_json='[]'

    jq -cn --arg package "$package" --arg installed "$installed" \
       --arg candidate "$candidate" --arg pocket "$pocket" \
       --argjson cves "$cves_json" --slurpfile feed "$WORK_DIR/feed_index.json" '
      ([ $cves[] as $id | $feed[0][$id].cvss // empty ] | max // null) as $max
      | {
          package: $package,
          installed_version: $installed,
          candidate_version: $candidate,
          source_pocket: $pocket,
          cves: $cves,
          max_cvss: $max,
          severity: (if $max == null then "unknown"
                     elif $max >= 9 then "critical"
                     elif $max >= 7 then "high"
                     elif $max >= 4 then "medium"
                     elif $max > 0 then "low" else "none" end),
          in_cisa_kev: any($cves[] as $id | $feed[0][$id].kev == true; .)
        }
    ' >> "$WORK_DIR/packages.ndjson"
done < "$WORK_DIR/upgradable.txt"

# 6. Write one complete, valid JSON document, with the required packages array.
# Use a temporary file and rename so a failed run cannot truncate the last report.
report_tmp=$(mktemp "$PROJECT_DIR/.vulnerability_inventory.XXXXXXXX")
trap 'rm -rf -- "$WORK_DIR"; rm -f -- "$report_tmp"' EXIT
jq -n --arg generated_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
   --arg hostname "$(hostname)" \
   --argjson installed_count "$(wc -l < "$WORK_DIR/installed.tsv")" \
   --argjson upgradeable_count "$checked" \
   --argjson security_upgrade_count "$security_count" \
   --slurpfile packages "$WORK_DIR/packages.ndjson" '
   {
     generated_at: $generated_at,
     hostname: $hostname,
     installed_package_count: $installed_count,
     upgradeable_package_count: $upgradeable_count,
     security_upgrade_count: $security_upgrade_count,
     packages: $packages
   }
' > "$report_tmp"
mv -- "$report_tmp" "$OUTPUT"
printf 'Inventory saved: %s\n' "$OUTPUT"
printf 'Installed: %s | Upgradable: %s | Security upgrades: %s\n' \
    "$(wc -l < "$WORK_DIR/installed.tsv")" "$checked" "$security_count"
