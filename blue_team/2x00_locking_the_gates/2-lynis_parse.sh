#!/bin/bash

# Task 2 - Lynis Audit Parser
# This reads a Lynis report and converts the findings into JSON.
# Usage: ./2-lynis_parse.sh lynis-report.dat

# Check that a report file was provided
if [ $# -ne 1 ] || [ ! -r "$1" ]; then
    echo "Please provide a readable Lynis report file." >&2
    exit 1
fi

REPORT="$1"

# Check that jq is available
if ! command -v jq > /dev/null; then
    echo "jq is required to create the JSON output." >&2
    exit 1
fi

# Get the hardening index from the report
INDEX=$(grep -m1 '^hardening_index=' "$REPORT" | cut -d= -f2)

if ! [[ "$INDEX" =~ ^[0-9]+$ ]]; then
    echo "Could not find a valid hardening index." >&2
    exit 1
fi

# Start the JSON output
echo "{"
echo "  \"hardening_index\": $INDEX,"
echo '  "findings": ['

FIRST=true

# Read the report one line at a time
while IFS= read -r line; do

    # Identify the finding type
    case "$line" in
        warning\[\]=*) SEVERITY="warning" ;;
        suggestion\[\]=*) SEVERITY="suggestion" ;;
        manual_check\[\]=*) SEVERITY="manual_check" ;;
        *) continue ;;
    esac

    # Separate the test ID and message
    DATA="${line#*=}"
    TEST_ID="${DATA%%|*}"
    REST="${DATA#*|}"
    MESSAGE="${REST%%|*}"

    # Skip entries without the expected fields
    if [ "$DATA" = "$REST" ] || [ -z "$TEST_ID" ]; then
        continue
    fi

    # Add commas between findings
    if [ "$FIRST" = false ]; then
        echo ","
    fi

    FIRST=false

    # Convert each finding into JSON
    jq -nc \
        --arg severity "$SEVERITY" \
        --arg test_id "$TEST_ID" \
        --arg message "$MESSAGE" \
        '{severity: $severity, test_id: $test_id, message: $message}'

done < "$REPORT"

# Finish the JSON output
echo ""
echo "  ]"
echo "}"
