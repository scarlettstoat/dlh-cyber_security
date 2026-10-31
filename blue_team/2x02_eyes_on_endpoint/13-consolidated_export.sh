#!/bin/bash
# Name: 13-consolidated_export.sh
# Purpose: Prepare a Windows/Linux telemetry handoff with UTC timestamps and attacker ground truth.
# Author: Suraya
# Project: MedDefense - Eyes on the Endpoint (2x02), Task 13
# Run: ./13-consolidated_export.sh (with the four input JSON files beside this script)

set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
    echo '[!] Python 3 is required to process the JSON exports.' >&2
    exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# Use Python's standard JSON and datetime libraries to preserve event fields
# and handle timezone offsets consistently (no extra packages required).
python3 - "$SCRIPT_DIR" "$@" <<'PY'
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

script_dir = Path(sys.argv[1])
parser = argparse.ArgumentParser(description='Build the Task 13 SOC telemetry handoff.')
parser.add_argument('--windows', type=Path,
                    default=script_dir / 'windows_events_export.json')
parser.add_argument('--linux', type=Path,
                    default=script_dir / 'linux_events_export.json')
parser.add_argument('--windows-ground-truth', type=Path,
                    default=script_dir / 'windows_attack_log.json')
parser.add_argument('--linux-ground-truth', type=Path,
                    default=script_dir / 'linux_attack_log.json')
parser.add_argument('--output-dir', type=Path,
                    default=script_dir / 'telemetry_handoff')
args = parser.parse_args(sys.argv[2:])

REQUIRED = ('timestamp', 'hostname', 'source_type', 'event_category')
UTC = timezone.utc


def read_array(path, label, preferred_key):
    """Accept a JSON array or a named array inside a JSON export object."""
    try:
        with path.open('r', encoding='utf-8-sig') as handle:
            data = json.load(handle)
    except FileNotFoundError:
        raise ValueError(f'{label} file not found: {path}') from None
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f'Cannot read {label} file {path}: {exc}') from exc

    if isinstance(data, dict):
        data = data.get(preferred_key)
    if not isinstance(data, list):
        raise ValueError(f'{label}: expected a JSON array (or an object containing "{preferred_key}").')
    for index, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            raise ValueError(f'{label}: item {index} must be a JSON object.')
    return data


def utc_timestamp(value, label):
    """Convert a recorded time with its offset to UTC ISO 8601."""
    try:
        if isinstance(value, bool):
            raise ValueError('boolean is not a timestamp')
        if isinstance(value, (int, float)):
            seconds = value / 1000 if abs(value) >= 100_000_000_000 else value
            moment = datetime.fromtimestamp(seconds, tz=UTC)
        elif isinstance(value, str) and value.strip():
            text = value.strip()
            # Supports both 2026-10-31T15:30:00Z and ISO timestamps with offsets.
            moment = datetime.fromisoformat(text.replace('Z', '+00:00'))
            if moment.tzinfo is None:
                # The earlier Tasks 3, 7, 9 and 11 already export UTC timestamps.
                moment = moment.replace(tzinfo=UTC)
        else:
            raise ValueError('timestamp must be a nonempty string or Unix epoch')
        return moment.astimezone(UTC).isoformat().replace('+00:00', 'Z')
    except (ValueError, OverflowError, OSError) as exc:
        raise ValueError(f'{label}: invalid timestamp {value!r} ({exc})') from exc


def normalize_events(events, platform):
    normalized = []
    for number, event in enumerate(events, start=1):
        missing = [field for field in REQUIRED
                   if field not in event or event[field] is None
                   or (isinstance(event[field], str) and not event[field].strip())]
        if missing:
            raise ValueError(f'{platform} event {number}: missing required fields: {", ".join(missing)}')
        updated = dict(event)
        updated['timestamp'] = utc_timestamp(updated['timestamp'], f'{platform} event {number}')
        updated['platform'] = platform
        normalized.append(updated)
    normalized.sort(key=lambda event: datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00')))
    return normalized


def normalize_ground_truth(actions, platform):
    combined = []
    for number, action in enumerate(actions, start=1):
        if 'timestamp' not in action:
            raise ValueError(f'{platform} ground truth action {number}: missing timestamp')
        updated = dict(action)
        updated['timestamp'] = utc_timestamp(updated['timestamp'], f'{platform} action {number}')
        updated['platform'] = platform
        # Preserve the action numbers, command and expected detection sources.
        if 'completed_at_utc' in updated and updated['completed_at_utc']:
            updated['completed_at_utc'] = utc_timestamp(
                updated['completed_at_utc'], f'{platform} action {number} completion')
        combined.append(updated)
    return combined


def write_json(path, records):
    """Write to a temporary file, then replace the finished JSON atomically."""
    temporary = path.with_name(path.name + '.tmp')
    try:
        with temporary.open('w', encoding='utf-8') as handle:
            json.dump(records, handle, ensure_ascii=False, indent=2)
            handle.write('\n')
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def file_size(path):
    return f'{path.stat().st_size / (1024 * 1024):.2f} MB'


try:
    windows_raw = read_array(args.windows, 'Windows telemetry', 'events')
    linux_raw = read_array(args.linux, 'Linux telemetry', 'events')
    print(f'[*] Loading Windows events ({len(windows_raw):,})...')
    print(f'[*] Loading Linux events ({len(linux_raw):,})...')

    print('[*] Normalizing timestamps to UTC...')
    windows_events = normalize_events(windows_raw, 'Windows')
    linux_events = normalize_events(linux_raw, 'Linux')
    print(f'    Windows: {len(windows_events):,} events normalized')
    print(f'    Linux: {len(linux_events):,} events normalized')

    print('[*] Verifying field consistency...')
    # normalize_events() has already checked every required field on every event.
    print('    Required fields present in all events    [OK]')

    print('[*] Combining ground truth...')
    windows_actions = read_array(args.windows_ground_truth, 'Windows ground truth', 'actions')
    linux_actions = read_array(args.linux_ground_truth, 'Linux ground truth', 'actions')
    ground_truth = (normalize_ground_truth(windows_actions, 'Windows') +
                    normalize_ground_truth(linux_actions, 'Linux'))
    ground_truth.sort(key=lambda action: datetime.fromisoformat(action['timestamp'].replace('Z', '+00:00')))
    print(f'    Windows actions: {len(windows_actions)} | '
          f'Linux actions: {len(linux_actions)} | Total: {len(ground_truth)}')

    args.output_dir.mkdir(parents=True, exist_ok=True)
    windows_output = args.output_dir / 'windows_events.json'
    linux_output = args.output_dir / 'linux_events.json'
    truth_output = args.output_dir / 'attack_ground_truth.json'
    write_json(windows_output, windows_events)
    write_json(linux_output, linux_events)
    write_json(truth_output, ground_truth)

    print('[*] Building handoff directory...')
    print(f'{args.output_dir}/')
    print(f'  windows_events.json       ({len(windows_events):,} events, {file_size(windows_output)})')
    print(f'  linux_events.json         ({len(linux_events):,} events, {file_size(linux_output)})')
    print(f'  attack_ground_truth.json  ({len(ground_truth)} actions, {file_size(truth_output)})')
    print(f'Total: {len(windows_events) + len(linux_events):,} events across 2 platforms')
except (ValueError, OSError) as exc:
    print(f'[!] {exc}', file=sys.stderr)
    sys.exit(1)
PY
