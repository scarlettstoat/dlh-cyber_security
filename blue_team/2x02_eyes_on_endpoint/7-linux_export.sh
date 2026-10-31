#!/bin/bash
# Name: 7-linux_export.sh
# Purpose: Export auth.log, auditd and syslog events as normalised JSON for SOC analysis.
# Author: Suraya

set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
    echo '[!] Python 3 is required to parse timestamps and write valid JSON.' >&2
    exit 1
fi

# Python's standard library handles three log formats without extra packages.
# Keep the default export beside this script, even when started elsewhere.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export LINUX_EXPORT_OUTPUT_DEFAULT="$SCRIPT_DIR/linux_events_export.json"
python3 - "$@" <<'PY'
import argparse
import collections
import datetime as dt
import ipaddress
import json
import os
import re
import socket
import sys
import tempfile
import time
from pathlib import Path

UTC = dt.timezone.utc
DEFAULT_HOST = socket.gethostname()
DEFAULT_OUTPUT = Path(os.environ['LINUX_EXPORT_OUTPUT_DEFAULT'])

parser = argparse.ArgumentParser(description='Export Linux security telemetry to JSON.')
parser.add_argument('--auth-log', default='/var/log/auth.log', help='Path to auth.log')
parser.add_argument('--audit-log', default='/var/log/audit/audit.log', help='Path to audit.log')
parser.add_argument('--syslog', default='/var/log/syslog', help='Path to syslog')
parser.add_argument('--output', default=str(DEFAULT_OUTPUT), help='JSON output path')
window = parser.add_mutually_exclusive_group()
window.add_argument('--date', help='UTC day to export (YYYY-MM-DD)')
window.add_argument('--hours', type=int, help='Most recent number of hours (default 24)')
window.add_argument('--start', help='UTC start time (ISO 8601)')
parser.add_argument('--end', help='UTC end time (ISO 8601, requires --start)')
args = parser.parse_args()


def parse_iso(value):
    try:
        result = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        parser.error('Invalid ISO 8601 timestamp: ' + str(exc))
    if result.tzinfo is None:
        result = result.replace(tzinfo=UTC)
    return result.astimezone(UTC)


now = dt.datetime.now(UTC)
if args.date:
    try:
        day = dt.date.fromisoformat(args.date)
    except ValueError:
        parser.error('--date must be YYYY-MM-DD')
    start = dt.datetime.combine(day, dt.time.min, tzinfo=UTC)
    end = dt.datetime.combine(day, dt.time.max, tzinfo=UTC)
elif args.start:
    if not args.end:
        parser.error('--start requires --end')
    start, end = parse_iso(args.start), parse_iso(args.end)
else:
    if args.end:
        parser.error('--end requires --start')
    if args.hours is not None and args.hours < 1:
        parser.error('--hours must be greater than zero')
    end = now
    start = end - dt.timedelta(hours=args.hours or 24)
if start > end:
    parser.error('Start time must be earlier than end time')


def iso(timestamp):
    return timestamp.astimezone(UTC).isoformat(timespec='seconds').replace('+00:00', 'Z')


def in_window(timestamp):
    return start <= timestamp <= end


# Rsyslog auth.log and syslog normally omit the year and use the local timezone.
# mktime() applies the host's local timezone, including historical DST rules.
ISO_SYSLOG_RE = re.compile(
    r'^(?P<stamp>\d{4}-\d{2}-\d{2}T\S+)\s+'
    r'(?P<host>\S+)\s+(?P<provider>[^:\[]+)'
    r'(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$'
)
SYSLOG_RE = re.compile(
    r'^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+'
    r'(?P<clock>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<provider>[^:\[]+)'
    r'(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$'
)


def syslog_timestamp(month, day, clock):
    candidates = []
    for year in range(start.year - 1, end.year + 2):
        try:
            stamp = dt.datetime.strptime(
                f'{year} {month} {day} {clock}', '%Y %b %d %H:%M:%S'
            )
        except ValueError:
            continue
        epoch = time.mktime(stamp.timetuple())
        candidate = dt.datetime.fromtimestamp(epoch, UTC)
        distance = max((start - candidate).total_seconds(),
                       (candidate - end).total_seconds(), 0)
        candidates.append((distance, candidate))
    return min(candidates, key=lambda pair: pair[0])[1] if candidates else None


def base_event(timestamp, hostname, source_type, provider, message, category, event_id=None):
    # Core keys align with the Windows export from Task 3.
    return {
        'timestamp': iso(timestamp),
        'hostname': hostname,
        'platform': 'Linux',
        'source_type': source_type,
        'channel': source_type,
        'event_id': event_id,
        'event_category': category,
        'provider': provider,
        'raw_message': message,
    }


def read_syslog_format(path, source):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as file:
            for line in file:
                line = line.rstrip('\n')
                iso_match = ISO_SYSLOG_RE.match(line)
                match = iso_match or SYSLOG_RE.match(line)
                if not match:
                    continue
                fields = match.groupdict()
                if iso_match:
                    try:
                        timestamp = dt.datetime.fromisoformat(
                            fields['stamp'].replace('Z', '+00:00')
                        )
                        if timestamp.tzinfo is None:
                            timestamp = timestamp.replace(tzinfo=UTC)
                        timestamp = timestamp.astimezone(UTC)
                    except ValueError:
                        continue
                else:
                    timestamp = syslog_timestamp(
                        fields['month'], fields['day'], fields['clock']
                    )
                if timestamp is None or not in_window(timestamp):
                    continue
                yield timestamp, fields
    except (OSError, PermissionError) as exc:
        print(f'[!] Cannot read {source} ({path}): {exc}', file=sys.stderr)
        return


ssh_success = re.compile(r'Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+([\dA-Fa-f:.]+)', re.I)
ssh_failure = re.compile(
    r'Failed\s+(\S+)\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+([\dA-Fa-f:.]+)', re.I
)
ssh_other = re.compile(r'(?:Invalid user|Disconnected from|Connection closed by|authentication failure)', re.I)


def parse_auth(path):
    results = []
    counts = collections.Counter()
    for timestamp, parts in read_syslog_format(path, 'auth.log'):
        message = parts['message']
        provider = parts['provider'].strip()
        lower = provider.lower()
        category = None
        details = {}
        if lower == 'sshd' or lower.startswith('sshd-'):
            match_ok = ssh_success.search(message)
            match_fail = ssh_failure.search(message)
            if match_ok:
                category = 'ssh_login_success'
                details = {'auth_method': match_ok.group(1), 'user': match_ok.group(2),
                           'source_ip': match_ok.group(3), 'success': True}
            elif match_fail:
                category = 'ssh_login_failure'
                details = {'auth_method': match_fail.group(1), 'user': match_fail.group(2),
                           'source_ip': match_fail.group(3), 'success': False}
            elif ssh_other.search(message):
                category = 'ssh_other'
                ip = re.search(r'\bfrom\s+([\dA-Fa-f:.]+)', message)
                if ip:
                    details['source_ip'] = ip.group(1)
            elif 'pam_' in message.lower():
                category = 'pam'
        elif lower == 'sudo':
            category = 'sudo'
            match_user = re.match(r'\s*(\S+)\s*:', message)
            match_command = re.search(r'(?:^|;\s*)COMMAND=(.*)$', message)
            match_target = re.search(r'(?:^|;\s*)USER=(\S+)', message)
            if match_user:
                details['user'] = match_user.group(1)
            if match_command:
                details['command_line'] = match_command.group(1).strip()
            if match_target:
                details['target_user'] = match_target.group(1)
        elif lower == 'su' or lower.startswith('su['):
            category = 'su'
            match_su = re.search(r'(?:Successful|FAILED)\s+su\s+for\s+(\S+)\s+by\s+(\S+)', message, re.I)
            if match_su:
                details['target_user'], details['user'] = match_su.groups()
            details['success'] = not bool(re.search(r'FAILED|failure', message, re.I))
        elif 'pam_' in message.lower():
            category = 'pam'
        if category is None:
            continue  # Focus on authentication and privilege-use events.
        record = base_event(timestamp, parts['host'], 'auth.log', provider,
                            message, category, provider)
        record.update(details)
        if parts['pid']:
            record['pid'] = int(parts['pid'])
        results.append(record)
        counts['ssh' if category.startswith('ssh_') else category] += 1
    print(f'[*] Parsing auth.log... {len(results):,} events')
    print(f"    SSH logins: {counts['ssh']:,} | sudo: {counts['sudo']:,} | "
          f"su: {counts['su']:,} | PAM: {counts['pam']:,}")
    return results


AUDIT_RE = re.compile(r'\btype=(\w+)\s+msg=audit\((\d+(?:\.\d+)?):(\d+)\):')
AUDIT_NODE_RE = re.compile(r'\bnode=(\S+)')
AUDIT_KV = re.compile(r'([a-zA-Z][\w]*)=(?:"((?:\\.|[^"\\])*)"|(\S+))')


def parse_kv(text):
    return {match.group(1): (match.group(2) if match.group(2) is not None
                              else match.group(3))
            for match in AUDIT_KV.finditer(text)}


def decode_exec_arg(value):
    # auditd sometimes hex-encodes command arguments with spaces/control bytes.
    if value and len(value) % 2 == 0 and re.fullmatch(r'[0-9A-Fa-f]+', value):
        try:
            result = bytes.fromhex(value).decode('utf-8', 'replace')
            if all(ch.isprintable() or ch.isspace() for ch in result):
                return result
        except ValueError:
            pass
    return value or ''


def decode_sockaddr(hex_string):
    if not hex_string or not re.fullmatch(r'[0-9A-Fa-f]+', hex_string):
        return {}
    try:
        data = bytes.fromhex(hex_string)
        if len(data) < 4:
            return {}
        family = int.from_bytes(data[0:2], 'little')
        port = int.from_bytes(data[2:4], 'big')
        if family == socket.AF_INET and len(data) >= 8:
            return {'destination_ip': str(ipaddress.IPv4Address(data[4:8])),
                    'destination_port': port}
        if family == socket.AF_INET6 and len(data) >= 24:
            return {'destination_ip': str(ipaddress.IPv6Address(data[8:24])),
                    'destination_port': port}
        if family == socket.AF_UNIX:
            path = data[2:].split(b'\0', 1)[0].decode('utf-8', 'replace')
            return {'socket_path': path}
    except (ValueError, OSError):
        pass
    return {}


def parse_audit(path):
    events = {}
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as file:
            for line in file:
                header = AUDIT_RE.search(line)
                if not header:
                    continue
                kind, epoch, serial = header.groups()
                try:
                    timestamp = dt.datetime.fromtimestamp(float(epoch), UTC)
                except (ValueError, OverflowError):
                    continue
                if not in_window(timestamp):
                    continue
                key = (epoch, serial)
                if key not in events:
                    host = AUDIT_NODE_RE.search(line)
                    events[key] = {'timestamp': timestamp,
                                   'hostname': host.group(1) if host else DEFAULT_HOST,
                                   'serial': serial, 'records': [], 'types': set()}
                info = events[key]
                info['types'].add(kind)
                info['records'].append((kind, parse_kv(line), line.rstrip('\n')))
    except (OSError, PermissionError) as exc:
        print(f'[!] Cannot read audit.log ({path}): {exc}', file=sys.stderr)

    results = []
    counts = collections.Counter()
    for group in events.values():
        grouped = group['records']
        syscall = next((fields for kind, fields, _ in grouped if kind == 'SYSCALL'), {})
        execve = next((fields for kind, fields, _ in grouped if kind == 'EXECVE'), {})
        paths = [fields.get('name') for kind, fields, _ in grouped
                 if kind == 'PATH' and fields.get('name')]
        sockaddr = next((fields.get('saddr') for kind, fields, _ in grouped
                         if kind == 'SOCKADDR'), None)
        audit_key = syscall.get('key', '').strip('"')
        syscall_id = syscall.get('syscall', '')
        types = group['types']

        if 'EXECVE' in types or syscall_id in ('59', '322', 'execve', 'execveat') or audit_key == 'process_exec':
            category, label = 'process_execution', 'execve'
        elif 'SOCKADDR' in types or syscall_id in ('41', '42', 'socket', 'connect') or audit_key == 'network_connect':
            category, label = 'network_connection', 'network'
        elif paths or audit_key in ('ssh_keys', 'cron_persist', 'sudoers'):
            category, label = 'file_access', 'file_access'
        else:
            category, label = 'other', 'other'

        raw_message = '\n'.join(raw for _, _, raw in grouped)
        record = base_event(group['timestamp'], group['hostname'], 'auditd',
                            'auditd', raw_message, category, syscall_id or None)
        record['audit_serial'] = int(group['serial'])
        if audit_key and audit_key != '(null)':
            record['audit_key'] = audit_key
        if syscall.get('exe'):
            record['process'] = syscall['exe']
        if syscall.get('uid'):
            record['uid'] = syscall['uid']
        if syscall.get('auid'):
            record['audit_uid'] = syscall['auid']
        if syscall.get('success'):
            record['success'] = syscall['success'].lower() == 'yes'
        if paths:
            record['path'] = paths[0]
            record['paths'] = paths
        if category == 'process_execution':
            argkeys = sorted((key for key in execve if re.fullmatch(r'a\d+', key)),
                             key=lambda key: int(key[1:]))
            argv = [decode_exec_arg(execve[key]) for key in argkeys]
            record['command_line'] = ' '.join(argv) if argv else syscall.get('exe') or syscall.get('comm', '')
        if category == 'network_connection':
            record.update(decode_sockaddr(sockaddr))
        results.append(record)
        counts[label] += 1

    print(f'[*] Parsing audit.log... {len(results):,} events')
    print(f"    execve: {counts['execve']:,} | file_access: {counts['file_access']:,} | "
          f"network: {counts['network']:,} | other: {counts['other']:,}")
    return results


SERVICE_RE = re.compile(r'\b(Starting|Started|Stopping|Stopped|Reloading|Reloaded|Deactivated|Activating|Stopped successfully)\b', re.I)
ERROR_RE = re.compile(r'\b(error|failed|failure|fatal|critical|denied|segfault|panic)\b', re.I)


def parse_syslog(path):
    results = []
    counts = collections.Counter()
    for timestamp, parts in read_syslog_format(path, 'syslog'):
        message = parts['message']
        provider = parts['provider'].strip()
        if ERROR_RE.search(message):
            category = 'error'
        elif SERVICE_RE.search(message):
            category = 'service'
        else:
            category = 'other'
        record = base_event(timestamp, parts['host'], 'syslog', provider,
                            message, category, provider)
        if parts['pid']:
            record['pid'] = int(parts['pid'])
        match = SERVICE_RE.search(message)
        if category == 'service' and match:
            record['service_action'] = match.group(1).lower()
        results.append(record)
        counts[category] += 1
    print(f'[*] Parsing syslog... {len(results):,} events')
    print(f"    service: {counts['service']:,} | error: {counts['error']:,} | "
          f"other: {counts['other']:,}")
    return results


# Allow partial exports when one log is missing, but do not silently invent data.
readable = [p for p in (args.auth_log, args.audit_log, args.syslog)
            if os.path.isfile(p) and os.access(p, os.R_OK)]
if not readable:
    print('[!] No readable input logs. Run with sudo or provide log paths.', file=sys.stderr)
    sys.exit(1)

print('[*] Exporting Linux security events...')
records = parse_auth(args.auth_log) + parse_audit(args.audit_log) + parse_syslog(args.syslog)
records.sort(key=lambda event: event['timestamp'])

output_path = Path(args.output).expanduser().resolve()
os.umask(0o077)  # Exported security logs may contain sensitive information.
try:
    with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=output_path.parent,
                                     prefix='.linux_events_', suffix='.tmp',
                                     delete=False) as file:
        tmp_path = file.name
        json.dump(records, file, indent=2, ensure_ascii=False)
        file.write('\n')
    os.replace(tmp_path, output_path)
except OSError as exc:
    if 'tmp_path' in locals():
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
    print(f'[!] Unable to write JSON: {exc}', file=sys.stderr)
    sys.exit(1)

print(f'Total events: {len(records):,}')
print(f'Time range: {iso(start)} to {iso(end)}')
print(f'JSON exported: {output_path}')
PY
