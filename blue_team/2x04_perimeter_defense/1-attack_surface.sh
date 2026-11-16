#!/bin/bash
# Classify Task 0 listeners using local catalogue files; no network state changes.
# Usage: sudo ./1-attack_surface.sh [baseline.json [catalogue.json [criticality.json]]]
set -euo pipefail
export LC_ALL=C

if [[ $(id -u) -ne 0 ]]; then
    printf 'Run with sudo to resolve socket binaries and process details.\n' >&2
    exit 1
fi
if (( $# > 3 )); then
    printf 'Usage: %s [baseline.json [catalogue.json [criticality.json]]]\n' "$0" >&2
    exit 1
fi
for dependency in python3 dpkg; do
    if ! command -v "$dependency" >/dev/null 2>&1; then
        printf 'Missing required command: %s\n' "$dependency" >&2
        exit 1
    fi
done

# Prefer the supplied lab assets. Explicit arguments can select local copies.
policy_path() {
    if [[ -r /home/analyst/MedDefense_Lab/$1 ]]; then
        printf '/home/analyst/MedDefense_Lab/%s\n' "$1"
    else
        printf '%s\n' "$1"
    fi
}
baseline_file=${1:-network_baseline.json}
catalogue_file=${2:-$(policy_path service_catalog.json)}
criticality_file=${3:-$(policy_path service_criticality.json)}
for input_file in "$baseline_file" "$catalogue_file" "$criticality_file"; do
    if [[ ! -f $input_file || ! -r $input_file ]]; then
        printf 'Missing readable input file: %s\n' "$input_file" >&2
        exit 1
    fi
done
printf 'Baseline: %s\nCatalogue: %s\nCriticality: %s\n' \
    "$baseline_file" "$catalogue_file" "$criticality_file"

work_dir=$(mktemp -d "$PWD/.attack-surface.XXXXXX")
trap 'rm -rf -- "$work_dir"' EXIT
python3 - "$baseline_file" "$catalogue_file" "$criticality_file" "$work_dir/attack_surface.json" <<'PY'
"""Local attack-surface analysis using a Task 0 baseline and explicit policy files."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import socket
import subprocess

SEVERITIES = ('critical', 'high', 'medium', 'low')
INSECURE_FUNCTIONS = {
    'telnet': 'telnet', 'ftp': 'ftp', 'snmpv1': 'snmpv1',
    'snmpv2c': 'snmpv2c', 'rlogin': 'rlogin',
    'nfs v2/v3': 'nfs_v2_v3', 'nfs_v2_v3': 'nfs_v2_v3',
    'nfsv2/v3': 'nfs_v2_v3', 'nfs_v2/v3': 'nfs_v2_v3',
    'nfs_v2': 'nfs_v2', 'nfs_v3': 'nfs_v3',
}


def local_query(arguments):
    """Run one bounded, read-only query without a shell or network service."""
    try:
        result = subprocess.run(
            arguments, capture_output=True, text=True, timeout=5,
            env=dict(os.environ, LC_ALL='C', SYSTEMD_PAGER='cat'),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return '', str(error)
    if result.returncode:
        return '', result.stderr.strip() or f'exit status {result.returncode}'
    return result.stdout, None


def owning_packages(binary, query=local_query):
    """Query the binary path, including original paths on merged-/usr hosts."""
    candidates = [binary]
    for legacy in ('/bin', '/sbin', '/lib', '/lib64'):
        modern = '/usr' + legacy
        if binary.startswith(modern + '/') and os.path.realpath(legacy) == modern:
            candidates.append(binary[len('/usr'):])
    last_error = None
    for candidate in candidates:
        output, error = query(['dpkg', '-S', candidate])
        if error:
            last_error = error
            continue
        packages = []
        for line in output.splitlines():
            owner, separator, path = line.rpartition(': ')
            if separator and path == candidate:
                packages.extend(owner.split(', '))
        if packages:
            return sorted(set(packages)), None
    return [], last_error or 'No package owns the binary path in the dpkg database'


def service_details(proc_dir, query=local_query):
    """Find the containing service in cgroups, then query its configured unit."""
    candidates = set()
    try:
        for line in (proc_dir / 'cgroup').read_text().splitlines():
            parts = line.split(':', 2)
            if len(parts) != 3:
                continue
            services = [part for part in parts[2].split('/') if part.endswith('.service')]
            if services:
                unit = services[-1]
                manager = next((part for part in services[:-1] if re.fullmatch(r'user@\d+\.service', part)), None)
                candidates.add((unit, manager))
    except OSError as error:
        return None, {}, str(error)
    if not candidates:
        return None, {}, None
    if len(candidates) != 1:
        return None, {}, 'Conflicting service memberships in the process cgroups'
    unit, manager = candidates.pop()
    arguments = ['systemctl']
    if manager:
        uid = manager.split('@', 1)[1].split('.', 1)[0]
        arguments += ['--user', f'--machine={uid}@.host']
    arguments += [
        'show', unit, '--no-pager', '--all',
        '--property=Id,LoadState,ActiveState,SubState,MainPID,FragmentPath,ExecStart,ControlGroup',
    ]
    output, error = query(arguments)
    if error:
        return unit, {}, error
    properties = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
    if properties.get('LoadState') != 'loaded' or not properties.get('Id'):
        return unit, properties, 'systemctl did not return a loaded service unit'
    return properties['Id'], properties, None


def resolve_owner(owner, proc_root=Path('/proc'), query=local_query):
    """Preserve baseline identity and explicitly report failed live enrichment."""
    result = {
        'name': owner['name'], 'pid': owner['pid'], 'fd': owner.get('fd'),
        'binary': None, 'binary_deleted': False, 'package': None, 'packages': [],
        'service_unit': None, 'service_properties': {}, 'enrichment_warnings': [],
    }
    warnings = result['enrichment_warnings']
    proc_dir = proc_root / str(owner['pid'])
    try:
        current_name = (proc_dir / 'comm').read_text().rstrip('\n')
        if current_name != owner['name']:
            warnings.append('PID now belongs to a different process; rerun Task 0')
            return result
        if owner.get('fd') is not None:
            descriptor = os.readlink(proc_dir / 'fd' / str(owner['fd']))
            if not descriptor.startswith('socket:['):
                warnings.append('Baseline file descriptor is no longer a socket; rerun Task 0')
                return result
        binary = os.readlink(proc_dir / 'exe')
    except OSError as error:
        warnings.append(f'Process enrichment unavailable: {error}')
        return result
    result['binary_deleted'] = binary.endswith(' (deleted)')
    result['binary'] = binary[:-10] if result['binary_deleted'] else binary
    packages, error = owning_packages(result['binary'], query)
    result['packages'] = packages
    result['package'] = packages[0] if packages else None
    if error:
        warnings.append(f'Package resolution unavailable: {error}')
    unit, properties, error = service_details(proc_dir, query)
    result['service_unit'] = unit
    result['service_properties'] = properties
    if error:
        warnings.append(f'Service resolution unavailable: {error}')
    return result


def exposure_flags(bind_addr, function):
    flags = []
    label = function.strip().lower()
    if bind_addr == '0.0.0.0' and label in ('database', 'rpc'):
        flags.extend(['bound_0.0.0.0', f'{label}_exposed'])
    if label in INSECURE_FUNCTIONS:
        flags.append('insecure_protocol_' + INSECURE_FUNCTIONS[label])
    return flags


def validate_baseline(baseline, current_hostname=None):
    if not isinstance(baseline, dict) or not isinstance(baseline.get('hostname'), str):
        raise ValueError('Baseline must contain a hostname string')
    if baseline['hostname'] != (current_hostname or socket.gethostname()):
        raise ValueError('Baseline belongs to a different host; run Task 0 on this endpoint')
    listeners = baseline.get('listening_sockets')
    if not isinstance(listeners, list):
        raise ValueError('Baseline listening_sockets must be an array')
    for entry in listeners:
        if not isinstance(entry, dict) or entry.get('protocol') not in ('tcp', 'udp'):
            raise ValueError('Every listener must have a tcp/udp protocol')
        if type(entry.get('local_port')) is not int or not 1 <= entry['local_port'] <= 65535:
            raise ValueError('Every listener must have an integer local_port in 1..65535')
        if not isinstance(entry.get('local_address'), str) or not entry['local_address']:
            raise ValueError('Every listener must have a nonempty local_address')
        if not isinstance(entry.get('processes'), list):
            raise ValueError('Every listener must retain its baseline processes array')
        for owner in entry['processes']:
            if not isinstance(owner, dict) or not isinstance(owner.get('name'), str):
                raise ValueError('Every baseline process must have a name')
            if type(owner.get('pid')) is not int or owner['pid'] <= 0:
                raise ValueError('Every baseline process must have a positive integer PID')
            if owner.get('fd') is not None and (type(owner['fd']) is not int or owner['fd'] < 0):
                raise ValueError('A baseline process fd must be a nonnegative integer')
    return listeners


def build_report(baseline, function_lookup, criticality_lookup, enricher=resolve_owner):
    """Keep one output record per baseline listener, including unresolved owners."""
    listeners = validate_baseline(baseline)
    sockets = []
    for entry in listeners:
        owners = [enricher(owner) for owner in entry['processes']]
        primary = next((owner for owner in owners if owner['binary']), owners[0] if owners else {})
        record = {
            'proto': entry['protocol'], 'port': entry['local_port'],
            'bind_addr': entry['local_address'], 'process': primary.get('name'),
            'pid': primary.get('pid'), 'binary': primary.get('binary'),
            'package': primary.get('package'), 'service_unit': primary.get('service_unit'),
            'owners': owners,
        }
        function = function_lookup(record)
        if not isinstance(function, str) or not function.strip():
            raise ValueError('Catalogue lookup must return a function label or unknown')
        criticality = criticality_lookup(record, function)
        if criticality not in SEVERITIES:
            raise ValueError(f'No valid supplied criticality for {record["proto"]}/{record["port"]}')
        record.update(function=function, criticality=criticality,
                      exposure_flags=exposure_flags(record['bind_addr'], function))
        sockets.append(record)
    summary = {
        'total_sockets': len(sockets),
        'flagged_sockets': sum(bool(item['exposure_flags']) for item in sockets),
        'flagged_by_severity': {
            severity: sum(bool(item['exposure_flags']) and item['criticality'] == severity for item in sockets)
            for severity in SEVERITIES
        },
        'unknown_functions': sum(item['function'].strip().lower() == 'unknown' for item in sockets),
        'sockets_with_enrichment_warnings': sum(
            not item['owners'] or any(owner['enrichment_warnings'] for owner in item['owners'])
            for item in sockets
        ),
    }
    return {
        'generated_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        'hostname': baseline['hostname'], 'sockets': sockets, 'summary': summary,
    }


def write_report(path, report):
    """Produce newline-terminated JSON; the Bash wrapper publishes atomically."""
    with Path(path).open('w', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')


def load_policies(catalogue, criticality):
    """Validate the observed ports/processes catalogue and function/level map."""
    if not isinstance(catalogue, dict) or not any(
        key in catalogue for key in ('ports', 'processes')
    ):
        raise ValueError('service_catalog.json must contain ports and/or processes maps')
    ports = catalogue.get('ports', {})
    processes = catalogue.get('processes', {})
    if not isinstance(ports, dict) or not isinstance(processes, dict):
        raise ValueError('Catalogue ports and processes must be JSON objects')
    for key, label in list(ports.items()) + list(processes.items()):
        if not key or not isinstance(label, str) or not label.strip():
            raise ValueError('Every catalogue entry must have a nonempty function label')
        if label != label.strip():
            raise ValueError('Catalogue function labels must not contain surrounding whitespace')
    if any(not key.isdecimal() or not 1 <= int(key) <= 65535 for key in ports):
        raise ValueError('Catalogue ports must be numeric string keys in 1..65535')
    if not isinstance(criticality, dict) or not criticality:
        raise ValueError('service_criticality.json must map functions to criticality labels')
    if any(level not in SEVERITIES for level in criticality.values()):
        raise ValueError('Criticality labels must be critical, high, medium or low')
    missing = (set(ports.values()) | set(processes.values()) | {'unknown'}) - criticality.keys()
    if missing:
        raise ValueError('Missing supplied criticality for: ' + ', '.join(sorted(missing)))
    return ports, processes, criticality


def catalogue_function(record, ports, processes):
    """Prefer named process evidence, then use the supplied port mapping."""
    matches = {
        owner['name']: processes[owner['name']]
        for owner in record['owners'] if owner['name'] in processes
    }
    labels = set(matches.values())
    if len(labels) > 1:
        record['function_basis'] = {'type': 'conflicting_process_labels', 'matches': matches}
        return 'unknown'
    if labels:
        record['function_basis'] = {'type': 'catalogue_process', 'matches': matches}
        return next(iter(labels))
    key = str(record['port'])
    record['function_basis'] = {
        'type': 'catalogue_port' if key in ports else 'unmapped', 'key': key,
    }
    return ports.get(key, 'unknown')


import sys

try:
    inputs = []
    for filename in sys.argv[1:4]:
        with open(filename, encoding='utf-8') as stream:
            inputs.append(json.load(stream))
    baseline, catalogue, criticality = inputs
    ports, processes, levels = load_policies(catalogue, criticality)
    report = build_report(
        baseline,
        lambda row: catalogue_function(row, ports, processes),
        lambda row, function: levels[function],
    )
    write_report(sys.argv[4], report)
except (OSError, ValueError, KeyError, TypeError) as error:
    print(f'Attack-surface analysis failed: {error}', file=sys.stderr)
    sys.exit(1)

summary = report['summary']
print(
    f"Classified {summary['total_sockets']} socket(s): "
    f"{summary['flagged_sockets']} flagged, "
    f"{summary['unknown_functions']} unknown function(s)."
)
if summary['sockets_with_enrichment_warnings']:
    print(
        f"Warning: {summary['sockets_with_enrichment_warnings']} socket(s) have "
        "incomplete owner enrichment; inspect owners[].enrichment_warnings. "
        "Refresh Task 0 first if a process or descriptor has changed.",
        file=sys.stderr,
    )
PY

mv -f -- "$work_dir/attack_surface.json" "$PWD/attack_surface.json"
printf 'Saved attack_surface.json\n'

