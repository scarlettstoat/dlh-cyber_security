#!/bin/bash
# Offline setup. Check the supplied assets first with --check-inputs.
set -euo pipefail
if ! command -v python3 >/dev/null 2>&1; then
    printf 'Missing prerequisite: python3\n' >&2
    exit 1
fi
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 - "$project_dir" "$@" <<'PY'
"""Use only local lab assets and cached distribution packages; never start an IDS."""
import argparse
from contextlib import contextmanager
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import uuid

RULES = Path('/var/lib/suricata/rules')
LOGS = Path('/var/log/suricata')
SMOKE = Path('/tmp/suricata-smoke')
BACKUPS = Path('/var/backups')
LOCK = Path('/run/meddefense-suricata-setup.lock')
POLICY_RC = Path('/usr/sbin/policy-rc.d')
SYSTEMD = Path('/run/systemd/system')
SUPPORT = Path('/etc/suricata')


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest() if hasattr(hashlib, 'file_digest') else hash_stream(stream)


def hash_stream(stream):
    value = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        value.update(block)
    return value.hexdigest()


def atomic_write(path, contents, mode=0o644):
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(contents if isinstance(contents, bytes) else contents.encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def execute(arguments, timeout=300):
    environment = dict(os.environ, DEBIAN_FRONTEND='noninteractive') if arguments[0] == 'apt-get' else None
    return subprocess.run(arguments, capture_output=True, text=True, errors='replace', timeout=timeout, env=environment)


def required(arguments, timeout=300):
    result = execute(arguments, timeout)
    if result.returncode:
        raise RuntimeError(shlex.join(arguments) + ': ' + result.stderr.strip())
    return result.stdout


def file_state(path):
    if path.is_symlink():
        raise ValueError('Refusing a symlink at a managed file: ' + str(path))
    if not path.exists():
        return {'path': str(path), 'exists': False}
    if not path.is_file():
        raise ValueError('Expected a regular file: ' + str(path))
    info = path.stat()
    return {'path': str(path), 'exists': True, 'sha256': digest(path),
            'size': info.st_size, 'mode': oct(info.st_mode & 0o7777), 'uid': info.st_uid, 'gid': info.st_gid}


def service_state():
    if not SYSTEMD.is_dir() or not shutil.which('systemctl'):
        return {'manager': 'unavailable'}
    result = execute(['systemctl', 'show', 'suricata.service',
                      '--property=LoadState,ActiveState,UnitFileState'])
    if result.returncode:
        raise RuntimeError('Cannot inspect suricata.service: ' + result.stderr.strip())
    return {'manager': 'systemd', **dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)}


def packages_state():
    state = {}
    for package in ('suricata', 'jq'):
        binary = shutil.which(package)
        item = {'binary': binary, 'package_status': None}
        if shutil.which('dpkg-query'):
            result = execute(['dpkg-query', '-W', '-f=${db:Status-Status}\t${Version}\n', package])
            item['package_status'] = result.stdout.strip() if result.returncode == 0 else 'not installed'
        state[package] = item
    return state


def discover_inputs(lab):
    source = lab / 'suricata' / 'rules'
    capture = lab / 'PCAPs' / 'smoke.pcap'
    if not source.is_dir() or not capture.is_file():
        raise FileNotFoundError('The supplied lab assets are required: ' + str(source) +
                                ' and ' + str(capture) + '. Obtain the course bundle; no replacement feed/PCAP is downloaded.')
    files = []
    for path in sorted(source.rglob('*')):
        if path.is_symlink():
            raise ValueError('The supplied rules directory must contain regular files, not symlinks: ' + str(path))
        if path.is_file():
            relative = path.relative_to(source).as_posix()
            if not re.fullmatch(r'[A-Za-z0-9_.\-/]+', relative):
                raise ValueError('Unsupported filename in the provided ruleset: ' + relative)
            files.append((relative, path))
    rule_files = [name for name, _ in files if name.lower().endswith('.rules')]
    if not rule_files:
        raise ValueError('No provided .rules files were found in ' + str(source))
    custom = RULES / 'meddefense.rules'
    for name, path in files:
        if name == 'meddefense.rules' and custom.exists() and digest(path) != digest(custom):
            raise ValueError('The provided meddefense.rules conflicts with existing custom rules; custom rules were preserved.')
    return source, capture, files, list(dict.fromkeys(rule_files + ['meddefense.rules']))


def render_config(rule_files, classification, reference):
    # -r selects offline input. The YAML flag alone cannot select a capture mode.
    content = '''%YAML 1.1
---
# MedDefense: run with suricata -c ./suricata.yaml -r <provided.pcap> -l <output-dir>.
# This file is local to the project; it is not the system service configuration.
vars:
  address-groups:
    HOME_NET: "[10.10.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    DC_SERVERS: "$HOME_NET"
    TELNET_SERVERS: "$HOME_NET"
    FTP_SERVERS: "$HOME_NET"
    DNP3_SERVER: "$HOME_NET"
    DNP3_CLIENT: "$HOME_NET"
    MODBUS_SERVER: "$HOME_NET"
    MODBUS_CLIENT: "$HOME_NET"
    ENIP_SERVER: "$HOME_NET"
    ENIP_CLIENT: "$HOME_NET"
    AIM_SERVERS: "$EXTERNAL_NET"
  port-groups:
    HTTP_PORTS: "[80,81,311,591,593,800,801,808,880,901,903,981,1010,1311,1830,2301,2381,2809,3128,3702,4343,4848,5250,7001,7144,7145,7510,7777,7779,8000,8008,8014,8028,8080,8088,8090,8118,8123,8180,8181,8243,8280,8300,8333,8530,8531,8800,8888,8899,8983,9000,9060,9080,9090,9443,9999,10000,11371,19227,34443,34445,50002,55555]"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    ENIP_PORTS: 44818
    FTP_PORTS: 21
    FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"
    GENEVE_PORTS: 6081
    VXLAN_PORTS: 4789
    TEREDO_PORTS: 3544
    SIP_PORTS: "[5060,5061]"
runmode: single
default-rule-path: __RULES__
rule-files:
__RULE_FILES__
default-log-dir: __LOGS__
classification-file: __CLASSIFICATION__
reference-config-file: __REFERENCE__
pcap-file:
  enabled: yes
  checksum-checks: auto
  delete-when-done: no
outputs:
  - eve-log:
      enabled: yes
      type: json
      filetype: regular
      filename: eve.json
      threaded: false
      types:
        - alert
        - http
        - dns
        - tls
        - files:  # Suricata's logger name; emitted records have event_type: fileinfo.
            force-magic: no
        - flow
        - stats
app-layer:
  protocols:
    http:
      enabled: yes
      libhtp:
        default-config:
          personality: IDS
          request-body-limit: 100kb
          response-body-limit: 100kb
    dns:
      tcp:
        enabled: yes
      udp:
        enabled: yes
    tls:
      enabled: yes
logging:
  default-log-level: info
  outputs:
    - console:
        enabled: yes
    - file:
        enabled: yes
        filename: suricata.log
'''
    replacements = {'__RULES__': json.dumps(str(RULES)), '__LOGS__': json.dumps(str(LOGS)),
                    '__CLASSIFICATION__': json.dumps(str(classification)), '__REFERENCE__': json.dumps(str(reference)),
                    '__RULE_FILES__': '\n'.join('  - ' + json.dumps(name) for name in rule_files)}
    for key, value in replacements.items():
        content = content.replace(key, value)
    return content


@contextmanager
def prevent_package_start():
    # Delegate other services to the original policy, and restore it even on failure.
    previous = POLICY_RC.with_name('.meddefense-policy-rc.d-' + uuid.uuid4().hex)
    had_policy = os.path.lexists(POLICY_RC)
    guard_installed = False
    try:
        if had_policy:
            POLICY_RC.rename(previous)
        guard = '#!/bin/bash\nfor argument in "$@"; do\n' + \
                '    case "$argument" in suricata|suricata.service|*/suricata) exit 101 ;; esac\ndone\n'
        guard += 'exec ' + shlex.quote(str(previous)) + ' "$@"\n' if had_policy else 'exit 0\n'
        atomic_write(POLICY_RC, guard, 0o755)
        guard_installed = True
        yield
    finally:
        if guard_installed:
            POLICY_RC.unlink(missing_ok=True)
        if had_policy and os.path.lexists(previous):
            previous.rename(POLICY_RC)


def keep_service_off(before):
    if before['manager'] == 'systemd':
        if before.get('UnitFileState') != 'masked' or before.get('ActiveState') not in ('inactive', 'failed'):
            required(['systemctl', 'mask', '--now', 'suricata.service'])
    elif (Path('/etc/init.d') / 'suricata').exists():
        required(['service', 'suricata', 'stop'])
        required(['update-rc.d', 'suricata', 'disable'])


def parse_rule_summary(output):
    pattern = r'(\d+) rule files? processed[.:]\s*(\d+) rules? successfully loaded,\s*(\d+) rules? failed(?:,\s*(\d+) rules? skipped)?'
    summaries = re.findall(pattern, output)
    if len(summaries) != 1:
        raise RuntimeError('Cannot read one unambiguous engine rule-load summary; inspect suricata-config-test.log.')
    files, loaded, failed, skipped = (int(value or 0) for value in summaries[0])
    if failed or skipped or loaded == 0:
        raise RuntimeError(f'Incomplete rule load: {loaded} loaded, {failed} failed, {skipped} skipped.')
    return files, loaded


def logged_command(arguments, path, timeout=300):
    try:
        result = execute(arguments, timeout)
    except subprocess.TimeoutExpired as error:
        output = (error.stdout or b'')
        output = output.decode(errors='replace') if isinstance(output, bytes) else output
        atomic_write(path, output + '\nCommand timed out.\n')
        return subprocess.CompletedProcess(arguments, 124, output, 'Command timed out')
    atomic_write(path, (result.stdout + result.stderr).rstrip() + '\n')
    return result


def main(project, arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab-dir', type=Path, default=Path('/home/analyst/MedDefense_Lab'))
    parser.add_argument('--check-inputs', action='store_true', help='Check local assets/dependencies without system changes')
    args = parser.parse_args(arguments)
    project = Path(project).resolve()
    report_path = project / 'setup_verification.json'
    report = {'generated_at': stamp(), 'status': 'started', 'installed_version': None,
              'rule_files_loaded': None, 'rule_count': None, 'config_test_exit': None,
              'smoke_pcap': str(args.lab_dir.resolve() / 'PCAPs' / 'smoke.pcap'), 'smoke_alerts': None,
              'offline_only': True, 'package_install_mode': 'APT --no-download (cached distribution packages)'}
    undo, lock, backup = [], None, None

    def save():
        atomic_write(report_path, json.dumps(report, indent=2) + '\n')

    def update_file(target, content, backup_name):
        contents = content if isinstance(content, bytes) else content.encode()
        old = file_state(target)
        if old['exists'] and digest(target) == hashlib.sha256(contents).hexdigest():
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        previous = backup / backup_name if old['exists'] else None
        if previous:
            previous.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, previous)
        undo.append((target, previous, old))
        atomic_write(target, contents)

    try:
        source, capture, files, rule_files = discover_inputs(args.lab_dir.resolve())
        report['inputs'] = {'rules_source': str(source), 'source_file_count': len(files),
                            'provided_rule_file_count': sum(name.lower().endswith('.rules') for name, _ in files),
                            'smoke_sha256': digest(capture)}
        report['packages_before'] = packages_state()
        if args.check_inputs:
            report['status'] = 'inputs_checked'
            save()
            missing = [name for name, item in report['packages_before'].items() if not item['binary']]
            print(f'Found {len(files)} provided file(s) and {capture}.')
            print('Missing commands: ' + (', '.join(missing) if missing else 'none'))
            print('Saved setup_verification.json. Setup and replay have not run yet.')
            return 0
        if os.geteuid() != 0:
            raise RuntimeError('Run setup with sudo; --check-inputs does not need root.')
        lock = LOCK.open('a')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if RULES.is_symlink() or (RULES.exists() and not RULES.is_dir()) or SMOKE.is_symlink():
            raise RuntimeError('Rules/smoke locations must be real directories, not symlinks.')
        before_files = [file_state(RULES / name) for name, _ in files]
        if 'meddefense.rules' not in [name for name, _ in files]:
            before_files.append(file_state(RULES / 'meddefense.rules'))
        report['before'] = {'service': service_state(), 'rule_files': before_files,
                            'project_yaml': file_state(project / 'suricata.yaml'),
                            'smoke_directory_exists': SMOKE.exists()}
        backup = BACKUPS / ('meddefense-suricata-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
        report['backup_directory'] = str(backup)
        report['status'] = 'measured'
        save()
        backup.mkdir(mode=0o700, parents=True)
        keep_service_off(report['before']['service'])
        missing = [name for name, item in report['packages_before'].items() if not item['binary']]
        if missing:
            if not shutil.which('apt-get'):
                raise RuntimeError('Missing commands require a Debian/Ubuntu/Kali distribution package cache.')
            with prevent_package_start():
                installation = logged_command(
                    ['apt-get', '--no-download', '--no-remove', '--yes', '--no-install-recommends', 'install', *missing],
                    project / 'suricata-package-install.log')
            report['package_install_exit'] = installation.returncode
            save()
            if installation.returncode:
                raise RuntimeError('Offline package installation failed. Prepare suricata/jq and dependencies in the APT cache, then rerun. See suricata-package-install.log.')
        if not shutil.which('suricata') or not shutil.which('jq'):
            raise RuntimeError('suricata and jq must both be available after installation.')
        # Package installation may create a SysV unit; keep it disabled as well.
        keep_service_off(service_state())
        banner = required(['suricata', '-V']).strip()
        version = re.search(r'\bversion\s+(\S+)', banner, re.IGNORECASE)
        if not version:
            raise RuntimeError('Cannot extract the installed Suricata version: ' + banner)
        report['installed_version'] = version.group(1)
        report['version_banner'] = banner
        RULES.mkdir(parents=True, exist_ok=True)
        for name, path in files:
            update_file(RULES / name, path.read_bytes(), 'rules/' + name)
        custom = RULES / 'meddefense.rules'
        if not custom.exists():
            update_file(custom, '# MedDefense custom rules are added in Task 10.\n', 'rules/meddefense.rules')
        verified = [name for name, path in files if (RULES / name).is_file() and digest(path) == digest(RULES / name)]
        report['copy_verification'] = {'source_file_count': len(files), 'verified_file_count': len(verified),
                                       'configured_rule_files': rule_files,
                                       'custom_rules_preserved': any(item['path'] == str(custom) and item['exists'] for item in before_files)}
        if len(verified) != len(files):
            raise RuntimeError('The copied ruleset does not match the supplied files.')
        report['rule_files'] = rule_files
        classification = RULES / 'classification.config' if (RULES / 'classification.config').is_file() else SUPPORT / 'classification.config'
        reference = RULES / 'reference.config' if (RULES / 'reference.config').is_file() else SUPPORT / 'reference.config'
        if not classification.is_file() or not reference.is_file():
            raise RuntimeError('Suricata classification.config/reference.config must be supplied by the lab or distribution package.')
        configuration = render_config(rule_files, classification, reference)
        update_file(project / 'suricata.yaml', configuration, 'suricata-before.yaml')
        LOGS.mkdir(parents=True, exist_ok=True)
        report['status'] = 'configured'
        save()
        config_command = ['suricata', '-T', '-c', './suricata.yaml', '-v', '--init-errors-fatal']
        report['config_test_command'] = config_command
        # Relative config path is intentionally evaluated in the project directory.
        old_directory = Path.cwd()
        os.chdir(project)
        try:
            checked = logged_command(config_command, project / 'suricata-config-test.log')
            report['config_test_exit'] = checked.returncode
            save()
            if checked.returncode:
                raise RuntimeError('Suricata rejected the configuration/rules; inspect suricata-config-test.log.')
            report['rule_files_loaded'], report['rule_count'] = parse_rule_summary(checked.stdout + checked.stderr)
            if report['rule_files_loaded'] != len(rule_files):
                raise RuntimeError('The engine processed a different file count from the configured ruleset.')
            if SMOKE.exists():
                if not SMOKE.is_dir():
                    raise RuntimeError('The smoke output path is not a directory.')
                archive = SMOKE.with_name(SMOKE.name + '.previous-' + uuid.uuid4().hex)
                report['previous_smoke_archive'] = str(archive)
                save()
                SMOKE.rename(archive)
            SMOKE.mkdir(mode=0o700)
            smoke_command = ['suricata', '-c', './suricata.yaml', '-r', str(capture), '-l', str(SMOKE), '--init-errors-fatal']
            report['smoke_command'] = smoke_command
            save()
            replay = logged_command(smoke_command, project / 'suricata-smoke.log')
            report['smoke_exit'] = replay.returncode
            if replay.returncode:
                raise RuntimeError('Offline replay failed; inspect suricata-smoke.log.')
            eve = SMOKE / 'eve.json'
            if not eve.is_file():
                raise RuntimeError('Offline replay did not create a fresh eve.json.')
            query = 'reduce inputs as $event (0; if ($event | type) != "object" then error("EVE record is not an object") elif $event.event_type == "alert" then . + 1 else . end)'
            report['smoke_alerts'] = int(required(['jq', '-n', query, str(eve)]).strip())
            report['smoke_eve'] = str(eve)
            report['smoke_eve_sha256'] = digest(eve)
            report['pcap_unchanged'] = report['inputs']['smoke_sha256'] == digest(capture)
            save()
            if not report['pcap_unchanged']:
                raise RuntimeError('The provided smoke capture changed during replay.')
            if report['smoke_alerts'] < 1:
                raise RuntimeError('No alerts matched the supplied smoke capture; inspect the provided rules and suricata-smoke.log.')
        finally:
            os.chdir(old_directory)
        report['service_after'] = service_state()
        if report['service_after'].get('ActiveState') in ('active', 'activating', 'reloading'):
            raise RuntimeError('suricata.service is unexpectedly active.')
        report.update(status='passed', completed_at=stamp())
        save()
        print(f"Suricata {report['installed_version']}: verified {len(verified)} provided file(s), {report['rule_count']} loaded rules.")
        print(f"Configuration test passed; offline smoke replay produced {report['smoke_alerts']} alert(s).")
        print('Saved suricata.yaml and setup_verification.json. Suricata is used offline only.')
        return 0
    except BaseException as error:
        report.update(status='failed', error=str(error))
        recovery_errors = []
        for target, previous, old in reversed(undo):
            try:
                if previous:
                    shutil.copy2(previous, target)
                    os.chown(target, old['uid'], old['gid'])
                else:
                    target.unlink(missing_ok=True)
            except OSError as recovery_error:
                recovery_errors.append(str(recovery_error))
        report['file_changes_restored'] = bool(undo) and not recovery_errors
        if recovery_errors:
            report['recovery_errors'] = recovery_errors
        save()
        print('Suricata setup stopped: ' + str(error), file=sys.stderr)
        print('Details saved in setup_verification.json.', file=sys.stderr)
        return 1
    finally:
        if lock:
            lock.close()


if __name__ == '__main__':
    def interrupted(number, frame):
        raise RuntimeError('Interrupted by signal ' + str(number))
    for caught in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(caught, interrupted)
    sys.exit(main(sys.argv[1], sys.argv[2:]))
PY

