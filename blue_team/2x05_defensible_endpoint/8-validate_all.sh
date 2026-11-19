#!/bin/bash
# Evaluate the Task 2 contract and publish an end-to-end validation report.
set -euo pipefail
export LC_ALL=C
root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
exec python3 - "$root" "$@" <<'PYTHON'
import argparse
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile

WINDOWS_HOSTS = {"hawthorne-adm-01", "hawthorne-adm-0"}
BASH = ("bash", "--noprofile", "--norc", "-o", "pipefail")


def run(root, *argv):
    env = os.environ.copy()
    env.pop("BASH_ENV", None)
    env.pop("ENV", None)
    return subprocess.run(argv, cwd=root, env=env, stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=30)


def publish(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8",
                                     dir=path.parent, delete=False) as stream:
        temp = Path(stream.name)
        try:
            stream.write(text)
            stream.close()
            temp.replace(path)
        finally:
            temp.unlink(missing_ok=True)


def save_report(path, data):
    publish(path, json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def command_key(control):
    return control["id"], control["platform"], control["check_target"]


def load_contract(root, target):
    original = target.read_bytes()
    # Validate the exact snapshot and use the repository generator to identify
    # reviewed command checks. Editing the generated JSON alone grants no execution.
    with tempfile.TemporaryDirectory(prefix="capstone-contract-") as directory:
        work = Path(directory)
        source = work / "2-target_state.sh"
        shutil.copyfile(root / source.name, source)
        staged = work / "capstone/target_state.json"
        staged.parent.mkdir()
        staged.write_bytes(original)
        for flag in ("--validate", "--force"):
            result = run(work, *BASH, str(source), flag)
            if result.returncode:
                raise ValueError(result.stderr.strip() or f"Task 2 {flag} failed.")
        reviewed = json.loads(staged.read_text(encoding="utf-8"))["controls"]
    approved = {command_key(row) for row in reviewed if row["check_type"] == "command_exit_zero"}
    return json.loads(original)["controls"], sha256(original).hexdigest(), approved


def collect_windows_script(path, controls, approved, digest):
    checks = [
        {"id": row["id"], "command": row["check_target"]}
        for row in controls if row["platform"] == "windows"
        and row["check_type"] == "command_exit_zero" and command_key(row) in approved
    ]
    template = r"""# Run this collector in Windows PowerShell on the Hawthorne Windows endpoint.
param([string]$OutputPath = (Join-Path $PSScriptRoot 'windows_validation_evidence.json'))
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess) {
    throw 'Run in 64-bit Windows PowerShell on hawthorne-adm-01.'
}
$computer = ([Net.Dns]::GetHostName() -split '\.')[0]
if ($computer -notin @('hawthorne-adm-01', 'hawthorne-adm-0')) {
    throw 'Expected the Hawthorne Windows endpoint.'
}
$checks = ConvertFrom-Json @'
__CHECKS__
'@
$engine = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$before = @'
$ErrorActionPreference = 'Stop'
try {
'@
$after = @'
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 125
}
'@
$rows = @(
    foreach ($check in $checks) {
        $program = @($before, $check.command, $after) -join [Environment]::NewLine
        $ErrorActionPreference = 'Continue'
        try {
            $lines = @(& $engine -NoLogo -NoProfile -NonInteractive -Command $program 2>&1)
            $code = $LASTEXITCODE
        }
        finally { $ErrorActionPreference = 'Stop' }
        [ordered]@{
            id = $check.id
            command = $check.command
            exit_code = $code
            output = ($lines | Select-Object -Last 12 | Out-String).Trim()
        }
    }
)
$proof = [ordered]@{
    schema_version = 'capstone-windows-checks-v1'
    hostname = $computer
    checked_at = [DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffzzz',
                                                 [Globalization.CultureInfo]::InvariantCulture)
    target_sha256 = '__DIGEST__'
    results = $rows
}
$resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$temp = $resolved + '.' + [Guid]::NewGuid().ToString('N')
try {
    [IO.File]::WriteAllText($temp, (($proof | ConvertTo-Json -Depth 6) + [Environment]::NewLine),
                           [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temp -Destination $resolved -Force
}
finally { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
Write-Output "Windows evidence saved to $resolved"
"""
    publish(path, template.replace("__CHECKS__", json.dumps(checks, indent=2))
            .replace("__DIGEST__", digest))


def load_windows_evidence(path, digest):
    proof = json.loads(path.read_text(encoding="utf-8-sig"))
    if (proof["schema_version"] != "capstone-windows-checks-v1"
            or proof["target_sha256"] != digest
            or proof["hostname"].lower() not in WINDOWS_HOSTS):
        raise ValueError("Windows evidence does not match the Hawthorne host and target snapshot.")
    timestamp = datetime.fromisoformat(proof["checked_at"].replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        raise ValueError("Windows evidence time has no timezone.")
    rows = proof["results"]
    if (not isinstance(rows, list)
            or len({row["id"] for row in rows}) != len(rows)):
        raise ValueError("Invalid Windows evidence rows.")
    return proof


def json_check(root, path, selector, expected, kind, evidence):
    numeric = kind == "json_field_gte"
    compare = """if type != "number" or ($expected | type) != "number"
                 then error("Numeric comparison requires two numbers")
                 else . >= $expected end""" if numeric else ". == $expected"
    query = (
        'if length != 1 then error("Expected one JSON document") '
        f'else [.[0] | ({selector})] end | '
        'if length != 1 then error("Expected one selected value") else .[0] end | '
        '{actual: ., passed: (' + compare + ')}'
    )
    result = run(root, "jq", "-cs", "--argjson", "expected", json.dumps(expected), query, str(path))
    evidence["exit_code"] = result.returncode
    if result.returncode:
        raise ValueError(result.stderr.strip() or "jq could not evaluate the selector.")
    answer = json.loads(result.stdout)
    evidence["actual_value"] = answer["actual"]
    return "pass" if answer["passed"] is True else "fail"


def command_check(root, control, evidence, approved, windows):
    command = control["check_target"]
    evidence["command"] = command
    if command_key(control) not in approved:
        raise ValueError("This command is absent from the reviewed Task 2 generator.")

    if control["platform"] == "windows":
        proof_path, proof, proof_error = windows
        evidence["path"] = str(proof_path)
        if proof_error:
            raise ValueError(proof_error)
        row = next((row for row in proof["results"] if row["id"] == control["id"]), None)
        if row is None or row["command"] != command or type(row["exit_code"]) is not int:
            raise ValueError("Matching Windows command evidence is missing or invalid.")
        evidence.update(hostname=proof["hostname"], checked_at=proof["checked_at"],
                        output=row.get("output", ""))
        code = row["exit_code"]
    else:
        result = run(root, *BASH, "-c", command)
        evidence.update(stdout=result.stdout[-2000:], stderr=result.stderr[-2000:])
        code = result.returncode
    evidence["exit_code"] = code
    if code < 0 or code >= 125:
        raise ValueError(f"Command could not complete (exit {code}).")
    return "pass" if code == 0 else "fail"


def evaluate(root, control, approved, windows):
    kind, target = control["check_type"], control["check_target"]
    expected = control["expected_value"]
    evidence = {"target": target}
    try:
        if kind == "command_exit_zero":
            verdict = command_check(root, control, evidence, approved, windows)
        elif kind in {"json_field_equals", "json_field_gte"}:
            name, separator, selector = target.partition(":")
            path = root / name
            evidence.update(path=str(path), selector=selector)
            if not separator or not name or not selector.strip():
                raise ValueError("Expected a JSON path followed by a jq selector.")
            verdict = json_check(root, path, selector, expected, kind, evidence)
        elif kind == "file_exists":
            path = root / target
            evidence["path"] = str(path)
            try:
                path.stat()
                exists = True
            except (FileNotFoundError, NotADirectoryError):
                exists = False
            evidence["exists"] = exists
            verdict = "pass" if exists else "fail"
        elif kind == "grep_match":
            path = root / target
            evidence.update(path=str(path), pattern=expected)
            result = run(root, "grep", "-E", "-n", "-m", "1", "-e", expected, "--", str(path))
            evidence["exit_code"] = result.returncode
            if result.returncode not in {0, 1}:
                raise ValueError(result.stderr.strip() or "grep could not inspect the file.")
            evidence["match"] = result.stdout.rstrip("\n") if result.returncode == 0 else None
            verdict = "pass" if result.returncode == 0 else "fail"
        else:
            raise ValueError(f"Unsupported control type: {kind}")
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        evidence["error"] = str(error)
        verdict = "error"
    return {**control, "verdict": verdict, "evidence": evidence}


def totals(rows):
    counts = Counter(row["verdict"] for row in rows)
    return dict(total_controls=len(rows), pass_count=counts["pass"],
                fail_count=counts["fail"], error_count=counts["error"],
                pass_percentage=round(counts["pass"] * 100 / len(rows), 2) if rows else 0.0)


def print_table(families, total):
    print(f'{"Family":<15} {"Total":>5} {"Pass":>5} {"Fail":>5} {"Error":>5} {"Pass %":>8}')
    for name, group in (*families.items(), ("TOTAL", total)):
        print(f'{name:<15} {group["total_controls"]:>5} {group["pass_count"]:>5} '
              f'{group["fail_count"]:>5} {group["error_count"]:>5} {group["pass_percentage"]:>7.2f}%')


def main():
    root = Path(sys.argv[1])
    parser = argparse.ArgumentParser(description="Validate every control in capstone/target_state.json.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--emit-windows-checks", action="store_true",
                      help="Write the PowerShell collector for Windows command evidence.")
    mode.add_argument("--windows-evidence", type=Path,
                      default=root / "capstone/windows_validation_evidence.json")
    args = parser.parse_args(sys.argv[2:])

    target = root / "capstone/target_state.json"
    output = root / "capstone/validation_report.json"
    report = {"schema_version": "capstone-validation-v1",
              "timestamp": datetime.now(timezone.utc).isoformat(), "hostname": socket.gethostname(),
              "target_path": str(target), "ready": False}
    try:
        controls, digest, approved = load_contract(root, target)
        report["target_sha256"] = digest
        if args.emit_windows_checks:
            collector = root / "capstone/8-windows_validation.ps1"
            collect_windows_script(collector, controls, approved, digest)
            print(collector)
            return 0

        proof, proof_error = None, None
        if any(row["platform"] == "windows" and row["check_type"] == "command_exit_zero"
               for row in controls):
            try:
                proof = load_windows_evidence(args.windows_evidence, digest)
            except FileNotFoundError:
                proof_error = "Windows evidence is missing. Use --emit-windows-checks to generate the collector."
            except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
                proof_error = str(error)

        rows = [evaluate(root, control, approved, (args.windows_evidence, proof, proof_error))
                for control in controls]
        total = totals(rows)
        families = {name: totals([row for row in rows if row["family"] == name])
                    for name in sorted({row["family"] for row in rows})}
        ready = total["fail_count"] == 0 and total["error_count"] == 0
        report.update(total, ready=ready, families=families, results=rows)
        save_report(output, report)
        print_table(families, total)
        print(f"\nValidation report: {output}", flush=True)
        for row in rows:
            if row["verdict"] != "pass":
                evidence = row["evidence"]
                source = evidence.get("path") or " ".join(evidence["target"].split())
                print(f'{row["id"]} {row["verdict"]}  {source}', file=sys.stderr)
        return 0 if ready else 1
    except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired) as error:
        if not args.emit_windows_checks:
            report.update(totals([]), ready=False, error_count=1,
                          input_error=str(error), families={}, results=[])
            try:
                save_report(output, report)
            except OSError as write_error:
                print(f"Could not save {output}. {write_error}", file=sys.stderr)
        print(f"Validation could not run. {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
PYTHON
