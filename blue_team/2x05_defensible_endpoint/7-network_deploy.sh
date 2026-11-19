#!/bin/bash
# Deploy and validate the Hawthorne network controls and save the evidence.
set -euo pipefail
export LC_ALL=C

for tool in bash dirname hostname jq python3 nft ip suricata dnsmasq dig systemctl; do
    command -v "$tool" >/dev/null 2>&1 || { printf 'Missing command: %s\n' "$tool" >&2; exit 2; }
done
host=$(hostname -s)
if [[ $host != hawthorne-app-01 ]] || (( EUID != 0 )); then
    printf 'Run with sudo on hawthorne-app-01. Current host: %s\n' "$host" >&2
    exit 2
fi
root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
bash "$root/2-target_state.sh" --validate
export CAPSTONE_ARTIFACTS_DIR="$root/capstone/network/"

exec python3 - "$root" "$host" "$@" <<'PYTHON'
import argparse
from collections import Counter
from datetime import datetime, timezone
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

LAB = Path("/home/analyst/MedDefense_Lab/capstone")
DNS_FRAGMENT = Path("/etc/dnsmasq.d/meddefense-blocklist.conf")


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def run(work, *command, check=True):
    env = dict(os.environ, CAPSTONE_ARTIFACTS_DIR=str(work) + "/")
    result = subprocess.run(command, cwd=work, env=env,
                            capture_output=True, text=True, timeout=600)
    with (work / "network_deploy.log").open("a", encoding="utf-8") as log:
        log.write(f"\n{command!r} -> {result.returncode}\n")
        log.write(result.stdout + result.stderr)
    if check and result.returncode:
        raise RuntimeError(f"{Path(command[0]).name} exited {result.returncode}. See network_deploy.log.")
    return result


def validate_firewall(work, legacy):
    result = run(work, "bash", str(legacy / "4-nftables_config.sh"),
                 "--apply", "--policy", str(work / "segmentation_rules.json"), check=False)
    path = work / "nftables_apply_log.json"
    report = read_json(path) if path.is_file() else {}
    checks = {
        "apply": result.returncode == 0 and report.get("applied") is True,
        "preflight": report.get("preflight", {}).get("errors") == [],
        "syntax": report.get("validation", {}).get("exit_code") == 0,
        "rollback_syntax": report.get("rollback", {}).get("validation_exit_code") == 0,
        "live_table": report.get("verification", {}).get("passed") is True,
    }
    passed = all(checks.values())
    write_json(work / "firewall_validation.json", {
        "passed": passed, "checks": checks, "pipeline_exit_code": result.returncode,
        "ruleset": "capstone/network/nftables.conf",
        "details": "capstone/network/nftables_apply_log.json" if path.is_file() else None,
    })
    if not passed:
        raise RuntimeError("Firewall validation failed. See firewall_validation.json.")


def prepare_suricata(work, legacy, policy):
    custom = work / "meddefense_custom.rules"
    supplied = next((path for path in (
        LAB / "meddefense_custom.rules", LAB / "meddefense.rules",
        LAB / "suricata/rules/meddefense_custom.rules",
    ) if path.is_file()), None)
    shutil.copyfile(supplied or legacy / "meddefense.rules", custom)

    active_lines = [line for line in custom.read_text(encoding="utf-8").splitlines()
                    if line.strip() and not line.lstrip().startswith("#")]
    ids = re.findall(r"\bsid:\s*(\d+)\s*;", "\n".join(active_lines))
    sids = {int(sid) for sid in ids}
    if len(sids) < 6 or len(sids) != len(ids):
        raise ValueError("Expected at least six distinct custom rule SIDs.")

    config = (legacy / "suricata.yaml").read_text(encoding="utf-8")
    if supplied:
        zones = [str(ipaddress.ip_network(zone["cidr"])) for zone in policy["zones"]]
        home_net = json.dumps("[" + ",".join(zones) + "]")
        config = re.sub(r"(?m)^    HOME_NET: .*", f"    HOME_NET: {home_net}", config, count=1)

    rule_dirs = (LAB / "suricata/rules", LAB.parent / "suricata/rules", Path("/var/lib/suricata/rules"))
    base_rules = []
    for directory in rule_dirs:
        base_rules = sorted(path.resolve() for path in directory.rglob("*.rules")
                            if path.is_file() and path.name not in {"meddefense.rules", custom.name})
        if base_rules:
            break
    supported_dirs = (*rule_dirs, Path("/etc/suricata"), Path("/usr/share/suricata"))
    for setting, filename in (("classification-file", "classification.config"),
                              ("reference-config-file", "reference.config")):
        support = next((directory / filename for directory in supported_dirs
                        if (directory / filename).is_file()), None)
        if support is None:
            raise FileNotFoundError(f"Missing Suricata support file: {filename}")
        config = re.sub(rf"(?m)^{setting}: .*", f"{setting}: {json.dumps(str(support))}", config, count=1)
    rule_files = "rule-files:\n" + "".join(f"  - {json.dumps(str(path))}\n" for path in base_rules)
    if not base_rules:
        rule_files = "rule-files: []\n"
    config, replaces = re.subn(r"(?m)^rule-files:\n(?:  - [^\n]+\n)+", lambda _: rule_files, config, count=1)
    if replaces != 1:
        raise ValueError("The previous Suricata configuration has an unsupported rule-files layout.")
    (work / "suricata.yaml").write_text(config, encoding="utf-8")
    return custom, sids, "-s" if base_rules else "-S"


def suricata_command(custom, rule_option):
    return ("suricata", "-c", "./suricata.yaml", "--init-errors-fatal", rule_option, str(custom))


def capture_alerts(work, command, pcap):
    with tempfile.TemporaryDirectory(prefix="eve-", dir=work) as logs:
        run(work, *command, "--set", "pcap-file.delete-when-done=no",
            "-r", str(pcap), "-l", logs)
        with (Path(logs) / "eve.json").open(encoding="utf-8") as events:
            for line in events:
                if line.strip():
                    event = json.loads(line)
                    if event.get("event_type") == "alert":
                        yield event


def replay(work, captures, custom, rule_option):
    command = suricata_command(custom, rule_option)
    run(work, *command, "-T", "-l", str(work))
    rows, alerts = [], []
    for name, pcap in captures.items():
        print(f"Replaying {name}", flush=True)
        before = len(alerts)
        result = {"pcap": name, "passed": False}
        try:
            for event in capture_alerts(work, command, pcap):
                detail = event["alert"]
                row = {key: event.get(key) for key in
                       ("timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "proto")}
                row.update(pcap=name, signature_id=int(detail["signature_id"]),
                           signature=detail["signature"], alert_category=detail.get("category"),
                           severity=detail.get("severity"))
                alerts.append(row)
            result["passed"] = True
        except (OSError, ValueError, KeyError, RuntimeError, subprocess.TimeoutExpired) as error:
            result["error"] = str(error)
        result["alert_count"] = len(alerts) - before
        rows.append(result)
    write_json(work / "suricata_alerts.json", {
        "capture_count": len(rows), "total_alerts": len(alerts), "captures": rows, "alerts": alerts,
    })
    if not all(row["passed"] for row in rows):
        raise RuntimeError("One or more PCAP replays failed. See suricata_alerts.json.")


def validate_custom(work, legacy, pcap_dir, captures, custom, sids, manifest):
    if manifest:
        if not manifest.is_file():
            raise FileNotFoundError(manifest)
        cases = read_json(manifest)
        if isinstance(cases, dict):
            cases = cases.get("cases")
        if not isinstance(cases, list) or not cases:
            raise ValueError("Expected a labelled PCAP case list.")
        command = suricata_command(custom, "-S")
        hits = {}
        capture_names = {path: name for name, path in captures.items()}
        rows = []
        for case in cases:
            sid, expected = case["sid"], case.get("expected", "fire")
            if type(sid) is not int or sid not in sids or expected not in {"fire", "no alert"}:
                raise ValueError("Label cases need a custom SID and expected 'fire' or 'no alert'.")
            choices = [(directory / case["pcap"]).resolve()
                       for directory in (manifest.parent, pcap_dir, pcap_dir / "labels")]
            matches = {capture_names[path] for path in choices if path in capture_names}
            if len(matches) != 1:
                raise ValueError(f"Missing or ambiguous labelled PCAP: {case['pcap']}")
            name = matches.pop()
            if name not in hits:
                hits[name] = Counter(int(event["alert"]["signature_id"])
                                     for event in capture_alerts(work, command, captures[name]))
            count = hits[name][sid]
            rows.append({"sid": sid, "pcap": name, "expected": expected, "hits": count,
                         "passed": (count > 0) == (expected == "fire")})
    else:
        labels = pcap_dir / "labels" if (pcap_dir / "labels").is_dir() else pcap_dir
        runner = work / "10-rule_validation.sh"
        shutil.copyfile(legacy / runner.name, runner)
        shutil.copyfile(custom, work / "meddefense.rules")
        result = run(work, "bash", str(runner), str(labels), check=False)
        rows = read_json(work / "rule_validation.json")["results"]
        if result.returncode and all(row["passed"] for row in rows):
            raise RuntimeError("The custom rule validator failed. See network_deploy.log.")

    results, negatives = [], []
    for row in rows:
        entry = dict(row, alerts_detected=row["hits"], result="pass" if row["passed"] else "fail")
        (results if row["expected"] == "fire" else negatives).append(entry)
    missing = sorted(sids - {row["sid"] for row in rows})
    passed = (not missing and len({row["sid"] for row in results} & sids) >= 6
              and all(row["sid"] in sids and row["passed"] is True for row in rows))
    write_json(work / "custom_rule_validation.json", {
        "passed": passed, "results": results, "negative_checks": negatives, "unvalidated_sids": missing,
    })
    if not passed:
        raise RuntimeError("Custom rule validation failed. See custom_rule_validation.json.")


def read_domains(path):
    domains = {}
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    for raw in path.read_text(encoding="utf-8").splitlines():
        domain = raw.partition("#")[0].strip().lower().rstrip(".")
        if not domain:
            continue
        if len(domain) > 253 or not re.fullmatch(rf"{label}(?:\.{label})+", domain):
            raise ValueError(f"Invalid blocklist domain: {domain}")
        domains[domain] = None
    if not domains:
        raise ValueError("The capstone DNS blocklist is empty.")
    return list(domains)


def replace_bytes(path, contents, mode=0o644):
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".capstone-dns-", delete=False) as stream:
        temporary = Path(stream.name)
    try:
        temporary.write_bytes(contents)
        temporary.chmod(mode)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def configure_dns(work, domains):
    unit = "dnsmasq.service"
    report = {"passed": False, "checks": []}
    was_active = run(work, "systemctl", "is-active", "--quiet", unit, check=False).returncode == 0
    if DNS_FRAGMENT.is_symlink():
        raise ValueError(f"Cannot replace a symlink: {DNS_FRAGMENT}")
    previous = DNS_FRAGMENT.read_bytes() if DNS_FRAGMENT.exists() else None
    previous_mode = stat.S_IMODE(DNS_FRAGMENT.stat().st_mode) if previous is not None else 0o644
    contents = ("listen-address=127.0.0.1\nbind-interfaces\n" +
                "".join(f"address=/{name}/0.0.0.0\nlocal=/{name}/\n" for name in domains)).encode()
    candidate = work / "dnsmasq-blocklist.conf"
    candidate.write_bytes(contents)
    changed = False
    start_attempted = False
    try:
        run(work, "dnsmasq", "--test", "--conf-file=" + str(candidate))
        if contents != previous:
            DNS_FRAGMENT.parent.mkdir(parents=True, exist_ok=True)
            replace_bytes(DNS_FRAGMENT, contents)
            changed = True
        if changed or not was_active:
            start_attempted = True
            run(work, "systemctl", "restart" if was_active else "start", unit)
        run(work, "systemctl", "is-active", "--quiet", unit)
        for domain in domains:
            response = run(work, "dig", "@127.0.0.1", "-q", domain + ".", "-t", "A",
                           "+short", "+time=2", "+tries=1", check=False)
            addresses = response.stdout.split()
            report["checks"].append({"domain": domain, "answers": addresses,
                                     "passed": response.returncode == 0 and addresses == ["0.0.0.0"]})
        if not all(row["passed"] for row in report["checks"]):
            raise RuntimeError("A blocklist domain failed its local DNS check.")
        report["passed"] = True
    except (Exception, KeyboardInterrupt) as error:
        report["error"] = str(error)
        if changed:
            if previous is None:
                DNS_FRAGMENT.unlink(missing_ok=True)
            else:
                replace_bytes(DNS_FRAGMENT, previous, previous_mode)
        if start_attempted:
            recovery = run(work, "systemctl", "restart" if was_active else "stop", unit, check=False)
            report["recovery_exit_code"] = recovery.returncode
        raise
    finally:
        write_json(work / "dns_filter_report.json", report)


def deploy(root, host, case_file, output, work):
    legacy = root.parent / "2x04_perimeter_defense"
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "hostname": host,
              "passed": False, "steps_passed": []}
    step = "inputs"
    try:
        pcap_dir = (LAB / "PCAPs").resolve()
        captures = {path.relative_to(pcap_dir).as_posix(): path.resolve()
                    for path in sorted(pcap_dir.rglob("*"))
                    if path.is_file() and not path.is_symlink() and path.suffix.lower() in {".pcap", ".pcapng"}}
        if not captures:
            raise FileNotFoundError(f"No PCAP or PCAPNG files under {pcap_dir}")
        domains = read_domains(LAB / "dns_blocklist.txt")
        segmentation = work / "segmentation_rules.json"
        shutil.copyfile(LAB / "segmentation_rules.json", segmentation)
        policy = read_json(segmentation)
        windows = "6-windows_firewall.ps1"
        shutil.copyfile(legacy / windows, work / windows)
        report["windows_firewall"] = {"status": "ready_for_native_apply",
                                      "helper": "capstone/network/" + windows}
        report["steps_passed"].append(step)

        step = "firewall_validation"
        validate_firewall(work, legacy)
        report["steps_passed"].append(step)

        step = "offline_suricata_replay"
        custom, sids, option = prepare_suricata(work, legacy, policy)
        replay(work, captures, custom, option)
        report["steps_passed"].append(step)

        step = "custom_rule_validation"
        manifest = case_file or next((path for path in (
            LAB / "rule_validation_cases.json", pcap_dir / "rule_validation_cases.json",
            pcap_dir / "labels.json",
            pcap_dir / "labels/manifest.json",
        ) if path.is_file()), None)
        validate_custom(work, legacy, pcap_dir, captures, custom, sids, manifest)
        report["steps_passed"].append(step)

        step = "dns_filter_validation"
        configure_dns(work, domains)
        report["steps_passed"].append(step)
        report["passed"] = True
    except (Exception, KeyboardInterrupt) as error:
        report.update(failed_step=step, error=str(error) or "Interrupted.")
        print(f"Stopped at {step}: {report['error']}", file=sys.stderr)

    artifacts = ("segmentation_rules.json", "nftables.conf", "nftables_apply_log.json",
                 "firewall_validation.json", "suricata.yaml", "meddefense_custom.rules",
                 "suricata_alerts.json", "rule_validation.json", "custom_rule_validation.json",
                 "dnsmasq-blocklist.conf", "dns_filter_report.json", "6-windows_firewall.ps1",
                 "network_deploy.log")
    report["artifacts"] = {name: f"capstone/network/{name}" for name in artifacts if (work / name).is_file()}
    summary = "network_deploy_summary.json"
    write_json(work / summary, report)
    previous = [name for name in (*artifacts, summary) if (output / name).is_file()]
    if previous:
        archive = Path(tempfile.mkdtemp(prefix=".previous-", dir=output))
        for name in previous:
            (output / name).replace(archive / name)
    for name in (*report["artifacts"], summary):
        (work / name).replace(output / name)
    print(f"Network deployment summary: {output / summary}")
    return int(not report["passed"])


def main():
    parser = argparse.ArgumentParser(description="Apply and validate the Hawthorne network defence stack.")
    parser.add_argument("--rule-cases", type=Path, help="Use a supplied JSON list of SID-to-PCAP cases.")
    args = parser.parse_args(sys.argv[3:])
    root, host = Path(sys.argv[1]), sys.argv[2]
    output = Path(os.environ["CAPSTONE_ARTIFACTS_DIR"])
    output.mkdir(parents=True, exist_ok=True)
    with (output / ".network_deploy.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("Another network deployment is in progress.", file=sys.stderr)
            return 1
        with tempfile.TemporaryDirectory(prefix=".network-run-", dir=output.parent) as stage:
            work = Path(stage) / "capstone/network"
            work.mkdir(parents=True)
            return deploy(root, host, args.rule_cases, output, work)


if __name__ == "__main__":
    sys.exit(main())
PYTHON
