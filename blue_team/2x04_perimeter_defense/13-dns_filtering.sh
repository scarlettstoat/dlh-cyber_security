#!/bin/bash
set -euo pipefail
project="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 - "$project" "$@" <<'PY'
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser(description="Set up the MedDefense loopback DNS filter.")
parser.add_argument("--lab-dir", type=Path, default=Path("/home/analyst/MedDefense_Lab/dns"))
parser.add_argument("--unlisted", default="iana.org")
args = parser.parse_args(sys.argv[2:])
project = Path(sys.argv[1])
conf = Path("/etc/dnsmasq.d")
upstream = conf / "meddefense-upstream.conf"
blocked_conf = conf / "meddefense-blocklist.conf"
main_conf = conf / "meddefense-loopback.conf"
override = Path("/etc/systemd/system/dnsmasq.service.d/90-meddefense.conf")
resolver = Path("/etc/resolv.conf")
unit = "dnsmasq.service"
report = {"status": "failed", "checks": []}
previous = {}
changed = []


def run(*command, check=True):
    result = subprocess.run(command, text=True, capture_output=True)
    if check and result.returncode:
        raise RuntimeError(f"{' '.join(command)}: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout.strip()


def save(path, contents):
    if path.is_file() and path.read_text() == contents:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as stream:
        staged = Path(stream.name)
        stream.write(contents)
    try:
        staged.chmod(0o644)
        staged.replace(path)
    finally:
        staged.unlink(missing_ok=True)
    return True


def domain(value):
    value = value.rstrip(".").lower()
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if len(value) > 253 or not re.fullmatch(rf"{label}(?:\.{label})+", value):
        raise ValueError(f"Invalid domain: {value}")
    return value


def domains(name):
    return list(dict.fromkeys(domain(line) for raw in (args.lab_dir / name).read_text().splitlines()
                              if (line := raw.split("#", 1)[0].strip())))


def snapshot_resolver():
    return {"symlink": os.readlink(resolver) if resolver.is_symlink() else None,
            "contents": resolver.read_text()}


def addresses(value):
    result = []
    for line in value.splitlines():
        try:
            result.append(str(ipaddress.IPv4Address(line.strip())))
        except ValueError:
            continue
    return result


try:
    if os.geteuid():
        raise RuntimeError("Run with sudo.")
    block, allow = domains("blocklist.txt"), domains("allowlist.txt")
    unlisted = domain(args.unlisted)

    def matches(name):
        return any(name == entry or name.endswith("." + entry) for entry in block)

    if not block or not allow or matches(allow[0]) or matches(unlisted) or unlisted in allow:
        raise ValueError("Check the lists and choose an unlisted domain outside blocked suffixes.")

    upstream_text = (upstream if upstream.is_file() else args.lab_dir / upstream.name).read_text()
    servers = []
    for raw in upstream_text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line == "no-resolv":
            continue
        if not line.startswith("server="):
            raise ValueError(f"Unexpected upstream setting: {line}")
        server = ipaddress.ip_address(line.split("=", 1)[1])
        if server.is_loopback or server.is_unspecified:
            raise ValueError(f"Upstream must be a separate resolver: {server}")
        servers.append(str(server))
    if not servers:
        raise ValueError("No upstream DNS servers configured.")

    configs = {
        upstream: upstream_text.rstrip() + "\n",
        blocked_conf: "".join(f"address=/{name}/0.0.0.0\nlocal=/{name}/\n" for name in block),
        main_conf: "listen-address=127.0.0.1\nbind-interfaces\nno-resolv\nno-hosts\n"
                   f"conf-file={upstream}\nconf-file={blocked_conf}\n"
                   "log-queries\nlog-facility=/var/log/dnsmasq.log\n",
        override: "[Service]\nType=simple\nPIDFile=\nExecStartPre=\nExecStart=\n"
                  f"ExecStart=/usr/sbin/dnsmasq --keep-in-foreground --conf-file={main_conf}\n"
                  "ExecStartPost=\nExecStop=\nExecStopPost=\nExecReload=\n",
    }
    active = run("systemctl", "is-active", unit, check=False) == "active"
    for path in configs:
        if path.is_symlink():
            raise ValueError(f"Managed configuration is a symlink: {path}")
        previous[path] = path.read_text() if path.exists() else None
    before = {"resolv_conf": snapshot_resolver(), "service_active": active,
              "port_53_listeners": run("ss", "-lntup", "sport = :53"),
              "configuration": {str(k): v for k, v in previous.items()}}
    save(project / "dns_filter_before.json", json.dumps(before, indent=2) + "\n")

    # Install from cached distribution packages while preventing package service hooks.
    package_status = run("dpkg-query", "-W", "-f=${db:Status-Status}", "dnsmasq", check=False)
    packages = ([] if package_status == "installed" else ["dnsmasq"])
    if not shutil.which("dig"):
        packages.append("bind9-dnsutils")
    if packages:
        policy = Path("/usr/sbin/policy-rc.d")
        if os.path.lexists(policy):
            raise RuntimeError("An existing policy-rc.d is present. Have the lab administrator install the missing packages under that policy.")
        with policy.open("x") as guard:
            guard.write("#!/bin/bash\nexit 101\n")
        try:
            policy.chmod(0o755)
            run("apt-get", "--no-download", "--no-remove", "--yes", "--no-install-recommends",
                "install", *packages)
        finally:
            policy.unlink()

    for path, content in configs.items():
        if save(path, content):
            changed.append(path)
    run("/usr/sbin/dnsmasq", "--test", f"--conf-file={main_conf}")
    if changed:
        run("systemctl", "daemon-reload")
        run("systemctl", "restart", unit)
    elif not active:
        run("systemctl", "start", unit)
    run("systemctl", "is-active", "--quiet", unit)
    report.update(service_active=True, upstream_servers=servers, blocked_domains=len(block))
    report["resolv_conf_unchanged"] = snapshot_resolver() == before["resolv_conf"]
    if not report["resolv_conf_unchanged"]:
        raise RuntimeError("/etc/resolv.conf changed during setup.")

    for kind, name in (("allowed", allow[0]), ("blocked", block[0]), ("unlisted", unlisted)):
        reply = run("dig", "@127.0.0.1", name + ".", "A", "+short", "+time=3", "+tries=2", check=False)
        answer = addresses(reply)
        passed = (answer == ["0.0.0.0"] if kind == "blocked"
                  else bool(answer) and "0.0.0.0" not in answer)
        report["checks"].append({"kind": kind, "domain": name, "answers": answer, "passed": passed})
        print(f"{kind}: {name} -> {', '.join(answer) or 'no A answer'} [{'PASS' if passed else 'FAIL'}]")
    if all(result["passed"] for result in report["checks"]):
        report["status"] = "passed"
    else:
        report["error"] = "One or more DNS validation queries failed."
except (OSError, ValueError, RuntimeError) as error:
    report["error"] = str(error)
    print(f"DNS setup stopped: {error}", file=sys.stderr)
    if changed:
        run("systemctl", "stop", unit, check=False)
        for path in reversed(changed):
            if previous[path] is None:
                path.unlink(missing_ok=True)
            else:
                save(path, previous[path])
        run("systemctl", "daemon-reload", check=False)
        if active:
            run("systemctl", "start", unit, check=False)

save(project / "dns_filter_report.json", json.dumps(report, indent=2) + "\n")
sys.exit(report["status"] != "passed")
PY

