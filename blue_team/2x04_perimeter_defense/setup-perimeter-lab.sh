#!/bin/bash
# Create one isolated INTERNAL endpoint for the Task 4 nftables exercise.
set -euo pipefail
for dependency in python3 ip nft; do
    if ! command -v "$dependency" >/dev/null 2>&1; then
        printf 'Missing required command: %s\n' "$dependency" >&2
        exit 1
    fi
done
exec python3 - <<'PY'
import datetime
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

NAME = "meddefense-lab"
INTERFACE = "lab0"
STATE = Path("/var/lib/meddefense-perimeter-lab")
NETNS_ROOT = Path("/run/netns")
REPORT = Path("perimeter_lab_setup.json")


def command(arguments):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError(" ".join(arguments) + ": " + result.stderr.strip())
    return result.stdout


def write_json(path, value, mode=0o644):
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def host_snapshot():
    return {
        "addresses": json.loads(command(["ip", "-j", "addr", "show"])),
        "routes": json.loads(command(["ip", "-j", "route", "show"])),
        "ruleset": json.loads(command(["nft", "-s", "-j", "list", "ruleset"])),
        "namespaces": command(["ip", "netns", "list"]),
        "network_namespace_id": os.readlink("/proc/self/ns/net"),
    }


def address_signature(snapshot):
    return sorted((entry["ifname"], address["family"], address["local"], address["prefixlen"])
                  for entry in snapshot["addresses"] for address in entry.get("addr_info", []))


def setup():
    if os.geteuid() != 0:
        raise RuntimeError("Run this setup script with sudo")
    policy = json.loads(Path("segmentation_rules.json").read_text())
    internal = next(zone for zone in policy["zones"] if zone["name"] == "INTERNAL")
    database = next((host for host in internal.get("hosts", []) if host.get("role") == "database"), None)
    if database is None:
        raise ValueError("The INTERNAL zone needs a named database host for this lab endpoint")
    network = ipaddress.ip_network(internal["cidr"])
    address = ipaddress.ip_address(database["address"])
    if network.version != 4 or address not in network:
        raise ValueError("The INTERNAL database needs an address in the planned IPv4 subnet")
    endpoint = str(address) + "/" + str(network.prefixlen)
    report = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "namespace": NAME,
        "endpoint_name": database["name"],
        "endpoint_address": endpoint,
        "status": "started",
        "scope": "Isolated INTERNAL test endpoint; not the VM's normal network",
    }
    created = False
    lock = None
    try:
        # Check shared state and save the measurement before any network changes.
        STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
        lock = (STATE / "setup.lock").open("a")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = host_snapshot()
        report["before"] = before
        report["status"] = "measured"
        write_json(REPORT, report)
        owner_file = STATE / "owner.json"
        marker = NETNS_ROOT / NAME
        exists = NAME in [line.split()[0] for line in before["namespaces"].splitlines() if line.strip()]
        if exists:
            if not owner_file.is_file():
                raise RuntimeError("An existing meddefense-lab namespace has no ownership record; left unchanged")
            owner = json.loads(owner_file.read_text())
            if owner.get("namespace") != NAME or owner.get("namespace_inode") != marker.stat().st_ino:
                raise RuntimeError("The namespace ownership record does not match; left unchanged")
            if owner.get("endpoint_address") != endpoint:
                raise RuntimeError("The existing lab uses a different address plan; left unchanged")
        else:
            command(["ip", "netns", "add", NAME])
            created = True
            write_json(owner_file, {
                "namespace": NAME, "namespace_inode": marker.stat().st_ino,
                "endpoint_address": endpoint,
            }, 0o600)
        links = json.loads(command(["ip", "-n", NAME, "-j", "-d", "link", "show"]))
        addresses = json.loads(command(["ip", "-n", NAME, "-j", "addr", "show"]))
        report["lab_before"] = {
            "links": links, "addresses": addresses,
            "routes": json.loads(command(["ip", "-n", NAME, "-j", "route", "show"])),
        }
        write_json(REPORT, report)
        link = next((entry for entry in links if entry["ifname"] == INTERFACE), None)
        if link and link.get("linkinfo", {}).get("info_kind") != "dummy":
            raise RuntimeError("Existing lab0 is not the expected dummy interface; left unchanged")
        if link is None:
            command(["ip", "-n", NAME, "link", "add", INTERFACE, "type", "dummy"])
        current = {(entry["ifname"], value["local"], value["prefixlen"])
                   for entry in addresses for value in entry.get("addr_info", [])}
        if (INTERFACE, str(address), network.prefixlen) not in current:
            command(["ip", "-n", NAME, "addr", "add", endpoint, "dev", INTERFACE])
        for interface in ("lo", INTERFACE):
            entry = next((item for item in addresses if item["ifname"] == interface), None)
            if entry is None or "UP" not in entry.get("flags", []):
                command(["ip", "-n", NAME, "link", "set", interface, "up"])
        report["lab_addresses"] = json.loads(command(["ip", "-n", NAME, "-j", "addr", "show"]))
        report["lab_network_namespace_id"] = command(
            ["ip", "netns", "exec", NAME, "readlink", "/proc/self/ns/net"]
        ).strip()
        after = host_snapshot()
        report["after"] = after
        report["host_addresses_unchanged"] = address_signature(before) == address_signature(after)
        report["host_ruleset_unchanged"] = before["ruleset"] == after["ruleset"]
        if not report["host_addresses_unchanged"] or not report["host_ruleset_unchanged"]:
            raise RuntimeError("The normal VM network changed during setup; review the before/after evidence")
        report["status"] = "ready"
        report["created_namespace"] = created
        write_json(REPORT, report)
        print("Isolated lab ready: " + NAME)
        print("INTERNAL test endpoint: " + database["name"] + " at " + endpoint)
        print("The VM's normal addresses and firewall rules are unchanged.")
        print("Saved perimeter_lab_setup.json")
        return 0
    except BaseException as error:
        report.update(status="failed", error=str(error))
        if created:
            try:
                command(["ip", "netns", "delete", NAME])
                (STATE / "owner.json").unlink(missing_ok=True)
                report["cleanup"] = "Removed only the namespace created by this attempt"
            except BaseException as cleanup_error:
                report["cleanup_error"] = str(cleanup_error)
        write_json(REPORT, report)
        raise
    finally:
        if lock:
            lock.close()


if __name__ == "__main__":
    try:
        sys.exit(setup())
    except BaseException as error:
        if isinstance(error, SystemExit):
            raise
        print("Lab setup stopped: " + str(error), file=sys.stderr)
        sys.exit(1)
PY

