#!/bin/bash
# Compile and safely apply the Task 2 policy. Start with --render-only.
set -euo pipefail
if ! command -v python3 >/dev/null 2>&1; then
    printf "Missing required command: python3\n" >&2
    exit 1
fi
exec python3 - "$@" <<'PY'
"""Compile Task 2's contract and replace only table inet meddefense."""
import argparse
import collections
import datetime
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile

TABLE = "meddefense"
ZONE_NAMES = {"DMZ", "INTERNAL", "MGMT", "MEDDEV"}
BACKUPS = Path("/var/backups")
APPLY_LOCK = Path("/run/meddefense-nftables.lock")
REPORT = Path("nftables_apply_log.json")


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def atomic_write(path, text, mode=0o644):
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def save_report(report):
    atomic_write(REPORT, json.dumps(report, indent=2) + "\n")


def run(arguments, timeout=30):
    return subprocess.run(arguments, capture_output=True, text=True, timeout=timeout)


def required(arguments):
    result = run(arguments)
    if result.returncode:
        raise RuntimeError("Command failed: " + shlex.join(arguments) + ": " + result.stderr.strip())
    return result.stdout


def network_list(values):
    if not isinstance(values, list) or not values:
        raise ValueError("Every flow requires nonempty src_cidrs and dst_cidrs")
    values = [ipaddress.ip_network(value, strict=True) for value in values]
    if any(value.version != 4 for value in values):
        raise ValueError("This Task 2 contract must contain IPv4 CIDRs")
    return sorted(set(values), key=lambda value: (int(value.network_address), value.prefixlen))


def render(policy):
    zones, flows = policy.get("zones"), policy.get("flows")
    if not isinstance(zones, list) or not isinstance(flows, list):
        raise ValueError("The policy must contain zones and flows arrays")
    if len(zones) != 4 or {zone.get("name") for zone in zones} != ZONE_NAMES:
        raise ValueError("Exactly DMZ, INTERNAL, MGMT and MEDDEV zones are required")
    zone_map = {zone["name"]: zone for zone in zones}
    nets = {name: network_list([zone["cidr"]])[0] for name, zone in zone_map.items()}
    for name, zone in zone_map.items():
        if zone.get("default_inbound") != "drop" or zone.get("default_outbound") != "accept":
            raise ValueError("Zone defaults must be inbound drop and outbound accept")
        if any(nets[name].overlaps(other) for key, other in nets.items() if key != name):
            raise ValueError("Zone CIDRs must not overlap")
    sets = {name: [str(network)] for name, network in nets.items()}
    sets["ALL_ZONES"] = [str(network) for network in nets.values()]
    outside = [ipaddress.ip_network("0.0.0.0/0")]
    for excluded in nets.values():
        outside = [part for candidate in outside for part in (
            candidate.address_exclude(excluded) if excluded.subnet_of(candidate) else [candidate])]
    sets["OUTSIDE_ZONES"] = [str(network) for network in sorted(
        outside, key=lambda value: (int(value.network_address), value.prefixlen))]
    references, ids, terminal_seen = {}, set(), False
    for flow in flows:
        identifier = flow.get("id", "")
        if not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", identifier):
            raise ValueError("Flow IDs must be safe nftables identifiers")
        if identifier in ids:
            raise ValueError("Duplicate flow ID: " + identifier)
        ids.add(identifier)
        action = flow.get("action")
        if action not in ("allow", "deny_all"):
            raise ValueError("Supported actions are allow and deny_all")
        if action == "deny_all":
            terminal_seen = True
            if flow.get("proto") != "all" or flow.get("dport") is not None:
                raise ValueError("deny_all must match all protocols and ports")
        elif terminal_seen:
            raise ValueError("Allow flows must precede terminal deny_all flows")
        elif flow.get("proto") not in ("tcp", "udp") or type(flow.get("dport")) is not int or not 1 <= flow["dport"] <= 65535:
            raise ValueError("Allow flows require tcp/udp and an integer port")
        if flow.get("src_zone") not in ZONE_NAMES | {"ALL"} or flow.get("dst_zone") not in ZONE_NAMES | {"INTERNET"}:
            raise ValueError("Unrecognised source or destination zone")
        for side in ("src", "dst"):
            values = network_list(flow.get(side + "_cidrs"))
            zone = flow[side + "_zone"]
            bounds = list(nets.values()) if zone == "ALL" else outside if zone == "INTERNET" else [nets[zone]]
            if any(not any(value.subnet_of(bound) for bound in bounds) for value in values):
                raise ValueError(identifier + ": address selector exceeds its zone")
            names = flow.get(side + "_hosts", [])
            if names:
                hosts = {host["name"]: host["address"] for host in zone_map[zone].get("hosts", [])}
                expected = {str(ipaddress.ip_network(hosts[name] + "/32")) for name in names}
                if {str(value) for value in values} != expected:
                    raise ValueError(identifier + ": named-host selectors do not match")
            canonical = {str(value) for value in values}
            reference = next((name for name, members in sets.items() if set(members) == canonical), None)
            if reference is None:
                reference = "FLOW_" + identifier + "_" + side.upper()
                sets[reference] = [str(value) for value in values]
            references[(identifier, side)] = reference

    rules = {"input": [], "forward": [], "output": []}
    comments = {chain: [] for chain in rules}

    def rule(chain, expression, identifier):
        comment = "md:" + chain + ":" + identifier
        rules[chain].append(expression + " comment " + json.dumps(comment))
        comments[chain].append(comment)

    for chain in rules:
        rule(chain, "ct state established,related counter accept", "established")
        if chain in ("input", "output"):
            rule(chain, ("iifname" if chain == "input" else "oifname") + ' "lo" counter accept', "loopback")
        rule(chain, "ct state invalid counter drop", "invalid")
    rule("input", "icmp type { destination-unreachable, time-exceeded, parameter-problem, echo-reply } counter accept", "icmp_errors")
    rule("input", "ip saddr @MGMT icmp type echo-request counter accept", "icmp_mgmt")
    rule("input", "icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } counter accept", "icmpv6_errors")
    nd = "ip6 hoplimit 255 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } counter accept"
    rule("input", nd, "icmpv6_neighbours")
    rule("output", nd, "icmpv6_neighbours")
    for chain in rules:
        for flow in flows:
            expression = "ip saddr @" + references[(flow["id"], "src")] + " ip daddr @" + references[(flow["id"], "dst")]
            if flow["action"] == "allow":
                expression += " " + flow["proto"] + " dport " + str(flow["dport"]) + " counter accept"
            else:
                expression += ' counter log prefix "MEDDEFENSE_DROP ' + chain + ' " drop'
            rule(chain, expression, flow["id"])
    # Apply per-zone outbound defaults to forwarded external traffic as well.
    for name in zone_map:
        external_deny = any(flow["src_zone"] == name and flow["dst_zone"] == "INTERNET"
                            and flow["action"] == "deny_all"
                            and set(flow["dst_cidrs"]) == set(sets["OUTSIDE_ZONES"]) for flow in flows)
        if not external_deny:
            rule("forward", "ip saddr @" + name + " ip daddr @OUTSIDE_ZONES counter accept", "egress_" + name)
    for chain in ("input", "forward"):
        rule(chain, 'counter log prefix "MEDDEFENSE_DROP ' + chain + ' " drop', "terminal")
    # The source contract has no IPv6 application-zone model.
    rule("output", 'meta nfproto ipv6 counter log prefix "MEDDEFENSE_DROP output6 " drop', "unmodelled_ipv6")
    lines = [
        "# Generated from segmentation_rules.json; IPv4 zone policy.",
        "# Input hooks select packets destined to this host; destination sets remain enforced.",
        "# IPv6: existing connections and essential neighbour/control traffic only.",
        "# Replace only this table in one atomic transaction, including on repeat runs.",
        "add table inet meddefense", "delete table inet meddefense", "table inet meddefense {",
    ]
    for name, members in sets.items():
        lines += ["    set " + name + " {", "        type ipv4_addr", "        flags interval",
                  "        auto-merge", "        elements = { " + ", ".join(members) + " }", "    }"]
    for chain, members in rules.items():
        default = "accept" if chain == "output" else "drop"
        lines += ["    chain " + chain + " {",
                  "        type filter hook " + chain + " priority filter; policy " + default + ";"]
        lines += ["        " + member for member in members]
        lines += ["    }"]
    lines += ["}", ""]
    expected = {"rule_count": sum(map(len, rules.values())),
                "chain_counts": {name: len(value) for name, value in rules.items()},
                "comments": comments, "sets": sorted(sets)}
    return "\n".join(lines), expected


def evaluate(policy, source, destination, protocol, port):
    source, destination = ipaddress.ip_address(source), ipaddress.ip_address(destination)
    for flow in policy["flows"]:
        if any(source in ipaddress.ip_network(cidr) for cidr in flow["src_cidrs"]) and any(
            destination in ipaddress.ip_network(cidr) for cidr in flow["dst_cidrs"]
        ) and flow["proto"] in ("all", protocol) and flow["dport"] in (None, port):
            return flow["action"]
    return None


def preflight(policy, interfaces, ssh_connection=None, remote_session=False):
    networks = [ipaddress.ip_network(zone["cidr"]) for zone in policy["zones"]]
    mapped, unmodelled, ipv6 = [], [], []
    for interface in interfaces:
        if "UP" not in interface.get("flags", []) or interface.get("ifname") == "lo":
            continue
        for address in interface.get("addr_info", []):
            ip = ipaddress.ip_address(address["local"])
            if ip.is_loopback or ip.is_link_local:
                continue
            item = {"interface": interface["ifname"], "address": str(ip)}
            if ip.version == 6:
                ipv6.append(item)
            elif any(ip in network for network in networks):
                mapped.append(item)
            else:
                unmodelled.append(item)
    result = {"mapped_addresses": mapped, "unmodelled_addresses": unmodelled,
              "unmodelled_ipv6_addresses": ipv6, "errors": []}
    if not mapped:
        result["errors"].append("No active host IPv4 address belongs to the segmentation zones")
    if unmodelled:
        result["errors"].append("Active addresses, including any Docker bridges, are outside the policy zones")
    if ipv6:
        result["errors"].append("The IPv4-only plan does not cover active global/ULA IPv6 addresses")
    if remote_session and not ssh_connection:
        result["errors"].append("SSH detected without SSH_CONNECTION; use the VM console")
    if ssh_connection:
        fields = ssh_connection.split()
        if len(fields) != 4:
            result["errors"].append("Unrecognised SSH_CONNECTION record")
        else:
            client, _, local, port = fields
            try:
                result["ssh"] = {"client": client, "local": local, "server_port": int(port)}
                if evaluate(policy, client, local, "tcp", int(port)) != "allow":
                    result["errors"].append("The policy does not permit a new connection on the current SSH path")
            except (ValueError, TypeError):
                result["errors"].append("SSH connection addresses/port do not match this policy")
    return result


def ssh_ancestor():
    pid = os.getppid()
    for _ in range(20):
        if pid <= 1:
            break
        try:
            values = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
            if values.get("Name", "").strip().startswith("sshd"):
                return True
            pid = int(values["PPid"].strip())
        except (OSError, KeyError, ValueError):
            break
    return False


def verify(loaded, expected):
    chains, counts, comments, sets = {}, collections.Counter(), collections.defaultdict(list), set()
    for item in loaded.get("nftables", []):
        for kind in ("chain", "rule", "set"):
            value = item.get(kind, {})
            if value.get("family") != "inet" or value.get("table") != TABLE:
                continue
            if kind == "chain":
                chains[value["name"]] = value
            elif kind == "rule":
                counts[value["chain"]] += 1
                comments[value["chain"]].append(value.get("comment"))
            else:
                sets.add(value["name"])
    errors = []
    for name, policy in (("input", "drop"), ("forward", "drop"), ("output", "accept")):
        if chains.get(name, {}).get("policy") != policy or chains.get(name, {}).get("hook") != name:
            errors.append("Incorrect base-chain policy/hook: " + name)
        if counts[name] != expected["chain_counts"][name] or comments[name] != expected["comments"][name]:
            errors.append("Rule count/order/comments do not match: " + name)
    if sets != set(expected["sets"]):
        errors.append("The loaded named sets do not match")
    if sum(counts.values()) != expected["rule_count"]:
        errors.append("The loaded total is not the expected total")
    return {"passed": not errors, "errors": errors, "actual_rule_count": sum(counts.values()),
            "actual_chain_counts": dict(counts), "expected_rule_count": expected["rule_count"]}


WATCHDOG = r'''
import fcntl, json, subprocess, sys, time
from pathlib import Path
nft, rollback, control, seconds = sys.argv[1], sys.argv[2], Path(sys.argv[3]), int(sys.argv[4])
deadline = time.monotonic() + seconds
while time.monotonic() < deadline:
    if control.with_suffix(".committed").exists():
        sys.exit(0)
    time.sleep(0.25)
with control.with_suffix(".lock").open("a") as stream:
    fcntl.flock(stream, fcntl.LOCK_EX)
    if control.with_suffix(".committed").exists():
        sys.exit(0)
    try:
        result = subprocess.run([nft, "-f", rollback], capture_output=True, text=True, timeout=30)
        status = {"rolled_back": result.returncode == 0, "exit_code": result.returncode, "stderr": result.stderr}
    except Exception as error:
        status = {"rolled_back": False, "error": str(error)}
    control.with_suffix(".result.json").write_text(json.dumps(status) + "\n")
'''


def commit_watchdog(control):
    with control.with_suffix(".lock").open("a") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        result = control.with_suffix(".result.json")
        if result.exists():
            raise RuntimeError("Automatic rollback already ran: " + result.read_text())
        atomic_write(control.with_suffix(".committed"), "verified\n", 0o600)


def main():
    parser = argparse.ArgumentParser(description="Compile and safely apply table inet meddefense")
    modes = parser.add_mutually_exclusive_group()
    for flag, mode in (("--render-only", "render"), ("--check-only", "check"), ("--apply", "apply")):
        modes.add_argument(flag, dest="mode", action="store_const", const=mode)
    parser.set_defaults(mode="apply")
    parser.add_argument("--policy", default="segmentation_rules.json")
    parser.add_argument("--rollback-seconds", type=int, default=120)
    args = parser.parse_args()
    if not 60 <= args.rollback_seconds <= 600:
        parser.error("--rollback-seconds must be between 60 and 600")
    report = {"generated_at": stamp(), "hostname": socket.gethostname(), "mode": args.mode,
              "status": "started", "applied": False, "policy": str(Path(args.policy).resolve())}
    rollback_file = watchdog = control = apply_lock = None
    nft, attempted = shutil.which("nft"), False
    try:
        policy_bytes = Path(args.policy).read_bytes()
        policy = json.loads(policy_bytes)
        configuration, expected = render(policy)
        atomic_write("nftables.conf", configuration)
        report["render"] = {"file": str(Path("nftables.conf").resolve()),
                            "sha256": hashlib.sha256(configuration.encode()).hexdigest(),
                            "policy_sha256": hashlib.sha256(policy_bytes).hexdigest(), **expected}
        report["status"] = "rendered"
        save_report(report)
        if args.mode == "render":
            print(f"Rendered nftables.conf: {expected['rule_count']} rules in input, forward and output.")
            print("No firewall changes were applied. Next step: sudo ./4-nftables_config.sh --check-only")
            return 0
        if os.geteuid() != 0:
            raise RuntimeError("Use sudo for --check-only or --apply; --render-only does not need sudo")
        if not nft or not shutil.which("ip"):
            raise RuntimeError("Local nft and ip commands are required; packages are not downloaded at runtime")
        if args.mode == "apply":
            apply_lock = APPLY_LOCK.open("a")
            fcntl.flock(apply_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before_json = json.loads(required([nft, "-j", "list", "ruleset"]))
        before_text = required([nft, "list", "ruleset"])
        interfaces = json.loads(required(["ip", "-j", "addr", "show"]))
        routes = json.loads(required(["ip", "-j", "route", "show"]))
        report["pre_state"] = {"captured_at": stamp(), "ruleset": before_json,
                               "interfaces": interfaces, "routes": routes}
        report["preflight"] = preflight(policy, interfaces, os.environ.get("SSH_CONNECTION"), ssh_ancestor())
        report["status"] = "measured"
        save_report(report)
        with tempfile.TemporaryDirectory(prefix="meddefense-nft-") as directory:
            candidate = Path(directory) / "nftables.conf"
            atomic_write(candidate, configuration, 0o600)
            check = run([nft, "-c", "-f", str(candidate)])
            report["validation"] = {"exit_code": check.returncode, "stdout": check.stdout, "stderr": check.stderr}
            save_report(report)
            if check.returncode:
                raise RuntimeError("nft -c rejected the candidate: " + check.stderr.strip())
            if args.mode == "check":
                report["status"] = "checked"
                save_report(report)
                print(f"nft check passed: {expected['rule_count']} expected rules. No firewall changes were applied.")
                if report["preflight"]["errors"]:
                    print("Apply preflight is blocked:")
                    for error in report["preflight"]["errors"]:
                        print(" - " + error)
                return 0
            if report["preflight"]["errors"]:
                raise RuntimeError("Apply preflight blocked: " + "; ".join(report["preflight"]["errors"]))
            BACKUPS.mkdir(mode=0o755, parents=True, exist_ok=True)
            identifier = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            backup = BACKUPS / ("nftables-rollback-" + identifier + ".nft")
            rollback_file = BACKUPS / ("nftables-rollback-" + identifier + "-meddefense.nft")
            atomic_write(backup, before_text, 0o600)
            existed = any(item.get("table", {}).get("family") == "inet"
                          and item["table"].get("name") == TABLE for item in before_json.get("nftables", []))
            previous_table = required([nft, "list", "table", "inet", TABLE]) if existed else ""
            atomic_write(rollback_file, ("add table inet meddefense\ndelete table inet meddefense\n" + previous_table).rstrip() + "\n", 0o600)
            control = BACKUPS / ("meddefense-watchdog-" + identifier)
            report["rollback"] = {"full_ruleset_backup": str(backup), "scoped_restore": str(rollback_file),
                                  "command": shlex.join(["sudo", nft, "-f", str(rollback_file)]),
                                  "timeout_seconds": args.rollback_seconds,
                                  "automatic_status": str(control.with_suffix(".result.json"))}
            report["status"] = "backed_up"
            save_report(report)
            restore_check = run([nft, "-c", "-f", str(rollback_file)])
            report["rollback"]["validation_exit_code"] = restore_check.returncode
            save_report(report)
            if restore_check.returncode:
                raise RuntimeError("Rollback configuration failed its nft check: " + restore_check.stderr.strip())
            watchdog = subprocess.Popen(
                [sys.executable, "-c", WATCHDOG, nft, str(rollback_file), str(control), str(args.rollback_seconds)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            report["status"] = "applying"
            save_report(report)
            attempted = True
            loaded = run([nft, "-f", str(candidate)])
            report["apply_exit_code"] = loaded.returncode
            if loaded.returncode:
                raise RuntimeError("Atomic load failed: " + loaded.stderr.strip())
            report["post_state"] = json.loads(required([nft, "-j", "list", "ruleset"]))
            live = json.loads(required([nft, "-j", "list", "table", "inet", TABLE]))
            report["verification"] = verify(live, expected)
            if not report["verification"]["passed"]:
                raise RuntimeError("Loaded rules did not match counts, order, sets or chain policies")
            commit_watchdog(control)
            report.update(applied=True, status="applied", completed_at=stamp())
            save_report(report)
            print(f"Applied table inet meddefense: verified {expected['rule_count']} rules.")
            print("Rollback command: " + report["rollback"]["command"])
            print("Saved nftables_apply_log.json")
            return 0
    except BaseException as error:
        report.update(error=str(error), status="failed")
        if attempted and rollback_file and nft:
            try:
                result = run([nft, "-f", str(rollback_file)])
                report["recovery"] = {"exit_code": result.returncode, "stderr": result.stderr}
                report["status"] = "rolled_back" if result.returncode == 0 else "rollback_failed"
                if result.returncode == 0 and control:
                    atomic_write(control.with_suffix(".committed"), "restored\n", 0o600)
            except BaseException as recovery_error:
                report.update(status="rollback_failed", recovery_error=str(recovery_error))
        elif control:
            atomic_write(control.with_suffix(".committed"), "not_applied\n", 0o600)
        save_report(report)
        print("Task 4 stopped: " + str(error), file=sys.stderr)
        print("Details saved in nftables_apply_log.json", file=sys.stderr)
        return 1
    finally:
        if watchdog and control and control.with_suffix(".committed").exists():
            try:
                watchdog.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        if apply_lock:
            apply_lock.close()


if __name__ == "__main__":
    def interrupted(number, frame):
        raise RuntimeError("Interrupted by signal " + str(number))
    for caught_signal in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(caught_signal, interrupted)
    sys.exit(main())

PY

