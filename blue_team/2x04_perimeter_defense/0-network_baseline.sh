#!/bin/bash
# Capture the endpoint's network baseline without changing network settings.
# Python 3's standard library handles JSON and the portable ss text format.
set -euo pipefail
export LC_ALL=C

if [[ $(id -u) -ne 0 ]]; then
    printf 'Run this script with sudo to collect socket process/PID details.\n' >&2
    exit 1
fi

for dependency in ip ss python3; do
    if ! command -v "$dependency" >/dev/null 2>&1; then
        printf 'Missing required command: %s\n' "$dependency" >&2
        exit 1
    fi
done

# Stage the capture beside the output; publish it only after every step succeeds.
work_dir=$(mktemp -d "$PWD/.network-baseline.XXXXXX")
trap 'rm -rf -- "$work_dir"' EXIT

capture() {
    local filename=$1
    shift
    if ! "$@" >"$work_dir/$filename" 2>"$work_dir/$filename.err"; then
        printf 'Capture failed: %s\n' "$*" >&2
        cat "$work_dir/$filename.err" >&2
        exit 1
    fi
    # ss can report a permission/netlink failure despite returning status zero.
    if [[ -s "$work_dir/$filename.err" ]]; then
        printf 'Capture reported a problem: %s\n' "$*" >&2
        cat "$work_dir/$filename.err" >&2
        exit 1
    fi
}

date -u '+%Y-%m-%dT%H:%M:%SZ' >"$work_dir/timestamp.txt"
capture interfaces.json ip -j addr show
capture routes4.json ip -j route show
capture routes6.json ip -6 -j route show
capture neighbors.json ip -j neigh show
capture listening.txt ss -tulnpH
capture established.txt ss -tnpH state established
capture resolv.conf cat /etc/resolv.conf

resolved_state=unavailable
if command -v systemctl >/dev/null 2>&1; then
    resolved_state=$(systemctl is-active systemd-resolved 2>/dev/null || true)
    resolved_state=${resolved_state:-unavailable}
fi
printf '%s\n' "$resolved_state" >"$work_dir/resolved_state.txt"
if [[ $resolved_state == active ]]; then
    if ! command -v resolvectl >/dev/null 2>&1; then
        printf 'systemd-resolved is active, but resolvectl is unavailable.\n' >&2
        exit 1
    fi
    capture resolvectl.txt resolvectl status --no-pager
fi

python3 - "$work_dir" <<'PY'
import json
import re
import socket
import sys
from pathlib import Path

work = Path(sys.argv[1])


def read_json(filename):
    with (work / filename).open(encoding="utf-8") as stream:
        records = json.load(stream)
    if not isinstance(records, list) or not all(
        isinstance(record, dict) for record in records
    ):
        raise ValueError(f"{filename}: expected an array of objects")
    return records


def endpoint(value):
    address, port = value.rsplit(":", 1)
    return address.strip("[]"), None if port == "*" else int(port)


def parse_sockets(filename, default_state=None):
    # ss may omit both Netid and State when a single TCP state is selected.
    row_pattern = re.compile(
        r"^(?:(tcp6?|udp6?)\s+)?(?:(LISTEN|UNCONN|ESTAB)\s+)?"
        r"(\d+)\s+(\d+)\s+(\S+)\s+(\S+)(?:\s+(.*))?$"
    )
    owner_pattern = re.compile(r'\("((?:[^"\\]|\\.)*)",pid=(\d+),fd=(\d+)\)')
    records = []
    for line in (work / filename).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        match = row_pattern.fullmatch(line.strip())
        if match is None:
            raise ValueError(f"{filename}: unrecognised ss row: {line}")
        protocol, state, recv_q, send_q, local, peer, owners = match.groups()
        if protocol is None and default_state is None:
            raise ValueError(f"{filename}: missing socket protocol")
        if state is None and default_state is None:
            raise ValueError(f"{filename}: missing socket state")
        local_address, local_port = endpoint(local)
        peer_address, peer_port = endpoint(peer)
        processes = [
            {"name": name, "pid": int(pid), "fd": int(fd)}
            for name, pid, fd in owner_pattern.findall(owners or "")
        ]
        records.append({
            "protocol": (protocol or "tcp").rstrip("6"),
            "state": state or default_state,
            "recv_q": int(recv_q),
            "send_q": int(send_q),
            "local_address": local_address,
            "local_port": local_port,
            "peer_address": peer_address,
            "peer_port": peer_port,
            "processes": processes,
            "process_resolution": "resolved" if processes else "unavailable",
        })
    return records


def build_baseline():
    interfaces = [
        {
            "name": item["ifname"],
            "mac": item.get("address"),
            "link_state": item.get("operstate"),
            "flags": item.get("flags", []),
            "addresses": item.get("addr_info", []),
        }
        for item in read_json("interfaces.json")
        # Loopback is administratively UP even when operstate is UNKNOWN.
        if "UP" in item.get("flags", [])
    ]
    routes = [
        dict(item, family=family)
        for filename, family in (("routes4.json", "inet"), ("routes6.json", "inet6"))
        for item in read_json(filename)
    ]
    neighbors = []
    for item in read_json("neighbors.json"):
        state = item.get("state", [])
        neighbors.append({
            "ip": item["dst"],
            "mac": item.get("lladdr"),
            "interface": item.get("dev"),
            "state": [state] if isinstance(state, str) else state,
        })

    listeners = parse_sockets("listening.txt")
    connections = parse_sockets("established.txt", default_state="ESTAB")
    for connection in connections:
        # A snapshot cannot prove the SYN initiator. Preserve all established
        # connections and explicitly label listener-based direction as inferred.
        listener_match = any(
            listener["protocol"] == "tcp"
            and listener["local_port"] == connection["local_port"]
            and listener["local_address"] in (
                "*", "0.0.0.0", "::", connection["local_address"]
            )
            for listener in listeners
        )
        connection["direction"] = (
            "inbound_candidate" if listener_match else "outbound_candidate"
        )
        connection["direction_basis"] = "inferred_from_local_listener_match"

    resolv_conf = (work / "resolv.conf").read_text(encoding="utf-8")
    resolved_state = (work / "resolved_state.txt").read_text(encoding="utf-8").strip()
    dns = {
        "nameservers": [],
        "search": [],
        "domain": None,
        "options": [],
        "resolv_conf_path": "/etc/resolv.conf",
        "resolv_conf_content": resolv_conf,
        "systemd_resolved_state": resolved_state,
        "resolvectl_status": None,
    }
    for line in resolv_conf.splitlines():
        fields = re.split(r"[#;]", line, maxsplit=1)[0].split()
        if len(fields) < 2:
            continue
        if fields[0] == "nameserver":
            dns["nameservers"].append(fields[1])
        elif fields[0] in ("search", "options"):
            dns[fields[0]] = fields[1:]
        elif fields[0] == "domain":
            dns["domain"] = fields[1]
    if resolved_state == "active":
        dns["resolvectl_status"] = (work / "resolvectl.txt").read_text(encoding="utf-8")

    missing_owners = sum(
        not item["processes"] for item in listeners + connections
    )
    if missing_owners:
        print(
            f"Warning: {missing_owners} socket(s) have no visible process owner; "
            "see process_resolution in the JSON.",
            file=sys.stderr,
        )

    return {
        "timestamp": (work / "timestamp.txt").read_text(encoding="utf-8").strip(),
        "hostname": socket.gethostname(),
        "interfaces": interfaces,
        "routes": routes,
        "neighbors": neighbors,
        "listening_sockets": listeners,
        "established_connections": connections,
        "dns_resolvers": dns,
    }


try:
    baseline = build_baseline()
    with (work / "network_baseline.json").open("w", encoding="utf-8") as stream:
        json.dump(baseline, stream, indent=2)
        stream.write("\n")
except (OSError, ValueError, KeyError, TypeError) as error:
    print(f"Baseline capture failed: {error}", file=sys.stderr)
    sys.exit(1)

print(
    f"Captured {len(baseline['interfaces'])} active interface(s), "
    f"{len(baseline['listening_sockets'])} listener(s), and "
    f"{len(baseline['established_connections'])} established TCP connection(s)."
)
PY

mv -f -- "$work_dir/network_baseline.json" "$PWD/network_baseline.json"
printf 'Saved network_baseline.json\n'

