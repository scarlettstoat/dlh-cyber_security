#!/bin/bash
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 - "$project_dir" "$@" <<'PY'
import argparse
import csv
from decimal import Decimal
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser(description="Investigate a saved PCAP with TShark.")
parser.add_argument("pcap", nargs="?", type=Path,
                    default=Path("/home/analyst/MedDefense_Lab/PCAPs/suspicious_session.pcap"))
capture = parser.parse_args(sys.argv[2:]).pcap.resolve()
project = Path(sys.argv[1])


def tshark(*args):
    result = subprocess.run(
        ["tshark", "-n", "-r", str(capture), *args],
        capture_output=True, text=True, env={**os.environ, "LC_ALL": "C"},
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f"TShark exited {result.returncode}")
    return result.stdout


def fields(display_filter, columns):
    args = ["-T", "fields", "-E", "separator=,", "-E", "quote=d",
            "-E", "aggregator=|"]
    if display_filter:
        args[:0] = ["-Y", display_filter]
    for field, _ in columns:
        args.extend(("-e", field))
    return list(csv.reader(io.StringIO(tshark(*args))))


def events(display_filter, columns):
    common = [("frame.time_epoch", "timestamp"), ("ip.src", "src_ip"),
              ("ipv6.src", "src_ipv6"), ("ip.dst", "dst_ip"), ("ipv6.dst", "dst_ipv6")]
    schema = common + columns
    output = []
    for values in fields(display_filter, schema):
        row = dict(zip((name for _, name in schema), values, strict=True))
        row["src_ip"] = row["src_ip"] or row["src_ipv6"] or None
        row["dst_ip"] = row["dst_ip"] or row["dst_ipv6"] or None
        del row["src_ipv6"], row["dst_ipv6"]
        output.append(row)
    return output


def conversations(protocol):
    rows = []
    for line in tshark("-q", "-z", f"conv,{protocol}").splitlines():
        if "<->" not in line:
            continue
        parts = line.split()
        # Modern TShark includes units. Older versions can print raw bytes.
        data = iter(parts[3:])
        counters = []
        for _ in range(3):
            packets = int(next(data).replace(",", ""))
            number = Decimal(next(data).replace(",", ""))
            unit = next(data) if re.search(r"\s(?:bytes?|[kKMGT]i?B)\s", line) else "bytes"
            multiplier = {"byte": 1, "bytes": 1, "B": 1, "kB": 1000, "KB": 1000,
                          "MB": 1000**2, "GB": 1000**3, "TB": 1000**4,
                          "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3,
                          "TiB": 1024**4}[unit]
            counters.append({"packets": packets, "bytes": int(number * multiplier)})
        start, duration = map(float, data)
        rows.append({"protocol": protocol, "endpoint_a": parts[0], "endpoint_b": parts[2],
                     "a_to_b": counters[1], "b_to_a": counters[0], **counters[2],
                     "start_offset_seconds": start, "duration_seconds": duration})
    rows.sort(key=lambda row: (-row["bytes"], -row["packets"], row["endpoint_a"], row["endpoint_b"]))
    return rows


def protocol_hierarchy():
    stack = []
    rows = []
    for line in tshark("-q", "-z", "io,phs").splitlines():
        match = re.fullmatch(r"(\s*)(\S+)\s+frames:(\d+)\s+bytes:(\d+)\s*", line)
        if match:
            indent, protocol, packets, byte_count = match.groups()
            depth = len(indent)
            while stack and stack[-1][0] >= depth:
                stack.pop()
            stack.append((depth, protocol))
            rows.append({"protocol": protocol, "path": [value for _, value in stack],
                         "packets": int(packets), "bytes": int(byte_count)})
    return rows


def investigate():
    if not capture.is_file():
        raise FileNotFoundError(capture)
    tcp = conversations("tcp")
    udp = conversations("udp")
    dns = events("dns.flags.response==0", [("dns.qry.name", "query"), ("dns.qry.type", "query_type")])
    http = events("http.request", [("http.host", "host"), ("http.request.method", "method"),
                                   ("http.request.uri", "uri")])
    tls = events("tls.handshake.type==1", [("tls.handshake.extensions_server_name", "sni")])
    transfers = events("http.content_type or smb2.filename",
                       [("http.file_data", "http_file_data"), ("smb2.filename", "smb_filename"),
                        ("http.content_type", "http_content_type")])
    hierarchy = protocol_hierarchy()
    frames = fields(None, [("frame.time_epoch", "time"), ("frame.protocols", "stack")])
    times = [Decimal(time) for time, _ in frames]
    # Assign each frame once. The hierarchy retains overlapping protocol layers.
    counts = dict.fromkeys(("tcp", "udp", "icmp", "other"), 0)
    for _, protocols in frames:
        transport = next((p for p in protocols.split(":")
                          if p in ("tcp", "udp", "icmp", "icmpv6")), "other")
        counts["icmp" if transport == "icmpv6" else transport] += 1
    distribution = [{"protocol": p, "packets": n, "percent": round(100 * n / len(frames), 2)}
                    for p, n in counts.items()] if frames else []
    long_labels = []
    for row in dns:
        for query in row["query"].split("|"):
            length = len(query.split(".", 1)[0])
            if length > 50:
                long_labels.append({**row, "query": query, "leftmost_label_length": length})
    top = sorted(tcp + udp, key=lambda row: (-row["bytes"], -row["packets"]))[:5]
    return {
        "pcap": str(capture), "packet_count": len(frames),
        "duration_seconds": float(max(times) - min(times)) if times else 0,
        "first_packet_epoch": str(min(times)) if times else None,
        "last_packet_epoch": str(max(times)) if times else None,
        "tcp_conversation_count": len(tcp), "udp_conversation_count": len(udp),
        "tcp_conversations": tcp[:10], "udp_conversations": udp[:10],
        "top_conversations": top, "dns_queries": dns, "http_requests": http,
        "tls_sni": tls, "file_transfers": transfers, "protocol_hierarchy": hierarchy,
        "protocol_distribution": distribution, "long_dns_labels": long_labels,
    }


try:
    report = investigate()
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=project,
                                     prefix=".pcap-findings-", delete=False) as stream:
        temporary = Path(stream.name)
        try:
            json.dump(report, stream, indent=2)
            stream.write("\n")
            stream.close()
            temporary.chmod(0o644)
            temporary.replace(project / "pcap_findings.json")
        finally:
            temporary.unlink(missing_ok=True)
except (OSError, ValueError, ArithmeticError, RuntimeError, StopIteration, KeyError) as error:
    parser.exit(1, f"PCAP investigation stopped: {error}\n")

print(f"[*] PCAP: {capture}")
print(f"[*] Duration: {report['duration_seconds']:.2f} s  Packets: {report['packet_count']:,}")
print("Top conversations by bytes:")
for row in report["top_conversations"]:
    print(f"  {row['endpoint_a']} <-> {row['endpoint_b']}  {row['protocol']}  "
          f"{row['packets']:,} packets  {row['bytes']:,} bytes")
print("Long DNS labels (>50 characters):")
for row in report["long_dns_labels"]:
    print(f"  {row['query']!r} ({row['leftmost_label_length']} characters)")
if not report["long_dns_labels"]:
    print("  None")
print("Saved pcap_findings.json")
PY

