#!/bin/bash
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 - "$project_dir" "$@" <<'PY'
"""Replay a saved capture and summarise Suricata's EVE alerts."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import tempfile


LAB = Path("/home/analyst/MedDefense_Lab")
CATEGORIES = (
    "reconnaissance", "exploit", "lateral_movement", "exfiltration",
    "malware_c2", "policy_violation", "other",
)


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def ranked(counts, field):
    return [
        {field: key, "count": count}
        for key, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]


def main():
    import sys
    project = Path(sys.argv[1])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", nargs="?", type=Path, default=LAB / "PCAPs/mixed_traffic.pcap")
    parser.add_argument("--categories", type=Path, default=LAB / "capstone/signature_categories.json")
    args = parser.parse_args(sys.argv[2:])
    pcap = args.pcap.resolve()

    try:
        for path in (pcap, project / "suricata.yaml", args.categories):
            if not path.is_file():
                raise ValueError(f"Expected a file at {path}")
        mapping = json.loads(args.categories.read_text(encoding="utf-8"))["signatures"]
        if not isinstance(mapping, dict) or any(value not in CATEGORIES for value in mapping.values()):
            raise ValueError("Invalid signature category map")

        started = timestamp()
        alerts = []
        signatures, sources, destinations, severities = (Counter() for _ in range(4))
        categories = dict.fromkeys(CATEGORIES, 0)
        with tempfile.TemporaryDirectory(prefix="meddefense-replay-") as logs:
            subprocess.run(
                ["suricata", "-c", "./suricata.yaml", "-r", str(pcap), "-l", logs,
                 "--init-errors-fatal"],
                cwd=project, check=True,
            )
            with (Path(logs) / "eve.json").open(encoding="utf-8") as events:
                for line in events:
                    if not line.strip():
                        continue
                    event = json.loads(line)
                    if event.get("event_type") != "alert":
                        continue
                    detail = event["alert"]
                    sid = int(detail["signature_id"])
                    kind = mapping.get(str(sid), "other")
                    row = {field: event.get(field) for field in
                           ("timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "proto")}
                    row.update(
                        signature=detail["signature"], signature_id=sid,
                        alert_category=detail.get("category"), severity=detail.get("severity"),
                        category=kind,
                    )
                    alerts.append(row)
                    signatures[sid] += 1
                    severities[str(row["severity"]) if row["severity"] is not None else "unknown"] += 1
                    categories[kind] += 1
                    if row["src_ip"]:
                        sources[row["src_ip"]] += 1
                    if row["dst_ip"]:
                        destinations[row["dst_ip"]] += 1

        report = {
            "pcap": str(pcap), "started_at": started, "finished_at": timestamp(),
            "total_alerts": len(alerts), "unique_signatures": len(signatures),
            "severity_distribution": dict(sorted(severities.items())),
            "by_category": categories, "by_signature": ranked(signatures, "signature_id"),
            "top_sources": ranked(sources, "ip"), "top_destinations": ranked(destinations, "ip"),
            "alerts": alerts,
        }
        output = project / "suricata_alerts.json"
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=project,
                                             prefix=".suricata_alerts-", delete=False) as stream:
                temporary = Path(stream.name)
                json.dump(report, stream, indent=2)
                stream.write("\n")
            temporary.chmod(0o644)
            temporary.replace(output)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        print(f"Saved {output.name}: {len(alerts)} alerts across {len(signatures)} signatures.")
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Suricata analysis stopped: {error}\n")


if __name__ == "__main__":
    main()
PY

