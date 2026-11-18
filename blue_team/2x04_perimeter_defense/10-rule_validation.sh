#!/bin/bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
exec python3 - "$@" <<'PY'
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser(description="Validate MedDefense alerts against offline captures.")
parser.add_argument("labels", nargs="?", type=Path,
                    default=Path("/home/analyst/MedDefense_Lab/PCAPs/labels"))
args = parser.parse_args()
cases = [
    (9000001, "meddev_egress.pcap", True),
    (9000002, "guest_smb.pcap", True),
    (9000003, "large_outbound.pcap", True),
    (9000004, "dns_tunnel.pcap", True),
    (9000005, "clinical_wrong_db.pcap", True),
    (9000006, "telnet_meddev.pcap", True),
    # This supplied capture has TCP egress and allowed UDP/123 only.
    (9000007, "meddev_egress.pcap", False),
]
results = []
for sid, name, should_fire in cases:
    capture = (args.labels / name).resolve()
    row = {"sid": sid, "pcap": str(capture),
           "expected": "fire" if should_fire else "no alert", "hits": None, "passed": False}
    try:
        if not capture.is_file():
            raise FileNotFoundError(capture)
        with tempfile.TemporaryDirectory(prefix="meddefense-validation-") as logs:
            run = subprocess.run(
                ["suricata", "-c", "./suricata.yaml", "-S", "./meddefense.rules",
                 "-r", str(capture), "-l", logs, "--init-errors-fatal"],
                capture_output=True, text=True, check=False,
            )
            row["exit_code"] = run.returncode
            if run.returncode:
                raise RuntimeError((run.stdout + run.stderr).strip())
            with (Path(logs) / "eve.json").open(encoding="utf-8") as events:
                hits = 0
                for line in events:
                    if line.strip():
                        event = json.loads(line)
                        if event.get("event_type") == "alert" and event["alert"]["signature_id"] == sid:
                            hits += 1
            row["hits"] = hits
            row["passed"] = (hits > 0) == should_fire
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        row["error"] = str(error)
    results.append(row)
    print(f"{sid} {name}: expected {row['expected']}, hits={row['hits']} "
          f"[{'PASS' if row['passed'] else 'FAIL'}]")
    if "error" in row:
        print(row["error"], file=sys.stderr)

passed = sum(row["passed"] for row in results)
report = {"rules": len(cases), "passed": passed, "failed": len(cases) - passed,
          "results": results}
Path("rule_validation.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(f"Passed: {passed}; failed: {report['failed']}")
sys.exit(int(report["failed"] != 0))
PY

