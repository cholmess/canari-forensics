from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


def export_findings_csv(evidence_path: str | Path, out_csv: str | Path) -> int:
    evidence = json.loads(Path(evidence_path).read_text(encoding="utf-8"))
    findings: list[dict[str, Any]] = list(evidence.get("findings", []))

    out = Path(out_csv)
    out.parent.mkdir(parents=True, exist_ok=True)

    fields = [
        "finding_id",
        "severity",
        "kind",
        "pattern_id",
        "pattern_name",
        "confidence",
        "trace_id",
        "timestamp",
        "matched_value",
        "context",
        "action",
    ]

    with out.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for finding in findings:
            row = {k: finding.get(k, "") for k in fields}
            writer.writerow(row)

    return len(findings)
