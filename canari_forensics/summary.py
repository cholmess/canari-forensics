from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any


def summarize_evidence(path: str | Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    findings = list(payload.get("findings", []))

    sev_counts = Counter(str(f.get("severity", "UNKNOWN")) for f in findings)
    overall = "LOW"
    if sev_counts.get("CRITICAL", 0) > 0:
        overall = "CRITICAL"
    elif sev_counts.get("HIGH", 0) > 0:
        overall = "HIGH"
    elif sev_counts.get("MEDIUM", 0) > 0:
        overall = "MEDIUM"

    top_findings = findings[:5]

    return {
        "client": payload.get("client"),
        "application": payload.get("application"),
        "overall_risk": overall,
        "findings_count": len(findings),
        "severity_counts": dict(sev_counts),
        "top_findings": [
            {
                "finding_id": f.get("finding_id"),
                "severity": f.get("severity"),
                "pattern_name": f.get("pattern_name"),
                "trace_id": f.get("trace_id"),
                "timestamp": f.get("timestamp"),
            }
            for f in top_findings
        ],
    }
