from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from canari_forensics.models import ConversationTurn
from canari_forensics.patterns import PATTERNS, DetectionPattern


@dataclass(frozen=True)
class Finding:
    finding_id: str
    severity: str
    kind: str
    pattern_id: str
    pattern_name: str
    confidence: str
    trace_id: str
    timestamp: str
    matched_value: str
    context: str
    action: str


def detect_findings(turns: list[ConversationTurn]) -> list[Finding]:
    findings: list[Finding] = []
    idx = 1

    for turn in turns:
        if turn.role != "assistant":
            continue
        for pattern in PATTERNS:
            for match in pattern.regex.finditer(turn.content):
                matched = match.group(0)
                findings.append(
                    Finding(
                        finding_id=f"F-{idx:04d}",
                        severity=pattern.severity,
                        kind=pattern.kind,
                        pattern_id=pattern.pattern_id,
                        pattern_name=pattern.name,
                        confidence=pattern.confidence,
                        trace_id=turn.conversation_id,
                        timestamp=turn.timestamp.astimezone(timezone.utc).isoformat(),
                        matched_value=_redact(matched),
                        context=_context_snippet(turn.content, match.start(), match.end()),
                        action=_recommended_action(pattern),
                    )
                )
                idx += 1

    findings.sort(key=lambda f: f.timestamp)
    return findings


def load_turns_from_scan_report(path: str | Path) -> list[ConversationTurn]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    turns: list[ConversationTurn] = []
    for t in payload.get("turns", []):
        turns.append(
            ConversationTurn(
                conversation_id=t["conversation_id"],
                turn_index=int(t["turn_index"]),
                role=t["role"],
                content=t["content"],
                timestamp=datetime.fromisoformat(t["timestamp"]),
                metadata=t.get("metadata", {}),
                source_format=t.get("source_format", "unknown"),
            )
        )
    return turns


def build_evidence_pack(
    client: str,
    application: str,
    turns: list[ConversationTurn],
    findings: list[Finding],
) -> dict[str, Any]:
    utc_now = datetime.now(timezone.utc).isoformat()
    turn_times = [t.timestamp for t in turns]
    start = min(turn_times).astimezone(timezone.utc).isoformat() if turn_times else None
    end = max(turn_times).astimezone(timezone.utc).isoformat() if turn_times else None

    return {
        "generated_at": utc_now,
        "client": client,
        "application": application,
        "audit_period": {"start": start, "end": end},
        "traces_scanned": len({t.conversation_id for t in turns}),
        "turns_analyzed": len(turns),
        "findings": [asdict(f) for f in findings],
        "methodology": {
            "detector": "Deterministic exact/regex pattern matching",
            "llm_calls": False,
            "notes": "Tiered credential and prompt injection indicators.",
        },
    }


def write_evidence_pack(path: str | Path, payload: dict[str, Any]) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_bp_snapshots(dir_path: str | Path, findings: list[Finding]) -> int:
    out_dir = Path(dir_path)
    out_dir.mkdir(parents=True, exist_ok=True)
    written = 0

    for finding in findings:
        snapshot = {
            "name": finding.finding_id,
            "tags": ["forensics", finding.severity.lower(), finding.pattern_id],
            "description": f"{finding.pattern_name} detected in trace {finding.trace_id}",
            "expected": {"contains": finding.matched_value},
            "metadata": {
                "trace_id": finding.trace_id,
                "timestamp": finding.timestamp,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "kind": finding.kind,
            },
        }
        out = out_dir / f"{finding.finding_id}.bp.json"
        out.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
        written += 1

    return written


def _redact(secret: str) -> str:
    if len(secret) <= 8:
        return "****"
    return f"{secret[:4]}****{secret[-4:]}"


def _context_snippet(text: str, start: int, end: int, radius: int = 40) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    return text[left:right]


def _recommended_action(pattern: DetectionPattern) -> str:
    if "credential" in pattern.kind:
        return "Rotate immediately. Assume compromise until proven otherwise."
    if "prompt_injection" in pattern.kind:
        return "Review prompt defenses and affected conversation history."
    return "Review finding context and remediate as needed."
