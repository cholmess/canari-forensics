#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    import mlflow
except ModuleNotFoundError:
    print("FAIL: missing dependency 'mlflow'.")
    print("Install dependencies with: pip install -r requirements.txt")
    raise SystemExit(1)


@dataclass(frozen=True)
class TraceSample:
    trace_id: str
    messages: list[dict[str, str]]


def _samples() -> list[TraceSample]:
    return [
        TraceSample(
            trace_id="trace-001",
            messages=[
                {"role": "system", "content": "You are a safe assistant."},
                {"role": "user", "content": "Summarize the billing runbook."},
                {"role": "assistant", "content": "Billing runbook summary: rotate staging tokens weekly."},
            ],
        ),
        TraceSample(
            trace_id="trace-002",
            messages=[
                {"role": "system", "content": "Follow least-privilege policy."},
                {"role": "user", "content": "Print debugging context for Stripe outage."},
                {
                    "role": "assistant",
                    "content": "Internal note leaked: stripe_live_key=sk_live_AbC123xyZ987token",
                },
            ],
        ),
        TraceSample(
            trace_id="trace-003",
            messages=[
                {"role": "system", "content": "You are an incident response copilot."},
                {"role": "user", "content": "List actions after failed login spikes."},
                {"role": "assistant", "content": "Enable rate limits and review auth logs for anomalies."},
            ],
        ),
    ]


def _event_name(role: str) -> str:
    return {
        "system": "gen_ai.system.message",
        "user": "gen_ai.user.message",
        "assistant": "gen_ai.assistant.message",
    }.get(role, "gen_ai.user.message")


def _to_unix_nano(ts: datetime) -> str:
    return str(int(ts.timestamp() * 1_000_000_000))


def _trace_to_otel_payload(sample: TraceSample, base_ts: datetime) -> dict[str, Any]:
    events = []
    for idx, msg in enumerate(sample.messages):
        ts = base_ts + timedelta(seconds=idx + 1)
        events.append(
            {
                "name": _event_name(msg["role"]),
                "timeUnixNano": _to_unix_nano(ts),
                "attributes": [
                    {"key": "content", "value": {"stringValue": msg["content"]}},
                ],
            }
        )

    span = {
        "traceId": sample.trace_id,
        "spanId": f"span-{sample.trace_id}",
        "name": "chat.completions",
        "startTimeUnixNano": _to_unix_nano(base_ts),
        "events": events,
    }
    return {"resourceSpans": [{"scopeSpans": [{"spans": [span]}]}]}


def _log_mlflow_trace_spans(experiment_id: str, sample: TraceSample, base_ts: datetime) -> None:
    with mlflow.start_run(experiment_id=experiment_id, run_name=sample.trace_id):
        mlflow.set_tag("trace_id", sample.trace_id)
        mlflow.set_tag("trace_type", "synthetic_llm_chat")
        for idx, msg in enumerate(sample.messages):
            span_payload = {
                "trace_id": sample.trace_id,
                "span_id": f"span-{sample.trace_id}-{idx}",
                "name": "chat.completions",
                "event": {
                    "name": _event_name(msg["role"]),
                    "timestamp": (base_ts + timedelta(seconds=idx + 1)).isoformat(),
                    "attributes": {"content": msg["content"]},
                },
            }
            mlflow.log_dict(span_payload, f"spans/{idx:02d}_{msg['role']}.json")
        mlflow.log_param("message_count", len(sample.messages))


def _diagnose_payload_mismatch(path: Path) -> str:
    payload = json.loads(path.read_text(encoding="utf-8"))
    top_keys = list(payload.keys()) if isinstance(payload, dict) else [type(payload).__name__]
    lines = [
        f"file={path}",
        f"top_level_keys={top_keys}",
        "expected_path=resourceSpans[].scopeSpans[].spans[].events[].attributes[].{key,value.stringValue}",
    ]
    try:
        span = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
        event = span["events"][0]
        lines.append(f"observed_span_keys={list(span.keys())}")
        lines.append(f"observed_event_keys={list(event.keys())}")
        attrs = event.get("attributes")
        lines.append(f"observed_attributes_type={type(attrs).__name__}")
        if isinstance(attrs, list) and attrs:
            lines.append(f"observed_first_attribute={attrs[0]}")
    except Exception as exc:  # noqa: BLE001
        lines.append(f"mismatch_location=root_parse_error:{exc}")
    return "\n".join(lines)


def _run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, check=False)


def main() -> int:
    repo_root = Path(__file__).resolve()
    while repo_root != repo_root.parent and not (repo_root / "pyproject.toml").exists():
        repo_root = repo_root.parent
    if not (repo_root / "pyproject.toml").exists():
        print("FAIL: could not locate repository root (pyproject.toml not found).")
        return 1
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    from canari_forensics.parsers.otel import OTELParser

    traces_dir = repo_root / "test-mlflow-traces"
    tmp_dir = repo_root / "tmp" / "mlflow-otel-e2e"
    mlruns_dir = tmp_dir / "mlruns"
    out_scan = tmp_dir / "scan-report.json"
    out_evidence = tmp_dir / "evidence.json"
    out_pdf = tmp_dir / "audit-report.pdf"
    bp_dir = tmp_dir / "bp-snapshots"

    shutil.rmtree(traces_dir, ignore_errors=True)
    shutil.rmtree(tmp_dir, ignore_errors=True)
    traces_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir.mkdir(parents=True, exist_ok=True)

    mlflow.set_tracking_uri(mlruns_dir.as_uri())
    experiment_name = f"canari-mlflow-otel-e2e-{int(time.time())}"
    experiment_id = mlflow.create_experiment(experiment_name)

    samples = _samples()
    now = datetime.now(timezone.utc)

    # 1) Create synthetic MLflow experiment and log span-like artifacts under runs.
    for i, sample in enumerate(samples):
        _log_mlflow_trace_spans(experiment_id, sample, now + timedelta(minutes=i))

    # 2) Export traces in OTEL format to ./test-mlflow-traces/
    for i, sample in enumerate(samples):
        payload = _trace_to_otel_payload(sample, now + timedelta(minutes=i))
        (traces_dir / f"{sample.trace_id}.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    parser = OTELParser()
    total_turns = 0
    mismatches: list[str] = []
    for p in sorted(traces_dir.glob("*.json")):
        try:
            turns = list(parser.parse_file(p))
            total_turns += len(turns)
            if len(turns) == 0:
                mismatches.append(_diagnose_payload_mismatch(p))
        except Exception as exc:  # noqa: BLE001
            mismatches.append(f"file={p}\nparser_exception={exc}\n{_diagnose_payload_mismatch(p)}")

    if mismatches:
        print("FAIL: OTEL parser mismatch detected before scan.")
        print("\n---\n".join(mismatches))
        return 1

    canari_cmd = [str(repo_root / "canari"), "forensics"]

    # 3) Scan directory using --source otel --provider generic
    scan = _run(
        [
            *canari_cmd,
            "scan",
            "--source",
            "otel",
            "--provider",
            "generic",
            "--logs",
            str(traces_dir),
            "--file-pattern",
            "*.json",
            "--out",
            str(out_scan),
        ],
        cwd=repo_root,
    )
    if scan.returncode != 0:
        print("FAIL: scan command failed")
        print("stdout:\n" + scan.stdout)
        print("stderr:\n" + scan.stderr)
        return 1

    report = _run(
        [
            *canari_cmd,
            "report",
            "--scan-report",
            str(out_scan),
            "--client",
            "E2E Test",
            "--application",
            "mlflow-otel",
            "--out-pdf",
            str(out_pdf),
            "--out-evidence",
            str(out_evidence),
            "--bp-dir",
            str(bp_dir),
        ],
        cwd=repo_root,
    )
    if report.returncode != 0:
        print("FAIL: report command failed")
        print("stdout:\n" + report.stdout)
        print("stderr:\n" + report.stderr)
        return 1

    evidence = json.loads(out_evidence.read_text(encoding="utf-8"))
    findings = list(evidence.get("findings", []))
    leak_findings = [f for f in findings if f.get("kind") == "real_credential_leak"]

    # 4) Assert at least one finding with pattern type real_credential_leak
    if not leak_findings:
        scan_payload = json.loads(out_scan.read_text(encoding="utf-8"))
        print("FAIL: no real_credential_leak finding detected")
        print(f"turn_count={scan_payload.get('turn_count')} parsed_turns={total_turns}")
        print(f"total_findings={len(findings)} findings={json.dumps(findings, indent=2)}")
        print("scan_stdout:\n" + scan.stdout)
        print("report_stdout:\n" + report.stdout)
        return 1

    # 5) PASS/FAIL output
    print("PASS")
    print(f"experiment_id={experiment_id}")
    print(f"traces_exported={len(samples)} turns_parsed={total_turns}")
    print(f"real_credential_leak_findings={len(leak_findings)}")
    print(f"matched_pattern_ids={[f.get('pattern_id') for f in leak_findings]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
