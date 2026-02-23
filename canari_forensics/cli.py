from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from canari_forensics.audit import AuditManager
from canari_forensics.config import load_simple_yaml
from canari_forensics.errors import CanariError, ConfigError, InputError, NotFoundError, UsageError
from canari_forensics.models import ConversationTurn
from canari_forensics.parsers.databricks import DatabricksAIGatewayParser
from canari_forensics.parsers.otel import OTELParser
from canari_forensics.pdf import SimplePDF
from canari_forensics.receiver import OTLPReceiver
from canari_forensics.reporting import (
    build_evidence_pack,
    detect_findings,
    load_turns_from_scan_report,
    write_bp_snapshots,
    write_evidence_pack,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="canari", description="Canari Forensics CLI")
    sub = parser.add_subparsers(dest="command")

    forensics = sub.add_parser("forensics", help="Forensics operations")
    forensics_sub = forensics.add_subparsers(dest="forensics_command")

    scan = forensics_sub.add_parser("scan", help="Scan traces")
    scan.add_argument("--source", choices=["otel", "databricks"], required=True)
    scan.add_argument("--out", required=True)
    scan.add_argument("--provider", default="generic", choices=["generic", "datadog", "honeycomb", "databricks"])
    scan.add_argument("--logs", help="Path to OTEL log JSON file or directory")
    scan.add_argument("--format", default="otlp-json", choices=["otlp-json", "mlflow"])
    scan.add_argument("--file-pattern", default="*.json", help="Glob pattern for OTEL files")
    scan.add_argument("--experiment-id", help="MLflow/Databricks experiment ID")
    scan.add_argument("--tracking-uri", default="databricks")
    scan.add_argument("--max-results", type=int, default=1000)

    receive = forensics_sub.add_parser("receive", help="Run OTLP receiver")
    receive.add_argument("--host", default="0.0.0.0")
    receive.add_argument("--port", type=int, default=4318)
    receive.add_argument("--db", required=True)

    report = forensics_sub.add_parser("report", help="Generate enterprise audit report")
    report.add_argument("--scan-report", required=True, help="Path to scan JSON output")
    report.add_argument("--client", required=True)
    report.add_argument("--application", required=True)
    report.add_argument("--out-pdf", required=True)
    report.add_argument("--out-evidence", required=True)
    report.add_argument("--bp-dir", required=True)

    audit = forensics_sub.add_parser("audit", help="Manage staged audits")
    audit_sub = audit.add_subparsers(dest="audit_command")

    audit_init = audit_sub.add_parser("init", help="Initialize an audit workspace")
    audit_init.add_argument("--name", required=True)
    audit_init.add_argument("--source", choices=["otel", "databricks"], required=True)
    audit_init.add_argument("--provider", default="generic", choices=["generic", "datadog", "honeycomb", "databricks"])
    audit_init.add_argument("--logs")
    audit_init.add_argument("--experiment-id")
    audit_init.add_argument("--tracking-uri", default="databricks")
    audit_init.add_argument("--client", required=True)
    audit_init.add_argument("--application", required=True)

    audit_scan = audit_sub.add_parser("scan", help="Run scan for a saved audit")
    audit_scan.add_argument("--audit-id", required=True)
    audit_scan.add_argument("--file-pattern", default="*.json")
    audit_scan.add_argument("--max-results", type=int, default=1000)

    audit_report = audit_sub.add_parser("report", help="Generate report for a saved audit")
    audit_report.add_argument("--audit-id", required=True)

    audit_run = audit_sub.add_parser("run", help="Run init+scan+report from config")
    audit_run.add_argument("--config", default=".canari.yml")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command != "forensics":
            raise UsageError("Missing command. Use: canari forensics ...")

        if args.forensics_command == "scan":
            return _main_scan(args)

        if args.forensics_command == "receive":
            receiver = OTLPReceiver(host=args.host, port=args.port, db_path=args.db)
            print(f"Canari OTLP receiver listening on http://{args.host}:{args.port}/v1/traces")
            try:
                receiver.serve_forever()
            except KeyboardInterrupt:  # pragma: no cover
                pass
            return 0

        if args.forensics_command == "report":
            return _main_report(args)

        if args.forensics_command == "audit":
            return _main_audit(args)

        raise UsageError("Missing subcommand. Use: canari forensics <scan|report|receive|audit>")

    except CanariError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code


def _main_audit(args: argparse.Namespace) -> int:
    mgr = AuditManager()

    if args.audit_command == "init":
        paths = mgr.init_audit(
            name=args.name,
            source=args.source,
            provider=args.provider,
            logs=args.logs,
            experiment_id=args.experiment_id,
            tracking_uri=args.tracking_uri,
            client=args.client,
            application=args.application,
        )
        print(f"Audit initialized: {paths.root}")
        return 0

    if args.audit_command == "scan":
        try:
            meta = mgr.load_metadata(args.audit_id)
        except FileNotFoundError as exc:
            raise NotFoundError(str(exc)) from exc

        scan_args = argparse.Namespace(
            source=meta["source"],
            provider=meta.get("provider", "generic"),
            format="otlp-json",
            logs=meta.get("logs"),
            experiment_id=meta.get("experiment_id"),
            tracking_uri=meta.get("tracking_uri", "databricks"),
            max_results=args.max_results,
            file_pattern=args.file_pattern,
            out=meta["scan_report"],
        )
        return _main_scan(scan_args)

    if args.audit_command == "report":
        try:
            meta = mgr.load_metadata(args.audit_id)
        except FileNotFoundError as exc:
            raise NotFoundError(str(exc)) from exc

        report_args = argparse.Namespace(
            scan_report=meta["scan_report"],
            client=meta["client"],
            application=meta["application"],
            out_pdf=meta["pdf"],
            out_evidence=meta["evidence"],
            bp_dir=meta["bp_dir"],
        )
        return _main_report(report_args)

    if args.audit_command == "run":
        return _audit_run_from_config(args.config, mgr)

    raise UsageError("Missing audit subcommand. Use: canari forensics audit <init|scan|report|run>")


def _audit_run_from_config(config_path: str, mgr: AuditManager) -> int:
    cfg = load_simple_yaml(config_path)
    fcfg = cfg.get("forensics", {})
    if not isinstance(fcfg, dict):
        raise ConfigError("Config key 'forensics' must be a mapping")

    name = str(fcfg.get("audit_name", "Canari Audit"))
    source = str(fcfg.get("source", "otel"))
    provider = str(fcfg.get("provider", "generic"))
    logs = fcfg.get("logs")
    experiment_id = fcfg.get("experiment_id")
    tracking_uri = str(fcfg.get("tracking_uri", "databricks"))
    client = str(fcfg.get("client", "Unknown Client"))
    application = str(fcfg.get("application", "Unknown Application"))
    file_pattern = str(fcfg.get("file_pattern", "*.json"))
    max_results = int(fcfg.get("max_results", 1000))

    paths = mgr.init_audit(
        name=name,
        source=source,
        provider=provider,
        logs=str(logs) if logs else None,
        experiment_id=str(experiment_id) if experiment_id else None,
        tracking_uri=tracking_uri,
        client=client,
        application=application,
    )
    audit_id = paths.root.name

    scan_rc = _main_audit(
        argparse.Namespace(
            audit_command="scan",
            audit_id=audit_id,
            file_pattern=file_pattern,
            max_results=max_results,
        )
    )
    if scan_rc != 0:
        return scan_rc

    report_rc = _main_audit(argparse.Namespace(audit_command="report", audit_id=audit_id))
    if report_rc != 0:
        return report_rc

    print(f"Audit run complete: {paths.root}")
    return 0


def _main_scan(args: argparse.Namespace) -> int:
    import json

    turns = _run_scan(args)

    payload = {
        "source": args.source,
        "provider": args.provider,
        "format": args.format,
        "turn_count": len(turns),
        "assistant_turn_count": sum(1 for t in turns if t.role == "assistant"),
        "conversations": len({t.conversation_id for t in turns}),
        "turns": [
            {
                "conversation_id": t.conversation_id,
                "turn_index": t.turn_index,
                "role": t.role,
                "content": t.content,
                "timestamp": t.timestamp.isoformat(),
                "metadata": t.metadata,
                "source_format": t.source_format,
            }
            for t in turns
        ],
    }

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(
        f"Scanned {payload['turn_count']} turns across {payload['conversations']} conversations. "
        f"Report: {out}"
    )
    return 0


def _main_report(args: argparse.Namespace) -> int:
    try:
        turns = load_turns_from_scan_report(args.scan_report)
    except FileNotFoundError as exc:
        raise NotFoundError(f"Scan report not found: {args.scan_report}") from exc

    findings = detect_findings(turns)
    evidence = build_evidence_pack(args.client, args.application, turns, findings)
    write_evidence_pack(args.out_evidence, evidence)
    snapshots = write_bp_snapshots(args.bp_dir, findings)

    lines = _build_pdf_lines(args.client, args.application, turns, findings, snapshots)
    SimplePDF().write(args.out_pdf, lines)

    print(
        f"Report generated. findings={len(findings)} evidence={args.out_evidence} "
        f"pdf={args.out_pdf} bp_snapshots={snapshots}"
    )
    return 0


def _build_pdf_lines(
    client: str,
    application: str,
    turns: list[ConversationTurn],
    findings: list,
    snapshots: int,
) -> list[str]:
    severities = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
    overall = "LOW"
    if findings:
        overall = max((f.severity for f in findings), key=lambda s: severities.get(s, 0))

    lines = [
        "CANARI FORENSICS - LLM SECURITY AUDIT REPORT",
        f"Client: {client}",
        f"Application: {application}",
        f"Traces scanned: {len({t.conversation_id for t in turns})}",
        f"Turns analyzed: {len(turns)}",
        f"Findings: {len(findings)}",
        f"Overall Risk: {overall}",
        f"BreakPoint snapshots: {snapshots}",
        "",
        "FINDINGS",
    ]

    if not findings:
        lines.append("No findings detected.")
        return lines

    for f in findings[:20]:
        lines.extend(
            [
                f"{f.finding_id} [{f.severity}] {f.pattern_name}",
                f"Trace: {f.trace_id}",
                f"Timestamp: {f.timestamp}",
                f"Value: {f.matched_value}",
                f"Action: {f.action}",
                "",
            ]
        )
    return lines


def _run_scan(args: argparse.Namespace) -> list[ConversationTurn]:
    if args.source == "otel":
        if not args.logs:
            raise InputError("--logs is required when --source otel")
        parser = OTELParser()
        path = Path(args.logs)
        if not path.exists():
            raise NotFoundError(f"Logs path not found: {path}")
        if path.is_dir():
            turns: list[ConversationTurn] = []
            for file_path in sorted(path.rglob(args.file_pattern)):
                turns.extend(parser.parse_file(file_path))
            return turns
        return list(parser.parse_file(path))

    if args.source == "databricks":
        if not args.experiment_id:
            raise InputError("--experiment-id is required when --source databricks")
        parser = DatabricksAIGatewayParser()
        try:
            return list(
                parser.parse_mlflow_experiment(
                    experiment_id=args.experiment_id,
                    tracking_uri=args.tracking_uri,
                    max_results=args.max_results,
                )
            )
        except RuntimeError as exc:
            raise InputError(str(exc)) from exc

    raise UsageError(f"Unsupported source: {args.source}")


if __name__ == "__main__":
    raise SystemExit(main())
