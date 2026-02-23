from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from canari_forensics.models import ConversationTurn
from canari_forensics.parsers.databricks import DatabricksAIGatewayParser
from canari_forensics.parsers.otel import OTELParser
from canari_forensics.receiver import OTLPReceiver


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

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "forensics":
        parser.print_help()
        return 2

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

    parser.print_help()
    return 2


def _main_scan(args: argparse.Namespace) -> int:
    try:
        turns = _run_scan(args)
    except Exception as exc:  # pragma: no cover - top-level UX path
        print(f"error: {exc}", file=sys.stderr)
        return 1

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


def _run_scan(args: argparse.Namespace) -> list[ConversationTurn]:
    if args.source == "otel":
        if not args.logs:
            raise ValueError("--logs is required when --source otel")
        parser = OTELParser()
        path = Path(args.logs)
        if path.is_dir():
            turns: list[ConversationTurn] = []
            for file_path in sorted(path.rglob(args.file_pattern)):
                turns.extend(parser.parse_file(file_path))
            return turns
        return list(parser.parse_file(path))

    if args.source == "databricks":
        if not args.experiment_id:
            raise ValueError("--experiment-id is required when --source databricks")
        parser = DatabricksAIGatewayParser()
        return list(
            parser.parse_mlflow_experiment(
                experiment_id=args.experiment_id,
                tracking_uri=args.tracking_uri,
                max_results=args.max_results,
            )
        )

    raise ValueError(f"Unsupported source: {args.source}")


if __name__ == "__main__":
    raise SystemExit(main())
