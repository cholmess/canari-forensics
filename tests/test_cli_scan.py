from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from canari_forensics.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


class CLIScanTests(unittest.TestCase):
    def test_scan_otel_file_writes_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.json"
            rc = main(
                [
                    "forensics",
                    "scan",
                    "--source",
                    "otel",
                    "--logs",
                    str(FIXTURES / "otlp_sample.json"),
                    "--out",
                    str(out),
                ]
            )
            self.assertEqual(rc, 0)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["source"], "otel")
            self.assertEqual(payload["turn_count"], 3)

    def test_scan_databricks_requires_experiment_id(self) -> None:
        rc = main(["forensics", "scan", "--source", "databricks", "--out", "x.json"])
        self.assertEqual(rc, 3)

    def test_scan_databricks_with_mocked_parser(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "db-report.json"

            fake_turns = [
                {
                    "conversation_id": "c1",
                    "turn_index": 0,
                    "role": "assistant",
                    "content": "leak",
                    "timestamp": "2026-02-22T14:29:00+00:00",
                    "metadata": {"span_id": "s1"},
                    "source_format": "databricks",
                }
            ]

            from canari_forensics.models import ConversationTurn
            from datetime import datetime, timezone

            mocked = [
                ConversationTurn(
                    conversation_id="c1",
                    turn_index=0,
                    role="assistant",
                    content="leak",
                    timestamp=datetime(2026, 2, 22, 14, 29, 0, tzinfo=timezone.utc),
                    metadata={"span_id": "s1"},
                    source_format="databricks",
                )
            ]

            with patch(
                "canari_forensics.parsers.databricks.DatabricksAIGatewayParser.parse_mlflow_experiment",
                return_value=iter(mocked),
            ):
                rc = main(
                    [
                        "forensics",
                        "scan",
                        "--source",
                        "databricks",
                        "--experiment-id",
                        "123",
                        "--out",
                        str(out),
                    ]
                )

            self.assertEqual(rc, 0)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["source"], "databricks")
            self.assertEqual(payload["turn_count"], 1)
            self.assertEqual(payload["turns"][0]["content"], fake_turns[0]["content"])


if __name__ == "__main__":
    unittest.main()
