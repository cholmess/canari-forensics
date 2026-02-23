from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from canari_forensics.cli import main
from canari_forensics.receiver import OTLPReceiver
from canari_forensics.storage import SQLiteTurnStore

FIXTURES = Path(__file__).parent / "fixtures"


class Phase2SourcesAndReceiverTests(unittest.TestCase):
    def test_scan_otel_generic_provider_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.json"
            rc = main(
                [
                    "forensics",
                    "scan",
                    "--source",
                    "otel",
                    "--provider",
                    "generic",
                    "--logs",
                    str(FIXTURES),
                    "--file-pattern",
                    "otlp_sample.json",
                    "--out",
                    str(out),
                ]
            )
            self.assertEqual(rc, 0)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["provider"], "generic")
            self.assertEqual(payload["turn_count"], 3)

    def test_scan_otel_datadog_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report-datadog.json"
            rc = main(
                [
                    "forensics",
                    "scan",
                    "--source",
                    "otel",
                    "--provider",
                    "datadog",
                    "--logs",
                    str(FIXTURES / "otlp_sample.json"),
                    "--out",
                    str(out),
                ]
            )
            self.assertEqual(rc, 0)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["provider"], "datadog")
            self.assertEqual(payload["assistant_turn_count"], 2)

    def test_receiver_ingests_otlp_and_persists_sqlite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "forensics.db")
            receiver = OTLPReceiver(host="127.0.0.1", port=43189, db_path=db_path)
            payload = (FIXTURES / "otlp_sample.json").read_text(encoding="utf-8")

            inserted = receiver.ingest_payload(payload)
            self.assertEqual(inserted, 3)

            store = SQLiteTurnStore(db_path)
            self.assertEqual(store.count_turns(), 3)


if __name__ == "__main__":
    unittest.main()
