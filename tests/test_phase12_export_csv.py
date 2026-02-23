from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from canari_forensics.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


class Phase12ExportCSVTests(unittest.TestCase):
    def test_export_findings_csv_from_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scan = Path(tmp) / "scan.json"
            evidence = Path(tmp) / "evidence.json"
            pdf = Path(tmp) / "report.pdf"
            bp = Path(tmp) / "bp"
            out_csv = Path(tmp) / "findings.csv"

            rc_scan = main(
                [
                    "forensics",
                    "scan",
                    "--source",
                    "otel",
                    "--logs",
                    str(FIXTURES / "otlp_sample.json"),
                    "--out",
                    str(scan),
                ]
            )
            self.assertEqual(rc_scan, 0)

            rc_report = main(
                [
                    "forensics",
                    "report",
                    "--scan-report",
                    str(scan),
                    "--client",
                    "Acme",
                    "--application",
                    "App",
                    "--out-pdf",
                    str(pdf),
                    "--out-evidence",
                    str(evidence),
                    "--bp-dir",
                    str(bp),
                ]
            )
            self.assertEqual(rc_report, 0)

            rc_export = main(
                [
                    "forensics",
                    "export",
                    "--from-evidence",
                    str(evidence),
                    "--out-csv",
                    str(out_csv),
                ]
            )
            self.assertEqual(rc_export, 0)
            self.assertTrue(out_csv.exists())

            with out_csv.open("r", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            evidence_payload = json.loads(evidence.read_text(encoding="utf-8"))
            self.assertEqual(len(rows), len(evidence_payload.get("findings", [])))


if __name__ == "__main__":
    unittest.main()
