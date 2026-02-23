from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from canari_forensics.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


class Phase3ReportingTests(unittest.TestCase):
    def test_report_generates_pdf_evidence_and_bp_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scan_report = Path(tmp) / "scan.json"
            evidence = Path(tmp) / "evidence.json"
            pdf = Path(tmp) / "audit.pdf"
            bp_dir = Path(tmp) / "bp"

            scan_rc = main(
                [
                    "forensics",
                    "scan",
                    "--source",
                    "otel",
                    "--logs",
                    str(FIXTURES / "otlp_sample.json"),
                    "--out",
                    str(scan_report),
                ]
            )
            self.assertEqual(scan_rc, 0)

            report_rc = main(
                [
                    "forensics",
                    "report",
                    "--scan-report",
                    str(scan_report),
                    "--client",
                    "Acme Corp",
                    "--application",
                    "AI Gateway",
                    "--out-pdf",
                    str(pdf),
                    "--out-evidence",
                    str(evidence),
                    "--bp-dir",
                    str(bp_dir),
                ]
            )
            self.assertEqual(report_rc, 0)
            self.assertTrue(pdf.exists())
            self.assertGreater(pdf.stat().st_size, 100)
            self.assertTrue(evidence.exists())

            payload = json.loads(evidence.read_text(encoding="utf-8"))
            self.assertEqual(payload["client"], "Acme Corp")
            self.assertGreaterEqual(len(payload["findings"]), 1)

            bp_files = sorted(bp_dir.glob("*.bp.json"))
            self.assertGreaterEqual(len(bp_files), 1)
            sample_bp = json.loads(bp_files[0].read_text(encoding="utf-8"))
            self.assertIn("expected", sample_bp)


if __name__ == "__main__":
    unittest.main()
