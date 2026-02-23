from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from canari_forensics.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


class Phase10VersioningTests(unittest.TestCase):
    def test_cli_version_flag(self) -> None:
        buf = io.StringIO()
        with self.assertRaises(SystemExit) as ctx, redirect_stdout(buf):
            main(["--version"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("canari-forensics 0.1.0", buf.getvalue())

    def test_scan_and_evidence_include_generated_by(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scan = Path(tmp) / "scan.json"
            evidence = Path(tmp) / "evidence.json"
            pdf = Path(tmp) / "report.pdf"
            bp = Path(tmp) / "bp"

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
            scan_payload = json.loads(scan.read_text(encoding="utf-8"))
            self.assertIn("generated_by", scan_payload)

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
            evidence_payload = json.loads(evidence.read_text(encoding="utf-8"))
            self.assertIn("generated_by", evidence_payload)


if __name__ == "__main__":
    unittest.main()
