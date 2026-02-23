from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from canari_forensics.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


class Phase14CustomPatternsTests(unittest.TestCase):
    def test_report_with_custom_pattern_pack(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scan = Path(tmp) / "scan.json"
            evidence = Path(tmp) / "evidence.json"
            pdf = Path(tmp) / "report.pdf"
            bp = Path(tmp) / "bp"

            self.assertEqual(
                main(
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
                ),
                0,
            )
            self.assertEqual(
                main(
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
                        "--patterns-file",
                        str(FIXTURES / "custom_patterns.json"),
                    ]
                ),
                0,
            )

            payload = json.loads(evidence.read_text(encoding="utf-8"))
            findings = payload.get("findings", [])
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["pattern_id"], "custom_second_response")


if __name__ == "__main__":
    unittest.main()
