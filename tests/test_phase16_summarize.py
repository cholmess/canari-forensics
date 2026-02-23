from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from canari_forensics.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


class Phase16SummarizeTests(unittest.TestCase):
    def test_summarize_text_and_json(self) -> None:
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
                    ]
                ),
                0,
            )

            with patch("builtins.print") as p:
                rc = main(["forensics", "summarize", "--from-evidence", str(evidence)])
            self.assertEqual(rc, 0)
            lines = [" ".join(map(str, c.args)) for c in p.call_args_list]
            self.assertTrue(any("overall_risk:" in ln for ln in lines))

            with patch("builtins.print") as p2:
                rc2 = main(["forensics", "summarize", "--from-evidence", str(evidence), "--json"])
            self.assertEqual(rc2, 0)
            payload = json.loads(p2.call_args.args[0])
            self.assertIn("severity_counts", payload)


if __name__ == "__main__":
    unittest.main()
