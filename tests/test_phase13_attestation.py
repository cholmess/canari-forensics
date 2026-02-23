from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from canari_forensics.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


class Phase13AttestationTests(unittest.TestCase):
    def test_attestation_create_and_verify(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scan = Path(tmp) / "scan.json"
            evidence = Path(tmp) / "evidence.json"
            pdf = Path(tmp) / "report.pdf"
            bp = Path(tmp) / "bp"
            att = Path(tmp) / "evidence.attestation.json"

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

            self.assertEqual(
                main(
                    [
                        "forensics",
                        "attest",
                        "--evidence",
                        str(evidence),
                        "--out",
                        str(att),
                    ]
                ),
                0,
            )
            self.assertTrue(att.exists())

            payload = json.loads(att.read_text(encoding="utf-8"))
            self.assertIn("sha256", payload)

            self.assertEqual(main(["forensics", "attest", "--verify", str(att)]), 0)

            # Tamper evidence and ensure verification fails
            evidence.write_text(evidence.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            self.assertEqual(main(["forensics", "attest", "--verify", str(att)]), 1)


if __name__ == "__main__":
    unittest.main()
