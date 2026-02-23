from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from canari_forensics.cli import main


class Phase8CLIValidationTests(unittest.TestCase):
    def test_scan_otel_missing_logs_fails(self) -> None:
        rc = main(["forensics", "scan", "--source", "otel", "--out", "x.json"])
        self.assertEqual(rc, 3)

    def test_scan_otel_missing_file_fails(self) -> None:
        rc = main(
            [
                "forensics",
                "scan",
                "--source",
                "otel",
                "--logs",
                "./does-not-exist.json",
                "--out",
                "x.json",
            ]
        )
        self.assertEqual(rc, 4)

    def test_report_missing_scan_report_fails(self) -> None:
        rc = main(
            [
                "forensics",
                "report",
                "--scan-report",
                "./missing-scan.json",
                "--client",
                "Acme",
                "--application",
                "App",
                "--out-pdf",
                "out.pdf",
                "--out-evidence",
                "evidence.json",
                "--bp-dir",
                "bp",
            ]
        )
        self.assertEqual(rc, 4)

    def test_audit_scan_unknown_id_fails(self) -> None:
        rc = main(["forensics", "audit", "scan", "--audit-id", "missing-id"])
        self.assertEqual(rc, 4)

    def test_audit_run_invalid_config_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "bad.yml"
            cfg.write_text("forensics\n  source: otel\n", encoding="utf-8")
            rc = main(["forensics", "audit", "run", "--config", str(cfg)])
            self.assertEqual(rc, 5)


if __name__ == "__main__":
    unittest.main()
