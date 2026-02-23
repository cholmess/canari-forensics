from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from canari_forensics.cli import main


class Phase9ErrorCodesTests(unittest.TestCase):
    def test_input_error_code_for_missing_logs(self) -> None:
        rc = main(["forensics", "scan", "--source", "otel", "--out", "x.json"])
        self.assertEqual(rc, 3)

    def test_not_found_error_code_for_missing_logs_path(self) -> None:
        rc = main(
            [
                "forensics",
                "scan",
                "--source",
                "otel",
                "--logs",
                "missing.json",
                "--out",
                "x.json",
            ]
        )
        self.assertEqual(rc, 4)

    def test_not_found_error_code_for_missing_audit(self) -> None:
        rc = main(["forensics", "audit", "scan", "--audit-id", "missing-audit"])
        self.assertEqual(rc, 4)

    def test_config_error_code_for_invalid_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "bad.yml"
            cfg.write_text("forensics\n  source: otel\n", encoding="utf-8")
            rc = main(["forensics", "audit", "run", "--config", str(cfg)])
            self.assertEqual(rc, 5)


if __name__ == "__main__":
    unittest.main()
