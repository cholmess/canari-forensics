from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from canari_forensics.cli import main
from canari_forensics.config import load_simple_yaml

FIXTURES = Path(__file__).parent / "fixtures"


class Phase5ConfigRunTests(unittest.TestCase):
    def test_load_simple_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "cfg.yml"
            cfg.write_text(
                """
forensics:
  source: otel
  provider: generic
  logs: ./logs
  max_results: 1000
  enabled: true
""".strip()
                + "\n",
                encoding="utf-8",
            )
            data = load_simple_yaml(cfg)
            self.assertEqual(data["forensics"]["source"], "otel")
            self.assertEqual(data["forensics"]["max_results"], 1000)
            self.assertTrue(data["forensics"]["enabled"])

    def test_audit_run_from_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                Path(".canari.yml").write_text(
                    f"""
forensics:
  source: otel
  provider: generic
  logs: {FIXTURES / "otlp_sample.json"}
  file_pattern: "*.json"
  client: "Acme Corp"
  application: "AI Gateway"
  audit_name: "Q1 2026 AI Gateway Audit"
  tracking_uri: mlflow
  max_results: 1000
""".strip()
                    + "\n",
                    encoding="utf-8",
                )

                rc = main(["forensics", "audit", "run", "--config", ".canari.yml"])
                self.assertEqual(rc, 0)

                audit_root = Path(".canari/audits/q1-2026-ai-gateway-audit")
                self.assertTrue((audit_root / "scan-report.json").exists())
                self.assertTrue((audit_root / "evidence.json").exists())
                self.assertTrue((audit_root / "audit-report.pdf").exists())
            finally:
                os.chdir(cwd)


if __name__ == "__main__":
    unittest.main()
