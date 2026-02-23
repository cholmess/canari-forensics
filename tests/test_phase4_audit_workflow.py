from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from canari_forensics.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


class Phase4AuditWorkflowTests(unittest.TestCase):
    def test_audit_workflow_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                init_rc = main(
                    [
                        "forensics",
                        "audit",
                        "init",
                        "--name",
                        "Q1 2026 AI Gateway Audit",
                        "--source",
                        "otel",
                        "--provider",
                        "generic",
                        "--logs",
                        str(FIXTURES / "otlp_sample.json"),
                        "--client",
                        "Acme Corp",
                        "--application",
                        "AI Gateway",
                    ]
                )
                self.assertEqual(init_rc, 0)

                audit_id = "q1-2026-ai-gateway-audit"
                scan_rc = main(["forensics", "audit", "scan", "--audit-id", audit_id])
                self.assertEqual(scan_rc, 0)

                report_rc = main(["forensics", "audit", "report", "--audit-id", audit_id])
                self.assertEqual(report_rc, 0)

                root = Path(".canari/audits") / audit_id
                self.assertTrue((root / "scan-report.json").exists())
                self.assertTrue((root / "evidence.json").exists())
                self.assertTrue((root / "audit-report.pdf").exists())

                evidence = json.loads((root / "evidence.json").read_text(encoding="utf-8"))
                self.assertEqual(evidence["client"], "Acme Corp")
            finally:
                os.chdir(cwd)


if __name__ == "__main__":
    unittest.main()
