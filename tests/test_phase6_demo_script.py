from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


class Phase6DemoScriptTests(unittest.TestCase):
    def test_demo_script_produces_artifacts(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        script = repo_root / "scripts" / "demo_local_audit.sh"

        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run([str(script), tmp], check=True)

            artifact_root = Path(tmp) / ".canari" / "audits" / "demo-local-otel-audit"
            self.assertTrue((artifact_root / "audit.json").exists())
            self.assertTrue((artifact_root / "scan-report.json").exists())
            self.assertTrue((artifact_root / "evidence.json").exists())
            self.assertTrue((artifact_root / "audit-report.pdf").exists())


if __name__ == "__main__":
    unittest.main()
