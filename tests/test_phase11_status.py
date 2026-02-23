from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from canari_forensics.cli import main


class Phase11StatusTests(unittest.TestCase):
    def test_status_text_and_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                Path(".canari.yml").write_text("forensics:\n  source: otel\n", encoding="utf-8")
                (Path(".canari") / "audits" / "a1").mkdir(parents=True, exist_ok=True)

                with patch("builtins.print") as p:
                    rc = main(["forensics", "status"])
                self.assertEqual(rc, 0)
                joined = "\n".join(" ".join(map(str, c.args)) for c in p.call_args_list)
                self.assertIn("audits_count:", joined)

                with patch("builtins.print") as p2:
                    rc2 = main(["forensics", "status", "--json"])
                self.assertEqual(rc2, 0)
                json_text = p2.call_args.args[0]
                payload = json.loads(json_text)
                self.assertEqual(payload["has_config"], True)
                self.assertEqual(payload["audits_count"], 1)
            finally:
                os.chdir(cwd)


if __name__ == "__main__":
    unittest.main()
