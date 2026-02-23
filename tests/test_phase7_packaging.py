from __future__ import annotations

import subprocess
import unittest


class Phase7PackagingTests(unittest.TestCase):
    def test_module_entrypoint_help(self) -> None:
        proc = subprocess.run(
            ["python3", "-m", "canari_forensics", "--help"],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("Canari Forensics CLI", proc.stdout)


if __name__ == "__main__":
    unittest.main()
