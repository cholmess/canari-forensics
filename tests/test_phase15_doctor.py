from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from canari_forensics.cli import main


class Phase15DoctorTests(unittest.TestCase):
    def test_doctor_json_output(self) -> None:
        with patch("builtins.print") as p:
            rc = main(["forensics", "doctor", "--json"])
        self.assertIn(rc, (0, 1))
        payload = json.loads(p.call_args.args[0])
        self.assertIn("ok", payload)
        self.assertIn("checks", payload)

    def test_doctor_text_output(self) -> None:
        with patch("builtins.print") as p:
            rc = main(["forensics", "doctor"])
        self.assertIn(rc, (0, 1))
        lines = [" ".join(map(str, c.args)) for c in p.call_args_list]
        self.assertTrue(any("overall_ok:" in line for line in lines))


if __name__ == "__main__":
    unittest.main()
