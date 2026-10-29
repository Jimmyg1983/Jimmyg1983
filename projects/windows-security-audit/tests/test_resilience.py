"""Regression tests for malformed Windows audit responses, with no real system calls."""
import contextlib
import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import audit


class ResilienceTests(unittest.TestCase):
    @patch.object(audit.platform, "system", return_value="Windows")
    @patch.object(audit.subprocess, "run", side_effect=FileNotFoundError("powershell.exe"))
    def test_missing_powershell(self, _run, _system):
        with self.assertRaisesRegex(SystemExit, "Audit could not complete"):
            audit.main()

    @patch.object(audit.platform, "system", return_value="Windows")
    @patch.object(audit.subprocess, "run")
    def test_unexpected_json_array(self, run, _system):
        run.return_value = MagicMock(returncode=0, stdout="[]")
        with self.assertRaisesRegex(SystemExit, "unexpected PowerShell response"):
            audit.main()

    @patch.object(audit.Path, "write_text")
    @patch.object(audit.platform, "system", return_value="Windows")
    @patch.object(audit.subprocess, "run")
    def test_malformed_sections(self, run, _system, _write):
        run.return_value = MagicMock(returncode=0, stdout=json.dumps({
            "firewall": {"status": "ok", "profiles": [{"Name": "Domain"}]},
            "defender": None, "uac": [], "encryption": "unknown",
            "antivirus_products": {"status": "ok", "names": 7}
        }))
        with contextlib.redirect_stdout(io.StringIO()) as output:
            audit.main()
        self.assertIn("Firewall Domain: UNKNOWN", output.getvalue())
        self.assertIn("Defender: UNKNOWN", output.getvalue())

    @patch.object(audit.Path, "write_text")
    @patch.object(audit.platform, "system", return_value="Windows")
    @patch.object(audit.subprocess, "run")
    def test_null_firewall_profiles(self, run, _system, _write):
        run.return_value = MagicMock(returncode=0, stdout=json.dumps({
            "firewall": {"status": "ok", "profiles": None}
        }))
        with contextlib.redirect_stdout(io.StringIO()) as output:
            audit.main()
        self.assertIn("Firewall profiles: UNKNOWN", output.getvalue())


if __name__ == "__main__":
    unittest.main()
