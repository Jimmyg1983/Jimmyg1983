"""Windows audit tests using mocks; safe on non-Windows hosts."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
from unittest.mock import mock_open
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import audit


class AuditTests(unittest.TestCase):
    @patch.object(audit.platform, "system", return_value="Linux")
    def test_windows_only(self, _system):
        with self.assertRaisesRegex(SystemExit, "Windows only"):
            audit.main()

    @patch.object(audit.platform, "system", return_value="Windows")
    @patch.object(audit.subprocess, "run")
    def test_unknown_checks_and_local_json(self, run, _system):
        run.return_value = MagicMock(returncode=0, stdout=json.dumps({
            "firewall": {"status": "unknown"},
            "defender": {"status": "unknown"},
            "uac": {"status": "unknown"},
            "encryption": {"status": "unknown"},
            "antivirus_products": {"status": "unknown"},
        }))
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(audit.Path, "write_text", autospec=True) as write:
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    audit.main()
                self.assertIn("UNKNOWN", output.getvalue())
                self.assertEqual(write.call_count, 1)
                saved = json.loads(write.call_args.args[1])
                self.assertIn("timestamp_utc", saved)
                self.assertIn("checks", saved)


if __name__ == "__main__":
    unittest.main()
