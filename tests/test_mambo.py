import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "examples" / "simple_crackme"


def symbol_address(binary: Path, name: str) -> str:
    output = subprocess.check_output(["nm", "-n", str(binary)], text=True)
    match = re.search(rf"^([0-9a-fA-F]+)\s+\w\s+{re.escape(name)}$", output, re.MULTILINE)
    if not match:
        raise AssertionError(f"symbol {name!r} not found")
    return "0x" + match.group(1)


class MamboEndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run(["make", "all"], cwd=ROOT, check=True)

    def test_finds_payload_and_payload_reaches_target(self):
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "mambo.py"),
                "--binary",
                str(BINARY),
                "--start",
                symbol_address(BINARY, "main"),
                "--end",
                symbol_address(BINARY, "mambo_success"),
            ],
            cwd=ROOT,
            check=True,
            text=True,
            capture_output=True,
        )
        match = re.search(r"Payload \(hex\): ([0-9a-f]+)", completed.stdout)
        self.assertIsNotNone(match, completed.stdout)
        payload = bytes.fromhex(match.group(1))
        self.assertEqual(payload, b"MAMBO")

        crackme = subprocess.run([str(BINARY)], input=payload, capture_output=True, check=True)
        self.assertEqual(crackme.stdout, b"Correct Key!\n")

    def test_reports_its_version_without_a_binary(self):
        completed = subprocess.run(
            [sys.executable, str(ROOT / "mambo.py"), "--version"],
            cwd=ROOT,
            check=True,
            text=True,
            capture_output=True,
        )
        self.assertRegex(completed.stdout, r"mambo\.py 0\.1\.0")


if __name__ == "__main__":
    unittest.main()
