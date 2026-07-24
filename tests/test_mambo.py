import re
import json
import subprocess
import sys
import unittest
from pathlib import Path

from mambo import Mambo, MamboError


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
                "--start-symbol",
                "main",
                "--end-symbol",
                "mambo_success",
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

    def test_solves_looping_custom_hash(self):
        binary = ROOT / "examples" / "hash_crackme"
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "mambo.py"),
                "--binary",
                str(binary),
                "--start",
                symbol_address(binary, "main"),
                "--end",
                symbol_address(binary, "mambo_hash_success"),
            ],
            cwd=ROOT,
            check=True,
            text=True,
            capture_output=True,
        )
        match = re.search(r"Payload \(hex\): ([0-9a-f]+)", completed.stdout)
        self.assertIsNotNone(match, completed.stdout)
        payload = bytes.fromhex(match.group(1))
        self.assertEqual(len(payload), 6)
        self.assertTrue(payload.isalnum())

        crackme = subprocess.run([str(binary)], input=payload, capture_output=True, check=True)
        self.assertEqual(crackme.stdout, b"You guessed the password? No way\nHash accepted!\n")

    def test_reports_its_version_without_a_binary(self):
        completed = subprocess.run(
            [sys.executable, str(ROOT / "mambo.py"), "--version"],
            cwd=ROOT,
            check=True,
            text=True,
            capture_output=True,
        )
        self.assertRegex(completed.stdout, r"mambo\.py 0\.1\.0")

    def test_emits_json_for_automation(self):
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "mambo.py"),
                "--json",
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
        result = json.loads(completed.stdout)
        self.assertEqual(result["payload_hex"], "4d414d424f")
        self.assertIn("explored_states", result)

    def test_prompts_for_missing_start_and_end_addresses(self):
        completed = subprocess.run(
            [sys.executable, str(ROOT / "mambo.py"), "--binary", str(BINARY)],
            cwd=ROOT,
            input=f"{symbol_address(BINARY, 'main')}\n{symbol_address(BINARY, 'mambo_success')}\n",
            check=True,
            text=True,
            capture_output=True,
        )
        self.assertIn("Start address: End address:", completed.stdout)
        self.assertIn("Payload (hex): 4d414d424f", completed.stdout)

    def test_rejects_pie_binary(self):
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "mambo.py"),
                "--binary",
                "/bin/ls",
                "--start",
                "0x1",
                "--end",
                "0x2",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("PIE binaries are not supported", completed.stderr)

    def test_rejects_non_positive_execution_limits(self):
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
                "--max-steps",
                "0",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("execution limits must be positive", completed.stderr)


class MamboApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run(["make", "all"], cwd=ROOT, check=True)

    def test_solves_through_the_public_api(self):
        result = Mambo(BINARY).solve(
            int(symbol_address(BINARY, "main"), 0),
            int(symbol_address(BINARY, "mambo_success"), 0),
        )

        self.assertIsNotNone(result)
        self.assertEqual(result.payload, b"MAMBO")
        self.assertGreater(result.explored_states, 0)

    def test_solves_named_symbols_through_the_public_api(self):
        result = Mambo(BINARY).solve_symbols("main", "mambo_success")

        self.assertIsNotNone(result)
        self.assertEqual(result.payload, b"MAMBO")

    def test_public_api_validates_execution_limits(self):
        with self.assertRaisesRegex(MamboError, "execution limits must be positive"):
            Mambo(BINARY, max_steps=0)


if __name__ == "__main__":
    unittest.main()
