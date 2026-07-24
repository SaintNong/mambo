import re
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mambo import Mambo, MamboError
from mambo.elf import ELFImage
from mambo.executor import SymbolicExecutor, bv, concrete


ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "examples" / "simple_crackme"
I386_BINARY = ROOT / "examples" / "simple_crackme_i386"
HASH_BINARY = ROOT / "examples" / "hash_crackme"
I386_HASH_BINARY = ROOT / "examples" / "hash_crackme_i386"
STREAM_BINARY = ROOT / "examples" / "stream_crackme"
I386_STREAM_BINARY = ROOT / "examples" / "stream_crackme_i386"


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

    def test_defaults_to_main_with_end_symbol(self):
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "mambo.py"),
                "--binary",
                str(BINARY),
                "--end-symbol",
                "mambo_success",
            ],
            cwd=ROOT,
            check=True,
            text=True,
            capture_output=True,
        )
        self.assertIn("Payload (hex): 4d414d424f", completed.stdout)

    def test_finds_i386_payload_and_payload_reaches_target(self):
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "mambo.py"),
                "--binary",
                str(I386_BINARY),
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

        crackme = subprocess.run(
            [str(I386_BINARY)], input=payload, capture_output=True, check=True
        )
        self.assertEqual(crackme.stdout, b"Correct Key!\n")

    def test_solves_relocated_stream_globals(self):
        image = ELFImage(STREAM_BINARY)
        self.assertEqual(set(image.external_object_slots.values()), {"stdin", "stdout"})

        result = Mambo(STREAM_BINARY).solve_symbol("main", "mambo_stream_success")

        self.assertIsNotNone(result)
        self.assertEqual(result.payload, b"MAMBO")
        crackme = subprocess.run(
            [str(STREAM_BINARY)], input=result.payload, capture_output=True, check=True
        )
        self.assertEqual(crackme.stdout, b"Stream accepted!\n")

    def test_solves_i386_relocated_stream_globals(self):
        result = Mambo(I386_STREAM_BINARY).solve_symbol("main", "mambo_stream_success")

        self.assertIsNotNone(result)
        self.assertEqual(result.payload, b"MAMBO")
        crackme = subprocess.run(
            [str(I386_STREAM_BINARY)],
            input=result.payload,
            capture_output=True,
            check=True,
        )
        self.assertEqual(crackme.stdout, b"Stream accepted!\n")

    def test_solves_looping_custom_hash(self):
        binary = HASH_BINARY
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

    def test_solves_looping_custom_hash_on_i386(self):
        binary = I386_HASH_BINARY
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

        crackme = subprocess.run(
            [str(binary)], input=payload, capture_output=True, check=True
        )
        self.assertEqual(
            crackme.stdout, b"You guessed the password? No way\nHash accepted!\n"
        )

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
        self.assertIsInstance(result["elapsed_seconds"], float)
        self.assertGreaterEqual(result["elapsed_seconds"], 0.0)

    def test_prompts_for_missing_start_and_end_addresses(self):
        completed = subprocess.run(
            [sys.executable, str(ROOT / "mambo.py"), "--binary", str(BINARY)],
            cwd=ROOT,
            input=f"{symbol_address(BINARY, 'main')}\n{symbol_address(BINARY, 'mambo_success')}\n",
            check=True,
            text=True,
            capture_output=True,
        )
        self.assertIn("Detected executable symbols in [", completed.stdout)
        self.assertIn("Start address or symbol [defaulted: main = ", completed.stdout)
        self.assertIn("End address or symbol:", completed.stdout)
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

    def test_loader_accepts_both_x86_variants_and_rejects_non_x86(self):
        self.assertEqual(ELFImage(BINARY).architecture.name, "x86-64")
        self.assertEqual(ELFImage(I386_BINARY).architecture.name, "i386")

        # e_machine is the two-byte little-endian field at offset 18.  Rewriting
        # a copy to EM_ARM produces a valid non-PIE but unsupported ELF header.
        with tempfile.TemporaryDirectory() as directory:
            unsupported = Path(directory) / "unsupported"
            data = bytearray(BINARY.read_bytes())
            data[18:20] = (40).to_bytes(2, "little")  # EM_ARM
            unsupported.write_bytes(data)
            with self.assertRaisesRegex(
                MamboError, "i386 or x86-64"
            ):
                ELFImage(unsupported)

    def test_i386_fgets_uses_cdecl_stack_arguments_and_eax_return(self):
        image = ELFImage(I386_BINARY)
        executor = SymbolicExecutor(
            image,
            int(symbol_address(I386_BINARY, "main"), 0),
            int(symbol_address(I386_BINARY, "mambo_success"), 0),
        )
        state = executor.initial_state()
        stack, destination = 0xFFFF_E000, 0xFFFF_D000
        executor.write_register(state, "esp", bv(stack, 32))
        executor.write_memory(state, stack, bv(destination, 32), 4)
        executor.write_memory(state, stack + 4, bv(6, 32), 4)

        executor.hook(state, "fgets")

        self.assertEqual(state.input_count, 5)
        self.assertEqual(
            concrete(executor.read_register(state, "eax"), "fgets return"),
            destination,
        )
        self.assertEqual(
            concrete(executor.read_memory(state, destination + 5, 1), "terminator"),
            0,
        )

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
        self.assertIsInstance(result.elapsed_seconds, float)
        self.assertGreaterEqual(result.elapsed_seconds, 0.0)
        self.assertFalse(hasattr(result, "constraints"))
        self.assertIn("Payload (hex): 4d414d424f", str(result))
        self.assertIn("Explored states:", str(result))
        self.assertIn("Elapsed seconds:", str(result))

    def test_solves_named_symbols_through_the_public_api(self):
        result = Mambo(BINARY).solve_symbol("main", "mambo_success")

        self.assertIsNotNone(result)
        self.assertEqual(result.payload, b"MAMBO")

    def test_solves_i386_through_the_public_api(self):
        result = Mambo(I386_BINARY).solve_symbol("main", "mambo_success")

        self.assertIsNotNone(result)
        self.assertEqual(result.payload, b"MAMBO")

    def test_defaults_to_main_for_single_endpoint(self):
        solver = Mambo(BINARY)

        address_result = solver.solve(int(symbol_address(BINARY, "mambo_success"), 0))
        symbol_result = solver.solve_symbol("mambo_success")

        self.assertEqual(address_result.payload, b"MAMBO")
        self.assertEqual(symbol_result.payload, b"MAMBO")

    def test_public_api_validates_execution_limits(self):
        with self.assertRaisesRegex(MamboError, "execution limits must be positive"):
            Mambo(BINARY, max_steps=0)


if __name__ == "__main__":
    unittest.main()
