#!/usr/bin/env python3
"""cli for Mambo"""

from __future__ import annotations

import argparse
import json
import string
import sys
from typing import List, Optional

from mambo import DEFAULT_MAX_INPUT, DEFAULT_MAX_STATES, DEFAULT_MAX_STEPS, Mambo, MamboError

VERSION = "0.1.0"


def address(value: str) -> int:
    """parse an integer address accepted by ``int(..., 0)``."""
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid address: {value!r}") from exc


def printable_payload(payload: bytes) -> str:
    """helper func to replace unprintable with '.'"""
    return "".join(chr(byte) if chr(byte) in string.printable and byte not in b"\\\r\n\t" else "." for byte in payload)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Find stdin bytes that reach an address in an x86-64 ELF")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("--binary", required=True, help="non-PIE x86-64 ELF to analyze")
    parser.add_argument("--start", type=address, help="starting virtual address (for example 0x401176)")
    parser.add_argument("--end", type=address, help="target virtual address")
    parser.add_argument("--max-input", type=int, default=DEFAULT_MAX_INPUT, help="maximum symbolic stdin bytes (default: 64)")
    parser.add_argument("--max-states", type=int, default=DEFAULT_MAX_STATES, help="maximum paths to explore")
    parser.add_argument("--max-steps", type=int, default=DEFAULT_MAX_STEPS, help="maximum instructions per path")
    parser.add_argument("--json", action="store_true", help="emit a machine-readable result")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.start is None:
        args.start = address(input("Start address: ").strip())
    if args.end is None:
        args.end = address(input("End address: ").strip())

    try:
        result = Mambo(
            args.binary,
            args.start,
            args.end,
            max_input=args.max_input,
            max_states=args.max_states,
            max_steps=args.max_steps,
        ).run()
    except (MamboError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if result is None:
        print("No satisfiable path found within the execution limits.")
        return 1
    if args.json:
        print(json.dumps({
            "end": f"0x{args.end:x}",
            "payload_hex": result.payload.hex(),
            "payload_ascii": printable_payload(result.payload),
            "explored_states": result.explored_states,
            "executed_instructions": result.executed_instructions,
        }))
    else:
        print(f"Reached 0x{args.end:x}")
        print(f"Payload (hex): {result.payload.hex()}")
        print(f"Payload (ASCII): {printable_payload(result.payload)}")
        print(f"Explored states: {result.explored_states}; executed instructions: {result.executed_instructions}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
