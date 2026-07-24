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


def resolve_endpoint(value: str, solver: Mambo) -> int:
    """Resolve an interactive endpoint as a hexadecimal address or symbol."""
    if value.lower().startswith("0x"):
        return address(value)
    return solver.symbol_address(value)


def prompt_endpoint(prompt: str, solver: Mambo, default: Optional[int] = None) -> int:
    """Prompt until an endpoint resolves to an executable address."""
    while True:
        value = input(prompt).strip()
        if not value:
            if default is not None:
                return default
            print("error: an address or symbol is required", file=sys.stderr)
            continue
        try:
            return resolve_endpoint(value, solver)
        except (MamboError, argparse.ArgumentTypeError) as exc:
            print(f"error: {exc}", file=sys.stderr)


def print_symbols(solver: Mambo) -> None:
    """Display the executable symbols available for interactive selection."""
    symbols = solver.symbols()
    print(f"Detected executable symbols in [{solver.binary}]")
    if not symbols:
        print("  (none)")
        return
    for name, value in symbols:
        print(f"  {name}: 0x{value:x}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Find stdin bytes that reach an address in an x86-64 ELF")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("--binary", required=True, help="non-PIE x86-64 ELF to analyze")
    start = parser.add_mutually_exclusive_group()
    start.add_argument("--start", type=address, help="starting virtual address (for example 0x401176)")
    start.add_argument("--start-symbol", help="starting symbol name")
    end = parser.add_mutually_exclusive_group()
    end.add_argument("--end", type=address, help="target virtual address")
    end.add_argument("--end-symbol", help="target symbol name")
    parser.add_argument("--max-input", type=int, default=DEFAULT_MAX_INPUT, help="maximum symbolic stdin bytes (default: 64)")
    parser.add_argument("--max-states", type=int, default=DEFAULT_MAX_STATES, help="maximum paths to explore")
    parser.add_argument("--max-steps", type=int, default=DEFAULT_MAX_STEPS, help="maximum instructions per path")
    parser.add_argument("--json", action="store_true", help="emit a machine-readable result")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        solver = Mambo(
            args.binary,
            max_input=args.max_input,
            max_states=args.max_states,
            max_steps=args.max_steps,
        )
        interactive = args.end is None and args.end_symbol is None
        if interactive:
            print_symbols(solver)

        if args.start_symbol is not None:
            args.start = solver.symbol_address(args.start_symbol)
        elif args.start is None:
            main_address = None
            try:
                main_address = solver.symbol_address("main")
            except MamboError:
                pass
            if not interactive:
                if main_address is None:
                    raise MamboError("symbol not found: main; provide an explicit start address or symbol")
                args.start = main_address
            else:
                default = f" [defaulted: main = 0x{main_address:x}]" if main_address is not None else ""
                args.start = prompt_endpoint(f"Start address or symbol{default}: ", solver, main_address)

        if args.end_symbol is not None:
            args.end = solver.symbol_address(args.end_symbol)
        elif args.end is None:
            args.end = prompt_endpoint("End address or symbol: ", solver)

        result = solver.solve(args.start, args.end)
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
