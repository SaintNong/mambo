"""Public Mambo API."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, overload

from .elf import ELFImage
from .errors import MamboError
from .executor import SymbolicExecutor
from .models import ExecutionResult

DEFAULT_MAX_INPUT = 64
DEFAULT_MAX_STATES = 1000
DEFAULT_MAX_STEPS = 10000


class Mambo:
    """Find stdin bytes that make an ELF execution reach a target address.

    Args:
        binary: Path to a non-PIE x86 ELF binary (i386 or x86-64).
        max_input: Maximum number of symbolic stdin bytes.
        max_states: Maximum number of paths to explore.
        max_steps: Maximum instructions executed by each path.
    """

    def __init__(
        self,
        binary: str | Path,
        *,
        max_input: int = DEFAULT_MAX_INPUT,
        max_states: int = DEFAULT_MAX_STATES,
        max_steps: int = DEFAULT_MAX_STEPS,
    ) -> None:
        if max_input < 1 or max_states < 1 or max_steps < 1:
            raise MamboError("execution limits must be positive")
        self.binary = Path(binary)
        self.max_input = max_input
        self.max_states = max_states
        self.max_steps = max_steps
        self.image = ELFImage(self.binary)

    def _solve_addresses(self, start: int, end: int) -> Optional[ExecutionResult]:
        """Solve the bounded path exploration, or return ``None`` if no path is found."""
        return SymbolicExecutor(
            self.image,
            start,
            end,
            max_input=self.max_input,
            max_states=self.max_states,
            max_steps=self.max_steps,
        ).execute()

    @overload
    def solve(self, end: int) -> Optional[ExecutionResult]: ...

    @overload
    def solve(self, start: int, end: int) -> Optional[ExecutionResult]: ...

    def solve(self, *addresses: int) -> Optional[ExecutionResult]:
        """Solve from ``main`` to an end address, or between two addresses."""
        if len(addresses) == 1:
            start = self.symbol_address("main")
            end = addresses[0]
        elif len(addresses) == 2:
            start, end = addresses
        else:
            raise TypeError("solve() expects end or start and end addresses")
        return self._solve_addresses(start, end)

    def symbol_address(self, name: str) -> int:
        """Resolve a symbol name to its unique executable address."""
        return self.image.symbol_address(name)

    def symbols(self) -> List[tuple[str, int]]:
        """Return uniquely named executable symbols and their addresses."""
        return self.image.executable_symbols()

    @overload
    def solve_symbol(self, end: str) -> Optional[ExecutionResult]: ...

    @overload
    def solve_symbol(self, start: str, end: str) -> Optional[ExecutionResult]: ...

    def solve_symbol(self, *names: str) -> Optional[ExecutionResult]:
        """Solve from ``main`` to an end symbol, or between two symbols."""
        if len(names) == 1:
            start = self.symbol_address("main")
            end = self.symbol_address(names[0])
        elif len(names) == 2:
            start = self.symbol_address(names[0])
            end = self.symbol_address(names[1])
        else:
            raise TypeError("solve_symbol() expects end or start and end symbols")
        return self._solve_addresses(start, end)
