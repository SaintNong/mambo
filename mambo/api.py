"""Public Mambo API."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

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
        binary: Path to a non-PIE x86-64 ELF binary.
        start: Virtual address at which to start execution.
        end: Virtual address to reach.
        max_input: Maximum number of symbolic stdin bytes.
        max_states: Maximum number of paths to explore.
        max_steps: Maximum instructions executed by each path.
    """

    def __init__(
        self,
        binary: str | Path,
        start: int,
        end: int,
        *,
        max_input: int = DEFAULT_MAX_INPUT,
        max_states: int = DEFAULT_MAX_STATES,
        max_steps: int = DEFAULT_MAX_STEPS,
    ) -> None:
        if max_input < 1 or max_states < 1 or max_steps < 1:
            raise MamboError("execution limits must be positive")
        self.binary = Path(binary)
        self.start = start
        self.end = end
        self.max_input = max_input
        self.max_states = max_states
        self.max_steps = max_steps

    def run(self) -> Optional[ExecutionResult]:
        """Execute the bounded path exploration, or return ``None`` if no path is found."""
        image = ELFImage(self.binary)
        return SymbolicExecutor(
            image,
            self.start,
            self.end,
            max_input=self.max_input,
            max_states=self.max_states,
            max_steps=self.max_steps,
        ).run()

    def solve(self) -> Optional[ExecutionResult]:
        """Alias for :meth:`run` for users phrasing analysis as a solve operation."""
        return self.run()
