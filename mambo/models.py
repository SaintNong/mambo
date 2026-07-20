"""Data structures shared by ELF loader and symbolic executor."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import z3


@dataclass
class Segment:
    address: int
    data: bytes
    memory_size: int
    executable: bool

    def contains(self, address: int, size: int = 1) -> bool:
        return self.address <= address and address + size <= self.address + self.memory_size


@dataclass
class State:
    pc: int
    registers: Dict[str, z3.BitVecRef]
    memory: Dict[int, z3.BitVecRef] = field(default_factory=dict)
    constraints: List[z3.BoolRef] = field(default_factory=list)
    comparison: Optional[Tuple[str, z3.BitVecRef, z3.BitVecRef]] = None
    input_count: int = 0
    steps: int = 0

    def fork(self) -> "State":
        return State(
            self.pc,
            self.registers.copy(),
            self.memory.copy(),
            self.constraints.copy(),
            self.comparison,
            self.input_count,
            self.steps,
        )


@dataclass
class ExecutionResult:
    """The satisfying input and exploration metrics for a completed analysis."""

    payload: bytes
    constraints: List[z3.BoolRef]
    explored_states: int
    executed_instructions: int
