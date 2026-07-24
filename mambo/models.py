"""Data structures shared by ELF loader and symbolic executor."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import z3


@dataclass(frozen=True)
class ArchitectureProfile:
    """Execution details for one supported non-PIE x86 ELF variant."""

    name: str
    capstone_mode: int
    address_bits: int
    instruction_pointer: str
    stack_pointer: str
    frame_pointer: str
    return_register: str
    stack_slot_size: int
    initial_stack: int
    argument_registers: Tuple[str, ...]

    @property
    def address_mask(self) -> int:
        """Mask used for architectural address wrapping."""
        return (1 << self.address_bits) - 1


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
    explored_states: int
    executed_instructions: int
    elapsed_seconds: float

    def __str__(self) -> str:
        # this is enough useful context for users who just print(result)
        payload_ascii = "".join(
            chr(byte) if 32 <= byte <= 126 else "."
            for byte in self.payload
        )
        return "\n".join(
            (
                f"Payload (hex): {self.payload.hex()}",
                f"Payload (ASCII): {payload_ascii}",
                f"Explored states: {self.explored_states}",
                f"Executed instructions: {self.executed_instructions}",
                f"Elapsed seconds: {self.elapsed_seconds:.6f}",
            )
        )
