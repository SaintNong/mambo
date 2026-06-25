#!/usr/bin/env python3
"""A deliberately small x86-64 symbolic executor for educational binaries."""

from __future__ import annotations

import argparse
import string
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection
import z3

VERSION = "0.1.0"
DEFAULT_MAX_INPUT = 64
DEFAULT_MAX_STATES = 1000
DEFAULT_MAX_STEPS = 10000


class MamboError(Exception):
    """An input or execution error that should be shown without a traceback."""


@dataclass
class Segment:
    address: int
    data: bytes
    memory_size: int
    executable: bool

    def contains(self, address: int, size: int = 1) -> bool:
        return self.address <= address and address + size <= self.address + self.memory_size


class ELFImage:
    """The parts of an ELF needed by the executor."""

    def __init__(self, path: str):
        self.path = Path(path)
        try:
            self._raw = self.path.read_bytes()
        except OSError as exc:
            raise MamboError(f"cannot read binary: {exc}") from exc

        self.segments: List[Segment] = []
        self.symbols: Dict[int, str] = {}
        self.hooks: Dict[int, str] = {}

        with self.path.open("rb") as stream:
            elf = ELFFile(stream)
            if elf.get_machine_arch() != "x64":
                raise MamboError("only x86-64 ELF binaries are supported")
            if elf.header["e_type"] == "ET_DYN":
                raise MamboError("PIE binaries are not supported; compile with -fno-pie -no-pie")

            for segment in elf.iter_segments():
                if segment["p_type"] == "PT_LOAD":
                    self.segments.append(
                        Segment(
                            int(segment["p_vaddr"]),
                            segment.data(),
                            int(segment["p_memsz"]),
                            bool(int(segment["p_flags"]) & 1),
                        )
                    )

            for section in elf.iter_sections():
                if isinstance(section, SymbolTableSection):
                    for symbol in section.iter_symbols():
                        address = int(symbol["st_value"])
                        if address and symbol.name:
                            self.symbols.setdefault(address, symbol.name)

            self._load_plt_hooks(elf)

    def _load_plt_hooks(self, elf: ELFFile) -> None:
        relocations: List[str] = []
        for section in elf.iter_sections():
            if not isinstance(section, RelocationSection) or ".plt" not in section.name:
                continue
            symbols = elf.get_section(section["sh_link"])
            for relocation in section.iter_relocations():
                symbol = symbols.get_symbol(relocation["r_info_sym"])
                relocations.append(symbol.name)

        if not relocations:
            return
        plt_sec = elf.get_section_by_name(".plt.sec")
        reserved_entry = False
        if plt_sec is None:
            plt_sec = elf.get_section_by_name(".plt")
            reserved_entry = True
        if plt_sec is None:
            return

        entry_size = int(plt_sec["sh_entsize"] or 16)
        base = int(plt_sec["sh_addr"])
        for index, name in enumerate(relocations):
            address = base + (index + (1 if reserved_entry else 0)) * entry_size
            self.hooks[address] = name

    def read(self, address: int, size: int) -> bytes:
        for segment in self.segments:
            if segment.contains(address, size):
                offset = address - segment.address
                available = segment.data[offset : offset + size]
                return available + bytes(size - len(available))
        raise MamboError(f"unmapped memory read at 0x{address:x}")

    def byte(self, address: int) -> int:
        return self.read(address, 1)[0]

    def is_executable(self, address: int) -> bool:
        return any(segment.executable and segment.contains(address) for segment in self.segments)


REGISTER_PARTS: Dict[str, Tuple[str, int, int]] = {}


def _register_family(base: str, dword: str, word: str, low: str, high: Optional[str] = None) -> None:
    REGISTER_PARTS[base] = (base, 64, 0)
    REGISTER_PARTS[dword] = (base, 32, 0)
    REGISTER_PARTS[word] = (base, 16, 0)
    REGISTER_PARTS[low] = (base, 8, 0)
    if high:
        REGISTER_PARTS[high] = (base, 8, 8)


_register_family("rax", "eax", "ax", "al", "ah")
_register_family("rbx", "ebx", "bx", "bl", "bh")
_register_family("rcx", "ecx", "cx", "cl", "ch")
_register_family("rdx", "edx", "dx", "dl", "dh")
_register_family("rsi", "esi", "si", "sil")
_register_family("rdi", "edi", "di", "dil")
_register_family("rbp", "ebp", "bp", "bpl")
_register_family("rsp", "esp", "sp", "spl")
for _number in range(8, 16):
    _register_family(f"r{_number}", f"r{_number}d", f"r{_number}w", f"r{_number}b")
REGISTER_PARTS["rip"] = ("rip", 64, 0)


def bv(value: int, width: int) -> z3.BitVecRef:
    return z3.BitVecVal(value % (1 << width), width)


def resize(value: z3.BitVecRef, width: int, signed: bool = False) -> z3.BitVecRef:
    current = value.size()
    if current == width:
        return value
    if current > width:
        return z3.Extract(width - 1, 0, value)
    extension = width - current
    return z3.SignExt(extension, value) if signed else z3.ZeroExt(extension, value)


def concrete(value: z3.BitVecRef, what: str) -> int:
    simplified = z3.simplify(value)
    if not z3.is_bv_value(simplified):
        raise MamboError(f"symbolic {what} is outside the MVP's supported subset")
    return simplified.as_long()


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
    payload: bytes
    constraints: List[z3.BoolRef]
    explored_states: int
    executed_instructions: int


class SymbolicExecutor:
    """A bounded path explorer for straightforward x86-64 crackmes."""

    INPUT_HOOKS = {"read", "__read_chk", "gets", "fgets", "getchar"}
    OUTPUT_HOOKS = {"write", "puts", "printf", "__printf_chk", "putchar"}

    def __init__(
        self,
        image: ELFImage,
        start: int,
        end: int,
        *,
        max_input: int = 64,
        max_states: int = 1000,
        max_steps: int = 10000,
    ):
        if not image.is_executable(start):
            raise MamboError(f"start address 0x{start:x} is not executable")
        if not image.is_executable(end):
            raise MamboError(f"end address 0x{end:x} is not executable")
        self.image = image
        self.start = start
        self.end = end
        self.max_input = max_input
        self.max_states = max_states
        self.max_steps = max_steps
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        self.input_symbols: List[z3.BitVecRef] = []
        self.executed = 0

    def initial_state(self) -> State:
        registers = {name: bv(0, 64) for name, width, _ in REGISTER_PARTS.values() if width == 64}
        stack = 0x7FFF_FFFF_F000
        registers["rsp"] = bv(stack, 64)
        registers["rip"] = bv(self.start, 64)
        state = State(self.start, registers)
        self.write_memory(state, stack, bv(0, 64), 8)  # synthetic return sentinel
        return state

    def decode(self, address: int):
        try:
            data = self.image.read(address, 15)
        except MamboError:
            return None
        return next(self.md.disasm(data, address, count=1), None)

    def read_register(self, state: State, name: str) -> z3.BitVecRef:
        try:
            base, width, offset = REGISTER_PARTS[name]
        except KeyError as exc:
            raise MamboError(f"unsupported register {name}") from exc
        value = state.registers.get(base, bv(0, 64))
        if width == 64:
            return value
        return z3.Extract(offset + width - 1, offset, value)

    def write_register(self, state: State, name: str, value: z3.BitVecRef) -> None:
        base, width, offset = REGISTER_PARTS[name]
        value = resize(value, width)
        if width == 64:
            state.registers[base] = value
        elif width == 32:
            state.registers[base] = z3.ZeroExt(32, value)
        else:
            old = state.registers.get(base, bv(0, 64))
            high_size = 64 - offset - width
            pieces = []
            if high_size:
                pieces.append(z3.Extract(63, offset + width, old))
            pieces.append(value)
            if offset:
                pieces.append(z3.Extract(offset - 1, 0, old))
            state.registers[base] = pieces[0] if len(pieces) == 1 else z3.Concat(*pieces)

    def memory_address(self, state: State, insn, operand) -> int:
        address = operand.mem.disp
        if operand.mem.base:
            base_name = insn.reg_name(operand.mem.base)
            if base_name == "rip":
                address += insn.address + insn.size
            else:
                address += concrete(self.read_register(state, base_name), "memory address")
        if operand.mem.index:
            index_name = insn.reg_name(operand.mem.index)
            address += concrete(self.read_register(state, index_name), "memory address") * operand.mem.scale
        return address & ((1 << 64) - 1)

    def read_memory(self, state: State, address: int, size: int) -> z3.BitVecRef:
        parts = []
        for offset in reversed(range(size)):
            byte_value = state.memory.get(address + offset)
            if byte_value is None:
                byte_value = bv(self.image.byte(address + offset), 8)
            parts.append(byte_value)
        return parts[0] if len(parts) == 1 else z3.Concat(*parts)

    @staticmethod
    def write_memory(state: State, address: int, value: z3.BitVecRef, size: int) -> None:
        value = resize(value, size * 8)
        for offset in range(size):
            state.memory[address + offset] = z3.Extract(offset * 8 + 7, offset * 8, value)

    def read_operand(self, state: State, insn, operand) -> z3.BitVecRef:
        width = operand.size * 8
        if operand.type == X86_OP_REG:
            return self.read_register(state, insn.reg_name(operand.reg))
        if operand.type == X86_OP_IMM:
            return bv(operand.imm, width or 64)
        if operand.type == X86_OP_MEM:
            return self.read_memory(state, self.memory_address(state, insn, operand), operand.size)
        raise MamboError(f"unsupported operand in '{insn.mnemonic} {insn.op_str}'")

    def write_operand(self, state: State, insn, operand, value: z3.BitVecRef) -> None:
        if operand.type == X86_OP_REG:
            self.write_register(state, insn.reg_name(operand.reg), value)
        elif operand.type == X86_OP_MEM:
            self.write_memory(state, self.memory_address(state, insn, operand), value, operand.size)
        else:
            raise MamboError(f"unsupported destination in '{insn.mnemonic} {insn.op_str}'")

    @staticmethod
    def satisfiable(constraints: Iterable[z3.BoolRef]) -> bool:
        solver = z3.Solver()
        solver.add(*constraints)
        return solver.check() == z3.sat

    def condition(self, mnemonic: str, comparison) -> z3.BoolRef:
        if comparison is None:
            raise MamboError(f"conditional jump {mnemonic} has no modeled cmp/test")
        kind, left, right = comparison
        equal = left == right
        conditions = {
            "je": equal,
            "jz": equal,
            "jne": z3.Not(equal),
            "jnz": z3.Not(equal),
        }
        if mnemonic in conditions:
            return conditions[mnemonic]
        if kind == "test":
            raise MamboError(f"unsupported flag use after test: {mnemonic}")
        signed = {
            "jl": left < right,
            "jnge": left < right,
            "jle": left <= right,
            "jng": left <= right,
            "jg": left > right,
            "jnle": left > right,
            "jge": left >= right,
            "jnl": left >= right,
        }
        unsigned = {
            "jb": z3.ULT(left, right),
            "jnae": z3.ULT(left, right),
            "jc": z3.ULT(left, right),
            "jbe": z3.ULE(left, right),
            "jna": z3.ULE(left, right),
            "ja": z3.UGT(left, right),
            "jnbe": z3.UGT(left, right),
            "jae": z3.UGE(left, right),
            "jnb": z3.UGE(left, right),
            "jnc": z3.UGE(left, right),
        }
        if mnemonic in signed:
            return signed[mnemonic]
        if mnemonic in unsigned:
            return unsigned[mnemonic]
        raise MamboError(f"unsupported conditional jump {mnemonic}")

    def symbolic_byte(self, index: int) -> z3.BitVecRef:
        while len(self.input_symbols) <= index:
            self.input_symbols.append(z3.BitVec(f"stdin_{len(self.input_symbols)}", 8))
        return self.input_symbols[index]

    def hook(self, state: State, name: str) -> None:
        name = name.split("@")[0]
        if name in {"read", "__read_chk"}:
            destination = concrete(self.read_register(state, "rsi"), "read buffer")
            requested = concrete(self.read_register(state, "rdx"), "read size")
            count = min(requested, self.max_input - state.input_count)
            for offset in range(count):
                self.write_memory(state, destination + offset, self.symbolic_byte(state.input_count + offset), 1)
            state.input_count += count
            self.write_register(state, "rax", bv(count, 64))
        elif name == "gets":
            destination = concrete(self.read_register(state, "rdi"), "gets buffer")
            count = self.max_input - state.input_count
            for offset in range(count):
                self.write_memory(state, destination + offset, self.symbolic_byte(state.input_count + offset), 1)
            state.input_count += count
            self.write_memory(state, destination + count, bv(0, 8), 1)
            self.write_register(state, "rax", bv(destination, 64))
        elif name == "fgets":
            destination = concrete(self.read_register(state, "rdi"), "fgets buffer")
            requested = concrete(self.read_register(state, "rsi"), "fgets size")
            count = max(0, min(requested - 1, self.max_input - state.input_count))
            for offset in range(count):
                self.write_memory(state, destination + offset, self.symbolic_byte(state.input_count + offset), 1)
            state.input_count += count
            self.write_memory(state, destination + count, bv(0, 8), 1)
            self.write_register(state, "rax", bv(destination, 64))
        elif name == "getchar":
            if state.input_count >= self.max_input:
                self.write_register(state, "eax", bv(0xFFFFFFFF, 32))
            else:
                value = self.symbolic_byte(state.input_count)
                state.input_count += 1
                self.write_register(state, "eax", z3.ZeroExt(24, value))
        elif name in self.OUTPUT_HOOKS:
            self.write_register(state, "rax", bv(0, 64))
        else:
            raise MamboError(f"unsupported external call {name!r}")

    def execute_one(self, state: State) -> List[State]:
        insn = self.decode(state.pc)
        if insn is None:
            return []
        state.steps += 1
        self.executed += 1
        next_pc = insn.address + insn.size
        state.pc = next_pc
        self.write_register(state, "rip", bv(next_pc, 64))
        mnemonic = insn.mnemonic
        operands = insn.operands

        if mnemonic in {"nop", "endbr64"}:
            return [state]
        if mnemonic == "mov":
            self.write_operand(state, insn, operands[0], self.read_operand(state, insn, operands[1]))
        elif mnemonic in {"movzx", "movsx", "movsxd"}:
            source = self.read_operand(state, insn, operands[1])
            destination_width = operands[0].size * 8
            self.write_operand(state, insn, operands[0], resize(source, destination_width, mnemonic != "movzx"))
        elif mnemonic == "lea":
            self.write_operand(state, insn, operands[0], bv(self.memory_address(state, insn, operands[1]), operands[0].size * 8))
        elif mnemonic == "push":
            stack = concrete(self.read_register(state, "rsp"), "stack pointer") - 8
            self.write_register(state, "rsp", bv(stack, 64))
            self.write_memory(state, stack, resize(self.read_operand(state, insn, operands[0]), 64), 8)
        elif mnemonic == "pop":
            stack = concrete(self.read_register(state, "rsp"), "stack pointer")
            self.write_operand(state, insn, operands[0], self.read_memory(state, stack, 8))
            self.write_register(state, "rsp", bv(stack + 8, 64))
        elif mnemonic == "leave":
            stack = concrete(self.read_register(state, "rbp"), "frame pointer")
            self.write_register(state, "rsp", bv(stack, 64))
            self.write_register(state, "rbp", self.read_memory(state, stack, 8))
            self.write_register(state, "rsp", bv(stack + 8, 64))
        elif mnemonic == "ret":
            stack = concrete(self.read_register(state, "rsp"), "stack pointer")
            target = concrete(self.read_memory(state, stack, 8), "return address")
            if target == 0:
                return []
            state.pc = target
            self.write_register(state, "rsp", bv(stack + 8, 64))
        elif mnemonic == "call":
            target = concrete(self.read_operand(state, insn, operands[0]), "call target")
            hook_name = self.image.hooks.get(target)
            if hook_name:
                self.hook(state, hook_name)
            else:
                stack = concrete(self.read_register(state, "rsp"), "stack pointer") - 8
                self.write_register(state, "rsp", bv(stack, 64))
                self.write_memory(state, stack, bv(next_pc, 64), 8)
                state.pc = target
        elif mnemonic == "jmp":
            state.pc = concrete(self.read_operand(state, insn, operands[0]), "jump target")
        elif mnemonic.startswith("j"):
            target = concrete(self.read_operand(state, insn, operands[0]), "jump target")
            condition = self.condition(mnemonic, state.comparison)
            taken = state.fork()
            taken.pc = target
            taken.constraints.append(condition)
            state.constraints.append(z3.Not(condition))
            successors = []
            if self.satisfiable(taken.constraints):
                successors.append(taken)
            if self.satisfiable(state.constraints):
                successors.append(state)
            return successors
        elif mnemonic == "cmp":
            left = self.read_operand(state, insn, operands[0])
            right = resize(self.read_operand(state, insn, operands[1]), left.size())
            state.comparison = ("cmp", left, right)
        elif mnemonic == "test":
            left = self.read_operand(state, insn, operands[0])
            right = resize(self.read_operand(state, insn, operands[1]), left.size())
            state.comparison = ("test", left & right, bv(0, left.size()))
        elif mnemonic in {"add", "sub", "and", "or", "xor"}:
            left = self.read_operand(state, insn, operands[0])
            right = resize(self.read_operand(state, insn, operands[1]), left.size())
            operations = {
                "add": left + right,
                "sub": left - right,
                "and": left & right,
                "or": left | right,
                "xor": left ^ right,
            }
            self.write_operand(state, insn, operands[0], operations[mnemonic])
        elif mnemonic in {"inc", "dec"}:
            value = self.read_operand(state, insn, operands[0])
            self.write_operand(state, insn, operands[0], value + (1 if mnemonic == "inc" else -1))
        elif mnemonic in {"cdqe", "cltq"}:
            self.write_register(state, "rax", z3.SignExt(32, self.read_register(state, "eax")))
        else:
            raise MamboError(f"unsupported instruction at 0x{insn.address:x}: {mnemonic} {insn.op_str}")
        return [state]

    def solve(self, state: State, explored: int) -> ExecutionResult:
        solver = z3.Solver()
        solver.add(*state.constraints)
        if solver.check() != z3.sat:
            raise MamboError("internal error: target state is unsatisfiable")
        model = solver.model()
        payload = bytes(
            model.eval(self.symbolic_byte(index), model_completion=True).as_long()
            for index in range(state.input_count)
        )
        return ExecutionResult(payload, state.constraints, explored, self.executed)

    def run(self) -> Optional[ExecutionResult]:
        pending = [self.initial_state()]
        explored = 0
        while pending and explored < self.max_states:
            state = pending.pop()
            explored += 1
            while state.steps < self.max_steps:
                if state.pc == self.end:
                    return self.solve(state, explored)
                successors = self.execute_one(state)
                if not successors:
                    break
                state = successors[0]
                pending.extend(successors[1:])
        return None


def address(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid address: {value!r}") from exc


def printable_payload(payload: bytes) -> str:
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
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.start is None:
        args.start = address(input("Start address: ").strip())
    if args.end is None:
        args.end = address(input("End address: ").strip())
    if args.max_input < 1 or args.max_states < 1 or args.max_steps < 1:
        print("error: execution limits must be positive", file=sys.stderr)
        return 2

    try:
        image = ELFImage(args.binary)
        result = SymbolicExecutor(
            image,
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
    print(f"Reached 0x{args.end:x}")
    print(f"Payload (hex): {result.payload.hex()}")
    print(f"Payload (ASCII): {printable_payload(result.payload)}")
    print(f"Explored states: {result.explored_states}; executed instructions: {result.executed_instructions}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
