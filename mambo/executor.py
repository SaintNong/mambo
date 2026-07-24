"""Symbolic execution engine for supported x86-64 subset."""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Tuple

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
import z3

from .elf import ELFImage
from .errors import MamboError
from .models import ExecutionResult, State


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
        raise MamboError(f"symbolic {what} is outside our supported set")
    return simplified.as_long()


class SymbolicExecutor:
    """A bounded path explorer for straightforward x86-64 crackmes."""

    INPUT_HOOKS = {"read", "__read_chk", "gets", "fgets", "getchar"}
    OUTPUT_HOOKS = {"write", "puts", "printf", "__printf_chk", "putchar"}

    def __init__(self, image: ELFImage, start: int, end: int, *, max_input: int = 64,
                 max_states: int = 1000, max_steps: int = 10000):
        if not image.is_executable(start):
            raise MamboError(f"start address 0x{start:x} is not executable")
        if not image.is_executable(end):
            raise MamboError(f"end address 0x{end:x} is not executable")
        self.image, self.start, self.end = image, start, end
        self.max_input, self.max_states, self.max_steps = max_input, max_states, max_steps
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
        self.write_memory(state, stack, bv(0, 64), 8)
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
        return value if width == 64 else z3.Extract(offset + width - 1, offset, value)

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
            address += insn.address + insn.size if base_name == "rip" else concrete(self.read_register(state, base_name), "memory address")
        if operand.mem.index:
            address += concrete(self.read_register(state, insn.reg_name(operand.mem.index)), "memory address") * operand.mem.scale
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
        solver = z3.Solver(); solver.add(*constraints)
        return solver.check() == z3.sat

    def condition(self, mnemonic: str, comparison) -> z3.BoolRef:
        if comparison is None:
            raise MamboError(f"conditional jump {mnemonic} has no modeled cmp/test")
        kind, left, right = comparison
        equal = left == right
        conditions = {"je": equal, "jz": equal, "jne": z3.Not(equal), "jnz": z3.Not(equal)}
        if mnemonic in conditions:
            return conditions[mnemonic]
        if kind == "test":
            raise MamboError(f"unsupported flag use after test: {mnemonic}")
        signed = {"jl": left < right, "jnge": left < right, "jle": left <= right, "jng": left <= right,
                  "jg": left > right, "jnle": left > right, "jge": left >= right, "jnl": left >= right}
        unsigned = {"jb": z3.ULT(left, right), "jnae": z3.ULT(left, right), "jc": z3.ULT(left, right),
                    "jbe": z3.ULE(left, right), "jna": z3.ULE(left, right), "ja": z3.UGT(left, right),
                    "jnbe": z3.UGT(left, right), "jae": z3.UGE(left, right), "jnb": z3.UGE(left, right), "jnc": z3.UGE(left, right)}
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
            for offset in range(count): self.write_memory(state, destination + offset, self.symbolic_byte(state.input_count + offset), 1)
            state.input_count += count; self.write_register(state, "rax", bv(count, 64))
        elif name == "gets":
            destination = concrete(self.read_register(state, "rdi"), "gets buffer"); count = self.max_input - state.input_count
            for offset in range(count): self.write_memory(state, destination + offset, self.symbolic_byte(state.input_count + offset), 1)
            state.input_count += count; self.write_memory(state, destination + count, bv(0, 8), 1); self.write_register(state, "rax", bv(destination, 64))
        elif name == "fgets":
            destination = concrete(self.read_register(state, "rdi"), "fgets buffer"); requested = concrete(self.read_register(state, "rsi"), "fgets size")
            count = max(0, min(requested - 1, self.max_input - state.input_count))
            for offset in range(count): self.write_memory(state, destination + offset, self.symbolic_byte(state.input_count + offset), 1)
            state.input_count += count; self.write_memory(state, destination + count, bv(0, 8), 1); self.write_register(state, "rax", bv(destination, 64))
        elif name == "getchar":
            if state.input_count >= self.max_input:
                self.write_register(state, "eax", bv(0xFFFFFFFF, 32))
            else:
                value = self.symbolic_byte(state.input_count); state.input_count += 1; self.write_register(state, "eax", z3.ZeroExt(24, value))
        elif name in self.OUTPUT_HOOKS:
            self.write_register(state, "rax", bv(0, 64))
        else:
            raise MamboError(f"unsupported external call {name!r}")

    def execute_one(self, state: State) -> List[State]:
        insn = self.decode(state.pc)
        if insn is None: return []
        state.steps += 1; self.executed += 1
        next_pc = insn.address + insn.size; state.pc = next_pc; self.write_register(state, "rip", bv(next_pc, 64))
        mnemonic, operands = insn.mnemonic, insn.operands
        if mnemonic in {"nop", "endbr64"}: return [state]
        if mnemonic == "mov": self.write_operand(state, insn, operands[0], self.read_operand(state, insn, operands[1]))
        elif mnemonic in {"movzx", "movsx", "movsxd"}:
            self.write_operand(state, insn, operands[0], resize(self.read_operand(state, insn, operands[1]), operands[0].size * 8, mnemonic != "movzx"))
        elif mnemonic == "lea": self.write_operand(state, insn, operands[0], bv(self.memory_address(state, insn, operands[1]), operands[0].size * 8))
        elif mnemonic == "push":
            stack = concrete(self.read_register(state, "rsp"), "stack pointer") - 8; self.write_register(state, "rsp", bv(stack, 64)); self.write_memory(state, stack, resize(self.read_operand(state, insn, operands[0]), 64), 8)
        elif mnemonic == "pop":
            stack = concrete(self.read_register(state, "rsp"), "stack pointer"); self.write_operand(state, insn, operands[0], self.read_memory(state, stack, 8)); self.write_register(state, "rsp", bv(stack + 8, 64))
        elif mnemonic == "leave":
            stack = concrete(self.read_register(state, "rbp"), "frame pointer"); self.write_register(state, "rsp", bv(stack, 64)); self.write_register(state, "rbp", self.read_memory(state, stack, 8)); self.write_register(state, "rsp", bv(stack + 8, 64))
        elif mnemonic == "ret":
            stack = concrete(self.read_register(state, "rsp"), "stack pointer"); target = concrete(self.read_memory(state, stack, 8), "return address")
            if target == 0: return []
            state.pc = target; self.write_register(state, "rsp", bv(stack + 8, 64))
        elif mnemonic == "call":
            target = concrete(self.read_operand(state, insn, operands[0]), "call target"); hook_name = self.image.hooks.get(target)
            if hook_name: self.hook(state, hook_name)
            else:
                stack = concrete(self.read_register(state, "rsp"), "stack pointer") - 8; self.write_register(state, "rsp", bv(stack, 64)); self.write_memory(state, stack, bv(next_pc, 64), 8); state.pc = target
        elif mnemonic == "jmp": state.pc = concrete(self.read_operand(state, insn, operands[0]), "jump target")
        elif mnemonic.startswith("j"):
            target = concrete(self.read_operand(state, insn, operands[0]), "jump target"); condition = self.condition(mnemonic, state.comparison)
            taken = state.fork(); taken.pc = target; taken.constraints.append(condition); state.constraints.append(z3.Not(condition)); successors = []
            if self.satisfiable(taken.constraints): successors.append(taken)
            if self.satisfiable(state.constraints): successors.append(state)
            return successors
        elif mnemonic == "cmp":
            left = self.read_operand(state, insn, operands[0]); state.comparison = ("cmp", left, resize(self.read_operand(state, insn, operands[1]), left.size()))
        elif mnemonic == "test":
            left = self.read_operand(state, insn, operands[0]); state.comparison = ("test", left & resize(self.read_operand(state, insn, operands[1]), left.size()), bv(0, left.size()))
        elif mnemonic in {"add", "sub", "and", "or", "xor"}:
            left = self.read_operand(state, insn, operands[0]); right = resize(self.read_operand(state, insn, operands[1]), left.size())
            self.write_operand(state, insn, operands[0], {"add": left + right, "sub": left - right, "and": left & right, "or": left | right, "xor": left ^ right}[mnemonic])
        elif mnemonic == "imul":
            if len(operands) == 2: left, right = self.read_operand(state, insn, operands[0]), resize(self.read_operand(state, insn, operands[1]), self.read_operand(state, insn, operands[0]).size())
            elif len(operands) == 3: left, right = self.read_operand(state, insn, operands[1]), resize(self.read_operand(state, insn, operands[2]), self.read_operand(state, insn, operands[1]).size())
            else: raise MamboError(f"unsupported imul form: {insn.op_str}")
            self.write_operand(state, insn, operands[0], left * right)
        elif mnemonic in {"shl", "sal", "shr", "sar", "rol", "ror"}:
            value = self.read_operand(state, insn, operands[0]); count = concrete(self.read_operand(state, insn, operands[1]), "shift count")
            result = value << count if mnemonic in {"shl", "sal"} else z3.LShR(value, count) if mnemonic == "shr" else value >> count if mnemonic == "sar" else z3.RotateLeft(value, count) if mnemonic == "rol" else z3.RotateRight(value, count)
            self.write_operand(state, insn, operands[0], result)
        elif mnemonic in {"inc", "dec"}: self.write_operand(state, insn, operands[0], self.read_operand(state, insn, operands[0]) + (1 if mnemonic == "inc" else -1))
        elif mnemonic in {"cdqe", "cltq"}: self.write_register(state, "rax", z3.SignExt(32, self.read_register(state, "eax")))
        else: raise MamboError(f"unsupported instruction at 0x{insn.address:x}: {mnemonic} {insn.op_str}")
        return [state]

    def solve(self, state: State, explored: int) -> ExecutionResult:
        solver = z3.Solver(); solver.add(*state.constraints)
        if solver.check() != z3.sat: raise MamboError("internal error: target state is unsatisfiable")
        model = solver.model()
        payload = bytes(model.eval(self.symbolic_byte(index), model_completion=True).as_long() for index in range(state.input_count))
        return ExecutionResult(payload, explored, self.executed)

    def execute(self) -> Optional[ExecutionResult]:
        pending, explored = [self.initial_state()], 0
        while pending and explored < self.max_states:
            state = pending.pop(); explored += 1
            while state.steps < self.max_steps:
                if state.pc == self.end: return self.solve(state, explored)
                successors = self.execute_one(state)
                if not successors: break
                state = successors[0]; pending.extend(successors[1:])
        return None
