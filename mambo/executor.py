"""Symbolic execution engine for the supported i386 and x86-64 subsets."""

from __future__ import annotations

import time
from typing import Dict, Iterable, List, Optional, Tuple

from capstone import Cs, CS_ARCH_X86
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
import z3

from .elf import ELFImage
from .errors import MamboError
from .models import ExecutionResult, State

# MAP: conditional mnemonics -> function(left, right)
EQUALITY_CONDITIONS = {
    "je": lambda l, r: l == r,
    "jz": lambda l, r: l == r,
    "jne": lambda l, r: l != r,
    "jnz": lambda l, r: l != r,
}

SIGNED_CONDITIONS = {
    "jl": lambda l, r: l < r,
    "jnge": lambda l, r: l < r,
    "jle": lambda l, r: l <= r,
    "jng": lambda l, r: l <= r,
    "jg": lambda l, r: l > r,
    "jnle": lambda l, r: l > r,
    "jge": lambda l, r: l >= r,
    "jnl": lambda l, r: l >= r,
}

UNSIGNED_CONDITIONS = {
    "jb": z3.ULT,
    "jnae": z3.ULT,
    "jc": z3.ULT,
    "jbe": z3.ULE,
    "jna": z3.ULE,
    "ja": z3.UGT,
    "jnbe": z3.UGT,
    "jae": z3.UGE,
    "jnb": z3.UGE,
    "jnc": z3.UGE,
}

# MAP: Register name -> family name, visible width, LSB offset.
# This models aliases like `eax` and `al`; each family is stored at the active
# architecture's native width.
REGISTER_PARTS: Dict[str, Tuple[str, int, int]] = {}
REGISTER_BASES: set[str] = set()


def _register_family(
    base: str, dword: str, word: str, low: str, high: Optional[str] = None
) -> None:
    # register the alias to our global map
    REGISTER_BASES.add(base)
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
REGISTER_PARTS["eip"] = ("rip", 32, 0)
REGISTER_BASES.add("rip")


def bv(value: int, width: int) -> z3.BitVecRef:
    # Create z3 width-bit value, wraps integers to width
    return z3.BitVecVal(value % (1 << width), width)


def resize(value: z3.BitVecRef, width: int, signed: bool = False) -> z3.BitVecRef:
    # resize bit-vector by truncating or zero/sign-extending
    current = value.size()
    if current == width:
        return value
    if current > width:
        return z3.Extract(width - 1, 0, value)
    extension = width - current
    return z3.SignExt(extension, value) if signed else z3.ZeroExt(extension, value)


def concrete(value: z3.BitVecRef, what: str) -> int:
    # Return concrete bit vector value, using z3 to simplify.
    # Function also catches and reports unsupported use.
    simplified = z3.simplify(value)
    if not z3.is_bv_value(simplified):
        raise MamboError(f"symbolic {what} is outside our supported set")
    return simplified.as_long()


class SymbolicExecutor:
    """Explores bounded, satisfiable i386 or x86-64 paths between two addresses."""

    INPUT_HOOKS = {"read", "__read_chk", "gets", "fgets", "getchar"}
    OUTPUT_HOOKS = {
        "write",
        "puts",
        "printf",
        "__printf_chk",
        "putchar",
        "fflush",
    }

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
        self.image, self.start, self.end = image, start, end
        self.max_input, self.max_states, self.max_steps = (
            max_input,
            max_states,
            max_steps,
        )
        self.architecture = image.architecture
        self.md = Cs(CS_ARCH_X86, self.architecture.capstone_mode)
        self.md.detail = True
        self.input_symbols: List[z3.BitVecRef] = []
        self.executed = 0
        libc_base = (
            0x7FFF_0000_0000
            if self.architecture.address_bits == 64
            else 0xFF00_0000
        )
        self.external_object_addresses = {
            name: libc_base + index * 0x100
            for index, name in enumerate(sorted(set(image.external_object_slots.values())))
        }

    def initial_state(self) -> State:
        """returns a starting CPU state"""
        registers = {
            name: bv(0, self.architecture.address_bits) for name in REGISTER_BASES
        }
        stack = self.architecture.initial_stack
        registers["rsp"] = bv(stack, self.architecture.address_bits)
        registers["rip"] = bv(self.start, self.architecture.address_bits)
        state = State(self.start, registers)
        self.write_memory(
            state,
            stack,
            bv(0, self.architecture.address_bits),
            self.architecture.stack_slot_size,
        )
        # Dynamic ELF loaders normally relocate these slots to libc variables
        # such as `stdin`.  Model each variable as one concrete pointer-sized
        # cell containing a non-null opaque stream handle.
        for slot, name in self.image.external_object_slots.items():
            address = self.external_object_addresses[name]
            self.write_memory(
                state,
                slot,
                bv(address, self.architecture.address_bits),
                self.architecture.stack_slot_size,
            )
            self.write_memory(
                state,
                address,
                bv(address + self.architecture.stack_slot_size, self.architecture.address_bits),
                self.architecture.stack_slot_size,
            )
        return state

    def decode(self, address: int):
        """decode one instruction at an address."""
        try:
            data = self.image.read(address, 15)
        except MamboError:
            return None
        return next(self.md.disasm(data, address, count=1), None)

    def set_program_counter(self, state: State, address: int) -> None:
        """Update the concrete program counter and its architectural register."""
        address &= self.architecture.address_mask
        state.pc = address
        self.write_register(
            state,
            self.architecture.instruction_pointer,
            bv(address, self.architecture.address_bits),
        )

    def read_register(self, state: State, name: str) -> z3.BitVecRef:
        """read a register or one of its aliases."""
        try:
            base, width, offset = REGISTER_PARTS[name]
        except KeyError as exc:
            raise MamboError(f"unsupported register {name}") from exc
        if width > self.architecture.address_bits:
            raise MamboError(f"unsupported register {name}")
        value = state.registers.get(base, bv(0, self.architecture.address_bits))

        return (
            value
            if width == self.architecture.address_bits
            else z3.Extract(offset + width - 1, offset, value)
        )

    def write_register(self, state: State, name: str, value: z3.BitVecRef) -> None:
        """write a value to a register or one of its aliases."""
        base, width, offset = REGISTER_PARTS[name]
        if width > self.architecture.address_bits:
            raise MamboError(f"unsupported register {name}")
        value = resize(value, width)
        if width == self.architecture.address_bits:
            state.registers[base] = value
        elif width == 32 and self.architecture.address_bits == 64:
            state.registers[base] = z3.ZeroExt(32, value)
        else:
            old = state.registers.get(base, bv(0, self.architecture.address_bits))
            high_size = self.architecture.address_bits - offset - width
            pieces = []
            if high_size:
                pieces.append(z3.Extract(self.architecture.address_bits - 1, offset + width, old))
            pieces.append(value)
            if offset:
                pieces.append(z3.Extract(offset - 1, 0, old))
            state.registers[base] = (
                pieces[0]
                if len(pieces) == 1
                else z3.Concat(*pieces)
            )

    def memory_address(self, state: State, insn, operand) -> int:
        """memory address resolver"""
        address = operand.mem.disp
        if operand.mem.base:
            base_name = insn.reg_name(operand.mem.base)
            address += (
                insn.address + insn.size
                if base_name == "rip"
                else concrete(self.read_register(state, base_name), "memory address")
            )
        if operand.mem.index:
            address += (
                concrete(
                    self.read_register(state, insn.reg_name(operand.mem.index)),
                    "memory address",
                )
                * operand.mem.scale
            )
        return address & self.architecture.address_mask

    def read_memory(self, state: State, address: int, size: int) -> z3.BitVecRef:
        """read a little-endian value from memory."""
        parts = []
        for offset in reversed(range(size)):
            byte_address = (address + offset) & self.architecture.address_mask
            byte_value = state.memory.get(byte_address)
            if byte_value is None:
                byte_value = bv(self.image.byte(byte_address), 8)
            parts.append(byte_value)
        return parts[0] if len(parts) == 1 else z3.Concat(*parts)

    def write_memory(
        self, state: State, address: int, value: z3.BitVecRef, size: int
    ) -> None:
        """write a little-endian value to memory."""
        value = resize(value, size * 8)
        for offset in range(size):
            state.memory[(address + offset) & self.architecture.address_mask] = z3.Extract(
                offset * 8 + 7, offset * 8, value
            )

    def read_operand(self, state: State, insn, operand) -> z3.BitVecRef:
        """read operand -> z3 bit-vector."""
        width = operand.size * 8
        if operand.type == X86_OP_REG:
            return self.read_register(state, insn.reg_name(operand.reg))
        if operand.type == X86_OP_IMM:
            return bv(operand.imm, width or self.architecture.address_bits)
        if operand.type == X86_OP_MEM:
            return self.read_memory(
                state, self.memory_address(state, insn, operand), operand.size
            )
        raise MamboError(f"unsupported operand in '{insn.mnemonic} {insn.op_str}'")

    def write_operand(self, state: State, insn, operand, value: z3.BitVecRef) -> None:
        """write bit-vector to register or memory destination."""
        if operand.type == X86_OP_REG:
            self.write_register(state, insn.reg_name(operand.reg), value)
        elif operand.type == X86_OP_MEM:
            self.write_memory(
                state, self.memory_address(state, insn, operand), value, operand.size
            )
        else:
            raise MamboError(
                f"unsupported destination in '{insn.mnemonic} {insn.op_str}'"
            )

    @staticmethod
    def satisfiable(constraints: Iterable[z3.BoolRef]) -> bool:
        solver = z3.Solver()
        solver.add(*constraints)
        return solver.check() == z3.sat

    def condition(self, mnemonic: str, comparison) -> z3.BoolRef:
        """Convert an x86 conditional jump to a Z3 boolean constraint."""
        if comparison is None:
            raise MamboError(f"conditional jump {mnemonic} has no modeled cmp/test")

        # unpack
        kind, left, right = comparison

        if mnemonic in EQUALITY_CONDITIONS:
            return EQUALITY_CONDITIONS[mnemonic](left, right)

        if kind == "test":
            raise MamboError(f"unsupported flag use after test: {mnemonic}")

        if mnemonic in SIGNED_CONDITIONS:
            return SIGNED_CONDITIONS[mnemonic](left, right)

        if mnemonic in UNSIGNED_CONDITIONS:
            return UNSIGNED_CONDITIONS[mnemonic](left, right)

        raise MamboError(f"unsupported conditional jump {mnemonic}")

    def symbolic_byte(self, index: int) -> z3.BitVecRef:
        """Creates the Z3 symbolic variable for stdin[index]"""
        while len(self.input_symbols) <= index:
            self.input_symbols.append(z3.BitVec(f"stdin_{len(self.input_symbols)}", 8))
        return self.input_symbols[index]

    def hook_argument(self, state: State, index: int) -> z3.BitVecRef:
        """Return one integer/pointer argument using the active platform ABI."""
        if self.architecture.argument_registers:
            return self.read_register(state, self.architecture.argument_registers[index])
        stack = concrete(
            self.read_register(state, self.architecture.stack_pointer), "stack pointer"
        )
        return self.read_memory(
            state, stack + index * self.architecture.stack_slot_size,
            self.architecture.stack_slot_size,
        )

    def hook_return(self, state: State, value: int) -> None:
        """Set an integer or pointer result in the active platform return register."""
        self.write_register(
            state, self.architecture.return_register,
            bv(value, self.architecture.address_bits),
        )

    def hook(self, state: State, name: str) -> None:
        """a crude simulation of libc i/o functions"""
        name = name.split("@")[0]
        if name in {"read", "__read_chk"}:
            # fill requested buffer with next stdin symbols.
            destination = concrete(self.hook_argument(state, 1), "read buffer")
            requested = concrete(self.hook_argument(state, 2), "read size")
            count = min(requested, self.max_input - state.input_count)
            for offset in range(count):
                self.write_memory(
                    state,
                    destination + offset,
                    self.symbolic_byte(state.input_count + offset),
                    1,
                )
            state.input_count += count
            self.hook_return(state, count)
        elif name == "gets":
            # gets() consumes the remaining input and appends a terminator.
            destination = concrete(self.hook_argument(state, 0), "gets buffer")
            count = self.max_input - state.input_count
            for offset in range(count):
                self.write_memory(
                    state,
                    destination + offset,
                    self.symbolic_byte(state.input_count + offset),
                    1,
                )
            state.input_count += count
            self.write_memory(state, destination + count, bv(0, 8), 1)
            self.hook_return(state, destination)
        elif name == "fgets":
            # fgets() reserves one byte for its terminating NUL.
            destination = concrete(self.hook_argument(state, 0), "fgets buffer")
            requested = concrete(self.hook_argument(state, 1), "fgets size")
            count = max(0, min(requested - 1, self.max_input - state.input_count))
            for offset in range(count):
                self.write_memory(
                    state,
                    destination + offset,
                    self.symbolic_byte(state.input_count + offset),
                    1,
                )
            state.input_count += count
            self.write_memory(state, destination + count, bv(0, 8), 1)
            self.hook_return(state, destination)
        elif name == "getchar":
            # return one symbolic byte, or EOF after the input limit.
            if state.input_count >= self.max_input:
                self.write_register(state, "eax", bv(0xFFFFFFFF, 32))
            else:
                value = self.symbolic_byte(state.input_count)
                state.input_count += 1
                self.write_register(state, "eax", z3.ZeroExt(24, value))
        elif name in self.OUTPUT_HOOKS:
            # TODO: catch output
            self.hook_return(state, 0)
        else:
            raise MamboError(f"unsupported external call {name!r}")

    def execute_one(self, state: State) -> List[State]:
        """decodes one instruction then simulates execution"""

        # decode instruction and update executor state
        insn = self.decode(state.pc)
        if insn is None:
            return []
        state.steps += 1
        self.executed += 1

        # shared updates across all instructions
        next_pc = insn.address + insn.size
        self.set_program_counter(state, next_pc)

        mnemonic, operands = insn.mnemonic.removeprefix("notrack "), insn.operands

        # === data movement instructions ===
        if mnemonic in {"nop", "endbr64", "endbr32"}:
            return [state]
        if mnemonic == "mov":
            self.write_operand(
                state, insn, operands[0], self.read_operand(state, insn, operands[1])
            )
        elif mnemonic in {"movzx", "movsx", "movsxd"}:
            self.write_operand(
                state,
                insn,
                operands[0],
                resize(
                    self.read_operand(state, insn, operands[1]),
                    operands[0].size * 8,
                    mnemonic != "movzx",
                ),
            )
        elif mnemonic == "lea":
            self.write_operand(
                state,
                insn,
                operands[0],
                bv(self.memory_address(state, insn, operands[1]), operands[0].size * 8),
            )

        # === stack ops ===
        elif mnemonic == "push":
            stack = (
                concrete(
                    self.read_register(state, self.architecture.stack_pointer),
                    "stack pointer",
                )
                - self.architecture.stack_slot_size
            ) & self.architecture.address_mask
            self.write_register(
                state, self.architecture.stack_pointer,
                bv(stack, self.architecture.address_bits),
            )
            self.write_memory(
                state, stack,
                resize(self.read_operand(state, insn, operands[0]), self.architecture.address_bits),
                self.architecture.stack_slot_size,
            )
        elif mnemonic == "pop":
            stack = concrete(
                self.read_register(state, self.architecture.stack_pointer), "stack pointer"
            )
            self.write_operand(
                state, insn, operands[0],
                self.read_memory(state, stack, self.architecture.stack_slot_size),
            )
            self.write_register(
                state, self.architecture.stack_pointer,
                bv(
                    stack + self.architecture.stack_slot_size,
                    self.architecture.address_bits,
                ),
            )
        elif mnemonic == "leave":
            stack = concrete(
                self.read_register(state, self.architecture.frame_pointer), "frame pointer"
            )
            self.write_register(
                state, self.architecture.stack_pointer,
                bv(stack, self.architecture.address_bits),
            )
            self.write_register(
                state, self.architecture.frame_pointer,
                self.read_memory(state, stack, self.architecture.stack_slot_size),
            )
            self.write_register(
                state, self.architecture.stack_pointer,
                bv(
                    stack + self.architecture.stack_slot_size,
                    self.architecture.address_bits,
                ),
            )
        elif mnemonic == "ret":
            stack = concrete(
                self.read_register(state, self.architecture.stack_pointer), "stack pointer"
            )
            target = concrete(
                self.read_memory(state, stack, self.architecture.stack_slot_size),
                "return address",
            )
            if target == 0:
                return []
            self.set_program_counter(state, target)
            cleanup = operands[0].imm if operands else 0
            self.write_register(
                state, self.architecture.stack_pointer,
                bv(
                    stack + self.architecture.stack_slot_size + cleanup,
                    self.architecture.address_bits,
                ),
            )
        elif mnemonic == "call":
            # execute call differently depending on userspace func or stdlib func
            target = concrete(
                self.read_operand(state, insn, operands[0]), "call target"
            )
            hook_name = self.image.hooks.get(target)
            if hook_name:
                # external calls are handled by hook's simulation
                self.hook(state, hook_name)
            else:
                # internal calls use the stack
                stack = (
                    concrete(
                        self.read_register(state, self.architecture.stack_pointer),
                        "stack pointer",
                    )
                    - self.architecture.stack_slot_size
                ) & self.architecture.address_mask
                self.write_register(
                    state, self.architecture.stack_pointer,
                    bv(stack, self.architecture.address_bits),
                )
                self.write_memory(
                    state, stack, bv(next_pc, self.architecture.address_bits),
                    self.architecture.stack_slot_size,
                )
                self.set_program_counter(state, target)
        elif mnemonic == "jmp":
            # on jump simply update state pc -> jump target
            self.set_program_counter(
                state,
                concrete(self.read_operand(state, insn, operands[0]), "jump target"),
            )
        elif mnemonic.startswith("j"):
            # fork conditional jumps and retain only satisfiable branches.
            target = concrete(
                self.read_operand(state, insn, operands[0]), "jump target"
            )
            condition = self.condition(mnemonic, state.comparison)
            taken = state.fork()
            self.set_program_counter(taken, target)
            taken.constraints.append(condition)
            state.constraints.append(z3.Not(condition))
            successors = []
            if self.satisfiable(taken.constraints):
                successors.append(taken)
            if self.satisfiable(state.constraints):
                successors.append(state)
            return successors
        elif mnemonic == "cmp":
            # save comparison operands for the following conditional jump.
            left = self.read_operand(state, insn, operands[0])
            state.comparison = (
                "cmp",
                left,
                resize(self.read_operand(state, insn, operands[1]), left.size()),
            )
        elif mnemonic == "test":
            left = self.read_operand(state, insn, operands[0])
            state.comparison = (
                "test",
                left & resize(self.read_operand(state, insn, operands[1]), left.size()),
                bv(0, left.size()),
            )
        elif mnemonic in {"add", "sub", "and", "or", "xor"}:
            # simple integer ops: apply and write the results of integer operation to destination.
            left = self.read_operand(state, insn, operands[0])
            right = resize(self.read_operand(state, insn, operands[1]), left.size())
            self.write_operand(
                state,
                insn,
                operands[0],
                {
                    "add": left + right,
                    "sub": left - right,
                    "and": left & right,
                    "or": left | right,
                    "xor": left ^ right,
                }[mnemonic],
            )
        elif mnemonic == "imul":
            # special imul operation
            if len(operands) == 2:
                left, right = self.read_operand(state, insn, operands[0]), resize(
                    self.read_operand(state, insn, operands[1]),
                    self.read_operand(state, insn, operands[0]).size(),
                )
            elif len(operands) == 3:
                left, right = self.read_operand(state, insn, operands[1]), resize(
                    self.read_operand(state, insn, operands[2]),
                    self.read_operand(state, insn, operands[1]).size(),
                )
            else:
                raise MamboError(f"unsupported imul form: {insn.op_str}")
            self.write_operand(state, insn, operands[0], left * right)
        elif mnemonic in {"shl", "sal", "shr", "sar", "rol", "ror"}:
            # rotation operations
            value = self.read_operand(state, insn, operands[0])
            count = concrete(self.read_operand(state, insn, operands[1]), "shift count")
            result = (
                value << count
                if mnemonic in {"shl", "sal"}
                else z3.LShR(value, count)
                if mnemonic == "shr"
                else value >> count
                if mnemonic == "sar"
                else z3.RotateLeft(value, count)
                if mnemonic == "rol"
                else z3.RotateRight(value, count)
            )
            self.write_operand(state, insn, operands[0], result)
        elif mnemonic in {"inc", "dec"}:
            # increment / decrement
            self.write_operand(
                state,
                insn,
                operands[0],
                self.read_operand(state, insn, operands[0])
                + (1 if mnemonic == "inc" else -1),
            )
        elif mnemonic in {"cdqe", "cltq"}:
            # sign extension
            self.write_register(
                state, "rax", z3.SignExt(32, self.read_register(state, "eax"))
            )
        else:
            raise MamboError(
                f"unsupported instruction at 0x{insn.address:x}: {mnemonic} {insn.op_str}"
            )
        return [state]

    def solve(self, state: State, explored: int, started: float) -> ExecutionResult:
        # Once we reach the target state we compile our accumulated list of constraints and check
        # if it's mathematically satisfiable using z3.

        solver = z3.Solver()
        solver.add(*state.constraints)
        if solver.check() != z3.sat:
            raise MamboError("internal error: target state is unsatisfiable")

        # Solution confirmed working, gather and return our execution results.
        model = solver.model()
        payload = bytes(
            model.eval(self.symbolic_byte(index), model_completion=True).as_long()
            for index in range(state.input_count)
        )
        return ExecutionResult(
            payload, explored, self.executed, time.monotonic() - started
        )

    def execute(self) -> Optional[ExecutionResult]:
        """DFS exploration of possible states until we reach the end, or run out of states"""
        started = time.monotonic()
        pending, explored = [self.initial_state()], 0
        while pending and explored < self.max_states:
            state = pending.pop()
            explored += 1

            while state.steps < self.max_steps:
                if state.pc == self.end:
                    return self.solve(state, explored, started)

                # Convert instruction at pc -> z3 constraints, then returns successor states.
                successors = self.execute_one(state)
                if not successors:
                    break

                # Always take the first branch and push alternatives to the stack.
                state = successors[0]
                pending.extend(successors[1:])
        return None
