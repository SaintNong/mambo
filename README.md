# Mambo

[![Tests](https://github.com/SaintNong/mambo/actions/workflows/test.yml/badge.svg)](https://github.com/SaintNong/mambo/actions/workflows/test.yml)

<div align="center">
  <img src="img/mambo.jpg" alt="beautiful mambo" width="35%">
  <img src="img/mambo2.jpg" alt="beautiful mambo x2" width="45%">
</div>

Mambo is a lightweight symbolic execution engine.
Mainly made as a learning project, though intended to be useful to CTF players.

## technology stack

Mambo at its core is a combination of the following two libraries:
- z3 for solving
- capstone for disassembling machine code

> (it also uses pyelftools to parse ELF files and load their sections.)

## What does this do?

Mambo's primary function is basically angr but easier, from a CTF player perspective.

You only really need three things to get started:

1. A binary.
2. The **start address** or symbol from which to begin exploration.
3. The **end address** or symbol where we want to end up.

If a path is found that connects your start and end addresses, Mambo solves the gathered constraints to provide the exact `stdin` payload required to reach the target.


## Usage

Using Mambo is easy. Provide the target binary and either the hexadecimal start and end addresses or the corresponding symbol names.

### Commands

```bash
python mambo.py --binary [TARGET_BINARY] --start [START_ADDRESS_HEX] --end [END_ADDRESS_HEX]

# Or use symbol names
python mambo.py --binary [TARGET_BINARY] --start-symbol [START_SYMBOL] --end-symbol [END_SYMBOL]

# Or just 
python mambo.py --binary [TARGET_BINARY]
# .. and an interactive CLI will ask you for start and end addresses
```

Mambo currently targets non-PIE x86-64 ELF crackmes. It models stack-local memory, direct calls/returns, comparisons and conditional jumps, plus symbolic stdin from `read`, `gets`, `fgets`, and `getchar`. Output calls such as `write` and `puts` are modeled as no-ops that return zero; their stdout is not captured during analysis. It supports the following arithmetic operations: addition, XOR, multiplication, shifts, and rotations.

### Python API

> if anyone ever uses this please message me on discord because that would be hilarious (don't use this, get help)

Use `Mambo` directly when embedding the solver in another tool. `solve()` returns an `ExecutionResult`, or `None` when no satisfiable path is found within the configured limits.

```python
from mambo import Mambo

solver = Mambo("examples/simple_crackme")
result = solver.solve(0x40116b, 0x401156)
if result is not None:
    print(result.payload)

# Symbol names can be used instead
result = solver.solve_symbols("main", "mambo_success")
```

The `Mambo` constructor accepts the same `max_input`, `max_states`, and `max_steps` limits as the CLI. Invalid input, binary, and executor conditions raise `MamboError`.

The included examples can be exercised using their named symbols:

```bash
.venv/bin/python mambo.py --binary examples/simple_crackme --start-symbol main --end-symbol mambo_success

# Emit the satisfying payload as one JSON object for scripts
.venv/bin/python mambo.py --json --binary examples/simple_crackme --start-symbol main --end-symbol mambo_success

.venv/bin/python mambo.py --binary examples/hash_crackme --start-symbol main --end-symbol mambo_hash_success

```

Test the project with:

```bash
make test PYTHON=.venv/bin/python
```

## Installation

### Prerequisites

* Python 3.x
* `pip` package manager

Install the Python dependencies and build the included example:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
make
```

## Limitations

### Supported

- Non-PIE x86-64 ELF binaries
- Stack-local and mapped ELF memory
- Direct `call`, `ret`, `jmp`, and conditional jumps (`je`/`jne` and signed or unsigned relational variants)
- Basic data movement: `mov`, `movzx`, `movsx`, `movsxd`, and `lea`
- Stack and control instructions: `push`, `pop`, `leave`, `nop`, and `endbr64`
- Integer operations: `add`, `sub`, `and`, `or`, `xor`, `imul`, `inc`, `dec`, shifts, and rotates
- Comparisons with `cmp` and `test`
- Symbolic input from `read`, `gets`, `fgets`, and `getchar`
- Common output functions such as `write`, `puts`, `printf`, and `putchar` are modeled as no-ops returning zero

### Not supported

- stdout is not captured
- PIE or non-x86-64 binaries
- Heap allocation, `malloc` and `free`
- Indirect or unresolved calls
- Symbolic memory addresses
- Full operating-system or library behavior
- Other x86-64 instructions, including `setcc`, `cmovcc`, `mul`/`div`, string instructions, SIMD instructions, and system calls

Keep in mind that not finding a path does not prove that no path exists.
