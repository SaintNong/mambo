# Mambo

[![Tests](https://github.com/SaintNong/mambo/actions/workflows/test.yml/badge.svg)](https://github.com/SaintNong/mambo/actions/workflows/test.yml)

Mambo is a lightweight symbolic execution engine.
Mainly made as a learning project, though intended to be useful to CTF players.

<div align="center">
  <p>Some beautiful pictures of mambo.</p>
  <img src="img/mambo.jpg" alt="beautiful mambo" width="35%">
  <img src="img/mambo2.jpg" alt="beautiful mambo x2" width="45%">
</div>


## Technology stack

Mambo at its core is a combination of the following two libraries:
- z3 for solving
- capstone for disassembling machine code

> (it also uses pyelftools to parse ELF files and load their sections.)

## What does this do?

Mambo's primary function is basically angr but easier, from a CTF player perspective.

You only really need two things to get started:

1. A binary.
2. The ending address or symbol where we want to end up.

If a path is found that connects your start and end addresses, Mambo solves the gathered constraints to provide the exact `stdin` payload required to reach the target.

Mambo currently is best for non-PIE x86-64 ELF crackmes. It models stack-local memory, direct calls/returns, comparisons and conditional jumps, plus symbolic stdin from `read`, `gets`, `fgets`, and `getchar`. Output calls such as `write` and `puts` are modeled as no-ops that always return zero; though their stdout is not captured during analysis. It supports the following arithmetic operations: addition, subtraction, bitwise AND/OR/XOR, signed multiplication (`imul`), increment/decrement, shifts, and rotations.

## Usage

Using Mambo is easy. Provide the target binary and either the hex start and end addresses, or the corresponding symbol names.

### Command Line

> if anyone ever uses this please message me on discord because that would be hilarious

```bash
# Easiest way
python mambo.py --binary [TARGET_BINARY]
# .. and an interactive CLI will ask you for start and end addresses/symbols
#    it will even print all executable symbols in the binary

# Using hex start/end
python mambo.py --binary [TARGET_BINARY] --start [START_ADDR] --end [END_ADDR]

# Or use symbol names
python mambo.py --binary [TARGET_BINARY] --start-symbol [START] --end-symbol [END]

```


### Python API

Use `Mambo` directly when embedding the solver in a CTF-style solve script:

```python
from mambo import Mambo

# (make sure to run make first so this binary exists)
solver = Mambo("examples/simple_crackme")
result = solver.solve_symbol("mambo_success")

if result is not None:
    print(result.payload)
```

Use `solve_symbol` when the binary has useful symbols; use `solve` when working
with disassembly addresses or to go to the middle of a function. If the start point is omitted, exploration
begins at `main`.


#### Creating a solver

```python
solver = Mambo(
    "path/to/binary",
    max_input=64,
    max_states=1000,
    max_steps=10_000,
)
```

| Argument | Description |
|---|---|
| `binary` | Path to a non-PIE x86-64 ELF binary |
| `max_input` | Maximum number of symbolic stdin bytes |
| `max_states` | Maximum number of paths to explore |
| `max_steps` | Maximum instructions executed by each path |

#### Solving

| Method | Arguments | Description |
|---|---|---|
| `solve(end)` | End address | Solve from `main` to an address |
| `solve(start, end)` | Start and end addresses | Solve between two addresses |
| `solve_symbol(end)` | End symbol | Solve from `main` to a symbol |
| `solve_symbol(start, end)` | Start and end symbols | Solve between two symbols |

Addresses are integers, for example `0x401156`. Symbols are strings, such as
`"main"` or `"mambo_success"`.

> [!NOTE]
> omitted start require an executable ELF symbol named `main`.
> This can fail for fully stripped binaries or binaries with a custom entry point.
> Use explicit start and end addresses with `solve(start, end)` when
> `main` cannot be resolved.

#### Results

Each solve method returns an `ExecutionResult`, or `None` if no satisfiable path
is found within the configured limits:

```python
result.payload
result.explored_states
result.executed_instructions
result.elapsed_seconds
```

Invalid arguments, binaries, or executor conditions raise `MamboError`.

See [`demo.py`](demo.py) for additional examples.


## Installation

Prerequisites are python 3.x, and pip.

Install the Python dependencies and build the included example:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
make
```

Test the project with:

```bash
make test PYTHON=.venv/bin/python
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
