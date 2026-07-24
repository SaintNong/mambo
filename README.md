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
- capstone for reading ELFs

> (it also has pyelftools but that's for loading the binary sections.)

## What does this do?

Mambo's primary function is basically angr but easier, from a CTF player perspective.

You only really need three things to get started:

1. A binary.
2. The memory **start address** from which to begin exploration.
3. The memory **end address** where we want to end up.

If a path is found that connects your start and end addresses, Mambo solves the gathered constraints to provide the exact `stdin` payload required to reach the target.


## Usage

Using Mambo is easy. Provide the target binary and the hexadecimal start and end memory addresses of the functions or code blocks you are interested in.

### Commands

```bash
python mambo.py --binary [TARGET_BINARY] --start [START_ADDRESS_HEX] --end [END_ADDRESS_HEX]

# Or just 
python mambo.py --binary [TARGET_BINARY]
# .. and an interactive CLI will ask you for start and end addresses
```

Mambo currently targets non-PIE x86-64 ELF crackmes. It models stack-local memory, direct calls/returns, comparisons and conditional jumps, plus symbolic stdin from `read`, `gets`, `fgets`, and `getchar`. Output calls such as `write` and `puts` are safely skipped. It also supports the arithmetic used by the included hash fixture: addition, XOR, multiplication, shifts, and rotations.

### Python API

> if anyone ever uses this please message me on discord because that would be hilarious (don't use this, get help)

Use `Mambo` directly when embedding the solver in another tool. `run()` (or its `solve()` alias) returns an `ExecutionResult`, or `None` when no satisfiable path is found within the configured limits.

```python
from mambo import Mambo

result = Mambo("examples/simple_crackme", 0x401175, 0x401156).solve()
if result is not None:
    print(result.payload)
```

The `Mambo` constructor accepts the same `max_input`, `max_states`, and `max_steps` limits as the CLI. Invalid input, binary, and executor conditions raise `MamboError`.

The included examples can be exercised using their named symbols:

```bash
# Find start and end addresses
START=0x$(nm examples/simple_crackme | awk '$3 == "main" {print $1}')
END=0x$(nm examples/simple_crackme | awk '$3 == "mambo_success" {print $1}')
.venv/bin/python mambo.py --binary examples/simple_crackme --start "$START" --end "$END"

# Emit the satisfying payload as one JSON object for scripts
.venv/bin/python mambo.py --json --binary examples/simple_crackme --start "$START" --end "$END"

START=0x$(nm examples/hash_crackme | awk '$3 == "main" {print $1}')
END=0x$(nm examples/hash_crackme | awk '$3 == "mambo_hash_success" {print $1}')
.venv/bin/python mambo.py --binary examples/hash_crackme --start "$START" --end "$END"

```

Run our test suite with:

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
