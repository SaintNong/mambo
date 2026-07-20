# Mambo

<div align="center">
  <img src="img/mambo.jpg" alt="beautiful mambo">
</div>

Mambo is a lightweight Python-based binary analysis framework designed for basic symbolic execution tasks.
Mainly made as a learning project, though intended to be useful to CTF players.

## technology stack

Mambo at it's core is a combination of the following two libraries:
- z3 for solving
- capstone for reading ELFs

> (it also has pyelftools but that's for loading the binary.)

## What does this do?

Mambo's primary function is basically angr but easier, from a CTF player perspective.

* You only really need three things to get started:
1. A binary.
2. The memory **start address** from which to begin exploration.
3. The memory **end address** where we want to end up.

* If a path is found that connects your start and end addresses, Mambo solves the gathered constraints to provide the exact `stdin` payload required to reach the target.



## Usage

Using Mambo is straightforward. Provide the target binary and the hexadecimal start and end memory addresses of the functions or code blocks you are interested in.

### Commands

```bash
python mambo.py --binary [TARGET_BINARY] --start [START_ADDRESS_HEX] --end [END_ADDRESS_HEX]

# Or just 
python mambo.py --binary [TARGET_BINARY]
# .. and an interactive CLI will ask you for start and end addresses

# Inspect the installed MVP version
python mambo.py --version
```

Mambo currently targets non-PIE x86-64 ELF crackmes. It models stack-local memory, direct calls/returns, comparisons and conditional jumps, plus symbolic stdin from `read`, `gets`, `fgets`, and `getchar`. Output calls such as `write` and `puts` are safely skipped. It also supports the arithmetic used by the included hash fixture: addition, XOR, multiplication, shifts, and rotations.

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