"""ELF parsing and memory access for the executor."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

from .errors import MamboError
from .models import Segment


class ELFImage:
    """The parts of an ELF file needed by the executor."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        try:
            self._raw = self.path.read_bytes()
        except OSError as exc:
            raise MamboError(f"cannot read binary: {exc}") from exc

        self.segments: List[Segment] = []
        self.symbols: Dict[int, str] = {}
        self.symbol_addresses: Dict[str, List[int]] = {}
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
                            self.symbol_addresses.setdefault(symbol.name, []).append(address)

            self._load_plt_hooks(elf)

        self.symbol_addresses = {
            name: sorted(set(addresses))
            for name, addresses in self.symbol_addresses.items()
        }

    def symbol_address(self, name: str) -> int:
        """Return the unique executable address for a symbol name."""
        addresses = self.symbol_addresses.get(name, [])
        if not addresses:
            raise MamboError(f"symbol not found: {name}")
        if len(addresses) > 1:
            formatted = ", ".join(f"0x{address:x}" for address in addresses)
            raise MamboError(f"symbol {name!r} is ambiguous: {formatted}")
        address = addresses[0]
        if not self.is_executable(address):
            raise MamboError(f"symbol {name!r} is not executable")
        return address

    def executable_symbols(self) -> List[tuple[str, int]]:
        """Return uniquely named executable symbols and their addresses."""
        symbols = []
        for name, addresses in self.symbol_addresses.items():
            if len(addresses) == 1 and self.is_executable(addresses[0]):
                symbols.append((name, addresses[0]))
        return sorted(symbols, key=lambda item: (item[1], item[0]))

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
