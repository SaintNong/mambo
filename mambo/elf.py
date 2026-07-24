"""load ELF metadata and provide api for memory access for the execution engine"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from capstone import CS_MODE_32, CS_MODE_64

from .errors import MamboError
from .models import ArchitectureProfile, Segment


ARCHITECTURES = {
    "x64": ArchitectureProfile(
        "x86-64", CS_MODE_64, 64, "rip", "rsp", "rbp", "rax", 8,
        0x7FFF_FFFF_F000,
        ("rdi", "rsi", "rdx", "rcx", "r8", "r9"),
    ),
    "x86": ArchitectureProfile(
        "i386", CS_MODE_32, 32, "eip", "esp", "ebp", "eax", 4,
        0xFFFF_F000, (),
    ),
}


class ELFImage:
    """Represent the executable parts of a non-PIE i386 or x86-64 ELF file."""

    def __init__(self, path: str | Path):
        """load segments, symbols, and external function hooks from a binary."""
        self.path = Path(path)
        try:
            self._raw = self.path.read_bytes()
        except OSError as exc:
            raise MamboError(f"cannot read binary: {exc}") from exc

        self.segments: List[Segment] = []
        self.symbols: Dict[int, str] = {}
        self.symbol_addresses: Dict[str, List[int]] = {}
        self.hooks: Dict[int, str] = {}
        self.external_object_slots: Dict[int, str] = {}

        with self.path.open("rb") as stream:
            elf = ELFFile(stream)
            machine = elf.get_machine_arch()
            try:
                self.architecture = ARCHITECTURES[machine]
            except KeyError as exc:
                raise MamboError(
                    "only non-PIE x86 ELF binaries (i386 or x86-64) are supported"
                ) from exc
            if elf.header["e_type"] == "ET_DYN":
                raise MamboError("PIE binaries are not supported; compile with -fno-pie -no-pie")

            # Keep loadable segments for instruction and data memory access.
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

            # Index symbols both by address and by name for endpoint lookup.
            for section in elf.iter_sections():
                if isinstance(section, SymbolTableSection):
                    for symbol in section.iter_symbols():
                        address = int(symbol["st_value"])
                        if address and symbol.name:
                            self.symbols.setdefault(address, symbol.name)
                            self.symbol_addresses.setdefault(symbol.name, []).append(address)

            self._load_plt_hooks(elf)
            self._load_external_object_slots(elf)

        self.symbol_addresses = {
            name: sorted(set(addresses))
            for name, addresses in self.symbol_addresses.items()
        }

    def symbol_address(self, name: str) -> int:
        """return the executable address for a symbol name."""
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
        """return uniquely named executable symbols and their addresses."""
        symbols = []
        for name, addresses in self.symbol_addresses.items():
            if len(addresses) == 1 and self.is_executable(addresses[0]):
                symbols.append((name, addresses[0]))
        return sorted(symbols, key=lambda item: (item[1], item[0]))

    def _load_plt_hooks(self, elf: ELFFile) -> None:
        """map PLT entry addresses to the external functions they call."""
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

        # GNU i386/x86-64 PLT stubs are 16 bytes.  Some i386 linkers report
        # the instruction-alignment value (4) as ``sh_entsize`` for ``.plt``.
        entry_size = 16
        base = int(plt_sec["sh_addr"])
        for index, name in enumerate(relocations):
            address = base + (index + (1 if reserved_entry else 0)) * entry_size
            self.hooks[address] = name

    def _load_external_object_slots(self, elf: ELFFile) -> None:
        """Find relocated libc stream-global pointers used by the executable."""
        for section in elf.iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            symbols = elf.get_section(section["sh_link"])
            for relocation in section.iter_relocations():
                symbol = symbols.get_symbol(relocation["r_info_sym"])
                if (
                    symbol.name in {"stdin", "stdout", "stderr"}
                    and symbol["st_info"]["type"] == "STT_OBJECT"
                ):
                    self.external_object_slots[int(relocation["r_offset"])] = symbol.name

    def read(self, address: int, size: int) -> bytes:
        """read bytes from a mapped loadable segment."""
        for segment in self.segments:
            if segment.contains(address, size):
                offset = address - segment.address
                available = segment.data[offset : offset + size]
                return available + bytes(size - len(available))
        raise MamboError(f"unmapped memory read at 0x{address:x}")

    def byte(self, address: int) -> int:
        """read one byte from mapped memory."""
        return self.read(address, 1)[0]

    def is_executable(self, address: int) -> bool:
        """return whether an address belongs to an executable segment."""
        return any(segment.executable and segment.contains(address) for segment in self.segments)
