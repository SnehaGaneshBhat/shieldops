"""Helpers for reading supported Linux ELF binaries."""

import re
from dataclasses import dataclass, field

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

SUPPORTED_ARCH = {"x64", "AArch64"}
SUFFIX_RE = re.compile(r"[.](constprop|isra|part|cold|lto_priv|localalias)([.][0-9]+)?$")


class NotSupportedBinary(Exception):
    """Raised for non-ELF, malformed, or unsupported-architecture input."""


@dataclass
class ElfInfo:
    path: str
    defined_funcs: set = field(default_factory=set)
    imports: set = field(default_factory=set)
    rodata_strings: set = field(default_factory=set)
    has_symtab: bool = False
    sections: list = field(default_factory=list)


def _clean(name):
    name = name.split("@")[0]
    while True:
        shorter = SUFFIX_RE.sub("", name)
        if shorter == name:
            return name
        name = shorter


def load_elf(path):
    info = ElfInfo(path=str(path))
    with open(path, "rb") as stream:
        if stream.read(4) != bytes([0x7F, 0x45, 0x4C, 0x46]):
            raise NotSupportedBinary("Output is not an ELF file. The MVP supports Linux ELF only")
        stream.seek(0)
        try:
            elf = ELFFile(stream)
            if elf.get_machine_arch() not in SUPPORTED_ARCH:
                raise NotSupportedBinary("Unsupported ELF architecture. The MVP supports x86-64 and AArch64")
            info.sections = [section.name for section in elf.iter_sections()]
            symtab = elf.get_section_by_name(".symtab")
            if isinstance(symtab, SymbolTableSection):
                info.has_symtab = True
                for sym in symtab.iter_symbols():
                    if sym.name and sym["st_info"]["type"] == "STT_FUNC" and sym["st_shndx"] != "SHN_UNDEF":
                        info.defined_funcs.add(_clean(sym.name))
            dynsym = elf.get_section_by_name(".dynsym")
            if isinstance(dynsym, SymbolTableSection):
                for sym in dynsym.iter_symbols():
                    if sym.name and sym["st_shndx"] == "SHN_UNDEF":
                        info.imports.add(_clean(sym.name))
            rodata = elf.get_section_by_name(".rodata")
            if rodata is not None:
                for chunk in rodata.data().split(bytes([0])):
                    try:
                        text = chunk.decode("utf-8").strip()
                    except UnicodeDecodeError:
                        continue
                    if text and text.isprintable():
                        info.rodata_strings.add(text)
        except ELFError as exc:
            raise NotSupportedBinary(f"Could not parse ELF file: {exc}") from exc
    return info
