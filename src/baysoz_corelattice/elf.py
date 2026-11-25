"""Minimal, bounds-checked ELF64 reader for BTF-bearing object files.

The reader deliberately implements only what the oracle needs: section names and
section payloads.  It never maps, loads, or executes the object.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

ELF_MAGIC = b"\x7fELF"
ELFCLASS64 = 2
EV_CURRENT = 1
SHT_NOBITS = 8
SHN_XINDEX = 0xFFFF
MAX_SECTIONS = 1 << 20
MAX_SECTION_SIZE = 1 << 30


class ElfError(ValueError):
    """Raised when an ELF container violates the parsed ABI subset."""


@dataclass(frozen=True, slots=True)
class Section:
    """A parsed ELF section header plus its in-memory payload."""

    index: int
    name: str
    section_type: int
    offset: int
    size: int
    payload: bytes


@dataclass(frozen=True, slots=True)
class ElfImage:
    """Immutable view of an ELF64 object's sections."""

    sections: tuple[Section, ...]
    machine: int
    little_endian: bool

    def payload(self, name: str) -> bytes | None:
        """Return a named section payload, or None when the section is absent."""
        for section in self.sections:
            if section.name == name:
                return section.payload
        return None

    def require(self, name: str) -> bytes:
        """Return a named section payload or raise a precise parsing error."""
        payload = self.payload(name)
        if payload is None:
            raise ElfError(f"required section {name!r} is missing from ELF object")
        return payload


def _endianness(data: bytes) -> bool:
    if len(data) < 16 or data[:4] != ELF_MAGIC:
        raise ElfError("missing ELF64 magic")
    if data[4] != ELFCLASS64:
        raise ElfError("only ELF64 objects are supported")
    if data[5] not in (1, 2):
        raise ElfError("invalid ELF byte order")
    if data[6] != EV_CURRENT:
        raise ElfError("unsupported ELF version")
    return data[5] == 1


def parse_elf(data: bytes) -> ElfImage:
    """Parse ELF64 section headers and payloads with strict bounds checks."""
    little_endian = _endianness(data)
    prefix = "<" if little_endian else ">"
    header_size = struct.calcsize(prefix + "HHIQQQIHHHHHH")
    if len(data) < 16 + header_size:
        raise ElfError("truncated ELF header")
    fields = struct.unpack_from(prefix + "HHIQQQIHHHHHH", data, 16)
    (
        _e_type,
        machine,
        e_version,
        _e_entry,
        _e_phoff,
        e_shoff,
        _e_flags,
        _e_ehsize,
        _e_phentsize,
        _e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = fields
    if e_version != EV_CURRENT:
        raise ElfError("unsupported ELF header version")
    expected_shentsize = struct.calcsize(prefix + "IIQQQQIIQQ")
    if e_shentsize != expected_shentsize:
        raise ElfError(f"unexpected ELF section header size {e_shentsize}")
    if e_shoff == 0 or e_shnum == 0:
        raise ElfError("ELF object has no section table")
    if e_shnum > MAX_SECTIONS:
        raise ElfError("ELF section count exceeds the supported limit")
    table_end = e_shoff + e_shnum * e_shentsize
    if e_shoff < 16 + header_size or table_end > len(data):
        raise ElfError("ELF section table is out of bounds")

    headers: list[tuple[int, int, int, int, bytes]] = []
    for index in range(e_shnum):
        offset = e_shoff + index * e_shentsize
        sh_name, sh_type, _flags, _addr, sh_offset, sh_size, _link, _info, _align, _entsize = (
            struct.unpack_from(prefix + "IIQQQQIIQQ", data, offset)
        )
        if sh_type == SHT_NOBITS:
            payload = b""
        else:
            if sh_offset > len(data) or sh_size > MAX_SECTION_SIZE:
                raise ElfError(f"section {index} has an out-of-bounds payload")
            if sh_offset + sh_size > len(data):
                raise ElfError(f"section {index} payload is truncated")
            payload = data[sh_offset : sh_offset + sh_size]
        headers.append((sh_name, sh_type, sh_offset, sh_size, payload))

    name_index = e_shstrndx
    if name_index == SHN_XINDEX:
        name_index = struct.unpack_from(prefix + "I", data, e_shoff + 40)[0]
    if name_index >= len(headers):
        raise ElfError("ELF section name table index is out of bounds")
    shstrtab = headers[name_index][4]
    sections = tuple(
        Section(
            index=index,
            name=_string(shstrtab, sh_name, f"section {index} name"),
            section_type=sh_type,
            offset=sh_offset,
            size=sh_size,
            payload=payload,
        )
        for index, (sh_name, sh_type, sh_offset, sh_size, payload) in enumerate(headers)
    )
    return ElfImage(sections, machine, little_endian)


def _string(table: bytes, offset: int, label: str) -> str:
    if offset >= len(table):
        raise ElfError(f"{label} offset is out of bounds")
    end = table.find(b"\x00", offset)
    if end < 0:
        raise ElfError(f"{label} is not NUL terminated")
    try:
        return table[offset:end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ElfError(f"{label} is not valid UTF-8") from exc
