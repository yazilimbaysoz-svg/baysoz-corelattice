"""Binary fixture builders for adversarial BTF/CO-RE tests.

Every fixture is constructed from the documented Linux UAPI layouts; no golden
binary blobs are copied from third parties.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

BTF_MAGIC = 0xEB9F
KIND_INT = 1
KIND_PTR = 2
KIND_ARRAY = 3
KIND_STRUCT = 4
KIND_UNION = 5
KIND_ENUM = 6
KIND_TYPEDEF = 8
KIND_ENUM64 = 19


@dataclass(slots=True)
class BtfBuilder:
    """Assemble a spec-compliant BTF blob for negative and positive tests."""

    strings: bytearray = field(default_factory=lambda: bytearray(b"\x00"))
    _offsets: dict[str, int] = field(default_factory=dict)
    records: list[tuple[int, int, int, bytes]] = field(default_factory=list)

    def string(self, value: str) -> int:
        """Intern a string and return its BTF string-table offset."""
        if not value:
            return 0
        if value not in self._offsets:
            self._offsets[value] = len(self.strings)
            self.strings.extend(value.encode("utf-8") + b"\x00")
        return self._offsets[value]

    def add(
        self,
        name: str,
        kind: int,
        *,
        vlen: int = 0,
        kflag: bool = False,
        size: int = 0,
        ref: int = 0,
        extra: bytes = b"",
    ) -> int:
        """Append a BTF type record and return its 1-based type id."""
        info = (vlen & 0xFFFFFF) | ((kind & 0x7F) << 24) | ((1 << 31) if kflag else 0)
        self.records.append((self.string(name), info, size if not ref else ref, extra))
        return len(self.records)

    def int_type(self, name: str, bits: int = 32, signed: bool = False) -> int:
        """Add an integer type with the correct encoding word."""
        encoding = (1 if signed else 0) << 24
        encoded = struct.pack("<I", encoding | bits)
        return self.add(name, KIND_INT, size=(bits + 7) // 8, extra=encoded)

    def ptr_type(self, target: int) -> int:
        """Add a pointer type."""
        return self.add("", KIND_PTR, ref=target)

    def typedef(self, name: str, target: int) -> int:
        """Add a typedef alias."""
        return self.add(name, KIND_TYPEDEF, ref=target)

    def array_type(self, element: int, index: int, count: int) -> int:
        """Add a fixed-size array type."""
        return self.add(
            "",
            KIND_ARRAY,
            extra=struct.pack("<III", element, index, count),
        )

    def struct_type(
        self,
        name: str,
        members: list[tuple[str, int, int, int]],
        *,
        kind: int = KIND_STRUCT,
        kflag: bool = False,
        size: int = 64,
    ) -> int:
        """Add a struct/union; members are (name, type_id, byte_or_bit_offset, bit_size)."""
        extra = b"".join(
            struct.pack(
                "<III",
                self.string(member_name),
                type_id,
                ((bit_size << 24) | (offset if kflag else offset)) & 0xFFFFFFFF,
            )
            for member_name, type_id, offset, bit_size in members
        )
        return self.add(name, kind, vlen=len(members), kflag=kflag, size=size, extra=extra)

    def enum_type(
        self,
        name: str,
        values: list[tuple[str, int]],
        *,
        kind: int = KIND_ENUM,
        size: int = 4,
    ) -> int:
        """Add a 32-bit or 64-bit enumeration."""
        if kind == KIND_ENUM:
            extra = b"".join(
                struct.pack("<Ii", self.string(member_name), value)
                for member_name, value in values
            )
        else:
            extra = b"".join(
                struct.pack("<III", self.string(member_name), value & 0xFFFFFFFF, value >> 32)
                for member_name, value in values
            )
        return self.add(name, kind, vlen=len(values), size=size, extra=extra)

    def build(self, *, corrupt_magic: bool = False, truncate: int = 0) -> bytes:
        """Serialize the BTF blob with optional adversarial corruption."""
        type_blob = bytearray()
        for name_off, info, ref, extra in self.records:
            type_blob.extend(struct.pack("<III", name_off, info, ref))
            type_blob.extend(extra)
        payload = bytes(type_blob[: len(type_blob) - truncate]) if truncate else bytes(type_blob)
        strings = bytes(self.strings)
        magic = 0xDEAD if corrupt_magic else BTF_MAGIC
        return struct.pack(
            "<HBBIIIII", magic, 1, 0, 24, 0, len(payload), len(payload), len(strings)
        ) + payload + strings


def make_ext(
    builder: BtfBuilder,
    relocations: list[tuple[int, int, str, int]],
    *,
    section: str = ".text",
    record_size: int = 16,
    bad_kind: bool = False,
) -> bytes:
    """Serialize a .BTF.ext blob with CO-RE relocation records."""
    info = bytearray(struct.pack("<I", record_size))
    info.extend(struct.pack("<II", builder.string(section), len(relocations)))
    for insn_off, type_id, access, kind in relocations:
        info.extend(
            struct.pack(
                "<IIII",
                insn_off,
                type_id,
                builder.string(access),
                99 if bad_kind else kind,
            )[:record_size]
        )
    header = struct.pack(
        "<HBBIIIII",
        BTF_MAGIC,
        1,
        0,
        32,
        0,
        0,
        0,
        0,
    )
    return header + struct.pack("<II", 0, len(info)) + bytes(info)


def make_elf(sections: dict[str, bytes], *, bad_magic: bool = False) -> bytes:
    """Serialize a minimal but valid ELF64 object with named sections."""
    shstrtab = bytearray(b"\x00")
    name_offsets = {".shstrtab": 0}
    for name in sections:
        name_offsets[name] = len(shstrtab)
        shstrtab.extend(name.encode("utf-8") + b"\x00")

    payloads = {name: data for name, data in sections.items()}
    payloads[".shstrtab"] = bytes(shstrtab)
    ordered = [".shstrtab", *sections]

    body = bytearray()
    offsets: dict[str, int] = {}
    for name in ordered:
        while len(body) % 8:
            body.append(0)
        offsets[name] = 64 + len(body)
        body.extend(payloads[name])
    while len(body) % 8:
        body.append(0)
    shoff = 64 + len(body)
    shnum = len(ordered) + 1

    headers = bytearray(b"\x00" * 64)
    for name in ordered:
        data = payloads[name]
        headers.extend(
            struct.pack(
                "<IIQQQQIIQQ",
                name_offsets[name],
                1,
                0,
                0,
                offsets[name],
                len(data),
                0,
                0,
                8,
                0,
            )
        )

    ident = bytearray(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)
    if bad_magic:
        ident[0] = 0x00
    elf_header = bytes(ident) + struct.pack(
        "<HHIQQQIHHHHHH",
        1,
        247,
        1,
        0,
        0,
        shoff,
        0,
        64,
        0,
        0,
        64,
        shnum,
        1,
    )
    return elf_header + bytes(body) + bytes(headers)
