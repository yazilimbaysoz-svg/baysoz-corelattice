"""Pure-Python BTF reader with a strict type graph and bounded recursion.

The parser implements the Linux UAPI ``struct btf_header``/``struct btf_type``
layout for little- and big-endian blobs, including split-BTF compatible headers.
It performs no syscalls and never trusts offsets from the input.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

BTF_MAGIC = 0xEB9F
BTF_VERSION = 1
BTF_HEADER_MIN = 24
BTF_HEADER_MAX = 64
MAX_TYPES = 1 << 22
MAX_STRINGS = 1 << 28

KIND_UNKNOWN = 0
KIND_INT = 1
KIND_PTR = 2
KIND_ARRAY = 3
KIND_STRUCT = 4
KIND_UNION = 5
KIND_ENUM = 6
KIND_FWD = 7
KIND_TYPEDEF = 8
KIND_VOLATILE = 9
KIND_CONST = 10
KIND_RESTRICT = 11
KIND_FUNC = 12
KIND_FUNC_PROTO = 13
KIND_VAR = 14
KIND_DATASEC = 15
KIND_FLOAT = 16
KIND_DECL_TAG = 17
KIND_TYPE_TAG = 18
KIND_ENUM64 = 19
KIND_LOC_PARAM = 20
KIND_LOC_PROTO = 21
KIND_LOCSEC = 22

KIND_NAMES = {
    KIND_UNKNOWN: "unknown",
    KIND_INT: "int",
    KIND_PTR: "ptr",
    KIND_ARRAY: "array",
    KIND_STRUCT: "struct",
    KIND_UNION: "union",
    KIND_ENUM: "enum",
    KIND_FWD: "fwd",
    KIND_TYPEDEF: "typedef",
    KIND_VOLATILE: "volatile",
    KIND_CONST: "const",
    KIND_RESTRICT: "restrict",
    KIND_FUNC: "func",
    KIND_FUNC_PROTO: "func_proto",
    KIND_VAR: "var",
    KIND_DATASEC: "datasec",
    KIND_FLOAT: "float",
    KIND_DECL_TAG: "decl_tag",
    KIND_TYPE_TAG: "type_tag",
    KIND_ENUM64: "enum64",
    KIND_LOC_PARAM: "loc_param",
    KIND_LOC_PROTO: "loc_proto",
    KIND_LOCSEC: "locsec",
}

QUALIFIER_KINDS = frozenset(
    {KIND_TYPEDEF, KIND_VOLATILE, KIND_CONST, KIND_RESTRICT, KIND_TYPE_TAG, KIND_DECL_TAG}
)
COMPOSITE_KINDS = frozenset({KIND_STRUCT, KIND_UNION})
ENUM_KINDS = frozenset({KIND_ENUM, KIND_ENUM64})
MAX_RESOLVE_DEPTH = 64


class BtfError(ValueError):
    """Raised when a BTF blob violates the parsed ABI subset."""


@dataclass(frozen=True, slots=True)
class Member:
    """A struct or union member with both byte and bit geometry."""

    name: str
    type_id: int
    byte_offset: int
    bit_offset: int
    bitfield_size: int

    @property
    def end_bit(self) -> int:
        """Exclusive upper bound of the member in bit space."""
        return self.bit_offset + (self.bitfield_size or 0)


@dataclass(frozen=True, slots=True)
class EnumValue:
    """A named enumeration constant."""

    name: str
    value: int


@dataclass(frozen=True, slots=True)
class ArrayInfo:
    """BTF array geometry."""

    element_type: int
    index_type: int
    count: int


@dataclass(frozen=True, slots=True)
class BtfType:
    """One parsed BTF type record."""

    id: int
    name: str
    kind: int
    kind_flag: bool
    vlen: int
    size: int
    type_ref: int
    members: tuple[Member, ...] = ()
    enum_values: tuple[EnumValue, ...] = ()
    array: ArrayInfo | None = None
    int_bits: int = 0
    int_signed: bool = False

    @property
    def kind_name(self) -> str:
        """Human-readable BTF kind."""
        return KIND_NAMES.get(self.kind, f"kind-{self.kind}")


@dataclass(frozen=True, slots=True)
class Btf:
    """Immutable parsed BTF blob."""

    types: tuple[BtfType, ...]
    little_endian: bool
    origin: str = "BTF"
    base: Btf | None = None
    _strings: bytes = b""

    def __len__(self) -> int:
        return len(self.types)

    def type_at(self, type_id: int) -> BtfType:
        """Return a type by id, falling back to the base BTF for split objects."""
        if 0 < type_id <= len(self.types):
            return self.types[type_id - 1]
        if self.base is not None:
            return self.base.type_at(type_id)
        raise BtfError(f"type id {type_id} is out of range for {self.origin}")

    def has_type(self, type_id: int) -> bool:
        """Return True when a type id exists in this BTF or its base."""
        if 0 < type_id <= len(self.types):
            return True
        return self.base is not None and self.base.has_type(type_id)

    def string(self, offset: int) -> str:
        """Return the BTF string at an offset from this blob or its base."""
        return self._string_offset(offset)

    def _string_offset(self, offset: int) -> str:
        if 0 <= offset < len(self._strings):
            return _string(self._strings, offset, self.origin)
        if self.base is not None:
            return self.base.string(offset)
        raise BtfError(f"{self.origin}: string offset {offset} is out of bounds")

    def find_by_name(self, name: str, kinds: frozenset[int] | None = None) -> tuple[int, ...]:
        """Return all type ids with a given name, optionally filtered by kind."""
        result = [t.id for t in self.types if t.name == name and (kinds is None or t.kind in kinds)]
        if self.base is not None:
            result.extend(self.base.find_by_name(name, kinds))
        return tuple(result)

    def strip_qualifiers(self, type_id: int) -> BtfType:
        """Follow typedefs and qualifiers to the underlying concrete type."""
        seen: set[int] = set()
        current = self.type_at(type_id)
        while current.kind in QUALIFIER_KINDS and current.type_ref:
            if current.id in seen or len(seen) >= MAX_RESOLVE_DEPTH:
                raise BtfError(f"qualifier cycle at type id {current.id}")
            seen.add(current.id)
            current = self.type_at(current.type_ref)
        return current

    def size_of(self, type_id: int, pointer_size: int = 8) -> int:
        """Return the byte size of a type, or 0 when the kind carries no size."""
        target = self.strip_qualifiers(type_id)
        sized = {KIND_INT, KIND_FLOAT, KIND_ENUM, KIND_ENUM64, *COMPOSITE_KINDS, KIND_DATASEC}
        if target.kind in sized:
            return target.size
        if target.kind == KIND_ARRAY and target.array is not None:
            return target.array.count * self.size_of(target.array.element_type, pointer_size)
        if target.kind == KIND_PTR:
            return pointer_size
        return 0

    def is_signed(self, type_id: int) -> bool:
        """Return signedness of an integer type after qualifier stripping."""
        return self.strip_qualifiers(type_id).int_signed

    def label(self, type_id: int) -> str:
        """Return a stable human-readable type label."""
        target = self.strip_qualifiers(type_id)
        return f"{target.kind_name} {target.name!r} (id={target.id})"


def parse_btf(
    data: bytes,
    *,
    origin: str = "BTF",
    base: Btf | None = None,
    little_endian: bool = True,
) -> Btf:
    """Parse a raw BTF blob with strict header, string, and type bounds."""
    if len(data) < BTF_HEADER_MIN:
        raise BtfError(f"{origin}: truncated BTF header")
    prefix = "<" if little_endian else ">"
    magic, version, _flags, hdr_len, type_off, type_len, str_off, str_len = struct.unpack_from(
        prefix + "HBBIIIII", data, 0
    )
    if magic != BTF_MAGIC:
        raise BtfError(f"{origin}: invalid BTF magic 0x{magic:04x}")
    if version != BTF_VERSION:
        raise BtfError(f"{origin}: unsupported BTF version {version}")
    if not BTF_HEADER_MIN <= hdr_len <= BTF_HEADER_MAX or hdr_len > len(data):
        raise BtfError(f"{origin}: invalid BTF header length {hdr_len}")
    if type_off > len(data) - hdr_len or type_len > len(data) - hdr_len - type_off:
        raise BtfError(f"{origin}: type section is out of bounds")
    if str_off > len(data) - hdr_len or str_len > len(data) - hdr_len - str_off:
        raise BtfError(f"{origin}: string section is out of bounds")
    if type_len % 4 or str_len > MAX_STRINGS:
        raise BtfError(f"{origin}: misaligned type section or oversized string section")
    type_blob = data[hdr_len + type_off : hdr_len + type_off + type_len]
    string_blob = data[hdr_len + str_off : hdr_len + str_off + str_len]
    if string_blob and string_blob[-1] != 0:
        raise BtfError(f"{origin}: string section is not NUL terminated")

    types = _parse_types(type_blob, string_blob, origin, little_endian)
    return Btf(tuple(types), little_endian, origin, base, string_blob)


def _string(table: bytes, offset: int, origin: str) -> str:
    if offset >= len(table):
        raise BtfError(f"{origin}: string offset {offset} is out of bounds")
    end = table.find(b"\x00", offset)
    if end < 0:
        raise BtfError(f"{origin}: string at offset {offset} is not NUL terminated")
    try:
        return table[offset:end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BtfError(f"{origin}: string at offset {offset} is not UTF-8") from exc


def _extra_size(kind: int, vlen: int) -> int:
    if kind in {
        KIND_UNKNOWN,
        KIND_PTR,
        KIND_FWD,
        KIND_FUNC,
        KIND_VOLATILE,
        KIND_CONST,
        KIND_RESTRICT,
        KIND_FLOAT,
        KIND_TYPEDEF,
        KIND_TYPE_TAG,
    }:
        return 0
    if kind in {KIND_INT, KIND_VAR, KIND_DECL_TAG}:
        return 4
    if kind == KIND_LOC_PARAM:
        return 4 + vlen * 4
    if kind == KIND_ARRAY:
        return 12
    if kind in COMPOSITE_KINDS or kind in {KIND_DATASEC, KIND_LOCSEC, KIND_ENUM64}:
        return vlen * 12
    if kind == KIND_ENUM:
        return vlen * 8
    if kind == KIND_LOC_PROTO:
        return vlen * 4
    if kind == KIND_FUNC_PROTO:
        return vlen * 8
    raise BtfError(f"unsupported BTF kind {kind}")


def _parse_types(blob: bytes, strings: bytes, origin: str, little_endian: bool) -> list[BtfType]:
    prefix = "<" if little_endian else ">"
    types: list[BtfType] = []
    cursor = 0
    while cursor < len(blob):
        if len(blob) - cursor < 12:
            raise BtfError(f"{origin}: truncated type record at offset {cursor}")
        name_off, info, size_or_type = struct.unpack_from(prefix + "III", blob, cursor)
        kind = (info >> 24) & 0x7F
        vlen = info & 0xFFFFFF
        kind_flag = bool(info >> 31)
        extra = _extra_size(kind, vlen)
        record_size = 12 + extra
        if cursor + record_size > len(blob):
            raise BtfError(f"{origin}: type record at offset {cursor} is truncated")
        type_id = len(types) + 1
        if type_id > MAX_TYPES:
            raise BtfError(f"{origin}: too many BTF types")
        name = _string(strings, name_off, origin)
        extra_blob = blob[cursor + 12 : cursor + record_size]
        parsed = _parse_extra(
            type_id, name, kind, kind_flag, vlen, size_or_type, extra_blob, strings, origin, prefix
        )
        types.append(parsed)
        cursor += record_size
    return types


def _parse_extra(
    type_id: int,
    name: str,
    kind: int,
    kind_flag: bool,
    vlen: int,
    size_or_type: int,
    extra: bytes,
    strings: bytes,
    origin: str,
    prefix: str,
) -> BtfType:
    common = {"id": type_id, "name": name, "kind": kind, "kind_flag": kind_flag, "vlen": vlen}
    if kind == KIND_INT:
        raw = struct.unpack_from(prefix + "I", extra, 0)[0]
        return BtfType(
            **common,
            size=size_or_type,
            type_ref=0,
            int_bits=raw & 0xFF,
            int_signed=bool((raw >> 24) & 0x0F & 0x01),
        )
    if kind in COMPOSITE_KINDS:
        members: list[Member] = []
        for index in range(vlen):
            name_off, type_ref, offset = struct.unpack_from(prefix + "III", extra, index * 12)
            bitfield_size = offset >> 24 if kind_flag else 0
            raw_offset = offset & 0xFFFFFF
            bit_offset = raw_offset if kind_flag else raw_offset * 8
            members.append(
                Member(
                    name=_string(strings, name_off, origin),
                    type_id=type_ref,
                    byte_offset=bit_offset // 8,
                    bit_offset=bit_offset,
                    bitfield_size=bitfield_size,
                )
            )
        return BtfType(**common, size=size_or_type, type_ref=0, members=tuple(members))
    if kind == KIND_ARRAY:
        element_type, index_type, count = struct.unpack_from(prefix + "III", extra, 0)
        return BtfType(
            **common,
            size=0,
            type_ref=0,
            array=ArrayInfo(element_type, index_type, count),
        )
    if kind in ENUM_KINDS:
        values: list[EnumValue] = []
        step = 12 if kind == KIND_ENUM64 else 8
        for index in range(vlen):
            name_off = struct.unpack_from(prefix + "I", extra, index * step)[0]
            if kind == KIND_ENUM64:
                low, high = struct.unpack_from(prefix + "II", extra, index * step + 4)
                value = low | (high << 32)
            else:
                value = struct.unpack_from(prefix + "i", extra, index * step + 4)[0]
            values.append(EnumValue(_string(strings, name_off, origin), value))
        return BtfType(**common, size=size_or_type, type_ref=0, enum_values=tuple(values))
    if kind == KIND_FUNC_PROTO:
        return BtfType(**common, size=0, type_ref=size_or_type)
    if kind == KIND_VAR:
        return BtfType(**common, size=0, type_ref=size_or_type)
    if kind in {KIND_DATASEC, KIND_LOCSEC}:
        return BtfType(**common, size=size_or_type, type_ref=0)
    resolved_size = size_or_type if kind in {KIND_INT, KIND_FLOAT} else 0
    return BtfType(**common, size=resolved_size, type_ref=size_or_type)
