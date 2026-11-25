"""CO-RE relocation decoding and cross-kernel conformance evaluation.

The evaluator mirrors the semantics documented in ``struct bpf_core_relo``:
an access string is a GEP-like path of member and array indices rooted in a
named BTF type.  Both the local build and every supplied target kernel BTF are
walked with the same rules, then drift is classified into deterministic rules.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .btf import (
    Btf,
    BtfError,
    BtfType,
    COMPOSITE_KINDS,
    ENUM_KINDS,
    KIND_ARRAY,
    KIND_PTR,
)
from .findings import (
    SEVERITY_ERROR,
    SEVERITY_NOTE,
    SEVERITY_WARNING,
    Finding,
    make_finding,
)

BTF_EXT_MAGIC = 0xEB9F
BTF_EXT_HEADER_MIN = 24
BTF_EXT_HEADER_WITH_CORE = 32
CORE_RECORD_MIN = 16
MAX_RELOCATIONS = 1 << 20
MAX_ACCESS_COMPONENTS = 64
POINTER_SIZE = 8

RELO_NAMES = {
    0: "FIELD_BYTE_OFFSET",
    1: "FIELD_BYTE_SIZE",
    2: "FIELD_EXISTS",
    3: "FIELD_SIGNED",
    4: "FIELD_LSHIFT_U64",
    5: "FIELD_RSHIFT_U64",
    6: "TYPE_ID_LOCAL",
    7: "TYPE_ID_TARGET",
    8: "TYPE_EXISTS",
    9: "TYPE_SIZE",
    10: "ENUMVAL_EXISTS",
    11: "ENUMVAL_VALUE",
    12: "TYPE_MATCHES",
}

FIELD_KINDS = frozenset({0, 1, 2, 3, 4, 5})
TYPE_KINDS = frozenset({6, 7, 8, 9, 12})
ENUM_KINDS_RELO = frozenset({10, 11})


class CoreError(ValueError):
    """Raised when CO-RE metadata cannot be decoded safely."""


@dataclass(frozen=True, slots=True)
class CoreRelocation:
    """One decoded ``struct bpf_core_relo`` record."""

    index: int
    section: str
    insn_off: int
    type_id: int
    access_off: int
    access: str
    kind: int

    @property
    def kind_name(self) -> str:
        """Stable relocation kind name."""
        return RELO_NAMES.get(self.kind, f"UNKNOWN-{self.kind}")


@dataclass(frozen=True, slots=True)
class _Token:
    kind: str
    value: int


@dataclass(frozen=True, slots=True)
class _PathResult:
    type_id: int
    byte_offset: int
    bit_offset: int
    field_name: str
    field_type: int
    bitfield_size: int


def _ext_header(data: bytes, little_endian: bool) -> tuple[int, int, int]:
    if len(data) < BTF_EXT_HEADER_MIN:
        raise CoreError(".BTF.ext header is truncated")
    prefix = "<" if little_endian else ">"
    fields = struct.unpack_from(prefix + "HBBIIIII", data, 0)
    magic, version, _flags, hdr_len = fields[:4]
    if magic != BTF_EXT_MAGIC:
        raise CoreError(f".BTF.ext has invalid magic 0x{magic:04x}")
    if version != 1:
        raise CoreError(f"unsupported .BTF.ext version {version}")
    if not BTF_EXT_HEADER_MIN <= hdr_len <= len(data):
        raise CoreError(f".BTF.ext has invalid header length {hdr_len}")
    if hdr_len < BTF_EXT_HEADER_WITH_CORE:
        return hdr_len, 0, 0
    core_off, core_len = struct.unpack_from(prefix + "II", data, 24)
    return hdr_len, core_off, core_len


def parse_core_relocations(
    ext: bytes,
    btf: Btf,
    *,
    little_endian: bool = True,
) -> tuple[CoreRelocation, ...]:
    """Decode all CO-RE relocation records from a ``.BTF.ext`` payload."""
    hdr_len, core_off, core_len = _ext_header(ext, little_endian)
    if core_len == 0:
        return ()
    if core_off > len(ext) - hdr_len or core_len > len(ext) - hdr_len - core_off:
        raise CoreError(".BTF.ext core_relocation section is out of bounds")
    info = ext[hdr_len + core_off : hdr_len + core_off + core_len]
    if len(info) < 4:
        raise CoreError(".BTF.ext core_relocation section lacks a record size")
    prefix = "<" if little_endian else ">"
    record_size = struct.unpack_from(prefix + "I", info, 0)[0]
    if record_size < CORE_RECORD_MIN:
        raise CoreError(f"CO-RE record size {record_size} is smaller than the ABI minimum")
    if record_size > 4096:
        raise CoreError(f"CO-RE record size {record_size} exceeds the supported limit")

    relocations: list[CoreRelocation] = []
    pos = 4
    while pos < len(info):
        if len(info) - pos < 8:
            raise CoreError("truncated CO-RE info section header")
        sec_name_off, num_info = struct.unpack_from(prefix + "II", info, pos)
        section = btf.string(sec_name_off)
        pos += 8
        needed = num_info * record_size
        if needed > len(info) - pos:
            raise CoreError(f"CO-RE section {section!r} declares more records than available")
        for local_index in range(num_info):
            if len(relocations) >= MAX_RELOCATIONS:
                raise CoreError("CO-RE relocation count exceeds the supported limit")
            start = pos + local_index * record_size
            insn_off, type_id, access_off, kind = struct.unpack_from(prefix + "IIII", info, start)
            if kind not in RELO_NAMES:
                raise CoreError(f"unknown CO-RE relocation kind {kind}")
            if not btf.has_type(type_id):
                raise CoreError(f"CO-RE type id {type_id} is out of range")
            access = btf.string(access_off)
            relocations.append(
                CoreRelocation(
                    index=len(relocations),
                    section=section,
                    insn_off=insn_off,
                    type_id=type_id,
                    access_off=access_off,
                    access=access,
                    kind=kind,
                )
            )
        pos += needed
    return tuple(relocations)


def _parse_access(access: str) -> tuple[_Token, ...]:
    if not access:
        return ()
    parts = access.split(":")
    if len(parts) > MAX_ACCESS_COMPONENTS:
        raise CoreError("CO-RE access string has too many components")
    tokens: list[_Token] = []
    for part in parts:
        if part.startswith("[") and part.endswith("]"):
            value = part[1:-1]
            if not value.isascii() or not value.isdigit():
                raise CoreError(f"malformed array index in access string {access!r}")
            tokens.append(_Token("index", int(value)))
        elif part.isascii() and part.isdigit():
            tokens.append(_Token("field", int(part)))
        else:
            raise CoreError(f"malformed component {part!r} in access string {access!r}")
    return tuple(tokens)


def _walk(btf: Btf, root: BtfType, tokens: tuple[_Token, ...]) -> _PathResult:
    current = root
    byte_offset = 0
    bit_offset = 0
    field_name = ""
    field_type = root.id
    bitfield_size = 0
    for token in tokens:
        if current.kind in COMPOSITE_KINDS:
            if token.kind != "field" or token.value >= len(current.members):
                raise CoreError(
                    f"field {token.value} does not exist in {btf.label(current.id)}"
                )
            member = current.members[token.value]
            byte_offset += member.byte_offset
            bit_offset += member.bit_offset
            field_name = member.name
            field_type = member.type_id
            bitfield_size = member.bitfield_size
            current = btf.strip_qualifiers(member.type_id)
            continue
        if current.kind in {KIND_PTR, KIND_ARRAY}:
            if current.kind == KIND_ARRAY and current.array is not None:
                element = current.array.element_type
                count = current.array.count
            elif current.kind == KIND_PTR and current.type_ref:
                element = current.type_ref
                count = 0
            else:
                raise CoreError(f"cannot index malformed {current.kind_name} type id {current.id}")
            if count and token.value >= count:
                label = btf.label(current.id)
                raise CoreError(f"array index {token.value} is out of range for {label}")
            if token.value > 1_000_000:
                raise CoreError("CO-RE access string uses an implausible pointer index")
            element_size = btf.size_of(element, POINTER_SIZE)
            byte_offset += token.value * element_size
            bit_offset += token.value * element_size * 8
            field_type = element
            field_name = ""
            bitfield_size = 0
            current = btf.strip_qualifiers(element)
            continue
        if token.kind == "field" and token.value == 0:
            continue
        raise CoreError(f"cannot traverse {current.kind_name} type id {current.id} in access path")
    return _PathResult(current.id, byte_offset, bit_offset, field_name, field_type, bitfield_size)


def _structural_key(t: BtfType) -> tuple[str, tuple[str, ...]]:
    return t.name, tuple(member.name for member in t.members)


def _candidate_score(btf: Btf, candidate: BtfType, local: BtfType) -> int:
    score = 0
    if candidate.kind == local.kind:
        score += 100
    if candidate.size == local.size:
        score += 50
    names = tuple(m.name for m in candidate.members)
    local_names = tuple(m.name for m in local.members)
    score += sum(1 for left, right in zip(names, local_names, strict=False) if left == right) * 10
    return score


def _resolve_target(
    local: BtfType,
    targets: tuple[Btf, ...],
) -> tuple[BtfType | None, Btf | None, bool]:
    """Return (best candidate, its BTF, ambiguous) using name and layout evidence."""
    wanted_kinds = frozenset({local.kind})
    if local.kind not in COMPOSITE_KINDS and local.kind not in ENUM_KINDS:
        wanted_kinds = frozenset({local.kind, KIND_PTR, KIND_ARRAY})
    candidates: list[tuple[BtfType, Btf, int]] = []
    for target in targets:
        ids = target.find_by_name(local.name, wanted_kinds) if local.name else ()
        for type_id in ids:
            candidate = target.type_at(type_id)
            candidates.append((candidate, target, _candidate_score(target, candidate, local)))
    if not candidates and local.name and local.kind in {KIND_PTR, KIND_ARRAY}:
        for target in targets:
            for candidate in target.types:
                if candidate.kind == local.kind and candidate.name == local.name:
                    score = _candidate_score(target, candidate, local)
                    candidates.append((candidate, target, score))
    if not candidates and local.kind in COMPOSITE_KINDS and local.members:
        key = _structural_key(local)[1]
        for target in targets:
            for candidate in target.types:
                if candidate.kind == local.kind and _structural_key(candidate)[1] == key:
                    score = _candidate_score(target, candidate, local)
                    candidates.append((candidate, target, score))
    if not candidates:
        return None, None, False
    best_score = max(score for _candidate, _btf, score in candidates)
    best = [item for item in candidates if item[2] == best_score]
    if len(best) > 1:
        keys = {_structural_key(item[0]) for item in best}
        if len(keys) > 1 or len(best) > 1:
            return best[0][0], best[0][1], True
    return best[0][0], best[0][1], False


def _evidence(pairs: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
    return pairs


def evaluate_relocations(
    local: Btf,
    targets: tuple[Btf, ...],
    relocations: tuple[CoreRelocation, ...],
    *,
    verbose: bool = False,
) -> list[Finding]:
    """Evaluate relocations against every target BTF and return sorted findings."""
    findings: list[Finding] = []
    for relo in relocations:
        context = {
            "section": relo.section,
            "relocation_index": relo.index,
            "insn_off": relo.insn_off,
            "access": relo.access,
            "local": local.label(relo.type_id),
        }
        try:
            tokens = _parse_access(relo.access)
            local_root = local.strip_qualifiers(relo.type_id)
        except (BtfError, CoreError) as exc:
            findings.append(
                make_finding(
                    "CORE_RELO_MALFORMED",
                    SEVERITY_ERROR,
                    str(exc),
                    target="",
                    evidence=_evidence((("relo_kind", relo.kind_name),)),
                    **context,
                )
            )
            continue

        if relo.kind == 6:
            findings.append(
                make_finding(
                    "PASS",
                    SEVERITY_NOTE,
                    f"local type id {relo.type_id} resolved to {local.label(relo.type_id)}",
                    target="local",
                    evidence=_evidence((("relo_kind", relo.kind_name),)),
                    **context,
                )
            )
            continue

        target_type, target_btf, ambiguous = _resolve_target(local_root, targets)
        if ambiguous:
            findings.append(
                make_finding(
                    "TYPE_AMBIGUOUS",
                    SEVERITY_ERROR,
                    f"multiple target types match {local_root.name!r}; refusing to bind silently",
                    target="ambiguous",
                    evidence=_evidence(
                        (("relo_kind", relo.kind_name), ("root_kind", local_root.kind_name))
                    ),
                    **context,
                )
            )
            continue
        if target_type is None or target_btf is None:
            findings.append(
                make_finding(
                    "TYPE_MISSING",
                    SEVERITY_ERROR,
                    f"root type {local_root.name!r} is absent from all target BTF inputs",
                    target="",
                    evidence=_evidence((("relo_kind", relo.kind_name),)),
                    **context,
                )
            )
            continue
        if target_btf is None:
            continue
        target_label = target_btf.label(target_type.id)
        context["target"] = target_label

        if relo.kind in ENUM_KINDS_RELO:
            findings.extend(
                _evaluate_enum(
                    relo, local, target_btf, local_root, target_type, tokens, verbose, context
                )
            )
            continue
        if relo.kind in TYPE_KINDS:
            findings.extend(
                _evaluate_type(relo, local, target_btf, target_type, verbose, context)
            )
            continue

        try:
            local_path = _walk(local, local_root, tokens)
            target_path = _walk(target_btf, target_type, tokens)
        except (BtfError, CoreError) as exc:
            rule = "FIELD_INDEX_INVALID" if "out of range" in str(exc) else "FIELD_MISSING"
            findings.append(
                make_finding(
                    rule,
                    SEVERITY_ERROR,
                    str(exc),
                    evidence=_evidence((("relo_kind", relo.kind_name),)),
                    **context,
                )
            )
            continue
        findings.extend(
            _evaluate_field(relo, local, target_btf, local_path, target_path, verbose, context)
        )
    return findings


def _evaluate_type(
    relo: CoreRelocation,
    local: Btf,
    target_btf: Btf,
    target_type: BtfType,
    verbose: bool,
    context: dict[str, str | int],
) -> list[Finding]:
    local_root = local.strip_qualifiers(relo.type_id)
    local_size = local.size_of(local_root.id, POINTER_SIZE)
    target_size = target_btf.size_of(target_type.id, POINTER_SIZE)
    if relo.kind == 9 and target_size != local_size:
        return [
            make_finding(
                "TYPE_SIZE_DRIFT",
                SEVERITY_WARNING,
                f"type size changed from {local_size} to {target_size} bytes",
                evidence=_evidence(
                    (("relo_kind", relo.kind_name), ("local_size", str(local_size)),
                     ("target_size", str(target_size)))
                ),
                **context,
            )
        ]
    return [
        make_finding(
            "PASS",
            SEVERITY_NOTE,
            f"{relo.kind_name} resolved on target kernel",
            evidence=_evidence((("relo_kind", relo.kind_name),)),
            **context,
        )
    ]


def _evaluate_enum(
    relo: CoreRelocation,
    local: Btf,
    target_btf: Btf,
    local_root: BtfType,
    target_type: BtfType,
    tokens: tuple[_Token, ...],
    verbose: bool,
    context: dict[str, str | int],
) -> list[Finding]:
    if local_root.kind not in ENUM_KINDS or target_type.kind not in ENUM_KINDS:
        return [
            make_finding(
                "CORE_RELO_MALFORMED",
                SEVERITY_ERROR,
                "enum relocation root is not an enum type",
                evidence=_evidence((("relo_kind", relo.kind_name),)),
                **context,
            )
        ]
    if len(tokens) != 1 or tokens[0].kind != "field":
        return [
            make_finding(
                "CORE_RELO_MALFORMED",
                SEVERITY_ERROR,
                "enum relocation access string must be a single numeric index",
                evidence=_evidence((("relo_kind", relo.kind_name),)),
                **context,
            )
        ]
    index = tokens[0].value
    if index >= len(local_root.enum_values):
        return [
            make_finding(
                "CORE_RELO_MALFORMED",
                SEVERITY_ERROR,
                f"enum index {index} is out of range in the local BTF",
                evidence=_evidence((("relo_kind", relo.kind_name),)),
                **context,
            )
        ]
    local_value = local_root.enum_values[index]
    matches = [value for value in target_type.enum_values if value.name == local_value.name]
    if not matches:
        return [
            make_finding(
                "ENUM_DRIFT",
                SEVERITY_ERROR if relo.kind == 10 else SEVERITY_WARNING,
                f"enum member {local_value.name!r} is absent from the target kernel",
                evidence=_evidence((("relo_kind", relo.kind_name),)),
                **context,
            )
        ]
    target_value = matches[0]
    if target_value.value != local_value.value:
        return [
            make_finding(
                "ENUM_DRIFT",
                SEVERITY_WARNING,
                f"enum member {local_value.name!r} changed from {local_value.value} "
                f"to {target_value.value}",
                evidence=_evidence(
                    (("relo_kind", relo.kind_name), ("local_value", str(local_value.value)),
                     ("target_value", str(target_value.value)))
                ),
                **context,
            )
        ]
    return [
        make_finding(
            "PASS",
            SEVERITY_NOTE,
            f"enum member {local_value.name!r} matches the target kernel",
            evidence=_evidence((("relo_kind", relo.kind_name),)),
            **context,
        )
    ]


def _evaluate_field(
    relo: CoreRelocation,
    local: Btf,
    target_btf: Btf,
    local_path: _PathResult,
    target_path: _PathResult,
    verbose: bool,
    context: dict[str, str | int],
) -> list[Finding]:
    local_size = local.size_of(local_path.field_type, POINTER_SIZE)
    target_size = target_btf.size_of(target_path.field_type, POINTER_SIZE)
    kind = relo.kind
    evidence = (
        ("relo_kind", relo.kind_name),
        ("access", relo.access),
        ("local_offset", str(local_path.byte_offset)),
        ("target_offset", str(target_path.byte_offset)),
        ("local_size", str(local_size)),
        ("target_size", str(target_size)),
    )
    if kind == 2:
        return [
            make_finding(
                "PASS",
                SEVERITY_NOTE,
                f"field path {relo.access!r} exists on the target kernel",
                evidence=evidence,
                **context,
            )
        ]
    if kind == 3:
        local_signed = local.is_signed(local_path.field_type)
        target_signed = target_btf.is_signed(target_path.field_type)
        if local_signed != target_signed:
            return [
                make_finding(
                    "SIGNEDNESS_FLIP",
                    SEVERITY_ERROR,
                    f"field {target_path.field_name!r} changed signedness: "
                    f"{'signed' if local_signed else 'unsigned'} -> "
                    f"{'signed' if target_signed else 'unsigned'}",
                    evidence=evidence,
                    **context,
                )
            ]
    if kind in {4, 5}:
        if local_path.bitfield_size == 0 or target_path.bitfield_size == 0:
            if local_path.bitfield_size != target_path.bitfield_size:
                return [
                    make_finding(
                        "BITFIELD_DRIFT",
                        SEVERITY_ERROR,
                        "bitfield geometry changed between local build and target kernel",
                        evidence=evidence,
                        **context,
                    )
                ]
        local_shift = (
            64 - local_path.bitfield_size - local_path.bit_offset
            if kind == 4 and local_path.bitfield_size
            else 64 - local_path.bitfield_size if kind == 5 and local_path.bitfield_size else 0
        )
        target_shift = (
            64 - target_path.bitfield_size - target_path.bit_offset
            if kind == 4 and target_path.bitfield_size
            else 64 - target_path.bitfield_size if kind == 5 and target_path.bitfield_size else 0
        )
        if local_shift != target_shift:
            return [
                make_finding(
                    "BITFIELD_DRIFT",
                    SEVERITY_WARNING,
                    f"{relo.kind_name} changes from {local_shift} to {target_shift}",
                    evidence=evidence,
                    **context,
                )
            ]
    if kind == 0 and local_path.byte_offset != target_path.byte_offset:
        return [
            make_finding(
                "FIELD_OFFSET_DRIFT",
                SEVERITY_WARNING,
                f"field offset for {target_path.field_name!r} changed from "
                f"{local_path.byte_offset} to {target_path.byte_offset} bytes",
                evidence=evidence,
                **context,
            )
        ]
    if kind == 1 and local_size != target_size:
        return [
            make_finding(
                "FIELD_SIZE_DRIFT",
                SEVERITY_WARNING,
                f"field size for {target_path.field_name!r} changed from {local_size} "
                f"to {target_size} bytes",
                evidence=evidence,
                **context,
            )
        ]
    return [
        make_finding(
            "PASS",
            SEVERITY_NOTE,
            f"{relo.kind_name} resolved for field {target_path.field_name!r}",
            evidence=evidence,
            **context,
        )
    ]
