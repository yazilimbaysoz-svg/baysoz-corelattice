"""Finding model shared by the CO-RE resolver and the SARIF reporter.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

SEVERITY_ERROR = "error"
SEVERITY_WARNING = "warning"
SEVERITY_NOTE = "note"

RULE_METADATA: dict[str, tuple[str, str]] = {
    "BTF_MALFORMED": (
        "Malformed or truncated BTF metadata",
        "Reject BTF sections whose header, type graph, or string table violates the ABI.",
    ),
    "ELF_MALFORMED": (
        "Malformed or truncated ELF object",
        "Reject ELF containers with invalid headers, sections, or section tables.",
    ),
    "CORE_RELO_MALFORMED": (
        "Malformed CO-RE relocation record",
        "Reject relocation records with unknown kinds, bad access strings, or broken references.",
    ),
    "TYPE_MISSING": (
        "Target type is absent from the kernel BTF",
        "A CO-RE relocation cannot resolve its root type on the target kernel.",
    ),
    "TYPE_AMBIGUOUS": (
        "Target type resolution is ambiguous",
        "Multiple equally plausible target types match a relocated root type; the loader may bind "
        "to a different layout than the one audited.",
    ),
    "FIELD_MISSING": (
        "Target field is absent",
        "A field-based CO-RE relocation points at a member that does not exist on the target.",
    ),
    "FIELD_INDEX_INVALID": (
        "Field or array index is out of range",
        "A relocation access string selects a member or element that cannot exist.",
    ),
    "SIGNEDNESS_FLIP": (
        "Field signedness differs from the local build",
        "Signedness changes alter arithmetic and verifier range reasoning after relocation.",
    ),
    "TYPE_SIZE_DRIFT": (
        "Target type size differs from the local build",
        "A type is present with a different byte size, which can invalidate copied values.",
    ),
    "FIELD_OFFSET_DRIFT": (
        "Target field offset differs from the local build",
        "CO-RE will patch the offset; the audit records the layout drift for review.",
    ),
    "FIELD_SIZE_DRIFT": (
        "Target field size differs from the local build",
        "CO-RE will patch the size; verify that downstream copies remain safe.",
    ),
    "BITFIELD_DRIFT": (
        "Bitfield geometry differs from the local build",
        "Bit offset or width changes alter shift relocations and mask semantics.",
    ),
    "ENUM_DRIFT": (
        "Enumeration member value differs from the local build",
        "CO-RE will patch the value; verify that control-flow decisions remain equivalent.",
    ),
    "QUALIFIER_UNSUPPORTED": (
        "Relocation traverses a type the oracle cannot interpret",
        "The access path requires a type kind outside the supported BTF subset.",
    ),
    "PASS": (
        "Relocation resolved without conformance findings",
        "Informational record emitted with verbose reporting.",
    ),
}


@dataclass(frozen=True, slots=True)
class Finding:
    """A deterministic, source-attributed conformance finding."""

    rule_id: str
    severity: str
    message: str
    section: str
    relocation_index: int
    insn_off: int
    access: str
    local: str
    target: str
    evidence: tuple[tuple[str, str], ...] = ()

    def as_dict(self) -> dict[str, Any]:
        """Return a stable JSON representation used by tests and CI artifacts."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "section": self.section,
            "relocation_index": self.relocation_index,
            "insn_off": self.insn_off,
            "access": self.access,
            "local": self.local,
            "target": self.target,
            "evidence": [{"key": key, "value": value} for key, value in self.evidence],
        }


def make_finding(
    rule_id: str,
    severity: str,
    message: str,
    *,
    section: str = ".BTF.ext",
    relocation_index: int = -1,
    insn_off: int = -1,
    access: str = "",
    local: str = "",
    target: str = "",
    evidence: tuple[tuple[str, str], ...] = (),
) -> Finding:
    """Construct a finding with validated rule identifiers."""
    if rule_id not in RULE_METADATA:
        raise ValueError(f"unknown rule id: {rule_id}")
    if severity not in (SEVERITY_ERROR, SEVERITY_WARNING, SEVERITY_NOTE):
        raise ValueError(f"unknown severity: {severity}")
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message=message,
        section=section,
        relocation_index=relocation_index,
        insn_off=insn_off,
        access=access,
        local=local,
        target=target,
        evidence=evidence,
    )
