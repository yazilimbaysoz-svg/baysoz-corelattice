"""Deterministic SARIF 2.1.0 report generation.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from typing import Any

from .findings import RULE_METADATA, Finding

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "baysoz-corelattice"
TOOL_URI = "https://github.com/yazilimbaysoz-svg/baysoz-corelattice"


def _level(severity: str) -> str:
    return {"error": "error", "warning": "warning", "note": "note"}.get(severity, "note")


def build_sarif(
    findings: tuple[Finding, ...],
    *,
    program: str,
    targets: tuple[str, ...],
    include_notes: bool = False,
) -> dict[str, Any]:
    """Build a stable SARIF document suitable for CI diffing."""
    visible = tuple(item for item in findings if include_notes or item.severity != "note")
    used_rules = sorted({item.rule_id for item in visible} | {item.rule_id for item in findings})
    rules = [
        {
            "id": rule_id,
            "name": RULE_METADATA[rule_id][0],
            "shortDescription": {"text": RULE_METADATA[rule_id][0]},
            "fullDescription": {"text": RULE_METADATA[rule_id][1]},
            "defaultConfiguration": {"level": "error" if rule_id not in {"PASS"} else "note"},
            "helpUri": TOOL_URI + "#rules",
        }
        for rule_id in used_rules
        if rule_id in RULE_METADATA
    ]
    results = [
        {
            "ruleId": item.rule_id,
            "level": _level(item.severity),
            "message": {"text": item.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": program},
                        "region": {"startLine": 1, "startColumn": 1},
                    },
                    "logicalLocations": [
                        {
                            "name": item.section,
                            "fullyQualifiedName": f"{item.section}:insn+{item.insn_off}",
                        }
                    ],
                }
            ],
            "properties": {
                "relocation_index": item.relocation_index,
                "insn_off": item.insn_off,
                "access": item.access,
                "local": item.local,
                "target": item.target,
                "evidence": [{"key": key, "value": value} for key, value in item.evidence],
            },
        }
        for item in visible
    ]
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": "1.0.0",
                        "semanticVersion": "1.0.0",
                        "informationUri": TOOL_URI,
                        "organization": "Baysöz Labs <baysozlabs@proton.me>",
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "commandLine": f"{TOOL_NAME} check --program {program} "
                        f"--target {' --target '.join(targets)}",
                    }
                ],
                "results": results,
                "properties": {
                    "baysöz-labs": "baysozlabs@proton.me",
                    "targets": list(targets),
                },
            }
        ],
    }
