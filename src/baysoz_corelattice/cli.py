"""Command-line interface for the CO-RE conformance oracle.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from . import __version__
from .btf import Btf, BtfError, KIND_NAMES, parse_btf
from .core import CoreError, evaluate_relocations, parse_core_relocations
from .elf import ElfError, parse_elf
from .findings import (
    SEVERITY_ERROR,
    SEVERITY_NOTE,
    SEVERITY_WARNING,
    Finding,
    make_finding,
)
from .sarif import build_sarif

ATTRIBUTION = "Baysöz Labs <baysozlabs@proton.me>"
BANNER = f"baysoz-corelattice {__version__} — offline CO-RE conformance oracle"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="corelattice",
        description=(
            "Offline eBPF CO-RE relocation conformance oracle: parse ELF .BTF/.BTF.ext, "
            "resolve relocations against target kernel BTF, emit deterministic SARIF."
        ),
        epilog=f"Developed by {ATTRIBUTION}. No network calls, no kernel access, no telemetry.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"baysoz-corelattice {__version__} — {ATTRIBUTION}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser(
        "check",
        help="audit a BPF object against one or more target kernel BTF blobs",
        description="Audit CO-RE relocations in a BPF ELF object offline.",
        epilog=f"Developed by {ATTRIBUTION}.",
    )
    check.add_argument(
        "--program", required=True, type=Path, help="BPF ELF object with .BTF/.BTF.ext"
    )
    check.add_argument(
        "--target",
        required=True,
        action="append",
        type=Path,
        help="target kernel BTF blob or ELF object (repeatable)",
    )
    check.add_argument("--sarif", type=Path, help="write a SARIF 2.1.0 report to this path")
    check.add_argument("--json", action="store_true", help="emit findings as JSON on stdout")
    check.add_argument("--verbose", action="store_true", help="include passing relocations")
    check.add_argument(
        "--fail-on",
        choices=("error", "warning", "none"),
        default="error",
        help="minimum severity that fails the run (default: error)",
    )

    inspect = subparsers.add_parser(
        "inspect",
        help="inspect BTF types from a raw blob or ELF object",
        description="Print parsed BTF type records without loading anything.",
        epilog=f"Developed by {ATTRIBUTION}.",
    )
    inspect.add_argument("source", type=Path, help="raw BTF blob or ELF object")
    inspect.add_argument("--name", help="exact type name filter")
    inspect.add_argument("--kind", help="BTF kind name filter, e.g. struct or enum64")
    inspect.add_argument("--limit", type=int, default=25, help="maximum rows (default: 25)")
    inspect.add_argument("--json", action="store_true", help="emit JSON on stdout")
    return parser


def _read_bytes(path: Path, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise CoreError(f"cannot read {label} {path}: {exc.strerror}") from exc


def _btf_from_source(path: Path, label: str) -> Btf:
    data = _read_bytes(path, label)
    if data[:4] == b"\x7fELF":
        image = parse_elf(data)
        payload = image.require(".BTF")
        return parse_btf(payload, origin=f"{label}:{path}")
    return parse_btf(data, origin=f"{label}:{path}")


def _finding_from_error(exc: Exception, path: Path, rule: str) -> Finding:
    return make_finding(
        rule,
        SEVERITY_ERROR,
        str(exc),
        section=str(path),
        evidence=(("attribution", ATTRIBUTION),),
    )


def _run_check(args: argparse.Namespace) -> int:
    try:
        image = parse_elf(_read_bytes(args.program, "program"))
        program_btf = parse_btf(image.require(".BTF"), origin=f"program:{args.program}")
        ext = image.payload(".BTF.ext") or b""
        relocations = parse_core_relocations(ext, program_btf)
        targets = tuple(_btf_from_source(path, "target") for path in args.target)
    except (ElfError, BtfError, CoreError) as exc:
        rule = (
            "ELF_MALFORMED"
            if isinstance(exc, ElfError)
            else "BTF_MALFORMED"
            if isinstance(exc, BtfError)
            else "CORE_RELO_MALFORMED"
        )
        path = args.program if rule == "ELF_MALFORMED" else args.target[0]
        findings = (_finding_from_error(exc, path, rule),)
        return _emit(args, findings, (), [], 2, local_btf=None, failed=True, parse_error=True)

    findings = tuple(evaluate_relocations(program_btf, targets, relocations, verbose=args.verbose))
    errors = sum(1 for item in findings if item.severity == SEVERITY_ERROR)
    warnings = sum(1 for item in findings if item.severity == SEVERITY_WARNING)
    failed = (
        errors > 0
        if args.fail_on == "error"
        else errors + warnings > 0
        if args.fail_on == "warning"
        else False
    )
    return _emit(
        args,
        findings,
        targets,
        relocations,
        1 if failed else 0,
        local_btf=program_btf,
        failed=failed,
        parse_error=False,
    )


def _emit(
    args: argparse.Namespace,
    findings: tuple[Finding, ...],
    targets: tuple[Btf, ...],
    relocations: Sequence[Any],
    exit_code: int,
    *,
    local_btf: Btf | None,
    failed: bool,
    parse_error: bool = False,
) -> int:
    if args.sarif is not None:
        document = build_sarif(
            findings,
            program=str(args.program),
            targets=tuple(str(path) for path in args.target),
            include_notes=args.verbose,
        )
        encoded = json.dumps(document, indent=2, sort_keys=True) + "\n"
        args.sarif.write_text(encoded, encoding="utf-8")
    if args.json:
        payload = {
            "tool": "baysoz-corelattice",
            "attribution": ATTRIBUTION,
            "program": str(args.program),
            "targets": [str(path) for path in args.target],
            "relocation_count": len(relocations),
            "findings": [
                item.as_dict()
                for item in findings
                if args.verbose or item.severity != SEVERITY_NOTE
            ],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        _print_human(args, findings, targets, relocations, local_btf, failed, parse_error)
    return exit_code


def _print_human(
    args: argparse.Namespace,
    findings: tuple[Finding, ...],
    targets: tuple[Btf, ...],
    relocations: Sequence[Any],
    local_btf: Btf | None,
    failed: bool,
    parse_error: bool,
) -> None:
    print(BANNER)
    print(f"program: {args.program}")
    print(f"targets: {', '.join(str(path) for path in args.target)}")
    if not parse_error and local_btf is not None:
        print(f"local_types: {len(local_btf)}")
        print(f"target_types: {', '.join(str(len(btf)) for btf in targets)}")
        print(f"relocations: {len(relocations)}")
    errors = sum(1 for item in findings if item.severity == SEVERITY_ERROR)
    warnings = sum(1 for item in findings if item.severity == SEVERITY_WARNING)
    visible = [item for item in findings if args.verbose or item.severity != SEVERITY_NOTE]
    print(f"findings: {errors} error, {warnings} warning, {len(visible)} reported")
    for item in visible:
        detail = f" insn+{item.insn_off}" if item.insn_off >= 0 else ""
        print(f"- {item.rule_id} {item.severity}{detail}: {item.message}")
    print(f"verdict: {'FAIL' if failed else 'PASS'}")
    print(f"Attribution: {ATTRIBUTION}")


def _run_inspect(args: argparse.Namespace) -> int:
    try:
        btf = _btf_from_source(args.source, "source")
    except (BtfError, CoreError, ElfError) as exc:
        print(BANNER)
        print(f"error: {exc}")
        print(f"Attribution: {ATTRIBUTION}")
        return 2
    if args.limit < 0:
        print("error: --limit must be non-negative")
        return 2
    kind_filter = None
    if args.kind:
        kind_filter = next(
            (kind for kind, name in KIND_NAMES.items() if name == args.kind.lower()), None
        )
        if kind_filter is None:
            print(f"error: unknown BTF kind {args.kind!r}")
            return 2
    rows = [
        item
        for item in btf.types
        if (args.name is None or item.name == args.name)
        and (kind_filter is None or item.kind == kind_filter)
    ][: args.limit]
    if args.json:
        print(
            json.dumps(
                {
                    "tool": "baysoz-corelattice",
                    "attribution": ATTRIBUTION,
                    "source": str(args.source),
                    "type_count": len(btf),
                    "types": [
                        {
                            "id": item.id,
                            "name": item.name,
                            "kind": item.kind_name,
                            "size": item.size,
                            "members": len(item.members),
                            "values": len(item.enum_values),
                        }
                        for item in rows
                    ],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    print(BANNER)
    print(f"source: {args.source}")
    print(f"types: {len(btf)}")
    print(f"{'ID':>8}  {'KIND':<12}  {'SIZE':>8}  {'N':>4}  NAME")
    for item in rows:
        count = len(item.members) or len(item.enum_values)
        print(f"{item.id:>8}  {item.kind_name:<12}  {item.size:>8}  {count:>4}  {item.name!r}")
    print(f"Attribution: {ATTRIBUTION}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point; returns a process exit code."""
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "check":
        return _run_check(args)
    return _run_inspect(args)


if __name__ == "__main__":
    sys.exit(main())
