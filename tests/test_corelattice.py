"""Adversarial conformance tests for the Baysöz Labs CO-RE oracle.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from baysoz_corelattice.btf import BtfError, parse_btf
from baysoz_corelattice.cli import main
from baysoz_corelattice.core import CoreError, evaluate_relocations, parse_core_relocations
from baysoz_corelattice.elf import ElfError, parse_elf
from baysoz_corelattice.sarif import build_sarif

from .builder import (
    KIND_ENUM,
    KIND_STRUCT,
    BtfBuilder,
    make_elf,
    make_ext,
)

VMLINUX = Path("/sys/kernel/btf/vmlinux")


def _elf(builder: BtfBuilder, relocations: list[tuple[int, int, str, int]]) -> bytes:
    ext = make_ext(builder, relocations)
    return make_elf({".BTF": builder.build(), ".BTF.ext": ext})


def _rules(findings: object) -> set[str]:
    return {item.rule_id for item in findings}  # type: ignore[attr-defined]


def _basic_pair() -> tuple[BtfBuilder, BtfBuilder, list[tuple[int, int, str, int]]]:
    local = BtfBuilder()
    u32 = local.int_type("unsigned int", 32, False)
    charp = local.ptr_type(local.int_type("char", 8, False))
    root = local.struct_type(
        "probe_event", [("pid", u32, 0, 0), ("name", charp, 8, 0), ("flags", u32, 16, 0)], size=24
    )
    target = BtfBuilder()
    tu32 = target.int_type("unsigned int", 32, False)
    tcharp = target.ptr_type(target.int_type("char", 8, False))
    tsigned = target.int_type("int", 32, True)
    target.struct_type(
        "probe_event",
        [("pid", tu32, 8, 0), ("name", tcharp, 16, 0), ("flags", tsigned, 24, 0)],
        size=32,
    )
    relocations = [
        (0, root, "0", 0),
        (8, root, "2", 3),
        (16, root, "1", 2),
        (24, root, "0", 9),
    ]
    return local, target, relocations


def test_drift_and_signedness_detected() -> None:
    local_builder, target_builder, relocations = _basic_pair()
    image = parse_elf(_elf(local_builder, relocations))
    local = parse_btf(image.require(".BTF"))
    target = parse_btf(target_builder.build())
    decoded = parse_core_relocations(image.require(".BTF.ext"), local)
    assert len(decoded) == 4
    findings = evaluate_relocations(local, (target,), decoded)
    assert _rules(findings) == {
        "FIELD_OFFSET_DRIFT",
        "SIGNEDNESS_FLIP",
        "TYPE_SIZE_DRIFT",
        "PASS",
    }
    signedness = next(item for item in findings if item.rule_id == "SIGNEDNESS_FLIP")
    assert signedness.severity == "error"
    assert "unsigned -> signed" in signedness.message
    drift = next(item for item in findings if item.rule_id == "FIELD_OFFSET_DRIFT")
    assert ("target_offset", "8") in drift.evidence


def test_missing_field_is_an_error() -> None:
    local = BtfBuilder()
    u32 = local.int_type("u32", 32)
    root = local.struct_type("sample", [("a", u32, 0, 0), ("b", u32, 4, 0)], size=8)
    target = BtfBuilder()
    tu32 = target.int_type("u32", 32)
    target.struct_type("sample", [("a", tu32, 0, 0)], size=4)
    relocations = [(0, root, "1", 2)]
    ext = make_ext(local, relocations)
    local_btf = parse_btf(local.build())
    decoded = parse_core_relocations(ext, local_btf)
    findings = evaluate_relocations(local_btf, (parse_btf(target.build()),), decoded)
    assert "FIELD_MISSING" in _rules(findings)
    assert all(item.severity == "error" for item in findings if item.rule_id == "FIELD_MISSING")


def test_ambiguous_target_type_is_rejected() -> None:
    local = BtfBuilder()
    u32 = local.int_type("u32", 32)
    root = local.struct_type("ambiguous", [("a", u32, 0, 0)], size=4)
    target = BtfBuilder()
    tu32 = target.int_type("u32", 32)
    target.struct_type("ambiguous", [("a", tu32, 0, 0)], size=4)
    target.struct_type("ambiguous", [("a", tu32, 0, 0)], size=4)
    relocations = [(0, root, "0", 2)]
    ext = make_ext(local, relocations)
    local_btf = parse_btf(local.build())
    decoded = parse_core_relocations(ext, local_btf)
    findings = evaluate_relocations(local_btf, (parse_btf(target.build()),), decoded)
    assert "TYPE_AMBIGUOUS" in _rules(findings)


def test_enum_value_drift_and_existence() -> None:
    local = BtfBuilder()
    enum = local.enum_type("mode", [("OFF", 0), ("ON", 1)], kind=KIND_ENUM)
    target = BtfBuilder()
    target.enum_type("mode", [("OFF", 0), ("ON", 7)], kind=KIND_ENUM)
    relocations = [(0, enum, "0", 10), (8, enum, "1", 11)]
    ext = make_ext(local, relocations)
    local_btf = parse_btf(local.build())
    decoded = parse_core_relocations(ext, local_btf)
    findings = evaluate_relocations(local_btf, (parse_btf(target.build()),), decoded)
    assert "ENUM_DRIFT" in _rules(findings)
    drift = next(item for item in findings if item.rule_id == "ENUM_DRIFT")
    assert "changed from 1 to 7" in drift.message


def test_enum64_member_removal_is_an_error() -> None:
    local = BtfBuilder()
    enum = local.enum_type("wide", [("A", 1), ("B", 1 << 40)], kind=19)
    target = BtfBuilder()
    target.enum_type("wide", [("A", 1)], kind=19)
    relocations = [(0, enum, "1", 10)]
    ext = make_ext(local, relocations)
    local_btf = parse_btf(local.build())
    decoded = parse_core_relocations(ext, local_btf)
    findings = evaluate_relocations(local_btf, (parse_btf(target.build()),), decoded)
    assert "ENUM_DRIFT" in _rules(findings)
    assert "absent" in findings[0].message


def test_bitfield_shift_drift() -> None:
    local = BtfBuilder()
    u32 = local.int_type("u32", 32)
    root = local.struct_type("bits", [("field", u32, 4, 3)], kflag=True, size=4)
    target = BtfBuilder()
    tu32 = target.int_type("u32", 32)
    target.struct_type("bits", [("field", tu32, 8, 3)], kflag=True, size=4)
    relocations = [(0, root, "0", 4), (8, root, "0", 5)]
    ext = make_ext(local, relocations)
    local_btf = parse_btf(local.build())
    decoded = parse_core_relocations(ext, local_btf)
    findings = evaluate_relocations(local_btf, (parse_btf(target.build()),), decoded)
    assert "BITFIELD_DRIFT" in _rules(findings)


def test_array_access_and_bounds() -> None:
    local = BtfBuilder()
    u32 = local.int_type("u32", 32)
    index = local.int_type("u32", 32)
    array = local.array_type(u32, index, 4)
    root = local.struct_type("packet", [("data", array, 0, 0)], size=16)
    target = BtfBuilder()
    tu32 = target.int_type("u32", 32)
    tindex = target.int_type("u32", 32)
    tarray = target.array_type(tu32, tindex, 4)
    target.struct_type("packet", [("data", tarray, 0, 0)], size=16)
    relocations = [(0, root, "0:[2]", 0), (8, root, "0:[9]", 0)]
    ext = make_ext(local, relocations)
    local_btf = parse_btf(local.build())
    decoded = parse_core_relocations(ext, local_btf)
    findings = evaluate_relocations(local_btf, (parse_btf(target.build()),), decoded)
    assert "FIELD_INDEX_INVALID" in _rules(findings)
    assert any(item.access == "0:[2]" and item.rule_id == "PASS" for item in findings)


def test_malformed_binary_inputs_are_rejected() -> None:
    builder = BtfBuilder()
    builder.int_type("u32", 32)
    with pytest.raises(BtfError):
        parse_btf(builder.build(corrupt_magic=True))
    with pytest.raises(BtfError):
        parse_btf(builder.build(truncate=4))
    with pytest.raises(ElfError):
        parse_elf(make_elf({".BTF": builder.build()}, bad_magic=True))
    bad_ext = make_ext(builder, [(0, 1, "0", 2)], bad_kind=True)
    with pytest.raises(CoreError):
        parse_core_relocations(bad_ext, parse_btf(builder.build()))


def test_malformed_access_strings_are_rejected() -> None:
    builder = BtfBuilder()
    u32 = builder.int_type("u32", 32)
    root = builder.struct_type("sample", [("a", u32, 0, 0)], size=4)
    ext = make_ext(builder, [(0, root, "a:0", 2)])
    local_btf = parse_btf(builder.build())
    decoded = parse_core_relocations(ext, local_btf)
    findings = evaluate_relocations(local_btf, (local_btf,), decoded)
    assert "CORE_RELO_MALFORMED" in _rules(findings)


def test_sarif_is_deterministic_and_attributed() -> None:
    local_builder, target_builder, relocations = _basic_pair()
    ext = make_ext(local_builder, relocations)
    local = parse_btf(local_builder.build())
    target = parse_btf(target_builder.build())
    decoded = parse_core_relocations(ext, local)
    findings = tuple(evaluate_relocations(local, (target,), decoded))
    first = build_sarif(findings, program="probe.o", targets=("vmlinux",))
    second = build_sarif(findings, program="probe.o", targets=("vmlinux",))
    assert first == second
    assert first["version"] == "2.1.0"
    driver = first["runs"][0]["tool"]["driver"]
    assert "Baysöz Labs <baysozlabs@proton.me>" == driver["organization"]
    assert {"SIGNEDNESS_FLIP", "FIELD_OFFSET_DRIFT", "TYPE_SIZE_DRIFT"} <= {
        rule["id"] for rule in driver["rules"]
    }


def test_cli_version_help_and_check_end_to_end(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as version_exit:
        main(["--version"])
    assert version_exit.value.code == 0
    assert "Baysöz Labs" in capsys.readouterr().out
    with pytest.raises(SystemExit) as help_exit:
        main(["--help"])
    assert help_exit.value.code == 0
    assert "baysozlabs@proton.me" in capsys.readouterr().out

    local_builder, target_builder, relocations = _basic_pair()
    program = tmp_path / "probe.o"
    target_path = tmp_path / "vmlinux.btf"
    report = tmp_path / "findings.sarif"
    program.write_bytes(_elf(local_builder, relocations))
    target_path.write_bytes(target_builder.build())

    exit_code = main(
        [
            "check",
            "--program",
            str(program),
            "--target",
            str(target_path),
            "--sarif",
            str(report),
            "--json",
        ]
    )
    assert exit_code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["attribution"] == "Baysöz Labs <baysozlabs@proton.me>"
    assert payload["relocation_count"] == 4
    assert "SIGNEDNESS_FLIP" in _rules(
        [type("F", (), {"rule_id": item["rule_id"]}) for item in payload["findings"]]
    )
    sarif = json.loads(report.read_text(encoding="utf-8"))
    assert sarif["runs"][0]["results"]

    capsys.readouterr()
    assert (
        main(
            [
                "check",
                "--program",
                str(program),
                "--target",
                str(target_path),
                "--fail-on",
                "none",
            ]
        )
        == 0
    )
    assert "verdict: PASS" in capsys.readouterr().out


def test_cli_parse_error_is_reported(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = tmp_path / "bad.o"
    bad.write_bytes(b"not an elf")
    target = tmp_path / "vmlinux.btf"
    target.write_bytes(BtfBuilder().build())
    assert main(["check", "--program", str(bad), "--target", str(target)]) == 2
    output = capsys.readouterr().out
    assert "ELF_MALFORMED" in output
    assert "baysozlabs@proton.me" in output


@pytest.mark.skipif(not VMLINUX.exists(), reason="live kernel BTF is not mounted")
def test_real_kernel_btf_drives_adversarial_checks() -> None:
    kernel = parse_btf(VMLINUX.read_bytes(), origin="vmlinux")
    ids = kernel.find_by_name("task_struct", frozenset({KIND_STRUCT}))
    assert len(ids) == 1
    task = kernel.type_at(ids[0])
    assert task.size > 1000
    assert len(task.members) > 100
    assert any(member.name == "pid" for member in task.members)

    local = BtfBuilder()
    u32 = local.int_type("u32", 32)
    members = [("pid", u32, 0, 0), ("state", u32, 4, 0)]
    local_root = local.struct_type("task_struct", members, size=8)
    valid_ext = make_ext(local, [(0, local_root, "1", 0)])
    local_btf = parse_btf(local.build())
    valid = parse_core_relocations(valid_ext, local_btf)
    findings = evaluate_relocations(local_btf, (kernel,), valid)
    assert "FIELD_OFFSET_DRIFT" in _rules(findings)

    hostile_ext = make_ext(local, [(0, local_root, "999999", 0)])
    hostile_btf = parse_btf(local.build())
    hostile = parse_core_relocations(hostile_ext, hostile_btf)
    hostile_findings = evaluate_relocations(hostile_btf, (kernel,), hostile)
    assert "FIELD_MISSING" in _rules(hostile_findings)


@pytest.mark.skipif(not VMLINUX.exists(), reason="live kernel BTF is not mounted")
def test_cli_inspect_real_kernel(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output = tmp_path / "types.json"
    assert main(["inspect", str(VMLINUX), "--name", "task_struct", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["attribution"] == "Baysöz Labs <baysozlabs@proton.me>"
    assert payload["types"][0]["name"] == "task_struct"
    output.write_text("", encoding="utf-8")
