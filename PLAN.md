# Delivery Plan — Baysöz Labs

Owner: Baysöz Labs <baysozlabs@proton.me> · <https://github.com/yazilimbaysoz-svg/baysoz-corelattice>

## Phase 1 — Selection (complete)

- Inspected `existing-repos.json` (36 prior projects) and excluded overlapping domains.
- Queried live GitHub trends with `gh search repos` for eBPF, BTF, OTLP, semantic conventions,
  exposition formats, and verifier tooling.
- Queried live open issues with `gh search issues`; extracted CO-RE ambiguity, BTF rejection,
  signedness mismatch, and type-id safety reports.
- Selected kernel-ABI conformance as the non-trivial gap.

## Phase 2 — Implementation (complete)

- Pure-Python 3.13 package with zero runtime dependencies.
- ELF64/BTF/`.BTF.ext` parsers with strict bounds and ABI coverage.
- All 13 CO-RE relocation kinds evaluated across multiple target BTFs.
- Deterministic SARIF 2.1.0 and JSON output; `check` and `inspect` CLI commands.
- Enterprise documentation, MIT licence, CI workflow, and quality gates.

## Phase 3 — Verification (in progress)

- Synthetic adversarial fixtures generated from UAPI layouts (no copied blobs).
- Live `/sys/kernel/btf/vmlinux` parsing and hostile relocation checks.
- Gates: `uv venv`, `uv pip install -e .`, `uv pip install pytest`, `uv run pytest -q`,
  `ruff check --select E,F,W,S,B .`, `semgrep --config p/default --error .`.
- Supreme Grand Jury Tribunal: live execution against real kernel BTF and malformed inputs;
  unanimous PASS required before release.

### Supreme Grand Jury Tribunal — UNANIMOUS PASS (2026-11-25)

| Juror | Live evidence | Verdict |
| --- | --- | --- |
| Runtime | Installed CLI audited a 5-relocation corpus against the real `/sys/kernel/btf/vmlinux` (172,471 types): `FIELD_OFFSET_DRIFT` at insn+8, `FIELD_MISSING` for hostile field index `999999`, `TYPE_SIZE_DRIFT` 8→9856 bytes, exit 1; malformed ELF exited 2 with `ELF_MALFORMED`; `inspect` resolved `task_struct` id 158900, size 9856, 268 members. | PASS |
| Library | Direct API evaluation of the same real kernel BTF produced the same rule set, one error and two warnings; SARIF generated twice was byte-identical and carried `Baysöz Labs <baysozlabs@proton.me>`. | PASS |
| Integrity | `ruff` and `semgrep` reported zero findings; source contains no `TODO`, `FIXME`, `NotImplemented`, `pass`, or stub markers; no socket/subprocess/urllib/requests imports; `--version` and `--help` attribute Baysöz Labs. | PASS |

The Tribunal found no stubs, no hallucinated rules, and no unreported drift. Release authorized.

## Phase 4 — Release (in progress)

- Public repository under `yazilimbaysoz-svg` with crisp description and topics.
- Showcase result JSON written only to the designated factory result path.

## Non-goals

- No kernel module, no `bpf()` syscall use, no daemon, no database, no web UI.
- No local LLM, no model downloads, no network dependency at runtime.
- No generic BPF verifier replacement; this tool audits relocation metadata before load.

Baysöz Labs <baysozlabs@proton.me>
