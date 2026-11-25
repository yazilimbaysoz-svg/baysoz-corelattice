# baysoz-corelattice

Baysöz Labs <baysozlabs@proton.me> · <https://github.com/yazilimbaysoz-svg/baysoz-corelattice>

[![CI](https://github.com/yazilimbaysoz-svg/baysoz-corelattice/actions/workflows/ci.yml/badge.svg)](https://github.com/yazilimbaysoz-svg/baysoz-corelattice/actions/workflows/ci.yml)
[![Python 3.13+](https://img.shields.io/badge/python-3.13%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![SARIF 2.1.0](https://img.shields.io/badge/report-SARIF%202.1.0-purple.svg)](docs/ARCHITECTURE.md)
[![Zero runtime dependencies](https://img.shields.io/badge/runtime-stdlib%20only-brightgreen.svg)](pyproject.toml)

**Offline eBPF CO-RE relocation conformance oracle with BTF type-drift detection and SARIF CI gates.**
Developed by Baysöz Labs <baysozlabs@proton.me>.

## Why

CO-RE ("compile once, run everywhere") relocations are normally resolved on the target node at
load time. A kernel field can move, disappear, change signedness, change width, or become
ambiguous because two types share a name. `baysoz-corelattice` moves that discovery into CI:
it reads the actual `.BTF` and `.BTF.ext` records from a BPF object and audits every relocation
against one or more target kernel BTF snapshots, emitting deterministic SARIF.

It performs no syscalls, starts no services, loads no local LLM, and makes no network calls.

## Install

```bash
uv venv
uv pip install -e .
uv pip install pytest ruff semgrep
```

Python 3.13+ is required. Runtime dependencies: none (standard library only).

## CLI

```
corelattice --version
corelattice --help
corelattice check --program probe.o --target /sys/kernel/btf/vmlinux --sarif relocations.sarif
corelattice check --program probe.o --target kernel-a.btf --target kernel-b.btf --json --fail-on warning
corelattice inspect /sys/kernel/btf/vmlinux --name task_struct
```

`--version` and `--help` both print `Baysöz Labs <baysozlabs@proton.me>`.

### Real CLI output

Auditing a synthetic `probe_event` object against a target where `pid` moved, `flags` became
signed, and the struct grew:

```text
$ corelattice check --program probe.o --target target.btf
baysoz-corelattice 1.0.0 — offline CO-RE conformance oracle
program: probe.o
targets: target.btf
local_types: 4
target_types: 5
relocations: 4
findings: 1 error, 2 warning, 3 reported
- FIELD_OFFSET_DRIFT warning insn+0: field offset for 'pid' changed from 0 to 8 bytes
- SIGNEDNESS_FLIP error insn+8: field 'flags' changed signedness: unsigned -> signed
- TYPE_SIZE_DRIFT warning insn+24: type size changed from 24 to 32 bytes
verdict: FAIL
Attribution: Baysöz Labs <baysozlabs@proton.me>
```

Inspecting a real live kernel BTF type:

```text
$ corelattice inspect /sys/kernel/btf/vmlinux --name task_struct
baysoz-corelattice 1.0.0 — offline CO-RE conformance oracle
source: /sys/kernel/btf/vmlinux
types: 172471
      ID  KIND              SIZE     N  NAME
  158900  struct            9856   268  'task_struct'
Attribution: Baysöz Labs <baysozlabs@proton.me>
```

## Architecture

```text
BPF ELF ──> elf.parse_elf ──> .BTF ──> btf.parse_btf ──> local Btf
                 └────────> .BTF.ext ─> core.parse_core_relocations ──> relocations

target BTF(s) ──> btf.parse_btf ──> core.evaluate_relocations ──> Finding[]
                                                              └──> SARIF / JSON / text
```

- `src/baysoz_corelattice/elf.py` — bounds-checked ELF64 section reader.
- `src/baysoz_corelattice/btf.py` — BTF type graph, strings, qualifiers, sizes, enums.
- `src/baysoz_corelattice/core.py` — all 13 CO-RE relocation kinds and access-path walking.
- `src/baysoz_corelattice/findings.py` — stable rule catalogue.
- `src/baysoz_corelattice/sarif.py` — deterministic SARIF 2.1.0 output.
- `src/baysoz_corelattice/cli.py` — `check` and `inspect` commands.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for ABI coverage and invariants, and
[docs/MARKET_RESEARCH.md](docs/MARKET_RESEARCH.md) for the live GitHub evidence behind the
project choice.

## Detected rules

`BTF_MALFORMED`, `ELF_MALFORMED`, `CORE_RELO_MALFORMED`, `TYPE_MISSING`, `TYPE_AMBIGUOUS`,
`FIELD_MISSING`, `FIELD_INDEX_INVALID`, `SIGNEDNESS_FLIP`, `TYPE_SIZE_DRIFT`,
`FIELD_OFFSET_DRIFT`, `FIELD_SIZE_DRIFT`, `BITFIELD_DRIFT`, `ENUM_DRIFT`, `QUALIFIER_UNSUPPORTED`,
`PASS`.

## Quality gates

```bash
uv venv && uv pip install -e . && uv pip install pytest
uv run pytest -q
ruff check --select E,F,W,S,B .
semgrep --config p/default --error .
```

## Documentation

- [Market research](docs/MARKET_RESEARCH.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Plan](PLAN.md)
- [Security](SECURITY.md)
- [Changelog](CHANGELOG.md)
- [MIT licence](LICENSE)

Baysöz Labs <baysozlabs@proton.me>
