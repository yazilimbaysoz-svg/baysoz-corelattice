# Security Policy — Baysöz Labs

Project: baysoz-corelattice · Maintainer: Baysöz Labs <baysozlabs@proton.me>

## Threat model

Inputs are untrusted binary artifacts: ELF objects from CI, BTF snapshots from kernels or
modules, and relocation access strings produced by toolchains. The attacker controls byte
content and may attempt memory exhaustion, out-of-bounds reads, path surprises, or deceptive
reports. The tool runs in CI with access to local files only.

## Controls

- **Bounds-first parsing.** Header, section, type, and string accesses are validated before
  slicing. Truncated or overlapping data raises a typed error, never an uncaught `IndexError`.
- **Explicit caps.** `MAX_SECTIONS`, `MAX_SECTION_SIZE`, `MAX_TYPES`, `MAX_STRINGS`,
  `MAX_RELOCATIONS`, `MAX_ACCESS_COMPONENTS`, and qualifier-cycle detection bound CPU/memory.
- **No code execution.** ELF sections are bytes. The reader never maps executable segments,
  never calls `dlopen`, and never invokes `bpftool` or any external process.
- **No network.** No HTTP client, socket, or telemetry dependency exists in the package.
- **Strict decoding.** BTF strings must be UTF-8 and NUL terminated; unknown kinds, unknown
  relocation kinds, malformed access components, and out-of-range type ids are errors.
- **Fail-closed ambiguity.** Equal-scoring target types produce `TYPE_AMBIGUOUS` rather than a
  best-effort guess that could hide an out-of-bounds read.
- **Safe output.** Reports are JSON/SARIF generated with `json.dumps`; no shell interpolation,
  no format-string execution from input. Paths appear only as opaque strings.
- **Minimal supply chain.** Runtime requires Python 3.13+ and the standard library only; CI
  installs `pytest`, `ruff`, and `semgrep` as development gates.

## Reporting

Please report vulnerabilities privately to Baysöz Labs <baysozlabs@proton.me>. Include a
reproducer artifact and the affected version from `corelattice --version`. Do not open a
public issue for an unpatched memory-safety or bypass report.

Baysöz Labs <baysozlabs@proton.me>
