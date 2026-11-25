# Changelog — Baysöz Labs

All notable changes to baysoz-corelattice are documented here.

Maintainer: Baysöz Labs <baysozlabs@proton.me> · <https://github.com/yazilimbaysoz-svg/baysoz-corelattice>

## [1.0.0] — 2026-11-25

### Added

- Pure-Python ELF64 reader with bounds-checked section extraction.
- BTF parser for all standard type kinds, split-BTF base fallback, and UTF-8 string tables.
- `.BTF.ext` CO-RE record decoder covering all 13 `bpf_core_relo_kind` values.
- Target type resolution with name and structural evidence; ambiguous matches fail closed.
- Drift rules for offsets, sizes, signedness, bitfields, enums, missing and invalid paths.
- `corelattice check` and `corelattice inspect` commands with JSON and SARIF 2.1.0 output.
- Deterministic CI gates, adversarial fixture suite, and live kernel BTF verification.

### Attribution

Developed and maintained by Baysöz Labs <baysozlabs@proton.me>.

Baysöz Labs <baysozlabs@proton.me>
