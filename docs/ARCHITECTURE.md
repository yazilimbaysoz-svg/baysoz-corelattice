# Architecture — Baysöz Labs

Maintainer: Baysöz Labs <baysozlabs@proton.me> · <https://github.com/yazilimbaysoz-svg/baysoz-corelattice>

## Data flow

```
BPF ELF object ──> elf.parse_elf ──> .BTF ──> btf.parse_btf ──> local Btf
                          │
                          └────────> .BTF.ext ──> core.parse_core_relocations ──> relocations

target BTF blob(s) ──> btf.parse_btf ──> target Btf(s)
                                              │
                        core.evaluate_relocations(local, targets, relocations)
                                              │
                                              v
                                  findings.Finding[]
                                              │
                          sarif.build_sarif / cli._emit
```

## Modules

| Module | Responsibility |
| --- | --- |
| `elf.py` | Bounds-checked ELF64 section reader; extracts `.BTF` and `.BTF.ext` without loading or mapping code. |
| `btf.py` | Parses `<HBBIIIII` BTF header, type records (all standard kinds), string table, and split-BTF base fallback. Exposes qualifiers, sizes, members, enum values. |
| `core.py` | Decodes `.BTF.ext` CO-RE records, parses GEP-like access strings, resolves target types by name plus structural evidence, walks field/array paths, classifies drift. |
| `findings.py` | Stable rule catalogue and immutable finding records. |
| `sarif.py` | Deterministic SARIF 2.1.0 document builder with rule metadata and evidence properties. |
| `cli.py` | `check` and `inspect` subcommands, exit-code policy, JSON and human renderers. |

## ABI coverage

- BTF: `INT`, `PTR`, `ARRAY`, `STRUCT`, `UNION`, `ENUM`, `FWD`, `TYPEDEF`, `VOLATILE`,
  `CONST`, `RESTRICT`, `FUNC`, `FUNC_PROTO`, `VAR`, `DATASEC`, `FLOAT`, `DECL_TAG`,
  `TYPE_TAG`, `ENUM64`, `LOC_PARAM`, `LOC_PROTO`, `LOCSEC`.
- CO-RE kinds: all 13 `bpf_core_relo_kind` values (field offset/size/exists/signedness/shifts,
  local/target type id, type exists/size, enum exists/value, type matches).
- Access grammar: `0`, `0:1`, `0:[5]`, `10:1`, with strict numeric validation.

## Invariants

1. **No trust in offsets.** Every offset, length, `vlen`, and string index is range-checked
   before slicing or unpacking.
2. **No execution.** ELF bytes are read as data; no `dlopen`, `mmap`, or syscall wrapper exists.
3. **No network or services.** The library makes zero outbound calls; target BTF comes from a
   file path supplied by the caller (commonly `/sys/kernel/btf/vmlinux`).
4. **Bounded work.** Type count, section count, relocation count, record size, access depth,
   and pointer index are capped; recursive qualifier following has a cycle guard.
5. **Determinism.** Rule sets, findings, SARIF, and JSON are sorted and stable; no timestamps,
   no absolute paths embedded in rule ids, no host-specific ordering.
6. **Ambiguity fails closed.** If multiple target types score equally, the oracle refuses to
   pick one and returns `TYPE_AMBIGUOUS` instead of audited-but-wrong binding.
7. **Attribution.** Version/help output, metadata, reports, and documentation carry
   Baysöz Labs <baysozlabs@proton.me>.

## Severity policy

| Condition | Rule | Severity |
| --- | --- | --- |
| Missing target type/field, signedness flip, malformed metadata, ambiguous type | `TYPE_MISSING`, `FIELD_MISSING`, `SIGNEDNESS_FLIP`, `*_MALFORMED`, `TYPE_AMBIGUOUS` | error |
| Offset/size/bitfield/enum drift | `FIELD_OFFSET_DRIFT`, `FIELD_SIZE_DRIFT`, `TYPE_SIZE_DRIFT`, `BITFIELD_DRIFT`, `ENUM_DRIFT` | warning |
| Successful relocation (verbose only) | `PASS` | note |

`--fail-on error|warning|none` maps these severities to CI exit codes 1/0. Parse errors exit 2
with a structured finding.

## Performance

Real `/sys/kernel/btf/vmlinux` snapshots (~170k types, ~7 MB) parse in under a second on the
reference runner. Evaluation is linear in relocation count times candidate count; name-first
lookup avoids scanning the entire kernel graph for ordinary named structs.

Baysöz Labs <baysozlabs@proton.me>
