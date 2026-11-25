# Market Research — Baysöz Labs

Maintainer: Baysöz Labs <baysozlabs@proton.me> · <https://github.com/yazilimbaysoz-svg/baysoz-corelattice>

## 1. Live GitHub evidence (queried 2026-11-25)

`gh search repos` and `gh search issues` were executed against the live GitHub API. The
signal is not "another observability tool": it is a **portability verification gap** in
eBPF-based systems observability.

| Repository (live stars) | Why it matters |
| --- | --- |
| `vectordotdev/vector` (22,964) | Observability pipelines are routinely compiled as eBPF agents; fleet-wide kernel heterogeneity is a deployment fact. |
| `cilium/ebpf` (8,047) | Pure-Go eBPF loader; CO-RE loading and BTF handling are core runtime concerns. |
| `aya-rs/aya` (4,931) | Rust eBPF framework with explicit CO-RE relocation support and unresolved correctness issues. |
| `open-telemetry/opentelemetry-proto` (831) | Telemetry wire contracts are standardized, but the kernel ABI that produces telemetry is not. |
| `aquasecurity/btfhub` (490) | Exists solely because many kernels ship without usable BTF; target BTF collection is already an ecosystem workflow. |
| `vbpf/prevail` (476) | Verifier research confirms that static preflight analysis is a legitimate production discipline. |
| `trailofbits/mquire` (194) | Uses kernel-embedded BTF for type-aware analysis without debug info, proving BTF is a first-class introspection input. |
| `open-telemetry/semantic-conventions` (696), `open-telemetry/weaver` (541) | Show that schema/drift gates are valued; the same pattern is missing for kernel type layouts. |

Open issues mined with `gh search issues` (verbatim titles):

- <https://github.com/aya-rs/aya/issues/1727> — "CO-RE relocations can mix duplicate named target structs and cause OOB reads".
- <https://github.com/aya-rs/aya/issues/1875> — "Fall back when the kernel rejects BTF".
- <https://github.com/aya-rs/aya/issues/349> — "Add BTF relocation support in eBPF programs" (19 comments).
- <https://github.com/libbpf/libbpf/issues/996> — "`bpf_core_type_matches()` doesn't match plain `char` across kernel and BPF builds, because `char` signedness differs".
- <https://github.com/libbpf/libbpf/issues/995> — "`bpf_core_type_matches()` fails across GCC/clang because integer type names are compared".
- <https://github.com/libbpf/libbpf/issues/983> — "`btf__align_of()`: NULL pointer dereference (SIGSEGV) on out-of-range type id".
- <https://github.com/open-telemetry/weaver/issues/24> — "Detection of breaking changes and automation of version management for public APIs".
- <https://github.com/open-telemetry/semantic-conventions/issues/1369> — "Add policy to check that attribute does not change the type during/after deprecation."

These are not feature requests for a new agent or dashboard. They are load-time correctness
and ABI-drift failures that currently surface **on production nodes**, after rollout.

## 2. The gap

CO-RE ("compile once, run everywhere") relocations are resolved by libbpf/aya at load time.
A field can disappear, move, change signedness, change width, or become ambiguous because two
kernel types share a name. Today the typical detection path is:

1. build an eBPF object with `.BTF` + `.BTF.ext`;
2. deploy to a fleet;
3. discover a verifier/loader failure or, worse, a silently wrong offset;
4. triage with a BTF dump and a kernel symbol file.

There is no widely used CI gate that reads the *relocation records themselves*, walks both the
local object type graph and one or more target kernel BTF graphs, classifies the drift, and
emits a machine-consumable SARIF result. `bpftool btf dump` shows types; it does not audit a
specific relocation corpus against a fleet of kernels.

## 3. Why this is not redundant with the existing Baysöz Labs catalogue

`existing-repos.json` already covers pprof regression, trace propagation, Alertmanager routes,
PromQL conformance, cardinality, OTel collector policy, NetworkPolicy reachability, Gateway API
conflicts, archive confinement, JOSE confusion, DDL safety, and more. None of them parse ELF
`.BTF`/`.BTF.ext` or implement CO-RE relocation semantics. The closest neighbours are
complementary, not overlapping:

- `baysoz-otelgate` gates collector configuration; this gates kernel type ABI.
- `baysoz-profilediff` compares pprof samples; this compares BTF type layouts.
- `baysoz-tracecontinuity` checks W3C propagation; this checks the eBPF probes that may emit spans.
- `baysoz-reachoracle` audits Python advisories; this audits binary metadata before it reaches a node.

Trivial utilities, wrappers around `bpftool`, and single-rule linters were explicitly rejected.
The selected tool has a real binary format, a real specification (`include/uapi/linux/btf.h`
and `struct bpf_core_relo`), real adversarial fixtures, and real kernel BTF input.

## 4. Product decision

Build **baysoz-corelattice**: a zero-service, zero-LLM, pure Python 3.13 CLI/library that

- parses ELF64 section tables, BTF type graphs, and `.BTF.ext` CO-RE records with strict bounds;
- resolves field, type, enum, and bitfield relocations against one or more target BTFs;
- detects missing/ambiguous types, missing fields, signedness flips, size and offset drift,
  bitfield geometry changes, and enum drift;
- emits deterministic SARIF 2.1.0 for CI enforcement.

Target users: platform/SRE teams shipping eBPF-based observability agents, security teams
operating type-aware kernel tooling, and distro/kernel maintainers validating BTF snapshots.

Baysöz Labs <baysozlabs@proton.me>
