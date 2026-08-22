# GotYaForce assembly ABI canonicalization

Status: **review-ready after implementation-discovered array-adjustment correction; prior PASS superseded**.
This document authorizes no implementation or live mutation. Human approval
is required before the task plan may be executed. The 2026-08-21 PASS review
predates the exact pinned-Clang adjusted-array counterexample below and is no
longer controlling; an independent rereview of this amendment is required.

`verified_against`: current OGhidra `fork/main`
`f757a7e115327f23b061568a99c1a134a79ca118`; implementation code/interfaces/
tests baseline `4291b24c128c598360f9dc57b46be3efd1084c61`; GotYaForce remote refs and
data identities listed in the next section.

## Verified against

Evidence snapshot: `2026-08-21T20:55:23.2884599-04:00`
(`America/New_York`).

- OGhidra: `fork/main` and this successor commit's parent are exactly
  `f757a7e115327f23b061568a99c1a134a79ca118`. That commit adds only the prior
  design document over implementation code/interfaces/tests baseline
  `4291b24c128c598360f9dc57b46be3efd1084c61`.
- GotYaForce remote heads (read with `git ls-remote origin`): `main`
  `3fe888dc5193c1c5ea345911f771f63210fcf179`, `port-staging`
  `0901d3cd24820364d3e0649b848757eb3bccb5e0`, and `port-progress`
  `4294758ba2c49c6ab0b784ad09de8b23870d9628`.
- The inspected product worktree is `main` at
  `0901d3cd24820364d3e0649b848757eb3bccb5e0` and is dirty. Existing product
  changes are not inputs to this spec commit and were not modified.
- Current exact data identities:

  | Input | Bytes | SHA-256 |
  |---|---:|---|
  | `research/decomp/data/oracle-registry.json` | 8,636,470 | `77d58ab931757f5226b10e7d808a969bb470312e5a852a3b33cda87c83a66aa4` |
  | `research/decomp/data/build_oracle_registry.py` | 20,485 | `6cfb1cc8529831c1a16b09764cf58997c405bb9a1dd7292218b14c23129c52e4` |
  | `research/decomp/data/build_unit_priority.py` | 4,753 | `fa50abadc9fe739457592c97733e6335ba3f1e2f28dcc997f179d960e9c43de6` |
  | `research/decomp/data/assembly-gate.json` | 60,228 | `293f3958d030ca56677a5718894fbca6e4b2823a8cf731c76c8ef8ff7869b698` |
  | `research/decomp/generated/finish-game-port/wasm-units-state.json` | 234,419 | `c36a77b764fe815415602b6b83a6792e7f2ce947f553b377e2cf629709150181` |
  | `research/decomp/generated/finish-game-port/events.jsonl` | 505,909 | `83d9a0b1d023343097bbb298d9f0764ed598f6afde086c8b35e51ce0dbd1a788` |
  | `research/decomp/generated/finish-game-port/knowledge-registry.json` | 159,314 | `8b3a8f61c027a00288eed8a689c830c668c130bd8314b863087e3327dc937339` |

The snapshot is descriptive, not a precondition that these mutable ledger
hashes remain forever. Implementation must take a fresh stable snapshot and
bind its own receipts. At the snapshot, the `rig supervisor` scheduled task is
`Disabled` and the manual gate is `paused=false`, changed by `cli` at
`2026-08-21T18:46:49.2987965-04:00`. The last published supervisor record is
therefore stale at `2026-08-21T18:46:40-0400`; it still says supervisor/base
mode `manual-paused`, `driver_pid=null`, `manual_paused=true`, and
`release_verified=true`. Do not interpret that stale record as a currently
closed manual gate. No driver is published and the three mutable product
hashes above remain unchanged. The preceding externally opened 18:00 EDT run
had advanced `port-progress`, selected c0018 `auto-c0018-018` at attempt 4,
and recorded `linked=false` without a verdict. Current state therefore still
has c0018 `porting`/attempt 4 while c0035 is `pending`/attempt 4 after its
earlier attempt-5 `linked=false` interruption.

## Objective and scope

Make GotYaForce's continuous Wasm assembly gate derive shared internal
function ABIs from unique owner definitions, canonicalize the whole selected
bundle before compilation, and retry composition without asking an LLM to fix
a structural cross-unit problem. Success means an exact candidate and window
receive an auditable composition result, with precise contributors, without
changing the candidate's behavioral tier.

In scope: GotYaForce's Phase-0 owner registry, decompile corpus, OGhidra port
driver, assembly gate, journal, promotion transaction, and public/private test
lanes. **OMR is explicitly out of scope**, as are gameplay integration,
unrelated registry policy, model changes, and new oracle coverage.

## Current verified facts and interface gap

1. The current owner registry has top-level keys `meta`, `summary`,
   `ranked_units`, `functions`, and `excluded`, contains 10,954 function
   records, and has no schema discriminator. The builder emits the unversioned
   shape (`build_oracle_registry.py:416-445`); the priority consumer loads it
   without validation (`build_unit_priority.py:80-86`). Its anomaly list has
   exactly eight name-coordinate mismatches, all produced by the explicit
   source-marker-wins rule at `build_oracle_registry.py:261-266`.
2. `port_assembly_gate.py:315-435` merges headers registry-less;
   `:592-626` compares header/prelude guesses; `:640-667` attributes a parsed
   linker symbol to every selected unit; and `:1145-1324` owns gate
   orchestration. The linker runner compiles all C inputs in one emcc command
   (`port_wasm_units.py:1800-1851`), so it has no stable object attribution.
3. The candidate is already private and digest-bound before the gate
   (`port_wasm_units.py:3866-3924`), but a composition failure deletes the
   promotion attempt (`:3925-3947`) and enters the general retry record
   (`:3956-3966`). `_fail` marks assembly as pipeline-control and journals it
   (`:4307-4387`), but there is no retained-candidate composition lane.
4. Commit `4291b24` added stable schema-1 assembly-ledger folding as
   non-injectable, non-behavioral evidence
   (`port_knowledge_registry.py:238-264,309-512`). That advisory evidence is
   not owner authority and must not be reused as such.
5. The live assembly ledger is schema 1, has `largest_n_passed=5`, and its
   last run is an N=5 pass checked `2026-08-21T16:20:42.497489Z` over
   `auto-c0033-006` through `auto-c0033-010`, candidate digest
   `8e15a6c0041cb70e34c7d3be6e0aa54888870f2f8f4ddabf844a898498778635`.
   Mutable unit/supervisor history is stated only in the single timestamped
   authoritative snapshot under `Verified against`; it is not duplicated here.

### Independently verified owner bytes

Line ranges are 1-based and inclusive; hashes cover exact raw range bytes,
including CRLF and comments.

| Symbol | Owner record | Exact range | Bytes | Range SHA-256 | Canonical prototype |
|---|---|---|---:|---|---|
| `zz_00076d0_` | `auto-c0000-006` | `research/decomp/ghidra-export/chunk_0000.c:1991-2033` | 1,666 | `511a8c5b23ac7f8a7c6d6e2e0ba1427869872a731fc7368cc4ecb930198cd79c` | `void zz_00076d0_(undefined8,double,double,double,double,double,double,double,int,float *,undefined *,undefined4,undefined4,undefined4,undefined4,undefined4);` |
| `zz_00f0104_` | `auto-c0026-002` | `research/decomp/ghidra-export/chunk_0026.c:685-722` | 1,137 | `40d65919bf9c15148666824e63f10c0373fec32aa1c31a3b2adffe5782f92f94` | `void zz_00f0104_(int,uint,uint);` |

Whole-file SHA-256 values are `aa267e91ecf01cc1560cac4b2af44a024d2c3e3fd4241ba80b75e254752156a4`
for `chunk_0000.c` (172,214 bytes) and
`9356e934916cb50a34c31e7f26137a76c677d001c9109d799529ff2aaa40176f`
for `chunk_0026.c` (127,078 bytes).

The canonical state records historical candidate digests
`e96ef43340ddd601613940fd3a7cd1aa2c778ffe1f5d43e64aeb41651ceaf4f4`
for `auto-c0018-018` and
`04243bba39c02497077e668df7eadda68fd489427d9d67772166689cf3524352`
for `auto-c0035-006`. **These hashes are evidence-only.** The exact directory
bytes were not recovered or verified in this review, so neither hash is a
fixture identity, a reproducible test claim, or proof that current staging
bytes match the historical candidate.

## Deep module and interface

Add `src/port_assembly_abi.py` as one deep module with a phased interface. The
phase types prevent callers from inventing an object manifest, skipping owner
revalidation, or confusing a canonicalization plan with a composition result:

```python
def load_owner_snapshot(
    product_root: Path,
    registry_path: Path,
    declarator_parser: DeclaratorParser,
) -> OwnerSnapshot: ...

def plan_canonicalization(
    bundle: AssemblyBundle, owners: OwnerSnapshot
) -> CanonicalizationPlan | AssemblyAbiRefusal: ...

def analyze_composition(
    plan: CanonicalizationPlan,
    objects: tuple[ObjectObservation, ...],
    outcome: ToolOutcome,
    retry_history: RetryHistory,
) -> CompositionDraft: ...

def revalidate_receipt(
    receipt: CanonicalizationReceipt | CompositionReceipt,
    product_root: Path,
    observed: ReceiptObservation,
) -> RevalidatedReceipt | AssemblyAbiRefusal: ...

def finalize_composition(
    finalization: FinalizationInput,
) -> CompositionResult: ...
```

`load_owner_snapshot` is the production adapter at the product-owner seam and
owns every registry/source path check, stable read, C-definition parse, and
owner digest. `plan_canonicalization` is pure: it returns only derived header/
prelude bytes, ordered `TranslationUnitPlan` records, relevant owner bindings,
ordered owner/variant `CompatibilityEvidence`, discarded variants, and
`CanonicalizationReceipt`; it cannot claim any object or link result.
`analyze_composition` is pure: it accepts one observation per
planned object plus completed compiler/link/inspector/smoke evidence, validates
the one-to-one translation-unit mapping, computes precise object manifests and
diagnostic contributors, classifies blocker versus transient fault, and
returns an in-memory `CompositionDraft`, `CompositionReceipt`, and retry
material; it writes nothing. `revalidate_receipt` owns a
fresh stable product-registry/source re-read and compares the caller-supplied
private bundle/object/tool digests to the receipt. `finalize_composition` is the
only seam that converts any member of the closed finalization-input union into
the exact immutable `CompositionResult`; it validates early-failure evidence,
embeds actual revalidation check digests when a boundary was reached,
constructs and self-validates `result_id`, and never performs I/O. Tests may
construct an in-memory `OwnerSnapshot`, but production can
obtain one only through the v1 adapter.

Ownership outside the module is exact:

- `src/port_assembly_gate.py` is the only writer of derived bundle/object/
  smoke files. After a complete plan, it atomically materializes under the
  owned attempt, hashes the materialization, and calls `revalidate_receipt`
  with stage `pre-compile`.
- The gate invokes injected compiler, object-inspector, linker, and Node-smoke
  adapters. The compiler produces one named object per translation-unit plan;
  the inspector produces typed `ObjectObservation` data. Neither adapter
  chooses owners or contributors. The gate passes observations/diagnostics to
  `analyze_composition` with the driver-supplied `RetryHistory`, receives a
  `CompositionDraft`/`CompositionReceipt`, then calls `revalidate_receipt` on
  that exact composition receipt with stage `pre-publication`. It finally calls
  `finalize_composition` with exactly one union member: early owner/planning/
  materialization evidence, a failed pre-compile check, or the draft plus the
  actual pre-compile/pre-publication checks. Every member carries the same
  driver-supplied durable `RetryHistory`; the draft binds its canonical digest,
  and the finalizer alone produces the final retry projection. It invokes no tool or analyzer
  after a failed pre-compile check.
- `src/port_assembly_abi.py` alone normalizes prototypes, validates object
  observations, attributes symbols, classifies composition outcomes, hashes
  ABI receipts, and rechecks owner evidence. It performs no writes, Git,
  journal, state, model, compiler, inspector, link, smoke, or promotion call.
- `src/port_assembly_gate.py` returns the complete in-memory
  `CompositionResult`; neither it nor the deep module writes an assembly
  result, blocked manifest, marker, ledger, journal, or state file.
- `WasmUnitDriver` in `src/port_wasm_units.py` is the sole durable writer and
  sequencer of immutable assembly-result/blocked manifests, the private
  promotion marker, retry scheduling fields, progress-journal transition,
  canonical state, product install/commit/push, and recovery. It validates the
  returned complete result and finalizer-owned ID projection, serializes it
  without field mutation, writes manifests, and then
  invokes the Task 3 `record_gate_result` atomic helper to fold local
  `assembly-gate.json`. That helper owns only the exact ledger lock/read/
  idempotency/write critical section; the driver owns whether and when it
  runs. The driver owns durable retry history and sleeping; the module alone
  validates that history and classifies the current outcome, and its pure
  finalizer calculates the next count/status/backoff/fingerprints only after
  final revalidation. The driver never parses or classifies
  an ABI outcome.

The deletion test is satisfied: deleting this module would redistribute
schema validation, stable source reads, C-definition parsing, declaration
replacement, observation validation, attribution, outcome classification,
receipt hashing, and receipt revalidation into the gate and driver.

## Normative contract

### 1. Strict `oracle_registry_schema=1` owner adapter

- The product builder adds top-level integer `oracle_registry_schema: 1` and
  deterministically regenerates the registry. `bool`, string, missing, zero,
  and unknown versions are rejected; do not infer v1 from fields.
- V1 has exactly six top-level keys and no aliases or extensions:
  `oracle_registry_schema: int`, `meta: object`, `summary: object`,
  `ranked_units: list[object]`, `functions: list[object]`, and
  `excluded: list[object]`. JSON `null`, boolean-as-integer, duplicate object
  keys, non-UTF-8, NaN/Infinity, or an extra/missing top-level key is invalid.
- `meta` requires exactly `generated_by: nonempty string`, `inputs: object`
  whose exact keys `queue`, `skipped`, `chunk_index`, and `family_coverage`
  map to nonempty product-root-relative POSIX strings, and `conventions:
  object` with the exact six current string keys `address`,
  `structural_class`, `citation_grade`, `gap_alignment`,
  `ranked_units_sort`, and `oracle_able_units`. Unknown nested keys refuse.
- `summary` requires exactly fourteen fields. Nonnegative integers are
  `functions_total`, `units_total`, `excluded_total`,
  `gap_aligned_functions`, `gap_aligned_functions_partial_family`, and
  `fully_gap_aligned_units`. `excluded_reasons`,
  `structural_class_counts`, and `citation_grade_counts` are string to
  nonnegative-integer maps; `class_by_citation_grade` is a string to that map;
  `fully_gap_aligned_unit_names` and `anomalies` are lists of strings;
  `oracle_able_units` is exactly the four bucket names
  `differential_vs_ts`, `state_diff`, `citations_no_family`, and `trace_only`
  mapped to nonnegative integers; and `oracle_able_unit_names` has those exact
  keys mapped to unique sorted string lists. Counts must agree with records
  and lists. The OGhidra adapter validates but does not use summary as owner
  evidence.
- Each ranked-unit record requires the current eleven fields: nonempty strings
  `unit`, `oracle_kind`, `max_structural_class`; nonnegative integers
  `fn_count`, `gap_partial_slots`, `port_citations`, `port_grade_fns`,
  `total_citations`, `total_loc`; `gap_family_ctors: list[string]`; and exact
  boolean `fully_gap_aligned`. Each excluded record requires nonempty strings
  `name`, `address`, `chunk`, and `reason`.
- Every function record requires exactly the current seventeen keys. Owner-critical
  fields are unique nonempty C identifier `name`; lowercase `0x` plus eight
  hex digits `address`; nonempty `unit`; `chunk_file`; exactly two positive
  ordered integer `line_range` values; positive integer `loc` equal to the
  inclusive range length; nonempty strings `return_type` and
  `structural_class`; `params: list[string]`; exact booleans `returns_value`
  and `has_pointer_args`; `external_callees` exactly `{count:
  nonnegative-int, list: unique sorted list[string]}` with matching count;
  `global_refs` a unique ordered list of exact `{symbol: string,
  prefix_type: string, width_known: bool}` objects; `ts_citations` a unique
  ordered list of exact `{where: product-relative path + ':' + positive line,
  grade: 'port'|'unported'|'weak'}` objects; `citation_grade` one of
  `port|unported|weak|none|null`; `citation_scan_skipped` either
  `ambiguous_name` or null; and `gap_alignment` either null or exact
  `{family_ctor: lowercase 0x + eight hex digits, partial_slots:
  nonnegative-int, members: unique list[string]}`. `structural_class` is one
  of `A|B|C|D|E`. Container counts, `returns_value`, and pointer presence must
  agree with the normalized prototype. Schema-1 parameter spelling is
  loss-preserving: `params=[]` means an unspecified `()`, while
  `params=['void']` means explicit `(void)`; `void` is forbidden in every other
  list position. The producer must stop collapsing these two forms, and both
  consumers test their distinction. Each other entry is one complete ordered
  parameter declarator (including any nested function-pointer/array syntax),
  without a top-level comma.
  Schema validation checks all records, not merely the two current RCA owners.
- Function names and non-null addresses are globally one-to-one. A duplicate
  name, duplicate authoritative address, or duplicate JSON key is invalid even
  when byte-identical. A `zz_`/`FUN_` label's encoded historical coordinate is
  not independently authoritative: the exact chunk marker at the function's
  `line_range[0]` is the authoritative coordinate, `_index.tsv` corroborates
  it, and `name` remains the stable symbol label. The builder's current
  deterministic marker-wins rule is preserved; it emits `address` from the
  marker and one exact summary anomaly when the label encodes another value.
  The producer and both consumers refuse only if marker, index, emitted
  address, and anomaly do not agree—not merely because label/address differ.
- Regeneration must keep 10,954 functions, 1,018 exclusions, exactly eight
  marker-wins anomalies, and no rename, exclusion, or address rewrite beyond
  the already-authoritative marker values. The eight required fixture tuples
  (`name`, encoded label coordinate -> marker/emitted coordinate, unit) are:

  | Stable label | Label coordinate -> authoritative marker | Unit |
  |---|---|---|
  | `zz_00262b4_` | `0x800262b4 -> 0x80026250` | `auto-c0003-004` |
  | `zz_00c3484_` | `0x800c3484 -> 0x800c2d4c` | `auto-c0020-004` |
  | `zz_0147d74_` | `0x80147d74 -> 0x80147ce4` | `auto-c0038-005` |
  | `zz_0181c70_` | `0x80181c70 -> 0x80181c54` | `auto-c0045-009` |
  | `zz_01aadb4_` | `0x801aadb4 -> 0x801aad50` | `auto-c0051-010` |
  | `zz_0232a10_` | `0x80232a10 -> 0x80232a08` | `auto-c0068-012` |
  | `zz_0281554_` | `0x80281554 -> 0x802813dc` | `auto-c0076-007` |
  | `zz_02a8e80_` | `0x802a8e80 -> 0x802a8b3c` | `auto-c0078-016` |

  Product producer/priority-consumer tests and the separate OGhidra adapter
  fixture exercise all eight acceptance rows plus missing/wrong marker,
  index disagreement, missing/extra anomaly, duplicate name, and duplicate
  authoritative-address refusals. Records remain sorted by authoritative
  address then stable name.
- `build_unit_priority.py` imports the shared product-side v1 validator before
  consuming the registry. Product tests separately exercise producer output,
  deterministic regeneration, and priority-consumer rejection. OGhidra Task 2
  separately tests its adapter; Task 1 does not claim OGhidra already passes.
- The adapter parameter is `product_root`, not `corpus_root`. It must be an
  absolute, existing ordinary directory. Each `chunk_file` is an NFC-normalized
  POSIX relative path with the exact case-sensitive prefix
  `research/decomp/ghidra-export/`, suffix `.c`, no drive/UNC/ADS/absolute
  syntax, backslash, empty/`.`/`..` segment, control character, or case-folded
  duplicate. Join it exactly once as `product_root / chunk_file`.
- Enumerate every on-disk component to require exact spelling and reject a
  symlink, junction, mount/reparse point, hard-linked file (`st_nlink != 1`),
  device, FIFO, socket, or any non-regular final file. Verify resolved and
  case-folded containment under `product_root`, then recheck the same identity
  after the read. These rules apply to the registry path and every owner path.
- Owner resolution applies to a discovered function symbol when it is present
  in the validated owner index or, when absent, matches the game-internal namespaces
  `zz_[0-9A-Fa-f]{7}_` or `FUN_80[0-9A-Fa-f]{6}`. A namespace match absent from
  the index is `owner_missing`; more than one record is `owner_ambiguous`.
  An index record always wins over prefix classification. When absent from the
  index, `gnt4_*` SDK imports, `emscripten_*`, `invoke_*`, `dynCall_*`, compiler
  `__*` helpers, and explicitly whitelisted external callees are not owner-
  eligible. Other absent symbols retain the current registry-less rule: identical
  declarations deduplicate, while divergence fails closed; absence from the
  owner index alone is not a refusal.
- The mutable advisory `knowledge-registry.json` and its assembly-conflict
  fold are never owner adapters and never select an ABI.

### 2. Stable source range and digest binding

- A stable read records Windows volume serial/file ID, reparse tag, mode,
  link count, size, and nanosecond mtime before opening; reads through that
  handle; records them again after EOF; and requires the identities and
  metadata to match. Read registry bytes this way, compute
  `registry_sha256`, and parse only after stability is proven.
- Read every cited source the same way. Slice exact raw bytes by 1-based,
  inclusive physical lines with line endings retained. Record whole-file and
  range SHA-256, byte length, relative path, range, and stable file identity.
- The range must contain exactly one direct definition of the named symbol.
  Its parsed normalized prototype must equal `return_type + name + params`.
  Zero definitions, multiple definitions, malformed C, or disagreement is a
  typed refusal, never a guessed owner.
- The production `DeclaratorParser` adapter is the already-installed pinned
  Emscripten Clang, resolved only as
  `product_root/research/tools/emsdk/upstream/bin/clang.exe`. It receives a
  digest-bound, include-free type/tag preamble plus one sentinel declaration
  through stdin and runs this exact argv (no shell):
  `clang.exe --target=wasm32-unknown-emscripten -std=gnu11 -x c -Xclang
  -ast-dump=json -Xclang -ast-dump-filter -Xclang __oghidra_abi_probe
  -fsyntax-only -`. Current read-only validation on 2026-08-21 succeeded with
  Clang `24.0.0git` / LLVM revision `ff6d537b14d737719d6377789784d04ff9565f65`;
  binary SHA-256 `633be119308de42bd096a455faf321216423427ea1bac0f7de2d790f30232a93`;
  raw 216-byte `--version` stdout SHA-256
  `f58b2b92936b6a2b3ba1b3f74bcfb0fc2556933478adca609626efba57fb0637`.
  These identities describe the reviewed tree, not a permanent allowlist: an
  approved upgrade changes the assembly world and must pass conformance first.
- Task 2 embeds `ABI_PREAMBLE_V1` directly in `src/port_assembly_abi.py`; it is
  not read or generated from a product file. Its value is exactly the following
  1,870 UTF-8/ASCII bytes, with LF line endings and the shown final LF, SHA-256
  `c08c52ac4f22928ab46312b6a42695a3ef4336d10b469ea5dd310973ab850bbf`:

  ```c
  _Static_assert(__CHAR_BIT__ == 8, "ABI_PREAMBLE_V1 char");
  _Static_assert(sizeof(_Bool) == 1, "ABI_PREAMBLE_V1 bool");
  _Static_assert(__SIZEOF_SHORT__ == 2, "ABI_PREAMBLE_V1 short");
  _Static_assert(__SIZEOF_INT__ == 4, "ABI_PREAMBLE_V1 int");
  _Static_assert(__SIZEOF_LONG__ == 4, "ABI_PREAMBLE_V1 long");
  _Static_assert(__SIZEOF_LONG_LONG__ == 8, "ABI_PREAMBLE_V1 long long");
  _Static_assert(__SIZEOF_POINTER__ == 4, "ABI_PREAMBLE_V1 pointer");
  _Static_assert(__SIZEOF_FLOAT__ == 4, "ABI_PREAMBLE_V1 float");
  _Static_assert(__SIZEOF_DOUBLE__ == 8, "ABI_PREAMBLE_V1 double");
  _Static_assert(__SIZEOF_WCHAR_T__ == 4, "ABI_PREAMBLE_V1 wchar_t");
  _Static_assert(__SIZEOF_SIZE_T__ == 4, "ABI_PREAMBLE_V1 size_t");
  typedef struct __oghidra_FILE_v1 FILE;
  typedef struct __oghidra_FILE_v1 __FILE;
  typedef int (*__compar_fn_t)(const void *, const void *);
  typedef _Bool bool;
  typedef unsigned char byte;
  typedef void code;
  typedef long long longlong;
  typedef unsigned long size_t;
  typedef unsigned int uint;
  typedef unsigned long ulong;
  typedef unsigned long long ulonglong;
  typedef unsigned char undefined;
  typedef unsigned char undefined1;
  typedef unsigned short undefined2;
  typedef unsigned int undefined4;
  typedef unsigned long long undefined8;
  typedef unsigned short ushort;
  typedef int wchar_t;
  #define FILE struct __oghidra_FILE_v1
  #define __FILE struct __oghidra_FILE_v1
  #define __compar_fn_t __typeof__(int (*)(const void *, const void *))
  #define bool _Bool
  #define byte unsigned char
  #define code void
  #define longlong long long
  #define size_t unsigned long
  #define uint unsigned int
  #define ulong unsigned long
  #define ulonglong unsigned long long
  #define undefined unsigned char
  #define undefined1 unsigned char
  #define undefined2 unsigned short
  #define undefined4 unsigned int
  #define undefined8 unsigned long long
  #define ushort unsigned short
  #define wchar_t int
  ```

  The typedefs are the spelling environment; the later object-like macros are
  active only for ABI probes and recursively expose the fixed underlying type
  to Clang. Spelling parse/print appends the module's exact 273-byte
  `ABI_SPELLING_UNDEF_V1` constant (LF and final LF; SHA-256
  `d64b6528c22b9579689d2c677915eb20830b27bc465945ff7925dc0a2d65aa78`):

  ```c
  #undef FILE
  #undef __FILE
  #undef __compar_fn_t
  #undef bool
  #undef byte
  #undef code
  #undef longlong
  #undef size_t
  #undef uint
  #undef ulong
  #undef ulonglong
  #undef undefined
  #undef undefined1
  #undef undefined2
  #undef undefined4
  #undef undefined8
  #undef ushort
  #undef wchar_t
  ```

  Therefore the same embedded mapping supports spelling-preserving emission
  and typedef-insensitive equality without a product artifact or parser
  dependency. Both constant digests, byte lengths, target, Clang binary/version,
  and the mode (`abi` without undef; `spelling` with undef) enter the parser
  identity and assembly world.
- The closed mapping was audited over all 10,954 current registry records. Its
  non-builtin signature vocabulary is exactly `FILE`, `__FILE`,
  `__compar_fn_t`, `bool`, `byte`, `longlong`, `size_t`, `uint`, `ulonglong`,
  `undefined`, `undefined1`, `undefined2`, `undefined4`, `undefined8`, `ushort`,
  and `wchar_t`; current corpus/seed dialect additionally requires `code` and
  `ulong`, so both are mapped. `FILE`/`__FILE` are the same opaque incomplete
  tag and are valid only behind pointers. The pinned wasm32 assertions bind
  8-bit bytes, 16-bit short, 32-bit int/long/pointer/float/`size_t`/`wchar_t`,
  and 64-bit long-long/double; `undefined8` is unsigned integer, never double.
  An absent identifier/tag, a mapped name with another meaning, a redefinition,
  preamble directive in owner/registry text, incomplete type by value, or any
  declaration contributed by the appended owner/registry fragment outside the
  one sentinel is a typed
  `abi_preamble_unknown_or_ambiguous_type` refusal. No caller-supplied typedef,
  tag, include, macro, or ordering override is accepted. A future vocabulary
  addition changes these exact bytes/version and must pass review/conformance.
- Schema 1 supports the lossless Clang `gnu11` C declarator subset that the
  registry's `return_type` plus `params` fields can express: built-in integer/
  floating types, the exact closed aliases and opaque FILE tag above, `_Bool`,
  per-level `const|volatile|restrict`, pointers, fixed and
  incomplete parameter arrays, nested function-pointer parameters, fixed
  prototypes, `(void)`, unspecified `()`, and `...`. Default C/`cdecl` is the
  only calling convention. A function-returning-pointer/function declarator
  places the function name inside its return declarator and therefore cannot
  be reconstructed losslessly from schema 1; refuse it as
  `registry_shape_unrepresentable_return_declarator`. Schema 1 also has no
  declaration-attribute field, so any function `Attr` is refused as
  `registry_shape_unrepresentable_attribute` even when Clang knows it. K&R
  definitions, unresolved/out-of-preamble typedef or tag names, anonymous
  aggregates, macro-dependent owner declarators, owner-written `typeof`,
  vector/ext-int types,
  asm labels, non-C calling conventions, any diagnostic on stderr, nonzero
  exit, multiple/no matching `FunctionDecl`, or an unknown AST field needed by
  the projection are typed refusals.
- A small deterministic token scanner, not a type parser, locates the expected
  direct function name and balanced declarator/body brace while honoring C
  comments, strings, characters, escapes, brackets, and parentheses. It
  replaces only the name with `__oghidra_abi_probe` and the body with `{}`;
  Clang alone decides declarator structure. The scanner refuses imbalance,
  directives/macros in the declarator, or more than one direct definition.
- `declarator_ast_schema=1` separates spelling from ABI identity. Its spelling
  projection is exactly `spelled_function_type` from the spelling-mode
  `FunctionDecl.type.qualType`, ordered `spelled_parameter_types` from each
  original `ParmVarDecl.type.qualType`, `prototype_kind:
  'unspecified'|'void'|'prototype'`, `variadic: bool`,
  `calling_convention: 'c'`, `attributes: []`, and the canonical prototype
  bytes. These fields drive owner spelling/emission only and never ABI equality.
  AST IDs, locations, and implicit nodes are excluded from durable identity;
  source offsets are temporary emitter inputs.
- ABI evidence uses pinned-Clang probes and exact `AbiTuple`, never an
  invented C-type parser. From the
  successful spelling-mode print, the token scanner obtains the flat return
  spelling and ordered abstract parameter spellings after identifier erasure;
  function-returning-pointer is already refused. Any user fragment containing
  the reserved `__oghidra_abi_` prefix refuses. With `ABI_PREAMBLE_V1` macros
  active, create one zero-padded declaration per parameter in order:
  `typedef __typeof__(PARAMETER) __oghidra_abi_param_0000;`, then declare
  `void __oghidra_abi_probe(__oghidra_abi_param_0000, ...)` with the original
  ellipsis/prototype kind. Run the exact JSON argv filtered to
  `__oghidra_abi_probe`. Require exactly the original arity/order and require
  each synthetic `ParmVarDecl.type.desugaredQualType` to exist as a nonempty
  string except for the one bounded adjusted-parameter path below. The active
  exact macros make alias expansion recursive. Clang alone owns array/function
  parameter adjustment; no Python type or qualifier normalization is allowed.
- Pinned Clang 24 can remove the synthetic typedef while adjusting an array
  parameter and then omit `ParmVarDecl.type.desugaredQualType`. In that exact
  case, do **not** accept `qualType` as the ABI value and do not refuse the
  schema-supported array. Require the node's `type` object to have exactly one
  key, a nonempty string `qualType`; call this observed adjusted spelling `Q`.
  Reject CR, LF, NUL, non-UTF-8, an empty value, another/missing type key, or
  any arity/order/prototype ambiguity. For each such ordinal in ascending
  order, run one second deterministic `VarDecl` probe whose stdin is exactly
  `ABI_PREAMBLE_V1` followed immediately by these two UTF-8/LF lines, with the
  zero-padded four-digit ordinal and `Q` inserted only at `{Q}`:

  ```c
  typedef __typeof__({Q}) __oghidra_abi_adjusted_param_type_0000;
  __oghidra_abi_adjusted_param_type_0000 __oghidra_abi_adjusted_param_probe_0000;
  ```

  Its no-shell argv is the exact bound JSON argv with only the filter value
  changed from `__oghidra_abi_probe` to the matching
  `__oghidra_abi_adjusted_param_probe_0000`. Require exit zero, empty stderr,
  strict-UTF-8 stdout containing exactly one JSON value, root
  `kind='VarDecl'`, exact sentinel `name`, and `root.type.qualType` equal to the
  matching `__oghidra_abi_adjusted_param_type_0000`. Only the nonempty string
  `root.type.desugaredQualType` becomes the `AbiTuple` parameter. AST IDs and
  `typeAliasDeclId` are ignored; missing/multiple/wrong nodes or fields,
  diagnostics, decode/JSON failure, nonzero exit, a remaining forbidden alias
  token under the rule below, or a result inconsistent with arity/order is typed
  `abi_adjusted_parameter_probe_invalid`. Thus observed `Q` is merely
  digest-bound Clang input to a second Clang-owned desugaring, never an unbound
  fallback or durable ABI answer.
- Return identity uses a separate JSON invocation. For a non-void flat return,
  append the LF-terminated synthetic typedef named
  `__oghidra_abi_return_type` with exact source form `typedef
  __typeof__(RETURN) __oghidra_abi_return_type;`, followed by
  `__oghidra_abi_return_type __oghidra_abi_return_probe;`, filter to the one
  `VarDecl`, and require its `type.desugaredQualType` without fallback. Its
  argv is exactly the bound JSON argv above with only the filter value changed
  from `__oghidra_abi_probe` to `__oghidra_abi_return_probe`. This is
  the pinned-Clang field actually observed for both `uint` and `unsigned int`.
  Closed aliases `void` and `code` are the sole object-inexpressible return
  case: both must parse as a function return under the active mapping and map
  to exact canonical string `void`; no other missing VarDecl field is allowed.
  Unknown/multiple nodes, warnings/stderr, forbidden alias text remaining in a
  desugared value, or an arity/variadic/prototype mismatch refuses.
- The closed source-alias-token set is exactly `FILE`, `__FILE`,
  `__compar_fn_t`, `bool`, `byte`, `code`, `longlong`, `size_t`, `uint`,
  `ulong`, `ulonglong`, `undefined`, `undefined1`, `undefined2`, `undefined4`,
  `undefined8`, `ushort`, and `wchar_t`. The forbidden-remnant set is that
  exact set minus `bool`. Tokenize every primary, adjusted-secondary, and
  return `desugaredQualType` as C identifier tokens and refuse
  `abi_probe_alias_not_desugared` if any forbidden-remnant member remains.
  Pinned Clang 24 under the exact 1,870-byte preamble reports builtin `_Bool`
  with the complete identifier token `bool` in these mandatory
  `desugaredQualType` fields because the preamble's spelling-mode typedef is
  visible. That exact compiler-owned token is the sole exception and remains
  verbatim in `AbiTuple`; Python must not replace it with `_Bool` or perform
  any contextual/string normalization. The exception applies only to a
  mandatory `desugaredQualType` obtained from a successful bound primary,
  adjusted-secondary, or return probe. It never permits a `qualType` fallback,
  fabricated/fake production evidence, another alias, or a changed
  preamble/tool identity.
- `AbiTuple` is exactly `{abi_tuple_schema: 1, return_type: string,
  parameter_types: list[string], arity: nonnegative-int, variadic: bool,
  prototype_kind: 'unspecified'|'void'|'prototype',
  calling_convention: 'c'}`. `arity == len(parameter_types)`. Default C is
  fixed by the target/argv and the prior refusal of every calling-convention
  attribute; it is not inferred from a type string. The tuple is durable,
  desugared evidence and a receipt input, but tuple spelling equality is not
  owner-versus-variant ABI compatibility: Clang legitimately preserves
  adjusted top-level parameter qualifiers in these fields. The payload is
  canonical JSON (`sort_keys=True`, UTF-8, no insignificant whitespace) plus
  one LF. `abi_tuple_sha256` hashes exactly ASCII
  `OGHIDRA_ABI_TUPLE_V1`, one NUL byte, the payload length as unsigned 8-byte
  big-endian, then the payload. The tuple payload/digest, preamble/undef
  digests, all probe evidence below, exact argv, and Clang identities enter
  `owner_binding_sha256` and the assembly world.
- `AbiProbeEvidence` is exact canonical schema-1 data:
  `{abi_probe_schema: 1, parameter_source_size: positive-int,
  parameter_source_sha256: sha256, adjusted_parameters: list[exact {ordinal:
  nonnegative-int, observed_adjusted_qual_type: nonempty string,
  source_size: positive-int, source_sha256: sha256,
  desugared_qual_type: nonempty string}], return_source_size: positive-int,
  return_source_sha256: sha256}`. Adjusted entries are unique and ordinal-
  sorted; absence is `[]`, never null. Every source hash covers exact stdin;
  executable/binary/version/target/dialect/filter argv remain in parser
  identity. The complete evidence enters the owner-only binding, relevant
  catalog, canonicalization receipt, assembly world, and retry fingerprint.
  Any primary/secondary source, AST projection, or tool identity change opens a
  different world; no adjusted string is normalized before hashing.
- Pinned Clang alone decides owner-versus-variant ABI compatibility after both
  declarations pass schema/refusal checks. There is no qualifier stripping and
  no tuple/string equality gate. Starting from each exact canonical no-LF
  prototype, the existing token scanner replaces only its complete stable
  symbol token with `__oghidra_abi_compat_left` or
  `__oghidra_abi_compat_right`. The complete compatibility stdin is exactly
  `ABI_PREAMBLE_V1`, the left prototype, LF, the right prototype, LF, then this
  exact ASCII line and final LF:

  ```c
  enum { __oghidra_abi_compat_result = __builtin_types_compatible_p(__typeof__(&__oghidra_abi_compat_left), __typeof__(&__oghidra_abi_compat_right)) };
  ```

  The address expressions make the two operands complete adjusted function-
  pointer types owned by Clang, including return type, adjusted parameters,
  arity, prototype kind, variadic bit, nested qualifiers, and calling
  convention. Run this exact no-shell argv:
  `clang.exe --target=wasm32-unknown-emscripten -std=gnu11 -x c -Xclang
  -ast-dump=json -Xclang -ast-dump-filter -Xclang
  __oghidra_abi_compat_result -fsyntax-only -`. Require exit zero, empty stderr,
  and strict-UTF-8 stdout containing exactly one JSON value. It must be an
  `EnumConstantDecl` named `__oghidra_abi_compat_result` with
  `type={"qualType":"int"}`, exactly one `inner` node that is a
  `ConstantExpr` with that same type, `valueCategory="prvalue"`, value exactly
  string `"0"` or `"1"`, and exactly one child of kind `TypeTraitExpr`.
  AST IDs and source ranges are ignored; missing/multiple/wrong nodes, another
  value, diagnostic bytes, decode/JSON failure, or nonzero exit is typed
  `abi_compatibility_probe_invalid`. Value `"1"` is compatible; value `"0"`
  is a deterministic `owner_variant_abi_incompatible` blocker. No LLM runs.
- `CompatibilityEvidence` is exact schema-1 canonical JSON:
  `{compatibility_schema: 1, symbol: C identifier, source_relpath: owned
  relative string, owner_prototype_sha256: sha256,
  variant_prototype_sha256: sha256, owner_abi_tuple_sha256: sha256,
  variant_abi_tuple_sha256: sha256, probe_source_size: positive-int,
  probe_source_sha256: sha256, parser_identity_sha256: sha256,
  result: 'compatible'|'incompatible'}`. `probe_source_sha256` is over the
  exact stdin bytes above. `parser_identity_sha256` binds schema, resolved
  Clang path/binary/version, target/dialect, exact preamble length/digest, and
  exact compatibility argv. Evidence lists sort by
  `(symbol,source_relpath,variant_prototype_sha256)` and reject duplicates.
  This pair-specific source/result never enters the owner-only
  `owner_binding_sha256`; it enters the canonicalization receipt, assembly
  world, and retry fingerprint, so a variant change is deterministic without
  pretending the two `AbiTuple` payloads are spelling-equal.
- Named-declarator emission has one production path and no Python type parser.
  First make the sentinel declaration by the scanner above, replacing the
  body with `;`. From the successful JSON AST, require each named
  `ParmVarDecl.loc.offset`/`tokLen` to address exactly its UTF-8 identifier
  token inside that stdin buffer; reject absent, macro/spelling, overlapping,
  out-of-range, non-identifier, or non-byte-aligned locations. Delete those
  parameter-name byte intervals from right to left. Do not otherwise edit
  whitespace or types. Feed exact `ABI_PREAMBLE_V1 +
  ABI_SPELLING_UNDEF_V1` plus that unnamed declaration to this second exact
  no-shell argv:
  `clang.exe --target=wasm32-unknown-emscripten -std=gnu11 -x c -Xclang
  -ast-print -fsyntax-only -`. The executable, target, dialect, preamble,
  binary/version digests, all exact argv arrays, and projection schema are one
  bound parser/emitter identity.
- Decode printer stdout as strict UTF-8, normalize CRLF and bare CR to LF, and
  use the same comment/string-aware top-level token scanner over the **entire**
  stdout, never a line-based search. It must partition every non-whitespace byte
  into complete balanced top-level declarations before selecting exactly one
  semicolon-terminated declaration containing the sentinel identifier as a
  complete token. At adapter initialization, print exact `ABI_PREAMBLE_V1 +
  ABI_SPELLING_UNDEF_V1` alone with the same argv and bind its normalized
  complete-declaration sequence and stdout digest into parser identity. Every
  non-sentinel declaration in a real print must byte-match that sequence in
  order. Reject garbage or an incomplete declaration anywhere before or after
  the sentinel, any extra/missing/reordered preamble declaration,
  zero/two sentinel matches, diagnostics, a body/directive in the selected
  declaration, or trailing tokens after its one `;`. Trim only
  leading/trailing horizontal whitespace, replace the sentinel token with the
  original stable symbol label, and emit the resulting declaration as UTF-8
  with exactly one semicolon and no final newline. Clang owns all interior
  spacing. Reparse those exact bytes with the JSON argv and require identical
  spelling projection and separately recomputed `AbiTuple`, prototype kind,
  variadic bit, and empty attributes. Owner-versus-variant acceptance uses the
  compatibility probe above, not tuple-payload equality.
  Independently parse the owner definition and registry declaration and
  require their projections, `loc`, and range to agree.
- Current pinned-Clang byte conformance (canonical emitted rows reparse to the
  same spelling projection and tuple evidence; `hex` is the exact emitted
  no-LF byte string):

  | case | schema-1 outcome / canonical prototype bytes |
  |---|---|
  | typedef sugar (`typedef unsigned int uint`) | pass: `uint synthetic(uint);`; hex `75696e742073796e7468657469632875696e74293b`; ABI parameter `unsigned int`, spelling `uint` |
  | nested function-pointer parameter | pass: `void synthetic(int (*)(const char *, unsigned int));`; hex `766f69642073796e74686574696328696e7420282a2928636f6e73742063686172202a2c20756e7369676e656420696e7429293b` |
  | function returning function pointer | refuse `registry_shape_unrepresentable_return_declarator`; no emitted bytes |
  | adjusted array `unsigned a[4]` | pass: `void synthetic(unsigned int[4]);`; hex `766f69642073796e74686574696328756e7369676e656420696e745b345d293b`; reparsed parameter `unsigned int *` |
  | unspecified `()` | pass: `void synthetic();`; hex `766f69642073796e74686574696328293b`; kind `unspecified` |
  | explicit `(void)` | pass: `void synthetic(void);`; hex `766f69642073796e74686574696328766f6964293b`; kind `void` |
  | function `__attribute__((used))` | refuse `registry_shape_unrepresentable_attribute`; no emitted bytes |

  Adjusted-array extraction vectors are normative and use the exact primary
  JSON argv. For parameter spelling `unsigned int[4]`, stdin is the 1,870-byte
  preamble followed by this exact 114-byte ASCII suffix (`\n` denotes one LF):

  ```text
  typedef __typeof__(unsigned int[4]) __oghidra_abi_param_0000;\nvoid __oghidra_abi_probe(__oghidra_abi_param_0000);\n
  ```

  The complete stdin is 1,984 bytes, SHA-256
  `50073f94f5ea6a2db084c0d3061af01fe373a08d065f70a143abbdd95711ef0c`.
  Pinned Clang exits zero with empty stderr; the sole filtered
  `FunctionDecl.type` is exactly `{"qualType":"void (unsigned int *)"}` and
  its ordinal-zero `ParmVarDecl.type` is exactly
  `{"qualType":"unsigned int *"}` with no `desugaredQualType`. This absence
  triggers the bounded secondary path; it is not itself a pass or ABI value.

  Here `Q` is exact observed `unsigned int *`. The secondary source defined
  above is 2,025 bytes, SHA-256
  `af0eed3c64a8436bddeba4b67642910ec7af0a18c2e074dab43901338f4e7b08`.
  The exact adjusted-sentinel argv exits zero with empty stderr and one root
  `VarDecl` named `__oghidra_abi_adjusted_param_probe_0000`; its projected type
  is `qualType='__oghidra_abi_adjusted_param_type_0000'` and mandatory
  `desugaredQualType='unsigned int *'`. The final tuple parameter is therefore
  `unsigned int *` and the adjusted-array row passes.

  The typedef-array spelling `uint[4]` relies only on the embedded preamble.
  Its exact primary source is 1,976 bytes, SHA-256
  `1ab534677857681dae3650ac3058eadf16376eb9475711f3b3116b218a03cf28`;
  it produces the same primary `FunctionDecl`/missing-field observation and
  therefore the byte-identical 2,025-byte secondary source/result. Tests
  reconstruct all three sources, assert both primary AST paths and the
  secondary `VarDecl` path, and typed-refuse every malformed/missing/ambiguous
  variant. A direct use of either primary `qualType` is a test failure.

  The pinned `_Bool` representation vectors are independently normative. The
  parameter stdin is the 1,870-byte preamble followed by this exact 104-byte
  ASCII suffix (`\n` denotes one LF):

  ```text
  typedef __typeof__(_Bool) __oghidra_abi_param_0000;\nvoid __oghidra_abi_probe(__oghidra_abi_param_0000);\n
  ```

  The complete stdin is 1,974 bytes, SHA-256
  `979dcb0e8c3b7f16df0f079eb32dc88ec29edd8aee45e6f6869bc88ffca645ee`.
  The exact parameter JSON argv exits zero with empty stderr; the sole
  ordinal-zero node projects
  `{"desugaredQualType":"bool","qualType":"__oghidra_abi_param_0000"}`
  after ignored `typeAliasDeclId`. The return stdin is the same preamble plus
  this exact 107-byte suffix:

  ```text
  typedef __typeof__(_Bool) __oghidra_abi_return_type;\n__oghidra_abi_return_type __oghidra_abi_return_probe;\n
  ```

  The complete stdin is 1,977 bytes, SHA-256
  `d1ab6f90f9fd697bbab8be406c2277bea262d73f95856af612b46db5c6dab503`.
  The exact return JSON argv exits zero with empty stderr; the sole `VarDecl`
  projects
  `{"desugaredQualType":"bool","qualType":"__oghidra_abi_return_type"}`
  after ignored `typeAliasDeclId`. Replacing `_Bool` with source spelling
  `bool` produces the same two projected type objects: parameter source
  `1,973 / c9a06c3b229b3212f3416aebc9e945f0373ce68708bb6f1ee31a13514ab94369`
  and return source
  `1,976 / 971b34604b31d95f4d04d44df8bd15ecf40817df70c541c5553d6954b62fdb4c`.
  Thus `void synthetic(_Bool);` and `void synthetic(bool);` both produce exact
  payload
  `{"abi_tuple_schema":1,"arity":1,"calling_convention":"c","parameter_types":["bool"],"prototype_kind":"prototype","return_type":"void","variadic":false}\n`
  (152 bytes) and framed digest
  `1d4fc56beae25b544724f2105c503133143ef8f12b6e65598abdc1ed4ae14bd4`.
  `_Bool synthetic(void);` and `bool synthetic(void);` both produce exact
  payload
  `{"abi_tuple_schema":1,"arity":0,"calling_convention":"c","parameter_types":[],"prototype_kind":"void","return_type":"bool","variadic":false}\n`
  (141 bytes) and framed digest
  `d53e301357f4fd5f53d2c51e68c0dd88b3dc8c61917c35752947f785fff1d85b`.
  Crossed refusals cover missing `desugaredQualType` with `qualType='bool'`,
  caller substitution of `_Bool` for the observed durable `bool`, `bool` from
  an unbound tool/preamble or non-production fake, and every remaining source
  alias token in a mandatory field. A complete token such as `boolish` is not
  this exception and is handled by ordinary C type/name validation.

  Typedef-insensitive ABI vectors are normative. Each pair produces byte-equal
  tuple payloads even though owner spelling emission remains different:

  - `void synthetic(uint);` versus `void synthetic(unsigned int);` produces
    `{"abi_tuple_schema":1,"arity":1,"calling_convention":"c","parameter_types":["unsigned int"],"prototype_kind":"prototype","return_type":"void","variadic":false}\n`
    and framed digest
    `5c14caef4ae18991d24cdfd6c1f2b78a809137b287e50bc635dcf77a82b28a6d`.
  - `uint synthetic(void);` versus `unsigned int synthetic(void);` produces
    `{"abi_tuple_schema":1,"arity":0,"calling_convention":"c","parameter_types":[],"prototype_kind":"void","return_type":"unsigned int","variadic":false}\n`
    and framed digest
    `d25e22e0761cfaa90006e18e308eccaaa492da20122ef1d33fdbd8a28efc278f`.
  - `uint synthetic(uint);` versus `unsigned int synthetic(unsigned int);`
    produces
    `{"abi_tuple_schema":1,"arity":1,"calling_convention":"c","parameter_types":["unsigned int"],"prototype_kind":"prototype","return_type":"unsigned int","variadic":false}\n`
    and framed digest
    `11acd06ddd182b790b3f9703469d778442bf8874c4bc334b9acdd80ce2887e56`.

  Clang-owned compatibility vectors are independently normative. Each source
  is framed from exact `ABI_PREAMBLE_V1`, the shown left canonical declaration
  plus LF, the shown right canonical declaration plus LF, and the exact enum
  line plus LF above. Tuple payloads remain recorded and need not be byte-equal.

  | left / right canonical declarations | bytes | stdin SHA-256 | exact result |
  |---|---:|---|---:|
  | `void __oghidra_abi_compat_left(int);` / `void __oghidra_abi_compat_right(const int);` | 2,101 | `79f9ffd619450cc9201ee8f5f4b82e246649b30f732e0ee364b647b35c570144` | `1` |
  | `void __oghidra_abi_compat_left(int *);` / `void __oghidra_abi_compat_right(int *const);` | 2,104 | `297332a57a770c0eb8b8d76b658e59650f7bb54599cd92d5b3d2caec8a5b2f3b` | `1` |
  | `void __oghidra_abi_compat_left(int *);` / `void __oghidra_abi_compat_right(int *restrict);` | 2,107 | `2ad0833c5d3c9c7439e23eec4881ad48418e2b7e205695739c0b5e937fc3c624` | `1` |
  | `void __oghidra_abi_compat_left(int *);` / `void __oghidra_abi_compat_right(const int *);` | 2,105 | `13a49f7cac54fb1b6c03e662da84f7c7577e5e2710710abda68555c79b7ae35b` | `0` |
  | `void __oghidra_abi_compat_left(int *);` / `void __oghidra_abi_compat_right(volatile int *);` | 2,108 | `b3ca6f185440ad21f696ee78a00038bcc57651a00beb5a393dc31d16eb38671f` | `0` |

  Thus Clang accepts top-level parameter `const`, pointer `const`, and pointer
  `restrict` differences after function-parameter adjustment, while retaining
  pointee `const` and `volatile` as ABI distinctions. Tests reconstruct all
  five sources byte-for-byte, recompute the hashes, exercise the exact argv and
  JSON extraction, and assert that tuple spelling is not the decision rule.

  The preamble-dependent conformance source `FILE *synthetic(__compar_fn_t cb,
  wchar_t *w, undefined8 x);` must fail without the embedded preamble and pass
  only with it. Spelling mode emits exact no-LF bytes `FILE
  *synthetic(__compar_fn_t, wchar_t *, undefined8);` (hex
  `46494c45202a73796e746865746963285f5f636f6d7061725f666e5f742c2077636861725f74202a2c20756e646566696e656438293b`).
  ABI mode must return this exact payload:

  ```json
  {"abi_tuple_schema":1,"arity":3,"calling_convention":"c","parameter_types":["int (*)(const void *, const void *)","int *","unsigned long long"],"prototype_kind":"prototype","return_type":"struct __oghidra_FILE_v1 *","variadic":false}
  ```

  plus LF, 234 payload bytes, and framed digest
  `58eb175039b96ae787e5545786e27975e613f2a9dbf16c5105cffc5e9ca38edd`.
  Tests recompute all four frames and compare tuple bytes before digests.

  The read-only 2026-08-21 probe also observed exact sentinel printer lines
  `uint __oghidra_abi_probe(uint);`, `void __oghidra_abi_probe(int
  (*)(const char *, unsigned int));`, and `void
  __oghidra_abi_probe(unsigned int[4]);`; each had LF only, zero exit, and
  empty stderr. Additional fresh probes observed mandatory
  `ParmVarDecl.type.desugaredQualType='unsigned int'` and
  `VarDecl.type.desugaredQualType='unsigned int'` for both `uint` and
  `unsigned int`, and recursively canonicalized `wchar_t *` to `int *` through
  the active mapping. Fresh compatibility probes produced the exact
  `1,1,1,0,0` results and five source digests above. Tests assert the
  table/vectors at byte level, all reparses, exact argv/probe sources, and
  fail-closed offsets/refusals.
- `DeclaratorParser` is an injected internal seam: production uses only the
  Clang adapter; interface tests use a deterministic fake that returns fixture
  projections. Fail-closed real-Clang conformance covers primitive/qualified
  pointers, all seven table rows, variadics, and every refused dialect feature.
  No Python parser package or new dependency is added.
- `revalidate_receipt` performs fresh stable reads and compares identities,
  registry/range/whole-file digests, private bundle/object digests, and the
  bound tool world at `pre-compile` and `pre-publication`. Any change
  invalidates the receipt before a tool or publication side effect.
- `owner_binding_sha256` hashes canonical JSON containing schema, symbol,
  record fields, spelling-preserving canonical prototype, exact `AbiTuple`
  payload and framed digest, both embedded preamble constant digests/lengths,
  the complete owner-only `AbiProbeEvidence`, parser identity,
  path/range, whole-file digest, and range digest. It never includes a caller
  variant or pairwise compatibility result. `relevant_catalog_sha256` hashes
  only sorted bindings for symbols relevant to the bundle; `registry_sha256`
  remains provenance but unrelated registry churn does not reopen a
  composition red.

### 3. Bundle-only owner-derived canonicalization

- Inputs are exact name/digest-bound candidate and prior artifacts already
  copied into the private promotion attempt. Never edit a staged, verified,
  source-corpus, or product-worktree file.
- Discover shared internal function symbols across every header, pre-verbatim
  source prelude, direct definition, and body reference in the bundle.
- A unique verified owner definition outranks caller/header guesses. Replace
  every declaration for that symbol in every derived header and pre-verbatim
  prelude with the one canonical prototype. Do not edit a verbatim body or a
  direct definition. Before replacement, compare each owner/variant pair with
  the exact pinned-Clang compatibility probe. Only result `compatible` may be
  discarded and replaced; `incompatible` is contested. Record each comparison,
  its exact source digest, both tuple evidence digests, result, variant, and
  source.
- Canonicalization is atomic: first validate and plan the entire bundle in
  memory, then write all derived files under the owned attempt directory. A
  refusal writes no partial canonical bundle.
- For an owner-eligible symbol, zero verified owners, multiple owner records,
  multiple direct definitions, any Clang-incompatible declaration variant, or
  any selected direct definition contradicting the catalog is contested.
  The gate stops before compile/link and records a structural refusal.
- Resolution evidence includes symbol, owner unit/path/range, registry/range/
  owner-binding digests, chosen prototype, ordered compatibility checks with
  exact probe-source/result identities, discarded variants, affected artifacts,
  and derived bundle digest. It makes no behavioral claim.

### 4. Precise object attribution

- A `TranslationUnitPlan` fixes `unit_id`, role, source artifact identity,
  derived-source SHA-256, ordered compile argv, and unique NFC POSIX object
  relpath. The gate materializes each plan and invokes the compiler once per
  plan. It may link only after every planned object exists and passes the
  pre-compile receipt revalidation.
- For each object, the gate invokes the bound LLVM `llvm-nm`-compatible
  inspector and constructs `ObjectObservation(object_relpath,
  object_sha256, defined_symbols, imported_symbols, inspector_receipt)`.
  Symbol entries preserve Wasm kind, normalized signature/type when present,
  visibility, and role. `analyze_composition` requires exactly one observation
  for every plan, no unplanned object, matching object digest/path, and a
  successful inspector receipt before it creates an object manifest.
- `InspectorReceipt` is exactly `{execution_completed: bool, success: bool,
  exit_status: int|null, stdout_sha256: sha256|null, stderr_sha256:
  sha256|null, parser_version: nonempty string, fault_class:
  null|'spawn'|'timeout'|'crash'|'io', diagnostic_sha256: sha256|null}`.
  Success requires `execution_completed=true`, `exit_status=0`, both stream
  digests, `fault_class=null`, and `diagnostic_sha256=null`. A completed
  failure requires integer exit status, both stream digests, null fault, and a
  diagnostic digest. An execution fault requires completed/success false,
  null exit status, a named fault and diagnostic digest; stream digests hash
  captured partial bytes when present. Every other combination refuses.
- `StageChildReceipt` is the exact closed object `{stage_child_receipt_schema:
  1, child_ordinal: nonnegative-int, object_ordinal: nonnegative-int, unit:
  nonempty string, stage: 'compile'|'inspect', terminal: bool, argv:
  nonempty list[string], object_relpath: owned relative string, input_sha256:
  sha256, object_sha256: sha256|null, state:
  'passed'|'failed'|'faulted', execution_completed: bool, exit_status:
  int|null, stdout_size: nonnegative-int, stdout_sha256: sha256,
  stderr_size: nonnegative-int, stderr_sha256: sha256, parser_version:
  nonempty string, diagnostic_sha256: sha256|null, symbol: C identifier|null,
  fault_class: null|'spawn'|'timeout'|'crash'|'io'|'lock'|'stable_read'}`.
  `input_sha256` is the derived-source digest for compile and the stable input-
  object digest for inspect. Compile pass requires `object_sha256`; compile
  failure/fault permits it only when a stable ordinary output was actually
  observed. Inspect always requires `object_sha256=input_sha256`. Pass requires
  completed true, exit zero, null diagnostic/symbol/fault; failed requires
  completed true, integer exit, nonnull diagnostic, null fault; faulted requires
  completed false, null exit, nonnull diagnostic/fault. Stream size/digest bind
  the exact raw bytes captured even for a fault; zero bytes use SHA-256 of empty
  bytes, never null. A diagnostic parser may set one symbol only on failed/
  faulted children.
- A compile/inspect child list is nonempty, `child_ordinal` is exactly its
  zero-based position, `object_ordinal`/path/unit are unique and follow the
  plan order, and exactly its last child has `terminal=true`. All children
  before the terminal are `passed`; the terminal is `passed` iff the aggregate
  stage passed, otherwise it alone is `failed|faulted`. Execution stops there.
  The closed transcript is exact `{stage_child_transcript_schema: 1, stage:
  'compile'|'inspect', children: list[StageChildReceipt]}` serialized as
  canonical compact sorted-key UTF-8 JSON plus LF; its SHA-256 is
  `child_transcript_sha256`.
- Aggregate stream preimages are independently exact canonical JSON plus LF:
  `{stage_stream_schema: 1, stage, stream: 'stdout'|'stderr', children:
  list[{child_ordinal, size, sha256}]}` in child order. The StageReceipt stream
  digest is the SHA-256 of that preimage, not concatenated raw bytes. Its exit,
  completed, parser, diagnostic, symbol, and fault fields equal the terminal
  child's fields; `named_object_relpaths` is every child path in order. Thus
  result/retry IDs bind both raw-child digests and transcript structure without
  depending on process buffering.
- `StageReceipt` is exact `{stage_receipt_schema: 1, stage:
  'compile'|'inspect'|'link'|'instantiate'|'smoke', state:
  'not_run'|'passed'|'failed'|'faulted', execution_completed: bool,
  exit_status: int|null, stdout_sha256: sha256|null, stderr_sha256: sha256|null,
  parser_version: nonempty string|null, diagnostic_sha256: sha256|null,
  symbol: C identifier|null, named_object_relpaths: list[owned relative string],
  fault_class: null|'spawn'|'timeout'|'crash'|'io'|'lock'|'stable_read',
  child_receipts: list[StageChildReceipt], child_transcript_sha256:
  sha256|null}`.
  Object paths are unique in plan order. A compile receipt names exactly the
  attempted translation-unit objects through its terminal child; inspect names
  exactly the inspected objects through its terminal child; link names every
  ordered link input; instantiate/smoke name `[]`. `not_run` always has `[]`.
  `symbol` is null on pass/not-run and for instantiate/smoke; on a failed or
  faulted compile/inspect/link receipt it is either the single identifier
  parsed from that stage's diagnostic or null. Compile/inspect require the
  exact nonempty child list/transcript and aggregates above whenever attempted;
  all other stages and every `not_run` receipt require `child_receipts=[]` and
  null transcript. `exit_status` is zero on aggregate pass or the terminal
  child status on completed failure.
- The per-receipt truth matrix is closed: `not_run` means completed false and
  every evidence field null/empty; `passed` means completed true, exit zero,
  both stream digests and parser version present, diagnostic/fault null;
  `failed` means completed true, integer exit (zero is allowed for a semantic
  parser/smoke failure), both stream digests/parser/diagnostic present and fault
  null; `faulted` means completed false, exit null, parser/diagnostic/fault
  present, with nullable stream digests only for captured partial bytes. No
  other null/value combination is valid.
- `ToolOutcome` is exactly `{tool_outcome_schema: 1, receipts:
  [StageReceipt,StageReceipt,StageReceipt,StageReceipt,StageReceipt]}` in fixed
  stage order compile, inspect, link, instantiate, smoke. A pass has all five
  receipts `passed`. A non-pass has zero or more prior `passed` receipts, then
  exactly one first `failed|faulted` attempted stage, then only `not_run`.
  Skips, a passed stage after a non-pass, two attempted failures, wrong order,
  unknown keys/enums, or bool-as-int refuses. Outcome classification/stage/code
  are derived from this tuple and normalized diagnostic parsing; no lossy
  linked/instantiated/smoke booleans exist. The module correlates a symbol only
  to manifests that define or import it; it never copies the whole window into
  `conflict.units`.

  Normative state vectors use `P=passed`, `F=failed`, `X=faulted`, `N=not_run`:

  | result / terminal stage | compile | inspect | link | instantiate | smoke |
  |---|---|---|---|---|---|
  | pass | P | P | P | P | P |
  | compile completed/fault | F/X | N | N | N | N |
  | inspect completed/fault | P | F/X | N | N | N |
  | link completed/fault | P | P | F/X | N | N |
  | instantiate completed/fault | P | P | P | F/X | N |
  | smoke completed/fault | P | P | P | P | F/X |

  Tests instantiate both `F` and `X` for every terminal row and the exact field
  matrix for every cell. The exhaustive refusal set is the complement of these
  eleven vectors: any reordered/short/long tuple, `N` before `P`, `P` after
  `F|X`, two `F|X`, or field/state violation must refuse before hashing.
  The assembly retry fingerprint includes every nonnull
  `child_transcript_sha256` in stage order in addition to the aggregate stage
  fields, so changing argv/object/raw-stream evidence changes result ID and
  retry identity.

  Normative child vectors use this exact generator contract, not host process
  output. For child `i`, unit is `synthetic-u<i>`, path is `obj/<i>.o`, input
  digest is SHA-256 of ASCII `<stage>:input:<i>`, and compile object digest on
  pass is SHA-256 of ASCII `compile:object:<i>`; inspect object digest equals
  its input digest. Compile argv is exactly `['emcc','-c','u<i>.c','-o',path]`;
  inspect argv is `['llvm-nm',path]`. Raw stream bytes are UTF-8 ASCII
  `<stage>:<stream>:<i>:<state>\n`. Parser version is
  `synthetic-<stage>-parser-v1`. Failed/faulted diagnostic digest is SHA-256 of
  ASCII `<stage>:diagnostic:<i>:<state>`, symbol is `bad_symbol`; completed
  failure exit is 2, and fault is `timeout`. The following 12 rows give
  transcript byte count/digest and aggregate stdout/stderr digests:

  | stage | children/states | transcript bytes / SHA-256 | stdout SHA-256 | stderr SHA-256 |
  |---|---|---|---|---|
  | compile | 1 / P | `793 / 79c076271b1b98f935eaa39743cb853295d3b785d91b7dfe90d345f6f7479e4f` | `d33a223670cffdc68f5f51af4d3b821abe3fa1fa703a485b7b7a5959c35ac27f` | `b116c438f4bcea2ac63b2ebfddaa247a3e1d72eeb3564ffc5262a9072c82d970` |
  | compile | 1 / F | `801 / 3af9ef3f51f1a70c2550c1a5b6f48b3c2e82f3aacf81ff42b3add58f2ac225b2` | `2ef81149897af5e05ba6bf4f1a697e68a07f26eb2d7dc86430583b0d3c7d576a` | `f9383afa6d133c9e2c30a3d453510857fb6c0f587ab1094bb3a75dc2925cd2d6` |
  | compile | 1 / X | `811 / 7b8afc5d68acf223f4ed13075a538e12853263b047800a4a5793a766217b4bd7` | `48d2eca464c3b455ab6eaa0841a1e5e06883866df0928e10615429d279a3d021` | `86a2506daa0b66a6c44105ff9cae49e6a7bf1594bf22639cbc2b8c09d2dd2b3f` |
  | compile | 2 / PP | `1520 / 13c20432c56b218755e17b2e57cf1dad1df16177e50afb8abd3849e412d6f80c` | `387b91409407d15b6eb8425ad050fcdddd4489b665b30a760e88c2972790e15b` | `6704730c1fc47c1c1b716767500a880bae53f228313af769228d2e50e52dcd38` |
  | compile | 2 / PF | `1528 / 8da406382d8272ba2a8b50367baa72977141ed365e5e8d61b7b810accbed313c` | `7e3f04cb5c417c16e04458cf643be87d6c006d0b505f9e5cade8f6d4127fd111` | `9aa670d5a0a5efe680d8905cc8934166c349edda99674d96513b3f10aff13e5e` |
  | compile | 2 / PX | `1538 / 660f97017cfbf93fd805ceac8d2f0a32aaa5fe4d510bbf7d00d96aa1795d2ad8` | `2c07c78ecbb1d7315d040bd5f251df6e115805d9c57dcf73e1735ca598c97808` | `f6185a8b985f964e4befb06740509d581ee2173e4ef204cde557b9c7cb5fa163` |
  | inspect | 1 / P | `779 / 0e306c34ee6daf6b7c031d4f94b26db064e41836a22cfa022d24c3252e144ed4` | `f046343904baef900e5b5279edfe4b4b0b823489a76d4c772cb43f8fe2bf6489` | `8a3a35e24d043e63dec034f478051c5cae3784c838fac7cc05d4a5b64cdd1c57` |
  | inspect | 1 / F | `849 / ff6ef02cf81a1c0b04b1ff65c5258c73c3df390f13797468a7c41a7ed03b300d` | `f43dc2f2bbb805194e45dcf50947dd3d36fde9c7d4af3da897627b333e88c872` | `f91dd727681720968f654926d7056963c7e21055e53f3c5e9994aad5fd5cd7bd` |
  | inspect | 1 / X | `859 / b1a469e9c67b44b286cabcfa78d1d7d47fdf98a9580889b912221e0bdc03abfb` | `5f0939e61fb6b572e395fd18c936877f62f62fe11507195b36338bd09edfb54d` | `6e25aea57e357d374b4016e5fab61b9b639dda3ad851f5e458f7b349b52c7e27` |
  | inspect | 2 / PP | `1492 / 41210c875d75be710ef3974f31083c50b1a197131f70a25e7ae3282026cb47e1` | `21830a6728634ebfc130a3095fccdf463f388584fa2d48835b292bb3122ec00f` | `19da7f3fb33a901ad9d4595fb9e3c8c4268479321cb4bacf2dc16c85194633ed` |
  | inspect | 2 / PF | `1562 / 26bda588a97ad331232122b4efc00502f1ec6fc456373be581dabcb64a867e19` | `fb6fbf8f81ab217033a5cdaa87d5d33aac763912647f57aa64533d02c9f618de` | `61481a06e7c22b650ede1dbecc148fb379e1b2ae8daacc7a26b3173677ecf91e` |
  | inspect | 2 / PX | `1572 / 95e8fe238d044bd3da26b8b1573a1f9e117e4d529cbed356d6407e1c4f74108b` | `05e648cd2fa28862a6ca4aac9d423aa4262536571917bafa2cd5f24d2c3e924e` | `6026580853f11064c37617771fdfd791e1dfd4dc1aeea90486e5d938e4697bbf` |

  For example, the exact 1,528-byte compile/PF transcript is this JSON plus LF:

  ```json
  {"children":[{"argv":["emcc","-c","u0.c","-o","obj/0.o"],"child_ordinal":0,"diagnostic_sha256":null,"execution_completed":true,"exit_status":0,"fault_class":null,"input_sha256":"a3ce973ac8959c59913c1919fb4c2d42626d04f18837ef6bc3ea66237a562209","object_ordinal":0,"object_relpath":"obj/0.o","object_sha256":"9796d39e80e3864272c26fa9407f4add720ee56e4b640a88cdd9df05a16b5354","parser_version":"synthetic-compile-parser-v1","stage":"compile","stage_child_receipt_schema":1,"state":"passed","stderr_sha256":"489c910c843de67b128b684c849067771b91af854bab5e5599c34cf58a75b8bb","stderr_size":24,"stdout_sha256":"85e982a9556993ee56418312a4e626c3ba1e0fa5605d724c95fc593b7ddf67f7","stdout_size":24,"symbol":null,"terminal":false,"unit":"synthetic-u0"},{"argv":["emcc","-c","u1.c","-o","obj/1.o"],"child_ordinal":1,"diagnostic_sha256":"aa4913c93bd2fda45cb32a01e43406e1f3448f9cd09aa2f7143dcb2bbb1f7794","execution_completed":true,"exit_status":2,"fault_class":null,"input_sha256":"92a7e969bf98307740452ebf1e0209cea684ec1e6837ce498a5796efcb2937ef","object_ordinal":1,"object_relpath":"obj/1.o","object_sha256":null,"parser_version":"synthetic-compile-parser-v1","stage":"compile","stage_child_receipt_schema":1,"state":"failed","stderr_sha256":"3bb7b40b4308616b587f3a8f96278d884269a7aaba76c885ef7a8d28a6b17644","stderr_size":24,"stdout_sha256":"c742ef1c667bb7f941cd4e1f0e69fa883567258984f29de2ec26596e87670a11","stdout_size":24,"symbol":"bad_symbol","terminal":true,"unit":"synthetic-u1"}],"stage":"compile","stage_child_transcript_schema":1}
  ```

  Tests reconstruct all twelve byte streams and refuse an extra/missing child,
  duplicate/out-of-order ordinal/path, nonterminal stop, multiple terminals,
  child after terminal, prior non-pass, stage/argv/path/digest mismatch, raw
  size/digest mismatch, aggregate mismatch, or transcript mismatch.
- A symbol contributor records unit/object identity and digest, role
  (`definition` or `import`), and canonical ABI shape. A symbol-less
  diagnostic remains `unattributed` with the full object inventory. A
  completed but unparseable diagnostic or completed inspection lacking the
  required symbol/type data is deterministic
  `object-attribution-unavailable`; an inspector execution/I/O fault is the
  transient class defined below. `SymbolObservation.visibility` is exactly
  `default|hidden`; no other spelling is accepted. If any object needed for a
  symbol correlation has null/missing ABI evidence, the result is globally
  unattributed with **zero** contributors, never a partial contributor list.
  Neither case may fabricate contributors.

### 5. Composition retry identity and retained candidate

On any composition outcome, retain the owned promotion attempt and candidate.
`ToolWorldPreimage` is the exact closed object `{tool_world_schema: 1,
identities: list[exact {role:
'clang'|'emcc'|'node'|'object-inspector'|'smoke-script'|'wasm-ld',
resolved_path: absolute ordinary-file string, file_sha256: sha256,
version_sha256: sha256}], argv: exact {compile: list[list[string]], inspect:
list[list[string]], link: list[string], instantiate: list[string], smoke:
list[string]}, environment: list[exact {name: string, value_sha256: sha256}]}`.
Identities sort by role, environment by name, compile/inspect remain exact plan
order, and the other argv lists are semantic order. `tool_world_sha256` is the
SHA-256 of this canonical JSON plus LF. The result's `tool_world` is exactly the
preimage plus that digest; it has no assembly/candidate fields.

`AssemblyWorldPreimage` is the exact closed object `{assembly_world_schema: 1,
candidate: Candidate, window: list[WindowItem], relevant_owner_bindings:
list[exact {symbol: C identifier, owner_binding_sha256: sha256}],
compatibility_checks: list[CompatibilityEvidence],
abi_probe_evidence_sha256s: list[exact {symbol: C identifier,
abi_probe_evidence_sha256: sha256}], schema_versions: exact
{assembly_result_schema: 1, canonicalization_schema: 1,
compatibility_schema: 1, oracle_registry_schema: 1}, implementation: exact
{assembly_module_revision: nonempty string, driver_revision: nonempty string},
tool_world_sha256: sha256}`. The candidate/window use their reusable exact
shapes; the three evidence lists use their previously defined sort orders and
reject duplicate symbols/variants. `assembly_world_sha256` is the SHA-256 of
this canonical JSON plus LF. It is broad and never recomputed from `tool_world`
alone. Unknown/missing keys, wrong schema/types/order, implicit PATH names,
unrecorded environment, or a changed argv/ref/evidence/implementation refuses.
The compiler identity binds `emcc`, Clang and `wasm-ld`; inspector binds its
executable/parser; runtime binds Node; smoke binds exact script bytes.

Normative world vectors use canonical UTF-8 bytes exactly as shown plus one LF.
The 1,771-byte `ToolWorldPreimage` is:

```json
{"argv":{"compile":[["emcc","-c","candidate.c","-o","candidate.o"]],"inspect":[["llvm-nm","candidate.o"]],"instantiate":["node","instantiate.js","candidate.wasm"],"link":["emcc","candidate.o","-o","candidate.wasm"],"smoke":["node","smoke.js","candidate.wasm"]},"environment":[{"name":"EMSDK","value_sha256":"3131313131313131313131313131313131313131313131313131313131313131"}],"identities":[{"file_sha256":"1111111111111111111111111111111111111111111111111111111111111111","resolved_path":"D:/synthetic/clang.exe","role":"clang","version_sha256":"2121212121212121212121212121212121212121212121212121212121212121"},{"file_sha256":"1212121212121212121212121212121212121212121212121212121212121212","resolved_path":"D:/synthetic/emcc.bat","role":"emcc","version_sha256":"2222222222222222222222222222222222222222222222222222222222222222"},{"file_sha256":"1313131313131313131313131313131313131313131313131313131313131313","resolved_path":"D:/synthetic/node.exe","role":"node","version_sha256":"2323232323232323232323232323232323232323232323232323232323232323"},{"file_sha256":"1414141414141414141414141414141414141414141414141414141414141414","resolved_path":"D:/synthetic/llvm-nm.exe","role":"object-inspector","version_sha256":"2424242424242424242424242424242424242424242424242424242424242424"},{"file_sha256":"1515151515151515151515151515151515151515151515151515151515151515","resolved_path":"D:/synthetic/smoke.js","role":"smoke-script","version_sha256":"2525252525252525252525252525252525252525252525252525252525252525"},{"file_sha256":"1616161616161616161616161616161616161616161616161616161616161616","resolved_path":"D:/synthetic/wasm-ld.exe","role":"wasm-ld","version_sha256":"2626262626262626262626262626262626262626262626262626262626262626"}],"tool_world_schema":1}
```

Its digest is `1ce523c15a3d30aafba7e59d93848de812cb5225495175e3554fba3b8f89b5d7`.
The corresponding 776-byte `AssemblyWorldPreimage` is:

```json
{"abi_probe_evidence_sha256s":[],"assembly_world_schema":1,"candidate":{"artifact_relpath":"candidate/candidate.c","artifact_sha256":"4141414141414141414141414141414141414141414141414141414141414141","artifact_size":64,"header_sha256":"4343434343434343434343434343434343434343434343434343434343434343","source_sha256":"4242424242424242424242424242424242424242424242424242424242424242"},"compatibility_checks":[],"implementation":{"assembly_module_revision":"synthetic-module-v1","driver_revision":"synthetic-driver-v1"},"relevant_owner_bindings":[],"schema_versions":{"assembly_result_schema":1,"canonicalization_schema":1,"compatibility_schema":1,"oracle_registry_schema":1},"tool_world_sha256":"1ce523c15a3d30aafba7e59d93848de812cb5225495175e3554fba3b8f89b5d7","window":[]}
```

Its digest is `496bc357be857357f7377a63a012fc91491def0c3740460af6c7188792f130bc`.
Changing only Node `version_sha256` from repeated `23` to repeated `27` keeps
both payload lengths 1,771/776, changes the tool digest to
`f8731b73c66514bf126ec2880e4ff3e4fb487d3d8314332332d1c514a0b897bf`
and, after substituting only that digest, changes assembly to
`376296a0c2a54cfef787f7e9fabd5866aad97dcbbade954a87a306e3b93e27b6`.
Changing only candidate `artifact_sha256` from repeated `41` to repeated `44`
leaves tool digest `1ce523c1...b5d7` unchanged and changes only assembly to
`c4ccdfaeda65f828060bb2acb693c8dc16478d85ce45018dd77a7b7f3366e059`.
Tests reconstruct full bytes before hashes and refuse every unknown/missing/
wrong-type field or noncanonical collection order.

`StageTranscriptRef` is exact `{stage: 'compile'|'inspect',
child_transcript_sha256: sha256}`. It lists only nonnull child transcripts in
stage order. `AssemblyRetryFingerprintPreimage` is the exact closed object
`{assembly_retry_fingerprint_schema: 1, assembly_world_sha256: sha256,
classification: 'pass'|'deterministic_blocker'|'transient_fault', stage:
'owner'|'canonicalize'|'materialize'|'compile'|'inspect'|'link'|'instantiate'|
'smoke'|'revalidate'|'internal', code: nonempty string, evidence_sha256:
sha256|null, contributors: list[Contributor], unattributed: bool,
stage_transcripts: list[StageTranscriptRef]}`. Contributors and transcript refs
use their existing unique canonical orders. `evidence_sha256` is null only for
pass, the final normalized diagnostic digest for a deterministic blocker, and
the exact `transient_fault_fingerprint` for a transient fault.
`assembly_retry_fingerprint` is SHA-256 of canonical compact sorted-key UTF-8
JSON plus LF for that object. Unknown/missing keys, wrong enums/order, duplicate
contributors/transcripts, or an outcome/preimage mismatch refuses.

`TransientFaultFingerprintPreimage` is exact
`{transient_fault_fingerprint_schema: 1, assembly_world_sha256: sha256,
candidate_sha256: sha256, stage: 'owner'|'canonicalize'|'materialize'|'compile'|
'inspect'|'link'|'instantiate'|'smoke'|'revalidate'|'internal', code: nonempty
string, fault_class: 'spawn'|'timeout'|'crash'|'io'|'lock'|'stable_read',
tool_role: null|'emcc'|'object-inspector'|'node'}`.
`candidate_sha256` is exactly `scaffold.candidate.artifact_sha256`; source and
header digests remain separately bound through the assembly world and may not
substitute here. Tool role is a total finalizer-owned projection of the
attempted stage:

| stage | exact `tool_role` |
|---|---|
| `owner`, `canonicalize`, `materialize`, `revalidate`, `internal` | null |
| `compile` | `emcc` |
| `inspect` | `object-inspector` |
| `link` | `emcc` |
| `instantiate` | `node` |
| `smoke` | `node` |

The launched adapter owns the role: `wasm-ld` and `smoke-script` remain bound
tool-world identities but are never transient adapter roles. A link fault is
therefore `emcc`, not `wasm-ld`; a smoke fault is `node`, not `smoke-script`.
The gate reports typed attempted stage/fault evidence; the pure finalizer
derives this table and refuses any caller-supplied or observed crossed role.
It deliberately excludes raw diagnostic text,
clock, attempt/count/backoff and check/observation digests, so the same
normalized fault advances rather than resetting. Its canonical JSON plus LF
hash is `transient_fault_fingerprint`. Only relevant bindings enter the world:
unrelated owner records and the advisory registry do not. A full-registry
digest change alone does not reopen a blocker.

`RetryHistory` is exact `{history_schema: 1, prior_transient_fingerprint:
sha256|null, completed_transient_attempts: 0|1|2|3}`. Its canonical JSON plus
LF SHA-256 is `retry_history_sha256`; a positive count requires a nonnull prior
fingerprint. It comes only from the
driver's validated durable prior results. The driver owns storage and sleeping;
it cannot choose classification or hashes. The module validates history and,
for the same current transient fingerprint, maps prior count `0 ->
(1,30,'transient_retry')`, `1 -> (2,120,'transient_retry')`, `2 ->
(3,600,'transient_retry')`, and `3 ->
(3,null,'assembly_transient_exhausted')`. A different/null fingerprint resets
the effective prior count to zero. Malformed, future-schema, negative, or
count/fingerprint-inconsistent history refuses. Pass/deterministic outcomes
emit their fixed null/zero retry fields independent of stale transient history.

#### Normative retry fingerprint and history vectors

#### Pass assembly retry

```json
{"assembly_retry_fingerprint_schema":1,"assembly_world_sha256":"6161616161616161616161616161616161616161616161616161616161616161","classification":"pass","code":"pass","contributors":[],"evidence_sha256":null,"stage":"smoke","stage_transcripts":[{"child_transcript_sha256":"5597071754af9bbe42a2fa65fc43043c1c59cc2153d23e8940adaf0f86ecdc87","stage":"compile"},{"child_transcript_sha256":"67eb92399a94b59e58f244e30399c1f6ad1d88fb06af787a6b493fbd4c9fbf37","stage":"inspect"}],"unattributed":false}
```

Bytes/hash: `495 / b37031144deaa31b131447f2938b2293caec39f5e9f3dcca0617422b9ec93164`.

#### Tool non-pass assembly retry

```json
{"assembly_retry_fingerprint_schema":1,"assembly_world_sha256":"6161616161616161616161616161616161616161616161616161616161616161","classification":"deterministic_blocker","code":"link_failed","contributors":[],"evidence_sha256":"851f979c3701c10cee340cfa30875d5995909faee390513106fab27d26b8fdd6","stage":"link","stage_transcripts":[{"child_transcript_sha256":"5597071754af9bbe42a2fa65fc43043c1c59cc2153d23e8940adaf0f86ecdc87","stage":"compile"},{"child_transcript_sha256":"67eb92399a94b59e58f244e30399c1f6ad1d88fb06af787a6b493fbd4c9fbf37","stage":"inspect"}],"unattributed":true}
```

Bytes/hash: `579 / 6292936147b9211849c805a7bd6cc01f13bd006ff0f60ae69628992020417a9e`.

#### Deterministic pre-publication retry

```json
{"assembly_retry_fingerprint_schema":1,"assembly_world_sha256":"6161616161616161616161616161616161616161616161616161616161616161","classification":"deterministic_blocker","code":"owner_changed","contributors":[],"evidence_sha256":"636ec1a7f9396e105e53491352f30f91426bf6b3dfb079ea7688e407ba389aba","stage":"revalidate","stage_transcripts":[{"child_transcript_sha256":"5597071754af9bbe42a2fa65fc43043c1c59cc2153d23e8940adaf0f86ecdc87","stage":"compile"},{"child_transcript_sha256":"67eb92399a94b59e58f244e30399c1f6ad1d88fb06af787a6b493fbd4c9fbf37","stage":"inspect"}],"unattributed":true}
```

Bytes/hash: `587 / b898e560c2dacb3d5221649b1d64a7cb123a0e84c112e073988ffe72c7064846`.

#### Transient fault identity

```json
{"assembly_world_sha256":"6161616161616161616161616161616161616161616161616161616161616161","candidate_sha256":"4141414141414141414141414141414141414141414141414141414141414141","code":"stable_read_fault","fault_class":"stable_read","stage":"revalidate","tool_role":null,"transient_fault_fingerprint_schema":1}
```

Bytes/hash: `311 / 5200c61f3b31b5b0a561bfd616c9628c0a03430f4c0a0f82826c18a755457f2a`.

The following ambiguous-stage vectors use the same exact world and Candidate
artifact digest. They prove the total adapter-role projection:

#### compile transient adapter role

```json
{"assembly_world_sha256":"6161616161616161616161616161616161616161616161616161616161616161","candidate_sha256":"4141414141414141414141414141414141414141414141414141414141414141","code":"compile_timeout","fault_class":"timeout","stage":"compile","tool_role":"emcc","transient_fault_fingerprint_schema":1}
```

Bytes/hash: `304 / e160a4cdf08620333f62dbe127e89e7004b39401046340cc2e3f4a6dbcf66d1d`.

#### link transient adapter role

```json
{"assembly_world_sha256":"6161616161616161616161616161616161616161616161616161616161616161","candidate_sha256":"4141414141414141414141414141414141414141414141414141414141414141","code":"link_timeout","fault_class":"timeout","stage":"link","tool_role":"emcc","transient_fault_fingerprint_schema":1}
```

Bytes/hash: `298 / 4a1d5a6a7c2caf1847ed6e1bd1bf66058ec766c3f4a29e4ed6cce8672243374f`.

#### instantiate transient adapter role

```json
{"assembly_world_sha256":"6161616161616161616161616161616161616161616161616161616161616161","candidate_sha256":"4141414141414141414141414141414141414141414141414141414141414141","code":"instantiate_timeout","fault_class":"timeout","stage":"instantiate","tool_role":"node","transient_fault_fingerprint_schema":1}
```

Bytes/hash: `312 / b7ec8759bd43168f719ee347bda230df312b1b6b54453ac35eb9d3ded18590b4`.

#### smoke transient adapter role

```json
{"assembly_world_sha256":"6161616161616161616161616161616161616161616161616161616161616161","candidate_sha256":"4141414141414141414141414141414141414141414141414141414141414141","code":"smoke_timeout","fault_class":"timeout","stage":"smoke","tool_role":"node","transient_fault_fingerprint_schema":1}
```

Bytes/hash: `300 / 8c883f29210350f9773917ff34e33c2f07c9061effb297e6981d8137cb05fa2f`.

Crossed-role refusals cover every non-table pair, including compile/node,
inspect/emcc, link/wasm-ld, link/node, instantiate/emcc, smoke/smoke-script,
smoke/emcc, and every nonnull role on an early/revalidate/internal stage.
Substituting Candidate source/header digest for artifact digest also refuses.

#### Transient assembly retry

```json
{"assembly_retry_fingerprint_schema":1,"assembly_world_sha256":"6161616161616161616161616161616161616161616161616161616161616161","classification":"transient_fault","code":"stable_read_fault","contributors":[],"evidence_sha256":"5200c61f3b31b5b0a561bfd616c9628c0a03430f4c0a0f82826c18a755457f2a","stage":"revalidate","stage_transcripts":[{"child_transcript_sha256":"5597071754af9bbe42a2fa65fc43043c1c59cc2153d23e8940adaf0f86ecdc87","stage":"compile"},{"child_transcript_sha256":"67eb92399a94b59e58f244e30399c1f6ad1d88fb06af787a6b493fbd4c9fbf37","stage":"inspect"}],"unattributed":true}
```

Bytes/hash: `585 / 0d5e000eb991471ed939846165d13d0616275c86ca36df485d1bdd941b97c81c`.

The identical transient refusal advances only from durable history:

| prior history bytes / SHA-256 | emitted count / backoff / status | emitted result_id |
|---|---|---|
| `89 / 53baf513a523c322f7ddae9ac2645f8960908cc16e3e2ba808baf2754c52b7dd` | `1 / 30 / transient_retry` | `32f2f5c141bfbd75e387e70b9e0db776c0dcd93cea0f22797da34e799b816056` |
| `151 / afa81cd0efc31f94c70d0929836a412f0ebf7375b13f1f8b8c9348880f58351d` | `2 / 120 / transient_retry` | `c26d66010b1990a4d36ef00434c69434c946f9bfb9b5e5c70e8b31379419dd3f` |
| `151 / a851fbc456f8fc7bcd91ff2bf9c424addd5f4bbe6396dd5a311790e4268f7774` | `3 / 600 / transient_retry` | `1d8fd0422404bd67aa8e98ef213c5232e66e360d9543ba037ba906020b154170` |
| `151 / 785c9881b21e62cb0400fed221d1d1f19552ff46c457e6ea1d4a8afc1347c0ae` | `3 / null / assembly_transient_exhausted` | `e75ac59c25a4d1695cae5be22e20d3b2d273297ecaa333aa115f42b70b0d6897` |

The deterministic vector always emits `waiting_assembly_world_change`, count 0 and null transient/backoff fields for every valid history; its assembly retry fingerprint is `b898e560c2dacb3d5221649b1d64a7cb123a0e84c112e073988ffe72c7064846`. The transient fingerprint is `5200c61f3b31b5b0a561bfd616c9628c0a03430f4c0a0f82826c18a755457f2a`, and repeated transient assembly fingerprint remains `0d5e000eb991471ed939846165d13d0616275c86ca36df485d1bdd941b97c81c` across all four rows.

Changing only the compile transcript ref from
`5597071754af9bbe42a2fa65fc43043c1c59cc2153d23e8940adaf0f86ecdc87`
to repeated `aa` leaves the transient fault fingerprint unchanged, changes
the transient assembly preimage digest to
`5524da65b3fed9def49091168cdfbc3891e0a51b4f4c489c2b145429cd306111`,
and therefore changes the result ID. Tests reconstruct the literal preimages,
all history hashes/rows and this mutation. Exact changed-fingerprint history
`{"completed_transient_attempts":1,"history_schema":1,
"prior_transient_fingerprint":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}`
plus LF is 151 bytes / SHA-256
`628186e9735fcefb168eab2f5cd1b508c91b21cebc0c8d94a234d07a2b3ce4a8`;
it resets to count 1/backoff 30 and result ID
`32f2f5c141bfbd75e387e70b9e0db776c0dcd93cea0f22797da34e799b816056`,
while a same fingerprint advances.

Outcomes have two disjoint recovery classes:

- A **deterministic composition blocker** follows completed tool execution or
  a stable schema/owner/canonicalization/direct-definition/link/import/
  instantiate/smoke-structure refusal. The same retry fingerprint reports
  `waiting_assembly_world_change`. A changed candidate, window, relevant owner
  binding, implementation, argv/environment, tool identity, inspector parser,
  Node, or smoke script reruns canonicalization/compile/inspect/link/smoke from
  the retained candidate only.
- A **transient assembly fault** is limited to tool spawn/timeout/crash,
  sharing violation/file lock, stable-read race, temporary inspector I/O, or
  malformed/truncated tool output when execution did not complete. Its
  `transient_fault_fingerprint` hashes world, stage, tool identity, normalized
  OS/timeout class, and retained candidate. The same candidate gets at most
  three assembly-only retries after 30 seconds, 2 minutes, and 10 minutes.
  The counter resets only when that fault fingerprint or assembly world
  changes. Exhaustion records `assembly_transient_exhausted` and waits for an
  operator/world change; it is never reclassified as structural evidence.

Both classes remain `red_retryable`, `last_stage=assembly`, and
`failure_domain=pipeline-control`. `WasmUnitDriver._next_unit` routes the owned
retained candidate directly to this lane; no scheduler dispatch change is
needed. Neither class increments a source attempt, rematerializes candidate
source, calls compile-fix, targeted questions, diagnosis, or any LLM. A
journal-only recovery reuses the completed immutable result and transition ID,
performs no tool retry, and consumes no transient retry. These guarantees are
enforced by a driver state-machine branch that has no model/diagnosis
dependency.

### 6. Journal, promotion, and behavior tiers

Receipt stages are a closed matrix. `pre-compile` accepts only the plan's
`CanonicalizationReceipt` and requires empty object bindings because no tool
has run. `pre-publication` accepts only the draft's `CompositionReceipt` and
requires the exact ordinal/path/digest `ObjectObservation` set plus bound tool
world; a bare canonicalization receipt or empty/partial object bindings refuses
`composition_receipt_required`. The receipts are not interchangeable even when
their owner/catalog fields match.

Every revalidation attempt canonically hashes exact `{stage, receipt_sha256,
observation_sha256, passed, refusal_code}` as `check_sha256`; `refusal_code` is
null only on pass. `RevalidationCheck` is exactly those five fields plus
`check_sha256`. A successful `RevalidatedReceipt` contains a passing check; a
revalidation `AssemblyAbiRefusal` contains a non-passing check. Both bind the
same receipt/observation/stage fields.

`ResultScaffold` is the exact nine-key projection of the final 13-key result
excluding `result_id`, `outcome`, `revalidation`, and `retry`: it contains
`assembly_result_schema=1`, unit, attempt, candidate, window, behavior tier,
canonicalization, objects, and tool_world in their exact shapes below.
`OutcomeProjection` is the exact seven-key result `outcome` object defined below.
`CompositionDraft` is exact `{composition_draft_schema: 1, scaffold:
ResultScaffold, analyzed_outcome: OutcomeProjection, composition_receipt:
CompositionReceipt, retry_history_sha256: sha256}`. `FailureEvidence` is exact
`{stage: 'owner'|'canonicalize'|'materialize', classification:
'deterministic_blocker'|'transient_fault', code: nonempty string,
diagnostic_sha256: sha256, fault_class:
null|'spawn'|'timeout'|'crash'|'io'|'lock'|'stable_read'}`. Deterministic
requires null fault and transient requires nonnull fault.

`RevalidationFailure` is exact `{stage: 'revalidate', classification:
'deterministic_blocker'|'transient_fault', code: nonempty string,
diagnostic_sha256: sha256, check_sha256: sha256, fault_class:
null|'io'|'lock'|'stable_read'}`. Deterministic requires null fault; transient
requires a nonnull fault. Its code and check digest
must equal the attached failed `RevalidationCheck`; it is not a second source
of truth. All inputs carry a valid exact `tool_world` and `RetryHistory` even
when tools were not invoked; only the finalizer binds the final retry output.

`PrePublicationDecision` is a closed tagged union:

- `{status: 'not_reached', check: null, failure: null}`;
- `{status: 'passed', check: RevalidationCheck(passed=true), failure: null}`;
- `{status: 'refused', check: RevalidationCheck(passed=false), failure:
  RevalidationFailure}`.

The refused member requires identical `check_sha256` and refusal code in both
nested objects and a real nonnull diagnostic digest in the failure. No-check or
passing decisions require failure null. Unknown keys/statuses and every crossed
combination refuse before the result projection is hashed.
For `not_reached`, the finalizer retains the draft's non-pass outcome. For
`passed`, it requires the draft outcome to pass and retains it. For `refused`,
it requires the draft tool tuple to pass, replaces classification/code/
diagnostic from the `RevalidationFailure`, fixes stage to `revalidate`, retains
the complete stage-receipt tuple, and emits `contributors=[]` and
`unattributed=true`; no object is falsely blamed for a product re-read failure.

`FinalizationInput` is one closed tagged union; unknown keys are refused:

- `PreDraftFailureInput` = `{finalization_input_schema: 1, kind:
  'pre_draft_failure', scaffold: ResultScaffold, failure: FailureEvidence,
  retry_history: RetryHistory, pre_compile: null, pre_publication: null}`.
  Objects and all tool receipts are empty/not-run. Owner failure requires canonicalization `not_started`,
  canonicalize failure requires `failed`, and materialize failure requires
  `planned`; any other stage/status pair refuses.
- `PrecompileFailureInput` = `{finalization_input_schema: 1, kind:
  'precompile_refusal', scaffold: ResultScaffold, failure: RevalidationFailure,
  retry_history: RetryHistory, pre_compile:
  RevalidationCheck(passed=false), pre_publication: null}`. The refusal and
  check must have the same code/check digest and bind the scaffold's canonical
  receipt; canonicalization is `planned`, objects are empty, and every tool
  receipt is `not_run`.
- `PostAnalysisInput` = `{finalization_input_schema: 1, kind:
  'post_analysis', draft: CompositionDraft, pre_compile:
  RevalidationCheck(passed=true), pre_publication:
  PrePublicationDecision, retry_history: RetryHistory}`. Its history digest must
  equal `draft.retry_history_sha256`. A passed/refused check must bind the draft's
  `CompositionReceipt`/objects/tool world. Tool/analyze non-pass requires
  `not_reached`; a tool-pass requires exactly `passed|refused`.

The pure finalizer is the sole constructor of `outcome`, `revalidation`,
`retry`, and `result_id`. It checks all scaffold/draft/receipt/history
identities, derives the two exact retry fingerprints and count/status/backoff
from final outcome plus durable history, and returns the complete immutable
13-key `CompositionResult`. The canonical ID preimage is the complete result
projection with only `result_id` absent, canonical JSON plus LF;
`result_id=SHA256(preimage)`. The finalizer inserts it before returning and
self-recomputes it without mutation. The driver only validates the received
object and ID projection and atomically writes the final canonical bytes; it
never adds, removes, or changes a field.

The stage/receipt/null cross-product is exhaustive:

| failure/pass point | finalization kind | pre-compile | pre-publication | tool/analyze calls | result revalidation hashes |
|---|---|---|---|---|---|
| owner/canonicalize/materialize refusal | `pre_draft_failure` | null | null | zero | null / null |
| pre-compile refusal | `precompile_refusal` | failed real check | null | **zero** | check / null |
| compile/inspect/link/instantiate/smoke/analyze non-pass | `post_analysis` | passed check | `not_reached`, null failure | only through terminal stage | check / null |
| pre-publication refusal | `post_analysis` | passed check | `refused`, failed real check + matching failure | completed tuple | check / check |
| pass | `post_analysis` | passed check | `passed`, null failure | all five passed | check / check |

Every other combination refuses: in particular pre-draft with a check,
precompile-refusal without its real digest, post-analysis without precompile
success, pass without two checks, prepublication on a canonical receipt, or a
tool receipt after precompile refusal. Tests use compiler/inspector/link/Node/
analyze spies and assert exactly zero calls in the precompile-refusal vector.

#### Normative complete finalization vectors

Every JSON block below is canonical compact sorted-key UTF-8 plus its shown
final LF. Check hashes are SHA-256 of the exact five-key check projection
defined above; result IDs are SHA-256 of the complete result projection with
only `result_id` absent. These are full objects, not partial fixtures. Each
shown first-attempt input carries the exact empty history
`{"completed_transient_attempts":0,"history_schema":1,
"prior_transient_fingerprint":null}` plus LF, 89 bytes / SHA-256
`53baf513a523c322f7ddae9ac2645f8960908cc16e3e2ba808baf2754c52b7dd`;
post-analysis drafts carry that exact `retry_history_sha256`.

#### pass

Pre-compile check is `7d3739653926d62e6ec0a8769805916242ab20267dfb5e25c5010c567f5f74c6`. The exact pre-publication decision is:

```json
{"check":{"check_sha256":"82f64bf9d672102074e0172b663ffbe6c9dafa33c3ba56ca1a8b3742581d0dbb","observation_sha256":"1872befdd387ff1422631d080eca9ead263db313a88d0c0dae71b4dfba21eab4","passed":true,"receipt_sha256":"c9b5d457928ea8cc69fb3f4f53b6d51ca0b02893fa63020f0ece097c53f38d9f","refusal_code":null,"stage":"pre-publication"},"failure":null,"status":"passed"}
```

The ID preimage is 8,009 bytes; `result_id` is `07a540545f0b0db883e906d7e6c456352789bc2fbfc5d9a18005af54fb04ced9`. The complete 8,088-byte result is:

```json
{"assembly_result_schema":1,"attempt":1,"behavior_tier":"compile_only","candidate":{"artifact_relpath":"candidate.c","artifact_sha256":"4141414141414141414141414141414141414141414141414141414141414141","artifact_size":64,"header_sha256":"4343434343434343434343434343434343434343434343434343434343434343","source_sha256":"4242424242424242424242424242424242424242424242424242424242424242"},"canonicalization":{"bundle_sha256":"5151515151515151515151515151515151515151515151515151515151515151","canonicalization_schema":1,"compatibility_checks":[],"discarded_variants":[],"owner_bindings":[],"relevant_catalog_sha256":"5252525252525252525252525252525252525252525252525252525252525252","status":"planned","translation_units":[{"compile_argv_sha256":"e42d3646adf2a7bd60ceb87af84ae391a2e8723006a9eb940a36d3995effa0d1","derived_source_sha256":"a3ce973ac8959c59913c1919fb4c2d42626d04f18837ef6bc3ea66237a562209","object_relpath":"candidate.o","ordinal":0,"role":"candidate","source_sha256":"4242424242424242424242424242424242424242424242424242424242424242","unit":"synthetic-u"}]},"objects":[{"defined_symbols":[],"imported_symbols":[],"inspector_receipt_sha256":"87d84ca58cbd08b5cb4659c52fabcc87000e0eb6ea9a49b4673ae4e9e84ee702","object_relpath":"candidate.o","object_sha256":"9796d39e80e3864272c26fa9407f4add720ee56e4b640a88cdd9df05a16b5354","object_size":32,"ordinal":0,"unit":"synthetic-u"}],"outcome":{"classification":"pass","code":"pass","contributors":[],"diagnostic_sha256":null,"stage":"smoke","stage_receipts":[{"child_receipts":[{"argv":["emcc","-c","candidate.c","-o","candidate.o"],"child_ordinal":0,"diagnostic_sha256":null,"execution_completed":true,"exit_status":0,"fault_class":null,"input_sha256":"a3ce973ac8959c59913c1919fb4c2d42626d04f18837ef6bc3ea66237a562209","object_ordinal":0,"object_relpath":"candidate.o","object_sha256":"9796d39e80e3864272c26fa9407f4add720ee56e4b640a88cdd9df05a16b5354","parser_version":"synthetic-compile-parser-v1","stage":"compile","stage_child_receipt_schema":1,"state":"passed","stderr_sha256":"489c910c843de67b128b684c849067771b91af854bab5e5599c34cf58a75b8bb","stderr_size":24,"stdout_sha256":"85e982a9556993ee56418312a4e626c3ba1e0fa5605d724c95fc593b7ddf67f7","stdout_size":24,"symbol":null,"terminal":true,"unit":"synthetic-u"}],"child_transcript_sha256":"5597071754af9bbe42a2fa65fc43043c1c59cc2153d23e8940adaf0f86ecdc87","diagnostic_sha256":null,"execution_completed":true,"exit_status":0,"fault_class":null,"named_object_relpaths":["candidate.o"],"parser_version":"synthetic-compile-parser-v1","stage":"compile","stage_receipt_schema":1,"state":"passed","stderr_sha256":"b116c438f4bcea2ac63b2ebfddaa247a3e1d72eeb3564ffc5262a9072c82d970","stdout_sha256":"d33a223670cffdc68f5f51af4d3b821abe3fa1fa703a485b7b7a5959c35ac27f","symbol":null},{"child_receipts":[{"argv":["llvm-nm","candidate.o"],"child_ordinal":0,"diagnostic_sha256":null,"execution_completed":true,"exit_status":0,"fault_class":null,"input_sha256":"9796d39e80e3864272c26fa9407f4add720ee56e4b640a88cdd9df05a16b5354","object_ordinal":0,"object_relpath":"candidate.o","object_sha256":"9796d39e80e3864272c26fa9407f4add720ee56e4b640a88cdd9df05a16b5354","parser_version":"synthetic-inspect-parser-v1","stage":"inspect","stage_child_receipt_schema":1,"state":"passed","stderr_sha256":"0e998d65f40fdc0f1ec0aff8bd5b5bd661ab9cf9973d359b228f484acd5f1ed9","stderr_size":24,"stdout_sha256":"d7dc7b2e512ea4543cecbe07911be308568a139ad1a8a14dd4d46f4690d6636a","stdout_size":24,"symbol":null,"terminal":true,"unit":"synthetic-u"}],"child_transcript_sha256":"67eb92399a94b59e58f244e30399c1f6ad1d88fb06af787a6b493fbd4c9fbf37","diagnostic_sha256":null,"execution_completed":true,"exit_status":0,"fault_class":null,"named_object_relpaths":["candidate.o"],"parser_version":"synthetic-inspect-parser-v1","stage":"inspect","stage_receipt_schema":1,"state":"passed","stderr_sha256":"8a3a35e24d043e63dec034f478051c5cae3784c838fac7cc05d4a5b64cdd1c57","stdout_sha256":"f046343904baef900e5b5279edfe4b4b0b823489a76d4c772cb43f8fe2bf6489","symbol":null},{"child_receipts":[],"child_transcript_sha256":null,"diagnostic_sha256":null,"execution_completed":true,"exit_status":0,"fault_class":null,"named_object_relpaths":["candidate.o"],"parser_version":"synthetic-link-parser-v1","stage":"link","stage_receipt_schema":1,"state":"passed","stderr_sha256":"117a72cb8592f535a1a7fe408c2c7fda6673bb4afdbe6ad8867b824ab788b6b3","stdout_sha256":"115fb89eab424714138920cb65144b8bce9f9ad060d6345fb741d1e4f21904ae","symbol":null},{"child_receipts":[],"child_transcript_sha256":null,"diagnostic_sha256":null,"execution_completed":true,"exit_status":0,"fault_class":null,"named_object_relpaths":[],"parser_version":"synthetic-instantiate-parser-v1","stage":"instantiate","stage_receipt_schema":1,"state":"passed","stderr_sha256":"5c6c1d8ec39ae71fff8e948678da80cf26e48b4705297615b4459e54468d9fed","stdout_sha256":"dd20395fa27c5d9008f6168ed34a81e06f128b1424c572d76fa91fc8bd4225b8","symbol":null},{"child_receipts":[],"child_transcript_sha256":null,"diagnostic_sha256":null,"execution_completed":true,"exit_status":0,"fault_class":null,"named_object_relpaths":[],"parser_version":"synthetic-smoke-parser-v1","stage":"smoke","stage_receipt_schema":1,"state":"passed","stderr_sha256":"f61850da616a9f5b3100d9da1f9dfe1ab446d04432bbf58d57cd2d2a91daf07b","stdout_sha256":"a1a73ff7b5098c9ec2309ae2fb03e881065dc6142fc235c57afba975d202ad14","symbol":null}],"unattributed":false},"result_id":"07a540545f0b0db883e906d7e6c456352789bc2fbfc5d9a18005af54fb04ced9","retry":{"assembly_retry_fingerprint":"b37031144deaa31b131447f2938b2293caec39f5e9f3dcca0617422b9ec93164","assembly_world_sha256":"6161616161616161616161616161616161616161616161616161616161616161","backoff_seconds":null,"class":"none","status":"pass","transient_fault_fingerprint":null,"transient_retry_count":0},"revalidation":{"pre_compile_sha256":"7d3739653926d62e6ec0a8769805916242ab20267dfb5e25c5010c567f5f74c6","pre_publication_sha256":"82f64bf9d672102074e0172b663ffbe6c9dafa33c3ba56ca1a8b3742581d0dbb"},"tool_world":{"argv":{"compile":[["emcc","-c","candidate.c","-o","candidate.o"]],"inspect":[["llvm-nm","candidate.o"]],"instantiate":["node","instantiate.js","candidate.wasm"],"link":["emcc","candidate.o","-o","candidate.wasm"],"smoke":["node","smoke.js","candidate.wasm"]},"environment":[{"name":"EMSDK","value_sha256":"3131313131313131313131313131313131313131313131313131313131313131"}],"identities":[{"file_sha256":"1111111111111111111111111111111111111111111111111111111111111111","resolved_path":"D:/synthetic/clang.exe","role":"clang","version_sha256":"2121212121212121212121212121212121212121212121212121212121212121"},{"file_sha256":"1212121212121212121212121212121212121212121212121212121212121212","resolved_path":"D:/synthetic/emcc.bat","role":"emcc","version_sha256":"2222222222222222222222222222222222222222222222222222222222222222"},{"file_sha256":"1313131313131313131313131313131313131313131313131313131313131313","resolved_path":"D:/synthetic/node.exe","role":"node","version_sha256":"2323232323232323232323232323232323232323232323232323232323232323"},{"file_sha256":"1414141414141414141414141414141414141414141414141414141414141414","resolved_path":"D:/synthetic/llvm-nm.exe","role":"object-inspector","version_sha256":"2424242424242424242424242424242424242424242424242424242424242424"},{"file_sha256":"1515151515151515151515151515151515151515151515151515151515151515","resolved_path":"D:/synthetic/smoke.js","role":"smoke-script","version_sha256":"2525252525252525252525252525252525252525252525252525252525252525"},{"file_sha256":"1616161616161616161616161616161616161616161616161616161616161616","resolved_path":"D:/synthetic/wasm-ld.exe","role":"wasm-ld","version_sha256":"2626262626262626262626262626262626262626262626262626262626262626"}],"tool_world_schema":1,"tool_world_sha256":"1ce523c15a3d30aafba7e59d93848de812cb5225495175e3554fba3b8f89b5d7"},"unit":"synthetic-u","window":[{"artifact_relpath":"candidate.c","artifact_sha256":"4141414141414141414141414141414141414141414141414141414141414141","artifact_size":64,"ordinal":0,"unit":"synthetic-u"}]}
```

#### tool non-pass

Pre-compile check is `7d3739653926d62e6ec0a8769805916242ab20267dfb5e25c5010c567f5f74c6`. The exact pre-publication decision is:

```json
{"check":null,"failure":null,"status":"not_reached"}
```

The ID preimage is 7,853 bytes; `result_id` is `2cba2aa68db75c0d464ab8e89a3e6c44104bd79bd1ab7e40190e643e30b0e389`. The complete 7,932-byte result is:

```json
{"assembly_result_schema":1,"attempt":1,"behavior_tier":"compile_only","candidate":{"artifact_relpath":"candidate.c","artifact_sha256":"4141414141414141414141414141414141414141414141414141414141414141","artifact_size":64,"header_sha256":"4343434343434343434343434343434343434343434343434343434343434343","source_sha256":"4242424242424242424242424242424242424242424242424242424242424242"},"canonicalization":{"bundle_sha256":"5151515151515151515151515151515151515151515151515151515151515151","canonicalization_schema":1,"compatibility_checks":[],"discarded_variants":[],"owner_bindings":[],"relevant_catalog_sha256":"5252525252525252525252525252525252525252525252525252525252525252","status":"planned","translation_units":[{"compile_argv_sha256":"e42d3646adf2a7bd60ceb87af84ae391a2e8723006a9eb940a36d3995effa0d1","derived_source_sha256":"a3ce973ac8959c59913c1919fb4c2d42626d04f18837ef6bc3ea66237a562209","object_relpath":"candidate.o","ordinal":0,"role":"candidate","source_sha256":"4242424242424242424242424242424242424242424242424242424242424242","unit":"synthetic-u"}]},"objects":[{"defined_symbols":[],"imported_symbols":[],"inspector_receipt_sha256":"87d84ca58cbd08b5cb4659c52fabcc87000e0eb6ea9a49b4673ae4e9e84ee702","object_relpath":"candidate.o","object_sha256":"9796d39e80e3864272c26fa9407f4add720ee56e4b640a88cdd9df05a16b5354","object_size":32,"ordinal":0,"unit":"synthetic-u"}],"outcome":{"classification":"deterministic_blocker","code":"link_failed","contributors":[],"diagnostic_sha256":"851f979c3701c10cee340cfa30875d5995909faee390513106fab27d26b8fdd6","stage":"link","stage_receipts":[{"child_receipts":[{"argv":["emcc","-c","candidate.c","-o","candidate.o"],"child_ordinal":0,"diagnostic_sha256":null,"execution_completed":true,"exit_status":0,"fault_class":null,"input_sha256":"a3ce973ac8959c59913c1919fb4c2d42626d04f18837ef6bc3ea66237a562209","object_ordinal":0,"object_relpath":"candidate.o","object_sha256":"9796d39e80e3864272c26fa9407f4add720ee56e4b640a88cdd9df05a16b5354","parser_version":"synthetic-compile-parser-v1","stage":"compile","stage_child_receipt_schema":1,"state":"passed","stderr_sha256":"489c910c843de67b128b684c849067771b91af854bab5e5599c34cf58a75b8bb","stderr_size":24,"stdout_sha256":"85e982a9556993ee56418312a4e626c3ba1e0fa5605d724c95fc593b7ddf67f7","stdout_size":24,"symbol":null,"terminal":true,"unit":"synthetic-u"}],"child_transcript_sha256":"5597071754af9bbe42a2fa65fc43043c1c59cc2153d23e8940adaf0f86ecdc87","diagnostic_sha256":null,"execution_completed":true,"exit_status":0,"fault_class":null,"named_object_relpaths":["candidate.o"],"parser_version":"synthetic-compile-parser-v1","stage":"compile","stage_receipt_schema":1,"state":"passed","stderr_sha256":"b116c438f4bcea2ac63b2ebfddaa247a3e1d72eeb3564ffc5262a9072c82d970","stdout_sha256":"d33a223670cffdc68f5f51af4d3b821abe3fa1fa703a485b7b7a5959c35ac27f","symbol":null},{"child_receipts":[{"argv":["llvm-nm","candidate.o"],"child_ordinal":0,"diagnostic_sha256":null,"execution_completed":true,"exit_status":0,"fault_class":null,"input_sha256":"9796d39e80e3864272c26fa9407f4add720ee56e4b640a88cdd9df05a16b5354","object_ordinal":0,"object_relpath":"candidate.o","object_sha256":"9796d39e80e3864272c26fa9407f4add720ee56e4b640a88cdd9df05a16b5354","parser_version":"synthetic-inspect-parser-v1","stage":"inspect","stage_child_receipt_schema":1,"state":"passed","stderr_sha256":"0e998d65f40fdc0f1ec0aff8bd5b5bd661ab9cf9973d359b228f484acd5f1ed9","stderr_size":24,"stdout_sha256":"d7dc7b2e512ea4543cecbe07911be308568a139ad1a8a14dd4d46f4690d6636a","stdout_size":24,"symbol":null,"terminal":true,"unit":"synthetic-u"}],"child_transcript_sha256":"67eb92399a94b59e58f244e30399c1f6ad1d88fb06af787a6b493fbd4c9fbf37","diagnostic_sha256":null,"execution_completed":true,"exit_status":0,"fault_class":null,"named_object_relpaths":["candidate.o"],"parser_version":"synthetic-inspect-parser-v1","stage":"inspect","stage_receipt_schema":1,"state":"passed","stderr_sha256":"8a3a35e24d043e63dec034f478051c5cae3784c838fac7cc05d4a5b64cdd1c57","stdout_sha256":"f046343904baef900e5b5279edfe4b4b0b823489a76d4c772cb43f8fe2bf6489","symbol":null},{"child_receipts":[],"child_transcript_sha256":null,"diagnostic_sha256":"851f979c3701c10cee340cfa30875d5995909faee390513106fab27d26b8fdd6","execution_completed":true,"exit_status":2,"fault_class":null,"named_object_relpaths":["candidate.o"],"parser_version":"synthetic-link-parser-v1","stage":"link","stage_receipt_schema":1,"state":"failed","stderr_sha256":"117a72cb8592f535a1a7fe408c2c7fda6673bb4afdbe6ad8867b824ab788b6b3","stdout_sha256":"115fb89eab424714138920cb65144b8bce9f9ad060d6345fb741d1e4f21904ae","symbol":"bad_symbol"},{"child_receipts":[],"child_transcript_sha256":null,"diagnostic_sha256":null,"execution_completed":false,"exit_status":null,"fault_class":null,"named_object_relpaths":[],"parser_version":null,"stage":"instantiate","stage_receipt_schema":1,"state":"not_run","stderr_sha256":null,"stdout_sha256":null,"symbol":null},{"child_receipts":[],"child_transcript_sha256":null,"diagnostic_sha256":null,"execution_completed":false,"exit_status":null,"fault_class":null,"named_object_relpaths":[],"parser_version":null,"stage":"smoke","stage_receipt_schema":1,"state":"not_run","stderr_sha256":null,"stdout_sha256":null,"symbol":null}],"unattributed":true},"result_id":"2cba2aa68db75c0d464ab8e89a3e6c44104bd79bd1ab7e40190e643e30b0e389","retry":{"assembly_retry_fingerprint":"6292936147b9211849c805a7bd6cc01f13bd006ff0f60ae69628992020417a9e","assembly_world_sha256":"6161616161616161616161616161616161616161616161616161616161616161","backoff_seconds":null,"class":"deterministic_blocker","status":"waiting_assembly_world_change","transient_fault_fingerprint":null,"transient_retry_count":0},"revalidation":{"pre_compile_sha256":"7d3739653926d62e6ec0a8769805916242ab20267dfb5e25c5010c567f5f74c6","pre_publication_sha256":null},"tool_world":{"argv":{"compile":[["emcc","-c","candidate.c","-o","candidate.o"]],"inspect":[["llvm-nm","candidate.o"]],"instantiate":["node","instantiate.js","candidate.wasm"],"link":["emcc","candidate.o","-o","candidate.wasm"],"smoke":["node","smoke.js","candidate.wasm"]},"environment":[{"name":"EMSDK","value_sha256":"3131313131313131313131313131313131313131313131313131313131313131"}],"identities":[{"file_sha256":"1111111111111111111111111111111111111111111111111111111111111111","resolved_path":"D:/synthetic/clang.exe","role":"clang","version_sha256":"2121212121212121212121212121212121212121212121212121212121212121"},{"file_sha256":"1212121212121212121212121212121212121212121212121212121212121212","resolved_path":"D:/synthetic/emcc.bat","role":"emcc","version_sha256":"2222222222222222222222222222222222222222222222222222222222222222"},{"file_sha256":"1313131313131313131313131313131313131313131313131313131313131313","resolved_path":"D:/synthetic/node.exe","role":"node","version_sha256":"2323232323232323232323232323232323232323232323232323232323232323"},{"file_sha256":"1414141414141414141414141414141414141414141414141414141414141414","resolved_path":"D:/synthetic/llvm-nm.exe","role":"object-inspector","version_sha256":"2424242424242424242424242424242424242424242424242424242424242424"},{"file_sha256":"1515151515151515151515151515151515151515151515151515151515151515","resolved_path":"D:/synthetic/smoke.js","role":"smoke-script","version_sha256":"2525252525252525252525252525252525252525252525252525252525252525"},{"file_sha256":"1616161616161616161616161616161616161616161616161616161616161616","resolved_path":"D:/synthetic/wasm-ld.exe","role":"wasm-ld","version_sha256":"2626262626262626262626262626262626262626262626262626262626262626"}],"tool_world_schema":1,"tool_world_sha256":"1ce523c15a3d30aafba7e59d93848de812cb5225495175e3554fba3b8f89b5d7"},"unit":"synthetic-u","window":[{"artifact_relpath":"candidate.c","artifact_sha256":"4141414141414141414141414141414141414141414141414141414141414141","artifact_size":64,"ordinal":0,"unit":"synthetic-u"}]}
```

#### deterministic pre-publication refusal

Pre-compile check is `7d3739653926d62e6ec0a8769805916242ab20267dfb5e25c5010c567f5f74c6`. The exact pre-publication decision is:

```json
{"check":{"check_sha256":"f8b21bd18b69f8448af010ed6cc99ba91bcc04746fc787ebdfd0388f9af16dd7","observation_sha256":"a234dbcf40eea7b08f11e0bee5c0dd9618643c6aafcb24bf4475985015a30325","passed":false,"receipt_sha256":"c9b5d457928ea8cc69fb3f4f53b6d51ca0b02893fa63020f0ece097c53f38d9f","refusal_code":"owner_changed","stage":"pre-publication"},"failure":{"check_sha256":"f8b21bd18b69f8448af010ed6cc99ba91bcc04746fc787ebdfd0388f9af16dd7","classification":"deterministic_blocker","code":"owner_changed","diagnostic_sha256":"636ec1a7f9396e105e53491352f30f91426bf6b3dfb079ea7688e407ba389aba","fault_class":null,"stage":"revalidate"},"status":"refused"}
```

The ID preimage is 8,143 bytes; `result_id` is `f8a525c79497bbe197d0eca0a5bfff93168ac40dc26b6106a230063a72d6154f`. The complete 8,222-byte result is:

```json
{"assembly_result_schema":1,"attempt":1,"behavior_tier":"compile_only","candidate":{"artifact_relpath":"candidate.c","artifact_sha256":"4141414141414141414141414141414141414141414141414141414141414141","artifact_size":64,"header_sha256":"4343434343434343434343434343434343434343434343434343434343434343","source_sha256":"4242424242424242424242424242424242424242424242424242424242424242"},"canonicalization":{"bundle_sha256":"5151515151515151515151515151515151515151515151515151515151515151","canonicalization_schema":1,"compatibility_checks":[],"discarded_variants":[],"owner_bindings":[],"relevant_catalog_sha256":"5252525252525252525252525252525252525252525252525252525252525252","status":"planned","translation_units":[{"compile_argv_sha256":"e42d3646adf2a7bd60ceb87af84ae391a2e8723006a9eb940a36d3995effa0d1","derived_source_sha256":"a3ce973ac8959c59913c1919fb4c2d42626d04f18837ef6bc3ea66237a562209","object_relpath":"candidate.o","ordinal":0,"role":"candidate","source_sha256":"4242424242424242424242424242424242424242424242424242424242424242","unit":"synthetic-u"}]},"objects":[{"defined_symbols":[],"imported_symbols":[],"inspector_receipt_sha256":"87d84ca58cbd08b5cb4659c52fabcc87000e0eb6ea9a49b4673ae4e9e84ee702","object_relpath":"candidate.o","object_sha256":"9796d39e80e3864272c26fa9407f4add720ee56e4b640a88cdd9df05a16b5354","object_size":32,"ordinal":0,"unit":"synthetic-u"}],"outcome":{"classification":"deterministic_blocker","code":"owner_changed","contributors":[],"diagnostic_sha256":"636ec1a7f9396e105e53491352f30f91426bf6b3dfb079ea7688e407ba389aba","stage":"revalidate","stage_receipts":[{"child_receipts":[{"argv":["emcc","-c","candidate.c","-o","candidate.o"],"child_ordinal":0,"diagnostic_sha256":null,"execution_completed":true,"exit_status":0,"fault_class":null,"input_sha256":"a3ce973ac8959c59913c1919fb4c2d42626d04f18837ef6bc3ea66237a562209","object_ordinal":0,"object_relpath":"candidate.o","object_sha256":"9796d39e80e3864272c26fa9407f4add720ee56e4b640a88cdd9df05a16b5354","parser_version":"synthetic-compile-parser-v1","stage":"compile","stage_child_receipt_schema":1,"state":"passed","stderr_sha256":"489c910c843de67b128b684c849067771b91af854bab5e5599c34cf58a75b8bb","stderr_size":24,"stdout_sha256":"85e982a9556993ee56418312a4e626c3ba1e0fa5605d724c95fc593b7ddf67f7","stdout_size":24,"symbol":null,"terminal":true,"unit":"synthetic-u"}],"child_transcript_sha256":"5597071754af9bbe42a2fa65fc43043c1c59cc2153d23e8940adaf0f86ecdc87","diagnostic_sha256":null,"execution_completed":true,"exit_status":0,"fault_class":null,"named_object_relpaths":["candidate.o"],"parser_version":"synthetic-compile-parser-v1","stage":"compile","stage_receipt_schema":1,"state":"passed","stderr_sha256":"b116c438f4bcea2ac63b2ebfddaa247a3e1d72eeb3564ffc5262a9072c82d970","stdout_sha256":"d33a223670cffdc68f5f51af4d3b821abe3fa1fa703a485b7b7a5959c35ac27f","symbol":null},{"child_receipts":[{"argv":["llvm-nm","candidate.o"],"child_ordinal":0,"diagnostic_sha256":null,"execution_completed":true,"exit_status":0,"fault_class":null,"input_sha256":"9796d39e80e3864272c26fa9407f4add720ee56e4b640a88cdd9df05a16b5354","object_ordinal":0,"object_relpath":"candidate.o","object_sha256":"9796d39e80e3864272c26fa9407f4add720ee56e4b640a88cdd9df05a16b5354","parser_version":"synthetic-inspect-parser-v1","stage":"inspect","stage_child_receipt_schema":1,"state":"passed","stderr_sha256":"0e998d65f40fdc0f1ec0aff8bd5b5bd661ab9cf9973d359b228f484acd5f1ed9","stderr_size":24,"stdout_sha256":"d7dc7b2e512ea4543cecbe07911be308568a139ad1a8a14dd4d46f4690d6636a","stdout_size":24,"symbol":null,"terminal":true,"unit":"synthetic-u"}],"child_transcript_sha256":"67eb92399a94b59e58f244e30399c1f6ad1d88fb06af787a6b493fbd4c9fbf37","diagnostic_sha256":null,"execution_completed":true,"exit_status":0,"fault_class":null,"named_object_relpaths":["candidate.o"],"parser_version":"synthetic-inspect-parser-v1","stage":"inspect","stage_receipt_schema":1,"state":"passed","stderr_sha256":"8a3a35e24d043e63dec034f478051c5cae3784c838fac7cc05d4a5b64cdd1c57","stdout_sha256":"f046343904baef900e5b5279edfe4b4b0b823489a76d4c772cb43f8fe2bf6489","symbol":null},{"child_receipts":[],"child_transcript_sha256":null,"diagnostic_sha256":null,"execution_completed":true,"exit_status":0,"fault_class":null,"named_object_relpaths":["candidate.o"],"parser_version":"synthetic-link-parser-v1","stage":"link","stage_receipt_schema":1,"state":"passed","stderr_sha256":"117a72cb8592f535a1a7fe408c2c7fda6673bb4afdbe6ad8867b824ab788b6b3","stdout_sha256":"115fb89eab424714138920cb65144b8bce9f9ad060d6345fb741d1e4f21904ae","symbol":null},{"child_receipts":[],"child_transcript_sha256":null,"diagnostic_sha256":null,"execution_completed":true,"exit_status":0,"fault_class":null,"named_object_relpaths":[],"parser_version":"synthetic-instantiate-parser-v1","stage":"instantiate","stage_receipt_schema":1,"state":"passed","stderr_sha256":"5c6c1d8ec39ae71fff8e948678da80cf26e48b4705297615b4459e54468d9fed","stdout_sha256":"dd20395fa27c5d9008f6168ed34a81e06f128b1424c572d76fa91fc8bd4225b8","symbol":null},{"child_receipts":[],"child_transcript_sha256":null,"diagnostic_sha256":null,"execution_completed":true,"exit_status":0,"fault_class":null,"named_object_relpaths":[],"parser_version":"synthetic-smoke-parser-v1","stage":"smoke","stage_receipt_schema":1,"state":"passed","stderr_sha256":"f61850da616a9f5b3100d9da1f9dfe1ab446d04432bbf58d57cd2d2a91daf07b","stdout_sha256":"a1a73ff7b5098c9ec2309ae2fb03e881065dc6142fc235c57afba975d202ad14","symbol":null}],"unattributed":true},"result_id":"f8a525c79497bbe197d0eca0a5bfff93168ac40dc26b6106a230063a72d6154f","retry":{"assembly_retry_fingerprint":"b898e560c2dacb3d5221649b1d64a7cb123a0e84c112e073988ffe72c7064846","assembly_world_sha256":"6161616161616161616161616161616161616161616161616161616161616161","backoff_seconds":null,"class":"deterministic_blocker","status":"waiting_assembly_world_change","transient_fault_fingerprint":null,"transient_retry_count":0},"revalidation":{"pre_compile_sha256":"7d3739653926d62e6ec0a8769805916242ab20267dfb5e25c5010c567f5f74c6","pre_publication_sha256":"f8b21bd18b69f8448af010ed6cc99ba91bcc04746fc787ebdfd0388f9af16dd7"},"tool_world":{"argv":{"compile":[["emcc","-c","candidate.c","-o","candidate.o"]],"inspect":[["llvm-nm","candidate.o"]],"instantiate":["node","instantiate.js","candidate.wasm"],"link":["emcc","candidate.o","-o","candidate.wasm"],"smoke":["node","smoke.js","candidate.wasm"]},"environment":[{"name":"EMSDK","value_sha256":"3131313131313131313131313131313131313131313131313131313131313131"}],"identities":[{"file_sha256":"1111111111111111111111111111111111111111111111111111111111111111","resolved_path":"D:/synthetic/clang.exe","role":"clang","version_sha256":"2121212121212121212121212121212121212121212121212121212121212121"},{"file_sha256":"1212121212121212121212121212121212121212121212121212121212121212","resolved_path":"D:/synthetic/emcc.bat","role":"emcc","version_sha256":"2222222222222222222222222222222222222222222222222222222222222222"},{"file_sha256":"1313131313131313131313131313131313131313131313131313131313131313","resolved_path":"D:/synthetic/node.exe","role":"node","version_sha256":"2323232323232323232323232323232323232323232323232323232323232323"},{"file_sha256":"1414141414141414141414141414141414141414141414141414141414141414","resolved_path":"D:/synthetic/llvm-nm.exe","role":"object-inspector","version_sha256":"2424242424242424242424242424242424242424242424242424242424242424"},{"file_sha256":"1515151515151515151515151515151515151515151515151515151515151515","resolved_path":"D:/synthetic/smoke.js","role":"smoke-script","version_sha256":"2525252525252525252525252525252525252525252525252525252525252525"},{"file_sha256":"1616161616161616161616161616161616161616161616161616161616161616","resolved_path":"D:/synthetic/wasm-ld.exe","role":"wasm-ld","version_sha256":"2626262626262626262626262626262626262626262626262626262626262626"}],"tool_world_schema":1,"tool_world_sha256":"1ce523c15a3d30aafba7e59d93848de812cb5225495175e3554fba3b8f89b5d7"},"unit":"synthetic-u","window":[{"artifact_relpath":"candidate.c","artifact_sha256":"4141414141414141414141414141414141414141414141414141414141414141","artifact_size":64,"ordinal":0,"unit":"synthetic-u"}]}
```

#### transient pre-publication refusal

Pre-compile check is `7d3739653926d62e6ec0a8769805916242ab20267dfb5e25c5010c567f5f74c6`. The exact pre-publication decision is:

```json
{"check":{"check_sha256":"ed9398df334b1699708362bf2541c8542cad8f10528cd9fe7adcd5a2abbde5a8","observation_sha256":"efe3c180fa92cf4e5262f01b3afbd23d67a4d706bc049d38605fa47ff17e5dc6","passed":false,"receipt_sha256":"c9b5d457928ea8cc69fb3f4f53b6d51ca0b02893fa63020f0ece097c53f38d9f","refusal_code":"stable_read_fault","stage":"pre-publication"},"failure":{"check_sha256":"ed9398df334b1699708362bf2541c8542cad8f10528cd9fe7adcd5a2abbde5a8","classification":"transient_fault","code":"stable_read_fault","diagnostic_sha256":"856a0f667d6f19654b7e4dd480d0644cfd95469a7b5bf1ab99c078faed6d359c","fault_class":"stable_read","stage":"revalidate"},"status":"refused"}
```

The ID preimage is 8,181 bytes; `result_id` is `32f2f5c141bfbd75e387e70b9e0db776c0dcd93cea0f22797da34e799b816056`. The complete 8,260-byte result is:

```json
{"assembly_result_schema":1,"attempt":1,"behavior_tier":"compile_only","candidate":{"artifact_relpath":"candidate.c","artifact_sha256":"4141414141414141414141414141414141414141414141414141414141414141","artifact_size":64,"header_sha256":"4343434343434343434343434343434343434343434343434343434343434343","source_sha256":"4242424242424242424242424242424242424242424242424242424242424242"},"canonicalization":{"bundle_sha256":"5151515151515151515151515151515151515151515151515151515151515151","canonicalization_schema":1,"compatibility_checks":[],"discarded_variants":[],"owner_bindings":[],"relevant_catalog_sha256":"5252525252525252525252525252525252525252525252525252525252525252","status":"planned","translation_units":[{"compile_argv_sha256":"e42d3646adf2a7bd60ceb87af84ae391a2e8723006a9eb940a36d3995effa0d1","derived_source_sha256":"a3ce973ac8959c59913c1919fb4c2d42626d04f18837ef6bc3ea66237a562209","object_relpath":"candidate.o","ordinal":0,"role":"candidate","source_sha256":"4242424242424242424242424242424242424242424242424242424242424242","unit":"synthetic-u"}]},"objects":[{"defined_symbols":[],"imported_symbols":[],"inspector_receipt_sha256":"87d84ca58cbd08b5cb4659c52fabcc87000e0eb6ea9a49b4673ae4e9e84ee702","object_relpath":"candidate.o","object_sha256":"9796d39e80e3864272c26fa9407f4add720ee56e4b640a88cdd9df05a16b5354","object_size":32,"ordinal":0,"unit":"synthetic-u"}],"outcome":{"classification":"transient_fault","code":"stable_read_fault","contributors":[],"diagnostic_sha256":"856a0f667d6f19654b7e4dd480d0644cfd95469a7b5bf1ab99c078faed6d359c","stage":"revalidate","stage_receipts":[{"child_receipts":[{"argv":["emcc","-c","candidate.c","-o","candidate.o"],"child_ordinal":0,"diagnostic_sha256":null,"execution_completed":true,"exit_status":0,"fault_class":null,"input_sha256":"a3ce973ac8959c59913c1919fb4c2d42626d04f18837ef6bc3ea66237a562209","object_ordinal":0,"object_relpath":"candidate.o","object_sha256":"9796d39e80e3864272c26fa9407f4add720ee56e4b640a88cdd9df05a16b5354","parser_version":"synthetic-compile-parser-v1","stage":"compile","stage_child_receipt_schema":1,"state":"passed","stderr_sha256":"489c910c843de67b128b684c849067771b91af854bab5e5599c34cf58a75b8bb","stderr_size":24,"stdout_sha256":"85e982a9556993ee56418312a4e626c3ba1e0fa5605d724c95fc593b7ddf67f7","stdout_size":24,"symbol":null,"terminal":true,"unit":"synthetic-u"}],"child_transcript_sha256":"5597071754af9bbe42a2fa65fc43043c1c59cc2153d23e8940adaf0f86ecdc87","diagnostic_sha256":null,"execution_completed":true,"exit_status":0,"fault_class":null,"named_object_relpaths":["candidate.o"],"parser_version":"synthetic-compile-parser-v1","stage":"compile","stage_receipt_schema":1,"state":"passed","stderr_sha256":"b116c438f4bcea2ac63b2ebfddaa247a3e1d72eeb3564ffc5262a9072c82d970","stdout_sha256":"d33a223670cffdc68f5f51af4d3b821abe3fa1fa703a485b7b7a5959c35ac27f","symbol":null},{"child_receipts":[{"argv":["llvm-nm","candidate.o"],"child_ordinal":0,"diagnostic_sha256":null,"execution_completed":true,"exit_status":0,"fault_class":null,"input_sha256":"9796d39e80e3864272c26fa9407f4add720ee56e4b640a88cdd9df05a16b5354","object_ordinal":0,"object_relpath":"candidate.o","object_sha256":"9796d39e80e3864272c26fa9407f4add720ee56e4b640a88cdd9df05a16b5354","parser_version":"synthetic-inspect-parser-v1","stage":"inspect","stage_child_receipt_schema":1,"state":"passed","stderr_sha256":"0e998d65f40fdc0f1ec0aff8bd5b5bd661ab9cf9973d359b228f484acd5f1ed9","stderr_size":24,"stdout_sha256":"d7dc7b2e512ea4543cecbe07911be308568a139ad1a8a14dd4d46f4690d6636a","stdout_size":24,"symbol":null,"terminal":true,"unit":"synthetic-u"}],"child_transcript_sha256":"67eb92399a94b59e58f244e30399c1f6ad1d88fb06af787a6b493fbd4c9fbf37","diagnostic_sha256":null,"execution_completed":true,"exit_status":0,"fault_class":null,"named_object_relpaths":["candidate.o"],"parser_version":"synthetic-inspect-parser-v1","stage":"inspect","stage_receipt_schema":1,"state":"passed","stderr_sha256":"8a3a35e24d043e63dec034f478051c5cae3784c838fac7cc05d4a5b64cdd1c57","stdout_sha256":"f046343904baef900e5b5279edfe4b4b0b823489a76d4c772cb43f8fe2bf6489","symbol":null},{"child_receipts":[],"child_transcript_sha256":null,"diagnostic_sha256":null,"execution_completed":true,"exit_status":0,"fault_class":null,"named_object_relpaths":["candidate.o"],"parser_version":"synthetic-link-parser-v1","stage":"link","stage_receipt_schema":1,"state":"passed","stderr_sha256":"117a72cb8592f535a1a7fe408c2c7fda6673bb4afdbe6ad8867b824ab788b6b3","stdout_sha256":"115fb89eab424714138920cb65144b8bce9f9ad060d6345fb741d1e4f21904ae","symbol":null},{"child_receipts":[],"child_transcript_sha256":null,"diagnostic_sha256":null,"execution_completed":true,"exit_status":0,"fault_class":null,"named_object_relpaths":[],"parser_version":"synthetic-instantiate-parser-v1","stage":"instantiate","stage_receipt_schema":1,"state":"passed","stderr_sha256":"5c6c1d8ec39ae71fff8e948678da80cf26e48b4705297615b4459e54468d9fed","stdout_sha256":"dd20395fa27c5d9008f6168ed34a81e06f128b1424c572d76fa91fc8bd4225b8","symbol":null},{"child_receipts":[],"child_transcript_sha256":null,"diagnostic_sha256":null,"execution_completed":true,"exit_status":0,"fault_class":null,"named_object_relpaths":[],"parser_version":"synthetic-smoke-parser-v1","stage":"smoke","stage_receipt_schema":1,"state":"passed","stderr_sha256":"f61850da616a9f5b3100d9da1f9dfe1ab446d04432bbf58d57cd2d2a91daf07b","stdout_sha256":"a1a73ff7b5098c9ec2309ae2fb03e881065dc6142fc235c57afba975d202ad14","symbol":null}],"unattributed":true},"result_id":"32f2f5c141bfbd75e387e70b9e0db776c0dcd93cea0f22797da34e799b816056","retry":{"assembly_retry_fingerprint":"0d5e000eb991471ed939846165d13d0616275c86ca36df485d1bdd941b97c81c","assembly_world_sha256":"6161616161616161616161616161616161616161616161616161616161616161","backoff_seconds":30,"class":"transient_fault","status":"transient_retry","transient_fault_fingerprint":"5200c61f3b31b5b0a561bfd616c9628c0a03430f4c0a0f82826c18a755457f2a","transient_retry_count":1},"revalidation":{"pre_compile_sha256":"7d3739653926d62e6ec0a8769805916242ab20267dfb5e25c5010c567f5f74c6","pre_publication_sha256":"ed9398df334b1699708362bf2541c8542cad8f10528cd9fe7adcd5a2abbde5a8"},"tool_world":{"argv":{"compile":[["emcc","-c","candidate.c","-o","candidate.o"]],"inspect":[["llvm-nm","candidate.o"]],"instantiate":["node","instantiate.js","candidate.wasm"],"link":["emcc","candidate.o","-o","candidate.wasm"],"smoke":["node","smoke.js","candidate.wasm"]},"environment":[{"name":"EMSDK","value_sha256":"3131313131313131313131313131313131313131313131313131313131313131"}],"identities":[{"file_sha256":"1111111111111111111111111111111111111111111111111111111111111111","resolved_path":"D:/synthetic/clang.exe","role":"clang","version_sha256":"2121212121212121212121212121212121212121212121212121212121212121"},{"file_sha256":"1212121212121212121212121212121212121212121212121212121212121212","resolved_path":"D:/synthetic/emcc.bat","role":"emcc","version_sha256":"2222222222222222222222222222222222222222222222222222222222222222"},{"file_sha256":"1313131313131313131313131313131313131313131313131313131313131313","resolved_path":"D:/synthetic/node.exe","role":"node","version_sha256":"2323232323232323232323232323232323232323232323232323232323232323"},{"file_sha256":"1414141414141414141414141414141414141414141414141414141414141414","resolved_path":"D:/synthetic/llvm-nm.exe","role":"object-inspector","version_sha256":"2424242424242424242424242424242424242424242424242424242424242424"},{"file_sha256":"1515151515151515151515151515151515151515151515151515151515151515","resolved_path":"D:/synthetic/smoke.js","role":"smoke-script","version_sha256":"2525252525252525252525252525252525252525252525252525252525252525"},{"file_sha256":"1616161616161616161616161616161616161616161616161616161616161616","resolved_path":"D:/synthetic/wasm-ld.exe","role":"wasm-ld","version_sha256":"2626262626262626262626262626262626262626262626262626262626262626"}],"tool_world_schema":1,"tool_world_sha256":"1ce523c15a3d30aafba7e59d93848de812cb5225495175e3554fba3b8f89b5d7"},"unit":"synthetic-u","window":[{"artifact_relpath":"candidate.c","artifact_sha256":"4141414141414141414141414141414141414141414141414141414141414141","artifact_size":64,"ordinal":0,"unit":"synthetic-u"}]}
```


Crossed-combination refusals mutate each decision independently and must fail
before hashing: `not_reached` with either nonnull member; `passed` with a
null/failed check or any failure; `refused` with null/passing check, null
failure, classification outside the closed enum, null diagnostic, different
code, different check digest, deterministic/non-null fault, transient/null
fault, or a check not binding the draft composition
receipt. Tool non-pass with `passed|refused`, or an all-pass tool tuple with
`not_reached`, also refuses. Tests recompute all four IDs from literal bytes
and prove changing any child transcript digest changes both result ID and the
assembly retry fingerprint. Missing/mismatched/future `RetryHistory`, or a
history digest different from the draft, refuses before result hashing.

The private attempt has a mutable control marker, but durable evidence is
immutable. Canonical JSON means UTF-8, sorted keys, no insignificant
whitespace, LF, integers only where specified, and a trailing LF.

1. The gate returns one in-memory `CompositionResult`; it writes no durable
   evidence. The driver rejects missing/extra fields, wrong types, bool-as-int,
   non-NFC strings, unsorted collections, invalid paths/hashes/enums, or a
   result inconsistent with the owned attempt. The following reusable shapes
   are exact; every object rejects unknown keys:

   - `Candidate` = `{artifact_relpath: owned NFC POSIX relative string,
     artifact_sha256: sha256, artifact_size: nonnegative-int, source_sha256:
     sha256, header_sha256: sha256}`.
   - `WindowItem` = `{ordinal: nonnegative-int, unit: nonempty string,
     artifact_relpath: owned relative string, artifact_sha256: sha256,
     artifact_size: nonnegative-int}`, uniquely sorted by ordinal from zero.
   - `OwnerBinding` = `{symbol: C identifier, unit: nonempty string,
     chunk_file: product-relative string, line_range: [positive-int,
     positive-int], normalized_prototype: nonempty string,
     owner_binding_sha256: sha256}`, uniquely sorted by symbol.
   - `CompatibilityEvidence` = the exact schema-1 object defined in section 2.
     Its `source_relpath` identifies the variant declaration; entries are
     uniquely sorted by `(symbol,source_relpath,variant_prototype_sha256)`.
   - `SymbolObservation` = `{name: C identifier, kind:
     'function'|'global'|'table'|'memory'|'tag', abi_sha256: sha256|null,
     visibility: 'default'|'hidden'}`. `abi_sha256` may be null only when the
     inspector format cannot carry a type and the outcome does not attribute
     an ABI conflict to that symbol.
   - `Contributor` = `{symbol: C identifier, unit: nonempty string,
     object_relpath: owned relative string, object_sha256: sha256, role:
     'definition'|'import', abi_sha256: sha256}`; unique sorted by
     `(symbol,unit,object_relpath,role)`.

2. The immutable result has exactly thirteen top-level keys:
   `assembly_result_schema: 1`, `result_id: sha256`, `unit: nonempty string`,
   `attempt: positive-int`, `candidate: Candidate`, `window:
   list[WindowItem]`, `behavior_tier: 'compile_only'|'oracle_green'`, and these
   six exact nested values:

   - `canonicalization` = `{canonicalization_schema: 1, status:
     'not_started'|'failed'|'planned', bundle_sha256: sha256|null,
     relevant_catalog_sha256: sha256|null, owner_bindings:
     list[OwnerBinding], compatibility_checks: list[CompatibilityEvidence],
     discarded_variants: list[exact {symbol: C identifier,
     source_relpath: owned relative string, prototype_sha256: sha256}],
     translation_units: list[exact {ordinal: nonnegative-int, unit: nonempty
     string, role: 'candidate'|'window', source_sha256: sha256,
     derived_source_sha256: sha256, object_relpath: owned relative string,
     compile_argv_sha256: sha256}]}`. `not_started` requires both digests null
     and every list empty; `failed` requires null bundle, a real relevant-
     catalog digest and no translation units; `planned` requires both digests.
     Every discarded variant has exactly one
     matching `compatibility_checks` entry with result `compatible`; a result
     `incompatible` permits no write and produces the deterministic blocker.
     Variants sort by `(symbol,source_relpath,prototype_sha256)`;
     translation units sort by ordinal from zero.
   - `objects` = an ordinal-sorted list of exact `{ordinal, unit,
     object_relpath, object_size, object_sha256, defined_symbols:
     list[SymbolObservation], imported_symbols: list[SymbolObservation],
     inspector_receipt_sha256}`; symbol lists are unique sorted by
     `(name,kind)`.
   - `tool_world` = `{tool_world_sha256: sha256, tool_world_schema: 1,
     identities:
     list[{role: 'emcc'|'clang'|'wasm-ld'|'object-inspector'|'node'|
     'smoke-script', resolved_path: absolute string, file_sha256: sha256,
     version_sha256: sha256}], argv: {compile: list[list[string]], inspect:
     list[list[string]], link: list[string], instantiate: list[string], smoke:
     list[string]},
     environment: list[{name: string, value_sha256: sha256}]}`. Roles and
     environment names are unique sorted; argv order is semantic. The world
     hash preimage is canonical `tool_world` with only
     `tool_world_sha256` removed. It contains tools/argv/environment only.
   - `outcome` = `{classification:
     'pass'|'deterministic_blocker'|'transient_fault', stage:
     'owner'|'canonicalize'|'materialize'|'compile'|'inspect'|'link'|
     'instantiate'|'smoke'|'revalidate'|'internal', code: nonempty string,
     stage_receipts: [StageReceipt,StageReceipt,StageReceipt,StageReceipt,
     StageReceipt], diagnostic_sha256: sha256|null, contributors:
     list[Contributor], unattributed: bool}`. The receipt tuple obeys the exact
     truth matrix above. Owner/canonicalize/materialize/pre-compile refusals use
     all `not_run`; a post-tool revalidation refusal retains the completed tool
     history. `diagnostic_sha256` is null only for pass.
   - `revalidation` = `{pre_compile_sha256: sha256|null,
     pre_publication_sha256: sha256|null}`; null is allowed only when failure
     occurred before that boundary.
   - `retry` = `{class: 'none'|'deterministic_blocker'|'transient_fault',
     status: 'pass'|'waiting_assembly_world_change'|'transient_retry'|
     'assembly_transient_exhausted', assembly_world_sha256: sha256,
     assembly_retry_fingerprint: sha256,
     transient_fault_fingerprint: sha256|null, transient_retry_count:
     nonnegative-int, backoff_seconds: null|30|120|600}`. Null transient fields
     are required for `none`/deterministic; transient status/count/backoff must
     agree with the bounded schedule.

   The deep finalizer constructs the ID preimage and complete result exactly as
   specified above. The driver builds a separate read-only validation
   projection that excludes `result_id`, recomputes it, requires equality, and
   writes the unchanged complete object to
   `assembly-result/<result_id>.json` atomically. `result_sha256` always means
   the SHA-256 of those final bytes. Result schema 1 contains no timestamp,
   clock, run ID, journal receipt, or manifest path; none enters either hash.
3. After the result is durable, the driver folds its deterministic ledger
   projection into local `assembly-gate.json` through `record_gate_result`,
   passing the lowercase `result_id` and SHA-256 of the final result bytes.
   Assembly-ledger schema remains integer `schema: 1`: this avoids breaking
   the current schema-1 knowledge consumer. Task 3 adds one backward-compatible
   top-level member, `processed_results`, whose exact shape is an object from
   lowercase 64-hex `result_id` keys to lowercase 64-hex final-result digests.
   Keys serialize in lexical order. A valid legacy schema-1 ledger may omit
   this member and is read as an empty map; every successful id-aware write
   emits it. Missing ledger creates the existing schema-1 fields plus this
   empty map. Non-object ledger, corrupt JSON, non-integer/wrong `schema`, or a
   malformed processed entry is a typed refusal with no rebuild/write; no
   future schema is silently downgraded.

   The actual serialization lock is
   `DriverLock(ledger_path.with_name('assembly-gate.lock'))`; create only its
   parent, acquire before reading either ledger bytes or parsed content, hold
   through validation/fold/`atomic_write_json`, and release in `finally`.
   Failure to acquire returns transient `assembly_ledger_busy` and writes
   nothing. Lock order is the already-held `wasm-units.lock` then this ledger
   lock; no code acquires them in reverse. Under that lock, same ID/same digest
   returns the parsed ledger without invoking the ledger fold's timestamp or
   writing the ledger: ledger file bytes, `runs_total`, `last_run`,
   `updated_at`, and conflict counters remain exactly unchanged. Same
   ID/different digest refuses
   `assembly_result_id_digest_conflict` before any mutation. A new ID applies
   the existing counter/timestamp/conflict fold once, inserts its digest, and
   writes atomically. A fold/write fault stops before blocked/success marker
   transition; recovery replays from the immutable result. Tests compare raw
   before/after bytes, exercise distinct IDs for intentional repeated runs,
   and prove same-ID divergence, bad schema/index, lock contention, and stale
   lock recovery are zero-ledger-write paths.
4. For a blocker, `transition_id` is SHA-256 of exactly this canonical object:
   `{transition_schema: 1, kind: 'composition_blocked', unit, attempt,
   state_preimage_sha256, result_id, result_sha256, candidate_sha256,
   behavior_tier, retry: {class, assembly_retry_fingerprint,
   transient_retry_count}}`. It contains no timestamp, run ID, receipt,
   directory, filename, manifest relpath/hash, projected-state hash, or remote
   value. Only after computing the ID does the driver derive the fixed path
   `assembly-blocked/<transition_id>.json`; therefore no identifier/path cycle
   exists. “State preimage” is the exact canonical state bytes already saved
   after `status=porting` and attempt increment, immediately before blocking.
5. The blocked-state projection updates only the named unit with `status:
   red_retryable`, `last_stage: assembly`, `failure_domain: pipeline-control`,
   `diagnosis_eligible: false`, unchanged `tier`, and exact result/transition/
   retry/manifest reference fields. `projected_state_semantic_sha256` hashes
   the complete projected canonical state with
   `assembly_blocked_manifest_sha256` fixed to 64 ASCII zeroes and no progress
   receipt field. The driver then writes immutable
   `assembly-blocked/<transition_id>.json` with exactly fourteen keys:
   `assembly_blocked_schema: 1`, `transition_id`, `unit`, `attempt`,
   `state_preimage_sha256`, `projected_state_semantic_sha256`, `result_id`,
   `result_sha256`, `candidate: Candidate`, `window: list[WindowItem]`,
   `owner_bindings: list[{symbol,owner_binding_sha256}]`,
   `assembly_world_sha256: sha256`, `retry` in the exact result shape, and
   `behavior_tier`. Owner refs sort by symbol. No field is nullable except the
   two retry fields defined above; unknown/missing/nonnormalized fields refuse.
   Blocked schema 1 contains no timestamp, next-retry wall clock, run ID,
   receipt, full projected-state hash, or its own path/hash.
6. After hashing the blocked manifest, the driver inserts its digest into the
   same projected state and hashes the exact final bytes as
   `projected_state_sha256`. A transient `next_retry_not_before` may live in
   the mutable marker/final state and therefore participates in that full-byte
   digest, but never in immutable IDs/manifests. The mutable marker enters
   `assembly-blocked` and stores result/manifest paths and hashes, transition
   ID, semantic/full projected-state hashes, scheduling time if any, and
   phase. Canonical state references only immutable manifest/result evidence,
   never the marker digest.
7. `_checkpoint` constructs exactly
   `UnitTransition(unit=unit, result='retryable', stage='assembly',
   attempt=attempt, detail='composition_blocked result_id=' + result_id,
   product_commit=None, product_pushed=None, oracle_summary=None, model=None,
   tier=behavior_tier, product_commit_failed=False,
   product_commit_detail='', extra=...)`. Its `to_record` output has every
   outer field fixed: `schema=1`; `unit` is the transition unit;
   `unit_id=stable_unit_id(unit)`; `timestamp` and `run_id` are journal-owned;
   `result='retryable'`; `stage='assembly'`; `attempt` is the same positive
   transition attempt; `detail` is the exact digest-bound string above;
   `product_commit=null`; `product_pushed=null`; `product_effect='no
   product-tree change by design'`; `product_commit_failed=false`;
   `oracle_summary=null`; `model=null`; `tier=behavior_tier`; and `extra` is
   present. There is no other record key. The stable semantic `extra` has
   exactly `transition_id`, `assembly_result_id`, `assembly_result_sha256`,
   `assembly_blocked_manifest_sha256`, `state_preimage_sha256`,
   `projected_state_semantic_sha256`, `projected_state_sha256`,
   `assembly_retry_fingerprint`, and `retry_class`. Journal-added `timestamp`
   and `run_id` are the only fields excluded by existing
   `ProgressJournal.transition_semantics`; journal semantics stay unchanged.
   Recovery requires every remote record to equal that complete semantic
   object exactly.

   The existing `ProgressJournal.authoritative_transition_receipt` is
   sufficient and is not changed. After its internal double `ls-remote`
   confirmation, the driver persists only this exact marker projection:
   `{transition_id, authoritative: true, remote: true, remote_sha,
   remote_record_sha256}`. `remote_sha` is the one lowercase 40/64-hex value
   exposed by the existing receipt; `remote_record_sha256` is SHA-256 of the
   complete expected timestamp/run-ID-free semantics encoded as canonical JSON
   (`sort_keys=True`, UTF-8, no insignificant whitespace) plus one LF.
   `remote_records` must be
   nonempty and every record must match; `authoritative` and `remote` must both
   be exact booleans true. Local/branch/commit fields and the two internal
   `ls-remote` observations are neither exposed nor invented as durable
   fields. After storing this projection in the marker, atomically save the
   byte-identical projected state. A journal outage leaves the already-
   incremented preimage state unchanged. A record with the same transition ID
   but any different semantic outer/`extra` value refuses
   `progress_transition_semantic_conflict` before append or state advance.
   Different timestamp/run ID alone remains an idempotent duplicate under the
   current ProgressJournal rule.

#### Deterministic transition vector

Each JSON line below is the exact canonical UTF-8 bytes plus one final LF.
Hashing this transition preimage:

```json
{"attempt":2,"behavior_tier":"compile_only","candidate_sha256":"1111111111111111111111111111111111111111111111111111111111111111","kind":"composition_blocked","result_id":"2222222222222222222222222222222222222222222222222222222222222222","result_sha256":"3333333333333333333333333333333333333333333333333333333333333333","retry":{"assembly_retry_fingerprint":"4444444444444444444444444444444444444444444444444444444444444444","class":"deterministic_blocker","transient_retry_count":0},"state_preimage_sha256":"5555555555555555555555555555555555555555555555555555555555555555","transition_schema":1,"unit":"synthetic-u"}
```

produces transition ID
`85cf5e3c0b91fdc36a49b519d837fabf7691cec2b418406194a35b03600fd5e0`
and only then path
`assembly-blocked/85cf5e3c0b91fdc36a49b519d837fabf7691cec2b418406194a35b03600fd5e0.json`.
The semantic projected-state bytes are:

```json
{"units":{"synthetic-u":{"assembly_blocked_manifest_relpath":"assembly-blocked/85cf5e3c0b91fdc36a49b519d837fabf7691cec2b418406194a35b03600fd5e0.json","assembly_blocked_manifest_sha256":"0000000000000000000000000000000000000000000000000000000000000000","assembly_result_id":"2222222222222222222222222222222222222222222222222222222222222222","assembly_result_sha256":"3333333333333333333333333333333333333333333333333333333333333333","assembly_retry_class":"deterministic_blocker","assembly_retry_fingerprint":"4444444444444444444444444444444444444444444444444444444444444444","assembly_transition_id":"85cf5e3c0b91fdc36a49b519d837fabf7691cec2b418406194a35b03600fd5e0","attempts":2,"diagnosis_eligible":false,"failure_domain":"pipeline-control","last_stage":"assembly","status":"red_retryable","tier":"compile_only"}}}
```

with SHA-256
`21df203c7aacc943f272066f34aaca5715854ad59d194def011c0438a6fd449f`.
The exact blocked-manifest bytes are:

```json
{"assembly_blocked_schema":1,"assembly_world_sha256":"8888888888888888888888888888888888888888888888888888888888888888","attempt":2,"behavior_tier":"compile_only","candidate":{"artifact_relpath":"candidate","artifact_sha256":"1111111111111111111111111111111111111111111111111111111111111111","artifact_size":1,"header_sha256":"6666666666666666666666666666666666666666666666666666666666666666","source_sha256":"7777777777777777777777777777777777777777777777777777777777777777"},"owner_bindings":[],"projected_state_semantic_sha256":"21df203c7aacc943f272066f34aaca5715854ad59d194def011c0438a6fd449f","result_id":"2222222222222222222222222222222222222222222222222222222222222222","result_sha256":"3333333333333333333333333333333333333333333333333333333333333333","retry":{"assembly_retry_fingerprint":"4444444444444444444444444444444444444444444444444444444444444444","backoff_seconds":null,"class":"deterministic_blocker","status":"waiting_assembly_world_change","transient_fault_fingerprint":null,"transient_retry_count":0},"state_preimage_sha256":"5555555555555555555555555555555555555555555555555555555555555555","transition_id":"85cf5e3c0b91fdc36a49b519d837fabf7691cec2b418406194a35b03600fd5e0","unit":"synthetic-u","window":[{"artifact_relpath":"candidate","artifact_sha256":"1111111111111111111111111111111111111111111111111111111111111111","artifact_size":1,"ordinal":0,"unit":"synthetic-u"}]}
```

with SHA-256
`17059ed2e9e81f5297d4e59a5d75354878ab47d9c0ca07ccbf89ef1e1bb79bc1`.
Replacing only the semantic projection's 64 zeroes with that manifest hash
produces the exact full projected-state SHA-256
`8bf77598cbe453a4fb4d0f13c7cf58eceb511fbdd9203ff34c4801b9fbfcac03`.
Tests recompute every value rather than treating the strings as snapshots.

For the same synthetic values, the normative complete journal record (the
fixed timestamp/run ID are illustrative journal-owned values) is exactly:

```json
{"attempt":2,"detail":"composition_blocked result_id=2222222222222222222222222222222222222222222222222222222222222222","extra":{"assembly_blocked_manifest_sha256":"17059ed2e9e81f5297d4e59a5d75354878ab47d9c0ca07ccbf89ef1e1bb79bc1","assembly_result_id":"2222222222222222222222222222222222222222222222222222222222222222","assembly_result_sha256":"3333333333333333333333333333333333333333333333333333333333333333","assembly_retry_fingerprint":"4444444444444444444444444444444444444444444444444444444444444444","projected_state_semantic_sha256":"21df203c7aacc943f272066f34aaca5715854ad59d194def011c0438a6fd449f","projected_state_sha256":"8bf77598cbe453a4fb4d0f13c7cf58eceb511fbdd9203ff34c4801b9fbfcac03","retry_class":"deterministic_blocker","state_preimage_sha256":"5555555555555555555555555555555555555555555555555555555555555555","transition_id":"85cf5e3c0b91fdc36a49b519d837fabf7691cec2b418406194a35b03600fd5e0"},"model":null,"oracle_summary":null,"product_commit":null,"product_commit_failed":false,"product_effect":"no product-tree change by design","product_pushed":null,"result":"retryable","run_id":"synthetic-run","schema":1,"stage":"assembly","tier":"compile_only","timestamp":"2030-01-02T03:04:05Z","unit":"synthetic-u","unit_id":"synthetic-u"}
```

Its canonical full-record SHA-256 is
`c3fa6414a384aac50f466f2cfffde17cd975b767cae834eadcbed5d6c4a3b141`.
Applying the unchanged `transition_semantics` exclusion gives exactly:

```json
{"attempt":2,"detail":"composition_blocked result_id=2222222222222222222222222222222222222222222222222222222222222222","extra":{"assembly_blocked_manifest_sha256":"17059ed2e9e81f5297d4e59a5d75354878ab47d9c0ca07ccbf89ef1e1bb79bc1","assembly_result_id":"2222222222222222222222222222222222222222222222222222222222222222","assembly_result_sha256":"3333333333333333333333333333333333333333333333333333333333333333","assembly_retry_fingerprint":"4444444444444444444444444444444444444444444444444444444444444444","projected_state_semantic_sha256":"21df203c7aacc943f272066f34aaca5715854ad59d194def011c0438a6fd449f","projected_state_sha256":"8bf77598cbe453a4fb4d0f13c7cf58eceb511fbdd9203ff34c4801b9fbfcac03","retry_class":"deterministic_blocker","state_preimage_sha256":"5555555555555555555555555555555555555555555555555555555555555555","transition_id":"85cf5e3c0b91fdc36a49b519d837fabf7691cec2b418406194a35b03600fd5e0"},"model":null,"oracle_summary":null,"product_commit":null,"product_commit_failed":false,"product_effect":"no product-tree change by design","product_pushed":null,"result":"retryable","schema":1,"stage":"assembly","tier":"compile_only","unit":"synthetic-u","unit_id":"synthetic-u"}
```

Thus `remote_record_sha256` is
`0ed217da30ae21b0bf7dc018361d384699a61691cae4b7b55e0a8d4bf7918c10`.
Tests reconstruct via `UnitTransition.to_record`, call the existing semantic
projection, recompute both hashes, accept a same-ID record differing only in
timestamp/run ID, and refuse a same-ID record differing in each outer field or
each of the nine `extra` fields.

Blocked recovery is ordered and idempotent: missing result reruns only the
permitted assembly action; result without fold replays the local fold; fold
without blocked manifest derives it; manifest without marker repairs the
pointer; marker without remote receipt checkpoints the same transition;
remote push without a local receipt discovers and verifies the exact event and
advertised tip; receipt without state saves only if the current state equals
the recorded preimage; state without cleanup remains intentionally retained.
Any digest/preimage divergence quarantines without a second event or state
edit. A new transient tool retry creates new result/transition manifests and
keeps all earlier immutable evidence.

On success, the driver first validates the returned in-memory result, writes
the immutable result, and completes the idempotent local fold. The existing
product transaction order is then normative: write the verified
`gate-passed` marker; install the artifact; fold/harvest advisory evidence;
prepare/adopt the path-scoped product commit; change the marker to
`publishing` with commit and remote preimage; push the explicit
`HEAD:refs/heads/port-staging` refspec; project green state; obtain and verify
the authoritative `port-progress` receipt against the advertised remote tip;
record `checkpointed` plus the receipt in the marker; atomically save the same
projected green state; then clean the attempt. There is no progress-journal
transition before install. Recovery resumes the first unverified phase and
never repeats a non-idempotent side effect.

Canonicalized link plus instantiation proves only structural composition.
`compile_only` stays `compile_only (UNVERIFIED)`; `oracle_green` is preserved
only when a behavioral oracle independently passed. No assembly receipt may
create `oracle_green`, `verified`, `promoted-to-product`, or gameplay credit.

## Fixtures and testing strategy

Public tests use one minimized, hand-written, synthetic fixture file. It
contains invented owner bodies, a five-object window, 3-argument and
16-argument conflicts, zero/two-owner cases, and explicit synthetic payload
digests. Historical GotYaForce hashes appear only in metadata named
`historical_evidence_sha256`; tests must never compare them to synthetic
payload digests or claim historical reproduction.

The opt-in private lane has this exact contract:

- `OGHIDRA_ASSEMBLY_ABI_PRIVATE_FIXTURE_ROOT` is an absolute ordinary
  directory and `OGHIDRA_ASSEMBLY_ABI_PRIVATE_MANIFEST_SHA256` is exactly 64
  lowercase hex digits. Both absent truthfully deselect the private marker;
  exactly one present fails collection. The root is read-only test input, must
  not be inside a promotion/staging directory, and contains the exact ordinary
  file `assembly-abi-private-manifest.json`; its raw-byte SHA-256 must equal
  the environment value before JSON parsing.
- The manifest is UTF-8 canonical JSON with exact top-level keys
  `private_assembly_abi_schema: 1`, `fixture_id: nonempty string`,
  `inventory: list[object]`, and `cases: list[object]`. `inventory` covers
  every descendant other than the manifest itself and contains exact
  `{path: NFC POSIX relative string, kind: 'file'|'directory', size:
  nonnegative-int, sha256: lowercase SHA-256|null}` records. Directories use
  null/size 0; files use exact raw size/hash. Paths are strictly sorted,
  unique both ordinally and after Unicode case-folding, contain no empty/dot/
  dot-dot/backslash/drive/UNC/ADS/control segment, and may not escape root.
- Each case has exactly `case_id`, `candidate`, `window`, `owners`, and
  `expected`; no nested value is nullable. Case IDs are unique sorted strings.
  `candidate` is exact `{unit, directory_relpath, directory_sha256,
  artifact_relpath, artifact_sha256}`. Each ordinal-sorted `window` item adds
  `ordinal` to those same five keys; ordinals are unique from zero. Directory
  paths name inventory directories; artifact paths name descendant inventory
  files; every manifest/file/directory digest must match.
- `owners` is uniquely symbol-sorted exact `{symbol: C identifier, unit:
  nonempty string, source_relpath: inventory file, source_sha256: sha256,
  line_range: [positive-int,positive-int], range_sha256: sha256,
  owner_binding_sha256: sha256}`. The inclusive range must be ordered and its
  retained-line-ending digest must match the source bytes.
- `expected` is exact `{canonicalization_schema: 1, result_schema: 1,
  relevant_catalog_sha256: sha256, decision:
  'pass'|'waiting_assembly_world_change'|'transient_retry'|
  'assembly_transient_exhausted', behavior_tier:
  'compile_only'|'oracle_green', retry_class:
  'none'|'deterministic_blocker'|'transient_fault',
  assembly_retry_fingerprint: sha256, contributors: list[object],
  unattributed: bool}`. Each contributor is exact `{symbol, unit,
  object_relpath, object_sha256, role: 'definition'|'import', abi_sha256}`,
  unique sorted by `(symbol,unit,object_relpath,role)`, and its object must be
  in the case window/inventory. `pass` requires `retry_class=none`, empty
  contributors, and `unattributed=false`; other decision/class combinations
  must match Section 5. Unknown/missing keys, wrong ordering/type/enum, or an
  unreferenced path refuse. No historical hash may appear unless its named
  directory is inventoried and independently verifies.
- Root, manifest, every path component, and every opened file receive the same
  exact-spelling, containment, stable-identity, hardlink, reparse, and special-
  file checks as product input. Each case-directory digest uses the current
  `unit_artifact_sha256` framing exactly: sort `rglob('*')` by POSIX relpath;
  reject symlinks/special files; hash 4-byte big-endian UTF-8 path length,
  path bytes, then `D` for a directory or `F`, 8-byte big-endian payload
  length, and payload bytes for a file. The manifest's expected digest and
  recomputed digest must match.

  One normative vector has candidate file bytes
  `int fixture(void){return 7;}\n` (29 bytes), SHA-256
  `20b12a5fdc95d41ed77a5f8c791b8ca7e287c448291f6d57ffd052659afeaeb8`.
  Its candidate-directory framing is hex
  `00000006756e69742e6346000000000000001d696e74206669787475726528766f6964297b72657475726e20373b7d0a`
  and SHA-256
  `753614caf2ae356f2f204f37c7c9a028078971d7af7c449b767af1e3ce982507`.
  Owner file bytes `int fixture_owner(void){return 7;}\n` are 35 bytes with
  SHA-256 `eb3de2969f48d834228125a8e6e1e6c8a149f44964a3d3a8b0df9f9a1d6f7067`.
  With those two files, the exact canonical manifest bytes plus final LF are:

  ```json
  {"cases":[{"candidate":{"artifact_relpath":"cases/case-01/candidate/unit.c","artifact_sha256":"20b12a5fdc95d41ed77a5f8c791b8ca7e287c448291f6d57ffd052659afeaeb8","directory_relpath":"cases/case-01/candidate","directory_sha256":"753614caf2ae356f2f204f37c7c9a028078971d7af7c449b767af1e3ce982507","unit":"synthetic-candidate"},"case_id":"case-01","expected":{"assembly_retry_fingerprint":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","behavior_tier":"compile_only","canonicalization_schema":1,"contributors":[],"decision":"pass","relevant_catalog_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","result_schema":1,"retry_class":"none","unattributed":false},"owners":[{"line_range":[1,1],"owner_binding_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","range_sha256":"eb3de2969f48d834228125a8e6e1e6c8a149f44964a3d3a8b0df9f9a1d6f7067","source_relpath":"cases/case-01/owners/owner.c","source_sha256":"eb3de2969f48d834228125a8e6e1e6c8a149f44964a3d3a8b0df9f9a1d6f7067","symbol":"fixture_owner","unit":"synthetic-owner"}],"window":[{"artifact_relpath":"cases/case-01/candidate/unit.c","artifact_sha256":"20b12a5fdc95d41ed77a5f8c791b8ca7e287c448291f6d57ffd052659afeaeb8","directory_relpath":"cases/case-01/candidate","directory_sha256":"753614caf2ae356f2f204f37c7c9a028078971d7af7c449b767af1e3ce982507","ordinal":0,"unit":"synthetic-candidate"}]}],"fixture_id":"assembly-abi-private-vector-1","inventory":[{"kind":"directory","path":"cases","sha256":null,"size":0},{"kind":"directory","path":"cases/case-01","sha256":null,"size":0},{"kind":"directory","path":"cases/case-01/candidate","sha256":null,"size":0},{"kind":"file","path":"cases/case-01/candidate/unit.c","sha256":"20b12a5fdc95d41ed77a5f8c791b8ca7e287c448291f6d57ffd052659afeaeb8","size":29},{"kind":"directory","path":"cases/case-01/owners","sha256":null,"size":0},{"kind":"file","path":"cases/case-01/owners/owner.c","sha256":"eb3de2969f48d834228125a8e6e1e6c8a149f44964a3d3a8b0df9f9a1d6f7067","size":35}],"private_assembly_abi_schema":1}
  ```

  Raw manifest SHA-256 is
  `e7ae7f54a43c0f824162e8e6042ee87ff64f0ea411a6eb7a7624edaf1ce75f88`.
  Public tests construct these bytes, recompute both hashes, and mutate every
  nested key/order/type/enum/path to prove fail-closed validation.
- Register the exact pytest marker `private_assembly_abi` in `pyproject.toml`.
  Public CI runs `-m "not private_assembly_abi"` with both variables absent.
  An approved local private run uses `-m private_assembly_abi` with both
  variables present; no network fetch, log reconstruction, fallback to
  current staging, or skip-on-mismatch is allowed.

Test through the assembly ABI interface and driver outcomes:

- strict v1 acceptance and rejection of absent/bool/string/unknown schema;
- stable-read races, path escape, range drift, parse mismatch, and owner
  multiplicity refusals;
- whole-bundle canonicalization, verbatim-body preservation, atomic refusal,
  and receipt determinism;
- two-of-five precise attribution and unattributed fail-closed behavior;
- unchanged structural waiting, unchanged transient retry/backoff/exhaustion,
  changed-world recovery, journal-only recovery, restart retention,
  quarantine, and zero model/diagnosis/targeted-question calls;
- local-fold failure, journal failure, authoritative remote receipt replay,
  and every blocked/success promotion crash boundary;
- compile-only/oracle-green separation;
- optional private exact cases only when authoritative bytes exist.

## Commands

Run from the implementation worktree. All shell commands use `rtk`; all pytest
commands use D:-backed temporary storage.

```powershell
rtk git ls-remote fork refs/heads/main
rtk git -C D:\GotYaForce ls-remote origin refs/heads/main refs/heads/port-staging refs/heads/port-progress
rtk D:\GotYaForce\research\tools\emsdk\upstream\bin\clang.exe --version

rtk D:\GotYaForce\research\tools\OGhidra\.venv\Scripts\python.exe -m pytest -q --basetemp D:\GotYaForce\.tmp\pytest-assembly-abi-module tests\test_port_assembly_abi.py tests\test_port_assembly_gate.py
rtk D:\GotYaForce\research\tools\OGhidra\.venv\Scripts\python.exe -m pytest -q --basetemp D:\GotYaForce\.tmp\pytest-assembly-abi-driver tests\test_port_wasm_units.py tests\test_port_question_escalation.py tests\test_port_progress.py tests\test_port_knowledge_registry.py
rtk D:\GotYaForce\research\tools\OGhidra\.venv\Scripts\python.exe -m pytest -q -m "not private_assembly_abi" --basetemp D:\GotYaForce\.tmp\pytest-assembly-abi-public tests
$env:OGHIDRA_ASSEMBLY_ABI_PRIVATE_FIXTURE_ROOT='D:\GotYaForce\.tmp\approved-private-assembly-abi'; $env:OGHIDRA_ASSEMBLY_ABI_PRIVATE_MANIFEST_SHA256='<approved-lowercase-sha256>'; rtk D:\GotYaForce\research\tools\OGhidra\.venv\Scripts\python.exe -m pytest -q -m private_assembly_abi --basetemp D:\GotYaForce\.tmp\pytest-assembly-abi-private tests\test_port_assembly_abi.py
rtk D:\GotYaForce\research\tools\OGhidra\.venv\Scripts\python.exe -m ruff check src tests
rtk git diff --check fork/main...HEAD
rtk git diff --name-only fork/main...HEAD
```

Product schema generation and validation, after approval and from
`D:\GotYaForce`:

```powershell
rtk C:\Users\manny\AppData\Local\Programs\Python\Python313\python.exe research\decomp\data\build_oracle_registry.py
rtk C:\Users\manny\AppData\Local\Programs\Python\Python313\python.exe research\decomp\data\build_unit_priority.py
rtk C:\Users\manny\AppData\Local\Programs\Python\Python313\python.exe -m pytest -q --basetemp D:\GotYaForce\.tmp\pytest-oracle-registry-schema research\decomp\data\test_oracle_registry_schema.py
```

## Dependency-ordered implementation tasks

1. **Version the product owner contract.** Files (5):
   `research/decomp/data/build_oracle_registry.py`,
   `research/decomp/data/build_unit_priority.py`,
   `research/decomp/data/oracle_registry_schema.py`,
   `research/decomp/data/oracle-registry.json`, and
   `research/decomp/data/test_oracle_registry_schema.py`.
   Acceptance: one shared product validator; deterministic schema-1 producer
   output; the priority consumer rejects malformed/non-v1 output before use;
   producer and consumer tests are distinct; all eight marker-wins rows are
   accepted only with exact marker/index/anomaly agreement; regeneration keeps
   10,954 functions, 1,018 exclusions, eight anomalies, stable names and
   authoritative addresses; and `[]` versus `['void']` survives production and
   both consumers without count/order drift.
   Verify with the product commands above and byte-deterministic second run.
2. **Create the owner adapter and deep assembly module.** Files (3):
   `src/port_assembly_abi.py`, `tests/test_port_assembly_abi.py`, and
   `tests/fixtures/assembly_abi_synthetic_v1.json`.
   Acceptance: strict independent OGhidra adapter tests including all eight
   marker-wins rows; stable snapshot/range validation; injected production-
   Clang/fake parser seam; exact embedded preamble/undef bytes and complete
   audited alias/tag refusals; all bound argv arrays; source-offset
   parameter-name erasure and whole-stdout top-level `-ast-print` extraction;
   mandatory synthetic-param/return `desugaredQualType` ABI tuple and framing,
   including exact `_Bool`/`bool` parameter and return sources, compiler-owned
   `bool` tuple vectors, and crossed refusals without Python rewriting;
   exact adjusted-array primary/secondary sources, AST paths, digests, and
   refusal vectors; all seven
   byte pass/refusal/reparse vectors plus four typedef/preamble ABI vectors;
   exact Clang-owned compatibility source/argv/JSON projection with five
   qualifier vectors and pair-specific evidence/retry digests; exact gnu11
   conformance refusals; complete closed-alias enforcement; exact inspector
   receipts, all eleven five-stage truth vectors/refusal complement, exact
   StageChildReceipt/transcript/aggregate validation, and all twelve one/multi-
   child digest vectors; both
   canonical world payload/digest vectors plus tool-only/assembly-only changes;
   closed/versioned retry-history and both fingerprint preimages, literal pass/
   tool/deterministic/transient/mutation vectors, repeated transient schedule,
   changed-fingerprint reset, exact Candidate-artifact projection, total stage-
   to-adapter-role table with compile/link/instantiate/smoke vectors and crossed
   refusals, and finalizer-only retry construction; the
   three-way finalization union, closed
   prepublication decision/refusal evidence, four full result-ID vectors and
   crossed refusals; owner/tool digests; and
   pure planning/composition/revalidation. Tests explicitly prove unequal tuple
   spellings can be compatible and pointee qualifiers remain incompatible.
3. **Replace registry-less merge with bundle canonicalization and object
   attribution.** Files (4): `src/port_assembly_gate.py`,
   `src/port_wasm_units.py`, `tests/test_port_assembly_gate.py`, and
   `tests/test_port_assembly_abi.py`. Acceptance: gate-owned writes/compiler/
   inspector/rechecks, deterministic per-object compile/link manifests, exact
   construction of ordered compile/inspect child receipts plus transcript and
   stream aggregates for single/multi pass/completed-failure/fault, exact
   contributors, bound tool/smoke identities, a complete in-memory
   `CompositionResult` only through the exact finalization union, and no gate/
   deep-module durable evidence write. Pre-draft and precompile refusals return
   complete results; the gate passes the same driver-owned `RetryHistory` to
   analyze and every finalization member, and the draft history digest must
   match. The gate constructs typed attempted-stage/fault evidence from the
   adapter it actually invoked; Task 2's finalizer alone derives/validates the
   closed role projection without Task 3 reclassification. Precompile refusal
   executes zero tool/analyze spies; bare
   canonical receipts at prepublication and null pass hashes refuse; callers
   never insert/remove result fields or IDs. This
   task also owns the schema-1 `processed_results` result-ID/digest index and
   `assembly-gate.lock` critical section: same-ID/same-digest is a raw-byte
   no-op, same-ID/different-digest/bad schema/busy lock refuses without ledger
   mutation, and distinct result IDs preserve the current recurrence fold.
4. **Add retained-candidate composition retry.** Files (4):
   `src/port_assembly_abi.py`, `src/port_wasm_units.py`,
   `tests/test_port_wasm_units.py`, and
   `tests/test_port_question_escalation.py`.
   Acceptance: `_next_unit` routes retained candidates; unchanged deterministic
   blockers wait; the driver supplies exact durable `RetryHistory` while the
   accepted Task 2 finalizer alone validates/classifies/hashes and emits the
   final count/backoff projection; Task 4 consumes it without reclassification;
   statuses are
   `1/30`, `2/120`, `3/600`, then exhausted; relevant world changes rerun
   assembly only; journal-only recovery uses no tools; all paths make zero
   LLM/diagnosis/question calls. No scheduler file changes.
5. **Bind journal and promotion semantics.** Files (3):
   `src/port_wasm_units.py`, `tests/test_port_wasm_units.py`, and
   `tests/test_port_progress.py`.
   Acceptance: the driver is the sole result/blocked writer and validates the
   deep-finalizer-owned ID without field mutation; exact schema-1
   bytes/IDs and every normative transition/state/remote-record hash;
   idempotent local fold;
   path-cycle-free transition; existing authoritative receipt projected as
   one `remote_sha`; crash-edge replay; actual success order; and no false
   settlement/authority/tier change. `src/port_progress.py` is unchanged
   because its current double-confirmed receipt is sufficient; its tests prove
   that contract. Task 5 may start only after Task 3's result-ID ledger tests
   pass; it reuses that accepted helper unchanged. Verify focused progress/
   driver, then full suite.
6. **Enable the optional private exact lane.** Files (4):
   `src/port_assembly_abi.py`, `tests/test_port_assembly_abi.py`, and
   `tests/fixtures/assembly_abi_synthetic_v1.json`, and `pyproject.toml`.
   Acceptance: exact marker registration; both environment values absent
   truthfully deselect; partial configuration fails; every nested private
   shape/ref/order/enum and the normative manifest/directory vector verify;
   historical claims occur only after exact bytes verify.

No task changes more than five files. Tasks 2-6 depend on Task 1; Task 3 on 2;
Task 4 on 3; Task 5 on 4; Task 6 on 2 and 5. Do not parallelize tasks sharing
`port_wasm_units.py`.

## Refusal conditions and boundaries

Always: preserve private candidate and immutable evidence; validate all
digests at use; emit exact receipts; use path-scoped Git operations; run
focused/full tests and Ruff; keep behavior tier explicit.

Ask first: product schema regeneration/commit, changes to journal schema,
promotion ordering, dependencies, CI, public fixture policy, or any live
resume/retry/push.

Never: accept unversioned registry as v1; use advisory knowledge as owner
authority; choose among ambiguous definitions; edit verbatim bodies or
canonical product artifacts; call an LLM for composition failure; hand-edit
state; settle c0018/c0035 as structural; publish private candidate bytes;
claim historical hash reproduction without bytes; mutate OMR; push to OGhidra
`origin`.

Implementation and live acceptance must refuse when any of these holds:
wrong/missing schema, unstable registry/source/state, path escape or special
file, owner range/prototype drift, zero/multiple owner, selected direct-owner
contradiction, candidate/window digest drift, unavailable precise attribution,
unbound/changed compiler, inspector, Node, flags, or smoke identity; immutable
manifest/transition/state-projection mismatch; journal receipt mismatch;
unexpected Git diff/ref movement; dirty overlapping paths; private fixture
mismatch; or missing human approval.

## Live acceptance sequence (after review and implementation only)

1. Re-run both `ls-remote` commands and record exact heads; require the reviewed
   OGhidra implementation commit and clean intended diffs.
2. Pause through `D:\rig\state\manual-gate.json`; wait for
   `mode=manual-paused`, `driver_pid=null`, and `release_verified=true`. Never
   raw-kill. Take stable hashes of state, events, gate, registry, and owner
   ranges.
3. Run product schema generation twice, require byte-identical second output,
   run schema tests, inspect only the five Task-1 paths, and obtain explicit
   owner approval before committing them.
4. Run focused and full OGhidra commands from fresh D:-backed basetemps. Run
   public tests with the private variable absent. Run the private lane only if
   an approved authoritative root passes exact inventory and digest checks.
5. Install/merge only reviewed commits using the documented product and fork
   remotes. Confirm no unexpected ref, state, gate, or task movement.
6. Unpause through the manual gate. For each retained c0018/c0035 candidate,
   require one candidate-bound composition lifecycle with zero new model and
   diagnosis calls. If exact historical bytes were not recovered, label the
   run a fresh-candidate acceptance and do not claim historical reproduction.
7. Require canonical owner receipts, precise contributor sets, link/smoke,
   journal receipt, promotion transaction, explicit `port-staging` push, and
   exact `port-progress` receipt. Verify remote tips with `git ls-remote`.
8. Confirm compile-only remains `UNVERIFIED`, state/events/gate agree, no
   orphan attempt exists except intentional `assembly-blocked` retention, and
   the next unit is not selected until the prior transaction is durable.
9. On any refusal, pause through the gate, preserve the private attempt and
   receipts, perform RCA, and make no manual state correction.

## Success criteria and unresolved questions

Review is complete when the owner accepts this interface, schema change,
fixture split, task graph, refusals, and live sequence. Implementation is
complete only when every public test/verification command passes, exact
receipts prove the contract, and live acceptance produces no false tier or
publication.

Unresolved:

1. Where are authoritative byte-exact directories for historical candidates
   `e96ef433...` and `04243bba...`? Until recovered, private historical tests
   must refuse and these values remain evidence-only.
2. Should blocked private attempts have a retention limit? Recommendation:
   retain until a journaled pass, explicit reviewed abandonment, or verified
   superseding candidate; never time-based deletion.
3. Product Task 1 crosses the OGhidra repository seam and requires a separate
   approved product commit. The exact integration/merge order must be chosen
   by the owner before implementation begins.
