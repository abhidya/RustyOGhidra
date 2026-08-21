# D5 — the int→double idiom miscompiles under the integer seed: fix design (v1, for adversarial review)

Status: DESIGN ONLY — no implementation ships with this doc. Companion to
`compile-fix-loop-design.md` v4; amends its seed-header world-state (the
"integer `undefined8`/`CONCAT44`" line in the v4 status header acquires the
defect described here) and proposes the resolution of the T2b `undefined8_fork`
conflict class (`t2b-backfill-report.md`, Class 1). Section references of the
form §2.x are into the v4 design unless prefixed D5-.

**World state at writing (verified in-repo, 2026-08-21; every number in this
doc was recomputed from the working tree tonight, not carried from the defect
memo):** driver LIVE on `main` (OGhidra `6d14ed1`, T1+T2a+T2b+T2c+T3 landed);
19+5 units staged/verified; assembly gate running rolling N=5 windows;
registry in advisory mode.

## D5-0. The defect, mechanism first

`gnt4_shim_seed.h:45` (and the identical macro in the driver `SYSTEM_PROMPT`,
`src/port_wasm_units.py:165`) defines the Tier-0 canonical pseudo-op:

```c
#define CONCAT44(hi, lo) \
  (((unsigned long long)(unsigned int)(hi) << 32) | (unsigned int)(lo))
```

Ghidra's decompilation of Gekko code emits the PPC int→double idiom as

```c
(double)(float)((double)CONCAT44(0x43300000, x ^ 0x80000000) - DOUBLE_80439e88)
```

On the original hardware this sequence is a **bit reinterpretation**: the
compiler stores `0x43300000` into the high word and the sign-flipped integer
into the low word of a stack slot, reloads the 8 bytes with `lfd`, and
subtracts the magic constant 2^52+2^31 — because the PPC750 (Gekko) **has no
fcfid instruction**; the magic-number dance IS the architecture's only
int→double conversion. Ghidra's `(double)` cast on the CONCAT44 result models
the `lfd`: a *retype of bits*, not a value conversion.

Under the integer macro, C semantics read the same tokens as **arithmetic**
u64→f64 conversion: `CONCAT44(0x43300000, 100 ^ 0x80000000)` ≈ 4.85e18, cast
to double arithmetically, minus 2^52 leaves ≈ 4.85e18, and every downstream
`(short)(int)` truncation saturates (`i32.trunc_sat` in the emitted wasm).

**Probe evidence (adversarial verification, 2026-08-20/21):** the staged
`auto-c0035-002` wasm, `FUN_80131688`, which reads the s16 at
`param_9+0x1900`, converts it via the idiom, scales by `FLOAT_80439e80`, and
stores it back (`unit.c:47-51`) — probed directly with inputs 100, 50, −200,
0: **every input produced −1** (saturation → 0x7fffffff → low 16 bits). The
unit is compile-green, link-green, import-green, and behaviourally wrong on
every input. This is the exact failure class the compile-only tier was
predicted to hide, now demonstrated: **no compile diagnostic can ever catch
it, and no header edit can ever fix it** — the `(double)` cast is inside the
verbatim, LLM-uneditable `unit.c`.

## D5-1. Evidence base (recomputed from the trees tonight; method stated per number)

Scanner: paren-matching, whitespace/newline-tolerant between all tokens
(including inside the cast's own parentheses — one fleet site wraps
`(\n double)CONCAT44`, which single-line grep misses). Comments and string
literals do not occur inside the matched shape in either tree.

**Staged trees** (`research/decomp/port-units-staging/`;
`research/decomp/port-units/`, 3 oracle-green PoC units). **Snapshot
semantics [R1]: this table is a dated census run, not a stable fact — the
live driver stages new units continuously (between this doc's first commit
and its review, hours apart, the driver staged five more idiom-bearing
integer-seed units: auto-c0035-006 (5 sites), auto-c0011-004 (4),
auto-c0011-012 (3), auto-c0011-011 (1), auto-c0019-000 (1)). The scanner is
the authority; the table is its 2026-08-21 output.** Original-snapshot rows
kept, refresh rows added:

| Unit | Sites | `CONCAT44` macro | `undefined8` | Idiom result today |
|---|---|---|---|---|
| auto-c0001-011 | 14 | integer | ull | **WRONG** (arithmetic conversion) |
| auto-c0001-014 | 12 | integer | ull | **WRONG** |
| auto-c0035-002 | 3 | integer | ull | **WRONG** (the probed unit) |
| auto-c0034-018 | 1 | integer | ull | **WRONG** |
| auto-c0035-006 | 5 | integer | ull | **WRONG** (staged after first commit) |
| auto-c0011-004 | 4 | integer | ull | **WRONG** (staged after first commit) |
| auto-c0011-012 | 3 | integer | ull | **WRONG** (staged after first commit) |
| auto-c0011-011 | 1 | integer | ull | **WRONG** (staged after first commit) |
| auto-c0019-000 | 1 | integer | ull | **WRONG** (staged after first commit) |
| auto-c0001-012 | 7 | union bit-cast | double | correct at idiom sites; fork-conflicted (T2b Class 1) |
| auto-c0001-003 | 6 | union bit-cast | ull | correct at idiom sites; half-converted (T2b) |
| auto-c0000-006 | 2 | union bit-cast | double | correct; fork-conflicted |
| auto-c0001-004 | 1 | union bit-cast | double | correct; fork-conflicted |
| auto-c0001-007 | 1 | union bit-cast | double | correct; fork-conflicted |
| auto-c0001-010 | 1 | union bit-cast | double | correct; fork-conflicted |
| damage-core (oracle-green) | 1 | union bit-cast | double | correct (PoC island) |
| other site-free staging units + collision-core, knockback-core | 0 | — | — | unaffected |

Totals, 2026-08-21 refresh: **62 idiom sites across 15 staging units**
(first-commit snapshot: 48/10; the defect memo's "42" was additionally a
single-line-grep undercount — 6 sites wrap the `CONCAT44(0x43300000,`
across a line break), plus 1 site in oracle-green `damage-core`. Of the 62:
**44 sites in 9 units are computing wrong values in the staged artifacts
today** (integer macro; 30/4 at first commit — the delta is one night of
driver output, which is the mint-rate datum D5-6's provision prices in);
the other 18 sites in 6 units are correct only
because those units still carry the PoC union macro — i.e. they are exactly
the T2b `undefined8_fork` cohort scheduled for re-port under the integer
seed, at which point **their 18 sites would silently join the broken set**.
The defect and the fork are one problem: T2b's "canonical = integer"
resolution is unsound as written, because the integer seed miscompiles the
idiom that the double seed existed to serve.

**Fleet** (`research/decomp/ghidra-export/chunk_*.c`, 80 chunks — the source
every future unit extracts from):

- **2,229 `CONCAT44(` call sites** total.
- **2,143 (96.1%) have a `(double)` cast applied directly** to the call (or
  to a parenthesized expression whose leftmost operand is the call). Spread
  over 77 of 80 chunks — this is not a corner case, it is the dominant use.
- **`(double)` is the ONLY cast ever applied directly to a CONCAT44 call**
  in the entire export (scanned for float/int/uint/short/char/longlong/
  ulonglong/undefined8: zero hits). There is no arithmetic-conversion use to
  protect — consistent with the hardware argument above: on a Gekko binary,
  a `(double)`-of-CONCAT44 is a reinterpretation *by construction*.
- **86 sites (3.9%) use CONCAT44 as a plain integer** — the reason Tier-0
  abandoned the double-returning macro (a double CONCAT44 makes
  `CONCAT44(...) ^ 0x80000000` a constraint violation and the unit cannot
  compile). Both cohorts are therefore wrong fleet-wide: the double macro
  cannot compile 86 sites; the integer macro miscompiles 2,143.
- **18 of the 2,143 have a non-`0x43300000` high word**: hand-assembled IEEE
  doubles — copysign (`local_18._0_4_ & 0x7fffffff | local_10 & 0x80000000`),
  exponent construction (`... + in_r6 * 0x100000`), a `>> 0x20` hi-word
  round-trip. All are bit reinterpretations too; a fix anchored on the
  `0x43300000` constant would silently miscompile them later.
- **0 dataflow-separated sites**: no case where a CONCAT44 result is assigned
  to a variable that is later `(double)`-cast (scanned assignment→cast within
  each chunk). The lexical shape is the complete shape, today.
- 24 `SUB84(` sites — the *reverse* idiom family (double bits → integer
  halves). None staged yet; out of D5 scope; filed as the D6 watch item
  (D5-8, F-D5-9).

## D5-2. Idiom grammar (all variants present in the trees)

Variants, with counts (fleet / staged as of the 2026-08-21 refresh):

| # | Shape (normalized) | Fleet | Staged |
|---|---|---|---|
| V1 | `(double)CONCAT44(0x43300000, X ^ 0x80000000) − M` — signed, xor inside lo, subtract adjacent | 1,272 | 21 |
| V2 | `(double)(CONCAT44(0x43300000, X) ^ 0x80000000)` — signed, xor OUTSIDE on the u64 (flips lo bit 31; same value), subtract usually deferred | 170+59* | 8+4* |
| V3 | `(double)CONCAT44(0x43300000, X) − M` — unsigned, subtract adjacent | 603 | 29 |
| V4 | V1/V3 with the subtraction textually deferred (result stored to a `double` local, `− M` on a later statement) | 79 | 5 |
| V5 | `(double)CONCAT44(E_hi, E_lo)` — non-magic high word (copysign / exponent assembly) | 18 | 0 |

\* the two deferred-xor rows overlap V4's counting; the union of all rows is
the 2,143. `M` is either a `DOUBLE_<addr>` macro (2^52 or 2^52+2^31, address
varies per chunk: `DOUBLE_80436f88`, `DOUBLE_80436b30`, `DOUBLE_80436bd0`,
`DOUBLE_80439e88`, …) or a `double` local previously loaded from one. `X` is
arbitrary: casts, memory reads, locals, `(int)short`, `(uint)byte`.

**The load-bearing observation: the variants only differ in material the fix
does not touch.** The xor is correct integer arithmetic under the integer
macro (V2's u64 xor and V1's u32 xor produce the same low-word flip); the
subtraction is correct *double* arithmetic once the bits are reinterpreted;
`X`, `M`, adjacency, and the high word are free. The single broken atom, in
every variant, is the same: **a C value-conversion `(double)` cast where the
original semantics are a bit reinterpretation.** So the transform grammar is
one rule, not five:

> **G:** a `(double)` cast token sequence whose operand, after skipping at
> most one opening parenthesis, begins with a `CONCAT44(` call — i.e. the
> cast applies to (i) the call itself, or (ii) a parenthesized expression
> whose leftmost primary is the call (V2's xor-outside shape). Whitespace and
> newlines may appear between any two tokens, including inside `( double )`.

G matches all 2,143 fleet sites and all 63 staged sites, subtractions and
xors untouched. G deliberately does **not** condition on `0x43300000` (V5),
on the xor, or on the subtraction — matching on those would trade a complete
census-verified shape for a fragile pattern-of-patterns.

## D5-3. Where to fix — options

### (a) Deterministic materialization-time transform — RECOMMENDED

Rewrite, at the point where `unit.c` text is materialized from the export:

```c
/* V1/V3/V5: cast directly on the call */
(double)CONCAT44(H, L)            →  __gnt4_bitcast_f64(CONCAT44(H, L))
/* V2: cast on a parenthesized expr whose leftmost primary is the call */
(double)(CONCAT44(H, L) ^ K)      →  __gnt4_bitcast_f64(CONCAT44(H, L) ^ K)
```

with one helper added to `gnt4_shim_seed.h` (name verified: zero occurrences
anywhere in the export or staged trees):

```c
/* PPC lfd-of-assembled-bits: reinterpret a u64 bit pattern as an IEEE754
 * double. The extraction transform (D5) rewrites Ghidra's reinterpretation
 * casts `(double)CONCAT44(...)` to this helper; a bare (double) cast on an
 * integer in unit.c is then always a genuine value conversion. */
static inline double __gnt4_bitcast_f64(unsigned long long __u) {
  union { unsigned long long u; double d; } __b;
  __b.u = __u;
  return __b.d;
}
```

(The union bit-cast is the construction the PoC's oracle-green units already
proved on this toolchain; emcc/clang compiles it to a single
`f64.reinterpret_i64`.)

**Placement — the driver's materialization step, NOT the queue generator.**
The defect memo frames this as "the queue generator recognizes the idiom",
but the queue (`wasm-units.json`) stores *line ranges*, not text; the text is
materialized by `extract_verbatim()` (`src/port_wasm_units.py:280`) at build
time, at three call sites: the main flow (`:1898`), the §2.12(b) diagnosis
prompt (`:2783`), and the F4 offline replay (`:3327`). Transforming at
generation time would require persisting transformed text in the queue — a
second provenance channel that can drift from the export. Transforming at
materialization keeps the queue format byte-identical, applies to all 1,396
queued units and all future re-extractions with zero queue migration, and
puts the transform version under the driver git rev — which is already a
**world-hash component (§2.8)**, so landing it is automatically a
world-delta for every red (see D5-5).

Concretely:

- `extract_verbatim()` **stays byte-faithful, untouched** — its test
  (`test_extract_verbatim_is_byte_faithful`) keeps passing unmodified. The
  transform is a separate pure function
  `rewrite_fp_reinterpret(text) -> (text, n_sites)` applied to the verbatim
  blocks *after* the original-text hashes are recorded.
- The three materialization call sites are folded into one
  `materialize_unit_c(unit) -> (unit_c, extraction_records, transform_record)`
  so the built unit, the diagnosis prompt's "verbatim (read-only)" display,
  and the F4 replay can never diverge on whether the transform ran. (The
  diagnosis prompt showing transformed text is correct: the question is "why
  can no header fix *what compiles*".)
- The scanner is token/paren-matching (the grammar G), not a regex over
  lines; it is deterministic, idempotent (`__gnt4_bitcast_f64(` never matches
  G's cast prefix), and **identity on site-free text** — the property the
  migration leans on (D5-6).

**Verbatim-invariant analysis.** The invariant's *contract* — stated in the
seed comment, the assembly gate ("definitions live in the verbatim unit.c
files, which are uneditable"), and the diagnosis prompt — is that **the LLM
never edits unit.c**; every LLM degree of freedom lives in the header. That
contract is untouched: the transform is deterministic, versioned, reviewed
code, the same trust class as `extract_verbatim`'s marker-driven slicing and
the generator's mechanical scaffolding (prefix-derived `GC_*` widths, the
DAT_-lvalue and PTR_-is-a-name rules of `b19ed78`/`a614928` — generation
already *interprets* Ghidra output mechanically; it has just never rewritten
body text before). What changes is the invariant's *wording*: from "unit.c
is byte-verbatim from the export" to

> **unit.c is a deterministic function of (export text, extraction spec,
> transform version), with both pre- and post-transform hashes recorded; the
> LLM never edits it.**

The property reviews actually rely on — reproducibility and
LLM-unforgeability — survives; the property given up — byte-identity with
the export — was already false for semantics (byte-identity is what
*produces* the miscompile). One rule to keep the wording honest: **the
transform's output must remain semantically traceable line-by-line** — G's
rewrite is intra-expression, adds no lines, reorders nothing, so
`/* ==== VERBATIM: file start-end ==== */` markers keep their meaning
(renaming the marker to `VERBATIM+D5` is included so the artifact never
claims byte-fidelity it no longer has).

### (b) Make CONCAT44 return a union/struct with implicit conversions — impossible in C, concretely

The wish: a `CONCAT44` whose result converts to `double` as bits and to
integer as value, resolving per use site. C has no user-defined conversions;
every concrete encoding fails on one cohort or the other:

- **Return a union** `union u8 { unsigned long long u; double d; }`:
  `(double)CONCAT44(...)` is a cast of a union type — a **constraint
  violation** (C11 6.5.4p2: cast operand must be scalar). The 2,143 sites
  stop compiling. And the 86 integer sites (`CONCAT44(a,b) ^ c`,
  `CONCAT44(a,b) >> n`) violate 6.5.10/6.5.7 (operands must have integer
  type). Both cohorts die at once.
- **Return double + union bit-cast inside** (the PoC macro): the 2,143
  fp sites work; the 86 integer sites are constraint violations (`^` on a
  double). This is precisely why Tier-0 abandoned it — re-adopting it
  re-breaks the queue's general population.
- **`_Generic`**: selects on the *type of an operand you already have*, not
  on the *context the result flows into*. The macro cannot see the enclosing
  `(double)` cast; C has no result-type overloading. Dead end by language
  definition, not by cleverness deficit.
- **`__attribute__((transparent_union))`**: applies to function *parameters*
  only — it makes a union accept multiple argument types, it does nothing
  for a *returned* value's conversions.
- **Compile units as C++** (conversion operators would genuinely work, and
  `extern "C"` would keep the export/import seam un-mangled): still
  rejected on proportionality and semantics — it changes the language of
  verbatim code that is C by construction (Ghidra emits C; preludes,
  casts, and implicit conversions assume C semantics, and C++ diverges
  exactly in the conversion rules this defect lives in), forcing
  revalidation of the entire staged corpus + oracle harness. A toolchain
  migration to fix one idiom is out of all proportion, and reviewability
  of "C++ now compiles this differently where?" is hopeless.

No preprocessor or type-system construct can make one expression have two
types depending on its consumer. The fork exists because C forces a choice
per *token sequence*; the only way to serve both cohorts is for the two uses
to be **different token sequences** — which is exactly what option (a) does.

### (c) Per-site LLM header guidance via the knowledge registry — insufficient by construction

The registry (§2.11) can inject advice and the prompt can carry rules, but
every lever they own edits the **header**. The broken atom is a cast
*inside* `unit.c`, which the LLM is forbidden to touch (and the driver never
applies model output to it). No header text can intercept a cast expression:

- `#define double ...` in the header would rewrite every *declaration*
  (`double dVar3;`) as well as every cast, including the correct
  `(double)(float)` promotion chains — instant, total miscompilation, plus
  redefining a keyword is undefined behavior territory (C11 7.1.2's spirit;
  clang warns and the fingerprint fills with noise).
- A `CONCAT44` redefinition is the fork itself — either flavor breaks one
  cohort (option b).
- Guidance could only teach the model to *work around* wrong values it can
  never observe (compile-only units run no behavior) — there is no
  diagnostic to react to; the loop's information channel carries nothing
  about this defect. §0.1 seals it: spending model calls on a defect with a
  known deterministic fix is the definition of the waste the owner principle
  forbids.

The registry still has a supporting role (D5-5): the helper and macro become
seed-tier knowledge, and the SYSTEM_PROMPT gains one rule so the model never
"repairs" the helper.

### (d) Other options considered and rejected

- **Rewrite `ghidra-export/chunk_*.c` in place** (fix the source of truth
  once): contaminates the ground-truth layer every provenance hash chains
  to; invalidates the recorded per-range sha256 of every staged unit and the
  T2b prelude cross-checks; unreproducible against a future re-export from
  the Ghidra project; and re-export would silently resurrect the defect.
  The export must stay exactly what Ghidra said.
- **Post-process the wasm** (rewrite `f64.convert_i64_u` →
  `f64.reinterpret_i64`): by the time emcc has optimized, the conversion may
  be folded, strength-reduced, or fused; matching it is heuristic,
  unauditable against source, and silently incomplete. Rejected on
  reviewability alone.
- **Teach the oracle tier to catch it instead of fixing it**: oracles are
  the *acceptance gate* for the fix (D5-7) and would eventually catch each
  affected unit one at a time — at a median 16.1-min-per-call re-port cost
  per catch, against a defect whose complete fleet census is already known.
  Detection is not a substitute for a deterministic repair.

## D5-4. Provenance semantics

Current records (per staged `provenance.json`): per-block
`{file, start, end, sha256(raw)}` + `extracted_sha256` over the concatenated
verbatim. Grep confirms nothing outside `port_wasm_units.py` consumes
`extracted_sha256` today; the sidecar binding key is `exports_sha256`
(untouched — export sets do not change).

Rule: **provenance answers two different questions; record both, conflate
neither.**

- *"Is this really what the export says?"* — the per-block `sha256` and
  `extracted_sha256` stay **pre-transform**, computed on raw extracted bytes
  exactly as today. The chain export → extraction is unbroken; an auditor
  can re-slice the chunk file and match hashes without knowing the transform
  exists.
- *"Is this artifact the output of transform vN?"* — a new provenance block:

  ```json
  "transform": {
    "name": "d5-fp-reinterpret",
    "version": 1,
    "sites": 3,
    "sites_per_block": [1, 0, 2, 0, 0, 0, 0, 0],
    "transformed_sha256": "<sha256 of the concatenated post-transform verbatim>"
  }
  ```

  `version` is a code constant bumped on any grammar change (belt to the
  driver-rev suspenders: per-unit staleness becomes decidable from the
  artifact alone, no git archaeology).

**Staleness predicate, generalized [R2]** — an artifact is D5-stale iff

```
no transform key                                       (pre-D5 artifact)
∨ ( transform.version < current
    ∧ T_current(extractions) ≠ transform.transformed_sha256 )
```

The first disjunct is the migration census (D5-6); the second covers every
future grammar bump: an artifact built by an older transform whose *output
would now differ* is stale, while an old-version artifact whose bytes the
current transform reproduces is re-stamped in place (version bump in
provenance, no rebuild — the identity case). **Policy [R2]: a green whose
recorded `transformed_sha256` differs from the current transform's output is
revoked through the same `verdict_revoked` journal path as the D5-6
migration — never rebuilt-in-place around a settled verdict, and never
hand-edited in state.** Absence-of-key and version-stale-with-differing-
output are thereby one predicate with one consequence, mechanically
evaluable from the artifact alone.

## D5-5. Interactions with the running mechanisms

- **World-hash / retry gating (§2.8).** The driver git rev is a world-hash
  component, so landing the transform re-opens **every** red — not only
  D5-affected ones. Intended and safe: the §2.8 ordering heuristic
  (error-class match first) sorts the flood, and reds whose failure had
  nothing to do with fp will fail again into `waiting_world_change` at one
  attempt's cost each, per the design's own economics. No new world-hash
  component is needed (the transform version rides the driver rev); the
  provenance `transform.version` (D5-4) is what makes *green* staleness
  decidable, since greens are outside the world-hash's jurisdiction.
- **Greens are settled — revocation must go through the journal (§2.9
  [V4-9]).** The 10 affected staged verdicts cannot be hand-unsettled
  (AGENTS.md: the 2026-08-20 out-of-band migration is the standing
  counterexample). Migration uses the sanctioned settle CLI family extended
  with a `revoke-unit --reason d5 ...` path emitting `verdict_revoked`
  events — the event kind §2.9 already names.
- **T2b assembly gate / parsers.** The gate's header-merge and
  prelude-cross-check layers parse *headers* and *prelude prototypes*; the
  transform edits only verbatim body expressions — no parser sees a
  difference. The helper lands in the seed, so every merged header carries
  one identical seed-inherited definition (`static inline`, so even a
  hypothetical duplicate is benign, but the merge's seed-dedup means there
  is exactly one). The gate's Class-1 `undefined8_fork` conflicts drain as
  rebuilt units enter windows; `largest_n_passed` stays a high-water mark
  per the recorded advisory (dashboards read `last_run`).
- **T2c registry.** The helper + integer CONCAT44 + integer undefined8 are
  **seed-tier** entries; the harvest's seed-inherited exclusion [V4-1]
  guarantees no unit ever "harvests" them back as its own decision. One
  SYSTEM_PROMPT addition (PROMPT_VERSION bump — itself a world-delta):
  *"`__gnt4_bitcast_f64` is seed-provided; never redefine, wrap, or remove
  it; a `(double)` cast you see in unit.c is a genuine value conversion."*
  The oracle-tier semantic survival check (§2.11 [V4-6]) applies to the
  helper like any authoritative seed line once the registry carries it.
- **Structural classifier / void-result detector.** Runs on transformed
  text; the helper is a declared double-returning function — no new shapes.
  The §2.7 concrete-type case is unaffected (the transform removes
  `(double)`-on-integer sites, i.e. strictly shrinks the population of
  suspicious casts).
- **Oracle sidecars.** Bound by `exports_sha256`; export sets unchanged;
  sidecars survive the migration untouched.

## D5-6. Migration

Census predicate (mechanical): **D5-stale per D5-4 [R2]** — lacks
`transform` key (∨ version-stale with differing output, for future bumps) —
∧ transform-on-its-extractions is non-identity. For site-free artifacts the
transform is identity, so **their artifacts and verdicts stand** — asserted,
not assumed, by the identity check (`transformed_sha256 ==
extracted_sha256`, stamped at their next routine touch; no revocation, no
rebuild).

**The predicate, not any unit list, is the migration input [R1].** This
doc's first commit named four wrong-today units; the live driver staged
five more idiom-bearing integer-seed units within hours (D5-1), silently
obsoleting the list while the predicate stayed exactly correct. A migration
step that names units contradicts the census it defines. So:

Order of operations:

1. **Land the transform + helper + prompt rule + tests** (D5-7 gate items
   1–2 green) behind the cooperative driver recycle, like every tranche.
2. **Revoke-and-requeue every integer-macro unit the census predicate
   selects, EVALUATED AT MIGRATION TIME** via the journal revocation path
   (as of the 2026-08-21 refresh the predicate selects 9 units / 44 sites:
   c0001-011, c0001-014, c0011-004, c0011-011, c0011-012, c0019-000,
   c0034-018, c0035-002, c0035-006 — recorded here as the current
   evaluation, never as the input). Cost honesty: these go green cheaply
   (c0035-002: 1 iteration, 0 model calls) and the transform *removes* the
   hardest header decision, so expected re-port cost is ~0–2 model calls
   per unit; worst case is a normal attempt. Their harvested registry
   entries: all are `compile_only`-tier; revocation triggers the [V4-7]
   demote path (tombstoned where sole-sourced) and re-harvest on the new
   green re-supplies them — no special case.

   **Mint-rate provision [R1]: minting of D5-wrong greens CONTINUES until
   step 1 lands — accepted, not gated.** The alternative — holding back
   pending units whose extractions contain idiom sites — would gate on a
   property of 96.1% of the fleet's CONCAT44 uses spread over 77 of 80
   chunks: effectively pausing the pipeline for the fix's landing time,
   spending the driver's only irreplaceable resource (wall-clock GPU
   throughput, G2/G3) to avoid rework that costs ~0–2 model calls per
   affected unit and is swept up by the same predicate evaluation either
   way. Each night of continued minting adds roughly what tonight added
   (5 units / 14 sites — the measured mint-rate datum, D5-1); the rework
   stays strictly cheaper than the stall unless landing slips by weeks.
   Bound, so the acceptance is falsifiable rather than open-ended: if the
   transform has not landed within 14 days of this doc's acceptance, or if
   predicate-selected units exceed 40, the choice is re-decided at §4-page
   level (the census script makes the count a one-command check) — that is
   a re-decision trigger, not an automatic gate.
3. **Revoke-and-requeue the 6 union-macro staging units** (c0000-006,
   c0001-003, c0001-004, c0001-007, c0001-010, c0001-012 — with c0000-004,
   c0000-008, c0000-018, c0001-005, c0002-001, the rest of the T2b
   double-cohort, whose re-port the backfill report already ordered). Under
   transform + integer seed their idiom sites compile to the helper and
   their old fork headers are never re-created. This step *is* the T2b
   Class-1 resolution, now sound.
4. **PoC island experiment** (the 3 oracle-green units — the only units
   with behavioral proof to lose). The transform makes unification
   *testable* instead of forced: re-materialize collision/damage/
   knockback-core from their extraction specs under integer seed +
   transform (damage-core's 1 idiom site becomes the helper; the other two
   are site-free), rebuild, **re-run their real oracles**. Oracle-green ⇒
   the fork is dead everywhere, one canonical seed, T2b Class 1 closed.
   Oracle-red ⇒ their double-typedef headers encode something the census
   missed (e.g. `undefined8` locals genuinely used as doubles outside the
   idiom); the island stays sealed and excluded from assembly windows
   (status quo per the backfill report), and the failure is a filed
   finding, not a regression — their current verdicts are never revoked
   until the rebuilt units pass. **Until step 4 completes, fix and island
   coexist**; the fix does not depend on unification, it only enables it.
5. Queue-wide: nothing. The 1,372 pending units simply materialize through
   the transform on their first build.

## D5-7. Acceptance gate (measurable, in order)

1. **Transform unit tests** (blocking): one golden in/out pair per variant
   V1–V5, a multi-line-wrapped site (including the `(\n double)` cast
   split), the xor-outside shape, a non-magic-hi shape, idempotence
   (`T(T(x)) == T(x)`), identity on site-free text, and a negative test
   that `CONCAT44` *without* an adjacent `(double)` cast (integer cohort)
   is untouched.
2. **Residual census = 0** (blocking, becomes a permanent test): the D5-1
   scanner over every built `unit.c` in both staged trees reports zero
   remaining `(double)`-on-CONCAT44 sites after migration steps 2–3.
3. **The pilot probe flips** (blocking): rebuilt `auto-c0035-002`,
   `FUN_80131688`, same harness as the adversarial probe — s16 inputs
   {100, 50, −200, 0} at `param_9+0x1900` must produce four *distinct,
   input-proportional* stored values equal to the PPC-semantics reference
   `(short)(int)((double)(float)(double)x * FLOAT_80439e80_value)` — and
   specifically not −1. (ROM-correct by construction of the reference; the
   probe becomes the regression fixture named in the defect memo.)
4. **`auto-c0035-002` oracle re-run green** once its sidecar exists (oracle
   workstream); until then item 3 is the behavioral gate and the unit stays
   `compile_only` like its cohort — the fix does not upgrade tiers.
5. **Assembly-gate window**: a rolling window containing ≥2 rebuilt units
   links + instantiates with **zero `undefined8_fork` conflicts filed** for
   the rebuilt set.
6. **PoC island** (step-4 outcome, non-blocking for D5 itself): 3/3 oracle
   re-runs green ⇒ record fork closed; any red ⇒ island finding filed with
   the failing oracle diff attached.

## D5-8. Failure modes (adversarial)

- **F-D5-1: a genuine arithmetic `(double)CONCAT44` exists somewhere.**
  Would be miscompiled *by the transform* into a reinterpretation. Standing
  evidence it cannot: Gekko has no fcfid, so original code physically could
  not convert that way, and the census found `(double)` to be the only cast
  ever applied to CONCAT44 across 2,229 sites. Falsifier: the census script
  runs on every future re-export; a hit halts the transform version bump
  and files for manual review. This is the design's ground assumption,
  stated as such.
- **F-D5-2: dataflow-separated reinterpretation** (`u = CONCAT44(...); …
  (double)u`) — lexically invisible to G. Measured **zero** in the current
  export; but the guard scan ships with the transform and stamps
  `d5_residual_risk: n` into provenance for any unit where a non-cast
  CONCAT44 assignment coexists with a later `(double)<same-identifier>`
  cast; n>0 pages rather than silently building. Cost: one regex pass.
- **F-D5-3: scanner false positives in comments/strings.** The idiom shape
  does not occur in comments today, but the scanner tokenizes
  comment/string-aware anyway (test-pinned) — a chunk containing
  `/* (double)CONCAT44 ... */` must pass through untouched.
- **F-D5-4: the model "repairs" the helper.** The header rewrite each round
  could redefine or shadow `__gnt4_bitcast_f64`. Mitigations: the
  SYSTEM_PROMPT rule (D5-5), the seed-merge replacing rather than
  duplicating, and — once the registry carries it as an authoritative seed
  entry — the [V4-6] semantic survival check filing `registry_deviation`.
  Residual: a deviated-but-compiling redefinition on a green; caught at
  harvest like any authoritative deviation.
- **F-D5-5: provenance consumers assume `extracted_sha256 ==
  sha(unit.c minus header/prelude)`.** Grep found no such consumer; the
  worry is future code. The `transform` block plus the `VERBATIM+D5` marker
  rename make the post-transform state self-describing; a consumer that
  ignores both was reading bytes it never validated.
- **F-D5-6: transform-version drift between the three materialization
  sites.** Killed structurally by the single `materialize_unit_c()` (D5-3a);
  a test asserts the diagnosis and F4 paths share it.
- **F-D5-7: the world-hash flood.** Landing reopens all reds (D5-5);
  bounded by the §2.8 ordering heuristic and by the fact that pending
  (never-attempted) units outrank reds in the selector. Worst case is the
  pre-existing retry economics, not a new class.
- **F-D5-8: half-migrated tree** (transform landed, old artifacts not yet
  revoked): the staged tree then mixes pre/post-D5 artifacts. The census
  predicate (D5-4) makes the mix enumerable at any instant, and gate item 2
  stays red until it drains — the state is visible, not latent.
- **F-D5-9: the reverse idiom (SUB84 family, 24 fleet sites) reaches
  staging before a D6 design exists.** Louder than the D5 shape at every
  layer: the seed defines **no SUB84 macro at all**, so a site fails at
  compile as an undeclared identifier (or, past clang's implicit-decl
  error, at the link/import gate) — never silently. The residual risk is
  the compile-fix loop *authoring* a wrong SUB84 macro to clear that
  diagnostic; the census script watches SUB84 counts in staged trees so a
  first-ever staged site triggers the D6 design review before, not after,
  a model-authored macro settles anything.
- **F-D5-10: counting disputes.** Every number in D5-1/D5-2 regenerates
  from two ~40-line scanner scripts run against the working tree; the memo's
  42-vs-48 delta is explained (line-wrapped sites) rather than averaged.
  If a reviewer's recount disagrees, the scanner, not the prose, is the
  arbiter.

## D5-9. Falsifiers

- **F-D5-A (ground assumption):** any `(double)CONCAT44` site in any export
  revision that is provably an arithmetic conversion (requires exhibiting a
  Gekko-feasible codegen for it) falsifies the reinterpretation-by-
  construction claim; the transform is then demoted from unconditional to
  allowlist-gated. The census script is the standing experiment.
- **F-D5-B:** if the F-D5-2 guard ever fires (dataflow-separated site), the
  lexical-completeness claim is dead; the affected unit blocks until G grows
  a local dataflow rule or the unit is manually dispositioned.
- **F-D5-C:** if a rebuilt unit's re-port costs more than its original port
  (model calls), the "transform removes the hardest header decision" claim
  is wrong — measure across migration steps 2–3 and report in the tranche
  postmortem.
- **F-D5-D:** if the PoC island re-oracle (migration step 4) goes red, the
  double-typedef cohort encoded semantics beyond the idiom; the unification
  claim is falsified for those units and the census must be extended to
  `undefined8`-as-double dataflow before any further cohort canonicalization.

## D5-10. Traceability

| Goal | This design |
|---|---|
| G1 playable, buildable | removes a silent behavioral-wrongness class from 96% of the fleet's fp conversions; unblocks the sound version of T2b Class-1 canonicalization; makes PoC-cohort unification testable |
| G2 no dead ends | deterministic fix, zero model calls per site vs. an undetectable-in-loop defect the LLM could never fix (the cast is outside its edit surface) |
| G3 pushes/heartbeat | migration revocations flow through journal events ([V4-9] rule); census + residual gate are committed tests, not tribal knowledge |
| G4 dead ends killed provably | the probe fixture (gate 3) turns the defect into a permanent regression test; F-D5-A/B keep the ground assumptions falsifiable |
