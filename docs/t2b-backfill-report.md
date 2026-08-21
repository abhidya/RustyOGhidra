# T2b composability backfill — first assembly-gate sweep over the existing green/staged units

Date: 2026-08-21 (sweep `2026-08-21T01:0xZ`, driver rev on top of `bb8cbaa`)
Mechanism: continuous assembly gate, design §2.13 [V4-11] (`src/port_assembly_gate.py`,
CLI `python -m src.port_wasm_units assembly-gate --all`).
Ledger: `research/decomp/data/assembly-gate.json` (GotYaForce tracked data dir).

This is the first time any two units of the port were ever composed. Every
unit below is individually green (3 oracle-green, 16 compile-only staged);
their *mutual* composability was conjecture until this sweep.

## Headline

| Measure | Value |
|---|---|
| Units swept | **19** (3 `port-units/`, 16 `port-units-staging/`) |
| Full 19-unit merge | **FAIL at header merge** — 41 contested conflicts, no silent winner picked |
| Conflict classes | 32 collision_stub, 4 dat_width_divergence, 3 declaration_divergence, 2 undefined8_fork |
| Pairwise-conflicting unit pairs | **126 of 171** (73.7%) |
| Largest mutually-conflict-free subset found (greedy) | **7 units — and it links AND instantiates**: `auto-c0000-004`, `auto-c0000-006`, `auto-c0001-004`, `auto-c0001-007`, `auto-c0002-001`, `damage-core`, `knockback-core` |
| Largest integer-cohort probe | 3 units (`auto-c0035-002`, `auto-c0034-018`, `auto-c0011-005`) link + instantiate |

So the pipeline output is *not* un-assemblable — a 7-unit composition already
produces a loadable wasm under one `emcc` invocation with a merged header and
the shared flat arena. The blockers are exactly the two predicted classes plus
two long-tail classes, all enumerated below with proposed resolutions.

Method note: conflicts were detected at three layers, in order — (1) header
merge (§2.11 precedence, registry-less: any divergence between two units'
declarations of one symbol is contested and fails loudly), (2) header-extern
vs `unit.c`-prelude prototype cross-check (found *empirically* by the first
sweep: the merge cannot see preludes because they live inside the verbatim,
uneditable `unit.c`), (3) the linker itself. Parameter names, `extern`
keywords, and punctuation spacing are normalized away — only real prototype
divergence conflicts. Layers (1)+(2) already account for all 41; no
conflict-free full-set link was reachable to exercise layer (3) beyond the
7-unit probe.

## Class 1 — undefined8 fork (2 conflicts, all 19 units implicated)

The single biggest split: the PoC-era seed types `undefined8` as `double`
with a union-bit-cast `CONCAT44` (the PPC int→double reinterpretation was
folded into the macro); the current generator seed (`gnt4_shim_seed.h`) and
the driver `SYSTEM_PROMPT` mandate `unsigned long long` with a pure-integer
`CONCAT44` and the `(double)`/`^ 0x80000000` idiom left to the caller.

| Symbol | Variant A (double cohort — 11 units) | Variant B (integer cohort — 8 units) |
|---|---|---|
| `undefined8` | `typedef double undefined8;` — c0000-004, c0000-006, c0000-008, c0001-004, c0001-007, c0001-010, c0001-012, c0002-001, collision-core, damage-core, knockback-core | `typedef unsigned long long undefined8;` — c0000-018, c0001-003, c0001-005, c0001-011, c0001-014, c0011-005, c0034-018, c0035-002 |
| `CONCAT44` | union bit-cast returning `double` (same 11 units + c0000-018, c0001-003, c0001-005 — three integer-typedef units still carry the double macro) | integer shift-or — c0001-011 (with a redundant extra cast), c0001-014, c0011-005, c0034-018, c0035-002 |

Note the inconsistency *inside* the integer cohort: c0000-018, c0001-003 and
c0001-005 typedef `undefined8` as integer but kept the PoC double `CONCAT44`
(the model edited the typedef, not the macro). c0001-011 wrote its own
integer variant that differs textually from the seed's.

**Proposed resolution.** Canonical = **integer** (`unsigned long long` +
integer `CONCAT44`): it is what the SYSTEM_PROMPT teaches, what
`gnt4_shim_seed.h` seeds, and the only form that compiles arbitrary chunks
(the double form makes the caller-side `^ 0x80000000` xor illegal).
Mechanically:

1. The 8 staged double-cohort auto units (c0000-004/006/008, c0001-004/007/
   010/012, c0002-001) are `compile_only` inventory, not integrated product —
   re-port them under the current integer seed. The T2b gate code itself is a
   `driver_rev` world-change (§2.8), so they are re-schedulable the normal
   way after unsettling; cheapest is a re-port lane at T3's verification
   queue, or simply accepting new-generation replacements.
2. The 3 oracle-green PoC units (collision/damage/knockback-core) **cannot
   silently adopt the integer macro**: their verbatim `.c` uses
   `(double)CONCAT44(...)` as a *reinterpretation*, so a value-converting
   `(double)` over an integer `CONCAT44` changes semantics. They keep their
   double-flavor headers until re-extracted/re-oracled; until then, exclude
   them from assembly windows (recency-based windows already do). Owner
   decision filed: re-extract with the caller-side idiom, or keep them as a
   sealed PoC island.
3. Fix the 3 half-converted integer units (c0000-018, c0001-003, c0001-005)
   by re-porting; their `CONCAT44` is latently wrong for any integer use
   site even standalone.

## Class 2 — collision stubs (32 conflicts)

Two sub-shapes, one root cause: the generator's default extern stub for an
external callee is `extern int zz_xxx_();` (prefix-derived, arity unknown),
while any unit that *contains the callee's definition* (or saw its call
sites) carries the real prototype. The default stub loses every time.

**(a) header-extern vs header-extern (20 conflicts):**

| Symbol | Default/poorer variant (units) | Informed variant (units) |
|---|---|---|
| `gnt4_PSVECSubtract_bl` | `undefined8` return — c0001-011 | `void` return — 18 other units |
| `gnt4_PSVECAdd_bl` | `undefined8` return — c0001-011 | `void` return — 18 other units |
| `gnt4_PSMTXConcat_bl` | `undefined8` return — c0001-011 | `double` return — c0001-012 |
| `gnt4_PSMTXTrans_bl` | `undefined8` return — c0001-011 | `void` return — c0001-012 |
| `FUN_80047aa4` | `int FUN_80047aa4();` — c0001-010 | `void FUN_80047aa4(int);` — c0001-011 |
| `zz_0006fb4_` | `int ();` — c0001-010, c0001-012 | 16-arg `undefined8 (...)` — c0001-011 vs c0001-014 (arg-12 `int` vs `short *`: three-way) |
| `zz_0007cd0_` | `int ();` — c0001-010 | `void (int,int,int,int)` — c0001-011 vs `void (int,int,char *,int)` — c0001-014 (three-way) |
| `zz_0089100_` | `int ();` — c0001-010, c0001-012 | `void (int,int,int);` — c0001-011 |
| `zz_00076d0_` | `int ();` — c0001-012, c0034-018 | 16-arg `undefined8 (...)` — c0001-011 |
| `zz_0007834_` | `int ();` — c0001-012 | 16-arg `undefined8 (...)` — c0001-011 vs c0001-014 (tail-arg types differ: three-way) |
| `zz_0007c30_` | `int ();` — c0000-006, c0001-012, c0034-018 | 16-arg `undefined8 (...)` — c0001-011 vs c0001-014 (`uint` vs `short *` arg-12: three-way) |
| `zz_00086b8_` | `int ();` — c0000-006, c0001-012, c0034-018 | 16-arg `undefined8 (...)` — c0001-011 vs c0001-014 (`uint` vs `short *` arg-12: three-way) |
| `zz_0009958_` | `int ();` — c0001-012 | `void (int,int);` — c0001-011 |
| `zz_0011ce0_` | `int ();` — c0001-012 | `int (int);` — c0001-011 |
| `zz_0010664_` | `int ();` — c0001-004 | `void (int);` — c0001-003 |
| `FUN_801fe050` | `int ();` — c0001-004 | `void (int);` — c0001-005 |
| `FUN_801fe134` | `int ();` — c0001-004 | `void (void);` — c0001-005 |
| `zz_0045204_` | `int ();` — c0001-004 | `double (short);` — c0001-005 |
| `zz_0045238_` | `int ();` — c0001-004 | `double (short);` — c0001-005, c0001-014 |
| `zz_0007cac_` | `undefined8 (double,int)` — c0001-011 | `double (double,int)` — c0001-014 (return-type fork of the undefined8 fork) |

**(b) header-extern vs unit.c-prelude prototype (12 conflicts).** The
prelude prototype is generated from the chunk markers of the unit that
*defines* the function — it is definition-derived and therefore
authoritative; under a merged header these pairs are hard
`conflicting types` compile errors:

| Symbol | Default header stub (unit) | Definition-derived prelude (unit) |
|---|---|---|
| `FUN_8000f604` | `int ();` — c0001-004 | `void (int,int)` — c0001-005 |
| `zz_0006f98_` | `int ();` — c0034-018 | `int (int)` — c0000-006 |
| `zz_0007ae4_` | 16-arg `undefined8 (... void *, char *, short *, ...)` — c0001-014 (header) | 16-arg `void (... undefined4 *, char *, undefined4, ...)` — c0000-008 |
| `zz_0007cf4_` | `int ();` — c0001-010 | `void (int,undefined4,undefined4,undefined4)` — c0000-008 |
| `zz_0012638_` | `int ();` — c0001-010 | `void (undefined8,undefined8,double×6,int)` — c0001-011 |
| `zz_0012984_` | `int ();` — c0001-010 | 16-arg `void (...)` — c0001-011 |
| `zz_0012e4c_` | `int ();` — c0001-010 | `void (int,undefined4×7)` — c0001-011 |
| `zz_00131b8_` | `int ();` — c0001-010 | 16-arg `void (...)` — c0001-011 |
| `zz_00133f4_` | `int ();` — c0001-010 | 16-arg `void (...)` — c0001-011 |
| `zz_0013690_` | `int ();` — c0001-010 | `void (undefined8,undefined8,double×6,int)` — c0001-012 |
| `zz_0013a28_` | `int ();` — c0001-010 | 16-arg `void (...)` — c0001-012 |
| `zz_0013d80_` | `int ();` — c0001-010 | 16-arg `void (...)` — c0001-012 |

**Proposed resolution.**

1. **Precedence rule (feed to the T2c registry as its first tier-ladder
   case):** definition-derived prelude prototype > call-site-derived full
   prototype > generator default `extern int f();`. All but two conflicts in
   this class dissolve under that rule with no human input.
2. **Generator fix (cheap, structural):** the default stub `extern int
   zz_xxx_();` is the single root cause of 26 of the 32. Teach
   `port_unit_generator` to consult the whole-program manifest for a chunk
   that *defines* the callee and copy its marker prototype instead of
   emitting the arity-unknown default. That prevents every future instance.
3. The genuine three-way disagreements (`zz_0006fb4_`, `zz_0007c30_`,
   `zz_00086b8_`, `zz_0007834_`, `zz_0007cd0_`: c0001-011 vs c0001-014 argue
   `uint`/`int` vs `short *` for arg 12) need the defining chunk's verbatim
   text as arbiter — registry conflict records now exist for each; resolve
   at T2c harvest by reading the definition, not by vote.
4. `gnt4_PS*` SDK seam signatures should be **pinned in the seed header**
   (they are the JS-provided seam; the browser shim's expectations file is
   the source of truth) so a model rewrite can never fork them again —
   c0001-011's `undefined8` returns are model drift, not evidence.

## Class 3 — DAT width divergence (4 conflicts)

| Symbol | Variants (units) | Proposed resolution |
|---|---|---|
| `DAT_803b0720` | `GC_F32` — 17 units (seed-inherited) vs `GC_U32` — collision-core | Both 4-byte, arena-layout-safe; lvalue type differs. 17× `GC_F32` is *seed-inherited* (worthless as evidence — T2c's harvest exclusion exists for exactly this); collision-core's `GC_U32` is oracle-green and hand-derived. Read collision-core's use sites; likely resolution: `GC_U32` (bit-pattern compare), keep `F32` only if the fp read is real. Registry arbitration case. |
| `DAT_803c4e84` | `GC_U8` — c0001-005/007/010/011 vs `GC_IPTR` — c0001-012 | Width disagreement (1 vs 4 bytes) — semantically dangerous. 4 independent (non-seed) `GC_U8` derivations vs 1; audit c0001-012's use site, expected resolution `GC_U8`. |
| `DAT_804361fc` | `GC_U8` — c0001-010/012 vs `GC_IPTR` — c0001-011/014 | 2 vs 2, no majority. Resolve from the verbatim use sites (a byte-indexed table read vs an int load are distinguishable mechanically); file as the registry's first contested-address entry. |
| `DAT_803c7422` | `GC_IPTR` — c0001-012 vs `GC_U8` — c0001-011 | `0x803c7422 % 4 == 2`: an aligned `int` at that address is implausible on PPC. Expected resolution `GC_U8` (or `GC_S16`); audit c0001-012. |

## Class 4 — declaration divergence, long tail (3 conflicts)

| Symbol | Variants (units) | Proposed resolution |
|---|---|---|
| `ABS` | `__builtin_fabs(x)` — 18 units vs `fabs((double)(x))` — c0001-003 | Semantically identical for double args. Canonicalize the seed's `__builtin_fabs` (no `math.h` dependency); regen c0001-003's header at its next attempt. |
| `SQRT` | `(sqrt((double)(x)))` — c0001-003 vs `sqrt(x)` — c0001-005 | Same under default promotion. Canonicalize one form in the seed; trivial. |
| `code` | `typedef void (code)();` — 16 units vs `typedef void code();` — collision-core | The parens are redundant; the two are the *same type*. Either canonicalize the seed form on collision-core's next touch, or teach the normalizer that redundant declarator parens are churn. Zero-risk. |

## What the gate does about all this going forward

- The rolling N=5 gate now runs after **every** green; the current window
  (`c0001-014`, `c0002-001`, `c0035-002`, `c0034-018`, `c0011-005`) fails on
  exactly one unit (`c0002-001`, double cohort) — as the integer cohort
  grows, the window will start passing and `largest_n_passed` becomes the
  honest G1 metric (§10).
- Every conflict above is filed (deduplicated, with first/last-seen and
  occurrence counts) in `research/decomp/data/assembly-gate.json`; failures
  page via `assembly_gate_failed` events (§4 invariant row).
- The T2c registry inherits these 41 records as its opening conflict ledger
  and the precedence rules proposed here as its first tier-ladder inputs.
