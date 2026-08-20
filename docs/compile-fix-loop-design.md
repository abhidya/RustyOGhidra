# Compile-fix loop redesign — defended design (v4, information-monotone workflow)

Status: v1 was adversarially reviewed; all BLOCKING/MAJOR findings were resolved
in v2, each marked `[R#]`. v2's T1 tranche has landed in `src/port_wasm_units.py`
(depth cap 4, stage-aware stuck-abort, deduplicated feedback, re-ask, D14,
`-ferror-limit=0`). v3 redesigned the workflow around an owner principle that v2
violated, marked `[V3-#]`. **v3 was then adversarially reviewed and FAILED** on
one BLOCKING finding (the registry echo chamber, F1) plus ten majors (F2–F11);
v4 applies that verdict in full. v4 changes are marked `[V4-#]` where `#` is the
review finding number.

**World state at v4 (verified in-repo, 2026-08-20):**

- The queue Tier-0 generation fixes LANDED (OGhidra `05b94ea`, GotYaForce
  `9fccede`): `SKIP_PREFIXES` now catches both `gnt4_` and `gnt4-` (996 SDK
  functions were being queued through the hyphen variant); non-C-identifier
  exports (truncated demangled C++) are excluded at generation time, with every
  exclusion recorded in `wasm-units-skipped.json` (996 `sdk_prefix` + 22
  `non_c_identifier`); the queue regenerated **1520 → 1,396 units / 10,954
  exports**; the settled-verdict migration is done (`wasm-units-migration.json`:
  15 verdicts carried on identical export sets, 6 recorded-and-left-pending);
  generated units now start from the generator's own
  `finish-game-port/gnt4_shim_seed.h` (integer `undefined8`/`CONCAT44`,
  matching the driver prompt — the PoC's seed left byte-for-byte untouched).
  49 port tests green.
- T1 is landed in `src/port_wasm_units.py`; the port pipeline is **OFFLINE**
  pending the T2a fixes (§9).

The owner principle, unchanged:

> "If it works on the assumption we retry with the same inputs hoping for
> different results, that is an incorrect use of AI. For LLMs we need to build a
> proper port workflow based on the end-to-end goals."

## 0. Goals (the only source of requirements)

G1. A **playable, buildable** version of the game.
G2. Steady progress; **no time wasted on dead ends**.
G3. **Git pushes are the heartbeat** — absence must mean breakage, detectably.
G4. Dead ends **detected and killed fast**, automatically where provable.

### 0.1 The v3 principle: information monotonicity [V3-1]

Every LLM call must either **(a) carry more information** than the previous call
on the same problem, or **(b) ask a different question**. This holds at all
three timescales:

- **Within a unit** (round N+1 of the compile-fix loop): already monotone — each
  round adds the new compiler diagnostics produced by the previously applied
  header. Kept as-is (§2.2 guards the degenerate case where the diagnostics did
  NOT change).
- **Across attempts on one unit** (attempt N+1 after a red verdict): v2 §2.3's
  primary levers were seed/temperature schedules — **same-information
  resampling**, which the principle forbids as a primary mechanism. Replaced:
  an attempt is scheduled only when the **world has changed** since the last
  verdict, and its prompt carries a **post-mortem** of the failed attempt
  (§2.3, §2.8).
- **Across units of the program**: the queue's 1,396 units [V4-2 count] are
  extractions from ONE program (the whole-program manifest at
  `research/decomp/generated/finish-game-port/whole-program-manifest.json`
  inventories all 11,980 functions, `inventory_complete=true`). Units share
  `DAT_` addresses, typedef conventions, pseudo-op macros, and function
  prototypes — yet today every unit re-derives all of them from the same cold
  seed header. v3 adds a **knowledge registry** (§2.11): green decisions are
  harvested and later units start warmer ([V4-1]: harvested compile-only
  knowledge is *advisory* until behaviourally verified — see §2.11). The
  registry doubles as the header-reconciliation ledger final assembly needs,
  and [V4-11] the **continuous assembly gate** (§2.13) exercises that ledger
  empirically from the first N greens, which turns G1 from a disclaimer into
  a running mechanism (§3, §10).

Corollary used throughout: **a retry whose inputs are identical to the failed
attempt is not scheduled.** Deprioritising is allowed; blind re-running is not.

## 1. Evidence base (recomputed in v2 — [R5]; corrections [V4-9])

The v1 numbers were contaminated: ≥15 of the ~58 "wasted" iterations were
infrastructure outages (cygpath PATH, bash-paren export, banner truncation)
whose fixes are already live — both affected units went green on rerun at
iterations 1–2. Restated on clean data:

- Greens where LLM repair actually happened: **n=7** (not 15; 7 greens linked
  at iteration 1 with no model call, 3 used hand-authored seeds).
  Link iterations: 2,2,2,2,3,3,5 → **1 of 7 (14%) needed >3**.
  Wilson 95% CI for P(>3): [2.6%, 51%]. The sample is small and drawn from the
  first two batches + hand-picked cores — likely easier than the remaining
  1,485 (37% pseudo-op, 29% `(&DAT_)[i]` classes are underrepresented).
- Model-call + build gap, measured (n=118): **median 16.1 min, p90 32.1 min,
  max 107.8 min** (not "25–45 min").
- Failure shape when genuine: oscillation (byte-identical wrong `#define` at
  iterations 3/5/7 under different prompts — prior-driven mode collapse).
  [V3-1 note: mode collapse recurring across *different prompts* at temp 0.7 is
  itself evidence that sampling variation is a weak lever — the fix is
  different *information*, not different dice.]
- Static profile of all units: 6.4% provably unfixable, 37% pseudo-ops,
  29% `(&DAT_)[i]`, 44% clean. [V4-9]: these percentages were computed on the
  old 1,520-unit queue; the Tier-0 regeneration (status header) removed the
  996 SDK functions and 22 non-exportable names (units 1520 → 1,396), so the
  class mix must be recomputed on the new queue before F1's window is scored.
  The split is retained as the *ordering* evidence it was used for, not as
  current absolute truth.
- Greens count, stated precisely [V4-9] (v3 left this implicit): live state
  after the migration is **1,381 pending / 12 green / 3 structural_ineligible
  = 1,396**. Historical green verdicts total 16: 12 carried onto identical
  export sets, 4 chunk_0000 greens recorded in `wasm-units-migration.json`
  and left pending because the SDK skips shifted their batches. The journal's
  16 `wasm_unit_green` events reconcile against this only *via* the migration
  file — see the settle-through-journal rule in §2.9 [V4-9c].

Research (arXiv 2604.10508, 2505.02931, s41598-025-27846-5, 2608.05643): two
repair rounds capture most gains; decay per attempt; diverse independent
attempts beat deep single-chain iteration; noisy feedback degrades repair.
[V3-1 note: the "diverse attempts" finding is honoured by *informational*
diversity (different seed-header content, different question), which subsumes
sampling diversity.]

## 2. The loop redesign

### 2.1 Depth: cap 4 in T1, 3 when T2's recovery lands — G2 [R1][R4] [unchanged]

n=7 with 14% needing >3 does not support a hard 3 while there is no recovery
path — capping at 3 in T1 would strand the >3 class for months behind 1,486
pending units. So: `OGHIDRA_PORT_MAX_ITERS=4` at T1 (landed); drop to 3 only
when the T2 retry lane + carry exist, and only if F1's measurement window
supports it. Within-unit rounds are information-gaining by construction (new
diagnostics each round), so the principle does not force a change here.

### 2.2 Stuck-abort, stage-aware — G2, G4 [R1][R2] [unchanged, landed]

Progress signals are only comparable **within a stage**; crossing a stage
boundary is progress by definition:

- Stages: `compile-errors → link-gate (undefined symbols) → import-gate`.
  A transition between stages NEVER triggers abort — correctly `#define`-ing a
  missing symbol legitimately converts 1 link-gate line into N compile
  diagnostics at the use sites (unmasking, not regression).
- Fingerprint = sha256 of sorted dedup'd diagnostics, with header-located
  diagnostics normalised to `gnt4_shim.h:*: error: <text>` (the model rewrites
  the whole header each round, so raw line numbers churn and mask true
  oscillation). Errors only; the prompt's summary may keep warnings but the
  fingerprint does not.
- Build adds `-ferror-limit=0` so the fingerprint sees the true error set; the
  prompt summariser still truncates (§2.4).
- **Abort when:** the fingerprint is unchanged after a round in which a *new*
  header was actually applied. Rounds where no new header was applied (§2.5
  fallback) are exempt from comparison — and skip the rebuild entirely, since
  the identical input yields the identical output.
- The single "error count increased ⇒ abort" rule is **dropped** (correct
  fixes transiently increase counts; count is not monotone under clang error
  recovery). Count is recorded for selection of the best round, nothing more.

[V3-1 note: the stuck-abort is the within-unit enforcement of the principle —
an applied fix that produced zero informational change ends the attempt.]

### 2.3 Retry = new information, never resampling — G2, G4 [V3-2; coherence fix V4-4]

v2 made seed/temperature schedules the primary retry lever. Killed: a retry
whose only difference is sampling noise is same-information resampling.

**[V4-4] Scheduling vs prompt content — v3 conflated them.** v3 listed the
post-mortem as one of three things that could make attempt N+1 "differ" from
attempt N, implying a post-mortem alone licenses a retry. It does not. A
post-mortem is derived entirely from the failed attempt's own inputs and
outputs — carrying it adds no information *about the world* — so **a
post-mortem alone never makes a retry schedulable**. Scheduling is gated
exclusively by a world-delta (§2.8). The post-mortem is prompt *content*
attached to every retry that the world-delta gate has already scheduled, and
whether it helps at all (vs anchoring the model on the failed trajectory) is
an open question measured by falsifier F7 (§8), not an assumption.

So: an attempt N+1 is **scheduled** only by §2.8's world-changed gate, and its
prompt then differs from attempt N's in:

1. **Post-mortem carry (content, not license [V4-4]).** The retry prompt includes a distilled
   post-mortem of the failed attempt, 5–10 lines, **mechanically extracted**
   from the per-round records the loop already keeps (`rounds[]`: iteration,
   stage, error count, header path — plus final fingerprint and verdict):

   ```
   POST-MORTEM of attempt N (failed <date>):
   rounds: 4; stages: compile, compile, link-gate, link-gate
   best round: 2 (3 errors), header: header-iter2.h
   never cleared: <the diagnostic line(s) present in every round>
   ending: <stuck-oscillation | depth-cap | stage + last error>
   world at failure: registry v<K>, prompt v<P>
   ```

   No LLM writes the post-mortem; it is string assembly from state.

   **Data T2a must record to make this assemblable [V4-4]** — today's
   `rounds[]` keeps only iteration/stage/error-count/header-path, which cannot
   answer "never cleared" mechanically, and `header-iter{I}.h` files are
   overwritten by the next attempt, destroying the artifact the carry decision
   needs:

   - `rounds[]` gains, per round, the **normalized diagnostic set** (the
     §2.2-normalised, sorted, dedup'd error lines) and its **fingerprint** —
     "never cleared" is then a set intersection, and cross-attempt oscillation
     detection becomes a fingerprint comparison.
   - **Per-attempt best-header snapshots under attempt-scoped filenames**
     (`header-attempt{A}-iter{I}.h`), never overwritten by later attempts.

2. **World change since the verdict (the scheduling gate — §2.8).** New
   registry entries intersecting the unit's symbols/addresses, a code/toolchain
   fix matching the unit's recorded error class, or a prompt-rule change. The
   changed input (augmented seed header, fixed toolchain, new system prompt) is
   the informational delta.

3. **A different question (§2.12)** — targeted-symbol or diagnosis prompt
   instead of "fix the whole header" again.

**Carry vs fresh stays conditioned on the abort reason** [R7, kept]: attempt 1
ended with monotone error decrease reaching ≤2 errors → attempt 2 carries the
best header (near-miss worth finishing). Attempt 1 oscillated or regressed →
attempt 2 goes fresh — but "fresh" now means the **current augmented seed**
(§2.11), which differs from attempt 1's seed whenever the registry grew; the
informational delta is the seed content, not the dice. (Fewest-errors remains
gameable — a K&R `int f();` silences arity errors under the existing warning
suppressions — so "best" is advisory, never a green criterion.)

**Sampling variation is demoted to a tertiary lever** and is only permitted
*alongside* an informational delta, never as the sole difference between
attempts. Justification for keeping it at all: two attempts with different
information should also be decorrelated in trajectory (the observed mode
collapse shows the model's prior can dominate the prompt), so a per-attempt
seed accompanies the new information. The seed passthrough (a 5-line client
change; the server accepts it) ships in T2 for this purpose. F2 is redefined
accordingly (§8): it now measures conversion of *world-changed* retries, and
the seed's marginal contribution is measured only as an A/B *within* that
population.

**The post-mortem itself is A/B-tested [V4-4].** Falsifier F7 (§8) runs
post-mortem on/off within world-changed retries and tracks conversion AND the
**resurrection rate** — a `#define` that failed in attempt N re-emitted
byte-identical in attempt N+1. The §1 oscillation evidence (byte-identical
wrong `#define` under *different prompts*) cuts both ways: it motivated
information-carrying retries, but it is equally consistent with the model
anchoring on any prior trajectory shown to it. If anchoring is confirmed, the
post-mortem is reduced to **diagnostics-only phrased as prohibition** ("these
lines were tried and failed; do not re-emit them") and the failed-header carry
is dropped.

### 2.4 Feedback construction — G2 [unchanged, landed]

Prompt compiler-output = `summarise_build_error()` with deduplication
(invocation echo stripped) instead of the raw `(stderr+stdout)[-6000:]` tail.
Operator and model see the same evidence. [V4-9] Budgets as actually landed:
the function's **default budget is 1,200 chars**; the compile-fix call site
passes **2,000** (`src/port_wasm_units.py:313` and `:1058`) — v3's "≤2000"
described only the call site.

### 2.5 Malformed replies are round-level — G2 [R2] [landed; loophole closed V4-9]

One immediate re-ask on no-extractable-header; if that fails, the round is
recorded as `no_new_header` and the loop proceeds without rebuilding (§2.2
exemption). An attempt is never failed over a missing fence. [V3-1 note: the
re-ask is principle-compliant — it adds the one fact the model lacked ("your
previous reply carried no usable code block"), so it is not same-input retry.]

**[V4-9] The landed code has one surviving same-input round.** After the
format-reminder re-ask also fails, the round records `no_new_header` and the
loop `continue`s (`src/port_wasm_units.py:1055-1064` re-ask fall-through) —
the *next* iteration then calls the model with **byte-identical inputs**: same
header (nothing was applied), same summarised errors (nothing was rebuilt),
same base prompt. That is exactly the retry §0.1 forbids, hiding inside the
round-level rule. T2a fix, either arm acceptable:

- a **second consecutive** `no_new_header` round **ENDS the attempt** (red,
  retryable — the world-changed gate then governs, as for any red); or
- the follow-up call must **carry the recorded reply-shape evidence** in its
  prompt ("your last reply was: <shape>; emit exactly one fenced C header"),
  making it informationally distinct the way the first re-ask already is.

The first re-ask is fine; the bug is the unbounded repetition after it.

### 2.6 Oversize handling — G2 [R3] [unchanged]

Preflight (chars/2 vs served context) runs **before the first model call** —
not before the unit, since an oversized unit can still win a free iteration-1
link. On a genuine context fault the unit records `required_tokens` and status
`blocked_oversize`, with honest semantics: **at the current 262,144 serving
maximum this is permanent** unless the model/serving changes; the selector
skips such units while `required_tokens > served`. Queue-wide sizes (median
235 lines, p99 1,142, max 5,030 ≈ 125k tokens) say the affected set at 262k is
plausibly empty — this is a config-regression guard, not a unit classifier.
Status accounting: `blocked_oversize` is excluded from `_work_remains()` only
while blocked, and a pass that settles nothing but oversize units must NOT
return `EXIT_PROGRESSED`. Ships in T2. [V3-2 note: `blocked_oversize` is the
template for §2.8's `waiting_world_change` accounting — same pattern, same
honesty requirement.]

### 2.7 Structural classifier: proven cases only — G4 [R6] [unchanged; §2.12 feeds it]

v1's "every diagnostic points into unit.c involving only locals" is **wrong**:
a local's *type* can be a header typedef, so the header can be the fix even
when the diagnostic line names only locals (the split-statement
`undefined8`/`CONCAT44` idiom produces exactly this shape, and the fix was in
the header). Line-level identifier tests discard dataflow. Therefore:

- Keep the void-result detector (proven: 5 catches, 0 false positives; landed).
- Add **only** the concrete-type case actually observed: a local declared in
  `unit.c` with a concrete built-in type (e.g. `char *local_68`) cast to/from
  an incompatible concrete built-in type, where neither type involves any
  header-defined typedef or macro. Everything else stays retryable.
- **F4 stays executable** [R6]: a monthly bounded recheck — sample up to 5
  `structural_ineligible` units, replay offline with the current loop; any
  that links freezes the classifier to the void-result detector and reopens
  the class. [V3-5]: §2.12's diagnosis question feeds this sample
  conservatively — an LLM "STRUCTURAL" verdict **never settles a unit**; it
  only deprioritises and nominates the unit for the F4 replay sample, where a
  provable outcome decides.

### 2.8 Retry lane → world-changed gating — G2, G4 [V3-4; world-hash + terminal protocol V4-3]

v2's lane preferred reds whose error signature matched a code fix landed after
their verdict (9 of the 13 reds in v2's evidence window). v3 generalises: a
red unit is **schedulable only when the world changed** since its verdict.
"World changed" means any of:

- **Registry delta:** the registry (§2.11) gained or changed entries whose
  symbol/address set intersects the unit's recorded symbol set.
- **Code fix:** a driver/toolchain fix landed whose declared error-class
  signature matches the unit's recorded error class (the existing mechanism).
- **Prompt delta:** the system prompt / injected rules changed
  (`prompt_version` bump).

**Mechanics [V4-3] — a mechanical world-hash, not a declared ledger.** v3's
`fix_ledger_version` required someone to *declare* that a landed fix matches a
unit's error class — a human bottleneck and a lie-by-omission channel: any
world change nobody thought to declare (a serving-config bump, a toolchain
upgrade) leaves schedulable retries unscheduled forever. Replaced: at verdict
time `_fail` records a **world-hash** — sha256 over the tuple

```
(serving config: model id + served context length,
 toolchain version: emcc -v string,
 driver git rev,
 PROMPT_VERSION,
 registry_version)
```

— plus the unit's symbol set and final error class. Every component is read
mechanically from the running system; nothing is declared. At selection time
`_next_unit` skips a red whose recorded world-hash equals the current hash
*and* whose symbol set gained no registry entries. Error-class-fix matching
survives as an **ordering heuristic** among already-schedulable reds (largest
relevant delta first: error-class match, then count of new registry entries
touching the unit, then fewest-attempts — replacing the blind every-Nth
rotation), never as the gate itself.

**Encoded as a regression test [V4-3] — the live counterexample:** the two
context-budget reds `auto-c0000-017` (required 34,008 tokens) and
`auto-c0001-000` (required 33,974) were verdicted when the serving maximum was
32,768; serving is now 262,144. No code fix was declared for them and no
registry entry touches them — under v3's fix-ledger scheme they wait forever
on a declaration nobody would think to make. Under the world-hash they MUST be
schedulable (the serving-config component changed). This pair is the test
fixture for the hash's composition.

**If nothing changed, the retry is not scheduled** — this replaces
retry-forever. Honest accounting (same pattern as §2.6): reds waiting on a
world change still count as work in `_work_remains()`, but a pass that finds
only such units writes run-state `status="waiting_world_change"` and must NOT
return `EXIT_PROGRESSED`; the supervisor reads the status from run-state.json
(§2.9 — no new exit codes before Phase 3). Starvation risk is bounded in
practice: 1,381 never-attempted units precede this situation, and every green
that harvests entries bumps the registry version, re-opening every red whose
symbols it touches.

**Terminal-state protocol [V4-3] — `waiting_world_change` must terminate in a
decidable page, not a spin.** v3 named the state but not its end. When zero
pending units remain and every red is zero-delta:

1. Each such red receives exactly **one §2.12(b) diagnosis call** (already
   bounded to once per unit lifetime, so re-entering the terminal state later
   re-spends nothing). This narrow use of the diagnosis question is pulled
   forward into T2a; the general escalation lane stays in T3 (§2.12).
2. The driver writes the terminal run-state and a **dedicated §4 page row
   fires with the diagnosis outputs attached** — the owner receives "here is
   every stuck unit and the model's one-line reason for each": a work order,
   not a stall report.

**Run-state semantics, named now [V4-3]:** `run-state.json` gains a
`run_state` field with values `progressing | waiting_world_change |
provider_paused`. This is a **run-state field, not a new exit code** — exit
codes stay frozen until Phase 3 per §2.9; the supervisor keeps reading the
file it already reads.

### 2.9 Budgets, exit codes, counters — G3 [R3] [unchanged + V3-4 status]

- Per-run model-call budget honouring `OGHIDRA_PORT_REQUEST_LIMIT`.
- Outcome reporting: the driver records `last_unit_outcome` in run-state.json
  (a channel the supervisor already reads) instead of a new exit code — the
  supervisor cannot learn `EXIT_NO_PROGRESS` until rig changes are approved
  (Phase 3), and an unknown exit code would be interpreted by code this design
  does not control. Exit-code change deferred to Phase 3 with the rig work.
  [V3-4]: `waiting_world_change` is a run-state status under the same rule.
- Counters [R3]: **cumulative `model_requests` is retained** (the rig
  dashboard consumes its sum) and a per-attempt `attempts[]` array is added
  alongside. Live incoherence example preserved for the test suite:
  a green whose provenance says `model_requests=7` where all 7 were spent on
  an infra-outage attempt and the winning attempt used 0.
- **Settles go through the journal — rule from a live precedent [V4-9].** The
  2026-08-20 settled-verdict migration wrote 15 carried verdicts directly into
  `wasm-units-state.json` via `port_queue_migrate` **without emitting a single
  journal event** — `events.jsonl` has no migration or settle kind, so it now
  shows 16 `wasm_unit_green` events against 12 greens in live state, and only
  the side-car migration file explains the difference. The migration itself
  was correct and documented; the *channel* was out-of-band. Rule (T2a, and
  mirrored in `AGENTS.md` so agents inherit it): **any operation that settles,
  carries, or unsettles a unit verdict MUST go through a code path that emits
  the corresponding journal event** (`verdict_migrated`, `verdict_revoked`,
  ...). G3 says pushes are the heartbeat; the journal is the heartbeat's
  ledger, and a state file that can silently diverge from it is a G3 breach in
  waiting.

### 2.10 Transient I/O is not structural — [unchanged, landed]

`OSError` on the header seed ⇒ retryable, never settled.

### 2.11 Knowledge registry: cross-unit accumulation — G1, G2 [V3-3; rewritten V4-1, V4-5, V4-6, V4-7, V4-8, V4-10]

All 1,396 units are extractions of one program sharing one flat address space;
today each re-derives typedefs, `DAT_` typings, and prototypes from the same
cold seed. The registry makes green-time decisions reusable and, by the same
stroke, becomes the assembly reconciliation ledger (§3).

**File:** `research/decomp/generated/finish-game-port/knowledge-registry.json`
— in-repo, versioned by git *and* by a monotonic `version` counter (the counter
is what §2.8's gating compares; git history is the audit trail).

[V4-8] **The path as specced in v3 would have been silently untracked:**
`research/decomp/generated/finish-game-port/` is gitignored wholesale
(GotYaForce `.gitignore:63`; the tracked queue files predate or were
force-added past the rule). "Versioned by git" was therefore false as written.
T2c ships a negation exception
(`!research/decomp/generated/finish-game-port/knowledge-registry.json`) **and
a test that the path is trackable** (`git check-ignore` must reject it) —
named explicitly in T2c's scope (§9) so it cannot be forgotten as a one-line
afterthought.

**Schema (registry_schema 1):**

```json
{
  "registry_schema": 1,
  "program": "gnt4",
  "version": 42,
  "updated_at": "2026-08-20T00:00:00Z",
  "entries": {
    "dat:0x802c44f8": {
      "kind": "dat_typing",
      "symbol": "DAT_802c44f8",
      "address": "0x802c44f8",
      "macro": "#define DAT_802c44f8 (*(unsigned char *)(unsigned int)0x802c44f8)",
      "c_type": "unsigned char",
      "lvalue": true,
      "tier": "oracle_green",
      "source_units": ["collision-core"],
      "harvested_at": "2026-08-20T00:00:00Z",
      "conflicts": []
    },
    "fn:zz_0005744_": {
      "kind": "prototype",
      "symbol": "zz_0005744_",
      "declaration": "double zz_0005744_(float *param_1, float *param_2, float *param_3);",
      "tier": "compile_only",
      "source_units": ["auto-c0000-002"],
      "harvested_at": "...",
      "conflicts": []
    },
    "macro:CONCAT44": {
      "kind": "pseudo_op",
      "symbol": "CONCAT44",
      "macro": "#define CONCAT44(hi,lo) (((unsigned long long)(unsigned int)(hi) << 32) | (unsigned int)(lo))",
      "tier": "oracle_green",
      "source_units": ["..."],
      "conflicts": []
    },
    "typedef:undefined8": {
      "kind": "typedef",
      "symbol": "undefined8",
      "declaration": "typedef unsigned long long undefined8;",
      "tier": "seed",
      "source_units": [],
      "conflicts": []
    }
  }
}
```

Entry kinds: `dat_typing` (`DAT_`/`PTR_DAT_` macro with address), `prototype`,
`pseudo_op` (CONCAT/SUB/ZEXT/SEXT macro forms), `typedef`. Tier ladder:
`seed` < `compile_only` < `oracle_green`.

**Harvest step (mechanical, no LLM) — redefined [V4-1]:** at green/staged
time, diff the winning `gnt4_shim.h` against the unit's *augmented* seed;
parse out `#define (PTR_)?DAT_<hex8>` lines, prototype declarations, and
pseudo-op macro definitions. Harvest = **decisions evidenced by the unit's
verbatim `.c`**, with two exclusions that v3 lacked:

- **Seed-inherited content is never harvested.** Any line already present in
  the seed the unit started from (including injected registry lines) is not
  that unit's decision; harvesting it would launder the seed back into
  "evidence" and inflate agreement.
- **Stub definitions for functions the unit calls but does not define are
  never harvested.** A green unit necessarily stubs its callees; those stubs
  are scaffolding assembly must *replace*, not knowledge it must honour.

This second exclusion is what makes the `oracle_green` tier **populatable at
all** without poisoning: v3's harvest, applied to the PoC's oracle-verified
units, would have imported their structural stubs as behaviourally-verified
truth — the review's concrete objection to how the top tier gets its first
entries. With the exclusions, an oracle-verified unit contributes exactly its
evidenced `dat_typing`s, pseudo-op forms, and the prototypes of functions it
*defines* — nothing it faked to link. Record tier from the unit's tier. Bump
`version` iff entries were added or changed.

**Injection step (unit start) — a seed/prelude-aware MERGE, tiered by trust
[V4-1, V4-5; REWRITTEN — this resolves the review's BLOCKING finding]:**
compute the unit's symbol set — `DAT_<hex8>` / `PTR_DAT_<hex8>` occurrences in
the verbatim text, plus prelude/export/callee identifiers. Select registry
entries whose key intersects that set (relevance = symbol/address
intersection, nothing fuzzier). Then merge, never append [V4-5]:

- If the seed already carries a line for the symbol (a seed `#define` or
  typedef), the entry **replaces the seed's line in place** — never both. v3's
  append produced duplicate macro definitions: at best `-Wmacro-redefined`
  noise polluting every fingerprint, at worst two silently divergent
  definitions where position decides semantics.
- A `prototype` entry for a symbol **the unit's prelude already declares is
  not injected**: the prelude is generated from Ghidra's own signature for
  this unit and outranks a sibling unit's compile-time guess. If the registry
  entry disagrees with the prelude, that disagreement is recorded on the entry
  as a **pending conflict** — data, surfaced; not an injection.
- No symbol ever appears twice in the assembled header.

**Tier decides HOW an entry is injected — v3's blanket-authoritative block was
an echo chamber [V4-1]:** v3 injected `compile_only` entries with a
do-not-alter rule and then defined conflicts as later units disagreeing. But a
registry that instructs agreement measures *obedience*, not correctness: the
first unit's guess for a shared address would propagate to every later unit
touching it, each "confirming" it under instruction, while the conflict
counter — the design's own G1 safety mechanism — read zero. One early wrong
`dat_typing` on the 29% shared-`(&DAT_)[i]` class poisons the ledger exactly
where the ledger matters most. Passing emcc proves a typing is
*self-consistent within one unit*, not that it is the program's typing.
Therefore:

- **`oracle_green` entries — authoritative injection** (reserved for this tier
  alone): fenced block, prompt rule *"these lines were established by
  behaviourally-verified units of this same program; do not alter them — adapt
  your other declarations instead"*, and the semantic survival check below.
- **`compile_only` entries — ADVISORY ONLY**, injected as a commented block:

  ```c
  /* ==== REGISTRY (advisory): previous units of this program compiled with
     the typings below. Verify each against THIS unit's use sites before
     adopting it; you are free to disagree — a reasoned disagreement is
     wanted data. ==== */
  /* #define DAT_802c44f8 (*(unsigned char *)(unsigned int)0x802c44f8) */
  ```

  No do-not-alter rule and **no survival check of any kind** for advisory
  entries — the unit derives its own typing with the hint in view. At harvest,
  the unit's independent derivation is compared against the advisory entry;
  disagreement is recorded as a conflict. **Independent derivation IS the
  conflict detector** — the same LLM work that ports the unit doubles as the
  registry's per-entry replication experiment, at zero extra calls. Agreement
  under advisory injection is evidence; agreement under instruction was noise.

**Injection size bound, written down [V4-10] (no cap imposed):** relevant-entry
injection against the queue's symbol-set sizes lands around **~300 tokens
median, ~2k tokens worst case** (a `(&DAT_)[i]`-heavy unit against a mature
registry). The real cost is **output-side regurgitation**: the model rewrites
the whole header every round, so injected lines are re-emitted in every reply
— k rounds × block size at output-token prices. Against the measured 16.1-min
median call this is noise relative to a single saved round, which is why no
cap is needed; the bound is recorded so the F6 holdout window can falsify
"noise" if the worst case grows.

**Survival check — semantic, oracle-tier only [V4-6]:** v3's post-apply check
was a verbatim string comparison — defeated by whitespace, comment stripping,
or legitimate reordering; it would have spammed `registry_deviation` on
cosmetic edits while missing a semantically-changed macro that kept its
prefix. Replaced: re-parse the applied header, extract the macro definitions
and declaration signatures for the injected **authoritative** symbols, and
compare **normalized token sequences** (whitespace/comment-insensitive; for
prototypes, the normalized signature). Applies **only to `oracle_green`
authoritative entries** — advisory entries are free to be ignored; that is
their point. A semantic mutation does not abort the round (the header may
still compile) but is recorded as `registry_deviation` and, if the unit goes
green with the deviation, becomes a conflict record at harvest.

**Conflict policy — surfaced immediately, never deferred to assembly:**

- Higher tier wins for injection: `oracle_green` over `compile_only` over
  `seed` — where "wins" now means it is the entry *presented* (authoritatively
  for `oracle_green`, advisorily for `compile_only` [V4-1]). The losing typing
  is appended to the entry's `conflicts[]` with unit and timestamp — never
  silently dropped.
- Same-tier disagreement (two `compile_only` units typing one address
  differently): the address becomes **contested** — not injected even
  advisorily (presenting a coin-flip is worse than a cold start), a
  `registry_conflict` event is emitted, and the dashboard conflict counter
  increments the moment the second unit lands, not at assembly time.
- `oracle_green` vs `oracle_green` disagreement: page the owner (§4). Two
  behaviourally-verified units disagreeing on one address's type is a real
  program-semantics finding (likely a union or a re-used region) and is
  exactly what assembly must know about first.

**Re-tier / demote / revoke [V4-7] — tiers move in both directions.** v3 had
promotion implicitly and no demotion path at all; a registry that can only
gain confidence converges on its earliest mistakes. Every tier move bumps
`version`, so §2.8's gating sees demotions the same as additions:

- **Promotion:** when a staged unit passes its oracle (T3 verification queue),
  its harvested entries promote `compile_only` → `oracle_green` — and
  promotion **recomputes conflicts**: a same-tier-contested address may now
  have a winner (re-enabling injection); an entry that now collides with an
  existing `oracle_green` escalates to the green-green page instead of
  silently winning by recency.
- **Demotion / revocation:** a **failed oracle re-run on a staged unit**
  (F5's scenario) downgrades or removes every entry whose only source is that
  unit — down to `compile_only` where independent compile-only sources agree,
  otherwise removed with a tombstone recorded in `conflicts[]` (an entry that
  vanishes without trace would un-explain past injections).

The conflict list **is** the cross-unit DAT-type reconciliation report — it is
generated as a by-product of porting instead of by archaeology afterwards
(§3), and the §2.13 assembly gate [V4-11] is its **empirical** complement:
harvest-time comparison catches the disagreements units wrote down; the link
catches the ones they didn't.

**Failure containment → holdout falsifier (F6, redefined [V4-1]):** v3's
containment metric — first-build error count of injected units vs class
baseline — measured *friction*, not *correctness*: an echo chamber lowers
first-build errors precisely while being wrong, so the metric could not detect
the design's worst failure mode. Replaced: **a deterministic N% of units
(10%, by unit-name hash) receive no injection at all — the holdout.** Holdout
units derive every typing independently. The registry-correctness metric is
the **agreement rate between holdout-derived typings and registry entries**
over the symbols both touch: sustained high agreement validates the registry;
falling agreement on a symbol class indicts the harvest or the tier ladder.
First-build error count is retained only as a cheap ops signal, no longer the
falsifier.

### 2.12 Different-question escalation — G2, G4 [V3-5, new]

After a failed attempt, re-asking "fix the whole header" with the same unit is
not the only move. Two alternate questions are permitted, each costed against
the measured 16.1-min median call:

- **(a) Targeted symbol question.** When the failed attempt's final diagnostics
  implicate ≤5 symbols, the next attempt may open with: *"declare exactly
  these N symbols given these call sites"* — prompt contains only the
  diagnostics and the mechanically-extracted `.c` lines referencing those
  symbols, not the whole unit. The reply is merged into the augmented seed and
  the normal loop resumes. Cost: one model call, with a much smaller prefill
  than a full round; budgeted as **replacing** the retry's first full-header
  round, so the attempt's call count does not grow. It is a different question
  *and* carries the post-mortem, satisfying §0.1 twice over.
- **(b) Diagnosis question.** At most once per unit lifetime, after the second
  failed attempt: *"why can no header fix this? answer STRUCTURAL or FIXABLE
  with one reason."* Output is tiny; cost ≤1 median call, bounded to the
  (small) ≥2-failed-attempts population. Consumption is conservative by
  construction (§2.7): STRUCTURAL deprioritises the unit and nominates it for
  the F4 replay sample — **it never settles**; FIXABLE appends its one reason
  line to the unit's post-mortem, so the next scheduled attempt carries it.

Escalation ships in T3 (§9): its value depends on the registry having first
drained the failure pool, and its cost (a median-length call per use) is only
justified against units the cheaper mechanisms have already failed twice.
[V4-3] One narrow exception is pulled forward into T2a: §2.8's terminal-state
protocol invokes the (b) diagnosis question once per zero-delta red when the
queue is otherwise exhausted, so the `waiting_world_change` page carries a
reason per stuck unit. Same prompt, same once-per-unit-lifetime bound; only
the trigger ships early.

### 2.13 Continuous assembly gate — THE interim G1 mechanism — G1, G4 [V4-11, new]

Every mechanism above keeps units *individually* green; until v4 nothing ever
linked two of them together — G1's first executable evidence sat behind a
future assembly workstream. The review's verdict: make composition
continuous, starting from the first handful of greens.

**Mechanism — specced as the simplest form that can fail honestly:** on every
green (or every Nth green; N configurable, default 5), take the last N
green/staged units and run **one `emcc` invocation over their `unit.c` files
together**:

- **merged headers** — the registry's merge logic (§2.11 [V4-5]) already
  defines precedence: authoritative entries win, contested/advisory conflicts
  fail the merge loudly rather than picking silently;
- **one shared arena** — the single `-sINITIAL_MEMORY=2155479040` flat image
  every unit already assumes; no `-sIMPORTED_MEMORY` side modules — that
  machinery is strictly more moving parts than a loadability gate needs, and
  the gate's own failures will say when real assembly outgrows the single
  invocation;
- **externs deduplicated via prelude signatures** — two units both stubbing
  the same callee keep exactly one definition; a signature mismatch between
  their stubs is itself a filed conflict.

The gate **passes iff the link produces a loadable wasm** (instantiation
smoke-test under node; no behaviour asserted — behaviour stays the oracle
tier's job). On failure: **page** (§4 row) and **file conflict records**
against the implicated registry entries/symbols — the failing diagnostics
name symbols, and symbols name entries.

Two roles, one mechanism:

1. **The interim G1 mechanism.** From T2b onward, "progress toward a buildable
   game" is measured by the largest N the gate has passed — not by counting
   individually-green units whose mutual composability is conjecture. §10's
   G1 row traces here, not to a futures-only workstream.
2. **The registry's empirical conflict detector [V4-1].** §2.11's harvest-time
   comparison catches disagreements units wrote down; the linker catches the
   ones they didn't — type-incompatible extern redeclarations, duplicate
   definitions, layout-divergent macro use — with the compiler as arbiter
   instead of string comparison.

### 2.14 Queue ordering toward product gaps — G1, G2 [V4-2, new]

The Tier-0 fixes (status header) corrected what the queue *contains*; this
corrects what it serves first. Pending units are currently served in chunk
order — an accident of the address-space walk, uncorrelated with what a
playable game needs. The strategy doc
(`research/decomp/port-strategy-research-2026-08-09.md`, option C,
recommendation 1) already names the product-gap order: the 12 unbridged
family files, then the **71 missing + 234 partial action slots across 325**
(the dominant combat-fidelity gap), then VERSUS wiring.

**Spec: a sort key on the existing queue, not a new queue.** Each queue entry
gains `product_priority` (int, lower serves first), assigned by the generator
by mapping the audit scripts' family/action-slot gap lists onto the chunks
containing those functions; unmapped chunks keep a default tail priority.
`_next_unit` orders pending units by `(product_priority, chunk_order)`.
Regeneration is cheap by construction: `port_queue_fill --rebuild` (landed in
the Tier-0 commit) resweeps generated units while `port_queue_migrate`
carries verdicts — re-keying is a regen, not a migration project. Ships in
T2a as a generator/selector tweak.

## 3. G1: per-unit work feeds assembly by construction [V3-6, replaces v2 §3's disclaimer]

v2 stated the G1 gap honestly and left assembly as "a separate workstream that
does not yet exist." v3 closes the *design* gap: the registry is built as the
assembly input, and the facts on the ground make composition tractable:

- The whole-program manifest exists
  (`research/decomp/generated/finish-game-port/whole-program-manifest.json`):
  11,980 functions inventoried (`inventory_complete=true`), grouping/bundling
  in progress (`bundles_complete=false`). The unit queue is not an ad-hoc pile;
  it is a scheduled decomposition of one known program.
- Every unit builds with `-sINITIAL_MEMORY=2155479040` — a flat image of the
  GameCube address space. `DAT_` macros dereference **absolute addresses** into
  that one image, so two units that agree on an address's type are already
  memory-compatible; the only cross-unit *data* contract is exactly what the
  registry records and conflict-checks at green time (§2.11). 29% of units
  touch the shared `(&DAT_)[i]` class, so conflicts are near-certain — which is
  why they surface at the second-lander, not at assembly.
- The PoC (`research/decomp/poc/wasm-port-poc/`: arena harnesses,
  `browser-expectations.json`, per-area shims, `build.sh`) is the seed of the
  assembly harness: it already links multiple areas against shared
  expectations.

Assembly deliverables, restated as consumers of existing mechanisms:

1. **Cross-unit DAT-type reconciliation report** = the registry conflict list
   (§2.11) plus the §2.13 gate's link-failure conflicts [V4-11] — generated
   continuously, zero archaeology.
2. **Shared-memory link plan** (single module vs shared-memory imports): the
   flat INITIAL_MEMORY image makes a single shared memory the default
   candidate; the registry's `dat_typing` entries enumerate every absolute
   address any unit touches, which is the input that plan needs.
3. **Symbol dedup policy**: the registry's `prototype` entries are the
   canonical signature set; duplicate definitions across units resolve against
   it.

Unchanged from v2:

- Metric change (T2): dashboard headline = `verified_green` vs `staged`;
  progress toward G1 is the verified count. Staged is inventory.
- Verification queue (T3, **new work, ~200+ lines, not a re-run**): staged
  units are currently `green/compile_only` in state — i.e. settled and
  unselectable — and the loop resets headers to seed, so promotion requires a
  new selector lane (`verify_pending`), loading the *staged artifact's*
  header, an oracle-only stage, artifact move, provenance rewrite, commit
  path. Costed honestly as a subsystem.

Final assembly remains its own workstream — but the units hand it a ledger and
a conflict-free (or conflict-*known*) address map by construction, instead of
1,396 independent headers to reconcile after the fact. [V4-11] And it no
longer starts cold: the §2.13 gate has been continuously linking rolling
N-unit windows since T2b, so assembly begins from a composition that already
loads, with every known incompatibility filed as a conflict record.

## 4. Monitoring invariants — G3, G4 [R8] [+ V3-3 row]

| Invariant | Threshold | Tranche | Action |
|---|---|---|---|
| Push silence while `running` | **4 h** (= 2.5 h ceiling + max observed stage 1.8 h + margin, boundary-enforced); T2 adds an hourly mid-unit heartbeat commit, after which the threshold drops to 2 h | T1 — **ownership caveat [V4-9]: the cron lives on the rig supervisor (2026-08-16 split), so this repo can request the threshold but cannot attest it; treat as landed-by-report, verifiable only rig-side** | alert + RCA |
| Unit wall clock | 2.5 h, **boundary-enforced** (a synchronous model call can overshoot by one call — stated, not hidden) | T1 | abort attempt, retryable, move on |
| Repair round | fingerprint unchanged after an applied header (§2.2) | T1 | abort attempt early |
| Reds:greens | 3:1 over trailing 10 **model-call-consuming attempts** (instant structural settles excluded — a batch of free correct kills must not page; they serve G4) | T2 | pause-and-page: design-failure signal |
| Verified fraction | falling while staged grows | T3 | flag unverifiable-inventory build-up |
| Registry conflicts [V3-3] | any `oracle_green` vs `oracle_green` conflict; or contested-address count > 5% of registry `dat_typing` entries | T2c | page (green-green); relevance-filter review (contested growth) |
| World-change starvation [V3-4] | run-state `waiting_world_change` while pending (never-attempted) units exist | T2a | bug: the selector must prefer pending work; page |
| Terminal `waiting_world_change` [V4-3] | zero pendings ∧ every red zero-delta | T2a | one §2.12(b) diagnosis per red, then page **with diagnoses attached** (a work order, not a stall report) |
| Assembly-gate failure [V4-11] | any N-green link/instantiation failure (§2.13) | T2b | page + file conflicts against implicated registry entries/symbols |
| Registry holdout agreement [V4-1] | agreement rate (holdout-derived vs registry, §2.11/F6) falling window-over-window | T2c | audit harvest + tier ladder; freeze advisory injection for the disagreeing symbol class |

Expected post-T1 base rate is unknown until F1's window runs; the 3:1
threshold is provisional and set from the first 30 post-T1 attempts.

## 5. Tool decisions (unchanged from v1/v2, all goal-traced)

Grammar-constrained JSON for code: **reject** (2 tok/s 27B + documented
codegen degradation; fence failures now bounded to one re-ask). Structured
metadata: reject for now. Pydantic unit-state records: **adopt** (D8 becomes
unrepresentable). Explicit stage functions: **adopt** as refactor (landed).
External orchestration frameworks: **reject**. [V3-3 note: the registry is a
JSON *state file* maintained by deterministic code, not model-emitted JSON —
the grammar-constraint rejection does not apply to it.]

## 6. Cost model (recomputed in v2 — [R5]; v3 deltas are directional only)

At measured median 16 min/round: current failed unit ≈ 7 rounds ≈ 1.9 h
(not 3.5 h); redesigned failed unit ≈ ≤4 rounds, stuck-abort typically 2–3 ≈
0.5–0.8 h. Savings ≈ 1.0–1.3 h per genuine failing unit — infra-outage
attempts excluded from the projection since those fixes already landed.
Campaign-order estimate: **150–250 GPU-hours**, dominated by the depth cap and
instant structural settling; the v1 figure (300–500) double-counted
already-banked infra fixes. Extrapolation caveat unchanged: per-class green
rates unmeasured. [V3-3/V3-4, directional, no invented numbers: registry
injection can only reduce round counts if the registry is *correct* — which
is now what F6's holdout agreement rate measures [V4-1], with first-build
error count kept as the cheap warm-start ops signal; world-changed gating
eliminates the entire class of zero-delta retries, which v2 would have spent
whole attempts on. Neither effect is quantified until the F2/F6 windows run.]

## 7. Supervisor arbitration (requirement recorded; Phase 3, owner approval) [unchanged]

Pausing/deprioritising one unit must not monopolise the GPU slot: the
supervisor currently equates "gate paused" with "slot empty" and evicts
foreign models, which blocked the next-priority unit. Arbitration = the
highest-priority runnable unit gets the slot. Interim workaround documented in
AGENTS.md (disable task; restore checklist).

## 8. Falsifiers

- **F1 (depth):** measured over the first 30 post-T1 repair-greens: if >10%
  link at exactly iteration 4 (i.e. would have died under cap 3), cap stays 4.
- **F2 (retry conversion — redefined [V3-2]):** conversion rate of
  *world-changed* retries (post-mortem + registry delta) vs the clean
  historical baseline (infra-outage conversions excluded). The per-attempt
  seed's marginal value is measured only as an A/B *within* the world-changed
  population; if it shows nothing, the seed schedule is dropped entirely.
- **F3 (stuck-abort):** replay 5 aborted attempts offline at depth 8; any that
  links ⇒ tighten the abort rule.
- **F4 (classifier):** monthly bounded recheck, §2.7 — the §2.12 diagnosis
  question feeds its sample, never the settle path.
- **F5 (verification):** oracle re-runs failing at high rate on staged units ⇒
  verification must move earlier.
- **F6 (registry holdout — redefined [V4-1], replaces the first-build-error
  metric):** a deterministic 10% of units receive no injection; the
  registry-correctness metric is the **agreement rate between holdout-derived
  typings and registry entries** over shared symbols (§2.11). Falling
  agreement ⇒ audit harvest/tier ladder and freeze advisory injection for the
  disagreeing symbol class. First-build error count survives as an ops signal
  only — it measured friction, and an echo chamber improves it while wrong.
  Retained from v3: any injected *authoritative* entry a unit had to deviate
  from to go green is prima facie evidence the entry (or its tier) is wrong —
  audit it.
- **F7 (post-mortem A/B [V4-4], new):** within world-changed retries, A/B the
  post-mortem block on/off. Track conversion rate AND **resurrection rate** —
  a `#define` that failed in attempt N re-emitted byte-identical in attempt
  N+1. If the post-mortem arm converts no better, or resurrects more
  (anchoring confirmed), the post-mortem is reduced to **diagnostics-only
  phrased as prohibition** ("these lines were tried and failed; do not
  re-emit them") and the failed-header carry is dropped.

## 9. Migration [V4-11 re-ordered: T2a → T2b → T2c; T1 + Tier-0 landed]

The v3 tranche order put the registry first inside a monolithic T2. The
review's re-order stands on two arguments: the small landed-code fixes (F9)
close active §0.1 violations in code that is running the moment the port comes
back online, and the assembly gate must exist **before** the registry so the
registry's tiers are born with their empirical conflict detector already
watching (§2.13). Registry last, in advisory mode.

- **T1 — landed** (`src/port_wasm_units.py`): depth cap 4 + env
  (**`OGHIDRA_PORT_MAX_ITERS`** — v3 wrote the internal constant name
  `MAX_COMPILE_ITERS` as the env var; that constant merely reads the env
  [V4-9]); stage-aware stuck-abort (`classify_build_stage`,
  `diagnostic_fingerprint`, `is_stuck`, with the §2.5 exemption); clean
  deduplicated feedback (`summarise_build_error`, default 1,200 chars /
  call-site 2,000 [V4-9]); malformed-reply re-ask + unclosed-fence recovery;
  D14 fix; `-ferror-limit=0`; push-silence threshold 4 h — cron ownership
  caveat per §4 [V4-9].
- **Tier-0 queue-generation fixes — landed [V4-2]** (OGhidra `05b94ea`,
  GotYaForce `9fccede`): dual-separator `SKIP_PREFIXES`; non-C-identifier
  export exclusion at generation + `wasm-units-skipped.json` report; queue
  1520 → 1,396 units / 10,954 exports; `gnt4_shim_seed.h` integer seed
  (PoC seed untouched); `port_queue_fill --rebuild` + `port_queue_migrate`
  (15 verdicts carried, 6 recorded); 49 tests green.
- **T2a — small landed-code fixes + honest gating [V4-9, V4-3, V4-4, V4-2]:**
  - second-consecutive `no_new_header` ends the attempt, or the follow-up
    call carries reply-shape evidence (§2.5 — kills the surviving same-input
    round at `src/port_wasm_units.py:1055-1064`);
  - settle-through-journal rule + `verdict_migrated`-class events (§2.9;
    mirrored in `AGENTS.md`);
  - **world-hash gating** (§2.8): `_fail` records the mechanical world-hash +
    symbol set + error class; `_next_unit` skips zero-delta reds; ordering =
    error-class match, registry-delta size, attempts. Regression test: the
    two context-budget reds (`auto-c0000-017`, `auto-c0001-000`) must be
    schedulable under the serving-config component;
  - **terminal protocol** (§2.8): one §2.12(b) diagnosis per zero-delta red
    at queue exhaustion; `run_state` field
    (`progressing | waiting_world_change | provider_paused`); page with
    diagnoses attached; no new exit codes;
  - *post-mortem data capture* (§2.3 [V4-4]): `rounds[]` gains normalized
    diagnostic sets + fingerprints; per-attempt best-header snapshots under
    attempt-scoped filenames; `_fail` persists rounds, best-header path,
    final fingerprint, error class; `_compile_fix` gains the post-mortem
    block on attempts ≥2 (A/B-flagged for F7);
  - `product_priority` sort key on the queue (§2.14) — generator assigns,
    `_next_unit` orders by `(product_priority, chunk_order)`.
- **T2b — continuous assembly gate (§2.13) [V4-11]:** header-merge tool
  (reusing §2.11's merge precedence rules), N-green single-invocation `emcc`
  link with shared arena + prelude-signature extern dedup, node instantiation
  smoke, page + conflict filing on failure. Ships before the registry
  deliberately: the gate is meaningful with zero registry entries (it links
  whatever greens exist), and it is the empirical detector the registry's
  tier ladder depends on.
- **T2c — registry, advisory mode (§2.11) [V4-1, V4-5, V4-6, V4-7, V4-8]:**
  new file `src/port_knowledge_registry.py` (load/save;
  `harvest(...)` with the seed-inherited and callee-stub exclusions;
  `augment(...)` as seed/prelude-aware merge; `relevant_delta(...)`; conflict
  recording; re-tier/demote/revoke). Touch points in `src/port_wasm_units.py`:
  `_process_unit` step 2 calls `augment()` and records
  `registry_version_used`; step 5 (green/staged) calls `harvest()`, emits
  `registry_conflict`, commits the registry with the unit's artifact commit
  (one push, G3-preserving); `SYSTEM_PROMPT` gains the oracle-tier
  authoritative rule + advisory-block wording and a `PROMPT_VERSION` constant
  recorded per attempt; post-applied-header **semantic** survival check
  (oracle-tier entries only) + `registry_deviation` event; **gitignore
  negation exception + registry-path trackability test [V4-8]**; 10% holdout
  assignment (F6). Carried from v2's T2: seed passthrough (tertiary, §2.3);
  conditional carry (A/B under F2/F7); oversize settle + preflight; run
  budget; cumulative+per-attempt counters; pydantic state records; heartbeat
  commit + 2 h threshold; verified/staged dashboard split; §4 monitoring rows.
- **T3 — unchanged scope:** concrete-type structural classifier + F4 recheck;
  verification queue subsystem (now also the promotion driver for [V4-7]
  re-tiering); **question escalation (§2.12)** — targeted-symbol and the
  general diagnosis lane (the terminal-protocol trigger shipped in T2a);
  supervisor arbitration + exit codes (with owner).

Each tranche ships behind the cooperative driver recycle; F1–F7 windows run
before the next tranche.

## 10. Goals traceability [V3-7; updated V4-11]

Every mechanism traces to a goal; every goal traces to mechanisms — and no
goal traces to a disclaimer. [V4-11] G1's **interim mechanism is the
continuous assembly gate (§2.13, T2b)** — a running gate from the first N
greens, not a futures-only workstream.

| Mechanism | G1 | G2 | G3 | G4 |
|---|---|---|---|---|
| §2.1 depth cap 4→3 | | ✓ | | |
| §2.2 stage-aware stuck-abort | | ✓ | | ✓ |
| §2.3 post-mortem retry + info-monotone attempts | | ✓ | | ✓ |
| §2.4 clean deduplicated feedback | | ✓ | | |
| §2.5 round-level re-ask | | ✓ | | |
| §2.6 oversize preflight + honest accounting | | ✓ | ✓ | |
| §2.7 structural classifier (proven only) + F4 | | | | ✓ |
| §2.8 world-changed retry gating | | ✓ | | ✓ |
| §2.9 budgets, run-state outcomes, counters | | | ✓ | |
| §2.10 transient I/O retryable | | ✓ | | |
| §2.11 knowledge registry (advisory harvest/merge-inject/conflict/re-tier) | ✓ | ✓ | | |
| §2.12 different-question escalation | | ✓ | | ✓ |
| §2.13 continuous assembly gate [V4-11] | ✓ | | | ✓ |
| §2.14 product-gap queue ordering [V4-2] | ✓ | ✓ | | |
| §3 verification queue + assembly-by-construction | ✓ | | | |
| §4 monitoring invariants (incl. conflict + starvation rows) | | | ✓ | ✓ |
| commit-per-match + registry co-commit + heartbeat commit | | | ✓ | |

| Goal | Served by |
|---|---|
| G1 playable, buildable game | **§2.13 continuous assembly gate — the interim mechanism [V4-11]**; §2.14 product-gap ordering; §2.11 registry as assembly ledger; §3 verification queue, flat-memory composition plan, conflict report by construction |
| G2 steady progress, no dead ends | §2.1–§2.6, §2.8 gating (no zero-delta retries; terminal protocol ends the wait decidably), §2.10, §2.11 warmer starts, §2.12 cheaper questions, §2.14 highest-value-first |
| G3 pushes are the heartbeat | §2.9 run-state outcomes + counters + settle-through-journal rule [V4-9]; §4 push-silence + starvation invariants; registry co-commit with unit commits |
| G4 dead ends killed fast, provably | §2.2 stuck-abort, §2.5 no-header attempt end [V4-9], §2.7 provable settling + F4, §2.8 not-scheduling unchanged-world retries, §2.12 diagnosis (conservative feed), §2.13 gate failures paged at N-greens not at assembly, §4 reds:greens page |

## Changelog v2 → v3

- **[V3-1]** §0.1: information-monotonicity principle adopted; every mechanism
  audited against it (§2.1/§2.2/§2.5 justified as compliant, not grandfathered).
- **[V3-2]** §2.3 replaced: seed/temperature schedules demoted from primary
  retry lever to tertiary decorrelation alongside an informational delta;
  post-mortem carry (mechanical, from `rounds[]`) on every retry; F2 redefined.
- **[V3-3]** §2.11 new: knowledge registry — schema, mechanical harvest,
  symbol/address-intersection injection, tiered conflict policy with
  immediate surfacing, F6 falsifier, monitoring row.
- **[V3-4]** §2.8 generalised: error-class-fixed-since lane becomes
  world-changed gating (registry delta ∨ code fix ∨ prompt delta); zero-delta
  retries are not scheduled; `waiting_world_change` accounting (§2.6 pattern).
- **[V3-5]** §2.12 new: different-question escalation (targeted-symbol,
  diagnosis) costed against the 16.1-min median; diagnosis feeds §2.7/F4
  conservatively and never settles.
- **[V3-6]** §3 rewritten: G1 no longer traces to a disclaimer — the registry
  is designed as the assembly input; flat `-sINITIAL_MEMORY` image + manifest
  + PoC harness stated as the composition basis; deliverables restated as
  consumers of the registry.
- **[V3-7]** §10 new: bidirectional goals traceability table.
- Evidence base (§1) and cost model (§6) numbers re-verified against v2's
  recomputation and kept unchanged; v3 adds no new measurements, only
  directional claims gated by F2/F6.

## Changelog v3 → v4 (applying the adversarial review v3 failed; [V4-#] = finding #)

- **[V4-1] BLOCKING — registry echo chamber resolved.** §2.11 rewritten:
  `compile_only` entries inject as ADVISORY commented blocks (no do-not-alter
  rule, no survival check); authoritative injection reserved for
  `oracle_green`; independent derivation is the conflict detector. Harvest
  redefined (evidence-linked to the unit's verbatim `.c`, excluding
  seed-inherited content and callee stubs) so the oracle tier is populatable
  without importing PoC structural stubs. F6 replaced by the 10% no-injection
  holdout with agreement rate as the correctness metric.
- **[V4-2]** Tier-0 queue fixes recorded as landed (status header; queue
  1520 → 1,396 / 10,954); §2.14 added: `product_priority` sort key ordering
  the queue toward strategy-doc option C's family/action-slot gaps.
- **[V4-3]** §2.8: declared `fix_ledger_version` replaced by a mechanical
  world-hash (serving config, toolchain, driver rev, prompt, registry);
  terminal `waiting_world_change` protocol (one diagnosis per zero-delta red,
  page with diagnoses); `run_state` field semantics named; the two
  context-budget reds encoded as the schedulability regression test.
- **[V4-4]** §2.3 coherence fix: a post-mortem never licenses scheduling
  (world-delta does; post-mortem is prompt content); T2a data spec —
  `rounds[]` normalized diagnostic sets + fingerprints, attempt-scoped
  best-header snapshots; new falsifier F7 (post-mortem A/B, conversion +
  resurrection rate; anchoring ⇒ diagnostics-only-as-prohibition, drop the
  failed-header carry).
- **[V4-5]** Injection is a seed/prelude-aware merge: replace covered seed
  lines, never duplicate, skip prototypes the prelude declares (recorded as
  pending conflicts).
- **[V4-6]** Survival check is semantic (normalized macro token-sequences /
  signatures on re-parse), and applies only to `oracle_green` entries.
- **[V4-7]** Registry re-tier/demote/revoke semantics: promotion recomputes
  conflicts; a failed oracle re-run downgrades/removes the unit's harvested
  entries (with tombstones); every move bumps `version`.
- **[V4-8]** Registry path is inside a wholesale-gitignored directory:
  negation exception + trackability test, named in T2c scope.
- **[V4-9]** Landed-code and doc corrections: second-consecutive
  `no_new_header` ends the attempt (kills the same-input round at
  `port_wasm_units.py:1055-1064`, T2a); env var is `OGHIDRA_PORT_MAX_ITERS`;
  summarise budgets 1,200 default / 2,000 call-site; greens count stated
  precisely (12 live green / 16 historical verdicts); cron ownership caveat
  (rig-side, landed-by-report); the 2026-08-20 out-of-band migration recorded
  as precedent and the settle-through-journal rule added (§2.9, AGENTS.md).
- **[V4-10]** Injection bloat bound written down: ~300 tokens median, ~2k
  worst case, plus the per-round output-regurgitation cost; no cap needed.
- **[V4-11]** §2.13 added: continuous assembly gate (single-`emcc` link of the
  last N greens, merged headers, shared arena, prelude-signature extern
  dedup, node loadability smoke) — THE interim G1 mechanism (§10) and the
  registry's empirical conflict detector. Tranches re-ordered: **T2a** small
  fixes + world-hash gating + terminal protocol, **T2b** assembly gate,
  **T2c** registry advisory-mode, **T3** unchanged.
