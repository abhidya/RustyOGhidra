# Compile-fix loop redesign — defended design (v3, information-monotone workflow)

Status: v1 was adversarially reviewed; all BLOCKING/MAJOR findings were resolved
in v2, each marked `[R#]`. v2's T1 tranche has landed in `src/port_wasm_units.py`
(depth cap 4, stage-aware stuck-abort, deduplicated feedback, re-ask, D14,
`-ferror-limit=0`). v3 redesigns the workflow around an owner principle that v2
violated, marked `[V3-#]`:

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
- **Across units of the program**: the 1,520 units are extractions from ONE
  program (the whole-program manifest at
  `research/decomp/generated/finish-game-port/whole-program-manifest.json`
  inventories all 11,980 functions, `inventory_complete=true`). Units share
  `DAT_` addresses, typedef conventions, pseudo-op macros, and function
  prototypes — yet today every unit re-derives all of them from the same cold
  seed header. v3 adds a **knowledge registry** (§2.11): green decisions are
  harvested and later units start warmer. The registry doubles as the
  header-reconciliation ledger final assembly needs, which turns G1 from a
  disclaimer into a mechanism (§3).

Corollary used throughout: **a retry whose inputs are identical to the failed
attempt is not scheduled.** Deprioritising is allowed; blind re-running is not.

## 1. Evidence base (recomputed in v2 — [R5]; re-verified for v3, unchanged)

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
- Static profile of all 1520 units: 6.4% provably unfixable, 37% pseudo-ops,
  29% `(&DAT_)[i]`, 44% clean.

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

### 2.3 Retry = new information, never resampling — G2, G4 [V3-2, replaces v2 §2.3]

v2 made seed/temperature schedules the primary retry lever. Killed: a retry
whose only difference is sampling noise is same-information resampling. An
attempt N+1 on a red unit must differ from attempt N in at least one of:

1. **Post-mortem carry (always present).** The retry prompt includes a distilled
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

   No LLM writes the post-mortem; it is string assembly from state. This alone
   makes every retry informationally distinct from the original attempt (the
   original had no post-mortem).

2. **World change since the verdict (gates scheduling — see §2.8).** New
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

### 2.4 Feedback construction — G2 [unchanged, landed]

Prompt compiler-output = `summarise_build_error()` with deduplication
(≤2000 chars, invocation echo stripped) instead of the raw
`(stderr+stdout)[-6000:]` tail. Operator and model see the same evidence.

### 2.5 Malformed replies are round-level — G2 [R2] [unchanged, landed]

One immediate re-ask on no-extractable-header; if that fails, the round is
recorded as `no_new_header` and the loop proceeds without rebuilding (§2.2
exemption). An attempt is never failed over a missing fence. [V3-1 note: the
re-ask is principle-compliant — it adds the one fact the model lacked ("your
previous reply carried no usable code block"), so it is not same-input retry.]

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

### 2.8 Retry lane → world-changed gating — G2, G4 [V3-4, generalises v2 §2.8]

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

Mechanics: at verdict time `_fail` records
`world_version = {registry_version, prompt_version, fix_ledger_version}` plus
the unit's symbol set and final error class. At selection time `_next_unit`
skips a red whose recorded world version still matches the current world *and*
whose symbol set gained no registry entries. Ordering among schedulable reds:
largest relevant delta first (error-class-fix match, then count of new
registry entries touching the unit), then fewest-attempts — replacing the
blind every-Nth rotation.

**If nothing changed, the retry is not scheduled** — this replaces
retry-forever. Honest accounting (same pattern as §2.6): reds waiting on a
world change still count as work in `_work_remains()`, but a pass that finds
only such units writes run-state `status="waiting_world_change"` and must NOT
return `EXIT_PROGRESSED`; the supervisor reads the status from run-state.json
(§2.9 — no new exit codes before Phase 3). Starvation risk is bounded in
practice: 1,485 never-attempted units precede this situation, and every green
that harvests entries bumps the registry version, re-opening every red whose
symbols it touches.

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

### 2.10 Transient I/O is not structural — [unchanged, landed]

`OSError` on the header seed ⇒ retryable, never settled.

### 2.11 Knowledge registry: cross-unit accumulation — G1, G2 [V3-3, new]

All 1,520 units are extractions of one program sharing one flat address space;
today each re-derives typedefs, `DAT_` typings, and prototypes from the same
cold seed. The registry makes green-time decisions reusable and, by the same
stroke, becomes the assembly reconciliation ledger (§3).

**File:** `research/decomp/generated/finish-game-port/knowledge-registry.json`
— in-repo, versioned by git *and* by a monotonic `version` counter (the counter
is what §2.8's gating compares; git history is the audit trail).

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

**Harvest step (mechanical, no LLM):** at green/staged time, diff the winning
`gnt4_shim.h` against the unit's seed; parse out `#define (PTR_)?DAT_<hex8>`
lines, prototype declarations for symbols in the unit's prelude/callee set,
and pseudo-op macro definitions. Only harvest entries whose symbol actually
appears in the unit's verbatim `.c` (evidence-linked — a decl the model
gratuitously added but nothing used is not knowledge). Record tier from the
unit's tier. Bump `version` iff entries were added or changed.

**Injection step (unit start):** compute the unit's symbol set — `DAT_<hex8>` /
`PTR_DAT_<hex8>` occurrences in the verbatim text, plus prelude/export/callee
identifiers. Select registry entries whose key intersects that set (relevance
= symbol/address intersection, nothing fuzzier). Append them to the seed
header under a fenced block:

```c
/* ==== REGISTRY (established by green units of this same program; authoritative) ==== */
```

The compile-fix prompt gains one rule: *registry-block lines were established
by units of this same program that already passed their gates; treat them as
authoritative and do not alter them — adapt your other declarations instead.*
The driver checks after each applied header that injected registry lines
survived verbatim (a string check); a mutation does not abort the round (the
header may still compile) but is recorded as `registry_deviation` and, if the
unit goes green with the deviation, becomes a conflict record at harvest.

**Conflict policy — surfaced immediately, never deferred to assembly:**

- Higher tier wins for injection: `oracle_green` over `compile_only` over
  `seed`. The losing typing is appended to the entry's `conflicts[]` with unit
  and timestamp — never silently dropped.
- Same-tier disagreement (two `compile_only` units typing one address
  differently): the address becomes **contested** — no injection of that entry
  (injecting a coin-flip is worse than a cold start), a `registry_conflict`
  event is emitted, and the dashboard conflict counter increments the moment
  the second unit lands, not at assembly time.
- `oracle_green` vs `oracle_green` disagreement: page the owner (§4). Two
  behaviourally-verified units disagreeing on one address's type is a real
  program-semantics finding (likely a union or a re-used region) and is
  exactly what assembly must know about first.

The conflict list **is** the cross-unit DAT-type reconciliation report — it is
generated as a by-product of porting instead of by archaeology afterwards (§3).

**Failure containment (F6, §8):** injection must not poison easy units. The
first-build error count with injection is compared against the unit-class
baseline; if injected units regress at first build, the relevance filter is too
loose and tightens to exact-address matches only.

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
   (§2.11) — generated continuously, zero archaeology.
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

Final assembly remains its own workstream — but v3's units hand it a ledger and
a conflict-free (or conflict-*known*) address map by construction, instead of
1,520 independent headers to reconcile after the fact.

## 4. Monitoring invariants — G3, G4 [R8] [+ V3-3 row]

| Invariant | Threshold | Tranche | Action |
|---|---|---|---|
| Push silence while `running` | **4 h** (= 2.5 h ceiling + max observed stage 1.8 h + margin, boundary-enforced); T2 adds an hourly mid-unit heartbeat commit, after which the threshold drops to 2 h | T1 (threshold in existing cron) | alert + RCA |
| Unit wall clock | 2.5 h, **boundary-enforced** (a synchronous model call can overshoot by one call — stated, not hidden) | T1 | abort attempt, retryable, move on |
| Repair round | fingerprint unchanged after an applied header (§2.2) | T1 | abort attempt early |
| Reds:greens | 3:1 over trailing 10 **model-call-consuming attempts** (instant structural settles excluded — a batch of free correct kills must not page; they serve G4) | T2 | pause-and-page: design-failure signal |
| Verified fraction | falling while staged grows | T3 | flag unverifiable-inventory build-up |
| Registry conflicts [V3-3] | any `oracle_green` vs `oracle_green` conflict; or contested-address count > 5% of registry `dat_typing` entries | T2 | page (green-green); relevance-filter review (contested growth) |
| World-change starvation [V3-4] | run-state `waiting_world_change` while pending (never-attempted) units exist | T2 | bug: the selector must prefer pending work; page |

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
injection can only reduce round counts if F6 holds (warmer starts on the 29%
shared-`DAT_` class); world-changed gating eliminates the entire class of
zero-delta retries, which v2 would have spent whole attempts on. Neither
effect is quantified until the F2/F6 windows run.]

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
- **F6 (registry injection [V3-3]):** injected units' first-build error counts
  vs class baseline; regression ⇒ tighten relevance to exact-address matches.
  Additionally: any injected entry that a unit had to *deviate from* to go
  green is prima facie evidence the entry (or its tier) is wrong — audit it.

## 9. Migration [V3 re-scoped; T1 landed]

- **T1 — landed** (`src/port_wasm_units.py`): depth cap 4 + env
  (`MAX_COMPILE_ITERS`); stage-aware stuck-abort (`classify_build_stage`,
  `diagnostic_fingerprint`, `is_stuck`, with the §2.5 exemption); clean
  deduplicated feedback (`summarise_build_error`); malformed-reply re-ask +
  unclosed-fence recovery; D14 fix; `-ferror-limit=0`; push-silence threshold
  4 h in the existing cron.
- **T2 — the information-monotone core [V3]:**
  - *Registry module* (new file `src/port_knowledge_registry.py`: load/save,
    `harvest(seed_text, final_header, unit_symbols, unit_name, tier)`,
    `augment(seed_text, unit_symbols)`, `relevant_delta(unit_symbols,
    since_version)`, conflict recording). Touch points in
    `src/port_wasm_units.py`:
    - `_process_unit` step 2 (header scaffold, ~line 995): after reading the
      seed, call `augment()` with the unit symbol set (regex over the verbatim
      text for `(PTR_)?DAT_[0-9a-fA-F]{8}` + prelude/export/callee
      identifiers) and write the augmented header; record
      `registry_version_used`.
    - `_process_unit` step 5 (green/staged path, after artifact copy): call
      `harvest()`; emit `registry_conflict` events; commit the registry file
      with the unit's artifact commit (one push, G3-preserving).
    - `SYSTEM_PROMPT`: add the registry-authoritative rule; introduce
      `PROMPT_VERSION` constant recorded per attempt.
    - post-applied-header check: injected-lines-survived string check;
      `registry_deviation` event.
  - *Post-mortem retry*: `_process_unit` already builds `rounds[]`; `_fail`
    (~line 1310) persists `rounds`, best-round header path, final fingerprint,
    error class, and `world_version` into the unit record; `_compile_fix`
    prompt gains an optional post-mortem block on attempts ≥2.
  - *World-changed gating*: `_next_unit` (~line 1420) skips reds whose
    recorded `world_version` matches the current world and whose symbols
    gained no registry entries; ordering = error-class-fix match, then
    registry-delta size, then attempts+interruptions. `run()` writes
    `waiting_world_change` run-state status when only such units remain (must
    not report `EXIT_PROGRESSED`); `_work_remains` unchanged (reds are still
    work).
  - Carried from v2's T2: seed passthrough (tertiary, §2.3); conditional
    carry (A/B under F2's new definition); oversize settle + preflight; run
    budget; cumulative+per-attempt counters; pydantic state records; heartbeat
    commit + 2 h threshold; verified/staged dashboard split; registry conflict
    + starvation monitoring rows (§4).
- **T3:** concrete-type structural classifier + F4 recheck; verification queue
  subsystem; **question escalation (§2.12)** — targeted-symbol and diagnosis
  prompts (cost-justified only after the registry has drained the failure
  pool; each use is a ~16-min median call and the diagnosis question is
  bounded to once per unit); supervisor arbitration + exit codes (with owner).

Each tranche ships behind the cooperative driver recycle; F1–F6 windows run
before the next tranche.

## 10. Goals traceability [V3-7]

Every mechanism traces to a goal; every goal traces to mechanisms — and no
goal traces to a disclaimer.

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
| §2.11 knowledge registry (harvest/inject/conflict) | ✓ | ✓ | | |
| §2.12 different-question escalation | | ✓ | | ✓ |
| §3 verification queue + assembly-by-construction | ✓ | | | |
| §4 monitoring invariants (incl. conflict + starvation rows) | | | ✓ | ✓ |
| commit-per-match + registry co-commit + heartbeat commit | | | ✓ | |

| Goal | Served by |
|---|---|
| G1 playable, buildable game | §2.11 registry as assembly ledger; §3 verification queue, flat-memory composition plan, conflict report by construction |
| G2 steady progress, no dead ends | §2.1–§2.6, §2.8 gating (no zero-delta retries), §2.10, §2.11 warmer starts, §2.12 cheaper questions |
| G3 pushes are the heartbeat | §2.9 run-state outcomes + counters; §4 push-silence + starvation invariants; registry co-commit with unit commits |
| G4 dead ends killed fast, provably | §2.2 stuck-abort, §2.7 provable settling + F4, §2.8 not-scheduling unchanged-world retries, §2.12 diagnosis (conservative feed), §4 reds:greens page |

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
