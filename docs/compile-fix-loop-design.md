# Compile-fix loop redesign — defended design (v2, post-adversarial-review)

Status: reviewed. v1 was adversarially reviewed; all BLOCKING/MAJOR findings are
resolved below, each marked `[R#]`. Port stays offline until Tranche 1 lands.

## 0. Goals (the only source of requirements)

G1. A **playable, buildable** version of the game.
G2. Steady progress; **no time wasted on dead ends**.
G3. **Git pushes are the heartbeat** — absence must mean breakage, detectably.
G4. Dead ends **detected and killed fast**, automatically where provable.

## 1. Evidence base (recomputed — [R5])

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
- Static profile of all 1520 units: 6.4% provably unfixable, 37% pseudo-ops,
  29% `(&DAT_)[i]`, 44% clean.

Research (arXiv 2604.10508, 2505.02931, s41598-025-27846-5, 2608.05643): two
repair rounds capture most gains; decay per attempt; diverse independent
attempts beat deep single-chain iteration; noisy feedback degrades repair.

## 2. The loop redesign

### 2.1 Depth: cap 4 in T1, 3 when T2's recovery lands — G2 [R1][R4]
n=7 with 14% needing >3 does not support a hard 3 while there is no recovery
path — capping at 3 in T1 would strand the >3 class for months behind 1,486
pending units. So: `OGHIDRA_PORT_MAX_ITERS=4` at T1; drop to 3 only when the
T2 retry lane + carry exist, and only if F1's measurement window supports it.

### 2.2 Stuck-abort, stage-aware — G2, G4 [R1][R2]
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

### 2.3 Retry strategy: measured, not assumed — G2 [R7]
- **Diversity levers (T2):** add `seed` passthrough to the client (a 5-line
  change; the server accepts it) with a per-attempt seed schedule — the
  observed mode collapse recurred across *different prompts* at temp 0.7, so
  temperature alone is not a sufficient lever. Temperature schedule
  (0.7 → 1.0) stays as the second lever; error-order shuffling is a third,
  cheap option if F2 shows both insufficient.
- **Carry vs fresh is conditioned on the abort reason,** not hard-coded:
  attempt 1 ended with monotone error decrease reaching ≤2 errors → attempt 2
  carries the best header (near-miss worth finishing). Attempt 1 oscillated or
  regressed → attempt 2 goes fresh-from-seed at the next diversity step
  (carrying an oscillating chain's artifact imports its wrong decisions, and
  fewest-errors is gameable — a K&R `int f();` silences arity errors under the
  existing warning suppressions, so "best" can be semantically dead).
  The order is env-selectable and F2's A/B decides the default.

### 2.4 Feedback construction — G2
Prompt compiler-output = `summarise_build_error()` with deduplication added
(≤2000 chars, invocation echo stripped) instead of the raw
`(stderr+stdout)[-6000:]` tail. Operator and model see the same evidence.

### 2.5 Malformed replies are round-level — G2 [R2]
One immediate re-ask on no-extractable-header; if that fails, the round is
recorded as `no_new_header` and the loop proceeds without rebuilding (§2.2
exemption). An attempt is never failed over a missing fence.

### 2.6 Oversize handling — G2 [R3]
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
return `EXIT_PROGRESSED`. **Moved to T2** — it touches selector, exit paths,
state schema, and journal counts; it is not small, and at 262k it is not
urgent.

### 2.7 Structural classifier: proven cases only — G4 [R6]
v1's "every diagnostic points into unit.c involving only locals" is **wrong**:
a local's *type* can be a header typedef, so the header can be the fix even
when the diagnostic line names only locals (the split-statement
`undefined8`/`CONCAT44` idiom produces exactly this shape, and the fix was in
the header). Line-level identifier tests discard dataflow. Therefore:

- Keep the void-result detector (proven: 5 catches, 0 false positives).
- Add **only** the concrete-type case actually observed: a local declared in
  `unit.c` with a concrete built-in type (e.g. `char *local_68`) cast to/from
  an incompatible concrete built-in type, where neither type involves any
  header-defined typedef or macro. Everything else stays retryable.
- **F4 becomes executable** [R6]: a monthly bounded recheck — sample up to 5
  `structural_ineligible` units, replay offline with the current loop; any
  that links freezes the classifier to the void-result detector and reopens
  the class. Without this, the falsifier is starved by the very mechanism it
  guards (settled units are never attempted again).

### 2.8 Retry lane — G2 [R4][R7]
Every Nth selection (default 10) takes a retryable unit — ordered by
**error-class-fixed-since**: prefer reds whose recorded error signature
matches a code fix landed after their verdict (9 of the current 13 reds are in
this category), then fewest-attempts. The data is already in state records;
the ordering is a sort key. Ships in T2 with the carry logic; the T1 cap stays
at 4 precisely because this lane doesn't exist yet.

### 2.9 Budgets, exit codes, counters — G3 [R3]
- Per-run model-call budget honouring `OGHIDRA_PORT_REQUEST_LIMIT`.
- Outcome reporting: the driver records `last_unit_outcome` in run-state.json
  (a channel the supervisor already reads) instead of a new exit code — the
  supervisor cannot learn `EXIT_NO_PROGRESS` until rig changes are approved
  (Phase 3), and an unknown exit code would be interpreted by code this design
  does not control. Exit-code change deferred to Phase 3 with the rig work.
- Counters [R3]: **cumulative `model_requests` is retained** (the rig
  dashboard consumes its sum) and a per-attempt `attempts[]` array is added
  alongside. Live incoherence example preserved for the test suite:
  a green whose provenance says `model_requests=7` where all 7 were spent on
  an infra-outage attempt and the winning attempt used 0.

### 2.10 Transient I/O is not structural — [unchanged]
`OSError` on the header seed ⇒ retryable, never settled.

## 3. Compile-only greens and G1 [R9 — the gap, stated]

- Metric change (T2): dashboard headline = `verified_green` vs `staged`;
  progress toward G1 is the verified count. Staged is inventory.
- Verification queue (T3, **new work, ~200+ lines, not a re-run**): staged
  units are currently `green/compile_only` in state — i.e. settled and
  unselectable — and the loop resets headers to seed, so promotion requires a
  new selector lane (`verify_pending`), loading the *staged artifact's*
  header, an oracle-only stage, artifact move, provenance rewrite, commit
  path. Costed honestly as a subsystem.
- **G1 gap, stated plainly [R9]:** nothing in this design assembles 1,520
  per-unit wasm modules into one game. Per-unit greens provably do not
  compose today: each unit carries its own header with independent
  `#define DAT_xxxx (*(T*)0xADDR)` typing decisions (29% of units touch the
  same-address class, so conflicts are near-certain), duplicate symbol
  definitions, and a private 2 GB linear memory per module vs one shared
  GameCube address space. **Final assembly is a separate workstream that does
  not yet exist.** G1 is served by this design only transitively — it
  produces verified per-unit artifacts and an auditable ledger of typing
  decisions (header archive per unit) that the assembly workstream will need.
  First assembly deliverables when that workstream opens: cross-unit DAT-type
  reconciliation report; shared-memory link plan (single module or shared
  memory imports); symbol dedup policy.

## 4. Monitoring invariants — G3, G4 [R8]

| Invariant | Threshold | Tranche | Action |
|---|---|---|---|
| Push silence while `running` | **4 h** (= 2.5 h ceiling + max observed stage 1.8 h + margin, boundary-enforced); T2 adds an hourly mid-unit heartbeat commit, after which the threshold drops to 2 h | T1 (threshold in existing cron) | alert + RCA |
| Unit wall clock | 2.5 h, **boundary-enforced** (a synchronous model call can overshoot by one call — stated, not hidden) | T1 | abort attempt, retryable, move on |
| Repair round | fingerprint unchanged after an applied header (§2.2) | T1 | abort attempt early |
| Reds:greens | 3:1 over trailing 10 **model-call-consuming attempts** (instant structural settles excluded — a batch of free correct kills must not page; they serve G4) | T2 | pause-and-page: design-failure signal |
| Verified fraction | falling while staged grows | T3 | flag unverifiable-inventory build-up |

Expected post-T1 base rate is unknown until F1's window runs; the 3:1
threshold is provisional and set from the first 30 post-T1 attempts.

## 5. Tool decisions (unchanged from v1, all goal-traced)

Grammar-constrained JSON for code: **reject** (2 tok/s 27B + documented
codegen degradation; fence failures now bounded to one re-ask). Structured
metadata: reject for now. Pydantic unit-state records: **adopt** (D8 becomes
unrepresentable). Explicit stage functions: **adopt** as refactor. External
orchestration frameworks: **reject**.

## 6. Cost model (recomputed — [R5])

At measured median 16 min/round: current failed unit ≈ 7 rounds ≈ 1.9 h
(not 3.5 h); redesigned failed unit ≈ ≤4 rounds, stuck-abort typically 2–3 ≈
0.5–0.8 h. Savings ≈ 1.0–1.3 h per genuine failing unit — infra-outage
attempts excluded from the projection since those fixes already landed.
Campaign-order estimate: **150–250 GPU-hours**, dominated by the depth cap and
instant structural settling; the v1 figure (300–500) double-counted
already-banked infra fixes. Extrapolation caveat unchanged: per-class green
rates unmeasured.

## 7. Supervisor arbitration (requirement recorded; Phase 3, owner approval)

Pausing/deprioritising one unit must not monopolise the GPU slot: the
supervisor currently equates "gate paused" with "slot empty" and evicts
foreign models, which blocked the next-priority unit. Arbitration = the
highest-priority runnable unit gets the slot. Interim workaround documented in
AGENTS.md (disable task; restore checklist).

## 8. Falsifiers

- **F1 (depth):** measured over the first 30 post-T1 repair-greens: if >10%
  link at exactly iteration 4 (i.e. would have died under cap 3), cap stays 4.
- **F2 (diversity):** retry conversion under seed+temperature schedule vs the
  clean historical baseline (infra-outage conversions excluded — they
  converted because the toolchain was fixed, not sampling).
- **F3 (stuck-abort):** replay 5 aborted attempts offline at depth 8; any that
  links ⇒ tighten the abort rule.
- **F4 (classifier):** monthly bounded recheck, §2.7 — now executable.
- **F5 (verification):** oracle re-runs failing at high rate on staged units ⇒
  verification must move earlier.

## 9. Migration (port offline until T1 lands) [R3 — re-scoped]

- **T1 — small and mechanical, honestly:** depth cap 4 + env; stage-aware
  stuck-abort (§2.2, with the §2.5 exemption); clean deduplicated feedback;
  malformed-reply re-ask; D14 fix; `-ferror-limit=0`; push-silence threshold
  4 h in the existing cron. Tests for each, including: link-gate→compile
  transition must NOT abort; no-new-header round must NOT rebuild or compare.
- **T2:** seed passthrough + diversity schedule; conditional carry (A/B);
  retry lane (error-class-fixed-since); oversize settle + preflight;
  run budget; cumulative+per-attempt counters; pydantic state records;
  heartbeat commit + 2 h threshold; verified/staged dashboard split.
- **T3:** concrete-type structural classifier + F4 recheck; verification
  queue subsystem; supervisor arbitration + exit codes (with owner).

Each tranche ships behind the cooperative driver recycle; F1–F5 windows run
before the next tranche.
