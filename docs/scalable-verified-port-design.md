# Scalable verified 1:1 port pipeline

## Product definition

OGhidra's port workflow is an autonomous local-LLM port factory. One user action starts a durable
run that inventories the original program, extracts evidence, plans dependency order, generates
and integrates GotYaForce code, builds the browser game, runs automatic behavior/browser tests,
repairs failures, and continues until the recreation satisfies its completion suite.

The primary user experience is:

```text
Finish Game Port
```

After that button is pressed, the user may watch progress but is not required to classify
functions, approve green candidates, write tests, or restart individual passes.

The autonomous run is:

```text
Ghidra program
  -> structured function bundles
  -> exact/parameterized equivalence groups
  -> selected canonical functions
  -> local-Qwen port artifacts
  -> deterministic evidence validation
  -> GotYaForce importer profiles
  -> automatic compile and differential tests
  -> automatic runtime integration
  -> integration/browser replay
  -> repair/replan loop
  -> completed browser recreation
```

Success means GotYaForce builds, its completion scenarios pass in the browser, and every
game-relevant canonical implementation is integrated, replaced by an explicit browser-native
equivalent, or proven unreachable. A model response is never treated as an oracle, but deterministic
verification is a promotion gate rather than a mandatory human-review gate.

## Current vertical slice

The working Eagle Jet slice covers `FUN_8012b458` and exercises the complete promotion path:

- Live Ghidra evidence collection and a versioned port artifact.
- Qwen structured output through JSON Schema and Pydantic v2.
- Durable raw-response and evidence checkpoints; completed inference survives exporter or
  model-server failure.
- Deterministic scoring across retained Qwen attempts.
- Deterministic claim validation and rejection of unsupported claims.
- A trusted GotYaForce importer profile that emits an isolated TypeScript candidate.
- Automatic TypeScript compilation during the port run.
- Boundary scenarios generated from artifact branches and comparisons.
- Differential execution against the existing GotYaForce Eagle Jet implementation.
- A machine-readable automatic-verification artifact.
- No handwritten scenario list and no handwritten expected outputs in the verifier.
- Transactional promotion through a generated production registry.
- Complete combat-package build and ROM replay suite after promotion.
- Production browser-game build followed by real Chrome execution.
- Automatic registry rollback if a downstream build, ROM, or browser gate fails.
- Persistent JSON progress after every stage.

Press the POC button from the GotYaForce root:

```powershell
# Deterministic replay of the retained local-Qwen artifact
pnpm port:finish:poc

# Collect live Ghidra evidence and request a new local-Qwen artifact
pnpm port:finish:poc:fresh

# Explicitly rescore retained Qwen attempts and resume
pnpm port:finish:poc:resume
```

The fresh live-service run completed with this result:

```json
{
  "status": "completed",
  "localModel": "unsloth/Qwen3.6-35B-A3B-MTP-GGUF:UD-IQ3_S",
  "functionAddress": "0x8012b458",
  "productionPromotion": "promoted",
  "generatedScenarios": "compile passed; 12/12 generated scenarios; 0 handwritten",
  "combat": "passed",
  "webBuild": "passed",
  "browser": "chrome.exe; data-gf-runtime=loaded",
  "progressState": "research/decomp/generated/finish-game-port-poc/run-state.json"
}
```

In the latest run Qwen produced three retained attempts. Their validated importer coverage was
9/12, 12/12, and 12/12 required facts. The controller rejected attempt 1, selected attempt 3,
passed 64 evidence/schema checks, and completed every production gate. A malformed optional
Port IR was dropped, but only because the retained Qwen claims still covered all 12 required
mechanics. The fresh command now performs this response scoring and recovery inside the original
one-button run; the explicit resume command exists for process or machine restarts.

The scenarios are a deterministic boundary matrix derived from the artifact. For the current
function this covers entry and update paths, multiple delta-time values, and above/exact/below
timer boundaries. A regression test mutates the generated `effectMode` constant while leaving the
candidate compilable; automatic differential verification rejects the mutation.

This proves one autonomous production unit from decompiler evidence through a running browser.
It does not claim that one imported function completes the game; the remaining work is to
generalize the proven unit and schedule it across the gameplay dependency graph.

## One-button autonomous controller

`Finish Game Port` starts or resumes one persistent controller. The controller owns the entire
workflow and keeps useful work moving even when individual functions are blocked.

The POC implements this contract for one address in `scripts/finish-game-port-poc.mjs`. The scaled
controller moves the same state machine into OGhidra, replaces the hard-coded address/profile with
a durable queue, and reports aggregate game completion.

The controller:

1. Starts or health-checks GhidraMCP, the configured local Qwen service, build workers, the
   GotYaForce development server, and the browser-test runner.
2. Inventories and fingerprints the current program.
3. Builds a dependency DAG and equivalence groups.
4. Selects the highest-impact unblocked canonical unit.
5. Collects structured evidence and asks Qwen for a port artifact or integration decision.
6. Validates evidence, generates code, compiles, and executes derived tests.
7. Promotes a green candidate into the real runtime transactionally.
8. Rebuilds and runs deterministic combat and browser replays.
9. Keeps the promotion when all affected gates remain green; otherwise rolls it back and enters
   a bounded repair loop.
10. Replans around unresolved units and continues until the completion suite is green.

The normal loop does not wait for human approval. Human interaction is optional for inspecting
progress, changing priorities, or supplying genuinely unavailable external evidence.

### Local-LLM worker roles

One local model can perform several isolated roles under a deterministic orchestrator:

- **Planner:** chooses dependency-closed, gameplay-relevant work.
- **Evidence analyst:** requests more Ghidra facts and produces structured claims.
- **Port compiler:** produces language-neutral IR and target integration intent.
- **Repair worker:** receives compiler, differential, or browser failure details and proposes a
  constrained correction.
- **Coverage worker:** locates the next missing behavior from browser/completion failures.

Workers cannot declare their own output verified. The controller owns schemas, evidence checks,
compilation, promotion, rollback, and test results.

### Repair and continuation policy

Failures are inputs to the next automatic pass:

```text
invalid model output -> schema-guided repair
model service disconnect -> resume the retained evidence and completed raw response
missing evidence -> expand function bundle/dependency closure
compile failure -> compiler diagnostic repair
function mismatch -> first-divergence repair
combat mismatch -> deterministic replay minimization
browser failure -> input/state replay plus runtime integration repair
repeated blocker -> quarantine unit, replan other reachable work
```

Attempts and failure signatures are cached. The controller does not loop indefinitely on the same
unchanged failure; it advances other work and retries when a dependency, profile, or evidence
revision changes.

## Why structured function bundles precede Qwen

The DOL loader correctly establishes the executable memory map, entry point, PowerPC language,
small-data registers, and optional map symbols. Ghidra Auto Analysis then discovers additional
functions. The resulting function inventory is not itself a set of unique port implementations:

- Map switch labels may overlap their containing functions and must remain labels.
- Ghidra may discover genuine compiler-emitted duplicate functions at distinct addresses.
- Every original address must remain addressable even when implementations are equivalent.
- Plain decompiled C loses control-flow, SSA, storage-width, token-address, and decompiler-status
  information needed for reliable equivalence and code generation.

The current HTTP decompile endpoint creates a `DecompInterface` for one request and returns only
paginated C text. The scaled workflow therefore requires a structured `function_bundle` endpoint
before an all-functions Qwen run.

The endpoint contract should be versioned and include:

```json
{
  "bundle_schema": 1,
  "identity": {
    "address": "0x8012b458",
    "body_ranges": [],
    "prototype": "",
    "thunk": false,
    "inline": false,
    "no_return": false
  },
  "decompiler": {
    "c": "",
    "completed": true,
    "warnings": [],
    "errors": []
  },
  "cfg": {
    "blocks": [],
    "edges": []
  },
  "normalized_pcode": [],
  "calls": [],
  "data_references": [],
  "fingerprints": {
    "bytes": null,
    "instruction_shape": null,
    "normalized_pcode": null
  }
}
```

The extension should retain a configured `DecompInterface` per open program and dispose or reopen
it when the program changes. Extraction must expose completion/errors explicitly rather than
saving a failed request as a behavior summary.

## Equivalence and address preservation

Equivalence is established before Qwen using a proof ladder:

1. **Thunk identity**: preserve the thunk address and point it at the final callee.
2. **Exact normalized P-code**: operations, constants, call targets, memory effects, widths, and
   CFG match. Multiple addresses may reference one canonical port implementation.
3. **Parameterized equivalence**: equality holds only after an explicit substitution set.
   Generate one implementation plus a specialization table.
4. **Similarity only**: BSim or instruction-shape similarity proposes a group for analysis but
   never authorizes merging.

An equivalence group must retain:

```json
{
  "canonical_address": "0x80107320",
  "member_addresses": ["0x80107320", "0x8012f664"],
  "proof": "exact_normalized_pcode",
  "fingerprint": "...",
  "substitutions": []
}
```

This changes the scaling unit from “one Qwen call per Ghidra address” to “one Qwen call per
relevant canonical implementation.” Aliases remain in the manifest and dispatch tables.

## Port artifact and Qwen contract

Qwen receives the structured bundle, relevant direct dependencies, known data records, and the
equivalence-group identity. Its output remains a proposal and contains:

- Mechanical claims with stable IDs and evidence references.
- Semantic hypotheses kept separate from observations.
- Reads, writes, widths, signedness, constants, calls, and control flow.
- Explicit unresolved or host-bound dependencies.
- A language-neutral port IR.
- Observable fields/calls needed by an importer profile.
- Suitability: low-level port, typed integration, table extraction, host API, or more analysis.

Qwen participation is a hard generation requirement. Every importer fact must be authorized by a
validated Qwen claim or operation and independently corroborated by authoritative evidence.
Evidence-only recovery is forbidden: deleting Qwen mechanics from the Eagle Jet artifact leaves
the same Ghidra evidence but produces 0/12 facts and blocks the candidate.

Port IR is optional because model-generated syntax can degrade in long structured responses. An
invalid IR may be discarded, but this never bypasses Qwen: generation can continue only when the
remaining validated Qwen claims cover every required importer fact. When several responses are
retained, the controller deterministically scores their verified fact coverage and selects the
highest-coverage attempt; ties prefer the newest attempt.

Qwen does not supply trusted expected test results. Boundary cases are derived mechanically from
validated control flow and comparisons. Expected behavior comes from an independent oracle:

- Captured Dolphin/ROM traces when available.
- Existing reviewed GotYaForce behavior.
- A structured High P-code/port-IR interpreter for supported low-level operations.
- Reviewed decoded tables and helper contracts.

If no independent oracle exists, the result is `blocked_needs_oracle`, never `passed`.

## Automatic verification contract

Every imported candidate runs the following gates immediately:

```text
artifact schema
  -> evidence/claim validation
  -> importer dependency resolution
  -> candidate generation
  -> TypeScript compilation
  -> generated boundary matrix
  -> differential function execution
  -> deterministic combat replay, when mapped
  -> browser replay, when integrated
```

The machine-readable result records:

- Artifact and function/equivalence fingerprint.
- Candidate and importer-profile revision.
- Compiler command, exit code, stdout, and stderr.
- Scenario-generation algorithm and seed.
- Zero handwritten scenarios.
- Input, expected observation, actual observation, and mismatch per scenario.
- Oracle kind and provenance.
- Final status and blockers.

One semantic-mutation test is mandatory for each verifier class: a candidate that still compiles
but changes an observed write, branch, or call must fail differential verification.

### Test levels

1. **Function differential** runs for every candidate with an oracle profile.
2. **Headless combat replay** runs for candidates mapped into the deterministic combat runtime.
3. **Browser replay** runs after a function family is integrated. Playwright drives recorded
   inputs and reads stable simulation snapshots; screenshots are diagnostics, not the oracle.
4. **ROM trace comparison** remains the highest-confidence development-time behavior oracle.

Launching a browser for every low-level helper would be slow and make failures difficult to
attribute. Browser verification is grouped by integrated gameplay behavior; function tests run
immediately after each import.

## Batch and session model

The Ghidra project remains authoritative for symbols, types, comments, and analysis changes.
The OGhidra session owns user-visible run state. Large evidence/model artifacts remain external.

An OGhidra session stores a reference to a durable port-run manifest containing:

- Program and binary hash.
- Ghidra, extension, decompiler-option, prompt, schema, model, and importer revisions.
- Complete function inventory, including failed discoveries and aliases.
- Structured bundle/fingerprint locations.
- Equivalence-group membership and proof.
- Queue status, attempts, errors, and checkpoints.
- Artifact, generated candidate, and automatic-verification locations.

The queue state is:

```text
discovered
  -> bundled
  -> grouped
  -> excluded | queued
  -> model_generated
  -> evidence_verified
  -> generated
  -> compiled
  -> behavior_verified
  -> integration_verified
  -> integrated
```

Terminal exception states include `decompile_failed`, `model_invalid`, `evidence_rejected`,
`missing_profile`, `compile_failed`, `behavior_mismatch`, and `needs_oracle`.

Checkpoint after every state transition. Resume is keyed by the binary hash plus function or
normalized-P-code fingerprint and all producer revisions. A changed fingerprint invalidates only
the affected downstream work.

## OGhidra GUI

The primary action is `Analysis -> Finish Game Port`. Pressing it starts or resumes the complete
autonomous controller. The main view shows:

- Overall recreation percentage and completion-suite status.
- Current autonomous goal, active local-LLM worker, function/equivalence group, and dependency.
- Inventory, bundling, equivalence, generation, integration, build, combat, and browser progress.
- A live browser preview that refreshes after verified promotions.
- Recent promotions, automatic rollbacks, repaired failures, quarantined blockers, and Qwen work.
- Estimated remaining canonical units and gameplay scenarios.
- Pause, resume, stop-after-current-unit, and reprioritize controls.
- Optional inspectors for C, CFG, P-code, evidence, model output, generated diff, and first mismatch.

Advanced controls may scope a diagnostic run to one function or family, but this is not the
primary product path. The GUI invokes the same durable controller as the headless CLI. Closing the
GUI does not stop the port run unless the user explicitly requests it.

### Implemented GUI vertical slice

The OGhidra GUI now contains the `Analysis -> Finish Game Port` action and a non-modal dashboard.
It launches the Node controller as a detached process, persists its PID/log/control files, and can
reattach after the dashboard or OGhidra closes. The dashboard renders stage progress, the port
queue, live output, production-promotion status, safe-boundary pause/resume, stop-with-rollback,
and a production browser-preview launcher.

The dashboard's liveness contract includes elapsed time, stage-aware ETA, stages/minute, Qwen
tokens/second, local-model API/structured-output calls, and exact Ghidra collection calls. ETA is
the sum of historical median durations for the remaining stage IDs in the same run mode, with
the elapsed portion of the active stage removed. Missing history yields **Calibrating**, not a
naive whole-run extrapolation. Token throughput uses API usage fields when present and a labeled
deterministic estimate otherwise.

The active saved OGhidra session is handed to the exporter as advisory historical context. The
workflow does not require its vector index to be loaded: semantic vectors are a discovery aid,
whereas decompilation, disassembly, references, bytes, compilation, and differential execution
are the authority chain.

Structured validity is not treated as importer readiness. The controller ranks retained Qwen
responses by deterministic target-profile coverage, repairs the best response with missing-fact
shape feedback, and stops only at a bounded budget or complete coverage. Generated candidates
remain isolated until compile and differential gates pass. Promotion copies candidate source and
updates registration as one rollback domain.

The process-control contract was exercised against the production POC: it paused after web build
at 7/8 stages while the detached process remained alive, resumed under the same PID, completed the
Chrome stage, and finished 8/8 with the candidate promoted.

The current GUI queue contains the verified Eagle Jet `0x8012b458` vertical slice. The dashboard
is the product shell for the whole-program scheduler; showing the 11,972-address inventory as
schedulable before structured bundles/equivalence grouping exist would be false progress.

## Whole-program execution strategy

For the current 11,972-function Ghidra inventory:

1. Extract structured bundles for every address without invoking Qwen.
2. Record failures rather than treating HTTP/model error text as analysis.
3. Compute exact fingerprints and candidate similarity groups.
4. Preserve all addresses; select canonical representatives.
5. Exclude proven imports, thunks, runtime/library code, and platform-only initialization.
6. Prioritize gameplay-reachable canonical groups and leaf dependencies.
7. Run Qwen once per relevant canonical group.
8. Validate, generate, compile, and test immediately.
9. Automatically promote green candidates into the production runtime using a reversible
   transaction.
10. Rebuild and run browser replays after coherent gameplay families integrate.
11. Feed failures back into evidence, repair, dependency, and integration workers.
12. Continue until the complete-game acceptance suite passes.

No final “process 12,000 reports” or required manual-integration phase exists.

## Visible completion and end result

Progress is measured against user-visible game completion, not raw function count alone:

- Boot/menu/select/challenge/versus flows complete.
- Every playable Borg family and command slot reaches an implemented behavior.
- Shared combat, physics, AI, projectile, damage, status, mission, save, audio, rendering, and
  asset pipelines satisfy their completion scenarios.
- Deterministic long-running battle replays remain stable.
- Browser input-to-snapshot replays pass.
- No gameplay-reachable unit remains `missing_profile`, `needs_oracle`, or
  `behavior_mismatch`.

Function coverage remains visible as a diagnostic denominator, while completion-suite coverage is
the product percentage shown most prominently.

The final run result contains:

```json
{
  "status": "complete",
  "browser_build": "passed",
  "completion_scenarios": {
    "passed": 0,
    "total": 0
  },
  "gameplay_canonical_units": {
    "integrated": 0,
    "browser_native_replacements": 0,
    "proven_unreachable": 0,
    "remaining": 0
  }
}
```

The zero values above describe the contract fields, not current project measurements.

## Product goals and measurements

- **Reproducible:** identical evidence and revisions reproduce the same artifact and candidate.
- **Resumable:** process termination loses at most the currently active state transition.
- **Evidence-bound:** unsupported claims cannot become verified code.
- **Deduplicated:** proven equivalent addresses share analysis and implementation work.
- **Immediately tested:** every generated candidate compiles and runs its available oracle before
  the next queue item is considered complete.
- **Autonomous:** green candidates promote without human approval; failures enter bounded repair
  and replanning loops.
- **Visible:** the browser preview, completion scenarios, active worker, promotions, and remaining
  scope update continuously.
- **Address-faithful:** original addresses and dispatch relationships are never erased.
- **Transactional integration:** compilation alone never authorizes promotion; the controller
  automatically promotes only after required gates pass and rolls back affected failures.

Primary dashboard measurements:

- Inventory and bundle coverage.
- Exact and parameterized equivalence-group counts.
- Qwen calls avoided by grouping/exclusion.
- Evidence-validation pass/rejection counts.
- Compile pass rate.
- Differential scenario pass rate.
- Missing-profile and missing-oracle counts.
- Integrated address and canonical-implementation coverage.

## Remaining implementation

The autonomous production vertical slice is working. Scaling it to the complete game still
requires:

1. Persistent structured `function_bundle`/High P-code endpoint.
2. Exact normalized-P-code fingerprints and whole-program equivalence report.
3. Whole-program manifest and dependency/equivalence scheduler. Per-stage JSON checkpointing and
   inference-response resume already work in the POC.
4. Generic importer-profile registry beyond `0x8012b458`.
5. Port-IR interpreter for functions without an existing GotYaForce oracle.
6. Automatic deterministic combat-replay generation.
7. Gameplay-input browser replay and stable simulation snapshot comparison. The POC currently
   proves that the promoted production bundle builds and executes in Chrome.
8. Generic transactional integration across generated modules. Registry promotion and rollback
   are implemented for the Eagle Jet slice.
9. Local-LLM planner/repair orchestration and automatic dependency replanning.
10. Populate the implemented OGhidra dashboard with the whole-program scheduler, complete-game
    acceptance manifest, browser gameplay snapshots, and aggregate completion measurements.

Implementation order follows that list. Structured extraction and equivalence grouping come before
the all-functions Qwen run because they determine the correct unit of work. The autonomous
controller, promotion loop, and completion suite turn those units into the one-button product.
