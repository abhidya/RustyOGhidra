# Evidence-first 1:1 port workflow

The Gotcha Force launcher now starts OGhidra in `port_1to1` mode. Hybrid search finds likely
functions, but a search result or prior LLM summary is never evidence for a ROM-exact claim.

## Run from the OGhidra GUI

Launch OGhidra and choose **Analysis → Finish Game Port**:

```powershell
.\.venv\Scripts\python.exe main.py --ui
```

The action starts a detached controller and opens a durable dashboard with pipeline progress,
port-queue state, live logs, safe-boundary pause/resume, stop-with-rollback, and browser-preview
controls. Closing OGhidra does not terminate the run. Reopening the action attaches to the active
PID and reconstructs progress from `research/decomp/generated/finish-game-port-poc/run-state.json`.

Liveness is derived from durable telemetry rather than UI polling: elapsed time, per-stage
historical-median ETA, stages/minute, local-model API calls, structured responses, exact Ghidra
collection calls, and Qwen tokens/second. Endpoint token usage is preferred; a deterministic
tokenizer estimate is used and visibly labeled when usage is missing. ETA remains **Calibrating**
until a completed run in the same mode supplies comparable stage durations.

When a saved session is active, the GUI hands its `session.json` to every exporter invocation.
The resulting session summary is advisory evidence and the session artifact sidecar remains
linked to the port artifact. Loading its RAG vectors is not required. Vectors may improve
discovery, but only freshly collected binary evidence can support exact claims.

The integrated queue currently executes the verified Eagle Jet `0x8012b458` production slice.
Whole-program scheduling and equivalence grouping remain the next scaling layer.

## Export a compiler-facing function artifact

With the Ghidra CodeBrowser and OGhidraMCP service running:

```powershell
rtk .venv/Scripts/python.exe main.py export-port `
  --address 0x8012b458 `
  --ghidra-backend http `
  --output port_artifacts/8012b458.port.json
```

The command writes:

- `*.evidence.json` — immutable Ghidra evidence, including direct-callee decompiles
- `*.prompt.txt` — exact prompt and Pydantic JSON Schema
- `*.raw-attempt-N.txt` — untouched local-model responses
- `*.validation.json` — deterministic checks and syntax-only repairs
- the final `*.json` artifact, but only when Pydantic parsing succeeds

Generation is bounded to three attempts. The function exporter requests strict JSON Schema
directly for the tested local endpoint; the shared client still supports forced tool calls and
validated plain JSON for compatible providers. A model can propose mechanics, but only
deterministic code can retain a claim, mark it verified, or make an artifact importable.

The whole-run controller adds an outer importer-readiness loop. If a response is schema-valid but
misses target-profile mechanics, it keeps the best retained response and asks Qwen to repair only
the deterministic missing fact shapes. Candidate code is written under the run directory, not
over production. The controller copies it into production only after compilation and automatically
derived differential scenarios pass, and rollback restores both source and registration.

For offline replay, pass `--evidence-file` and `--model-response`. This bypasses Ghidra and the
model without weakening validation:

```powershell
rtk .venv/Scripts/python.exe main.py export-port `
  --address 0x8012b458 `
  --evidence-file port_artifacts/8012b458.evidence.json `
  --model-response saved-response.json `
  --output replay/8012b458.port.json
```

## One run, one port unit

Scope each query to one family and one action index:

> Build a version-1 port dossier for EAGLE ROBOT action 0. Trace every constructor route,
> variant, phase, helper, constant, transition, and host-dependent return. Do not implement.

OGhidra follows this chain:

1. constructor and per-Borg configuration
2. root action-index dispatcher
3. variant routing and raw table addresses
4. every reachable phase function
5. helper arguments and literal side effects
6. raw DOL constants and signed/width-sensitive operations
7. contradictions, missing code, and host-bound results

The final analysis must contain one fenced dossier JSON object. Valid objects are written
atomically to `port_dossiers/`. Invalid or uncited `DERIVED_ROM` output is rejected.

## Evidence bundles

For a reproducible offline/model comparison, build a deterministic bundle from selected sources:

```powershell
rtk .venv/Scripts/python.exe port_dossier.py bundle `
  --family EAGLE_ROBOT `
  --action-index 0 `
  --constructor 0x80129608 `
  --source authoritative:decompile:D:/GotYaForce/research/decomp/ghidra-export/chunk_0036.c `
  --source verified_derived:notes:D:/GotYaForce/research/decomp/oghidra-first-pass-port-findings-2026-07-12.md `
  --output port_dossiers/eagle-robot-action-0.bundle.json
```

Every source is tagged, hashed, sorted by evidence tier, and optionally embedded as text. Use
`--manifest-only` when another system already has access to the files.

## Verification and implementation

Run an adversarial query against the dossier before implementation:

> Verify this dossier claim by claim. Try to disprove branch direction, fallthrough, integer
> width/signedness, float bits, table indexes, helper arguments, and reachable phase coverage.

For a supported GotYaForce importer profile, importing an artifact now generates the isolated
candidate, compiles it, derives a deterministic transition-boundary matrix from the artifact, and
compares it with the profile's independent oracle. Test scenarios and expected outputs are not
handwritten into the verifier:

```powershell
pnpm import:oghidra-port `
  --artifact research/decomp/generated/8012b458.port.json
```

The command writes `*-auto-verification.json` and fails when compilation or differential behavior
fails. Unsupported profiles remain explicit blockers. Preserve unresolved host behavior as a
named field/callback/blocker rather than a silent fallback.

See [the scalable verified-port design](scalable-verified-port-design.md) for structured
function bundles, equivalence grouping, session/GUI behavior, and browser replay.

Validate manually edited dossiers with:

```powershell
rtk .venv/Scripts/python.exe port_dossier.py validate port_dossiers/example.json
```

## Mechanics benchmark

Use a reviewed dossier from an already verified family as the gold file:

```powershell
rtk .venv/Scripts/python.exe eval_port_workflow.py candidate.json gold.json
```

The gate measures claim precision/recall, evidence/status accuracy, phase recovery, variant
recovery, boundary tests, and named blockers. This replaces naming quality as the relevant metric
for 1:1-port assistance.

## Differential traces

Trace files are either a JSON list of frames or `{ "frames": [...] }`. Use identical field names
for ROM and port state, for example:

```json
{
  "frames": [
    { "frame": 0, "phase": 1, "x": 0.0, "y": 10.0, "vx": 2.0, "timer": 20.0 },
    { "frame": 1, "phase": 1, "x": 2.0, "y": 9.0, "vx": 2.0, "timer": 19.0 }
  ]
}
```

Compare them with:

```powershell
rtk .venv/Scripts/python.exe port_dossier.py compare-traces rom.json port.json `
  --fields phase x y vx timer --tolerance 0.000001
```

The command reports only the first divergent frame and fields so the LLM debugs a precise
mechanical mismatch instead of judging whether gameplay looks plausible.

## Session semantics

New sessions use schema version 2 and atomic writes. The legacy `rag_vectors` field remains for
compatibility but is explicitly labeled `retrieval_documents`; it does not contain embeddings.
Sessions can also carry evidence artifacts, an embedding-store reference, and a validated dossier.
Existing schema-less sessions remain loadable.

Use `-LegacyMode` on `start-oghidra-gotcha-force.ps1` to disable the new defaults.
