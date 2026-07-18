# Evidence-first 1:1 port workflow

The Gotcha Force launcher now starts OGhidra in `port_1to1` mode. Hybrid search finds likely
functions, but a search result or prior LLM summary is never evidence for a ROM-exact claim.

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

Only then transcribe the verified state machine into `packages/combat/src/families` or
`packages/combat/src/rom`. Generate boundary tests for both sides of every transition. Preserve
unresolved host behavior as a named field/callback/blocker rather than a silent fallback.

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

