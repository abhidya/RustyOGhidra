# Spec: Gotcha Force evidence-first 1:1 port workflow

## Objective

Turn OGhidra from a bulk function-naming assistant into an evidence-first assistant for
transcribing one Gotcha Force Borg family/action at a time. The LLM may discover and organize
evidence, but only directly cited ROM/decompile/disassembly facts may be marked `DERIVED_ROM`.
Existing naming sessions remain loadable.

## Tech stack

- Python 3 and the existing OGhidra/GhidraMCP bridge
- Pydantic-backed OGhidra configuration and prompt construction
- JSON dossiers and JSON Schema-compatible validation without new dependencies
- PowerShell launcher for the local Gotcha Force environment
- pytest for unit and workflow tests

## Commands

```powershell
# Launch the evidence-first UI (default)
rtk powershell -ExecutionPolicy Bypass -File research/tools/OGhidra/start-oghidra-gotcha-force.ps1

# Launch the legacy/default OGhidra mode
rtk powershell -ExecutionPolicy Bypass -File research/tools/OGhidra/start-oghidra-gotcha-force.ps1 -LegacyMode

# Validate a generated dossier
rtk research/tools/OGhidra/.venv/Scripts/python.exe research/tools/OGhidra/port_dossier.py validate path/to/dossier.json

# Compare a captured ROM trace with a port trace
rtk research/tools/OGhidra/.venv/Scripts/python.exe research/tools/OGhidra/port_dossier.py compare-traces rom.json port.json

# Run focused tests
rtk pytest research/tools/OGhidra/tests/test_port_workflow.py research/tools/OGhidra/tests/test_enhanced_session_manager.py
```

## Project structure

- `src/port_workflow.py`: prompts, evidence tiers, dossier validation, and trace comparison
- `port_dossier.py`: command-line validation/comparison entry point
- `schemas/port-dossier.schema.json`: versioned interchange contract
- `port_dossiers/`: generated per-family/action dossiers
- `analysis_sessions/`: backward-compatible session snapshots with structured evidence additions
- `tests/test_port_workflow.py`: dossier, prompt, and trace tests
- `docs/port-1to1-workflow.md`: operator workflow

## Code style

Use typed, deterministic functions for all gates. Keep LLM text outside validators.

```python
result = validate_dossier(payload)
if result.errors:
    raise ValueError("; ".join(result.errors))
```

Evidence tiers are `authoritative`, `verified_derived`, `observed`, `inferred`, and `advisory`.
Only the first three may support a `DERIVED_ROM` claim, and every such claim needs a concrete
address/range plus at least one source citation.

## Testing strategy

- Unit-test mode-specific prompt routing and strict dossier validation.
- Unit-test atomic session replacement, collision-resistant IDs, and legacy loading.
- Unit-test trace comparison at the first divergent frame.
- Parse every existing session as a backward-compatibility smoke check.
- Run the existing OGhidra prompt tests after changing prompt routing.

## Boundaries

- Always: preserve evidence tiers, exact numeric representation, source addresses, unknowns, and blockers.
- Always: write sessions and dossiers atomically.
- Always: keep existing sessions loadable.
- Ask first: adding dependencies or changing the combat runtime/data formats.
- Never: promote LLM prose, wiki content, or an inferred field name to `DERIVED_ROM` by itself.
- Never: fabricate Dolphin observations or silently replace an unresolved host result.
- Never: modify unrelated dirty combat/runtime files.

## Success criteria

1. The launcher enables `port_1to1` mode and hybrid retrieval by default, with `-LegacyMode` opt-out.
2. Planning, execution, analysis, evaluation, and review receive port-specific evidence rules.
3. A versioned dossier can represent actions, variants, phases, claims, evidence, blockers, and tests.
4. Validation rejects uncited or inference-only `DERIVED_ROM` claims.
5. Trace comparison reports the first divergent frame and fields.
6. Sessions use collision-resistant IDs and atomic writes while old sessions still load.
7. Session data distinguishes retrieval documents from actual embeddings and can store dossier/evidence links.
8. Focused and existing prompt tests pass.

## Task breakdown

- [x] Add the port workflow schema, validator, trace comparator, CLI, and tests.
- [x] Add `port_1to1` prompt mode and route all agent phases through it.
- [x] Add launcher and UI defaults for the new mode.
- [x] Harden session IDs/writes and extend the backward-compatible schema.
- [x] Add operator documentation and mechanics-evaluation guidance.
- [x] Run focused tests, existing prompt tests, and session compatibility checks.

## Open questions

None blocking. Live Dolphin capture remains an external input; this change validates and compares
provided traces but does not control the emulator.
