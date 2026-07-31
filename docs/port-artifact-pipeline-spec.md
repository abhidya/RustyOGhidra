# Spec: Function-level 1:1 port artifact pipeline

## Objective

Extend the existing `port_1to1` dossier workflow with a reproducible function-level artifact that
can cross the RustyOGhidra/GotYaForce boundary. RustyOGhidra owns evidence collection, model
provenance, Pydantic parsing, deterministic validation, bounded repair, and artifact export.
GotYaForce owns trusted templates, runtime bindings, import reports, and compilation checks.

The first vertical slice is `FUN_8012b458` (Eagle Jet action 1). Generated candidates remain
isolated from handwritten production modules until a human explicitly integrates them.

## Tech stack

- Python 3.12, Pydantic 2, existing Ghidra HTTP/pyGhidra clients, and pytest
- Existing OpenAI-compatible custom API client with tool-schema, JSON-schema, and plain-JSON fallbacks
- Versioned JSON artifacts with atomic writes and preserved raw model responses
- Node.js 20 and deterministic `.mjs` import/code-generation tooling in GotYaForce

## Commands

```powershell
# RustyOGhidra unit tests
rtk .venv/Scripts/python.exe -m pytest tests/test_port_artifact.py tests/test_port_exporter.py

# Export from a live Ghidra backend
rtk .venv/Scripts/python.exe main.py export-port --address 0x8012b458 --output port_artifacts/eagle-jet.json

# Reproduce from an explicit evidence bundle (offline/test path)
rtk .venv/Scripts/python.exe main.py export-port --address 0x8012b458 --evidence-file evidence.json --output port_artifacts/eagle-jet.json

# GotYaForce import and verification
rtk pnpm import:oghidra-port -- --artifact research/decomp/generated/8012b458.port.json
rtk pnpm test:oghidra-port
rtk pnpm typecheck
rtk pnpm build
rtk pnpm selfcheck:rom
```

## Project structure

- `src/port_artifact.py`: Pydantic schema, JSON extraction/repair, normalized addresses, validators
- `src/port_evidence.py`: backend-neutral Ghidra evidence collector
- `src/port_exporter.py`: structured generation, bounded repair, artifact store, session sidecar
- `main.py`: `export-port` CLI entry
- `port_artifacts/`: exported artifacts and raw-response/evidence sidecars
- `tests/test_port_artifact.py`: schema/parser/validator/serialization tests
- `tests/test_port_exporter.py`: fake-backend exporter and historical-session compatibility tests
- GotYaForce `scripts/import-oghidra-port-artifact.mjs`: deterministic importer and candidate generator
- GotYaForce `research/decomp/generated/`: artifacts and import reports
- GotYaForce `packages/combat/src/generated/oghidra/`: non-production generated candidates

## Code style

Pydantic enforces structure; deterministic code enforces evidence semantics:

```python
model_output = PortModelOutput.model_validate_json(raw_json)
artifact = assemble_artifact(identity, evidence, model_output)
report = validate_port_artifact(artifact)
if not report.passed:
    model_output = repair_once(raw_json, report)
```

Addresses are lowercase, zero-padded `0x` strings. Model-authored verification is never trusted.
Importer templates own all TypeScript imports and runtime field bindings.

## Testing strategy

- Unit tests use fake LLM and Ghidra clients; they exercise real parsing, evidence collection,
  validation, repair, serialization, session sidecar creation, and unsupported-dependency behavior.
- The Eagle Jet integration test uses authoritative decompile/DOL evidence and the configured local
  Qwen endpoint, then imports the resulting artifact and compiles the generated TypeScript.
- Existing historical sessions are sampled without mutation.
- Full GotYaForce typecheck, build, and ROM selfcheck remain release gates.

## Boundaries

- Always: preserve raw responses, prompt/model/binary provenance, unavailable evidence categories,
  unresolved dependencies, deterministic output, and existing handwritten fallbacks.
- Ask first: production registration of generated handlers, new runtime host APIs, or CI changes.
- Never: rewrite historical session prose, commit ROM bytes/assets, trust semantic names as facts,
  invent imports from model output, or mark compilation alone as behavioral verification.

## Success criteria

1. A real Ghidra function produces a schema-1 artifact with evidence, claims, IR, and validation.
2. Tool-call output remains supported; the local function exporter uses JSON Schema directly
   because the tested llama-server ignores forced tool choices.
3. Malformed output gets at most two bounded repairs per export invocation.
4. Mechanical claims cite collected evidence and pass deterministic address/offset/literal gates.
5. Historical sessions remain loadable and receive only a separate artifact-reference sidecar.
6. GotYaForce validates and imports the artifact without overwriting production files.
7. The Eagle Jet candidate compiles and matches the existing implementation’s expected facts.
8. Both repositories’ relevant tests and GotYaForce’s build/ROM selfcheck pass.

## Open questions

None blocking. Live Ghidra availability is an operational prerequisite for the live export command;
the explicit evidence-file path exists for deterministic tests and offline reproduction.
