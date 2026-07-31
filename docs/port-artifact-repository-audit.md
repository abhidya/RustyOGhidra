# Port artifact repository audit

## RustyOGhidra

- `port_1to1` is routed through `src/bridge.py`; `_analyze_for_port` ranks tool results, injects
  `schemas/port-dossier.schema.json`, and asks for fenced JSON.
- Phase prompts and the existing dossier validator live in `src/port_workflow.py`. The dossier is
  family/action-oriented and useful for research, but is not a function-level compiler artifact.
- `src/custom_api_client.py` uses OpenAI-compatible chat completions but currently sends neither
  `tools`/`tool_choice` nor `response_format`.
- `_capture_port_dossier` validates and atomically stores dossiers. Raw invalid model output is not
  a durable artifact and there is no bounded structured repair.
- `AbstractGhidraClient` exposes function metadata, decompile, disassembly, xrefs-to/from, raw-byte
  reads, and program metadata. HTTP and pyGhidra backends implement the common surface.
- `EnhancedSessionManager` stores schema-2 sessions and loads schema-less historical sessions.
  Existing optional evidence/dossier fields should not be expanded with duplicate decompilation.
- Pydantic 2 is already a declared dependency. Existing tests use pytest.
- `main.py` is the CLI/UI entry point but has no export-port command.

## GotYaForce

- `packages/combat/src/bridge.ts` preserves generic combat fallback for unregistered/incomplete
  families and registers the handwritten Eagle Jet family.
- `packages/combat/src/families/eagle-jet.ts` implements `FUN_8012b458`: effect byte `0x83`,
  45-frame timer, hit kind `0x7f`, cue `0x20`, Eagle Jet slots 4/5, and cleanup equivalent to
  `zz_006a53c_(actor, 0x10)`.
- ROM dispatch/runtime code is under `packages/combat/src/rom`; the Eagle Jet regression is in
  `rom.selfcheck.ts`.
- Root scripts provide `pnpm typecheck`, `pnpm build`, and `pnpm selfcheck:rom`.
- There is no artifact importer or generated-source policy today.

## Implementation seam

Keep the existing dossier workflow for family-wide research. Add a function artifact beside it:
Ghidra client → evidence bundle → Pydantic model output → deterministic validator → atomic artifact.
Then use a GotYaForce-owned importer template to generate isolated candidates and reports. This
avoids teaching RustyOGhidra about GotYaForce runtime internals and avoids a second combat engine.
