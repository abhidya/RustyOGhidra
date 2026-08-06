# Spec: Chunk and Execution-Unit Game Port Workflow

## Objective

Replace the default address-by-address autonomous source walker with a bounded workflow that:

1. analyzes one persisted Ghidra C export chunk as shared context;
2. partitions it into coherent execution units while preserving cross-chunk dependencies;
3. ports one selected unit against stable GameCube runtime and host contracts;
4. pauses without issuing generation requests when Ghidra or the model provider is unavailable; and
5. marks a unit integrated only when its declared runtime entry symbols are reachable and its verification gates pass.

The first product pilot is `chunk_0048.c`, with the Challenge controller/menu lifecycle as the highest-value unit. The legacy whole-program address stream remains available only through an explicit compatibility flag.

### Assumptions approved by the implementation request

- Existing semantic `RomActor` and browser systems remain in place; this change adds a memory-shaped compatibility core rather than rewriting them.
- Static `research/decomp/ghidra-export/chunk_*.c` and `_index.tsv` are usable while Ghidra is offline.
- Model output remains untrusted and cannot select arbitrary commands to execute.
- The GUI's default Finish Game Port action should start the safe Challenge chunk analysis, not the legacy address stream.

## Tech Stack

- Python 3.12, Pydantic, PydanticAI, pytest in `research/tools/OGhidra`.
- TypeScript 5.6 project references in `packages/core`.
- Existing local OpenAI-compatible Qwen provider through OGhidra configuration.

## Commands

```powershell
# Analyze one chunk and write its reusable analysis manifest.
python research/tools/OGhidra/main.py finish-port --chunk chunk_0048 --analyze-chunk

# List the execution units without calling a model.
python research/tools/OGhidra/main.py finish-port --chunk chunk_0048 --list-units

# Port one analyzed execution unit.
python research/tools/OGhidra/main.py finish-port --chunk chunk_0048 --port-unit challenge-controller

# Explicit compatibility escape hatch; never the GUI default.
python research/tools/OGhidra/main.py finish-port --legacy-address-stream --mode resume

# Focused verification.
python -m pytest research/tools/OGhidra/tests/test_port_chunk_workflow.py research/tools/OGhidra/tests/test_port_scheduler.py research/tools/OGhidra/tests/test_port_source_loop.py
pnpm --filter @gf/core build
pnpm typecheck
```

## Project Structure

```text
research/tools/OGhidra/src/port_chunk_workflow.py
  Chunk parsing, deterministic evidence, analysis schema, unit manifests, unit port orchestration.
research/tools/OGhidra/src/port_scheduler.py
  Safe CLI routing and legacy-stream provider pause behavior.
research/tools/OGhidra/src/port_source_loop.py
  Bounded generation/repair and unit-entry reachability gates.
research/tools/OGhidra/src/port_activity.py
  Run-scoped durable activity events.
research/decomp/generated/finish-game-port/chunks/<chunk>/analysis.json
  Reusable analysis and execution-unit manifest.
packages/core/src/gcRuntime.ts
  Big-endian memory, function registry, numeric compatibility, and host interfaces.
research/tools/OGhidra/tests/test_port_chunk_workflow.py
  Offline chunk workflow tests.
```

## Code Style

Python data crossing process/model boundaries uses strict Pydantic models. Runtime addresses are normalized unsigned 32-bit numbers or `0x`-prefixed lowercase strings.

```python
class ExecutionUnit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    function_addresses: list[str]
    external_dependencies: list[str] = []
    runtime_entry_symbols: list[str] = []
```

TypeScript memory operations preserve GameCube big-endian widths explicitly:

```ts
readF32(address: number): number {
  return this.view.getFloat32(this.offset(address), false);
}
```

## Testing Strategy

- Parser tests use miniature chunk/index fixtures and run with no Ghidra or model.
- Analysis tests validate strict saved model responses and deterministic fallback grouping.
- CLI tests prove `--list-units` performs no model call and legacy streaming requires an explicit flag.
- Scheduler tests prove a provider outage transitions to `paused_provider_unavailable` after one failed generation request.
- Source-loop tests prove attempts never overwrite earlier checkpoints and declared runtime symbols—not unrelated exports—must be reachable.
- TypeScript compile tests cover public runtime contracts; a small executable self-check covers big-endian memory and function aliases.
- Existing OGhidra, repository typecheck, ROM, game-session, and browser tests remain regression gates.

## Boundaries

- Always: keep model calls bounded; checkpoint analysis and attempts; validate paths and schemas; preserve user worktree changes; verify before integration.
- Ask first: remove existing semantic runtime modules, add dependencies, change CI, or automatically port more than the selected unit.
- Never: resume the address stream implicitly; run model-proposed shell commands; mark dead exports integrated; overwrite prior attempts; retry generation indefinitely; commit or push during analysis/list operations.

## Success Criteria

- PID/provider outages do not create repeated prompts or model calls; run state becomes `paused_provider_unavailable`.
- Every activity event includes the current `run_id`.
- Each source repair writes a new immutable attempt directory.
- `chunk_0048.c` is parsed as one chunk with all indexed functions and can produce/list execution units offline.
- Chunk analysis uses at most one structured model request and no model-driven repository browsing.
- Unit generation permits at most three workspace turns and three repair attempts by default.
- A selected unit is rejected if its declared runtime symbols have no executable production reference.
- `GcMemory` preserves big-endian signed/unsigned/f32 behavior and `GcFunctionRegistry` preserves address aliases.
- The GUI starts the Challenge chunk analysis instead of the legacy address walker.
- Focused pytest, `@gf/core` build, and repository typecheck pass.

## Open Questions

- Dolphin-derived differential scenarios remain a per-unit artifact and are not automatically synthesized in this slice.
- The first live Challenge controller port still requires an online Qwen provider; offline implementation covers analysis fixtures, deterministic grouping, manifests, and orchestration.
- Migrating existing `RomActor` families into raw memory is deliberately deferred; adapters can be introduced unit by unit.
