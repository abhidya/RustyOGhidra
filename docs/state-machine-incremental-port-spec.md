# Spec: Incremental State-Machine Port Pipeline

## Objective

Build a GotYaForce-specific workflow that discovers original GG4E state-machine execution
units through the live Ghidra HTTP API, produces evidence-backed port candidates with local
Qwen, verifies each candidate in an isolated Git worktree, and automatically fast-forward
pushes verified cumulative progress to `origin/main`.

The first proof of concept must demonstrate incrementality:

1. Probe and model two small, game-owned state-machine units.
2. Select units with concrete destination gaps and sufficient original evidence.
3. Apply unit 1 in an isolated integration worktree and pass all gates.
4. Apply unit 2 on top of unit 1 and pass all gates again.
5. Push neither unit if either unit fails.
6. If both pass, atomically fast-forward push the cumulative tip to `origin/main`.

The workflow must preserve distinct evidence statuses. Compilation, browser parity, and
existing TypeScript behavior do not constitute original-evidence verification.

## Tech Stack

- Python 3.12
- Pydantic 2 for probe, model-output, and durable-state schemas
- `requests` for the live Ghidra and OpenAI-compatible APIs
- Git disposable worktrees for candidate isolation
- Existing OGhidra atomic JSON writer and activity stream
- Existing GotYaForce pnpm/TypeScript verification commands
- Local Qwen through the configured OpenAI-compatible gateway

## Commands

Probe a dispatcher without modifying either repository:

```powershell
python main.py probe-state-machine `
  --address 0x800925a0 `
  --ghidra-url http://127.0.0.1:8080 `
  --max-handlers 32 `
  --output D:\GotYaForce\research\decomp\generated\state-machine-probes\800925a0.json
```

Probe a known table when the dispatcher does not expose it cleanly:

```powershell
python main.py probe-state-machine `
  --address 0x800925a0 `
  --table 0x802db478 `
  --state-offset 0x581 `
  --state-width 1 `
  --ghidra-url http://127.0.0.1:8080 `
  --output D:\GotYaForce\research\decomp\generated\state-machine-probes\800925a0.json
```

Run the cumulative two-unit POC and push its final verified tip to `main`:

```powershell
python main.py prove-incremental-port `
  --unit <first-probe.json> `
  --unit <second-probe.json> `
  --base origin/main `
  --push-main
```

Run OGhidra tests:

```powershell
python -m pytest -q
ruff check src tests
```

Run GotYaForce gates inside the candidate worktree:

```powershell
pnpm typecheck
pnpm --filter @gf/combat build
pnpm selfcheck:rom
pnpm selfcheck:game-session
pnpm --filter game build
pnpm smoke:browser
```

## Project Structure

```text
research/tools/OGhidra/
  src/state_machine_probe.py       Live API probe and GG4E table decoding
  src/incremental_port.py          Two-unit cumulative worktree transaction
  src/port_source_loop.py          Bounded Qwen patch generation and validation
  src/port_workflow.py             Existing atomic durable-state helpers
  tests/test_state_machine_probe.py
  tests/test_incremental_port.py
  tests/fixtures/
    broken_combat_response.txt     Prior destructive response rejection fixture

research/decomp/generated/
  state-machine-probes/            Read-only probe artifacts
  incremental-port/                Prompts, responses, patches, gates, and state
```

Generated run artifacts remain outside implementation commits except for small deliberate
test fixtures.

## State-Machine Probe Contract

The probe calls only read-only Ghidra endpoints:

- `/function_bundle`
- `/decompile_function`
- `/xrefs_to`
- `/xrefs_from`
- `/read_bytes`
- `/list_functions`
- `/data`

The preflight must fail with `blocked_no_program` when Ghidra reports `No program loaded`.
It must never silently replace live evidence with a saved-session summary.

GG4E table decoding uses:

- 4-byte pointers
- big-endian byte order
- 4-byte alignment
- executable-address validation against the live function inventory
- table boundaries from Ghidra's defined `PTR_FUN_*` data labels
- a configurable maximum handler count
- termination on the first invalid pointer after at least one valid entry

The probe emits:

```json
{
  "schema": 1,
  "unit_id": "state-machine-800925a0",
  "kind": "state_dispatcher",
  "root_addresses": ["0x800925a0"],
  "state_field": {
    "offset": "0x581",
    "width": 1,
    "signedness": "signed"
  },
  "function_pointer_tables": [
    {
      "address": "0x802db478",
      "dispatcher_address": "0x800925a0",
      "state_field": {
        "offset": "0x581",
        "width": 1,
        "signedness": "signed"
      },
      "pointer_size": 4,
      "endianness": "big",
      "entries": []
    }
  ],
  "handlers": [],
  "transitions": [],
  "callers": [],
  "callees": [],
  "global_reads": [],
  "global_writes": [],
  "constants": [],
  "raw_constant_bits": [],
  "update_order": [],
  "existing_destination_code": [],
  "evidence": [],
  "unknowns": []
}
```

Every handler and transition must cite a function address plus decompile, instruction, raw
table-byte, or xref evidence. Inferences remain marked `derived` or `tentative`.

## Model and Patch Contract

Qwen receives only the probed execution unit, its direct ownership chain, relevant
destination interfaces, and one small analogous implementation.

Defaults:

- maximum output: 8,192 tokens
- temperature: 0.1
- maximum attempts: 2
- finite request deadline
- explicit cancellation

The model returns structured semantics followed by a bounded unified diff. Complete
replacement contents for an existing file are rejected.

Patch validation rejects:

- paths outside the unit allow-list
- missing exact diff context
- complete existing-file replacement
- excessive deletion or total changed lines
- truncated JSON or Markdown-wrapped patches
- unbalanced source delimiters
- removed expected exports
- placeholder implementations
- test-only changes that conceal a production defect

## Incremental Git Transaction

1. Fetch `origin/main` and record its commit.
2. Create one disposable integration branch and worktree from that commit.
3. Probe/select unit 1 and save all evidence outside the worktree.
4. Generate and validate a bounded patch.
5. Apply only inside the worktree.
6. Run unit-specific and full configured gates.
7. Commit unit 1 inside the worktree.
8. Generate unit 2 against the new unit-1 commit.
9. Apply, verify, and commit unit 2.
10. Re-fetch `origin/main`.
11. Require `origin/main` to equal the recorded base.
12. Fast-forward push `HEAD:refs/heads/main`.
13. Never force push.

If either unit or any gate fails, restore/delete only the disposable worktree, record the
failure, and push nothing. If remote `main` advances, mark `push_race`, retain the verified
candidate, and push nothing.

After the two-unit proof succeeds, later verified units may use the same transaction one at
a time and automatically fast-forward push to `main`.

## Code Style

Use typed Pydantic models for external data and small pure functions for binary decoding:

```python
def decode_be_pointer(raw: bytes) -> int:
    if len(raw) != 4:
        raise ValueError("GG4E pointers must contain exactly four bytes")
    return int.from_bytes(raw, byteorder="big", signed=False)
```

- `snake_case` Python names
- explicit `Path` usage
- no broad exception swallowing in safety or Git code
- deterministic ordering in JSON output
- line length compatible with the existing Ruff configuration

## Testing Strategy

Unit tests:

- 32-bit big-endian pointer decoding
- dispatcher/table extraction from deterministic fake API responses
- `No program loaded` preflight
- invalid and truncated table termination
- evidence citation validation
- full-file and prior `combat.ts` response rejection
- patch path/size/context checks
- remote-main race rejection
- no force-push path

Integration tests:

- fake Ghidra HTTP server produces one code-driven and one table-driven unit
- two valid patches accumulate in one disposable worktree
- unit-2 failure pushes nothing
- both passing units produce one fast-forward push to a disposable bare repository's `main`
- production checkout remains byte-identical on success and failure

Live proof:

- `boot.dol` is loaded in Ghidra
- two small game-owned units have original evidence and real destination gaps
- both cumulative candidates pass every GotYaForce gate
- final tip is automatically fast-forward pushed to `origin/main`

## Boundaries

### Always

- Use original GG4E evidence as the semantic authority.
- Probe the live Ghidra program before generating a candidate.
- Apply model patches only in a disposable worktree.
- Preserve prompts, raw responses, evidence, patches, and gate logs.
- Require cumulative verification before pushing the POC.
- Re-check remote `main` immediately before pushing.

### Ask First

- Adding a new third-party dependency.
- Changing the configured GotYaForce gate list.
- Expanding patch allow-lists beyond the selected execution unit.
- Replacing fast-forward main pushes with another publication policy.

### Never

- Force push.
- Push a failed or partially verified POC.
- Edit the production checkout from model output.
- Treat existing TypeScript, screenshots, or browser parity as original proof.
- Invent missing transitions, handler ownership, constants, or timers.
- Commit credentials, tokens, or local secret configuration.

## Success Criteria

1. The probe reconstructs a known GG4E dispatcher/table fixture using 4-byte big-endian
   pointers and cites every handler entry.
2. A live missing-program state is reported as blocked rather than guessed.
3. The prior destructive model response is rejected before filesystem mutation.
4. Unit 1 passes in isolation and unit 2 passes cumulatively on top of unit 1.
5. Failure of either unit produces no remote update.
6. Remote advancement produces `push_race` and no force push.
7. Two passing units cause one automatic fast-forward update of `origin/main`.
8. The production checkout remains unchanged throughout the transaction.
9. Full OGhidra and GotYaForce verification passes.
10. The final report distinguishes compiled, test-passed, browser-regression,
    original-evidence, and trace-verified status.

## Open Questions

- The two final POC units will be selected from probe results. Existing Eagle Jet
  `0x8012b458` is a useful code-driven fixture but does not count as a new incremental unit
  unless the probe identifies a genuine unimplemented destination gap.
