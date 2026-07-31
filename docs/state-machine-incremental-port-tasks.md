# Tasks: Incremental State-Machine Port Pipeline

- [ ] Implement the GG4E state-machine probe core.
  - Acceptance: Pydantic artifact schema, 4-byte big-endian pointer decoding, dispatcher
    metadata extraction, bounded table walk, evidence records, and explicit blocked status.
  - Verify: `python -m pytest -q tests/test_state_machine_probe.py`
  - Files: `src/state_machine_probe.py`, `tests/test_state_machine_probe.py`

- [ ] Expose the probe through the OGhidra CLI.
  - Acceptance: `main.py probe-state-machine --help` works and the command writes an atomic
    deterministic JSON artifact.
  - Verify: CLI test plus a fake-client probe.
  - Files: `main.py`, `src/state_machine_probe.py`, `tests/test_state_machine_probe.py`

- [ ] Replace complete-file model output with bounded unified diffs.
  - Acceptance: existing-file replacement, path escape, oversized patches, missing context,
    placeholders, and the captured destructive response are rejected before application.
  - Verify: `python -m pytest -q tests/test_port_source_loop.py`
  - Files: `src/port_source_loop.py`, `tests/test_port_source_loop.py`,
    `tests/fixtures/broken_combat_response.txt`

- [ ] Implement the cumulative disposable-worktree transaction.
  - Acceptance: two unit patches commit sequentially in one worktree; either failure pushes
    nothing; production checkout is unchanged.
  - Verify: `python -m pytest -q tests/test_incremental_port.py`
  - Files: `src/incremental_port.py`, `tests/test_incremental_port.py`

- [ ] Add guarded automatic main push.
  - Acceptance: only the cumulative passing tip fast-forward pushes to `main`; remote movement
    produces `push_race`; no force-push command exists.
  - Verify: disposable bare-repository integration tests.
  - Files: `src/incremental_port.py`, `tests/test_incremental_port.py`

- [ ] Wire the two-unit POC CLI to the probe and source loop.
  - Acceptance: `main.py prove-incremental-port --unit A --unit B --push-main` performs the
    approved transaction and saves durable artifacts.
  - Verify: CLI integration test with fake model responses and Git remote.
  - Files: `main.py`, `src/incremental_port.py`, `tests/test_incremental_port.py`

- [ ] Run the live proof and repository gates.
  - Acceptance: live `boot.dol`, two genuine destination gaps, two cumulative passing commits,
    one fast-forward main push, and a report with evidence-status distinctions.
  - Verify: full pytest/Ruff and GotYaForce pnpm gates from the spec.
  - Files: generated run artifacts and the final workflow report only.
