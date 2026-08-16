"""The unit-transition invariant, at the driver level.

Before the workflow starts unit B after leaving unit A, a durable progress
record for A must exist. These tests drive the real ``WasmUnitDriver`` with a
recording journal and assert that every path that causes the selector to move on
emits exactly one checkpoint, correctly classified.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from src.port_driver import EXIT_NO_WORK, EXIT_PROGRESSED, EXIT_STOPPED
from src.port_progress import (
    RESULT_DEFERRED,
    RESULT_GATE_FAILED,
    RESULT_GREEN,
    RESULT_RETRYABLE,
    RESULT_STAGED,
    RESULT_STRUCTURAL_INELIGIBLE,
)
from src.port_wasm_units import WasmUnitDriver


class RecordingJournal:
    def __init__(self):
        self.transitions = []
        self.machine_only = []
        self.flushes = 0
        self.pending = False

    def checkpoint(self, *, transition=None, units=None, **kwargs):
        if transition is None:
            self.machine_only.append(kwargs)
        else:
            self.transitions.append(transition)
        return {"recorded": True, "committed": True, "pushed": True}

    def push_is_pending(self) -> bool:
        return self.pending

    def flush_pending_push(self):
        self.flushes += 1
        self.pending = False
        return {"pushed": True}


def _completed(rc: int = 0, stdout: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["git"], returncode=rc, stdout=stdout, stderr="")


def _repo(tmp_path: Path, units: list[dict]) -> Path:
    repo = tmp_path / "repo"
    (repo / "research/decomp/ghidra-export").mkdir(parents=True)
    (repo / "research/decomp/generated/finish-game-port").mkdir(parents=True)
    (repo / "research/decomp/poc").mkdir(parents=True)
    (repo / "research/decomp/ghidra-export/chunk_9999.c").write_text(
        "// line1\nint zz_test_(int a)\n{\n  return a + 1;\n}\n// tail\n", encoding="utf-8"
    )
    (repo / "research/decomp/poc/seed.h").write_text("/* seed */\n", encoding="utf-8")
    (repo / "research/decomp/generated/finish-game-port/wasm-units.json").write_text(
        json.dumps({"queue_schema": 1, "units": units}), encoding="utf-8"
    )
    return repo


def _unit(name: str, *, start: int = 2, end: int = 5, oracle: dict | None = None) -> dict:
    return {
        "name": name,
        "extractions": [
            {"file": "research/decomp/ghidra-export/chunk_9999.c", "start": start, "end": end}
        ],
        "exported_functions": ["zz_test_"],
        "header_seed": "research/decomp/poc/seed.h",
        "oracle": oracle
        if oracle is not None
        else {
            "command": ["node", "fake.mjs"],
            "cwd": "research/decomp/poc",
            "env": {},
            "success_patterns": ["PASS"],
        },
    }


def _linking_build(workdir, exports, extra=None):
    """A build that succeeds -- and produces the artifact the green path copies."""
    (workdir / "unit.wasm").write_bytes(b"\x00asm\x01\x00\x00\x00")
    return True, ""


class StubLLM:
    """Always returns a plausible header so the compile-fix loop can iterate."""

    default_model = "configured/model"

    def __init__(self):
        self.calls = 0

    def generate(self, **kwargs):
        self.calls += 1
        return "```c\n/* patched header */\n```"


def _driver(repo: Path, journal: RecordingJournal, **kwargs) -> WasmUnitDriver:
    defaults = dict(
        repo_root=repo,
        units_budget=1,
        journal=journal,
        git_runner=lambda *args: _completed(0, "deadbeefcafe\n"),
        build_runner=_linking_build,
        oracle_runner=lambda unit, wasm: (True, "16/16", "PASS"),
    )
    defaults.update(kwargs)
    return WasmUnitDriver(**defaults)


# ------------------------------------------------------------------- classes


def test_green_unit_emits_a_green_checkpoint_carrying_the_product_sha(tmp_path):
    journal = RecordingJournal()
    driver = _driver(_repo(tmp_path, [_unit("unit-a")]), journal)

    assert driver.run() in (EXIT_NO_WORK, EXIT_PROGRESSED)

    green = [t for t in journal.transitions if t.result == RESULT_GREEN]
    assert len(green) == 1
    assert green[0].unit == "unit-a"
    assert green[0].stage == "commit"
    assert green[0].product_commit == "deadbeefcafe"
    assert green[0].tier == "oracle_green"
    assert green[0].oracle_summary == "16/16"


def test_compile_only_unit_emits_a_staged_checkpoint(tmp_path):
    journal = RecordingJournal()
    repo = _repo(tmp_path, [_unit("unit-a", oracle={"type": "compile_only"})])
    driver = _driver(repo, journal)

    driver.run()

    staged = [t for t in journal.transitions if t.result == RESULT_STAGED]
    assert len(staged) == 1
    assert staged[0].tier == "compile_only"
    assert staged[0].product_commit == "deadbeefcafe"
    assert "UNVERIFIED" in staged[0].detail


def test_link_gate_failure_is_a_gate_failure_at_wasm_link(tmp_path):
    journal = RecordingJournal()
    driver = _driver(
        _repo(tmp_path, [_unit("unit-a")]), journal,
        build_runner=lambda workdir, exports, extra=None: (False, "link gate: CONCAT44"),
        llm=StubLLM(),   # the header fix "works" but the gate keeps rejecting
    )

    driver.run()

    assert [(t.result, t.stage) for t in journal.transitions] == [
        (RESULT_GATE_FAILED, "wasm-link")
    ]


def test_oracle_red_is_a_gate_failure_at_oracle(tmp_path):
    journal = RecordingJournal()
    driver = _driver(
        _repo(tmp_path, [_unit("unit-a")]), journal,
        oracle_runner=lambda unit, wasm: (False, "3/16", "FAIL"),
    )

    driver.run()

    assert [(t.result, t.stage) for t in journal.transitions] == [
        (RESULT_GATE_FAILED, "oracle")
    ]


def test_llm_failure_is_retryable_at_compile_fix(tmp_path):
    journal = RecordingJournal()

    class BoomLLM:
        default_model = "configured/model"

        def generate(self, **kwargs):
            raise RuntimeError("400 Client Error: Bad Request")

    driver = _driver(
        _repo(tmp_path, [_unit("unit-a")]), journal,
        build_runner=lambda workdir, exports, extra=None: (False, "error: no CONCAT44"),
        llm=BoomLLM(),
    )

    driver.run()

    assert [(t.result, t.stage) for t in journal.transitions] == [
        (RESULT_RETRYABLE, "compile-fix")
    ]
    assert "400 Client Error" in journal.transitions[0].detail


def test_bad_extraction_range_is_structurally_ineligible(tmp_path):
    journal = RecordingJournal()
    driver = _driver(_repo(tmp_path, [_unit("unit-a", start=2, end=999)]), journal)

    driver.run()

    assert [(t.result, t.stage) for t in journal.transitions] == [
        (RESULT_STRUCTURAL_INELIGIBLE, "extract")
    ]


# ---------------------------------------------------------------- invariants


def test_every_unit_transition_is_checkpointed_before_the_next_unit(tmp_path):
    journal = RecordingJournal()
    units = [_unit(f"unit-{index}") for index in range(4)]
    driver = _driver(
        _repo(tmp_path, units), journal, until_blocked=True,
        oracle_runner=lambda unit, wasm: (False, "0/16", "FAIL"),
    )

    driver.run()

    assert [t.unit for t in journal.transitions] == [
        "unit-0", "unit-1", "unit-2", "unit-3"
    ]
    assert all(t.result == RESULT_GATE_FAILED for t in journal.transitions)


def test_a_unit_interrupted_mid_flight_is_reconciled_as_deferred(tmp_path):
    journal = RecordingJournal()
    repo = _repo(tmp_path, [_unit("unit-a"), _unit("unit-b")])
    state_path = repo / "research/decomp/generated/finish-game-port/wasm-units-state.json"
    state_path.write_text(
        json.dumps(
            {
                "state_schema": 1,
                "units": {
                    "unit-a": {"status": "porting", "attempts": 1, "last_stage": "build"}
                },
            }
        ),
        encoding="utf-8",
    )
    driver = _driver(repo, journal)

    driver.run()

    deferred = [t for t in journal.transitions if t.result == RESULT_DEFERRED]
    assert len(deferred) == 1
    assert deferred[0].unit == "unit-a"
    assert deferred[0].stage == "build"
    # ...and the unit is back in the pool, not stuck as `porting` forever.
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["units"]["unit-a"]["status"] in ("green", "pending", "red_retryable")


def test_structurally_ineligible_units_do_not_keep_the_queue_alive(tmp_path):
    """The false-work trap: a permanently ineligible unit must not make the
    driver report 'more work remains' forever and hot-loop the supervisor."""
    journal = RecordingJournal()
    driver = _driver(
        _repo(tmp_path, [_unit("unit-a", start=2, end=999)]), journal, until_blocked=True
    )

    assert driver.run() == EXIT_NO_WORK


def test_cooperative_stop_emits_a_machine_checkpoint(tmp_path):
    journal = RecordingJournal()
    repo = _repo(tmp_path, [_unit("unit-a")])
    (repo / "research/decomp/generated/finish-game-port/control.json").write_text(
        json.dumps({"command": "stop_after_stage"}), encoding="utf-8"
    )
    driver = _driver(repo, journal)

    assert driver.run() == EXIT_STOPPED
    assert journal.machine_only
    assert journal.machine_only[-1]["machine"].workflow_state == "stopped_at_boundary"


def test_pending_progress_push_is_retried_at_run_start(tmp_path):
    journal = RecordingJournal()
    journal.pending = True
    driver = _driver(_repo(tmp_path, [_unit("unit-a")]), journal)

    driver.run()

    assert journal.flushes == 1


def test_a_journal_that_raises_never_fails_a_unit(tmp_path):
    class ExplodingJournal(RecordingJournal):
        def checkpoint(self, **kwargs):
            raise RuntimeError("github is down and the disk is on fire")

    driver = _driver(_repo(tmp_path, [_unit("unit-a")]), ExplodingJournal())

    assert driver.run() in (EXIT_NO_WORK, EXIT_PROGRESSED)
    state = json.loads(
        (
            tmp_path / "repo/research/decomp/generated/finish-game-port/wasm-units-state.json"
        ).read_text(encoding="utf-8")
    )
    assert state["units"]["unit-a"]["status"] == "green"
