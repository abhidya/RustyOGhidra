import json
import os
from pathlib import Path

import pytest

from src.port_chunk_workflow import ChunkAnalysis, ExecutionUnit, ProviderUnavailable
from src.port_driver import (
    EXIT_LOCKED,
    EXIT_NO_WORK,
    EXIT_PROGRESSED,
    EXIT_PROVIDER_PAUSED,
    PortDriver,
    build_session_index,
)
from src.port_source_loop import SourceLoopResult


def fixture_repo(tmp_path: Path) -> Path:
    export = tmp_path / "research/decomp/ghidra-export"
    export.mkdir(parents=True)
    (export / "chunk_0048.c").write_text("// ==== 80001000  a ====\n", encoding="utf-8")
    run_root = tmp_path / "research/decomp/generated/finish-game-port"
    run_root.mkdir(parents=True)
    (run_root / "whole-program-manifest.json").write_text(
        json.dumps(
            {
                "functions": {
                    "0x80009000": {"port_status": "integrated", "fingerprint": "aa"},
                    "0x80009004": {"port_status": "integrated", "fingerprint": "bb"},
                    "0x80009008": {"port_status": "bundled"},
                }
            }
        ),
        encoding="utf-8",
    )
    return tmp_path


def unit(
    unit_id: str,
    addresses: list[str],
    *,
    classification: str = "game_owned",
    entry_symbols: list[str] | None = None,
) -> ExecutionUnit:
    return ExecutionUnit(
        id=unit_id,
        label=unit_id,
        classification=classification,
        summary="",
        function_addresses=addresses,
        runtime_entry_symbols=entry_symbols if entry_symbols is not None else [unit_id],
    )


def analysis_with(units: list[ExecutionUnit], *, generated_by: str = "model") -> ChunkAnalysis:
    return ChunkAnalysis(
        chunk="chunk_0048.c",
        chunk_sha256="0" * 64,
        function_count=sum(len(item.function_addresses) for item in units),
        generated_by=generated_by,
        generated_at="2026-08-06T00:00:00Z",
        functions=[
            {"address": address, "name": f"fn_{address}"}
            for item in units
            for address in item.function_addresses
        ],
        units=units,
    )


class StubWorkflow:
    def __init__(self, root: Path, analysis: ChunkAnalysis | None):
        self.root = root
        self.analysis = analysis
        self.analyze_calls = 0
        self.port_calls: list[str] = []
        self.port_results: dict[str, object] = {}

    def load_analysis(self, chunk: str) -> ChunkAnalysis:
        if self.analysis is None:
            raise FileNotFoundError(chunk)
        return self.analysis

    def analyze(self, chunk: str, *, force: bool = False) -> ChunkAnalysis:
        self.analyze_calls += 1
        if self.analysis is None:
            raise ValueError("invalid unit coverage")
        return self.analysis

    def port_unit(self, chunk: str, unit_id: str):
        self.port_calls.append(unit_id)
        result = self.port_results.get(unit_id)
        if isinstance(result, Exception):
            raise result
        if result is None:
            return SourceLoopResult(passed=True, attempts=1, files=[f"{unit_id}.ts"])
        return result

    def chunk_root(self, chunk: str) -> Path:
        return self.root / "research/decomp/generated/finish-game-port/chunks" / chunk


def make_driver(root: Path, workflow: StubWorkflow, **kwargs) -> PortDriver:
    return PortDriver(repo_root=root, workflow=workflow, **kwargs)


def read_ledger(root: Path) -> dict:
    path = root / "research/decomp/generated/finish-game-port/port-ledger.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_ledger_imports_legacy_integrations_once(tmp_path: Path):
    root = fixture_repo(tmp_path)
    workflow = StubWorkflow(root, analysis_with([unit("gx", ["0x80002000"], classification="hardware_or_sdk")]))

    exit_code = make_driver(root, workflow).run()

    ledger = read_ledger(root)
    assert exit_code == EXIT_NO_WORK
    assert ledger["imported_legacy"]["integrated_addresses"] == ["0x80009000", "0x80009004"]
    assert ledger["counters"]["functions_integrated"] == 2
    assert ledger["counters"]["functions_total"] == 3


def test_priority_combat_unit_ports_first_and_singletons_wait(tmp_path: Path):
    root = fixture_repo(tmp_path)
    units = [
        unit("boot-helpers", ["0x80001000", "0x80001004"], entry_symbols=["boot_helpers_init"]),
        unit(
            "challenge-controller",
            ["0x80001010", "0x80001014"],
            entry_symbols=["dispatch_challenge_flow_state"],
        ),
        unit("lone-fn", ["0x80001020"], entry_symbols=["lone_named_fn"]),
    ]
    workflow = StubWorkflow(root, analysis_with(units, generated_by="deterministic"))

    exit_code = make_driver(root, workflow).run()

    ledger = read_ledger(root)
    chunk_units = ledger["chunks"]["chunk_0048"]["units"]
    assert exit_code == EXIT_PROGRESSED
    assert workflow.port_calls == ["challenge-controller"]
    assert chunk_units["challenge-controller"]["status"] == "integrated"
    assert chunk_units["lone-fn"]["eligibility"] == "ineligible_singleton_pending_model"
    assert chunk_units["boot-helpers"]["eligibility"] == "eligible_pending_model_analysis"
    assert workflow.analyze_calls == 0


def test_existing_ledger_priorities_reconcile_from_code_defaults(tmp_path: Path):
    root = fixture_repo(tmp_path)
    workflow = StubWorkflow(root, analysis_with([unit("gx", ["0x80002000"], classification="hardware_or_sdk")]))
    # First run creates the ledger; simulate a stale seed list plus an
    # owner-added extra that must survive after the code defaults.
    make_driver(root, workflow).run()
    path = root / "research/decomp/generated/finish-game-port/port-ledger.json"
    ledger = json.loads(path.read_text(encoding="utf-8"))
    ledger["priority_chunks"] = ["chunk_0048", "chunk_9999"]
    path.write_text(json.dumps(ledger), encoding="utf-8")

    make_driver(root, workflow).run()

    from src.port_driver import DEFAULT_PRIORITY_CHUNKS, DEFAULT_PRIORITY_ENTRY_SYMBOLS

    ledger = read_ledger(root)
    assert ledger["priority_chunks"] == list(DEFAULT_PRIORITY_CHUNKS) + ["chunk_9999"]
    assert ledger["priority_entry_symbols"] == list(DEFAULT_PRIORITY_ENTRY_SYMBOLS)


def test_all_terminal_run_exits_zero_with_no_requests_or_ports(tmp_path: Path):
    root = fixture_repo(tmp_path)
    units = [
        unit("controller", ["0x80001000"], entry_symbols=["real_controller"]),
        unit("gx", ["0x80002000"], classification="hardware_or_sdk", entry_symbols=[]),
    ]
    workflow = StubWorkflow(root, analysis_with(units))

    first = make_driver(root, workflow).run()
    second = make_driver(root, workflow).run()

    assert first == EXIT_PROGRESSED
    assert second == EXIT_NO_WORK
    assert workflow.port_calls == ["controller"]
    assert workflow.analyze_calls == 0
    ledger = read_ledger(root)
    assert ledger["chunks"]["chunk_0048"]["units"]["gx"]["status"] == "skipped"


def test_units_covered_by_legacy_import_become_aliases(tmp_path: Path):
    root = fixture_repo(tmp_path)
    units = [unit("legacy-covered", ["0x80009000", "0x80009004"], entry_symbols=["real_name"])]
    workflow = StubWorkflow(root, analysis_with(units))

    exit_code = make_driver(root, workflow).run()

    assert exit_code == EXIT_NO_WORK
    assert workflow.port_calls == []
    ledger = read_ledger(root)
    assert ledger["chunks"]["chunk_0048"]["units"]["legacy-covered"]["status"] == "alias"


def test_concurrent_drive_is_blocked_by_the_lock(tmp_path: Path):
    root = fixture_repo(tmp_path)
    workflow = StubWorkflow(root, analysis_with([]))
    run_root = root / "research/decomp/generated/finish-game-port"
    (run_root / "driver.lock").write_text(
        json.dumps({"pid": os.getpid(), "started_at": "now"}), encoding="utf-8"
    )

    exit_code = make_driver(root, workflow).run()

    assert exit_code == EXIT_LOCKED
    assert workflow.port_calls == []


def test_stale_lock_from_dead_pid_is_reclaimed(tmp_path: Path):
    root = fixture_repo(tmp_path)
    workflow = StubWorkflow(root, analysis_with([]))
    run_root = root / "research/decomp/generated/finish-game-port"
    (run_root / "driver.lock").write_text(
        json.dumps({"pid": 999999999, "started_at": "then"}), encoding="utf-8"
    )

    exit_code = make_driver(root, workflow).run()

    assert exit_code == EXIT_NO_WORK
    assert not (run_root / "driver.lock").exists()


def test_interrupted_porting_unit_is_resumed_first(tmp_path: Path):
    root = fixture_repo(tmp_path)
    units = [
        unit("alpha", ["0x80001000"], entry_symbols=["alpha_real"]),
        unit("beta", ["0x80001010"], entry_symbols=["beta_real"]),
    ]
    workflow = StubWorkflow(root, analysis_with(units))
    driver = make_driver(root, workflow)
    ledger = driver._load_or_create_ledger()
    driver._unit_record(ledger, "chunk_0048", "beta").update(status="porting")
    driver._save_ledger(ledger, reason="test_setup")

    exit_code = driver.run()

    assert exit_code == EXIT_PROGRESSED
    assert workflow.port_calls == ["beta"]


def test_provider_outage_pauses_with_exit_4(tmp_path: Path):
    root = fixture_repo(tmp_path)
    units = [unit("alpha", ["0x80001000"], entry_symbols=["alpha_real"])]
    workflow = StubWorkflow(root, analysis_with(units))
    workflow.port_results["alpha"] = ProviderUnavailable("connection refused")

    exit_code = make_driver(root, workflow).run()

    assert exit_code == EXIT_PROVIDER_PAUSED
    ledger = read_ledger(root)
    assert ledger["chunks"]["chunk_0048"]["units"]["alpha"]["status"] == "paused_provider"


def test_progress_mirrors_real_counts_into_run_state(tmp_path: Path):
    root = fixture_repo(tmp_path)
    units = [unit("alpha", ["0x80001000", "0x80001004"], entry_symbols=["alpha_real"])]
    workflow = StubWorkflow(root, analysis_with(units))

    make_driver(root, workflow).run()

    state = json.loads(
        (root / "research/decomp/generated/finish-game-port/run-state.json").read_text(
            encoding="utf-8"
        )
    )
    assert state["run_mode"] == "driver"
    assert state["counters"]["units_integrated"] == 1
    assert state["counters"]["functions_integrated"] == 4  # 2 legacy + 2 new
    assert state["counters"]["chunks_total"] == 1
    assert state["progress"]["total_work"] == 3
    assert isinstance(state["queue"], list)


def test_run_state_is_driver_owned_and_porting_names_the_unit(tmp_path: Path):
    root = fixture_repo(tmp_path)
    units = [unit("alpha", ["0x80001000", "0x80001004"], entry_symbols=["alpha_real"])]
    workflow = StubWorkflow(root, analysis_with(units))
    driver = make_driver(root, workflow)
    state_path = root / "research/decomp/generated/finish-game-port/run-state.json"
    porting_snapshots: list[dict] = []
    original = workflow.port_unit

    def capture(chunk: str, unit_id: str):
        porting_snapshots.append(json.loads(state_path.read_text(encoding="utf-8")))
        return original(chunk, unit_id)

    workflow.port_unit = capture
    driver.run()

    # Mid-port, run-state must carry the driver's view including the unit.
    assert porting_snapshots[0]["run_mode"] == "driver"
    assert porting_snapshots[0]["status"] == "porting"
    assert porting_snapshots[0]["chunk"] == "chunk_0048"
    assert porting_snapshots[0]["unit"] == "alpha"
    # The unit workflow writes its own file, never run-state.json.
    from src.port_chunk_workflow import ChunkPortWorkflow

    assert ChunkPortWorkflow(repo_root=root).state_path.name == "unit-state.json"


def test_events_stream_records_the_step_with_run_ids(tmp_path: Path):
    root = fixture_repo(tmp_path)
    units = [unit("alpha", ["0x80001000"], entry_symbols=["alpha_real"])]
    workflow = StubWorkflow(root, analysis_with(units))

    make_driver(root, workflow).run()

    events_path = root / "research/decomp/generated/finish-game-port/events.jsonl"
    events = [
        json.loads(line)
        for line in events_path.read_text(encoding="utf-8").splitlines()
        if line
    ]
    kinds = [event["kind"] for event in events]
    assert "driver_started" in kinds
    assert "unit_started" in kinds
    assert "unit_integrated" in kinds
    assert all(event["run_id"] for event in events)


def session_dir(root: Path, name: str, functions: dict) -> None:
    directory = root / "analysis_sessions" / name
    directory.mkdir(parents=True)
    (directory / "session.json").write_text(
        json.dumps({"analyzed_functions": functions}), encoding="utf-8"
    )


def test_session_index_merges_latest_timestamp_wins(tmp_path: Path):
    session_dir(
        tmp_path,
        "session_1_old",
        {
            "80001000": {
                "new_name": "old_name",
                "behavior_summary": "old",
                "analysis_timestamp": 100.0,
            }
        },
    )
    session_dir(
        tmp_path,
        "session_2_new",
        {
            "80001000": {
                "new_name": "dispatch_challenge_flow_state",
                "behavior_summary": "Drives the challenge flow state machine.",
                "analysis_timestamp": 200.0,
            }
        },
    )
    output = tmp_path / "session-index.json"

    index = build_session_index(tmp_path / "analysis_sessions", output, floor=1)

    assert index["function_count"] == 1
    assert index["functions"]["0x80001000"]["name"] == "dispatch_challenge_flow_state"
    assert output.is_file()


def test_session_index_refuses_to_write_below_floor(tmp_path: Path):
    session_dir(
        tmp_path,
        "session_1",
        {"80001000": {"new_name": "x", "analysis_timestamp": 1.0}},
    )
    output = tmp_path / "session-index.json"

    with pytest.raises(ValueError, match="floor"):
        build_session_index(tmp_path / "analysis_sessions", output, floor=10)

    assert not output.exists()


def test_oversized_analysis_blocks_chunk_without_spending_budget(tmp_path: Path):
    from src.port_chunk_workflow import ChunkAnalysisOversized

    root = fixture_repo(tmp_path)
    workflow = StubWorkflow(root, None)
    workflow.last_analyze_requests = 0

    def oversized(chunk: str, *, force: bool = False):
        raise ChunkAnalysisOversized(f"{chunk}: too big for context")

    workflow.analyze = oversized

    exit_code = make_driver(root, workflow).run()

    ledger = read_ledger(root)
    analysis = ledger["chunks"]["chunk_0048"]["analysis"]
    # The block is a durable state change, so it counts as the step.
    assert exit_code == EXIT_PROGRESSED
    assert analysis["status"] == "analysis_blocked"
    assert "too big for context" in analysis["detail"]
    assert analysis.get("model_requests_spent", 0) == 0


def test_unrefined_units_in_model_analysis_defer_instead_of_skip(tmp_path: Path):
    # Refinement design: a model-generated analysis can carry untouched
    # clusters (split remainders). They must wait for judgment, never be
    # terminally skipped -- even when their entry symbols are placeholders.
    root = fixture_repo(tmp_path)
    units = [
        unit("refined", ["0x80001000"], entry_symbols=["real_entry"]),
        unit("leftover", ["0x80001004"], entry_symbols=["FUN_80001004"]),
    ]
    units[1] = units[1].model_copy(update={"provenance": "deterministic"})
    workflow = StubWorkflow(root, analysis_with(units, generated_by="model"))

    exit_code = make_driver(root, workflow).run()

    ledger = read_ledger(root)
    chunk_units = ledger["chunks"]["chunk_0048"]["units"]
    assert exit_code == EXIT_PROGRESSED
    assert workflow.port_calls == ["refined"]
    assert chunk_units["leftover"]["status"] == "pending"
    assert chunk_units["leftover"]["eligibility"] in (
        "eligible_pending_model_analysis",
        "ineligible_singleton_pending_model",
    )


def test_no_failure_is_ever_final(tmp_path: Path):
    # Owner design 2026-08-08: countdowns never kill work. Harness errors and
    # quality-gate failures alike leave the unit retryable with its feedback;
    # attempts only accumulate for ordering.
    root = fixture_repo(tmp_path)
    units = [unit("milestone", ["0x80001000"], entry_symbols=["real_entry"])]
    workflow = StubWorkflow(root, analysis_with(units))
    for error in (
        "UsageLimitExceeded: request_limit of 10 exceeded",
        "$ pnpm typecheck failed: TS2532",
    ):
        workflow.port_results["milestone"] = SourceLoopResult(
            passed=False, attempts=4, error=error
        )
        make_driver(root, workflow).run()
        record = read_ledger(root)["chunks"]["chunk_0048"]["units"]["milestone"]
        assert record["status"] == "rejected_retryable"
        assert record["error"] == error


def test_failed_units_sink_behind_less_attempted_work(tmp_path: Path):
    # Starvation is prevented by ordering, not by killing: after fresh-unit
    # ports, the failing unit comes around again.
    root = fixture_repo(tmp_path)
    units = [
        unit("flaky", ["0x80001000"], entry_symbols=["flaky_entry"]),
        unit("fresh", ["0x80001010"], entry_symbols=["fresh_entry"]),
    ]
    workflow = StubWorkflow(root, analysis_with(units))
    workflow.port_results["flaky"] = SourceLoopResult(
        passed=False, attempts=3, error="transient harness failure"
    )

    make_driver(root, workflow).run()  # flaky (address order) fails, gains attempts
    make_driver(root, workflow).run()  # fresh must be selected ahead of flaky now
    assert workflow.port_calls == ["flaky", "fresh"]

    make_driver(root, workflow).run()  # everything else done: flaky retries
    assert workflow.port_calls == ["flaky", "fresh", "flaky"]


def test_analysis_failures_never_block_and_ports_resume_when_analysis_lands(tmp_path: Path):
    # Owner design 2026-08-08: analysis spend is recorded and rotated, never a
    # death sentence. Repeated failures keep the chunk analyzable, and an
    # on-disk analysis makes its units portable immediately.
    root = fixture_repo(tmp_path)
    workflow = StubWorkflow(root, None)
    for _ in range(4):
        make_driver(root, workflow).run()
    record = read_ledger(root)["chunks"]["chunk_0048"]["analysis"]
    assert record["status"] == "analysis_failed"  # never analysis_blocked
    assert record["model_requests_spent"] == 4

    workflow.analysis = analysis_with(
        [unit("controller", ["0x80001000"], entry_symbols=["real_entry"])]
    )
    exit_code = make_driver(root, workflow).run()

    assert exit_code == EXIT_PROGRESSED
    assert workflow.port_calls == ["controller"]


def test_batch_push_uses_an_explicit_refspec(tmp_path: Path, monkeypatch):
    """Git side-effect audit regression: the D8 batch push must be
    `push origin HEAD` (current branch to its same-named origin branch),
    never a bare `git push` riding ambient upstream config."""
    import subprocess as real_subprocess

    from src import port_driver as module

    root = fixture_repo(tmp_path)
    driver = make_driver(root, StubWorkflow(root, None))
    driver._integrations_this_run = ["unit-x"]
    calls = []

    def fake_run(args, **kwargs):
        calls.append(tuple(args))
        return real_subprocess.CompletedProcess(
            args=args, returncode=0, stdout="", stderr=""
        )

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    driver._batch_push()
    pushes = [args for args in calls if len(args) > 1 and args[1] == "push"]
    assert pushes == [("git", "push", "origin", "HEAD")]
