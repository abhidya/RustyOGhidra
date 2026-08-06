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
