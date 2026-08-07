import json
from pathlib import Path

import pytest

from src.port_activity import PortActivity
from src.port_chunk_workflow import (
    ChunkPortWorkflow,
    ProviderUnavailable,
    UnitSkipResult,
    build_deterministic_analysis,
    parse_chunk_export,
    unit_eligibility,
)


def test_activity_events_always_include_a_run_id(tmp_path: Path):
    path = tmp_path / "activity.jsonl"
    PortActivity(path).emit("status", "ready")

    event = json.loads(path.read_text(encoding="utf-8"))

    assert event["run_id"]


def fixture_repo(tmp_path: Path) -> Path:
    export = tmp_path / "research/decomp/ghidra-export"
    export.mkdir(parents=True)
    (export / "_index.tsv").write_text(
        "80001000\tchallenge_root\tchunk_0048.c\n"
        "80001020\tchallenge_poll\tchunk_0048.c\n"
        "80002000\tgnt4_GXInit\tchunk_0048.c\n"
        "80003000\texternal_helper\tchunk_0001.c\n",
        encoding="utf-8",
    )
    (export / "chunk_0048.c").write_text(
        "// ==== 80001000  challenge_root ====\n\n"
        "void challenge_root(void) { challenge_poll(); external_helper(); DAT_80430000 = 1; }\n\n"
        "// ==== 80001020  challenge_poll ====\n\n"
        "void challenge_poll(void) { DAT_80430000 = DAT_80430000 + 1; }\n\n"
        "// ==== 80002000  gnt4_GXInit ====\n\n"
        "void gnt4_GXInit(void) { }\n",
        encoding="utf-8",
    )
    return tmp_path


def test_parse_chunk_preserves_functions_calls_globals_and_external_dependencies(tmp_path: Path):
    root = fixture_repo(tmp_path)

    chunk = parse_chunk_export(root, "chunk_0048")

    assert chunk.name == "chunk_0048.c"
    assert [function.address for function in chunk.functions] == [
        "0x80001000",
        "0x80001020",
        "0x80002000",
    ]
    assert chunk.functions[0].direct_calls == ["0x80001020", "0x80003000"]
    assert chunk.functions[0].shared_globals == ["DAT_80430000"]
    assert chunk.functions[0].source_start_line == 1
    assert chunk.functions[0].source_end_line < chunk.functions[1].source_start_line


def test_deterministic_analysis_groups_related_game_functions_and_classifies_sdk(tmp_path: Path):
    chunk = parse_chunk_export(fixture_repo(tmp_path), "0048")

    analysis = build_deterministic_analysis(chunk)

    game_unit = next(unit for unit in analysis.units if "0x80001000" in unit.function_addresses)
    sdk_unit = next(unit for unit in analysis.units if "0x80002000" in unit.function_addresses)
    assert game_unit.function_addresses == ["0x80001000", "0x80001020"]
    assert game_unit.external_dependencies == ["0x80003000"]
    assert game_unit.runtime_entry_symbols == ["challenge_root"]
    assert sdk_unit.classification == "hardware_or_sdk"
    assert analysis.function_count == 3


def test_analysis_from_saved_model_response_is_one_shot_and_list_is_offline(tmp_path: Path):
    root = fixture_repo(tmp_path)
    response = tmp_path / "analysis-response.json"
    response.write_text(
        json.dumps(
            {
                "subsystems": ["challenge frontend"],
                "state_dispatchers": ["0x80001000"],
                "callback_tables": [],
                "shared_globals": ["DAT_80430000"],
                "external_dependencies": ["0x80003000"],
                "hardware_or_sdk_functions": ["0x80002000"],
                "game_owned_functions": ["0x80001000", "0x80001020"],
                "units": [
                    {
                        "id": "challenge-controller",
                        "label": "Challenge controller",
                        "classification": "game_owned",
                        "summary": "Owns challenge selection state.",
                        "function_addresses": ["0x80001000", "0x80001020"],
                        "external_dependencies": ["0x80003000"],
                        "shared_globals": ["DAT_80430000"],
                        "runtime_entry_symbols": ["challenge_root"],
                        "target_source_paths": ["apps/game/src/ui/screens/Challenge.ts"],
                    },
                    {
                        "id": "gx-host",
                        "label": "GX host boundary",
                        "classification": "hardware_or_sdk",
                        "summary": "Host graphics initialization.",
                        "function_addresses": ["0x80002000"],
                        "external_dependencies": [],
                        "shared_globals": [],
                        "runtime_entry_symbols": [],
                        "target_source_paths": [],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    workflow = ChunkPortWorkflow(repo_root=root, llm_factory=lambda: pytest.fail("model called"))

    analysis = workflow.analyze("chunk_0048", model_response=response)
    listed = workflow.list_units("chunk_0048")

    assert analysis.generated_by == "saved_model_response"
    assert [unit.id for unit in listed] == ["challenge-controller", "gx-host"]
    assert workflow.analysis_path("chunk_0048").is_file()


def write_saved_response(tmp_path: Path, *, entry_symbols: list[str]) -> Path:
    response = tmp_path / "analysis-response.json"
    response.write_text(
        json.dumps(
            {
                "units": [
                    {
                        "id": "challenge-controller",
                        "label": "Challenge controller",
                        "classification": "game_owned",
                        "summary": "Owns challenge selection state.",
                        "function_addresses": ["0x80001000", "0x80001020"],
                        "runtime_entry_symbols": entry_symbols,
                    },
                    {
                        "id": "gx-host",
                        "label": "GX host boundary",
                        "classification": "hardware_or_sdk",
                        "summary": "Host graphics initialization.",
                        "function_addresses": ["0x80002000"],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    return response


def test_analyze_reuses_matching_analysis_with_zero_model_requests(tmp_path: Path):
    root = fixture_repo(tmp_path)
    seeded = ChunkPortWorkflow(repo_root=root, llm_factory=lambda: pytest.fail("model called"))
    seeded.analyze(
        "chunk_0048",
        model_response=write_saved_response(tmp_path, entry_symbols=["challenge_root"]),
    )

    rerun = ChunkPortWorkflow(repo_root=root, llm_factory=lambda: pytest.fail("model called"))
    analysis = rerun.analyze("chunk_0048")

    assert analysis.generated_by == "saved_model_response"
    state = json.loads(rerun.state_path.read_text(encoding="utf-8"))
    assert state["model_requests"] == 0
    assert state["reused_existing_analysis"] is True


def test_analyze_never_downgrades_existing_analysis_unless_forced(tmp_path: Path):
    root = fixture_repo(tmp_path)
    workflow = ChunkPortWorkflow(repo_root=root, llm_factory=lambda: pytest.fail("model called"))
    workflow.analyze(
        "chunk_0048",
        model_response=write_saved_response(tmp_path, entry_symbols=["challenge_root"]),
    )

    kept = workflow.analyze("chunk_0048", deterministic_only=True)
    forced = workflow.analyze("chunk_0048", deterministic_only=True, force=True)

    assert kept.generated_by == "saved_model_response"
    assert forced.generated_by == "deterministic"


def test_port_unit_skips_non_portable_classification_without_model_calls(tmp_path: Path):
    root = fixture_repo(tmp_path)
    workflow = ChunkPortWorkflow(repo_root=root, llm_factory=lambda: pytest.fail("model called"))
    workflow.analyze(
        "chunk_0048",
        model_response=write_saved_response(tmp_path, entry_symbols=["challenge_root"]),
    )

    result = workflow.port_unit("chunk_0048", "gx-host")

    assert isinstance(result, UnitSkipResult)
    assert result.eligibility == "ineligible_classification"
    assert result.model_requests == 0
    state = json.loads(workflow.state_path.read_text(encoding="utf-8"))
    assert state["status"] == "unit_skipped"


def test_port_unit_skips_placeholder_only_entry_symbols_without_model_calls(tmp_path: Path):
    root = fixture_repo(tmp_path)
    workflow = ChunkPortWorkflow(repo_root=root, llm_factory=lambda: pytest.fail("model called"))
    workflow.analyze(
        "chunk_0048",
        model_response=write_saved_response(
            tmp_path, entry_symbols=["FUN_80001000", "LAB_80001020"]
        ),
    )

    result = workflow.port_unit("chunk_0048", "challenge-controller")

    assert isinstance(result, UnitSkipResult)
    assert result.eligibility == "ineligible_fun_entry"


def test_session_index_enrichment_unlocks_placeholder_entry_symbols(tmp_path: Path):
    root = fixture_repo(tmp_path)
    run_root = root / "research/decomp/generated/finish-game-port"
    run_root.mkdir(parents=True)
    (run_root / "session-index.json").write_text(
        json.dumps(
            {
                "index_schema": 1,
                "functions": {
                    "0x80001000": {
                        "name": "dispatch_challenge_flow_state",
                        "summary": "Drives the challenge flow state machine.",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    workflow = ChunkPortWorkflow(repo_root=root, llm_factory=lambda: pytest.fail("model called"))
    workflow.analyze(
        "chunk_0048",
        model_response=write_saved_response(tmp_path, entry_symbols=["FUN_80001000"]),
    )

    listed = workflow.list_units("chunk_0048")

    controller = next(item for item in listed if item.id == "challenge-controller")
    assert controller.runtime_entry_symbols == ["dispatch_challenge_flow_state"]
    from src.port_chunk_workflow import unit_eligibility as eligibility

    assert eligibility(controller) == ("eligible", "")


def test_unit_eligibility_accepts_named_game_entry():
    from src.port_chunk_workflow import ExecutionUnit

    unit = ExecutionUnit(
        id="challenge-controller",
        label="Challenge controller",
        classification="game_owned",
        summary="",
        function_addresses=["0x80001000"],
        runtime_entry_symbols=["FUN_80001000", "dispatch_challenge_flow_state"],
    )

    assert unit_eligibility(unit) == ("eligible", "")


def test_cli_rejects_legacy_only_flags_on_chunk_path():
    from src.port_scheduler import main

    with pytest.raises(SystemExit) as excinfo:
        main(["--mode", "resume"])

    assert excinfo.value.code == 2


def test_cli_honors_control_stop_before_any_work(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import src.port_scheduler as port_scheduler

    root = fixture_repo(tmp_path)
    run_root = root / "research/decomp/generated/finish-game-port"
    run_root.mkdir(parents=True)
    (run_root / "control.json").write_text(
        json.dumps({"command": "stop_after_stage"}), encoding="utf-8"
    )
    monkeypatch.setattr(port_scheduler, "find_gotyaforce_root", lambda _=None: root)
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    monkeypatch.delenv("OGHIDRA_PORT_RUN_ID", raising=False)

    assert port_scheduler.main(["--chunk", "chunk_0048"]) == 2


class ScriptedLlm:
    """Returns queued structured responses and records every request's kwargs."""

    def __init__(self, responses: list[str]):
        self.responses = list(responses)
        self.calls: list[dict] = []

    def generate_structured(self, **kwargs):
        self.calls.append(kwargs)
        return self.responses.pop(0), "tool_call"


def model_response_json(*, complete: bool) -> str:
    units = [
        {
            "id": "challenge-controller",
            "label": "Challenge controller",
            "classification": "game_owned",
            "summary": "",
            "function_addresses": ["0x80001000", "0x80001020"],
            "runtime_entry_symbols": ["challenge_root"],
        }
    ]
    if complete:
        units.append(
            {
                "id": "gx-host",
                "label": "GX host",
                "classification": "hardware_or_sdk",
                "summary": "",
                "function_addresses": ["0x80002000"],
            }
        )
    return json.dumps({"units": units})


def test_analyzer_repairs_coverage_violations_within_request_budget(tmp_path: Path):
    root = fixture_repo(tmp_path)
    llm = ScriptedLlm([model_response_json(complete=False), model_response_json(complete=True)])
    workflow = ChunkPortWorkflow(repo_root=root, llm_factory=lambda: (llm, "custom_api", "qwen"))

    analysis = workflow.analyze("chunk_0048")

    assert analysis.generated_by == "model"
    assert workflow.last_analyze_requests == 2
    assert len(llm.calls) == 2
    assert "missing=['0x80002000']" in llm.calls[1]["prompt"]
    # Output budget scales with the chunk instead of the flat 32768 (G11/R12).
    assert llm.calls[0]["max_tokens"] == 4096
    chunk_root = workflow.chunk_root("chunk_0048")
    assert (chunk_root / "analysis-attempt-1.raw.txt").is_file()
    assert (chunk_root / "analysis-attempt-2.raw.txt").is_file()


def test_analyzer_gives_up_after_three_requests_and_archives_everything(tmp_path: Path):
    root = fixture_repo(tmp_path)
    llm = ScriptedLlm([model_response_json(complete=False)] * 3)
    workflow = ChunkPortWorkflow(repo_root=root, llm_factory=lambda: (llm, "custom_api", "qwen"))

    with pytest.raises(ValueError, match="after 3 structured requests"):
        workflow.analyze("chunk_0048")

    assert len(llm.calls) == 3
    state = json.loads(workflow.state_path.read_text(encoding="utf-8"))
    assert state["status"] == "analysis_failed"
    assert state["model_requests"] == 3
    chunk_root = workflow.chunk_root("chunk_0048")
    assert (chunk_root / "analysis-attempt-3.raw.txt").is_file()


def test_analyzer_derives_classification_lists_from_units(tmp_path: Path):
    root = fixture_repo(tmp_path)
    llm = ScriptedLlm([model_response_json(complete=True)])
    workflow = ChunkPortWorkflow(repo_root=root, llm_factory=lambda: (llm, "custom_api", "qwen"))

    analysis = workflow.analyze("chunk_0048")

    assert analysis.hardware_or_sdk_functions == ["0x80002000"]
    assert analysis.game_owned_functions == ["0x80001000", "0x80001020"]


def test_provider_failure_pauses_after_one_analysis_request(tmp_path: Path):
    root = fixture_repo(tmp_path)

    class OfflineLlm:
        def generate_structured(self, **_kwargs):
            raise ConnectionError("provider connection refused")

    workflow = ChunkPortWorkflow(
        repo_root=root,
        llm_factory=lambda: (OfflineLlm(), "custom_api", "qwen"),
    )

    with pytest.raises(ProviderUnavailable):
        workflow.analyze("chunk_0048")

    state = json.loads(workflow.state_path.read_text(encoding="utf-8"))
    assert state["status"] == "paused_provider_unavailable"
    assert state["model_requests"] == 1
