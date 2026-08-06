import json
from pathlib import Path

import pytest

from src.port_activity import PortActivity
from src.port_chunk_workflow import (
    ChunkPortWorkflow,
    ProviderUnavailable,
    build_deterministic_analysis,
    parse_chunk_export,
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
