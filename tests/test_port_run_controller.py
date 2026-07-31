import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from src.port_run_controller import PortRunController, find_gotyaforce_root, format_duration


def fake_repo(tmp_path: Path) -> Path:
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "finish-game-port-poc.mjs").write_text("// fixture\n", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"scripts":{}}\n', encoding="utf-8")
    return tmp_path


def test_find_repo_root_walks_up_from_oghidra_path(tmp_path):
    root = fake_repo(tmp_path)
    nested = root / "research" / "tools" / "OGhidra" / "src"
    nested.mkdir(parents=True)

    assert find_gotyaforce_root(nested) == root


def test_snapshot_exposes_stages_queue_and_progress(tmp_path):
    controller = PortRunController(fake_repo(tmp_path))
    controller.run_root.mkdir(parents=True)
    controller.state_path.write_text(
        json.dumps(
            {
                "status": "running",
                "objective": "Finish the game",
                "current_stage": "verify",
                "updated_at": "2026-07-30T00:00:00",
                "stages": {
                    "generate": {"label": "Generate", "status": "passed"},
                    "verify": {"label": "Verify", "status": "running"},
                },
                "queue": [
                    {"address": "0x8012b458", "family": "Eagle Jet", "status": "generated"}
                ],
                "promotion": {"status": "not_started"},
            }
        ),
        encoding="utf-8",
    )

    snapshot = controller.snapshot()

    assert snapshot.status == "running"
    assert snapshot.current_stage == "verify"
    assert snapshot.completed_stages == 1
    assert snapshot.total_stages == 2
    assert snapshot.progress_percent == 50.0
    assert snapshot.stages[1]["label"] == "Verify"
    assert snapshot.queue[0]["address"] == "0x8012b458"


def test_pause_and_stop_write_durable_control(tmp_path):
    controller = PortRunController(fake_repo(tmp_path))

    controller.pause()
    assert json.loads(controller.control_path.read_text())["command"] == "pause_after_stage"

    controller.stop_after_stage()
    assert json.loads(controller.control_path.read_text())["command"] == "stop_after_stage"


def test_stale_running_state_resumes_durable_manifest(tmp_path):
    controller = PortRunController(fake_repo(tmp_path))
    controller.run_root.mkdir(parents=True)
    controller.state_path.write_text('{"status":"running"}\n', encoding="utf-8")
    (controller.run_root / "whole-program-manifest.json").write_text(
        '{"functions":{}}\n',
        encoding="utf-8",
    )

    assert controller.is_running() is False
    assert controller.recommended_mode() == "resume"


def test_start_runs_detached_command_and_captures_log(tmp_path, monkeypatch):
    controller = PortRunController(fake_repo(tmp_path))
    session = tmp_path / "session.json"
    session.write_text('{"metadata": {}}\n', encoding="utf-8")
    monkeypatch.setattr(
        controller,
        "command_for",
        lambda _mode: [
            sys.executable,
            "-c",
            "import os; print('GUI_CONTROLLER_OK', os.getenv('OGHIDRA_ACTIVE_SESSION'), flush=True)",
        ],
    )

    pid = controller.start("fresh", session_path=session)
    assert pid > 0
    assert controller._process is not None
    controller._process.wait(timeout=10)
    for _ in range(20):
        delta = controller.read_log_delta()
        if "GUI_CONTROLLER_OK" in delta:
            break
        time.sleep(0.01)
    else:
        raise AssertionError("detached process output was not captured")

    metadata = json.loads(controller.metadata_path.read_text())
    assert metadata["pid"] == pid
    assert metadata["mode"] == "fresh"
    assert metadata["session_path"] == str(session.resolve())
    assert metadata["session_role"] == "advisory"
    assert metadata["vectors_required"] is False


def test_port_run_panel_module_imports_without_creating_tk_root():
    from src.gui.port_run_panel import PortRunPanel

    assert PortRunPanel.MODE_LABELS["Fresh whole-program run"] == "fresh"


def test_controller_reads_structured_activity_incrementally(tmp_path):
    controller = PortRunController(fake_repo(tmp_path))
    controller.run_root.mkdir(parents=True)
    controller.activity_path.write_text(
        '{"kind":"prompt","title":"Port request","content":"Function 1"}\n',
        encoding="utf-8",
    )

    assert controller.read_activity_delta()[0]["kind"] == "prompt"
    assert controller.read_activity_delta() == []

    with controller.activity_path.open("a", encoding="utf-8") as handle:
        handle.write('{"kind":"tool","title":"Qwen called","content":""}\n')

    assert controller.read_activity_delta()[0]["title"] == "Qwen called"


def test_controller_tails_and_bounds_large_existing_activity(tmp_path):
    controller = PortRunController(fake_repo(tmp_path))
    controller.run_root.mkdir(parents=True)
    with controller.activity_path.open("w", encoding="utf-8") as handle:
        for index in range(1500):
            handle.write(
                json.dumps(
                    {
                        "kind": "tool_delta",
                        "title": "Tool arguments",
                        "content": f"{index:04d}-" + ("x" * 600),
                    }
                )
                + "\n"
            )

    first = controller.read_activity_delta()

    assert first
    assert len(first) <= 500
    assert sum(len(event["content"]) for event in first) < 100_000
    assert not first[0]["content"].startswith("0000-")


def test_snapshot_reports_liveness_tool_calls_and_historical_eta(tmp_path):
    controller = PortRunController(fake_repo(tmp_path))
    controller.run_root.mkdir(parents=True)
    now = datetime.now(timezone.utc).isoformat()
    controller.state_path.write_text(
        json.dumps(
            {
                "status": "running",
                "run_mode": "fresh",
                "started_at": now,
                "stages": {
                    "collect": {"label": "Collect", "status": "passed"},
                    "model": {"label": "Model", "status": "pending"},
                },
                "session": {
                    "path": str(tmp_path / "session.json"),
                    "role": "advisory",
                    "vectors_required": False,
                },
            }
        ),
        encoding="utf-8",
    )
    controller.history_path.write_text(
        json.dumps(
            {
                "schema": 1,
                "runs": [
                    {
                        "run_mode": "fresh",
                        "started_at": "earlier",
                        "stage_durations_seconds": {"collect": 10, "model": 30},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    controller.liveness_path.write_text(
        json.dumps(
            {
                "api_calls": 2,
                "structured_tool_calls": 1,
                "prompt_tokens": 120,
                "completion_tokens": 60,
                "tokens_per_second": 12.5,
                "token_source": "estimated",
            }
        ),
        encoding="utf-8",
    )
    controller.evidence_path.write_text(
        json.dumps(
            {
                "collection_metrics": {
                    "tool_calls": 7,
                    "tool_call_breakdown": {"decompile": 1, "raw_bytes": 6},
                }
            }
        ),
        encoding="utf-8",
    )

    snapshot = controller.snapshot()

    assert snapshot.eta_seconds == 30
    assert snapshot.eta_source == "historical_stage_median"
    assert snapshot.tokens_per_second == 12.5
    assert snapshot.token_source == "estimated"
    assert snapshot.llm_api_calls == 2
    assert snapshot.structured_tool_calls == 1
    assert snapshot.ghidra_tool_calls == 7
    assert snapshot.ghidra_tool_call_breakdown["raw_bytes"] == 6
    assert snapshot.session_role == "advisory"
    assert snapshot.vectors_required is False
    assert format_duration(snapshot.eta_seconds) == "30s"


def test_completed_snapshot_records_stage_history_once(tmp_path):
    controller = PortRunController(fake_repo(tmp_path))
    controller.run_root.mkdir(parents=True)
    controller.state_path.write_text(
        json.dumps(
            {
                "status": "completed",
                "run_mode": "replay",
                "started_at": "2026-07-30T12:00:00Z",
                "completed_at": "2026-07-30T12:00:12Z",
                "stages": {
                    "artifact": {
                        "label": "Artifact",
                        "status": "passed",
                        "started_at": "2026-07-30T12:00:01Z",
                        "finished_at": "2026-07-30T12:00:04Z",
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    first = controller.snapshot()
    second = controller.snapshot()
    history = json.loads(controller.history_path.read_text())

    assert first.eta_seconds == 0
    assert first.elapsed_seconds == 12
    assert second.eta_source == "complete"
    assert len(history["runs"]) == 1
    assert history["runs"][0]["stage_durations_seconds"]["artifact"] == 3


def test_clear_failed_and_restart_restores_source_archives_and_requeues(tmp_path, monkeypatch):
    controller = PortRunController(fake_repo(tmp_path))
    controller.run_root.mkdir(parents=True)
    source = tmp_path / "apps" / "game" / "src" / "live.ts"
    source.parent.mkdir(parents=True)
    source.write_text("qwen partial edit\n", encoding="utf-8")

    checkpoint = controller.run_root / "source-checkpoints" / "80001000"
    backup = checkpoint / "original-source" / "apps" / "game" / "src" / "live.ts"
    backup.parent.mkdir(parents=True)
    backup.write_text("original source\n", encoding="utf-8")
    (checkpoint / "original-source.json").write_text(
        json.dumps(
            {
                "files": {
                    "apps/game/src/live.ts": {
                        "existed": True,
                        "backup": str(backup),
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    controller.state_path.write_text(
        json.dumps(
            {
                "status": "running",
                "queue": [{"address": "0x80001000", "status": "model_running"}],
            }
        ),
        encoding="utf-8",
    )
    manifest_path = controller.run_root / "whole-program-manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "functions": {
                    "0x80001000": {
                        "status": "bundled",
                        "port_status": "model_invalid",
                        "group_id": "old",
                    },
                    "0x80002000": {
                        "status": "bundled",
                        "port_status": "integrated",
                        "group_id": "kept",
                    },
                },
                "groups": {"old": {}},
                "schedule": ["old"],
            }
        ),
        encoding="utf-8",
    )
    controller.activity_path.write_text("old transcript\n", encoding="utf-8")

    local_app_data = tmp_path / "local-app-data"
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))
    monkeypatch.setattr(controller, "_stop_worker_tree", lambda: None)
    started = []

    def fake_start(mode, session_path=None):
        started.append((mode, session_path))
        return 4321

    monkeypatch.setattr(controller, "start", fake_start)

    result = controller.clear_failed_and_restart()

    updated = json.loads(manifest_path.read_text(encoding="utf-8"))
    archive = Path(result["archive"])
    assert result["pid"] == 4321
    assert result["reset_functions"] == 1
    assert result["preserved_bundles"] == 2
    assert started == [("resume", None)]
    assert source.read_text(encoding="utf-8") == "original source\n"
    assert "port_status" not in updated["functions"]["0x80001000"]
    assert updated["functions"]["0x80002000"]["port_status"] == "integrated"
    assert updated["groups"] == {}
    assert updated["schedule"] == []
    assert (archive / "activity.jsonl").is_file()
    assert (archive / "source-checkpoints" / "80001000" / "original-source.json").is_file()
