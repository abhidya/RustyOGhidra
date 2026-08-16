"""The machine contract the rig consumes.

The rig must be able to answer "is there actionable work?" **without touching a
model**, and must get a stable, machine-readable shape back.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.port_contract import (
    EXIT_OK,
    EXIT_UNUSABLE,
    build_status,
    driver_status,
    main,
    queue_status,
    write_control,
)


def _run_root(repo: Path) -> Path:
    root = repo / "research/decomp/generated/finish-game-port"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _queue(repo: Path, names: list[str]) -> None:
    _run_root(repo).joinpath("wasm-units.json").write_text(
        json.dumps({"queue_schema": 1, "units": [{"name": name} for name in names]}),
        encoding="utf-8",
    )


def _state(repo: Path, records: dict) -> None:
    _run_root(repo).joinpath("wasm-units-state.json").write_text(
        json.dumps({"state_schema": 1, "units": records}), encoding="utf-8"
    )


def test_work_is_eligible_while_any_unit_is_unsettled(tmp_path):
    _queue(tmp_path, ["a", "b", "c"])
    _state(tmp_path, {"a": {"status": "green", "tier": "oracle_green"}, "b": {"status": "red_retryable"}})

    work = queue_status(tmp_path, "wasm_units")

    assert work["eligible"] is True
    assert work["total"] == 3
    assert work["remaining"] == 2          # b (retryable) and c (untouched)
    assert work["counts"]["green"] == 1


def test_completed_queue_reports_no_work(tmp_path):
    _queue(tmp_path, ["a", "b"])
    _state(tmp_path, {
        "a": {"status": "green", "tier": "oracle_green"},
        "b": {"status": "green", "tier": "compile_only"},
    })

    work = queue_status(tmp_path, "wasm_units")

    assert work["eligible"] is False
    assert work["remaining"] == 0
    assert work["counts"]["staged"] == 1
    assert "settled" in work["reason"]


def test_structurally_ineligible_units_count_as_settled(tmp_path):
    _queue(tmp_path, ["a"])
    _state(tmp_path, {"a": {"status": "structural_ineligible"}})

    work = queue_status(tmp_path, "wasm_units")

    assert work["eligible"] is False       # never a permanent hot loop


def test_missing_state_means_everything_is_untouched_work(tmp_path):
    _queue(tmp_path, ["a", "b"])
    work = queue_status(tmp_path, "wasm_units")
    assert work["eligible"] is True
    assert work["remaining"] == 2


def test_unusable_queue_is_flagged_not_guessed(tmp_path):
    _run_root(tmp_path).joinpath("wasm-units.json").write_text("{oh no", encoding="utf-8")
    work = queue_status(tmp_path, "wasm_units")
    assert work["unusable"] is True
    assert work["eligible"] is False


def test_bom_prefixed_queue_is_read(tmp_path):
    _run_root(tmp_path).joinpath("wasm-units.json").write_text(
        json.dumps({"queue_schema": 1, "units": [{"name": "a"}]}), encoding="utf-8-sig"
    )
    assert queue_status(tmp_path, "wasm_units")["total"] == 1


def test_driver_status_reports_a_stale_lock(tmp_path):
    _run_root(tmp_path).joinpath("wasm-units.lock").write_text(
        json.dumps({"pid": 999999, "started_at": "x"}), encoding="utf-8"
    )
    status = driver_status(tmp_path, "wasm_units")
    assert status["lock_present"] is True
    assert status["lock_pid_alive"] is False
    assert status["lock_stale"] is True


def test_status_payload_shape_is_stable(tmp_path):
    _queue(tmp_path, ["a"])
    payload = build_status(tmp_path)
    for key in ("schema", "port_mode", "model", "work", "driver", "control"):
        assert key in payload
    assert "api_key" not in payload["model"]
    assert payload["model"]["api_key_present"] in (True, False)


def test_control_writes_are_atomic_and_sourced(tmp_path):
    path = write_control(tmp_path, "stop_after_stage", "rig-supervisor")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["command"] == "stop_after_stage"
    assert payload["source"] == "rig-supervisor"


def test_cli_status_exits_unusable_when_the_queue_is_broken(tmp_path, capsys):
    _run_root(tmp_path).joinpath("wasm-units.json").write_text("nope", encoding="utf-8")
    code = main(["status", "--json", "--repo-root", str(tmp_path)])
    assert code == EXIT_UNUSABLE
    payload = json.loads(capsys.readouterr().out)
    assert payload["work"]["unusable"] is True


def test_cli_config_is_machine_readable(capsys):
    assert main(["config", "--json"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["model"]
    assert payload["admin_base_url"].startswith("http")


def test_cli_stop_and_run_round_trip(tmp_path, capsys):
    assert main(["stop", "--repo-root", str(tmp_path)]) == EXIT_OK
    control = _run_root(tmp_path) / "control.json"
    assert json.loads(control.read_text(encoding="utf-8"))["command"] == "stop_after_stage"

    assert main(["run", "--repo-root", str(tmp_path)]) == EXIT_OK
    assert json.loads(control.read_text(encoding="utf-8"))["command"] == "run"


def test_queue_probe_makes_no_network_call(tmp_path, monkeypatch):
    """Work eligibility must be answerable before any serving host exists."""
    import requests

    def explode(*args, **kwargs):
        raise AssertionError("the work probe must not touch the network")

    monkeypatch.setattr(requests, "get", explode)
    monkeypatch.setattr(requests, "post", explode)
    _queue(tmp_path, ["a"])

    assert queue_status(tmp_path, "wasm_units")["eligible"] is True
