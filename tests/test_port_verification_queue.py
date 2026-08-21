"""T3 verification queue (design section 3; oracle plan section 3.4).

Offline tests for the oracle-commands.json sidecar overlay, the staged-unit
verification lane, the reverify-unit promotion path (provenance rewrite +
artifact move + registry re-tier + journaled commit), and the failure paths
(oracle red -> [V4-7] revoke; exports_sha256 mismatch -> loud stale event).
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from src.port_driver import EXIT_PROGRESSED
from src.port_knowledge_registry import REGISTRY_RELPATH, empty_registry, save_registry
from src.port_wasm_units import (
    WasmUnitDriver,
    exports_sha256,
    oracle_entry_sha,
    validate_oracle_entry,
)

RUN_ROOT = "research/decomp/generated/finish-game-port"


def _completed(rc: int = 0, stdout: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["git"], returncode=rc, stdout=stdout, stderr="")


def _entry(exports: list[str]) -> dict:
    functions = "".join(
        f"(?m)^\\[{name}\\] cases=100 exact=100 rounding_explained=0 "
        "unexplained=0 verdict: pass$\n"
        for name in exports
    ).splitlines()
    return {
        "exports_sha256": exports_sha256(exports),
        "oracle": {
            "command": ["node", "run-unit.mjs", "--unit", "unit-b"],
            "cwd": "research/decomp/oracle-harness",
            "env": {"ORACLE_WASM": "{wasm}"},
            "success_patterns": [
                "(?m)^ORACLE TOTAL functions=1/1 cases=100 UNEXPLAINED: 0 VERDICT: PASS$",
                *functions,
            ],
        },
    }


def _write_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "research/decomp/ghidra-export").mkdir(parents=True)
    (repo / RUN_ROOT).mkdir(parents=True)
    (repo / "research/decomp/poc").mkdir(parents=True)
    (repo / "research/decomp/data").mkdir(parents=True)
    chunk = repo / "research/decomp/ghidra-export/chunk_9999.c"
    chunk.write_text(
        "// line1\nint zz_test_(int a)\n{\n  return a + 1;\n}\n// tail\n",
        encoding="utf-8",
    )
    (repo / "research/decomp/poc/seed.h").write_text("/* seed */\n", encoding="utf-8")
    queue = {
        "queue_schema": 1,
        "units": [
            {
                "name": "unit-a",
                "extractions": [
                    {"file": "research/decomp/ghidra-export/chunk_9999.c", "start": 2, "end": 5}
                ],
                "prelude": ["int zz_test_(int a);"],
                "exported_functions": ["zz_test_"],
                "header_seed": "research/decomp/poc/seed.h",
                "oracle": {"type": "compile_only"},
            }
        ],
    }
    (repo / RUN_ROOT / "wasm-units.json").write_text(json.dumps(queue), encoding="utf-8")
    # unit-b: a staged compile-only green with a committed staged artifact.
    staged = repo / "research/decomp/port-units-staging/unit-b"
    staged.mkdir(parents=True)
    (staged / "unit.c").write_text("int zz_b_(void) { return 1; }\n", encoding="utf-8")
    (staged / "gnt4_shim.h").write_text("/* header */\n", encoding="utf-8")
    (staged / "unit.wasm").write_bytes(b"\x00asm")
    (staged / "oracle.log").write_text("compile_only tier\n", encoding="utf-8")
    (staged / "provenance.json").write_text(
        json.dumps(
            {
                "unit": "unit-b",
                "exported_functions": ["zz_b_"],
                "verified": False,
                "tier": "compile_only",
            }
        ),
        encoding="utf-8",
    )
    state = {
        "state_schema": 1,
        "created_at": "2026-08-20T00:00:00Z",
        "units": {
            "unit-b": {"status": "green", "attempts": 1, "tier": "compile_only"}
        },
    }
    (repo / RUN_ROOT / "wasm-units-state.json").write_text(
        json.dumps(state), encoding="utf-8"
    )
    (repo / "research/decomp/data/oracle-commands.json").write_text(
        json.dumps({"spec_schema": 1, "units": {"unit-b": _entry(["zz_b_"])}}),
        encoding="utf-8",
    )
    return repo


def _driver(repo: Path, **kwargs) -> WasmUnitDriver:
    defaults = dict(
        repo_root=repo,
        build_runner=lambda workdir, exports, extra=None: (True, ""),
        oracle_runner=lambda unit, wasm: (True, "100/100", "ORACLE PASS log"),
        git_runner=lambda *args: _completed(0, "abc123\n"),
    )
    defaults.update(kwargs)
    return WasmUnitDriver(**defaults)


def _events(repo: Path) -> list[dict]:
    path = repo / RUN_ROOT / "events.jsonl"
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _state(repo: Path) -> dict:
    return json.loads((repo / RUN_ROOT / "wasm-units-state.json").read_text())


# --------------------------------------------------------------- sidecar rules


def test_exports_sha256_is_order_insensitive():
    assert exports_sha256(["b", "a"]) == exports_sha256(["a", "b"])


def test_validate_oracle_entry_accepts_the_disciplined_shape():
    assert validate_oracle_entry("unit-b", _entry(["zz_b_"]), exports=["zz_b_"]) == []


def test_validate_oracle_entry_rejects_bare_anchor_and_missing_function():
    entry = _entry(["zz_b_"])
    entry["oracle"]["success_patterns"].append("^naked anchor$")
    problems = validate_oracle_entry("unit-b", entry, exports=["zz_b_", "zz_other_"])
    assert any("(?m)" in problem for problem in problems)
    assert any("zz_other_" in problem for problem in problems)


def test_validate_oracle_entry_requires_the_total_line_first():
    entry = _entry(["zz_b_"])
    entry["oracle"]["success_patterns"][0] = "(?m)^UNEXPLAINED: 0$"
    problems = validate_oracle_entry("unit-b", entry, exports=["zz_b_"])
    assert any("total line" in problem for problem in problems)


# --------------------------------------------------------------------- overlay


def test_effective_oracle_overlays_on_matching_export_hash(tmp_path):
    repo = _write_repo(tmp_path)
    sidecar = json.loads((repo / "research/decomp/data/oracle-commands.json").read_text())
    sidecar["units"]["unit-a"] = _entry(["zz_test_"])
    (repo / "research/decomp/data/oracle-commands.json").write_text(json.dumps(sidecar))
    driver = _driver(repo)
    unit = {
        "name": "unit-a",
        "exported_functions": ["zz_test_"],
        "oracle": {"type": "compile_only"},
    }
    spec = driver._effective_oracle(unit)
    assert spec["command"][0] == "node"
    assert spec.get("type") != "compile_only"


def test_effective_oracle_keeps_queue_spec_on_stale_hash(tmp_path):
    repo = _write_repo(tmp_path)
    sidecar = json.loads((repo / "research/decomp/data/oracle-commands.json").read_text())
    sidecar["units"]["unit-a"] = _entry(["zz_DIFFERENT_"])
    (repo / "research/decomp/data/oracle-commands.json").write_text(json.dumps(sidecar))
    driver = _driver(repo)
    unit = {
        "name": "unit-a",
        "exported_functions": ["zz_test_"],
        "oracle": {"type": "compile_only"},
    }
    # zz_DIFFERENT_ satisfies validation only if patterns cover the queue's
    # exports; validation runs against the QUEUE export list, so the missing
    # per-function pattern also makes the entry invalid -- either way the
    # queue spec must survive and the event must fire.
    assert driver._effective_oracle(unit) == {"type": "compile_only"}
    kinds = {event["kind"] for event in _events(repo)}
    assert kinds & {"oracle_spec_stale", "oracle_spec_invalid"}


def test_absent_sidecar_is_bit_identical_current_behaviour(tmp_path):
    repo = _write_repo(tmp_path)
    (repo / "research/decomp/data/oracle-commands.json").unlink()
    driver = _driver(repo)
    unit = {"name": "unit-a", "exported_functions": ["zz_test_"], "oracle": {"type": "compile_only"}}
    assert driver._effective_oracle(unit) == {"type": "compile_only"}


# ---------------------------------------------------------- verification lane


def test_run_promotes_staged_unit_through_the_verification_lane(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    git_calls: list[tuple] = []

    def fake_git(*args):
        git_calls.append(args)
        if args[0] == "rev-parse":
            return _completed(0, "deadbeef\n")
        return _completed(0)

    driver = _driver(repo, git_runner=fake_git)
    assert driver.run() == EXIT_PROGRESSED  # budget 1: the reverify was the step

    record = _state(repo)["units"]["unit-b"]
    assert record["tier"] == "oracle_green"
    assert record["status"] == "green"
    assert record["verify"]["status"] == "pass"
    promoted = repo / "research/decomp/port-units/unit-b"
    assert (promoted / "unit.wasm").is_file()
    provenance = json.loads((promoted / "provenance.json").read_text())
    assert provenance["verified"] is True
    assert provenance["tier"] == "oracle_green"
    assert provenance["previous_tier"] == "compile_only"
    assert provenance["oracle"]["summary"] == "100/100"
    assert not (repo / "research/decomp/port-units-staging/unit-b").exists()
    message = next(args for args in git_calls if args[0] == "commit")[2]
    assert "promoted" in message
    assert "Claude" not in message and "anthropic" not in message.lower()
    kinds = [event["kind"] for event in _events(repo)]
    assert "verdict_promoted" in kinds


def test_reverify_pass_promotes_registry_entries(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    registry = empty_registry()
    registry["entries"]["dat:0x80000000"] = {
        "kind": "dat_typing",
        "symbol": "DAT_80000000",
        "macro": "#define DAT_80000000 (*(unsigned char *)(unsigned int)0x80000000)",
        "tier": "compile_only",
        "source_units": ["unit-b"],
        "conflicts": [],
    }
    registry["version"] = 1
    registry_path = repo / REGISTRY_RELPATH
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    save_registry(registry_path, registry)
    driver = _driver(repo)
    result = driver.reverify_unit("unit-b")
    assert result["promoted"] is True
    after = json.loads(registry_path.read_text(encoding="utf-8"))
    assert after["entries"]["dat:0x80000000"]["tier"] == "oracle_green"
    assert after["version"] > 1


def test_reverify_fail_records_red_revokes_and_never_reruns_same_spec(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    registry = empty_registry()
    registry["entries"]["fn:zz_b_"] = {
        "kind": "prototype",
        "symbol": "zz_b_",
        "declaration": "int zz_b_(void);",
        "tier": "compile_only",
        "source_units": ["unit-b"],
        "conflicts": [],
    }
    registry["version"] = 1
    registry_path = repo / REGISTRY_RELPATH
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    save_registry(registry_path, registry)
    oracle_calls: list[str] = []

    def failing_oracle(unit, wasm):
        oracle_calls.append(unit["name"])
        return False, "3/9", "ORACLE FAIL log"

    driver = _driver(repo, oracle_runner=failing_oracle)
    assert driver.run() == EXIT_PROGRESSED
    record = _state(repo)["units"]["unit-b"]
    # The unit stays staged: a failed re-run changes no verdict.
    assert record["status"] == "green"
    assert record["tier"] == "compile_only"
    assert record["verify"]["status"] == "oracle_red"
    sidecar = json.loads(
        (repo / "research/decomp/data/oracle-commands.json").read_text()
    )
    assert record["verify"]["spec_sha256"] == oracle_entry_sha(sidecar["units"]["unit-b"])
    assert (repo / "research/decomp/port-units-staging/unit-b").is_dir()
    assert not (repo / "research/decomp/port-units/unit-b").exists()
    # [V4-7]: sole-source entries are revoked with a tombstone.
    after = json.loads(registry_path.read_text(encoding="utf-8"))
    entry = after["entries"]["fn:zz_b_"]
    assert entry["revoked"] is True
    assert any(conflict.get("tombstone") for conflict in entry["conflicts"])
    kinds = [event["kind"] for event in _events(repo)]
    assert "wasm_unit_reverify_red" in kinds
    # A second pass must NOT re-run the identical spec (section 0.1).
    driver2 = _driver(repo, oracle_runner=failing_oracle)
    driver2.run()
    assert oracle_calls == ["unit-b"]


def test_stale_staged_binding_is_loud_and_not_a_candidate(tmp_path):
    repo = _write_repo(tmp_path)
    sidecar = json.loads((repo / "research/decomp/data/oracle-commands.json").read_text())
    sidecar["units"]["unit-b"]["exports_sha256"] = exports_sha256(["zz_wrong_"])
    (repo / "research/decomp/data/oracle-commands.json").write_text(json.dumps(sidecar))
    driver = _driver(repo)
    assert driver._verification_candidates(driver._load_state()) == []
    assert any(
        event["kind"] == "oracle_spec_stale"
        and event.get("binding") == "staged_provenance"
        for event in _events(repo)
    )


def test_reverify_unit_cli_rejects_non_staged_units(tmp_path):
    repo = _write_repo(tmp_path)
    driver = _driver(repo)
    with pytest.raises(ValueError):
        driver.reverify_unit("never-heard-of-it")
    state = _state(repo)
    state["units"]["unit-b"]["tier"] = "oracle_green"
    (repo / RUN_ROOT / "wasm-units-state.json").write_text(json.dumps(state))
    with pytest.raises(ValueError):
        driver.reverify_unit("unit-b")


def test_unverified_inventory_buildup_pages_on_falling_fraction(tmp_path):
    repo = _write_repo(tmp_path)
    driver = _driver(repo)
    state = {
        "state_schema": 1,
        "units": {
            "v1": {"status": "green", "tier": "oracle_green"},
            "s1": {"status": "green", "tier": "compile_only"},
            "s2": {"status": "green", "tier": "compile_only"},
        },
        "verified_fraction_mark": {"verified": 1, "staged": 1, "fraction": 0.5},
    }
    driver._flag_unverified_inventory(state)
    assert any(
        event["kind"] == "unverified_inventory_buildup" for event in _events(repo)
    )
    assert state["verified_fraction_mark"]["staged"] == 2
    # a first-ever mark is a baseline, not a comparison: no page
    repo2 = _write_repo(tmp_path / "second")
    driver2 = _driver(repo2)
    state2 = {
        "state_schema": 1,
        "units": {"s1": {"status": "green", "tier": "compile_only"}},
    }
    driver2._flag_unverified_inventory(state2)
    assert not any(
        event["kind"] == "unverified_inventory_buildup" for event in _events(repo2)
    )


def test_run_state_counters_split_verified_from_staged(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    driver = _driver(repo)
    driver.run()
    run_state = json.loads((repo / RUN_ROOT / "run-state.json").read_text())
    counters = run_state["counters"]
    assert counters["units_verified"] == 1  # unit-b, just promoted
    assert counters["units_staged"] == 0
