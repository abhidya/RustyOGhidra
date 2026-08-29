"""Trace-verification maintenance verbs (Stage B at scale; src/port_trace_verify.py
+ the verify-unit / verify-sweep driver methods in src/port_wasm_units.py).

Offline tests: capture and harness invocations are mocked. Covered:
plan generation from oracle-registry prototypes (PPC arg mapping, skeleton
discipline, hand-authored plans never clobbered), scenario heuristic, the
FAIL-CLOSED compile_only -> oracle_green eligibility gate, verdict recording
into the canonical state (oracle block, oracle_divergent flag, progress
counter), sidecar publication feeding the EXISTING verification lane, and the
sweep's skip/budget/resilience rules.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from src.port_trace_verify import (
    GENERATED_BY,
    SCENARIOS_RELPATH,
    VerifySkip,
    build_sidecar_entry,
    eligible_for_oracle_green,
    generate_plan,
    load_registry_functions,
    plan_args,
    plan_path,
    plan_ret,
    family_scenario_index,
    refresh_plans,
    select_scenario,
    summarize_result,
)
from src.port_wasm_units import (
    WasmUnitDriver,
    exports_sha256,
    validate_oracle_entry,
)

RUN_ROOT = "research/decomp/generated/finish-game-port"
RESULTS = "research/decomp/data/oracle-results"


def _completed(rc: int = 0, stdout: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["git"], returncode=rc, stdout=stdout, stderr="")


def _registry_fn(
    name: str = "zz_b_",
    *,
    address: str = "0x80001000",
    return_type: str = "int",
    params: list[str] | None = None,
    returns_value: bool = True,
) -> dict:
    return {
        "name": name,
        "address": address,
        "unit": "unit-b",
        "return_type": return_type,
        "params": params if params is not None else ["int param_1"],
        "returns_value": returns_value,
    }


def _pass_payload(
    *,
    verdict: str = "pass",
    covered: int = 1,
    exported: int = 1,
    uncovered: list[str] | None = None,
    unexplained: int = 0,
    cases: int = 120,
) -> dict:
    fn_verdict = "pass" if unexplained == 0 else "fail"
    return {
        "result_schema": 1,
        "unit": "unit-b",
        "reference_kind": "dolphin_trace",
        "functions": [
            {
                "name": "zz_b_",
                "cases": cases,
                "exact": cases - unexplained,
                "rounding_explained": 0,
                "unexplained": unexplained,
                "verdict": fn_verdict,
            }
        ],
        "coverage": {
            "offsets_read_unwritten": 0,
            "sentinel_reads_detected": False,
            "stray_writes": [],
            "class_mismatches": [],
        },
        "export_coverage": {
            "covered": covered,
            "exported": exported,
            "uncovered": uncovered or [],
        },
        "corpus": {
            "mode": "replay",
            "file": "research/decomp/oracle-harness/corpora/unit-b.dolphin-trace.jsonl",
            "n": cases,
        },
        "unexplained_cases": [],
        "verdict": verdict,
    }


def _write_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / RUN_ROOT).mkdir(parents=True)
    (repo / "research/decomp/data").mkdir(parents=True)
    (repo / RESULTS).mkdir(parents=True)
    (repo / "research/tools/dolphin-trace/plans").mkdir(parents=True)
    (repo / "research/decomp/oracle-harness/corpora").mkdir(parents=True)
    queue = {
        "queue_schema": 1,
        "units": [
            {
                "name": "unit-b",
                "extractions": [],
                "prelude": [],
                "exported_functions": ["zz_b_"],
                "header_seed": "seed.h",
                "oracle": {"type": "compile_only"},
            }
        ],
    }
    (repo / RUN_ROOT / "wasm-units.json").write_text(json.dumps(queue), encoding="utf-8")
    staged = repo / "research/decomp/port-units-staging/unit-b"
    staged.mkdir(parents=True)
    (staged / "unit.c").write_text("int zz_b_(int a) { return a + 1; }\n", encoding="utf-8")
    (staged / "unit.wasm").write_bytes(b"\x00asm-unit-b")
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
        "created_at": "2026-08-26T00:00:00Z",
        "units": {
            "unit-b": {"status": "green", "attempts": 1, "tier": "compile_only"}
        },
    }
    (repo / RUN_ROOT / "wasm-units-state.json").write_text(
        json.dumps(state), encoding="utf-8"
    )
    (repo / "research/decomp/data/oracle-registry.json").write_text(
        json.dumps({"oracle_registry_schema": 1, "functions": [_registry_fn()]}),
        encoding="utf-8",
    )
    return repo


def _driver(repo: Path, **kwargs) -> WasmUnitDriver:
    defaults = dict(
        repo_root=repo,
        build_runner=lambda workdir, exports, extra=None: (True, ""),
        oracle_runner=lambda unit, wasm: (True, "120/120", "ORACLE PASS log"),
        git_runner=lambda *args: _completed(0, "abc123\n"),
    )
    defaults.update(kwargs)
    return WasmUnitDriver(**defaults)


def _harness(repo: Path, payload: dict | None, rc: int = 0, log: str = "ok"):
    """A fake harness runner that also writes the result artifact (as the
    real run-unit.mjs does)."""

    def run(name: str, wasm_path: Path):
        if payload is not None:
            (repo / RESULTS / f"{name}.json").write_text(
                json.dumps(payload), encoding="utf-8"
            )
        return rc, log, payload

    return run


def _no_capture(name, plans, scenario, cases):  # pragma: no cover - guard
    raise AssertionError("capture must not run in this test")


def _state(repo: Path) -> dict:
    return json.loads((repo / RUN_ROOT / "wasm-units-state.json").read_text())


def _events(repo: Path) -> list[dict]:
    path = repo / RUN_ROOT / "events.jsonl"
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


# ------------------------------------------------------------ plan generation


def test_plan_args_maps_gprs_in_order_and_pairs_64bit():
    args, skipped = plan_args(["int param_1", "int *param_2", "undefined8 param_3"])
    assert [a["reg"] for a in args] == ["r3", "r4", "r5", "r6"]
    assert args[2]["name"] == "param_3_hi" and args[3]["name"] == "param_3_lo"
    assert skipped == []


def test_plan_args_skips_fpr_and_stack_args_honestly():
    args, skipped = plan_args(
        ["float param_1", "int param_2"]
        + [f"int param_{i}" for i in range(3, 12)]
    )
    # float never consumes a GPR; ints run r3..r10 then spill
    assert [a["reg"] for a in args] == [f"r{i}" for i in range(3, 11)]
    assert any("FPR" in s for s in skipped)
    assert any("stack" in s for s in skipped)


def test_plan_ret_registers():
    assert plan_ret(_registry_fn(return_type="float")) == {"reg": "f1"}
    assert plan_ret(_registry_fn(return_type="int")) == {"reg": "r3"}
    assert plan_ret(_registry_fn(returns_value=False)) is None


def test_generate_plan_is_a_marked_skeleton():
    plan = generate_plan("unit-b", _registry_fn())
    assert plan["generated_by"] == GENERATED_BY
    assert plan["addr"] == "0x80001000"
    assert plan["reads"] == [] and plan["writes"] == []
    assert plan["args"] == [{"reg": "r3", "name": "param_1"}]
    assert plan["ret"] == {"reg": "r3"}


def test_refresh_plans_never_clobbers_hand_authored(tmp_path):
    repo = _write_repo(tmp_path)
    fns = load_registry_functions(repo)
    path = plan_path(repo, "unit-b", "zz_b_")
    path.write_text(
        json.dumps({"unit": "unit-b", "fn": "zz_b_", "addr": "0x80001000",
                    "args": [], "reads": [{"id": "authored", "addr": "r3", "width": 4}],
                    "ret": None, "writes": []}),
        encoding="utf-8",
    )
    summary = refresh_plans(repo, "unit-b", ["zz_b_", "zz_unknown_"], fns)
    assert summary["kept_authored"] == ["zz_b_"]
    assert summary["missing_registry"] == ["zz_unknown_"]
    kept = json.loads(path.read_text())
    assert kept["reads"][0]["id"] == "authored"


def test_refresh_plans_writes_and_refreshes_generated(tmp_path):
    repo = _write_repo(tmp_path)
    fns = load_registry_functions(repo)
    assert refresh_plans(repo, "unit-b", ["zz_b_"], fns)["written"] == ["zz_b_"]
    # unchanged on the second pass
    assert refresh_plans(repo, "unit-b", ["zz_b_"], fns)["unchanged"] == ["zz_b_"]
    # a registry prototype change refreshes the generated skeleton
    fns["zz_b_"]["params"] = ["int param_1", "int param_2"]
    assert refresh_plans(repo, "unit-b", ["zz_b_"], fns)["written"] == ["zz_b_"]
    plan = json.loads(plan_path(repo, "unit-b", "zz_b_").read_text())
    assert [a["reg"] for a in plan["args"]] == ["r3", "r4"]


# ---------------------------------------------------------- scenario heuristic


def test_scenario_heuristic_routes_title_chunk_and_defaults_battle():
    assert select_scenario("auto-c0013-004") == "title-attract"
    assert select_scenario("auto-c0001-007") == "battle-2v2-circle"
    assert select_scenario("damage-core") == "battle-2v2-circle"


def _scenario(repo, name, live_families):
    directory = repo / SCENARIOS_RELPATH
    directory.mkdir(parents=True, exist_ok=True)
    doc = {"scenario_schema": 1, "name": name, "save_state": None,
           "inject": None, "game_state": name, "dtm": None}
    if live_families is not None:
        doc["live_families"] = live_families
    (directory / f"{name}.json").write_text(json.dumps(doc), encoding="utf-8")


def test_family_scenario_index_reads_measured_live_families(tmp_path):
    _scenario(tmp_path, "battle-roster-0x801a10e8", ["0x801A10E8"])
    _scenario(tmp_path, "unmeasured", None)
    _scenario(tmp_path, "measured-empty", [])
    index = family_scenario_index(tmp_path)
    # canonicalized, and only scenarios that actually declare a family
    assert index == {"0x801a10e8": "battle-roster-0x801a10e8"}


def test_select_scenario_routes_to_the_family_that_made_it_live(tmp_path):
    _scenario(tmp_path, "battle-roster-0x801a10e8", ["0x801a10e8"])
    assert select_scenario(
        "auto-c0050-000", repo_root=tmp_path, families={"0x801a10e8"}
    ) == "battle-roster-0x801a10e8"


def test_select_scenario_fails_open_when_no_scenario_covers_the_family(tmp_path):
    _scenario(tmp_path, "battle-roster-0x801a10e8", ["0x801a10e8"])
    # a family nobody has covered still falls back to the v1 heuristic, so the
    # gate skips it visibly instead of the router inventing a state
    assert select_scenario(
        "auto-c0035-000", repo_root=tmp_path, families={"0x801301f8"}
    ) == "battle-2v2-circle"
    # and a caller that passes nothing behaves exactly as before
    assert select_scenario("auto-c0050-000") == "battle-2v2-circle"
    assert select_scenario("auto-c0050-000", repo_root=tmp_path,
                           families=frozenset()) == "battle-2v2-circle"


# ------------------------------------------------------- fail-closed tier gate


def test_eligible_full_coverage_pass_is_eligible():
    ok, reasons = eligible_for_oracle_green(_pass_payload())
    assert ok, reasons


@pytest.mark.parametrize(
    "mutate, needle",
    [
        (lambda p: p.update(verdict="partial"), "verdict"),
        (lambda p: p.update(rehearsal={"flip_arena_byte": "0x1"}), "rehearsal"),
        (lambda p: p["export_coverage"].update(covered=1, exported=2,
                                               uncovered=["zz_c_"]), "coverage"),
        (lambda p: p.pop("export_coverage"), "export_coverage"),
        (lambda p: p["functions"][0].update(unexplained=1, verdict="fail"),
         "unexplained"),
        (lambda p: p["functions"][0].update(cases=0, exact=0), "cases"),
        (lambda p: p.pop("functions"), "function"),
        (lambda p: p.pop("coverage"), "audit"),
        (lambda p: p["coverage"].update(stray_writes=["0x80001000"]), "stray"),
        (lambda p: p["coverage"].update(sentinel_reads_detected=True), "sentinel"),
    ],
)
def test_eligible_is_fail_closed(mutate, needle):
    payload = _pass_payload()
    mutate(payload)
    ok, reasons = eligible_for_oracle_green(payload)
    assert not ok
    assert any(needle.lower() in reason.lower() for reason in reasons), reasons


def test_eligible_refuses_missing_artifact():
    ok, reasons = eligible_for_oracle_green(None)
    assert not ok and reasons


def test_sidecar_entry_satisfies_the_sidecar_discipline():
    payload = _pass_payload()
    entry = build_sidecar_entry(
        "unit-b", ["zz_b_"], payload, exports_sha256(["zz_b_"])
    )
    assert validate_oracle_entry("unit-b", entry, exports=["zz_b_"]) == []
    assert entry["oracle"]["command"] == ["node", "run-unit.mjs", "--unit", "unit-b"]
    with pytest.raises(ValueError):
        build_sidecar_entry(
            "unit-b", ["zz_b_"], _pass_payload(verdict="partial"),
            exports_sha256(["zz_b_"]),
        )


def test_summarize_result_totals():
    core = summarize_result(_pass_payload(cases=120))
    assert core["verdict"] == "PASS"
    assert core["cases"] == 120 and core["byte_exact"] == 120
    assert summarize_result(None)["verdict"] == "ERROR"


# ------------------------------------------------------- verify-unit recording


def test_verify_unit_records_partial_without_tier_change(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    payload = _pass_payload(verdict="partial", covered=1, exported=2,
                            uncovered=["zz_c_"])
    driver = _driver(repo)
    result = driver.verify_unit(
        "unit-b", capture=False, harness_runner=_harness(repo, payload),
        capture_runner=_no_capture,
    )
    assert result["verdict"] == "PARTIAL"
    assert result["promoted"] is False
    assert result["not_promoted_reasons"]
    record = _state(repo)["units"]["unit-b"]
    assert record["tier"] == "compile_only"  # no automatic tier change
    assert record["oracle"]["verdict"] == "PARTIAL"
    assert record["oracle"]["cases"] == 120
    assert record["oracle"]["byte_exact"] == 120
    assert record["oracle"]["uncovered"] == ["zz_c_"]
    assert record["oracle"]["wasm_sha256"]
    assert not record.get("oracle_divergent")
    # no sidecar published for a partial
    assert not (repo / "research/decomp/data/oracle-commands.json").exists()
    kinds = [event["kind"] for event in _events(repo)]
    assert "wasm_unit_trace_verify" in kinds


def test_verify_unit_fail_flags_divergent_and_never_revokes(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    payload = _pass_payload(verdict="fail", unexplained=7)
    driver = _driver(repo)
    result = driver.verify_unit(
        "unit-b", capture=False, harness_runner=_harness(repo, payload, rc=1),
    )
    assert result["verdict"] == "FAIL"
    assert result["divergence_evidence"] == f"{RESULTS}/unit-b.json"
    record = _state(repo)["units"]["unit-b"]
    assert record["oracle_divergent"] is True
    assert record["oracle"]["divergence_evidence"] == f"{RESULTS}/unit-b.json"
    # not revoked: the unit stays a staged green, only flagged
    assert record["status"] == "green" and record["tier"] == "compile_only"
    assert (repo / "research/decomp/port-units-staging/unit-b").is_dir()


def test_verify_unit_full_pass_promotes_through_existing_path(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    driver = _driver(repo)
    result = driver.verify_unit(
        "unit-b", capture=False, harness_runner=_harness(repo, _pass_payload()),
    )
    assert result["verdict"] == "PASS"
    assert result["promoted"] is True
    record = _state(repo)["units"]["unit-b"]
    assert record["tier"] == "oracle_green"
    assert record["verify"]["status"] == "pass"
    assert record["oracle_divergent"] is False
    sidecar = json.loads(
        (repo / "research/decomp/data/oracle-commands.json").read_text()
    )
    assert sidecar["units"]["unit-b"]["exports_sha256"] == exports_sha256(["zz_b_"])
    assert (repo / "research/decomp/port-units/unit-b/unit.wasm").is_file()
    kinds = [event["kind"] for event in _events(repo)]
    assert "oracle_sidecar_published" in kinds
    assert "verdict_promoted" in kinds


def test_verify_unit_no_promote_defers_to_the_driver_lane(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    driver = _driver(repo)
    result = driver.verify_unit(
        "unit-b", capture=False, promote=False,
        harness_runner=_harness(repo, _pass_payload()),
    )
    assert result["promoted"] is False
    assert result["promotion"] == "deferred_to_driver_verification_lane"
    record = _state(repo)["units"]["unit-b"]
    assert record["tier"] == "compile_only"
    # the published sidecar entry puts the unit on the EXISTING verification
    # lane -- the supervisor-scheduled driver promotes it with no new stage
    lane = _driver(repo)
    assert lane._verification_candidates(lane._load_state()) == ["unit-b"]


def test_verify_unit_records_no_spec_without_divergence(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    driver = _driver(repo)
    result = driver.verify_unit(
        "unit-b", capture=False,
        harness_runner=_harness(
            repo, None, rc=2,
            log="ORACLE HARNESS ERROR: no spec module at specs/unit-b.spec.mjs",
        ),
    )
    assert result["verdict"] == "NO_SPEC"
    record = _state(repo)["units"]["unit-b"]
    assert record["oracle"]["verdict"] == "NO_SPEC"
    assert not record.get("oracle_divergent")
    assert record["tier"] == "compile_only"


def test_verify_unit_rejects_wrong_states(tmp_path):
    repo = _write_repo(tmp_path)
    driver = _driver(repo)
    with pytest.raises(ValueError):
        driver.verify_unit("never-heard-of-it", capture=False)
    state = _state(repo)
    state["units"]["unit-b"]["tier"] = "oracle_green"
    (repo / RUN_ROOT / "wasm-units-state.json").write_text(json.dumps(state))
    assert driver.verify_unit("unit-b", capture=False)["skipped"] == (
        "already oracle_green"
    )


def test_verify_unit_refreshes_plans_from_registry(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    driver = _driver(repo)
    result = driver.verify_unit(
        "unit-b", capture=False,
        harness_runner=_harness(repo, _pass_payload(verdict="partial",
                                                    covered=1, exported=2,
                                                    uncovered=["zz_c_"])),
    )
    assert result["plans"]["written"] == ["zz_b_"]
    plan = json.loads(plan_path(repo, "unit-b", "zz_b_").read_text())
    assert plan["generated_by"] == GENERATED_BY


def test_progress_counters_surface_divergent_units(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    driver = _driver(repo)
    driver.verify_unit(
        "unit-b", capture=False,
        harness_runner=_harness(repo, _pass_payload(verdict="fail", unexplained=3),
                                rc=1),
    )
    state = driver._load_state()
    driver._write_progress(state, "running")
    run_state = json.loads((repo / RUN_ROOT / "run-state.json").read_text())
    assert run_state["counters"]["units_oracle_divergent"] == 1


# ----------------------------------------------------------------- verify-sweep


def test_sweep_skips_already_attempted_at_same_bytes(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    payload = _pass_payload(verdict="partial", covered=1, exported=2,
                            uncovered=["zz_c_"])
    driver = _driver(repo)
    first = driver.verify_sweep(
        capture=False, harness_runner=_harness(repo, payload),
    )
    assert [a["unit"] for a in first["attempted"]] == ["unit-b"]
    second = _driver(repo).verify_sweep(
        capture=False, harness_runner=_harness(repo, payload),
    )
    assert second["attempted"] == []
    assert "already attempted" in second["skipped"]["unit-b"]
    # changed staged bytes re-open the attempt
    (repo / "research/decomp/port-units-staging/unit-b/unit.wasm").write_bytes(
        b"\x00asm-unit-b-v2"
    )
    third = _driver(repo).verify_sweep(
        capture=False, harness_runner=_harness(repo, payload),
    )
    assert [a["unit"] for a in third["attempted"]] == ["unit-b"]


def test_sweep_divergent_needs_retry_flag(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    fail = _pass_payload(verdict="fail", unexplained=2)
    _driver(repo).verify_sweep(capture=False, harness_runner=_harness(repo, fail, rc=1))
    assert _state(repo)["units"]["unit-b"]["oracle_divergent"] is True
    skipped = _driver(repo).verify_sweep(
        capture=False, harness_runner=_harness(repo, fail, rc=1),
    )
    assert skipped["attempted"] == []
    retried = _driver(repo).verify_sweep(
        capture=False, retry_divergent=True,
        harness_runner=_harness(repo, fail, rc=1),
    )
    assert [a["unit"] for a in retried["attempted"]] == ["unit-b"]


def test_sweep_is_resilient_to_capture_crashes(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    monkeypatch.setattr(
        "src.port_wasm_units.dolphin_contended", lambda repo_root, port=55555: None
    )

    def crashing_capture(name, plans, scenario, cases):
        raise OSError("stub session died mid-capture")

    report = _driver(repo).verify_sweep(
        capture=True, capture_runner=crashing_capture,
        harness_runner=_harness(repo, None),
    )
    assert report["attempted"] == [
        {"unit": "unit-b", "verdict": "ERROR",
         "error": "stub session died mid-capture"}
    ]
    record = _state(repo)["units"]["unit-b"]
    assert record["oracle"]["verdict"] == "ERROR"
    assert record["oracle"]["error"] == "stub session died mid-capture"
    assert record["tier"] == "compile_only"
    kinds = [event["kind"] for event in _events(repo)]
    assert "wasm_unit_trace_verify_error" in kinds


def test_sweep_stops_instead_of_fighting_dolphin(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    monkeypatch.setattr(
        "src.port_wasm_units.dolphin_contended",
        lambda repo_root, port=55555: "a Dolphin.exe process is already running",
    )
    report = _driver(repo).verify_sweep(capture=True)
    assert report["stopped"] == "dolphin_contended"
    assert report["attempted"] == []
    assert "dolphin_contended" in report["skipped"]["unit-b"]
    # nothing recorded as a verdict: contention is a skip, not an attempt
    assert "oracle" not in _state(repo)["units"]["unit-b"]


def test_sweep_honors_the_unit_budget(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    # a second staged green
    staged = repo / "research/decomp/port-units-staging/unit-c"
    staged.mkdir(parents=True)
    (staged / "unit.wasm").write_bytes(b"\x00asm-unit-c")
    (staged / "provenance.json").write_text(
        json.dumps({"unit": "unit-c", "exported_functions": ["zz_c_"],
                    "verified": False, "tier": "compile_only"}),
        encoding="utf-8",
    )
    state = _state(repo)
    state["units"]["unit-c"] = {"status": "green", "attempts": 1,
                               "tier": "compile_only"}
    (repo / RUN_ROOT / "wasm-units-state.json").write_text(json.dumps(state))
    payload = _pass_payload(verdict="partial", covered=1, exported=2,
                            uncovered=["zz_x_"])
    report = _driver(repo).verify_sweep(
        max_units=1, capture=False, harness_runner=_harness(repo, payload),
    )
    assert len(report["attempted"]) == 1
    assert report["stopped"] == "max_units"


def test_verify_skip_propagates_from_missing_artifact(tmp_path):
    repo = _write_repo(tmp_path)
    (repo / "research/decomp/port-units-staging/unit-b/unit.wasm").unlink()
    with pytest.raises(VerifySkip):
        _driver(repo).verify_unit("unit-b", capture=False)
