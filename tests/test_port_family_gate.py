"""Borg-family liveness gating for verify-sweep candidate selection
(src/port_family_gate.py + the ``family_gate`` path in
src/port_wasm_units.py::verify_sweep).

Covered: the family derivation itself (constructor-block ownership, registry-
first address resolution, Ghidra's zz_ name encoding, the deliberately open
last block), scenario live-set parsing in all three states (declared /
measured-empty / UNKNOWN), the ``family_not_live`` skip the sweep emits, the
blocked-inventory summary line, the fail-open degradations (no family index,
unknown liveness, non-family units), and the ``--no-family-gate`` escape
hatch.

Offline: no Dolphin, no harness, no network. One test reads the committed
family-coverage artifact and skips when it is not present.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from src.port_family_gate import (
    FAMILY_NOT_LIVE,
    FamilyIndex,
    ScenarioLiveness,
    UnitFamilies,
    address_from_name,
    blocked_inventory_summary,
    decide,
    export_address,
    scenario_live_families,
)
from src.port_wasm_units import WasmUnitDriver

RUN_ROOT = "research/decomp/generated/finish-game-port"
RESULTS = "research/decomp/data/oracle-results"
SCENARIOS = "research/tools/dolphin-trace/scenarios"
STAGING = "research/decomp/port-units-staging"

# Real ROM constructor addresses (research/decomp/data/
# family-state-machine-coverage.json). pl0300 owns [0x800c04c0, 0x800c7c80) --
# the only family live in the repo's one battle savestate.
PL0300 = "0x800c04c0"
PL0700 = "0x800c7c80"
PL0201 = "0x800c8560"
PL0600 = "0x800c91bc"


def _coverage_families() -> dict:
    return {
        "schemaVersion": 2,
        "families": [
            {"constructorAddress": PL0300, "members": ["pl0300", "pl030b"],
             "implementationMembers": [], "actions": []},
            {"constructorAddress": PL0700, "members": ["pl0700"],
             "implementationMembers": [], "actions": []},
            {"constructorAddress": PL0201, "members": ["pl0201"],
             "implementationMembers": [], "actions": []},
            {"constructorAddress": PL0600, "members": ["pl0600"],
             "implementationMembers": [], "actions": []},
        ],
    }


# --------------------------------------------------------- family derivation


def test_address_decoding_covers_both_ghidra_name_forms():
    # FUN_ carries the whole address; zz_ drops the leading '8' of 0x8xxxxxxx
    # (evidence index: zz_0027adc_ is the function at 0x80027adc).
    assert address_from_name("FUN_800c05bc") == 0x800C05BC
    assert address_from_name("zz_00c0d0c_") == 0x800C0D0C
    assert address_from_name("zz_0027adc_") == 0x80027ADC
    assert address_from_name("memcpy") is None


def test_export_address_prefers_the_registry_over_the_name():
    registry = {"renamed_helper": {"address": "0x800c0800"}}
    assert export_address("renamed_helper", registry) == 0x800C0800
    # a registry entry without a usable address falls back to the name
    assert export_address("FUN_800c064c", {"FUN_800c064c": {}}) == 0x800C064C
    assert export_address("FUN_800c064c", {}) == 0x800C064C


def test_family_index_assigns_a_known_unit_to_its_constructor_block(tmp_path):
    """auto-c0019-017's real export set must derive to pl0300 -- the family
    whose constructor block [0x800c04c0, 0x800c7c80) contains every one of
    them."""
    repo = tmp_path / "repo"
    (repo / "research/decomp/data").mkdir(parents=True)
    (repo / "research/decomp/data/family-state-machine-coverage.json").write_text(
        json.dumps(_coverage_families()), encoding="utf-8"
    )
    index = FamilyIndex.load(repo)
    exports = [
        "FUN_800c05bc", "FUN_800c064c", "FUN_800c066c", "FUN_800c0800",
        "FUN_800c086c", "FUN_800c08a8", "FUN_800c08f0", "FUN_800c0914",
    ]
    derived = index.unit_families(exports, {})
    assert derived.families == frozenset({PL0300})
    assert derived.undetermined == ()
    assert derived.gated is True
    assert index.label(PL0300) == "0x800c04c0/pl0300"


def test_family_index_uses_block_boundaries_not_unit_numbering(tmp_path):
    repo = tmp_path / "repo"
    (repo / "research/decomp/data").mkdir(parents=True)
    (repo / "research/decomp/data/family-state-machine-coverage.json").write_text(
        json.dumps(_coverage_families()), encoding="utf-8"
    )
    index = FamilyIndex.load(repo)
    assert index.family_for_address(0x800C04C0) == PL0300   # the constructor
    assert index.family_for_address(0x800C7C7F) == PL0300   # last byte of block
    assert index.family_for_address(0x800C7C80) == PL0700   # next constructor
    assert index.family_for_address(0x80001000) is None     # below every family
    # The last block has no next constructor to close it, so anything at or
    # past it is UNDETERMINED rather than attributed to pl0600 by guess.
    assert index.family_for_address(0x800C91BC) is None
    assert index.family_for_address(0x80200000) is None


def test_missing_coverage_artifact_yields_no_index(tmp_path):
    assert FamilyIndex.load(tmp_path / "nowhere") is None


def test_unit_mixing_family_and_non_family_code_is_not_gated(tmp_path):
    repo = tmp_path / "repo"
    (repo / "research/decomp/data").mkdir(parents=True)
    (repo / "research/decomp/data/family-state-machine-coverage.json").write_text(
        json.dumps(_coverage_families()), encoding="utf-8"
    )
    index = FamilyIndex.load(repo)
    derived = index.unit_families(["FUN_800c05bc", "FUN_80001000"], {})
    assert derived.families == frozenset({PL0300})
    assert derived.undetermined == ("FUN_80001000",)
    assert derived.gated is False
    live = ScenarioLiveness("s", frozenset({PL0700}), "test")
    assert decide(derived, live).selectable is True
    assert decide(derived, live).reason == "family_partially_undetermined"


def _committed_repo_root() -> Path | None:
    """The nearest ancestor holding the committed family-coverage artifact,
    so the regression below works from the live checkout AND from a worktree,
    and simply skips anywhere else."""
    for ancestor in Path(__file__).resolve().parents:
        if (ancestor / "research/decomp/data"
                / "family-state-machine-coverage.json").is_file():
            return ancestor
    return None


@pytest.mark.skipif(
    _committed_repo_root() is None,
    reason="committed family-coverage artifact not present in this checkout",
)
def test_committed_coverage_artifact_places_the_live_family_block():
    """Regression against the REAL artifact: the pl0300 block must still own
    the address range the five reachable staged units export from."""
    index = FamilyIndex.load(_committed_repo_root())
    assert index is not None
    for address in (0x800C05BC, 0x800C0D0C, 0x800C4468, 0x800C7350):
        assert index.family_for_address(address) == PL0300
    assert index.members_by_family[PL0300][:2] == ("pl0300", "pl030b")


# --------------------------------------------------------- scenario liveness


def _write_scenario(repo: Path, name: str, payload: dict) -> None:
    (repo / SCENARIOS).mkdir(parents=True, exist_ok=True)
    (repo / SCENARIOS / f"{name}.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )


def test_scenario_live_family_set_is_read_from_the_scenario_json(tmp_path):
    repo = tmp_path / "repo"
    _write_scenario(repo, "battle-2v2-circle", {
        "scenario_schema": 1,
        "name": "battle-2v2-circle",
        "live_families": ["0x800C04C0"],
        "live_families_basis": "MEASURED 2026-08-29",
    })
    liveness = scenario_live_families(repo, "battle-2v2-circle")
    assert liveness.known is True
    assert liveness.families == frozenset({PL0300})   # canonicalized lowercase
    assert liveness.basis == "MEASURED 2026-08-29"


def test_measured_empty_live_set_is_distinct_from_unknown(tmp_path):
    repo = tmp_path / "repo"
    _write_scenario(repo, "empty", {"scenario_schema": 1, "live_families": []})
    liveness = scenario_live_families(repo, "empty")
    assert liveness.known is True
    assert liveness.families == frozenset()


@pytest.mark.parametrize(
    "payload",
    [
        {"scenario_schema": 1},                              # field absent
        {"scenario_schema": 1, "live_families": None},       # explicitly unknown
        {"scenario_schema": 1, "live_families": "0x800c04c0"},  # wrong type
        {"scenario_schema": 1, "live_families": ["pl0300"]},  # unparseable entry
    ],
)
def test_undeclared_or_malformed_live_set_reads_as_unknown(tmp_path, payload):
    repo = tmp_path / "repo"
    _write_scenario(repo, "s", payload)
    liveness = scenario_live_families(repo, "s")
    assert liveness.known is False
    assert liveness.families is None


def test_missing_scenario_file_reads_as_unknown(tmp_path):
    liveness = scenario_live_families(tmp_path / "repo", "nope")
    assert liveness.known is False


# ------------------------------------------------------------ gate decision


def test_unknown_liveness_never_skips_anything():
    gated = UnitFamilies(frozenset({PL0700}), ())
    decision = decide(gated, ScenarioLiveness("s", None, "unmeasured"))
    assert decision.selectable is True
    assert decision.reason == "scenario_liveness_unknown"


def test_absent_family_is_the_only_skip():
    live = ScenarioLiveness("battle-2v2-circle", frozenset({PL0300}), "measured")
    assert decide(UnitFamilies(frozenset({PL0300}), ()), live).reason == "family_live"
    assert decide(UnitFamilies(frozenset(), ()), live).reason == "no_gating_family"
    blocked = decide(UnitFamilies(frozenset({PL0700}), ()), live)
    assert blocked.selectable is False
    assert blocked.reason == FAMILY_NOT_LIVE
    # a unit straddling two adjacent family blocks runs if EITHER is live
    both = decide(UnitFamilies(frozenset({PL0300, PL0700}), ()), live)
    assert both.selectable is True


def test_blocked_inventory_summary_counts_units_and_families():
    live = ScenarioLiveness("battle-2v2-circle", frozenset({PL0300}), "measured")
    blocked = {
        "u1": decide(UnitFamilies(frozenset({PL0700}), ()), live),
        "u2": decide(UnitFamilies(frozenset({PL0700}), ()), live),
        "u3": decide(UnitFamilies(frozenset({PL0201}), ()), live),
    }
    summary = blocked_inventory_summary(blocked)
    assert summary.startswith("family gate: 3 units skipped across 2 absent families")
    assert "0x800c7c80 x2" in summary
    assert "0x800c8560 x1" in summary
    assert blocked_inventory_summary({}) == (
        "family gate: 0 units skipped across 0 absent families"
    )


# ------------------------------------------------------- sweep integration


def _completed(rc: int = 0, stdout: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["git"], returncode=rc,
                                       stdout=stdout, stderr="")


def _stage(repo: Path, unit: str, exports: list[str]) -> None:
    staged = repo / STAGING / unit
    staged.mkdir(parents=True)
    (staged / "unit.wasm").write_bytes(b"\x00asm-" + unit.encode())
    (staged / "provenance.json").write_text(
        json.dumps({"unit": unit, "exported_functions": exports,
                    "verified": False, "tier": "compile_only"}),
        encoding="utf-8",
    )


def _write_repo(tmp_path: Path, *, with_coverage: bool = True,
                live_families: object = [PL0300]) -> Path:
    """Two staged compile-only greens: ``unit-live`` exports pl0300 code (the
    family the battle savestate loads), ``unit-dead`` exports pl0201 code."""
    repo = tmp_path / "repo"
    (repo / RUN_ROOT).mkdir(parents=True)
    (repo / "research/decomp/data").mkdir(parents=True)
    (repo / RESULTS).mkdir(parents=True)
    (repo / "research/tools/dolphin-trace/plans").mkdir(parents=True)
    (repo / "research/decomp/oracle-harness/corpora").mkdir(parents=True)
    units = {"unit-live": ["FUN_800c05bc"], "unit-dead": ["FUN_800c8600"]}
    (repo / RUN_ROOT / "wasm-units.json").write_text(
        json.dumps({
            "queue_schema": 1,
            "units": [
                {"name": name, "extractions": [], "prelude": [],
                 "exported_functions": exports, "header_seed": "seed.h",
                 "oracle": {"type": "compile_only"}}
                for name, exports in units.items()
            ],
        }),
        encoding="utf-8",
    )
    for name, exports in units.items():
        _stage(repo, name, exports)
    (repo / RUN_ROOT / "wasm-units-state.json").write_text(
        json.dumps({
            "state_schema": 1,
            "created_at": "2026-08-29T00:00:00Z",
            "units": {
                name: {"status": "green", "attempts": 1, "tier": "compile_only"}
                for name in units
            },
        }),
        encoding="utf-8",
    )
    (repo / "research/decomp/data/oracle-registry.json").write_text(
        json.dumps({"oracle_registry_schema": 1, "functions": [
            {"name": "FUN_800c05bc", "address": "0x800c05bc", "unit": "unit-live",
             "return_type": "void", "params": [], "returns_value": False},
            {"name": "FUN_800c8600", "address": "0x800c8600", "unit": "unit-dead",
             "return_type": "void", "params": [], "returns_value": False},
        ]}),
        encoding="utf-8",
    )
    if with_coverage:
        (repo / "research/decomp/data/family-state-machine-coverage.json").write_text(
            json.dumps(_coverage_families()), encoding="utf-8"
        )
    scenario = {
        "scenario_schema": 1,
        "name": "battle-2v2-circle",
        "save_state": "2v2 gred cotrolled players no cpu.sav",
        "inject": "circle+b",
        "game_state": "2v2 sav + circle+b injection",
        "dtm": None,
    }
    if live_families != "omit":
        scenario["live_families"] = live_families
        scenario["live_families_basis"] = "MEASURED 2026-08-29"
    _write_scenario(repo, "battle-2v2-circle", scenario)
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


def _harness(repo: Path):
    def run(name: str, wasm_path: Path):
        return 1, "no spec module", None
    return run


def test_sweep_skips_units_whose_family_is_not_live(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    report = _driver(repo).verify_sweep(
        capture=False, harness_runner=_harness(repo),
    )
    assert [a["unit"] for a in report["attempted"]] == ["unit-live"]
    reason = report["skipped"]["unit-dead"]
    assert reason.startswith(FAMILY_NOT_LIVE + ":")
    assert "0x800c8560/pl0201" in reason
    assert "battle-2v2-circle" in reason
    # the skip is structured, not only a log line
    blocked = report["family_gate"]["blocked"]["unit-dead"]
    assert blocked["reason"] == FAMILY_NOT_LIVE
    assert blocked["families"] == [PL0201]
    assert blocked["scenario"] == "battle-2v2-circle"
    # and the live unit is never treated as blocked
    assert "unit-live" not in report["family_gate"]["blocked"]
    assert report["family_gate"]["selectable_reasons"]["unit-live"] == "family_live"


def test_sweep_reports_the_blocked_inventory_summary(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    report = _driver(repo).verify_sweep(
        capture=False, harness_runner=_harness(repo),
    )
    gate = report["family_gate"]
    assert gate["enabled"] is True
    assert gate["units_considered"] == 2
    assert gate["summary"] == (
        "family gate: 1 units skipped across 1 absent families "
        "-- 0x800c8560/pl0201 x1"
    )
    assert gate["scenarios"]["battle-2v2-circle"]["live_families"] == [PL0300]
    assert gate["scenarios"]["battle-2v2-circle"]["known"] is True


def test_sweep_degrades_to_ungated_selection_when_liveness_is_unknown(
    tmp_path, monkeypatch
):
    """An UNKNOWN live set must never look like 'nothing is live'."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path, live_families="omit")
    report = _driver(repo).verify_sweep(
        max_units=5, capture=False, harness_runner=_harness(repo),
    )
    assert sorted(a["unit"] for a in report["attempted"]) == [
        "unit-dead", "unit-live",
    ]
    gate = report["family_gate"]
    assert gate["blocked"] == {}
    assert gate["scenarios"]["battle-2v2-circle"]["known"] is False
    assert gate["selectable_reasons"]["unit-dead"] == "scenario_liveness_unknown"


def test_sweep_disables_the_gate_without_a_family_index(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path, with_coverage=False)
    report = _driver(repo).verify_sweep(
        max_units=5, capture=False, harness_runner=_harness(repo),
    )
    assert sorted(a["unit"] for a in report["attempted"]) == [
        "unit-dead", "unit-live",
    ]
    gate = report["family_gate"]
    assert gate["enabled"] is False
    assert "family-state-machine-coverage.json" in gate["disabled_reason"]
    assert "DISABLED" in gate["summary"]


def test_no_family_gate_restores_ungated_selection(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    report = _driver(repo).verify_sweep(
        max_units=5, capture=False, family_gate=False,
        harness_runner=_harness(repo),
    )
    assert sorted(a["unit"] for a in report["attempted"]) == [
        "unit-dead", "unit-live",
    ]
    assert report["family_gate"]["enabled"] is False
    assert report["family_gate"]["disabled_reason"] == "--no-family-gate"
    assert "unit-dead" not in report["skipped"]


def test_sweep_emits_a_family_gate_event(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    _driver(repo).verify_sweep(capture=False, harness_runner=_harness(repo))
    events = [
        json.loads(line)
        for line in (repo / RUN_ROOT / "events.jsonl").read_text().splitlines()
        if line.strip()
    ]
    gate_events = [e for e in events
                   if e["kind"] == "wasm_unit_verify_sweep_family_gate"]
    assert len(gate_events) == 1
    assert gate_events[0]["blocked"] == 1
    assert gate_events[0]["enabled"] is True
