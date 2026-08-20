"""Queue generation gates: SDK skip (both separators), non-C-identifier
exclusion + skipped report, integer seed header, and settled-verdict migration
across a queue regeneration."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.port_queue_fill import (  # noqa: E402
    REASON_NON_C_IDENTIFIER,
    REASON_SDK,
    SKIP_PREFIXES,
    classify_blocks,
    skip_reason,
    write_skipped_report,
)
from src.port_queue_migrate import migrate_state  # noqa: E402
from src.port_unit_generator import (  # noqa: E402
    CORE_SEED,
    build_unit,
    is_c_identifier,
)
from src.port_wasm_units import SYSTEM_PROMPT  # noqa: E402

GOTYAFORCE = Path(r"D:\GotYaForce")


# --------------------------------------------------------------- skip rules


def test_skip_prefixes_cover_both_sdk_separators():
    # ghidra-export markers use hyphens ("gnt4-memset"); the old
    # underscore-only tuple let all 996 SDK functions into the queue.
    assert "gnt4_" in SKIP_PREFIXES and "gnt4-" in SKIP_PREFIXES


@pytest.mark.parametrize(
    "name,reason",
    [
        ("gnt4_PSVECAdd_bl", REASON_SDK),
        ("gnt4-memset", REASON_SDK),
        ("gnt4-__init_hardware-bl", REASON_SDK),
        ("cCameraManager::HasCamera(cBaseCamera", REASON_NON_C_IDENTIFIER),
        ("glxCopyMatrix(float", REASON_NON_C_IDENTIFIER),
        ("operator.new(unsigned", REASON_NON_C_IDENTIFIER),
        ("zz_0005630_", None),
        ("FUN_80031634", None),
        ("__check_pad3", None),
    ],
)
def test_skip_reason(name, reason):
    assert skip_reason(name) == reason


def test_is_c_identifier():
    assert is_c_identifier("a_B9")
    assert not is_c_identifier("9start")
    assert not is_c_identifier("has-hyphen")
    assert not is_c_identifier("ns::fn")
    assert not is_c_identifier("")


def test_classify_blocks_reports_skips_but_not_already_ported():
    blocks = [
        {"name": "zz_0000010_", "addr": "80000010"},
        {"name": "gnt4-memset", "addr": "80000020"},
        {"name": "Foo::bar(int", "addr": "80000030"},
        {"name": "zz_0000040_", "addr": "80000040"},  # already queued
    ]
    eligible, skipped = classify_blocks(blocks, already_ported={"zz_0000040_"})
    assert eligible == ["zz_0000010_"]
    assert [(s["name"], s["reason"]) for s in skipped] == [
        ("gnt4-memset", REASON_SDK),
        ("Foo::bar(int", REASON_NON_C_IDENTIFIER),
    ]
    assert all(s["addr"] for s in skipped)


def test_hyphenated_sdk_name_is_reported_as_sdk_not_identifier():
    # "gnt4-memset" fails both gates; the design-level reason wins.
    assert skip_reason("gnt4-memset") == REASON_SDK


# ---------------------------------------------------------- skipped report


def test_write_skipped_report_merges_per_chunk(tmp_path):
    path = tmp_path / "wasm-units-skipped.json"
    write_skipped_report(
        path,
        {
            "chunk_0000": [
                {"name": "gnt4-memset", "addr": "80003100", "reason": REASON_SDK}
            ],
            "chunk_0001": [],
        },
    )
    # A later subset sweep replaces only the chunks it swept.
    report = write_skipped_report(
        path,
        {
            "chunk_0002": [
                {
                    "name": "Foo::bar(int",
                    "addr": "80004100",
                    "reason": REASON_NON_C_IDENTIFIER,
                }
            ]
        },
    )
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert on_disk == report
    assert set(report["skipped_by_chunk"]) == {"chunk_0000", "chunk_0002"}
    assert report["total_skipped"] == 2


# ------------------------------------------------------------- seed header


@pytest.mark.skipif(not GOTYAFORCE.exists(), reason="GotYaForce checkout absent")
def test_seed_header_matches_driver_prompt():
    seed = (GOTYAFORCE / CORE_SEED).read_text(encoding="utf-8")
    # Integer undefined8 + integer CONCAT44 — exactly what SYSTEM_PROMPT
    # mandates; a double seed made the base self-contradictory and cost a
    # model round per unit.
    assert re.search(r"typedef\s+unsigned\s+long\s+long\s+undefined8;", seed)
    assert "typedef double undefined8;" not in seed
    concat = seed[seed.index("#define CONCAT44"):]
    concat = concat[: concat.index("\n\n")]
    assert "union" not in concat and "double" not in concat.replace(
        "int->double", ""
    )
    for line in (
        "typedef unsigned long long  undefined8",
        "CONCAT44(hi, lo)  = ((unsigned long long)(unsigned int)(hi) << 32)",
    ):
        assert line in SYSTEM_PROMPT


@pytest.mark.skipif(not GOTYAFORCE.exists(), reason="GotYaForce checkout absent")
def test_poc_seed_left_untouched():
    # The PoC damage unit was verified against the double-form seed; the fix
    # forked a generator-only seed instead of editing history under the PoC.
    poc = (
        GOTYAFORCE / "research/decomp/poc/wasm-port-poc/gnt4_shim.h"
    ).read_text(encoding="utf-8")
    assert "typedef double undefined8;" in poc
    assert CORE_SEED != "research/decomp/poc/wasm-port-poc/gnt4_shim.h"


# ------------------------------------------------------- generator + seed


def _mini_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "research/decomp/ghidra-export").mkdir(parents=True)
    seed = repo / CORE_SEED
    seed.parent.mkdir(parents=True, exist_ok=True)
    seed.write_text(
        "#ifndef S\n#define S\ntypedef unsigned long long undefined8;\n"
        "#define CONCAT44(hi, lo) (((unsigned long long)(unsigned int)(hi) "
        "<< 32) | (unsigned int)(lo))\n#endif\n",
        encoding="utf-8",
    )
    (repo / "research/decomp/ghidra-export/chunk_0000.c").write_text(
        "// ==== 80000010  zz_0000010_ ====\n"
        "void zz_0000010_(void)\n{\n  return;\n}\n"
        "// ==== 80000020  gnt4-memset ====\n"
        "void gnt4-memset(void)\n{\n  return;\n}\n"
        "// ==== 80000030  Foo::bar(int ====\n"
        "void Foo::bar(int x)\n{\n  return;\n}\n"
        "// ==== 80000040  FUN_80000040 ====\n"
        "void FUN_80000040(void)\n{\n  return;\n}\n",
        encoding="utf-8",
    )
    return repo


def test_build_unit_header_starts_from_generator_seed(tmp_path):
    repo = _mini_repo(tmp_path)
    unit = build_unit(repo, "chunk_0000", ["zz_0000010_"], None, "auto-c0000-000")
    header = (repo / unit["header_seed"]).read_text(encoding="utf-8")
    assert header.startswith("#ifndef S")
    assert "typedef unsigned long long undefined8;" in header


def test_fill_main_excludes_and_reports(tmp_path, monkeypatch, capsys):
    from src import port_queue_fill

    repo = _mini_repo(tmp_path)
    queue_path = repo / "research/decomp/generated/finish-game-port/wasm-units.json"
    queue_path.parent.mkdir(parents=True, exist_ok=True)
    queue_path.write_text(json.dumps({"queue_schema": 1, "units": []}))
    monkeypatch.setattr(
        sys, "argv", ["fill", "--repo", str(repo), "--batch", "8"]
    )
    port_queue_fill.main()
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    assert [u["name"] for u in queue["units"]] == ["auto-c0000-000"]
    assert queue["units"][0]["exported_functions"] == [
        "zz_0000010_",
        "FUN_80000040",
    ]
    report = json.loads(
        (queue_path.parent / "wasm-units-skipped.json").read_text(encoding="utf-8")
    )
    assert report["total_skipped"] == 2
    assert [(e["name"], e["reason"]) for e in report["skipped_by_chunk"]["chunk_0000"]] == [
        ("gnt4-memset", REASON_SDK),
        ("Foo::bar(int", REASON_NON_C_IDENTIFIER),
    ]
    assert "units_added=1" in capsys.readouterr().out


def test_fill_rebuild_drops_only_generated_units(tmp_path, monkeypatch):
    from src import port_queue_fill

    repo = _mini_repo(tmp_path)
    queue_path = repo / "research/decomp/generated/finish-game-port/wasm-units.json"
    queue_path.parent.mkdir(parents=True, exist_ok=True)
    manual = {
        "name": "damage-core",
        "exported_functions": ["zz_0000010_"],
        "oracle": {"type": "harness"},
    }
    stale = {
        "name": "auto-c0000-000",
        "generated_by": "port_unit_generator",
        "exported_functions": ["gnt4-memset"],
    }
    queue_path.write_text(json.dumps({"queue_schema": 1, "units": [manual, stale]}))
    monkeypatch.setattr(
        sys, "argv", ["fill", "--repo", str(repo), "--batch", "8", "--rebuild"]
    )
    port_queue_fill.main()
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    names = [u["name"] for u in queue["units"]]
    assert names == ["damage-core", "auto-c0000-000"]
    regenerated = queue["units"][1]
    # SDK export gone; damage-core's function stays excluded from auto units.
    assert regenerated["exported_functions"] == ["FUN_80000040"]


# --------------------------------------------------------------- migration


def _queue(units):
    return {"queue_schema": 1, "units": units}


def _unit(name, fns, generated=True):
    u = {"name": name, "exported_functions": fns}
    if generated:
        u["generated_by"] = "port_unit_generator"
    return u


def test_migrate_carries_identical_sets_only():
    old_queue = _queue(
        [
            _unit("damage-core", ["a", "b"], generated=False),
            _unit("auto-c0000-000", ["f1", "f2"]),
            _unit("auto-c0000-001", ["f3", "f4"]),
            _unit("auto-c0000-002", ["f5", "f6"]),
        ]
    )
    old_state = {
        "state_schema": 1,
        "created_at": "2026-08-01T00:00:00+00:00",
        "units": {
            "damage-core": {"status": "green", "attempts": 1, "commit": "abc"},
            "auto-c0000-000": {"status": "green", "attempts": 2, "commit": "def"},
            "auto-c0000-001": {"status": "structural_ineligible", "attempts": 1},
            "auto-c0000-002": {"status": "red_retryable", "attempts": 3},
        },
    }
    # Regeneration: 000 keeps its set under a NEW name, 001's batch shifted.
    new_queue = _queue(
        [
            _unit("damage-core", ["a", "b"], generated=False),
            _unit("auto-c0000-007", ["f1", "f2"]),
            _unit("auto-c0000-008", ["f3", "f5"]),
            _unit("auto-c0000-009", ["f4", "f6"]),
        ]
    )
    state, report = migrate_state(old_queue, old_state, new_queue)

    assert state["units"]["damage-core"]["commit"] == "abc"
    assert state["units"]["auto-c0000-007"] == {
        "status": "green",
        "attempts": 2,
        "commit": "def",
    }
    assert state["units"]["auto-c0000-008"] == {"status": "pending", "attempts": 0}
    assert state["units"]["auto-c0000-009"] == {"status": "pending", "attempts": 0}
    assert state["state_schema"] == 1
    assert state["created_at"] == "2026-08-01T00:00:00+00:00"

    assert report["summary"] == {
        "old_units": 4,
        "new_units": 4,
        "carried": 2,
        "dropped_set_changed": 1,
        "reset_unsettled": 1,
    }
    by_old = {e["old_unit"]: e for e in report["entries"]}
    assert by_old["auto-c0000-001"]["disposition"] == "dropped_set_changed"
    assert by_old["auto-c0000-001"]["new_units_overlapping"] == [
        "auto-c0000-008",
        "auto-c0000-009",
    ]
    assert by_old["auto-c0000-002"]["disposition"] == "reset_unsettled"


def test_migrate_never_guesses_between_duplicate_sets():
    old_queue = _queue([_unit("auto-c0000-000", ["f1"])])
    old_state = {
        "state_schema": 1,
        "units": {"auto-c0000-000": {"status": "green", "attempts": 1}},
    }
    new_queue = _queue([_unit("auto-a", ["f1"]), _unit("auto-b", ["f1"])])
    state, report = migrate_state(old_queue, old_state, new_queue)
    assert state["units"]["auto-a"]["status"] == "pending"
    assert state["units"]["auto-b"]["status"] == "pending"
    assert report["summary"]["dropped_set_changed"] == 1
