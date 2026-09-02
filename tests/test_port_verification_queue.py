"""T3 verification queue (design section 3; oracle plan section 3.4).

Offline tests for the oracle-commands.json sidecar overlay, the staged-unit
verification lane, the reverify-unit promotion path (provenance rewrite +
artifact move + registry re-tier + journaled commit), and the failure paths
(oracle red -> [V4-7] revoke; exports_sha256 mismatch -> loud stale event).
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from src.port_driver import EXIT_PROGRESSED
from src.port_knowledge_registry import REGISTRY_RELPATH, empty_registry, save_registry
from src.port_tiers import (
    TIER_BOUNDARY_GREEN,
    TIER_COMPILE_ONLY,
    TIER_ORACLE_GREEN,
    TIER_TRANSCRIPT_GREEN,
)
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


# -------------------------------------------- crash-safety (T3 review F1/F2)


def test_promotion_commits_before_staging_removal(tmp_path, monkeypatch):
    """F1 ordering: the staged copy must still exist when the promoted commit
    is made (a tree-kill at any point before that commit loses nothing), and
    the staging removal is its own later commit."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    staged_wasm = repo / "research/decomp/port-units-staging/unit-b/unit.wasm"
    commits: list[dict] = []

    def fake_git(*args):
        if args[0] == "commit":
            commits.append(
                {"message": args[2], "staged_exists": staged_wasm.is_file()}
            )
        if args[0] == "rev-parse":
            return _completed(0, "deadbeef\n")
        return _completed(0)

    driver = _driver(repo, git_runner=fake_git)
    driver.run()
    assert len(commits) == 2
    assert "promoted" in commits[0]["message"]
    assert commits[0]["staged_exists"] is True, (
        "the staged artifact must survive until the promoted commit lands"
    )
    assert "remove staged copy" in commits[1]["message"]
    assert commits[1]["staged_exists"] is False


def test_commit_failure_keeps_staged_copy_and_unit_retryable(tmp_path, monkeypatch):
    """F1 + F2: a failed promote commit leaves the staged artifact intact and
    the unit still a verification candidate; a later pass with working git
    finishes the promotion idempotently."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)

    def broken_git(*args):
        if args[0] == "commit":
            return _completed(1, "fatal: could not commit")
        if args[0] == "rev-parse":
            return _completed(0, "deadbeef\n")
        return _completed(0)

    driver = _driver(repo, git_runner=broken_git)
    driver.run()
    record = _state(repo)["units"]["unit-b"]
    assert record["tier"] == "compile_only"  # promotion NOT recorded
    assert record["verify"]["status"] == "commit_failed"
    assert (repo / "research/decomp/port-units-staging/unit-b/unit.wasm").is_file()
    # F2: commit_failed is transient -- the unit stays a candidate
    driver2 = _driver(repo, git_runner=broken_git)
    assert driver2._verification_candidates(driver2._load_state()) == ["unit-b"]
    # working git now: the promotion completes idempotently
    driver3 = _driver(repo)
    driver3.run()
    record = _state(repo)["units"]["unit-b"]
    assert record["tier"] == "oracle_green"
    assert record["verify"]["status"] == "pass"
    assert not (repo / "research/decomp/port-units-staging/unit-b").exists()


def test_transient_verify_error_leaves_candidate_oracle_red_does_not(tmp_path):
    """F2: only a COMPLETED oracle run under the same spec is unrepeatable."""
    repo = _write_repo(tmp_path)
    driver = _driver(repo)
    state = driver._load_state()
    sidecar = json.loads(
        (repo / "research/decomp/data/oracle-commands.json").read_text()
    )
    spec_sha = oracle_entry_sha(sidecar["units"]["unit-b"])
    state["units"]["unit-b"]["verify"] = {"status": "error", "spec_sha256": spec_sha}
    assert driver._verification_candidates(state) == ["unit-b"]
    state["units"]["unit-b"]["verify"] = {
        "status": "oracle_red",
        "spec_sha256": spec_sha,
    }
    assert driver._verification_candidates(state) == []


def test_reconcile_finishes_interrupted_promotion(tmp_path, monkeypatch):
    """F1 reconcile: promotion recorded (commit + state) but the driver died
    before the staging removal -- the next start finishes the cleanup."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    promoted = repo / "research/decomp/port-units/unit-b"
    promoted.mkdir(parents=True)
    (promoted / "provenance.json").write_text(
        json.dumps({"unit": "unit-b", "verified": True, "tier": "oracle_green"})
    )
    (promoted / "unit.wasm").write_bytes(b"\x00asm")
    state = {
        "state_schema": 1,
        "units": {
            "unit-b": {
                "status": "green",
                "attempts": 1,
                "tier": "oracle_green",
                "verify": {"status": "pass", "spec_sha256": "0" * 64},
            }
        },
    }
    (repo / RUN_ROOT / "wasm-units-state.json").write_text(json.dumps(state))
    driver = _driver(repo)
    driver.run()
    assert not (repo / "research/decomp/port-units-staging/unit-b").exists()
    assert (promoted / "unit.wasm").is_file()
    assert any(event["kind"] == "reverify_reconciled" for event in _events(repo))


def test_promotion_restores_entries_revoked_by_own_failed_reverify(tmp_path, monkeypatch):
    """F3: an entry revoked BY this unit's failed re-run is un-revoked (with a
    restored trail record) when the unit later promotes."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    registry = empty_registry()
    registry["entries"]["fn:zz_b_"] = {
        "kind": "prototype",
        "symbol": "zz_b_",
        "declaration": "int zz_b_(void);",
        "tier": "compile_only",
        "source_units": [],
        "revoked": True,
        "conflicts": [
            {
                "tombstone": True,
                "unit": "unit-b",
                "tier": "compile_only",
                "reason": "sole source failed its oracle re-run; entry revoked",
                "recorded_at": "2026-08-20T00:00:00Z",
            }
        ],
    }
    registry["version"] = 2
    registry_path = repo / REGISTRY_RELPATH
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    save_registry(registry_path, registry)
    driver = _driver(repo)
    result = driver.reverify_unit("unit-b")
    assert result["promoted"] is True
    after = json.loads(registry_path.read_text(encoding="utf-8"))
    entry = after["entries"]["fn:zz_b_"]
    assert entry["revoked"] is False
    assert entry["tier"] == "oracle_green"
    assert "unit-b" in entry["source_units"]
    assert any(conflict.get("restored") for conflict in entry["conflicts"])
    assert any(conflict.get("tombstone") for conflict in entry["conflicts"])
    assert any(event["kind"] == "registry_restored" for event in _events(repo))


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


# ------------------------------- per-FUNCTION console evidence (E6, the no-op)
#
# `_verification_candidates` returned [] on every driver pass because the only
# source it could read was the oracle_green sidecar. The two console standards
# that actually produced results -- transcript_green (16 passing functions) and
# boundary_green -- were invisible to it. These tests cover the second source,
# and above all they cover the bar it must NOT drop below.

TRANSCRIPT_WASM = b"\x00asm-evidence"
TRANSCRIPT_WASM_SHA = (
    "d6e5f7e4d4d0d6b62b3e9d18a5cbf1cc7f6e9a5b8e0f5b1c6c85a0d3a02b1f47"
)


def _transcript_artifact(
    unit: str, export: str, wasm_sha: str, over: dict | None = None
) -> dict:
    """A minimally-complete transcript_green result artifact, shaped exactly
    like the committed ones in research/decomp/data/oracle-results."""
    payload = {
        "result_schema": 1,
        "standard": "transcript_green",
        "unit": unit,
        "fn": export,
        "claim": {"established": True, "weaker_than": "oracle_green"},
        "harness": {
            "entry": "research/decomp/oracle-harness/run-transcript.mjs",
            "min_cases": 8,
        },
        "wasm": {"path": f"/staging/{unit}/unit.wasm", "sha256": wasm_sha},
        "capture": {
            "file": f"research/decomp/oracle-harness/corpora/{unit}.{export}"
                    ".transcript.jsonl",
            "cases": 24,
        },
        "function": {"export": export},
        "cases_passed": 24,
        "calls_matched": 24,
        "vacuous_cases": [],
        "divergence": None,
        "verdict": "pass",
    }
    payload.update(over or {})
    return payload


def _staged_with_evidence(
    tmp_path: Path, exports: list[str], artifacts: dict[str, dict] | None = None
) -> Path:
    """A repo whose `unit-b` is a staged compile-only green with `exports`, and
    whose oracle-results directory holds `artifacts` (keyed by export)."""
    repo = _write_repo(tmp_path)
    (repo / "research/decomp/data/oracle-commands.json").unlink()
    staged = repo / "research/decomp/port-units-staging/unit-b"
    (staged / "unit.wasm").write_bytes(TRANSCRIPT_WASM)
    sha = hashlib.sha256(TRANSCRIPT_WASM).hexdigest()
    (staged / "provenance.json").write_text(
        json.dumps({
            "unit": "unit-b",
            "exported_functions": exports,
            "verified": False,
            "tier": "compile_only",
        }),
        encoding="utf-8",
    )
    results = repo / "research/decomp/data/oracle-results"
    results.mkdir(parents=True, exist_ok=True)
    for export, payload in (
        artifacts
        if artifacts is not None
        else {name: _transcript_artifact("unit-b", name, sha) for name in exports}
    ).items():
        (results / f"unit-b.{export}.transcript.json").write_text(
            json.dumps(payload), encoding="utf-8"
        )
    return repo


def test_partial_function_evidence_is_not_a_candidate_but_is_reported(tmp_path):
    """The live shape today: every unit with console evidence has 1-3 of its
    8 exports verified. It must not promote, and it must not be silent."""
    sha = hashlib.sha256(TRANSCRIPT_WASM).hexdigest()
    repo = _staged_with_evidence(
        tmp_path, ["e0", "e1", "e2"],
        {"e0": _transcript_artifact("unit-b", "e0", sha)},
    )
    driver = _driver(repo)

    assert driver._verification_candidates(_state(repo)) == []

    scanned = [e for e in _events(repo) if e["kind"] == "function_evidence_scanned"]
    assert len(scanned) == 1
    assert scanned[0]["covered"] == 1 and scanned[0]["total"] == 3
    assert scanned[0]["tier"] is None
    assert sorted(scanned[0]["uncovered"]) == ["e1", "e2"]


def test_full_coverage_function_evidence_becomes_a_candidate(tmp_path):
    repo = _staged_with_evidence(tmp_path, ["e0", "e1"])
    driver = _driver(repo)
    assert driver._verification_candidates(_state(repo)) == ["unit-b"]


def test_evidence_for_other_wasm_bytes_is_refused(tmp_path):
    """claim-honesty rule 8: a result artifact records the sha256 of the wasm
    it replayed. Evidence about other bytes is evidence about another binary,
    and this binding is STRICTER than the sidecar's export-set hash."""
    repo = _staged_with_evidence(
        tmp_path, ["e0"], {"e0": _transcript_artifact("unit-b", "e0", "00" * 32)}
    )
    driver = _driver(repo)

    assert driver._verification_candidates(_state(repo)) == []
    scanned = [e for e in _events(repo) if e["kind"] == "function_evidence_scanned"]
    assert any("claim-honesty rule 8" in r for r in scanned[0]["refused"])


@pytest.mark.parametrize(
    ("mutation", "needle"),
    [
        ({"verdict": "fail"}, "verdict is 'fail'"),
        ({"divergence": {"case": 0}}, "divergence recorded"),
        ({"claim": {"established": False}}, "claim.established is not True"),
        ({"vacuous_cases": [1, 2]}, "vacuous case"),
        ({"cases_passed": 0}, "cases_passed 0"),
        ({"cases_passed": 3}, "below min_cases 8"),
        ({"result_schema": 2}, "result_schema 2 is not 1"),
        ({"standard": "oracle_green"}, "not a per-function verified tier"),
        ({"standard": "spine_green"}, "not a per-function verified tier"),
        ({"rehearsal": True}, "rehearsal-stamped"),
        ({"harness": {"entry": "run-unit.mjs", "min_cases": 8}},
         "is not run-transcript.mjs"),
        ({"unit": "someone-else"}, "artifact names unit"),
        ({"fn": "not_an_export", "function": {"export": "not_an_export"}},
         "not in the staged provenance export set"),
        ({"fn": "e0", "function": {"export": "e_other"}},
         "does not name exactly one export"),
        ({"wasm": {"sha256": None}}, "claim-honesty rule 8"),
    ],
)
def test_every_admission_check_is_fail_closed(tmp_path, mutation, needle):
    """One mutation per check, mirroring the mutant discipline the oracle
    harnesses already use. A missing or wrong field is a REFUSAL, never a
    default-pass."""
    sha = hashlib.sha256(TRANSCRIPT_WASM).hexdigest()
    repo = _staged_with_evidence(
        tmp_path, ["e0"],
        {"e0": _transcript_artifact("unit-b", "e0", sha, mutation)},
    )
    driver = _driver(repo)

    assert driver._verification_candidates(_state(repo)) == []
    scanned = [e for e in _events(repo) if e["kind"] == "function_evidence_scanned"]
    assert any(needle in reason for reason in scanned[0]["refused"]), scanned[0]


def test_a_mixed_unit_never_promotes(tmp_path):
    """Full coverage, two incomparable standards: MIXED, and mixed is not a
    tier a unit may be promoted to."""
    sha = hashlib.sha256(TRANSCRIPT_WASM).hexdigest()
    boundary = {
        "result_schema": 1,
        "standard": "boundary_green",
        "unit": "unit-b",
        "harness": {"entry": "research/decomp/oracle-harness/run-spine.mjs"},
        "wasm": {"sha256": sha},
        "capture": {"file": "research/decomp/oracle-harness/corpora/b.jsonl"},
        "spine": {"export": "e1"},
        "calls_matched": 274,
        "divergence": None,
        "verdict": "pass",
    }
    repo = _staged_with_evidence(
        tmp_path, ["e0", "e1"],
        {"e0": _transcript_artifact("unit-b", "e0", sha)},
    )
    (repo / "research/decomp/data/oracle-results/unit-b.e1.boundary.json").write_text(
        json.dumps(boundary), encoding="utf-8"
    )
    driver = _driver(repo)

    assert driver._verification_candidates(_state(repo)) == []
    scanned = [e for e in _events(repo) if e["kind"] == "function_evidence_scanned"]
    assert scanned[0]["tier"] == "mixed"
    assert scanned[0]["covered"] == scanned[0]["total"] == 2


def test_promotion_by_function_evidence_records_transcript_green_not_oracle_green(
    tmp_path,
):
    """The whole point: a console-derived pass now moves the ledger -- to the
    tier it actually earned, and to no stronger one."""
    repo = _staged_with_evidence(tmp_path, ["e0", "e1"])
    driver = _driver(repo)
    state = _state(repo)

    result = driver._reverify_unit_inner("unit-b", state)

    assert result["promoted"] is True
    assert state["units"]["unit-b"]["tier"] == TIER_TRANSCRIPT_GREEN
    provenance = json.loads(
        (repo / "research/decomp/port-units/unit-b/provenance.json").read_text()
    )
    assert provenance["tier"] == TIER_TRANSCRIPT_GREEN
    assert provenance["previous_tier"] == TIER_COMPILE_ONLY
    promoted = [e for e in _events(repo) if e["kind"] == "verdict_promoted"]
    assert promoted and promoted[0]["tier"] == TIER_TRANSCRIPT_GREEN

    # the spec it published is durable, reviewable, and one replay per export
    sidecar = json.loads(
        (repo / "research/decomp/data/oracle-commands.json").read_text()
    )
    entry = sidecar["units"]["unit-b"]
    assert entry["tier"] == TIER_TRANSCRIPT_GREEN
    assert [step["export"] for step in entry["oracle"]["steps"]] == ["e0", "e1"]
    for step in entry["oracle"]["steps"]:
        assert "run-transcript.mjs" in step["command"]
        assert "--min-cases" in step["command"]
        assert "TRANSCRIPT_GREEN" in step["success_patterns"][0]


# ------------------------------------------- sidecar discipline for the steps


def _steps_entry(exports: list[str], **over) -> dict:
    steps = [
        {
            "export": name,
            "command": ["node", "run-transcript.mjs", "--capture", f"{name}.jsonl"],
            "cwd": "research/decomp/oracle-harness",
            "env": {"ORACLE_WASM": "{wasm}"},
            "success_patterns": ["(?m)^.*VERDICT: TRANSCRIPT_GREEN$"],
        }
        for name in exports
    ]
    entry = {
        "exports_sha256": exports_sha256(exports),
        "tier": TIER_TRANSCRIPT_GREEN,
        "oracle": {"steps": steps},
    }
    entry.update(over)
    return entry


def test_a_steps_entry_must_cover_every_export():
    problems = validate_oracle_entry(
        "unit-b", _steps_entry(["e0"]), exports=["e0", "e1"]
    )
    assert any("no replay step for ['e1']" in p for p in problems)


def test_a_steps_entry_must_pin_its_own_standards_total_line():
    entry = _steps_entry(["e0"])
    entry["oracle"]["steps"][0]["success_patterns"] = [
        "(?m)^ORACLE TOTAL functions=1/1 cases=10 UNEXPLAINED: 0 VERDICT: PASS$"
    ]
    problems = validate_oracle_entry("unit-b", entry, exports=["e0"])
    assert any("TRANSCRIPT_GREEN" in p for p in problems)


def test_a_per_function_tier_may_not_use_the_single_command_form():
    entry = _entry(["zz_b_"])
    entry["tier"] = TIER_TRANSCRIPT_GREEN
    problems = validate_oracle_entry("unit-b", entry, exports=["zz_b_"])
    assert any("requires oracle.steps" in p for p in problems)


def test_an_unknown_tier_on_a_sidecar_entry_is_refused():
    """The promotion gate stays an ALLOWLIST. A sidecar entry declaring a tier
    outside VERIFIED_TIERS cannot promote anything, whatever it replays."""
    for tier in ("compile_only", "green", "transcript-green", None, 7):
        entry = _steps_entry(["e0"], tier=tier)
        problems = validate_oracle_entry("unit-b", entry, exports=["e0"])
        assert any("is not a verified tier" in p for p in problems), tier


def test_an_entry_without_a_tier_is_still_an_oracle_green_entry():
    """Bit-identical behaviour for every entry written before the field
    existed -- and defaulting to the STRONGEST standard is the one default
    that cannot silently weaken a claim."""
    assert validate_oracle_entry("unit-b", _entry(["zz_b_"]), exports=["zz_b_"]) == []


def test_run_oracle_dispatches_to_steps_and_ANDs_them(tmp_path, monkeypatch):
    """Every step must pass. One red step reds the unit, and the summary names
    which -- conjunction, never disjunction."""
    repo = _write_repo(tmp_path)
    driver = _driver(repo, oracle_runner=None)
    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(command)
        good = "TRANSCRIPT TOTAL cases=24/24 calls=24/24 rets=0 " \
               "DIVERGENCE: none VERDICT: TRANSCRIPT_GREEN"
        bad = "TRANSCRIPT DIVERGENCE: case 3"
        ok = "e1.jsonl" not in " ".join(command)
        return subprocess.CompletedProcess(
            args=command, returncode=0 if ok else 1,
            stdout=good if ok else bad, stderr="",
        )

    monkeypatch.setattr("src.port_wasm_units.subprocess.run", fake_run)
    monkeypatch.setattr("src.port_wasm_units.resolve_node_exe", lambda: "node")

    passed, summary, log = driver._run_oracle(
        {"name": "unit-b", "oracle": _steps_entry(["e0"])["oracle"]},
        repo / "unit.wasm",
    )
    assert passed is True and len(calls) == 1
    assert "TRANSCRIPT_GREEN" in log

    passed, summary, log = driver._run_oracle(
        {"name": "unit-b", "oracle": _steps_entry(["e0", "e1"])["oracle"]},
        repo / "unit.wasm",
    )
    assert passed is False
    assert "FAILED at e1" in summary
    assert len(calls) == 3          # every step is still run, for the log


def test_all_three_counters_agree_on_one_state(tmp_path):
    """The asymmetry that made the defect dangerous: `run-state.json`'s
    `units_verified` used the correct positive predicate while
    `port_contract.queue_status` and `port_progress.classify_counts` used
    "not compile_only", so two files published by the SAME run disagreed --
    and the looser number is the one in the README banner. They must now be
    the same predicate, on the same allowlist, over the same records.

    The mixture below is the live ledger's own shape: an oracle_green unit, a
    staged compile-only unit, and green records with no tier at all
    (`damage-core` and `knockback-core` carry exactly that).
    """
    from src.port_contract import queue_status
    from src.port_progress import classify_counts

    repo = _write_repo(tmp_path)
    records = {
        "u-oracle": {"status": "green", "tier": "oracle_green"},
        "u-transcript": {"status": "green", "tier": "transcript_green"},
        "u-boundary": {"status": "green", "tier": "boundary_green"},
        "u-staged": {"status": "green", "tier": "compile_only"},
        "u-notier": {"status": "green"},
        "u-typo": {"status": "green", "tier": "oracle-green"},
        "u-red": {"status": "red_retryable"},
    }
    (repo / RUN_ROOT / "wasm-units-state.json").write_text(
        json.dumps({"state_schema": 1, "units": records}), encoding="utf-8"
    )
    (repo / RUN_ROOT / "wasm-units.json").write_text(
        json.dumps({"queue_schema": 1,
                    "units": [{"name": name} for name in records]}),
        encoding="utf-8",
    )
    driver = _driver(repo)
    driver._write_progress({"units": records}, "running")
    counters = json.loads(
        (repo / RUN_ROOT / "run-state.json").read_text()
    )["counters"]
    progress = classify_counts(records)
    contract = queue_status(repo, "wasm_units")["counts"]

    assert counters["units_verified"] == progress["green"] == contract["green"] == 3
    assert counters["units_staged"] == progress["staged"] == contract["staged"] == 1
    assert (
        counters["units_unknown_tier"]
        == progress["unknown_tier"]
        == contract["unknown_tier"]
        == 2
    )
    # and the weaker standards are never totalled into the write-verified one
    assert counters["units_write_verified"] == 1
    assert counters["units_verified_by_tier"] == {
        "boundary_green": 1, "oracle_green": 1, "transcript_green": 1,
    }


# ------------------------------ source 3: a committed unit-level <unit>.json


def _unit_result(
    unit: str, exports: list[str], wasm_sha: str, over: dict | None = None
) -> dict:
    functions = [
        {"name": name, "verdict": "pass", "cases": 100, "exact": 100,
         "rounding_explained": 0, "unexplained": 0}
        for name in exports
    ]
    payload = {
        "result_schema": 1,
        "unit": unit,
        "verdict": "pass",
        "reference_kind": "dolphin_trace",
        "wasm": {"sha256": wasm_sha},
        "export_coverage": {
            "covered": len(exports), "exported": len(exports), "uncovered": [],
        },
        "functions": functions,
        "coverage": {
            "offsets_read_unwritten": 0, "sentinel_reads_detected": False,
            "stray_writes": [], "class_mismatches": [],
        },
    }
    payload.update(over or {})
    return payload


def _with_unit_result(
    tmp_path: Path, exports: list[str], over: dict | None = None
) -> Path:
    repo = _staged_with_evidence(tmp_path, exports, {})
    sha = hashlib.sha256(TRANSCRIPT_WASM).hexdigest()
    (repo / "research/decomp/data/oracle-results/unit-b.json").write_text(
        json.dumps(_unit_result("unit-b", exports, sha, over)), encoding="utf-8"
    )
    return repo


def test_a_committed_full_coverage_unit_result_is_a_candidate(tmp_path):
    repo = _with_unit_result(tmp_path, ["e0", "e1"])
    driver = _driver(repo)
    assert driver._verification_candidates(_state(repo)) == ["unit-b"]
    entry, reasons = driver._unit_result_entry("unit-b", ["e0", "e1"])
    assert reasons == []
    # the oracle_green form: ONE command, and the ORACLE TOTAL line pinned
    assert entry["oracle"]["command"][:2] == ["node", "run-unit.mjs"]
    assert "VERDICT: PASS" in entry["oracle"]["success_patterns"][0]
    assert entry.get("tier", "oracle_green") == "oracle_green"


@pytest.mark.parametrize(
    ("mutation", "needle"),
    [
        ({"verdict": "partial"}, "verdict is 'partial'"),
        ({"verdict": "fail"}, "verdict is 'fail'"),
        ({"export_coverage": {"covered": 1, "exported": 2, "uncovered": ["e1"]}},
         "is not full"),
        ({"rehearsal": True}, "rehearsal-stamped"),
        ({"result_schema": 2}, "result_schema 2 is not 1"),
        ({"unit": "other"}, "artifact names unit"),
        ({"wasm": {"sha256": "ab" * 32}}, "claim-honesty rule 8"),
        ({"coverage": {"offsets_read_unwritten": 1,
                       "sentinel_reads_detected": False,
                       "stray_writes": [], "class_mismatches": []}},
         "declared-read offsets unwritten"),
    ],
)
def test_a_unit_result_that_verify_unit_would_refuse_never_promotes(
    tmp_path, mutation, needle
):
    """Source 3 adds a source, not a shortcut: it runs the SAME
    eligible_for_oracle_green gate verify-unit runs, plus a staged-bytes
    binding that gate never had."""
    repo = _with_unit_result(tmp_path, ["e0", "e1"], mutation)
    driver = _driver(repo)
    assert driver._verification_candidates(_state(repo)) == []
    scanned = [e for e in _events(repo) if e["kind"] == "unit_result_scanned"]
    assert scanned, "the refusal must be reported, not silent"
    assert any(needle in reason for reason in scanned[0]["refused"]), scanned[0]


def test_a_unit_result_promotes_to_oracle_green(tmp_path):
    repo = _with_unit_result(tmp_path, ["e0", "e1"])
    driver = _driver(repo)
    state = _state(repo)
    result = driver._reverify_unit_inner("unit-b", state)
    assert result["promoted"] is True
    assert state["units"]["unit-b"]["tier"] == TIER_ORACLE_GREEN


def test_a_transcript_green_promotion_never_promotes_registry_entries(tmp_path):
    """port_knowledge_registry reserves AUTHORITATIVE injection for
    oracle_green, and `promote_unit_entries` writes that tier unconditionally.
    A transcript_green promotion must therefore leave the unit's harvested
    decisions advisory -- otherwise a callee-boundary claim would be relabelled
    write-verified inside the artifact that decides what gets injected into
    every later unit's prompt (claim-honesty rule 3)."""
    repo = _staged_with_evidence(tmp_path, ["e0", "e1"])
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
    state = _state(repo)

    result = driver._reverify_unit_inner("unit-b", state)

    assert result["promoted"] is True
    assert state["units"]["unit-b"]["tier"] == TIER_TRANSCRIPT_GREEN
    after = json.loads(registry_path.read_text(encoding="utf-8"))
    assert after["entries"]["dat:0x80000000"]["tier"] == "compile_only"
    withheld = [
        e for e in _events(repo) if e["kind"] == "registry_promotion_withheld"
    ]
    assert withheld and withheld[0]["tier"] == TIER_TRANSCRIPT_GREEN
    assert "reserved for oracle_green" in withheld[0]["reason"]
