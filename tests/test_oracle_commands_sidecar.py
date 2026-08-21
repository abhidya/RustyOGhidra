"""Oracle-spec sidecar validation + Phase 1 driver dry-run.

Oracle workstream Phase 1 (docs/oracle-workstream-plan.md §3.4 D-4, §6 gate
term 6). Validates research/decomp/data/oracle-commands.json against the S3
pattern discipline and the exports_sha256 binding rule, and dry-runs the
committed damage-core entry through the driver's REAL ``_run_oracle`` gate —
green on the clean replay, red under the deliberate-red rehearsal knob.

The driver overlay that CONSUMES the sidecar is Phase 2; nothing here touches
driver state, the queue, or the journal. ``_run_oracle`` only needs
``self.repo_root``, so the dry-run builds the object with ``__new__`` and never
runs ``__init__`` (no lock, no state files).
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path

import pytest

from src.port_wasm_units import WasmUnitDriver

OGHIDRA_ROOT = Path(__file__).resolve().parents[1]
GOTYAFORCE_ROOT = OGHIDRA_ROOT.parents[2]
SIDECAR = GOTYAFORCE_ROOT / "research" / "decomp" / "data" / "oracle-commands.json"
HARNESS_DIR = GOTYAFORCE_ROOT / "research" / "decomp" / "oracle-harness"
FIXTURE = HARNESS_DIR / "corpora" / "damage-core-poc.jsonl"
DAMAGE_CORE = GOTYAFORCE_ROOT / "research" / "decomp" / "port-units" / "damage-core"

TOTAL_LINE_RX = re.compile(
    r"^\(\?m\)\^ORACLE TOTAL functions=\d+/\d+ cases=\d+ UNEXPLAINED: 0 VERDICT: PASS\$$"
)

pytestmark = pytest.mark.skipif(
    not SIDECAR.is_file(), reason="GotYaForce oracle-commands.json sidecar not present"
)


def _load() -> dict:
    return json.loads(SIDECAR.read_text(encoding="utf-8"))


def _exports_sha256(names: list[str]) -> str:
    return hashlib.sha256("\n".join(sorted(names)).encode()).hexdigest()


def test_sidecar_schema_and_pattern_discipline() -> None:
    data = _load()
    assert data["spec_schema"] == 1
    assert data["units"], "sidecar has no unit entries"
    for name, entry in data["units"].items():
        assert re.fullmatch(r"[\w-]+", name), name
        assert re.fullmatch(r"[0-9a-f]{64}", entry["exports_sha256"]), name
        oracle = entry["oracle"]
        assert oracle["command"][0] == "node", "specs use bare 'node' (F-10)"
        assert oracle["cwd"] == "research/decomp/oracle-harness"
        patterns = oracle["success_patterns"]
        assert patterns, f"{name}: success_patterns required (I-5)"
        # S3/[R1]: the first pattern is the anchored total line with the (?m)
        # inline flag; a bare-anchored pattern can never match under the
        # driver's flagless re.search on a multi-line log.
        assert TOTAL_LINE_RX.match(patterns[0]), (
            f"{name}: first pattern must be the (?m)-anchored total line, got {patterns[0]!r}"
        )
        for pat in patterns:
            re.compile(pat)  # every pattern must be a valid regex
            if "^" in pat or "$" in pat:
                assert pat.startswith("(?m)"), (
                    f"{name}: anchored pattern without (?m) inline flag: {pat!r}"
                )


def test_damage_core_entry_binds_to_provenance_exports() -> None:
    data = _load()
    entry = data["units"]["damage-core"]
    provenance = json.loads((DAMAGE_CORE / "provenance.json").read_text(encoding="utf-8"))
    exported = provenance["exported_functions"]
    assert entry["exports_sha256"] == _exports_sha256(exported), (
        "exports_sha256 must bind to the committed artifact's provenance export set (§3.4)"
    )
    # One per-function pattern per exported function (S3 rule 2).
    patterns = "\n".join(entry["oracle"]["success_patterns"])
    for fn in exported:
        assert re.escape(fn) in patterns or fn in patterns, f"no per-function pattern for {fn}"


def _dry_run_driver(extra_env: dict[str, str] | None = None) -> tuple[bool, str, str]:
    entry = _load()["units"]["damage-core"]
    oracle = json.loads(json.dumps(entry["oracle"]))  # deep copy
    if extra_env:
        oracle.setdefault("env", {}).update(extra_env)
    driver = WasmUnitDriver.__new__(WasmUnitDriver)  # no __init__: no lock, no state
    driver.repo_root = GOTYAFORCE_ROOT
    return driver._run_oracle({"oracle": oracle}, DAMAGE_CORE / "unit.wasm")


needs_runtime = pytest.mark.skipif(
    not (FIXTURE.is_file() and (DAMAGE_CORE / "unit.wasm").is_file() and shutil.which("node")),
    reason="damage-core fixture/wasm/node not available",
)


@needs_runtime
def test_dry_run_clean_replay_is_green() -> None:
    passed, _summary, log = _dry_run_driver()
    assert passed, f"clean replay should pass the driver gate; log tail: {log[-800:]}"
    assert re.search(r"(?m)^ORACLE TOTAL functions=4/4 .* VERDICT: PASS$", log)


@needs_runtime
def test_dry_run_flipped_arena_byte_is_red() -> None:
    """Gate term 6: one flipped arena byte -> nonzero exit -> driver records red."""
    passed, _summary, log = _dry_run_driver({"ORACLE_FLIP_ARENA_BYTE": "80436f7e"})
    assert not passed, "deliberate-red rehearsal must fail the driver gate"
    assert "DELIBERATE-RED REHEARSAL" in log
    assert re.search(r"(?m)^ORACLE TOTAL functions=\d+/4 cases=\d+ UNEXPLAINED: [1-9]\d* VERDICT: FAIL$", log)
