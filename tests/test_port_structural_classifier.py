"""T3 concrete-type structural classifier + F4 recheck (design section 2.7).

The classifier settles ONLY the proven case: a cast error between concrete
built-in types, on a source line whose every identifier is declared in the
verbatim .c with a concrete built-in type, surviving every applied header of
the attempt. The F4 recheck replays settled/nominated units offline and
reports the classifier-freeze signal; it never settles or unsettles.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from src.port_wasm_units import (
    WasmUnitDriver,
    concrete_type_contradictions,
)

RUN_ROOT = "research/decomp/generated/finish-game-port"

UNIT_C = (
    "#include \"gnt4_shim.h\"\n"
    "\n"
    "void zz_test_(void)\n"
    "{\n"
    "  char *local_68;\n"
    "  float fVar1;\n"
    "  fVar1 = (float)local_68;\n"
    "}\n"
)
CAST_LINE = 7  # "fVar1 = (float)local_68;"
CAST_DIAG = f"unit.c:{CAST_LINE}:11: error: pointer cannot be cast to type 'float'"


def _rounds(*diag_sets: list[str]) -> list[dict]:
    return [
        {"iteration": i + 1, "stage": "compile", "error_count": len(diags),
         "header": "h", "diagnostics": diags, "fingerprint": str(i)}
        for i, diags in enumerate(diag_sets)
    ]


# ------------------------------------------------------------- pure classifier


def test_concrete_cast_on_local_declared_concrete_is_proven():
    proofs = concrete_type_contradictions(
        UNIT_C, _rounds([CAST_DIAG], [CAST_DIAG])
    )
    assert len(proofs) == 1
    assert f"unit.c:{CAST_LINE}" in proofs[0]


def test_header_typedef_types_are_never_proven():
    unit_c = UNIT_C.replace("char *local_68", "undefined8 local_68")
    diag = f"unit.c:{CAST_LINE}:11: error: cannot cast 'undefined8' to type 'float'"
    assert concrete_type_contradictions(unit_c, _rounds([diag])) == []


def test_dat_symbol_on_the_line_is_never_proven():
    unit_c = UNIT_C.replace("(float)local_68", "(float)DAT_802c44f8")
    assert concrete_type_contradictions(unit_c, _rounds([CAST_DIAG])) == []


def test_diag_cleared_in_a_later_round_is_never_proven():
    # the second applied header removed it: header-DEPENDENT by evidence
    assert concrete_type_contradictions(
        UNIT_C, _rounds([CAST_DIAG], ["unit.c:2:1: error: other"])
    ) == []


def test_non_cast_errors_are_never_proven():
    diag = f"unit.c:{CAST_LINE}:11: error: expected ';' after expression"
    assert concrete_type_contradictions(UNIT_C, _rounds([diag])) == []


# ----------------------------------------------------------------- integration


def _completed(rc: int = 0, stdout: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["git"], returncode=rc, stdout=stdout, stderr="")


def _write_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "research/decomp/ghidra-export").mkdir(parents=True)
    (repo / RUN_ROOT).mkdir(parents=True)
    (repo / "research/decomp/poc").mkdir(parents=True)
    # chunk body = UNIT_C minus the include; the driver prepends the include
    # and (no prelude here) the verbatim marker line.
    body = "void zz_test_(void)\n{\n  char *local_68;\n  float fVar1;\n  fVar1 = (float)local_68;\n}\n"
    chunk = repo / "research/decomp/ghidra-export/chunk_9999.c"
    chunk.write_text("// pad\n" + body + "// tail\n", encoding="utf-8")
    (repo / "research/decomp/poc/seed.h").write_text("/* seed */\n", encoding="utf-8")
    queue = {
        "queue_schema": 1,
        "units": [
            {
                "name": "unit-a",
                "extractions": [
                    {"file": "research/decomp/ghidra-export/chunk_9999.c", "start": 2, "end": 7}
                ],
                "prelude": [],
                "exported_functions": ["zz_test_"],
                "header_seed": "research/decomp/poc/seed.h",
                "oracle": {"type": "compile_only"},
            }
        ],
    }
    (repo / RUN_ROOT / "wasm-units.json").write_text(json.dumps(queue), encoding="utf-8")
    return repo


class HeaderLLM:
    default_model = "fake"

    def __init__(self):
        self.calls = 0

    def generate(self, **kwargs):
        self.calls += 1
        return f"```c\n/* attempt {self.calls} */\n```"


def _driver(repo: Path, **kwargs) -> WasmUnitDriver:
    defaults = dict(
        repo_root=repo,
        build_runner=lambda workdir, exports, extra=None: (True, ""),
        oracle_runner=lambda unit, wasm: (True, "1/1", "PASS"),
        git_runner=lambda *args: _completed(0, "abc123\n"),
    )
    defaults.update(kwargs)
    return WasmUnitDriver(**defaults)


def _cast_build_runner():
    counter = {"n": 0}

    def build(workdir, exports, extra=None):
        counter["n"] += 1
        unit_c = (workdir / "unit.c").read_text(encoding="utf-8")
        line = next(
            i
            for i, text in enumerate(unit_c.splitlines(), start=1)
            if "(float)local_68" in text
        )
        return False, (
            f"unit.c:{line}:11: error: pointer cannot be cast to type 'float'\n"
            f"unit.c:1:1: error: filler variant {counter['n']}"
        )

    return build


def test_persistent_concrete_cast_settles_structural(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    driver = _driver(repo, build_runner=_cast_build_runner(), llm=HeaderLLM())
    driver.run()
    state = json.loads((repo / RUN_ROOT / "wasm-units-state.json").read_text())
    record = state["units"]["unit-a"]
    assert record["status"] == "structural_ineligible"
    assert "concrete-type contradiction" in record["error"]
    assert "pointer cannot be cast" in record["error"]


def test_fixable_looking_failure_stays_retryable(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    counter = {"n": 0}

    def build(workdir, exports, extra=None):
        counter["n"] += 1
        return False, (
            f"unit.c:3:1: error: unknown type name 'sometype'\n"
            f"unit.c:1:1: error: filler variant {counter['n']}"
        )

    driver = _driver(repo, build_runner=build, llm=HeaderLLM())
    driver.run()
    state = json.loads((repo / RUN_ROOT / "wasm-units-state.json").read_text())
    assert state["units"]["unit-a"]["status"] == "red_retryable"


# ------------------------------------------------------------------ F4 recheck


def test_f4_recheck_reports_freeze_signal_and_never_settles(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    # queue a second unit so the nominated red exists too
    queue = json.loads((repo / RUN_ROOT / "wasm-units.json").read_text())
    second = dict(queue["units"][0])
    second = json.loads(json.dumps(queue["units"][0]))
    second["name"] = "unit-nominated"
    queue["units"].append(second)
    (repo / RUN_ROOT / "wasm-units.json").write_text(json.dumps(queue))
    state = {
        "state_schema": 1,
        "units": {
            "unit-a": {
                "status": "structural_ineligible",
                "attempts": 1,
                "error": "concrete-type contradiction ...",
            },
            "unit-nominated": {
                "status": "red_retryable",
                "attempts": 3,
                "f4_nominated": True,
                "diagnosis": {"verdict": "STRUCTURAL", "reason": "r"},
            },
        },
    }
    (repo / RUN_ROOT / "wasm-units-state.json").write_text(json.dumps(state))

    def linking_build(workdir, exports, extra=None):
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    driver = _driver(repo, build_runner=linking_build)
    result = driver.f4_recheck(5)
    # nominated red replays first, then the settled unit
    assert [r["unit"] for r in result["sample"]] == ["unit-nominated", "unit-a"]
    assert all(r["linked"] for r in result["sample"])
    # a SETTLED unit linking is the freeze signal (a nominated red linking
    # merely proves FIXABLE)
    assert result["classifier_freeze_signal"] is True
    # the recheck reports -- verdicts are untouched
    after = json.loads((repo / RUN_ROOT / "wasm-units-state.json").read_text())
    assert after["units"]["unit-a"]["status"] == "structural_ineligible"
    assert after["units"]["unit-nominated"]["status"] == "red_retryable"
    events = [
        json.loads(line)
        for line in (repo / RUN_ROOT / "events.jsonl").read_text().splitlines()
    ]
    assert any(e["kind"] == "f4_recheck" for e in events)


def test_f4_recheck_no_freeze_when_replay_still_fails(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    state = {
        "state_schema": 1,
        "units": {
            "unit-a": {"status": "structural_ineligible", "attempts": 1},
        },
    }
    (repo / RUN_ROOT / "wasm-units-state.json").write_text(json.dumps(state))
    driver = _driver(
        repo,
        build_runner=_cast_build_runner(),
        llm=HeaderLLM(),
    )
    result = driver.f4_recheck(5)
    assert result["classifier_freeze_signal"] is False
    assert result["sample"][0]["linked"] is False
