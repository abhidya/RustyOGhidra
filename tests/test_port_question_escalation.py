"""T3 question escalation (design section 2.12).

(a) targeted-symbol question: a retry whose previous attempt's final
diagnostics implicate <=5 symbols opens with the narrow declare-these-symbols
question, merged into the seed, REPLACING the retry's first full-header round
(call count does not grow). (b) diagnosis question: once per unit lifetime
after the second failed attempt -- STRUCTURAL deprioritises + nominates for F4
and never settles; the terminal waiting_world_change page carries diagnoses.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from src.port_driver import EXIT_NO_WORK
from src.port_wasm_units import (
    DIAGNOSIS_MALFORMED_LIMIT,
    MAX_COMPILE_ITERS,
    WasmUnitDriver,
    assemble_post_mortem,
    merge_targeted_declarations,
    referencing_lines,
    targeted_question_symbols,
)

RUN_ROOT = "research/decomp/generated/finish-game-port"


def _completed(rc: int = 0, stdout: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["git"], returncode=rc, stdout=stdout, stderr="")


def _write_repo(tmp_path: Path, units: list[str] = ("unit-a",)) -> Path:
    repo = tmp_path / "repo"
    (repo / "research/decomp/ghidra-export").mkdir(parents=True)
    (repo / RUN_ROOT).mkdir(parents=True)
    (repo / "research/decomp/poc").mkdir(parents=True)
    chunk = repo / "research/decomp/ghidra-export/chunk_9999.c"
    chunk.write_text(
        "// line1\nint zz_test_(int a)\n{\n  return FOO + a;\n}\n// tail\n",
        encoding="utf-8",
    )
    (repo / "research/decomp/poc/seed.h").write_text(
        "/* seed */\n#define FOO 0\n", encoding="utf-8"
    )
    queue = {
        "queue_schema": 1,
        "units": [
            {
                "name": name,
                "extractions": [
                    {"file": "research/decomp/ghidra-export/chunk_9999.c", "start": 2, "end": 5}
                ],
                "prelude": ["int zz_test_(int a);"],
                "exported_functions": ["zz_test_"],
                "header_seed": "research/decomp/poc/seed.h",
                "oracle": {"type": "compile_only"},
            }
            for name in units
        ],
    }
    (repo / RUN_ROOT / "wasm-units.json").write_text(json.dumps(queue), encoding="utf-8")
    return repo


class RecordingLLM:
    """Answers by phase; records every call."""

    default_model = "fake"

    def __init__(self, replies: dict[str, str], default: str = "```c\n/* h */\n```"):
        self.replies = replies
        self.default = default
        self.calls: list[dict] = []

    def generate(self, **kwargs):
        self.calls.append(kwargs)
        phase = kwargs.get("phase", "")
        for prefix, reply in self.replies.items():
            if phase.startswith(prefix):
                return reply
        return self.default


def _driver(repo: Path, **kwargs) -> WasmUnitDriver:
    defaults = dict(
        repo_root=repo,
        build_runner=lambda workdir, exports, extra=None: (True, ""),
        oracle_runner=lambda unit, wasm: (True, "1/1", "PASS"),
        git_runner=lambda *args: _completed(0, "abc123\n"),
    )
    defaults.update(kwargs)
    return WasmUnitDriver(**defaults)


def _seed_red_state(repo: Path, diagnostics: list[str], attempts: int = 1) -> None:
    state = {
        "state_schema": 1,
        "created_at": "2026-08-20T00:00:00Z",
        "units": {
            "unit-a": {
                "status": "red_retryable",
                "attempts": attempts,
                "error": "not linked: previous failure",
                "last_stage": "wasm-link",
                "rounds": [
                    {
                        "iteration": 1,
                        "stage": "compile",
                        "error_count": len(diagnostics),
                        "header": "seed.h",
                        "diagnostics": diagnostics,
                        "fingerprint": "f" * 64,
                    }
                ],
                # no world_version recorded => pre-gate red, schedulable
            }
        },
    }
    (repo / RUN_ROOT / "wasm-units-state.json").write_text(
        json.dumps(state), encoding="utf-8"
    )


def _state(repo: Path) -> dict:
    return json.loads((repo / RUN_ROOT / "wasm-units-state.json").read_text())


def _events(repo: Path) -> list[dict]:
    path = repo / RUN_ROOT / "events.jsonl"
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


# ------------------------------------------------------------- pure functions


def test_targeted_question_symbols_extracts_and_bounds():
    assert targeted_question_symbols(
        ["unit.c:3:5: error: use of undeclared identifier 'FOO'"]
    ) == ["FOO"]
    # every error-shaped line must yield a symbol, or the narrow question
    # would leave part of the failure unaddressed
    assert targeted_question_symbols(
        [
            "unit.c:3:5: error: use of undeclared identifier 'FOO'",
            "unit.c:9:1: error: expected ';' after expression",
        ]
    ) == []
    many = [
        f"unit.c:{i}:1: error: use of undeclared identifier 'SYM_{i}'"
        for i in range(7)
    ]
    assert targeted_question_symbols(many) == []
    # import-gate lists qualify
    gate = (
        "link gate: these symbols are UNDEFINED and became wasm imports, but "
        "they are not gnt4_* SDK functions, so they must be DEFINED in "
        "gnt4_shim.h with correct PowerPC semantics: CONCAT44, DAT_802c44f8"
    )
    assert targeted_question_symbols([gate]) == ["CONCAT44", "DAT_802c44f8"]


def test_referencing_lines_pick_call_sites():
    text = "int a;\nint FOO;\nreturn FOO + 1;\n"
    lines = referencing_lines(text, ["FOO"])
    assert "2: int FOO;" in lines and "3: return FOO + 1;" in lines


def test_merge_targeted_declarations_replaces_never_duplicates():
    header = "#define FOO 0\nint keep_me(void);\nextern int BAR;\n"
    merged = merge_targeted_declarations(
        header, "#define FOO (*(int *)0x80001234)", ["FOO", "BAR"]
    )
    assert merged.count("#define FOO") == 1
    assert "(*(int *)0x80001234)" in merged
    assert "extern int BAR;" not in merged  # replaced (reply owns BAR now)
    assert "int keep_me(void);" in merged
    assert "TARGETED (design 2.12a)" in merged


def test_assemble_post_mortem_is_mechanical():
    record = {
        "attempts": 2,
        "error": "not linked: boom",
        "last_stage": "wasm-link",
        "world_version": {"registry_version": "7", "prompt_version": "2"},
        "rounds": [
            {"iteration": 1, "stage": "compile", "error_count": 4,
             "diagnostics": ["e1", "e2"]},
            {"iteration": 2, "stage": "compile", "error_count": 2,
             "diagnostics": ["e1"]},
        ],
        "diagnosis": {"verdict": "FIXABLE", "reason": "missing DAT typing"},
    }
    text = assemble_post_mortem(record)
    assert "rounds: 2" in text
    assert "best round: 2 (2 errors)" in text
    assert "never cleared: e1" in text
    assert "e2" not in text.split("never cleared")[1].splitlines()[0]
    assert "FIXABLE -- missing DAT typing" in text
    assert "registry v7, prompt v2" in text
    assert assemble_post_mortem({"attempts": 1}) == ""


# ------------------------------------------------- targeted question, in-loop


def test_retry_opens_with_targeted_question_and_merges(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    _seed_red_state(
        repo, ["unit.c:4:10: error: use of undeclared identifier 'FOO'"]
    )
    llm = RecordingLLM(
        {"wasm_targeted_symbols": "```c\n#define FOO (*(int *)0x80001234)\n```"}
    )

    def build(workdir, exports, extra=None):
        header = (workdir / "gnt4_shim.h").read_text(encoding="utf-8")
        if "0x80001234" in header:
            (workdir / "unit.wasm").write_bytes(b"\x00asm")
            return True, ""
        return False, "unit.c:4:10: error: use of undeclared identifier 'FOO'"

    driver = _driver(repo, llm=llm, build_runner=build)
    driver.run()
    record = _state(repo)["units"]["unit-a"]
    assert record["status"] == "green"
    assert llm.calls[0]["phase"].startswith("wasm_targeted_symbols")
    assert "Declare exactly these 1 symbol" in llm.calls[0]["prompt"]
    assert "POST-MORTEM" in llm.calls[0]["prompt"]
    staged_header = (
        repo / "research/decomp/port-units-staging/unit-a/gnt4_shim.h"
    ).read_text(encoding="utf-8")
    assert "TARGETED (design 2.12a)" in staged_header
    assert any(
        event["kind"] == "targeted_symbol_question" and event["merged"]
        for event in _events(repo)
    )


def test_targeted_call_replaces_a_round_so_budget_does_not_grow(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)

    def run_case(seed_previous_rounds: bool, tmp_repo: Path) -> int:
        counter = {"n": 0}

        def build(workdir, exports, extra=None):
            counter["n"] += 1
            # a different error every round: never stuck, never linked
            return False, (
                f"unit.c:4:10: error: use of undeclared identifier 'FOO'\n"
                f"unit.c:{counter['n']}:1: error: filler variant {counter['n']}"
            )

        llm = RecordingLLM(
            {"wasm_targeted_symbols": "```c\n#define FOO 1\n```"},
            default="```c\n/* header attempt */\n```",
        )
        if seed_previous_rounds:
            _seed_red_state(
                tmp_repo,
                ["unit.c:4:10: error: use of undeclared identifier 'FOO'"],
            )
        driver = _driver(tmp_repo, llm=llm, build_runner=build)
        driver.run()
        # count only the repair-loop calls: the general-lane diagnosis that
        # correctly fires after a SECOND failure is section 2.12(b)'s own
        # (bounded, once-per-lifetime) budget, not the attempt's.
        return len(
            [
                call
                for call in llm.calls
                if call["phase"].startswith(("wasm_compile_fix", "wasm_targeted_symbols"))
            ]
        )

    fresh = run_case(False, _write_repo(tmp_path / "fresh"))
    retry = run_case(True, _write_repo(tmp_path / "retry"))
    # fresh attempt: MAX-1 compile-fix calls; retry: 1 targeted + (MAX-2)
    # compile-fix calls -- identical totals, the call count did not grow.
    assert fresh == MAX_COMPILE_ITERS - 1
    assert retry == fresh


# ----------------------------------------------------------- diagnosis (2.12b)


def test_second_failure_triggers_one_structural_diagnosis(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    # previous attempt's diagnostics carry no extractable symbol, so the
    # targeted question does not fire and the full loop runs again
    _seed_red_state(repo, ["unit.c:9:1: error: expected ';' after expression"])
    llm = RecordingLLM(
        {"wasm_diagnosis": "STRUCTURAL: the verbatim file is self-contradictory"}
    )
    counter = {"n": 0}

    def build(workdir, exports, extra=None):
        counter["n"] += 1
        return False, f"unit.c:9:1: error: expected ';' variant {counter['n']}"

    driver = _driver(repo, llm=llm, build_runner=build)
    driver.run()
    record = _state(repo)["units"]["unit-a"]
    assert record["status"] == "red_retryable"  # STRUCTURAL never settles
    assert record["attempts"] == 2
    assert record["diagnosis"]["verdict"] == "STRUCTURAL"
    assert record["f4_nominated"] is True
    diagnosis_calls = [
        call for call in llm.calls if call["phase"].startswith("wasm_diagnosis")
    ]
    assert len(diagnosis_calls) == 1
    assert "Why can no header fix this?" in diagnosis_calls[0]["prompt"]
    assert any(
        event["kind"] == "diagnosis_question" and event["verdict"] == "STRUCTURAL"
        for event in _events(repo)
    )
    # once per lifetime: another failing pass asks no second diagnosis
    llm2 = RecordingLLM({"wasm_diagnosis": "STRUCTURAL: again"})
    # strip the recorded world_version so the red stays schedulable
    state = _state(repo)
    state["units"]["unit-a"].pop("world_version", None)
    (repo / RUN_ROOT / "wasm-units-state.json").write_text(json.dumps(state))
    driver2 = _driver(repo, llm=llm2, build_runner=build)
    driver2.run()
    assert not [
        call for call in llm2.calls if call["phase"].startswith("wasm_diagnosis")
    ]


def test_structural_diagnosis_sinks_across_priority_bands(tmp_path):
    """T3 review F4: a STRUCTURAL-diagnosed red in the HIGHEST product
    priority band must still serve after every non-structural unit in
    lower bands -- structural is the leading sort component, not a cost."""
    repo = _write_repo(tmp_path, units=["unit-a", "unit-b"])
    (repo / "research/decomp/data").mkdir(parents=True, exist_ok=True)
    (repo / "research/decomp/data/unit-priority.json").write_text(
        json.dumps({"priorities": {"unit-a": 1000, "unit-b": 0}}),
        encoding="utf-8",
    )
    driver = _driver(repo)
    state = {
        "state_schema": 1,
        "units": {
            "unit-a": {
                "status": "red_retryable",
                "attempts": 0,
                "diagnosis": {"verdict": "STRUCTURAL", "reason": "r"},
            },
            "unit-b": {"status": "red_retryable", "attempts": 50},
        },
    }
    queue = driver._load_queue()
    chosen = driver._next_unit(queue, state, set())
    assert chosen["name"] == "unit-b"
    # ...but it still runs when it is the only work left
    chosen2 = driver._next_unit(queue, state, {"unit-b"})
    assert chosen2["name"] == "unit-a"


def test_malformed_diagnosis_is_metered_and_retired(tmp_path, monkeypatch):
    """T3 review F5: a malformed diagnosis reply is counted (model_requests)
    and after DIAGNOSIS_MALFORMED_LIMIT malformed replies the question is
    recorded terminally UNPARSEABLE and never re-asked."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    llm = RecordingLLM({"wasm_diagnosis": "I cannot decide, sorry."})
    driver = _driver(repo, llm=llm)
    queue_unit = driver._load_queue()[0]
    state = driver._load_state()
    record = state.setdefault("units", {}).setdefault(
        "unit-a", {"status": "red_retryable", "attempts": 2}
    )
    for expected_malformed in range(1, DIAGNOSIS_MALFORMED_LIMIT + 1):
        result = driver._diagnose_unit(queue_unit, record, state)
        assert record["diagnosis_malformed"] == expected_malformed
        assert record["model_requests"] == expected_malformed
    assert result["verdict"] == "UNPARSEABLE"
    assert record["diagnosis"]["verdict"] == "UNPARSEABLE"
    assert not record.get("f4_nominated")  # nothing was learned
    calls_so_far = len(llm.calls)
    # retired: never re-asked
    assert driver._diagnose_unit(queue_unit, record, state)["verdict"] == "UNPARSEABLE"
    assert len(llm.calls) == calls_so_far
    assert any(
        event["kind"] == "diagnosis_unparseable" for event in _events(repo)
    )


def test_terminal_waiting_page_carries_diagnoses(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    llm = RecordingLLM({"wasm_diagnosis": "FIXABLE: needs a DAT_ lvalue typing"})
    driver = _driver(repo, llm=llm)
    world = driver._world_version()
    state = {
        "state_schema": 1,
        "units": {
            "unit-a": {
                "status": "red_retryable",
                "attempts": 1,
                "error": "not linked: x",
                "last_stage": "wasm-link",
                "world_version": world,
                "symbol_set": [],
            }
        },
    }
    (repo / RUN_ROOT / "wasm-units-state.json").write_text(json.dumps(state))
    assert driver.run() == EXIT_NO_WORK
    waiting = [e for e in _events(repo) if e["kind"] == "waiting_world_change"]
    assert waiting, "terminal state must page"
    assert waiting[-1]["diagnoses"] == [
        {
            "unit": "unit-a",
            "verdict": "FIXABLE",
            "reason": "needs a DAT_ lvalue typing",
        }
    ]
    record = _state(repo)["units"]["unit-a"]
    assert record["diagnosis"]["verdict"] == "FIXABLE"
    run_state = json.loads((repo / RUN_ROOT / "run-state.json").read_text())
    assert run_state["run_state"] == "waiting_world_change"
