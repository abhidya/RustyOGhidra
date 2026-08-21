"""Offline tests for the wasm-unit driver mode (src/port_wasm_units.py)."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from src.port_driver import EXIT_NO_WORK, EXIT_PROGRESSED, EXIT_STOPPED
from src.port_wasm_units import (
    WasmUnitDriver,
    extract_verbatim,
    scan_disallowed_imports,
)


def _write_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "research/decomp/ghidra-export").mkdir(parents=True)
    (repo / "research/decomp/generated/finish-game-port").mkdir(parents=True)
    (repo / "research/decomp/poc").mkdir(parents=True)
    chunk = repo / "research/decomp/ghidra-export/chunk_9999.c"
    chunk.write_text(
        "// line1\nint zz_test_(int a)\n{\n  return a + 1;\n}\n// tail\n",
        encoding="utf-8",
    )
    header = repo / "research/decomp/poc/seed.h"
    header.write_text("/* seed header */\n", encoding="utf-8")
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
                "oracle": {
                    "command": ["node", "fake.mjs"],
                    "cwd": "research/decomp/poc",
                    "env": {"POC_WASM": "{wasm}"},
                    "success_patterns": ["PASS"],
                },
            }
        ],
    }
    (repo / "research/decomp/generated/finish-game-port/wasm-units.json").write_text(
        json.dumps(queue), encoding="utf-8"
    )
    return repo


def _completed(rc: int = 0, stdout: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["git"], returncode=rc, stdout=stdout, stderr="")


def test_extract_verbatim_is_byte_faithful(tmp_path):
    repo = _write_repo(tmp_path)
    text, records = extract_verbatim(
        repo, [{"file": "research/decomp/ghidra-export/chunk_9999.c", "start": 2, "end": 5}]
    )
    raw = "int zz_test_(int a)\n{\n  return a + 1;\n}\n"
    assert raw in text
    assert records[0]["sha256"] == hashlib.sha256(raw.encode()).hexdigest()


def test_extract_verbatim_rejects_bad_range(tmp_path):
    repo = _write_repo(tmp_path)
    with pytest.raises(ValueError):
        extract_verbatim(
            repo,
            [{"file": "research/decomp/ghidra-export/chunk_9999.c", "start": 2, "end": 99}],
        )


def test_scan_disallowed_imports_flags_non_sdk(tmp_path):
    wasm = tmp_path / "unit.wasm"
    wasm.write_bytes(
        b"\x00asm....env.gnt4_PSVECSubtract_bl\x00...env.CONCAT44\x00...env.memory\x00"
    )
    assert scan_disallowed_imports(wasm) == ["CONCAT44"]


def _driver(repo: Path, **kwargs) -> WasmUnitDriver:
    defaults = dict(
        repo_root=repo,
        build_runner=lambda workdir, exports, extra=None: (True, ""),
        oracle_runner=lambda unit, wasm: (True, "1/1", "PASS log"),
        git_runner=lambda *args: _completed(0, "abc123\n"),
    )
    defaults.update(kwargs)
    return WasmUnitDriver(**defaults)


def test_control_stop_exits_before_any_unit(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    control = repo / "research/decomp/generated/finish-game-port/control.json"
    control.write_text(json.dumps({"command": "stop_after_stage"}), encoding="utf-8")
    processed = []
    driver = _driver(repo, build_runner=lambda *a: processed.append(a) or (True, ""))
    assert driver.run() == EXIT_STOPPED
    assert processed == []


def test_green_unit_commits_artifacts_and_completes(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    git_calls = []

    def fake_git(*args):
        git_calls.append(args)
        if args[0] == "rev-parse":
            return _completed(0, "deadbeef\n")
        return _completed(0)

    def fake_build(workdir, exports, extra=None):
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    driver = _driver(repo, git_runner=fake_git, build_runner=fake_build)
    assert driver.run() == EXIT_NO_WORK

    state = json.loads(
        (repo / "research/decomp/generated/finish-game-port/wasm-units-state.json").read_text()
    )
    record = state["units"]["unit-a"]
    assert record["status"] == "green"
    assert record["commit"] == "deadbeef"
    artifact_dir = repo / "research/decomp/port-units/unit-a"
    for name in ("unit.c", "gnt4_shim.h", "unit.wasm", "oracle.log", "provenance.json"):
        assert (artifact_dir / name).is_file(), name
    provenance = json.loads((artifact_dir / "provenance.json").read_text())
    assert provenance["extractions"][0]["sha256"]
    commit_message = next(args for args in git_calls if args[0] == "commit")[2]
    assert commit_message.startswith("port: unit-a wasm unit green")
    assert "Co-Authored-By" not in commit_message
    assert "Claude" not in commit_message
    assert "anthropic" not in commit_message.lower()
    # unit.c embeds the verbatim body untouched
    unit_c = (artifact_dir / "unit.c").read_text()
    assert "return a + 1;" in unit_c
    run_state = json.loads(
        (repo / "research/decomp/generated/finish-game-port/run-state.json").read_text()
    )
    assert run_state["run_mode"] == "driver"
    assert run_state["status"] == "completed"


def test_red_unit_stays_retryable_and_reports_progress(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)

    class NoBlockLLM:
        default_model = "fake"

        def generate(self, **_kwargs):
            return "no code block here"

    driver = _driver(
        repo,
        build_runner=lambda workdir, exports, extra=None: (False, "error: bad"),
        llm=NoBlockLLM(),
    )
    assert driver.run() == EXIT_PROGRESSED
    state = json.loads(
        (repo / "research/decomp/generated/finish-game-port/wasm-units-state.json").read_text()
    )
    record = state["units"]["unit-a"]
    assert record["status"] == "red_retryable"
    assert record["attempts"] == 1
    assert "no code block" in record["error"]
    # no artifacts, no commit for a red unit
    assert not (repo / "research/decomp/port-units/unit-a").exists()


def test_oracle_red_blocks_commit(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    git_calls = []

    def fake_build(workdir, exports, extra=None):
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    driver = _driver(
        repo,
        build_runner=fake_build,
        oracle_runner=lambda unit, wasm: (False, "3/9", "FAIL log"),
        git_runner=lambda *args: git_calls.append(args) or _completed(0),
    )
    assert driver.run() == EXIT_PROGRESSED
    assert git_calls == []
    state = json.loads(
        (repo / "research/decomp/generated/finish-game-port/wasm-units-state.json").read_text()
    )
    assert state["units"]["unit-a"]["status"] == "red_retryable"


def test_compile_fix_header_only_loop(tmp_path, monkeypatch):
    """The LLM's header lands in the workdir; the verbatim C is never rewritten."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    builds = []

    def flaky_build(workdir, exports, extra=None):
        builds.append((workdir / "gnt4_shim.h").read_text())
        if len(builds) == 1:
            return False, "error: use of undeclared identifier 'bool'"
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    class FixLLM:
        default_model = "fake-27b"

        def generate(self, **_kwargs):
            return "```c\n#include <stdbool.h>\n/* fixed */\n```"

    driver = _driver(repo, build_runner=flaky_build, llm=FixLLM())
    assert driver.run() == EXIT_NO_WORK
    assert builds[0] == "/* seed header */\n"
    assert "stdbool" in builds[1]
    state = json.loads(
        (repo / "research/decomp/generated/finish-game-port/wasm-units-state.json").read_text()
    )
    record = state["units"]["unit-a"]
    assert record["status"] == "green"
    assert record["model_requests"] == 1
    provenance = json.loads(
        (repo / "research/decomp/port-units/unit-a/provenance.json").read_text()
    )
    assert provenance["model"] == "fake-27b"
    assert provenance["compile_iterations"] == 2


def test_compile_fix_call_streams_with_phase_and_capped_tokens(tmp_path, monkeypatch):
    """The compile-fix LLM call must stream and cap its output budget.

    Non-streamed, llm-liveness.json freezes at request start for the whole
    generation (~23 min at 2.3 tok/s) -- indistinguishable from a hang, and
    the rig monitor's 20-minute staleness rule false-fires on every long
    call. Streaming (even with a no-op callback) makes the client's metrics
    wrapper advance liveness per chunk and turns the read timeout into
    time-between-stream-bytes. The 4096 cap halves the ~59-minute worst case
    the client-wide 8192 default permits; real replies are ~1.6-2k tokens and
    the loop already iterates on truncation.
    """
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    llm_calls = []

    def flaky_build(workdir, exports, extra=None):
        if not llm_calls:
            return False, "error: use of undeclared identifier 'bool'"
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    class RecordingLLM:
        default_model = "fake-27b"

        def generate(self, **kwargs):
            llm_calls.append(kwargs)
            return "```c\n#include <stdbool.h>\n/* fixed */\n```"

    driver = _driver(repo, build_runner=flaky_build, llm=RecordingLLM())
    assert driver.run() == EXIT_NO_WORK
    assert len(llm_calls) == 1
    kwargs = llm_calls[0]
    # phase follows the chunk-workflow naming convention: <kind>:<identifier>
    assert kwargs["phase"] == "wasm_compile_fix:unit-a"
    # a real (callable, no-op) stream_callback: passing it is what flips the
    # client onto the streaming path where liveness updates mid-request
    assert callable(kwargs["stream_callback"])
    assert kwargs["stream_callback"]("assistant_delta", {"text": "x"}) is None
    assert kwargs["max_tokens"] == 4096


def test_compile_only_unit_commits_to_staging_unverified(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    queue_path = repo / "research/decomp/generated/finish-game-port/wasm-units.json"
    queue = json.loads(queue_path.read_text())
    queue["units"][0]["oracle"] = {"type": "compile_only"}
    queue["units"][0]["allowed_extra_imports"] = ["FUN_80001234"]
    queue_path.write_text(json.dumps(queue), encoding="utf-8")
    git_calls = []

    def fake_git(*args):
        git_calls.append(args)
        if args[0] == "rev-parse":
            return _completed(0, "cafe1234\n")
        return _completed(0)

    def fake_build(workdir, exports, extra=None):
        assert extra == ["FUN_80001234"]
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    oracle_calls = []
    driver = _driver(
        repo,
        git_runner=fake_git,
        build_runner=fake_build,
        oracle_runner=lambda unit, wasm: oracle_calls.append(unit) or (True, "x", "y"),
    )
    assert driver.run() == EXIT_NO_WORK
    assert oracle_calls == []  # compile_only never runs a behavioral oracle
    staged = repo / "research/decomp/port-units-staging/unit-a/provenance.json"
    prov = json.loads(staged.read_text())
    assert prov["verified"] is False and prov["tier"] == "compile_only"
    add_call = next(c for c in git_calls if c[0] == "add")
    assert any("port-units-staging" in str(arg) for arg in add_call)
    commit_call = next(c for c in git_calls if c[0] == "commit")
    assert "port-staging:" in commit_call[2] and "unoracled" in commit_call[2]


def test_void_result_contradiction_is_detected():
    """A .c that declares a function void AND assigns its result is unfixable.

    Verbatim decompiler output cannot be edited, and the void declaration lives
    in the same translation unit, so no header can reconcile it. auto-c0000-013
    burned all 8 compile-fix iterations (~3.6h) alternating between the two dead
    ends before failing.
    """
    from src.port_wasm_units import void_result_contradictions

    source = """
void zz_0008f18_(undefined8 param_1, double param_2);
void zz_0008f18_(undefined8 param_1, double param_2) { return; }
void caller(void) {
    undefined8 uVar6;
    uVar6 = zz_0008f18_(uVar6, 1.0);
}
"""
    assert void_result_contradictions(source) == ["zz_0008f18_"]


def test_void_function_merely_called_is_not_a_contradiction():
    """Settling is permanent, so a bare call must never be flagged."""
    from src.port_wasm_units import void_result_contradictions

    source = """
void zz_cleanup_(int a);
void caller(void) {
    zz_cleanup_(1);
    if (zz_cleanup_ != 0) { return; }
}
"""
    assert void_result_contradictions(source) == []


def test_non_void_function_with_assignment_is_not_a_contradiction():
    from src.port_wasm_units import void_result_contradictions

    source = """
undefined8 zz_value_(int a);
void caller(void) {
    undefined8 v;
    v = zz_value_(1);
}
"""
    assert void_result_contradictions(source) == []


def test_unclosed_fence_is_recovered():
    """A ```c with no terminator still carries a usable header.

    auto-c0001-001 emitted 7,466 chars of correct header behind an unclosed
    fence and the whole round was discarded over the missing terminator.
    """
    from src.port_wasm_units import CODE_BLOCK, OPEN_FENCE

    reply = "```c\ntypedef unsigned long long undefined8;\nextern void zz_1_(short s);"
    assert CODE_BLOCK.findall(reply) == []          # the old path finds nothing
    opened = OPEN_FENCE.search(reply)
    assert opened is not None and reply.count("```") == 1
    body = reply[opened.end():].strip()
    assert body.startswith("typedef unsigned long long undefined8;")


def test_closed_fence_still_uses_the_normal_path():
    from src.port_wasm_units import CODE_BLOCK

    reply = "here you go\n```c\nint a;\n```\n"
    assert CODE_BLOCK.findall(reply) == ["int a;\n"]


def test_multi_block_reply_is_not_treated_as_unclosed():
    """The guard is `exactly one fence`, so well-formed replies never hit it."""
    from src.port_wasm_units import CODE_BLOCK

    reply = "```c\nint a;\n```\nand\n```c\nint b;\n```\n"
    assert reply.count("```") == 4
    assert len(CODE_BLOCK.findall(reply)) == 2


# ---------------------------------------------------------------- T1: depth cap


def test_depth_cap_default_is_four(monkeypatch):
    """Design 2.1: cap 4 in T1 (n=7 repair-greens, 1 needed 5 iterations)."""
    from src.port_wasm_units import MAX_COMPILE_ITERS

    assert MAX_COMPILE_ITERS == 4


# ------------------------------------------------- T1: stage-aware stuck-abort


def test_stage_transition_never_aborts():
    """Design 2.2: crossing a stage boundary is progress by definition, even
    when the diagnostic content fingerprints identically (a #define'd symbol
    legitimately converts link-gate lines into compile diagnostics)."""
    from src.port_wasm_units import is_stuck

    fp = "f" * 64
    assert not is_stuck("link-gate", fp, "compile", fp, True)
    assert not is_stuck("import-gate", fp, "link-gate", fp, True)


def test_identical_fingerprint_same_stage_after_applied_header_aborts():
    from src.port_wasm_units import is_stuck

    fp = "f" * 64
    assert is_stuck("compile", fp, "compile", fp, True)
    # ...but not when no new header was applied (the 2.5 exemption)
    assert not is_stuck("compile", fp, "compile", fp, False)
    # ...and never on the very first build (nothing to compare against)
    assert not is_stuck(None, None, "compile", fp, False)


def test_classify_build_stage():
    from src.port_wasm_units import classify_build_stage

    assert classify_build_stage(
        "link gate: these symbols are UNDEFINED and became wasm imports, but "
        "they are not gnt4_* SDK functions, so they must be DEFINED in "
        "gnt4_shim.h with correct PowerPC semantics: CONCAT44"
    ) == "import-gate"
    assert classify_build_stage(
        "wasm-ld: error: unit.o: undefined symbol: DoFoo"
    ) == "link-gate"
    assert classify_build_stage(
        "unit.c:5:1: error: call to undeclared function 'DoFoo'"
    ) == "compile"


def test_header_line_number_churn_fingerprints_equal():
    """The model rewrites the whole header each round, so gnt4_shim.h line
    numbers churn; a fingerprint that keeps them would mask true oscillation."""
    from src.port_wasm_units import diagnostic_fingerprint

    a = (
        "./gnt4_shim.h:12:9: error: unknown type name 'undefined8'\n"
        "unit.c:40:5: error: invalid operands to binary expression\n"
    )
    b = (
        "./gnt4_shim.h:57:1: error: unknown type name 'undefined8'\n"
        "unit.c:40:5: error: invalid operands to binary expression\n"
    )
    assert diagnostic_fingerprint(a) == diagnostic_fingerprint(b)


def test_unit_c_line_change_fingerprints_differ():
    """unit.c is verbatim and immovable, so a moved diagnostic is real change."""
    from src.port_wasm_units import diagnostic_fingerprint

    a = "unit.c:40:5: error: invalid operands to binary expression"
    b = "unit.c:41:5: error: invalid operands to binary expression"
    assert diagnostic_fingerprint(a) != diagnostic_fingerprint(b)


def test_stuck_abort_after_applied_header_with_same_diagnostics(tmp_path, monkeypatch):
    """Same stage + identical fingerprint right after an applied header: the
    attempt aborts retryable instead of burning the remaining iterations."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    builds = []

    def same_error_build(workdir, exports, extra=None):
        builds.append(1)
        return False, "unit.c:9:3: error: use of undeclared identifier 'x'"

    class FixLLM:
        default_model = "fake"

        def generate(self, **_kwargs):
            return "```c\n/* a new header that changes nothing */\n```"

    driver = _driver(repo, build_runner=same_error_build, llm=FixLLM())
    assert driver.run() == EXIT_PROGRESSED
    state = json.loads(
        (repo / "research/decomp/generated/finish-game-port/wasm-units-state.json").read_text()
    )
    record = state["units"]["unit-a"]
    assert record["status"] == "red_retryable"
    assert record["last_stage"] == "compile-fix"
    assert "stuck: identical diagnostics after applied fix" in record["error"]
    assert len(builds) == 2  # aborted right after the first post-fix rebuild


def test_link_gate_to_compile_transition_does_not_abort(tmp_path, monkeypatch):
    """Two consecutive failing rounds in DIFFERENT stages must keep iterating."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    responses = [
        (False, "wasm-ld: error: unit.o: undefined symbol: DoFoo"),
        (False, "unit.c:5:1: error: call to undeclared function 'DoFoo'"),
    ]

    def staged_build(workdir, exports, extra=None):
        if responses:
            return responses.pop(0)
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    class FixLLM:
        default_model = "fake"

        def generate(self, **_kwargs):
            return "```c\n/* another try */\n```"

    driver = _driver(repo, build_runner=staged_build, llm=FixLLM())
    assert driver.run() == EXIT_NO_WORK
    state = json.loads(
        (repo / "research/decomp/generated/finish-game-port/wasm-units-state.json").read_text()
    )
    assert state["units"]["unit-a"]["status"] == "green"


# ------------------------------------------- T1: malformed replies, re-ask, 2.5


def test_reask_recovers_a_malformed_reply(tmp_path, monkeypatch):
    """One fence-less reply triggers a single format-reminder re-ask, and a
    usable re-ask reply keeps the attempt alive."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    prompts = []
    replies = ["no fence here, sorry", "```c\n/* fixed */\n```"]

    def fake_build(workdir, exports, extra=None):
        if not (workdir / "unit.wasm").exists() and replies:
            return False, "error: bad"
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    class OnceLLM:
        default_model = "fake"

        def generate(self, prompt="", **_kwargs):
            prompts.append(prompt)
            return replies.pop(0)

    driver = _driver(repo, build_runner=fake_build, llm=OnceLLM())
    assert driver.run() == EXIT_NO_WORK
    state = json.loads(
        (repo / "research/decomp/generated/finish-game-port/wasm-units-state.json").read_text()
    )
    record = state["units"]["unit-a"]
    assert record["status"] == "green"
    assert record["model_requests"] == 2  # first ask + one re-ask
    assert "no usable" not in prompts[0]
    assert "Your previous reply contained no usable" in prompts[1]


def test_two_consecutive_no_header_rounds_end_the_attempt(tmp_path, monkeypatch):
    """Design 2.5 [V4-9]: after the format-reminder re-ask has also failed, a
    THIRD identical ask would be the same-input retry section 0.1 forbids. A
    second consecutive no_new_header round ends the attempt (red, retryable)
    with the reply shapes in the reason -- and never rebuilds the unchanged
    header."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    builds, prompts = [], []

    def counting_build(workdir, exports, extra=None):
        builds.append(1)
        return False, "error: bad"

    class ProseLLM:
        default_model = "fake"

        def generate(self, prompt="", **_kwargs):
            prompts.append(prompt)
            return "I cannot help with that."

    driver = _driver(repo, build_runner=counting_build, llm=ProseLLM())
    assert driver.run() == EXIT_PROGRESSED
    # the seed header was built exactly once; no_new_header rounds reused it
    assert len(builds) == 1
    # round 1: ask + re-ask; round 2: ask + re-ask; then the attempt ENDS --
    # the old behaviour spent a third round (6 prompts) on identical inputs
    assert len(prompts) == 4
    assert "Your previous reply contained no usable" in prompts[1]
    state = json.loads(
        (repo / "research/decomp/generated/finish-game-port/wasm-units-state.json").read_text()
    )
    record = state["units"]["unit-a"]
    assert record["status"] == "red_retryable"
    assert record["last_stage"] == "compile-fix"
    assert "two consecutive" in record["error"]
    assert "no code block" in record["error"]
    # the reason carries the recorded reply shapes as evidence
    assert "len=" in record["error"]


def test_single_no_header_round_recovers_when_next_round_extracts(
    tmp_path, monkeypatch
):
    """One no_new_header round stays ROUND-level: a usable header on the next
    round resets the consecutive count and the attempt proceeds to green."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    replies = ["prose only", "still prose", "```c\n/* fixed */\n```"]

    def fake_build(workdir, exports, extra=None):
        if replies:  # until the fix lands, keep failing
            return False, "error: bad"
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    class RecoveringLLM:
        default_model = "fake"

        def generate(self, **_kwargs):
            return replies.pop(0)

    driver = _driver(repo, build_runner=fake_build, llm=RecoveringLLM())
    assert driver.run() == EXIT_NO_WORK
    state = json.loads(
        (repo / "research/decomp/generated/finish-game-port/wasm-units-state.json").read_text()
    )
    record = state["units"]["unit-a"]
    assert record["status"] == "green"
    assert record["model_requests"] == 3  # ask + re-ask (missed) + recovered ask


# --------------------------------------------------- T1: feedback construction


def test_summarise_build_error_deduplicates_and_respects_budget():
    from src.port_wasm_units import summarise_build_error

    first = "unit.c:1:1: error: something went wrong"
    second = "unit.c:2:2: error: a different diagnosis"
    text = "\n".join([first] * 300 + [second])
    out = summarise_build_error(text, budget=2000)
    assert len(out) <= 2000
    assert out.count(first) == 1  # exact duplicates dropped
    assert second in out
    assert out.index(first) < out.index(second)  # first-occurrence order kept


def test_summarise_build_error_truncated_output_still_dedupes():
    from src.port_wasm_units import summarise_build_error

    lines = [f"unit.c:{n}:1: error: diag {n}" for n in range(200)]
    text = "\n".join(lines + lines)  # every line duplicated
    out = summarise_build_error(text, budget=2000)
    assert len(out) <= 2000
    for line in out.splitlines():
        assert out.count(line) == 1


# --------------------------------------------------------------- T1: D14 seed


def test_header_seed_read_error_is_retryable_not_structural(tmp_path, monkeypatch):
    """Design 2.10 / D14: OSError on the seed is transient I/O. Structural
    settling is permanent, so it must be reserved for provable dead queue
    entries (extraction-spec errors keep that verdict)."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    (repo / "research/decomp/poc/seed.h").unlink()
    driver = _driver(repo)
    assert driver.run() == EXIT_PROGRESSED  # unit is still workable next pass
    state = json.loads(
        (repo / "research/decomp/generated/finish-game-port/wasm-units-state.json").read_text()
    )
    record = state["units"]["unit-a"]
    assert record["status"] == "red_retryable"
    assert record["status"] != "structural_ineligible"
    assert "header seed" in record["error"]


# ------------------------------------------- T2a: post-mortem data capture, 2.3


def _state(repo: Path) -> dict:
    return json.loads(
        (repo / "research/decomp/generated/finish-game-port/wasm-units-state.json").read_text()
    )


def _state_path(repo: Path) -> Path:
    return repo / "research/decomp/generated/finish-game-port/wasm-units-state.json"


WORLD_KEYS = {
    "config_hash", "toolchain_hash", "driver_rev", "prompt_version", "registry_version",
}


def test_fail_records_rounds_with_diagnostics_fingerprint_and_world_version(
    tmp_path, monkeypatch
):
    """Design 2.3 [V4-4]: rounds[] gains the normalized diagnostic set and its
    fingerprint per round ("never cleared" becomes a set intersection), and
    every verdict records the world-version it was reached under (2.8)."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)

    def same_error_build(workdir, exports, extra=None):
        return False, "unit.c:9:3: error: use of undeclared identifier 'x'"

    class FixLLM:
        default_model = "fake"

        def generate(self, **_kwargs):
            return "```c\n/* a new header that changes nothing */\n```"

    driver = _driver(repo, build_runner=same_error_build, llm=FixLLM())
    assert driver.run() == EXIT_PROGRESSED
    record = _state(repo)["units"]["unit-a"]
    assert record["status"] == "red_retryable"
    rounds = record["rounds"]
    assert len(rounds) == 2  # first build + the post-fix rebuild that aborted
    for entry in rounds:
        assert entry["diagnostics"] == [
            "unit.c:9:3: error: use of undeclared identifier 'x'"
        ]
        assert len(entry["fingerprint"]) == 64
    assert rounds[0]["fingerprint"] == rounds[1]["fingerprint"]
    assert set(record["world_version"]) == WORLD_KEYS


def test_header_snapshots_are_attempt_scoped_and_never_overwritten(
    tmp_path, monkeypatch
):
    """Design 2.3 [V4-4]: per-attempt best-header snapshots live under
    header-attempt{A}-iter{I}.h; a later attempt must never destroy the
    artifact the post-mortem carry decision needs."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    counter = {"build": 0, "reply": 0}

    def changing_error_build(workdir, exports, extra=None):
        counter["build"] += 1
        return False, f"unit.c:{counter['build']}:1: error: diag {counter['build']}"

    class CountingLLM:
        default_model = "fake"

        def generate(self, **_kwargs):
            counter["reply"] += 1
            return f"```c\n/* header from call {counter['reply']} */\n```"

    driver = _driver(repo, build_runner=changing_error_build, llm=CountingLLM())
    assert driver.run() == EXIT_PROGRESSED  # depth cap, red_retryable
    workdir = repo / "research/decomp/generated/finish-game-port/wasm-units/unit-a"
    first = workdir / "header-attempt1-iter1.h"
    assert first.is_file()
    first_content = first.read_text()

    # Attempt 2 is only schedulable when the world changed (2.8): simulate a
    # prompt-rule change by rewriting the recorded component.
    state_path = _state_path(repo)
    state = json.loads(state_path.read_text())
    state["units"]["unit-a"]["world_version"]["prompt_version"] = "0"
    state_path.write_text(json.dumps(state), encoding="utf-8")

    driver2 = _driver(repo, build_runner=changing_error_build, llm=CountingLLM())
    assert driver2.run() == EXIT_PROGRESSED
    assert (workdir / "header-attempt2-iter1.h").is_file()
    # the earlier attempt's snapshot survives byte-identical
    assert first.read_text() == first_content
    record = _state(repo)["units"]["unit-a"]
    assert record["attempts"] == 2
    # rounds reference the attempt-scoped snapshot paths
    assert any("header-attempt2-iter" in r["header"] for r in record["rounds"])


# ------------------------------------------------ T2a: world-hash gating, 2.8


def test_zero_delta_red_is_skipped_and_run_state_says_waiting_world_change(
    tmp_path, monkeypatch
):
    """Design 2.8 [V4-3]: a red whose recorded world-version equals the current
    one in every component is not schedulable; a pass finding only such reds
    (and no pendings) writes run_state="waiting_world_change" and journals the
    event -- no new exit code."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)

    class ProseLLM:
        default_model = "fake"

        def generate(self, **_kwargs):
            return "no fence"

    red_driver = _driver(
        repo,
        build_runner=lambda workdir, exports, extra=None: (False, "error: bad"),
        llm=ProseLLM(),
    )
    assert red_driver.run() == EXIT_PROGRESSED
    assert _state(repo)["units"]["unit-a"]["status"] == "red_retryable"

    # Same world, fresh pass: the red is zero-delta, nothing is schedulable.
    calls = []
    second = _driver(
        repo,
        build_runner=lambda workdir, exports, extra=None: calls.append(1) or (True, ""),
    )
    assert second.run() == EXIT_NO_WORK
    assert calls == []  # the unit was never attempted
    run_state = json.loads(
        (repo / "research/decomp/generated/finish-game-port/run-state.json").read_text()
    )
    assert run_state["run_state"] == "waiting_world_change"
    assert run_state["status"] == "waiting_world_change"
    events = [
        json.loads(line)
        for line in (
            repo / "research/decomp/generated/finish-game-port/events.jsonl"
        ).read_text().splitlines()
        if line.strip()
    ]
    waiting = [e for e in events if e.get("kind") == "waiting_world_change"]
    assert waiting and waiting[-1]["reds"] == 1


def test_world_delta_in_any_component_makes_a_red_schedulable(tmp_path, monkeypatch):
    """A change in ANY world-version component re-opens the red."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)

    class ProseLLM:
        default_model = "fake"

        def generate(self, **_kwargs):
            return "no fence"

    red_driver = _driver(
        repo,
        build_runner=lambda workdir, exports, extra=None: (False, "error: bad"),
        llm=ProseLLM(),
    )
    assert red_driver.run() == EXIT_PROGRESSED

    state_path = _state_path(repo)
    state = json.loads(state_path.read_text())
    state["units"]["unit-a"]["world_version"]["driver_rev"] = "an-older-rev"
    state_path.write_text(json.dumps(state), encoding="utf-8")

    second = _driver(
        repo,
        build_runner=lambda workdir, exports, extra=None: (False, "error: bad"),
        llm=ProseLLM(),
    )
    assert second.run() == EXIT_PROGRESSED  # the unit was attempted again
    assert _state(repo)["units"]["unit-a"]["attempts"] == 2


def test_red_without_recorded_world_version_stays_schedulable(tmp_path, monkeypatch):
    """Reds verdicted before the gate landed carry no world-version; their
    world is unknown, so a delta cannot be excluded and they stay in the pool."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    driver = _driver(repo)
    state = {"units": {"unit-a": {"status": "red_retryable", "attempts": 3}}}
    queue = [{"name": "unit-a"}]
    assert driver._next_unit(queue, state, set()) is not None


def test_context_budget_red_verdicted_at_32768_is_schedulable_at_262144(
    tmp_path, monkeypatch
):
    """Design 2.8 [V4-3] regression fixture -- the live counterexample: the two
    context-budget reds (auto-c0000-017 required 34,008 tokens) were verdicted
    when the serving maximum was 32,768. Serving is now 262,144: no code fix
    was declared and no registry entry touches them, yet the serving-config
    component changed, so they MUST be schedulable."""
    from src.port_wasm_units import serving_config_hash

    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    driver = _driver(repo)
    base = {
        "toolchain_hash": "t" * 64,
        "driver_rev": "r" * 40,
        "prompt_version": "1",
        "registry_version": "0",
    }
    recorded = dict(base, config_hash=serving_config_hash("qwen-27b", 32768, 1200))
    current = dict(base, config_hash=serving_config_hash("qwen-27b", 262144, 1200))
    driver._world_version_cache = current
    state = {
        "units": {
            "auto-c0000-017": {
                "status": "red_retryable",
                "attempts": 1,
                "required_tokens": 34008,
                "world_version": recorded,
            }
        }
    }
    queue = [{"name": "auto-c0000-017"}]
    picked = driver._next_unit(queue, state, set())
    assert picked is not None and picked["name"] == "auto-c0000-017"
    # control: an identical serving config really is zero-delta
    state["units"]["auto-c0000-017"]["world_version"] = dict(current)
    assert driver._next_unit(queue, state, set()) is None


def test_pending_work_always_precedes_waiting_world_change(tmp_path, monkeypatch):
    """Section 4 starvation invariant: waiting_world_change while pending
    (never-attempted) units exist would be a selector bug -- a zero-delta red
    next to a pending unit must yield the pending unit."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    driver = _driver(repo)
    current = driver._world_version()
    state = {
        "units": {
            "unit-red": {
                "status": "red_retryable",
                "attempts": 2,
                "world_version": dict(current),
            },
            "unit-new": {"status": "pending", "attempts": 0},
        }
    }
    queue = [{"name": "unit-red"}, {"name": "unit-new"}]
    picked = driver._next_unit(queue, state, set())
    assert picked is not None and picked["name"] == "unit-new"
    assert driver._only_zero_delta_reds(state) is False


# --------------------------------------------- T2a: settle-through-journal, 2.9


class FakeJournal:
    def __init__(self):
        self.checkpoints = []

    def checkpoint(self, **kwargs):
        self.checkpoints.append(kwargs)

    def push_is_pending(self):
        return False

    def flush_pending_push(self):
        pass


def test_settle_unit_backs_up_edits_and_emits_journal_events(tmp_path, monkeypatch):
    """Design 2.9 [V4-9]: every settle goes through a code path that emits the
    journal event. settle-unit backs up the state file, edits the record,
    checkpoints the progress journal, journals events.jsonl, and saves."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    state_path = _state_path(repo)
    state_path.write_text(
        json.dumps(
            {
                "state_schema": 1,
                "created_at": "2026-08-20T00:00:00Z",
                "units": {"unit-a": {"status": "red_retryable", "attempts": 4}},
            }
        ),
        encoding="utf-8",
    )
    journal = FakeJournal()
    driver = _driver(repo, journal=journal)
    result = driver.settle_unit(
        "unit-a", "structural_ineligible", "hand-verified: no extractable code"
    )
    assert result["previous_status"] == "red_retryable"
    assert result["backup"] and result["backup"].startswith(
        "wasm-units-state.json.settle-backup-"
    )
    backup_path = state_path.parent / result["backup"]
    assert backup_path.is_file()
    # the backup preserves the PRE-settle record
    assert json.loads(backup_path.read_text())["units"]["unit-a"]["status"] == "red_retryable"
    record = _state(repo)["units"]["unit-a"]
    assert record["status"] == "structural_ineligible"
    assert record["settled_via"] == "settle-unit"
    assert record["settle_reason"] == "hand-verified: no extractable code"
    assert set(record["world_version"]) == WORLD_KEYS
    # the progress journal saw the transition
    assert len(journal.checkpoints) == 1
    transition = journal.checkpoints[0]["transition"]
    assert transition.unit == "unit-a"
    assert transition.result == "structural_ineligible"
    assert transition.stage == "manual-settle"
    assert transition.extra["settled_via"] == "settle-unit"
    # events.jsonl carries the settle event
    events = [
        json.loads(line)
        for line in (
            repo / "research/decomp/generated/finish-game-port/events.jsonl"
        ).read_text().splitlines()
        if line.strip()
    ]
    settled = [e for e in events if e.get("kind") == "verdict_settled"]
    assert settled and settled[-1]["unit"] == "unit-a"
    assert settled[-1]["via"] == "settle-unit"


def test_settle_unit_rejects_bad_status_unknown_unit_and_empty_reason(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    driver = _driver(repo, journal=FakeJournal())
    with pytest.raises(ValueError):
        driver.settle_unit("unit-a", "red_retryable", "not a settle status")
    with pytest.raises(ValueError):
        driver.settle_unit("no-such-unit", "structural_ineligible", "reason")
    with pytest.raises(ValueError):
        driver.settle_unit("unit-a", "structural_ineligible", "   ")


def test_settle_unit_cli_subcommand(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    from src.port_wasm_units import main

    repo = _write_repo(tmp_path)
    rc = main(
        [
            "settle-unit",
            "--unit", "unit-a",
            "--status", "structural_ineligible",
            "--reason", "cli settle test",
            "--repo-root", str(repo),
        ]
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["unit"] == "unit-a"
    assert _state(repo)["units"]["unit-a"]["status"] == "structural_ineligible"


# ------------------------------------------ T2a: product_priority ordering, 2.14


def test_priority_sidecar_leads_the_selection_order(tmp_path, monkeypatch):
    """Design 2.14 [V4-2]: product_priority (higher first) leads the sort key;
    queue order stays the tie-break; an absent sidecar preserves the previous
    ordering exactly."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    driver = _driver(repo)
    queue = [{"name": "unit-a"}, {"name": "unit-b"}]
    state = {
        "units": {
            "unit-a": {"status": "pending", "attempts": 0},
            "unit-b": {"status": "pending", "attempts": 0},
        }
    }
    # absent sidecar: queue order wins
    assert driver._next_unit(queue, state, set())["name"] == "unit-a"

    data_dir = repo / "research/decomp/data"
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "unit-priority.json").write_text(
        json.dumps({"priorities": {"unit-b": 305, "unit-a": 12}}), encoding="utf-8"
    )
    fresh = _driver(repo)
    assert fresh._next_unit(queue, state, set())["name"] == "unit-b"
    # priority never resurrects a zero-delta red or a settled unit
    state["units"]["unit-b"]["status"] = "green"
    assert fresh._next_unit(queue, state, set())["name"] == "unit-a"


def test_priority_ties_fall_back_to_attempts_then_queue_order(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    data_dir = repo / "research/decomp/data"
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "unit-priority.json").write_text(
        json.dumps({"priorities": {"unit-a": 100, "unit-b": 100}}), encoding="utf-8"
    )
    driver = _driver(repo)
    queue = [{"name": "unit-a"}, {"name": "unit-b"}]
    state = {
        "units": {
            "unit-a": {"status": "red_retryable", "attempts": 2},
            "unit-b": {"status": "pending", "attempts": 0},
        }
    }
    # equal priority: the less-attempted unit still wins
    assert driver._next_unit(queue, state, set())["name"] == "unit-b"


# ---------------------------------------------------------------------------
# Continuous assembly gate integration (design section 2.13 [V4-11], T2b)


def _seed_green_artifact(repo: Path, name: str, generated_at: str) -> None:
    """A pre-existing green artifact so the post-green gate has >= 2 units."""
    directory = repo / "research/decomp/port-units" / name
    directory.mkdir(parents=True)
    (directory / "unit.c").write_text(
        "int zz_prior_(int a)\n{\n  return a;\n}\n", encoding="utf-8"
    )
    (directory / "gnt4_shim.h").write_text("/* seed header */\n", encoding="utf-8")
    (directory / "provenance.json").write_text(
        json.dumps(
            {
                "unit": name,
                "generated_at": generated_at,
                "exported_functions": ["zz_prior_"],
                "allowed_extra_imports": [],
                "tier": "oracle_green",
            }
        ),
        encoding="utf-8",
    )


def test_green_unit_triggers_the_assembly_gate(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    _seed_green_artifact(repo, "prior-unit", "2026-08-01T00:00:00Z")
    gate_calls = []

    def fake_link(workdir, c_files, exports, allowed_extra):
        gate_calls.append((sorted(c_files), exports))
        (workdir / "assembly.wasm").write_bytes(b"\x00asm")
        return True, ""

    def fake_build(workdir, exports, extra=None):
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    driver = _driver(
        repo,
        build_runner=fake_build,
        assembly_link_runner=fake_link,
        assembly_smoke_runner=lambda wasm: (True, "ASSEMBLY_SMOKE_OK exports=2"),
    )
    assert driver.run() == EXIT_NO_WORK
    # The gate linked the fresh green together with the pre-existing one.
    assert gate_calls, "assembly gate never ran after a green"
    c_files, exports = gate_calls[0]
    assert c_files == ["prior-unit.c", "unit-a.c"]
    assert exports == ["zz_prior_", "zz_test_"]
    ledger = json.loads(
        (repo / "research/decomp/data/assembly-gate.json").read_text()
    )
    assert ledger["largest_n_passed"] == 2
    assert ledger["last_run"]["passed"] is True
    events = (
        repo / "research/decomp/generated/finish-game-port/events.jsonl"
    ).read_text()
    assert '"assembly_gate"' in events
    assert '"assembly_gate_failed"' not in events


def test_assembly_gate_failure_pages_but_never_costs_the_green(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    _seed_green_artifact(repo, "prior-unit", "2026-08-01T00:00:00Z")

    def fake_build(workdir, exports, extra=None):
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    driver = _driver(
        repo,
        build_runner=fake_build,
        assembly_link_runner=lambda *a: (
            False, "wasm-ld: error: duplicate symbol: zz_prior_"
        ),
        assembly_smoke_runner=lambda wasm: (True, "ASSEMBLY_SMOKE_OK"),
    )
    assert driver.run() == EXIT_NO_WORK
    state = json.loads(
        (repo / "research/decomp/generated/finish-game-port/wasm-units-state.json").read_text()
    )
    # The unit's verdict is untouched by the gate failure.
    assert state["units"]["unit-a"]["status"] == "green"
    events = (
        repo / "research/decomp/generated/finish-game-port/events.jsonl"
    ).read_text()
    assert '"assembly_gate_failed"' in events
    ledger = json.loads(
        (repo / "research/decomp/data/assembly-gate.json").read_text()
    )
    assert ledger["largest_n_passed"] == 0
    keys = list(ledger["conflicts"])
    assert any("zz_prior_" in key for key in keys)


def test_assembly_gate_internal_fault_degrades_to_an_event(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    _seed_green_artifact(repo, "prior-unit", "2026-08-01T00:00:00Z")

    def fake_build(workdir, exports, extra=None):
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    def exploding_link(*args):
        raise RuntimeError("emsdk on fire")

    driver = _driver(
        repo, build_runner=fake_build, assembly_link_runner=exploding_link
    )
    assert driver.run() == EXIT_NO_WORK
    state = json.loads(
        (repo / "research/decomp/generated/finish-game-port/wasm-units-state.json").read_text()
    )
    assert state["units"]["unit-a"]["status"] == "green"
    events = (
        repo / "research/decomp/generated/finish-game-port/events.jsonl"
    ).read_text()
    assert '"assembly_gate_error"' in events


def test_single_green_unit_skips_the_gate_quietly(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    gate_calls = []

    def fake_build(workdir, exports, extra=None):
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    driver = _driver(
        repo,
        build_runner=fake_build,
        assembly_link_runner=lambda *a: gate_calls.append(a) or (True, ""),
    )
    assert driver.run() == EXIT_NO_WORK
    assert gate_calls == []  # one unit is not a composition claim
    events = (
        repo / "research/decomp/generated/finish-game-port/events.jsonl"
    ).read_text()
    assert '"assembly_gate"' not in events


def test_assembly_gate_never_pushes(tmp_path, monkeypatch):
    """Regression: the gate's ledger commit must NOT carry its own push --
    a bare `git push` here landed one port-assembly commit on origin/main
    per green. The only push in a green run is the unit's own product push;
    every git call after the ledger enters the picture is push-free."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    _seed_green_artifact(repo, "prior-unit", "2026-08-01T00:00:00Z")
    git_calls = []

    def fake_git(*args):
        git_calls.append(args)
        if args[0] == "rev-parse":
            return _completed(0, "deadbeef\n")
        return _completed(0)

    def fake_build(workdir, exports, extra=None):
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    def fake_link(workdir, c_files, exports, allowed_extra):
        (workdir / "assembly.wasm").write_bytes(b"\x00asm")
        return True, ""

    driver = _driver(
        repo,
        git_runner=fake_git,
        build_runner=fake_build,
        assembly_link_runner=fake_link,
        assembly_smoke_runner=lambda wasm: (True, "ASSEMBLY_SMOKE_OK"),
    )
    assert driver.run() == EXIT_NO_WORK
    pushes = [args for args in git_calls if args[0] == "push"]
    assert len(pushes) == 1, "exactly the unit's product push, nothing more"
    ledger_indices = [
        i for i, args in enumerate(git_calls)
        if any("assembly-gate.json" in str(a) for a in args)
    ]
    assert ledger_indices, "the material first gate run must commit the ledger"
    after_ledger = git_calls[ledger_indices[0]:]
    assert all(args[0] != "push" for args in after_ledger)
    # The ledger commit itself is pathspec'd (never a tree-wide sweep).
    ledger_commits = [
        args for args in after_ledger
        if args[0] == "commit" and "assembly-gate.json" in " ".join(map(str, args))
    ]
    assert len(ledger_commits) == 1
    assert "--" in ledger_commits[0]


def _gate_driver_with_two_greens(repo, git_calls, *, link_ok=True, conflicts=None):
    """Driver wired for direct _maybe_run_assembly_gate calls over two
    pre-seeded green artifacts."""

    def fake_link(workdir, c_files, exports, allowed_extra):
        if link_ok:
            (workdir / "assembly.wasm").write_bytes(b"\x00asm")
            return True, ""
        return False, conflicts or "wasm-ld: error: duplicate symbol: zz_prior_"

    def fake_git(*args):
        git_calls.append(args)
        if args[0] == "rev-parse":
            return _completed(0, "deadbeef\n")
        return _completed(0)

    return _driver(
        repo,
        git_runner=fake_git,
        assembly_link_runner=fake_link,
        assembly_smoke_runner=lambda wasm: (True, "ASSEMBLY_SMOKE_OK"),
    )


def test_assembly_gate_unchanged_material_mints_no_commit(tmp_path, monkeypatch):
    """Regression: record_gate_result stamps last_run/updated_at on EVERY
    run, so an outcome-identical rerun rewrites the file -- but only material
    change (conflict identity, largest_n_passed) deserves a commit. A
    materially-unchanged rerun must produce zero git calls."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    _seed_green_artifact(repo, "prior-unit", "2026-08-01T00:00:00Z")
    _seed_green_artifact(repo, "other-unit", "2026-08-02T00:00:00Z")
    git_calls = []
    driver = _gate_driver_with_two_greens(repo, git_calls)

    driver._maybe_run_assembly_gate("other-unit")
    first_run_commits = [args for args in git_calls if args[0] == "commit"]
    assert len(first_run_commits) == 1  # largest_n_passed 0 -> 2 is material
    assert not [args for args in git_calls if args[0] == "push"]

    ledger_path = repo / "research/decomp/data/assembly-gate.json"
    before = json.loads(ledger_path.read_text())
    git_calls.clear()
    driver._maybe_run_assembly_gate("other-unit")
    after = json.loads(ledger_path.read_text())
    # The file DID churn (this is exactly why the raw diff is no commit signal)
    assert after["runs_total"] == before["runs_total"] + 1
    assert after["last_run"]["checked_at"] != before["last_run"]["checked_at"] or (
        after["updated_at"] != before["updated_at"]
    )
    assert git_calls == [], "immaterial ledger churn must not touch git"


def test_assembly_gate_repeat_conflict_is_immaterial(tmp_path, monkeypatch):
    """A failing gate files its conflict once; re-seeing the SAME conflict
    only bumps times_seen/last_seen, which is churn, not news -- no second
    commit, and never any push."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    _seed_green_artifact(repo, "prior-unit", "2026-08-01T00:00:00Z")
    _seed_green_artifact(repo, "other-unit", "2026-08-02T00:00:00Z")
    git_calls = []
    driver = _gate_driver_with_two_greens(repo, git_calls, link_ok=False)

    driver._maybe_run_assembly_gate("other-unit")
    assert len([args for args in git_calls if args[0] == "commit"]) == 1
    git_calls.clear()
    driver._maybe_run_assembly_gate("other-unit")
    assert git_calls == []
    ledger = json.loads(
        (repo / "research/decomp/data/assembly-gate.json").read_text()
    )
    only = next(iter(ledger["conflicts"].values()))
    assert only["times_seen"] == 2  # the recurrence is still recorded on disk
    assert not [args for args in git_calls if args[0] == "push"]


# ---------------------------------------------------------------------------
# Git side-effect audit invariants: every push carries an explicit refspec
# (bare `git push` rides ambient upstream config -- the gate-ledger bug),
# every add/commit is pathspec'd (never sweeps unrelated dirty files).


def test_product_push_uses_an_explicit_refspec(tmp_path, monkeypatch):
    """The green unit's product push must be `push origin HEAD` (current
    branch to its same-named origin branch), never a bare `git push`."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    git_calls = []

    def fake_git(*args):
        git_calls.append(args)
        if args[0] == "rev-parse":
            return _completed(0, "deadbeef\n")
        return _completed(0)

    def fake_build(workdir, exports, extra=None):
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    driver = _driver(repo, git_runner=fake_git, build_runner=fake_build)
    assert driver.run() == EXIT_NO_WORK
    pushes = [args for args in git_calls if args[0] == "push"]
    assert pushes == [("push", "origin", "HEAD")]
    # And every add/commit in the run is pathspec'd.
    for args in git_calls:
        if args[0] in ("add", "commit"):
            assert "--" in args, f"unpathspec'd git call: {args}"


def test_commit_paths_is_pathspecd_and_pushes_explicitly(tmp_path, monkeypatch):
    """The reverify/T3 promote path (_commit_paths) shares the audit
    invariants: pathspec'd add + commit, explicit-refspec push."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    git_calls = []

    def fake_git(*args):
        git_calls.append(args)
        if args[0] == "rev-parse":
            return _completed(0, "deadbeef\n")
        return _completed(0)

    driver = _driver(repo, git_runner=fake_git)
    sha, pushed, detail = driver._commit_paths(
        "port: audit-invariant probe", ["research/decomp/data/probe.json"]
    )
    assert sha == "deadbeef" and pushed and detail == ""
    assert [args for args in git_calls if args[0] == "push"] == [
        ("push", "origin", "HEAD")
    ]
    for args in git_calls:
        if args[0] in ("add", "commit"):
            assert "--" in args, f"unpathspec'd git call: {args}"
