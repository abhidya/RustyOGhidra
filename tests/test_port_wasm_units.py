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
    assert "port-units-staging" in add_call[1]
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


def test_no_new_header_round_skips_rebuild_and_never_fails_the_attempt(
    tmp_path, monkeypatch
):
    """A round with no extractable header neither rebuilds (identical input,
    identical output) nor compares fingerprints; the attempt only fails when
    the last allowed iteration ends without a link."""
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
    # the seed header was built exactly once; every no_new_header round reused it
    assert len(builds) == 1
    # each of the 3 fix rounds (cap 4 => 3 fix slots) asked twice: ask + re-ask
    assert len(prompts) == 6
    assert "Your previous reply contained no usable" in prompts[1]
    state = json.loads(
        (repo / "research/decomp/generated/finish-game-port/wasm-units-state.json").read_text()
    )
    record = state["units"]["unit-a"]
    assert record["status"] == "red_retryable"
    assert record["last_stage"] == "wasm-link"  # ran out of iterations, not failed mid-round
    assert "not linked" in record["error"]
    assert "no code block" in record["error"]


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
