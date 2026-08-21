"""Offline tests for the wasm-unit driver mode (src/port_wasm_units.py)."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from src.port_assembly_gate import load_unit_artifact, unit_artifact_sha256
from src.port_driver import EXIT_NO_WORK, EXIT_PROGRESSED, EXIT_STOPPED
from src.port_progress import PROGRESS_DIR, ProgressJournal
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


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    completed = subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True
    )
    if check:
        assert completed.returncode == 0, completed.stdout + completed.stderr
    return completed


def _init_bare_origin(repo: Path, tmp_path: Path) -> tuple[Path, str]:
    remote = tmp_path / "origin.git"
    _git(tmp_path, "init", "--bare", str(remote))
    _git(repo, "init")
    _git(repo, "config", "user.email", "port-test@example.invalid")
    _git(repo, "config", "user.name", "Port Test")
    _git(repo, "branch", "-M", "main")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "baseline")
    _git(repo, "remote", "add", "origin", str(remote))
    _git(repo, "push", "-u", "origin", "main")
    return remote, _git(repo, "rev-parse", "HEAD").stdout.strip()


def _remote_progress_events(remote: Path) -> list[dict]:
    shown = _git(
        remote.parent,
        "--git-dir",
        str(remote),
        "show",
        f"refs/heads/port-progress:{PROGRESS_DIR}/events.jsonl",
    )
    return [json.loads(line) for line in shown.stdout.splitlines() if line.strip()]


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
    state_path = repo / "research/decomp/generated/finish-game-port/wasm-units-state.json"
    state_path.write_text(json.dumps({
        "state_schema": 1,
        "units": {
            "unit-a": {
                "status": "pending", "attempts": 1,
                "tier": "compile_only", "commit": "deadcafe", "pushed": True,
                "revoked": {
                    "previous_commit": "deadcafe",
                    "reason": "superseded historical verdict",
                },
            }
        },
    }), encoding="utf-8")
    git_calls = []
    remote_sha = ["base0000"]

    def fake_git(*args):
        git_calls.append(args)
        if args[0] == "rev-parse":
            return _completed(0, "deadbeef\n")
        if args[0] == "ls-remote":
            return _completed(0, f"{remote_sha[0]}\trefs/heads/port-staging\n")
        if args[0] == "push":
            remote_sha[0] = "deadbeef"
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
    assert "revoked" not in record
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
    remote_sha = ["base0000"]

    def fake_git(*args):
        git_calls.append(args)
        if args[0] == "rev-parse":
            return _completed(0, "cafe1234\n")
        if args[0] == "ls-remote":
            return _completed(0, f"{remote_sha[0]}\trefs/heads/port-staging\n")
        if args[0] == "push":
            remote_sha[0] = "cafe1234"
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
        transition = kwargs.get("transition")
        transition_id = (
            transition.extra.get("transition_id")
            if transition is not None and isinstance(transition.extra, dict)
            else None
        )
        if transition_id and any(
            item.get("transition") is not None
            and item["transition"].extra.get("transition_id") == transition_id
            for item in self.checkpoints
        ):
            return {
                "recorded": True,
                "committed": True,
                "pushed": True,
                "idempotent": True,
            }
        self.checkpoints.append(kwargs)
        return {"recorded": True, "committed": True, "pushed": True}

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


def test_revoke_unit_backs_up_journals_projected_pending_and_is_idempotent(
    tmp_path, monkeypatch
):
    """A false green is unsettled through one durable, replay-safe event."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    state_path = _state_path(repo)
    state_path.write_text(
        json.dumps(
            {
                "state_schema": 1,
                "created_at": "2026-08-20T00:00:00Z",
                "units": {
                    "unit-a": {
                        "status": "green",
                        "attempts": 1,
                        "tier": "compile_only",
                        "oracle_summary": "compile-only (UNVERIFIED)",
                        "commit": "badc0ffee",
                        "pushed": True,
                        "world_version": {"driver_rev": "old"},
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    journal = FakeJournal()
    driver = _driver(repo, journal=journal)
    reason = "assembly gate failed after the legacy promotion ordering"

    result = driver.revoke_unit("unit-a", reason)
    assert result["previous_status"] == "green"
    assert result["previous_commit"] == "badc0ffee"
    assert result["backup"] and result["backup"].startswith(
        "wasm-units-state.json.settle-backup-"
    )
    assert result["transition_id"].startswith("verdict-revoke-")
    assert json.loads(
        (state_path.parent / result["backup"]).read_text()
    )["units"]["unit-a"]["status"] == "green"

    assert len(journal.checkpoints) == 1
    checkpoint = journal.checkpoints[0]
    transition = checkpoint["transition"]
    assert checkpoint["units"]["unit-a"]["status"] == "pending"
    assert checkpoint["machine"].workflow_state == "maintenance"
    assert checkpoint["driver_running"] is False
    assert checkpoint["machine"].active_model is None
    assert checkpoint["machine"].context_length is None
    assert transition.result == "deferred"
    assert transition.stage == "manual-revoke"
    assert transition.extra["previous_commit"] == "badc0ffee"
    assert transition.extra["transition_id"] == result["transition_id"]

    record = _state(repo)["units"]["unit-a"]
    assert record["status"] == "pending"
    assert record["last_stage"] == "manual-revoke"
    assert record["revoked"]["reason"] == reason
    assert record["revoked"]["previous_tier"] == "compile_only"
    for stale_key in ("tier", "oracle_summary", "commit", "pushed", "world_version"):
        assert stale_key not in record
    events = [
        json.loads(line)
        for line in (
            repo / "research/decomp/generated/finish-game-port/events.jsonl"
        ).read_text().splitlines()
        if line.strip()
    ]
    revoked = [event for event in events if event.get("kind") == "verdict_revoked"]
    assert len(revoked) == 1
    assert revoked[0]["transition_id"] == result["transition_id"]

    replay = driver.revoke_unit("unit-a", reason)
    assert replay["already_requeued"] is True
    assert replay["transition_id"] == result["transition_id"]
    assert len(journal.checkpoints) == 1


def test_revoke_unit_rejects_unsettled_unknown_and_empty_reason(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    driver = _driver(repo, journal=FakeJournal())
    with pytest.raises(ValueError, match="no settled verdict"):
        driver.revoke_unit("unit-a", "not actually settled")
    with pytest.raises(ValueError, match="unknown unit"):
        driver.revoke_unit("no-such-unit", "reason")
    with pytest.raises(ValueError, match="non-empty reason"):
        driver.revoke_unit("unit-a", "   ")


def test_revoke_unit_replays_same_transition_after_state_save_crash(
    tmp_path, monkeypatch
):
    """Journal-first recovery must finish without a duplicate transition."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    _state_path(repo).write_text(
        json.dumps(
            {
                "state_schema": 1,
                "created_at": "2026-08-20T00:00:00Z",
                "units": {
                    "unit-a": {
                        "status": "green",
                        "attempts": 1,
                        "tier": "compile_only",
                        "commit": "badc0ffee",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    journal = FakeJournal()
    first = _driver(repo, journal=journal)
    first.registry_path.write_text(
        json.dumps(
            {
                "registry_schema": 1,
                "program": "gnt4",
                "version": 1,
                "updated_at": "2026-08-20T00:00:00Z",
                "entries": {
                    "fn:zz_test_": {
                        "kind": "prototype",
                        "symbol": "zz_test_",
                        "declaration": "int zz_test_(int a);",
                        "tier": "compile_only",
                        "source_units": ["unit-a"],
                        "source_tiers": {"unit-a": "compile_only"},
                        "contested": False,
                        "conflicts": [],
                        "updated_version": 1,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    registry_preimage = json.loads(first.registry_path.read_text())
    real_save = first._save_state
    failed = {"once": False}

    def fail_once(state):
        if not failed["once"]:
            failed["once"] = True
            raise OSError("injected state-save crash")
        real_save(state)

    first._save_state = fail_once
    reason = "post-promotion composition gate failed"
    with pytest.raises(OSError, match="injected state-save crash"):
        first.revoke_unit("unit-a", reason)
    assert _state(repo)["units"]["unit-a"]["status"] == "green"
    assert json.loads(first.registry_path.read_text()) == registry_preimage
    assert len(journal.checkpoints) == 1
    transition_id = journal.checkpoints[0]["transition"].extra["transition_id"]

    restarted = _driver(repo, journal=journal)
    result = restarted.revoke_unit("unit-a", reason)
    assert result["transition_id"] == transition_id
    assert len(journal.checkpoints) == 1
    assert _state(repo)["units"]["unit-a"]["status"] == "pending"
    registry = json.loads(restarted.registry_path.read_text())
    assert registry["entries"]["fn:zz_test_"]["revoked"] is True
    assert registry["version"] == 2


def test_revoke_unit_real_progress_push_is_idempotent_across_crash(
    tmp_path, monkeypatch
):
    """The CLI contract is a real port-progress commit+push, not a fake receipt."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    _state_path(repo).write_text(
        json.dumps(
            {
                "state_schema": 1,
                "created_at": "2026-08-20T00:00:00Z",
                "units": {
                    "unit-a": {
                        "status": "green",
                        "attempts": 1,
                        "tier": "compile_only",
                        "oracle_summary": "compile-only (UNVERIFIED)",
                        "commit": "badc0ffee",
                        "pushed": True,
                        "push_detail": "legacy ordering",
                        "world_version": {"driver_rev": "old", "registry_version": "4"},
                        "promotion_transaction_id": "legacy-promotion-a",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    remote, product_main = _init_bare_origin(repo, tmp_path)
    journal = ProgressJournal(
        repo,
        run_root=repo / "research/decomp/generated/finish-game-port",
        worktree=tmp_path / "progress-wt",
        run_id="revoke-crash-run",
        enable_push=True,
    )
    driver = _driver(repo, journal=journal)
    real_save = driver._save_state
    failed = {"once": False}

    def fail_once(state):
        if not failed["once"]:
            failed["once"] = True
            raise OSError("injected state-save crash")
        real_save(state)

    driver._save_state = fail_once
    reason = "post-promotion composition gate failed"
    with pytest.raises(OSError, match="injected state-save crash"):
        driver.revoke_unit("unit-a", reason)
    assert _state(repo)["units"]["unit-a"]["status"] == "green"
    first_events = _remote_progress_events(remote)
    matching = [
        event
        for event in first_events
        if event.get("extra", {}).get("transition_id", "").startswith(
            "verdict-revoke-"
        )
    ]
    assert len(matching) == 1
    transition_id = matching[0]["extra"]["transition_id"]

    restarted_journal = ProgressJournal(
        repo,
        run_root=repo / "research/decomp/generated/finish-game-port",
        worktree=tmp_path / "progress-wt",
        run_id="revoke-restart-run",
        enable_push=True,
    )
    restarted = _driver(repo, journal=restarted_journal)
    result = restarted.revoke_unit("unit-a", reason)
    assert result["transition_id"] == transition_id
    assert _state(repo)["units"]["unit-a"]["status"] == "pending"
    matching = [
        event
        for event in _remote_progress_events(remote)
        if event.get("extra", {}).get("transition_id") == transition_id
    ]
    assert len(matching) == 1
    assert _git(repo, "rev-parse", "origin/main").stdout.strip() == product_main
    assert _git(
        repo, "ls-remote", "origin", "refs/heads/port-staging"
    ).stdout == ""


def test_revoke_unit_two_lifecycles_mint_distinct_full_preimage_ids(
    tmp_path, monkeypatch
):
    """Same visible verdict/reason but changed oracle/world/promotion is new."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    state_path = _state_path(repo)
    state_path.write_text(
        json.dumps(
            {
                "state_schema": 1,
                "created_at": "2026-08-20T00:00:00Z",
                "units": {
                    "unit-a": {
                        "status": "green",
                        "attempts": 1,
                        "tier": "compile_only",
                        "oracle_summary": "oracle-a",
                        "commit": "same-commit",
                        "pushed": True,
                        "push_detail": "push-a",
                        "world_version": {"driver_rev": "world-a"},
                        "promotion_transaction_id": "promotion-a",
                        "promotion_transition_id": "green-a",
                        "candidate_sha256": "candidate-a",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    remote, _ = _init_bare_origin(repo, tmp_path)
    journal = ProgressJournal(
        repo,
        run_root=repo / "research/decomp/generated/finish-game-port",
        worktree=tmp_path / "progress-wt-two",
        run_id="two-lifecycle-run",
        enable_push=True,
    )
    driver = _driver(repo, journal=journal)
    reason = "same composition failure"
    first = driver.revoke_unit("unit-a", reason)

    state = _state(repo)
    state["units"]["unit-a"].update(
        status="green",
        attempts=2,
        tier="compile_only",
        oracle_summary="oracle-b",
        commit="same-commit",
        pushed=True,
        push_detail="push-b",
        world_version={"driver_rev": "world-b"},
        promotion_transaction_id="promotion-b",
        promotion_transition_id="green-b",
        candidate_sha256="candidate-b",
    )
    state_path.write_text(json.dumps(state), encoding="utf-8")
    second = driver.revoke_unit("unit-a", reason)

    assert first["transition_id"] != second["transition_id"]
    events = _remote_progress_events(remote)
    ids = [
        event.get("extra", {}).get("transition_id")
        for event in events
        if event.get("stage") == "manual-revoke"
    ]
    assert ids.count(first["transition_id"]) == 1
    assert ids.count(second["transition_id"]) == 1


def test_revoke_unit_real_progress_push_failure_leaves_verdict_untouched(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    _state_path(repo).write_text(
        json.dumps(
            {
                "state_schema": 1,
                "created_at": "2026-08-20T00:00:00Z",
                "units": {"unit-a": {"status": "green", "attempts": 1}},
            }
        ),
        encoding="utf-8",
    )
    _init_bare_origin(repo, tmp_path)
    journal = ProgressJournal(
        repo,
        run_root=repo / "research/decomp/generated/finish-game-port",
        worktree=tmp_path / "progress-wt-fail",
        run_id="push-failure-run",
        remote="missing-remote",
        enable_push=True,
    )
    driver = _driver(repo, journal=journal)
    with pytest.raises(RuntimeError, match="not committed and pushed"):
        driver.revoke_unit("unit-a", "composition failure")
    assert _state(repo)["units"]["unit-a"]["status"] == "green"


def test_revoke_unit_journal_failure_leaves_state_registry_artifact_and_git_untouched(
    tmp_path, monkeypatch
):
    """No local journal record means no canonical or product-side mutation."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    _state_path(repo).write_text(
        json.dumps(
            {
                "state_schema": 1,
                "created_at": "2026-08-20T00:00:00Z",
                "units": {
                    "unit-a": {
                        "status": "green",
                        "attempts": 1,
                        "tier": "compile_only",
                        "commit": "badc0ffee",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    artifact = repo / "research/decomp/port-units-staging/unit-a"
    artifact.mkdir(parents=True)
    sentinel = artifact / "unit.wasm"
    sentinel.write_bytes(b"bad-but-auditable")
    registry_path = (
        repo / "research/decomp/generated/finish-game-port/knowledge-registry.json"
    )
    registry_path.write_text(
        json.dumps(
            {
                "registry_schema": 1,
                "program": "gnt4",
                "version": 0,
                "updated_at": "2026-08-20T00:00:00Z",
                "entries": {},
            }
        ),
        encoding="utf-8",
    )
    state_preimage = _state_path(repo).read_bytes()
    registry_preimage = registry_path.read_bytes()
    git_calls = []

    class RejectingJournal(FakeJournal):
        def checkpoint(self, **kwargs):
            self.checkpoints.append(kwargs)
            return {"recorded": False, "detail": "injected local journal failure"}

    driver = _driver(
        repo,
        journal=RejectingJournal(),
        git_runner=lambda *args: git_calls.append(args) or _completed(0),
    )
    with pytest.raises(RuntimeError, match="not committed and pushed"):
        driver.revoke_unit("unit-a", "composition failure")
    assert _state_path(repo).read_bytes() == state_preimage
    assert registry_path.read_bytes() == registry_preimage
    assert sentinel.read_bytes() == b"bad-but-auditable"
    assert git_calls == []
    events_path = repo / "research/decomp/generated/finish-game-port/events.jsonl"
    events = events_path.read_text() if events_path.is_file() else ""
    assert '"verdict_revoked"' not in events


def test_revoke_unit_refuses_while_driver_lock_is_held(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    _state_path(repo).write_text(
        json.dumps(
            {
                "state_schema": 1,
                "created_at": "2026-08-20T00:00:00Z",
                "units": {"unit-a": {"status": "green", "attempts": 1}},
            }
        ),
        encoding="utf-8",
    )
    holder = _driver(repo, journal=FakeJournal())
    contender = _driver(repo, journal=FakeJournal())
    assert holder.lock.acquire()
    try:
        with pytest.raises(RuntimeError, match="race its state writes"):
            contender.revoke_unit("unit-a", "must wait for boundary")
    finally:
        holder.lock.release()
    assert _state(repo)["units"]["unit-a"]["status"] == "green"


def test_revoke_unit_cli_subcommand(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    from src.port_wasm_units import main

    repo = _write_repo(tmp_path)
    _state_path(repo).write_text(
        json.dumps(
            {
                "state_schema": 1,
                "created_at": "2026-08-20T00:00:00Z",
                "units": {"unit-a": {"status": "green", "attempts": 1}},
            }
        ),
        encoding="utf-8",
    )
    remote, baseline = _init_bare_origin(repo, tmp_path)
    rc = main(
        [
            "revoke-unit",
            "--unit", "unit-a",
            "--reason", "cli revoke test",
            "--repo-root", str(repo),
        ]
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["unit"] == "unit-a"
    assert payload["already_requeued"] is False
    assert _state(repo)["units"]["unit-a"]["status"] == "pending"
    remote_events = _remote_progress_events(remote)
    revoked = [
        event for event in remote_events
        if event.get("extra", {}).get("revoked_via") == "revoke-unit"
    ]
    assert len(revoked) == 1
    assert revoked[0]["unit"] == "unit-a"
    assert _git(repo, "ls-remote", "origin", "refs/heads/main").stdout.split()[0] == baseline
    assert _git(
        repo, "ls-remote", "origin", "refs/heads/port-staging", check=False
    ).stdout == ""


def test_interrupted_porting_unit_is_journaled_refunded_and_requeued(
    tmp_path, monkeypatch
):
    """Run-start recovery settles no verdict and spends no phantom attempt."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    state = {
        "state_schema": 1,
        "created_at": "2026-08-20T00:00:00Z",
        "units": {
            "unit-a": {
                "status": "porting",
                "attempts": 1,
                "last_stage": "compile-fix",
            }
        },
    }
    _state_path(repo).write_text(json.dumps(state), encoding="utf-8")
    journal = FakeJournal()
    driver = _driver(repo, journal=journal)

    assert driver._reconcile_interrupted(state) is True

    record = _state(repo)["units"]["unit-a"]
    assert record["status"] == "pending"
    assert record["attempts"] == 0
    assert record["interruptions"] == 1
    assert "interrupted before a verdict" in record["error"]
    assert len(journal.checkpoints) == 1
    transition = journal.checkpoints[0]["transition"]
    assert transition.unit == "unit-a"
    assert transition.result == "deferred"
    assert transition.stage == "compile-fix"
    assert transition.attempt == 0
    assert "requeued" in transition.detail


def test_interrupted_reconcile_journal_failure_preserves_porting_preimage(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    state = {
        "state_schema": 1,
        "created_at": "2026-08-20T00:00:00Z",
        "units": {
            "unit-a": {
                "status": "porting",
                "attempts": 3,
                "interruptions": 2,
                "last_stage": "compile-fix",
            }
        },
    }
    _state_path(repo).write_text(json.dumps(state), encoding="utf-8")
    preimage = _state_path(repo).read_bytes()

    class RejectingJournal(FakeJournal):
        def checkpoint(self, **kwargs):
            self.checkpoints.append(kwargs)
            return {"recorded": False, "detail": "injected journal failure"}

    journal = RejectingJournal()
    driver = _driver(repo, journal=journal)

    assert driver._reconcile_interrupted(state) is False
    assert _state_path(repo).read_bytes() == preimage
    assert state["units"]["unit-a"] == {
        "status": "porting",
        "attempts": 3,
        "interruptions": 2,
        "last_stage": "compile-fix",
    }
    assert len(journal.checkpoints) == 1
    events = (driver.run_root / "events.jsonl").read_text(encoding="utf-8")
    assert '"interrupted_reconcile_blocked"' in events


def test_interrupted_reconcile_real_journal_crash_rerun_applies_once(
    tmp_path, monkeypatch
):
    """The journal-first/state-second crash window is exactly replayable."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    state = {
        "state_schema": 1,
        "created_at": "2026-08-20T00:00:00Z",
        "units": {
            "unit-a": {
                "status": "porting",
                "attempts": 1,
                "last_stage": "compile-fix",
                "promotion_transaction": {"phase": "prepared", "id": "tx-1"},
            }
        },
    }
    _state_path(repo).write_text(json.dumps(state), encoding="utf-8")
    remote, baseline = _init_bare_origin(repo, tmp_path)
    journal = ProgressJournal(
        repo,
        worktree=tmp_path / "progress-worktree",
        run_id="interrupted-lifecycle-1",
    )
    first = _driver(repo, journal=journal)

    def crash_after_journal(_projected):
        raise OSError("injected crash before canonical state save")

    first._save_state = crash_after_journal
    with pytest.raises(OSError, match="before canonical state save"):
        first._reconcile_interrupted(state)

    assert _state(repo)["units"]["unit-a"]["status"] == "porting"
    first_events = _remote_progress_events(remote)
    reconcile_events = [
        event for event in first_events
        if str(event.get("extra", {}).get("transition_id", "")).startswith(
            "interrupted-reconcile-"
        )
    ]
    assert len(reconcile_events) == 1
    transition_id = reconcile_events[0]["extra"]["transition_id"]

    restarted_state = json.loads(_state_path(repo).read_text(encoding="utf-8"))
    restarted_journal = ProgressJournal(
        repo,
        worktree=tmp_path / "progress-worktree",
        run_id="interrupted-lifecycle-2",
    )
    restarted = _driver(repo, journal=restarted_journal)
    assert restarted._reconcile_interrupted(restarted_state) is True

    record = _state(repo)["units"]["unit-a"]
    assert record["status"] == "pending"
    assert record["attempts"] == 0
    assert record["interruptions"] == 1
    assert record["interrupted_reconcile_transition_id"] == transition_id
    final_events = _remote_progress_events(remote)
    assert sum(
        event.get("extra", {}).get("transition_id") == transition_id
        for event in final_events
    ) == 1
    assert _git(repo, "ls-remote", "origin", "refs/heads/main").stdout.split()[0] == baseline
    assert _git(
        repo, "ls-remote", "origin", "refs/heads/port-staging", check=False
    ).stdout == ""


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


def _seed_green_artifact(
    repo: Path, name: str, generated_at: str, *, canonical: bool = True
) -> None:
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
    if canonical:
        state_path = (
            repo / "research/decomp/generated/finish-game-port/wasm-units-state.json"
        )
        state = (
            json.loads(state_path.read_text())
            if state_path.is_file()
            else {"state_schema": 1, "units": {}}
        )
        state.setdefault("units", {})[name] = {
            "status": "green",
            "attempts": 1,
            "tier": "oracle_green",
            "commit": "deadbeef",
            "pushed": True,
            "last_stage": "commit",
            "candidate_sha256": unit_artifact_sha256(directory),
        }
        state_path.write_text(json.dumps(state), encoding="utf-8")


def _rewrite_seed_function(repo: Path, name: str, function: str) -> None:
    directory = repo / "research/decomp/port-units" / name
    (directory / "unit.c").write_text(
        f"int {function}(int a)\n{{\n  return a;\n}}\n", encoding="utf-8"
    )
    provenance_path = directory / "provenance.json"
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    provenance["exported_functions"] = [function]
    provenance_path.write_text(json.dumps(provenance), encoding="utf-8")
    state_path = repo / "research/decomp/generated/finish-game-port/wasm-units-state.json"
    if state_path.is_file():
        state = json.loads(state_path.read_text(encoding="utf-8"))
        record = state.get("units", {}).get(name)
        if isinstance(record, dict):
            record["candidate_sha256"] = unit_artifact_sha256(directory)
            state_path.write_text(json.dumps(state), encoding="utf-8")


def _legacy_backfill_fixture(
    tmp_path: Path, *, journal=None,
    omit_from_commit: tuple[str, ...] = (),
    extra_ignore_patterns: tuple[str, ...] = (),
) -> tuple[Path, WasmUnitDriver, FakeJournal, Path]:
    repo = _write_repo(tmp_path)
    (repo / ".gitignore").write_text(
        "oracle.log\n" + "".join(f"{pattern}\n" for pattern in extra_ignore_patterns),
        encoding="utf-8",
    )
    artifact = repo / "research/decomp/port-units-staging/unit-a"
    artifact.mkdir(parents=True)
    (artifact / "unit.c").write_text(
        "int zz_test_(int a)\n{\n  return a;\n}\n", encoding="utf-8"
    )
    (artifact / "gnt4_shim.h").write_text("/* shim */\n", encoding="utf-8")
    (artifact / "unit.wasm").write_bytes(b"\x00asm")
    (artifact / "oracle.log").write_text("UNVERIFIED historical log\n", encoding="utf-8")
    (artifact / "provenance.json").write_text(json.dumps({
        "unit": "unit-a",
        "generated_at": "2026-08-01T00:00:00Z",
        "exported_functions": ["zz_test_"],
        "allowed_extra_imports": [],
        "tier": "compile_only",
    }), encoding="utf-8")
    assert _git(repo, "init").returncode == 0
    assert _git(repo, "config", "user.email", "port-test@example.invalid").returncode == 0
    assert _git(repo, "config", "user.name", "Port Test").returncode == 0
    assert _git(repo, "add", ".").returncode == 0
    for name in omit_from_commit:
        assert _git(
            repo, "rm", "--cached", "--",
            f"research/decomp/port-units-staging/unit-a/{name}",
        ).returncode == 0
    assert _git(repo, "commit", "-m", "legacy staged artifact").returncode == 0
    commit = _git(repo, "rev-parse", "HEAD").stdout.strip()
    assert _git(
        repo, "update-ref", "refs/remotes/origin/port-staging", commit
    ).returncode == 0
    _state_path(repo).write_text(json.dumps({
        "state_schema": 1,
        "units": {
            "unit-a": {
                "status": "green", "attempts": 1,
                "tier": "compile_only", "commit": commit, "pushed": True,
            }
        },
    }), encoding="utf-8")
    chosen_journal = journal or FakeJournal()

    def git_runner(*args):
        if args == ("ls-remote", "origin", "refs/heads/port-staging"):
            return _completed(
                0, f"{commit}\trefs/heads/port-staging\n"
            )
        return _git(repo, *args, check=False)

    driver = _driver(repo, journal=chosen_journal, git_runner=git_runner)
    driver._test_git_runner = git_runner
    return repo, driver, chosen_journal, artifact


def test_digest_backfill_journals_ignored_inventory_then_binds_once(tmp_path):
    repo, driver, journal, artifact = _legacy_backfill_fixture(tmp_path)
    artifact_preimage = unit_artifact_sha256(artifact)
    head_preimage = _git(repo, "rev-parse", "HEAD").stdout.strip()
    publication_preimage = _git(
        repo, "rev-parse", "refs/remotes/origin/port-staging"
    ).stdout.strip()

    result = driver.backfill_artifact_digest(
        "unit-a", "operator reviewed surviving legacy green"
    )

    assert result["already_bound"] is False
    assert result["candidate_sha256"] == artifact_preimage
    binding = result["binding"]
    assert binding["publication_ref"] == "refs/heads/port-staging"
    assert binding["publication_sha"] == publication_preimage
    assert binding["uncommitted_files"] == ["oracle.log"]
    assert binding["required_committed_files"] == [
        "gnt4_shim.h", "provenance.json", "unit.c", "unit.wasm"
    ]
    assert binding["ignored_extra_evidence"] == [{
        "path": "oracle.log",
        "repo_path": "research/decomp/port-units-staging/unit-a/oracle.log",
        "classification": "allowed-ignored-evidence",
        "allowlist_entry": "oracle.log",
        "git_check_ignore": binding["ignored_extra_evidence"][0]["git_check_ignore"],
    }]
    assert "oracle.log" in binding["ignored_extra_evidence"][0]["git_check_ignore"]
    assert [item["path"] for item in binding["file_inventory"]] == [
        "gnt4_shim.h", "oracle.log", "provenance.json", "unit.c", "unit.wasm"
    ]
    assert all(len(item["sha256"]) == 64 for item in binding["file_inventory"])
    record = _state(repo)["units"]["unit-a"]
    assert record["candidate_sha256"] == artifact_preimage
    assert record["artifact_digest_backfill"]["file_inventory"] == (
        binding["file_inventory"]
    )
    assert len(journal.checkpoints) == 1
    transition = journal.checkpoints[0]["transition"]
    assert transition.stage == "artifact-digest-backfill"
    assert transition.extra["artifact_sha256"] == artifact_preimage
    assert transition.extra["file_inventory"] == binding["file_inventory"]
    assert journal.checkpoints[0]["units"]["unit-a"]["candidate_sha256"] == (
        artifact_preimage
    )
    assert unit_artifact_sha256(artifact) == artifact_preimage
    assert _git(repo, "rev-parse", "HEAD").stdout.strip() == head_preimage
    assert _git(
        repo, "rev-parse", "refs/remotes/origin/port-staging"
    ).stdout.strip() == publication_preimage

    repeated = driver.backfill_artifact_digest("unit-a", "repeat is idempotent")
    assert repeated["already_bound"] is True
    assert len(journal.checkpoints) == 1
    driver._git_runner = lambda *args: pytest.fail(
        f"digest-bound selector performed Git I/O: {args}"
    )
    offline = driver.run_assembly_gate_now(n=None)
    assert offline["passed"] is None
    assert offline["units"] == ["unit-a"]
    assert offline["selection"]["eligible"][0]["artifact_binding"]["binding"] == (
        "canonical-digest"
    )


def test_missing_digest_selector_fails_closed_without_git_io(tmp_path):
    _repo, driver, _journal, _artifact = _legacy_backfill_fixture(tmp_path)
    driver._git_runner = lambda *args: pytest.fail(
        f"missing-digest selector performed Git I/O: {args}"
    )

    result = driver.run_assembly_gate_now(n=None)

    assert result["passed"] is None
    assert result["units"] == []
    assert result["selection"]["excluded"] == {
        "unit-a": "canonical-artifact-digest-missing"
    }


def test_digest_backfill_rejects_tracked_substitution_without_journal(tmp_path):
    repo, driver, journal, artifact = _legacy_backfill_fixture(tmp_path)
    (artifact / "unit.c").write_text("int substituted;\n", encoding="utf-8")
    state_preimage = _state_path(repo).read_bytes()

    with pytest.raises(RuntimeError, match="legacy-artifact-commit-mismatch"):
        driver.backfill_artifact_digest("unit-a", "must not bless substitution")

    assert _state_path(repo).read_bytes() == state_preimage
    assert journal.checkpoints == []


def test_digest_backfill_rejects_required_unit_c_omitted_from_commit(tmp_path):
    repo, driver, journal, _artifact = _legacy_backfill_fixture(
        tmp_path, omit_from_commit=("unit.c",)
    )
    state_preimage = _state_path(repo).read_bytes()

    with pytest.raises(
        RuntimeError, match="legacy-required-file-not-committed:unit.c"
    ):
        driver.backfill_artifact_digest("unit-a", "omitted source regression")

    assert _state_path(repo).read_bytes() == state_preimage
    assert journal.checkpoints == []


def test_digest_backfill_rejects_nonignored_surprise_file(tmp_path):
    repo, driver, journal, artifact = _legacy_backfill_fixture(tmp_path)
    (artifact / "surprise.txt").write_text("not published\n", encoding="utf-8")

    with pytest.raises(
        RuntimeError, match="legacy-extra-not-ignored:surprise.txt"
    ):
        driver.backfill_artifact_digest("unit-a", "nonignored extra regression")

    assert "candidate_sha256" not in _state(repo)["units"]["unit-a"]
    assert journal.checkpoints == []


def test_digest_backfill_rejects_unknown_ignored_extra(tmp_path):
    repo, driver, journal, artifact = _legacy_backfill_fixture(
        tmp_path, extra_ignore_patterns=("*.tmp",)
    )
    (artifact / "unknown.tmp").write_text("ignored but unknown\n", encoding="utf-8")

    with pytest.raises(
        RuntimeError, match="legacy-ignored-extra-not-allowlisted:unknown.tmp"
    ):
        driver.backfill_artifact_digest("unit-a", "unknown ignored regression")

    assert "candidate_sha256" not in _state(repo)["units"]["unit-a"]
    assert journal.checkpoints == []


def test_digest_backfill_allowlist_is_case_and_path_exact(tmp_path):
    repo, driver, journal, artifact = _legacy_backfill_fixture(tmp_path)
    (artifact / "oracle.log").unlink()
    (artifact / "Oracle.log").write_text("wrong case\n", encoding="utf-8")

    with pytest.raises(
        RuntimeError, match="legacy-ignored-extra-not-allowlisted:Oracle.log"
    ):
        driver.backfill_artifact_digest("unit-a", "case regression")
    with pytest.raises(ValueError, match="one plain unit name"):
        driver.backfill_artifact_digest("../unit-a", "path traversal regression")

    assert "candidate_sha256" not in _state(repo)["units"]["unit-a"]
    assert journal.checkpoints == []


def test_digest_backfill_rejects_symlink_entries(tmp_path, monkeypatch):
    repo, driver, journal, artifact = _legacy_backfill_fixture(tmp_path)
    linked = artifact / "surprise.link"
    linked.write_text("link stand-in\n", encoding="utf-8")
    real_is_symlink = Path.is_symlink
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda path: path == linked or real_is_symlink(path),
    )

    with pytest.raises(ValueError, match="artifact tree is unsafe"):
        driver.backfill_artifact_digest("unit-a", "symlink regression")

    assert "candidate_sha256" not in _state(repo)["units"]["unit-a"]
    assert journal.checkpoints == []


def test_digest_backfill_ignores_stale_local_ref_and_fails_remote_mismatch(tmp_path):
    repo, driver, journal, _artifact = _legacy_backfill_fixture(tmp_path)
    local_publication = _git(
        repo, "rev-parse", "refs/remotes/origin/port-staging"
    ).stdout.strip()
    real_runner = driver._test_git_runner

    def mismatched_remote(*args):
        if args == ("ls-remote", "origin", "refs/heads/port-staging"):
            return _completed(0, f"{'f' * 40}\trefs/heads/port-staging\n")
        return real_runner(*args)

    driver._git_runner = mismatched_remote
    with pytest.raises(
        RuntimeError, match="unreachable-from-publication-ref"
    ):
        driver.backfill_artifact_digest("unit-a", "stale local ref regression")

    assert _git(
        repo, "rev-parse", "refs/remotes/origin/port-staging"
    ).stdout.strip() == local_publication
    assert "candidate_sha256" not in _state(repo)["units"]["unit-a"]
    assert journal.checkpoints == []


def test_digest_backfill_fails_closed_when_remote_is_unavailable(tmp_path):
    repo, driver, journal, _artifact = _legacy_backfill_fixture(tmp_path)
    real_runner = driver._test_git_runner

    def offline_remote(*args):
        if args == ("ls-remote", "origin", "refs/heads/port-staging"):
            return _completed(1, "")
        return real_runner(*args)

    driver._git_runner = offline_remote
    with pytest.raises(RuntimeError, match="publication ref is unavailable"):
        driver.backfill_artifact_digest("unit-a", "offline remote regression")

    assert "candidate_sha256" not in _state(repo)["units"]["unit-a"]
    assert journal.checkpoints == []


def test_digest_backfill_race_after_journal_keeps_canonical_preimage(tmp_path):
    class MutatingJournal(FakeJournal):
        artifact: Path

        def checkpoint(self, **kwargs):
            result = super().checkpoint(**kwargs)
            self.artifact.joinpath("oracle.log").write_text(
                "changed after durable receipt\n", encoding="utf-8"
            )
            return result

    journal = MutatingJournal()
    repo, driver, _journal, artifact = _legacy_backfill_fixture(
        tmp_path, journal=journal
    )
    journal.artifact = artifact
    state_preimage = _state_path(repo).read_bytes()

    with pytest.raises(RuntimeError, match="artifact changed after digest checkpoint"):
        driver.backfill_artifact_digest("unit-a", "race regression")

    assert _state_path(repo).read_bytes() == state_preimage
    assert len(journal.checkpoints) == 1


def test_digest_backfill_save_crash_retries_same_transition(tmp_path):
    repo, driver, journal, _artifact = _legacy_backfill_fixture(tmp_path)
    state_preimage = _state_path(repo).read_bytes()
    transition_ids = []
    real_save = driver._save_state

    def fail_save(state):
        transition_ids.append(
            state["units"]["unit-a"]["artifact_digest_backfill"]["transition_id"]
        )
        raise OSError("injected canonical save crash")

    driver._save_state = fail_save
    with pytest.raises(OSError, match="injected canonical save crash"):
        driver.backfill_artifact_digest("unit-a", "crash-idempotent backfill")
    assert _state_path(repo).read_bytes() == state_preimage
    assert len(journal.checkpoints) == 1

    restarted = _driver(
        repo, journal=journal, git_runner=driver._test_git_runner
    )
    result = restarted.backfill_artifact_digest(
        "unit-a", "crash-idempotent backfill"
    )
    assert result["transition_id"] == transition_ids[0]
    assert len(journal.checkpoints) == 1
    assert _state(repo)["units"]["unit-a"]["candidate_sha256"] == (
        result["candidate_sha256"]
    )


def test_digest_backfill_retries_pending_progress_push(tmp_path):
    class PendingOnceJournal(FakeJournal):
        pending = True

        def checkpoint(self, **kwargs):
            result = super().checkpoint(**kwargs)
            if self.pending:
                self.pending = False
                return {"recorded": True, "committed": True, "pushed": False}
            return result

    journal = PendingOnceJournal()
    repo, driver, _journal, _artifact = _legacy_backfill_fixture(
        tmp_path, journal=journal
    )
    state_preimage = _state_path(repo).read_bytes()
    with pytest.raises(RuntimeError, match="not committed and pushed"):
        driver.backfill_artifact_digest("unit-a", "pending push retry")
    assert _state_path(repo).read_bytes() == state_preimage

    result = driver.backfill_artifact_digest("unit-a", "pending push retry")
    assert result["already_bound"] is False
    assert len(journal.checkpoints) == 1


def test_digest_backfill_refuses_while_driver_lock_is_held(tmp_path):
    repo, _driver_one, _journal, _artifact = _legacy_backfill_fixture(tmp_path)
    holder = _driver(repo, journal=FakeJournal(), git_runner=None)
    contender = _driver(repo, journal=FakeJournal(), git_runner=None)
    assert holder.lock.acquire()
    try:
        with pytest.raises(RuntimeError, match="race its state writes"):
            contender.backfill_artifact_digest("unit-a", "wait for boundary")
    finally:
        holder.lock.release()
    assert "candidate_sha256" not in _state(repo)["units"]["unit-a"]


def test_explicit_candidate_cannot_smuggle_newer_ineligible_history(tmp_path):
    repo = _write_repo(tmp_path)
    _seed_green_artifact(repo, "eligible", "2026-08-01T00:00:00Z")
    _rewrite_seed_function(repo, "eligible", "zz_eligible_")
    for index, name in enumerate(("pending", "failed", "revoked"), start=10):
        _seed_green_artifact(repo, name, f"2999-08-{index:02d}T00:00:00Z")
    _seed_green_artifact(
        repo, "unit-a", "3999-08-20T00:00:00Z", canonical=False
    )
    _rewrite_seed_function(repo, "unit-a", "zz_candidate_")
    candidate = load_unit_artifact(repo / "research/decomp/port-units/unit-a")
    assert candidate is not None
    state_path = repo / "research/decomp/generated/finish-game-port/wasm-units-state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["units"]["pending"]["status"] = "pending"
    state["units"]["failed"]["status"] = "failed"
    state["units"]["revoked"]["revoked"] = {
        "previous_commit": state["units"]["revoked"]["commit"],
        "reason": "current lifecycle revoked",
    }
    state["units"]["unit-a"] = {"status": "porting", "attempts": 1}
    state_path.write_text(json.dumps(state), encoding="utf-8")
    linked = []

    def fake_link(workdir, c_files, exports, allowed_extra):
        linked.append(list(c_files))
        (workdir / "assembly.wasm").write_bytes(b"\x00asm")
        return True, ""

    driver = _driver(
        repo,
        assembly_link_runner=fake_link,
        assembly_smoke_runner=lambda _wasm: (True, "ASSEMBLY_SMOKE_OK"),
    )
    result = driver.run_assembly_gate_now(n=3, candidate=candidate)

    assert result["passed"] is True
    assert linked == [["eligible.c", "unit-a.c"]]
    assert result["units"] == ["eligible", "unit-a"]
    assert result["selection"]["candidate"] == {
        "name": "unit-a",
        "artifact_sha256": candidate.sha256,
        "tier": "oracle_green",
        "authority": "private-explicit-candidate",
    }
    assert result["selection"]["excluded"] == {
        "failed": "canonical-status:failed",
        "pending": "canonical-status:pending",
        "revoked": "current-lifecycle-revocation-contradiction",
        "unit-a": "canonical-status:porting",
    }


def test_no_candidate_backfill_truthfully_reports_no_eligible_units(tmp_path):
    repo = _write_repo(tmp_path)
    _seed_green_artifact(repo, "failed", "2999-08-20T00:00:00Z")
    state_path = repo / "research/decomp/generated/finish-game-port/wasm-units-state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["units"]["failed"]["status"] = "red_retryable"
    state_path.write_text(json.dumps(state), encoding="utf-8")
    driver = _driver(
        repo,
        assembly_link_runner=lambda *args: pytest.fail("ineligible artifact linked"),
    )

    result = driver.run_assembly_gate_now(n=None)

    assert result["passed"] is None
    assert result["stage"] == "skipped"
    assert result["n"] == 0
    assert result["units"] == []
    assert result["selection"]["excluded"] == {
        "failed": "canonical-status:red_retryable"
    }


def test_canonical_state_mutation_during_gate_fails_closed(tmp_path):
    repo = _write_repo(tmp_path)
    _seed_green_artifact(repo, "unit-a", "2026-08-01T00:00:00Z")
    _seed_green_artifact(repo, "unit-b", "2026-08-02T00:00:00Z")
    _rewrite_seed_function(repo, "unit-a", "zz_a_")
    _rewrite_seed_function(repo, "unit-b", "zz_b_")
    state_path = repo / "research/decomp/generated/finish-game-port/wasm-units-state.json"

    def mutating_link(workdir, c_files, exports, allowed_extra):
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["selection_mutation"] = True
        state_path.write_text(json.dumps(state), encoding="utf-8")
        (workdir / "assembly.wasm").write_bytes(b"\x00asm")
        return True, ""

    driver = _driver(
        repo,
        assembly_link_runner=mutating_link,
        assembly_smoke_runner=lambda _wasm: (True, "ASSEMBLY_SMOKE_OK"),
    )
    result = driver.run_assembly_gate_now(n=None)

    assert result["passed"] is False
    assert result["stage"] == "canonical-state-integrity"
    assert result["detail"] == "canonical state changed during assembly gate"


def test_interrupted_record_must_reconcile_before_manual_selection(tmp_path):
    repo = _write_repo(tmp_path)
    _seed_green_artifact(repo, "eligible", "2026-08-01T00:00:00Z")
    state_path = repo / "research/decomp/generated/finish-game-port/wasm-units-state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["units"]["orphan"] = {"status": "porting", "attempts": 2}
    state_path.write_text(json.dumps(state), encoding="utf-8")
    driver = _driver(
        repo,
        assembly_link_runner=lambda *args: pytest.fail("interrupted state linked"),
    )

    result = driver.run_assembly_gate_now(n=None)

    assert result["passed"] is False
    assert result["stage"] == "canonical-state"
    assert "orphan" in result["detail"]


def test_green_unit_triggers_the_assembly_gate(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    _seed_green_artifact(repo, "prior-unit", "2026-08-01T00:00:00Z")
    gate_calls = []
    operation_order = []
    remote_sha = ["base0000"]

    def fake_link(workdir, c_files, exports, allowed_extra):
        assert not (repo / "research/decomp/port-units/unit-a").exists()
        operation_order.append("assembly_link")
        gate_calls.append((sorted(c_files), exports))
        (workdir / "assembly.wasm").write_bytes(b"\x00asm")
        return True, ""

    def fake_git(*args):
        operation_order.append(("git", *args))
        if args[0] == "rev-parse":
            return _completed(0, "deadbeef\n")
        if args[0] == "ls-remote":
            return _completed(0, f"{remote_sha[0]}\trefs/heads/port-staging\n")
        if args[0] == "push":
            remote_sha[0] = "deadbeef"
        return _completed(0)

    def fake_build(workdir, exports, extra=None):
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    driver = _driver(
        repo,
        git_runner=fake_git,
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
    assembly_index = operation_order.index("assembly_link")
    artifact_add_index = next(
        i
        for i, operation in enumerate(operation_order)
        if isinstance(operation, tuple)
        and operation[1] == "add"
        and "port-units/unit-a" in " ".join(map(str, operation))
    )
    push_index = next(
        i
        for i, operation in enumerate(operation_order)
        if isinstance(operation, tuple) and operation[1] == "push"
    )
    assert assembly_index < artifact_add_index < push_index
    ledger = json.loads(
        (repo / "research/decomp/data/assembly-gate.json").read_text()
    )
    assert ledger["largest_n_passed"] == 2
    assert ledger["last_run"]["passed"] is True
    events_text = (
        repo / "research/decomp/generated/finish-game-port/events.jsonl"
    ).read_text()
    assert '"assembly_gate"' in events_text
    assert '"assembly_gate_failed"' not in events_text
    events = [json.loads(line) for line in events_text.splitlines() if line.strip()]
    kinds = [event["kind"] for event in events]
    assert kinds.index("assembly_gate") < kinds.index("wasm_unit_green")


def test_assembly_gate_failure_blocks_green_commit_and_push(tmp_path, monkeypatch):
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

    journal = FakeJournal()
    driver = _driver(
        repo,
        git_runner=fake_git,
        journal=journal,
        build_runner=fake_build,
        assembly_link_runner=lambda *a: (
            False, "wasm-ld: error: duplicate symbol: zz_prior_"
        ),
        assembly_smoke_runner=lambda wasm: (True, "ASSEMBLY_SMOKE_OK"),
    )
    assert driver.run() == EXIT_PROGRESSED
    state = json.loads(
        (repo / "research/decomp/generated/finish-game-port/wasm-units-state.json").read_text()
    )
    record = state["units"]["unit-a"]
    assert record["status"] == "red_retryable"
    assert record["last_stage"] == "assembly"
    assert record["assembly_gate"]["passed"] is False
    # The candidate is materialized only long enough to run the gate. A failed
    # candidate must not remain selectable as a green/staged artifact.
    assert not (repo / "research/decomp/port-units/unit-a").exists()
    assert not (repo / "research/decomp/port-units-staging/unit-a").exists()
    assert not driver.registry_path.exists()
    artifact_git_calls = [
        args for args in git_calls if "port-units" in " ".join(map(str, args))
    ]
    assert artifact_git_calls == []
    assert not [args for args in git_calls if args[0] == "push"]
    events = (
        repo / "research/decomp/generated/finish-game-port/events.jsonl"
    ).read_text()
    assert '"assembly_gate_failed"' in events
    assert '"wasm_unit_red"' in events
    assert '"wasm_unit_green"' not in events
    assert len(journal.checkpoints) == 1
    transition = journal.checkpoints[0]["transition"]
    assert transition.unit == "unit-a"
    assert transition.result == "gate_failed"
    assert transition.stage == "assembly"
    assert transition.extra["assembly_gate"]["passed"] is False
    ledger = json.loads(
        (repo / "research/decomp/data/assembly-gate.json").read_text()
    )
    assert ledger["largest_n_passed"] == 0
    keys = list(ledger["conflicts"])
    assert any("zz_prior_" in key for key in keys)


def test_candidate_binding_defeats_future_dates_and_same_name_shadow(
    tmp_path, monkeypatch
):
    """The attempt candidate is explicit authority, not root/timestamp luck."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    monkeypatch.setenv("OGHIDRA_PORT_ASSEMBLY_N", "2")
    repo = _write_repo(tmp_path)
    _seed_green_artifact(repo, "future-unit", "2999-01-01T00:00:00Z")
    _seed_green_artifact(
        repo, "unit-a", "3999-01-01T00:00:00Z", canonical=False
    )
    sentinel = repo / "research/decomp/port-units/unit-a/KEEP-SENTINEL"
    sentinel.write_text("authoritative preimage\n", encoding="utf-8")
    old_digest = unit_artifact_sha256(sentinel.parent)
    observed = {}

    def fake_build(workdir, exports, extra=None):
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    def conflicting_link(workdir, c_files, exports, allowed_extra):
        candidate_dir = workdir.parent / "candidate"
        observed["sha256"] = unit_artifact_sha256(candidate_dir)
        observed["source"] = (candidate_dir / "unit.c").read_text(encoding="utf-8")
        observed["c_files"] = sorted(c_files)
        return False, "wasm-ld: error: duplicate symbol: zz_test_"

    driver = _driver(
        repo,
        journal=FakeJournal(),
        build_runner=fake_build,
        assembly_link_runner=conflicting_link,
        assembly_smoke_runner=lambda wasm: (True, "ASSEMBLY_SMOKE_OK"),
    )
    assert driver.run() == EXIT_PROGRESSED
    record = _state(repo)["units"]["unit-a"]
    evidence = record["assembly_gate"]
    assert evidence["expected_candidate"] == {
        "name": "unit-a",
        "sha256": observed["sha256"],
    }
    assert evidence["candidate"] == evidence["expected_candidate"]
    assert "return a + 1;" in observed["source"]
    assert observed["c_files"] == ["future-unit.c", "unit-a.c"]
    ledger = json.loads(driver.assembly_ledger_path.read_text())
    assert ledger["last_run"]["candidate"] == evidence["expected_candidate"]
    assert sentinel.read_text(encoding="utf-8") == "authoritative preimage\n"
    assert unit_artifact_sha256(sentinel.parent) == old_digest
    assert not list(driver.promotion_attempt_root.glob("*"))


def test_passing_gate_refuses_to_overwrite_same_name_artifact_preimage(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    _seed_green_artifact(repo, "prior-unit", "2026-08-01T00:00:00Z")
    _seed_green_artifact(
        repo, "unit-a", "2026-08-02T00:00:00Z", canonical=False
    )
    sentinel = repo / "research/decomp/port-units/unit-a/KEEP-SENTINEL"
    sentinel.write_text("do not replace\n", encoding="utf-8")
    before = unit_artifact_sha256(sentinel.parent)
    git_calls = []

    def fake_build(workdir, exports, extra=None):
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    def fake_link(workdir, c_files, exports, allowed_extra):
        (workdir / "assembly.wasm").write_bytes(b"\x00asm")
        return True, ""

    driver = _driver(
        repo,
        journal=FakeJournal(),
        git_runner=lambda *args: git_calls.append(args) or _completed(0),
        build_runner=fake_build,
        assembly_link_runner=fake_link,
        assembly_smoke_runner=lambda wasm: (True, "ASSEMBLY_SMOKE_OK"),
    )
    assert driver.run() == EXIT_PROGRESSED
    record = _state(repo)["units"]["unit-a"]
    assert record["status"] == "red_retryable"
    assert record["last_stage"] == "artifact-install"
    assert sentinel.read_text(encoding="utf-8") == "do not replace\n"
    assert unit_artifact_sha256(sentinel.parent) == before
    assert git_calls == []
    assert not list(driver.promotion_attempt_root.glob("*"))


def test_post_state_cleanup_failure_is_finished_on_restart_and_unowned_paths_survive(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    _seed_green_artifact(repo, "prior-unit", "2026-08-01T00:00:00Z")

    def fake_build(workdir, exports, extra=None):
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    journal = FakeJournal()
    driver = _driver(
        repo,
        journal=journal,
        build_runner=fake_build,
        assembly_link_runner=lambda *args: (True, ""),
        assembly_smoke_runner=lambda wasm: (True, "ASSEMBLY_SMOKE_OK"),
    )

    def fail_cleanup(_attempt_dir):
        raise OSError("simulated locked attempt")

    driver._cleanup_promotion_attempt = fail_cleanup
    assert driver.run() == EXIT_STOPPED
    assert _state(repo)["units"]["unit-a"]["status"] == "green"
    assert (repo / "research/decomp/port-units/unit-a").is_dir()
    owned = [path for path in driver.promotion_attempt_root.iterdir() if path.is_dir()]
    assert len(owned) == 1
    assert (owned[0] / ".promotion-attempt.json").is_file()
    marker = json.loads((owned[0] / ".promotion-attempt.json").read_text())
    assert marker["phase"] == "state-saved"
    unowned = driver.promotion_attempt_root / "do-not-touch"
    unowned.mkdir()
    (unowned / "sentinel").write_text("keep", encoding="utf-8")

    restarted = _driver(repo, journal=journal)
    restarted._validate_or_adopt_prepared_commit = lambda *args, **kwargs: "abc123"
    assert restarted._reconcile_orphan_promotion_attempts() is True
    assert unowned.is_dir() and (unowned / "sentinel").read_text() == "keep"
    assert not owned[0].exists()
    assert not list(restarted.promotion_quarantine_root.glob("*"))


def test_restart_rolls_back_crash_window_install_before_quarantine(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    driver = _driver(repo, journal=FakeJournal())
    workdir = tmp_path / "candidate-source"
    workdir.mkdir()
    (workdir / "unit.c").write_text("int zz_test_(void) { return 1; }\n")
    (workdir / "gnt4_shim.h").write_text("/* shim */\n")
    (workdir / "unit.wasm").write_bytes(b"\x00asm")
    (workdir / "oracle.log").write_text("PASS\n")
    destination = driver.artifact_root / "unit-a"
    transaction = driver._create_promotion_attempt(
        name="unit-a",
        attempt=1,
        workdir=workdir,
        provenance={
            "unit": "unit-a",
            "generated_at": "2026-08-21T00:00:00Z",
            "exported_functions": ["zz_test_"],
            "allowed_extra_imports": [],
            "tier": "oracle_green",
        },
        destination=destination,
    )
    attempt_dir = transaction.attempt_dir
    candidate = transaction.candidate
    driver._update_promotion_marker(attempt_dir, phase="installing")
    assert driver._install_promotion_candidate(candidate, destination) == "installed"
    assert destination.is_dir() and not candidate.directory.exists()

    restarted = _driver(repo, journal=FakeJournal())
    assert restarted._reconcile_orphan_promotion_attempts() is True
    assert not destination.exists()
    quarantined = list(restarted.promotion_quarantine_root.iterdir())
    assert len(quarantined) == 1
    restored = quarantined[0] / "candidate"
    assert restored.is_dir()
    assert unit_artifact_sha256(restored) == candidate.sha256


def test_failed_gate_leaves_real_product_head_and_bare_remote_unchanged(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    _seed_green_artifact(repo, "prior-unit", "2026-08-01T00:00:00Z")
    remote = tmp_path / "origin.git"

    def git(cwd, *args, check=True):
        completed = subprocess.run(
            ["git", *args], cwd=cwd, capture_output=True, text=True
        )
        if check:
            assert completed.returncode == 0, completed.stdout + completed.stderr
        return completed

    git(tmp_path, "init", "--bare", str(remote))
    git(repo, "init")
    git(repo, "config", "user.email", "port-test@example.invalid")
    git(repo, "config", "user.name", "Port Test")
    git(repo, "branch", "-M", "main")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "baseline")
    git(repo, "remote", "add", "origin", str(remote))
    git(repo, "push", "-u", "origin", "main")
    head_before = git(repo, "rev-parse", "HEAD").stdout.strip()
    remote_before = git(
        tmp_path, "--git-dir", str(remote), "rev-parse", "refs/heads/main"
    ).stdout.strip()

    def fake_build(workdir, exports, extra=None):
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    driver = _driver(
        repo,
        journal=FakeJournal(),
        git_runner=None,
        build_runner=fake_build,
        assembly_link_runner=lambda *args: (False, "link conflict"),
    )
    assert driver.run() == EXIT_PROGRESSED
    assert git(repo, "rev-parse", "HEAD").stdout.strip() == head_before
    assert (
        git(tmp_path, "--git-dir", str(remote), "rev-parse", "refs/heads/main")
        .stdout.strip()
        == remote_before
    )
    assert git(repo, "ls-remote", "origin", "refs/heads/port-staging").stdout == ""


@pytest.mark.parametrize(
    "crash_phase",
    ["install", "registry", "local_commit", "push", "checkpoint", "state_save"],
)
def test_promotion_transaction_recovers_each_phase_with_real_remote(
    tmp_path, monkeypatch, crash_phase
):
    """Every recorded phase converges without a rebuild or a second commit.

    Before the local commit, restart restores the exact artifact/registry
    preimages.  From the prepared commit onward, restart publishes and settles
    that exact SHA, including crashes after a successful remote update.
    """
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    _seed_green_artifact(repo, "prior-unit", "2026-08-01T00:00:00Z")
    remote = tmp_path / "origin.git"

    def git(cwd, *args, check=True):
        completed = subprocess.run(
            ["git", *args], cwd=cwd, capture_output=True, text=True
        )
        if check:
            assert completed.returncode == 0, completed.stdout + completed.stderr
        return completed

    git(tmp_path, "init", "--bare", str(remote))
    git(repo, "init")
    git(repo, "config", "user.email", "port-test@example.invalid")
    git(repo, "config", "user.name", "Port Test")
    git(repo, "branch", "-M", "main")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "baseline")
    git(repo, "remote", "add", "origin", str(remote))
    git(repo, "push", "-u", "origin", "main")
    baseline = git(repo, "rev-parse", "HEAD").stdout.strip()

    def fake_build(workdir, exports, extra=None):
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    def fake_link(workdir, c_files, exports, allowed_extra):
        (workdir / "assembly.wasm").write_bytes(b"\x00asm")
        return True, ""

    journal = FakeJournal()
    driver = _driver(
        repo,
        journal=journal,
        git_runner=None,
        build_runner=fake_build,
        assembly_link_runner=fake_link,
        assembly_smoke_runner=lambda wasm: (True, "ASSEMBLY_SMOKE_OK"),
    )
    crashed = {"done": False}

    def crash_once(phase, transaction):
        if phase == crash_phase and not crashed["done"]:
            crashed["done"] = True
            raise KeyboardInterrupt(f"fault after {phase}")

    driver._promotion_phase_boundary = crash_once
    with pytest.raises(KeyboardInterrupt, match=f"fault after {crash_phase}"):
        driver.run()

    state = driver._load_state()
    restarted = _driver(repo, journal=journal, git_runner=None)
    assert restarted._reconcile_orphan_promotion_attempts(state) is True
    assert not list(restarted.promotion_attempt_root.glob("*"))

    local_head = git(repo, "rev-parse", "HEAD").stdout.strip()
    remote_result = git(
        repo, "ls-remote", "origin", "refs/heads/port-staging", check=False
    )
    if crash_phase in {"install", "registry"}:
        assert local_head == baseline
        assert remote_result.stdout == ""
        assert not (repo / "research/decomp/port-units/unit-a").exists()
        assert not restarted.registry_path.exists()
        assert state["units"]["unit-a"]["status"] != "green"
        assert len(list(restarted.promotion_quarantine_root.iterdir())) == 1
        return

    remote_sha = remote_result.stdout.split()[0]
    assert local_head != baseline
    assert remote_sha == local_head
    assert git(repo, "rev-list", "--count", f"{baseline}..HEAD").stdout.strip() == "1"
    record = state["units"]["unit-a"]
    assert record["status"] == "green"
    assert record["commit"] == local_head
    assert record["pushed"] is True
    artifact = repo / "research/decomp/port-units/unit-a"
    assert unit_artifact_sha256(artifact) == record["candidate_sha256"]
    green_transitions = [
        checkpoint["transition"]
        for checkpoint in journal.checkpoints
        if checkpoint.get("transition") is not None
        and checkpoint["transition"].extra.get("promotion_transaction_id")
    ]
    assert len(green_transitions) == 1
    assert green_transitions[0].product_commit == local_head
    assert (
        green_transitions[0].extra["promotion_transaction_id"]
        == record["promotion_transaction_id"]
    )
    assert (
        green_transitions[0].extra["transition_id"]
        == record["promotion_transition_id"]
    )


@pytest.mark.parametrize("failure", ["push", "checkpoint", "state_save"])
def test_promotion_operation_failure_restarts_to_exact_prepared_sha(
    tmp_path, monkeypatch, failure
):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    _seed_green_artifact(repo, "prior-unit", "2026-08-01T00:00:00Z")
    remote = tmp_path / "origin.git"

    def git(cwd, *args, check=True):
        completed = subprocess.run(
            ["git", *args], cwd=cwd, capture_output=True, text=True
        )
        if check:
            assert completed.returncode == 0, completed.stdout + completed.stderr
        return completed

    git(tmp_path, "init", "--bare", str(remote))
    git(repo, "init")
    git(repo, "config", "user.email", "port-test@example.invalid")
    git(repo, "config", "user.name", "Port Test")
    git(repo, "branch", "-M", "main")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "baseline")
    git(repo, "remote", "add", "origin", str(remote))
    git(repo, "push", "-u", "origin", "main")
    baseline = git(repo, "rev-parse", "HEAD").stdout.strip()

    class FailOnceJournal(FakeJournal):
        failed = False

        def checkpoint(self, **kwargs):
            transition = kwargs.get("transition")
            if (
                failure == "checkpoint"
                and transition is not None
                and transition.extra.get("promotion_transaction_id")
                and not self.failed
            ):
                self.failed = True
                return {"recorded": False, "detail": "injected checkpoint failure"}
            return super().checkpoint(**kwargs)

    journal = FailOnceJournal()

    def fake_build(workdir, exports, extra=None):
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    def fake_link(workdir, c_files, exports, allowed_extra):
        (workdir / "assembly.wasm").write_bytes(b"\x00asm")
        return True, ""

    driver = _driver(
        repo,
        journal=journal,
        git_runner=None,
        build_runner=fake_build,
        assembly_link_runner=fake_link,
        assembly_smoke_runner=lambda wasm: (True, "ASSEMBLY_SMOKE_OK"),
    )
    if failure == "push":
        driver._push_product_sha = lambda sha: subprocess.CompletedProcess(
            ["git", "push"], 1, "", "injected push failure"
        )
    if failure == "state_save":
        real_save = driver._save_state
        failed = {"done": False}

        def fail_green_save(state):
            record = state.get("units", {}).get("unit-a", {})
            if record.get("status") == "green" and not failed["done"]:
                failed["done"] = True
                raise OSError("injected canonical state failure")
            real_save(state)

        driver._save_state = fail_green_save

    assert driver.run() == EXIT_STOPPED
    attempts = list(driver.promotion_attempt_root.glob("*"))
    assert len(attempts) == 1
    prepared = json.loads(
        (attempts[0] / ".promotion-attempt.json").read_text()
    )["prepared_commit"]
    assert git(repo, "rev-parse", "HEAD").stdout.strip() == prepared

    state = driver._load_state()
    restarted = _driver(repo, journal=journal, git_runner=None)
    assert restarted._reconcile_orphan_promotion_attempts(state) is True
    assert not list(restarted.promotion_attempt_root.glob("*"))
    remote_sha = git(
        repo, "ls-remote", "origin", "refs/heads/port-staging"
    ).stdout.split()[0]
    assert remote_sha == prepared
    assert git(repo, "rev-list", "--count", f"{baseline}..HEAD").stdout.strip() == "1"
    record = state["units"]["unit-a"]
    assert record["status"] == "green"
    assert record["commit"] == prepared
    transitions = [
        item["transition"]
        for item in journal.checkpoints
        if item.get("transition") is not None
        and item["transition"].extra.get("promotion_transaction_id")
    ]
    assert len(transitions) == 1
    assert transitions[0].product_commit == prepared
    assert transitions[0].extra["transition_id"] == record["promotion_transition_id"]


def test_branch_only_green_receipt_prevents_replay_after_checkpoint_crash(
    tmp_path, monkeypatch
):
    """A branch commit is a durable receipt even when the local append failed."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    _seed_green_artifact(repo, "prior-unit", "2026-08-01T00:00:00Z")
    remote = tmp_path / "origin.git"

    def git(cwd, *args, check=True):
        completed = subprocess.run(
            ["git", *args], cwd=cwd, capture_output=True, text=True
        )
        if check:
            assert completed.returncode == 0, completed.stdout + completed.stderr
        return completed

    git(tmp_path, "init", "--bare", str(remote))
    git(repo, "init")
    git(repo, "config", "user.email", "port-test@example.invalid")
    git(repo, "config", "user.name", "Port Test")
    git(repo, "branch", "-M", "main")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "baseline")
    git(repo, "remote", "add", "origin", str(remote))
    git(repo, "push", "-u", "origin", "main")
    baseline = git(repo, "rev-parse", "HEAD").stdout.strip()
    run_root = repo / "research/decomp/generated/finish-game-port"
    progress_worktree = tmp_path / "progress-worktree"
    journal = ProgressJournal(
        repo,
        run_root=run_root,
        worktree=progress_worktree,
        run_id="original-journal-run",
        enable_push=False,
    )
    real_append = journal._append_local_event

    def fail_green_local_append(record):
        if record.get("extra", {}).get("promotion_transaction_id"):
            raise OSError("injected local journal append failure")
        real_append(record)

    journal._append_local_event = fail_green_local_append

    def fake_build(workdir, exports, extra=None):
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    def fake_link(workdir, c_files, exports, allowed_extra):
        (workdir / "assembly.wasm").write_bytes(b"\x00asm")
        return True, ""

    driver = _driver(
        repo,
        journal=journal,
        git_runner=None,
        build_runner=fake_build,
        assembly_link_runner=fake_link,
        assembly_smoke_runner=lambda wasm: (True, "ASSEMBLY_SMOKE_OK"),
    )

    def crash_after_durable_checkpoint(phase, transaction):
        if phase == "checkpoint_durable":
            raise KeyboardInterrupt("crash after branch-only checkpoint")

    driver._promotion_phase_boundary = crash_after_durable_checkpoint
    with pytest.raises(KeyboardInterrupt, match="branch-only checkpoint"):
        driver.run()

    attempts = list(driver.promotion_attempt_root.glob("*"))
    assert len(attempts) == 1
    marker = json.loads((attempts[0] / ".promotion-attempt.json").read_text())
    assert marker["phase"] == "checkpointing"
    transition_id = marker["transition_id"]
    assert not journal.transition_receipt(transition_id)["local"]
    assert journal.transition_receipt(transition_id)["branch"]

    state = driver._load_state()
    restarted_journal = ProgressJournal(
        repo,
        run_root=run_root,
        worktree=progress_worktree,
        run_id="restart-journal-run",
        enable_push=False,
    )
    restarted = _driver(repo, journal=restarted_journal, git_runner=None)
    assert restarted._reconcile_orphan_promotion_attempts(state) is True
    assert restarted._reconcile_orphan_promotion_attempts(state) is True
    assert not list(restarted.promotion_attempt_root.glob("*"))

    branch_events = git(
        repo,
        "show",
        f"refs/heads/port-progress:{PROGRESS_DIR}/events.jsonl",
    ).stdout.splitlines()
    matching_events = [
        json.loads(line)
        for line in branch_events
        if json.loads(line).get("extra", {}).get("transition_id") == transition_id
    ]
    assert len(matching_events) == 1
    green_commits = [
        subject
        for subject in git(
            repo, "log", "--format=%s", "refs/heads/port-progress"
        ).stdout.splitlines()
        if subject.startswith("progress: unit-a green")
    ]
    assert len(green_commits) == 1
    product_head = git(repo, "rev-parse", "HEAD").stdout.strip()
    remote_head = git(
        repo, "ls-remote", "origin", "refs/heads/port-staging"
    ).stdout.split()[0]
    assert product_head == remote_head
    assert git(repo, "rev-list", "--count", f"{baseline}..HEAD").stdout.strip() == "1"
    record = state["units"]["unit-a"]
    assert record["status"] == "green"
    assert record["commit"] == product_head
    assert record["promotion_transition_id"] == transition_id


def test_assembly_failure_stops_if_required_journal_checkpoint_raises(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    _seed_green_artifact(repo, "prior-unit", "2026-08-01T00:00:00Z")

    class ExplodingJournal(FakeJournal):
        def checkpoint(self, **kwargs):
            raise RuntimeError("journal unavailable")

    def fake_build(workdir, exports, extra=None):
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    driver = _driver(
        repo,
        journal=ExplodingJournal(),
        build_runner=fake_build,
        assembly_link_runner=lambda *args: (False, "link conflict"),
    )
    assert driver.run() == EXIT_STOPPED
    record = _state(repo)["units"]["unit-a"]
    assert record["status"] == "porting"
    assert "assembly_gate" not in record
    events = (driver.run_root / "events.jsonl").read_text(encoding="utf-8")
    assert '"wasm_unit_journal_blocked"' in events
    assert '"wasm_unit_green"' not in events
    assert not list(driver.promotion_attempt_root.glob("*"))


def test_green_checkpoint_uses_the_same_projected_record_saved_canonically(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    journal = FakeJournal()

    def fake_build(workdir, exports, extra=None):
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    driver = _driver(repo, journal=journal, build_runner=fake_build)
    assert driver.run() == EXIT_NO_WORK
    transition_checkpoint = next(
        checkpoint
        for checkpoint in journal.checkpoints
        if checkpoint["transition"] is not None
    )
    journal_record = transition_checkpoint["units"]["unit-a"]
    canonical_record = _state(repo)["units"]["unit-a"]
    assert journal_record == canonical_record
    assert journal_record["status"] == "green"
    assert journal_record["commit"] == "abc123"
    assert transition_checkpoint["transition"].product_commit == "abc123"


def test_assembly_gate_internal_fault_fails_closed(tmp_path, monkeypatch):
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
    assert driver.run() == EXIT_PROGRESSED
    state = json.loads(
        (repo / "research/decomp/generated/finish-game-port/wasm-units-state.json").read_text()
    )
    assert state["units"]["unit-a"]["status"] == "red_retryable"
    assert state["units"]["unit-a"]["last_stage"] == "assembly"
    assert not (repo / "research/decomp/port-units/unit-a").exists()
    events = (
        repo / "research/decomp/generated/finish-game-port/events.jsonl"
    ).read_text()
    assert '"assembly_gate_error"' in events
    assert '"wasm_unit_green"' not in events


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


def test_assembly_gate_ledger_never_touches_git(tmp_path, monkeypatch):
    """Gate evidence is local journal/ledger data, never a product commit.

    The only git commit/push in a passing run belongs to the promoted artifact,
    and both happen after T2b succeeds.
    """
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    _seed_green_artifact(repo, "prior-unit", "2026-08-01T00:00:00Z")
    git_calls = []
    remote_sha = ["base0000"]

    def fake_git(*args):
        git_calls.append(args)
        if args[0] == "rev-parse":
            return _completed(0, "deadbeef\n")
        if args[0] == "ls-remote":
            return _completed(0, f"{remote_sha[0]}\trefs/heads/port-staging\n")
        if args[0] == "push":
            remote_sha[0] = "deadbeef"
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
    assert not [
        args
        for args in git_calls
        if "assembly-gate.json" in " ".join(map(str, args))
    ]


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
    assert git_calls == []

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
    assert git_calls == []
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
    """The green unit's product push must be the explicit interim refspec
    `push origin <sha>:refs/heads/port-staging` (owner-ordered, pending the
    topology design): local lineage unchanged, origin/main receives
    nothing, never a bare `git push`."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    git_calls = []
    remote_sha = ["base0000"]

    def fake_git(*args):
        git_calls.append(args)
        if args[0] == "rev-parse":
            return _completed(0, "deadbeef\n")
        if args[0] == "ls-remote":
            return _completed(0, f"{remote_sha[0]}\trefs/heads/port-staging\n")
        if args[0] == "push":
            remote_sha[0] = "deadbeef"
        return _completed(0)

    def fake_build(workdir, exports, extra=None):
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    driver = _driver(repo, git_runner=fake_git, build_runner=fake_build)
    assert driver.run() == EXIT_NO_WORK
    pushes = [args for args in git_calls if args[0] == "push"]
    assert pushes == [("push", "origin", "deadbeef:refs/heads/port-staging")]
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
        ("push", "origin", "deadbeef:refs/heads/port-staging")
    ]
    for args in git_calls:
        if args[0] in ("add", "commit"):
            assert "--" in args, f"unpathspec'd git call: {args}"
