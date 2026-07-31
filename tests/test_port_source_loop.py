from pathlib import Path

import pytest

from src.port_source_loop import (
    BrowserSourcePatch,
    SequentialSourcePortLoop,
    _json_payload,
    _safe_source_path,
)


def test_json_payload_accepts_tool_json_and_fence():
    payload = {"summary": "done", "files": [{"path": "apps/game/src/x.ts", "content": "x"}]}
    encoded = '{"summary":"done","files":[{"path":"apps/game/src/x.ts","content":"x"}]}'
    assert BrowserSourcePatch.model_validate(_json_payload(encoded))
    assert _json_payload(f"```json\n{encoded}\n```") == payload


def test_safe_source_path_rejects_escape(tmp_path: Path):
    with pytest.raises(ValueError):
        _safe_source_path(tmp_path, "../outside.ts")
    assert _safe_source_path(tmp_path, "apps/game/src/port.ts") == (
        tmp_path / "apps/game/src/port.ts"
    ).resolve()


def test_sequential_loop_writes_verifies_and_checkpoints(tmp_path: Path):
    source = tmp_path / "apps/game/src"
    source.mkdir(parents=True)
    (source / "existing.ts").write_text("export const oldValue = 1;\n", encoding="utf-8")

    class FakeLLM:
        def generate_structured(self, **_kwargs):
            return (
                '{"summary":"port","files":['
                '{"path":"apps/game/src/existing.ts","content":"export const oldValue = 2;"},'
                '{"path":"apps/game/src/port.ts","content":"export const ported = true;"}]}',
                "tool_call",
            )

    gates = []
    commits = []
    loop = SequentialSourcePortLoop(
        repo_root=tmp_path,
        run_root=tmp_path / ".run",
        llm_factory=lambda: (FakeLLM(), "fake", "qwen"),
        verify_runner=lambda _root, command: (gates.append(command) is None, "pass"),
        git_checkpointer=lambda _root, address, summary: (
            commits.append((address, summary)) or "deadbeef"
        ),
    )
    result = loop.run(
        address="0x80000000",
        aliases=["0x80000000"],
        bundle={"identity": {"name": "testPort"}, "decompiler": {"c": "void testPort(void) {}"}},
    )
    assert result.passed
    assert result.checkpoint == "deadbeef"
    assert (source / "port.ts").read_text(encoding="utf-8") == "export const ported = true;\n"
    original_manifest = tmp_path / ".run/source-checkpoints/80000000/original-source.json"
    assert original_manifest.is_file()
    assert (
        tmp_path
        / ".run/source-checkpoints/80000000/original-source/apps/game/src/existing.ts"
    ).read_text(encoding="utf-8") == "export const oldValue = 1;\n"
    assert len(gates) == 6
    assert commits == [("0x80000000", "port")]


def test_sequential_loop_feeds_gate_error_back_to_qwen(tmp_path: Path):
    (tmp_path / "apps/game/src").mkdir(parents=True)
    prompts = []

    class RepairingLLM:
        def generate_structured(self, **kwargs):
            prompts.append(kwargs["prompt"])
            if prompts and len(prompts) == 2:
                assert not (tmp_path / "apps/game/src/port.ts").exists()
            value = "broken" if len(prompts) == 1 else "fixed"
            return (
                '{"summary":"repair","files":[{"path":"apps/game/src/port.ts",'
                f'"content":"export const value = \\"{value}\\";'
                '"}]}',
                "tool_call",
            )

    gate_calls = 0

    def verify(_root, _command):
        nonlocal gate_calls
        gate_calls += 1
        return (False, "TS2322 first failure") if gate_calls == 1 else (True, "pass")

    result = SequentialSourcePortLoop(
        repo_root=tmp_path,
        run_root=tmp_path / ".run",
        llm_factory=lambda: (RepairingLLM(), "fake", "qwen"),
        verify_runner=verify,
        git_checkpointer=lambda *_args: "feedface",
    ).run(
        address="0x80000004",
        aliases=["0x80000004"],
        bundle={"identity": {"name": "repairPort"}, "decompiler": {"c": "void repairPort(void) {}"}},
        analysis_context={
            "saved_session_analysis": {"new_name": "repairGameplay", "behavior_summary": "gameplay"},
            "sibling_functions": {"callers": [], "callees": []},
            "research_corpus": {"exact": "known actor state", "semantic": ""},
        },
    )

    assert result.passed
    assert result.attempts == 2
    assert "TS2322 first failure" in prompts[1]
    assert "repairGameplay" in prompts[0]
    assert "known actor state" in prompts[0]
    assert '"fixed"' in (tmp_path / "apps/game/src/port.ts").read_text(encoding="utf-8")
