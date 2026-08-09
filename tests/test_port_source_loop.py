from pathlib import Path

import pytest

from src.custom_api_client import APIResponseError
from src.port_source_loop import (
    BrowserSourcePatch,
    ReadBrowserSource,
    SearchBrowserSource,
    SOURCE_CONTEXT_TOTAL_CHAR_LIMIT,
    SequentialSourcePortLoop,
    _json_payload,
    _next_attempt_number,
    _rank_source_context,
    _read_browser_source,
    _safe_source_path,
    _search_browser_source,
    _semantic_integration_check,
    _specific_symbol_reachability_check,
    _source_excerpt,
)


def test_attempt_numbers_are_monotonic_across_restarted_source_loops(tmp_path: Path):
    checkpoint = tmp_path / "source-checkpoints/80001000"
    (checkpoint / "attempt-01").mkdir(parents=True)
    (checkpoint / "attempt-03").mkdir()

    assert _next_attempt_number(checkpoint) == 4


def test_specific_symbol_reachability_rejects_unrelated_live_export(tmp_path: Path):
    package = tmp_path / "packages/combat/src"
    app = tmp_path / "apps/game/src"
    package.mkdir(parents=True)
    app.mkdir(parents=True)
    (package / "runtime.ts").write_text(
        "export function alreadyUsed() { return 1; }\n"
        "export function translatedEntry() { return 2; }\n",
        encoding="utf-8",
    )
    (app / "main.ts").write_text(
        'import { alreadyUsed } from "../../../packages/combat/src/runtime";\n'
        "alreadyUsed();\n",
        encoding="utf-8",
    )

    passed, detail = _specific_symbol_reachability_check(
        tmp_path,
        {"packages/combat/src/runtime.ts"},
        ["translatedEntry"],
    )

    assert passed is False
    assert "translatedEntry" in detail


def test_specific_symbol_reachability_accepts_executable_call_site(tmp_path: Path):
    package = tmp_path / "packages/combat/src"
    app = tmp_path / "apps/game/src"
    package.mkdir(parents=True)
    app.mkdir(parents=True)
    (package / "runtime.ts").write_text(
        "export function translatedEntry() { return 2; }\n",
        encoding="utf-8",
    )
    (app / "main.ts").write_text(
        'import { translatedEntry } from "../../../packages/combat/src/runtime";\n'
        "translatedEntry();\n",
        encoding="utf-8",
    )

    passed, detail = _specific_symbol_reachability_check(
        tmp_path,
        {"packages/combat/src/runtime.ts"},
        ["translatedEntry"],
    )

    assert passed is True
    assert "translatedEntry" in detail


def reachability_fixture(tmp_path: Path, app_main_ts: str) -> tuple[bool, str]:
    package = tmp_path / "packages/combat/src"
    app = tmp_path / "apps/game/src"
    package.mkdir(parents=True)
    app.mkdir(parents=True)
    (package / "runtime.ts").write_text(
        "export function translatedEntry() { return 2; }\n", encoding="utf-8"
    )
    (app / "main.ts").write_text(app_main_ts, encoding="utf-8")
    return _specific_symbol_reachability_check(
        tmp_path, {"packages/combat/src/runtime.ts"}, ["translatedEntry"]
    )


def test_specific_symbol_reachability_rejects_multiline_import_only(tmp_path: Path):
    # The 2026-08-07 challenge_menu_objects false positive: symbol present only
    # inside a multi-line import block (battleScene.ts:21-26 shape).
    passed, detail = reachability_fixture(
        tmp_path,
        "import {\n"
        "  translatedEntry,\n"
        "  somethingElse,\n"
        '} from "../../../packages/combat/src/runtime";\n'
        "somethingElse();\n",
    )
    assert passed is False
    assert "translatedEntry" in detail


def test_specific_symbol_reachability_accepts_call_after_multiline_import(tmp_path: Path):
    passed, _ = reachability_fixture(
        tmp_path,
        "import {\n"
        "  translatedEntry,\n"
        '} from "../../../packages/combat/src/runtime";\n'
        "translatedEntry();\n",
    )
    assert passed is True


def test_specific_symbol_reachability_rejects_block_comment_mention(tmp_path: Path):
    # Commented-out wiring plans must not count as production use sites, even
    # when the continuation line has no leading "*".
    passed, detail = reachability_fixture(
        tmp_path,
        "/*\n"
        "TODO: wire translatedEntry() into the scene update loop\n"
        "*/\n"
        "export const scene = 1;\n",
    )
    assert passed is False
    assert "translatedEntry" in detail


def test_specific_symbol_reachability_rejects_definition_only(tmp_path: Path):
    # A unit that defines its entry symbol in the app tree but never calls it
    # is still unreachable.
    passed, detail = reachability_fixture(
        tmp_path,
        "export function translatedEntry() { return 3; }\n",
    )
    assert passed is False
    assert "translatedEntry" in detail


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


def test_source_context_excludes_node_modules_and_obeys_total_budget(tmp_path: Path):
    source = tmp_path / "packages/combat/src"
    duplicate = tmp_path / "packages/missions/node_modules/@gf/combat/src"
    generated = tmp_path / "packages/combat/dist"
    source.mkdir(parents=True)
    duplicate.mkdir(parents=True)
    generated.mkdir(parents=True)
    for index in range(4):
        content = f"export const runtimeMemory{index} = " + repr("x" * 70000) + ";\n"
        (source / f"context-{index}.ts").write_text(content, encoding="utf-8")
        (duplicate / f"context-{index}.ts").write_text(content, encoding="utf-8")
        (generated / f"context-{index}.d.ts").write_text(content, encoding="utf-8")

    bundle = {
        "identity": {"name": "runtimeMemory"},
        "decompiler": {"c": "void runtimeMemory(void) {}"},
    }
    ranked = _rank_source_context(tmp_path, bundle)
    loop = SequentialSourcePortLoop(
        repo_root=tmp_path,
        run_root=tmp_path / ".run",
        llm_factory=lambda: (None, "fake", "qwen"),
    )
    prompt = loop._prompt(bundle, aliases=[], failure=None, attempt=1)
    source_context = prompt.split("Relevant current browser source excerpts:\n", 1)[1]

    assert ranked
    assert all("node_modules" not in path.parts for path in ranked)
    assert all("dist" not in path.parts for path in ranked)
    assert "node_modules" not in source_context
    assert "/dist/" not in source_context
    assert len(source_context) <= SOURCE_CONTEXT_TOTAL_CHAR_LIMIT + 1000


def test_source_context_uses_matching_window_instead_of_large_file_prefix(tmp_path: Path):
    source = tmp_path / "packages/combat/src"
    source.mkdir(parents=True)
    filler = "\n".join(f"export const filler{index} = {index};" for index in range(2000))
    marker = "export function stepRareMechanic(actor: RareMechanicActor) { return actor.phase; }"
    target = source / "combat.ts"
    target.write_text(f"{filler}\n{marker}\n", encoding="utf-8")

    excerpt = _source_excerpt(target, {"raremechanic"}, 4000)

    assert marker in excerpt
    assert "filler0 =" not in excerpt
    assert len(excerpt) <= 4000


def test_advisory_session_text_does_not_steer_source_ranking(tmp_path: Path):
    source = tmp_path / "packages/combat/src"
    source.mkdir(parents=True)
    (source / "real.ts").write_text(
        "export function stepRareMechanic() { return true; }\n",
        encoding="utf-8",
    )
    (source / "hallucinated.ts").write_text(
        "export function playstationVideoConfiguration() { return false; }\n",
        encoding="utf-8",
    )
    bundle = {
        "identity": {"name": "stepRareMechanic"},
        "decompiler": {"c": "void stepRareMechanic(void) {}"},
        "analysis_context": {
            "saved_session_analysis": {
                "behavior_summary": "PlayStation video configuration",
            }
        },
    }

    ranked = _rank_source_context(tmp_path, bundle)

    assert ranked[0].name == "real.ts"
    assert all(path.name != "hallucinated.ts" for path in ranked)


def test_bounded_workspace_read_and_search_only_expose_allowed_source(tmp_path: Path):
    source = tmp_path / "packages/combat/src"
    source.mkdir(parents=True)
    target = source / "prng.ts"
    target.write_text(
        "let hi = 0;\nlet lo = 0;\nexport function stepPrng() { return lo; }\n",
        encoding="utf-8",
    )

    read_result = _json_payload(
        _read_browser_source(
            tmp_path,
            ReadBrowserSource(path="packages/combat/src/prng.ts"),
        )
    )
    search_result = _json_payload(
        _search_browser_source(tmp_path, SearchBrowserSource(query="stepPrng"))
    )

    assert read_result["content"].startswith("let hi = 0;")
    assert read_result["requested_path"] == "packages/combat/src/prng.ts"
    assert read_result["total_lines"] == 3
    assert search_result["results"] == [
        {
            "path": "packages/combat/src/prng.ts",
            "line": 3,
            "text": "export function stepPrng() { return lo; }",
        }
    ]
    with pytest.raises(ValueError):
        _read_browser_source(tmp_path, ReadBrowserSource(path="../secret.ts"))


def test_workspace_read_resolves_typescript_source_from_runtime_js_specifier(tmp_path: Path):
    source = tmp_path / "packages/combat/src"
    source.mkdir(parents=True)
    (source / "prng.ts").write_text("export const seed = 195;\n", encoding="utf-8")

    result = _json_payload(
        _read_browser_source(
            tmp_path,
            ReadBrowserSource(path="packages/combat/src/prng.js"),
        )
    )

    assert result["requested_path"] == "packages/combat/src/prng.js"
    assert result["path"] == "packages/combat/src/prng.ts"
    assert "seed = 195" in result["content"]


def test_semantic_integration_rejects_reexport_only_package_code(tmp_path: Path):
    combat = tmp_path / "packages/combat/src"
    game = tmp_path / "apps/game/src"
    combat.mkdir(parents=True)
    game.mkdir(parents=True)
    (combat / "prng.ts").write_text(
        "export function stepPrng() { return 1; }\n",
        encoding="utf-8",
    )
    (combat / "combat.ts").write_text(
        'export { stepPrng } from "./prng.js";\n',
        encoding="utf-8",
    )
    (game / "main.ts").write_text("export const game = true;\n", encoding="utf-8")

    passed, failure = _semantic_integration_check(
        tmp_path,
        {"packages/combat/src/prng.ts", "packages/combat/src/combat.ts"},
    )

    assert not passed
    assert "not reachable" in failure

    (game / "main.ts").write_text(
        'import { stepPrng } from "../../../packages/combat/src/combat.js";\n'
        "export const game = stepPrng();\n",
        encoding="utf-8",
    )
    passed, detail = _semantic_integration_check(
        tmp_path,
        {"packages/combat/src/prng.ts", "packages/combat/src/combat.ts"},
    )

    assert passed
    assert "main.ts" in detail


def test_sequential_loop_writes_verifies_and_checkpoints(tmp_path: Path):
    source = tmp_path / "apps/game/src"
    source.mkdir(parents=True)
    (source / "existing.ts").write_text("export const oldValue = 1;\n", encoding="utf-8")

    class FakeLLM:
        def generate_structured(self, **_kwargs):
            return (
                '{"summary":"port","files":['
                '{"path":"apps/game/src/existing.ts","edits":['
                '{"find":"export const oldValue = 1;","replace":"export const oldValue = 2;"}]},'
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
        git_checkpointer=lambda _root, address, summary, _files: (
            commits.append((address, summary)) or "deadbeef"
        ),
        integration_checker=lambda *_args: (True, "reachable"),
    )
    result = loop.run(
        address="0x80000000",
        aliases=["0x80000000"],
        bundle={"identity": {"name": "testPort"}, "decompiler": {"c": "void testPort(void) {}"}},
    )
    assert result.passed
    assert result.checkpoint == "deadbeef"
    assert (source / "existing.ts").read_text(encoding="utf-8") == "export const oldValue = 2;\n"
    assert (source / "port.ts").read_text(encoding="utf-8") == "export const ported = true;\n"
    original_manifest = tmp_path / ".run/source-checkpoints/80000000/original-source.json"
    assert original_manifest.is_file()
    assert (
        tmp_path
        / ".run/source-checkpoints/80000000/original-source/apps/game/src/existing.ts"
    ).read_text(encoding="utf-8") == "export const oldValue = 1;\n"
    assert len(gates) == 6
    assert commits == [("0x80000000", "port")]


def test_combat_touching_patch_adds_family_audit_gates(tmp_path: Path):
    source = tmp_path / "packages/combat/src"
    source.mkdir(parents=True)

    class FakeLLM:
        def generate_structured(self, **_kwargs):
            return (
                '{"summary":"combat port","files":['
                '{"path":"packages/combat/src/challenge.ts",'
                '"content":"export const challengePorted = true;"}]}',
                "tool_call",
            )

    gates = []
    loop = SequentialSourcePortLoop(
        repo_root=tmp_path,
        run_root=tmp_path / ".run",
        llm_factory=lambda: (FakeLLM(), "fake", "qwen"),
        verify_runner=lambda _root, command: (gates.append(command) is None, "pass"),
        git_checkpointer=lambda *_args: "deadbeef",
        integration_checker=lambda *_args: (True, "reachable"),
    )
    result = loop.run(
        address="0x80195d8c",
        aliases=["0x80195d8c"],
        bundle={"identity": {"name": "challenge"}, "decompiler": {"c": "void f(void) {}"}},
    )

    assert result.passed
    assert len(gates) == 8
    assert gates[-2:] == [
        ("pnpm", "audit:family-state-machines"),
        ("pnpm", "audit:move-wiring"),
    ]


def test_prompt_probe_validates_response_without_writes_gates_or_git(tmp_path: Path):
    source = tmp_path / "apps/game/src"
    source.mkdir(parents=True)
    existing = source / "existing.ts"
    existing.write_text("export const value = 1;\n", encoding="utf-8")

    class FakeLLM:
        def generate_structured(self, **_kwargs):
            return (
                '{"summary":"probe","files":[{"path":"apps/game/src/existing.ts",'
                '"edits":[{"find":"value = 1","replace":"value = 2"}]}]}',
                "tool_call",
            )

    loop = SequentialSourcePortLoop(
        repo_root=tmp_path,
        run_root=tmp_path / ".run",
        llm_factory=lambda: (FakeLLM(), "fake", "qwen"),
        verify_runner=lambda *_args: (_ for _ in ()).throw(AssertionError("gates must not run")),
        git_checkpointer=lambda *_args: (_ for _ in ()).throw(AssertionError("git must not run")),
    )
    result = loop.run(
        address="0x80000008",
        aliases=["0x80000008"],
        bundle={"identity": {"name": "probe"}, "decompiler": {"c": "void probe(void) {}"}},
        dry_run=True,
    )

    assert result.passed
    assert result.dry_run
    assert result.summary == "probe"
    assert result.files == ["apps/game/src/existing.ts"]
    assert existing.read_text(encoding="utf-8") == "export const value = 1;\n"


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
        integration_checker=lambda *_args: (True, "reachable"),
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
    assert "Advisory saved-session analysis:" in prompts[0]
    assert "For an existing file, return ordered exact find/replace edits." in prompts[0]
    assert "Relevant current browser source excerpts:" in prompts[0]
    assert '"fixed"' in (tmp_path / "apps/game/src/port.ts").read_text(encoding="utf-8")


def test_protocol_failure_injects_exact_current_target_on_retry(tmp_path: Path):
    source = tmp_path / "packages/combat/src"
    source.mkdir(parents=True)
    target = source / "prng.ts"
    current = (
        "let lo = 0;\n"
        "let hi = 0;\n\n"
        "export function stepPrng(): number {\n"
        "  return lo;\n"
        "}\n"
    )
    target.write_text(current, encoding="utf-8")
    prompts = []

    class RepairingLLM:
        def generate_structured(self, **kwargs):
            prompts.append(kwargs["prompt"])
            if len(prompts) == 1:
                return (
                    '{"summary":"replace","files":[{"path":"packages/combat/src/prng.ts",'
                    '"content":"export function stepPrng() { return 1; }"}]}',
                    "tool_call",
                )
            assert current in kwargs["prompt"]
            return (
                '{"summary":"exact edit","files":[{"path":"packages/combat/src/prng.ts",'
                '"edits":[{"find":"  return lo;","replace":"  return (lo + 1) & 0xff;"}]}]}',
                "tool_call",
            )

    result = SequentialSourcePortLoop(
        repo_root=tmp_path,
        run_root=tmp_path / ".run",
        llm_factory=lambda: (RepairingLLM(), "fake", "qwen"),
        verify_runner=lambda *_args: (True, "pass"),
        git_checkpointer=lambda *_args: "c0ffee",
        integration_checker=lambda *_args: (True, "reachable"),
    ).run(
        address="0x80005630",
        aliases=["0x80005630"],
        bundle={"identity": {"name": "updateRandomState"}, "decompiler": {"c": "void f(void) {}"}},
    )

    assert result.passed
    assert result.attempts == 2
    assert "complete replacement of existing file" in prompts[1]
    assert "Required current browser source:" in prompts[1]
    assert "return (lo + 1)" in target.read_text(encoding="utf-8")


def test_adjacent_integrated_files_are_complete_context_for_next_unit(tmp_path: Path):
    source = tmp_path / "packages/combat/src"
    source.mkdir(parents=True)
    prompts = []
    responses = [
        (
            '{"summary":"first","files":[{"path":"packages/combat/src/prng.ts",'
            '"content":"export const adjacentSeed = 195;"}]}',
            "tool_call",
        ),
        (
            '{"summary":"second","files":[{"path":"packages/combat/src/consumer.ts",'
            '"content":"export const consumesAdjacentSeed = true;"}]}',
            "tool_call",
        ),
    ]

    class SequentialLLM:
        def generate_structured(self, **kwargs):
            prompts.append(kwargs["prompt"])
            return responses[len(prompts) - 1]

    loop = SequentialSourcePortLoop(
        repo_root=tmp_path,
        run_root=tmp_path / ".run",
        llm_factory=lambda: (SequentialLLM(), "fake", "qwen"),
        verify_runner=lambda *_args: (True, "pass"),
        git_checkpointer=lambda *_args: "facade",
        integration_checker=lambda *_args: (True, "reachable"),
    )
    first = loop.run(
        address="0x800055fc",
        aliases=["0x800055fc"],
        bundle={"identity": {"name": "stepPrng"}, "decompiler": {"c": "void f(void) {}"}},
    )
    second = loop.run(
        address="0x80005630",
        aliases=["0x80005630"],
        bundle={"identity": {"name": "usePrng"}, "decompiler": {"c": "void g(void) {}"}},
    )

    assert first.passed and second.passed
    assert "--- packages/combat/src/prng.ts ---" in prompts[1]
    assert "export const adjacentSeed = 195;" in prompts[1]


def test_qwen_can_read_then_submit_exact_workspace_edit(tmp_path: Path):
    source = tmp_path / "packages/combat/src"
    source.mkdir(parents=True)
    target = source / "prng.ts"
    target.write_text("export const seed = 0;\n", encoding="utf-8")

    class ToolUsingLLM:
        def __init__(self):
            self.calls = 0
            self.last_response_metadata = {}
            self.initial_messages = None

        def generate(self, **kwargs):
            self.calls += 1
            assert kwargs["tool_choice"] == "auto"
            assert {tool["function"]["name"] for tool in kwargs["tools"]} == {
                "read_browser_source",
                "search_browser_source",
                "submit_browser_source_patch",
            }
            if self.calls == 1:
                self.initial_messages = kwargs["messages"][:2]
                self.last_response_metadata = {"tool_name": "read_browser_source"}
                return '{"path":"packages/combat/src/prng.ts"}'
            assert kwargs["messages"][:2] == self.initial_messages
            assert kwargs["messages"][-1]["role"] == "tool"
            assert "export const seed = 0;" in kwargs["messages"][-1]["content"]
            self.last_response_metadata = {"tool_name": "submit_browser_source_patch"}
            return (
                '{"summary":"tool edit","files":[{"path":"packages/combat/src/prng.ts",'
                '"edits":[{"find":"seed = 0","replace":"seed = 195"}]}]}'
            )

    llm = ToolUsingLLM()
    result = SequentialSourcePortLoop(
        repo_root=tmp_path,
        run_root=tmp_path / ".run",
        llm_factory=lambda: (llm, "fake", "qwen"),
        verify_runner=lambda *_args: (True, "pass"),
        git_checkpointer=lambda *_args: "bada55",
        integration_checker=lambda *_args: (True, "reachable"),
    ).run(
        address="0x800055e0",
        aliases=["0x800055e0"],
        bundle={"identity": {"name": "seedPrng"}, "decompiler": {"c": "void f(void) {}"}},
    )

    assert result.passed
    assert llm.calls == 2
    assert target.read_text(encoding="utf-8") == "export const seed = 195;\n"


def test_workspace_tool_error_stays_in_same_conversation(tmp_path: Path):
    (tmp_path / "packages/combat/src").mkdir(parents=True)

    class RecoveringLLM:
        def __init__(self):
            self.calls = 0
            self.last_response_metadata = {}

        def generate(self, **kwargs):
            self.calls += 1
            if self.calls == 1:
                self.last_response_metadata = {"tool_name": "read_browser_source"}
                return '{"path":"packages/combat/src/missing.js"}'
            assert kwargs["messages"][-1]["role"] == "tool"
            assert '"recoverable": true' in kwargs["messages"][-1]["content"]
            assert "does not exist" in kwargs["messages"][-1]["content"]
            self.last_response_metadata = {"tool_name": "submit_browser_source_patch"}
            return (
                '{"summary":"recovered","files":[{"path":"packages/combat/src/recovered.ts",'
                '"content":"export const recovered = true;"}]}'
            )

    llm = RecoveringLLM()
    result = SequentialSourcePortLoop(
        repo_root=tmp_path,
        run_root=tmp_path / ".run",
        llm_factory=lambda: (llm, "fake", "qwen"),
        verify_runner=lambda *_args: (True, "pass"),
        git_checkpointer=lambda *_args: "decaf",
        integration_checker=lambda *_args: (True, "reachable"),
    ).run(
        address="0x80005630",
        aliases=["0x80005630"],
        bundle={"identity": {"name": "recover"}, "decompiler": {"c": "void f(void) {}"}},
    )

    assert result.passed
    assert llm.calls == 2
    assert (tmp_path / "packages/combat/src/recovered.ts").is_file()


def test_model_cannot_exclude_scheduler_assigned_source_unit():
    with pytest.raises(ValueError):
        BrowserSourcePatch.model_validate(
            {"summary": "runtime", "action": "exclude", "files": []}
        )


def test_sequential_loop_does_not_treat_protocol_failure_as_source_repair(tmp_path: Path):
    calls = 0

    class BrokenLLM:
        def generate_structured(self, **_kwargs):
            nonlocal calls
            calls += 1
            raise APIResponseError("empty stream")

    result = SequentialSourcePortLoop(
        repo_root=tmp_path,
        run_root=tmp_path / ".run",
        llm_factory=lambda: (BrokenLLM(), "fake", "qwen"),
    ).run(
        address="0x80003340",
        aliases=["0x80003340"],
        bundle={"identity": {"name": "__init_data"}, "decompiler": {"c": "void f(void) {}"}},
    )

    assert not result.passed
    assert result.attempts == 1
    assert calls == 1
    assert result.error == "APIResponseError: empty stream"


def test_sequential_loop_pauses_generic_provider_failure_after_one_request(tmp_path: Path):
    calls = 0

    class OfflineLLM:
        def generate_structured(self, **_kwargs):
            nonlocal calls
            calls += 1
            raise ConnectionError("connection refused")

    result = SequentialSourcePortLoop(
        repo_root=tmp_path,
        run_root=tmp_path / ".run",
        llm_factory=lambda: (OfflineLLM(), "fake", "qwen"),
    ).run(
        address="0x80004440",
        aliases=["0x80004440"],
        bundle={"identity": {"name": "offline"}, "decompiler": {"c": "void f(void) {}"}},
    )

    assert not result.passed
    assert result.attempts == 1
    assert calls == 1
    assert result.error == "ConnectionError: connection refused"


def test_closest_source_files_ranks_real_near_misses(tmp_path: Path):
    # The 2026-08-08 failure shape: model invents challengeFlowManager.ts while
    # challengeFlowVm.ts exists. The rejection must name the real candidates.
    from src.port_source_loop import _closest_source_files

    ui = tmp_path / "apps/game/src/ui"
    ui.mkdir(parents=True)
    (ui / "challengeFlowVm.ts").write_text("export const x = 1;\n", encoding="utf-8")
    (ui / "challengeFlowTables.generated.ts").write_text("", encoding="utf-8")
    (ui / "hudRenderer.ts").write_text("export const y = 2;\n", encoding="utf-8")
    (tmp_path / "packages/combat/src").mkdir(parents=True)
    (tmp_path / "packages/combat/src/runtime.ts").write_text("", encoding="utf-8")

    candidates = _closest_source_files(tmp_path, "apps/game/src/ui/challengeFlowManager.ts")

    assert candidates[0] == "apps/game/src/ui/challengeFlowVm.ts"
    assert all(not c.endswith(".generated.ts") for c in candidates)


def test_session_grounding_reaches_prompt_for_address_keyed_corpus(tmp_path: Path):
    # Audit drift item 4: the chunk workflow sends {address: {name, summary}}
    # and the old top-level field filter reduced it to {} in every port prompt.
    loop = SequentialSourcePortLoop(
        repo_root=tmp_path,
        run_root=tmp_path / ".run",
        llm_factory=lambda: (None, "fake", "qwen"),
    )
    bundle = {"identity": {"name": "fn"}, "decompiler": {"c": "void fn(void) {}"}}

    prompt = loop._prompt(
        bundle,
        aliases=[],
        failure=None,
        attempt=1,
        analysis_context={
            "saved_session_analysis": {
                "0x80001000": {
                    "name": "dispatch_x",
                    "summary": "Drives the X state machine.",
                }
            }
        },
    )

    assert "Drives the X state machine." in prompt
    assert "dispatch_x" in prompt
