import json
from pathlib import Path

import pytest

from src.port_scheduler import (
    PortScheduler,
    discover_analysis_session,
    dependency_order,
    exact_groups,
    extract_direct_calls,
    fingerprint_instructions,
    normalize_instruction_lines,
    parse_function_line,
    platform_exclusion_reason,
)
from src.port_source_loop import SourceLoopResult


def fake_repo(tmp_path: Path) -> Path:
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "finish-game-port-poc.mjs").write_text("// fixture\n", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"scripts":{}}\n', encoding="utf-8")
    return tmp_path


class FakeGhidra:
    def list_functions(self, offset=0, limit=200):
        assert offset == 0
        return [
            "[Total: 2] [Showing: 1-2]",
            "FUN_80001000 at 80001000",
            "FUN_80002000 at 80002000",
        ]

    def disassemble_function(self, address):
        base = address[2:]
        return [
            f"{base}: li r3,1",
            f"{int(base, 16) + 4:08x}: bl 0x80003000",
            f"{int(base, 16) + 8:08x}: blr",
        ]

    def get_function_by_address(self, address):
        return f"Function: FUN_{address[2:]} at {address[2:]}"

    def get_xrefs_to(self, address):
        return [{"from_address": "0x80004000"}]

    def get_xrefs_from(self, address):
        return [{"to_address": "0x80003000"}]

    def decompile_function_by_address(self, address):
        return f"void sibling_{address[-4:]}(void) {{}}"


class OfflineGhidra(FakeGhidra):
    def disassemble_function(self, address):
        return ["Request failed: connection actively refused"]


class EmptyGhidra(FakeGhidra):
    def list_functions(self, offset=0, limit=200):
        return ["No program loaded"]


def test_function_parsing_fingerprints_and_calls_are_address_stable():
    first = [
        "80001000: li r3,1 ; comment",
        "80001004: bl 0x80003000",
    ]
    second = [
        "80002000: li   r3,1",
        "80002004: bl 0x80003000",
    ]

    assert parse_function_line("FUN_80001000 at 80001000") == {
        "name": "FUN_80001000",
        "address": "0x80001000",
    }
    assert normalize_instruction_lines(first) == ["li r3,1", "bl 0x80003000"]
    assert fingerprint_instructions(first) == fingerprint_instructions(second)
    assert extract_direct_calls(first, "0x80001000") == ["0x80003000"]


def test_discovers_most_complete_saved_analysis(tmp_path):
    sessions = tmp_path / "analysis_sessions"
    small = sessions / "small" / "session.json"
    large = sessions / "large" / "session.json"
    small.parent.mkdir(parents=True)
    large.parent.mkdir(parents=True)
    small.write_text("{}", encoding="utf-8")
    large.write_text('{"analyzed_functions":{"80001000":{"address":"80001000"}}}', encoding="utf-8")
    assert discover_analysis_session(tmp_path) == large


def test_platform_exclusion_is_conservative_and_pre_model():
    assert platform_exclusion_reason(
        {"identity": {"name": "__check_pad3", "thunk": False}},
        {"behavior_summary": "startup check"},
    )
    assert platform_exclusion_reason(
        {"identity": {"name": "FUN_80001000", "thunk": False}},
        {"behavior_summary": "MetroTRK debug monitor initialization"},
    )
    assert platform_exclusion_reason(
        {"identity": {"name": "stepCombat", "thunk": False}},
        {"behavior_summary": "updates player combat state"},
    ) is None


def test_exact_groups_preserve_alias_addresses_and_dependency_order():
    groups = exact_groups(
        [
            {
                "address": "0x80001000",
                "fingerprint": "a" * 64,
                "dependencies": ["0x80003000"],
            },
            {
                "address": "0x80002000",
                "fingerprint": "a" * 64,
                "dependencies": ["0x80003000"],
            },
            {
                "address": "0x80003000",
                "fingerprint": "b" * 64,
                "dependencies": [],
            },
        ]
    )

    alias_group = next(group for group in groups if group["fingerprint"] == "a" * 64)
    dependency_group = next(group for group in groups if group["fingerprint"] == "b" * 64)
    order = dependency_order(groups)

    assert alias_group["canonical_address"] == "0x80001000"
    assert alias_group["member_addresses"] == ["0x80001000", "0x80002000"]
    assert order.index(dependency_group["id"]) < order.index(alias_group["id"])


def test_scheduler_zero_work_limit_only_checkpoints_inventory(tmp_path):
    scheduler = PortScheduler(
        repo_root=fake_repo(tmp_path),
        ghidra=FakeGhidra(),
        llm_factory=lambda: (_ for _ in ()).throw(AssertionError("LLM should not run")),
        max_units=0,
    )

    exit_code = scheduler.run()
    manifest = json.loads(scheduler.manifest_path.read_text())
    state = json.loads(scheduler.state_path.read_text())

    assert exit_code == 3
    assert manifest["inventory_complete"] is True
    assert manifest["bundles_complete"] is False
    assert manifest["groups_complete"] is False
    assert len(manifest["functions"]) == 2
    assert len(manifest["groups"]) == 0
    assert state["scope"]["kind"] == "whole_program"
    assert state["status"] == "partial"
    assert state["stages"]["inventory"]["status"] == "passed"
    assert state["stages"]["groups"]["status"] == "passed"
    assert state["stages"]["units"]["status"] == "partial"


def test_scheduler_sends_first_bundle_to_qwen_before_extracting_the_rest(tmp_path):
    scheduler = PortScheduler(
        repo_root=fake_repo(tmp_path),
        ghidra=FakeGhidra(),
        llm_factory=lambda: (_ for _ in ()).throw(AssertionError("replaced below")),
        max_units=1,
    )
    seen = []

    class FakeSourceLoop:
        def run(self, *, address, aliases, bundle, analysis_context):
            seen.append(
                    {
                        "address": address,
                        "aliases": aliases,
                        "bundle_address": bundle["identity"]["address"],
                        "saved_name": analysis_context["saved_session_analysis"]["new_name"],
                        "caller_count": len(analysis_context["sibling_functions"]["callers"]),
                    }
            )
            return SourceLoopResult(passed=True, attempts=1, action="exclude")

    session = tmp_path / "session.json"
    session.write_text(
        json.dumps(
            {
                "analyzed_functions": {
                    "80001000": {
                        "address": "80001000",
                        "new_name": "stepGameplay",
                        "behavior_summary": "updates player gameplay",
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    scheduler.session_path = session
    scheduler._session_functions = {
        "0x80001000": {
            "address": "80001000",
            "new_name": "stepGameplay",
            "behavior_summary": "updates player gameplay",
        }
    }
    scheduler.source_loop = FakeSourceLoop()

    exit_code = scheduler.run()
    manifest = json.loads(scheduler.manifest_path.read_text())

    assert exit_code == 3
    assert seen == [
        {
            "address": "0x80001000",
            "aliases": ["0x80001000"],
            "bundle_address": "0x80001000",
            "saved_name": "stepGameplay",
            "caller_count": 1,
        }
    ]
    assert manifest["functions"]["0x80001000"]["port_status"] == "excluded"
    assert manifest["functions"]["0x80002000"]["status"] == "discovered"
    assert manifest["bundles_complete"] is False


def test_scheduler_does_not_turn_service_outage_into_bundle_failures(tmp_path):
    scheduler = PortScheduler(
        repo_root=fake_repo(tmp_path),
        ghidra=OfflineGhidra(),
        llm_factory=lambda: (_ for _ in ()).throw(AssertionError("LLM should not run")),
    )

    with pytest.raises(ConnectionError):
        scheduler.run()

    manifest = json.loads(scheduler.manifest_path.read_text())
    state = json.loads(scheduler.state_path.read_text())
    first = manifest["functions"]["0x80001000"]
    assert first["status"] == "discovered"
    assert first["bundle_attempts"] == 1
    assert state["status"] == "failed"


def test_empty_ghidra_recovers_inventory_and_existing_bundles_from_export(tmp_path):
    root = fake_repo(tmp_path)
    export_root = root / "research" / "decomp" / "ghidra-export"
    export_root.mkdir(parents=True)
    (export_root / "chunk_0000.c").write_text(
        "// ==== 80001000  first_function ====\n\n"
        "// ==== 80002000  second_function ====\n",
        encoding="utf-8",
    )
    scheduler = PortScheduler(
        repo_root=root,
        ghidra=EmptyGhidra(),
        llm_factory=lambda: (_ for _ in ()).throw(AssertionError("LLM should not run")),
        max_units=0,
    )
    scheduler.bundle_root.mkdir(parents=True, exist_ok=True)
    (scheduler.bundle_root / "80001000.bundle.json").write_text(
        json.dumps(
            {
                "bundle_schema": 1,
                "identity": {"address": "80001000", "thunk": False},
                "calls": ["80003000"],
                "fingerprints": {"normalized_pcode": "a" * 64},
            }
        ),
        encoding="utf-8",
    )

    assert scheduler.run() == 3

    manifest = json.loads(scheduler.manifest_path.read_text())
    assert manifest["program"]["function_count"] == 2
    assert manifest["program"]["inventory_source"] == "ghidra-export checkpoint"
    assert manifest["functions"]["0x80001000"]["status"] == "bundled"
    assert manifest["functions"]["0x80001000"]["dependencies"] == ["0x80003000"]
    assert manifest["functions"]["0x80002000"]["status"] == "discovered"
