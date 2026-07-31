import json
from pathlib import Path

import pytest

from src.state_machine_probe import (
    GhidraProgramUnavailable,
    StateMachineProbe,
    decode_be_pointer,
    parse_dispatcher_metadata,
)


DISPATCHER = """
void FUN_800925a0(int param_1)
{
  (*(code *)(&PTR_FUN_802db478)[*(char *)(param_1 + 0x581)])();
  return;
}
"""


class FakeGhidra:
    def __init__(self, *, no_program: bool = False):
        self.no_program = no_program
        self.functions = {
            0x800925A0: "FUN_800925a0",
            0x800925DC: "FUN_800925dc",
            0x8009260C: "FUN_8009260c",
            0x8009263C: "FUN_8009263c",
            0x8009268C: "FUN_8009268c",
            0x800927C0: "FUN_800927c0",
        }
        self.decompiles = {
            "0x800925a0": DISPATCHER,
            "0x800925dc": (
                "void FUN_800925dc(int param_1) {\n"
                "  *(short *)(param_1 + 0x18da) = *(short *)(param_1 + 0x18da) >> 1;\n"
                "  *(char *)(param_1 + 0x581) = 2;\n"
                "}\n"
            ),
            "0x8009260c": (
                "void FUN_8009260c(int param_1) {\n"
                "  *(char *)(param_1 + 0x581) = *(char *)(param_1 + 0x581) + 1;\n"
                "}\n"
            ),
            "0x8009263c": "void FUN_8009263c(int param_1) { return; }\n",
            "0x8009268c": (
                "void FUN_8009268c(int param_1) {\n"
                "  *(char *)(param_1 + 0x540) = *(char *)(param_1 + 0x540) + 1;\n"
                "}\n"
            ),
            "0x800927c0": (
                "void FUN_800927c0(int param_1) {\n"
                "  *(char *)(param_1 + 0x540) = 0;\n"
                "}\n"
            ),
        }

    def function_bundle(self, address: str) -> dict:
        if self.no_program:
            raise GhidraProgramUnavailable("No program loaded")
        return {
            "bundle_schema": 1,
            "identity": {"address": address, "name": self.functions[int(address, 16)]},
            "decompiler": {"c": self.decompiles[address]},
            "calls": [],
            "normalized_disassembly": [],
            "normalized_pcode": [],
            "fingerprints": {},
        }

    def decompile(self, address: str) -> str:
        return self.decompiles[address]

    def list_functions(self) -> dict[int, str]:
        if self.no_program:
            raise GhidraProgramUnavailable("No program loaded")
        return self.functions

    def list_defined_data(self) -> dict[int, str]:
        return {0x802DB478: "PTR_FUN_802db478"}

    def read_bytes(self, address: str, length: int) -> bytes:
        assert address == "0x802db478"
        values = (0x800925DC, 0x8009260C, 0x8009263C, 0)
        return b"".join(value.to_bytes(4, "big") for value in values)[:length]

    def xrefs_to(self, address: str) -> list[str]:
        return [f"XREF to {address} from 0x800925a0"]

    def xrefs_from(self, address: str) -> list[str]:
        return [f"XREF from {address}"]


def test_decode_be_pointer_requires_exact_gg4e_width():
    assert decode_be_pointer(bytes.fromhex("800925dc")) == 0x800925DC
    with pytest.raises(ValueError, match="exactly four bytes"):
        decode_be_pointer(b"\x80\x09")


def test_parse_dispatcher_metadata_recovers_table_and_signed_byte_field():
    metadata = parse_dispatcher_metadata(DISPATCHER)
    assert metadata.table_address == "0x802db478"
    assert metadata.state_field.offset == "0x581"
    assert metadata.state_field.width == 1
    assert metadata.state_field.signedness == "signed"


def test_parse_dispatcher_metadata_accepts_named_pointer_symbol():
    metadata = parse_dispatcher_metadata(
        "(*(code *)(&PTR_zz_0091e34__802db448)"
        "[*(char *)(param_1 + 0x581)])();"
    )
    assert metadata.table_address == "0x802db448"


def test_probe_walks_big_endian_table_and_cites_handler_transitions(tmp_path: Path):
    output = tmp_path / "probe.json"
    artifact = StateMachineProbe(FakeGhidra()).probe(
        root_address="0x800925a0",
        max_handlers=8,
        output=output,
    )

    assert artifact.status == "ready"
    assert artifact.kind == "state_dispatcher"
    assert artifact.state_field is not None
    assert artifact.state_field.offset == "0x581"
    table = artifact.function_pointer_tables[0]
    assert table.pointer_size == 4
    assert table.endianness == "big"
    assert [entry.handler_address for entry in table.entries] == [
        "0x800925dc",
        "0x8009260c",
        "0x8009263c",
    ]
    assert [handler.address for handler in artifact.handlers] == [
        "0x800925dc",
        "0x8009260c",
        "0x8009263c",
    ]
    assert any(transition.to_value == "2" for transition in artifact.transitions)
    assert any("+ 1" in transition.expression for transition in artifact.transitions)
    assert all(record.source for record in artifact.evidence)

    serialized = json.loads(output.read_text(encoding="utf-8"))
    assert serialized["unit_id"] == "state-machine-800925a0"
    assert serialized["function_pointer_tables"][0]["entries"][0]["raw_bytes"] == "800925dc"


def test_probe_reports_missing_live_program_without_writing_ready_artifact(tmp_path: Path):
    output = tmp_path / "blocked.json"
    artifact = StateMachineProbe(FakeGhidra(no_program=True)).probe(
        root_address="0x800925a0",
        output=output,
    )

    assert artifact.status == "blocked_no_program"
    assert artifact.unknowns == ["No program loaded"]
    assert json.loads(output.read_text(encoding="utf-8"))["status"] == "blocked_no_program"


def test_explicit_table_override_supports_dispatchers_with_incomplete_decompile(tmp_path: Path):
    client = FakeGhidra()
    client.decompiles["0x800925a0"] = "void FUN_800925a0(int param_1) { /* indirect */ }\n"
    artifact = StateMachineProbe(client).probe(
        root_address="0x800925a0",
        table_address="0x802db478",
        state_offset="0x581",
        state_width=1,
        max_handlers=8,
        output=tmp_path / "explicit.json",
    )

    assert artifact.status == "ready"
    assert len(artifact.handlers) == 3


def test_probe_uses_ghidra_labels_to_split_adjacent_dispatch_tables(tmp_path: Path):
    client = FakeGhidra()
    client.list_defined_data = lambda: {  # type: ignore[method-assign]
        0x802DB478: "PTR_FUN_802db478",
        0x802DB48C: "PTR_FUN_802db48c",
    }
    client.decompiles["0x8009263c"] = """
void FUN_8009263c(int param_1)
{
  (*(code *)(&PTR_FUN_802db48c)[*(char *)(param_1 + 0x540)])();
}
"""

    outer_values = (
        0x800925DC,
        0x800925DC,
        0x8009260C,
        0x800925DC,
        0x8009263C,
        0x8009268C,
        0x800927C0,
        0,
    )

    def read_bytes(address: str, length: int) -> bytes:
        if address == "0x802db478":
            values = outer_values
        elif address == "0x802db48c":
            values = (0x8009268C, 0x800927C0, 0)
        else:
            raise AssertionError(address)
        return b"".join(value.to_bytes(4, "big") for value in values)[:length]

    client.read_bytes = read_bytes  # type: ignore[method-assign]
    artifact = StateMachineProbe(client).probe(
        root_address="0x800925a0",
        max_handlers=16,
        output=tmp_path / "adjacent.json",
    )

    assert [table.address for table in artifact.function_pointer_tables] == [
        "0x802db478",
        "0x802db48c",
    ]
    assert len(artifact.function_pointer_tables[0].entries) == 5
    assert artifact.function_pointer_tables[1].state_field is not None
    assert artifact.function_pointer_tables[1].state_field.offset == "0x540"
    assert [handler.address for handler in artifact.handlers].count("0x800925dc") == 1
    assert any(
        transition.state_offset == "0x540" and transition.to_value == "0"
        for transition in artifact.transitions
    )
