"""Backend-neutral evidence collection for one Ghidra function."""

from __future__ import annotations

import hashlib
import json
import re
import struct
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from src.port_artifact import (
    EvidenceBundle,
    EvidenceRecord,
    FunctionIdentity,
    ProgramIdentity,
    normalize_address,
)


ADDRESS_IN_TEXT_RE = re.compile(r"(?:0x)?([0-9a-fA-F]{8})")
SYMBOL_ADDRESS_RE = re.compile(r"(?:DAT|FLOAT|PTR|LAB)_([0-9a-fA-F]{8})")
DIRECT_CALL_RE = re.compile(r"\b(?:bl|call)\b[^0-9a-fA-F]*(?:0x)?([0-9a-fA-F]{8})\b", re.IGNORECASE)
FUNCTION_SYMBOL_RE = re.compile(r"\b(?:FUN_([0-9a-fA-F]{8})|zz_([0-9a-fA-F]{7})_)\b")


class CollectedFunction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    program: ProgramIdentity
    function: FunctionIdentity
    evidence: EvidenceBundle
    collection_metrics: dict[str, Any] = Field(default_factory=dict)


def _safe_collect(unavailable: list[str], category: str, callback, default):
    try:
        value = callback()
    except Exception as error:
        unavailable.append(f"{category}: {type(error).__name__}: {error}")
        return default
    if value is None or value == "" or value == []:
        unavailable.append(f"{category}: unavailable")
        return default
    if isinstance(value, str) and value.startswith(("Error", "Request failed")):
        unavailable.append(f"{category}: {value}")
        return default
    return value


def _first_address(text: str) -> str | None:
    match = ADDRESS_IN_TEXT_RE.search(text or "")
    return normalize_address(match.group(1)) if match else None


def _target_address(text: str) -> str | None:
    matches = ADDRESS_IN_TEXT_RE.findall(text or "")
    return normalize_address(matches[-1]) if matches else None


def _decode_big_endian_word(raw_text: str) -> dict[str, Any]:
    pairs = re.findall(r"(?<![0-9a-fA-F])([0-9a-fA-F]{2})(?![0-9a-fA-F])", raw_text)
    raw = bytes.fromhex("".join(pairs[:4])) if len(pairs) >= 4 else b""
    result: dict[str, Any] = {"raw": raw_text}
    if len(raw) == 4:
        result.update(
            {
                "raw_hex": raw.hex(),
                "u32_be": f"0x{struct.unpack('>I', raw)[0]:08x}",
                "s32_be": struct.unpack(">i", raw)[0],
                "f32_be": struct.unpack(">f", raw)[0],
            }
        )
    return result


def collect_function_evidence(
    client,
    address: str | int,
    *,
    session_summary: str | None = None,
    max_callee_decompiles: int = 8,
) -> CollectedFunction:
    function_address = normalize_address(address)
    unavailable: list[str] = []
    records: list[EvidenceRecord] = []
    tool_call_breakdown: dict[str, int] = {}

    def collect(category: str, callback, default):
        tool_call_breakdown[category] = tool_call_breakdown.get(category, 0) + 1
        return _safe_collect(unavailable, category, callback, default)

    program_info = collect(
        "program_metadata",
        client.get_current_program_info,
        {},
    )
    program = ProgramIdentity(
        program_name=str(program_info.get("name", "unknown")),
        sha256=program_info.get("sha256"),
        image_base=program_info.get("image_base", "0x80000000"),
        language=program_info.get("language", "PowerPC:BE:32"),
    )

    metadata = collect(
        "function_metadata",
        lambda: client.get_function_by_address(function_address),
        "",
    )
    if metadata:
        records.append(
            EvidenceRecord(
                id=f"function:{function_address}",
                kind="function_metadata",
                tier="authoritative",
                address=function_address,
                content=metadata,
            )
        )

    named_function = re.search(r"\bFunction:\s+([A-Za-z_][A-Za-z0-9_]*)\s+at\b", str(metadata))
    name_match = named_function or re.search(r"\b(FUN_[0-9a-fA-F]{8})\b", str(metadata))
    current_name = name_match.group(1) if name_match else f"FUN_{function_address[2:]}"
    size_match = re.search(r"\bsize\s*=\s*(0x[0-9a-fA-F]+|\d+)", str(metadata))
    size = int(size_match.group(1), 0) if size_match else None
    if size is None:
        body_match = re.search(r"\bBody:\s*([0-9a-fA-F]{8})\s*-\s*([0-9a-fA-F]{8})", str(metadata))
        if body_match:
            size = int(body_match.group(2), 16) - int(body_match.group(1), 16) + 1

    decompile = collect(
        "decompile",
        lambda: client.decompile_function_by_address(function_address, offset=0, limit=5000),
        "",
    )
    if decompile:
        records.append(
            EvidenceRecord(
                id=f"decompile:{function_address}",
                kind="decompile",
                tier="authoritative",
                address=function_address,
                content=decompile,
                sha256=hashlib.sha256(decompile.encode()).hexdigest(),
            )
        )

    instructions = collect(
        "disassembly",
        lambda: client.disassemble_function(function_address),
        [],
    )
    if isinstance(instructions, str):
        instructions = instructions.splitlines()
    for index, line in enumerate(instructions):
        instruction_address = _first_address(str(line))
        records.append(
            EvidenceRecord(
                id=(
                    f"instruction:{instruction_address}"
                    if instruction_address
                    else f"instruction:{function_address}:unknown-{index}"
                ),
                kind="instruction",
                tier="authoritative",
                address=instruction_address,
                content=str(line),
            )
        )

    callers = collect(
        "callers",
        lambda: client.get_xrefs_to(function_address, offset=0, limit=200),
        [],
    )
    if isinstance(callers, str):
        callers = callers.splitlines()
    callers = [line for line in callers if not str(line).lstrip().startswith("[")]
    for index, line in enumerate(callers):
        caller_address = _first_address(str(line))
        records.append(
            EvidenceRecord(
                id=f"caller:{caller_address or 'unknown'}:{index}",
                kind="caller",
                tier="authoritative",
                address=caller_address,
                content=str(line),
            )
        )

    refs_from = collect(
        "references_from",
        lambda: client.get_xrefs_from(function_address, offset=0, limit=500),
        [],
    )
    if isinstance(refs_from, str):
        refs_from = refs_from.splitlines()
    refs_from = [line for line in refs_from if not str(line).lstrip().startswith("[")]

    callee_addresses: set[str] = set()
    data_addresses: set[str] = set()
    for line in [*instructions, *refs_from]:
        text = str(line)
        direct = DIRECT_CALL_RE.search(text)
        symbols = FUNCTION_SYMBOL_RE.findall(text)
        symbol_targets = {
            normalize_address(full or f"8{short}")
            for full, short in symbols
        }
        target = normalize_address(direct.group(1)) if direct else _target_address(text)
        if target and ("CALL" in text.upper() or direct):
            callee_addresses.add(target)
        elif target and ("DATA" in text.upper() or SYMBOL_ADDRESS_RE.search(text)):
            data_addresses.add(target)
        callee_addresses.update(symbol_targets)

    for full, short in FUNCTION_SYMBOL_RE.findall(decompile):
        callee_addresses.add(normalize_address(full or f"8{short}"))
    for symbol_address in SYMBOL_ADDRESS_RE.findall(decompile):
        data_addresses.add(normalize_address(symbol_address))

    callee_addresses.discard(function_address)
    for callee in sorted(callee_addresses):
        supporting = [line for line in [*instructions, *refs_from] if callee[2:] in str(line).lower()]
        records.append(
            EvidenceRecord(
                id=f"callee:{callee}",
                kind="callee",
                tier="authoritative",
                address=callee,
                content=supporting,
            )
        )
    for callee in sorted(callee_addresses)[:max_callee_decompiles]:
        callee_decompile = collect(
            f"decompile:{callee}",
            lambda value=callee: client.decompile_function_by_address(value, offset=0, limit=1500),
            "",
        )
        if callee_decompile:
            records.append(
                EvidenceRecord(
                    id=f"decompile:{callee}",
                    kind="decompile",
                    tier="authoritative",
                    address=callee,
                    content=callee_decompile,
                    sha256=hashlib.sha256(callee_decompile.encode()).hexdigest(),
                )
            )

    for data_address in sorted(data_addresses):
        raw_text = collect(
            f"raw_bytes:{data_address}",
            lambda value=data_address: client.read_bytes(value, length=4, format="hex"),
            "",
        )
        content = _decode_big_endian_word(str(raw_text)) if raw_text else {"raw": None}
        records.append(
            EvidenceRecord(
                id=f"data:{data_address}",
                kind="raw_bytes",
                tier="authoritative",
                address=data_address,
                content=content,
            )
        )

    for index, line in enumerate(refs_from):
        target = _target_address(str(line))
        if target in callee_addresses or target in data_addresses:
            continue
        records.append(
            EvidenceRecord(
                id=f"data-reference:{target or 'unknown'}:{index}",
                kind="data_reference",
                tier="authoritative",
                address=target,
                content=str(line),
            )
        )

    if session_summary:
        records.append(
            EvidenceRecord(
                id=f"session-summary:{function_address}",
                kind="session_summary",
                tier="advisory",
                address=function_address,
                content=session_summary,
            )
        )

    body_material = decompile + "\n" + "\n".join(str(line) for line in instructions)
    function = FunctionIdentity(
        address=function_address,
        original_name=f"FUN_{function_address[2:]}",
        current_name=current_name,
        size=size,
        body_hash=hashlib.sha256(body_material.encode()).hexdigest() if body_material.strip() else None,
    )
    return CollectedFunction(
        program=program,
        function=function,
        evidence=EvidenceBundle(records=records, unavailable=unavailable),
        collection_metrics={
            "tool_calls": sum(tool_call_breakdown.values()),
            "tool_call_breakdown": tool_call_breakdown,
        },
    )


def collected_function_json(collected: CollectedFunction) -> str:
    return json.dumps(collected.model_dump(mode="json"), indent=2, sort_keys=True)
