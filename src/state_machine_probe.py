"""Read-only GG4E state-machine discovery through the live Ghidra HTTP API."""

from __future__ import annotations

import argparse
import base64
import json
import re
from pathlib import Path
from typing import Any, Literal, Protocol

import requests
from pydantic import BaseModel, ConfigDict, Field

from src.port_workflow import atomic_write_json


class GhidraProgramUnavailable(RuntimeError):
    """Raised when the Ghidra API is alive but no program is active."""


def normalize_address(value: str | int) -> str:
    number = value if isinstance(value, int) else int(str(value).strip(), 16)
    return f"0x{number:08x}"


def decode_be_pointer(raw: bytes) -> int:
    if len(raw) != 4:
        raise ValueError("GG4E pointers must contain exactly four bytes")
    return int.from_bytes(raw, byteorder="big", signed=False)


class StateField(BaseModel):
    offset: str
    width: int = Field(ge=1, le=4)
    signedness: Literal["signed", "unsigned", "unknown"] = "unknown"


class DispatcherMetadata(BaseModel):
    table_address: str | None = None
    state_field: StateField | None = None


TABLE_PATTERN = re.compile(
    r"PTR_[A-Za-z0-9_]*?(?P<address>[0-9a-fA-F]{8})\b"
)
INDEX_PATTERN = re.compile(
    r"\[\s*\*\(\s*(?P<ctype>char|signed char|unsigned char|byte|undefined1|u?int8_t)"
    r"\s*\*\s*\)\s*\(\s*param_\d+\s*\+\s*(?P<offset>0x[0-9a-fA-F]+|\d+)\s*\)\s*\]"
)


def parse_dispatcher_metadata(decompile: str) -> DispatcherMetadata:
    table_match = TABLE_PATTERN.search(decompile)
    index_match = INDEX_PATTERN.search(decompile)
    table_address = normalize_address(table_match.group("address")) if table_match else None
    state_field = None
    if index_match:
        ctype = " ".join(index_match.group("ctype").lower().split())
        signedness: Literal["signed", "unsigned", "unknown"]
        if ctype in {"char", "signed char"}:
            signedness = "signed"
        elif ctype in {"unsigned char", "byte", "uint8_t"}:
            signedness = "unsigned"
        else:
            signedness = "unknown"
        state_field = StateField(
            offset=normalize_address(int(index_match.group("offset"), 0)),
            width=1,
            signedness=signedness,
        )
        state_field.offset = f"0x{int(state_field.offset, 16):x}"
    return DispatcherMetadata(table_address=table_address, state_field=state_field)


class EvidenceRecord(BaseModel):
    kind: str
    source: str
    detail: str
    confidence: Literal["confirmed", "derived", "tentative"] = "confirmed"


class TableEntry(BaseModel):
    index: int
    entry_address: str
    handler_address: str
    function_name: str
    raw_bytes: str


class FunctionPointerTable(BaseModel):
    address: str
    dispatcher_address: str
    state_field: StateField | None = None
    pointer_size: int = 4
    endianness: Literal["big"] = "big"
    entries: list[TableEntry] = Field(default_factory=list)


class HandlerRecord(BaseModel):
    address: str
    name: str
    decompile: str
    callers: list[str] = Field(default_factory=list)
    callees: list[str] = Field(default_factory=list)
    bundle: dict[str, Any] = Field(default_factory=dict)


class TransitionRecord(BaseModel):
    handler_address: str
    state_offset: str
    expression: str
    to_value: str | None = None
    evidence: str
    confidence: Literal["derived"] = "derived"


class StateMachineArtifact(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    schema_version: Literal[1] = Field(default=1, alias="schema")
    status: Literal["ready", "blocked", "blocked_no_program"]
    unit_id: str
    kind: Literal["state_dispatcher", "code_driven_handler", "unknown"]
    root_addresses: list[str]
    state_field: StateField | None = None
    function_pointer_tables: list[FunctionPointerTable] = Field(default_factory=list)
    handlers: list[HandlerRecord] = Field(default_factory=list)
    transitions: list[TransitionRecord] = Field(default_factory=list)
    callers: list[str] = Field(default_factory=list)
    callees: list[str] = Field(default_factory=list)
    global_reads: list[str] = Field(default_factory=list)
    global_writes: list[str] = Field(default_factory=list)
    constants: list[str] = Field(default_factory=list)
    raw_constant_bits: list[str] = Field(default_factory=list)
    update_order: list[str] = Field(default_factory=list)
    existing_destination_code: list[str] = Field(default_factory=list)
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)


class ProbeClient(Protocol):
    def function_bundle(self, address: str) -> dict[str, Any]: ...

    def decompile(self, address: str) -> str: ...

    def list_functions(self) -> dict[int, str]: ...

    def list_defined_data(self) -> dict[int, str]: ...

    def read_bytes(self, address: str, length: int) -> bytes: ...

    def xrefs_to(self, address: str) -> list[str]: ...

    def xrefs_from(self, address: str) -> list[str]: ...


class GhidraHttpProbeClient:
    """Small read-only client with strict live-program preflight semantics."""

    def __init__(self, base_url: str = "http://127.0.0.1:8080", timeout_seconds: int = 30):
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def _get(self, endpoint: str, **params: Any) -> str:
        response = requests.get(
            f"{self.base_url}/{endpoint.lstrip('/')}",
            params=params,
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        text = response.text
        if "No program loaded" in text:
            raise GhidraProgramUnavailable("No program loaded")
        return text

    def function_bundle(self, address: str) -> dict[str, Any]:
        text = self._get("function_bundle", address=normalize_address(address))
        payload = json.loads(text)
        if payload.get("error"):
            error = str(payload["error"])
            if "No program loaded" in error:
                raise GhidraProgramUnavailable("No program loaded")
            raise RuntimeError(error)
        return payload

    def decompile(self, address: str) -> str:
        return self._get(
            "decompile_function",
            address=normalize_address(address),
            offset=0,
            limit=2000,
        )

    def list_functions(self) -> dict[int, str]:
        functions: dict[int, str] = {}
        offset = 0
        page_size = 10_000
        while True:
            lines = self._get("list_functions", offset=offset, limit=page_size).splitlines()
            for line in lines:
                match = re.match(
                    r"^(?P<name>.+?)\s+at\s+(?P<address>[0-9a-fA-F]{8,16})$",
                    line.strip(),
                )
                if match:
                    functions[int(match.group("address"), 16)] = match.group("name").strip()
            if len(lines) < page_size:
                break
            offset += page_size
        if not functions:
            raise RuntimeError("Ghidra returned no parseable functions")
        return functions

    def list_defined_data(self) -> dict[int, str]:
        labels: dict[int, str] = {}
        offset = 0
        page_size = 10_000
        while True:
            lines = self._get("data", offset=offset, limit=page_size).splitlines()
            for line in lines:
                match = re.match(
                    r"^(?P<address>[0-9a-fA-F]{8,16}):\s+"
                    r"(?P<label>.*?)\s+=\s+.*$",
                    line.strip(),
                )
                if match:
                    labels[int(match.group("address"), 16)] = match.group("label").strip()
            if len(lines) < page_size:
                break
            offset += page_size
        return labels

    def read_bytes(self, address: str, length: int) -> bytes:
        encoded = self._get(
            "read_bytes",
            address=normalize_address(address),
            length=length,
            format="raw",
        ).strip()
        try:
            return base64.b64decode(encoded, validate=True)
        except ValueError as error:
            raise RuntimeError(f"Ghidra returned invalid base64 for {address}") from error

    def xrefs_to(self, address: str) -> list[str]:
        return self._get(
            "xrefs_to",
            address=normalize_address(address),
            offset=0,
            limit=500,
        ).splitlines()

    def xrefs_from(self, address: str) -> list[str]:
        return self._get(
            "xrefs_from",
            address=normalize_address(address),
            offset=0,
            limit=500,
        ).splitlines()


ASSIGNMENT_PATTERN_TEMPLATE = (
    r"(?P<statement>\*\(\s*(?:char|signed char|unsigned char|byte|undefined1|u?int8_t)"
    r"\s*\*\s*\)\s*\(\s*param_\d+\s*\+\s*{offset}\s*\)\s*=\s*(?P<expression>[^;]+);)"
)


def extract_transitions(
    handler_address: str,
    decompile: str,
    state_field: StateField | None,
) -> list[TransitionRecord]:
    if state_field is None:
        return []
    offset_value = int(state_field.offset, 16)
    offset_variants = [re.escape(state_field.offset), str(offset_value)]
    pattern = re.compile(
        ASSIGNMENT_PATTERN_TEMPLATE.format(offset=f"(?:{'|'.join(offset_variants)})")
    )
    transitions = []
    for match in pattern.finditer(decompile):
        expression = match.group("expression").strip()
        direct = re.fullmatch(r"(?:0x[0-9a-fA-F]+|\d+)", expression)
        transitions.append(
            TransitionRecord(
                handler_address=handler_address,
                state_offset=state_field.offset,
                expression=expression,
                to_value=expression if direct else None,
                evidence=match.group("statement").strip(),
            )
        )
    return transitions


def _bundle_decompile(bundle: dict[str, Any]) -> str:
    decompiler = bundle.get("decompiler")
    if isinstance(decompiler, dict) and isinstance(decompiler.get("c"), str):
        return decompiler["c"]
    return ""


class StateMachineProbe:
    def __init__(self, client: ProbeClient):
        self.client = client

    @staticmethod
    def _write(output: Path | None, artifact: StateMachineArtifact) -> None:
        if output is not None:
            atomic_write_json(output, artifact.model_dump(mode="json", by_alias=True))

    def _blocked(
        self,
        root: str,
        output: Path | None,
        *,
        status: Literal["blocked", "blocked_no_program"],
        reason: str,
    ) -> StateMachineArtifact:
        artifact = StateMachineArtifact(
            status=status,
            unit_id=f"state-machine-{root.removeprefix('0x')}",
            kind="unknown",
            root_addresses=[root],
            unknowns=[reason],
        )
        self._write(output, artifact)
        return artifact

    def probe(
        self,
        *,
        root_address: str,
        table_address: str | None = None,
        state_offset: str | None = None,
        state_width: int = 1,
        max_handlers: int = 32,
        output: Path | None = None,
    ) -> StateMachineArtifact:
        root = normalize_address(root_address)
        output = output.resolve() if output is not None else None
        try:
            root_bundle = self.client.function_bundle(root)
            root_decompile = _bundle_decompile(root_bundle) or self.client.decompile(root)
            metadata = parse_dispatcher_metadata(root_decompile)
            resolved_table = normalize_address(table_address) if table_address else metadata.table_address
            state_field = metadata.state_field
            if state_offset is not None:
                state_field = StateField(
                    offset=f"0x{int(state_offset, 0):x}",
                    width=state_width,
                    signedness=state_field.signedness if state_field else "unknown",
                )

            evidence = [
                EvidenceRecord(
                    kind="decompile",
                    source=f"decompile:{root}",
                    detail=root_decompile,
                )
            ]
            callers = self.client.xrefs_to(root)
            callees = self.client.xrefs_from(root)
            handlers: list[HandlerRecord] = []
            transitions: list[TransitionRecord] = []
            tables: list[FunctionPointerTable] = []

            if resolved_table:
                function_map = self.client.list_functions()
                data_labels = self.client.list_defined_data()
                known_table_starts = sorted(
                    address
                    for address, label in data_labels.items()
                    if label.startswith("PTR_")
                    and label.lower().endswith(f"{address:08x}")
                )
                handler_records: dict[str, HandlerRecord] = {}
                handler_decompiles: dict[str, str] = {}
                visited_tables: set[str] = set()
                transition_keys: set[tuple[str, str, str]] = set()

                def load_handler(address: str, name: str) -> HandlerRecord:
                    existing = handler_records.get(address)
                    if existing is not None:
                        return existing
                    bundle = self.client.function_bundle(address)
                    decompile = _bundle_decompile(bundle) or self.client.decompile(address)
                    record = HandlerRecord(
                        address=address,
                        name=name,
                        decompile=decompile,
                        callers=self.client.xrefs_to(address),
                        callees=self.client.xrefs_from(address),
                        bundle=bundle,
                    )
                    handler_records[address] = record
                    handler_decompiles[address] = decompile
                    return record

                def walk_table(
                    address: str,
                    dispatcher_address: str,
                    table_state_field: StateField | None,
                ) -> bool:
                    address = normalize_address(address)
                    if address in visited_tables:
                        return True
                    visited_tables.add(address)

                    table_bytes = self.client.read_bytes(address, max_handlers * 4)
                    table_number = int(address, 16)
                    next_table = next(
                        (
                            candidate
                            for candidate in known_table_starts
                            if candidate > table_number
                        ),
                        None,
                    )
                    candidates: list[TableEntry] = []
                    child_dispatch_by_handler: dict[str, DispatcherMetadata] = {}
                    for index in range(min(max_handlers, len(table_bytes) // 4)):
                        entry_number = table_number + index * 4
                        if next_table is not None and entry_number >= next_table:
                            break
                        raw = table_bytes[index * 4 : index * 4 + 4]
                        pointer = decode_be_pointer(raw)
                        name = function_map.get(pointer)
                        if name is None:
                            break
                        handler_address = normalize_address(pointer)
                        candidates.append(
                            TableEntry(
                                index=index,
                                entry_address=normalize_address(table_number + index * 4),
                                handler_address=handler_address,
                                function_name=name,
                                raw_bytes=raw.hex(),
                            )
                        )
                        load_handler(handler_address, name)
                        child_dispatch = parse_dispatcher_metadata(
                            handler_decompiles[handler_address]
                        )
                        if child_dispatch.table_address:
                            child_dispatch_by_handler[handler_address] = child_dispatch

                    if not candidates:
                        return False

                    tables.append(
                        FunctionPointerTable(
                            address=address,
                            dispatcher_address=dispatcher_address,
                            state_field=table_state_field,
                            entries=candidates,
                        )
                    )
                    for entry in candidates:
                        evidence.append(
                            EvidenceRecord(
                                kind="raw_table_entry",
                                source=f"raw:{entry.entry_address}",
                                detail=(
                                    f"{entry.raw_bytes} -> "
                                    f"{entry.handler_address} {entry.function_name}"
                                ),
                            )
                        )
                        for transition in extract_transitions(
                            entry.handler_address,
                            handler_decompiles[entry.handler_address],
                            table_state_field,
                        ):
                            key = (
                                transition.handler_address,
                                transition.state_offset,
                                transition.evidence,
                            )
                            if key not in transition_keys:
                                transition_keys.add(key)
                                transitions.append(transition)

                    child_dispatchers: set[str] = set()
                    for entry in candidates:
                        child_dispatch = child_dispatch_by_handler.get(
                            entry.handler_address
                        )
                        if (
                            child_dispatch is None
                            or child_dispatch.table_address is None
                            or entry.handler_address in child_dispatchers
                        ):
                            continue
                        child_dispatchers.add(entry.handler_address)
                        walk_table(
                            child_dispatch.table_address,
                            entry.handler_address,
                            child_dispatch.state_field,
                        )
                    return True

                if not walk_table(resolved_table, root, state_field):
                    return self._blocked(
                        root,
                        output,
                        status="blocked",
                        reason=f"no valid GG4E function pointers at {resolved_table}",
                    )
                handlers.extend(handler_records.values())
            else:
                identity = root_bundle.get("identity")
                name = (
                    identity.get("name", root)
                    if isinstance(identity, dict)
                    else root
                )
                handlers.append(
                    HandlerRecord(
                        address=root,
                        name=str(name),
                        decompile=root_decompile,
                        callers=callers,
                        callees=callees,
                        bundle=root_bundle,
                    )
                )
                transitions.extend(extract_transitions(root, root_decompile, state_field))

            artifact = StateMachineArtifact(
                status="ready",
                unit_id=f"state-machine-{root.removeprefix('0x')}",
                kind="state_dispatcher" if resolved_table else "code_driven_handler",
                root_addresses=[root],
                state_field=state_field,
                function_pointer_tables=tables,
                handlers=handlers,
                transitions=transitions,
                callers=callers,
                callees=callees,
                evidence=evidence,
                unknowns=[] if state_field else ["state field was not recovered"],
            )
            self._write(output, artifact)
            return artifact
        except GhidraProgramUnavailable as error:
            return self._blocked(
                root,
                output,
                status="blocked_no_program",
                reason=str(error),
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--address", required=True)
    parser.add_argument("--table")
    parser.add_argument("--state-offset")
    parser.add_argument("--state-width", type=int, default=1)
    parser.add_argument("--ghidra-url", default="http://127.0.0.1:8080")
    parser.add_argument("--max-handlers", type=int, default=32)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    artifact = StateMachineProbe(GhidraHttpProbeClient(args.ghidra_url)).probe(
        root_address=args.address,
        table_address=args.table,
        state_offset=args.state_offset,
        state_width=args.state_width,
        max_handlers=args.max_handlers,
        output=args.output,
    )
    print(artifact.model_dump_json(indent=2, by_alias=True))
    return 0 if artifact.status == "ready" else 3


if __name__ == "__main__":
    raise SystemExit(main())
