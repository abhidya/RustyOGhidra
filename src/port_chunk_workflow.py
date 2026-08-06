"""Chunk-level analysis and execution-unit port orchestration.

Static Ghidra exports are authoritative while the live Ghidra service is offline. One
bounded structured model request may refine deterministic execution-unit candidates;
model-driven repository browsing is deliberately deferred to the selected unit.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from src.port_run_controller import find_gotyaforce_root
from src.port_source_loop import (
    SequentialSourcePortLoop,
    SourceLoopResult,
    _json_payload,
    is_provider_unavailable,
)


CHUNK_ANALYSIS_SCHEMA = 1
CHUNK_MARKER = re.compile(
    r"^// ==== (?P<address>[0-9a-fA-F]{8})\s+(?P<name>.+?) ====$",
    re.MULTILINE,
)
GLOBAL_TOKEN = re.compile(
    r"\b(?:DAT|PTR_DAT|PTR_FUN|FLOAT|DOUBLE|LAB)_[0-9a-fA-F]+\b"
)
CALL_TOKEN = re.compile(r"\b(?P<name>[A-Za-z_$][\w$]*)\s*\(")
SDK_NAME = re.compile(
    r"^(?:gnt4_)?(?:__|GX|OS|DVD|HSD|DSP|TRK|SI|VI|AI|AR|AX|memcpy|memset)",
    re.IGNORECASE,
)
TRANSIENT_MARKERS = (
    "connection",
    "readerror",
    "remoteprotocolerror",
    "timed out",
    "timeout",
    "empty stream",
    "service unavailable",
    "no model loaded",
    "connection refused",
    "status_code: 429",
    "status_code: 500",
    "status_code: 502",
    "status_code: 503",
    "status_code: 504",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def normalize_address(value: str) -> str:
    raw = str(value).strip().lower().removeprefix("0x")
    if not re.fullmatch(r"[0-9a-f]{8}", raw):
        raise ValueError(f"invalid function address: {value}")
    return f"0x{raw}"


def normalize_chunk_name(value: str) -> str:
    raw = Path(str(value).strip()).name.lower()
    match = re.fullmatch(r"(?:chunk_?)?(\d{1,4})(?:\.c)?", raw)
    if not match:
        raise ValueError(f"invalid chunk name: {value}")
    return f"chunk_{int(match.group(1)):04d}.c"


def slug(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return normalized or "unit"


class ProviderUnavailable(RuntimeError):
    """The external model provider is offline; callers must pause, not retry generation."""


class ChunkFunction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    address: str
    name: str
    source_start_line: int
    source_end_line: int
    c: str
    direct_calls: list[str] = Field(default_factory=list)
    shared_globals: list[str] = Field(default_factory=list)


class ParsedChunk(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    path: str
    sha256: str
    line_count: int
    functions: list[ChunkFunction]


UnitClassification = Literal[
    "game_owned",
    "shared_runtime",
    "hardware_or_sdk",
    "data_or_table",
    "unresolved",
]


class ExecutionUnit(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    label: str
    classification: UnitClassification
    summary: str
    function_addresses: list[str] = Field(min_length=1)
    external_dependencies: list[str] = Field(default_factory=list)
    shared_globals: list[str] = Field(default_factory=list)
    runtime_entry_symbols: list[str] = Field(default_factory=list)
    target_source_paths: list[str] = Field(default_factory=list)
    status: Literal["analyzed", "porting", "integrated", "rejected"] = "analyzed"

    @field_validator("function_addresses", "external_dependencies")
    @classmethod
    def normalize_addresses(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(normalize_address(value) for value in values))


class ChunkModelAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subsystems: list[str] = Field(default_factory=list)
    state_dispatchers: list[str] = Field(default_factory=list)
    callback_tables: list[str] = Field(default_factory=list)
    shared_globals: list[str] = Field(default_factory=list)
    external_dependencies: list[str] = Field(default_factory=list)
    hardware_or_sdk_functions: list[str] = Field(default_factory=list)
    game_owned_functions: list[str] = Field(default_factory=list)
    units: list[ExecutionUnit]


class ChunkAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema: int = CHUNK_ANALYSIS_SCHEMA
    chunk: str
    chunk_sha256: str
    function_count: int
    generated_by: Literal["deterministic", "model", "saved_model_response"]
    generated_at: str
    subsystems: list[str] = Field(default_factory=list)
    state_dispatchers: list[str] = Field(default_factory=list)
    callback_tables: list[str] = Field(default_factory=list)
    shared_globals: list[str] = Field(default_factory=list)
    external_dependencies: list[str] = Field(default_factory=list)
    hardware_or_sdk_functions: list[str] = Field(default_factory=list)
    game_owned_functions: list[str] = Field(default_factory=list)
    functions: list[dict[str, Any]]
    units: list[ExecutionUnit]


def _index_names(export_root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    index_path = export_root / "_index.tsv"
    if not index_path.is_file():
        return result
    for line in index_path.read_text(encoding="utf-8", errors="replace").splitlines():
        columns = line.split("\t")
        if len(columns) < 2:
            continue
        try:
            address = normalize_address(columns[0])
        except ValueError:
            continue
        result.setdefault(columns[1], address)
    return result


def parse_chunk_export(repo_root: str | Path, chunk: str) -> ParsedChunk:
    root = Path(repo_root).resolve()
    export_root = root / "research" / "decomp" / "ghidra-export"
    name = normalize_chunk_name(chunk)
    path = export_root / name
    if not path.is_file():
        raise FileNotFoundError(f"Ghidra export chunk not found: {path}")
    text = path.read_text(encoding="utf-8", errors="replace")
    markers = list(CHUNK_MARKER.finditer(text))
    if not markers:
        raise ValueError(f"chunk contains no function markers: {path}")
    name_to_address = _index_names(export_root)
    functions: list[ChunkFunction] = []
    for index, marker in enumerate(markers):
        end = markers[index + 1].start() if index + 1 < len(markers) else len(text)
        body = text[marker.start():end].rstrip()
        address = normalize_address(marker.group("address"))
        direct_calls = []
        for call in CALL_TOKEN.finditer(body):
            target = name_to_address.get(call.group("name"))
            if target and target != address and target not in direct_calls:
                direct_calls.append(target)
        functions.append(
            ChunkFunction(
                address=address,
                name=marker.group("name").strip(),
                source_start_line=text.count("\n", 0, marker.start()) + 1,
                source_end_line=(
                    text.count("\n", 0, end)
                    if index + 1 < len(markers)
                    else text.count("\n", 0, end) + 1
                ),
                c=body,
                direct_calls=direct_calls,
                shared_globals=sorted(set(GLOBAL_TOKEN.findall(body))),
            )
        )
    return ParsedChunk(
        name=name,
        path=path.relative_to(root).as_posix(),
        sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        line_count=text.count("\n") + 1,
        functions=functions,
    )


def _function_classification(function: ChunkFunction) -> UnitClassification:
    if SDK_NAME.match(function.name):
        return "hardware_or_sdk"
    if not function.direct_calls and not function.shared_globals and len(function.c) < 220:
        return "data_or_table"
    return "game_owned"


def _connected_components(chunk: ParsedChunk) -> list[list[str]]:
    functions = {function.address: function for function in chunk.functions}
    graph: dict[str, set[str]] = {address: set() for address in functions}
    for function in chunk.functions:
        for target in function.direct_calls:
            if target in functions:
                graph[function.address].add(target)
                graph[target].add(function.address)
    globals_to_functions: dict[str, list[str]] = defaultdict(list)
    for function in chunk.functions:
        for token in function.shared_globals:
            globals_to_functions[token].append(function.address)
    for members in globals_to_functions.values():
        if 1 < len(members) <= 8:
            for left, right in zip(members, members[1:]):
                if _function_classification(functions[left]) == _function_classification(functions[right]):
                    graph[left].add(right)
                    graph[right].add(left)
    remaining = set(functions)
    components: list[list[str]] = []
    while remaining:
        start = min(remaining)
        queue = deque([start])
        component: list[str] = []
        remaining.remove(start)
        while queue:
            current = queue.popleft()
            component.append(current)
            for neighbor in sorted(graph[current]):
                if neighbor in remaining:
                    remaining.remove(neighbor)
                    queue.append(neighbor)
        components.append(sorted(component, key=lambda address: int(address, 16)))
    return components


def build_deterministic_analysis(chunk: ParsedChunk) -> ChunkAnalysis:
    by_address = {function.address: function for function in chunk.functions}
    units: list[ExecutionUnit] = []
    used_ids: set[str] = set()
    for component in _connected_components(chunk):
        # Large decompiler neighborhoods are context, not safe generation units.
        slices = [component[index:index + 40] for index in range(0, len(component), 40)]
        for part_index, addresses in enumerate(slices, start=1):
            members = [by_address[address] for address in addresses]
            classifications = {_function_classification(function) for function in members}
            classification: UnitClassification = (
                next(iter(classifications)) if len(classifications) == 1 else "unresolved"
            )
            incoming = {
                target
                for member in members
                for target in member.direct_calls
                if target in addresses
            }
            entry_functions = [member for member in members if member.address not in incoming]
            if not entry_functions:
                entry_functions = members[:1]
            base_id = slug(entry_functions[0].name)
            if len(slices) > 1:
                base_id = f"{base_id}-{part_index}"
            unit_id = base_id
            suffix = 2
            while unit_id in used_ids:
                unit_id = f"{base_id}-{suffix}"
                suffix += 1
            used_ids.add(unit_id)
            external = sorted(
                {
                    target
                    for member in members
                    for target in member.direct_calls
                    if target not in addresses
                }
            )
            units.append(
                ExecutionUnit(
                    id=unit_id,
                    label=entry_functions[0].name,
                    classification=classification,
                    summary=(
                        f"Deterministic candidate containing {len(members)} related function(s); "
                        "model analysis should refine ownership before production porting."
                    ),
                    function_addresses=addresses,
                    external_dependencies=external,
                    shared_globals=sorted(
                        {token for member in members for token in member.shared_globals}
                    ),
                    runtime_entry_symbols=(
                        [function.name for function in entry_functions]
                        if classification == "game_owned"
                        else []
                    ),
                )
            )
    hardware = [
        function.address
        for function in chunk.functions
        if _function_classification(function) == "hardware_or_sdk"
    ]
    game = [
        function.address
        for function in chunk.functions
        if _function_classification(function) == "game_owned"
    ]
    external = sorted(
        {
            target
            for function in chunk.functions
            for target in function.direct_calls
            if target not in by_address
        }
    )
    return ChunkAnalysis(
        chunk=chunk.name,
        chunk_sha256=chunk.sha256,
        function_count=len(chunk.functions),
        generated_by="deterministic",
        generated_at=utc_now(),
        shared_globals=sorted({token for function in chunk.functions for token in function.shared_globals}),
        external_dependencies=external,
        hardware_or_sdk_functions=hardware,
        game_owned_functions=game,
        functions=[
            {
                "address": function.address,
                "name": function.name,
                "source_start_line": function.source_start_line,
                "source_end_line": function.source_end_line,
                "direct_calls": function.direct_calls,
                "shared_globals": function.shared_globals,
            }
            for function in chunk.functions
        ],
        units=units,
    )


def _model_prompt(chunk: ParsedChunk, deterministic: ChunkAnalysis) -> str:
    facts = {
        "chunk": chunk.name,
        "function_count": len(chunk.functions),
        "functions": deterministic.functions,
        "candidate_units": [unit.model_dump(mode="json") for unit in deterministic.units],
    }
    return f"""Analyze this complete Ghidra export chunk as shared translation context.

Return execution units, not one TypeScript file and not one unit per function. Every original
function address must appear in exactly one unit. Keep SDK/hardware/data units separate from
game-owned state controllers. A generation unit should normally contain 2-40 tightly related
functions. Record cross-chunk calls as external dependencies. runtime_entry_symbols must be exact
function names from the chunk that a production caller must reach. target_source_paths may name
only likely existing browser source integration files; use an empty list when unresolved.

Deterministic evidence:
{json.dumps(facts, indent=2)}

Complete decompiler chunk:
{chr(10).join(function.c for function in chunk.functions)}
"""


class ChunkPortWorkflow:
    def __init__(
        self,
        *,
        repo_root: str | Path | None = None,
        llm_factory: Callable[[], tuple[Any, str, str]] | None = None,
    ):
        # Explicit roots are authoritative for embedded callers and isolated tests.
        self.repo_root = (
            Path(repo_root).resolve()
            if repo_root is not None
            else find_gotyaforce_root()
        )
        self.run_root = self.repo_root / "research/decomp/generated/finish-game-port/chunks"
        self.run_id = os.getenv("OGHIDRA_PORT_RUN_ID") or utc_now()
        self.llm_factory = llm_factory or self._default_llm_factory
        self.state_path = self.run_root.parent / "run-state.json"

    @staticmethod
    def _default_llm_factory() -> tuple[Any, str, str]:
        from src.config import get_config
        from src.port_cli import _llm_for_config

        return _llm_for_config(get_config())

    def chunk_root(self, chunk: str) -> Path:
        name = normalize_chunk_name(chunk)
        return self.run_root / name.removesuffix(".c")

    def analysis_path(self, chunk: str) -> Path:
        return self.chunk_root(chunk) / "analysis.json"

    def _write_state(self, chunk: str, **updates: Any) -> None:
        state = {
            "run_schema": 3,
            "run_mode": "chunk_unit",
            "objective": "Port coherent GameCube execution units",
            "scope": {"kind": "chunk", "chunk": normalize_chunk_name(chunk)},
            "run_id": self.run_id,
            "chunk": normalize_chunk_name(chunk),
            "updated_at": utc_now(),
            **updates,
        }
        atomic_write_json(self.state_path, state)

    def _validate_model_analysis(
        self,
        chunk: ParsedChunk,
        payload: ChunkModelAnalysis,
        *,
        generated_by: Literal["model", "saved_model_response"],
    ) -> ChunkAnalysis:
        known = {function.address for function in chunk.functions}
        assigned: list[str] = [address for unit in payload.units for address in unit.function_addresses]
        unknown = sorted(set(assigned) - known)
        duplicate = sorted({address for address in assigned if assigned.count(address) > 1})
        missing = sorted(known - set(assigned))
        if unknown or duplicate or missing:
            raise ValueError(
                f"invalid unit coverage: unknown={unknown}, duplicate={duplicate}, missing={missing}"
            )
        return ChunkAnalysis(
            chunk=chunk.name,
            chunk_sha256=chunk.sha256,
            function_count=len(chunk.functions),
            generated_by=generated_by,
            generated_at=utc_now(),
            subsystems=payload.subsystems,
            state_dispatchers=[normalize_address(value) for value in payload.state_dispatchers],
            callback_tables=payload.callback_tables,
            shared_globals=payload.shared_globals,
            external_dependencies=[normalize_address(value) for value in payload.external_dependencies],
            hardware_or_sdk_functions=[normalize_address(value) for value in payload.hardware_or_sdk_functions],
            game_owned_functions=[normalize_address(value) for value in payload.game_owned_functions],
            functions=build_deterministic_analysis(chunk).functions,
            units=payload.units,
        )

    def analyze(
        self,
        chunk_name: str,
        *,
        model_response: str | Path | None = None,
        deterministic_only: bool = False,
    ) -> ChunkAnalysis:
        chunk = parse_chunk_export(self.repo_root, chunk_name)
        deterministic = build_deterministic_analysis(chunk)
        self._write_state(chunk.name, status="analyzing", model_requests=0)
        if deterministic_only:
            analysis = deterministic
        elif model_response is not None:
            raw = Path(model_response).read_text(encoding="utf-8")
            payload = ChunkModelAnalysis.model_validate(_json_payload(raw))
            analysis = self._validate_model_analysis(
                chunk, payload, generated_by="saved_model_response"
            )
        else:
            self._write_state(chunk.name, status="model_running", model_requests=1)
            try:
                llm, provider, model_name = self.llm_factory()
                raw, _mode = llm.generate_structured(
                    prompt=_model_prompt(chunk, deterministic),
                    schema=ChunkModelAnalysis.model_json_schema(),
                    tool_name="submit_chunk_analysis",
                    model=model_name,
                    system_prompt=(
                        "You partition complete Ghidra export chunks into coherent execution units. "
                        "Return only the requested strict structured result; do not browse source or generate code."
                    ),
                    temperature=0.1,
                    max_tokens=int(os.getenv("OGHIDRA_CHUNK_ANALYSIS_MAX_TOKENS", "32768")),
                    phase=f"chunk_analysis:{chunk.name}",
                    accept_plain_tool_response=True,
                    # Stream for two reasons, both learned the hard way:
                    # 1. liveness telemetry (current_completion_tokens,
                    #    tokens_per_second) only updates mid-request on the
                    #    streaming path -- non-streamed, a 40-minute generation
                    #    reports "out 0 tok, 0.0 tok/s" the whole time and is
                    #    indistinguishable from a hang;
                    # 2. requests' read timeout is time-between-BYTES; with no
                    #    stream a generation longer than CUSTOM_API_TIMEOUT
                    #    dies even though the server is healthy and working.
                    # The callback itself has nothing to do -- the client's
                    # metrics wrapper does the liveness accounting.
                    stream_callback=lambda _event_type, _event: None,
                )
                payload = ChunkModelAnalysis.model_validate(_json_payload(raw))
                analysis = self._validate_model_analysis(chunk, payload, generated_by="model")
                self._write_state(
                    chunk.name,
                    status="analyzed",
                    model_requests=1,
                    provider=provider,
                    model=model_name,
                )
            except Exception as error:
                message = f"{type(error).__name__}: {error}"
                lowered = message.lower()
                if any(marker in lowered for marker in TRANSIENT_MARKERS):
                    self._write_state(
                        chunk.name,
                        status="paused_provider_unavailable",
                        model_requests=1,
                        error=message,
                    )
                    raise ProviderUnavailable(message) from error
                self._write_state(
                    chunk.name,
                    status="analysis_failed",
                    model_requests=1,
                    error=message,
                )
                raise
        atomic_write_json(self.analysis_path(chunk.name), analysis.model_dump(mode="json"))
        self._write_state(
            chunk.name,
            status="analyzed",
            model_requests=0 if deterministic_only or model_response is not None else 1,
            units=len(analysis.units),
            analysis=str(self.analysis_path(chunk.name)),
        )
        return analysis

    def load_analysis(self, chunk: str) -> ChunkAnalysis:
        path = self.analysis_path(chunk)
        if not path.is_file():
            raise FileNotFoundError(
                f"chunk analysis does not exist: {path}; run --analyze-chunk first"
            )
        analysis = ChunkAnalysis.model_validate_json(path.read_text(encoding="utf-8"))
        parsed = parse_chunk_export(self.repo_root, chunk)
        if analysis.chunk_sha256 != parsed.sha256:
            raise ValueError("chunk export changed after analysis; rerun --analyze-chunk")
        return analysis

    def list_units(self, chunk: str) -> list[ExecutionUnit]:
        return self.load_analysis(chunk).units

    def port_unit(self, chunk_name: str, unit_id: str) -> SourceLoopResult:
        analysis = self.load_analysis(chunk_name)
        chunk = parse_chunk_export(self.repo_root, chunk_name)
        unit = next((candidate for candidate in analysis.units if candidate.id == unit_id), None)
        if unit is None:
            raise KeyError(f"unknown execution unit {unit_id!r}")
        if unit.classification in {"hardware_or_sdk", "data_or_table"}:
            raise ValueError(
                f"unit {unit.id} is classified {unit.classification}; implement it as a host/data adapter, not a source port"
            )
        selected = {
            function.address: function
            for function in chunk.functions
            if function.address in unit.function_addresses
        }
        if len(selected) != len(unit.function_addresses):
            raise ValueError("unit references functions missing from the current chunk")
        unit_root = self.chunk_root(chunk.name) / "units" / unit.id
        source_loop = SequentialSourcePortLoop(
            repo_root=self.repo_root,
            run_root=unit_root,
            llm_factory=self.llm_factory,
        )
        entry_address = unit.function_addresses[0]
        bundle = {
            "bundle_schema": 1,
            "identity": {
                "address": entry_address,
                "name": unit.id,
                "thunk": False,
            },
            "decompiler": {
                "c": "\n\n".join(selected[address].c for address in unit.function_addresses),
                "completed": True,
                "warnings": [],
                "errors": [],
            },
            "calls": unit.external_dependencies,
            "normalized_disassembly": [],
            "normalized_pcode": [],
            "fingerprints": {"chunk": chunk.sha256},
        }
        self._write_state(chunk.name, status="porting", unit=unit.id, model_requests=0)
        result = source_loop.run(
            address=entry_address,
            aliases=unit.function_addresses,
            bundle=bundle,
            analysis_context={
                "execution_unit": unit.model_dump(mode="json"),
                "chunk": chunk.name,
                "cross_chunk_dependencies": unit.external_dependencies,
            },
            required_context_paths=set(unit.target_source_paths),
            required_runtime_symbols=unit.runtime_entry_symbols,
        )
        if not result.passed and result.error and is_provider_unavailable(result.error):
            self._write_state(
                chunk.name,
                status="paused_provider_unavailable",
                unit=unit.id,
                attempts=result.attempts,
                error=result.error,
            )
            raise ProviderUnavailable(result.error)
        self._write_state(
            chunk.name,
            status="integrated" if result.passed else "unit_rejected",
            unit=unit.id,
            attempts=result.attempts,
            files=result.files,
            error=result.error,
        )
        return result
