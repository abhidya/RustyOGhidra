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

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from src.port_run_controller import find_gotyaforce_root
from src.port_source_loop import (
    SequentialSourcePortLoop,
    SourceLoopResult,
    _json_payload,
    is_provider_unavailable,
)


CHUNK_ANALYSIS_SCHEMA = 1
# Rank provenance so a cheap re-run can never clobber a paid-for artifact (G6/R8).
ANALYSIS_PROVENANCE_RANK = {"deterministic": 0, "saved_model_response": 1, "model": 2}
# Total structured requests per chunk analysis, repairs included (R11).
ANALYSIS_MAX_REQUESTS = int(os.getenv("OGHIDRA_CHUNK_ANALYSIS_MAX_REQUESTS", "3"))
# Entry symbols that are raw decompiler placeholders cannot pass the runtime
# reachability gate, so generating for them is guaranteed waste (G10/R13).
PLACEHOLDER_ENTRY_SYMBOL = re.compile(r"^(?:FUN|LAB)_[0-9a-fA-F]{8}$")
# Session-corpus names that are themselves placeholders (zz_ mangles included)
# carry no naming signal and must not be used for enrichment.
SESSION_NAME_JUNK = re.compile(r"^(?:FUN|LAB)_[0-9a-fA-F]{8}$|^zz_[0-9a-fA-F]+_?$")
PORTABLE_CLASSIFICATIONS = {"game_owned", "shared_runtime"}
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
    # Ghidra placeholder names literally encode their address; the model
    # naturally writes them in address slots because they fill the prompt
    # (`FUN_8006f0cc` in state_dispatchers rejected a second 150/150-coverage
    # analysis on 2026-08-08). Decode instead of rejecting -- same rule the
    # unit-symbol enrichment already applies.
    placeholder = re.fullmatch(r"(?:fun|lab)_([0-9a-f]{8})", raw)
    if placeholder:
        raw = placeholder.group(1)
    # Model transcriptions drop a leading zero from the low digits often enough
    # to matter (a single `0x80064d4` once discarded a full 150/150-coverage
    # analysis): repair 7-digit 8xxxxxxx forms by re-padding the low digits
    # instead of rejecting the whole structured response.
    if re.fullmatch(r"8[0-9a-f]{6}", raw):
        raw = "8" + raw[1:].zfill(7)
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


class ChunkAnalysisOversized(RuntimeError):
    """The chunk prompt cannot fit the model context; retrying cannot help.

    Callers must not spend analysis budget on this -- the server rejects the
    request deterministically before any generation happens.
    """


class UnitSkipResult(BaseModel):
    """Typed no-work outcome: the unit cannot pass validation, so nothing was generated (R13)."""

    model_config = ConfigDict(extra="forbid")

    skipped: Literal[True] = True
    passed: Literal[False] = False
    unit_id: str
    eligibility: Literal["ineligible_classification", "ineligible_fun_entry"]
    reason: str
    model_requests: Literal[0] = 0


def unit_eligibility(unit: "ExecutionUnit") -> tuple[str, str]:
    """Decide before any generation whether a unit can possibly pass the gates.

    Returns ("eligible", "") or an (eligibility, reason) pair matching UnitSkipResult.
    """
    if unit.classification not in PORTABLE_CLASSIFICATIONS:
        return (
            "ineligible_classification",
            f"classification {unit.classification!r} is implemented as a host/data adapter, not a source port",
        )
    named_entries = [
        symbol
        for symbol in unit.runtime_entry_symbols
        if not PLACEHOLDER_ENTRY_SYMBOL.match(symbol)
    ]
    if not named_entries:
        return (
            "ineligible_fun_entry",
            "no runtime entry symbol survives the FUN_/LAB_ placeholder filter; "
            "the reachability gate would reject the port after paying full generation",
        )
    return ("eligible", "")


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


def parse_chunk_export(
    repo_root: str | Path,
    chunk: str,
    *,
    rename_map: dict[str, str] | None = None,
) -> ParsedChunk:
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
        marker_name = marker.group("name").strip()
        if SESSION_NAME_JUNK.match(marker_name):
            # Session-rename enrichment (R23): the session corpus supplies real
            # names where the export only has FUN_/LAB_/zz_ placeholders. Real
            # export names are never overridden -- they are themselves curated
            # (e.g. dispatch_challenge_flow_state) and anchor product priorities.
            marker_name = (rename_map or {}).get(address) or marker_name
        functions.append(
            ChunkFunction(
                address=address,
                name=marker_name,
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


def _model_prompt(
    chunk: ParsedChunk,
    deterministic: ChunkAnalysis,
    *,
    repair_feedback: str | None = None,
) -> str:
    facts = {
        "chunk": chunk.name,
        "function_count": len(chunk.functions),
        "functions": deterministic.functions,
        # Membership only. A full schema-shaped candidate dump (labels,
        # boilerplate summaries, dependency lists) is a copy-paste target:
        # observed live, repair rounds degenerated into transcribing it
        # verbatim until truncation instead of analyzing.
        "candidate_groupings": [
            {"id": unit.id, "function_addresses": unit.function_addresses}
            for unit in deterministic.units
        ],
    }
    # Appended AFTER the static evidence: the evidence prefix is identical
    # across attempts and prompt-caches at ~100% (measured 111,006/111,010
    # cached tokens); injecting feedback ahead of it forced a full re-prefill
    # (~10 min on this hardware) on every repair round.
    repair_section = (
        f"""

A previous attempt at this exact task was rejected. Fix ONLY the reported problem and
return the complete corrected assignment (the validator re-checks full coverage). Do not
copy candidate_groupings back as your answer; produce your own analysis:
{repair_feedback}
"""
        if repair_feedback
        else ""
    )
    return f"""Analyze this complete Ghidra export chunk as shared translation context.

Return execution units, not one TypeScript file and not one unit per function. Every original
function address must appear in exactly one unit. Keep SDK/hardware/data units separate from
game-owned state controllers. A generation unit should normally contain 2-40 tightly related
functions. Record cross-chunk calls as external dependencies. runtime_entry_symbols must be exact
function names from the chunk that a production caller must reach. target_source_paths may name
only likely existing browser source integration files; use an empty list when unresolved.
To conserve output, leave hardware_or_sdk_functions and game_owned_functions as empty lists --
they are derived from your units' classifications; do not repeat per-function metadata.
Emit compact single-line JSON with no indentation or extra whitespace.

Deterministic evidence:
{json.dumps(facts, indent=2)}

Complete decompiler chunk:
{chr(10).join(function.c for function in chunk.functions)}
{repair_section}"""


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
        # unit-state.json, NOT run-state.json: run-state is driver-owned. Both
        # writers previously shared run-state.json and raced mid-port, so the
        # supervisor could not trust it while a step was in flight.
        self.state_path = self.run_root.parent / "unit-state.json"
        self.session_index_path = self.run_root.parent / "session-index.json"
        self._session_functions_cache: dict[str, dict[str, Any]] | None = None
        # Structured requests spent by the most recent analyze(); drivers use
        # this for per-chunk request accounting (R11).
        self.last_analyze_requests = 0

    def _session_functions(self) -> dict[str, dict[str, Any]]:
        """Address-keyed {name, summary} view of session-index.json; {} when absent."""
        if self._session_functions_cache is None:
            functions: dict[str, dict[str, Any]] = {}
            try:
                payload = json.loads(self.session_index_path.read_text(encoding="utf-8"))
                raw = payload.get("functions", {})
                if isinstance(raw, dict):
                    functions = {
                        address: entry
                        for address, entry in raw.items()
                        if isinstance(entry, dict)
                    }
            except (FileNotFoundError, json.JSONDecodeError, OSError):
                functions = {}
            self._session_functions_cache = functions
        return self._session_functions_cache

    def _rename_map(self) -> dict[str, str]:
        return {
            address: name
            for address, entry in self._session_functions().items()
            if (name := str(entry.get("name") or "")) and not SESSION_NAME_JUNK.match(name)
        }

    def _enrich_units(self, analysis: ChunkAnalysis) -> ChunkAnalysis:
        """Apply session renames to an already-saved analysis, in memory only.

        Analyses written before the session index existed carry FUN_/zz_
        placeholder entry symbols; substituting the corpus names here unlocks
        eligibility (G10) without touching the paid-for artifact on disk.
        """
        rename = self._rename_map()
        if not rename:
            return analysis
        address_by_name = {
            str(function.get("name")): str(function.get("address"))
            for function in analysis.functions
            if isinstance(function, dict)
        }
        for function in analysis.functions:
            if isinstance(function, dict):
                address = str(function.get("address"))
                if address in rename and SESSION_NAME_JUNK.match(str(function.get("name") or "")):
                    function["name"] = rename[address]
        for unit in analysis.units:
            enriched = []
            for symbol in unit.runtime_entry_symbols:
                if not SESSION_NAME_JUNK.match(symbol):
                    # Real export names are authoritative; only placeholders
                    # (FUN_/LAB_/zz_) are eligible for substitution.
                    enriched.append(symbol)
                    continue
                address = address_by_name.get(symbol)
                if address is None:
                    # FUN_/LAB_ placeholders literally encode their address.
                    placeholder = re.fullmatch(r"(?:FUN|LAB)_([0-9a-fA-F]{8})", symbol)
                    address = f"0x{placeholder.group(1).lower()}" if placeholder else None
                enriched.append((rename.get(address) if address else None) or symbol)
            unit.runtime_entry_symbols = list(dict.fromkeys(enriched))
        return analysis

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
        hardware = payload.hardware_or_sdk_functions or [
            address
            for unit in payload.units
            if unit.classification == "hardware_or_sdk"
            for address in unit.function_addresses
        ]
        game = payload.game_owned_functions or [
            address
            for unit in payload.units
            if unit.classification == "game_owned"
            for address in unit.function_addresses
        ]
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
            hardware_or_sdk_functions=[normalize_address(value) for value in hardware],
            game_owned_functions=[normalize_address(value) for value in game],
            functions=build_deterministic_analysis(chunk).functions,
            units=payload.units,
        )

    def _model_analyze_with_repair(
        self, chunk: ParsedChunk, deterministic: ChunkAnalysis
    ) -> ChunkAnalysis:
        """One structured analysis with bounded delta-repair (D4, R11/R12/R14).

        Output budget scales with the chunk and is deliberately NOT ceiling-
        clamped: the measured demand for a 150-function chunk is 123-134
        tokens/function (~20k total), and the prior ``min(..., 28672)`` /
        90 tok/fn heuristic sat BELOW that -- it guaranteed the truncation it
        was meant to prevent while the flat 32,768 had parsed cleanly four
        times in a row. Reasoning-model thinking tokens also spend from this
        same budget. The serving context, not this client, is the real bound.
        Coverage/parse failures feed the exact violations back for at most
        ``ANALYSIS_MAX_REQUESTS - 1`` repair rounds. Every raw response is
        archived before validation so a failed run no longer discards a
        20-minute generation.
        """
        fn_count = len(chunk.functions)
        max_tokens = int(
            os.getenv(
                "OGHIDRA_CHUNK_ANALYSIS_MAX_TOKENS",
                str(max(32768, 160 * fn_count + 4096)),
            )
        )
        # Preflight BEFORE any request: the server rejects on prompt tokens
        # alone, deterministically, at ~2.05 chars/token on these decompiler
        # exports (observed: 289,876 chars -> 141,173 tokens). Retrying is a
        # guaranteed 400 -- five chunks burned their full 3-request analysis
        # budgets in minutes on 2026-08-08 before anyone looked. //2 slightly
        # overestimates tokens, which is the safe direction.
        context_limit = int(os.getenv("OGHIDRA_PORT_CONTEXT_TOKENS", "131072"))
        estimated_prompt_tokens = (
            len(_model_prompt(chunk, deterministic, repair_feedback=None)) // 2
        )
        if estimated_prompt_tokens > context_limit:
            self._write_state(chunk.name, status="analysis_oversized", model_requests=0)
            raise ChunkAnalysisOversized(
                f"{chunk.name}: ~{estimated_prompt_tokens} prompt tokens exceeds the "
                f"{context_limit}-token context window; split the chunk or raise the "
                "served context before re-attempting"
            )
        llm, provider, model_name = self.llm_factory()
        archive_root = self.chunk_root(chunk.name)
        repair_feedback: str | None = None
        last_error: Exception | None = None
        self.last_analyze_requests = 0
        for attempt in range(1, ANALYSIS_MAX_REQUESTS + 1):
            self.last_analyze_requests = attempt
            self._write_state(chunk.name, status="model_running", model_requests=attempt)
            try:
                raw, _mode = llm.generate_structured(
                    prompt=_model_prompt(chunk, deterministic, repair_feedback=repair_feedback),
                    schema=ChunkModelAnalysis.model_json_schema(),
                    tool_name="submit_chunk_analysis",
                    model=model_name,
                    system_prompt=(
                        "You partition complete Ghidra export chunks into coherent execution units. "
                        "Return only the requested strict structured result; do not browse source or generate code."
                    ),
                    temperature=0.1,
                    max_tokens=max_tokens,
                    phase=f"chunk_analysis:{chunk.name}:attempt{attempt}",
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
            except Exception as error:
                message = f"{type(error).__name__}: {error}"
                if any(marker in message.lower() for marker in TRANSIENT_MARKERS):
                    self._write_state(
                        chunk.name,
                        status="paused_provider_unavailable",
                        model_requests=attempt,
                        error=message,
                    )
                    raise ProviderUnavailable(message) from error
                self._write_state(
                    chunk.name, status="analysis_failed", model_requests=attempt, error=message
                )
                raise
            archive = archive_root / f"analysis-attempt-{attempt}.raw.txt"
            archive.parent.mkdir(parents=True, exist_ok=True)
            archive.write_text(raw, encoding="utf-8")
            try:
                payload = ChunkModelAnalysis.model_validate(_json_payload(raw))
                analysis = self._validate_model_analysis(chunk, payload, generated_by="model")
            except (ValueError, ValidationError) as error:
                # Truncated JSON parses fail here too -- both are repairable.
                last_error = error
                repair_feedback = str(error)[:4000]
                continue
            self._write_state(
                chunk.name,
                status="analyzed",
                model_requests=attempt,
                provider=provider,
                model=model_name,
            )
            return analysis
        message = (
            f"model analysis failed after {ANALYSIS_MAX_REQUESTS} structured requests: {last_error}"
        )
        self._write_state(
            chunk.name,
            status="analysis_failed",
            model_requests=ANALYSIS_MAX_REQUESTS,
            error=message,
        )
        raise ValueError(message)

    def _existing_analysis(self, chunk: ParsedChunk) -> ChunkAnalysis | None:
        """Return the on-disk analysis when it still matches the chunk export, else None."""
        path = self.analysis_path(chunk.name)
        if not path.is_file():
            return None
        try:
            analysis = ChunkAnalysis.model_validate_json(path.read_text(encoding="utf-8"))
        except Exception:
            return None
        if analysis.chunk_sha256 != chunk.sha256:
            return None
        return analysis

    def analyze(
        self,
        chunk_name: str,
        *,
        model_response: str | Path | None = None,
        deterministic_only: bool = False,
        force: bool = False,
    ) -> ChunkAnalysis:
        chunk = parse_chunk_export(self.repo_root, chunk_name, rename_map=self._rename_map())
        # Reuse instead of re-analyzing (G3/G5): a matching sha means the on-disk
        # artifact is still valid, so re-running must cost zero model requests (R7).
        # Provenance upgrades (deterministic -> model) are the driver's decision;
        # --force-reanalyze is the owner's override.
        existing = None if force else self._existing_analysis(chunk)
        if existing is not None:
            self._write_state(
                chunk.name,
                status="analyzed",
                model_requests=0,
                reused_existing_analysis=True,
                generated_by=existing.generated_by,
                units=len(existing.units),
                analysis=str(self.analysis_path(chunk.name)),
            )
            return self._enrich_units(existing)
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
            analysis = self._model_analyze_with_repair(chunk, deterministic)
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
        return self._enrich_units(analysis)

    def list_units(self, chunk: str) -> list[ExecutionUnit]:
        return self.load_analysis(chunk).units

    def port_unit(self, chunk_name: str, unit_id: str) -> SourceLoopResult | UnitSkipResult:
        analysis = self.load_analysis(chunk_name)
        chunk = parse_chunk_export(self.repo_root, chunk_name, rename_map=self._rename_map())
        unit = next((candidate for candidate in analysis.units if candidate.id == unit_id), None)
        if unit is None:
            raise KeyError(f"unknown execution unit {unit_id!r}")
        eligibility, reason = unit_eligibility(unit)
        if eligibility != "eligible":
            # Skip before any generation (G10/G15/R13): an ineligible unit is a
            # recorded outcome, not a crash, and must cost zero model requests.
            self._write_state(
                chunk.name,
                status="unit_skipped",
                unit=unit.id,
                eligibility=eligibility,
                model_requests=0,
            )
            return UnitSkipResult(unit_id=unit.id, eligibility=eligibility, reason=reason)
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
        session = self._session_functions()
        session_summaries = {
            address: {
                "name": session[address].get("name"),
                "summary": session[address].get("summary"),
            }
            for address in unit.function_addresses
            if address in session
        }
        result = source_loop.run(
            address=entry_address,
            aliases=unit.function_addresses,
            bundle=bundle,
            analysis_context={
                "execution_unit": unit.model_dump(mode="json"),
                "chunk": chunk.name,
                "cross_chunk_dependencies": unit.external_dependencies,
                # Advisory grounding from the curated session corpus (R23);
                # the source loop frames it as saved analysis, fresh evidence wins.
                "saved_session_analysis": session_summaries,
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
