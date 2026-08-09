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
    # Per-unit provenance (refinement design, 2026-08-08): "deterministic"
    # means no model judgment has touched this unit yet -- the driver defers
    # it, it is never port-eligible. Default "model_refined" keeps analyses
    # persisted before this field existed (all fresh-emission era, therefore
    # model-authored) eligible when reloaded from disk.
    provenance: Literal["deterministic", "model_refined"] = "model_refined"

    @field_validator("function_addresses", "external_dependencies")
    @classmethod
    def normalize_addresses(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(normalize_address(value) for value in values))


# ---------------------------------------------------------------------------
# Refinement ops (the model's ONLY output surface for chunk analysis).
#
# Invariant: everything mechanically derivable is mechanically derived --
# addresses, coverage, dependencies, globals. The model contributes judgment:
# names, classifications, entry symbols, summaries, and grouping decisions
# expressed as operations over the deterministic clusters. Coverage cannot be
# incomplete because nothing ever re-creates it.
# ---------------------------------------------------------------------------


class ClusterJudgment(BaseModel):
    """Model-authored judgment applied to one resulting unit."""

    model_config = ConfigDict(extra="forbid")

    label: str
    classification: UnitClassification
    summary: str
    runtime_entry_symbols: list[str] = Field(default_factory=list)
    target_source_paths: list[str] = Field(default_factory=list)


class RefineOp(BaseModel):
    """Judgment on one deterministic cluster, membership unchanged."""

    model_config = ConfigDict(extra="forbid")

    cluster: str
    judgment: ClusterJudgment


class MergeOp(BaseModel):
    """Fuse two or more deterministic clusters into one unit."""

    model_config = ConfigDict(extra="forbid")

    clusters: list[str] = Field(min_length=2)
    judgment: ClusterJudgment


class SplitGroup(BaseModel):
    """One side of a split, identified by exact function NAMES (never addresses)."""

    model_config = ConfigDict(extra="forbid")

    functions: list[str] = Field(min_length=1)
    judgment: ClusterJudgment


class SplitOp(BaseModel):
    """Divide one deterministic cluster; unlisted members stay together, unrefined."""

    model_config = ConfigDict(extra="forbid")

    cluster: str
    groups: list[SplitGroup] = Field(min_length=1)


class ChunkRefinementOps(BaseModel):
    """The model's structured response: operations over deterministic clusters."""

    model_config = ConfigDict(extra="forbid")

    refine: list[RefineOp] = Field(default_factory=list)
    merge: list[MergeOp] = Field(default_factory=list)
    split: list[SplitOp] = Field(default_factory=list)


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
                    provenance="deterministic",
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
    by_address = {function.address: function for function in chunk.functions}
    cluster_edges: dict[str, set[str]] = {}
    address_to_cluster = {
        address: unit.id
        for unit in deterministic.units
        for address in unit.function_addresses
    }
    for unit in deterministic.units:
        targets = {
            address_to_cluster[target]
            for address in unit.function_addresses
            for target in by_address[address].direct_calls
            if target in address_to_cluster and address_to_cluster[target] != unit.id
        }
        if targets:
            cluster_edges[unit.id] = targets
    facts = {
        "chunk": chunk.name,
        "function_count": len(chunk.functions),
        # Clusters are the ONLY things the model references; addresses appear
        # as read-only context and must never be transcribed back.
        "clusters": [
            {
                "id": unit.id,
                "heuristic_classification": unit.classification,
                "functions": [
                    {"name": by_address[address].name, "address": address}
                    for address in unit.function_addresses
                ],
            }
            for unit in deterministic.units
        ],
        "cross_cluster_calls": {
            cluster: sorted(targets) for cluster, targets in sorted(cluster_edges.items())
        },
    }
    # Appended AFTER the static evidence: the evidence prefix is identical
    # across attempts and prompt-caches at ~100% (measured 111,006/111,010
    # cached tokens); injecting feedback ahead of it forced a full re-prefill
    # (~10 min on this hardware) on every repair round.
    repair_section = (
        f"""

A previous attempt at this exact task was rejected. Fix the reported problems and return
the complete corrected op list (ops are small; re-emit all of them):
{repair_feedback}
"""
        if repair_feedback
        else ""
    )
    return f"""Refine the deterministic clustering of this Ghidra export chunk.

The chunk is already partitioned into clusters (see facts). You never write address lists;
you emit OPERATIONS over cluster ids, and membership/coverage/dependencies are derived
mechanically. Decide EVERY cluster exactly once, choosing per cluster one of:
- refine: keep its membership; supply judgment (label, classification, summary,
  runtime_entry_symbols, target_source_paths).
- merge: fuse 2+ clusters that form one coherent subsystem (cross_cluster_calls shows
  where the heuristic split real subsystems, including size-sliced -1/-2 suffix pairs);
  supply one judgment for the merged unit.
- split: divide a cluster whose members do not belong together; give each group its
  member function NAMES (exact names from the facts) plus judgment. Unlisted members
  stay together automatically.

Judgment rules: classification is one of game_owned, shared_runtime, hardware_or_sdk,
data_or_table, unresolved. Keep SDK/hardware/data separate from game-owned state
controllers. For game_owned and shared_runtime units, runtime_entry_symbols must name the
real entry functions a production caller must reach (exact chunk function names, never
FUN_/LAB_ placeholders); for other classifications leave it empty. target_source_paths may
name only likely existing browser source integration files; empty when unresolved.
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

    def _apply_refinement_ops(
        self,
        chunk: ParsedChunk,
        deterministic: ChunkAnalysis,
        ops: ChunkRefinementOps,
        *,
        generated_by: Literal["model", "saved_model_response"],
    ) -> ChunkAnalysis:
        """Mechanically apply model judgment to the deterministic partition.

        Coverage is inherited from the deterministic base by construction --
        there is no coverage to validate because the model never writes
        address lists. Validation here checks that the OPS are well-formed:
        known cluster ids, each cluster decided exactly once, split function
        names resolvable, portable units carrying a real entry symbol. Every
        violation raises ValueError with the exact defect, which the repair
        loop feeds back; repairs re-emit the (small) op list, never addresses.
        """
        by_id = {unit.id: unit for unit in deterministic.units}
        by_name = {function.name: function for function in chunk.functions}
        functions_by_address = {function.address: function for function in chunk.functions}
        errors: list[str] = []

        referenced: list[str] = (
            [op.cluster for op in ops.refine]
            + [cluster for op in ops.merge for cluster in op.clusters]
            + [op.cluster for op in ops.split]
        )
        unknown_ids = sorted({cluster for cluster in referenced if cluster not in by_id})
        if unknown_ids:
            errors.append(f"unknown cluster ids: {unknown_ids}")
        seen: set[str] = set()
        double = sorted({cluster for cluster in referenced if cluster in seen or seen.add(cluster)})
        if double:
            errors.append(f"cluster ids decided more than once: {double}")
        undecided = sorted(set(by_id) - set(referenced))
        if undecided:
            errors.append(
                "every deterministic cluster needs exactly one decision "
                f"(refine, merge, or split); undecided: {undecided}"
            )
        if errors:
            raise ValueError("invalid refinement ops: " + "; ".join(errors))

        def judged_unit(
            unit_id: str,
            label_source: str,
            addresses: list[str],
            judgment: ClusterJudgment,
        ) -> ExecutionUnit:
            members = [functions_by_address[address] for address in addresses]
            if judgment.classification in PORTABLE_CLASSIFICATIONS:
                # Entry symbols must exist for portable units. Placeholder-only
                # entries are ACCEPTED here (a function whose only exact name is
                # FUN_xxxxxxxx cannot be named otherwise without inventing) --
                # session enrichment and unit_eligibility arbitrate them
                # downstream, exactly as before.
                if not judgment.runtime_entry_symbols:
                    raise ValueError(
                        f"unit {unit_id!r} is {judgment.classification} but names no "
                        "runtime_entry_symbols; list the exact entry function names a "
                        "production caller must reach"
                    )
            return ExecutionUnit(
                id=unit_id,
                label=judgment.label or label_source,
                classification=judgment.classification,
                summary=judgment.summary,
                function_addresses=addresses,
                external_dependencies=sorted(
                    {
                        target
                        for member in members
                        for target in member.direct_calls
                        if target not in addresses
                    }
                ),
                shared_globals=sorted(
                    {token for member in members for token in member.shared_globals}
                ),
                runtime_entry_symbols=list(dict.fromkeys(judgment.runtime_entry_symbols)),
                target_source_paths=judgment.target_source_paths,
                provenance="model_refined",
            )

        units: list[ExecutionUnit] = []
        merged_ids = {cluster for op in ops.merge for cluster in op.clusters}
        split_ids = {op.cluster for op in ops.split}
        refine_by_id = {op.cluster: op for op in ops.refine}

        for base in deterministic.units:
            if base.id in merged_ids or base.id in split_ids:
                continue
            refine_op = refine_by_id.get(base.id)
            units.append(
                judged_unit(base.id, base.label, base.function_addresses, refine_op.judgment)
            )

        for op in ops.merge:
            addresses = [
                address
                for cluster in op.clusters
                for address in by_id[cluster].function_addresses
            ]
            units.append(judged_unit(op.clusters[0], by_id[op.clusters[0]].label, addresses, op.judgment))

        for op in ops.split:
            base = by_id[op.cluster]
            base_names = {functions_by_address[a].name: a for a in base.function_addresses}
            taken: set[str] = set()
            for index, group in enumerate(op.groups, start=1):
                addresses = []
                for name in group.functions:
                    address = base_names.get(name)
                    if address is None:
                        raise ValueError(
                            f"split of {op.cluster!r}: function {name!r} is not a member "
                            f"of that cluster (members: {sorted(base_names)})"
                        )
                    if address in taken:
                        raise ValueError(
                            f"split of {op.cluster!r}: function {name!r} listed in more than one group"
                        )
                    taken.add(address)
                    addresses.append(address)
                units.append(
                    judged_unit(f"{op.cluster}-s{index}", base.label, addresses, group.judgment)
                )
            rest = [a for a in base.function_addresses if a not in taken]
            if rest:
                # Unlisted members stay together with deterministic provenance:
                # undecided work remains visible and deferred, never invented.
                units.append(
                    base.model_copy(
                        update={
                            "id": f"{op.cluster}-rest",
                            "function_addresses": rest,
                            "provenance": "deterministic",
                        }
                    )
                )

        hardware = [
            address
            for unit in units
            if unit.classification == "hardware_or_sdk"
            for address in unit.function_addresses
        ]
        game = [
            address
            for unit in units
            if unit.classification == "game_owned"
            for address in unit.function_addresses
        ]
        return ChunkAnalysis(
            chunk=chunk.name,
            chunk_sha256=chunk.sha256,
            function_count=len(chunk.functions),
            generated_by=generated_by,
            generated_at=utc_now(),
            shared_globals=deterministic.shared_globals,
            external_dependencies=deterministic.external_dependencies,
            hardware_or_sdk_functions=hardware,
            game_owned_functions=game,
            functions=deterministic.functions,
            units=units,
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
        # Refinement ops are per-CLUSTER, not per-function: the output no
        # longer scales with address transcription. Budget generously per
        # cluster (judgment text + thinking tokens share this budget).
        cluster_count = len(deterministic.units)
        max_tokens = int(
            os.getenv(
                "OGHIDRA_CHUNK_ANALYSIS_MAX_TOKENS",
                str(max(16384, 512 * cluster_count + 4096)),
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
                    schema=ChunkRefinementOps.model_json_schema(),
                    tool_name="submit_chunk_refinement",
                    model=model_name,
                    system_prompt=(
                        "You refine deterministic clusterings of Ghidra export chunks by emitting "
                        "merge/split/refine operations. Return only the requested strict structured "
                        "result; never transcribe address lists, browse source, or generate code."
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
                ops = ChunkRefinementOps.model_validate(_json_payload(raw))
                analysis = self._apply_refinement_ops(
                    chunk, deterministic, ops, generated_by="model"
                )
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
            ops = ChunkRefinementOps.model_validate(_json_payload(raw))
            analysis = self._apply_refinement_ops(
                chunk, deterministic, ops, generated_by="saved_model_response"
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
