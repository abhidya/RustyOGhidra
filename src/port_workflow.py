"""Evidence gates and deterministic artifacts for Gotcha Force 1:1 ports."""

from __future__ import annotations

import json
import math
import os
import tempfile
import hashlib
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence


PORT_MODE = "port_1to1"
DOSSIER_VERSION = 1
EVIDENCE_TIERS = (
    "authoritative",
    "verified_derived",
    "observed",
    "inferred",
    "advisory",
)
DERIVED_ROM_TIERS = frozenset({"authoritative", "verified_derived", "observed"})
CLAIM_STATUSES = frozenset({"DERIVED_ROM", "OBSERVED", "INFERRED", "TUNED", "BLOCKED"})


PORT_PLANNING_PROMPT = """
You are planning an evidence-first 1:1 port of Gotcha Force (GG4E) from GameCube PowerPC code.
Scope exactly one Borg family and one action index at a time. Plan to locate the constructor,
root action dispatcher, variant routing, phase tables, every reachable phase function, helper
arguments, raw DOL constants, actor-field reads/writes, transitions, and unresolved host gates.
Use function-summary search only for discovery. Every mechanical conclusion must be re-opened in
the decompile/disassembly or a decoded ROM table. The required deliverable is a structured port
dossier, implementation targets, transition tests, and named blockers—not a naming report.
""".strip()

PORT_EXECUTION_PROMPT = """
You are extracting checkable mechanics for a 1:1 Gotcha Force port.

Follow this order: SCOPE -> CONSTRUCTOR -> DISPATCH -> TABLES -> PHASES -> HELPERS -> VERIFY.
Do not bulk-dump unrelated functions. For every claim preserve address/range, integer width and
signedness, raw float bits, comparison direction, branch fallthrough, table stride/index, casts,
read-before-write order, helper arguments, and side effects. Unknown fields remain field_0xNNN.

Evidence tiers:
- authoritative: DOL bytes, disassembly, decompile, symbol map, decoded table
- verified_derived: reviewed dossier/port finding backed by authoritative citations
- observed: Dolphin trace
- inferred: LLM hypothesis or prior summary
- advisory: wiki or general notes

Only authoritative, verified_derived, or observed evidence may support DERIVED_ROM. Search results,
prior LLM summaries, inferred references, and wiki prose are leads only. Explicitly record
contradictions and host-dependent blockers. Never invent a fallback to make a phase look complete.
""".strip()

PORT_ANALYSIS_PROMPT = """
Synthesize the gathered evidence into a version-1 port dossier. Separate literal mechanics from
semantic interpretation. Include action/variant/phase routing, claims, evidence citations,
unresolved host gates, and boundary test vectors. Mark unsupported conclusions INFERRED or BLOCKED.
Do not promote a claim merely because multiple LLM summaries repeat it. End with exactly one
```json fenced object conforming to schemas/port-dossier.schema.json so it can be validated and
saved automatically. Prose may precede the fence; nothing may follow it.
""".strip()

PORT_EVALUATION_PROMPT = """
Act as an adversarial verifier of a proposed Gotcha Force 1:1 port dossier. Try to disprove every
claim against the cited bytes, decompile, disassembly, tables, and traces. Check missing branches,
wrong signedness/width, float conversion, comparison direction, fallthrough, table indexing,
dropped helper arguments, caller/callee confusion, and unresolved host returns. Reject any
DERIVED_ROM claim without a concrete address/range and qualifying evidence.
""".strip()

PORT_REVIEW_PROMPT = """
Review the proposed port for evidence completeness, not plausibility. APPROVE only if every
DERIVED_ROM behavior is cited, all reachable variants/phases are accounted for, contradictions are
resolved or blocked, generated transition tests cover branch boundaries, and remaining host gates
are explicit. Otherwise return NEEDS_IMPROVEMENT with exact missing addresses or evidence.
""".strip()


def prompt_for_phase(phase: str) -> str:
    prompts = {
        "planning": PORT_PLANNING_PROMPT,
        "execution": PORT_EXECUTION_PROMPT,
        "analysis": PORT_ANALYSIS_PROMPT,
        "evaluation": PORT_EVALUATION_PROMPT,
        "review": PORT_REVIEW_PROMPT,
    }
    return prompts.get(phase, PORT_EXECUTION_PROMPT)


@dataclass(frozen=True)
class ValidationResult:
    errors: List[str]
    warnings: List[str]

    @property
    def valid(self) -> bool:
        return not self.errors


def _is_address(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    value = value.lower()
    if value.startswith("0x"):
        value = value[2:]
    return len(value) == 8 and all(c in "0123456789abcdef" for c in value)


def _validate_evidence(evidence: Any, path: str, errors: List[str]) -> List[str]:
    qualifying: List[str] = []
    if not isinstance(evidence, list) or not evidence:
        errors.append(f"{path} must contain at least one evidence record")
        return qualifying
    for index, item in enumerate(evidence):
        ep = f"{path}[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{ep} must be an object")
            continue
        tier = item.get("tier")
        if tier not in EVIDENCE_TIERS:
            errors.append(f"{ep}.tier must be one of {', '.join(EVIDENCE_TIERS)}")
        source = item.get("source")
        if not isinstance(source, str) or not source.strip():
            errors.append(f"{ep}.source is required")
        if tier in DERIVED_ROM_TIERS:
            qualifying.append(str(tier))
    return qualifying


def validate_dossier(payload: Any) -> ValidationResult:
    errors: List[str] = []
    warnings: List[str] = []
    if not isinstance(payload, dict):
        return ValidationResult(["dossier must be a JSON object"], warnings)
    if payload.get("version") != DOSSIER_VERSION:
        errors.append(f"version must be {DOSSIER_VERSION}")
    scope = payload.get("scope")
    if not isinstance(scope, dict):
        errors.append("scope must be an object")
    else:
        if not str(scope.get("family", "")).strip():
            errors.append("scope.family is required")
        if not isinstance(scope.get("actionIndex"), int) or scope.get("actionIndex") < 0:
            errors.append("scope.actionIndex must be a non-negative integer")
        ctor = scope.get("constructorAddress")
        if ctor is not None and not _is_address(ctor):
            errors.append("scope.constructorAddress must be an 8-digit address")

    claims = payload.get("claims")
    if not isinstance(claims, list) or not claims:
        errors.append("claims must be a non-empty list")
        claims = []
    ids = set()
    for index, claim in enumerate(claims):
        cp = f"claims[{index}]"
        if not isinstance(claim, dict):
            errors.append(f"{cp} must be an object")
            continue
        claim_id = claim.get("claimId")
        if not isinstance(claim_id, str) or not claim_id.strip():
            errors.append(f"{cp}.claimId is required")
        elif claim_id in ids:
            errors.append(f"{cp}.claimId duplicates {claim_id}")
        else:
            ids.add(claim_id)
        status = claim.get("status")
        if status not in CLAIM_STATUSES:
            errors.append(f"{cp}.status must be one of {', '.join(sorted(CLAIM_STATUSES))}")
        function = claim.get("function")
        address_range = claim.get("addressRange")
        if function is not None and not _is_address(function):
            errors.append(f"{cp}.function must be an 8-digit address")
        has_range = (
            isinstance(address_range, list)
            and len(address_range) == 2
            and all(_is_address(address) for address in address_range)
        )
        if status == "DERIVED_ROM" and not (has_range or _is_address(function)):
            errors.append(f"{cp} DERIVED_ROM requires function or addressRange")
        qualifying = _validate_evidence(claim.get("evidence"), f"{cp}.evidence", errors)
        if status == "DERIVED_ROM" and not qualifying:
            errors.append(f"{cp} DERIVED_ROM requires authoritative, verified_derived, or observed evidence")
        if not str(claim.get("statement", "")).strip():
            errors.append(f"{cp}.statement is required")
        if status in {"INFERRED", "TUNED", "BLOCKED"} and not claim.get("unresolved"):
            warnings.append(f"{cp} should explain its unresolved evidence or blocker")

    for field in ("variants", "phases", "blockers", "tests"):
        value = payload.get(field, [])
        if not isinstance(value, list):
            errors.append(f"{field} must be a list")
    return ValidationResult(errors, warnings)


def atomic_write_json(path: os.PathLike[str] | str, payload: Mapping[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False, default=str)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        # Windows denies replacement while another process has the destination
        # briefly open (GUI polling, antivirus, indexer). Preserve atomic writes,
        # but wait out the transient sharing violation instead of killing the run.
        for attempt in range(40):
            try:
                os.replace(tmp_name, target)
                break
            except PermissionError:
                if os.name != "nt" or attempt == 39:
                    raise
                time.sleep(0.05)
    except Exception:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def extract_dossier(text: str) -> Dict[str, Any] | None:
    """Return the first valid dossier embedded as fenced or raw JSON."""
    candidates = re.findall(r"```json\s*(\{.*?\})\s*```", text or "", flags=re.DOTALL | re.IGNORECASE)
    stripped = (text or "").strip()
    if stripped.startswith("{"):
        candidates.append(stripped)
    for candidate in candidates:
        try:
            payload = json.loads(candidate)
        except (TypeError, ValueError):
            continue
        if validate_dossier(payload).valid:
            return payload
    return None


def build_evidence_bundle(
    scope: Mapping[str, Any], sources: Sequence[Mapping[str, Any]], include_content: bool = True
) -> Dict[str, Any]:
    """Build a deterministic, tiered context bundle from explicitly selected local sources."""
    rows = []
    for source in sources:
        path = Path(str(source["path"]))
        tier = str(source["tier"])
        if tier not in EVIDENCE_TIERS:
            raise ValueError(f"invalid evidence tier: {tier}")
        raw = path.read_bytes()
        row = {
            "path": str(path.resolve()),
            "tier": tier,
            "kind": str(source.get("kind", "document")),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
        }
        if include_content:
            row["content"] = raw.decode("utf-8", errors="replace")
        rows.append(row)
    rows.sort(key=lambda row: (EVIDENCE_TIERS.index(row["tier"]), row["path"]))
    return {"version": 1, "scope": dict(scope), "sources": rows}


def load_trace(path: os.PathLike[str] | str) -> List[Dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    frames = data.get("frames") if isinstance(data, dict) else data
    if not isinstance(frames, list):
        raise ValueError("trace must be a list or an object containing a frames list")
    return frames


def _equal_value(left: Any, right: Any, tolerance: float) -> bool:
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        if isinstance(left, bool) or isinstance(right, bool):
            return left == right
        return math.isclose(float(left), float(right), rel_tol=0.0, abs_tol=tolerance)
    return left == right


def compare_traces(
    rom_frames: Sequence[Mapping[str, Any]],
    port_frames: Sequence[Mapping[str, Any]],
    fields: Iterable[str] | None = None,
    tolerance: float = 1e-6,
) -> Dict[str, Any]:
    common = min(len(rom_frames), len(port_frames))
    for index in range(common):
        rom = rom_frames[index]
        port = port_frames[index]
        keys = list(fields) if fields is not None else sorted(set(rom) | set(port))
        differences = {
            key: {"rom": rom.get(key), "port": port.get(key)}
            for key in keys
            if not _equal_value(rom.get(key), port.get(key), tolerance)
        }
        if differences:
            return {"match": False, "frameIndex": index, "differences": differences}
    if len(rom_frames) != len(port_frames):
        return {
            "match": False,
            "frameIndex": common,
            "differences": {"frameCount": {"rom": len(rom_frames), "port": len(port_frames)}},
        }
    return {"match": True, "framesCompared": common, "differences": {}}
