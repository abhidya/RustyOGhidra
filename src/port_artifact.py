"""Versioned, evidence-linked function artifacts for source-derived ports."""

from __future__ import annotations

import json
import os
import time
import re
import tempfile
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator


Address = str
EvidenceTier = Literal["authoritative", "verified_derived", "observed", "inferred", "advisory"]
ClaimVerification = Literal["pending", "verified", "rejected"]
ArtifactStatus = Literal["unverified", "verified", "failed"]

ADDRESS_RE = re.compile(r"(?:0x|FUN_)?([0-9a-fA-F]{1,8})$")
HEX_LITERAL_RE = re.compile(r"0x[0-9a-fA-F]+")


def normalize_address(value: str | int) -> Address:
    """Return a canonical lowercase 32-bit address."""
    if isinstance(value, bool):
        raise ValueError("boolean is not an address")
    if isinstance(value, int):
        parsed = value
    else:
        match = ADDRESS_RE.fullmatch(str(value).strip())
        if not match:
            raise ValueError(f"invalid 32-bit address: {value!r}")
        parsed = int(match.group(1), 16)
    if parsed < 0 or parsed > 0xFFFFFFFF:
        raise ValueError(f"address is outside 32-bit range: {value!r}")
    return f"0x{parsed:08x}"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Producer(StrictModel):
    application: str = "RustyOGhidra"
    task_mode: str = "port_1to1"
    prompt_revision: str = "port-1to1-artifact-v1"
    model_provider: str
    model_name: str
    structured_output_mode: Literal["tool_call", "json_schema", "plain_json", "fixture"]


class ProgramIdentity(StrictModel):
    program_name: str
    sha256: str | None = None
    image_base: Address = "0x80000000"
    language: str = "PowerPC:BE:32"

    _normalize_base = field_validator("image_base", mode="before")(normalize_address)

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[0-9a-fA-F]{64}", value):
            raise ValueError("sha256 must contain 64 hexadecimal characters")
        return value.lower() if value else None


class FunctionIdentity(StrictModel):
    address: Address
    original_name: str
    current_name: str
    size: int | None = Field(default=None, ge=0)
    body_hash: str | None = None

    _normalize_address = field_validator("address", mode="before")(normalize_address)


class EvidenceRecord(StrictModel):
    id: str
    kind: Literal[
        "function_metadata",
        "decompile",
        "instruction",
        "caller",
        "callee",
        "data_reference",
        "raw_bytes",
        "session_summary",
    ]
    tier: EvidenceTier
    address: Address | None = None
    content: Any = None
    sha256: str | None = None

    @field_validator("address", mode="before")
    @classmethod
    def normalize_optional_address(cls, value: Any) -> Any:
        return normalize_address(value) if value is not None else None


class EvidenceBundle(StrictModel):
    records: list[EvidenceRecord] = Field(default_factory=list)
    unavailable: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_record_ids(self) -> "EvidenceBundle":
        ids = [record.id for record in self.records]
        if len(ids) != len(set(ids)):
            raise ValueError("evidence record IDs must be unique")
        return self


class Dependency(StrictModel):
    address: Address | None = None
    name: str | None = None
    status: Literal["resolved", "unresolved", "unsupported"]
    reason: str | None = None

    @field_validator("address", mode="before")
    @classmethod
    def normalize_optional_address(cls, value: Any) -> Any:
        return normalize_address(value) if value is not None else None


class Claim(StrictModel):
    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    kind: str
    value: dict[str, Any]
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_refs: list[str]
    verification: ClaimVerification = "pending"


class Analysis(StrictModel):
    classification: str | None = None
    summary: str
    claims: list[Claim] = Field(max_length=24)
    hypotheses: list[str]
    unknowns: list[str]
    dependencies: list[Dependency]
    suitability: Literal[
        "low_level_port",
        "typed_handwritten_integration",
        "table_extraction",
        "host_api_implementation",
        "further_analysis",
    ]


CONTROL_FLOW_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "label": ("id",),
    "branch_if_zero": ("target_label", "false_target"),
    "branch_if_eq": ("source", "value", "target_label", "false_target"),
    "branch_if_ne": ("source", "value", "target_label", "false_target"),
    "branch_if_false": ("source", "target_label", "false_target"),
    "branch_if_lte": ("lhs", "rhs", "target_label", "false_target"),
    "jump": ("target_label",),
    "call": ("callee", "args"),
}
TERMINATORS = {
    "return",
    "stop",
    "jump",
    "branch_if_zero",
    "branch_if_eq",
    "branch_if_ne",
    "branch_if_false",
    "branch_if_lte",
}


class PortOperation(BaseModel):
    model_config = ConfigDict(extra="allow")
    type: str
    id: str | None = None
    offset: str | None = None
    source: Any = None
    value: Any = None
    target_label: str | None = None
    false_target: str | None = None
    callee: Address | None = None
    args: list[Any] | None = None
    target: str | None = None
    lhs: Any = None
    rhs: Any = None
    mask: Any = None
    width: int | None = None
    signed: bool | None = None
    fallthrough: bool | None = None

    @field_validator("callee", mode="before")
    @classmethod
    def normalize_optional_callee(cls, value: Any) -> Any:
        return normalize_address(value) if value is not None else None

    @model_validator(mode="after")
    def validate_operands(self) -> "PortOperation":
        data = self.model_dump()
        required = CONTROL_FLOW_REQUIREMENTS.get(self.type, ())
        missing = [name for name in required if data.get(name) is None]
        if self.type == "branch_if_zero" and data.get("offset") is None and data.get("source") is None:
            missing.append("offset or source")
        if missing:
            raise ValueError(f"{self.type} requires {', '.join(missing)}")
        return self


class PortIR(StrictModel):
    kind: str
    entry: list[PortOperation]
    update: list[PortOperation]
    exit: list[PortOperation]

    @model_validator(mode="after")
    def validate_control_flow(self) -> "PortIR":
        operations = [*self.entry, *self.update, *self.exit]
        labels = {
            str(operation.id)
            for operation in operations
            if operation.type == "label" and operation.id is not None
        }
        for operation in operations:
            for field in ("target_label", "false_target"):
                target = getattr(operation, field)
                if target is not None and str(target) not in labels:
                    raise ValueError(f"{operation.type}.{field} references unknown label {target!r}")

        for sequence_name, sequence in (("entry", self.entry), ("update", self.update), ("exit", self.exit)):
            label_indexes = [index for index, operation in enumerate(sequence) if operation.type == "label"]
            for current, following in zip(label_indexes, label_indexes[1:]):
                block = sequence[current + 1 : following]
                if not block:
                    raise ValueError(f"{sequence_name} label block is empty")
                tail = block[-1]
                if tail.type not in TERMINATORS and not tail.fallthrough:
                    label = sequence[current].id
                    raise ValueError(
                        f"{sequence_name} label {label!r} falls through without an explicit terminator"
                    )
        return self


class PortModelOutput(StrictModel):
    analysis: Analysis
    port_ir: PortIR | None


class VerificationCheck(StrictModel):
    name: str
    passed: bool
    detail: str


class Verification(StrictModel):
    checks: list[VerificationCheck] = Field(default_factory=list)
    status: ArtifactStatus = "unverified"
    integration_status: Literal["not_assessed", "candidate", "blocked"] = "not_assessed"


class PortArtifact(StrictModel):
    artifact_schema: Literal[1] = 1
    producer: Producer
    program: ProgramIdentity
    function: FunctionIdentity
    evidence: EvidenceBundle
    analysis: Analysis
    port_ir: PortIR | None
    verification: Verification = Field(default_factory=Verification)


class ParsedModelOutput(StrictModel):
    output: PortModelOutput
    syntax_repairs: list[dict[str, str]] = Field(default_factory=list)


class ArtifactValidation(StrictModel):
    passed: bool
    checks_passed: int
    checks_failed: int
    checks: list[VerificationCheck]


def _repair_bare_hex_literals(text: str) -> tuple[str, list[dict[str, str]]]:
    repaired: list[str] = []
    repairs: list[dict[str, str]] = []
    index = 0
    in_string = False
    escaped = False
    while index < len(text):
        char = text[index]
        if in_string:
            repaired.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            repaired.append(char)
            index += 1
            continue
        match = HEX_LITERAL_RE.match(text, index)
        if match:
            original = match.group(0)
            replacement = str(int(original, 16))
            repaired.append(replacement)
            repairs.append({"kind": "bare_hex_to_decimal", "from": original, "to": replacement})
            index = match.end()
            continue
        repaired.append(char)
        index += 1
    return "".join(repaired), repairs


def _json_candidate(raw: str) -> str:
    stripped = (raw or "").strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", stripped, flags=re.DOTALL | re.IGNORECASE)
    return fenced.group(1) if fenced else stripped


def _load_json_payload(candidate: str) -> tuple[Any, list[dict[str, str]]]:
    """Decode one root JSON value, tolerating only text after a complete value."""
    try:
        return json.loads(candidate), []
    except json.JSONDecodeError as original_error:
        try:
            payload, end = json.JSONDecoder().raw_decode(candidate.lstrip())
        except json.JSONDecodeError:
            raise original_error
        trailing = candidate.lstrip()[end:].strip()
        if not trailing:
            raise original_error
        return payload, [
            {
                "kind": "trailing_output_ignored",
                "from": f"{len(trailing)} trailing characters",
                "to": "complete root JSON value",
            }
        ]


def _normalize_operation_aliases(payload: Any) -> list[dict[str, str]]:
    """Normalize common schema-name aliases without inventing behavior."""
    repairs: list[dict[str, str]] = []
    if not isinstance(payload, dict):
        return repairs
    port_ir = payload.get("port_ir")
    if not isinstance(port_ir, dict):
        return repairs

    for section in ("entry", "update", "exit"):
        operations = port_ir.get(section)
        if not isinstance(operations, list):
            continue
        for index, operation in enumerate(operations):
            if not isinstance(operation, dict):
                continue
            canonical_fields = {
                "id",
                "offset",
                "source",
                "value",
                "target_label",
                "false_target",
                "callee",
                "args",
                "target",
                "lhs",
                "rhs",
                "mask",
                "width",
                "signed",
                "fallthrough",
            }
            for key in list(operation):
                # Qwen occasionally emits an escaped quote as part of a field name during a
                # long structured response (for example ``target_label": ``). JSON recovery
                # can preserve that punctuation in the decoded key, so normalize only a
                # canonical field followed exclusively by harmless key punctuation.
                stripped = re.sub(r'[\s:"\\]+$', "", key)
                if key != stripped and stripped in canonical_fields and stripped not in operation:
                    operation[stripped] = operation.pop(key)
                    repairs.append(
                        {
                            "kind": f"operation_field_punctuation:{section}.{index}",
                            "from": key,
                            "to": stripped,
                        }
                    )
            operation_type = operation.get("type")
            aliases: dict[str, str] = {}
            if operation_type == "label":
                aliases["name"] = "id"
            elif operation_type == "call":
                aliases.update({"address": "callee", "function": "callee", "arguments": "args"})
            elif operation_type == "jump":
                aliases["target"] = "target_label"
            elif operation_type in {
                "branch_if_zero",
                "branch_if_eq",
                "branch_if_ne",
                "branch_if_false",
                "branch_if_lte",
                "branch_if_not_equal",
            }:
                aliases.update(
                    {
                        "true_label": "target_label",
                        "true_target": "target_label",
                        "false_label": "false_target",
                    }
                )
                if operation_type == "branch_if_lte":
                    aliases.update(
                        {
                            "lhs_var": "lhs",
                            "rhs_literal": "rhs",
                        }
                    )
                if operation_type == "branch_if_false":
                    aliases["target"] = "target_label"

            if operation_type == "branch_if_not_equal":
                operation["type"] = "branch_if_ne"
                if "target" in operation and "value" not in operation:
                    operation["value"] = operation.pop("target")
                repairs.append(
                    {
                        "kind": "operation_type_alias",
                        "from": "branch_if_not_equal",
                        "to": "branch_if_ne",
                    }
                )

            for old, new in aliases.items():
                if old in operation and new not in operation:
                    operation[new] = operation.pop(old)
                    repairs.append(
                        {
                            "kind": f"operation_field_alias:{section}.{index}",
                            "from": old,
                            "to": new,
                        }
                    )
    return repairs


def _append_terminal_labels(payload: Any) -> list[dict[str, str]]:
    """Materialize conventional terminal sentinels without inventing mechanics."""
    repairs: list[dict[str, str]] = []
    if not isinstance(payload, dict):
        return repairs
    port_ir = payload.get("port_ir")
    if not isinstance(port_ir, dict):
        return repairs

    operations = [
        operation
        for section in ("entry", "update", "exit")
        for operation in port_ir.get(section, [])
        if isinstance(operation, dict)
    ]
    labels = {
        str(operation.get("id"))
        for operation in operations
        if operation.get("type") == "label" and operation.get("id") is not None
    }
    referenced = {
        str(operation.get(field))
        for operation in operations
        for field in ("target_label", "false_target")
        if operation.get(field) is not None
    }
    missing_terminals = sorted((referenced - labels) & {"END", "EXIT", "RETURN"})
    exit_operations = port_ir.get("exit")
    if not isinstance(exit_operations, list):
        return repairs
    for label in missing_terminals:
        exit_operations.extend(({"type": "label", "id": label}, {"type": "return"}))
        repairs.append(
            {
                "kind": "missing_terminal_label",
                "from": f"undefined {label}",
                "to": f"explicit {label} return block",
            }
        )
    return repairs


def _mark_explicit_fallthrough(payload: Any) -> list[dict[str, str]]:
    """Make list-order fallthrough explicit without changing its destination."""
    repairs: list[dict[str, str]] = []
    if not isinstance(payload, dict):
        return repairs
    port_ir = payload.get("port_ir")
    if not isinstance(port_ir, dict):
        return repairs

    for section in ("entry", "update", "exit"):
        operations = port_ir.get(section)
        if not isinstance(operations, list):
            continue
        label_indexes = [
            index
            for index, operation in enumerate(operations)
            if isinstance(operation, dict) and operation.get("type") == "label"
        ]
        for current, following in zip(label_indexes, label_indexes[1:]):
            block = operations[current + 1 : following]
            if not block or not isinstance(block[-1], dict):
                continue
            tail = block[-1]
            if tail.get("type") in TERMINATORS or tail.get("fallthrough") is not None:
                continue
            tail["fallthrough"] = True
            repairs.append(
                {
                    "kind": f"explicit_fallthrough:{section}.{following - 1}",
                    "from": "implicit list-order fallthrough",
                    "to": str(operations[following].get("id")),
                }
            )
    return repairs


def parse_model_output(raw: str) -> ParsedModelOutput:
    candidate = _json_candidate(raw)
    repairs: list[dict[str, str]] = []
    try:
        payload, load_repairs = _load_json_payload(candidate)
        repairs.extend(load_repairs)
    except json.JSONDecodeError:
        candidate, hex_repairs = _repair_bare_hex_literals(candidate)
        repairs.extend(hex_repairs)
        try:
            payload, load_repairs = _load_json_payload(candidate)
            repairs.extend(load_repairs)
        except json.JSONDecodeError as error:
            raise ValueError(f"response does not contain valid port model JSON: {error}") from error
    repairs.extend(_normalize_operation_aliases(payload))
    repairs.extend(_append_terminal_labels(payload))
    repairs.extend(_mark_explicit_fallthrough(payload))
    try:
        output = PortModelOutput.model_validate(payload)
    except ValidationError as error:
        # Port IR is optional and never authoritative. If Qwen produced a valid evidence-linked
        # analysis but corrupted only the proposed IR, retain the analysis and force downstream
        # code generation to use deterministic evidence/importer profiles.
        if not error.errors() or any(
            tuple(item.get("loc", ()))[:1] != ("port_ir",)
            for item in error.errors()
        ):
            raise
        analysis = Analysis.model_validate(payload.get("analysis"))
        output = PortModelOutput(analysis=analysis, port_ir=None)
        repairs.append(
            {
                "kind": "invalid_port_ir_dropped",
                "from": f"{len(error.errors())} Port IR validation error(s)",
                "to": "null Port IR; retain validated analysis only",
            }
        )
    return ParsedModelOutput(output=output, syntax_repairs=repairs)


def _flatten_values(value: Any, path: tuple[str, ...] = ()):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _flatten_values(child, (*path, str(key)))
    elif isinstance(value, list):
        for child in value:
            yield from _flatten_values(child, path)
    else:
        yield path, value


def _literal_forms(value: Any) -> set[str]:
    if isinstance(value, bool):
        return {str(value).lower()}
    if isinstance(value, int):
        hexadecimal = f"-0x{abs(value):x}" if value < 0 else f"0x{value:x}"
        return {str(value), hexadecimal}
    if isinstance(value, float):
        return {str(value), f"{value:g}"}
    if isinstance(value, str):
        tokens = re.findall(
            r"(?<![0-9a-z_])(?:-?0x[0-9a-f]+|-?\d+(?:\.\d+)?)(?![0-9a-z_])",
            value.lower(),
        )
        forms: set[str] = set()
        for token in tokens:
            if re.fullmatch(r"-?0x[0-9a-f]+", token):
                sign = -1 if token.startswith("-") else 1
                forms.update(_literal_forms(sign * int(token.removeprefix("-"), 16)))
            elif re.fullmatch(r"-?\d+", token):
                forms.update(_literal_forms(int(token)))
            else:
                forms.update(_literal_forms(float(token)))
        return forms
    return set()


def _address_forms(value: Any) -> set[str]:
    try:
        normalized = normalize_address(value)
    except (TypeError, ValueError):
        return set()
    compact = normalized[2:]
    forms = {normalized, compact}
    if compact.startswith("80"):
        forms.add(compact[1:])
    return forms


def _contains_form(text: str, forms: set[str]) -> bool:
    for form in forms:
        escaped = re.escape(form.lower())
        if re.search(rf"(?<![0-9a-z]){escaped}(?![0-9a-z])", text):
            return True
    return False


def _claim_requirements(claim: Claim) -> tuple[list[set[str]], list[set[str]]]:
    requirements: list[set[str]] = []
    anchors: list[set[str]] = []
    for path, value in _flatten_values(claim.value):
        key = path[-1].lower() if path else ""
        if "address" in key or key == "callee":
            forms = _address_forms(value)
            if not forms and isinstance(value, str):
                forms = _literal_forms(value)
            if forms:
                requirements.append(forms)
                anchors.append(forms)
        elif "offset" in key:
            forms = _literal_forms(value)
            if forms:
                requirements.append(forms)
                anchors.append(forms)
        elif key in {"value", "argument", "constant", "mask"} and isinstance(value, (int, float, str)):
            forms = _literal_forms(value)
            if forms:
                requirements.append(forms)
        elif key == "args" and isinstance(value, (int, float)):
            requirements.append(_literal_forms(value))
    return [forms for forms in requirements if forms], [forms for forms in anchors if forms]


def enrich_claim_evidence(artifact: PortArtifact) -> list[dict[str, str]]:
    """Append authoritative evidence only when it supplies a missing anchored literal."""
    evidence_by_id = {record.id: record for record in artifact.evidence.records}
    qualifying = [
        record
        for record in artifact.evidence.records
        if record.tier in {"authoritative", "verified_derived", "observed"}
    ]
    enrichments: list[dict[str, str]] = []

    for claim in artifact.analysis.claims:
        cited_records = [evidence_by_id[ref] for ref in claim.evidence_refs if ref in evidence_by_id]
        cited_text = json.dumps(
            [record.model_dump(mode="json") for record in cited_records],
            sort_keys=True,
        ).lower()
        requirements, anchors = _claim_requirements(claim)
        missing = [forms for forms in requirements if not _contains_form(cited_text, forms)]
        if not missing or not anchors:
            continue

        for record in qualifying:
            if record.id in claim.evidence_refs:
                continue
            if isinstance(record.content, str):
                fragments = [
                    json.dumps(
                        {"address": record.address, "content": fragment},
                        sort_keys=True,
                    ).lower()
                    for fragment in re.split(r"[\r\n;]+", record.content)
                    if fragment.strip()
                ]
            else:
                fragments = [json.dumps(record.model_dump(mode="json"), sort_keys=True).lower()]
            correlated = any(
                any(_contains_form(fragment, forms) for forms in anchors)
                and all(_contains_form(fragment, forms) for forms in missing)
                for fragment in fragments
            )
            if not correlated:
                continue
            claim.evidence_refs.append(record.id)
            enrichments.append(
                {
                    "claim_id": claim.id,
                    "evidence_id": record.id,
                    "reason": "authoritative record contains the claim anchor and every missing literal",
                }
            )
            break
    return enrichments


def prune_rejected_claims(artifact: PortArtifact) -> list[dict[str, str]]:
    """Remove model claims that deterministic evidence validation rejected."""
    retained: list[Claim] = []
    pruned: list[dict[str, str]] = []
    for claim in artifact.analysis.claims:
        if claim.verification != "rejected":
            retained.append(claim)
            continue
        pruned.append(
            {
                "claim_id": claim.id,
                "reason": "deterministic evidence validation rejected the model claim",
                "value": json.dumps(claim.value, sort_keys=True),
            }
        )
    artifact.analysis.claims = retained
    return pruned


def validate_port_artifact(artifact: PortArtifact) -> ArtifactValidation:
    """Validate mechanical claims without consulting another model and update status in-place."""
    checks: list[VerificationCheck] = []

    def add(name: str, passed: bool, detail: str) -> None:
        checks.append(VerificationCheck(name=name, passed=passed, detail=detail))

    evidence_by_id = {record.id: record for record in artifact.evidence.records}
    add("schema-version", artifact.artifact_schema == 1, "artifact_schema must be 1")
    add(
        "normalized-function-address",
        artifact.function.address == normalize_address(artifact.function.address),
        "function address must be canonical",
    )
    add("claims-present", bool(artifact.analysis.claims), "analysis must contain at least one claim")

    unresolved = [
        dependency
        for dependency in artifact.analysis.dependencies
        if dependency.status in {"unresolved", "unsupported"}
    ]
    add(
        "dependencies-explicit",
        all(dependency.status in {"resolved", "unresolved", "unsupported"} for dependency in artifact.analysis.dependencies),
        "every dependency must carry an explicit resolution status",
    )

    for claim in artifact.analysis.claims:
        cited = [evidence_by_id.get(ref) for ref in claim.evidence_refs]
        refs_valid = bool(cited) and all(record is not None for record in cited)
        add(
            f"claim-evidence:{claim.id}",
            refs_valid,
            "every claim must cite existing evidence records",
        )
        qualifying = [
            record
            for record in cited
            if record is not None and record.tier in {"authoritative", "verified_derived", "observed"}
        ]
        add(
            f"claim-authority:{claim.id}",
            bool(qualifying),
            "mechanical claims require authoritative, verified-derived, or observed evidence",
        )
        cited_text = json.dumps(
            [record.model_dump(mode="json") for record in qualifying],
            sort_keys=True,
        ).lower()
        literal_checks: list[bool] = []
        for path, value in _flatten_values(claim.value):
            key = path[-1].lower() if path else ""
            if "address" in key or key == "callee":
                try:
                    normalized = normalize_address(value)
                except (TypeError, ValueError):
                    forms = _literal_forms(value) if isinstance(value, str) else set()
                    literal_checks.append(bool(forms) and _contains_form(cited_text, forms))
                else:
                    literal_checks.append(_contains_form(cited_text, _address_forms(normalized)))
            elif "offset" in key:
                forms = _literal_forms(value)
                literal_checks.append(bool(forms) and _contains_form(cited_text, forms))
            elif key in {"value", "argument", "constant", "mask"} and isinstance(value, (int, float, str)):
                forms = _literal_forms(value)
                if forms:
                    literal_checks.append(_contains_form(cited_text, forms))
            elif key == "args" and isinstance(value, (int, float)):
                literal_checks.append(_contains_form(cited_text, _literal_forms(value)))
        literals_valid = all(literal_checks)
        add(
            f"claim-mechanics:{claim.id}",
            literals_valid,
            "claimed addresses, offsets, and numeric literals must occur in cited evidence",
        )
        claim.verification = "verified" if refs_valid and bool(qualifying) and literals_valid else "rejected"

    passed = all(check.passed for check in checks)
    artifact.verification = Verification(
        checks=checks,
        status="verified" if passed else "failed",
        integration_status="blocked" if unresolved or not passed else "candidate",
    )
    return ArtifactValidation(
        passed=passed,
        checks_passed=sum(check.passed for check in checks),
        checks_failed=sum(not check.passed for check in checks),
        checks=checks,
    )


def atomic_write_artifact(path: os.PathLike[str] | str, artifact: PortArtifact) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(artifact.model_dump_json(indent=2))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        # Windows denies replacement while another process holds the destination
        # open (antivirus, indexer). Wait out the transient sharing violation
        # rather than discarding output that is already written.
        for attempt in range(40):
            try:
                os.replace(temporary, target)
                break
            except PermissionError:
                if os.name != "nt" or attempt == 39:
                    raise
                time.sleep(0.05)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
