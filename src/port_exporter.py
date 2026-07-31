"""Structured generation, bounded repair, validation, and export."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from src.port_artifact import (
    ArtifactValidation,
    PortArtifact,
    PortModelOutput,
    Producer,
    Verification,
    atomic_write_artifact,
    enrich_claim_evidence,
    normalize_address,
    parse_model_output,
    prune_rejected_claims,
    validate_port_artifact,
)
from src.port_evidence import CollectedFunction


PROMPT_REVISION = "port-1to1-artifact-v1"


@dataclass(frozen=True)
class ExportResult:
    artifact: PortArtifact
    report: ArtifactValidation
    attempts: int
    output_path: Path


def build_port_prompt(
    collected: CollectedFunction,
    generation_requirements: str | None = None,
) -> str:
    schema = PortModelOutput.model_json_schema()
    evidence = collected.model_dump(mode="json")
    requirements = (
        "\n\nDeterministic downstream integration requirements:\n"
        + generation_requirements.strip()
        + "\nSatisfy these only when the collected evidence supports them; never invent a value."
        if generation_requirements and generation_requirements.strip()
        else ""
    )
    return f"""
Produce the structured analysis and language-neutral port IR for one source-derived function.
Return only data conforming to the supplied schema.

Rules:
- Authoritative evidence supports mechanical observations; advisory session summaries are leads only.
- Preserve exact control flow, widths, signedness, comparison direction, helper arguments, and addresses.
- Every claim needs a stable ID and evidence_refs that exactly match evidence record IDs.
- Emit no more than 24 grouped mechanical claims. Do not echo one claim per instruction.
- Claim value must be an object with explicit fields such as offset, value, width, callee, or args.
- Group repeated calls and related control flow. Reserve claims for source-relevant effects exposed
  by direct-callee decompiles instead of spending the entire claim budget on instruction echoes.
- Cite a decompile record whenever a claim contains normalized literals or call arguments that are
  not printed literally in the cited assembly instruction.
- Put semantic interpretations in hypotheses, never in mechanical field names.
- Treat current and historical function names as hypotheses, not proof of game semantics.
- List unresolved/unsupported callees and host behaviors in dependencies.
- Use explicit true and false targets for conditional IR operations.
- Every target_label and false_target must name a label operation emitted in this same port_ir.
- For a function exit, emit an explicit RETURN label and return operation.
- Use an explicit jump/return between labeled blocks; do not rely on accidental fallthrough.
- Use only these canonical control-flow shapes:
  label: {{"type":"label","id":"BLOCK"}}
  call: {{"type":"call","callee":"0x80000000","args":["param_1",1]}}
  jump: {{"type":"jump","target_label":"BLOCK"}}
  branch_if_zero: {{"type":"branch_if_zero","source":"flag","target_label":"ZERO","false_target":"NONZERO"}}
  branch_if_eq/ne: {{"type":"branch_if_eq","source":"state","value":1543,"target_label":"MATCH","false_target":"OTHER"}}
  branch_if_lte: {{"type":"branch_if_lte","lhs":"timer","rhs":0.0,"target_label":"EXPIRED","false_target":"ACTIVE"}}
- Never use name for label IDs, address/function for call targets, arguments for call args,
  target for jump labels, true_label/false_label, or invented branch type names.
- A failed/small decompile is not a source stub when disassembly exists.
- Do not emit placeholder behavior or declare the function integrated.
- Keep every claim verification value as "pending"; deterministic code owns promotion.

Pydantic JSON schema:
{json.dumps(schema, indent=2, sort_keys=True)}

Collected evidence:
{json.dumps(evidence, indent=2, sort_keys=True)}
{requirements}
""".strip()


def build_repair_prompt(raw: str, failures: list[str], collected: CollectedFunction) -> str:
    schema = PortModelOutput.model_json_schema()
    return f"""
Repair one structured port-model response. Return the complete corrected object only.
Do not add evidence, change provenance, or mark claims verified. Preserve already-correct claims.
Claim value must be an object. Use only the canonical PortOperation field names in the schema.
For every branch, supply both target_label and false_target.
Every target_label and false_target must name an emitted label. If a branch exits the function,
emit an explicit terminal label and return operation.
Never change an address, constant, mask, offset, argument, or branch direction just to satisfy a
validator. Add the authoritative evidence reference containing the same mechanic. If the mechanic
is actually unsupported, remove that claim and put the uncertainty in unknowns.

Deterministic failures:
{json.dumps(failures, indent=2)}

Valid evidence IDs:
{json.dumps([record.id for record in collected.evidence.records], indent=2)}

Authoritative and advisory evidence:
{json.dumps(collected.evidence.model_dump(mode="json"), indent=2, sort_keys=True)}

Pydantic JSON schema:
{json.dumps(schema, indent=2, sort_keys=True)}

Response to repair:
{raw}
""".strip()


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _sidecar_path(output_path: Path, suffix: str) -> Path:
    return output_path.with_name(f"{output_path.stem}.{suffix}")


def _generate(llm, prompt: str, schema: dict[str, Any]) -> tuple[str, str]:
    if hasattr(llm, "generate_structured"):
        return llm.generate_structured(
            prompt=prompt,
            schema=schema,
            tool_name="submit_port_model",
            system_prompt=(
                "You are a compiler-pipeline reverse engineer. Evidence outranks prior prose. "
                "Return mechanically exact structured data."
            ),
            temperature=0.1,
            max_tokens=24000,
            phase="analysis",
            prefer_json_schema=True,
        )
    return (
        llm.generate(
            prompt=prompt,
            system_prompt="Return strict JSON for a mechanically exact source-derived port.",
            temperature=0.1,
            max_tokens=24000,
            phase="analysis",
        ),
        "plain_json",
    )


def _assemble(
    collected: CollectedFunction,
    output: PortModelOutput,
    *,
    model_provider: str,
    model_name: str,
    structured_output_mode: str,
) -> PortArtifact:
    for claim in output.analysis.claims:
        claim.verification = "pending"
    return PortArtifact(
        producer=Producer(
            prompt_revision=PROMPT_REVISION,
            model_provider=model_provider,
            model_name=model_name,
            structured_output_mode=structured_output_mode,
        ),
        program=collected.program,
        function=collected.function,
        evidence=collected.evidence,
        analysis=output.analysis,
        port_ir=output.port_ir,
        verification=Verification(status="unverified"),
    )


def _validation_failures(report: ArtifactValidation, artifact: PortArtifact) -> list[str]:
    claims = {claim.id: claim for claim in artifact.analysis.claims}
    failures: list[str] = []
    for check in report.checks:
        if check.passed:
            continue
        detail = f"{check.name}: {check.detail}"
        if check.name.startswith("claim-mechanics:"):
            claim_id = check.name.removeprefix("claim-mechanics:")
            claim = claims.get(claim_id)
            if claim is not None:
                detail += f"; rejected claim={claim.model_dump_json()}"
        failures.append(detail)
    return failures


def attach_session_sidecar(session_path: Path, artifact_path: Path, artifact: PortArtifact) -> Path:
    sidecar = session_path.parent / "port-artifacts.json"
    if sidecar.exists():
        payload = json.loads(sidecar.read_text(encoding="utf-8"))
    else:
        payload = {"schema": 1, "artifacts": []}
    records = [
        record
        for record in payload.get("artifacts", [])
        if record.get("function_address") != artifact.function.address
    ]
    records.append(
        {
            "function_address": artifact.function.address,
            "path": str(artifact_path.resolve()),
            "body_hash": artifact.function.body_hash,
            "artifact_schema": artifact.artifact_schema,
        }
    )
    records.sort(key=lambda record: (record["function_address"], record["path"]))
    payload["artifacts"] = records
    _atomic_write_json(sidecar, payload)
    return sidecar


def export_port_artifact(
    *,
    collected: CollectedFunction,
    llm,
    output_path: str | Path,
    model_provider: str,
    model_name: str,
    session_path: str | Path | None = None,
    generation_requirements: str | None = None,
) -> ExportResult:
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write_json(
        _sidecar_path(target, "evidence.json"),
        collected.model_dump(mode="json"),
    )

    prompt = build_port_prompt(collected, generation_requirements)
    _sidecar_path(target, "prompt.txt").write_text(prompt + "\n", encoding="utf-8")
    schema = PortModelOutput.model_json_schema()
    attempts = 0
    failures: list[str] = []
    artifact: PortArtifact | None = None
    report: ArtifactValidation | None = None
    raw = ""
    syntax_repairs: list[dict[str, str]] = []
    evidence_enrichments: list[dict[str, str]] = []
    claim_prunings: list[dict[str, str]] = []

    while attempts < 3:
        attempts += 1
        generation_prompt = prompt if attempts == 1 else build_repair_prompt(raw, failures, collected)
        raw, mode = _generate(llm, generation_prompt, schema)
        _sidecar_path(target, f"raw-attempt-{attempts}.txt").write_text(raw + "\n", encoding="utf-8")
        try:
            parsed = parse_model_output(raw)
            syntax_repairs = parsed.syntax_repairs
            artifact = _assemble(
                collected,
                parsed.output,
                model_provider=model_provider,
                model_name=model_name,
                structured_output_mode=mode,
            )
            evidence_enrichments = enrich_claim_evidence(artifact)
            report = validate_port_artifact(artifact)
            claim_prunings = prune_rejected_claims(artifact)
            if claim_prunings:
                report = validate_port_artifact(artifact)
            failures = _validation_failures(report, artifact)
            if report.passed:
                break
        except (ValueError, ValidationError) as error:
            failures = [str(error)]

    if artifact is None or report is None:
        _atomic_write_json(
            _sidecar_path(target, "validation.json"),
            {
                "passed": False,
                "attempts": attempts,
                "errors": failures,
                "model_metrics": getattr(llm, "generation_metrics", {}),
                "collection_metrics": collected.collection_metrics,
            },
        )
        raise ValueError("model output failed Pydantic parsing after bounded repair: " + "; ".join(failures))

    _atomic_write_json(
        _sidecar_path(target, "validation.json"),
        {
            **report.model_dump(mode="json"),
            "attempts": attempts,
            "syntax": "pydantic-v2",
            "syntax_repairs": syntax_repairs,
            "evidence_enrichments": evidence_enrichments,
            "claim_prunings": claim_prunings,
            "model_metrics": getattr(llm, "generation_metrics", {}),
            "collection_metrics": collected.collection_metrics,
        },
    )
    atomic_write_artifact(target, artifact)
    if session_path is not None:
        attach_session_sidecar(Path(session_path), target, artifact)
    return ExportResult(artifact=artifact, report=report, attempts=attempts, output_path=target)


def historical_summary(session_path: str | Path, address: str | int) -> str | None:
    payload = json.loads(Path(session_path).read_text(encoding="utf-8"))
    functions = payload.get("analyzed_functions", {})
    normalized = normalize_address(address)[2:]
    candidates = (normalized, f"0x{normalized}", f"FUN_{normalized}")
    for key in candidates:
        value = functions.get(key)
        if isinstance(value, dict) and value.get("behavior_summary"):
            return str(value["behavior_summary"])
    for value in functions.values():
        if not isinstance(value, dict):
            continue
        try:
            item_address = normalize_address(value.get("address", ""))
        except ValueError:
            continue
        if item_address == f"0x{normalized}" and value.get("behavior_summary"):
            return str(value["behavior_summary"])
    return None
