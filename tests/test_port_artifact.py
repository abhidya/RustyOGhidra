import json

import pytest
from pydantic import ValidationError

from src.port_artifact import (
    Analysis,
    Claim,
    Dependency,
    EvidenceBundle,
    EvidenceRecord,
    FunctionIdentity,
    PortArtifact,
    PortIR,
    PortModelOutput,
    Producer,
    ProgramIdentity,
    Verification,
    atomic_write_artifact,
    enrich_claim_evidence,
    normalize_address,
    parse_model_output,
    prune_rejected_claims,
    validate_port_artifact,
)


def model_output_dict():
    return {
        "analysis": {
            "classification": "code_driven_state_handler",
            "summary": "Writes a mode byte and seeds a timer.",
            "claims": [
                {
                    "id": "mode-write",
                    "kind": "memory_write",
                    "value": {"offset": "0x6e8", "value": "0x83", "width": 1},
                    "confidence": 1.0,
                    "evidence_refs": ["decompile:0x8012b458"],
                    "verification": "pending",
                }
            ],
            "hypotheses": [],
            "unknowns": [],
            "dependencies": [],
            "suitability": "typed_handwritten_integration",
        },
        "port_ir": {
            "kind": "per_frame_state_handler",
            "entry": [
                {
                    "type": "branch_if_zero",
                    "offset": "0x540",
                    "target_label": "INIT",
                    "false_target": "UPDATE",
                }
            ],
            "update": [
                {"type": "label", "id": "INIT"},
                {"type": "jump", "target_label": "RETURN"},
                {"type": "label", "id": "UPDATE"},
                {"type": "jump", "target_label": "RETURN"},
                {"type": "label", "id": "RETURN"},
                {"type": "return"},
            ],
            "exit": [{"type": "return"}],
        },
    }


def artifact():
    output = PortModelOutput.model_validate(model_output_dict())
    return PortArtifact(
        producer=Producer(
            model_provider="custom_api",
            model_name="qwen-test",
            structured_output_mode="tool_call",
        ),
        program=ProgramIdentity(program_name="boot.dol"),
        function=FunctionIdentity(
            address="8012B458",
            original_name="FUN_8012b458",
            current_name="FUN_8012b458",
        ),
        evidence=EvidenceBundle(
            records=[
                EvidenceRecord(
                    id="decompile:0x8012b458",
                    kind="decompile",
                    tier="authoritative",
                    address="0x8012b458",
                    content="*(undefined1 *)(param_1 + 0x6e8) = 0x83;",
                )
            ]
        ),
        analysis=output.analysis,
        port_ir=output.port_ir,
        verification=Verification(),
    )


def test_structured_model_output_parsing():
    parsed = parse_model_output(json.dumps(model_output_dict()))
    assert parsed.output.analysis.classification == "code_driven_state_handler"
    assert parsed.output.port_ir.update[-1].type == "return"
    assert parsed.syntax_repairs == []


def test_bare_hex_json_is_repaired_but_unrecoverable_json_is_rejected():
    raw = json.dumps(model_output_dict()).replace('"value": "0x83"', '"value": 0x83')
    parsed = parse_model_output(raw)
    assert parsed.output.analysis.claims[0].value["value"] == 131
    assert parsed.syntax_repairs[0]["kind"] == "bare_hex_to_decimal"
    with pytest.raises(ValueError, match="valid port model JSON"):
        parse_model_output("not-json")


def test_complete_json_ignores_trailing_model_degeneration():
    parsed = parse_model_output(json.dumps(model_output_dict()) + '\n,", :", ",')

    assert parsed.output.analysis.summary == "Writes a mode byte and seeds a timer."
    assert parsed.syntax_repairs[0]["kind"] == "trailing_output_ignored"
    assert parsed.syntax_repairs[0]["to"] == "complete root JSON value"


def test_conventional_missing_exit_label_is_materialized():
    payload = model_output_dict()
    payload["port_ir"]["exit"] = [
        {"type": "label", "id": "CHECK"},
        {
            "type": "branch_if_lte",
            "lhs": "timer",
            "rhs": 0.0,
            "target_label": "EXIT",
            "false_target": "EXIT",
        },
    ]

    parsed = parse_model_output(json.dumps(payload))

    assert [operation.type for operation in parsed.output.port_ir.exit[-2:]] == ["label", "return"]
    assert parsed.output.port_ir.exit[-2].id == "EXIT"
    assert parsed.syntax_repairs[-1]["kind"] == "missing_terminal_label"


def test_adjacent_block_fallthrough_is_made_explicit():
    payload = model_output_dict()
    payload["port_ir"]["entry"] = [{"type": "return"}]
    payload["port_ir"]["update"] = [
        {"type": "label", "id": "FIRST"},
        {"type": "store", "offset": "0x540", "value": 1, "width": 8},
        {"type": "label", "id": "RETURN"},
        {"type": "return"},
    ]

    parsed = parse_model_output(json.dumps(payload))

    assert parsed.output.port_ir.update[1].fallthrough is True
    assert any(repair["kind"].startswith("explicit_fallthrough") for repair in parsed.syntax_repairs)


def test_common_qwen_operation_aliases_are_normalized_before_validation():
    payload = model_output_dict()
    payload["port_ir"]["entry"] = [
        {
            "type": "branch_if_not_equal",
            "source": "state",
            "target": 0x607,
            "target_label: ": "UPDATE",
            "false_target: ": "INIT",
        }
    ]
    payload["port_ir"]["update"] = [
        {"type": "label", "name": "INIT"},
        {"type": "call", "function": "0x8016c7ec", "arguments": ["param_1", 1, 0]},
        {"type": "jump", "target": "RETURN"},
        {"type": "label", "name": "UPDATE"},
        {"type": "jump", "target": "RETURN"},
        {"type": "label", "name": "RETURN"},
        {"type": "return"},
    ]
    parsed = parse_model_output(json.dumps(payload))
    branch = parsed.output.port_ir.entry[0]
    call = parsed.output.port_ir.update[1]
    assert branch.type == "branch_if_ne"
    assert branch.value == 0x607
    assert branch.target_label == "UPDATE"
    assert branch.false_target == "INIT"
    assert call.callee == "0x8016c7ec"
    assert call.args == ["param_1", 1, 0]
    assert any(repair["kind"].startswith("operation_field_punctuation") for repair in parsed.syntax_repairs)


def test_qwen_lte_operand_aliases_are_normalized():
    payload = model_output_dict()
    payload["port_ir"]["entry"] = [
        {
            "type": "branch_if_lte",
            "lhs_var": "timer",
            "rhs_literal": 0.0,
            "target_label: ": "RETURN",
            "false_target: ": "UPDATE",
        }
    ]

    parsed = parse_model_output(json.dumps(payload))
    branch = parsed.output.port_ir.entry[0]

    assert branch.lhs == "timer"
    assert branch.rhs == 0.0
    assert branch.target_label == "RETURN"
    assert branch.false_target == "UPDATE"


def test_qwen_escaped_quote_field_punctuation_is_normalized():
    payload = model_output_dict()
    payload["port_ir"]["entry"] = [
        {
            "type": "branch_if_lte",
            "lhs": "timer",
            "rhs": 0.0,
            'target_label": ': "RETURN",
            'false_target": ': "UPDATE",
        }
    ]

    parsed = parse_model_output(json.dumps(payload))
    branch = parsed.output.port_ir.entry[0]

    assert branch.target_label == "RETURN"
    assert branch.false_target == "UPDATE"
    assert sum(
        repair["kind"].startswith("operation_field_punctuation")
        for repair in parsed.syntax_repairs
    ) == 2


def test_invalid_optional_port_ir_is_dropped_when_analysis_is_valid():
    payload = model_output_dict()
    payload["port_ir"]["entry"] = [
        {
            "type": "branch_if_lte",
            "lhs": "timer",
            "target_label": "RETURN",
        }
    ]

    parsed = parse_model_output(json.dumps(payload))

    assert parsed.output.port_ir is None
    assert parsed.output.analysis.summary == "Writes a mode byte and seeds a timer."
    assert parsed.syntax_repairs[-1] == {
        "kind": "invalid_port_ir_dropped",
        "from": "1 Port IR validation error(s)",
        "to": "null Port IR; retain validated analysis only",
    }


def test_address_normalization_is_32_bit_lowercase():
    assert normalize_address("FUN_8012B458") == "0x8012b458"
    assert normalize_address(0x607) == "0x00000607"
    with pytest.raises(ValueError):
        normalize_address("xyz")


def test_port_ir_rejects_missing_branch_operands():
    payload = model_output_dict()
    payload["port_ir"]["update"].insert(
        1,
        {"type": "branch_if_eq", "value": "0x607", "target_label": "RETURN"},
    )
    with pytest.raises(ValidationError, match="branch_if_eq requires source"):
        PortModelOutput.model_validate(payload)


def test_claim_evidence_validation_promotes_supported_mechanical_claim():
    value = artifact()
    report = validate_port_artifact(value)
    assert report.passed
    assert report.checks_failed == 0
    assert value.analysis.claims[0].verification == "verified"
    assert value.verification.status == "verified"


def test_claim_with_unknown_evidence_reference_is_rejected():
    value = artifact()
    value.analysis.claims[0].evidence_refs = ["instruction:0x8012b470"]
    report = validate_port_artifact(value)
    assert not report.passed
    assert any(check.name == "claim-evidence:mode-write" and not check.passed for check in report.checks)
    assert value.analysis.claims[0].verification == "rejected"


def test_numeric_call_arguments_must_appear_in_cited_evidence():
    value = artifact()
    value.analysis.claims[0] = Claim(
        id="helper-call",
        kind="call",
        value={"callee": "0x800107a0", "args": ["param_1", 0x7F]},
        confidence=1.0,
        evidence_refs=["decompile:0x8012b458"],
    )
    report = validate_port_artifact(value)
    assert not report.passed
    assert any(check.name == "claim-mechanics:helper-call" and not check.passed for check in report.checks)


def test_symbolic_value_expression_checks_embedded_numeric_literal_only():
    value = artifact()
    value.analysis.claims[0] = Claim(
        id="masked-store",
        kind="store",
        value={"offset": "0x6e8", "value": "loaded_value & 0x83", "width": 8},
        confidence=1.0,
        evidence_refs=["decompile:0x8012b458"],
    )

    assert validate_port_artifact(value).passed


def test_address_expression_and_decimal_offset_match_hex_evidence():
    value = artifact()
    value.evidence.records[0].content = (
        "stwu r1,-0x10(r1); *(undefined1 *)(param_1 + 0x6e8) = 0x83; addi r1,r1,0x10;"
    )
    value.analysis.claims = [
        Claim(
            id="address-expression",
            kind="store",
            value={"address": "param_1 + 0x6e8", "value": 0x83, "width": 8},
            confidence=1.0,
            evidence_refs=["decompile:0x8012b458"],
        ),
        Claim(
            id="stack-offset",
            kind="stack_frame",
            value={"offset": "-16", "width": 32},
            confidence=1.0,
            evidence_refs=["decompile:0x8012b458"],
        ),
    ]

    assert validate_port_artifact(value).passed


def test_evidence_enrichment_requires_matching_anchor_and_missing_literal():
    value = artifact()
    value.evidence.records = [
        EvidenceRecord(
            id="instruction:0x8012b494",
            kind="instruction",
            tier="authoritative",
            address="0x8012b494",
            content="8012b494: bl 0x800107a0",
        ),
        EvidenceRecord(
            id="decompile:0x8012b458",
            kind="decompile",
            tier="authoritative",
            address="0x8012b458",
            content="zz_00107a0_(param_1,0x7f);",
        ),
        EvidenceRecord(
            id="decompile:unrelated",
            kind="decompile",
            tier="authoritative",
            content="other_helper(param_1,0x7f);",
        ),
    ]
    value.analysis.claims[0] = Claim(
        id="helper-call",
        kind="call",
        value={"callee": "0x800107a0", "args": ["param_1", 0x7F]},
        confidence=1.0,
        evidence_refs=["instruction:0x8012b494"],
    )
    enrichments = enrich_claim_evidence(value)
    assert value.analysis.claims[0].evidence_refs == [
        "instruction:0x8012b494",
        "decompile:0x8012b458",
    ]
    assert enrichments[0]["claim_id"] == "helper-call"
    assert validate_port_artifact(value).passed


def test_evidence_enrichment_requires_anchor_and_literal_in_same_statement():
    value = artifact()
    value.evidence.records = [
        EvidenceRecord(
            id="instruction:0x8012b470",
            kind="instruction",
            tier="authoritative",
            address="0x8012b470",
            content="stb r0,0x6e8(r31)",
        ),
        EvidenceRecord(
            id="decompile:0x8012b458",
            kind="decompile",
            tier="authoritative",
            address="0x8012b458",
            content="actor + 0x6e8 = 0x83;\nother_flag = 0;",
        ),
    ]
    value.analysis.claims[0] = Claim(
        id="wrong-zero",
        kind="store",
        value={"offset": "0x6e8", "value": 0},
        confidence=1.0,
        evidence_refs=["instruction:0x8012b470"],
    )

    assert enrich_claim_evidence(value) == []
    assert not validate_port_artifact(value).passed


def test_rejected_model_claims_can_be_pruned_without_changing_evidence():
    value = artifact()
    valid_claim = value.analysis.claims[0]
    invalid_claim = Claim(
        id="wrong-zero",
        kind="store",
        value={"offset": "0x6e8", "value": 0},
        confidence=1.0,
        evidence_refs=["decompile:0x8012b458"],
    )
    value.analysis.claims = [valid_claim, invalid_claim]
    assert not validate_port_artifact(value).passed

    pruned = prune_rejected_claims(value)

    assert [claim.id for claim in value.analysis.claims] == ["mode-write"]
    assert pruned[0]["claim_id"] == "wrong-zero"
    assert validate_port_artifact(value).passed


def test_unresolved_dependency_preserves_claim_verification_but_blocks_integration():
    value = artifact()
    value.analysis.dependencies = [
        Dependency(address="0x800107a0", name="retire_hitbox", status="unresolved")
    ]
    report = validate_port_artifact(value)
    assert report.passed
    assert value.verification.status == "verified"
    assert value.verification.integration_status == "blocked"


def test_artifact_serialization_round_trip(tmp_path):
    value = artifact()
    assert validate_port_artifact(value).passed
    target = tmp_path / "artifact.json"
    atomic_write_artifact(target, value)
    loaded = PortArtifact.model_validate_json(target.read_text(encoding="utf-8"))
    assert loaded == value
    assert not list(tmp_path.glob("*.tmp"))
