import hashlib
import json
from pathlib import Path

from src.port_artifact import PortArtifact
from src.port_evidence import collect_function_evidence
from src.port_cli import main as port_cli_main
from src.port_exporter import build_port_prompt, export_port_artifact


class FakeGhidra:
    def get_current_program_info(self):
        return {"name": "boot.dol", "language": "PowerPC:BE:32"}

    def get_function_by_address(self, address):
        return "FUN_8012b458 @ 8012b458 size=0xfc"

    def decompile_function_by_address(self, address, offset=0, limit=500):
        return """
void FUN_8012b458(int param_1) {
  *(undefined1 *)(param_1 + 0x6e8) = 0x83;
  fVar2 = FLOAT_80439d80;
  if (*(char *)(param_1 + 0x540) == 0) {
    *(float *)(param_1 + 0x558) = fVar2;
    zz_00107a0_(param_1,0x7f);
  }
}
""".strip()

    def disassemble_function(self, address):
        return [
            "8012b458: 98 7f 06 e8 stb r3,0x6e8(r31)",
            "8012b480: 48 00 00 01 bl 0x800107a0",
        ]

    def get_xrefs_to(self, address, offset=0, limit=100):
        return ["8012b14c -> 8012b458 CALL"]

    def get_xrefs_from(self, address, offset=0, limit=100):
        return ["8012b480 -> 800107a0 CALL", "8012b464 -> 80439d80 DATA"]

    def read_bytes(self, address, length=16, format="hex"):
        assert address == "0x80439d80"
        return "42 34 00 00"


def test_prompt_includes_downstream_requirements_without_elevating_them_to_evidence():
    collected = collect_function_evidence(FakeGhidra(), "0x8012b458")

    prompt = build_port_prompt(collected, "Cover the timer update when evidence supports it.")

    assert "Deterministic downstream integration requirements" in prompt
    assert "Cover the timer update" in prompt
    assert "never invent a value" in prompt


class FakeLLM:
    default_model = "qwen-test"

    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = 0

    def generate_structured(self, **kwargs):
        self.calls += 1
        return next(self.responses), "tool_call"


def valid_model_output():
    return {
        "analysis": {
            "classification": "code_driven_state_handler",
            "summary": "Seeds a 45-frame timer.",
            "claims": [
                {
                    "id": "timer-seed",
                    "kind": "timer_constant",
                    "value": {
                        "offset": "0x558",
                        "value": 45.0,
                        "source_address": "0x80439d80",
                    },
                    "confidence": 1.0,
                    "evidence_refs": [
                        "decompile:0x8012b458",
                        "data:0x80439d80",
                    ],
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


def test_evidence_collector_preserves_backend_results_and_big_endian_constant():
    collected = collect_function_evidence(FakeGhidra(), "8012B458")
    assert collected.function.address == "0x8012b458"
    assert collected.function.body_hash == hashlib.sha256(
        (
            next(r.content for r in collected.evidence.records if r.kind == "decompile")
            + "\n"
            + "\n".join(FakeGhidra().disassemble_function("0x8012b458"))
        ).encode()
    ).hexdigest()
    raw = next(r for r in collected.evidence.records if r.id == "data:0x80439d80")
    assert raw.content["u32_be"] == "0x42340000"
    assert raw.content["f32_be"] == 45.0
    assert any(r.id == "callee:0x800107a0" for r in collected.evidence.records)
    assert any(r.id == "decompile:0x800107a0" for r in collected.evidence.records)


def test_export_runs_one_bounded_repair_and_preserves_raw_responses(tmp_path):
    malformed = json.dumps(valid_model_output())
    malformed = malformed.replace('"source": "borg_id",', "")
    invalid = valid_model_output()
    invalid["analysis"]["claims"][0]["value"] = "not-an-object"
    invalid["port_ir"]["update"].insert(
        1,
        {"type": "branch_if_eq", "value": "0x607", "target_label": "RETURN"},
    )
    llm = FakeLLM([json.dumps(invalid), json.dumps(valid_model_output())])
    output = tmp_path / "fn.json"
    result = export_port_artifact(
        collected=collect_function_evidence(FakeGhidra(), "0x8012b458"),
        llm=llm,
        output_path=output,
        model_provider="custom_api",
        model_name="qwen-test",
    )
    assert result.report.passed
    assert result.attempts == 2
    assert llm.calls == 2
    assert output.exists()
    assert (tmp_path / "fn.raw-attempt-1.txt").exists()
    assert (tmp_path / "fn.raw-attempt-2.txt").exists()
    assert PortArtifact.model_validate_json(output.read_text(encoding="utf-8")).verification.status == "verified"


def test_session_attachment_is_a_sidecar_and_does_not_rewrite_history(tmp_path):
    session = tmp_path / "session.json"
    original = {
        "analyzed_functions": {
            "8012b458": {
                "address": "8012b458",
                "behavior_summary": "historical prose",
            }
        }
    }
    session.write_text(json.dumps(original), encoding="utf-8")
    before = session.read_bytes()
    output = tmp_path / "artifact.json"
    result = export_port_artifact(
        collected=collect_function_evidence(FakeGhidra(), "0x8012b458"),
        llm=FakeLLM([json.dumps(valid_model_output())]),
        output_path=output,
        model_provider="custom_api",
        model_name="qwen-test",
        session_path=session,
    )
    assert result.report.passed
    assert session.read_bytes() == before
    sidecar = json.loads((tmp_path / "port-artifacts.json").read_text(encoding="utf-8"))
    assert sidecar["artifacts"][0]["function_address"] == "0x8012b458"
    assert Path(sidecar["artifacts"][0]["path"]).name == "artifact.json"


def test_export_port_cli_replays_explicit_evidence_and_model_response(tmp_path):
    collected = collect_function_evidence(FakeGhidra(), "0x8012b458")
    evidence = tmp_path / "evidence.json"
    evidence.write_text(collected.model_dump_json(indent=2), encoding="utf-8")
    response = tmp_path / "response.json"
    response.write_text(json.dumps(valid_model_output()), encoding="utf-8")
    output = tmp_path / "artifact.json"
    assert port_cli_main(
        [
            "--address",
            "0x8012b458",
            "--evidence-file",
            str(evidence),
            "--model-response",
            str(response),
            "--output",
            str(output),
        ]
    ) == 0
    assert PortArtifact.model_validate_json(output.read_text(encoding="utf-8")).producer.structured_output_mode == "fixture"


def test_export_port_cli_preserves_explicit_live_response_provenance(tmp_path):
    collected = collect_function_evidence(FakeGhidra(), "0x8012b458")
    evidence = tmp_path / "evidence.json"
    evidence.write_text(collected.model_dump_json(indent=2), encoding="utf-8")
    response = tmp_path / "response.json"
    response.write_text(json.dumps(valid_model_output()), encoding="utf-8")
    output = tmp_path / "artifact.json"
    assert port_cli_main(
        [
            "--address",
            "0x8012b458",
            "--evidence-file",
            str(evidence),
            "--model-response",
            str(response),
            "--response-provider",
            "custom_api",
            "--response-model",
            "qwen-live",
            "--response-mode",
            "plain_json",
            "--output",
            str(output),
        ]
    ) == 0
    artifact = PortArtifact.model_validate_json(output.read_text(encoding="utf-8"))
    assert artifact.producer.model_provider == "custom_api"
    assert artifact.producer.model_name == "qwen-live"
    assert artifact.producer.structured_output_mode == "plain_json"
