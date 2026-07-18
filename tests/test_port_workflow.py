import json

from src.port_workflow import build_evidence_bundle, compare_traces, extract_dossier, prompt_for_phase, validate_dossier


def dossier(status="DERIVED_ROM", tier="authoritative"):
    return {
        "version": 1,
        "scope": {"family": "EAGLE_ROBOT", "actionIndex": 0, "constructorAddress": "0x80129608"},
        "variants": [],
        "phases": [],
        "claims": [
            {
                "claimId": "eagle.action0.timer",
                "status": status,
                "function": "0x80129abc",
                "statement": "The phase exits when the timer reaches 20.0.",
                "evidence": [{"tier": tier, "source": "chunk_0036.c:412-418"}],
                "unresolved": ["semantic field name"] if status != "DERIVED_ROM" else [],
            }
        ],
        "blockers": [],
        "tests": [],
    }


def test_valid_derived_claim_requires_direct_evidence():
    assert validate_dossier(dossier()).valid
    result = validate_dossier(dossier(tier="inferred"))
    assert not result.valid
    assert any("requires authoritative" in error for error in result.errors)


def test_inferred_claim_is_allowed_but_stays_labeled():
    assert validate_dossier(dossier(status="INFERRED", tier="inferred")).valid


def test_port_prompts_are_mechanics_and_evidence_specific():
    execution = prompt_for_phase("execution")
    assert "CONSTRUCTOR -> DISPATCH -> TABLES -> PHASES" in execution
    assert "Only authoritative" in execution
    assert "malware" not in execution.lower()
    assert "adversarial verifier" in prompt_for_phase("evaluation")


def test_trace_comparison_reports_first_divergent_frame():
    rom = [{"phase": 0, "x": 1.0}, {"phase": 1, "x": 2.0}, {"phase": 2, "x": 3.0}]
    port = [{"phase": 0, "x": 1.0}, {"phase": 1, "x": 2.25}, {"phase": 9, "x": 3.0}]
    result = compare_traces(rom, port, fields=["phase", "x"])
    assert result["match"] is False
    assert result["frameIndex"] == 1
    assert result["differences"] == {"x": {"rom": 2.0, "port": 2.25}}


def test_trace_comparison_supports_float_tolerance():
    assert compare_traces([{"x": 1.0}], [{"x": 1.00001}], tolerance=0.001)["match"]


def test_extract_dossier_ignores_unvalidated_json():
    valid = dossier()
    text = "lead\n```json\n" + json.dumps(valid) + "\n```"
    assert extract_dossier(text) == valid
    assert extract_dossier("```json\n{}\n```") is None


def test_context_bundle_hashes_and_orders_evidence(tmp_path):
    inferred = tmp_path / "summary.txt"
    authoritative = tmp_path / "decompile.c"
    inferred.write_text("guess", encoding="utf-8")
    authoritative.write_text("literal", encoding="utf-8")
    bundle = build_evidence_bundle(
        {"family": "ROBOT", "actionIndex": 0},
        [
            {"tier": "inferred", "kind": "summary", "path": inferred},
            {"tier": "authoritative", "kind": "decompile", "path": authoritative},
        ],
    )
    assert [row["tier"] for row in bundle["sources"]] == ["authoritative", "inferred"]
    assert bundle["sources"][0]["content"] == "literal"
    assert len(bundle["sources"][0]["sha256"]) == 64


def test_mechanics_eval_scores_claim_and_route_recovery():
    from eval_port_workflow import score

    gold = dossier()
    gold["variants"] = [{"variantId": "v0"}]
    gold["phases"] = [{"phaseId": "p0"}]
    candidate = json.loads(json.dumps(gold))
    result = score(candidate, gold)
    assert result["claimRecall"] == 1.0
    assert result["statusAccuracy"] == 1.0
    assert result["phaseRecovery"] == 1.0
    assert result["variantRecovery"] == 1.0
