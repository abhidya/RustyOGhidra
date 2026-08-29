"""Tests for the LLM plan/spec derivation stage.

The point of these tests is NOT that the generator produces a plan -- it is that
the generator REFUSES the plans it must refuse. Every test named *_refused
encodes a way an LLM-derived plan can be wrong while looking fine, and asserts
that the pipeline stops rather than emitting a spec that under-checks.

The model is mocked throughout: derivation quality is measured separately
against the hand-authored auto-c0020-007 plans (tools/diff_against_gold.py).
"""

from __future__ import annotations

import json

import pytest

from src.port_c_evidence import analyse_function, split_unit_functions
from src.port_plan_derive import (
    assemble_plan,
    build_prompt,
    parse_addr,
    parse_reply,
    validate_plan,
)
from src.port_spec_emit import SDK_SHIMS, classify_export, emit_spec

# --------------------------------------------------------------------- fixtures

DECREMENT_C = """// ==== 800c42bc  FUN_800c42bc ====

void FUN_800c42bc(int param_1)

{
  float fVar1;
  float fVar2;
  float fVar3;

  fVar3 = FLOAT_80438744;
  fVar2 = *(float *)(param_1 + 0x184) - *(float *)(param_1 + 0x44);
  fVar1 = fVar2 / FLOAT_8043875c;
  *(float *)(param_1 + 0x184) = fVar2;
  *(float *)(param_1 + 0x60) = fVar1;
  if (fVar1 <= fVar3) {
    zz_00c42a8_(param_1);
  }
  return;
}
"""

# same body with the ROM callee removed -- the MECHANICAL tier
PURE_C = DECREMENT_C.replace("    zz_00c42a8_(param_1);\n", "    return;\n")

REGISTRY_ENTRY = {
    "name": "FUN_800c42bc",
    "address": "0x800c42bc",
    "params": ["int param_1"],
    "return_type": "void",
    "returns_value": False,
    "chunk_file": "research/decomp/ghidra-export/chunk_0020.c",
    "line_range": [2431, 2449],
}

GOOD_PAYLOAD = {
    "reads": [
        {"id": "a184_pre", "addr": "r3+0x184", "width": 4,
         "evidence": "fVar2 = *(float *)(param_1 + 0x184) - *(float *)(param_1 + 0x44);"},
        {"id": "a44", "addr": "r3+0x44", "width": 4,
         "evidence": "fVar2 = *(float *)(param_1 + 0x184) - *(float *)(param_1 + 0x44);"},
        {"id": "f_8744", "addr": "0x80438744", "width": 4,
         "evidence": "fVar3 = FLOAT_80438744;"},
        {"id": "f_875c", "addr": "0x8043875c", "width": 4,
         "evidence": "fVar1 = fVar2 / FLOAT_8043875c;"},
    ],
    "writes": [
        {"id": "w184", "addr": "r3+0x184", "width": 4,
         "evidence": "*(float *)(param_1 + 0x184) = fVar2;"},
        {"id": "w60", "addr": "r3+0x60", "width": 4,
         "evidence": "*(float *)(param_1 + 0x60) = fVar1;"},
    ],
    "note": "per-frame decrement",
}


def _evidence(body=DECREMENT_C):
    name = "FUN_800c42bc"
    return analyse_function(name, split_unit_functions(body)[name], ["int param_1"])


def _plan(payload=None, body=DECREMENT_C):
    return assemble_plan("auto-c0020-007", "FUN_800c42bc", REGISTRY_ENTRY,
                         json.loads(json.dumps(payload or GOOD_PAYLOAD)))


def _validate(payload=None, body=DECREMENT_C, **kw):
    return validate_plan(_plan(payload, body), _evidence(body), REGISTRY_ENTRY, **kw)


# ------------------------------------------------------------------ evidence


def test_evidence_finds_reads_writes_and_rom_constants():
    evidence = _evidence()
    assert (1, 0x184) in evidence.param_offsets("read")
    assert (1, 0x44) in evidence.param_offsets("read")
    assert (1, 0x184) in evidence.param_offsets("write")
    assert (1, 0x60) in evidence.param_offsets("write")
    assert evidence.absolute_addrs() == {0x80438744, 0x8043875C}
    assert "zz_00c42a8_" in evidence.callees


def test_evidence_reads_nested_pointer_chase():
    body = """// ==== 800c4838  FUN_800c4838 ====
void FUN_800c4838(int param_1)
{
  if (*(char *)(*(int *)(param_1 + 0x90) + 0x18) < '\\x02') {
    *(undefined1 *)(param_1 + 0x82) = 0;
  }
  return;
}
"""
    evidence = analyse_function("FUN_800c4838",
                                split_unit_functions(body)["FUN_800c4838"],
                                ["int param_1"])
    # the chase is nested in parentheses; a paren-free regex silently loses it
    assert (1, 0x18) in evidence.chase_offsets()
    assert (1, 0x90) in evidence.param_offsets("read")


def test_evidence_decimal_offsets_and_negative_table_base():
    body = """// ==== 800c4540  zz_test_ ====
void zz_test_(int param_1)
{
  int iVar3;
  iVar3 = (uint)*(byte *)(param_1 + 0x11) * 0x44;
  uVar4 = *(uint *)(param_1 + 200);
  gnt4_PSMTXMultVec_bl((float *)(param_1 + 0x144),(float *)(iVar3 + -0x7fcfceb8),afStack_28);
  *(undefined4 *)(param_1 + 0x150) = *(undefined4 *)(uVar4 + 100);
  return;
}
"""
    evidence = analyse_function("zz_test_", split_unit_functions(body)["zz_test_"],
                                ["int param_1"])
    assert (1, 0xC8) in evidence.param_offsets("read")   # decimal 200
    assert 0x80303148 in evidence.absolute_addrs()       # -0x7fcfceb8 two's complement
    assert (1, 0x64) in evidence.chase_offsets()         # via the uVar4 local


def test_evidence_ignores_pointer_parameter_declarations():
    """`undefined1 *param_9` in a signature is a declaration, not a load."""
    body = """// ==== 800c4448  FUN_800c4448 ====
void FUN_800c4448(undefined8 param_1,undefined1 *param_9)
{
  zz_0088e50_(param_1,param_9);
  return;
}
"""
    evidence = analyse_function("FUN_800c4448",
                                split_unit_functions(body)["FUN_800c4448"],
                                ["undefined8 param_1", "undefined1 *param_9"])
    assert not evidence.direct_param_reads()


# ------------------------------------------------------- address expressions


@pytest.mark.parametrize("expr,form,param,offset", [
    ("r3+0x184", "direct", 1, 0x184),
    ("r3", "direct", 1, 0),
    ("[r3+0x90]+0x18", "chase", 1, 0x18),
])
def test_parse_addr_shapes(expr, form, param, offset):
    parsed = parse_addr(expr, {"r3": 1})
    assert (parsed.form, parsed.param, parsed.offset) == (form, param, offset)


def test_parse_addr_strided_table():
    parsed = parse_addr("0x8030316c + ((([r3+0x11]) >> 24) * 0x44)", {"r3": 1})
    assert parsed.form == "absolute_strided"
    assert parsed.base_addr == 0x8030316C
    assert parsed.inner_loads == [(1, 0x11)]


def test_parse_addr_rejects_undeclared_register():
    assert "not a declared argument" in parse_addr("r7+0x10", {"r3": 1}).error


def test_parse_addr_rejects_c_syntax():
    # capture_oracle.py would reject this at capture time, on a live emulator boot
    assert parse_addr("*(float *)(param_1 + 4)", {"r3": 1}).error


# ------------------------------------------------------------- validation


def test_good_plan_validates():
    assert _validate().verdict == "validated"


def test_hallucinated_offset_refused():
    payload = json.loads(json.dumps(GOOD_PAYLOAD))
    payload["reads"].append({
        "id": "invented", "addr": "r3+0x2a0", "width": 4,
        "evidence": "fVar3 = FLOAT_80438744;"})
    result = _validate(payload)
    assert result.verdict == "refused"
    assert any(e.status == "ungrounded" for e in result.entries)


def test_missing_store_refused_as_under_declaration():
    """The dangerous failure: a write set that misses a store still 'passes'
    every case a generated spec would run."""
    payload = json.loads(json.dumps(GOOD_PAYLOAD))
    payload["writes"] = [payload["writes"][0]]      # drop w60
    result = _validate(payload)
    assert result.verdict == "refused"
    assert any("0x60" in reason for reason in result.undeclared_writes)


def test_uncited_entry_refused():
    payload = json.loads(json.dumps(GOOD_PAYLOAD))
    payload["reads"][0].pop("evidence")
    result = _validate(payload)
    assert result.verdict == "refused"
    assert any(e.status == "citation_missing" for e in result.entries)


def test_fabricated_citation_refused():
    payload = json.loads(json.dumps(GOOD_PAYLOAD))
    payload["reads"][0]["evidence"] = "*(float *)(param_1 + 0x2a0) = 1.0;"
    assert _validate(payload).verdict == "refused"


def test_direction_confusion_refused():
    """An offset the C only READS, declared as a write."""
    payload = json.loads(json.dumps(GOOD_PAYLOAD))
    payload["writes"].append({
        "id": "w44", "addr": "r3+0x44", "width": 4,
        "evidence": "fVar2 = *(float *)(param_1 + 0x184) - *(float *)(param_1 + 0x44);"})
    result = _validate(payload)
    assert result.verdict == "refused"
    assert any("only as a read" in e.detail for e in result.entries)


def test_bad_width_refused():
    payload = json.loads(json.dumps(GOOD_PAYLOAD))
    payload["reads"][0]["width"] = 3
    assert _validate(payload).verdict == "refused"


def test_rom_constant_not_named_by_this_c_is_flagged_not_accepted():
    """The auto-c0020-007 `sdk_ca90` case: a real constant, but one a human
    imported from the SDK callee's body. Grounded nowhere in this function."""
    payload = json.loads(json.dumps(GOOD_PAYLOAD))
    payload["reads"].append({
        "id": "sdk_ca90", "addr": "0x8043ca90", "width": 8,
        "evidence": "fVar3 = FLOAT_80438744;"})
    result = _validate(payload)
    assert result.verdict == "flagged"
    assert any(e.status == "ungrounded_rom_const" for e in result.entries)


def test_read_after_unconditional_own_write_need_not_be_declared():
    body = """// ==== 800c4308  FUN_800c4308 ====
void FUN_800c4308(int param_1)
{
  *(float *)(param_1 + 0x180) = 1.0;
  if (*(float *)(param_1 + 0x180) < 2.0) {
    *(float *)(param_1 + 0x184) = 0.0;
  }
  return;
}
"""
    payload = {
        "reads": [], "writes": [
            {"id": "w180", "addr": "r3+0x180", "width": 4,
             "evidence": "*(float *)(param_1 + 0x180) = 1.0;"},
            {"id": "w184", "addr": "r3+0x184", "width": 4,
             "evidence": "*(float *)(param_1 + 0x184) = 0.0;"},
        ]}
    name = "FUN_800c4308"
    evidence = analyse_function(name, split_unit_functions(body)[name], ["int param_1"])
    plan = assemble_plan("u", name, {**REGISTRY_ENTRY, "name": name}, payload)
    assert validate_plan(plan, evidence, REGISTRY_ENTRY).verdict == "validated"


def test_coalesced_write_range_covers_two_adjacent_stores():
    body = """// ==== 800c4308  FUN_800c4308 ====
void FUN_800c4308(int param_1)
{
  *(undefined4 *)(param_1 + 0x58) = 1;
  *(undefined4 *)(param_1 + 0x5c) = 2;
  return;
}
"""
    payload = {"reads": [], "writes": [
        {"id": "w58", "addr": "r3+0x58", "width": 8,
         "evidence": "*(undefined4 *)(param_1 + 0x58) = 1;"}]}
    name = "FUN_800c4308"
    evidence = analyse_function(name, split_unit_functions(body)[name], ["int param_1"])
    plan = assemble_plan("u", name, {**REGISTRY_ENTRY, "name": name}, payload)
    assert validate_plan(plan, evidence, REGISTRY_ENTRY).verdict == "validated"


# ---------------------------------------------------------------- reply parsing


def test_parse_reply_accepts_fenced_json():
    payload, _ = parse_reply('here you go\n```json\n{"reads": []}\n```\n')
    assert payload == {"reads": []}


def test_parse_reply_salvages_unclosed_fence():
    payload, _ = parse_reply('```json\n{"reads": [], "writes": []}\n')
    assert payload == {"reads": [], "writes": []}


def test_parse_reply_reports_shape_when_unusable():
    payload, shape = parse_reply("I cannot determine the read set.")
    assert payload is None and "head=" in shape


# --------------------------------------------------------------------- tiering


def test_rom_callee_puts_export_in_human_tier():
    tier = classify_export("FUN_800c42bc", _evidence(DECREMENT_C), _plan(), "validated")
    assert tier.tier == "human"
    assert "zz_00c42a8_" in tier.reasons[0]


def test_callee_free_export_is_mechanical():
    tier = classify_export("FUN_800c42bc", _evidence(PURE_C), _plan(body=PURE_C),
                           "validated")
    assert tier.tier == "mechanical"


def test_empty_write_set_never_reaches_a_spec():
    """A spec with nothing to compare passes every case."""
    payload = {"reads": GOOD_PAYLOAD["reads"], "writes": []}
    tier = classify_export("FUN_800c42bc", _evidence(PURE_C),
                           _plan(payload, PURE_C), "validated")
    assert tier.tier == "human"
    assert any("passes every case" in r for r in tier.reasons)


def test_unvalidated_plan_never_reaches_a_spec():
    tier = classify_export("FUN_800c42bc", _evidence(PURE_C), _plan(body=PURE_C),
                           "flagged")
    assert tier.tier == "human"


def test_sdk_helper_without_a_vetted_shim_is_human_tier():
    body = PURE_C.replace("  fVar3 = FLOAT_80438744;",
                          "  gnt4_PSVECNormalize_bl(param_1,param_1);")
    tier = classify_export("FUN_800c42bc", _evidence(body), _plan(body=body),
                           "validated")
    assert tier.tier == "human"
    assert "gnt4_PSVECNormalize_bl" not in SDK_SHIMS


# ------------------------------------------------------------------ spec emit


def test_emitted_spec_compares_every_declared_write():
    fn = "FUN_800c42bc"
    evidence = _evidence(PURE_C)
    plan = _plan(body=PURE_C)
    tiers = {fn: classify_export(fn, evidence, plan, "validated")}
    source = emit_spec("auto-c0020-007", {fn: plan}, {fn: evidence}, tiers, [fn])
    assert 'name: "w184"' in source
    assert 'name: "w60"' in source
    assert "codec.diffPostState(gotBacks)" in source     # stray-write detection
    assert "codec.auditReads(" in source                 # sentinel-read detection
    assert 'reference_kind: "dolphin_trace"' in source
    assert "export function makeShims" in source
    assert "export function createRunner" in source


def test_emitted_spec_names_the_exports_it_does_not_cover():
    fn, other = "FUN_800c42bc", "zz_other_"
    evidence = _evidence(PURE_C)
    plan = _plan(body=PURE_C)
    tiers = {
        fn: classify_export(fn, evidence, plan, "validated"),
        other: classify_export(other, _evidence(DECREMENT_C), _plan(), "validated"),
    }
    source = emit_spec("auto-c0020-007", {fn: plan},
                       {fn: evidence, other: _evidence(DECREMENT_C)},
                       tiers, [fn, other])
    assert f'uncovered_exports: ["{other}"]' in source
    assert f"//   {other}: NOT COVERED" in source


def test_prompt_demands_a_citation_and_forbids_param_syntax():
    args = [{"reg": "r3", "name": "param_1"}]
    prompt = build_prompt("FUN_800c42bc", DECREMENT_C, args, "void f(int)", [])
    assert "`line` field" in prompt
    assert "must itself contain" in prompt
    assert "never `param_N`" in prompt
    assert "DECLARE EVERY DIRECT STORE" in prompt
    # the C must be shown WITH line numbers, or a line citation means nothing
    assert "  11  " in prompt


# ------------------------------------------------- conditional-write pre-state


EARLY_RETURN_C = """// ==== 80014bc4  zz_0014bc4_ ====
void zz_0014bc4_(int param_1)
{
  if (*(short *)(param_1 + 0x178) != 0) {
    *(short *)(param_1 + 0x178) = *(short *)(param_1 + 0x178) + -1;
    return;
  }
  *(undefined1 *)(param_1 + 0x170) = 1;
  return;
}
"""


def _early_return_evidence():
    name = "zz_0014bc4_"
    return analyse_function(name, split_unit_functions(EARLY_RETURN_C)[name],
                            ["int param_1"])


def test_top_level_store_after_an_early_return_is_not_unconditional():
    """Brace depth 0 does not mean 'runs on every call' once the body has an
    `if (...) { ...; return; }` above the store."""
    evidence = _early_return_evidence()
    unconditional = {(a.param, a.offset) for a in evidence.unconditional_writes()}
    assert (1, 0x170) not in unconditional


def test_conditional_write_without_pre_state_never_reaches_a_spec():
    """The replay poisons its arena; on a call whose branch does not store, a
    write with no captured pre-state compares poison against the console's
    untouched bytes and blames the unit."""
    payload = {
        "reads": [{"id": "r178", "addr": "r3+0x178", "width": 2,
                   "evidence": "if (*(short *)(param_1 + 0x178) != 0) {"}],
        "writes": [
            {"id": "w178", "addr": "r3+0x178", "width": 2,
             "evidence": "*(short *)(param_1 + 0x178) = *(short *)(param_1 + 0x178) + -1;"},
            {"id": "w170", "addr": "r3+0x170", "width": 1,
             "evidence": "*(undefined1 *)(param_1 + 0x170) = 1;"},
        ],
    }
    name = "zz_0014bc4_"
    evidence = _early_return_evidence()
    plan = assemble_plan("u", name, {**REGISTRY_ENTRY, "name": name}, payload)
    tier = classify_export(name, evidence, plan, "validated")
    assert tier.tier == "human"
    assert any("pre-state" in reason for reason in tier.reasons)


def test_unconditional_write_needs_no_pre_state():
    """FUN_800c42bc stores +0x60 on every call, so the gold plan rightly omits a
    +0x60 read -- the rule must not demand one."""
    evidence = _evidence(PURE_C)
    tier = classify_export("FUN_800c42bc", evidence, _plan(body=PURE_C), "validated")
    assert tier.tier == "mechanical"


def test_static_derivation_emits_pre_state_reads_for_every_write():
    from src.port_plan_derive import derive_plan_statically

    name = "zz_0014bc4_"
    plan, why = derive_plan_statically("u", name, {**REGISTRY_ENTRY, "name": name},
                                       _early_return_evidence())
    assert plan is not None, why
    read_addrs = {(e["addr"], e["width"]) for e in plan["reads"]}
    for write in plan["writes"]:
        assert (write["addr"], write["width"]) in read_addrs


def test_static_derivation_refuses_indirect_dispatch():
    from src.port_plan_derive import derive_plan_statically

    body = EARLY_RETURN_C.replace(
        "  *(undefined1 *)(param_1 + 0x170) = 1;",
        "  (*(code *)(&PTR_FUN_8032e3b8)[*(char *)(param_1 + 0x540)])();")
    name = "zz_0014bc4_"
    evidence = analyse_function(name, split_unit_functions(body)[name],
                                ["int param_1"])
    plan, why = derive_plan_statically("u", name, {**REGISTRY_ENTRY, "name": name},
                                       evidence)
    assert plan is None and "function-pointer table" in why


def test_truncated_reply_never_yields_a_partial_write_set():
    """Measured on this rig: the model's reply for a larger function stopped
    mid-`writes` at ~2.3 KB with finish_reason "stop". Salvaging that into a
    plan would declare SOME of the stores -- the exact under-declaration the
    whole stage exists to prevent. It must fail, one way or another."""
    truncated = (
        '```json\n{\n  "reads": [\n'
        '    {"id": "a184_pre", "addr": "r3+0x184", "width": 4,\n'
        '     "evidence": "fVar2 = *(float *)(param_1 + 0x184) - *(float *)(param_1 + 0x44);"},\n'
        '    {"id": "a44", "addr": "r3+0x44", "width": 4,\n'
        '     "evidence": "fVar2 = *(float *)(param_1 + 0x184) - *(float *)(param_1 + 0x44);"}\n'
        '  ],\n  "writes": [\n'
        '    {"id": "w184", "addr": "r3+0x184", "width": 4,\n'
        '     "evidence": "*(float *)(param_1 + 0x184) = fVar2;"'
    )
    payload, shape = parse_reply(truncated)
    if payload is None:
        assert shape                       # refused at the parse boundary
        return
    plan = assemble_plan("u", "FUN_800c42bc", REGISTRY_ENTRY, payload)
    result = validate_plan(plan, _evidence(), REGISTRY_ENTRY)
    assert result.verdict == "refused"     # or at the coverage boundary
    assert result.undeclared_writes


def test_the_prompts_worked_example_validates_against_its_own_c():
    """The example teaches the model both the schema AND the line numbering. If
    its `line` fields point at the wrong lines, every reply learns the wrong
    convention -- and the first version of this example was off by two."""
    from src.port_plan_derive import _GOLD_C, _GOLD_JSON

    payload, shape = parse_reply("```json\n" + _GOLD_JSON + "\n```")
    assert payload is not None, shape
    name = "FUN_800c42bc"
    evidence = analyse_function(name, _GOLD_C, ["int param_1"])
    plan = assemble_plan("u", name, REGISTRY_ENTRY, payload)
    result = validate_plan(plan, evidence, REGISTRY_ENTRY)
    assert result.verdict == "validated", result.reasons()


def test_line_citation_must_point_at_a_line_naming_that_offset():
    payload = {
        "reads": [{"id": "a44", "addr": "r3+0x44", "width": 4, "line": 8}],
        "writes": [
            {"id": "w184", "addr": "r3+0x184", "width": 4, "line": 11},
            {"id": "w60", "addr": "r3+0x60", "width": 4, "line": 12},
        ],
    }
    # line 8 is `fVar3 = FLOAT_80438744;` -- it does not mention 0x44
    from src.port_plan_derive import _GOLD_C

    name = "FUN_800c42bc"
    evidence = analyse_function(name, _GOLD_C, ["int param_1"])
    plan = assemble_plan("u", name, REGISTRY_ENTRY, payload)
    result = validate_plan(plan, evidence, REGISTRY_ENTRY)
    assert any(e.status == "citation_missing" for e in result.entries)


def test_line_citation_out_of_range_is_refused():
    payload = {"reads": [{"id": "a44", "addr": "r3+0x44", "width": 4, "line": 999}],
               "writes": []}
    from src.port_plan_derive import _GOLD_C

    name = "FUN_800c42bc"
    evidence = analyse_function(name, _GOLD_C, ["int param_1"])
    plan = assemble_plan("u", name, REGISTRY_ENTRY, payload)
    result = validate_plan(plan, evidence, REGISTRY_ENTRY)
    assert any(e.status == "citation_missing" for e in result.entries)


def test_prompt_teaches_the_conditional_write_pre_state_rule():
    """Measured gap: without this rule the model produced a correct plan for
    zz_0014b3c_ that still could not be specced, because four of its writes are
    conditional and it declared no reads to seed them."""
    args = [{"reg": "r3", "name": "param_1"}]
    prompt = build_prompt("zz_0014b3c_", DECREMENT_C, args, "void f(int)", [])
    assert "CONDITIONAL STORE ALSO NEEDS A READ" in prompt
    assert "runs on EVERY call needs no such read" in prompt
