"""Indirect-call lowering: shapes, refusals, site identity, gate wiring.

THE BLOCKER THIS CLOSES (docs/verification-status.md section 3). Gotcha Force
dispatches through function pointers -- 2307 `(*(code *)...)(...)` /
`(**(code **)...)(...)` sites in the 80-chunk export -- and the pointer it
dispatches on is a GameCube CODE ADDRESS (0x80xxxxxx). `emcc` turns each of
those into a `call_indirect` on the MODULE'S OWN function table indexed by that
address, which is wrong twice over: 0x80xxxxxx is not a wasm table index, so
the call reaches an arbitrary wrong function or traps; and a `call_indirect` is
INVISIBLE to an import shim, which is why the transcript capture refuses every
function containing one (1602 functions, 14.6 % of the corpus -- the single
largest unverifiable class).

`src/port_indirect_lowering.py` is the rewrite that removes both problems at
once: the site becomes a per-call argument frame plus a call to the companion's
`__gf_dispatch_at`, so it goes through a thunk the gate wrote (right function,
or the DECLARED miss import) and, in trace mode, past two DECLARED observation
imports that see the site, the resolved target, the frame and the return.

Everything below is therefore about one property: the pass either lowers a
site or REFUSES the window. A silent pass-through is a wrong-function call at
run time, which is strictly worse than a refused window, so the fail-closed
tests are the load-bearing ones here.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from src.port_indirect_lowering import (
    DISPATCH_AT,
    HEADER_FILENAME,
    HEADER_TEXT,
    MAX_ARGS,
    SITES_FILENAME,
    decode_site_token,
    header_problems,
    lower_source,
    lower_window,
    lowering_evidence,
    site_word,
    sites_manifest,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


# --------------------------------------------------------- the two shapes


def test_the_measured_call_shapes_lower_to_a_frame_and_a_dispatch():
    """The two shapes Ghidra emits for a `bctrl`: 1555 `(*(code *)` and 752
    `(**(code **)` across the export. The first dereferences a code pointer
    the ROM already holds; the second dereferences the pointer STORED AT the
    expression, which is why only it wears `__GF_DEREF`."""
    source = (
        "// ==== 80003100  gf_call ====\n"
        "void gf_call(int *p, int x)\n{\n"
        "  (*(code *)p[3])(p,x);\n"
        "  (**(code **)(*p + 0x30))(p);\n"
        "  return;\n}\n"
    )
    text, sites, problems, non_call, seed = lower_source("u", "u.c", source)
    assert problems == [] and non_call == 0 and seed == 0
    assert [site.shape for site in sites] == ["code_ptr", "code_ptr_ptr"]
    assert [site.arg_count for site in sites] == [2, 1]
    assert [site.target_expr for site in sites] == ["p[3]", "(*p + 0x30)"]
    # Neither cast survives: a surviving one is the call_indirect this whole
    # pass exists to remove.
    assert "(code *)" not in text and "(code **)" not in text
    assert text.count(f"{DISPATCH_AT}(") == 2
    # The single-deref shape passes the value; the double-deref shape reads
    # the callee address OUT of linear memory first.
    assert "(unsigned int)(p[3])" in text
    assert "__GF_DEREF((*p + 0x30))" in text
    # Argument marshalling is positional and class-tagged by _Generic.
    assert "__GF_ARG(__gf_c, 0u, (p));" in text
    assert "__GF_ARG(__gf_c, 1u, (x));" in text
    assert "__gf_c.frame.arg_count = 2u;" in text
    # The rewritten source pulls in the macros it now depends on, exactly once.
    assert text.startswith(f'#include "{HEADER_FILENAME}"\n')
    assert text.count(f'#include "{HEADER_FILENAME}"') == 1


def test_a_zero_argument_site_still_states_its_arity():
    source = "void f(int *p)\n{\n  (*(code *)p[1])();\n}\n"
    text, sites, problems, _, _ = lower_source("u", "u.c", source)
    assert problems == [] and sites[0].arg_count == 0
    assert "__gf_c.frame.arg_count = 0u;" in text
    assert "__GF_ARG(" not in text


def test_the_lowered_site_is_ONE_statement_so_an_unbraced_if_stays_correct():
    """The decisive syntactic property. Several of these sites are the
    unbraced body of an `if`, so a bare `{ ... }` block would silently change
    the program's control flow -- the following statement would become
    unconditional. `do { ... } while (0)` is one statement, so it does not."""
    source = (
        "void f(int *p, int x)\n{\n"
        "  if (x != 0) (*(code *)p[3])(p);\n"
        "  x = 1;\n"
        "}\n"
    )
    text, _, problems, _, _ = lower_source("u", "u.c", source)
    assert problems == []
    # The `if` head is still followed DIRECTLY by the lowered statement, and
    # the lowered statement is a single `do { ... } while (0)`.
    assert re.search(r"if \(x != 0\) do \{ __gf_indirect_call ", text)
    assert re.search(r"\} while \(0\);", text)
    # ... and `x = 1;` is still outside it.
    assert text.index("} while (0);") < text.index("x = 1;")


def test_a_loop_head_is_also_a_statement_position():
    source = (
        "void f(int *p, int x)\n{\n"
        "  while (x) (*(code *)p[1])(p);\n"
        "  for (x = 0; x < 3; x++) (*(code *)p[2])(p);\n"
        "}\n"
    )
    text, sites, problems, _, _ = lower_source("u", "u.c", source)
    assert problems == [] and len(sites) == 2
    assert re.search(r"while \(x\) do \{ ", text)
    assert re.search(r"x\+\+\) do \{ ", text)


@pytest.mark.parametrize(
    "body",
    [
        # A brace-less `else`: the preceding significant character is the `e`
        # of the keyword, not the `)` of a control-flow head.
        "  if (x) { x = 0; } else (*(code *)p[1])(p);\n",
        # A brace-less `do`: same shape, same reason.
        "  do (*(code *)p[1])(p); while (x);\n",
        # `switch (x) stmt;` is legal C and is a statement position, but
        # `switch` is not in the recognised head keywords.
        "  switch (x) (*(code *)p[1])(p);\n",
    ],
)
def test_statement_positions_the_pass_does_not_recognise_refuse_conservatively(
    body: str,
):
    """CONSERVATIVE GAP, recorded rather than hidden. These three ARE statement
    positions, so lowering them would be correct -- `_statement_context` just
    does not recognise them and files them as value context. That direction is
    safe (a refused window, not a wrong call), and pinning it here means the
    day someone widens the recogniser this test tells them which shapes moved.
    """
    source = f"void f(int *p, int x)\n{{\n{body}}}\n"
    text, sites, problems, _, _ = lower_source("u", "u.c", source)
    assert [p.code for p in problems] == ["indirect_value_context"]
    assert text == source and sites == []


# ------------------------------------------------------ not every cast is a call


def test_a_pointer_comparison_is_not_a_call_and_is_counted_not_missed():
    """`if (*(code **)(x + 0x100) != (code *)0x0)` is a NULL TEST, not a
    dispatch -- 100 of them in the export. Leaving it alone is correct;
    counting it is what proves the pass classified it rather than missing
    it."""
    source = (
        "void f(int x)\n{\n"
        "  if (*(code **)(x + 0x100) != (code *)0x0) {\n"
        "    return;\n  }\n"
        "  return;\n}\n"
    )
    text, sites, problems, non_call, _ = lower_source("u", "u.c", source)
    assert problems == [] and sites == []
    assert non_call == 1
    # Untouched, and NOT decorated with an include it does not need.
    assert text == source


def test_a_cast_inside_a_comment_or_a_string_is_not_a_call_site():
    source = (
        "void f(int *p)\n{\n"
        '  /* (*(code *)p[1])(p); */\n'
        '  const char *s = "(*(code *)p[1])(p);";\n'
        "  return;\n}\n"
    )
    text, sites, problems, non_call, _ = lower_source("u", "u.c", source)
    assert (sites, problems, non_call) == ([], [], 0)
    assert text == source


def test_a_source_with_no_indirect_call_is_left_byte_identical():
    source = "// ==== 80004200  g ====\nint g(int x)\n{\n  return x + 1;\n}\n"
    text, sites, problems, non_call, _ = lower_source("u", "u.c", source)
    assert (sites, problems, non_call) == ([], [], 0)
    assert text == source  # nothing rewritten => nothing rewritten


# ------------------------------------------------------------- fail closed


def test_a_call_whose_RESULT_IS_USED_is_refused_never_narrowed():
    """Design C8, refused deliberately. The uniform frame's i32 result is only
    a VIEW of the return slot -- for an i64 return it is not the PPC r3 image
    -- and an indirect site carries no callee prototype to derive the true
    return class from. Lowering it would narrow the return SILENTLY, which is
    precisely the "signature traps become silent mis-marshalling" risk."""
    source = "void f(int *p)\n{\n  int uVar1;\n  uVar1 = (*(code *)p[3])(p);\n}\n"
    text, sites, problems, _, _ = lower_source("unit-x", "unit-x.c", source)
    assert [p.code for p in problems] == ["indirect_value_context"]
    assert problems[0].unit == "unit-x" and problems[0].source == "unit-x.c"
    assert "IS USED" in problems[0].detail
    # The decisive property: a refused source is NOT rewritten, so no caller
    # can accidentally link a half-lowered translation unit.
    assert text == source
    assert sites == []


@pytest.mark.parametrize(
    "body",
    [
        # An assignment consumes the result.
        "  x = (*(code *)p[3])(p);\n",
        # So does an argument position.
        "  g((*(code *)p[3])(p));\n",
        # So does an operator.
        "  x = 1 + (*(code *)p[3])(p);\n",
    ],
)
def test_every_value_position_refuses(body: str):
    source = f"void f(int *p, int x)\n{{\n{body}}}\n"
    _, _, problems, _, _ = lower_source("u", "u.c", source)
    assert [p.code for p in problems] == ["indirect_value_context"]


@pytest.mark.parametrize(
    "source",
    [
        # The second arm of a conditional operator is ALSO preceded by `:`, and
        # there the RESULT IS USED. Reading every `:` as a statement label was a
        # FAIL-OPEN hole in a fail-closed pass: it would have narrowed these
        # returns through the frame's i32 view (design C8) without a word.
        "void f(int *p, int c, int x)\n{\n  x = c ? 0 : (*(code *)p[3])(p);\n}\n",
        # The mirror arm is preceded by `?` and was never at risk; asserted so
        # the two stay symmetric.
        "void f(int *p, int c, int x)\n{\n  x = c ? (*(code *)p[3])(p) : 0;\n}\n",
        # Nested, so the `:` is not the nearest interesting character.
        "void f(int *p, int c, int d, int x)\n{\n"
        "  x = c ? 0 : d ? 1 : (*(code *)p[3])(p);\n}\n",
    ],
)
def test_a_conditional_colon_is_not_a_statement_label(source: str):
    _, _, problems, _, _ = lower_source("u", "u.c", source)
    assert [p.code for p in problems] == ["indirect_value_context"]


@pytest.mark.parametrize(
    "body",
    [
        # ...while every shape that really IS a label keeps lowering. These are
        # the three the decompiled corpus emits and the only three recognised.
        "  switch (c) {\n  case 3:\n    (*(code *)p[3])(p);\n    break;\n  }\n",
        "  switch (c) {\n  default:\n    (*(code *)p[3])(p);\n  }\n",
        "LAB_80010e2c:\n  (*(code *)p[3])(p);\n",
    ],
)
def test_a_real_statement_label_still_lowers(body: str):
    source = f"void f(int *p, int c)\n{{\n{body}}}\n"
    _, sites, problems, _, _ = lower_source("u", "u.c", source)
    assert problems == []
    assert len(sites) == 1


def test_more_arguments_than_the_frame_has_slots_is_refused_never_truncated():
    """The frame carries GF_DISPATCH_MAX_ARGS slots. A call with more cannot
    be marshalled, and dropping the tail would be a silently wrong call."""
    args = ",".join(f"a{index}" for index in range(MAX_ARGS + 1))
    params = ",".join(f"int a{index}" for index in range(MAX_ARGS + 1))
    source = f"void f(int *p,{params})\n{{\n  (*(code *)p[3])({args});\n}}\n"
    text, sites, problems, _, _ = lower_source("u", "u.c", source)
    assert [p.code for p in problems] == ["indirect_arity_overflow"]
    assert f"{MAX_ARGS + 1} arguments exceeds the frame's {MAX_ARGS} slots" in (
        problems[0].detail
    )
    assert text == source and sites == []


def test_exactly_the_frames_capacity_still_lowers():
    """The boundary is a capacity, not a margin: MAX_ARGS arguments fit."""
    args = ",".join(f"a{index}" for index in range(MAX_ARGS))
    params = ",".join(f"int a{index}" for index in range(MAX_ARGS))
    source = f"void f(int *p,{params})\n{{\n  (*(code *)p[3])({args});\n}}\n"
    text, sites, problems, _, _ = lower_source("u", "u.c", source)
    assert problems == [] and sites[0].arg_count == MAX_ARGS
    assert f"__gf_c.frame.arg_count = {MAX_ARGS}u;" in text


@pytest.mark.parametrize(
    "source",
    [
        # The outer parenthesis never closes.
        "void f(int *p)\n{\n  (*(code *)p[3](p);\n}\n",
        # The argument list never closes.
        "void f(int *p)\n{\n  (*(code *)p[3])(p;\n}\n",
    ],
)
def test_unbalanced_parentheses_refuse_rather_than_guess(source: str):
    text, sites, problems, _, _ = lower_source("u", "u.c", source)
    assert [p.code for p in problems] == ["indirect_unparsed"]
    assert text == source and sites == []


def test_an_indirection_depth_the_pass_does_not_model_is_refused():
    source = "void f(int *p)\n{\n  (***(code ***)p[3])(p);\n}\n"
    _, _, problems, _, _ = lower_source("u", "u.c", source)
    assert [p.code for p in problems] == ["indirect_unparsed"]
    assert "indirection depth" in problems[0].detail


def test_one_bad_site_refuses_the_whole_source_even_beside_good_ones():
    source = (
        "void f(int *p, int x)\n{\n"
        "  (*(code *)p[3])(p);\n"
        "  x = (*(code *)p[4])(p);\n"
        "}\n"
    )
    text, _, problems, _, _ = lower_source("u", "u.c", source)
    assert [p.code for p in problems] == ["indirect_value_context"]
    assert text == source


def test_lower_window_returns_NO_sources_when_any_one_of_them_refuses():
    """The window-level half of fail-closed. A partially lowered window must
    never reach the linker: the good units would dispatch through the table
    while the refused one still holds a call_indirect on a GC address."""
    good = "void f(int *p)\n{\n  (*(code *)p[3])(p);\n}\n"
    bad = "void g(int *p, int x)\n{\n  x = (*(code *)p[3])(p);\n}\n"
    result = lower_window([("u1", "u1.c", good), ("u2", "u2.c", bad)])
    assert [p.code for p in result.problems] == ["indirect_value_context"]
    assert result.sources == {}, "a refused window hands back nothing to write"
    # The sites the good source DID yield are still reported, so the refusal
    # evidence shows what would have been lowered.
    assert [site.source for site in result.sites] == ["u1.c"]


def test_a_clean_window_hands_back_every_source_including_untouched_ones():
    good = "void f(int *p)\n{\n  (*(code *)p[3])(p);\n}\n"
    plain = "int g(int x)\n{\n  return x;\n}\n"
    result = lower_window([("u1", "u1.c", good), ("u2", "u2.c", plain)])
    assert result.problems == []
    assert sorted(result.sources) == ["u1.c", "u2.c"]
    assert result.sources["u2.c"] == plain  # untouched means untouched


# ------------------------------------------------------------ site identity


def test_site_ids_come_from_the_enclosing_marker_with_a_per_function_ordinal():
    """The decompiled C carries no per-instruction address, so a site is named
    by the GC address of the function it is IN plus its ordinal within that
    function. That is stable for a given source text, which is what a capture
    plan and a replay both need in order to name the same site."""
    source = (
        "// ==== 80003100  gf_first ====\n"
        "void gf_first(int *p)\n{\n"
        "  (*(code *)p[1])(p);\n"
        "  (*(code *)p[2])(p);\n"
        "}\n"
        "// ==== 800042a0  gf_second ====\n"
        "void gf_second(int *p)\n{\n"
        "  (*(code *)p[3])(p);\n"
        "}\n"
    )
    _, sites, problems, _, _ = lower_source("u", "u.c", source)
    assert problems == []
    assert [site.site for site in sites] == [
        "80003100:0",
        "80003100:1",
        "800042a0:0",
    ]
    assert [site.function for site in sites] == ["gf_first", "gf_first", "gf_second"]
    assert {site.site_kind for site in sites} == {"gc_address"}


def test_a_site_with_no_enclosing_marker_falls_back_to_a_window_ordinal():
    """A derived source that lost its markers still yields a NAMED site --
    just one whose id says so, rather than a silently address-shaped lie."""
    source = "void f(int *p)\n{\n  (*(code *)p[1])(p);\n}\n"
    _, sites, _, _, seed = lower_source("u", "u.c", source, site_seed=7)
    assert sites[0].site == "ord0007" and sites[0].site_kind == "ordinal"
    assert seed == 8, "the seed advances so a window never reuses an ordinal"


def test_the_window_ordinal_seed_carries_across_sources():
    a = "void f(int *p)\n{\n  (*(code *)p[1])(p);\n}\n"
    b = "void g(int *p)\n{\n  (*(code *)p[2])(p);\n}\n"
    result = lower_window([("u1", "u1.c", a), ("u2", "u2.c", b)])
    assert [site.site for site in result.sites] == ["ord0000", "ord0001"]


@pytest.mark.parametrize(
    "site_id",
    ["80003100:0", "80003100:1", "800042a0:15", "8027c34c:3", "80000000:0"],
)
def test_the_site_word_round_trips_through_decode(site_id: str):
    """The wire form the emitted C actually passes to `__gf_dispatch_at`. A
    trace line has to be self-describing, so the packing must be exactly
    invertible -- not merely unique."""
    assert decode_site_token(site_word(site_id)) == site_id


def test_the_site_word_is_what_the_emitted_call_passes():
    source = (
        "// ==== 80003100  gf_first ====\n"
        "void gf_first(int *p)\n{\n"
        "  (*(code *)p[1])(p);\n"
        "  (*(code *)p[2])(p);\n"
        "}\n"
    )
    text, sites, _, _, _ = lower_source("u", "u.c", source)
    for site in sites:
        token = f"0x{site_word(site.site):08x}u"
        assert f"{DISPATCH_AT}({token}," in text
        assert decode_site_token(int(token[2:-1], 16)) == site.site


# ------------------------------------------------------------ header + evidence


def test_the_emitted_header_declares_everything_the_lowering_emits():
    """The drift check. The rewrite is only as good as the macros it emits
    calls to, so a header that lost one of them must be loud, not a
    compile error the operator has to attribute by hand."""
    assert header_problems(HEADER_TEXT) == []
    assert header_problems("") == [
        "emitted header lost `__gf_indirect_call`",
        "emitted header lost `__GF_ARG`",
        "emitted header lost `__GF_ADDR`",
        f"emitted header lost `{DISPATCH_AT}`",
    ]
    assert header_problems(HEADER_TEXT.replace("__GF_ADDR", "__GF_GONE")) == [
        "emitted header lost `__GF_ADDR`"
    ]


def test_the_header_declares_the_companions_entry_with_the_uniform_signature():
    assert f"extern int {DISPATCH_AT}(unsigned int site, unsigned int gc_addr," in (
        HEADER_TEXT
    )
    assert '#include "gf_dispatch_frame.h"' in HEADER_TEXT


def test_evidence_counts_the_shapes_and_makes_no_behavioural_claim():
    source = (
        "// ==== 80003100  gf_first ====\n"
        "void gf_first(int *p)\n{\n"
        "  (*(code *)p[1])(p);\n"
        "  (**(code **)(*p + 4))(p);\n"
        "  if (*(code **)(*p + 8) != (code *)0x0) { return; }\n"
        "}\n"
    )
    result = lower_window([("u1", "u1.c", source)])
    evidence = lowering_evidence(result)
    assert evidence["sites"] == 2
    assert evidence["sites_by_shape"] == {"code_ptr": 1, "code_ptr_ptr": 1}
    assert evidence["non_call_casts"] == 1
    assert evidence["functions"] == ["gf_first"]
    assert evidence["header"] == HEADER_FILENAME
    assert evidence["sites_manifest"] == SITES_FILENAME
    assert evidence["dispatch_entry"] == DISPATCH_AT
    # Deterministic for a given window: the manifest digest is the receipt a
    # capture plan binds to.
    assert lowering_evidence(lower_window([("u1", "u1.c", source)])) == evidence
    # Structural only. Lowering a site says nothing about whether the module
    # behaves like the console -- that is run-dispatch.mjs's job.
    assert "behavior" not in json.dumps(evidence).lower().replace("behavioural", "")


def test_the_site_manifest_is_json_the_replay_can_read():
    source = (
        "// ==== 80003100  gf_first ====\n"
        "void gf_first(int *p)\n{\n  (*(code *)p[1])(p);\n}\n"
    )
    result = lower_window([("u1", "u1.c", source)])
    manifest = json.loads(sites_manifest(result))
    assert manifest["indirect_sites_schema"] == 1
    assert manifest["dispatch_entry"] == DISPATCH_AT
    assert manifest["sites"][0]["site"] == "80003100:0"


# ------------------------------------------- the companion's outbound half


def _companion_signatures():
    from src.port_dispatch_companion import derive_window_signatures

    source = (
        "// ==== 80003100  gf_thunked ====\n"
        "int gf_thunked(int a)\n{\n  return a + 1;\n}\n"
    )
    derived = derive_window_signatures([("u1", source, ["gf_thunked"])], {})
    assert derived.problems == []
    return derived.signatures


def test_a_companion_without_the_new_flags_is_what_it_always_was():
    """The OFF-shape guarantee. Every window that does not ask for the
    lowering must get byte-identically the companion it got before this
    module grew an outbound half."""
    from src.port_dispatch_companion import (
        DISPATCH_AT_EXPORT,
        TRACE_ENTER_IMPORT,
        TRACE_EXIT_IMPORT,
        companion_evidence,
        emit_companion_source,
    )

    signatures = _companion_signatures()
    text = emit_companion_source(signatures)
    assert text == emit_companion_source(signatures, dispatch_at=False, trace=False)
    assert DISPATCH_AT_EXPORT not in text
    assert TRACE_ENTER_IMPORT not in text and TRACE_EXIT_IMPORT not in text
    evidence = companion_evidence(signatures, text)
    assert "dispatch_at_export" not in evidence
    assert "trace_imports" not in evidence and "trace_claim" not in evidence


def test_trace_declares_both_imports_and_leaves_the_dispatch_body_alone():
    """Trace adds OBSERVATION, never behaviour: the same thunks, the same
    table, the same miss import, in the same order. The proof is textual --
    the untraced companion is a strict PREFIX of the traced one, so nothing
    already emitted was rewritten, only appended to."""
    from src.port_dispatch_companion import (
        DISPATCH_AT_EXPORT,
        DISPATCH_EXPORT,
        TRACE_ENTER_IMPORT,
        TRACE_EXIT_IMPORT,
        companion_evidence,
        emit_companion_source,
    )

    signatures = _companion_signatures()
    plain = emit_companion_source(signatures)
    traced = emit_companion_source(signatures, trace=True)
    assert traced.startswith(plain), "trace must append, never rewrite"
    assert f"extern void {TRACE_ENTER_IMPORT}(" in traced
    assert f"extern void {TRACE_EXIT_IMPORT}(" in traced
    assert f"int {DISPATCH_AT_EXPORT}(unsigned int site," in traced
    # `__gf_dispatch` itself is untouched -- it is defined in the shared
    # prefix, so the traced module dispatches exactly as the untraced one.
    assert f"{DISPATCH_EXPORT}(unsigned int gc_addr, int argptr)" in plain
    # trace implies dispatch_at, and the evidence says what it does NOT claim.
    evidence = companion_evidence(signatures, traced, trace=True)
    assert evidence["dispatch_at_export"] == DISPATCH_AT_EXPORT
    assert evidence["trace_imports"] == [TRACE_ENTER_IMPORT, TRACE_EXIT_IMPORT]
    assert "establish no tier" in evidence["trace_claim"]


def test_dispatch_at_without_trace_is_a_straight_forward_to_dispatch():
    from src.port_dispatch_companion import (
        DISPATCH_EXPORT,
        TRACE_ENTER_IMPORT,
        emit_companion_source,
    )

    text = emit_companion_source(_companion_signatures(), dispatch_at=True)
    assert TRACE_ENTER_IMPORT not in text
    assert f"return {DISPATCH_EXPORT}(gc_addr, argptr);" in text


# ------------------------------------------------------------- gate wiring


def _write_gate_unit(directory: Path, name: str, source_body: str, exports: list[str]):
    from src.port_assembly_gate import UnitArtifact, unit_artifact_sha256

    directory.mkdir(parents=True, exist_ok=True)
    (directory / "gnt4_shim.h").write_text(
        "#ifndef GNT4_SHIM_H\n#define GNT4_SHIM_H\n#endif\n",
        encoding="utf-8",
        newline="\n",
    )
    (directory / "unit.c").write_text(
        '#include "gnt4_shim.h"\n\n' + source_body, encoding="utf-8", newline="\n"
    )
    return UnitArtifact(
        name, directory, unit_artifact_sha256(directory), "", exports, [], "compile_only"
    )


def _capture_runner(captured: dict[str, Any], ok: bool = True, error: str = ""):
    def link_runner(workdir_arg, c_files, exports, allowed_extra):
        captured.update(
            workdir=workdir_arg, c_files=list(c_files), exports=list(exports),
            allowed_extra=list(allowed_extra),
        )
        return ok, error

    return link_runner


def _indirect_units(root: Path):
    a = _write_gate_unit(
        root / "unit-a",
        "unit-a",
        "// ==== 80003100  gf_ind_a ====\n"
        "void gf_ind_a(int *p, int x)\n{\n"
        "  if (x != 0) (*(code *)p[3])(p,x);\n"
        "  (**(code **)(*p + 0x30))(p);\n"
        "  return;\n}\n",
        ["gf_ind_a"],
    )
    b = _write_gate_unit(
        root / "unit-b",
        "unit-b",
        "// ==== 80004200  gf_plain_b ====\n"
        "int gf_plain_b(int x)\n{\n  return x + 1;\n}\n",
        ["gf_plain_b"],
    )
    return [a, b]


def test_gate_off_by_default_leaves_the_link_byte_identical(tmp_path: Path):
    from src.port_assembly_gate import run_assembly_gate
    from src.port_dispatch_companion import (
        DISPATCH_AT_EXPORT,
        TRACE_ENTER_IMPORT,
        TRACE_EXIT_IMPORT,
    )

    units = _indirect_units(tmp_path / "staging")
    workdir = tmp_path / "assembly"
    captured: dict[str, Any] = {}
    result = run_assembly_gate(units, workdir, _capture_runner(captured))
    assert result["passed"] is True
    assert not (workdir / HEADER_FILENAME).exists()
    assert not (workdir / SITES_FILENAME).exists()
    assert "indirect_lowering" not in result
    assert DISPATCH_AT_EXPORT not in captured["exports"]
    for name in (TRACE_ENTER_IMPORT, TRACE_EXIT_IMPORT):
        assert name not in captured["allowed_extra"]
    # The written source is the verbatim unit.c, call_indirect and all.
    assert "(*(code *)p[3])(p,x);" in (workdir / "unit-a.c").read_text(
        encoding="utf-8"
    )


def test_gate_on_lowers_the_sources_exports_the_entry_and_ledgers_it(tmp_path: Path):
    from src.port_assembly_gate import run_assembly_gate
    from src.port_dispatch_companion import COMPANION_FILENAME, DISPATCH_AT_EXPORT

    units = _indirect_units(tmp_path / "staging")
    workdir = tmp_path / "assembly"
    captured: dict[str, Any] = {}
    result = run_assembly_gate(
        units,
        workdir,
        _capture_runner(captured),
        dispatch_companion=True,
        indirect_lowering=True,
    )
    assert result["passed"] is True, result
    assert (workdir / HEADER_FILENAME).read_text(encoding="utf-8") == HEADER_TEXT
    lowered = (workdir / "unit-a.c").read_text(encoding="utf-8")
    assert lowered.startswith(f'#include "{HEADER_FILENAME}"\n')
    assert "(code *)" not in lowered and "(code **)" not in lowered
    assert lowered.count(f"{DISPATCH_AT}(") == 2
    # The unit with no indirect call is untouched.
    assert (workdir / "unit-b.c").read_text(encoding="utf-8").startswith(
        '#include "gnt4_shim.h"'
    )
    # The header is a HEADER: it is included by the sources, never compiled
    # as a translation unit of its own.
    assert HEADER_FILENAME not in captured["c_files"]
    assert captured["c_files"] == ["unit-a.c", "unit-b.c", COMPANION_FILENAME]
    assert DISPATCH_AT_EXPORT in captured["exports"]
    # The site manifest a capture plan binds to is committed beside them.
    manifest = json.loads((workdir / SITES_FILENAME).read_text(encoding="utf-8"))
    assert [site["site"] for site in manifest["sites"]] == [
        "80003100:0",
        "80003100:1",
    ]
    assert result["indirect_lowering"]["sites"] == 2
    assert result["dispatch"]["dispatch_at_export"] == DISPATCH_AT_EXPORT
    # The VERBATIM artifact was never edited -- only the derived copy.
    assert "(*(code *)p[3])(p,x);" in (units[0].directory / "unit.c").read_text(
        encoding="utf-8"
    )


def test_gate_refuses_the_lowering_without_the_companion(tmp_path: Path):
    """The lowered C calls `__gf_dispatch_at`, which only the companion
    defines. Under -sERROR_ON_UNDEFINED_SYMBOLS=0 an unpaired lowering would
    not fail to link -- it would silently turn every ROM call site into an
    undeclared host import. Refused loudly instead."""
    from src.port_assembly_gate import CLASS_INDIRECT_LOWERING_FAILED, run_assembly_gate

    units = _indirect_units(tmp_path / "staging")
    captured: dict[str, Any] = {}
    result = run_assembly_gate(
        units, tmp_path / "assembly", _capture_runner(captured), indirect_lowering=True
    )
    assert result["passed"] is False
    assert result["stage"] == "indirect-lowering"
    assert captured == {}, "the link must not be attempted after a refusal"
    (conflict,) = result["conflicts"]
    assert conflict["class"] == CLASS_INDIRECT_LOWERING_FAILED
    assert "dispatch_companion" in conflict["detail"]
    assert DISPATCH_AT in result["detail"]


def test_gate_trace_implies_the_lowering_and_still_needs_the_companion(tmp_path: Path):
    from src.port_assembly_gate import CLASS_INDIRECT_LOWERING_FAILED, run_assembly_gate

    result = run_assembly_gate(
        _indirect_units(tmp_path / "staging"),
        tmp_path / "assembly",
        _capture_runner({}),
        dispatch_trace=True,
    )
    assert result["passed"] is False
    assert result["conflicts"][0]["class"] == CLASS_INDIRECT_LOWERING_FAILED


def test_gate_refuses_loudly_when_a_site_cannot_be_lowered(tmp_path: Path):
    from src.port_assembly_gate import CLASS_INDIRECT_LOWERING_FAILED, run_assembly_gate

    units = _indirect_units(tmp_path / "staging")
    units.append(
        _write_gate_unit(
            tmp_path / "staging/unit-c",
            "unit-c",
            "// ==== 80005300  gf_uses_result ====\n"
            "int gf_uses_result(int *p)\n{\n  return (*(code *)p[3])(p);\n}\n",
            ["gf_uses_result"],
        )
    )
    workdir = tmp_path / "assembly"
    captured: dict[str, Any] = {}
    result = run_assembly_gate(
        units,
        workdir,
        _capture_runner(captured),
        dispatch_companion=True,
        indirect_lowering=True,
    )
    assert result["passed"] is False
    assert result["stage"] == "indirect-lowering"
    assert captured == {}, "the link must not be attempted after a refusal"
    classes = {conflict["class"] for conflict in result["conflicts"]}
    assert classes == {CLASS_INDIRECT_LOWERING_FAILED}
    assert "indirect_value_context" in result["conflicts"][0]["detail"]
    assert "wrong-function call or a trap" in result["detail"]
    # Fail-closed on disk too: NOTHING was rewritten, so a re-run of the gate
    # sees the same verbatim window.
    assert "(*(code *)p[3])(p,x);" in (workdir / "unit-a.c").read_text(
        encoding="utf-8"
    )
    assert not (workdir / HEADER_FILENAME).exists()


def test_gate_trace_declares_the_two_observation_imports(tmp_path: Path):
    from src.port_assembly_gate import run_assembly_gate
    from src.port_dispatch_companion import (
        COMPANION_FILENAME,
        TRACE_ENTER_IMPORT,
        TRACE_EXIT_IMPORT,
    )

    units = _indirect_units(tmp_path / "staging")
    workdir = tmp_path / "assembly"
    captured: dict[str, Any] = {}
    result = run_assembly_gate(
        units,
        workdir,
        _capture_runner(captured),
        dispatch_companion=True,
        indirect_lowering=True,
        dispatch_trace=True,
    )
    assert result["passed"] is True, result
    for name in (TRACE_ENTER_IMPORT, TRACE_EXIT_IMPORT):
        # DECLARED host callees, exactly like the miss handler: without this
        # the import scan would call the companion's own trace mode a
        # disallowed import.
        assert name in captured["allowed_extra"]
        assert f"extern void {name}(" in (workdir / COMPANION_FILENAME).read_text(
            encoding="utf-8"
        )
    assert result["dispatch"]["trace_imports"] == [
        TRACE_ENTER_IMPORT,
        TRACE_EXIT_IMPORT,
    ]


def test_the_lowering_runs_BEFORE_the_companion_derives_its_table(tmp_path: Path):
    """Ordering, proven rather than asserted. The companion derives its thunk
    signatures by RE-READING the written sources, so a site rewritten AFTER it
    ran would be absent from the very table it dispatches through. This
    observes the on-disk text at the moment the companion is entered."""
    import src.port_assembly_gate as gate

    units = _indirect_units(tmp_path / "staging")
    workdir = tmp_path / "assembly"
    seen: dict[str, str] = {}
    original = gate._emit_dispatch_companion

    def spy(result, units_arg, names, workdir_arg, c_files, **kwargs):
        seen["unit-a.c"] = (workdir_arg / "unit-a.c").read_text(encoding="utf-8")
        seen["header"] = str((workdir_arg / HEADER_FILENAME).is_file())
        return original(result, units_arg, names, workdir_arg, c_files, **kwargs)

    gate._emit_dispatch_companion = spy
    try:
        result = gate.run_assembly_gate(
            units,
            workdir,
            _capture_runner({}),
            dispatch_companion=True,
            indirect_lowering=True,
        )
    finally:
        gate._emit_dispatch_companion = original
    assert result["passed"] is True, result
    assert f"{DISPATCH_AT}(" in seen["unit-a.c"]
    assert "(code *)" not in seen["unit-a.c"]
    assert seen["header"] == "True"


def test_the_lowering_composes_with_the_wgpipe_lowering_and_the_companion(
    tmp_path: Path,
):
    """All three derived artifacts in one window. The wgpipe lowering runs
    first, then the indirect lowering, then the companion -- each later stage
    reads the text the earlier one left."""
    from src.port_assembly_gate import run_assembly_gate
    from src.port_wgpipe_lowering import WGPIPE_IMPORTS

    units = _indirect_units(tmp_path / "staging")
    units.append(
        _write_gate_unit(
            tmp_path / "staging/unit-c",
            "unit-c",
            "// ==== 80006400  gf_pipe_c ====\n"
            "void gf_pipe_c(unsigned int v, int *p)\n{\n"
            "  DAT_cc008000 = v;\n"
            "  (*(code *)p[3])(p);\n"
            "}\n",
            ["gf_pipe_c"],
        )
    )
    workdir = tmp_path / "assembly"
    captured: dict[str, Any] = {}
    result = run_assembly_gate(
        units,
        workdir,
        _capture_runner(captured),
        dispatch_companion=True,
        wgpipe_lowering=True,
        indirect_lowering=True,
    )
    assert result["passed"] is True, result
    lowered = (workdir / "unit-c.c").read_text(encoding="utf-8")
    assert "GF_WGPIPE_W32((v));" in lowered  # the wgpipe rewrite survived ...
    assert f"{DISPATCH_AT}(" in lowered  # ... and the indirect one landed on top
    assert result["wgpipe"]["stores"] == 1
    assert result["indirect_lowering"]["sites"] == 3
    assert result["dispatch"]["functions"] == 3
    assert set(WGPIPE_IMPORTS) <= set(captured["allowed_extra"])


def test_the_driver_reads_the_opt_ins_from_the_environment():
    source = (REPO_ROOT / "src/port_wasm_units.py").read_text(encoding="utf-8")
    assert 'os.getenv("OGHIDRA_PORT_INDIRECT_LOWERING", "") == "1"' in source
    assert 'os.getenv("OGHIDRA_PORT_DISPATCH_TRACE", "") == "1"' in source
    assert "indirect_lowering=(" in source and "dispatch_trace=(" in source
