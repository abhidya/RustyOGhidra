"""Write-gather-pipe lowering: shapes, refusals, gate wiring, real pilots.

THE BLOCKER THIS CLOSES (docs/gx-hle-host.md section 7.1). Gotcha Force
submits vertices by STORING them to the GameCube's memory-mapped write-gather
pipe at 0xCC008000 -- 1143 such stores in the export -- not by calling a
function. The composed module's linear memory ends far below that address, so
every one of those stores is an out-of-bounds TRAP, and the browser HLE host's
FIFO decoder sits waiting for data that can never arrive.

The pilots at the bottom take the ROM's OWN smallest draw function
(`zz_0027c34_`, chunk_0003.c:3285-3328) VERBATIM, run it through the real
gate with lowering on, link it with the pinned emsdk, execute it under node,
and check the exact `__gf_gx_wgpipe_*` call sequence and the exact big-endian
byte stream that reaches the host's decoder.
"""

from __future__ import annotations

import json
import re
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from src.port_wgpipe_lowering import (
    HEADER_FILENAME,
    HEADER_SHA256,
    HEADER_TEXT,
    LOWERABLE_OFFSETS,
    PIPE_BASE,
    PIPE_LIMIT,
    WGPIPE_ABI_VERSION,
    WGPIPE_IMPORTS,
    header_include_path,
    header_problems,
    lower_source,
    lower_window,
    lowering_evidence,
    mask_code,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _discover_product_root() -> Path:
    probe = "research/tools/emsdk/upstream/bin/clang.exe"
    for candidate in (REPO_ROOT, *REPO_ROOT.parents):
        if (candidate / probe).is_file():
            return candidate
    return REPO_ROOT


PRODUCT_ROOT = _discover_product_root()


def _toolchain_available() -> bool:
    from src.port_assembly_gate import _EMSCRIPTEN_VERSION_RELPATH, _TOOL_RELPATHS

    return all((PRODUCT_ROOT / rel).is_file() for rel in _TOOL_RELPATHS.values()) and (
        PRODUCT_ROOT / _EMSCRIPTEN_VERSION_RELPATH
    ).is_file()


requires_toolchain = pytest.mark.skipif(
    not _toolchain_available(), reason="emsdk toolchain not present in this checkout"
)

# The ROM's own smallest immediate-mode draw function, copied byte-for-byte
# out of research/decomp/ghidra-export/chunk_0003.c (lines 3285-3328). Nothing
# here is paraphrased: this is the decompiler's text, and it is what the
# pilots below compile.
ZZ_0027C34_VERBATIM = """// ==== 80027c34  zz_0027c34_ ====

void zz_0027c34_(void)

{
  undefined4 uVar1;
  float afStack_38 [14];

  if ((*(int *)(PTR_DAT_80433930 + 0x38) == 0) && (DAT_80436108 != 0)) {
    gnt4_GXSetCullMode_bl(2);
    gnt4_GXSetBlendMode_bl(1,4,5,0);
    gnt4_GXSetZMode_bl(1,7,0);
    gnt4_GXSetProjection_bl((undefined4 *)&DAT_803c0f40,1);
    gnt4_PSMTXIdentity_bl(afStack_38);
    gnt4_GXLoadPosMtxImm_bl(afStack_38,0);
    gnt4_GXSetCurrentMtx_bl(0);
    gnt4_GXClearVtxDesc_bl();
    gnt4_GXSetVtxDesc_bl(9,1);
    gnt4_GXSetVtxDesc_bl(0xb,1);
    gnt4_GXSetVtxAttrFmt_bl(0,9,0,3,0);
    gnt4_GXSetVtxAttrFmt_bl(0,0xb,1,5,0);
    gnt4_GXSetNumChans_bl(1);
    gnt4_GXSetNumTexGens_bl(0);
    gnt4_GXSetNumTevStages_bl(1);
    gnt4_GXSetChanCtrl_bl(4,0,1,1,0,0,2);
    gnt4_GXSetTevOrder_bl(0,0xff,0xff,4);
    gnt4_GXSetTevOp_bl(0,4);
    gnt4_GXBegin_bl(0x80,0,4);
    uVar1 = *DAT_8043610c;
    DAT_cc008000._0_2_ = 0;
    DAT_cc008000._0_2_ = 0;
    DAT_cc008000 = uVar1;
    DAT_cc008000._0_2_ = 0x280;
    DAT_cc008000._0_2_ = 0;
    DAT_cc008000 = uVar1;
    DAT_cc008000._0_2_ = 0x280;
    DAT_cc008000._0_2_ = 0x1c0;
    DAT_cc008000 = uVar1;
    DAT_cc008000._0_2_ = 0;
    DAT_cc008000._0_2_ = 0x1c0;
    DAT_cc008000 = uVar1;
  }
  return;
}
"""


# ------------------------------------------------------- the store shapes


def test_the_three_measured_store_shapes_lower_by_width():
    """The enumeration IS the spec: scanning the whole export finds exactly
    three spellings -- `DAT_cc008000 = v` (713), `._0_1_ =` (311) and
    `._0_2_ =` (119) -- and each lowers to the import of its own width."""
    source = (
        "void f(unsigned int v) {\n"
        "  DAT_cc008000._0_1_ = 0x10;\n"
        "  DAT_cc008000._0_2_ = 0x280;\n"
        "  DAT_cc008000 = v;\n"
        "}\n"
    )
    out = lower_source("u", "u.c", source)
    assert out.problems == []
    assert [store.width for store in out.stores] == [1, 2, 4]
    assert [store.address for store in out.stores] == [PIPE_BASE] * 3
    assert "GF_WGPIPE_W8((0x10));" in out.text
    assert "GF_WGPIPE_W16((0x280));" in out.text
    assert "GF_WGPIPE_W32((v));" in out.text
    # The verbatim right-hand side survives untouched, and nothing else in
    # the file moves.
    assert out.text.endswith("}\n")


def test_the_second_pipe_word_lowers_in_program_order():
    """0xCC008004 is the second word of the SDK's 8-byte matrix pushes. The
    hardware gathers a write to ANY address in the 32-byte window into the
    same stream in program order, so it lowers to the same u32 import and
    keeps its position."""
    source = "void f(unsigned int a, unsigned int b) {\n  DAT_cc008000 = a;\n  DAT_cc008004 = b;\n}\n"
    out = lower_source("u", "u.c", source)
    assert out.problems == []
    assert [store.address for store in out.stores] == [0xCC008000, 0xCC008004]
    body = out.text
    assert body.index("GF_WGPIPE_W32((a));") < body.index("GF_WGPIPE_W32((b));")


def test_a_multi_line_store_statement_lowers_whole():
    """Eight of the export's stores span more than one line. A line-oriented
    rewriter would truncate them; this one bounds the statement by its
    terminator."""
    source = (
        "void f(unsigned int p) {\n"
        "  DAT_cc008000 = (p + 0x10) * 0x1000000 |\n"
        "                 (p & 0xff);\n"
        "}\n"
    )
    out = lower_source("u", "u.c", source)
    assert out.problems == []
    assert len(out.stores) == 1
    assert "GF_WGPIPE_W32(((p + 0x10) * 0x1000000 |\n                 (p & 0xff)));" in out.text


def test_a_comma_operator_right_hand_side_stays_one_macro_argument():
    source = "void f(unsigned int a, unsigned int b) {\n  DAT_cc008000 = (a, b);\n}\n"
    out = lower_source("u", "u.c", source)
    assert out.problems == []
    assert "GF_WGPIPE_W32(((a, b)));" in out.text


def test_pipe_references_inside_comments_and_strings_are_not_stores():
    source = (
        "/* DAT_cc008000 = 1; in a comment */\n"
        'const char *s = "DAT_cc008000";\n'
        "// DAT_cc008000 = 2;\n"
        "void f(void) { DAT_cc008000 = 3; }\n"
    )
    out = lower_source("u", "u.c", source)
    assert out.problems == []
    assert len(out.stores) == 1
    assert out.text.count("GF_WGPIPE_W32") == 1
    assert "/* DAT_cc008000 = 1; in a comment */" in out.text
    assert '"DAT_cc008000"' in out.text


def test_mask_code_preserves_length_and_lines():
    source = '/* a */ x = "b"; // c\ny;\n'
    mask = mask_code(source)
    assert len(mask) == len(source)
    assert mask.count("\n") == source.count("\n")
    assert "a" not in mask and "b" not in mask and "c" not in mask
    assert "x =" in mask and "y;" in mask


def test_a_source_without_the_pipe_is_left_untouched():
    source = "void f(void) { DAT_80436108 = 1; }\n"
    out = lower_source("u", "u.c", source)
    assert out.problems == []
    assert out.stores == []
    assert out.text is None  # nothing rewritten => nothing rewritten


# ------------------------------------------------------------- fail closed


@pytest.mark.parametrize(
    "source, code",
    [
        # A READ of the pipe. Lowering has no value to hand back, and leaving
        # it is an out-of-bounds load.
        ("void f(unsigned int *o) { *o = DAT_cc008000; }\n", "wgpipe_unlowerable_site"),
        # Read-modify-write on MMIO: the read half cannot be serviced.
        ("void f(void) { DAT_cc008000 |= 1; }\n", "wgpipe_unlowerable_site"),
        # Address-of: the pipe address escapes into a pointer.
        ("void f(void **o) { *o = &DAT_cc008000; }\n", "wgpipe_unlowerable_site"),
        # A bare literal store, no Ghidra global involved.
        ("void f(void) { *(unsigned int *)0xcc008000 = 1; }\n", "wgpipe_unlowerable_site"),
        # A field spelling the lowering does not model (byte 1 of the word).
        ("void f(void) { DAT_cc008000._1_1_ = 1; }\n", "wgpipe_unlowerable_site"),
        # Inside the window but at an offset whose gather order this lowering
        # does not model.
        ("void f(unsigned int v) { DAT_cc008008 = v; }\n", "wgpipe_offset_unsupported"),
        # Not statement-initial: the assignment's value is consumed.
        ("void f(unsigned int *o) { *o = DAT_cc008000 = 3; }\n", "wgpipe_store_not_statement"),
        # An 8-byte store: no host import carries that width.
        ("void f(unsigned long long v) { DAT_cc008000._0_8_ = v; }\n", "wgpipe_width_unsupported"),
    ],
)
def test_unlowerable_pipe_shapes_refuse_and_never_pass_through(source: str, code: str):
    out = lower_source("unit-x", "unit-x.c", source)
    assert out.problems, f"expected a refusal for: {source!r}"
    assert out.problems[0].code == code
    assert out.problems[0].unit == "unit-x"
    # The decisive property: a refused source is NOT rewritten, so no caller
    # can accidentally link a half-lowered translation unit.
    assert out.text is None


def test_a_refusal_names_the_file_and_line():
    source = "void f(unsigned int *o) {\n\n  *o = DAT_cc008000;\n}\n"
    out = lower_source("u", "sub/u.c", source)
    assert out.problems[0].line == 3
    assert "sub/u.c:3" in out.problems[0].detail


def test_one_bad_store_refuses_the_whole_source_even_beside_good_ones():
    source = (
        "void f(unsigned int v, unsigned int *o) {\n"
        "  DAT_cc008000 = v;\n"
        "  *o = DAT_cc008000;\n"
        "}\n"
    )
    out = lower_source("u", "u.c", source)
    assert out.text is None
    assert [p.code for p in out.problems] == ["wgpipe_unlowerable_site"]


def test_a_header_that_declares_the_pipe_symbol_is_not_a_store():
    """After the sources are lowered nothing dereferences the declaration, so
    it is dead, not dangerous."""
    header = (
        "#define DAT_cc008000 (*(unsigned int *)(unsigned int)0xcc008000u)\n"
        "extern unsigned int DAT_cc008004;\n"
    )
    assert header_problems("u", "u/gnt4_shim.h", header) == []


def test_a_header_that_performs_a_pipe_store_refuses():
    """The one fail-open the source rewriter could have: a store inside a
    header expands into every including translation unit, where the rewriter
    never looks. Closed by refusing, not by rewriting a shared declaration."""
    header = "static inline void push(unsigned int v) { DAT_cc008000 = v; }\n"
    found = header_problems("u", "u/gnt4_shim.h", header)
    assert [f.code for f in found] == ["wgpipe_header_store"]
    assert "u/gnt4_shim.h:1" in found[0].detail


def test_gate_refuses_a_window_whose_derived_header_stores_to_the_pipe(tmp_path: Path):
    from src.port_assembly_gate import CLASS_WGPIPE_LOWERING_FAILED, run_assembly_gate

    shim = (
        "#ifndef GNT4_SHIM_H\n#define GNT4_SHIM_H\n"
        "static void gf_push(unsigned int v) { DAT_cc008000 = v; }\n"
        "#endif\n"
    )
    units = [
        _write_gate_unit(tmp_path / "staging/u1", "u1", "int a(int x){return x;}\n", ["a"], shim=shim),
        _write_gate_unit(tmp_path / "staging/u2", "u2", "int b(int x){return x;}\n", ["b"], shim=shim),
    ]
    workdir = tmp_path / "assembly"
    captured: dict[str, Any] = {}
    result = run_assembly_gate(
        units, workdir, _capture_runner(captured), wgpipe_lowering=True
    )
    assert result["passed"] is False
    assert captured == {}
    assert result["conflicts"][0]["class"] == CLASS_WGPIPE_LOWERING_FAILED
    assert "wgpipe_header_store" in result["conflicts"][0]["detail"]


# ------------------------------------------------- the whole export, measured


def _export_dir() -> Path:
    return PRODUCT_ROOT / "research/decomp/ghidra-export"


@pytest.mark.skipif(
    not (_discover_product_root() / "research/decomp/ghidra-export").is_dir(),
    reason="decompiled export not present in this checkout",
)
def test_every_pipe_store_in_the_whole_export_lowers_with_no_refusal():
    """The enumeration, re-measured on every run. If a new export ever
    introduces a store shape this lowering does not model, this test fails
    HERE rather than the gate failing on a live unit."""
    totals = {"u8": 0, "u16": 0, "u32": 0}
    addresses: dict[int, int] = {}
    problems: list[Any] = []
    for path in sorted(_export_dir().glob("*.c")):
        text = path.read_text(encoding="utf-8", errors="replace")
        if "cc00800" not in text:
            continue
        out = lower_source(path.stem, path.name, text)
        problems.extend(out.problems)
        for store in out.stores:
            totals[f"u{store.width * 8}"] += 1
            addresses[store.address] = addresses.get(store.address, 0) + 1
    assert problems == [], [p.to_dict() for p in problems[:5]]
    # The measured population, stated as numbers so a change is visible.
    assert addresses == {0xCC008000: 1143, 0xCC008004: 31}
    assert totals == {"u8": 311, "u16": 119, "u32": 744}
    assert sum(totals.values()) == 1174


# --------------------------------------------------------- the host contract


def test_the_import_names_match_the_hosts_own_roster():
    """Cross-repo contract. The four import names belong to the browser HLE
    host (packages/rom-runtime/src/gx/adapters.ts, WGPIPE_SYMBOLS); this
    module must never 'improve' them, because the host binds by name."""
    adapters = PRODUCT_ROOT / "packages/rom-runtime/src/gx/adapters.ts"
    if not adapters.is_file():
        pytest.skip("browser host not present in this checkout")
    text = adapters.read_text(encoding="utf-8")
    block = text.split("export const WGPIPE_SYMBOLS", 1)[1].split("] as const", 1)[0]
    host_names = tuple(re.findall(r'"(__gf_gx_wgpipe_\w+)"', block))
    assert host_names == WGPIPE_IMPORTS
    for name in WGPIPE_IMPORTS:
        assert f"extern void {name}(" in HEADER_TEXT


def test_the_header_declares_exactly_the_four_imports_and_proves_its_routing():
    for name in WGPIPE_IMPORTS:
        assert HEADER_TEXT.count(f"extern void {name}(") == 1
    assert "__gf_gx_wgpipe_f32(float value)" in HEADER_TEXT
    # The routing table is compiler-proved, not comment-proved.
    assert "_Static_assert(GF_WGPIPE_IS_FP(1.0f) == 1," in HEADER_TEXT
    assert "_Static_assert(GF_WGPIPE_IS_FP(1u) == 0," in HEADER_TEXT
    assert HEADER_SHA256 == __import__("hashlib").sha256(
        HEADER_TEXT.encode("utf-8")
    ).hexdigest()


def test_the_pipe_window_constants_are_the_hardware_ones():
    assert PIPE_BASE == 0xCC008000
    assert PIPE_LIMIT - PIPE_BASE == 32
    assert LOWERABLE_OFFSETS == (0x0, 0x4)
    assert WGPIPE_ABI_VERSION == 1


def test_the_include_path_reaches_the_workdir_root_from_any_depth():
    assert header_include_path("unit.c") == HEADER_FILENAME
    assert header_include_path("auto-c0003-001/unit.c") == "../" + HEADER_FILENAME
    assert header_include_path("a/b/unit.c") == "../../" + HEADER_FILENAME


def test_evidence_is_deterministic_and_makes_no_behavioural_claim():
    plan = lower_window(
        [
            ("u1", "u1/u1.c", "void f(unsigned int v){ DAT_cc008000 = v; DAT_cc008000._0_1_ = 1; }\n"),
            ("u2", "u2/u2.c", "void g(void){ return; }\n"),
        ]
    )
    evidence = lowering_evidence(plan)
    assert evidence == json.loads(json.dumps(evidence))
    assert evidence["stores"] == 2
    assert evidence["by_width"] == {"u32": 1, "u8": 1}
    assert evidence["by_address"] == {"0xcc008000": 2}
    assert evidence["imports"] == list(WGPIPE_IMPORTS)
    assert evidence["header_sha256"] == HEADER_SHA256
    assert [u["unit"] for u in evidence["units"]] == ["u1"]
    assert evidence["behavior_claim"] is None


def test_the_rom_draw_function_lowers_to_the_quad_the_host_expects():
    """`zz_0027c34_` verbatim: GXBegin(GX_QUADS, fmt 0, 4 verts) followed by
    12 pipe stores -- per vertex a S16 x, a S16 y and an RGBA8 colour, which
    is exactly the layout GXSetVtxAttrFmt(0, POS, XY, S16, 0) +
    GXSetVtxAttrFmt(0, CLR0, RGBA, RGBA8, 0) declared two lines earlier."""
    out = lower_source("rom", "rom.c", ZZ_0027C34_VERBATIM)
    assert out.problems == []
    assert [(s.width) for s in out.stores] == [2, 2, 4] * 4
    calls = re.findall(r"GF_WGPIPE_W(\d+)\(\((.*?)\)\);", out.text)
    assert calls == [
        ("16", "0"), ("16", "0"), ("32", "uVar1"),
        ("16", "0x280"), ("16", "0"), ("32", "uVar1"),
        ("16", "0x280"), ("16", "0x1c0"), ("32", "uVar1"),
        ("16", "0"), ("16", "0x1c0"), ("32", "uVar1"),
    ]
    # Everything that is NOT a pipe store is byte-identical.
    assert "gnt4_GXBegin_bl(0x80,0,4);" in out.text
    assert "uVar1 = *DAT_8043610c;" in out.text


# ------------------------------------------------------------- gate wiring


def _write_gate_unit(directory: Path, name: str, source_body: str, exports: list[str],
                     shim: str | None = None):
    from src.port_assembly_gate import UnitArtifact, unit_artifact_sha256

    directory.mkdir(parents=True, exist_ok=True)
    (directory / "gnt4_shim.h").write_text(
        shim or "#ifndef GNT4_SHIM_H\n#define GNT4_SHIM_H\n#endif\n",
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


def _pipe_units(root: Path):
    a = _write_gate_unit(
        root / "unit-a",
        "unit-a",
        "// ==== 80003100  gf_pipe_a ====\n"
        "void gf_pipe_a(unsigned int v)\n{\n"
        "  DAT_cc008000._0_2_ = 0x280;\n"
        "  DAT_cc008000 = v;\n}\n",
        ["gf_pipe_a"],
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

    units = _pipe_units(tmp_path / "staging")
    workdir = tmp_path / "assembly"
    captured: dict[str, Any] = {}
    result = run_assembly_gate(units, workdir, _capture_runner(captured))
    assert result["passed"] is True
    assert not (workdir / HEADER_FILENAME).exists()
    assert "wgpipe" not in result
    for name in WGPIPE_IMPORTS:
        assert name not in captured["allowed_extra"]
    # The written source is the verbatim unit.c, pipe store and all.
    assert "DAT_cc008000 = v;" in (workdir / "unit-a.c").read_text(encoding="utf-8")


def test_gate_on_lowers_the_sources_declares_the_imports_and_ledgers_it(tmp_path: Path):
    from src.port_assembly_gate import run_assembly_gate

    units = _pipe_units(tmp_path / "staging")
    workdir = tmp_path / "assembly"
    captured: dict[str, Any] = {}
    result = run_assembly_gate(
        units, workdir, _capture_runner(captured), wgpipe_lowering=True
    )
    assert result["passed"] is True, result
    assert (workdir / HEADER_FILENAME).read_text(encoding="utf-8") == HEADER_TEXT
    lowered = (workdir / "unit-a.c").read_text(encoding="utf-8")
    assert lowered.startswith(f'#include "{HEADER_FILENAME}"\n')
    assert "DAT_cc008000" not in lowered
    assert "GF_WGPIPE_W16((0x280));" in lowered and "GF_WGPIPE_W32((v));" in lowered
    # The unit with no pipe traffic is untouched.
    assert (workdir / "unit-b.c").read_text(encoding="utf-8").startswith("#include \"gnt4_shim.h\"")
    for name in WGPIPE_IMPORTS:
        assert name in captured["allowed_extra"]
    assert result["wgpipe"]["stores"] == 2
    assert result["wgpipe"]["units"][0]["unit"] == "unit-a"
    # The VERBATIM artifact was never edited -- only the derived copy.
    assert "DAT_cc008000 = v;" in (units[0].directory / "unit.c").read_text(encoding="utf-8")


def test_gate_on_with_no_pipe_traffic_writes_nothing(tmp_path: Path):
    """An ON-flagged window whose units never touch the pipe must link
    exactly like an OFF one -- no header, no include, no ledger entry."""
    from src.port_assembly_gate import run_assembly_gate

    units = [
        _write_gate_unit(tmp_path / "staging/u1", "u1", "int a(int x){return x;}\n", ["a"]),
        _write_gate_unit(tmp_path / "staging/u2", "u2", "int b(int x){return x;}\n", ["b"]),
    ]
    workdir = tmp_path / "assembly"
    captured: dict[str, Any] = {}
    result = run_assembly_gate(
        units, workdir, _capture_runner(captured), wgpipe_lowering=True
    )
    assert result["passed"] is True
    assert not (workdir / HEADER_FILENAME).exists()
    assert "wgpipe" not in result
    assert (workdir / "u1.c").read_text(encoding="utf-8").startswith('#include "gnt4_shim.h"')


def test_gate_refuses_loudly_when_a_pipe_reference_cannot_be_lowered(tmp_path: Path):
    from src.port_assembly_gate import CLASS_WGPIPE_LOWERING_FAILED, run_assembly_gate

    units = _pipe_units(tmp_path / "staging")
    units.append(
        _write_gate_unit(
            tmp_path / "staging/unit-c",
            "unit-c",
            "unsigned int gf_read_pipe(void)\n{\n  return DAT_cc008000;\n}\n",
            ["gf_read_pipe"],
        )
    )
    workdir = tmp_path / "assembly"
    captured: dict[str, Any] = {}
    result = run_assembly_gate(
        units, workdir, _capture_runner(captured), wgpipe_lowering=True
    )
    assert result["passed"] is False
    assert result["stage"] == "wgpipe-lowering"
    assert captured == {}, "the link must not be attempted after a refusal"
    classes = {c["class"] for c in result["conflicts"]}
    assert classes == {CLASS_WGPIPE_LOWERING_FAILED}
    assert "wgpipe_unlowerable_site" in result["conflicts"][0]["detail"]
    assert "out-of-bounds trap" in result["detail"]


def test_gate_on_composes_with_the_dispatch_companion(tmp_path: Path):
    """Both derived artifacts in one window. The lowering runs first, so the
    companion derives its signatures from the FINAL source text."""
    from src.port_assembly_gate import run_assembly_gate
    from src.port_dispatch_companion import COMPANION_FILENAME, MISS_IMPORT

    units = _pipe_units(tmp_path / "staging")
    workdir = tmp_path / "assembly"
    captured: dict[str, Any] = {}
    result = run_assembly_gate(
        units,
        workdir,
        _capture_runner(captured),
        dispatch_companion=True,
        wgpipe_lowering=True,
    )
    assert result["passed"] is True, result
    assert captured["c_files"][-1] == COMPANION_FILENAME
    assert MISS_IMPORT in captured["allowed_extra"]
    assert set(WGPIPE_IMPORTS) <= set(captured["allowed_extra"])
    assert result["wgpipe"]["stores"] == 2
    assert result["dispatch"]["functions"] == 2


def test_a_link_diagnostic_naming_the_header_is_attributed_to_the_lowering(tmp_path: Path):
    from src.port_assembly_gate import CLASS_WGPIPE_LOWERING_FAILED, run_assembly_gate

    units = _pipe_units(tmp_path / "staging")
    workdir = tmp_path / "assembly"
    result = run_assembly_gate(
        units,
        workdir,
        _capture_runner({}, ok=False, error="gf_gx_wgpipe.h:120:16: error: static assertion failed"),
        wgpipe_lowering=True,
    )
    assert result["passed"] is False
    assert result["conflicts"][0]["class"] == CLASS_WGPIPE_LOWERING_FAILED
    assert "static assertion failed" in result["conflicts"][0]["detail"]


def test_the_driver_reads_the_opt_in_from_the_environment():
    source = (REPO_ROOT / "src/port_wasm_units.py").read_text(encoding="utf-8")
    assert 'os.getenv("OGHIDRA_PORT_WGPIPE_LOWERING", "") == "1"' in source
    assert "wgpipe_lowering=(" in source


# ------------------------------------------------------------- real pilots

EXPORT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
BUILD_TIMEOUT_SECONDS = 900


def _real_link_runner():
    """The production link flags, plus the production disallowed-import scan.

    Keeping the scan means the pilots also prove the allowed_extra plumbing:
    without it the four FIFO imports would be rejected as unknown externals.
    """
    from src.port_assembly_gate import ASSEMBLY_WASM
    from src.port_wasm_units import (
        NO_WINDOW,
        build_environment,
        resolve_bash,
        scan_disallowed_imports,
        to_posix_path,
    )

    emsdk = PRODUCT_ROOT / "research/tools/emsdk"

    def link_runner(workdir: Path, c_files, exports, allowed_extra):
        valid = [name for name in exports if EXPORT_NAME.fullmatch(name)]
        exports_flag = ",".join("_" + name for name in valid)
        sources = " ".join(shlex.quote(name) for name in c_files)
        script = (
            f'source "{to_posix_path(emsdk)}/emsdk_env.sh" >/dev/null || '
            "{ echo 'emsdk_env.sh failed to load' >&2; exit 127; }; "
            f'cd "{to_posix_path(workdir)}" && '
            f"emcc {sources} -O1 -fno-strict-aliasing --no-entry "
            "-Wno-implicit-function-declaration -Wno-int-conversion "
            "-Wno-deprecated-non-prototype "
            "-Wno-incompatible-pointer-types -Wno-pointer-sign "
            "-ferror-limit=0 "
            "-sERROR_ON_UNDEFINED_SYMBOLS=0 -sINITIAL_MEMORY=2155479040 "
            "-sALLOW_MEMORY_GROWTH=0 "
            f"-sEXPORTED_FUNCTIONS={shlex.quote(exports_flag)} "
            f"-o {ASSEMBLY_WASM}"
        )
        completed = subprocess.run(
            [resolve_bash(), "-lc", script],
            capture_output=True,
            text=True,
            timeout=BUILD_TIMEOUT_SECONDS,
            env=build_environment(),
            creationflags=NO_WINDOW,
        )
        if completed.returncode != 0:
            return False, (completed.stderr + completed.stdout)[-8000:]
        bad = [
            name
            for name in scan_disallowed_imports(workdir / ASSEMBLY_WASM)
            if name not in set(allowed_extra)
        ]
        if bad:
            return False, "link gate: disallowed imports: " + ", ".join(bad)
        return True, ""

    return link_runner


# The pilot driver. Records every write-gather import call in order, with the
# value AND the big-endian bytes the host's FIFO decoder would serialize --
# packages/rom-runtime/src/gx/fifo.ts writeU16 emits (v>>8, v) and writeF32
# uses setFloat32(..., /*littleEndian=*/false). Reproducing that here is what
# turns "the import was called" into "the right bytes reach the decoder".
PILOT_DRIVER_JS = r"""
const fs = require('fs');
const bytes = fs.readFileSync(process.argv[2]);
const mod = new WebAssembly.Module(bytes);
const calls = [];
const stream = [];
const be = (v, n) => {
  const out = [];
  for (let i = n - 1; i >= 0; i--) out.push((v >>> (8 * i)) & 0xff);
  return out;
};
const record = (name, value, byteList) => {
  calls.push({ name, value });
  for (const b of byteList) stream.push(b);
};
const wg = {
  __gf_gx_wgpipe_u8: (v) => record('u8', v >>> 0 & 0xff, be(v >>> 0, 1)),
  __gf_gx_wgpipe_u16: (v) => record('u16', v >>> 0 & 0xffff, be(v >>> 0, 2)),
  __gf_gx_wgpipe_u32: (v) => record('u32', v >>> 0, be(v >>> 0, 4)),
  __gf_gx_wgpipe_f32: (v) => {
    const dv = new DataView(new ArrayBuffer(4));
    dv.setFloat32(0, v, false);
    record('f32', v, [dv.getUint8(0), dv.getUint8(1), dv.getUint8(2), dv.getUint8(3)]);
  },
};
const gxCalls = [];
const imports = {};
for (const imp of WebAssembly.Module.imports(mod)) {
  imports[imp.module] = imports[imp.module] || {};
  if (imp.kind === 'function' && wg[imp.name]) imports[imp.module][imp.name] = wg[imp.name];
  else if (imp.kind === 'function')
    imports[imp.module][imp.name] = (...args) => {
      gxCalls.push({ name: imp.name, args: args.map((a) => (typeof a === 'number' ? a : String(a))) });
      return 0;
    };
  else if (imp.kind === 'memory')
    imports[imp.module][imp.name] = new WebAssembly.Memory({ initial: 1 });
  else if (imp.kind === 'global') imports[imp.module][imp.name] = 0;
  else if (imp.kind === 'table')
    imports[imp.module][imp.name] = new WebAssembly.Table({ element: 'anyfunc', initial: 1 });
}
const instance = new WebAssembly.Instance(mod, imports);
const mem = instance.exports.memory;
const view = new DataView(mem.buffer);
const plan = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
for (const [addr, value] of plan.pokeU32 || []) view.setUint32(addr, value >>> 0, true);
for (const call of plan.call) instance.exports[call.name](...(call.args || []));
console.log('PILOT_RESULT ' + JSON.stringify({
  calls,
  streamHex: stream.map((b) => b.toString(16).padStart(2, '0')).join(''),
  gxCalls,
}));
"""


def _run_pilot(workdir: Path, plan: dict[str, Any]) -> dict[str, Any]:
    from src.port_assembly_gate import ASSEMBLY_WASM
    from src.port_wasm_units import NO_WINDOW, resolve_node_exe

    driver = workdir / "wgpipe-pilot.cjs"
    driver.write_text(PILOT_DRIVER_JS, encoding="utf-8", newline="\n")
    plan_path = workdir / "wgpipe-pilot-plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8", newline="\n")
    completed = None
    for _ in range(4):
        completed = subprocess.run(
            [resolve_node_exe(), str(driver), str(workdir / ASSEMBLY_WASM), str(plan_path)],
            capture_output=True,
            text=True,
            timeout=300,
            creationflags=NO_WINDOW,
        )
        if completed.returncode == 0:
            break
        if "Cannot allocate Wasm memory" not in (completed.stderr + completed.stdout):
            break
        time.sleep(3)
    assert completed is not None
    if completed.returncode != 0 and "Cannot allocate Wasm memory" in (
        completed.stderr + completed.stdout
    ):
        pytest.skip(
            "host cannot commit the production 2GB wasm arena right now "
            "(transient memory pressure); pilot not attempted under reduced flags"
        )
    assert completed.returncode == 0, completed.stderr + completed.stdout
    match = re.search(r"PILOT_RESULT (\{.*\})", completed.stdout)
    assert match, completed.stdout
    return json.loads(match.group(1))


# Every store shape, at every width, with the float/integer distinction the
# `_Generic` routing exists for: `f` and `g` hold the SAME 32-bit value in
# different types, so a lowering that routed floats through the integer
# import (or vice versa) would put different bytes on the wire.
PILOT_SHAPES_C = """// ==== 80003100  gf_wg_shapes ====

void gf_wg_shapes(unsigned int v, float f)
{
  DAT_cc008000._0_1_ = 0x10;
  DAT_cc008000._0_2_ = 0x280;
  DAT_cc008000 = v;
  DAT_cc008000 = f;
  DAT_cc008000 = (float)1.0;
  DAT_cc008004 = 0x11223344;
  DAT_cc008000._0_1_ = (unsigned char)(v >> 8);
  DAT_cc008000._0_2_ = (unsigned short)(v & 0xffff);
  return;
}
"""


@requires_toolchain
def test_pilot_every_store_shape_reaches_its_import_with_the_right_bytes(tmp_path: Path):
    from src.port_assembly_gate import ASSEMBLY_WASM, run_assembly_gate

    units = [
        _write_gate_unit(tmp_path / "staging/unit-a", "unit-a", PILOT_SHAPES_C, ["gf_wg_shapes"]),
        _write_gate_unit(
            tmp_path / "staging/unit-b", "unit-b",
            "// ==== 80004200  gf_plain_b ====\nint gf_plain_b(int x){ return x + 1; }\n",
            ["gf_plain_b"],
        ),
    ]
    workdir = tmp_path / "assembly"
    result = run_assembly_gate(units, workdir, _real_link_runner(), wgpipe_lowering=True)
    assert result["passed"] is True, result
    assert (workdir / ASSEMBLY_WASM).is_file()
    assert result["wgpipe"]["by_width"] == {"u16": 2, "u32": 4, "u8": 2}

    out = _run_pilot(workdir, {"call": [{"name": "gf_wg_shapes", "args": [0xAABBCCDD, 2.5]}]})
    assert [c["name"] for c in out["calls"]] == [
        "u8", "u16", "u32", "f32", "f32", "u32", "u8", "u16",
    ]
    assert out["calls"][0]["value"] == 0x10
    assert out["calls"][1]["value"] == 0x280
    assert out["calls"][2]["value"] == 0xAABBCCDD
    # THE POINT OF THE _Generic ROUTING: a float store carries the float, not
    # its integer truncation. 2.5 through the integer import would be 2.
    assert out["calls"][3] == {"name": "f32", "value": 2.5}
    assert out["calls"][4] == {"name": "f32", "value": 1.0}
    assert out["calls"][5]["value"] == 0x11223344
    assert out["calls"][6]["value"] == 0xCC
    assert out["calls"][7]["value"] == 0xCCDD

    # The exact big-endian byte stream the host's FIFO decoder consumes.
    assert out["streamHex"] == (
        "10"          # u8  0x10
        + "0280"      # u16 0x280
        + "aabbccdd"  # u32
        + "40200000"  # f32 2.5
        + "3f800000"  # f32 1.0
        + "11223344"  # u32 through the second pipe word
        + "cc"        # u8
        + "ccdd"      # u16
    )


# A gnt4_shim.h in the shape the pipeline's own seed uses (GC_* macros that
# dereference original GameCube addresses -- see
# research/decomp/generated/finish-game-port/gnt4_shim_seed.h), so the ROM
# function below compiles VERBATIM, with its globals resolved out of the
# shared arena exactly as a real unit's would be.
ROM_PILOT_SHIM = """#ifndef GNT4_SHIM_H
#define GNT4_SHIM_H
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined4;
#define GC_IPTR(a) (*(int *)(unsigned int)(a))
#define GC_U32P(a) (*(unsigned int **)(unsigned int)(a))
#define PTR_DAT_80433930 GC_IPTR(0x80433930)
#define DAT_80436108     GC_IPTR(0x80436108)
#define DAT_8043610c     GC_U32P(0x8043610c)
#define DAT_803c0f40     (*(undefined4 *)(unsigned int)0x803c0f40u)
#endif
"""

ROM_PILOT_STRUCT = 0x80500000
ROM_PILOT_COLOUR_SLOT = 0x80510000
ROM_PILOT_RGBA = 0x8090A0B0


@requires_toolchain
def test_pilot_the_roms_own_draw_function_submits_a_real_quad(tmp_path: Path):
    """END TO END on REAL ROM CODE. `zz_0027c34_` verbatim out of the export,
    through the real gate with lowering on, linked by the pinned emsdk, run
    under node. What comes out is the write-gather byte stream that
    packages/rom-runtime/src/gx/fifo.ts assembles into a GX_QUADS primitive:
    four vertices of S16 x, S16 y, RGBA8 colour."""
    from src.port_assembly_gate import ASSEMBLY_WASM, run_assembly_gate

    units = [
        _write_gate_unit(
            tmp_path / "staging/rom", "rom", ZZ_0027C34_VERBATIM, ["zz_0027c34_"],
            shim=ROM_PILOT_SHIM,
        ),
        _write_gate_unit(
            tmp_path / "staging/unit-b", "unit-b",
            "// ==== 80004200  gf_plain_b ====\nint gf_plain_b(int x){ return x + 1; }\n",
            ["gf_plain_b"], shim=ROM_PILOT_SHIM,
        ),
    ]
    workdir = tmp_path / "assembly"
    result = run_assembly_gate(units, workdir, _real_link_runner(), wgpipe_lowering=True)
    assert result["passed"] is True, result
    assert result["wgpipe"]["stores"] == 12
    assert result["wgpipe"]["by_width"] == {"u16": 8, "u32": 4}

    out = _run_pilot(
        workdir,
        {
            # The arena state the function's own guard reads: the struct
            # pointer, its [0x38] == 0, the enable flag, and the colour the
            # ROM pushes into every vertex.
            "pokeU32": [
                [0x80433930, ROM_PILOT_STRUCT],
                [ROM_PILOT_STRUCT + 0x38, 0],
                [0x80436108, 1],
                [0x8043610C, ROM_PILOT_COLOUR_SLOT],
                [ROM_PILOT_COLOUR_SLOT, ROM_PILOT_RGBA],
            ],
            "call": [{"name": "zz_0027c34_"}],
        },
    )

    # The ROM's own GX setup crossed the seam first, GXBegin last.
    gx_names = [c["name"] for c in out["gxCalls"]]
    assert gx_names[0] == "gnt4_GXSetCullMode_bl"
    assert gx_names[-1] == "gnt4_GXBegin_bl"
    begin = out["gxCalls"][-1]["args"]
    assert begin == [0x80, 0, 4], begin  # GX_QUADS, vtxfmt 0, four vertices

    # Then twelve pipe stores: (x:u16, y:u16, rgba:u32) per vertex.
    assert [c["name"] for c in out["calls"]] == ["u16", "u16", "u32"] * 4
    assert [c["value"] for c in out["calls"]] == [
        0x000, 0x000, ROM_PILOT_RGBA,
        0x280, 0x000, ROM_PILOT_RGBA,
        0x280, 0x1C0, ROM_PILOT_RGBA,
        0x000, 0x1C0, ROM_PILOT_RGBA,
    ]
    # The byte stream, big-endian console order, 32 bytes = 4 vertices x 8.
    rgba = f"{ROM_PILOT_RGBA:08x}"
    assert out["streamHex"] == (
        "0000" "0000" + rgba
        + "0280" "0000" + rgba
        + "0280" "01c0" + rgba
        + "0000" "01c0" + rgba
    )
    assert len(out["streamHex"]) // 2 == 32


def test_without_lowering_the_derived_source_keeps_the_trapping_store(tmp_path: Path):
    """The counterfactual. With the flag off the gate copies the ROM's store
    through verbatim, and 0xCC008000 is past the end of the linked module's
    memory (-sINITIAL_MEMORY=2155479040 == 0x807A0000), so the store is an
    out-of-bounds access. That is the blocker the lowering removes; nothing
    downstream of it can work while the store survives."""
    from src.port_assembly_gate import run_assembly_gate

    units = [
        _write_gate_unit(
            tmp_path / "staging/rom", "rom", ZZ_0027C34_VERBATIM, ["zz_0027c34_"],
            shim=ROM_PILOT_SHIM,
        ),
        _write_gate_unit(
            tmp_path / "staging/unit-b", "unit-b",
            "int gf_plain_b(int x){ return x + 1; }\n", ["gf_plain_b"],
            shim=ROM_PILOT_SHIM,
        ),
    ]
    workdir = tmp_path / "assembly"
    result = run_assembly_gate(units, workdir, _capture_runner({}))
    assert result["passed"] is True, result
    assert "wgpipe" not in result
    written = (workdir / "rom.c").read_text(encoding="utf-8")
    assert written.count("DAT_cc008000") == 12
    assert "GF_WGPIPE" not in written
    assert 0xCC008000 > 2155479040  # 0x807A0000, the composed module's memory


@requires_toolchain
def test_pilot_the_lowered_rom_unit_reaches_the_hosts_real_fifo_decoder(tmp_path: Path):
    """THE BLOCKER, closed end to end.

    The same gate-produced module as the pilot above, but this time its
    `__gf_gx_wgpipe_*` imports are wired to the browser HLE host's OWN decode
    side -- packages/rom-runtime/src/gx/{state,fifo,backend}.ts, imported by
    tools/gx_wgpipe_e2e_proof.mjs rather than reimplemented -- and the ROM's
    verbatim draw function is executed against it. What comes back is a
    GX_QUADS primitive with the four vertices the ROM wrote.

    Seam only. No frame produced by this path has ever been compared against a
    real GameCube frame; docs/gx-hle-host.md section 1 is unchanged.
    """
    from src.port_assembly_gate import ASSEMBLY_WASM, run_assembly_gate
    from src.port_wasm_units import NO_WINDOW, resolve_node_exe

    proof = REPO_ROOT / "tools/gx_wgpipe_e2e_proof.mjs"
    assert proof.is_file()
    if not (PRODUCT_ROOT / "packages/rom-runtime/src/gx/fifo.ts").is_file():
        pytest.skip("browser HLE host not present in this checkout")

    units = [
        _write_gate_unit(
            tmp_path / "staging/rom", "rom", ZZ_0027C34_VERBATIM, ["zz_0027c34_"],
            shim=ROM_PILOT_SHIM,
        ),
        _write_gate_unit(
            tmp_path / "staging/unit-b", "unit-b",
            "int gf_plain_b(int x){ return x + 1; }\n", ["gf_plain_b"],
            shim=ROM_PILOT_SHIM,
        ),
    ]
    workdir = tmp_path / "assembly"
    result = run_assembly_gate(units, workdir, _real_link_runner(), wgpipe_lowering=True)
    assert result["passed"] is True, result

    completed = subprocess.run(
        [resolve_node_exe(), str(proof), str(workdir / ASSEMBLY_WASM)],
        capture_output=True, text=True, timeout=600, creationflags=NO_WINDOW,
    )
    if completed.returncode == 3:
        pytest.skip(completed.stdout.strip() or "proof prerequisites missing")
    assert completed.returncode == 0, completed.stdout + completed.stderr
    match = re.search(r"GX_WGPIPE_E2E (\{.*\})", completed.stdout)
    assert match, completed.stdout
    out = json.loads(match.group(1))
    assert out["failed"] == 0, completed.stdout
    assert out["primitives"] == 1
    assert out["droppedFifoBytes"] == 0
    # The honesty gate: this proves the seam, never the frame.
    assert out["verified"] is False
