"""G2/H3 dispatch companion: derivation, frame ABI, gate wiring, pilots.

Design contract (docs/playable-port-design.md V3 G2 + V4 H3, upheld by V5):
link-time adapter thunks with one canonical signature, an address-keyed table,
and a defined miss-handler import. The pilot gate at the bottom exercises the
three cases H3 names: a matched-class dispatch, a deliberately CROSS-CLASS
dispatch, and a TABLE MISS serviced by the declared import with the address
ledgered -- all through the real emcc/node toolchain.
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

from src.port_dispatch_companion import (
    ARITY_EXPORT,
    COMPANION_FILENAME,
    DISPATCH_EXPORT,
    FRAME_ABI_VERSION,
    FRAME_ARGS_OFFSET,
    FRAME_HEADER_FILENAME,
    FRAME_HEADER_TEXT,
    FRAME_MAX_ARGS,
    FRAME_RET_OFFSET,
    FRAME_SIZE,
    FRAME_SLOT_SIZE,
    MISS_IMPORT,
    companion_evidence,
    derive_window_signatures,
    emit_companion_source,
    find_definition_head,
    marker_addresses,
    resolve_gc_address,
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


# ------------------------------------------------------- address derivation


def test_symbol_name_encoding_matches_the_registry_derivation():
    from src.port_assembly_abi import symbol_gc_address

    assert symbol_gc_address("zz_0006fb4_") == "80006fb4"
    assert symbol_gc_address("zz_00527d8_") == "800527d8"
    assert symbol_gc_address("FUN_80231370") == "80231370"
    assert symbol_gc_address("__check_pad3") is None
    assert symbol_gc_address("zz_06fb4_") is None  # wrong digit count
    assert symbol_gc_address("FUN_8023137") is None


def test_marker_addresses_parse_and_contradict():
    text = (
        "// ==== 80003100  __check_pad3 ====\n"
        "// ==== 80003140  __set_debug_bba ====\n"
        "// ==== 80003100  __check_pad3 ====\n"  # duplicate, identical: fine
    )
    addresses, contradictions = marker_addresses(text)
    assert addresses == {"__check_pad3": "80003100", "__set_debug_bba": "80003140"}
    assert contradictions == []
    _, contradictions = marker_addresses(
        "// ==== 80003100  f ====\n// ==== 80003104  f ====\n"
    )
    assert len(contradictions) == 1 and "80003104" in contradictions[0]


def test_resolve_gc_address_authority_order():
    # Marker beats name encoding only when they AGREE; disagreement refuses.
    address, source, detail = resolve_gc_address("zz_0003100_", {"zz_0003100_": "80003100"}, {})
    assert (address, source, detail) == ("80003100", "marker", None)
    address, source, detail = resolve_gc_address("zz_0003100_", {}, {})
    assert (address, source, detail) == ("80003100", "symbol_name", None)
    address, source, detail = resolve_gc_address("renamed", {}, {"renamed": "80004200"})
    assert (address, source, detail) == ("80004200", "owner_registry", None)
    address, source, detail = resolve_gc_address(
        "zz_0003100_", {"zz_0003100_": "80009999"}, {}
    )
    assert address is None and source == "contradiction" and "80009999" in detail
    address, source, detail = resolve_gc_address("renamed", {}, {})
    assert address is None and "no GC address derivable" in detail
    address, source, detail = resolve_gc_address("renamed", {}, {"renamed": "0x80004200"})
    assert address is None and "not 8 hex digits" in detail


def test_owner_registry_disagreement_is_a_contradiction():
    """Review F2: the owner registry is an INDEPENDENT address authority.

    A stale re-extraction can yield a marker and a name encoding that agree
    with each other but are both wrong; the registry is the only evidence
    that can catch the consistent-but-wrong pair. Agreement passes,
    disagreement refuses -- never a silent pick of either side.
    """
    # Agreeing registry passes, marker authority first.
    address, source, detail = resolve_gc_address(
        "zz_0003100_", {"zz_0003100_": "80003100"}, {"zz_0003100_": "80003100"}
    )
    assert (address, source, detail) == ("80003100", "marker", None)
    # Agreeing registry passes against the name encoding too.
    address, source, detail = resolve_gc_address(
        "zz_0003100_", {}, {"zz_0003100_": "80003100"}
    )
    assert (address, source, detail) == ("80003100", "symbol_name", None)
    # Marker vs registry disagreement refuses (the empirical F2 shape:
    # marker 80003100, registry 80999999 -- previously resolved silently).
    address, source, detail = resolve_gc_address(
        "gf_marked", {"gf_marked": "80003100"}, {"gf_marked": "80999999"}
    )
    assert address is None and source == "contradiction"
    assert "80003100" in detail and "80999999" in detail
    # Name-encoding vs registry disagreement refuses in the other direction.
    address, source, detail = resolve_gc_address(
        "zz_0003100_", {}, {"zz_0003100_": "80999999"}
    )
    assert address is None and source == "contradiction"
    assert "owner registry" in detail


def test_derivation_refuses_when_the_registry_contradicts_the_marker():
    derived = derive_window_signatures(
        [
            (
                "unit-a",
                "// ==== 80003100  f ====\nint f(void)\n{\n  return 0;\n}\n",
                ["f"],
            )
        ],
        {"f": "80999999"},
    )
    assert [p.code for p in derived.problems] == ["address_underivable"]
    assert "owner registry" in derived.problems[0].detail
    # The identical window with an AGREEING registry derives cleanly.
    derived = derive_window_signatures(
        [
            (
                "unit-a",
                "// ==== 80003100  f ====\nint f(void)\n{\n  return 0;\n}\n",
                ["f"],
            )
        ],
        {"f": "80003100"},
    )
    assert derived.problems == []
    assert derived.signatures[0].gc_address == "80003100"
    assert derived.signatures[0].address_source == "marker"


# ------------------------------------------------------- definition parsing


def test_find_definition_head_handles_ghidra_shapes():
    source = (
        '#include "gnt4_shim.h"\n'
        "\n"
        "/* prelude declarations never match */\n"
        "uint __check_pad3(undefined8 param_1,undefined8 param_2);\n"
        "void helper(int x);\n"
        "\n"
        "// ==== 80003100  __check_pad3 ====\n"
        "\n"
        "uint __check_pad3(undefined8 param_1,\n"
        "                 undefined8 param_2)\n"
        "\n"
        "{\n"
        "  helper((int)param_1);\n"
        "  return (uint)param_2;\n"
        "}\n"
    )
    head = find_definition_head(source, "__check_pad3")
    assert head is not None
    return_spelling, params = head
    assert return_spelling == "uint"
    assert params == ["undefined8 param_1", "undefined8 param_2"]
    # A symbol that is only CALLED (inside a body) is not a definition here.
    assert find_definition_head(source, "helper") is None


def test_find_definition_head_unprototyped_pointer_and_void():
    source = (
        "int FUN_80231370()\n{\n  return 0;\n}\n"
        "undefined8 * zz_0004200_(float *out, int table[4])\n{\n  return 0;\n}\n"
        "void zz_0004300_(void)\n{\n}\n"
    )
    assert find_definition_head(source, "FUN_80231370") == ("int", [])
    return_spelling, params = find_definition_head(source, "zz_0004200_")
    assert return_spelling == "undefined8 *"
    assert params == ["float *out", "int table[4]"]
    assert find_definition_head(source, "zz_0004300_") == ("void", ["void"])


def test_find_definition_head_is_not_polluted_by_adjacent_directives():
    # No prelude declarations: the first definition sits directly under the
    # include/defines, so the return-spelling backscan has no ';' boundary
    # and must not swallow directive text.
    source = (
        '#include "gnt4_shim.h"\n'
        "#define GC_U8(a) (*(unsigned char *)(a))\n"
        "\n"
        "// ==== 80003100  gf_add ====\n"
        "int gf_add(int a, int b)\n"
        "{\n  return a + b;\n}\n"
    )
    assert find_definition_head(source, "gf_add") == ("int", ["int a", "int b"])


def _one_unit(source: str, exports: list[str]):
    return derive_window_signatures([("unit-x", source, exports)])


def test_derive_signatures_classifies_scalars_pointers_and_names():
    source = (
        "// ==== 80003154  start ====\n"
        "void start(undefined8 param_1,double param_2,float param_3,\n"
        "           unsigned int param_4,long long param_5,char *name)\n"
        "{\n}\n"
    )
    derived = _one_unit(source, ["start"])
    assert derived.problems == []
    (signature,) = derived.signatures
    assert signature.gc_address == "80003154"
    assert signature.address_source == "marker"
    assert signature.return_class == "void"
    assert signature.param_classes == ("i64", "f64", "f32", "i32", "i64", "i32")


def test_derive_signatures_fails_closed():
    # Missing definition.
    derived = _one_unit("int zz_0003100_(void);\n", ["zz_0003100_"])
    assert [p.code for p in derived.problems] == ["missing_definition"]
    # Variadic.
    derived = _one_unit(
        "int zz_0003100_(int a, ...)\n{\n  return a;\n}\n", ["zz_0003100_"]
    )
    assert [p.code for p in derived.problems] == ["variadic_definition"]
    # Unknown parameter class (struct by value would change the wasm signature).
    derived = _one_unit(
        "int zz_0003100_(struct vec3 v)\n{\n  return 0;\n}\n", ["zz_0003100_"]
    )
    assert [p.code for p in derived.problems] == ["unknown_param_class"]
    # Renamed symbol with no marker and no owner record.
    derived = _one_unit("int renamed(void)\n{\n  return 0;\n}\n", ["renamed"])
    assert [p.code for p in derived.problems] == ["address_underivable"]
    # Two symbols claiming one address.
    derived = derive_window_signatures(
        [
            ("unit-a", "// ==== 80003100  f ====\nint f(void)\n{\n return 0;\n}\n", ["f"]),
            ("unit-b", "// ==== 80003100  g ====\nint g(void)\n{\n return 0;\n}\n", ["g"]),
        ]
    )
    assert [p.code for p in derived.problems] == ["address_collision"]
    # Arity beyond the frame.
    params = ", ".join(f"int p{i}" for i in range(FRAME_MAX_ARGS + 1))
    derived = _one_unit(
        f"int zz_0003100_({params})\n{{\n  return 0;\n}}\n", ["zz_0003100_"]
    )
    assert [p.code for p in derived.problems] == ["arity_over_frame"]


def test_owner_registry_address_is_the_fallback_for_renamed_symbols():
    derived = derive_window_signatures(
        [("unit-a", "int renamed(void)\n{\n  return 0;\n}\n", ["renamed"])],
        {"renamed": "80004200"},
    )
    assert derived.problems == []
    assert derived.signatures[0].gc_address == "80004200"
    assert derived.signatures[0].address_source == "owner_registry"


def test_defined_but_unregistered_function_is_a_refusal():
    """Review F1: derivation iterated EXPORTS only, so a function defined in
    the unit but absent from provenance.exported_functions got no thunk and
    no problem record -- its GC address would route to the miss handler as a
    wrong-behavior bridge call, violating the module docstring. Every marker
    symbol with a real definition head must be registered."""
    source = (
        "// ==== 80003100  gf_add ====\n"
        "int gf_add(int a, int b)\n{\n  return a + b;\n}\n"
        "\n"
        "// ==== 80003140  gf_orphan ====\n"
        "int gf_orphan(void)\n{\n  return 7;\n}\n"
    )
    derived = _one_unit(source, ["gf_add"])
    assert [p.code for p in derived.problems] == ["defined_not_registered"]
    (problem,) = derived.problems
    assert problem.symbol == "gf_orphan"
    assert "80003140" in problem.detail and "miss handler" in problem.detail
    # Registering both definitions derives cleanly -- the refusal is about
    # the gap, not about multi-definition sources.
    derived = _one_unit(source, ["gf_add", "gf_orphan"])
    assert derived.problems == []
    assert [s.symbol for s in derived.signatures] == ["gf_add", "gf_orphan"]
    # A marker whose symbol has no definition head (declaration only) is not
    # a defined function and raises nothing.
    declared = (
        "// ==== 80003100  gf_add ====\n"
        "int gf_add(int a, int b)\n{\n  return a + b;\n}\n"
        "\n"
        "// ==== 80003140  gf_decl ====\n"
        "int gf_decl(void);\n"
    )
    derived = _one_unit(declared, ["gf_add"])
    assert derived.problems == []


# ------------------------------------------------------------- frame ABI


def test_frame_abi_constants_are_consistent_and_documented():
    assert FRAME_SIZE == FRAME_ARGS_OFFSET + FRAME_MAX_ARGS * FRAME_SLOT_SIZE
    assert FRAME_RET_OFFSET == 0x08 and FRAME_ARGS_OFFSET == 0x10
    # The header carries the SAME numbers, compiler-proved by _Static_assert.
    assert f"#define GF_DISPATCH_FRAME_VERSION {FRAME_ABI_VERSION}" in FRAME_HEADER_TEXT
    assert f"#define GF_DISPATCH_MAX_ARGS {FRAME_MAX_ARGS}" in FRAME_HEADER_TEXT
    assert f"sizeof(__gf_dispatch_frame) == 0x{FRAME_SIZE:x}" in FRAME_HEADER_TEXT
    for macro, code in (
        ("GF_DISPATCH_CLASS_VOID", 0),
        ("GF_DISPATCH_CLASS_I32", 1),
        ("GF_DISPATCH_CLASS_I64", 2),
        ("GF_DISPATCH_CLASS_F32", 3),
        ("GF_DISPATCH_CLASS_F64", 4),
    ):
        assert f"#define {macro} {code}" in FRAME_HEADER_TEXT
    # Review F4: the header states the i64 return asymmetry (the thunk's i32
    # result is the LOW word; PPC32 EABI r3 carries the HIGH word; consumers
    # read the 8-byte ret slot) and the caller-extends argument convention.
    assert "LOW 32 bits" in FRAME_HEADER_TEXT
    assert "HIGH word" in FRAME_HEADER_TEXT
    assert "8-byte ret slot" in FRAME_HEADER_TEXT
    assert "caller-extends" in FRAME_HEADER_TEXT


def test_companion_emission_is_deterministic_and_address_sorted():
    derived = derive_window_signatures(
        [
            (
                "unit-a",
                "// ==== 80004200  zz_0004200_ ====\n"
                "double zz_0004200_(double x)\n{\n  return x;\n}\n",
                ["zz_0004200_"],
            ),
            (
                "unit-b",
                "// ==== 80003100  gf_add ====\n"
                "int gf_add(int a, int b)\n{\n  return a + b;\n}\n",
                ["gf_add"],
            ),
        ]
    )
    assert derived.problems == []
    text = emit_companion_source(derived.signatures)
    assert text == emit_companion_source(list(reversed(derived.signatures)))
    # Table sorted ascending by GC address regardless of unit order.
    addresses = re.findall(r"0x([0-9a-f]{8})u,", text)
    assert addresses == sorted(addresses) == ["80003100", "80004200"]
    assert f"extern int {MISS_IMPORT}(unsigned int gc_addr, int argptr);" in text
    assert f"int {DISPATCH_EXPORT}(unsigned int gc_addr, int argptr)" in text
    assert "__gf_thunk_80003100" in text and "__gf_thunk_80004200" in text
    # Arity ledger: per-entry known arity, a mismatch counter the host reads
    # through the export, and dispatch that still proceeds on mismatch.
    assert "__gf_dispatch_arity[2]" in text
    assert "2u, /* gf_add */" in text and "1u, /* zz_0004200_ */" in text
    assert f"unsigned int {ARITY_EXPORT}(void)" in text
    assert "__gf_arity_mismatch_count += 1u;" in text
    assert text.index("__gf_arity_mismatch_count += 1u;") < text.index(
        "return __gf_dispatch_thunks[mid](argptr);"
    )
    evidence = companion_evidence(derived.signatures, text)
    assert evidence["functions"] == 2
    assert evidence["frame_abi_version"] == FRAME_ABI_VERSION
    assert [entry["gc_address"] for entry in evidence["table"]] == addresses


def test_empty_window_companion_routes_everything_to_the_miss_handler():
    text = emit_companion_source([])
    assert f"return {MISS_IMPORT}(gc_addr, argptr);" in text
    assert "__gf_dispatch_addrs" not in text
    # The arity-ledger export exists in the empty shape too, so the module
    # interface does not change with table population.
    assert f"unsigned int {ARITY_EXPORT}(void)" in text


# ------------------------------------------------------------ gate wiring


def _write_gate_unit(directory: Path, name: str, source_body: str,
                     exports: list[str]):
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


def _pilot_units(root: Path):
    unit_a = _write_gate_unit(
        root / "unit-a",
        "unit-a",
        "// ==== 80003100  gf_pilot_add ====\n"
        "int gf_pilot_add(int a, int b)\n"
        "{\n  return a + b;\n}\n",
        ["gf_pilot_add"],
    )
    unit_b = _write_gate_unit(
        root / "unit-b",
        "unit-b",
        "// ==== 80004200  zz_0004200_ ====\n"
        "double zz_0004200_(double x)\n"
        "{\n  return x * 2.0 + 0.5;\n}\n",
        ["zz_0004200_"],
    )
    return [unit_a, unit_b]


def _pilot_wide_unit(root: Path):
    """An i64-returning callee (review F4): hi and lo words differ, so a
    `return 0;` mutation -- or returning the PPC-r3-style HIGH word through
    the i32 view -- cannot pass the pilot's assertions."""
    return _write_gate_unit(
        root / "unit-w",
        "unit-w",
        "// ==== 80005300  gf_pilot_wide ====\n"
        "long long gf_pilot_wide(int x)\n"
        "{\n  return ((long long)(x + 1) << 32) | 0x55667788u;\n}\n",
        ["gf_pilot_wide"],
    )


def test_gate_emits_companion_exports_dispatch_and_allows_miss(tmp_path: Path):
    from src.port_assembly_gate import run_assembly_gate

    units = _pilot_units(tmp_path / "staging")
    workdir = tmp_path / "assembly"
    captured: dict[str, Any] = {}

    def link_runner(workdir_arg, c_files, exports, allowed_extra):
        captured.update(
            workdir=workdir_arg, c_files=list(c_files), exports=list(exports),
            allowed_extra=list(allowed_extra),
        )
        return True, ""

    result = run_assembly_gate(units, workdir, link_runner, dispatch_companion=True)
    assert result["passed"] is True, result
    assert captured["c_files"][-1] == COMPANION_FILENAME
    assert DISPATCH_EXPORT in captured["exports"]
    assert ARITY_EXPORT in captured["exports"]
    assert MISS_IMPORT in captured["allowed_extra"]
    assert (workdir / COMPANION_FILENAME).is_file()
    assert (workdir / FRAME_HEADER_FILENAME).read_text(encoding="utf-8") == FRAME_HEADER_TEXT
    evidence = result["dispatch"]
    assert evidence["functions"] == 2
    assert [entry["symbol"] for entry in evidence["table"]] == [
        "gf_pilot_add", "zz_0004200_",
    ]


def test_gate_default_leaves_the_existing_link_byte_identical(tmp_path: Path):
    from src.port_assembly_gate import run_assembly_gate

    units = _pilot_units(tmp_path / "staging")
    workdir = tmp_path / "assembly"
    captured: dict[str, Any] = {}

    def link_runner(workdir_arg, c_files, exports, allowed_extra):
        captured.update(c_files=list(c_files), exports=list(exports))
        return True, ""

    result = run_assembly_gate(units, workdir, link_runner)
    assert result["passed"] is True
    assert COMPANION_FILENAME not in captured["c_files"]
    assert DISPATCH_EXPORT not in captured["exports"]
    assert ARITY_EXPORT not in captured["exports"]
    assert not (workdir / COMPANION_FILENAME).exists()
    assert "dispatch" not in result


def test_gate_refuses_loudly_when_the_companion_cannot_be_derived(tmp_path: Path):
    from src.port_assembly_gate import (
        CLASS_DISPATCH_COMPANION_FAILED,
        run_assembly_gate,
    )

    units = _pilot_units(tmp_path / "staging")
    # A renamed export with no marker and no owner record: underivable.
    units.append(
        _write_gate_unit(
            tmp_path / "staging" / "unit-c",
            "unit-c",
            "int renamed_orphan(void)\n{\n  return 0;\n}\n",
            ["renamed_orphan"],
        )
    )
    calls: list[str] = []

    def link_runner(workdir_arg, c_files, exports, allowed_extra):
        calls.append("linked")
        return True, ""

    result = run_assembly_gate(
        units, tmp_path / "assembly", link_runner, dispatch_companion=True
    )
    assert result["passed"] is False
    assert result["stage"] == "dispatch-companion"
    assert calls == []  # refused BEFORE the link: never a silent skip
    (conflict,) = result["conflicts"]
    assert conflict["class"] == CLASS_DISPATCH_COMPANION_FAILED
    assert conflict["symbol"] == "renamed_orphan"
    assert "address_underivable" in conflict["detail"]


def test_gate_attributes_companion_link_failures_to_the_dispatch_class(tmp_path: Path):
    from src.port_assembly_gate import (
        CLASS_DISPATCH_COMPANION_FAILED,
        run_assembly_gate,
    )

    units = _pilot_units(tmp_path / "staging")

    def link_runner(workdir_arg, c_files, exports, allowed_extra):
        return False, "gf_dispatch_companion.c:12:3: error: synthetic failure"

    result = run_assembly_gate(
        units, tmp_path / "assembly", link_runner, dispatch_companion=True
    )
    assert result["passed"] is False
    assert result["stage"] == "link"
    assert result["conflicts"][0]["class"] == CLASS_DISPATCH_COMPANION_FAILED
    assert "gf_dispatch_companion.c" in result["conflicts"][0]["detail"]


# ------------------------------------------------------------ pilot gate
#
# Real-toolchain pilots (design V4 H3 gate): a 2-function window linked by the
# gate with the companion enabled, then driven under node. Proves:
#   (a) a matched-class call through __gf_dispatch reaches the callee and
#       returns correctly (frame ret slot + ret_class + i32 view);
#   (b) a deliberately CROSS-CLASS dispatch -- a zero-arg-style call site
#       (arg_count=0, no slots written) into a two-parameter callee -- still
#       lands correctly through the uniform frame (the PPC register-residue
#       shape signature classes would have TRAPPED on);
#   (c) an unregistered address routes to __gf_dispatch_miss with the address
#       ledgered, and the miss handler's result propagates -- a miss is a
#       bridge call, never a trap.

PILOT_FRAME_ADDRESS = 0x40000000

PILOT_DRIVER_JS = r"""
const fs = require('fs');
const bytes = fs.readFileSync(process.argv[2]);
const mod = new WebAssembly.Module(bytes);
const missLedger = [];
const imports = {};
for (const imp of WebAssembly.Module.imports(mod)) {
  imports[imp.module] = imports[imp.module] || {};
  if (imp.kind === 'function' && imp.name === '__gf_dispatch_miss') {
    imports[imp.module][imp.name] = (gcAddr, argptr) => {
      missLedger.push({ gc_addr: gcAddr >>> 0, argptr: argptr >>> 0 });
      return 0x5150;
    };
  } else if (imp.kind === 'function') imports[imp.module][imp.name] = () => 0;
  else if (imp.kind === 'memory')
    imports[imp.module][imp.name] = new WebAssembly.Memory({ initial: 1 });
  else if (imp.kind === 'global') imports[imp.module][imp.name] = 0;
  else if (imp.kind === 'table')
    imports[imp.module][imp.name] =
      new WebAssembly.Table({ element: 'anyfunc', initial: 1 });
}
const instance = new WebAssembly.Instance(mod, imports);
const dispatch = instance.exports.__gf_dispatch;
const view = new DataView(instance.exports.memory.buffer);
const FRAME = 0x40000000;
const out = {};

// (a) matched-class: gf_pilot_add(7, 35) marshalled through the frame.
view.setUint32(FRAME + 0x00, 2, true);
view.setInt32(FRAME + 0x10, 7, true);
view.setInt32(FRAME + 0x18, 35, true);
out.matched = {
  ret: dispatch(0x80003100, FRAME) | 0,
  slot: view.getInt32(FRAME + 0x08, true),
  ret_class: view.getUint32(FRAME + 0x04, true),
};

// (b) cross-class: zero-arg-style call site into the two-parameter callee.
// arg_count=0 and NO slots written this time -- the slots still hold the
// residue of the previous call, exactly the PPC register-residue shape.
view.setUint32(FRAME + 0x00, 0, true);
out.crossClass = {
  ret: dispatch(0x80003100, FRAME) | 0,
  slot: view.getInt32(FRAME + 0x08, true),
};

// (a2) f64 marshalling: zz_0004200_(2.25) -> 5.0 through the frame slots.
view.setUint32(FRAME + 0x00, 1, true);
view.setFloat64(FRAME + 0x10, 2.25, true);
out.f64 = {
  ret: dispatch(0x80004200, FRAME) | 0,
  slot: view.getFloat64(FRAME + 0x08, true),
  ret_class: view.getUint32(FRAME + 0x04, true),
};

// (d) i64 return (review F4): the FULL width lands in the ret slot and the
// thunk's i32 view is the LOW word -- NOT a PPC r3 image (PPC32 EABI r3
// carries the HIGH word; consumers must read the 8-byte slot). Distinct hi
// and lo words make a `return 0;` mutation in the callee fail ret, slot,
// and split alike.
view.setUint32(FRAME + 0x00, 1, true);
view.setInt32(FRAME + 0x10, 0x11223343, true);
out.wide = {
  ret: dispatch(0x80005300, FRAME) | 0,
  slot_hex: view.getBigUint64(FRAME + 0x08, true).toString(16),
  ret_class: view.getUint32(FRAME + 0x04, true),
};

// (c) table miss: unregistered address routes to the declared import.
out.miss = { ret: dispatch(0x80999999, FRAME) | 0, ledger: missLedger };

// (e) arity ledger: the cross-class call in (b) wrote arg_count=0 into a
// two-parameter callee -- dispatched anyway, counted once. Every other call
// matched its callee's arity, and a miss is never an arity event.
out.arity_mismatches =
  instance.exports.__gf_dispatch_arity_mismatches() >>> 0;

console.log('PILOT_RESULT ' + JSON.stringify(out));
"""


def _real_link_runner():
    """A real emcc link mirroring WasmUnitDriver._emcc_link_many exactly.

    The driver method needs a fully-constructed driver (lock, journal,
    events); the pilot needs only the link. The flags below are the same
    string _emcc_link_many builds -- the pilot must not link under laxer or
    stricter settings than the live gate.
    """
    from src.port_wasm_units import (
        ASSEMBLY_WASM,
        BUILD_TIMEOUT_SECONDS,
        EXPORT_NAME,
        NO_WINDOW,
        build_environment,
        resolve_bash,
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
        return True, ""

    return link_runner


@requires_toolchain
def test_pilot_dispatch_matched_crossclass_and_miss(tmp_path: Path):
    from src.port_assembly_gate import ASSEMBLY_WASM, run_assembly_gate
    from src.port_wasm_units import NO_WINDOW, resolve_node_exe

    units = _pilot_units(tmp_path / "staging")
    units.append(_pilot_wide_unit(tmp_path / "staging"))
    workdir = tmp_path / "assembly"
    result = run_assembly_gate(
        units, workdir, _real_link_runner(), dispatch_companion=True
    )
    assert result["passed"] is True, result
    wasm_path = workdir / ASSEMBLY_WASM
    assert wasm_path.is_file()
    assert result["dispatch"]["functions"] == 3

    driver_path = workdir / "pilot-driver.cjs"
    driver_path.write_text(PILOT_DRIVER_JS, encoding="utf-8", newline="\n")
    # The pilot instantiates under the PRODUCTION arena size (2GB commit).
    # On a host running resident models the commit charge can be transiently
    # exhausted; retry, then SKIP loudly rather than silently shrinking the
    # flags the live gate links with.
    completed = None
    for _ in range(4):
        completed = subprocess.run(
            [resolve_node_exe(), str(driver_path), str(wasm_path)],
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
    if (
        completed.returncode != 0
        and "Cannot allocate Wasm memory" in (completed.stderr + completed.stdout)
    ):
        pytest.skip(
            "host cannot commit the production 2GB wasm arena right now "
            "(transient memory pressure); pilot instantiation not attempted "
            "under reduced flags"
        )
    assert completed.returncode == 0, completed.stderr + completed.stdout
    match = re.search(r"PILOT_RESULT (\{.*\})", completed.stdout)
    assert match, completed.stdout
    out = json.loads(match.group(1))

    # (a) matched-class dispatch: correct result in the i32 view, the frame
    # return slot, and the frame return class (I32 == 1).
    assert out["matched"] == {"ret": 42, "slot": 42, "ret_class": 1}

    # (b) deliberately cross-class dispatch: the zero-arg-style call site
    # still lands in the two-parameter callee and returns correctly through
    # the uniform frame (slot residue plays the argument registers).
    assert out["crossClass"] == {"ret": 42, "slot": 42}

    # (a2) f64 marshalling both directions: 2.25 * 2 + 0.5 == 5.0, canonical
    # i32 view is 0, full value in the frame slot, ret_class F64 == 4.
    assert out["f64"] == {"ret": 0, "slot": 5.0, "ret_class": 4}

    # (d) i64 return through the real toolchain: full 64-bit value in the
    # frame slot (hi word != lo word), ret_class I64 == 2, and the i32 view
    # is the LOW word -- the F4 contract a `return 0;` mutation would fail.
    assert out["wide"] == {
        "ret": 0x55667788,
        "slot_hex": "1122334455667788",
        "ret_class": 2,
    }

    # (c) table miss: routed to the declared import, address ledgered, the
    # handler's result propagated. Never a trap.
    assert out["miss"]["ret"] == 0x5150
    assert out["miss"]["ledger"] == [
        {"gc_addr": 0x80999999, "argptr": PILOT_FRAME_ADDRESS}
    ]

    # (e) arity ledger: exactly the one deliberate mismatch -- the (b)
    # cross-class call -- was counted, and it still dispatched.
    assert out["arity_mismatches"] == 1


@requires_toolchain
def test_pilot_dispatch_export_survives_the_real_link(tmp_path: Path):
    """The linked module really EXPORTS __gf_dispatch and IMPORTS the miss
    handler -- inspected from the wasm binary, not inferred from flags."""
    from src.port_assembly_gate import ASSEMBLY_WASM, run_assembly_gate
    from src.port_wasm_units import NO_WINDOW, resolve_node_exe

    units = _pilot_units(tmp_path / "staging")
    workdir = tmp_path / "assembly"
    result = run_assembly_gate(
        units, workdir, _real_link_runner(), dispatch_companion=True
    )
    assert result["passed"] is True, result
    inspect = workdir / "inspect.cjs"
    inspect.write_text(
        "// .cjs: `exports` is a wrapper identifier, so use fresh names.\n"
        "const fs = require('fs');\n"
        "const mod = new WebAssembly.Module(fs.readFileSync(process.argv[2]));\n"
        "const exportNames = WebAssembly.Module.exports(mod).map(e => e.name);\n"
        "const importNames = WebAssembly.Module.imports(mod).map(i => i.name);\n"
        "console.log(JSON.stringify({exports: exportNames, imports: importNames}));\n",
        encoding="utf-8",
        newline="\n",
    )
    completed = subprocess.run(
        [resolve_node_exe(), str(inspect), str(workdir / ASSEMBLY_WASM)],
        capture_output=True,
        text=True,
        timeout=300,
        creationflags=NO_WINDOW,
    )
    assert completed.returncode == 0, completed.stderr + completed.stdout
    shape = json.loads(completed.stdout.strip().splitlines()[-1])
    assert DISPATCH_EXPORT in shape["exports"]
    assert ARITY_EXPORT in shape["exports"]
    assert "gf_pilot_add" in shape["exports"] and "zz_0004200_" in shape["exports"]
    assert MISS_IMPORT in shape["imports"]
