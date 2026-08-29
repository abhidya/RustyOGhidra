"""port_spec_emit.py -- generate an oracle-harness spec module from a VALIDATED plan.

WHAT A SPEC HAS TO DO, AND WHY MOST CANNOT BE GENERATED
-------------------------------------------------------
`run-unit.mjs` replays a dolphin-trace corpus through a per-unit spec module:
the spec seeds the captured reads into the codec's poisoned scratch arena, calls
the staged wasm, and byte-compares the declared write set (any other changed
byte is a stray write). Where a function's memory behaviour is entirely its own,
that shape is mechanical and this module emits it.

Where it is NOT its own, generation stops. The cardinal failure of an
auto-generated spec is UNDER-CHECKING: a spec that declares nothing to compare
passes every case and reports a green that means nothing. So the tiering below
is deliberately pessimistic -- a unit is only auto-specced when every byte the
comparison depends on is accounted for:

  MECHANICAL  the function calls nothing. Every read and write is its own; the
              replay is fully determined by the plan. Emit the spec.
  SHIMMED     the function calls ONLY SDK maths helpers whose ROM bodies are
              already transcribed and proven (SDK_SHIMS below, carried over from
              the hand-authored auto-c0020-007 spec, which they replayed to
              789/815 byte-exact). Emit the spec with those shims installed.
  HUMAN       anything else -- and specifically any external ROM `zz_*` callee.
              A ROM callee may itself store into the memory being compared, so
              the spec must derive the console's branch from the captured
              evidence, require the wasm to take the same branch, and only then
              narrow the comparison to the bytes the unit owns
              (`zz_00c4540_`/`zz_006c440_` is the worked example). That is
              reasoning, not templating. Emit NO spec, emit a reason.

A HUMAN-tier export is reported, never silently emitted with an empty or
weakened comparison.

Python only (owner rule); pure stdlib.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.port_c_evidence import FunctionEvidence
from src.port_plan_derive import parse_addr, write_pre_state_gaps, _reg_to_param

SPECS_RELPATH = "research/decomp/oracle-harness/specs"

GENERATED_BY = "port_spec_emit v1"

# SDK maths helpers whose ROM bodies are transcribed from
# research/decomp/ghidra-export/chunk_0064.c and were proven against 815 live
# console cases by the hand-authored auto-c0020-007 spec. A call to any of these
# is replayable; a call to anything else is not.
SDK_SHIMS: dict[str, str] = {
    "gnt4_PSVECAdd_bl": """    gnt4_PSVECAdd_bl: (a, b, o) => {
      a >>>= 0; b >>>= 0; o >>>= 0;
      rec("gnt4_PSVECAdd_bl", [a, b, o]);
      const y = fr(gf(a + 4) + gf(b + 4));
      sf(o, fr(gf(a) + gf(b)));
      sf(o + 4, y);
      sf(o + 8, fr(gf(a + 8) + gf(b + 8)));
      return 0n;
    },""",
    "gnt4_PSVECSubtract_bl": """    gnt4_PSVECSubtract_bl: (a, b, o) => {
      a >>>= 0; b >>>= 0; o >>>= 0;
      rec("gnt4_PSVECSubtract_bl", [a, b, o]);
      const y = fr(gf(a + 4) - gf(b + 4));
      sf(o, fr(gf(a) - gf(b)));
      sf(o + 4, y);
      sf(o + 8, fr(gf(a + 8) - gf(b + 8)));
    },""",
    "gnt4_PSQUATScale_bl": """    gnt4_PSQUATScale_bl: (s, v, o) => {
      v >>>= 0; o >>>= 0;
      rec("gnt4_PSQUATScale_bl", [s, v, o]);
      const y = fr(gf(v + 4) * s);
      const z = fr(gf(v + 8) * s);
      sf(o, fr(gf(v) * s));
      sf(o + 4, y);
      sf(o + 8, z);
      return 0n;
    },""",
    "gnt4_PSVECSquareMag_bl": """    gnt4_PSVECSquareMag_bl: (a) => {
      a >>>= 0;
      rec("gnt4_PSVECSquareMag_bl", [a]);
      const x = gf(a), y = gf(a + 4), z = gf(a + 8);
      return z * z + x * x + y * y;
    },""",
    "gnt4_PSQUATDotProduct_bl": """    gnt4_PSQUATDotProduct_bl: (a, b) => {
      a >>>= 0; b >>>= 0;
      rec("gnt4_PSQUATDotProduct_bl", [a, b]);
      return gf(a) * gf(b) + gf(a + 4) * gf(b + 4) + gf(a + 8) * gf(b + 8);
    },""",
    "gnt4_PSVECSquareDistance_bl": """    gnt4_PSVECSquareDistance_bl: (a, b) => {
      a >>>= 0; b >>>= 0;
      rec("gnt4_PSVECSquareDistance_bl", [a, b]);
      const dx = gf(a) - gf(b), dy = gf(a + 4) - gf(b + 4), dz = gf(a + 8) - gf(b + 8);
      return dx * dx + dy * dy + dz * dz;
    },""",
    "gnt4_PSMTXMultVec_bl": """    gnt4_PSMTXMultVec_bl: (m, v, o) => {
      m >>>= 0; v >>>= 0; o >>>= 0;
      rec("gnt4_PSMTXMultVec_bl", [m, v, o]);
      const vx = gf(v), vy = gf(v + 4), vz = gf(v + 8);
      const row = (r) => {
        const a0 = gf(m + r * 16), a1 = gf(m + r * 16 + 4);
        const a2 = gf(m + r * 16 + 8), a3 = gf(m + r * 16 + 12);
        return fr(fr(fr(a2 * vz) + fr(a0 * vx)) + a3 * 1.0 + fr(a1 * vy));
      };
      const y = row(1), z = row(2);
      sf(o, row(0));
      sf(o + 4, y);
      sf(o + 8, z);
      return 0n;
    },""",
}

# gnt4_PSVECNormalize_bl is deliberately NOT in SDK_SHIMS. Its ROM body needs
# the two Newton constants at 0x8043ca90/94, which the unit's own C never names
# -- so the plan cannot declare them, the capture never records them, and a
# generated shim would have to hardcode 0.5/3.0. The hand-authored spec reads
# them from the console instead. Calling it puts a function in the HUMAN tier.

# Decompiler builtins that are not real callees.
_NON_CALLEES = {
    "SQRT", "ABS", "NAN", "CONCAT44", "CONCAT31", "CONCAT22", "CONCAT13",
    "SUB84", "SUB41", "SUB42", "countLeadingZeros", "countTrailingZeros",
    "__assert", "memcpy", "memset",
}

REGION_BASE = 0x80600000
REGION_STRIDE = 0x4000


@dataclass
class ExportTier:
    fn: str
    tier: str                       # mechanical | shimmed | human
    reasons: list[str] = field(default_factory=list)
    shims: list[str] = field(default_factory=list)


def real_callees(evidence: FunctionEvidence) -> set[str]:
    return {c for c in evidence.callees if c not in _NON_CALLEES}


def classify_export(fn: str, evidence: FunctionEvidence, plan: dict[str, Any],
                    verdict: str) -> ExportTier:
    """Which generation tier one export falls into. Pessimistic by construction."""
    reasons: list[str] = []
    if verdict != "validated":
        reasons.append(f"plan verdict is {verdict!r}, not 'validated'")
    callees = real_callees(evidence)
    rom = sorted(c for c in callees if not c.startswith("gnt4_"))
    sdk = sorted(c for c in callees if c.startswith("gnt4_"))
    unknown_sdk = [c for c in sdk if c not in SDK_SHIMS]

    if evidence.indirect_calls:
        reasons.append(
            "dispatches through a ROM function-pointer table: staged wasm has no "
            "address->function mapping, so the replay traps on every call")
    if rom:
        reasons.append(
            f"calls external ROM callee(s) {rom}: the callee may itself store into "
            f"the compared memory, so the spec must derive the console's branch "
            f"from the captured evidence and narrow the comparison to what the "
            f"unit owns -- reasoning a template cannot do")
    if unknown_sdk:
        reasons.append(
            f"calls SDK helper(s) {unknown_sdk} with no vetted shim body: a "
            f"guessed body would silently change what the replay compares")
    if not plan.get("writes"):
        reasons.append(
            "no declared write set: a spec with nothing to compare passes every "
            "case, which is worse than no spec at all")
    gaps = write_pre_state_gaps(plan, _reg_to_param(plan), evidence)
    if gaps:
        reasons.append(
            f"declared write(s) {gaps[:4]} have no pre-state in the read set: on a "
            f"call whose branch does not store there, the replay would compare its "
            f"poisoned arena byte against the console's untouched value and blame "
            f"the unit for the spec's gap")
    if plan.get("uncapturable_writes"):
        reasons.append(
            "the function stores through a non-argument base (allocator return / "
            "stack), which the capture cannot address off entry registers")

    if reasons:
        return ExportTier(fn, "human", reasons)
    return ExportTier(fn, "shimmed" if sdk else "mechanical", [], sdk)


# ----------------------------------------------------------------- emission


def _element_width(evidence: FunctionEvidence, param: int | None, offset: int,
                   width: int) -> int:
    """Byte-swap element size for one declared entry.

    Taken from the C's own casts, NOT from the declared width -- and this
    matters: an 8-byte entry can be one `double` (swap as 8) or two adjacent
    `undefined4` copies coalesced into one range (swap as 4). Swapping the
    second case as a double would silently compare the right bytes in the wrong
    order and manufacture a divergence.
    """
    widths = {
        a.width for a in evidence.accesses
        if a.param == param and a.width
        and offset <= a.offset < offset + width
        and a.kind in ("param", "chase")
    }
    if len(widths) == 1:
        only = widths.pop()
        return only if only <= width else width
    if not widths:
        return 4 if width >= 4 else width
    return min(widths)


def _is_float(evidence: FunctionEvidence, param: int | None, offset: int) -> bool:
    return any(
        "float" in (a.text or "") and a.param == param and a.offset == offset
        for a in evidence.accesses
    )


@dataclass
class RegionPlan:
    roots: dict[int, tuple[str, int]]        # param -> (js name, base)
    chases: dict[tuple[int, int], tuple[str, int]]  # (param, off) -> (name, base)
    absolutes: list[tuple[str, int, int]]    # (name, base, size)


def _plan_regions(plans: dict[str, dict[str, Any]],
                  evidences: dict[str, FunctionEvidence],
                  reg_params: dict[str, dict[str, int]]) -> RegionPlan:
    """Lay out the scratch arena: one region per parameter root, one per chased
    object, and one per absolute address window the unit reads."""
    roots: dict[int, tuple[str, int]] = {}
    chases: dict[tuple[int, int], tuple[str, int]] = {}
    max_off: dict[int, int] = {}
    chase_max: dict[tuple[int, int], int] = {}
    absolute: dict[int, int] = {}

    for fn, plan in plans.items():
        reg_param = reg_params[fn]
        for side in ("reads", "writes"):
            for entry in plan.get(side) or []:
                parsed = parse_addr(entry.get("addr", ""), reg_param)
                width = int(entry.get("width") or 0)
                if parsed.form == "direct" and parsed.param is not None:
                    max_off[parsed.param] = max(max_off.get(parsed.param, 0),
                                                parsed.offset + width)
                elif parsed.form == "chase" and parsed.param is not None:
                    root = parsed.inner_loads[0]
                    chase_max[root] = max(chase_max.get(root, 0),
                                          parsed.offset + width)
                    max_off[root[0]] = max(max_off.get(root[0], 0), root[1] + 4)
                elif parsed.form in ("absolute", "absolute_strided") \
                        and parsed.base_addr is not None:
                    # a strided table read is indexed by a byte, so the region has
                    # to span every row the index can select, not just row 0
                    stride = _stride_of(entry.get("addr", ""))
                    span = stride * 0x100 if (parsed.form == "absolute_strided"
                                              and stride) else width
                    absolute[parsed.base_addr] = max(
                        absolute.get(parsed.base_addr, 0), span)

    for index, param in enumerate(sorted(max_off)):
        roots[param] = (f"P{param}", REGION_BASE + index * REGION_STRIDE)
    offset = len(roots)
    for index, root in enumerate(sorted(chase_max)):
        chases[root] = (f"CH{root[0]}_{root[1]:x}",
                        REGION_BASE + (offset + index) * REGION_STRIDE)

    absolutes: list[tuple[str, int, int]] = []
    for base in sorted(absolute):
        absolutes.append((f"ABS_{base:08x}", base, absolute[base]))
    return RegionPlan(roots, chases, absolutes)


_STRIDE = re.compile(r"\*\s*(0x[0-9a-fA-F]+|\d+)\s*\)?\s*$")


def _stride_of(addr_expr: str) -> int:
    match = _STRIDE.search(str(addr_expr).strip())
    return int(match.group(1), 0) if match else 0


def _round_up(value: int, to: int = 0x40) -> int:
    return ((value + to - 1) // to) * to


def emit_spec(unit: str, plans: dict[str, dict[str, Any]],
              evidences: dict[str, FunctionEvidence],
              tiers: dict[str, ExportTier], all_exports: list[str]) -> str:
    """Render the .spec.mjs source for the auto-speccable exports of one unit."""
    covered = [fn for fn in all_exports
               if fn in plans and tiers[fn].tier in ("mechanical", "shimmed")]
    uncovered = [fn for fn in all_exports if fn not in covered]
    reg_params = {fn: _reg_to_param(plans[fn]) for fn in covered}
    regions = _plan_regions({fn: plans[fn] for fn in covered},
                            evidences, reg_params)

    shims = sorted({s for fn in covered for s in tiers[fn].shims})

    out: list[str] = []
    add = out.append

    # ---- header ----
    add(f"// {unit}.spec.mjs -- GENERATED by {GENERATED_BY} from validated capture plans.")
    add("//")
    add("// Reference: the real GG4E in the bundled Dolphin is the oracle. Each fixture")
    add("// case is one live call captured by research/tools/dolphin-trace/capture_oracle.py")
    add("// against a plan whose typed read/write sets were derived from the unit's")
    add("// verbatim C by the local model and then STATICALLY VALIDATED against that same")
    add("// C (src/port_plan_derive.py): every declared entry names memory the C really")
    add("// touches, and every direct store the C performs is in the write set.")
    add("//")
    add("// Replay = seed the captured reads into the poisoned scratch arena (rebasing")
    add("// parameter roots, byte-swapping BE console bytes to the LE arena element-wise),")
    add("// call the staged wasm, and byte-compare the declared write set. Any other")
    add("// changed byte is a stray write and fails the case.")
    add("//")
    add("// GENERATOR SCOPE -- what this file does NOT claim:")
    for fn in all_exports:
        tier = tiers.get(fn)
        if tier and tier.tier == "human":
            add(f"//   {fn}: NOT COVERED -- {tier.reasons[0]}")
    add("// Those exports keep run-unit.mjs's verdict at PARTIAL by design; they need a")
    add("// hand-authored runner, not a weaker generated one.")
    add("//")
    add("// min_cases below is a GENERATOR DEFAULT, not a measurement: set it from the")
    add("// capture sweep's real per-export case count before treating a PASS as coverage.")
    add('import fs from "node:fs";')
    add('import path from "node:path";')
    add('import { fileURLToPath } from "node:url";')
    add("")
    add("const here = path.dirname(fileURLToPath(import.meta.url));")
    add("")

    # ---- region constants ----
    add("// ---- rebased scratch regions (damage-core convention: above all DOL/bss) ----")
    region_lines: list[str] = []
    for param, (name, base) in sorted(regions.roots.items()):
        add(f"const {name} = 0x{base:08x};   // param_{param} root")
        size = _round_up(_root_size(param, plans, reg_params) + 0x10)
        region_lines.append(f'  {{ name: "{name}", base: {name}, size: 0x{size:x} }},')
    for (param, off), (name, base) in sorted(regions.chases.items()):
        add(f"const {name} = 0x{base:08x};   // [param_{param}+0x{off:x}] -- chased object")
        size = _round_up(_chase_size((param, off), plans, reg_params) + 0x10)
        region_lines.append(f'  {{ name: "{name}", base: {name}, size: 0x{size:x} }},')
    if regions.absolutes:
        add("// ---- absolute (compiled-in) ROM addresses: NOT rebasable ----")
    for name, base, size in regions.absolutes:
        add(f"const {name} = 0x{base:08x};")
        region_lines.append(
            f'  {{ name: "{name}", base: {name}, size: 0x{_round_up(size, 4):x} }},')
    add("")

    # ---- meta ----
    add("export const meta = {")
    add(f'  unit: "{unit}",')
    add('  reference_kind: "dolphin_trace",')
    add("  references: [")
    add('    "real GG4E in the bundled Dolphin (GDB-stub per-call capture; tool: '
        'research/tools/dolphin-trace/capture_oracle.py)",')
    add(f'    "plans: research/tools/dolphin-trace/plans/{unit}.*.json '
        f'(LLM-derived, statically validated by src/port_plan_derive.py)",')
    if shims:
        add('    "env shims: the ROM\'s own SDK bodies per '
            'research/decomp/ghidra-export/chunk_0064.c",')
    add("  ],")
    add('  arena: "arena-trace-empty.json",')
    add(f'  wasmDefault: "../port-units-staging/{unit}/unit.wasm",')
    add(f'  fixture: "corpora/{unit}.dolphin-trace.jsonl",')
    add("  functions: [")
    for fn in covered:
        plan = plans[fn]
        bound = "1.0" if _has_float_write(plan, evidences[fn], reg_params[fn]) else "0"
        note = _js_string(plan.get("note", ""))
        add(f'    {{ name: "{fn}", rounding_bound: {bound}, min_cases: 50,')
        add(f'      reference: "dolphin_trace {plan.get("addr")} '
            f'(entry+LR capture; plan {unit}.{fn}.json)",')
        add(f'      note: {note} }},')
    add("  ],")
    add(f"  uncovered_exports: {json.dumps(uncovered)},")
    add("  regions: [")
    out.extend(region_lines)
    add("  ],")
    add("};")
    add("")

    # ---- primitives ----
    add("// ---------------------------------------------------------------- primitives")
    add("const f32buf = new Float32Array(1);")
    add("const fr = (x) => { f32buf[0] = x; return f32buf[0]; };")
    add('const beBytes = (hex) => new Uint8Array(Buffer.from(hex, "hex"));')
    add("/** element-wise BE->LE swap at `width` (the arena-provenance rule) */")
    add("const swapped = (hex, width) => {")
    add("  const b = beBytes(hex);")
    add("  if (width <= 1) return b;")
    add("  const out = new Uint8Array(b.length);")
    add("  for (let i = 0; i < b.length; i += width) {")
    add("    for (let j = 0; j < width; j++) out[i + j] = b[i + width - 1 - j];")
    add("  }")
    add("  return out;")
    add("};")
    add("const ulpDist = (aBits, bBits) => {")
    add("  const fold = (u) => ((u & 0x80000000) ? (0x80000000 - (u & 0x7fffffff)) "
        ": (0x80000000 + u));")
    add("  return Math.abs(fold(aBits >>> 0) - fold(bBits >>> 0));")
    add("};")
    add("const ROUNDING_ULP = 4;")
    add("")

    # ---- shims ----
    add("// ------------------------------------------------------------------ env shims")
    add("// Anything NOT installed here stays a loud Proxy throw (lib/wasm.mjs): a call")
    add("// this generator did not account for fails the case instead of passing quietly.")
    add("const callLog = [];")
    add("")
    add("export function makeShims(memCtx) {")
    if shims:
        add("  const gf = (a) => memCtx.dv.getFloat32(a >>> 0, true);")
        add("  const sf = (a, v) => memCtx.dv.setFloat32(a >>> 0, v, true);")
        add("  const rec = (name, args) => { callLog.push({ name, args }); };")
        add("  return {")
        for shim in shims:
            add(SDK_SHIMS[shim])
        add("  };")
    else:
        add("  // every covered export calls nothing")
        add("  return {};")
    add("}")
    add("")

    # ---- runner ----
    add("export function createRunner({ ex, dv }) {")
    add("  const readsById = (rec) => { const by = {}; "
        "for (const r of rec.reads) by[r.id] = r; return by; };")
    add("  const writesById = (rec) => { const by = {}; "
        "for (const w of rec.writes) by[w.id] = w; return by; };")
    add("  const absOf = (r) => Number.parseInt(r.addr, 16) >>> 0;")
    add("")
    add("  const compare = (codec, fields) => {")
    add('    let cls = "exact";')
    add("    const fieldDump = [];")
    add("    const gotBacks = [];")
    add("    for (const f of fields) {")
    add("      const got = new Uint8Array(f.width);")
    add("      for (let i = 0; i < f.width; i++) got[i] = codec.u8[f.addr + i];")
    add("      gotBacks.push({ addr: f.addr, bytes: got });")
    add("      const want = swapped(f.wantHex, f.elem);")
    add("      let same = want.length === got.length;")
    add("      if (same) for (let i = 0; i < got.length; i++) "
        "if (got[i] !== want[i]) { same = false; break; }")
    add("      if (same) continue;")
    add("      if (f.float && f.width === 4) {")
    add("        const gotBits = dv.getUint32(f.addr, true) >>> 0;")
    add("        const wantBits = new DataView(want.buffer, want.byteOffset)"
        ".getUint32(0, true) >>> 0;")
    add("        const d = ulpDist(gotBits, wantBits);")
    add("        fieldDump.push({ f: f.name, got: gotBits.toString(16), "
        "want: wantBits.toString(16), ulp: d });")
    add('        if (d <= ROUNDING_ULP && cls !== "unexplained") '
        '{ cls = "rounding"; continue; }')
    add("      } else {")
    add("        fieldDump.push({ f: f.name, "
        'got: Buffer.from(got).toString("hex"), '
        'want: Buffer.from(want).toString("hex") });')
    add("      }")
    add('      cls = "unexplained";')
    add("    }")
    add("    return { cls, fieldDump, gotBacks };")
    add("  };")
    add("")
    add("  const finish = (fn, rec, cls, audit, post, extra) => {")
    add('    if (post.strayWrites.length > 0 && cls === "exact") cls = "unexplained";')
    add("    if (audit.missing > 0) cls = \"unexplained\";")
    add("    return {")
    add("      fn, n: rec.n, cls, audit, post,")
    add('      dump: cls === "exact" ? null : {')
    add("        n: rec.n, fn_n: rec.fn_n, calls: callLog.map((c) => c.name), ...extra,")
    add('        stray: post.strayWrites.map((a) => "0x" + a.toString(16)),')
    add("      },")
    add("    };")
    add("  };")
    add("")

    for fn in covered:
        out.extend(_emit_runner(fn, plans[fn], evidences[fn], reg_params[fn], regions))

    add("  const table = {")
    for fn in covered:
        add(f"    {fn}: run_{fn},")
    add("  };")
    add("")
    add("  return {")
    add("    unit: meta.unit,")
    add("    handleRecord(codec, rec) {")
    add('      if (rec.kind !== "case") throw new Error(`unknown record kind ${rec.kind}`);')
    add("      const run = table[rec.fn];")
    add("      if (!run) throw new Error(`case ${rec.n}: no runner for ${rec.fn}`);")
    add("      return run(codec, rec);")
    add("    },")
    add("  };")
    add("}")
    add("")
    add("export const __specPath = fileURLToPath(import.meta.url);")
    return "\n".join(out) + "\n"


def _root_size(param: int, plans: dict[str, dict[str, Any]],
               reg_params: dict[str, dict[str, int]]) -> int:
    size = 0
    for fn, plan in plans.items():
        for side in ("reads", "writes"):
            for entry in plan.get(side) or []:
                parsed = parse_addr(entry.get("addr", ""), reg_params[fn])
                if parsed.form == "direct" and parsed.param == param:
                    size = max(size, parsed.offset + int(entry.get("width") or 0))
                if parsed.form == "chase" and parsed.inner_loads \
                        and parsed.inner_loads[0][0] == param:
                    size = max(size, parsed.inner_loads[0][1] + 4)
    return size


def _chase_size(root: tuple[int, int], plans: dict[str, dict[str, Any]],
                reg_params: dict[str, dict[str, int]]) -> int:
    size = 0
    for fn, plan in plans.items():
        for side in ("reads", "writes"):
            for entry in plan.get(side) or []:
                parsed = parse_addr(entry.get("addr", ""), reg_params[fn])
                if parsed.form == "chase" and parsed.inner_loads \
                        and parsed.inner_loads[0] == root:
                    size = max(size, parsed.offset + int(entry.get("width") or 0))
    return size


def _has_float_write(plan: dict[str, Any], evidence: FunctionEvidence,
                     reg_param: dict[str, int]) -> bool:
    for entry in plan.get("writes") or []:
        parsed = parse_addr(entry.get("addr", ""), reg_param)
        if parsed.form == "direct" and _is_float(evidence, parsed.param, parsed.offset):
            return True
    return False


def _js_string(text: str) -> str:
    return json.dumps(str(text or "")[:400])


def _emit_runner(fn: str, plan: dict[str, Any], evidence: FunctionEvidence,
                 reg_param: dict[str, int], regions: RegionPlan) -> list[str]:
    lines: list[str] = []
    add = lines.append
    add(f"  // ---------------------------------------------------------- {fn}")
    add(f"  const run_{fn} = (codec, rec) => {{")
    add("    const R = readsById(rec), W = writesById(rec);")
    add("    const need = (id) => { if (!R[id]) throw new Error("
        "`case ${rec.n} missing read ${id}`); return R[id]; };")
    add("    codec.beginCase();")
    add("    const mustWrite = [];")

    # seed reads
    for entry in plan.get("reads") or []:
        parsed = parse_addr(entry.get("addr", ""), reg_param)
        width = int(entry.get("width") or 0)
        entry_id = entry["id"]
        optional = bool(entry.get("optional"))
        if parsed.form == "direct" and parsed.param in regions.roots:
            name, _base = regions.roots[parsed.param]
            elem = _element_width(evidence, parsed.param, parsed.offset, width)
            target = f"{name} + 0x{parsed.offset:x}"
            add(_seed(entry_id, target, width, elem, optional))
        elif parsed.form == "chase" and parsed.inner_loads:
            root = parsed.inner_loads[0]
            if root not in regions.chases:
                continue
            name, _base = regions.chases[root]
            elem = _element_width(evidence, parsed.param, parsed.offset, width)
            target = f"{name} + 0x{parsed.offset:x}"
            add(_seed(entry_id, target, width, elem, optional))
        elif parsed.form in ("absolute", "absolute_strided"):
            # the fixture records the ABSOLUTE address the console read, which is
            # what a strided table row needs -- seed exactly there
            elem = 8 if width == 8 else (width if width < 4 else 4)
            add(f"    {{ const r = {_need(entry_id, optional)}; "
                f"if (r) {{ const a = absOf(r); "
                f"codec.wBytes(a, swapped(r.be_hex, {elem})); "
                f"mustWrite.push([a, {width}]); }} }}")

    # rebase chased pointers
    for (param, off), (name, _base) in sorted(regions.chases.items()):
        if param not in regions.roots:
            continue
        root_name, _ = regions.roots[param]
        add(f"    codec.wU32({root_name} + 0x{off:x}, {name}); "
            f"mustWrite.push([{root_name} + 0x{off:x}, 4]);")

    add("    const audit = codec.auditReads({ mustWrite, arenaOk: [] });")
    add("    codec.snapshotExpected();")
    add("    callLog.length = 0;")
    add("    let trap = null;")
    call_args = ", ".join(
        regions.roots[p][0] for p in sorted(regions.roots)
        if any(parse_addr(e.get("addr", ""), reg_param).param == p
               for side in ("reads", "writes") for e in (plan.get(side) or []))
    ) or (regions.roots[min(regions.roots)][0] if regions.roots else "")
    add(f"    try {{ ex.{fn}({call_args}); }} "
        "catch (e) { trap = String((e && e.message) || e); }")

    # compare declared writes
    add("    const fields = [];")
    for entry in plan.get("writes") or []:
        parsed = parse_addr(entry.get("addr", ""), reg_param)
        width = int(entry.get("width") or 0)
        if parsed.form == "direct" and parsed.param in regions.roots:
            name, _base = regions.roots[parsed.param]
            elem = _element_width(evidence, parsed.param, parsed.offset, width)
            is_float = str(_is_float(evidence, parsed.param, parsed.offset)).lower()
            # A declared write that the fixture does not carry is a CORPUS
            # defect, not an optional comparison: skipping it would quietly
            # shrink what this case checks. Fail the case instead.
            add(f'    if (!W.{entry["id"]}) throw new Error('
                f'`case ${{rec.n}}: fixture has no write {entry["id"]} '
                f'declared by the plan`);')
            add(f'    fields.push({{ name: "{entry["id"]}", '
                f"addr: {name} + 0x{parsed.offset:x}, width: {width}, elem: {elem}, "
                f'float: {is_float}, wantHex: W.{entry["id"]}.be_hex }});')
    add("    const { cls, fieldDump, gotBacks } = trap")
    add('      ? { cls: "unexplained", fieldDump: [], gotBacks: [] }')
    add("      : compare(codec, fields);")
    add("    const post = codec.diffPostState(gotBacks);")
    add(f'    return finish("{fn}", rec, cls, audit, post, '
        "{ trap, fields: fieldDump });")
    add("  };")
    add("")
    return lines


def _need(entry_id: str, optional: bool) -> str:
    return f"R.{entry_id}" if optional else f'need("{entry_id}")'


def _seed(entry_id: str, target: str, width: int, elem: int, optional: bool) -> str:
    return (f"    {{ const r = {_need(entry_id, optional)}; if (r) {{ "
            f"codec.wBytes({target}, swapped(r.be_hex, {elem})); "
            f"mustWrite.push([{target}, {width}]); }} }}")


def spec_path(repo_root: Path, unit: str) -> Path:
    return Path(repo_root) / SPECS_RELPATH / f"{unit}.spec.mjs"
