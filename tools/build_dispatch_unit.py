#!/usr/bin/env python3
"""Build ONE staged unit as a dispatch-lowered, observable wasm module.

Operator-run, offline, model-free -- the same class of tool as
`tools/survey_plan_tiers.py`. It exists because the dispatch standard needs a
module whose indirect calls actually go through the gate's table, and the
driver's own build path (`src/port_wasm_units.py:emcc_build_unit`) has no
"rebuild unit X with the lowering" entry point.

What it does, in the gate's own order (src/port_assembly_gate.py):

  1. `src/port_indirect_lowering.py` rewrites every `(*(code *)...)(...)` in
     the unit's verbatim C into a frame build plus `__gf_dispatch_at`;
  2. `src/port_dispatch_companion.py` derives the address-keyed thunk table
     from the LOWERED source and emits the companion, with TRACE mode on so
     the two observation imports are declared;
  3. emcc links both translation units with byte-identical flags to the
     production per-unit build (`src/port_wasm_units.py:1288-1313`).

Output directory contents, all derived and all re-derivable:

    <unit>.c                    the lowered translation unit
    gnt4_shim.h                 copied from the staged unit, unmodified
    gf_dispatch_frame.h         frame ABI v1
    gf_indirect_lowering.h      the lowering's macros
    gf_dispatch_companion.c     thunks + table + __gf_dispatch(+_at)
    gf_indirect_sites.json      the site manifest a capture plan binds to
    gate-evidence.json          lowering + companion evidence, incl. the table
    unit.wasm                   the module

Usage:
    python tools/build_dispatch_unit.py --repo-root D:/GotYaForce \\
        --unit auto-c0011-005 \\
        --out D:/GotYaForce/research/decomp/port-units-dispatch/auto-c0011-005
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
OGHIDRA = TOOLS.parent
sys.path.insert(0, str(OGHIDRA))

from src.port_dispatch_companion import (  # noqa: E402
    ARITY_EXPORT, COMPANION_FILENAME, DISPATCH_AT_EXPORT, DISPATCH_EXPORT,
    FRAME_HEADER_FILENAME, FRAME_HEADER_TEXT, MISS_IMPORT, TRACE_ENTER_IMPORT,
    TRACE_EXIT_IMPORT, companion_evidence, derive_window_signatures,
    emit_companion_source,
)
from src.port_indirect_lowering import (  # noqa: E402
    HEADER_FILENAME, HEADER_TEXT, SITES_FILENAME, lower_window,
    lowering_evidence, sites_manifest,
)

MARK = re.compile(r"//\s*====\s*([0-9a-f]{8})\s+(\S+)\s*====")

# Byte-identical to src/port_wasm_units.py:emcc_build_unit. A gate that passed
# under laxer settings than the production build would prove nothing about the
# production build.
EMCC_FLAGS = (
    "-O1 -fno-strict-aliasing --no-entry "
    "-Wno-implicit-function-declaration -Wno-int-conversion "
    "-Wno-deprecated-non-prototype -Wno-incompatible-pointer-types "
    "-Wno-pointer-sign -ferror-limit=0 "
    "-sERROR_ON_UNDEFINED_SYMBOLS=0 -sINITIAL_MEMORY=2155479040 "
    "-sALLOW_MEMORY_GROWTH=0 "
)

BASH_CANDIDATES = (
    r"C:\Program Files\Git\bin\bash.exe",
    r"C:\Program Files (x86)\Git\bin\bash.exe",
)


def to_posix(p: Path) -> str:
    s = str(p).replace("\\", "/")
    if len(s) > 1 and s[1] == ":":
        s = "/" + s[0].lower() + s[2:]
    return s


def resolve_bash() -> str:
    for candidate in BASH_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    return "bash"


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo-root", default="D:/GotYaForce")
    ap.add_argument("--unit", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--no-trace", action="store_true",
                    help="lower the call sites but do NOT declare the "
                         "observation imports (proves the lowering does not "
                         "depend on being watched)")
    ap.add_argument("--emsdk", default="")
    a = ap.parse_args()

    repo = Path(a.repo_root)
    emsdk = Path(a.emsdk) if a.emsdk else repo / "research/tools/emsdk"
    staging = repo / "research/decomp/port-units-staging" / a.unit
    if not (staging / "unit.c").exists():
        sys.exit(f"no staged unit at {staging}")
    unit_c = (staging / "unit.c").read_text(encoding="utf-8-sig")
    shim = (staging / "gnt4_shim.h").read_text(encoding="utf-8-sig")
    exports = [m.group(2) for m in MARK.finditer(unit_c)]
    if not exports:
        sys.exit(f"{staging}/unit.c has no chunk markers")

    work = Path(a.out)
    work.mkdir(parents=True, exist_ok=True)

    lowered = lower_window([(a.unit, f"{a.unit}.c", unit_c)])
    if lowered.problems:
        print(json.dumps({"stage": "indirect-lowering", "refused": True,
                          "problems": [p.to_dict() for p in lowered.problems]},
                         indent=1))
        return 2
    if not lowered.sites:
        print(json.dumps({"stage": "indirect-lowering", "refused": True,
                          "detail": f"{a.unit} has no indirect call site: there "
                                    f"is nothing for dispatch_green to observe"},
                         indent=1))
        return 3
    src_text = lowered.sources[f"{a.unit}.c"]

    derived = derive_window_signatures([(a.unit, src_text, exports)], {})
    if derived.problems:
        print(json.dumps({"stage": "dispatch-companion", "refused": True,
                          "problems": [p.__dict__ for p in derived.problems]},
                         indent=1))
        return 2
    # dispatch_at is NOT optional here: the source we just lowered CALLS
    # __gf_dispatch_at, and the link runs with -sERROR_ON_UNDEFINED_SYMBOLS=0,
    # so omitting the definition would silently turn every lowered ROM call
    # site into an undeclared host import instead of a table dispatch.
    companion = emit_companion_source(derived.signatures, dispatch_at=True,
                                      trace=not a.no_trace)

    (work / "gnt4_shim.h").write_text(shim, encoding="utf-8", newline="\n")
    (work / f"{a.unit}.c").write_text(src_text, encoding="utf-8", newline="\n")
    (work / FRAME_HEADER_FILENAME).write_text(FRAME_HEADER_TEXT, encoding="utf-8", newline="\n")
    (work / HEADER_FILENAME).write_text(HEADER_TEXT, encoding="utf-8", newline="\n")
    (work / COMPANION_FILENAME).write_text(companion, encoding="utf-8", newline="\n")
    (work / SITES_FILENAME).write_text(sites_manifest(lowered), encoding="utf-8", newline="\n")

    evidence = {
        "schema": "gf.dispatch-unit-build.v1",
        "unit": a.unit,
        "source": f"research/decomp/port-units-staging/{a.unit}/unit.c",
        "built_by": "research/tools/OGhidra/tools/build_dispatch_unit.py",
        "trace": not a.no_trace,
        "claims": {
            "is": "A single staged unit rebuilt with the gate's indirect-call "
                  "lowering and dispatch companion, so its ROM function-pointer "
                  "dispatches go through the address-keyed table and are "
                  "observable at two declared imports.",
            "is_not": "Not a verification result and not a promotion. The module "
                      "is inventory until run-dispatch.mjs compares it against a "
                      "console capture.",
        },
        "indirect_lowering": lowering_evidence(lowered),
        "dispatch": companion_evidence(derived.signatures, companion,
                                       dispatch_at=True,
                                       trace=not a.no_trace),
    }
    (work / "gate-evidence.json").write_text(
        json.dumps(evidence, indent=1) + "\n", encoding="utf-8", newline="\n")

    export_flag = ",".join(
        f"_{n}" for n in exports + [DISPATCH_EXPORT, DISPATCH_AT_EXPORT, ARITY_EXPORT])
    sources = " ".join(shlex.quote(n) for n in [f"{a.unit}.c", COMPANION_FILENAME])
    script = (
        f'source "{to_posix(emsdk)}/emsdk_env.sh" >/dev/null || '
        "{ echo 'emsdk_env.sh failed to load' >&2; exit 127; }; "
        "command -v emcc >/dev/null || "
        "{ echo 'emcc not on PATH after sourcing emsdk_env.sh' >&2; exit 127; }; "
        f'cd "{to_posix(work)}" && '
        f"emcc {sources} {EMCC_FLAGS}"
        f"-sEXPORTED_FUNCTIONS={shlex.quote(export_flag)} -o unit.wasm"
    )
    env = dict(os.environ, EMSDK_QUIET="1")
    proc = subprocess.run([resolve_bash(), "-lc", script], capture_output=True,
                          text=True, timeout=900, env=env)
    report = {
        "unit": a.unit,
        "out": str(work),
        "lowered_sites": len(lowered.sites),
        "non_call_code_casts": lowered.non_call_casts,
        "thunks": len(derived.signatures),
        "trace": not a.no_trace,
        "declared_imports": ([MISS_IMPORT] if a.no_trace
                             else [MISS_IMPORT, TRACE_ENTER_IMPORT, TRACE_EXIT_IMPORT]),
        "emcc_exit": proc.returncode,
    }
    print(json.dumps(report, indent=1))
    if proc.returncode != 0:
        sys.stderr.write((proc.stdout or "")[-4000:] + "\n"
                         + (proc.stderr or "")[-8000:] + "\n")
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
