"""port_unit_generator.py — mechanical unit authoring for the automatic 1:1 chunk port.

Product requirement (owner, 2026-08-10): the pipeline must port GotYaForce chunks
automatically, not only hand-curated units. Everything a wasm unit needs is
derivable from the Ghidra export's ``// ==== <addr>  <name> ====`` markers:

- extraction line ranges  (marker -> line before the next marker, blanks trimmed)
- prototypes              (the function's own signature lines + ';')
- exported functions      (the marker names)
- header symbol scaffold  (DAT_/FLOAT_/DOUBLE_/PTR_* referenced by the body,
                           emitted as GC_* address macros; width from the prefix)
- external callees        (functions called but not included: declared extern and
                           whitelisted as wasm imports — the design's
                           "auto-stub + log unresolved imports")

Generated units default to the ``compile_only`` oracle tier: they are built,
link-gated, committed to research/decomp/port-units-staging/ with
``verified: false`` provenance, and NEVER wired into the app. Full oracle gating
(design stage 4) remains mandatory for promotion out of staging — this tier
exists so chunk coverage can proceed mechanically while oracles are authored.

CLI (run from the OGhidra checkout):
    python -m src.port_unit_generator --repo D:/GotYaForce --chunk chunk_0006 \
        --functions zz_0060000_ zz_0060100_          # explicit set
    python -m src.port_unit_generator --repo D:/GotYaForce --chunk chunk_0006 \
        --first 10 --append                          # first N fns, append to queue
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

MARKER = re.compile(r"^// ==== ([0-9a-f]{8})\s+(\S+) ====\s*$")
# Ghidra globals the body may reference; prefix decides the access width.
GLOBAL_REF = re.compile(
    r"\b((?:PTR_PTR|PTR_DAT|PTR_FUN|DOUBLE|FLOAT|DAT|UNK)_[0-9a-f]{8})\b"
)
CALLEE = re.compile(r"\b((?:zz_[0-9a-f]+_|FUN_[0-9a-f]{8}))\s*\(")
QUEUE_DEFAULT = "research/decomp/generated/finish-game-port/wasm-units.json"
HEADER_DIR = "research/decomp/generated/finish-game-port/headers"
# Generator's OWN seed: integer undefined8/CONCAT44, matching the driver's
# SYSTEM_PROMPT. The PoC seed (research/decomp/poc/wasm-port-poc/gnt4_shim.h)
# keeps its double-form CONCAT44 for the committed PoC units and is NOT used
# here — handing the model a seed that contradicts the prompt cost a model
# round per unit just to undo the typedef.
CORE_SEED = "research/decomp/generated/finish-game-port/gnt4_shim_seed.h"

# emcc -sEXPORTED_FUNCTIONS can only export C identifiers. Ghidra-export
# markers also carry truncated demangled C++ ("cCameraManager::HasCamera(...")
# and hyphenated SDK names; those must never reach a unit's export list
# (the driver's runtime filter in port_wasm_units.py stays as a guard).
C_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def is_c_identifier(name: str) -> bool:
    """True when `name` can be an emcc EXPORTED_FUNCTIONS symbol."""
    return bool(C_IDENTIFIER.fullmatch(name))

WIDTH_BY_PREFIX = {
    "FLOAT": "GC_F32",
    "DOUBLE": "GC_F64",
    "PTR_PTR": "GC_PTR",
    "PTR_DAT": "GC_PTR",
    "PTR_FUN": "GC_PTR",
    # DAT_/UNK_: byte-addressed default; Ghidra emits explicit casts at wider
    # reads, and (&DAT_x)[i] pointer arithmetic needs the byte base. The LLM
    # compile-fix loop may widen when a compile error demands it.
    "DAT": "GC_U8",
    "UNK": "GC_U8",
}


def scan_chunk(chunk_path: Path) -> list[dict[str, Any]]:
    """All function blocks in a chunk: name, addr, 1-based [start, end] lines."""
    lines = chunk_path.read_text(encoding="utf-8", errors="replace").splitlines()
    marks: list[tuple[int, str, str]] = []
    for i, line in enumerate(lines, 1):
        m = MARKER.match(line)
        if m:
            marks.append((i, m.group(1), m.group(2)))
    blocks = []
    for j, (start, addr, name) in enumerate(marks):
        end = (marks[j + 1][0] - 1) if j + 1 < len(marks) else len(lines)
        while end > start and not lines[end - 1].strip():
            end -= 1
        blocks.append({"name": name, "addr": addr, "start": start, "end": end,
                       "text": "\n".join(lines[start - 1:end])})
    return blocks


def signature_of(block_text: str, name: str) -> str | None:
    """The declaration line(s): from the first line containing `name(` up to the
    line ending with ')' that precedes the lone '{'. Ghidra always emits this."""
    lines = block_text.splitlines()
    for i, line in enumerate(lines):
        if name + "(" in line and not line.lstrip().startswith(("/*", "//", "*")):
            sig = [line.rstrip()]
            k = i
            while not sig[-1].rstrip().endswith(")") and k + 1 < len(lines):
                k += 1
                sig.append(lines[k].rstrip())
            return " ".join(part.strip() for part in sig)
    return None


def build_unit(
    repo_root: Path,
    chunk: str,
    wanted: list[str] | None,
    first: int | None,
    unit_name: str | None,
) -> dict[str, Any]:
    chunk_rel = f"research/decomp/ghidra-export/{chunk}.c"
    blocks = scan_chunk(repo_root / chunk_rel)
    if wanted:
        index = {b["name"]: b for b in blocks}
        missing = [w for w in wanted if w not in index]
        if missing:
            raise SystemExit(f"functions not found in {chunk}: {missing}")
        chosen = [index[w] for w in wanted]
    else:
        chosen = blocks[: first or 5]
    included = {b["name"] for b in chosen}

    prototypes, exports, extractions = [], [], []
    globals_seen: dict[str, str] = {}
    callees_external: set[str] = set()
    for b in chosen:
        extractions.append({"file": chunk_rel, "start": b["start"], "end": b["end"]})
        sig = signature_of(b["text"], b["name"])
        if sig:
            prototypes.append(sig + ";")
        exports.append(b["name"])
        for g in GLOBAL_REF.findall(b["text"]):
            prefix = g.rsplit("_", 1)[0]
            globals_seen.setdefault(g, WIDTH_BY_PREFIX.get(prefix, "GC_U8"))
        for callee in CALLEE.findall(b["text"]):
            if callee not in included:
                callees_external.add(callee)

    core = (repo_root / CORE_SEED).read_text(encoding="utf-8")
    known = set(re.findall(r"#define\s+(\w+)", core))
    extra = [
        f"#define {sym} {macro}(0x{sym.rsplit('_', 1)[1]})"
        for sym, macro in sorted(globals_seen.items())
        if sym not in known
    ]
    extern_lines = [
        # external callees stay undefined -> wasm env imports, whitelisted per
        # unit; a JS stub logs any call at runtime (design: auto-stub + log).
        f"extern int {name}();" for name in sorted(callees_external)
    ]
    header = core.rstrip() + "\n"
    header += (
        "\n/* ---- AUTO-GENERATED (port_unit_generator) ---- */\n"
        "/* Ghidra `code` for indirect dispatch: unprototyped so any-arg calls\n"
        " * compile. Staging units are never executed; address->wasm-table\n"
        " * dispatch mapping is a later pipeline stage. */\n"
        "typedef void (code)();\n"
    )
    if extra or extern_lines:
        header += (
            "/* unit-referenced globals + external callees; widths are prefix-derived"
            " defaults\n * (the compile-fix loop may refine them). */\n"
            + "\n".join(extra + extern_lines) + "\n"
        )
    name = unit_name or (chunk + "-" + chosen[0]["name"].strip("_").replace("zz_", "auto-"))
    header_rel = f"{HEADER_DIR}/{name}.h"
    header_path = repo_root / header_rel
    header_path.parent.mkdir(parents=True, exist_ok=True)
    with open(header_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(header)

    return {
        "name": name,
        "generated_by": "port_unit_generator",
        "extractions": extractions,
        "prelude": ["/* auto-generated prototypes (from chunk markers) */"] + prototypes,
        "exported_functions": exports,
        "header_seed": header_rel,
        "allowed_extra_imports": sorted(callees_external),
        "oracle": {"type": "compile_only"},
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", default=r"D:\GotYaForce")
    ap.add_argument("--chunk", required=True, help="e.g. chunk_0006")
    ap.add_argument("--functions", nargs="*", help="explicit function names")
    ap.add_argument("--first", type=int, help="take the first N functions")
    ap.add_argument("--name", help="unit name override")
    ap.add_argument("--append", action="store_true", help="append to the queue file")
    ap.add_argument("--queue", default=QUEUE_DEFAULT)
    args = ap.parse_args()

    repo_root = Path(args.repo)
    unit = build_unit(repo_root, args.chunk, args.functions, args.first, args.name)
    print(json.dumps(unit, indent=2))
    if args.append:
        queue_path = repo_root / args.queue
        queue = json.loads(queue_path.read_text(encoding="utf-8"))
        units = queue["units"] if isinstance(queue, dict) else queue
        if any(u["name"] == unit["name"] for u in units):
            raise SystemExit(f"unit {unit['name']} already queued")
        units.append(unit)
        with open(queue_path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(queue, fh, indent=1)
        print(f"appended to {queue_path}")


if __name__ == "__main__":
    main()
