"""Trace-verification maintenance stage: Dolphin capture -> oracle harness ->
verdict recording for staged compile-only greens (verification at scale).

Design contract: docs/playable-port-design.md Stage B + V5 verdict (PASS,
2026-08-25). The pilot (research/tools/dolphin-trace/README.md) proved the
mechanism: 120/120 byte-exact on auto-c0001-007/zz_0010980_, and a REAL
mis-lift caught on auto-c0001-005/FUN_8000fc2c. This module scales it into
two driver maintenance verbs, ``verify-unit`` and ``verify-sweep``
(src/port_wasm_units.py CLI), which:

  (a) generate/refresh per-function capture plans from the unit's prototypes
      (arg typing from research/decomp/data/oracle-registry.json, plan format
      exactly as research/tools/dolphin-trace/capture_oracle.py consumes it);
  (b) invoke the capture tool (launch our own headless Dolphin with the
      scenario's savestate, capture N cases per export, stop);
  (c) replay through the EXISTING harness
      (research/decomp/oracle-harness/run-unit.mjs); and
  (d) record the verdict in the unit's canonical state as an ``oracle`` block
      -- WITHOUT changing the promotion tier.

Tier upgrade follows the EXISTING rule only (oracle plan section 3.4 /
_reverify_unit_inner): compile_only -> oracle_green happens exclusively
through the oracle-commands.json sidecar + the journaled reverify promotion
path. On a FULL-COVERAGE PASS (fail-closed: every export covered, zero
unexplained divergence, clean coverage audit, no rehearsal stamp -- see
``eligible_for_oracle_green``) verify-unit publishes the unit's sidecar entry
and chains into that path; anything less records the verdict and changes no
tier. A FAIL additionally flags ``oracle_divergent`` on the unit record with
the divergence evidence path -- visible in progress reporting, never an
automatic revoke (the mis-lift fix goes through the driver's sanctioned
compile path, then re-verify).

SUPERVISOR INTEGRATION (decided from what the supervisor supports WITHOUT
modification): the rig supervisor's only seam is ``main.py port-contract``
(D:/rig/SUPERVISOR.md "The seam") -- it starts/stops the port driver as a
whole and has no stage-rotation interface, so capture cannot be a
supervisor-rotated stage without modifying the supervisor (forbidden).
Therefore verify-unit/verify-sweep are OPERATOR-RUN verbs. The handoff to the
scheduled driver is the sidecar itself: once a full-coverage PASS publishes a
unit's oracle-commands.json entry, the driver's OWN verification lane
(run() -> _verification_candidates -> _reverify_unit_inner) also picks it up
with zero model calls -- so ``verify-unit --no-promote`` composes with the
supervisor-scheduled driver unchanged.

CONCURRENCY / GPU RULES:
  - Both verbs take the driver lock (wasm-units.lock) and refuse while a
    driver is alive -- they can never run concurrently with the port driver's
    own Dolphin/GPU/model use.
  - Capture launches OUR OWN Dolphin with the Null video backend (CPU-only;
    the GPU stays free for the LLM slot) -- capture_oracle.py's default.
  - ``dolphin_contended`` refuses to fight any other Dolphin instance for the
    savestate/stub port: an existing capture pid-file, a listening stub port,
    or any running Dolphin.exe skips capture with a recorded note.

Python only (owner rule); pure stdlib.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Iterable

# ---------------------------------------------------------------- repo layout

CAPTURE_TOOL_RELPATH = "research/tools/dolphin-trace/capture_oracle.py"
PLANS_RELPATH = "research/tools/dolphin-trace/plans"
SCENARIOS_RELPATH = "research/tools/dolphin-trace/scenarios"
CORPORA_RELPATH = "research/decomp/oracle-harness/corpora"
HARNESS_CWD_RELPATH = "research/decomp/oracle-harness"
HARNESS_ENTRY = "run-unit.mjs"
RESULTS_RELPATH = "research/decomp/data/oracle-results"
ORACLE_REGISTRY_RELPATH = "research/decomp/data/oracle-registry.json"
CAPTURE_PID_RELPATH = "user-data/dolphin-oracle/capture-dolphin.pid"
CAPTURE_STUB_PORT = 55555

# Plans this module wrote carry this marker; a plan WITHOUT it is
# hand-authored (line-by-line from the unit's verbatim C, with real typed
# read/write sets) and is never overwritten -- authored plans are strictly
# richer than generated skeletons.
GENERATED_BY = "port_trace_verify plan generator v1"

_FLOAT_TYPES = {"float", "double"}
_PAIR_TYPES = {"undefined8", "long long", "longlong", "ulonglong", "uint64_t", "int64_t"}
_GPR_FIRST, _GPR_LAST = 3, 10


class VerifySkip(RuntimeError):
    """A verification attempt that must be skipped (not an error verdict):
    e.g. Dolphin contended, or no staged artifact."""


# ---------------------------------------------------------------- registry I/O

def load_registry_functions(repo_root: Path) -> dict[str, dict[str, Any]]:
    """oracle-registry.json ``functions`` keyed by name. The registry is the
    typing authority for capture plans (params/return_type per function)."""
    payload = json.loads(
        (Path(repo_root) / ORACLE_REGISTRY_RELPATH).read_text(encoding="utf-8-sig")
    )
    functions = payload.get("functions") or []
    return {fn["name"]: fn for fn in functions if isinstance(fn, dict) and fn.get("name")}


# ------------------------------------------------------------- plan generation

def _param_type(param: str) -> tuple[str, bool]:
    """('float', is_pointer) from a registry param string like
    'undefined8 param_1' / 'int *param_2' / 'code *param_3'."""
    text = param.strip()
    pointer = "*" in text
    # drop the trailing identifier; what remains is the type
    words = text.replace("*", " ").split()
    type_words = words[:-1] if len(words) > 1 else words
    return " ".join(type_words), pointer


def plan_args(params: list[str]) -> tuple[list[dict[str, str]], list[str]]:
    """PPC SVR4 argument mapping for the capture tool (GPR sampling only).

    Non-float params take r3..r10 in order; 64-bit integer params
    (undefined8 & friends) take a GPR PAIR, emitted as _hi/_lo entries.
    Float/double params live in f1.. and are NOT sampled by capture_oracle.py
    (it reads r0..r10 at entry) -- they are reported in ``skipped`` so the
    plan says honestly what it cannot see. Params past r10 spill to the stack
    and are likewise skipped.
    """
    args: list[dict[str, str]] = []
    skipped: list[str] = []
    gpr = _GPR_FIRST
    for index, param in enumerate(params or [], start=1):
        type_name, pointer = _param_type(param)
        name = f"param_{index}"
        if not pointer and type_name in _FLOAT_TYPES:
            skipped.append(f"{name}: {type_name} arg is FPR-passed (not sampled by capture tool)")
            continue
        needs = 2 if (not pointer and type_name in _PAIR_TYPES) else 1
        if gpr + needs - 1 > _GPR_LAST:
            skipped.append(f"{name}: beyond r{_GPR_LAST} (stack-passed; not sampled)")
            continue
        if needs == 2:
            args.append({"reg": f"r{gpr}", "name": f"{name}_hi"})
            args.append({"reg": f"r{gpr + 1}", "name": f"{name}_lo"})
        else:
            args.append({"reg": f"r{gpr}", "name": name})
        gpr += needs
    return args, skipped


def plan_ret(entry: dict[str, Any]) -> dict[str, str] | None:
    if not entry.get("returns_value"):
        return None
    type_name = str(entry.get("return_type") or "").strip()
    if type_name in _FLOAT_TYPES:
        return {"reg": "f1"}
    return {"reg": "r3"}


def generate_plan(unit: str, entry: dict[str, Any]) -> dict[str, Any]:
    """A capture-plan SKELETON from the registry prototype: correct entry
    address, arg registers, and return register. reads/writes stay empty --
    typed read/write sets require the verbatim C (hand-authoring, per the
    dolphin-trace README); a skeleton still captures (args, ret) per call and
    is upgraded in place when someone authors the sets."""
    args, skipped = plan_args(entry.get("params") or [])
    params = ", ".join(entry.get("params") or []) or "void"
    plan: dict[str, Any] = {
        "unit": unit,
        "fn": entry["name"],
        "addr": entry["address"],
        "prototype": f"{entry.get('return_type', 'void')} {entry['name']}({params})",
        "generated_by": GENERATED_BY,
        "note": (
            "SKELETON generated from oracle-registry.json prototypes: args/ret "
            "only. reads/writes need hand-authoring from the unit's verbatim C "
            "(research/tools/dolphin-trace/README.md) before a capture proves "
            "memory behaviour; editing them removes none of this plan's fields."
        ),
        "args": args,
        "reads": [],
        "ret": plan_ret(entry),
        "writes": [],
    }
    if skipped:
        plan["unsampled_args"] = skipped
    return plan


def plan_path(repo_root: Path, unit: str, fn: str) -> Path:
    return Path(repo_root) / PLANS_RELPATH / f"{unit}.{fn}.json"


def refresh_plans(
    repo_root: Path,
    unit: str,
    exports: list[str],
    registry_fns: dict[str, dict[str, Any]],
) -> dict[str, list[str]]:
    """Write/refresh generated plan skeletons for every export.

    Hand-authored plans (no ``generated_by`` marker) are NEVER overwritten.
    Exports absent from the registry are reported, not invented.
    """
    summary: dict[str, list[str]] = {
        "written": [], "kept_authored": [], "unchanged": [], "missing_registry": [],
    }
    for fn in exports:
        entry = registry_fns.get(fn)
        if entry is None:
            summary["missing_registry"].append(fn)
            continue
        path = plan_path(repo_root, unit, fn)
        fresh = generate_plan(unit, entry)
        if path.is_file():
            try:
                existing = json.loads(path.read_text(encoding="utf-8-sig"))
            except (json.JSONDecodeError, OSError):
                existing = None
            if not (isinstance(existing, dict) and existing.get("generated_by")):
                summary["kept_authored"].append(fn)
                continue
            if existing == fresh:
                summary["unchanged"].append(fn)
                continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(fresh, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
        summary["written"].append(fn)
    return summary


# ---------------------------------------------------------- scenario selection

# v1 unit-family -> scenario heuristic (documented in
# research/tools/dolphin-trace/scenarios/README.md). Units are chunk-scoped
# (auto-c<chunk>-<n>); chunk 0013 is the title/main-menu flow
# (research/decomp/index/title-main-menu-flow.md), everything else defaults to
# the proven live-battle scenario (the only state measured to fire per-frame
# helpers -- dolphin-trace README empirics, 2026-08-25).
DEFAULT_SCENARIO = "battle-2v2-circle"
TITLE_SCENARIO = "title-attract"
_TITLE_CHUNKS = {"0013"}
_UNIT_CHUNK = re.compile(r"^auto-c(\d{4})-\d+$")


def family_scenario_index(repo_root: Path) -> dict[str, str]:
    """borg family constructor address -> the scenario that makes it live.

    Built from the scenario library itself: every scenario states, in its own
    measured ``live_families``, which families it brings up. So the routing and
    the family gate read exactly the same field, and a scenario that has not
    been measured (``live_families`` absent/null) routes nothing.

    The entries that matter are the ones
    ``research/tools/dolphin-trace/force_navigator.py cover`` writes: one
    per blocked family, each re-loading the ROM's battle around a roster of
    that family's borg. Before those existed every unit routed to
    ``battle-2v2-circle``, whose single live family left 98 of 104 staged
    units skipped as ``family_not_live`` forever.
    """
    index: dict[str, str] = {}
    directory = Path(repo_root) / SCENARIOS_RELPATH
    for path in sorted(directory.glob("*.json")):
        try:
            doc = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(doc, dict) or doc.get("scenario_schema") != 1:
            continue
        families = doc.get("live_families")
        if not isinstance(families, list):
            continue
        name = str(doc.get("name") or path.stem)
        for family in families:
            try:
                key = f"0x{int(str(family), 16):08x}"
            except (TypeError, ValueError):
                continue
            index.setdefault(key, name)
    return index


def select_scenario(
    unit_name: str,
    repo_root: Path | None = None,
    families: Iterable[str] | None = None,
) -> str:
    """Which scripted game state to verify this unit in.

    Family routing is ADDITIVE and fails open: it only applies when the caller
    supplies both a repo root and the unit's gating families, and only when
    some scenario has actually measured one of them live. Everything else
    keeps the v1 chunk heuristic, so a caller that has not been updated, a
    unit with no gating family, and a family nobody has covered yet all behave
    exactly as before.
    """
    if repo_root is not None and families:
        index = family_scenario_index(Path(repo_root))
        for family in sorted(families):
            try:
                key = f"0x{int(str(family), 16):08x}"
            except (TypeError, ValueError):
                continue
            scenario = index.get(key)
            if scenario:
                return scenario
    match = _UNIT_CHUNK.match(unit_name)
    if match and match.group(1) in _TITLE_CHUNKS:
        return TITLE_SCENARIO
    return DEFAULT_SCENARIO


# ------------------------------------------------------------ verdict parsing

def summarize_result(payload: dict[str, Any] | None) -> dict[str, Any]:
    """Normalize a run-unit.mjs result artifact into the state-block core."""
    if not isinstance(payload, dict):
        return {"verdict": "ERROR", "cases": 0, "byte_exact": 0, "unexplained": 0,
                "exports_covered": 0, "exports_total": 0, "uncovered": []}
    functions = payload.get("functions") or []
    coverage = payload.get("export_coverage") or {}
    verdict = str(payload.get("verdict") or "error").upper()
    return {
        "verdict": verdict,
        "cases": sum(int(f.get("cases", 0)) for f in functions),
        "byte_exact": sum(int(f.get("exact", 0)) for f in functions),
        "unexplained": sum(int(f.get("unexplained", 0)) for f in functions),
        "exports_covered": int(coverage.get("covered", 0)),
        "exports_total": int(coverage.get("exported", 0)),
        "uncovered": list(coverage.get("uncovered") or []),
    }


def eligible_for_oracle_green(payload: Any) -> tuple[bool, list[str]]:
    """FAIL-CLOSED gate for compile_only -> oracle_green: every check must
    POSITIVELY pass; a missing field is a refusal, never a default-pass.

    Mirrors run-unit.mjs's own allPass conditions and re-checks them here so
    a malformed/truncated result artifact can never promote a unit.
    """
    reasons: list[str] = []
    if not isinstance(payload, dict):
        return False, ["result artifact missing or not an object"]
    if payload.get("verdict") != "pass":
        reasons.append(f"verdict is {payload.get('verdict')!r}, not 'pass'")
    if "rehearsal" in payload:
        reasons.append("rehearsal-stamped artifact is never a verification verdict")
    coverage = payload.get("export_coverage")
    if not isinstance(coverage, dict):
        reasons.append("export_coverage missing")
    else:
        covered = coverage.get("covered")
        exported = coverage.get("exported")
        if not (isinstance(covered, int) and isinstance(exported, int)
                and exported >= 1 and covered == exported):
            reasons.append(
                f"export coverage {covered}/{exported} is not full (all exports required)"
            )
        if coverage.get("uncovered"):
            reasons.append(f"uncovered exports: {coverage['uncovered'][:5]}")
    functions = payload.get("functions")
    if not (isinstance(functions, list) and functions):
        reasons.append("no per-function results")
    else:
        for fn in functions:
            name = fn.get("name", "?")
            if fn.get("verdict") != "pass":
                reasons.append(f"{name}: verdict {fn.get('verdict')!r}")
            if fn.get("unexplained") != 0:
                reasons.append(f"{name}: unexplained divergence {fn.get('unexplained')!r}")
            if not (isinstance(fn.get("cases"), int) and fn["cases"] >= 1):
                reasons.append(f"{name}: no cases ran")
    audit = payload.get("coverage")
    if not isinstance(audit, dict):
        reasons.append("coverage audit missing")
    else:
        if audit.get("offsets_read_unwritten") != 0:
            reasons.append("declared-read offsets unwritten")
        if audit.get("sentinel_reads_detected") is not False:
            reasons.append("sentinel reads detected (or audit missing)")
        if audit.get("stray_writes"):
            reasons.append(f"stray writes: {audit['stray_writes'][:4]}")
        if audit.get("class_mismatches"):
            reasons.append("class mismatches present")
    return (not reasons), reasons


def build_sidecar_entry(
    unit: str, exports: list[str], payload: dict[str, Any], exports_sha256: str
) -> dict[str, Any]:
    """An oracle-commands.json entry for a unit whose trace verdict is a
    full-coverage PASS -- the handoff that puts the unit onto the driver's
    existing verification lane / reverify promotion path. Pattern discipline
    per validate_oracle_entry (S3/I-5): anchored (?m) total line first, one
    per-function line each, then the coverage line. Replay of a pinned
    fixture is deterministic, so exact case counts are stable patterns."""
    ok, reasons = eligible_for_oracle_green(payload)
    if not ok:
        raise ValueError(f"{unit}: not eligible for a sidecar entry: {reasons[:3]}")
    functions = payload["functions"]
    total_cases = sum(int(f["cases"]) for f in functions)
    patterns = [
        "(?m)^ORACLE TOTAL functions=%d/%d cases=%d UNEXPLAINED: 0 VERDICT: PASS$"
        % (len(functions), len(functions), total_cases)
    ]
    for fn in functions:
        patterns.append(
            "(?m)^\\[%s\\] cases=%d exact=%d rounding_explained=%d unexplained=0 "
            "verdict: pass$"
            % (re.escape(fn["name"]), fn["cases"], fn["exact"],
               fn.get("rounding_explained", 0))
        )
    patterns.append(
        "(?m)^coverage: offsets_read_unwritten=0 sentinel_reads=none "
        "stray_writes=0 class_mismatches=0$"
    )
    return {
        "exports_sha256": exports_sha256,
        "oracle": {
            "command": ["node", HARNESS_ENTRY, "--unit", unit],
            "cwd": HARNESS_CWD_RELPATH,
            "env": {"ORACLE_WASM": "{wasm}"},
            "success_patterns": patterns,
        },
    }


# ------------------------------------------------------------ dolphin guards

def dolphin_contended(repo_root: Path, port: int = CAPTURE_STUB_PORT) -> str | None:
    """A reason string when ANY Dolphin activity could contend for the
    savestate/stub/GPU; None when capture may launch. Never fight another
    process for the Dolphin savestate -- skip with a note instead."""
    pid_file = Path(repo_root) / CAPTURE_PID_RELPATH
    if pid_file.is_file():
        return f"capture pid-file exists ({CAPTURE_PID_RELPATH}); another capture may own the instance"
    try:
        out = subprocess.run(
            ["netstat", "-an", "-p", "TCP"], capture_output=True, text=True, timeout=30,
        ).stdout
        if any(f":{port} " in line and "LISTENING" in line for line in out.splitlines()):
            return f"a GDB stub already listens on 127.0.0.1:{port}"
    except (OSError, subprocess.SubprocessError):
        pass  # netstat unavailable: fall through to the process check
    try:
        out = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq Dolphin.exe"],
            capture_output=True, text=True, timeout=30,
        ).stdout
        if "Dolphin.exe" in out:
            return "a Dolphin.exe process is already running (not ours to interrupt)"
    except (OSError, subprocess.SubprocessError):
        pass
    return None


# ------------------------------------------------------------ state recording

def oracle_state_block(
    payload: dict[str, Any] | None,
    *,
    wasm_sha256: str,
    scenario: str,
    captured: dict[str, Any],
    corpus_files: list[str],
    result_relpath: str | None,
    run_id: str,
    at: str,
    status: str | None = None,
) -> dict[str, Any]:
    """The unit-record ``oracle`` block (task: cases, byte-exact count,
    verdict, corpus paths -- bound to the exact staged wasm bytes so a sweep
    can skip already-verified artifacts and re-attempt changed ones)."""
    core = summarize_result(payload)
    if status is not None:
        core["verdict"] = status
    block = {
        "oracle_block_schema": 1,
        "reference_kind": (payload or {}).get("reference_kind", "dolphin_trace"),
        **core,
        "corpus_files": corpus_files,
        "result_path": result_relpath,
        "scenario": scenario,
        "captured": captured,
        "wasm_sha256": wasm_sha256,
        "run_id": run_id,
        "at": at,
    }
    if core["verdict"] == "FAIL" and result_relpath:
        block["divergence_evidence"] = result_relpath
    return block
