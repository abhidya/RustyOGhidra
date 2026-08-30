#!/usr/bin/env python3
"""survey_plan_tiers.py -- how much of the 1,396-unit corpus this can automate.

Runs the MODEL-FREE half of the derivation stage (src/port_c_evidence) over
every function in oracle-registry.json, slicing each one's verbatim C out of its
chunk file, and reports the tier it would land in. No LLM, no GPU: this is the
CEILING measurement -- the share of the corpus whose shape the generator can
even attempt, before the model's own accuracy is applied to it.

TWO CEILINGS ARE REPORTED
-------------------------
`tier_of` is the ORIGINAL, WRITE-SET ceiling: which functions a byte-exact
write-comparison spec (oracle_green, run-unit.mjs) could be built for. It is
brutal, and its dominant refusal is "function stores nothing a capture could
compare" -- for those functions the write-comparison standard is not hard, it
is EMPTY.

`transcript_tier_of` is the ceiling of the CALLEE-BOUNDARY standard
transcript_green (research/decomp/oracle-harness/run-transcript.mjs, captured by
research/tools/dolphin-trace/capture_transcript.py). A function with no writes
is not unobservable: it still has a return value and a sequence of calls to its
out-of-unit callees with concrete arguments. transcript_green verifies exactly
that, and it is STRICTLY WEAKER than oracle_green -- it does not compare memory
writes. The two are reported separately and then combined, never merged into one
number that hides which claim a function actually reaches.

Usage:
  python tools/survey_plan_tiers.py --repo-root D:/GotYaForce [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.port_c_evidence import analyse_function  # noqa: E402
from src.port_spec_emit import SDK_SHIMS, real_callees  # noqa: E402
from src.port_trace_verify import ORACLE_REGISTRY_RELPATH  # noqa: E402


def slice_c(repo_root: Path, entry: dict, cache: dict[str, list[str]]) -> str | None:
    chunk = entry.get("chunk_file")
    span = entry.get("line_range") or []
    if not chunk or len(span) != 2:
        return None
    lines = cache.get(chunk)
    if lines is None:
        path = repo_root / chunk
        if not path.is_file():
            cache[chunk] = []
            return None
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        cache[chunk] = lines
    if not lines:
        return None
    start, end = int(span[0]), int(span[1])
    if not (1 <= start <= end <= len(lines)):
        return None
    return "".join(lines[start - 1:end])


def tier_of(evidence, entry: dict) -> tuple[str, str]:
    """(tier, reason) from the C alone -- the ceiling, ignoring model accuracy."""
    callees = real_callees(evidence)
    rom = sorted(c for c in callees if not c.startswith("gnt4_"))
    sdk = sorted(c for c in callees if c.startswith("gnt4_"))
    unknown_sdk = [c for c in sdk if c not in SDK_SHIMS]

    writes = evidence.direct_param_writes()
    local_writes = evidence.has_local_base_writes()

    if not writes and not local_writes:
        return "no_write_set", "function stores nothing a capture could compare"
    if evidence.indirect_calls:
        return "human", "dispatches through a ROM function-pointer table (replay traps)"
    if local_writes and not writes:
        return "human", "stores only through a non-argument base (allocator/stack)"
    if rom:
        return "human", f"calls external ROM callee(s) ({len(rom)})"
    if unknown_sdk:
        return "human", f"calls SDK helper(s) with no vetted shim ({unknown_sdk[:2]})"
    if local_writes:
        return "human", "some stores go through a non-argument base"
    return ("shimmed" if sdk else "mechanical"), ""


# --------------------------------------------------------------------------
# transcript_green: the CALLEE-BOUNDARY ceiling
# --------------------------------------------------------------------------
# Mirrors, from the C alone, exactly what capture_transcript.py `sites` accepts
# or refuses against the ROM. Kept deliberately conservative: every predicate
# here has a counterpart refusal in the tool, so this survey cannot promise a
# function the capture tool would then turn away.

def transcript_tier_of(fn_name: str, unit: str, returns_value: bool,
                       closure_out_callees: set[str],
                       closure_indirect: bool) -> tuple[bool, str]:
    """(verifiable_by_transcript_green, reason_if_not).

    `closure_*` are computed over the TRANSITIVE IN-UNIT CLOSURE, because a call
    to another function of the same wasm module is an INTERNAL wasm call the
    import shims never see -- but the out-of-unit calls that in-unit callee makes
    ARE seen, and capture_transcript.py breakpoints them.
    """
    if closure_indirect:
        # emcc lowers `(*(code *)...)()` to call_indirect on the module's own
        # table; no import shim can observe it, so the transcript would have a
        # hole. capture_transcript.py refuses this case.
        return False, "dispatches through a ROM function-pointer table (no import to bind)"
    if not closure_out_callees and not returns_value:
        # Nothing is observable at the import boundary. run-transcript.mjs's
        # vacuity guard would refuse the capture anyway.
        return False, "empty transcript: no out-of-unit call and no return value"
    return True, ""


def build_closures(functions: list[dict], evidences: dict[str, object]
                   ) -> tuple[dict[str, set[str]], dict[str, bool]]:
    """Per function: its transitive out-of-unit callee set, and whether any
    function in its in-unit closure dispatches indirectly."""
    unit_of = {e.get("name"): e.get("unit") for e in functions}
    direct: dict[str, tuple[set[str], set[str], bool]] = {}
    for e in functions:
        name = e.get("name")
        ev = evidences.get(name)
        if ev is None:
            continue
        unit = e.get("unit")
        callees = real_callees(ev)
        in_unit = {c for c in callees if c != name and unit_of.get(c) == unit}
        out_unit = {c for c in callees if c not in in_unit and c != name}
        direct[name] = (in_unit, out_unit, bool(ev.indirect_calls))

    out_of: dict[str, set[str]] = {}
    ind: dict[str, bool] = {}
    for name in direct:
        seen, stack = set(), [name]
        outs, indirect = set(), False
        while stack:
            f = stack.pop()
            if f in seen or f not in direct:
                continue
            seen.add(f)
            f_in, f_out, f_ind = direct[f]
            outs |= f_out
            indirect = indirect or f_ind
            stack.extend(f_in)
        out_of[name], ind[name] = outs, indirect
    return out_of, ind


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default="D:/GotYaForce")
    parser.add_argument("--json", default="")
    parser.add_argument("--dump-fn-tiers", default="",
                        help="write the per-function tier table (for picking targets)")
    args = parser.parse_args()
    repo_root = Path(args.repo_root)

    payload = json.loads(
        (repo_root / ORACLE_REGISTRY_RELPATH).read_text(encoding="utf-8-sig"))
    functions = payload.get("functions") or []

    cache: dict[str, list[str]] = {}
    tiers = Counter()
    per_unit: dict[str, Counter] = defaultdict(Counter)
    reasons = Counter()
    plan_shape = Counter()
    # transcript_green pass
    evidences: dict[str, object] = {}
    entry_by_name: dict[str, dict] = {}
    write_tier_of_fn: dict[str, str] = {}

    for entry in functions:
        name = entry.get("name")
        unit = entry.get("unit") or "?"
        body = slice_c(repo_root, entry, cache)
        if body is None:
            tiers["no_source"] += 1
            per_unit[unit]["no_source"] += 1
            continue
        evidence = analyse_function(name, body, entry.get("params") or [])
        tier, reason = tier_of(evidence, entry)
        tiers[tier] += 1
        per_unit[unit][tier] += 1
        evidences[name] = evidence
        entry_by_name[name] = entry
        write_tier_of_fn[name] = tier
        if reason:
            reasons[reason.split("(")[0].strip()] += 1
        # how big is the plan the model would have to get right?
        entries = len(evidence.direct_param_reads()) + len(evidence.direct_param_writes())
        plan_shape["<=4" if entries <= 4 else ("5-12" if entries <= 12 else ">12")] += 1

    # ---- transcript_green ceiling + the COMBINED ceiling ----
    closure_out, closure_ind = build_closures(functions, evidences)
    transcript_ok: dict[str, bool] = {}
    transcript_refusals = Counter()
    combined = Counter()
    per_unit_combined: dict[str, Counter] = defaultdict(Counter)
    combined_of_fn: dict[str, str] = {}
    for name, entry in entry_by_name.items():
        unit = entry.get("unit") or "?"
        ok, why = transcript_tier_of(
            name, unit, bool(entry.get("returns_value")),
            closure_out.get(name, set()), closure_ind.get(name, False))
        transcript_ok[name] = ok
        if not ok:
            transcript_refusals[why] += 1
        # The COMBINED tier names the STRONGEST claim a function can reach.
        # oracle_green (a byte-exact write comparison) always outranks
        # transcript_green (call transcript + return value only).
        wt = write_tier_of_fn[name]
        if wt in ("mechanical", "shimmed"):
            best = "oracle_green_auto"
        elif ok:
            best = "transcript_green"
        else:
            best = "unverifiable"
        combined[best] += 1
        combined_of_fn[name] = best
        per_unit_combined[unit][best] += 1

    # unit-level rollup: a unit is auto-speccable only if EVERY export is
    # (run-unit.mjs demands full export coverage for an oracle_green promotion)
    unit_tiers = Counter()
    for unit, counts in per_unit.items():
        auto = counts["mechanical"] + counts["shimmed"]
        total = sum(counts.values())
        if auto == total:
            unit_tiers["all_exports_auto"] += 1
        elif auto:
            unit_tiers["partially_auto"] += 1
        else:
            unit_tiers["none_auto"] += 1

    total_fn = sum(tiers.values())
    print(f"functions analysed: {total_fn}   units: {len(per_unit)}")
    print("\nPER-FUNCTION TIER (the shape the generator can attempt):")
    for tier, count in tiers.most_common():
        print(f"  {tier:14s} {count:6d}  {100 * count / total_fn:5.1f}%")
    print("\nHUMAN-tier reasons:")
    for reason, count in reasons.most_common(6):
        print(f"  {count:6d}  {reason}")
    print("\nPLAN SIZE the model must get right (declared direct entries):")
    for bucket, count in plan_shape.most_common():
        print(f"  {bucket:5s} {count:6d}  {100 * count / total_fn:5.1f}%")
    print("\nPER-UNIT rollup (full export coverage is required for oracle_green):")
    total_units = sum(unit_tiers.values())
    for kind, count in unit_tiers.most_common():
        print(f"  {kind:18s} {count:5d}  {100 * count / total_units:5.1f}%")

    # ---- transcript_green ----
    n_transcript = sum(1 for v in transcript_ok.values() if v)
    print("\nTRANSCRIPT_GREEN ceiling (callee boundary + return value; WEAKER "
          "than oracle_green -- no write comparison):")
    print(f"  verifiable       {n_transcript:6d}  {100 * n_transcript / total_fn:5.1f}%")
    for why, count in transcript_refusals.most_common():
        print(f"  refused {count:6d}  {why}")

    print("\nCOMBINED CEILING -- the STRONGEST claim each function can reach:")
    for kind, count in combined.most_common():
        print(f"  {kind:18s} {count:6d}  {100 * count / total_fn:5.1f}%")
    verifiable = total_fn - combined["unverifiable"]
    print(f"  {'VERIFIABLE BY SOME TIER':18s} {verifiable:6d}  "
          f"{100 * verifiable / total_fn:5.1f}%")

    # Per-unit under the combined tiers. Full export coverage is what a unit
    # promotion demands; a unit whose exports reach a MIX of tiers is reported
    # as mixed, never rounded up to the stronger one.
    unit_combined = Counter()
    for unit, counts in per_unit_combined.items():
        total = sum(counts.values())
        if counts["unverifiable"]:
            unit_combined["has_unverifiable_export"] += 1
        elif counts["oracle_green_auto"] == total:
            unit_combined["all_exports_oracle_green"] += 1
        elif counts["transcript_green"] == total:
            unit_combined["all_exports_transcript_green"] += 1
        else:
            unit_combined["all_exports_covered_mixed_tiers"] += 1
    print("\nPER-UNIT rollup under the COMBINED tiers "
          "(full export coverage; a mixed unit is NOT rounded up):")
    for kind, count in unit_combined.most_common():
        print(f"  {kind:30s} {count:5d}  {100 * count / total_units:5.1f}%")
    covered = total_units - unit_combined["has_unverifiable_export"]
    print(f"  {'UNITS WITH FULL EXPORT COVERAGE':30s} {covered:5d}  "
          f"{100 * covered / total_units:5.1f}%")

    if args.json:
        Path(args.json).write_text(json.dumps({
            "functions": total_fn, "units": len(per_unit),
            "per_function_tier": dict(tiers), "per_unit_rollup": dict(unit_tiers),
            "human_reasons": dict(reasons), "plan_size": dict(plan_shape),
            "transcript_green": {
                "verifiable": n_transcript,
                "refusals": dict(transcript_refusals),
            },
            "combined_per_function": dict(combined),
            "combined_per_unit": dict(unit_combined),
        }, indent=2), encoding="utf-8")
    if args.dump_fn_tiers:
        Path(args.dump_fn_tiers).write_text(json.dumps({
            name: {"unit": entry_by_name[name].get("unit"),
                   "addr": entry_by_name[name].get("address"),
                   "write_tier": write_tier_of_fn[name],
                   "transcript": transcript_ok[name],
                   "combined": combined_of_fn[name],
                   "returns_value": bool(entry_by_name[name].get("returns_value")),
                   "out_of_unit_callees": sorted(closure_out.get(name, set())),
                   "indirect": closure_ind.get(name, False)}
            for name in entry_by_name
        }, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
