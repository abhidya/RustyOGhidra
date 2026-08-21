"""D5 idiom-fix transform + census scanner (docs/d5-idiom-fix-design.md).

The defect (D5-0): under the integer CONCAT44 seed macro, Ghidra's PPC
int->double idiom ``(double)CONCAT44(0x43300000, x ^ 0x80000000) - M`` is a
C *arithmetic* u64->f64 conversion where the original Gekko semantics are a
*bit reinterpretation* (the ``lfd`` of an assembled stack slot -- the PPC750
has no fcfid). Every downstream truncation then saturates.

The fix (D5-3a): a deterministic, versioned, pure materialization-time
transform implementing grammar G:

    G: a ``(double)`` cast token sequence whose operand, after skipping at
    most one opening parenthesis, begins with a ``CONCAT44(`` call -- i.e.
    the cast applies to (i) the call itself, or (ii) a parenthesized
    expression whose leftmost primary is the call (V2's xor-outside shape).
    Whitespace and newlines may appear between any two tokens, including
    inside ``( double )``.

Rewrites:

    (double)CONCAT44(H, L)        ->  __gnt4_bitcast_f64(CONCAT44(H, L))
    (double)(CONCAT44(H, L) ^ K)  ->  __gnt4_bitcast_f64(CONCAT44(H, L) ^ K)

G deliberately does NOT condition on 0x43300000 (V5 non-magic hi words are
in scope), on the xor, or on the subtraction. The scanner is token/paren
matching, comment- and string-literal-aware (F-D5-3), idempotent
(``__gnt4_bitcast_f64(`` never matches G's cast prefix), and identity on
site-free text.

This module is also the census authority (D5-1 "The scanner is the
authority"): ``python -m src.port_fp_transform census`` regenerates every
number in the design doc's evidence base from the working tree.

Pure functions only -- no driver state, no I/O outside the census CLI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

TRANSFORM_NAME = "d5-fp-reinterpret"
TRANSFORM_VERSION = 1

# Name verified collision-free (D5-3a): zero occurrences in the ghidra-export
# fleet, both staged trees, and the generated headers at design time; the
# guard test re-asserts it against the live trees.
HELPER_NAME = "__gnt4_bitcast_f64"

HELPER_DEFINITION = """\
/* PPC lfd-of-assembled-bits: reinterpret a u64 bit pattern as an IEEE754
 * double. The extraction transform (D5) rewrites Ghidra's reinterpretation
 * casts `(double)CONCAT44(...)` to this helper; a bare (double) cast on an
 * integer in unit.c is then always a genuine value conversion. */
static inline double __gnt4_bitcast_f64(unsigned long long __u) {
  union { unsigned long long u; double d; } __b;
  __b.u = __u;
  return __b.d;
}
"""

# Verbatim marker rename (D5-3a): a transformed block must never claim
# byte-fidelity it no longer has. Site-free blocks keep the plain marker.
VERBATIM_MARKER = "/* ==== VERBATIM:"
VERBATIM_D5_MARKER = "/* ==== VERBATIM+D5:"

_WS = " \t\r\n\f\v"
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


# ---------------------------------------------------------------------------
# Lexical helpers: comment- and string-aware walking (F-D5-3).


def _skip_literal(text: str, i: int) -> int:
    """``i`` at a quote character; return index just past the literal."""
    quote = text[i]
    i += 1
    n = len(text)
    while i < n:
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == quote:
            return i + 1
        i += 1
    return n


def _skip_gaps(text: str, i: int) -> int:
    """Skip whitespace and comments starting at ``i``."""
    n = len(text)
    while i < n:
        if text[i] in _WS:
            i += 1
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
        elif text.startswith("//", i):
            end = text.find("\n", i + 2)
            i = n if end < 0 else end
        else:
            break
    return i


def _token_at(text: str, i: int, word: str) -> bool:
    """Exact identifier token ``word`` at position ``i``."""
    if not text.startswith(word, i):
        return False
    if i > 0 and (text[i - 1].isalnum() or text[i - 1] == "_"):
        return False
    end = i + len(word)
    return end >= len(text) or not (text[end].isalnum() or text[end] == "_")


def _match_paren(text: str, i: int) -> int:
    """``i`` at ``(``; return index just past the matching ``)`` or -1."""
    depth = 0
    n = len(text)
    while i < n:
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        if text.startswith("//", i):
            end = text.find("\n", i + 2)
            i = n if end < 0 else end
            continue
        char = text[i]
        if char in "\"'":
            i = _skip_literal(text, i)
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def _has_top_level_comma(text: str) -> bool:
    depth = 0
    i = 0
    n = len(text)
    while i < n:
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        if text.startswith("//", i):
            end = text.find("\n", i + 2)
            i = n if end < 0 else end
            continue
        char = text[i]
        if char in "\"'":
            i = _skip_literal(text, i)
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            return True
        i += 1
    return False


# ---------------------------------------------------------------------------
# Grammar G: site matching.


def _match_site(text: str, i: int) -> dict[str, Any] | None:
    """``i`` at ``(``: match one grammar-G site starting here.

    Returns ``None`` or a site record::

        {"start", "end", "form", "operand", "cast_newlines", "hi"}

    ``operand`` is the helper's argument text (call for the direct form,
    inner parenthesized expression for the paren form). ``cast_newlines``
    preserves any newlines the removed cast tokens spanned, so the rewrite
    never changes the artifact's line count (line-by-line traceability,
    D5-3a). ``hi`` is the call's first argument, whitespace-collapsed (V5
    classification).
    """
    j = _skip_gaps(text, i + 1)
    if not _token_at(text, j, "double"):
        return None
    k = _skip_gaps(text, j + len("double"))
    if k >= len(text) or text[k] != ")":
        return None
    cast_end = k + 1
    m = _skip_gaps(text, cast_end)

    def _site(
        form: str, call_open: int, operand: str, end: int
    ) -> dict[str, Any]:
        call_close = _match_paren(text, call_open)
        args = text[call_open + 1 : call_close - 1]
        hi = _split_top_level(args)[0].strip() if args.strip() else ""
        return {
            "start": i,
            "end": end,
            "form": form,
            "operand": operand,
            "cast_newlines": "\n" * text.count("\n", i, cast_end),
            "hi": re.sub(r"\s+", " ", hi),
        }

    # Direct form (V1/V3/V4/V5): cast applied to the call itself.
    if _token_at(text, m, "CONCAT44"):
        p = _skip_gaps(text, m + len("CONCAT44"))
        if p < len(text) and text[p] == "(":
            q = _match_paren(text, p)
            if q > 0:
                return _site("direct", p, text[m:q], q)
        return None
    # Paren form (V2 xor-outside): cast on a parenthesized expression whose
    # LEFTMOST PRIMARY is the call. Skipping "at most one opening
    # parenthesis" is exactly this branch: anything else after the outer
    # paren -- another paren, an identifier, a further cast like (float) --
    # is an arithmetic promotion the transform must not touch (leftmost-
    # primary exclusion).
    if m < len(text) and text[m] == "(":
        r = _skip_gaps(text, m + 1)
        if _token_at(text, r, "CONCAT44"):
            p = _skip_gaps(text, r + len("CONCAT44"))
            if p < len(text) and text[p] == "(":
                q = _match_paren(text, m)
                if q > 0:
                    return _site("paren", p, text[m + 1 : q - 1], q)
    return None


def _split_top_level(text: str) -> list[str]:
    """Split ``text`` on top-level commas (comment/string aware)."""
    parts: list[str] = []
    depth = 0
    i = 0
    start = 0
    n = len(text)
    while i < n:
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        if text.startswith("//", i):
            end = text.find("\n", i + 2)
            i = n if end < 0 else end
            continue
        char = text[i]
        if char in "\"'":
            i = _skip_literal(text, i)
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(text[start:i])
            start = i + 1
        i += 1
    parts.append(text[start:])
    return parts


def _walk(text: str, on_open_paren):
    """Walk ``text`` outside comments/strings; at each code ``(`` call
    ``on_open_paren(i)`` which may return a skip-to index (or None)."""
    i = 0
    n = len(text)
    while i < n:
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        if text.startswith("//", i):
            end = text.find("\n", i + 2)
            i = n if end < 0 else end
            continue
        char = text[i]
        if char in "\"'":
            i = _skip_literal(text, i)
            continue
        if char == "(":
            jump = on_open_paren(i)
            if jump is not None:
                i = jump
                continue
        i += 1


def scan_sites(text: str) -> list[dict[str, Any]]:
    """All grammar-G sites in ``text``, nested sites included (a site inside
    another site's operand -- one exists in chunk_0061.c -- is listed too,
    keeping the census count equal to the rewrite fixpoint's site count)."""
    sites: list[dict[str, Any]] = []

    def visit(i: int):
        site = _match_site(text, i)
        if site is not None:
            sites.append(site)
            sites.extend(scan_sites(site["operand"]))
            return site["end"]
        return None

    _walk(text, visit)
    return sites


def _rewrite_once(text: str) -> tuple[str, int]:
    out: list[str] = []
    consumed = 0
    count = 0

    def visit(i: int):
        nonlocal consumed, count
        site = _match_site(text, i)
        if site is None:
            return None
        operand = site["operand"]
        if site["form"] == "paren" and _has_top_level_comma(operand):
            # A top-level comma operator inside the reused parens would split
            # the helper's argument list; keep the original grouping intact.
            operand = "(" + operand + ")"
        out.append(text[consumed:i])
        out.append(HELPER_NAME + site["cast_newlines"] + "(" + operand + ")")
        consumed = site["end"]
        count += 1
        return site["end"]

    _walk(text, visit)
    out.append(text[consumed:])
    return "".join(out), count


def rewrite_fp_reinterpret(text: str) -> tuple[str, int]:
    """The D5 transform T: rewrite every grammar-G site to the helper.

    Returns ``(text, n_sites)``. Deterministic; idempotent (T(T(x)) ==
    T(x)); identity on site-free text (the property the migration census
    leans on, D5-6). Runs to fixpoint so a site nested inside another
    site's operand is rewritten too.
    """
    total = 0
    while True:
        text, count = _rewrite_once(text)
        if count == 0:
            return text, total
        total += count


def rename_transformed_marker(block: str) -> str:
    """``VERBATIM:`` -> ``VERBATIM+D5:`` on a block the transform changed,
    so the artifact never claims byte-fidelity it no longer has (D5-3a)."""
    return block.replace(VERBATIM_MARKER, VERBATIM_D5_MARKER, 1)


def ensure_bitcast_helper(header_text: str) -> str:
    """Append the seed-tier helper definition when the header lacks it.

    Needed because generated per-unit headers are SNAPSHOTS of the core
    seed taken at generation time: landing the helper in gnt4_shim_seed.h
    reaches future generations only, while the 1,393 existing header_seed
    files predate D5. Deterministic, reviewed code -- the same trust class
    as the transform itself (D5-3a verbatim-invariant analysis).
    """
    if re.search(r"\bdouble\s+" + re.escape(HELPER_NAME) + r"\s*\(", header_text):
        return header_text
    return header_text.rstrip("\n") + "\n\n" + HELPER_DEFINITION


# ---------------------------------------------------------------------------
# F-D5-2 guard: dataflow-separated reinterpretation.

_ASSIGN_CONCAT = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*CONCAT44\s*\(")


def dataflow_residual_risk(text: str) -> int:
    """Identifiers assigned a raw CONCAT44 result that are also ``(double)``
    cast somewhere in the same text -- the shape grammar G cannot see.
    Measured zero across the whole export (D5-1); n>0 must page, never
    silently build (F-D5-2/F-D5-B)."""
    count = 0
    for ident in sorted(set(_ASSIGN_CONCAT.findall(text))):
        if re.search(
            r"\(\s*double\s*\)\s*\(?\s*" + re.escape(ident) + r"\b", text
        ):
            count += 1
    return count


# ---------------------------------------------------------------------------
# Provenance semantics (D5-4).


def transform_record(pre_blocks: list[str]) -> tuple[list[str], dict[str, Any]]:
    """Transform per-extraction blocks; return (post_blocks, provenance block).

    The provenance ``transform`` block answers "is this artifact the output
    of transform vN?" -- the pre-transform hashes stay untouched and keep
    answering "is this really what the export says?" (D5-4: record both,
    conflate neither).
    """
    post_blocks: list[str] = []
    sites_per_block: list[int] = []
    for block in pre_blocks:
        rewritten, sites = rewrite_fp_reinterpret(block)
        if sites:
            rewritten = rename_transformed_marker(rewritten)
        post_blocks.append(rewritten)
        sites_per_block.append(sites)
    combined = "\n".join(post_blocks)
    record = {
        "name": TRANSFORM_NAME,
        "version": TRANSFORM_VERSION,
        "sites": sum(sites_per_block),
        "sites_per_block": sites_per_block,
        "transformed_sha256": hashlib.sha256(
            combined.encode("utf-8")
        ).hexdigest(),
        # F-D5-2 guard verdict on the post-transform text.
        "d5_residual_risk": dataflow_residual_risk(combined),
    }
    return post_blocks, record


STALE = "stale"
RESTAMP = "restamp"
CURRENT = "current"


def transform_staleness(
    provenance: dict[str, Any] | None, current_transformed_sha256: str
) -> str:
    """Generalized staleness predicate (D5-4 [R2]) for one artifact.

    An artifact is D5-stale iff it has no transform key (pre-D5 artifact)
    OR its transform version is older AND the current transform's output
    differs from the recorded ``transformed_sha256``. An old-version
    artifact whose bytes the current transform reproduces is RESTAMP: the
    version is bumped in place, no rebuild, no revocation (the identity
    case).
    """
    block = (provenance or {}).get("transform")
    if not isinstance(block, dict) or block.get("name") != TRANSFORM_NAME:
        return STALE
    try:
        version = int(block.get("version") or 0)
    except (TypeError, ValueError):
        return STALE
    if version >= TRANSFORM_VERSION:
        return CURRENT
    if block.get("transformed_sha256") == current_transformed_sha256:
        return RESTAMP
    return STALE


def restamp_in_place(provenance: dict[str, Any]) -> dict[str, Any]:
    """Apply the RESTAMP consequence: bump the version on the artifact's
    existing transform block. Caller (the migration step) must only invoke
    this after ``transform_staleness`` returned RESTAMP."""
    provenance["transform"]["version"] = TRANSFORM_VERSION
    return provenance


# ---------------------------------------------------------------------------
# Census (D5-1 categories). The scanner, not the prose, is the arbiter
# (F-D5-10); this CLI is the standing experiment behind F-D5-A/F-D5-9.

_MAGIC_HI = "0x43300000"
# Casts other than (double) applied directly to a CONCAT44 call: the
# F-D5-A falsifier scan. (double) itself is grammar G.
_OTHER_CASTS = (
    "float", "int", "uint", "short", "char", "longlong", "ulonglong",
    "undefined8", "ushort", "ulong", "byte",
)


def _count_calls(text: str, name: str) -> int:
    """Token-accurate call-site count for ``name(`` outside comments and
    strings (and outside a #define of the same name's replacement -- the
    census targets chunk/unit text, which never defines pseudo-ops)."""
    count = 0
    i = 0
    n = len(text)
    while i < n:
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        if text.startswith("//", i):
            end = text.find("\n", i + 2)
            i = n if end < 0 else end
            continue
        char = text[i]
        if char in "\"'":
            i = _skip_literal(text, i)
            continue
        if _token_at(text, i, name):
            j = _skip_gaps(text, i + len(name))
            if j < n and text[j] == "(":
                count += 1
            i += len(name)
            continue
        i += 1
    return count


def _other_cast_sites(text: str) -> int:
    """Non-(double) casts applied directly to a CONCAT44 call (expect 0)."""
    count = 0

    def visit(i: int):
        nonlocal count
        j = _skip_gaps(text, i + 1)
        word = _IDENT.match(text, j)
        if not word or word.group(0) not in _OTHER_CASTS:
            return None
        k = _skip_gaps(text, word.end())
        if k >= len(text) or text[k] != ")":
            return None
        m = _skip_gaps(text, k + 1)
        if _token_at(text, m, "CONCAT44"):
            p = _skip_gaps(text, m + len("CONCAT44"))
            if p < len(text) and text[p] == "(":
                count += 1
        return None

    _walk(text, visit)
    return count


def census_text(text: str) -> dict[str, int]:
    """The D5-1 categories for one text."""
    sites = scan_sites(text)
    return {
        "concat44_calls": _count_calls(text, "CONCAT44"),
        "double_cast_sites": len(sites),
        "xor_outside_sites": sum(1 for s in sites if s["form"] == "paren"),
        "non_magic_hi_sites": sum(1 for s in sites if s["hi"] != _MAGIC_HI),
        "other_cast_sites": _other_cast_sites(text),
        "dataflow_separated": dataflow_residual_risk(text),
        "sub84_calls": _count_calls(text, "SUB84"),
        "helper_calls": _count_calls(text, HELPER_NAME),
    }


def _merge(total: dict[str, int], part: dict[str, int]) -> None:
    for key, value in part.items():
        total[key] = total.get(key, 0) + value


def census_paths(paths: list[Path]) -> dict[str, Any]:
    per_file: dict[str, dict[str, int]] = {}
    totals: dict[str, int] = {}
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="replace")
        counts = census_text(text)
        if any(counts.values()):
            per_file[str(path)] = counts
        _merge(totals, counts)
    return {"files": len(paths), "totals": totals, "per_file": per_file}


def _repo_targets(repo_root: Path) -> dict[str, list[Path]]:
    decomp = repo_root / "research" / "decomp"
    return {
        "fleet (ghidra-export)": sorted(
            (decomp / "ghidra-export").glob("chunk_*.c")
        ),
        "staging (port-units-staging)": sorted(
            (decomp / "port-units-staging").glob("*/unit.c")
        ),
        "verified (port-units)": sorted(
            (decomp / "port-units").glob("*/unit.c")
        ),
    }


def run_census(repo_root: Path, as_json: bool = False) -> str:
    report: dict[str, Any] = {}
    for label, paths in _repo_targets(repo_root).items():
        report[label] = census_paths(paths)
    if as_json:
        return json.dumps(report, indent=2)
    lines: list[str] = []
    for label, data in report.items():
        totals = data["totals"]
        lines.append(f"== {label}: {data['files']} files ==")
        for key in (
            "concat44_calls", "double_cast_sites", "xor_outside_sites",
            "non_magic_hi_sites", "other_cast_sites", "dataflow_separated",
            "sub84_calls", "helper_calls",
        ):
            lines.append(f"  {key}: {totals.get(key, 0)}")
        offenders = {
            name: counts["double_cast_sites"]
            for name, counts in data["per_file"].items()
            if counts["double_cast_sites"]
        }
        if offenders and ("staging" in label or "verified" in label):
            for name, sites in sorted(offenders.items()):
                lines.append(f"    {sites:4d} (double)CONCAT44 site(s)  {name}")
    lines.append(
        "watch items: other_cast_sites>0 falsifies F-D5-A (halt the version "
        "bump); dataflow_separated>0 fires F-D5-2/F-D5-B; a first staged "
        "sub84 call triggers the D6 design review (F-D5-9)."
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="D5 idiom census (docs/d5-idiom-fix-design.md D5-1): "
        "the scanner is the authority for every count in the design doc."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    census = sub.add_parser("census", help="run the D5-1 census")
    census.add_argument(
        "--repo", default=r"D:\GotYaForce", help="GotYaForce repo root"
    )
    census.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)
    if args.command == "census":
        print(run_census(Path(args.repo), as_json=args.as_json))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
