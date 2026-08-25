"""wasm-unit mode for the finish-port driver (production form of the 2026-08-09 POC).

Ports VERBATIM Ghidra C units to wasm, gates them (emcc link -> post-link import
whitelist -> oracle corpus diff), and commits each green unit into the product
repo ("commit-per-match"). The unit queue is a JSON file the owner curates:
research/decomp/generated/finish-game-port/wasm-units.json.

Activated only when OGHIDRA_PORT_MODE=wasm_units; otherwise the classic chunk
driver runs untouched (see src/port_scheduler.py dispatch). Supervision contract
is identical to port_driver: control.json honored at unit boundaries,
llm-liveness.json heartbeats, events.jsonl, run-state.json, and the port_driver
exit-code vocabulary, so the existing watchdog needs no changes.

Design rules carried over from the POC (POC-RESULTS-2026-08-09.md):
  - The extracted C is VERBATIM and never edited; the LLM compile-fix loop may
    only rewrite the scaffold header (gnt4_shim.h); depth is capped by
    OGHIDRA_PORT_MAX_ITERS (default 4, design doc section 2.1).
  - Never trust link success: undefined symbols silently become wasm env
    imports; only the gnt4_* SDK seam may remain imported (whitelist gate).
  - Only the oracle decides green. Failed units stay retryable forever
    (no countdowns); rotation is least-attempted-first -- but a red unit is
    only SCHEDULABLE when the world changed since its verdict (design section
    2.8 [V4-3]: the recorded world-version must differ in at least one
    component from the current one; zero-delta reds are skipped and a pass
    that finds nothing else writes run_state="waiting_world_change").

Settle-through-journal rule (design section 2.9 [V4-9], mirrored in the
GotYaForce AGENTS.md): any operation that settles, carries, or unsettles a
unit verdict MUST go through a code path that emits the corresponding journal
event. Hand-editing wasm-units-state.json is FORBIDDEN -- the 2026-08-20
migration wrote 15 verdicts straight into the state file without a single
journal event, and events.jsonl has disagreed with live state ever since.
Use ``settle_unit`` / ``revoke_unit`` (driver methods, or the corresponding
CLI subcommands of this module), which back up the state file, emit the
journal checkpoint + events.jsonl event, and save atomically.
"""

from __future__ import annotations

import json
import hashlib
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.port_assembly_gate import (
    header_defines_external_functions,
    BACKFILL_ALLOWED_IGNORED_EVIDENCE,
    BACKFILL_REQUIRED_COMMITTED_FILES,
    ELIGIBLE_CANONICAL_TIERS,
    ASSEMBLY_WASM,
    SMOKE_JS,
    UnitArtifact,
    assembly_window_size,
    load_unit_artifact,
    load_canonical_state_snapshot,
    prove_legacy_artifact_commit_tree,
    record_gate_result,
    run_assembly_gate,
    select_recent_green_units,
    unit_artifact_sha256,
    verify_canonical_state_snapshot,
)
from src.port_chunk_workflow import TRANSIENT_MARKERS, atomic_write_json, utc_now
from src.port_fp_transform import (
    CURRENT as D5_CURRENT,
    RESTAMP as D5_RESTAMP,
    ensure_bitcast_helper,
    transform_record,
    transform_staleness,
)
from src.port_knowledge_registry import (
    REGISTRY_RELPATH,
    TIER_COMPILE_ONLY,
    TIER_ORACLE_GREEN,
    augment_seed,
    check_survival,
    fold_assembly_conflict_ledger,
    harvest_unit,
    is_holdout,
    load_registry,
    prelude_prototypes,
    promote_unit_entries,
    record_surviving_deviations,
    read_stable_assembly_ledger_bytes,
    registry_version,
    relevant_delta,
    restore_unit_entries,
    revoke_unit_entries,
    save_registry,
    unit_symbol_set,
)
from src.port_driver import (
    EXIT_NO_WORK,
    EXIT_PROGRESSED,
    EXIT_PROVIDER_PAUSED,
    EXIT_STOPPED,
    EXIT_LOCKED,
    DriverEvents,
    DriverLock,
)
from src.port_model_config import resolve_port_model_config
from src.port_owner_decl_injection import (
    inject_owner_declarations,
    load_owner_prototypes,
    sync_owner_declarations,
)
from src.port_sdk_decl_injection import (
    inject_sdk_declarations,
    sync_sdk_declarations,
)
from src.port_progress import (
    RESULT_DEFERRED,
    RESULT_GATE_FAILED,
    RESULT_GREEN,
    RESULT_RETRYABLE,
    RESULT_STAGED,
    RESULT_STRUCTURAL_INELIGIBLE,
    MachineState,
    UnitTransition,
    journal_for,
)
from src.port_run_controller import find_gotyaforce_root

# Windows: this process may run under pythonw.exe (no console), and every
# console child then allocates a NEW console window that flashes on the owner's
# desktop. All supervision output belongs in the widget and the dashboard, not
# in transient terminals.
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


QUEUE_SCHEMA = 1
STATE_SCHEMA = 1
PROMOTION_ATTEMPT_SCHEMA = 1


@dataclass(frozen=True)
class PromotionTransaction:
    """One durable post-gate promotion intent and its owned workspace."""

    attempt_dir: Path
    candidate: UnitArtifact
    destination: Path


# Compile-fix depth cap (design section 2.1): across the n=7 clean repair-greens
# the link iterations were 2,2,2,2,3,3,5 -- one needed 5, so a hard cap of 3
# would strand that class while no recovery path exists. Cap 4 for T1; the cap
# drops to 3 only when T2's recovery (retry lane + carry) lands and F1's
# measurement window supports it.
MAX_COMPILE_ITERS = int(os.getenv("OGHIDRA_PORT_MAX_ITERS", "4"))
# emcc exports must be C identifiers; C++ signatures are not.
EXPORT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
BUILD_TIMEOUT_SECONDS = 600
ORACLE_TIMEOUT_SECONDS = 1800
# A ROM symbol referenced without being called -- its address taken and stored
# into a dispatch slot. Mirrors port_unit_generator.ADDR_TAKEN; keep the two in
# step, since that module decides the queue's whitelist and this one decides
# whether the live gate accepts an import the queue failed to list.
ADDRESS_TAKEN_SYMBOL = re.compile(r"\b((?:zz_[0-9a-f]+_|FUN_[0-9a-f]{8}))\b(?!\s*\()")
# Post-link import whitelist (POC finding: a missing CONCAT44 linked "fine" as a
# dead env import). Only the SDK seam may be imported; these wasm plumbing names
# are structural, not code imports.
ALLOWED_IMPORT_PREFIX = "gnt4_"
BENIGN_IMPORTS = {
    "memory",
    "__memory_base",
    "__table_base",
    "__indirect_function_table",
    "__stack_pointer",
}
# node.exe is not on the service PATH; OGHIDRA_NODE_EXE overrides, then PATH,
# then the rig's known runtime checkout.
NODE_FALLBACKS = [
    r"D:\manny\Documents\CustomCard\.codex\runtime\node\node-v24.18.0-win-x64\node.exe",
]

SYSTEM_PROMPT = """You are the compile-fix stage of a Ghidra-C -> wasm port pipeline for a
GameCube (PowerPC, big-endian) game. A verbatim Ghidra-decompiled C file fails to
compile with emscripten (clang, wasm32). You may ONLY change the support header
gnt4_shim.h — the .c file is verbatim decompiler output and must never be edited.

Fix the header so the C compiles AND keeps the original PowerPC runtime semantics
(Ghidra decompiler idioms must behave exactly as they did on the GameCube).

Ghidra's placeholder types have FIXED widths. Use exactly these -- they are not
open to interpretation, and getting one wrong cascades through the whole file:

    typedef unsigned char       undefined;
    typedef unsigned char       undefined1;
    typedef unsigned short      undefined2;
    typedef unsigned int        undefined4;
    typedef unsigned long long  undefined8;   /* an INTEGER, never double */
    typedef unsigned char       byte;
    typedef unsigned short      ushort;
    typedef unsigned int        uint;
    typedef unsigned long       ulong;
    typedef unsigned long long  ulonglong;
    typedef long long           longlong;

Ghidra's pseudo-operations are pure INTEGER bit manipulation. They never
return floating point, even when the surrounding code converts to double:

    CONCAT44(hi, lo)  = ((unsigned long long)(unsigned int)(hi) << 32)
                        | (unsigned int)(lo)
    CONCAT13(hi, lo)  = ((unsigned int)(unsigned char)(hi) << 24)
                        | ((lo) & 0xFFFFFF)
    SUBxy(v, n)       = the y low-order bytes of v starting at byte offset n
    ZEXTxy(v)         = zero-extend v to y bytes
    SEXTxy(v)         = sign-extend v to y bytes

`(double)(CONCAT44(0x43300000, x) ^ 0x80000000) - 4503599627370496.0` is the
standard PowerPC int->double idiom. The xor and the cast belong to the CALLER;
do NOT fold them into CONCAT44. A CONCAT that returns double makes the xor
illegal ('invalid operands to binary expression') and the unit cannot compile.

The pipeline pre-rewrites that idiom's reinterpretation cast to
`__gnt4_bitcast_f64(...)` before you ever see the .c file (D5 transform).
`__gnt4_bitcast_f64` is seed-provided; never redefine, wrap, or remove it.
A `(double)` cast you see in unit.c is a genuine value conversion.

Ghidra names raw data symbols `DAT_<addr>` / `PTR_DAT_<addr>` after WHERE the
value was found, not after any recovered type. The `PTR_` prefix is NOT a
promise that the symbol holds a pointer -- type it from how the .c uses it.

In particular `(&SYM)[i]` means SYM is the FIRST ELEMENT of a table, so SYM must
be declared as the ELEMENT type and `&SYM` is then the table base:

    (double)(float)(&PTR_DAT_802c3c58)[i * 3]

reads a float element, so declare the symbol as `float`, NOT as `float *`.
Declaring it a pointer makes `(&SYM)[i]` a pointer and the cast illegal
('pointer cannot be cast to type float').

More generally: whenever the .c takes a symbol's ADDRESS -- `(&SYM)[i]`,
`&SYM + n`, `*(short *)(&SYM + n)` -- SYM must be an LVALUE, i.e. a dereference
of its address:

    #define DAT_802c44f8 (*(unsigned char *)(unsigned int)0x802c44f8)   /* lvalue */
    #define DAT_802c44f8 0x802c44f8                                     /* WRONG */

A bare integer constant is an rvalue and its address cannot be taken ('cannot
take the address of an rvalue'). Pick the element type from the cast at the use
site; when the .c casts the computed address itself (e.g. `*(short *)(&SYM+n)`),
an `unsigned char` base makes the byte arithmetic come out right.

Function signatures must be read off the CALL SITES in the .c file, which is
verbatim decompiler output and authoritative. If a call passes 16 arguments,
declare 16 parameters; if a result is assigned, the return type must not be
void. Do not invent an arity or a return type that disagrees with the caller.

The header may carry two kinds of REGISTRY blocks from previously ported
units of this same program (design section 2.11):

- Lines in or marked by "REGISTRY (authoritative)" were established by
  BEHAVIOURALLY-VERIFIED units of this same program. Do not alter them --
  adapt your other declarations instead.
- The commented block marked "REGISTRY (advisory)" holds typings that
  previous units of this program merely COMPILED with. Verify each against
  THIS unit's use sites before adopting it; you are free to disagree -- a
  reasoned disagreement is wanted data. Never adopt an advisory line that
  contradicts what this .c file's own use sites require.

Output the COMPLETE corrected gnt4_shim.h in a single ```c code block. No other text
is used by the pipeline."""

# Thinking OFF, exactly as the chunk-era source loop learned to do it
# (src/port_source_loop.py PORT_DISABLE_THINKING). This server reports
# reasoning_style=enable_thinking with reasoning_always_on=false, so thinking is
# ON unless the request says otherwise -- and when it is on, the model spends the
# whole max_tokens budget in `reasoning_content` and returns an EMPTY `content`.
# The client then raises "returned no assistant content", which is how 8 of the
# 19 reds on 2026-08-15 were recorded as unit faults, plus 3 more that simply hit
# the 1200s read timeout mid-spiral. The disable machinery already existed; the
# wasm-unit path just never inherited it.
DISABLE_THINKING = os.getenv("OGHIDRA_PORT_DISABLE_THINKING", "1").lower() not in (
    "0", "false", "no",
)

# Qwen3.8-27B card, instruct (non-thinking) row. Measured at 262k ctx on a real
# compile-fix prompt: this profile returned a usable ```c block in 143s, while
# thinking-ON (1.0/0.95/20) spent 4217s and 8192 tokens inside reasoning_content
# and returned zero content. Overridable without a code change.
SAMPLING = {
    "temperature": float(os.getenv("OGHIDRA_PORT_TEMPERATURE", "0.7")),
    "top_p": float(os.getenv("OGHIDRA_PORT_TOP_P", "0.80")),
    "top_k": int(os.getenv("OGHIDRA_PORT_TOP_K", "20")),
    "min_p": float(os.getenv("OGHIDRA_PORT_MIN_P", "0.0")),
    "presence_penalty": float(os.getenv("OGHIDRA_PORT_PRESENCE_PENALTY", "1.5")),
}

# Compile-fix replies are one complete gnt4_shim.h -- ~1.6-2k tokens in
# practice (.env comment). The client-wide default of 8192 permits ~59-minute
# worst-case generations at 2.3 tok/s on the CPU-bound fallback model; 4096
# halves that ceiling while still leaving 2x headroom over real replies, and
# the loop already tolerates truncation (unclosed-fence salvage in
# _compile_fix, then the next compile names the error and iterates). Scoped to
# this call site on purpose -- other call paths keep the client default.
COMPILE_FIX_MAX_TOKENS = int(
    os.getenv("OGHIDRA_PORT_COMPILE_FIX_MAX_TOKENS", "4096")
)

CODE_BLOCK = re.compile(r"```(?:c|cpp|h)?\s*\n(.*?)```", re.S)
# An opening fence with no terminator: the model stopped before closing it.
OPEN_FENCE = re.compile(r"```(?:c|cpp|h)?[ \t]*\n")


def resolve_node_exe() -> str:
    """node for oracle harnesses: env override -> PATH -> rig runtime checkout."""
    override = os.getenv("OGHIDRA_NODE_EXE")
    if override and Path(override).is_file():
        return override
    found = shutil.which("node")
    if found:
        return found
    for candidate in NODE_FALLBACKS:
        if Path(candidate).is_file():
            return candidate
    raise FileNotFoundError(
        "node executable not found (set OGHIDRA_NODE_EXE or add node to PATH)"
    )


def extract_verbatim(repo_root: Path, extractions: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    """Python equivalent of the POC's sed extraction: 1-based inclusive ranges,
    bytes kept verbatim. Returns (combined text with markers, per-block records
    incl. sha256 of the raw extracted text)."""
    blocks: list[str] = []
    records: list[dict[str, Any]] = []
    for spec in extractions:
        source = repo_root / spec["file"]
        start, end = int(spec["start"]), int(spec["end"])
        lines = source.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        if not (1 <= start <= end <= len(lines)):
            raise ValueError(f"extraction range {start}-{end} out of bounds for {source}")
        raw = "".join(lines[start - 1 : end])
        records.append(
            {
                "file": spec["file"],
                "start": start,
                "end": end,
                "sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
            }
        )
        blocks.append(f"/* ==== VERBATIM: {spec['file']} {start}-{end} ==== */\n{raw}")
    return "\n".join(blocks), records


class MaterializedUnit:
    """Output of :func:`materialize_unit_c` -- the ONE seam through which
    unit.c text reaches a build, a diagnosis prompt, or an F4 replay."""

    __slots__ = (
        "unit_c", "verbatim", "extraction_records", "extracted_sha256",
        "transform",
    )

    def __init__(
        self,
        unit_c: str,
        verbatim: str,
        extraction_records: list[dict[str, Any]],
        extracted_sha256: str,
        transform: dict[str, Any],
    ) -> None:
        self.unit_c = unit_c
        self.verbatim = verbatim
        self.extraction_records = extraction_records
        self.extracted_sha256 = extracted_sha256
        self.transform = transform


def materialize_unit_c(repo_root: Path, unit: dict[str, Any]) -> MaterializedUnit:
    """Materialize a unit's C text: byte-faithful extraction, then the D5
    fp-reinterpret transform (docs/d5-idiom-fix-design.md D5-3a).

    ``extract_verbatim`` stays byte-faithful and is called ONLY here, so the
    built unit, the diagnosis prompt's read-only display, and the F4 offline
    replay can never diverge on whether the transform ran (F-D5-6). The
    per-block sha256s and ``extracted_sha256`` are recorded PRE-transform
    (the export-chain answer); the ``transform`` block carries the
    post-transform hash (the artifact answer) -- D5-4: both questions,
    conflated never. For site-free text the transform is identity and
    ``transform["transformed_sha256"] == extracted_sha256``.
    """
    pre_blocks: list[str] = []
    records: list[dict[str, Any]] = []
    for spec in unit["extractions"]:
        block, block_records = extract_verbatim(repo_root, [spec])
        pre_blocks.append(block)
        records.extend(block_records)
    pre_combined = "\n".join(pre_blocks)
    extracted_sha256 = hashlib.sha256(pre_combined.encode("utf-8")).hexdigest()
    post_blocks, transform = transform_record(pre_blocks)
    verbatim = "\n".join(post_blocks)
    prelude = "\n".join(unit.get("prelude", []))
    unit_c = (
        "#include \"gnt4_shim.h\"\n\n"
        + (prelude + "\n\n" if prelude else "")
        + verbatim
    )
    return MaterializedUnit(
        unit_c=unit_c,
        verbatim=verbatim,
        extraction_records=records,
        extracted_sha256=extracted_sha256,
        transform=transform,
    )


def scan_disallowed_imports(wasm_path: Path) -> list[str]:
    """POC link gate: find env.* import names that are not gnt4_* SDK functions.

    Same heuristic scan model_loop.py proved (name strings following 'env.' in
    the binary); false negatives are impossible for the failure mode this guards
    (an identifier-shaped undefined symbol imported from env)."""
    data = wasm_path.read_bytes()
    names = [
        match.decode("utf-8", "ignore").split("\x00")[0]
        for match in re.findall(rb"env.([\x20-\x7e]{2,40})", data)
    ]
    return sorted(
        {
            name
            for name in names
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)
            and not name.startswith(ALLOWED_IMPORT_PREFIX)
            and name not in BENIGN_IMPORTS
        }
    )


# Git Bash install roots, most specific first. The wasm build needs a POSIX
# shell that carries the Git toolchain, and PATH alone is not a safe way to find
# it (see resolve_bash).
GIT_BASH_CANDIDATES = [
    Path(r"C:\Program Files\Git\bin\bash.exe"),
    Path(r"C:\Program Files (x86)\Git\bin\bash.exe"),
]


def to_posix_path(path: Path) -> str:
    r"""``D:\GotYaForce\x`` -> ``/d/GotYaForce/x``, without shelling out.

    This is what ``cygpath -u`` does, and doing it in Python removes the runtime
    dependency on cygpath entirely -- which matters because cygpath lives in
    Git's /usr/bin and is NOT on the PATH a service-style scheduled task
    inherits. See resolve_bash for the incident.
    """
    text = str(Path(path).resolve())
    drive, separator, rest = text.partition(":")
    if separator and len(drive) == 1 and rest:
        return "/" + drive.lower() + rest.replace("\\", "/")
    return text.replace("\\", "/")


def resolve_bash() -> str:
    """A bash that carries the Git toolchain, not merely something named bash.

    2026-08-16: after the supervisor's scheduled task moved to an S4U principal
    (needed for the boot trigger), the driver stopped inheriting the interactive
    logon PATH. Every build then failed with

        /bin/bash: line 1: cygpath: command not found
        /bin/bash: line 1: emcc: command not found

    recorded as ``gate_failed at wasm-link`` -- a toolchain fault charged to the
    unit. Resolve the known Git Bash explicitly and only fall back to PATH.
    """
    for candidate in GIT_BASH_CANDIDATES:
        if candidate.is_file():
            return str(candidate)
    found = shutil.which("bash")
    if found:
        return found
    raise FileNotFoundError(
        "no bash found; the wasm build needs Git Bash (checked: "
        + ", ".join(str(c) for c in GIT_BASH_CANDIDATES) + ")"
    )



_OPERATOR_ONLY_BINDINGS = (
    "transition_id",
    "previous_record_sha256",
    "previous_commit",
    "previous_candidate_sha256",
)


def revoked_lifecycle_is_eligible(revoked: object, candidate_tier: str) -> bool:
    """May this unit's installed artifact be REPLACED by a rebuilt candidate?

    Replacing an artifact that is already installed is only allowed against a
    recorded revocation, so a rebuild can never silently overwrite a promoted
    unit. Two issuers can produce one, and they carry different evidence:

    `revoke-unit` -- the operator command. It computes a deterministic
    `transition_id`, hashes the record it superseded and names the commit that
    record was at, so every binding is required and must be well formed.

    `d5-migrate` -- the D5-6 migration, which revoked artifacts predating the
    `d5-fp-reinterpret` transform and requeued them for rebuild. It is a real,
    system-issued, reasoned revocation, but it never computed the operator
    bindings. Demanding them made 12 units permanently uninstallable: they
    rebuild, pass the N=5 assembly gate, and are refused at the last step, so
    every retry burns a full LLM generation plus gate on a unit that cannot
    succeed. Its own evidence is `transform_sites`, the count of rewritable
    idiom sites that justified the revocation.

    Backfilling the missing bindings was rejected deliberately: they describe
    a transition that happened on 2026-08-21 and inventing them now would be
    fabricating evidence about the past. A `d5-migrate` record that DOES
    carry any of them is therefore refused too -- genuine ones cannot have
    them, so their presence means the record was hand-written. That includes
    `previous_candidate_sha256`: a migration record carrying it would take
    the digest-only replacement branch (disk digest vs self-declared digest,
    no commit-tree proof), which is exactly the forgery this refusal closes.
    """
    if not isinstance(revoked, dict):
        return False
    if revoked.get("previous_status") != "green":
        return False
    if revoked.get("previous_tier") != candidate_tier:
        return False
    reason = revoked.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        return False

    via = revoked.get("via")
    if via == "revoke-unit":
        return (
            re.fullmatch(
                r"verdict-revoke-[0-9a-f]{64}", str(revoked.get("transition_id") or ""), re.I
            )
            is not None
            and re.fullmatch(
                r"[0-9a-f]{64}", str(revoked.get("previous_record_sha256") or ""), re.I
            )
            is not None
            and re.fullmatch(
                # Full 40-hex commit SHAs only: a prefix cannot be resolved
                # against the publication lineage without ambiguity.
                r"[0-9a-f]{40}", str(revoked.get("previous_commit") or ""), re.I
            )
            is not None
        )
    if via == "d5-migrate":
        sites = revoked.get("transform_sites")
        if isinstance(sites, bool) or not isinstance(sites, int) or sites <= 0:
            return False
        return all(revoked.get(name) is None for name in _OPERATOR_ONLY_BINDINGS)
    return False


def summarise_build_error(output: str, budget: int = 1200) -> str:
    """Keep the compiler's diagnosis, discard the invocation it echoes.

    emcc prints the failing clang command in full on error: ~500 characters of
    sysroot and -mllvm boilerplate that is identical for every unit and says
    nothing about why this one failed. A blind tail slice records that instead
    of the `error:` lines above it, which is how auto-c0000-005's record ended
    in "...ed." with the actual cause missing.

    Exact-duplicate lines are dropped, first occurrence wins (design section
    2.4): with -ferror-limit=0 a bad macro can emit the same diagnostic
    hundreds of times, spending the whole budget without adding evidence.
    The stuck-abort fingerprint consumes the RAW build output, never this
    summary -- truncation here must not be able to mask oscillation.
    """
    text = (output or "").strip()
    seen: set[str] = set()
    deduped: list[str] = []
    for line in text.splitlines():
        if line in seen:
            continue
        seen.add(line)
        deduped.append(line)
    text = "\n".join(deduped)
    if len(text) <= budget:
        return text
    markers = ("error:", "warning:", "undefined symbol", "fatal:")
    diagnostic = [
        line for line in text.splitlines()
        # the echoed invocation is one enormous line; a real diagnostic is not
        if any(m in line.lower() for m in markers) and len(line) < 400
    ]
    if diagnostic:
        joined = "\n".join(diagnostic)
        return joined[-budget:] if len(joined) > budget else joined
    return "..." + text[-budget:]


# ---------------------------------------------------------------------------
# Stage-aware stuck detection (design section 2.2). Pure functions with no
# driver state, so the abort rule is testable without running a build.

STAGE_COMPILE = "compile"
STAGE_LINK_GATE = "link-gate"
STAGE_IMPORT_GATE = "import-gate"

# _emcc_build's import-whitelist branch is the only producer of this prefix.
IMPORT_GATE_PREFIX = "link gate:"


def classify_build_stage(error_text: str) -> str:
    """Which gate produced this failed build's error text.

    Progress signals are only comparable WITHIN a stage; crossing a stage
    boundary is progress by definition -- correctly #define-ing a missing
    symbol legitimately converts one link-gate line into N compile diagnostics
    at the use sites (unmasking, not regression). The stuck-abort rule
    therefore needs the stage, not just the fingerprint.
    """
    text = (error_text or "").lstrip()
    if text.startswith(IMPORT_GATE_PREFIX):
        return STAGE_IMPORT_GATE
    lowered = text.lower()
    if "undefined symbol" in lowered or "wasm-ld: error" in lowered:
        return STAGE_LINK_GATE
    return STAGE_COMPILE


def extract_error_lines(error_text: str) -> list[str]:
    """The `error:` diagnostic lines of a build's RAW output. Always the raw
    text, never the summary: a truncated summary could make two different
    error sets fingerprint identically."""
    return [line for line in (error_text or "").splitlines() if "error:" in line]


def count_error_lines(error_text: str) -> int:
    """Recorded per round only to select the best round later. Section 2.2
    explicitly DROPS the old `count increased => abort` rule: counts are not
    monotone under clang error recovery, and a correct fix can transiently
    increase them."""
    return len(extract_error_lines(error_text))


def normalise_diagnostic(line: str) -> str:
    """gnt4_shim.h-located diagnostics lose their line numbers.

    The model rewrites the whole header every round, so raw header line
    numbers churn even when the diagnostic itself is byte-identical -- which
    would mask true oscillation. unit.c locations keep file:line:col: the .c
    is verbatim and immovable, so a moved unit.c diagnostic is real change.
    """
    head, sep, tail = line.partition("error:")
    if sep and "gnt4_shim.h" in head:
        return "gnt4_shim.h:*: error:" + tail.rstrip()
    return line.strip()


def normalized_diagnostics(error_text: str) -> list[str]:
    """The sorted, deduplicated, normalised diagnostic lines of a build.

    This is the per-round set the post-mortem needs (design section 2.3
    [V4-4]): "never cleared" is the intersection of these sets across rounds,
    and cross-attempt oscillation detection is a fingerprint comparison.
    Gate messages (link gate / import gate) carry no `error:` lines, so they
    fall back to the full normalised text: their content is stable symbol
    names, not churning line numbers, and two different missing-symbol sets
    must not fingerprint identically.
    """
    lines = extract_error_lines(error_text)
    if not lines:
        lines = [line for line in (error_text or "").splitlines() if line.strip()]
    return sorted({normalise_diagnostic(line) for line in lines})


def diagnostic_fingerprint(error_text: str) -> str:
    """sha256 over the sorted, deduplicated, normalised `error:` lines."""
    return hashlib.sha256(
        "\n".join(normalized_diagnostics(error_text)).encode("utf-8")
    ).hexdigest()


def is_stuck(
    previous_stage: str | None,
    previous_fingerprint: str | None,
    stage: str,
    fingerprint: str,
    header_applied: bool,
) -> bool:
    """Section 2.2 abort rule: identical diagnostics after an APPLIED fix,
    within one stage. A stage transition NEVER aborts. A round that applied no
    new header (section 2.5 fallback) never compares -- identical input
    trivially yields identical output and proves nothing about the model."""
    return (
        header_applied
        and previous_fingerprint is not None
        and stage == previous_stage
        and fingerprint == previous_fingerprint
    )


# ---------------------------------------------------------------------------
# World-version (design section 2.8 [V4-3]): a mechanical hash of everything
# that could make a retry informationally different from the failed attempt.
# Every component is READ from the running system; nothing is declared by a
# human. A red unit is schedulable only when the current world-version differs
# from the one recorded at its verdict in AT LEAST ONE component.

# Version of the prompt content the compile-fix loop injects (SYSTEM_PROMPT
# plus any injected rules). BUMP RULE: increment whenever the instructions the
# model receives change SEMANTICALLY -- a new rule, a changed idiom, a
# reworded constraint. Pure typo/whitespace fixes that cannot change model
# behaviour do not count. Bumping it is a world-change: every zero-delta red
# becomes schedulable again, so bump deliberately, never casually.
# v2 (T2c): SYSTEM_PROMPT gained the registry authoritative/advisory block
# rules -- a semantic change by the bump rule.
# v3 (D5): the __gnt4_bitcast_f64 seed-helper rule (never redefine, wrap, or
# remove; a bare (double) cast in unit.c is a genuine value conversion) --
# the D5-5 world-delta that rides the transform landing.
PROMPT_VERSION = 3


def registry_version_component(repo_root: Path) -> int:
    """The knowledge registry's monotonic version counter (design section
    2.11), read from the tracked registry file. Absent file => 0, keeping the
    world-hash shape stable with pre-T2c verdicts. An unreadable registry
    raises in load_registry; HERE it degrades to 0 -- the gate must not take
    the selector down, and a corrupt registry surfaces loudly on the
    harvest/augment paths that actually need its content."""
    try:
        return registry_version(load_registry(Path(repo_root) / REGISTRY_RELPATH))
    except (ValueError, OSError):
        return 0


def serving_config_hash(model: str, context_length: int, timeout: int) -> str:
    """Hash of the serving configuration a verdict was reached under.

    Model id + served context length + request timeout: the three knobs whose
    change can make a previously impossible unit possible (the live
    counterexample: two context-budget reds verdicted at 32,768 served tokens
    were unschedulable forever under declared-ledger gating after serving
    moved to 262,144 -- design section 2.8's regression fixture).
    """
    return hashlib.sha256(
        f"{model}|{context_length}|{timeout}".encode("utf-8")
    ).hexdigest()


def _resolve_serving_timeout() -> int:
    """CUSTOM_API_TIMEOUT with the same .env-wins precedence as the rest of
    the port-model configuration (src/port_model_config.py)."""
    from src.port_model_config import read_env_file

    values = read_env_file()
    raw = values.get("CUSTOM_API_TIMEOUT") or os.environ.get("CUSTOM_API_TIMEOUT") or "120"
    try:
        return int(raw)
    except ValueError:
        return 120


def emcc_version_string(repo_root: Path) -> str:
    """The pinned emscripten toolchain version, read mechanically.

    Read from the emsdk checkout's version file rather than by invoking
    ``emcc --version`` -- sourcing the toolchain costs seconds and needs Git
    Bash, while the version file IS what the invocation would print. An
    absent/unreadable file degrades to "unknown" (still a stable component:
    the hash only needs to CHANGE when the toolchain does).
    """
    path = (
        Path(repo_root)
        / "research/tools/emsdk/upstream/emscripten/emscripten-version.txt"
    )
    try:
        text = path.read_text(encoding="utf-8-sig").strip().strip('"').strip()
        return text or "unknown"
    except OSError:
        return "unknown"


def driver_git_rev() -> str:
    """HEAD of the OGhidra checkout this driver is running from."""
    try:
        completed = subprocess.run(
            [
                "git", "-C", str(Path(__file__).resolve().parent.parent),
                "rev-parse", "HEAD",
            ],
            capture_output=True, text=True, timeout=30, creationflags=NO_WINDOW,
        )
        if completed.returncode == 0 and completed.stdout.strip():
            return completed.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return "unknown"


def compute_world_version(repo_root: Path, model_config: Any) -> dict[str, str]:
    """The five-component world-version recorded at verdict time.

    Kept as a component DICT rather than one flat hash so a later reader can
    see WHICH component moved (the §2.8 ordering heuristic and the post-mortem
    both want that); equality across all components is the zero-delta test.
    """
    return {
        "config_hash": serving_config_hash(
            getattr(model_config, "model", "") or "",
            getattr(model_config, "max_seq_length", 0) or 0,
            _resolve_serving_timeout(),
        ),
        "toolchain_hash": hashlib.sha256(
            emcc_version_string(repo_root).encode("utf-8")
        ).hexdigest(),
        "driver_rev": driver_git_rev(),
        "prompt_version": str(PROMPT_VERSION),
        "registry_version": str(registry_version_component(repo_root)),
    }


VOID_DECL = re.compile(r"^\s*void\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.M)


def void_result_contradictions(unit_source: str) -> list[str]:
    """Functions the file declares `void` yet assigns the result of.

    Ghidra sometimes emits a recursive helper as `void` while its own generated
    body uses the return value. Since the .c is verbatim and the `void`
    declaration lives in the same translation unit, NO header can reconcile it:
    declaring the function non-void collides with that declaration, declaring it
    void leaves the assignment invalid. auto-c0000-013 spent all 8 compile-fix
    iterations (~3.6 hours of model time) alternating between those two dead
    ends before failing.

    Conservative on purpose -- the caller settles the unit permanently, so this
    must be provable rather than heuristic. Only `x = fn(` counts; a bare call
    or a comparison does not.
    """
    contradictions = []
    for name in sorted(set(VOID_DECL.findall(unit_source))):
        if re.search(rf"=\s*{re.escape(name)}\s*\(", unit_source):
            contradictions.append(name)
    return contradictions


# ---------------------------------------------------------------------------
# Concrete-type structural classifier (design section 2.7, T3). Only the case
# actually observed is provable: a local declared in unit.c with a CONCRETE
# built-in type, cast to/from an incompatible concrete built-in type, where
# neither type involves any header-defined typedef or macro. Everything else
# stays retryable. F4's monthly recheck (f4-recheck CLI) is the falsifier: any
# settled unit that links on replay freezes this classifier back to the
# void-result detector.

# Tokens a provably header-independent type may consist of. Anything else
# (undefined4, byte, uint, a struct tag, ...) can be a header typedef, so the
# contradiction would not be provable from the verbatim .c alone.
CONCRETE_TYPE_TOKENS = frozenset(
    {"void", "char", "short", "int", "long", "float", "double",
     "signed", "unsigned", "const", "volatile"}
)
_C_KEYWORDS = frozenset(
    {"if", "else", "for", "while", "do", "return", "sizeof", "switch", "case",
     "break", "continue", "goto", "static", "extern", "register", "struct",
     "union", "enum", "typedef", "default"}
) | CONCRETE_TYPE_TOKENS

_UNIT_C_ERROR = re.compile(r"(?:^|[/\\])unit\.c:(\d+):\d+:\s*error:\s*(.*)$")
_QUOTED_TYPE = re.compile(r"'([^']+)'")


def _is_concrete_builtin_type(type_text: str) -> bool:
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", type_text)
    return bool(tokens) and all(token in CONCRETE_TYPE_TOKENS for token in tokens)


def _declared_concrete_local(identifier: str, unit_c_text: str) -> bool:
    """Is ``identifier`` declared somewhere in the verbatim .c with a type made
    only of concrete built-in tokens? Covers both local declarations
    (``char *local_68;``) and parameters (``int param_1``)."""
    pattern = re.compile(
        r"\b(?:(?:unsigned|signed|const|volatile)\s+)*"
        r"(?:char|short|int|long|float|double)(?:\s+(?:long|int))?"
        r"\s*\**\s*" + re.escape(identifier) + r"\b"
    )
    return bool(pattern.search(unit_c_text))


def concrete_type_contradictions(
    unit_c_text: str, rounds: list[dict[str, Any]]
) -> list[str]:
    """Section 2.7's concrete-type case, proven from the attempt's own rounds.

    A diagnostic qualifies only when ALL of these hold:
    - it survived EVERY round of the attempt (up to 4 different headers were
      applied and none removed it -- 'never cleared', the section 2.3 set
      intersection), so it is header-independent empirically;
    - it is a cast error located in unit.c whose quoted types are all
      concrete built-ins (no header typedef can be involved);
    - every identifier on the named source line is a C keyword/builtin or an
      identifier declared IN the verbatim .c with a concrete built-in type
      (no DAT_ symbol, no undefinedN local, no callee -- nothing a header
      could redeclare).
    Conservative on purpose: the caller settles the unit permanently.
    """
    if not rounds:
        return []
    common: set[str] | None = None
    for round_record in rounds:
        diagnostics = set(round_record.get("diagnostics") or [])
        common = diagnostics if common is None else (common & diagnostics)
    if not common:
        return []
    source_lines = unit_c_text.splitlines()
    proofs: list[str] = []
    for diagnostic in sorted(common):
        match = _UNIT_C_ERROR.search(diagnostic)
        if not match:
            continue
        line_number, message = int(match.group(1)), match.group(2)
        if "cast" not in message:
            continue
        quoted = _QUOTED_TYPE.findall(message)
        if not quoted or not all(_is_concrete_builtin_type(q) for q in quoted):
            continue
        if not (1 <= line_number <= len(source_lines)):
            continue
        source_line = source_lines[line_number - 1]
        identifiers = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", source_line))
        if not identifiers:
            continue
        provable = True
        for identifier in identifiers:
            if identifier in _C_KEYWORDS:
                continue
            if not _declared_concrete_local(identifier, unit_c_text):
                provable = False
                break
        if provable:
            proofs.append(
                f"unit.c:{line_number}: {message} (line: {source_line.strip()[:120]})"
            )
    return proofs


# ---------------------------------------------------------------------------
# Question escalation (design section 2.12, T3): mechanically-extracted inputs
# for the targeted-symbol question (a) and the diagnosis question (b), plus
# the post-mortem assembly both carry (section 2.3 -- string assembly from
# state, no LLM writes it).

TARGETED_MAX_SYMBOLS = 5
# Section 2.12(b): after this many MALFORMED diagnosis replies (no
# STRUCTURAL/FIXABLE verdict extractable) the question is recorded terminally
# UNPARSEABLE and never re-asked -- re-asking with near-identical inputs is
# the section 0.1 forbidden retry (T3 review F5). The STRUCTURAL
# deprioritisation itself is the LEADING _next_unit sort component (T3 review
# F4), not a cost constant: a structural-diagnosed red sinks behind ALL
# schedulable non-structural work across product_priority bands.
DIAGNOSIS_MALFORMED_LIMIT = 2
# Source diagnosis answers one narrow question: whether the compiler/linker
# failure can be repaired through the generated shim.  Promotion and control
# failures have no source-level evidence and must never spend this lane.
SOURCE_DIAGNOSIS_STAGES = frozenset({"compile-fix", "wasm-link"})

_SYMBOL_DIAG_PATTERNS = [
    re.compile(r"use of undeclared identifier '([A-Za-z_]\w*)'"),
    re.compile(r"call to undeclared function '([A-Za-z_]\w*)'"),
    re.compile(r"unknown type name '([A-Za-z_]\w*)'"),
    re.compile(r"undefined symbol:?\s+([A-Za-z_]\w*)"),
]
_IMPORT_GATE_LIST = re.compile(r"semantics:\s*(.+)$")


def _line_is_error_shaped(line: str) -> bool:
    lowered = line.lower()
    return (
        "error:" in lowered
        or "undefined symbol" in lowered
        or line.lstrip().startswith(IMPORT_GATE_PREFIX)
    )


def targeted_question_symbols(diagnostics: list[str]) -> list[str]:
    """The symbols the failed attempt's final diagnostics implicate -- or []
    when the attempt does not qualify for the targeted-symbol question.

    Qualifies only when every error-shaped diagnostic line yields at least one
    symbol (the failure is FULLY about missing/undeclared symbols; a partial
    match would leave part of the failure unaddressed by the narrow question)
    and the distinct symbols number 1..TARGETED_MAX_SYMBOLS.
    """
    symbols: set[str] = set()
    for line in diagnostics or []:
        if not _line_is_error_shaped(line):
            continue  # boilerplate/context lines carry no requirement
        found: set[str] = set()
        for pattern in _SYMBOL_DIAG_PATTERNS:
            found.update(pattern.findall(line))
        gate_list = _IMPORT_GATE_LIST.search(line)
        if gate_list:
            found.update(re.findall(r"[A-Za-z_]\w*", gate_list.group(1)))
        if not found:
            return []
        symbols.update(found)
    if not (1 <= len(symbols) <= TARGETED_MAX_SYMBOLS):
        return []
    return sorted(symbols)


def referencing_lines(unit_c_text: str, symbols: list[str], cap: int = 60) -> str:
    """The verbatim .c lines referencing any of ``symbols``, with line numbers
    -- the call-site evidence the targeted question shows instead of the whole
    unit. Mechanical extraction, no LLM."""
    patterns = [re.compile(rf"\b{re.escape(symbol)}\b") for symbol in symbols]
    picked: list[str] = []
    for number, line in enumerate(unit_c_text.splitlines(), start=1):
        if any(pattern.search(line) for pattern in patterns):
            picked.append(f"{number}: {line.rstrip()}")
            if len(picked) >= cap:
                break
    return "\n".join(picked)


def assemble_post_mortem(record: dict[str, Any]) -> str:
    """Section 2.3's post-mortem: 5-10 lines, mechanically extracted from the
    per-round records the loop already keeps. Prompt CONTENT for retries and
    escalation questions -- never a scheduling license ([V4-4])."""
    rounds = record.get("rounds") or []
    if not rounds:
        return ""
    stages = ", ".join(str(r.get("stage", "?")) for r in rounds)
    best = min(rounds, key=lambda r: r.get("error_count", 1 << 30))
    never_cleared: set[str] | None = None
    for round_record in rounds:
        diagnostics = set(round_record.get("diagnostics") or [])
        never_cleared = (
            diagnostics if never_cleared is None else (never_cleared & diagnostics)
        )
    world = record.get("world_version") or {}
    lines = [
        f"POST-MORTEM of attempt {record.get('attempts', '?')} (failed):",
        f"rounds: {len(rounds)}; stages: {stages}",
        f"best round: {best.get('iteration')} ({best.get('error_count')} errors)",
    ]
    for diagnostic in sorted(never_cleared or set())[:4]:
        lines.append(f"never cleared: {diagnostic[:200]}")
    lines.append(
        f"ending: {record.get('last_stage', '?')} -- "
        f"{(record.get('error') or '')[:200]}"
    )
    diagnosis = record.get("diagnosis") or {}
    if diagnosis.get("verdict") == "FIXABLE" and diagnosis.get("reason"):
        lines.append(f"diagnosis: FIXABLE -- {diagnosis['reason'][:200]}")
    lines.append(
        "world at failure: registry v"
        f"{world.get('registry_version', '?')}, prompt v"
        f"{world.get('prompt_version', '?')}"
    )
    return "\n".join(lines)


def merge_targeted_declarations(
    header_text: str, reply_block: str, symbols: list[str]
) -> str:
    """Merge a targeted-symbol reply into the (augmented) seed header: any
    existing logical line that #defines or declares one of the symbols is
    replaced (never duplicated -- the section 2.11 [V4-5] merge rule), and the
    reply block is appended in a marked section."""
    logical: list[str] = []
    buffer: list[str] = []
    for line in header_text.splitlines():
        buffer.append(line)
        if not line.rstrip().endswith("\\"):
            logical.append("\n".join(buffer))
            buffer = []
    if buffer:
        logical.append("\n".join(buffer))
    kept: list[str] = []
    for chunk in logical:
        first = chunk.lstrip()
        if any(
            re.match(rf"#\s*define\s+{re.escape(symbol)}\b", first)
            for symbol in symbols
        ):
            continue
        if (
            not first.startswith("#")
            and chunk.strip().endswith(";")
            and any(
                re.search(rf"\b{re.escape(symbol)}\s*[\(;,\[=]", chunk)
                for symbol in symbols
            )
        ):
            continue
        kept.append(chunk)
    return (
        "\n".join(kept).rstrip("\n")
        + "\n\n/* ==== TARGETED (design 2.12a): model-declared symbols: "
        + ", ".join(symbols)
        + " ==== */\n"
        + reply_block.strip()
        + "\n"
    )


DIAGNOSIS_SYSTEM_PROMPT = """You are the diagnosis stage of a Ghidra-C -> wasm port pipeline. A verbatim
Ghidra-decompiled C file has repeatedly failed to compile; only the support
header gnt4_shim.h may ever be edited, never the .c file.

Answer ONE question: why can no header fix this? Reply with exactly one line:
STRUCTURAL: <one-sentence reason> -- if the .c file itself is self-contradictory
and NO header content could make it compile, or
FIXABLE: <one-sentence reason> -- if some header content could fix it (say what
kind). No other text."""

_DIAGNOSIS_VERDICT = re.compile(r"\b(STRUCTURAL|FIXABLE)\b")


# ---------------------------------------------------------------------------
# Oracle-spec sidecar (oracle-workstream-plan.md section 3.4 [CF-2.14], T3
# verification queue): per-unit oracle commands live in a tracked sidecar,
# bound to an export set by exports_sha256 -- the queue unit's export set for
# the pending-unit overlay, the STAGED artifact's provenance for reverify.

ORACLE_SIDECAR_RELPATH = "research/decomp/data/oracle-commands.json"
ORACLE_SIDECAR_SCHEMA = 1

# S3/[R1] pattern discipline: the first pattern must be the anchored total
# line with the (?m) inline flag -- _run_oracle calls re.search with no flags
# on a multi-line log, so a bare-anchored pattern can never match.
SIDECAR_TOTAL_LINE = re.compile(
    r"^\(\?m\)\^ORACLE TOTAL functions=\d+/\d+ cases=\d+ "
    r"UNEXPLAINED: 0 VERDICT: PASS\$$"
)


def exports_sha256(exported_functions: list[str]) -> str:
    """sha256 of the sorted export set, the sidecar binding key (I-9)."""
    return hashlib.sha256(
        "\n".join(sorted(exported_functions)).encode("utf-8")
    ).hexdigest()


def oracle_entry_sha(entry: dict[str, Any]) -> str:
    """Content hash of one sidecar entry: a failed reverify is not repeated
    until the spec (or the wasm) changes -- the section 0.1 rule applied to
    oracle re-runs."""
    return hashlib.sha256(
        json.dumps(entry, sort_keys=True).encode("utf-8")
    ).hexdigest()


def validate_oracle_entry(
    name: str, entry: dict[str, Any], exports: list[str] | None = None
) -> list[str]:
    """The S3/I-5 sidecar discipline as code. Returns problem strings; an
    empty list means the entry is usable. ``exports`` (when known) enforces
    one per-function pattern per exported function."""
    problems: list[str] = []
    if not isinstance(entry, dict):
        return [f"{name}: entry is not an object"]
    sha = entry.get("exports_sha256")
    if not (isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha)):
        problems.append(f"{name}: exports_sha256 missing or not a sha256 hex")
    oracle = entry.get("oracle")
    if not isinstance(oracle, dict):
        return problems + [f"{name}: oracle missing"]
    command = oracle.get("command")
    if not (
        isinstance(command, list)
        and command
        and all(isinstance(part, str) for part in command)
    ):
        problems.append(f"{name}: oracle.command must be a non-empty string list")
    if not isinstance(oracle.get("cwd"), str) or not oracle.get("cwd"):
        problems.append(f"{name}: oracle.cwd missing")
    patterns = oracle.get("success_patterns")
    if not (isinstance(patterns, list) and patterns):
        return problems + [f"{name}: success_patterns required (I-5)"]
    if not SIDECAR_TOTAL_LINE.match(patterns[0]):
        problems.append(
            f"{name}: first pattern must be the (?m)-anchored total line (S3/[R1])"
        )
    for pattern in patterns:
        try:
            re.compile(pattern)
        except re.error as error:
            problems.append(f"{name}: invalid regex {pattern!r}: {error}")
            continue
        if ("^" in pattern or "$" in pattern) and not pattern.startswith("(?m)"):
            problems.append(
                f"{name}: anchored pattern without (?m) inline flag: {pattern!r}"
            )
    if exports:
        joined = "\n".join(patterns)
        for function in exports:
            if re.escape(function) not in joined and function not in joined:
                problems.append(f"{name}: no per-function pattern for {function}")
    return problems


def build_environment() -> dict:
    """PATH the emsdk toolchain actually needs, independent of the parent's.

    ``emsdk_env.sh`` execs ``python`` (emsdk line 39). A scheduled task running
    under an S4U principal inherits a bare system PATH with no python and no
    Git tools, so sourcing emsdk silently failed and emcc was never defined --
    surfacing as ``gate_failed at wasm-link`` against an innocent unit.

    Prepend the directory of the interpreter that is running us (guaranteed to
    contain python.exe) plus Git's POSIX tools, so the build does not depend on
    how the process was launched.
    """
    environment = dict(os.environ)
    extra = [str(Path(sys.executable).parent)]
    for candidate in GIT_BASH_CANDIDATES:
        usr_bin = candidate.parent.parent / "usr" / "bin"
        if usr_bin.is_dir():
            extra.append(str(usr_bin))
        if candidate.parent.is_dir():
            extra.append(str(candidate.parent))
    environment["PATH"] = os.pathsep.join(extra + [environment.get("PATH", "")])
    # emsdk_env.sh prints a multi-line PATH banner on every invocation. It is
    # noise for a non-interactive build, and it is worse than noise on failure:
    # it filled all 600 recorded characters of auto-c0000-000's link error and
    # pushed the actual linker diagnosis out of the record entirely.
    environment["EMSDK_QUIET"] = "1"
    return environment


def emcc_build_unit(
    repo_root: Path,
    workdir: Path,
    exports: list[str],
    allowed_extra: list[str] | None = None,
) -> tuple[bool, str]:
    """Build one unit.c to unit.wasm and run the import-whitelist gate.

    Module-level so the D5 gate-3 probe (src/port_d5_probe.py) rebuilds
    through the IDENTICAL emcc invocation the driver uses -- the probe must
    exercise the production build path, not a lookalike."""
    bash = resolve_bash()
    emsdk = repo_root / "research/tools/emsdk"
    # A demangled C++ export (`cCameraManager::HasCamera(cBaseCamera*)`) took
    # auto-c0000-011's whole build down with a bash syntax error on 2026-08-20:
    # '(' opened a subshell, and the ',' split one symbol into two invalid ones.
    # emcc can only export C identifiers, so anything else is dropped -- loudly,
    # since a silently missing export becomes a confusing link failure later.
    valid, dropped = [], []
    for name in exports:
        (valid if EXPORT_NAME.fullmatch(name) else dropped).append(name)
    if dropped:
        print(f"  skipping {len(dropped)} non-identifier export(s): "
              f"{', '.join(dropped[:3])}{' ...' if len(dropped) > 3 else ''}")
    exports_flag = ",".join("_" + name for name in valid)
    # Paths converted in Python (no cygpath dependency), and the emsdk
    # source is NOT silenced: a toolchain that failed to load must name
    # itself rather than surface as a bare "emcc: command not found"
    # charged to the unit as a wasm-link gate failure.
    script = (
        f"source \"{to_posix_path(emsdk)}/emsdk_env.sh\" >/dev/null || "
        "{ echo 'emsdk_env.sh failed to load' >&2; exit 127; }; "
        "command -v emcc >/dev/null || "
        "{ echo 'emcc not on PATH after sourcing emsdk_env.sh' >&2; exit 127; }; "
        f"cd \"{to_posix_path(workdir)}\" && "
        "emcc unit.c -O1 -fno-strict-aliasing --no-entry "
        "-Wno-implicit-function-declaration -Wno-int-conversion "
        "-Wno-deprecated-non-prototype "
        # Ghidra lowers `undefined` to `unsigned char`, so decompiled C passes
        # `undefined **` where `char **` is declared. clang 16+ makes that an
        # ERROR by default, which is the whole auto-c0000-* wasm-link failure
        # family. Same class of concession as the three flags above; the oracle
        # gate still enforces actual behaviour.
        "-Wno-incompatible-pointer-types -Wno-pointer-sign "
        # Section 2.2: clang stops after 19 errors by default, so two
        # DIFFERENT error sets could share a truncated prefix and
        # fingerprint identically. The stuck-abort fingerprint needs the
        # full set; the prompt still receives the deduplicated
        # summarise_build_error() summary, never this firehose.
        "-ferror-limit=0 "
        "-sERROR_ON_UNDEFINED_SYMBOLS=0 -sINITIAL_MEMORY=2155479040 "
        "-sALLOW_MEMORY_GROWTH=0 "
        f"-sEXPORTED_FUNCTIONS={shlex.quote(exports_flag)} "
        "-o unit.wasm"
    )
    completed = subprocess.run(
        [bash, "-lc", script],
        capture_output=True,
        text=True,
        timeout=BUILD_TIMEOUT_SECONDS,
        env=build_environment(),
     creationflags=NO_WINDOW)
    if completed.returncode != 0:
        return False, (completed.stderr + completed.stdout)[-6000:]
    bad = scan_disallowed_imports(workdir / "unit.wasm")
    # Auto-generated units may declare external callees (functions outside the
    # unit's extraction set). Those stay wasm imports by design — the JS side
    # stubs+logs them (auto-stub rule) — so they are whitelisted per unit.
    if allowed_extra:
        bad = [name for name in bad if name not in allowed_extra]
    # A ROM symbol whose ADDRESS is taken and stored into a dispatch slot --
    # `*(code **)(puVar1 + 0xc) = zz_01a4e90_;` -- imports exactly like a direct
    # callee, but the queue's allowed_extra_imports missed it: that list comes
    # from a regex requiring a following "(". The gate then demands the model
    # DEFINE a function whose body lives in another chunk, it can only answer
    # with a prototype, diagnostics repeat verbatim, and the unit reds as
    # "stuck: identical diagnostics after applied fix".
    #
    # Reading them out of unit.c is safe precisely because unit.c is VERBATIM
    # decompiler output that the model may never edit (see SYSTEM_PROMPT), so
    # every symbol here is a real ROM symbol rather than something invented in a
    # reply. Unresolved ones still fail later at the assembly gate, exactly as
    # whitelisted imports do -- this defers the failure to where cross-unit
    # ownership is actually decided, it does not hide it.
    #
    # port_unit_generator.py now collects these too; this stays as the path that
    # works against the CURRENT queue, which was generated before that fix.
    if bad:
        try:
            verbatim = (workdir / "unit.c").read_text(encoding="utf-8", errors="replace")
        except OSError:
            verbatim = ""
        if verbatim:
            address_taken = set(ADDRESS_TAKEN_SYMBOL.findall(verbatim))
            bad = [name for name in bad if name not in address_taken]
    if bad:
        return False, (
            "link gate: these symbols are UNDEFINED and became wasm imports, but "
            "they are not gnt4_* SDK functions, so they must be DEFINED in "
            f"gnt4_shim.h with correct PowerPC semantics: {', '.join(bad)}\n"
            "(Ghidra decompiler helper idioms like CONCAT44 must behave exactly "
            "as the original PPC code did.)"
        )
    return True, ""


class WasmUnitDriver:
    """Queue-driven wasm unit porter with the port_driver supervision contract."""

    def __init__(
        self,
        *,
        repo_root: str | Path | None = None,
        units_budget: int = 1,
        until_blocked: bool = False,
        llm: Any | None = None,
        build_runner: Any | None = None,
        oracle_runner: Any | None = None,
        git_runner: Any | None = None,
        journal: Any | None = None,
        assembly_link_runner: Any | None = None,
        assembly_smoke_runner: Any | None = None,
    ):
        self.repo_root = (
            Path(repo_root).resolve() if repo_root is not None else find_gotyaforce_root()
        )
        self.run_root = self.repo_root / "research/decomp/generated/finish-game-port"
        self.queue_path = self.run_root / "wasm-units.json"
        self.state_path = self.run_root / "wasm-units-state.json"
        self.work_root = self.run_root / "wasm-units"
        self.promotion_attempt_root = self.work_root / "_promotion-attempts"
        self.promotion_quarantine_root = self.work_root / "_promotion-quarantine"
        self.artifact_root = self.repo_root / "research/decomp/port-units"
        self.staging_root = self.repo_root / "research/decomp/port-units-staging"
        self.lock = DriverLock(self.run_root / "wasm-units.lock")
        self.run_id = os.getenv("OGHIDRA_PORT_RUN_ID") or utc_now()
        self.events = DriverEvents(self.run_root / "events.jsonl", self.run_id)
        self.units_budget = max(1, units_budget)
        self.until_blocked = until_blocked
        self._llm = llm
        self._build_runner = build_runner or self._emcc_build
        self._oracle_runner = oracle_runner or self._run_oracle
        self._git_runner = git_runner or self._git
        self._greens_this_run = 0
        # Remote workflow journal: one durable progress record per unit
        # transition, on the port-progress branch. Never allowed to fail a unit.
        self._journal = journal if journal is not None else journal_for(
            self.repo_root, run_root=self.run_root, run_id=self.run_id
        )
        self._previous_unit: str | None = None
        self._previous_result: str | None = None
        self._model_config = resolve_port_model_config()
        self._provider_paused_detail: str | None = None
        # World-version (section 2.8 [V4-3]): computed once per run -- the
        # serving config, toolchain, driver rev and prompt version cannot
        # change under a running driver, and git/emsdk reads are not free.
        # The REGISTRY component is the exception: this driver's own harvests
        # bump it mid-run (every green re-opens the reds its symbols touch),
        # so _world_version refreshes it from the file, mtime-cached.
        self._world_version_cache: dict[str, str] | None = None
        # Knowledge registry (section 2.11, T2c): tracked in-repo next to the
        # queue files (the [V4-8] gitignore negation exception makes the path
        # trackable inside the wholesale-ignored generated dir).
        self.registry_path = self.repo_root / REGISTRY_RELPATH
        self._registry_cache: tuple[float, dict[str, Any]] | None = None
        # product_priority sidecar (section 2.14 [V4-2]). Lives in the tracked
        # data dir, NOT under generated/finish-game-port/ (that directory is
        # wholesale-gitignored in GotYaForce, .gitignore:63). Absent file =>
        # every unit priority 0 => ordering unchanged.
        self.priority_path = self.repo_root / "research/decomp/data/unit-priority.json"
        self._unit_priorities: dict[str, int] | None = None
        # Continuous assembly gate (section 2.13 [V4-11], T2b): before a
        # candidate can become green, it is explicitly bound by name+digest
        # and linked with up to N-1 green/staged units. The ledger is durable
        # local evidence and never creates its own product-lineage commit.
        self.assembly_ledger_path = (
            self.repo_root / "research/decomp/data/assembly-gate.json"
        )
        self._assembly_link_runner = assembly_link_runner or self._emcc_link_many
        self._assembly_smoke_runner = assembly_smoke_runner or self._node_smoke
        # Oracle-spec sidecar (T3 verification queue; oracle plan section 3.4):
        # tracked in the data dir like the priority sidecar. Absent file =>
        # bit-identical current behaviour (every unit keeps its queue spec).
        self.oracle_sidecar_path = self.repo_root / ORACLE_SIDECAR_RELPATH
        self._oracle_sidecar_cache: tuple[float, dict[str, Any]] | None = None
        # (unit, kind) pairs already reported this run -- one oracle_spec_*
        # event per unit per run, not one per attempt.
        self._sidecar_reported: set[tuple[str, str]] = set()

    # ------------------------------------------------------------------- state

    def _load_queue(self) -> list[dict[str, Any]]:
        payload = json.loads(self.queue_path.read_text(encoding="utf-8-sig"))
        if payload.get("queue_schema") != QUEUE_SCHEMA:
            raise ValueError(f"wasm-units.json queue_schema != {QUEUE_SCHEMA}")
        units = payload.get("units")
        if not isinstance(units, list) or not units:
            raise ValueError("wasm-units.json has no units")
        return units

    def _load_state(self) -> dict[str, Any]:
        try:
            state = json.loads(self.state_path.read_text(encoding="utf-8-sig"))
            if state.get("state_schema") == STATE_SCHEMA:
                return state
        except FileNotFoundError:
            return {"state_schema": STATE_SCHEMA, "created_at": utc_now(), "units": {}}
        except (json.JSONDecodeError, OSError):
            state = None
        # An unreadable or wrong-schema state file holds every green verdict and
        # attempt count in the run. Starting fresh over it would silently re-port
        # and re-commit units that are already done, so keep a copy and say so.
        backup = self.state_path.with_name(
            f"{self.state_path.name}.unreadable-{utc_now().replace(':', '').replace('-', '')}"
        )
        try:
            shutil.copyfile(self.state_path, backup)
            print(
                f"WARNING: {self.state_path.name} was unreadable or a foreign schema "
                f"(found {state.get('state_schema') if isinstance(state, dict) else 'unparseable'}); "
                f"preserved at {backup.name} and starting a fresh state file"
            )
            self.events.emit("state_file_reset", backup=backup.name)
        except OSError as error:
            print(f"WARNING: could not preserve the previous state file: {error}")
        return {"state_schema": STATE_SCHEMA, "created_at": utc_now(), "units": {}}

    def _save_state(self, state: dict[str, Any]) -> None:
        state["updated_at"] = utc_now()
        atomic_write_json(self.state_path, state)

    def _unit_state(self, state: dict[str, Any], name: str) -> dict[str, Any]:
        return state["units"].setdefault(name, {"status": "pending", "attempts": 0})

    def _world_version(self) -> dict[str, str]:
        if self._world_version_cache is None:
            self._world_version_cache = compute_world_version(
                self.repo_root, self._model_config
            )
        # Registry component stays live: this run's own greens bump it.
        world = dict(self._world_version_cache)
        world["registry_version"] = str(registry_version(self._registry()))
        return world

    def _registry(self) -> dict[str, Any]:
        """The knowledge registry, mtime-cached (read per selector pass over
        1,396 units; re-read only when the file actually changed)."""
        try:
            mtime = self.registry_path.stat().st_mtime
        except OSError:
            mtime = -1.0
        if self._registry_cache is None or self._registry_cache[0] != mtime:
            try:
                self._registry_cache = (mtime, load_registry(self.registry_path))
            except (ValueError, OSError) as error:
                # A corrupt registry must not take the driver down; it
                # surfaces as an event and the run proceeds registry-less
                # (advisory means losing it costs warmth, never correctness).
                self.events.emit("registry_unreadable", error=str(error)[:400])
                from src.port_knowledge_registry import empty_registry

                self._registry_cache = (mtime, empty_registry())
        return self._registry_cache[1]

    def _save_registry(self, registry: dict[str, Any]) -> None:
        save_registry(self.registry_path, registry)
        self._registry_cache = None  # force re-read; mtime moved

    def _unit_priority(self, name: str) -> int:
        """product_priority from the sidecar (section 2.14): higher serves
        first; a missing file or an unmapped unit is priority 0."""
        if self._unit_priorities is None:
            try:
                payload = json.loads(self.priority_path.read_text(encoding="utf-8-sig"))
                # Either {"priorities": {unit: int}} (the generator's shape,
                # with provenance metadata alongside) or a flat {unit: int}.
                mapping = payload.get("priorities", payload) if isinstance(payload, dict) else {}
                self._unit_priorities = {
                    str(unit): int(value)
                    for unit, value in mapping.items()
                    if isinstance(value, (int, float, str)) and str(value).lstrip("-").isdigit()
                }
            except (FileNotFoundError, json.JSONDecodeError, OSError, ValueError, AttributeError):
                self._unit_priorities = {}
        return self._unit_priorities.get(name, 0)

    # ---------------------------------------------------- oracle-spec sidecar

    def _oracle_sidecar(self) -> dict[str, Any]:
        """The oracle-commands sidecar's units map, mtime-cached. A malformed
        file degrades to {} with one event -- the sidecar must never take the
        selector down (same posture as the priority sidecar)."""
        try:
            mtime = self.oracle_sidecar_path.stat().st_mtime
        except OSError:
            mtime = -1.0
        if self._oracle_sidecar_cache is None or self._oracle_sidecar_cache[0] != mtime:
            units: dict[str, Any] = {}
            if mtime >= 0:
                try:
                    payload = json.loads(
                        self.oracle_sidecar_path.read_text(encoding="utf-8-sig")
                    )
                    if payload.get("spec_schema") != ORACLE_SIDECAR_SCHEMA:
                        raise ValueError(
                            f"spec_schema != {ORACLE_SIDECAR_SCHEMA}"
                        )
                    units = payload.get("units") or {}
                    if not isinstance(units, dict):
                        raise ValueError("units is not an object")
                except (json.JSONDecodeError, OSError, ValueError) as error:
                    units = {}
                    self.events.emit(
                        "oracle_sidecar_unreadable", error=str(error)[:400]
                    )
            self._oracle_sidecar_cache = (mtime, units)
        return self._oracle_sidecar_cache[1]

    def _sidecar_report_once(self, unit_name: str, kind: str, **payload: Any) -> None:
        if (unit_name, kind) in self._sidecar_reported:
            return
        self._sidecar_reported.add((unit_name, kind))
        self.events.emit(kind, unit=unit_name, **payload)

    def _effective_oracle(self, unit: dict[str, Any]) -> dict[str, Any] | None:
        """The oracle spec this attempt runs under: the sidecar entry overlays
        the queue spec IFF its exports_sha256 matches the queue unit's current
        export set (I-9). Absent file, absent entry, invalid entry, or hash
        mismatch => the unit keeps its queue spec -- bit-identical current
        behaviour; a mismatch additionally journals oracle_spec_stale so
        drift is visible, not silent."""
        name = unit["name"]
        entry = self._oracle_sidecar().get(name)
        if not entry:
            return unit.get("oracle")
        exports = unit.get("exported_functions") or []
        problems = validate_oracle_entry(name, entry, exports=exports)
        if problems:
            self._sidecar_report_once(
                name, "oracle_spec_invalid", problems=problems[:5]
            )
            return unit.get("oracle")
        if entry.get("exports_sha256") != exports_sha256(exports):
            self._sidecar_report_once(
                name, "oracle_spec_stale", binding="queue_exports"
            )
            return unit.get("oracle")
        self._sidecar_report_once(name, "oracle_spec_overlaid")
        return json.loads(json.dumps(entry["oracle"]))

    # ----------------------------------------------------------------- control

    def _control_command(self) -> str:
        try:
            return json.loads(
                (self.run_root / "control.json").read_text(encoding="utf-8-sig")
            ).get("command", "run")
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return "run"

    def _heartbeat(self, status: str) -> None:
        """Keep llm-liveness.json fresh between LLM calls (the CustomAPIClient
        owns it during streaming). Merge-update so client metrics survive."""
        path_value = os.getenv("OGHIDRA_PORT_LIVENESS_PATH")
        if not path_value:
            return
        path = Path(path_value)
        try:
            payload = json.loads(path.read_text(encoding="utf-8-sig"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            payload = {}
        payload.update(
            {
                "run_id": self.run_id,
                "status": status,
                "active": not status.endswith(":idle"),
                # UTC-Z, like every sibling stamp in this file. A naive local
                # stamp here made every consumer diffing against UTC see a
                # constant multi-hour staleness.
                "updated_at": utc_now(),
            }
        )
        try:
            atomic_write_json(path, payload)
        except OSError:
            pass  # telemetry never blocks port work

    def _write_progress(
        self,
        state: dict[str, Any],
        status: str,
        *,
        unit: str | None = None,
        run_state: str = "progressing",
    ) -> None:
        units = state.get("units", {})
        greens = sum(1 for record in units.values() if record.get("status") == "green")
        # Section 3 metric split: verified_green vs staged. Progress toward G1
        # is the verified count; staged compile-only greens are inventory.
        verified = sum(
            1
            for record in units.values()
            if record.get("status") == "green"
            and record.get("tier") == "oracle_green"
        )
        total = max(len(units), 1)
        payload = {
            "run_schema": 3,
            "run_mode": "driver",
            "objective": "Port verbatim Ghidra C units to oracle-gated wasm (wasm_units mode)",
            "run_id": self.run_id,
            "status": status,
            # Section 2.8 [V4-3] run-state semantics: progressing |
            # waiting_world_change | provider_paused. A run-state FIELD, not a
            # new exit code -- exit codes stay frozen until Phase 3 (section
            # 2.9); the supervisor keeps reading the file it already reads.
            "run_state": run_state,
            "updated_at": utc_now(),
            "progress": {
                "completed_work": greens,
                "total_work": len(units),
                "percent": greens / total * 100.0,
            },
            "counters": {
                "units_integrated": greens,
                "units_verified": verified,
                "units_staged": greens - verified,
                "units_known": len(units),
                "model_requests_total": sum(
                    record.get("model_requests", 0) for record in units.values()
                ),
                # Section 4 registry rows (T2c): version for delta-watching,
                # contested count for the >5%-of-dat_typing page threshold.
                "registry_version": registry_version(self._registry()),
                "registry_contested": sum(
                    1
                    for entry in (self._registry().get("entries") or {}).values()
                    if entry.get("contested")
                ),
            },
            "queue": [
                {"family": name, "status": record.get("status", "pending")}
                for name, record in units.items()
                if record.get("status") != "green"
            ][:5],
        }
        if unit is not None:
            payload["unit"] = unit
        atomic_write_json(self.run_root / "run-state.json", payload)
        self.events.emit("progress", **payload["counters"])

    def _flag_unverified_inventory(self, state: dict[str, Any]) -> None:
        """Section 4 T3 invariant row: page when the verified fraction falls
        while staged grows -- unverifiable-inventory build-up. The previous
        mark rides the state file so the comparison survives runs."""
        units = state.get("units", {})
        verified = sum(
            1
            for record in units.values()
            if record.get("status") == "green"
            and record.get("tier") == "oracle_green"
        )
        staged = sum(
            1
            for record in units.values()
            if record.get("status") == "green"
            and record.get("tier") != "oracle_green"
        )
        fraction = verified / max(verified + staged, 1)
        previous = state.get("verified_fraction_mark") or {}
        if (
            previous  # first mark is a baseline, not a comparison
            and staged > int(previous.get("staged", 0))
            and fraction < float(previous.get("fraction", 1.0))
        ):
            self.events.emit(
                "unverified_inventory_buildup",
                verified=verified,
                staged=staged,
                fraction=round(fraction, 4),
                previous_fraction=previous.get("fraction"),
            )
        state["verified_fraction_mark"] = {
            "verified": verified,
            "staged": staged,
            "fraction": round(fraction, 4),
            "at": utc_now(),
        }
        self._save_state(state)

    # ---------------------------------------------------------------- progress

    def _checkpoint(
        self,
        state: dict[str, Any],
        transition: UnitTransition | None,
        *,
        current_unit: str | None = None,
        current_stage: str | None = None,
        current_attempt: int = 0,
        workflow_state: str = "running",
        driver_running: bool = True,
        require_progress_push: bool = False,
    ) -> bool:
        """Emit one progress checkpoint and report whether it is durable.

        Called at EVERY unit transition, before the selector moves on -- the
        unit-transition invariant. A git/network fault degrades to a recorded
        pending push. Assembly verdict callers use the boolean to fail closed
        when even the local transition record could not be written.
        """
        machine = MachineState(
            workflow_state=workflow_state,
            driver_status="running" if driver_running else "stopped",
            manual_paused=workflow_state == "manual_paused",
            configured_model=self._model_config.model,
            active_model=self._model_config.model if driver_running else None,
            context_length=(
                self._model_config.max_seq_length or None
                if driver_running
                else None
            ),
        )
        try:
            result = self._journal.checkpoint(
                transition=transition,
                units=state.get("units", {}),
                machine=machine,
                previous_unit=self._previous_unit,
                previous_result=self._previous_result,
                current_unit=current_unit,
                current_stage=current_stage,
                current_attempt=current_attempt,
                driver_running=driver_running,
            )
        except Exception as error:  # noqa: BLE001 - telemetry is never fatal
            self.events.emit("progress_checkpoint_failed", error=str(error)[:400])
            return False
        durable = not isinstance(result, dict) or bool(result.get("recorded", True))
        if require_progress_push:
            durable = bool(
                isinstance(result, dict)
                and result.get("recorded")
                and result.get("committed")
                and result.get("pushed")
            )
        if not durable:
            self.events.emit(
                "progress_checkpoint_failed",
                error=str(
                    result.get("detail")
                    if isinstance(result, dict)
                    else "journal did not return a durable receipt"
                )[:400],
            )
            return False
        if transition is not None:
            self._previous_unit = transition.unit
            self._previous_result = transition.result
        return True

    @staticmethod
    def _project_record_update(
        state: dict[str, Any], name: str, record_update: dict[str, Any]
    ) -> dict[str, Any]:
        """Copy the canonical state with one projected unit record update."""
        projected = dict(state)
        units = dict(state.get("units", {}))
        record = dict(units.get(name, {}))
        record.update(record_update)
        units[name] = record
        projected["units"] = units
        return projected

    # --------------------------------------------------------------------- llm

    def _llm_client(self) -> Any:
        if self._llm is None:
            from src.config import get_config
            from src.custom_api_client import CustomAPIClient

            self._llm = CustomAPIClient(get_config().custom_api)
        return self._llm

    def _compile_fix(
        self,
        unit_c: str,
        header: str,
        errors: str,
        *,
        unit_name: str = "",
        format_reminder: bool = False,
    ) -> str | None:
        """One LLM round; returns the corrected header text or None.

        format_reminder is the section-2.5 re-ask: the same prompt, plus one
        line telling the model its previous reply carried no usable code block.
        """
        prompt = (
            f"Verbatim decompiled C (read-only):\n```c\n{unit_c}\n```\n\n"
            f"Current gnt4_shim.h:\n```c\n{header}\n```\n\n"
            f"Compiler output (deduplicated):\n```\n{errors}\n```\n\n"
            + (
                "Your previous reply contained no usable ```c code block. "
                "Reply with ONLY the complete corrected gnt4_shim.h in a "
                "single ```c block.\n"
                if format_reminder
                else ""
            )
            + "Return the complete corrected gnt4_shim.h."
        )
        reply = self._llm_client().generate(
            prompt=prompt,
            system_prompt=SYSTEM_PROMPT + (" /no_think" if DISABLE_THINKING else ""),
            max_tokens=COMPILE_FIX_MAX_TOKENS,
            phase=f"wasm_compile_fix:{unit_name}",
            # Stream for two reasons, both learned the hard way (same as
            # port_chunk_workflow's analysis call):
            # 1. liveness telemetry (current_completion_tokens,
            #    tokens_per_second) only updates mid-request on the streaming
            #    path -- non-streamed, a 23-minute generation reports
            #    "out 0 tok, 0.0 tok/s" the whole time, is indistinguishable
            #    from a hang, and false-fires the rig monitor's 20-minute
            #    staleness rule on every long call;
            # 2. requests' read timeout is time-between-BYTES; with no stream
            #    a generation longer than CUSTOM_API_TIMEOUT dies even though
            #    the server is healthy and working.
            # The callback itself has nothing to do -- the client's metrics
            # wrapper does the liveness accounting.
            stream_callback=lambda _event_type, _event: None,
            **SAMPLING,
            # Belt and braces, same as the source loop: the template kwarg is
            # honoured by llama.cpp/vLLM/SGLang and ignored elsewhere, and the
            # Qwen `/no_think` soft switch covers the rest.
            **(
                {"chat_template_kwargs": {"enable_thinking": False}}
                if DISABLE_THINKING
                else {}
            ),
        )
        matches = CODE_BLOCK.findall(reply or "")
        if not matches:
            # An UNCLOSED fence is recoverable and common: auto-c0001-001 emitted
            # 7,466 chars of correct header behind a ```c that was never closed,
            # and the entire round was discarded over a missing terminator. Take
            # the body anyway -- if it is truly truncated the next compile names
            # the error and the loop iterates, which beats losing the round.
            opened = OPEN_FENCE.search(reply or "")
            if opened and (reply or "").count("```") == 1:
                body = (reply or "")[opened.end():].strip()
                if body:
                    self._last_reply_shape = None
                    return body
            # Keep the shape of the reply: "no code block" with no evidence is
            # unactionable, and the interesting cases (refusal, prose, unfenced
            # header, truncation) are indistinguishable without it.
            body = (reply or "").strip()
            self._last_reply_shape = (
                f"len={len(body)} fences={body.count('```')} "
                f"head={body[:200]!r} tail={body[-120:]!r}"
                if body else "empty reply"
            )
            return None
        self._last_reply_shape = None
        return max(matches, key=len)

    # ------------------------------------------------------------------- build

    def _emcc_build(
        self,
        workdir: Path,
        exports: list[str],
        allowed_extra: list[str] | None = None,
    ) -> tuple[bool, str]:
        return emcc_build_unit(self.repo_root, workdir, exports, allowed_extra)

    # ---------------------------------------------------------- assembly gate

    def _emcc_link_many(
        self,
        workdir: Path,
        c_files: list[str],
        exports: list[str],
        allowed_extra: list[str],
    ) -> tuple[bool, str]:
        """One emcc invocation over N units' .c files together (section 2.13):
        merged header, the same shared flat arena every unit already assumes,
        externs deduplicated at the language level. Mirrors _emcc_build's
        flags exactly -- the gate must not pass under laxer settings than the
        per-unit build."""
        bash = resolve_bash()
        emsdk = self.repo_root / "research/tools/emsdk"
        valid = [name for name in exports if EXPORT_NAME.fullmatch(name)]
        exports_flag = ",".join("_" + name for name in valid)
        sources = " ".join(shlex.quote(name) for name in c_files)
        script = (
            f"source \"{to_posix_path(emsdk)}/emsdk_env.sh\" >/dev/null || "
            "{ echo 'emsdk_env.sh failed to load' >&2; exit 127; }; "
            "command -v emcc >/dev/null || "
            "{ echo 'emcc not on PATH after sourcing emsdk_env.sh' >&2; exit 127; }; "
            f"cd \"{to_posix_path(workdir)}\" && "
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
            [bash, "-lc", script],
            capture_output=True,
            text=True,
            timeout=BUILD_TIMEOUT_SECONDS,
            env=build_environment(),
            creationflags=NO_WINDOW,
        )
        if completed.returncode != 0:
            return False, (completed.stderr + completed.stdout)[-8000:]
        bad = scan_disallowed_imports(workdir / ASSEMBLY_WASM)
        bad = [name for name in bad if name not in set(allowed_extra)]
        # Same address-taken allowance as the per-unit gate, for the same
        # reason: a symbol stored into a dispatch slot rather than called is
        # missing from allowed_extra_imports, because that list comes from a
        # regex requiring a following "(". Keeping the two gates symmetric is
        # this function's stated contract -- it must not be LAXER than the
        # per-unit build, and after the per-unit fix it was stricter, which
        # turned units that now link individually into assembly-gate reds
        # (auto-c0053-012 on FUN_80047aa4 and FUN_801b9adc, both written as
        # `*(code **)(slot) = FUN_...;`).
        if bad:
            address_taken: set[str] = set()
            for c_name in c_files:
                try:
                    text = (workdir / c_name).read_text(
                        encoding="utf-8", errors="replace"
                    )
                except OSError:
                    continue
                address_taken.update(ADDRESS_TAKEN_SYMBOL.findall(text))
            bad = [name for name in bad if name not in address_taken]
        if bad:
            return False, (
                "link gate: these symbols are UNDEFINED across the assembled "
                "units and became wasm imports, but they are neither gnt4_* SDK "
                "functions nor whitelisted external callees: " + ", ".join(bad)
            )
        return True, ""

    def _node_smoke(self, wasm_path: Path) -> tuple[bool, str]:
        """Instantiation smoke under node: the gate passes iff the linked
        module LOADS. No behaviour asserted (that stays the oracle tier)."""
        # .cjs, not .js: the repo's package.json declares "type": "module",
        # which makes node treat any .js under it as ESM and reject require().
        script_path = wasm_path.parent / "assembly-smoke.cjs"
        script_path.write_text(SMOKE_JS, encoding="utf-8", newline="\n")
        completed = subprocess.run(
            [resolve_node_exe(), str(script_path), str(wasm_path)],
            capture_output=True,
            text=True,
            timeout=300,
            creationflags=NO_WINDOW,
        )
        log = completed.stdout + (
            "\n--- stderr ---\n" + completed.stderr if completed.stderr else ""
        )
        return completed.returncode == 0 and "ASSEMBLY_SMOKE_OK" in completed.stdout, log

    # ------------------------------------------------------- promotion attempt

    def _promotion_marker(self, attempt_dir: Path) -> dict[str, Any] | None:
        """Return a validated ownership marker for one private attempt."""
        try:
            if attempt_dir.is_symlink() or (
                hasattr(attempt_dir, "is_junction") and attempt_dir.is_junction()
            ):
                return None
            marker = json.loads(
                (attempt_dir / ".promotion-attempt.json").read_text(
                    encoding="utf-8-sig"
                )
            )
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return None
        if not isinstance(marker, dict):
            return None
        if marker.get("schema") != PROMOTION_ATTEMPT_SCHEMA:
            return None
        if marker.get("attempt_id") != attempt_dir.name:
            return None
        try:
            if attempt_dir.resolve().parent != self.promotion_attempt_root.resolve():
                return None
        except OSError:
            return None
        return marker

    def _create_promotion_attempt(
        self,
        *,
        name: str,
        attempt: int,
        workdir: Path,
        provenance: dict[str, Any],
        destination: Path,
    ) -> PromotionTransaction:
        """Copy a publish candidate into a private, ownership-marked attempt.

        Nothing under the authoritative artifact roots exists until T2b binds
        and passes this exact candidate digest.
        """
        self.promotion_attempt_root.mkdir(parents=True, exist_ok=True)
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", name).strip(".-") or "unit"
        attempt_id = f"{safe_name}-a{attempt}-{uuid.uuid4().hex}"
        attempt_dir = self.promotion_attempt_root / attempt_id
        artifact_preimage_exists = destination.exists()
        if artifact_preimage_exists and (
            destination.is_symlink()
            or (hasattr(destination, "is_junction") and destination.is_junction())
        ):
            raise RuntimeError("artifact destination is a link")
        attempt_dir.mkdir(exist_ok=False)
        artifact_preimage_sha256 = (
            unit_artifact_sha256(destination)
            if artifact_preimage_exists and destination.is_dir()
            else None
        )
        atomic_write_json(
            attempt_dir / ".promotion-attempt.json",
            {
                "schema": PROMOTION_ATTEMPT_SCHEMA,
                "attempt_id": attempt_id,
                "unit": name,
                "attempt": attempt,
                "run_id": self.run_id,
                "created_at": utc_now(),
                "phase": "creating",
                "destination": destination.relative_to(self.repo_root).as_posix(),
                "transaction_id": uuid.uuid4().hex,
                "artifact_preimage": {
                    "exists": artifact_preimage_exists,
                    "sha256": artifact_preimage_sha256,
                },
            },
        )
        candidate_dir = attempt_dir / "candidate"
        candidate_dir.mkdir()
        for file_name in ("unit.c", "gnt4_shim.h", "unit.wasm", "oracle.log"):
            shutil.copyfile(workdir / file_name, candidate_dir / file_name)
        atomic_write_json(candidate_dir / "provenance.json", provenance)
        candidate = load_unit_artifact(candidate_dir)
        if candidate is None or candidate.name != name:
            raise RuntimeError(f"private promotion candidate invalid for {name}")
        self._update_promotion_marker(
            attempt_dir,
            phase="candidate-private",
            candidate_sha256=candidate.sha256,
        )
        return PromotionTransaction(attempt_dir, candidate, destination)

    def _update_promotion_marker(self, attempt_dir: Path, **updates: Any) -> None:
        marker = self._promotion_marker(attempt_dir)
        if marker is None:
            raise RuntimeError(f"promotion attempt lost ownership: {attempt_dir}")
        marker.update(updates)
        marker["updated_at"] = utc_now()
        atomic_write_json(attempt_dir / ".promotion-attempt.json", marker)

    def _promotion_destination(self, marker: dict[str, Any]) -> Path | None:
        raw = marker.get("destination")
        unit = str(marker.get("unit") or "")
        if not isinstance(raw, str) or not unit:
            return None
        try:
            destination = Path(os.path.abspath(self.repo_root / raw))
            allowed = {
                Path(os.path.abspath(self.artifact_root / unit)),
                Path(os.path.abspath(self.staging_root / unit)),
            }
        except OSError:
            return None
        if destination not in allowed:
            return None
        if destination.is_symlink() or (
            hasattr(destination, "is_junction") and destination.is_junction()
        ):
            return None
        try:
            if destination.parent.resolve() not in {
                self.artifact_root.resolve(), self.staging_root.resolve()
            }:
                return None
        except OSError:
            return None
        return destination

    @staticmethod
    def _file_sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _capture_registry_preimage(self, transaction: PromotionTransaction) -> None:
        marker = self._promotion_marker(transaction.attempt_dir)
        if marker is None:
            raise RuntimeError("promotion marker unavailable before registry mutation")
        if marker.get("registry_preimage") is not None:
            return
        exists = self.registry_path.is_file()
        sha256 = self._file_sha256(self.registry_path) if exists else None
        backup = transaction.attempt_dir / "registry.preimage"
        if exists:
            shutil.copyfile(self.registry_path, backup)
            if self._file_sha256(backup) != sha256:
                raise RuntimeError("registry preimage backup verification failed")
        self._update_promotion_marker(
            transaction.attempt_dir,
            registry_preimage={
                "exists": exists,
                "sha256": sha256,
                "backup": backup.name if exists else None,
            },
        )

    def _record_registry_postimage(self, transaction: PromotionTransaction) -> None:
        self._update_promotion_marker(
            transaction.attempt_dir,
            registry_postimage={
                "exists": self.registry_path.is_file(),
                "sha256": (
                    self._file_sha256(self.registry_path)
                    if self.registry_path.is_file()
                    else None
                ),
            },
            phase="registry-saved",
        )

    def _restore_registry_preimage(self, marker: dict[str, Any], attempt_dir: Path) -> None:
        preimage = marker.get("registry_preimage")
        if not isinstance(preimage, dict):
            return
        postimage = marker.get("registry_postimage")
        current_exists = self.registry_path.is_file()
        current_sha = self._file_sha256(self.registry_path) if current_exists else None
        if isinstance(postimage, dict):
            if (
                current_exists != bool(postimage.get("exists"))
                or current_sha != postimage.get("sha256")
            ):
                raise RuntimeError("registry changed outside promotion transaction")
        elif (
            current_exists != bool(preimage.get("exists"))
            or current_sha != preimage.get("sha256")
        ):
            raise RuntimeError(
                "registry mutation lacks a durable postimage; refusing blind rollback"
            )
        if preimage.get("exists"):
            backup = attempt_dir / str(preimage.get("backup") or "")
            if (
                not backup.is_file()
                or self._file_sha256(backup) != preimage.get("sha256")
            ):
                raise RuntimeError("registry preimage backup is missing or corrupt")
            self.registry_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.registry_path.with_name(
                f".{self.registry_path.name}.promotion-restore-{uuid.uuid4().hex}"
            )
            shutil.copyfile(backup, temporary)
            os.replace(temporary, self.registry_path)
        elif self.registry_path.exists():
            self.registry_path.unlink()
        self._registry_cache = None

    def _rollback_artifact_precommit(
        self, marker: dict[str, Any], attempt_dir: Path
    ) -> None:
        destination = self._promotion_destination(marker)
        if destination is None:
            raise RuntimeError("promotion marker has invalid artifact destination")
        candidate_dir = attempt_dir / "candidate"
        preimage = marker.get("artifact_preimage") or {}
        if preimage.get("exists"):
            expected_preimage = preimage.get("sha256")
            replacement = marker.get("replacement_authorization")
            if not isinstance(replacement, dict):
                if not destination.is_dir():
                    raise RuntimeError("artifact preimage disappeared during transaction")
                if unit_artifact_sha256(destination) != expected_preimage:
                    raise RuntimeError("artifact preimage changed during transaction")
                return

            backup_name = replacement.get("backup")
            if backup_name != "artifact.preimage":
                raise RuntimeError("replacement preimage backup is not owned")
            backup = attempt_dir / backup_name
            candidate_sha = marker.get("candidate_sha256")
            destination_sha = (
                unit_artifact_sha256(destination) if destination.is_dir() else None
            )
            backup_sha = unit_artifact_sha256(backup) if backup.is_dir() else None

            # Before the first rename the authoritative preimage is untouched.
            if (
                destination_sha == expected_preimage
                and not backup.exists()
                and candidate_dir.is_dir()
            ):
                return
            # Crash gap: old destination was detached, candidate not installed.
            if (
                not destination.exists()
                and backup_sha == expected_preimage
                and candidate_dir.is_dir()
            ):
                backup.rename(destination)
            # Crash gap: candidate installed, marker write not yet durable.
            elif (
                destination_sha == candidate_sha
                and backup_sha == expected_preimage
                and not candidate_dir.exists()
            ):
                destination.rename(candidate_dir)
                backup.rename(destination)
            else:
                raise RuntimeError(
                    "replacement rollback found an ambiguous artifact state"
                )
            if (
                unit_artifact_sha256(destination) != expected_preimage
                or backup.exists()
                or not candidate_dir.is_dir()
                or unit_artifact_sha256(candidate_dir) != candidate_sha
            ):
                raise RuntimeError("replacement rollback did not restore preimage")
            return
        if candidate_dir.is_dir() and not destination.exists():
            return
        if not candidate_dir.exists() and destination.is_dir():
            if unit_artifact_sha256(destination) != marker.get("candidate_sha256"):
                raise RuntimeError("installed artifact changed before rollback")
            destination.rename(candidate_dir)
            if destination.exists() or not candidate_dir.is_dir():
                raise RuntimeError("artifact rollback did not complete")
            return
        raise RuntimeError("artifact rollback found an ambiguous preimage state")

    def _quarantine_transaction(
        self, attempt_dir: Path, marker: dict[str, Any], *, phase: str
    ) -> Path:
        self._update_promotion_marker(attempt_dir, phase=phase)
        marker = self._promotion_marker(attempt_dir) or marker
        self.promotion_quarantine_root.mkdir(parents=True, exist_ok=True)
        destination = self.promotion_quarantine_root / (
            f"{attempt_dir.name}-{phase}-{uuid.uuid4().hex}"
        )
        os.replace(attempt_dir, destination)
        if attempt_dir.exists() or not destination.is_dir():
            raise RuntimeError("promotion quarantine move did not complete")
        self.events.emit(
            "promotion_transaction_quarantined",
            unit=marker.get("unit"),
            transaction_id=marker.get("transaction_id"),
            phase=phase,
            quarantine=str(destination)[:400],
        )
        return destination

    def _promotion_phase_boundary(
        self, phase: str, transaction: PromotionTransaction
    ) -> None:
        """Fault-injection seam; production intentionally does nothing."""
        _ = (phase, transaction)

    def _rollback_uncommitted_transaction(
        self, transaction: PromotionTransaction, *, reason: str
    ) -> None:
        marker = self._promotion_marker(transaction.attempt_dir)
        if marker is None:
            raise RuntimeError("cannot roll back promotion without ownership marker")
        head_preimage = marker.get("head_preimage")
        if head_preimage:
            current = self._git_runner("rev-parse", "HEAD")
            if current.returncode != 0 or current.stdout.strip() != head_preimage:
                raise RuntimeError(
                    "local HEAD moved after commit intent; transaction must finalize"
                )
        self._restore_registry_preimage(marker, transaction.attempt_dir)
        self._rollback_artifact_precommit(marker, transaction.attempt_dir)
        paths = marker.get("commit_paths") or []
        if paths:
            reset = self._git_runner("reset", "-q", "HEAD", "--", *paths)
            if reset.returncode != 0:
                raise RuntimeError("promotion index rollback failed")
            cached = self._git_runner("diff", "--cached", "--quiet", "--", *paths)
            if cached.returncode != 0:
                raise RuntimeError("promotion paths remain staged after rollback")
        self._quarantine_transaction(
            transaction.attempt_dir,
            marker,
            phase=f"rolled-back-{re.sub(r'[^a-z0-9-]+', '-', reason.lower())}",
        )

    def _validate_or_adopt_prepared_commit(
        self,
        attempt_dir: Path,
        marker: dict[str, Any],
        *,
        prepared_in_process: bool = False,
    ) -> str:
        """Bind a crash-surviving local commit to the recorded preimages.

        ``git commit`` and the following marker write cannot be one filesystem
        transaction.  In that narrow gap, adoption is allowed only when HEAD
        is the sole child of the recorded preimage and changes only the exact
        recorded promotion paths.
        """
        head = self._git_runner("rev-parse", "HEAD")
        if head.returncode != 0 or not head.stdout.strip():
            raise RuntimeError("cannot read product HEAD during promotion recovery")
        current = head.stdout.strip()
        prepared = str(marker.get("prepared_commit") or "")
        if prepared and current != prepared:
            raise RuntimeError("product HEAD moved beyond the prepared promotion commit")
        if not prepared:
            preimage = str(marker.get("head_preimage") or "")
            if not preimage or current == preimage:
                raise RuntimeError("promotion has no prepared product commit")
            parent = self._git_runner("rev-parse", f"{current}^")
            if parent.returncode != 0 or parent.stdout.strip() != preimage:
                raise RuntimeError("unrecorded HEAD is not based on promotion preimage")

        expected_paths = {str(path) for path in marker.get("commit_paths") or []}
        destination = self._promotion_destination(marker)
        if destination is None:
            raise RuntimeError("promotion destination is invalid")
        artifact_path = destination.relative_to(self.repo_root).as_posix()
        if not prepared_in_process:
            subject = self._git_runner("show", "-s", "--format=%s", current)
            if (
                subject.returncode != 0
                or subject.stdout.rstrip("\r\n")
                != str(marker.get("commit_message") or "")
            ):
                raise RuntimeError("prepared commit message does not match promotion intent")
            changed = self._git_runner(
                "diff-tree", "--root", "--no-commit-id", "--name-only", "-r", current
            )
            if changed.returncode != 0:
                raise RuntimeError("cannot inspect prepared promotion commit")
            actual_paths = {
                line.strip() for line in changed.stdout.splitlines() if line.strip()
            }
            artifact_changed = any(
                path == artifact_path or path.startswith(f"{artifact_path}/")
                for path in actual_paths
            )
            paths_within_intent = all(
                any(
                    path == expected or path.startswith(f"{expected}/")
                    for expected in expected_paths
                )
                for path in actual_paths
            )
            if not artifact_changed or not paths_within_intent:
                raise RuntimeError("prepared commit changed paths outside promotion intent")
        elif artifact_path not in expected_paths:
            raise RuntimeError("prepared commit intent omits artifact path")
        if (
            not destination.is_dir()
            or unit_artifact_sha256(destination) != marker.get("candidate_sha256")
        ):
            raise RuntimeError("prepared commit artifact no longer matches candidate digest")
        postimage = marker.get("registry_postimage")
        if isinstance(postimage, dict):
            exists = self.registry_path.is_file()
            digest = self._file_sha256(self.registry_path) if exists else None
            if (
                exists != bool(postimage.get("exists"))
                or digest != postimage.get("sha256")
            ):
                raise RuntimeError("registry no longer matches prepared promotion commit")
        if not prepared:
            prepared = current
            self._update_promotion_marker(
                attempt_dir,
                phase="commit-prepared",
                prepared_commit=prepared,
            )
        return prepared

    @staticmethod
    def _replacement_green_evidence(
        marker: dict[str, Any]
    ) -> dict[str, Any] | None:
        authorization = marker.get("replacement_authorization")
        if not isinstance(authorization, dict):
            return None
        inventory = authorization.get("preimage_inventory") or []
        proof = authorization.get("proof") or {}
        inventory_payload = json.dumps(
            inventory, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        proof_payload = json.dumps(
            proof, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return {
            "schema": 1,
            "transaction_id": marker.get("transaction_id"),
            "revocation_transition_id": authorization.get(
                "revocation_transition_id"
            ),
            "previous_commit": authorization.get("previous_commit"),
            "preimage_sha256": authorization.get("preimage_sha256"),
            "preimage_inventory_sha256": hashlib.sha256(
                inventory_payload
            ).hexdigest(),
            "preimage_inventory_entries": len(inventory),
            "proof_binding": (
                proof.get("binding") if isinstance(proof, dict) else None
            ),
            "proof_sha256": hashlib.sha256(proof_payload).hexdigest(),
            "candidate_sha256": marker.get("candidate_sha256"),
        }

    @classmethod
    def _promotion_green_update(cls, marker: dict[str, Any]) -> dict[str, Any]:
        outcome = marker.get("outcome") or {}
        update = {
            "status": "green",
            "error": None,
            "oracle_summary": outcome.get("summary"),
            "commit": marker.get("prepared_commit"),
            "pushed": True,
            "tier": outcome.get("tier"),
            "last_stage": "commit",
            "promotion_transaction_id": marker.get("transaction_id"),
            "promotion_transition_id": marker.get("transition_id"),
            "candidate_sha256": marker.get("candidate_sha256"),
        }
        replacement = cls._replacement_green_evidence(marker)
        if replacement is not None:
            update["replacement_evidence"] = replacement
        return update

    @classmethod
    def _promotion_transition(cls, marker: dict[str, Any]) -> UnitTransition:
        outcome = marker.get("outcome") or {}
        transition_id = str(marker.get("transition_id") or "")
        extra = {
            "transition_id": transition_id,
            "transition_timestamp": marker.get("transition_timestamp"),
            "transition_run_id": marker.get("transition_run_id"),
            "promotion_transaction_id": marker.get("transaction_id"),
            "candidate_sha256": marker.get("candidate_sha256"),
        }
        replacement = cls._replacement_green_evidence(marker)
        if replacement is not None:
            extra["replacement_evidence"] = replacement
        return UnitTransition(
            unit=str(marker.get("unit") or ""),
            result=str(outcome.get("result") or RESULT_GREEN),
            stage="commit",
            attempt=int(outcome.get("attempt") or marker.get("attempt") or 0),
            detail=str(outcome.get("detail") or "promotion recovered"),
            product_commit=str(marker.get("prepared_commit") or "") or None,
            product_pushed=True,
            oracle_summary=outcome.get("summary"),
            model=outcome.get("model"),
            tier=outcome.get("tier"),
            extra=extra,
        )

    @staticmethod
    def _transition_semantics(record: dict[str, Any]) -> dict[str, Any]:
        return {
            key: value
            for key, value in record.items()
            if key not in {"timestamp", "run_id"}
        }

    def _journal_transition_status(
        self, expected: UnitTransition, *, require_remote: bool = False
    ) -> str:
        """Classify one transition, optionally requiring authoritative publication."""
        transition_id = str(expected.extra.get("transition_id") or "")
        if not transition_id:
            return "absent"
        expected_semantics = self._transition_semantics(
            expected.to_record("", "")
        )
        found = False

        def classify(records: list[dict[str, Any]]) -> str | None:
            nonlocal found
            matching = []
            for record in records:
                extra = record.get("extra") if isinstance(record, dict) else None
                if (
                    isinstance(extra, dict)
                    and extra.get("transition_id") == transition_id
                ):
                    matching.append(record)
            if not matching:
                return None
            found = True
            if any(
                self._transition_semantics(record) != expected_semantics
                for record in matching
            ):
                return "conflict"
            return "exact"

        receipt_reader = getattr(self._journal, "transition_receipt", None)
        if callable(receipt_reader):
            try:
                receipt = receipt_reader(transition_id)
            except Exception:  # noqa: BLE001 - recovery remains fail closed
                receipt = {}
            if isinstance(receipt, dict) and receipt.get("recorded"):
                records = receipt.get("records")
                if not isinstance(records, list) or not records:
                    return "conflict"
                receipt_status = classify(records)
                if receipt_status != "exact":
                    return "conflict"
        reader = getattr(self._journal, "_local_events", None)
        if callable(reader):
            try:
                records = reader()
            except Exception:  # noqa: BLE001 - recovery remains fail closed
                records = []
            if classify(records) == "conflict":
                return "conflict"
        checkpoints = getattr(self._journal, "checkpoints", None)
        if isinstance(checkpoints, list):
            for checkpoint in checkpoints:
                transition = (
                    checkpoint.get("transition")
                    if isinstance(checkpoint, dict)
                    else None
                )
                if isinstance(transition, UnitTransition):
                    status = classify([transition.to_record("", "")])
                    if status == "conflict":
                        return "conflict"
        if require_remote:
            remote_reader = getattr(
                self._journal, "authoritative_transition_receipt", None
            )
            if not callable(remote_reader):
                return "pending_remote"
            try:
                remote_receipt = remote_reader(transition_id)
            except Exception:  # noqa: BLE001 - remote proof is fail closed
                return "pending_remote"
            if not isinstance(remote_receipt, dict):
                return "pending_remote"
            remote_records = remote_receipt.get("remote_records")
            if not isinstance(remote_records, list):
                return "pending_remote"
            remote_status = classify(remote_records)
            if remote_status == "conflict":
                return "conflict"
            if not remote_receipt.get("authoritative") or remote_status != "exact":
                return "pending_remote"
            return "exact"
        return "exact" if found else "absent"

    def _finalize_promotion_transaction(
        self,
        state: dict[str, Any],
        attempt_dir: Path,
        marker: dict[str, Any],
        *,
        prepared_in_process: bool = False,
    ) -> bool:
        """Idempotently publish and durably settle one prepared transaction."""
        prepared = self._validate_or_adopt_prepared_commit(
            attempt_dir, marker, prepared_in_process=prepared_in_process
        )
        marker = self._promotion_marker(attempt_dir) or marker
        destination = self._promotion_destination(marker)
        candidate = load_unit_artifact(destination) if destination is not None else None
        if candidate is None or candidate.sha256 != marker.get("candidate_sha256"):
            raise RuntimeError("installed candidate unavailable during finalization")
        transaction = PromotionTransaction(attempt_dir, candidate, destination)
        self._verify_transaction_replacement_state(transaction)
        transition_id = str(marker.get("transition_id") or uuid.uuid4().hex)
        transition_timestamp = str(marker.get("transition_timestamp") or utc_now())
        transition_run_id = str(
            marker.get("transition_run_id") or marker.get("run_id") or self.run_id
        )
        remote_preimage = marker.get("remote_preimage")
        if "remote_preimage" not in marker:
            remote_preimage = self._remote_port_staging_sha()
        self._update_promotion_marker(
            attempt_dir,
            phase="publishing",
            prepared_commit=prepared,
            remote_preimage=remote_preimage,
            transition_id=transition_id,
            transition_timestamp=transition_timestamp,
            transition_run_id=transition_run_id,
        )
        remote = self._remote_port_staging_sha()
        if remote not in {remote_preimage, prepared}:
            raise RuntimeError("port-staging moved outside promotion transaction")
        if remote != prepared:
            self._verify_transaction_replacement_state(transaction)
            pushed = self._push_product_sha(prepared)
            remote = self._remote_port_staging_sha()
            if pushed.returncode != 0 or remote != prepared:
                self._update_promotion_marker(
                    attempt_dir,
                    phase="publication-pending",
                    push_result={
                        "pushed": False,
                        "detail": (pushed.stdout + pushed.stderr)[-400:],
                        "remote_sha": remote,
                    },
                )
                return False
        self._update_promotion_marker(
            attempt_dir,
            phase="published",
            push_result={"pushed": True, "detail": "", "remote_sha": prepared},
        )
        self._promotion_phase_boundary("push", transaction)
        self._verify_transaction_replacement_state(transaction)
        marker = self._promotion_marker(attempt_dir) or marker
        green_update = self._promotion_green_update(marker)
        projected = self._project_record_update(
            state, str(marker.get("unit")), green_update
        )
        # A successful promotion is a new canonical lifecycle. Revocation
        # metadata describes the superseded verdict and must not survive to
        # contradict this green record (or poison assembly eligibility).
        projected["units"][str(marker.get("unit"))].pop("revoked", None)
        for stale_key in (
            "diagnosis",
            "diagnosis_malformed",
            "diagnosis_invalidation",
            "f4_nominated",
            "source_failure_id",
            "failure_domain",
            "diagnosis_eligible",
        ):
            projected["units"][str(marker.get("unit"))].pop(stale_key, None)
        self._update_promotion_marker(
            attempt_dir, phase="checkpointing", green_record=green_update
        )
        self._verify_transaction_replacement_state(transaction)
        expected_transition = self._promotion_transition(marker)
        journal_status = self._journal_transition_status(
            expected_transition, require_remote=True
        )
        if journal_status == "conflict":
            raise RuntimeError(
                "promotion transition id exists with different durable semantics"
            )
        if journal_status != "exact":
            if not self._checkpoint(
                projected, expected_transition, require_progress_push=True
            ):
                return False
        if self._journal_transition_status(
            expected_transition, require_remote=True
        ) != "exact":
            raise RuntimeError(
                "promotion transition lacks an exact authoritative semantic receipt"
            )
        self._promotion_phase_boundary("checkpoint_durable", transaction)
        self._verify_transaction_replacement_state(transaction)
        self._update_promotion_marker(attempt_dir, phase="checkpointed")
        self._promotion_phase_boundary("checkpoint", transaction)
        self._verify_transaction_replacement_state(transaction)
        self._update_promotion_marker(
            attempt_dir,
            phase="state-saving",
            green_state_content_sha256=self._state_content_sha256(projected),
        )
        self._verify_transaction_replacement_state(transaction)
        self._save_state(projected)
        state.clear()
        state.update(projected)
        self._update_promotion_marker(attempt_dir, phase="state-saved")
        self._promotion_phase_boundary("state_save", transaction)
        self._verify_transaction_replacement_state(transaction)
        self._cleanup_promotion_attempt(attempt_dir)
        return True

    def _cleanup_promotion_attempt(self, attempt_dir: Path) -> None:
        """Delete only an ownership-marked private attempt and verify removal."""
        marker = self._promotion_marker(attempt_dir)
        if marker is None:
            raise RuntimeError(
                f"refusing to clean unowned promotion path: {attempt_dir}"
            )
        try:
            shutil.rmtree(attempt_dir)
        except Exception:  # noqa: BLE001 - restore ownership for restart
            attempt_dir.mkdir(parents=True, exist_ok=True)
            atomic_write_json(attempt_dir / ".promotion-attempt.json", marker)
            raise
        if attempt_dir.exists():
            atomic_write_json(attempt_dir / ".promotion-attempt.json", marker)
            raise RuntimeError(f"promotion attempt cleanup incomplete: {attempt_dir}")

    def _reconcile_orphan_promotion_attempts(
        self, state: dict[str, Any] | None = None
    ) -> bool:
        """Roll back pre-commit attempts or finalize exact committed intents.

        An owned marker is a transaction journal, not disposable scratch.  It
        remains beside the attempt until product publication, the green
        transition, and canonical state all agree on the same prepared SHA.
        """
        if state is None:
            state = self._load_state()
        if not self.promotion_attempt_root.is_dir():
            return True
        ok = True
        for attempt_dir in sorted(self.promotion_attempt_root.iterdir()):
            if not attempt_dir.is_dir():
                self.events.emit(
                    "promotion_attempt_unowned", path=str(attempt_dir)[:400]
                )
                continue
            marker = self._promotion_marker(attempt_dir)
            if marker is None:
                self.events.emit(
                    "promotion_attempt_unowned", path=str(attempt_dir)[:400]
                )
                continue
            try:
                phase = str(marker.get("phase") or "")
                committed = bool(marker.get("prepared_commit")) or phase in {
                    "commit-prepared",
                    "publishing",
                    "publication-pending",
                    "published",
                    "checkpointing",
                    "checkpointed",
                    "state-saved",
                }
                if phase == "commit-preparing" and not committed:
                    head = self._git_runner("rev-parse", "HEAD")
                    committed = (
                        head.returncode == 0
                        and bool(marker.get("head_preimage"))
                        and head.stdout.strip() != marker.get("head_preimage")
                    )
                if committed:
                    if not self._finalize_promotion_transaction(
                        state, attempt_dir, marker
                    ):
                        raise RuntimeError("promotion transaction remains pending")
                    self.events.emit(
                        "promotion_transaction_finalized",
                        unit=marker.get("unit"),
                        transaction_id=marker.get("transaction_id"),
                        prepared_commit=marker.get("prepared_commit"),
                    )
                    continue

                destination = self._promotion_destination(marker)
                if destination is None:
                    raise RuntimeError("owned attempt has invalid destination")
                candidate = load_unit_artifact(attempt_dir / "candidate")
                if candidate is None:
                    candidate = load_unit_artifact(destination)
                if candidate is None:
                    if phase == "creating" and not destination.exists():
                        self._quarantine_transaction(
                            attempt_dir, marker, phase="rolled-back-incomplete-create"
                        )
                        continue
                    raise RuntimeError("pre-commit transaction lost its candidate")
                transaction = PromotionTransaction(attempt_dir, candidate, destination)
                self._rollback_uncommitted_transaction(
                    transaction, reason="restart-precommit"
                )
                self.events.emit(
                    "promotion_transaction_rolled_back",
                    unit=marker.get("unit"),
                    transaction_id=marker.get("transaction_id"),
                )
            except Exception as error:  # noqa: BLE001 - fail closed on ambiguity
                ok = False
                self.events.emit(
                    "promotion_attempt_reconcile_failed",
                    unit=marker.get("unit"),
                    attempt_id=marker.get("attempt_id"),
                    error=str(error)[:400],
                )
        return ok

    @staticmethod
    def _record_sha256(record: dict[str, Any]) -> str:
        return hashlib.sha256(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    @classmethod
    def _state_content_sha256(cls, state: dict[str, Any]) -> str:
        """Bind canonical content while excluding its write-time timestamp."""
        return cls._record_sha256({
            key: value for key, value in state.items() if key != "updated_at"
        })

    @staticmethod
    def _artifact_inventory(directory: Path) -> list[dict[str, Any]]:
        if directory.is_symlink() or (
            hasattr(directory, "is_junction") and directory.is_junction()
        ):
            raise RuntimeError("artifact preimage directory is a link")
        inventory: list[dict[str, Any]] = []
        for path in sorted(directory.rglob("*"), key=lambda item: item.as_posix()):
            if path.is_symlink() or (
                hasattr(path, "is_junction") and path.is_junction()
            ):
                raise RuntimeError("artifact preimage inventory contains a link")
            if path.is_dir():
                continue
            if not path.is_file():
                raise RuntimeError("artifact preimage inventory has unsupported entry")
            payload = path.read_bytes()
            inventory.append({
                "path": path.relative_to(directory).as_posix(),
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
        return inventory

    def _replacement_authorization(
        self, transaction: PromotionTransaction, record: dict[str, Any]
    ) -> dict[str, Any]:
        """Bind one same-unit rebuild to its sanctioned revoked preimage.

        Mutable disk is never its own authorization.  Current lifecycles use
        their journal-carried digest; digest-less legacy lifecycles must prove
        the directory against the recorded commit on the authoritative remote
        publication lineage before a rename can occur.
        """
        marker = self._promotion_marker(transaction.attempt_dir)
        if marker is None:
            raise RuntimeError("promotion replacement lost ownership marker")
        snapshot = load_canonical_state_snapshot(self.state_path)
        canonical = snapshot.units.get(transaction.candidate.name)
        if (
            not isinstance(canonical, dict)
            or canonical.get("status") != record.get("status")
            or canonical.get("attempts") != record.get("attempts")
            or canonical.get("revoked") != record.get("revoked")
        ):
            raise RuntimeError("canonical unit state changed before replacement")
        revoked = canonical.get("revoked")
        if (
            canonical.get("status") != "porting"
            or int(canonical.get("attempts", 0)) != int(marker.get("attempt", -1))
            or not revoked_lifecycle_is_eligible(revoked, transaction.candidate.tier)
        ):
            raise RuntimeError("artifact preimage has no eligible revoked lifecycle")
        destination = transaction.destination
        expected_root = (
            self.artifact_root
            if transaction.candidate.tier == "oracle_green"
            else self.staging_root
        )
        if Path(os.path.abspath(destination)) != Path(
            os.path.abspath(expected_root / transaction.candidate.name)
        ):
            raise RuntimeError("revoked artifact destination has wrong tier root")
        if destination.is_symlink() or (
            hasattr(destination, "is_junction") and destination.is_junction()
        ):
            raise RuntimeError("revoked artifact destination is a link")
        existing = load_unit_artifact(destination)
        preimage = marker.get("artifact_preimage") or {}
        if (
            existing is None
            or existing.name != transaction.candidate.name
            or existing.tier != transaction.candidate.tier
            or existing.sha256 != preimage.get("sha256")
        ):
            raise RuntimeError("revoked artifact preimage changed before authorization")

        previous_digest = revoked.get("previous_candidate_sha256")
        # ``revoke-unit`` records name the revoked lifecycle's publication
        # commit itself.  ``d5-migrate`` never recorded that binding -- it is
        # operator-only, and revoked_lifecycle_is_eligible treats its presence
        # on a migration record as forgery -- but the migration also never
        # touched the record's own ``commit`` field, which still names the
        # commit the revoked green was published at.  Proving the on-disk
        # preimage against that commit on the authoritative publication
        # lineage is the same evidence the operator path carries, so use it;
        # nothing is written back to the revocation record.
        legacy_commit = revoked.get("previous_commit")
        if legacy_commit is None and revoked.get("via") == "d5-migrate":
            legacy_commit = canonical.get("commit")
        proof: dict[str, Any]
        if previous_digest is not None:
            if previous_digest != existing.sha256:
                raise RuntimeError("revoked artifact digest does not match preimage")
            proof = {
                "binding": "revocation-canonical-digest",
                "artifact_sha256": existing.sha256,
                "commit": revoked.get("previous_commit"),
            }
        else:
            backfill = canonical.get("artifact_digest_backfill")
            if (
                isinstance(backfill, dict)
                and backfill.get("artifact_sha256") == existing.sha256
                and legacy_commit is not None
                and backfill.get("commit") == legacy_commit
            ):
                proof = {
                    "binding": "revocation-journaled-backfill",
                    "artifact_sha256": existing.sha256,
                    "commit": legacy_commit,
                    "backfill_transition_id": backfill.get("transition_id"),
                }
            else:
                remote_sha = self._remote_port_staging_sha(strict=True)
                if remote_sha is None:
                    raise RuntimeError(
                        "authoritative port-staging ref unavailable for legacy preimage"
                    )
                proof, proof_error = prove_legacy_artifact_commit_tree(
                    existing,
                    {"commit": legacy_commit},
                    repo_root=self.repo_root,
                    git_runner=self._git_runner,
                    publication_ref="refs/heads/port-staging",
                    publication_sha=remote_sha,
                    required_committed_files=BACKFILL_REQUIRED_COMMITTED_FILES,
                    allowed_ignored_extras=BACKFILL_ALLOWED_IGNORED_EVIDENCE,
                )
                if proof is None:
                    raise RuntimeError(
                        f"legacy revoked artifact proof failed: {proof_error}"
                    )
        return {
            "schema": 1,
            "unit": transaction.candidate.name,
            "tier": transaction.candidate.tier,
            "canonical_state_sha256": snapshot.sha256,
            "canonical_record_sha256": self._record_sha256(canonical),
            "revocation_transition_id": revoked.get("transition_id"),
            "previous_record_sha256": revoked.get("previous_record_sha256"),
            "previous_commit": revoked.get("previous_commit"),
            "preimage_sha256": existing.sha256,
            "candidate_sha256": transaction.candidate.sha256,
            "backup": "artifact.preimage",
            "preimage_inventory": self._artifact_inventory(destination),
            "proof": proof,
        }

    def _verify_replacement_state(
        self,
        authorization: dict[str, Any],
        marker: dict[str, Any] | None = None,
    ) -> None:
        try:
            snapshot = load_canonical_state_snapshot(self.state_path)
        except ValueError as error:
            raise RuntimeError("canonical state unavailable during replacement") from error
        if marker is not None and marker.get("green_state_content_sha256"):
            try:
                payload = self.state_path.read_bytes()
                if hashlib.sha256(payload).hexdigest() != snapshot.sha256:
                    raise RuntimeError(
                        "canonical state changed during replacement verification"
                    )
                current_state = json.loads(payload.decode("utf-8-sig"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
                raise RuntimeError(
                    "canonical state unavailable during replacement verification"
                ) from error
            if self._state_content_sha256(current_state) == marker.get(
                "green_state_content_sha256"
            ):
                return
        canonical = snapshot.units.get(str(authorization.get("unit") or ""))
        if (
            snapshot.sha256 != authorization.get("canonical_state_sha256")
            or not isinstance(canonical, dict)
            or self._record_sha256(canonical)
            != authorization.get("canonical_record_sha256")
        ):
            raise RuntimeError("canonical state changed during artifact replacement")

    def _verify_transaction_replacement_state(
        self, transaction: PromotionTransaction
    ) -> None:
        marker = self._promotion_marker(transaction.attempt_dir)
        if marker is None:
            raise RuntimeError("promotion transaction lost its ownership marker")
        authorization = marker.get("replacement_authorization")
        if isinstance(authorization, dict):
            self._verify_replacement_state(authorization, marker)

    def _install_promotion_candidate(
        self, transaction: PromotionTransaction, record: dict[str, Any]
    ) -> str:
        """Install a candidate, replacing only its exact revoked predecessor.

        The two-directory swap is journaled in the owned attempt marker.  Its
        rollback understands both rename gaps, so restart restores the exact
        old artifact until the replacement has a published green transition.
        """
        candidate = transaction.candidate
        destination = transaction.destination
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            if destination.is_symlink() or (
                hasattr(destination, "is_junction") and destination.is_junction()
            ):
                raise RuntimeError("artifact destination is a link")
            existing = load_unit_artifact(destination)
            if (
                existing is None
                or existing.name != candidate.name
                or existing.sha256 != candidate.sha256
            ):
                authorization = self._replacement_authorization(transaction, record)
                backup = transaction.attempt_dir / authorization["backup"]
                if backup.exists():
                    raise RuntimeError("replacement preimage backup already exists")
                self._update_promotion_marker(
                    transaction.attempt_dir,
                    phase="replacement-authorized",
                    replacement_authorization=authorization,
                )
                self._promotion_phase_boundary("replacement_authorized", transaction)
                self._verify_replacement_state(authorization)
                if unit_artifact_sha256(destination) != authorization["preimage_sha256"]:
                    raise RuntimeError("artifact preimage raced replacement authorization")
                destination.rename(backup)
                self._promotion_phase_boundary("replacement_preimage_renamed", transaction)
                if (
                    destination.exists()
                    or unit_artifact_sha256(backup) != authorization["preimage_sha256"]
                ):
                    raise RuntimeError("revoked artifact preimage detach failed")
                self._update_promotion_marker(
                    transaction.attempt_dir, phase="replacement-preimage-detached"
                )
                self._verify_replacement_state(authorization)
                candidate.directory.rename(destination)
                self._promotion_phase_boundary("replacement_candidate_renamed", transaction)
                self._verify_replacement_state(authorization)
                installed = load_unit_artifact(destination)
                if (
                    installed is None
                    or installed.name != candidate.name
                    or installed.sha256 != candidate.sha256
                    or unit_artifact_sha256(backup) != authorization["preimage_sha256"]
                ):
                    raise RuntimeError("replacement artifact digest verification failed")
                return "revoked-preimage-replaced"
            return "preimage-verified"
        try:
            candidate.directory.rename(destination)
        except OSError:
            # Resolve an install race only when the winner is byte-identical.
            if destination.exists():
                existing = load_unit_artifact(destination)
                if (
                    existing is not None
                    and existing.name == candidate.name
                    and existing.sha256 == candidate.sha256
                ):
                    return "preimage-verified"
            raise
        installed = load_unit_artifact(destination)
        if (
            installed is None
            or installed.name != candidate.name
            or installed.sha256 != candidate.sha256
        ):
            raise RuntimeError(
                f"installed artifact failed digest verification: {destination}"
            )
        return "installed"

    def run_assembly_gate_now(
        self,
        n: int | None = None,
        *,
        workdir_name: str = "_assembly",
        candidate: UnitArtifact | None = None,
        workdir: Path | None = None,
    ) -> dict[str, Any]:
        """One assembly-gate pass over the last n green/staged units (n=None
        sweeps everything -- the backfill form). Emits NO events and takes no
        lock. Selection is bound to one stable canonical-state snapshot and
        fails closed if that state changes while the gate is running; callers
        must reconcile interrupted records before invoking this maintenance
        path."""
        try:
            snapshot = load_canonical_state_snapshot(self.state_path)
        except ValueError as error:
            return {
                "passed": False, "n": 0, "units": [],
                "stage": "canonical-state", "conflicts": [],
                "detail": str(error)[:1200], "candidate": (
                    {"name": candidate.name, "sha256": candidate.sha256}
                    if candidate is not None else None
                ),
                "selection": None,
            }
        interrupted = sorted(
            name for name, record in snapshot.units.items()
            if record.get("status") == "porting"
            and (candidate is None or name != candidate.name)
        )
        if interrupted:
            return {
                "passed": False, "n": 0, "units": [],
                "stage": "canonical-state", "conflicts": [],
                "detail": "interrupted canonical records require reconciliation "
                "before assembly selection: " + ", ".join(interrupted[:20]),
                "candidate": (
                    {"name": candidate.name, "sha256": candidate.sha256}
                    if candidate is not None else None
                ),
                "selection": {"canonical_state_sha256": snapshot.sha256},
            }
        prior, excluded = select_recent_green_units(
            [self.artifact_root, self.staging_root],
            None,
            canonical_snapshot=snapshot,
            root_tiers=["oracle_green", "compile_only"],
        )
        selection_evidence = {
            "canonical_state_sha256": snapshot.sha256,
            "eligible": [unit.canonical for unit in prior],
            "excluded": excluded,
        }
        if candidate is None:
            units = prior[-n:] if n is not None and n > 0 else prior
            selected_names = {unit.name for unit in units}
            selection_evidence["eligible"] = [
                unit.canonical for unit in prior if unit.name in selected_names
            ]
        else:
            # The candidate is explicit authority, never discovered through
            # timestamp/root selection. Exclude every same-name root artifact,
            # select at most N-1 prior units, then append the exact candidate.
            prior = [
                unit
                for unit in prior
                if unit.name != candidate.name
            ]
            if n is not None and n > 0:
                prior = prior[-max(0, n - 1):] if n > 1 else []
            units = [*prior, candidate]
            selection_evidence["eligible"] = [unit.canonical for unit in prior]
            selection_evidence["candidate"] = {
                "name": candidate.name,
                "artifact_sha256": candidate.sha256,
                "tier": candidate.tier,
                "authority": "private-explicit-candidate",
            }
        if len(units) < 2:
            try:
                digest_now = (
                    unit_artifact_sha256(candidate.directory)
                    if candidate is not None
                    else None
                )
            except OSError as error:
                digest_now = f"unreadable:{error}"
            if candidate is not None and digest_now != candidate.sha256:
                return {
                    "passed": False,
                    "n": len(units),
                    "units": [unit.name for unit in units],
                    "stage": "candidate-integrity",
                    "conflicts": [],
                    "detail": f"candidate digest changed before singleton gate: {digest_now}",
                    "candidate": {
                        "name": candidate.name,
                        "sha256": candidate.sha256,
                    },
                    "selection": selection_evidence,
                }
            if not verify_canonical_state_snapshot(snapshot):
                return {
                    "passed": False,
                    "n": len(units),
                    "units": [unit.name for unit in units],
                    "stage": "canonical-state-integrity",
                    "conflicts": [],
                    "detail": "canonical state changed during assembly selection",
                    "candidate": (
                        {"name": candidate.name, "sha256": candidate.sha256}
                        if candidate is not None else None
                    ),
                    "selection": selection_evidence,
                }
            return {
                "passed": None,
                "n": len(units),
                "units": [unit.name for unit in units],
                "stage": "skipped",
                "conflicts": [],
                "detail": "fewer than 2 green/staged units; nothing to compose",
                "candidate": (
                    {"name": candidate.name, "sha256": candidate.sha256}
                    if candidate is not None
                    else None
                ),
                "selection": selection_evidence,
            }
        gate_workdir = workdir or (self.work_root / workdir_name)
        result = run_assembly_gate(
            units,
            gate_workdir,
            link_runner=self._assembly_link_runner,
            smoke_runner=self._assembly_smoke_runner,
            candidate=candidate,
            selection_evidence=selection_evidence,
            canonicalization=self._canonicalization_request(units, gate_workdir),
        )
        if not verify_canonical_state_snapshot(snapshot):
            result["passed"] = False
            result["stage"] = "canonical-state-integrity"
            result["detail"] = "canonical state changed during assembly gate"
        record_gate_result(self.assembly_ledger_path, result)
        return result

    def _canonicalization_request(
        self, units: list[Any], workdir: Path
    ) -> Any | None:
        """Owner-derived canonicalization for this window, or None.

        Returning None keeps the registry-less merge, which is the only correct
        behaviour while the product registry is still pre-schema-1: the gate must
        not start failing because the owner catalog is unavailable. A refusal
        raised *inside* the gate is a different thing entirely and always stands.

        The snapshot is scoped to the symbols this window references. The pinned
        Clang runs twice per parsed record and the registry holds 10,954
        functions, so an unscoped load would cost hours for a handful of lookups.
        """
        try:
            from src.port_assembly_abi import ClangDeclaratorParser, load_owner_snapshot
            from src.port_assembly_gate import CanonicalizationRequest

            registry_path = self.repo_root / "research/decomp/data/oracle-registry.json"
            if not registry_path.is_file():
                return None
            identifier = re.compile(rb"[A-Za-z_][A-Za-z0-9_]*")
            symbols: set[str] = set()
            for unit in units:
                for name in ("unit.c", "gnt4_shim.h"):
                    data = (unit.directory / name).read_bytes()
                    symbols.update(match.group().decode("ascii") for match in identifier.finditer(data))
            workdir.mkdir(parents=True, exist_ok=True)
            smoke_script = workdir / "assembly-smoke.cjs"
            smoke_script.write_text(SMOKE_JS, encoding="utf-8", newline=chr(10))
            parser = ClangDeclaratorParser.from_product_root(self.repo_root)
            snapshot = load_owner_snapshot(self.repo_root, registry_path, parser, symbols=symbols)
            attempt = max(1, int(getattr(units[-1], "attempts", 1) or 1))
            request = CanonicalizationRequest(
                repo_root=self.repo_root,
                owner_snapshot=snapshot,
                attempt=attempt,
                behavior_tier="compile_only",
                smoke_script=smoke_script,
                # The same canon seed every (re)attempt already syncs per-unit
                # headers from (see sync_sdk_declarations); the gate reads it
                # fresh so stale gnt4_* declarations in already-staged window
                # units unify to the current canon instead of contesting every
                # new candidate at wasm-ld.
                sdk_seed_path=self.run_root / "gnt4_shim_seed.h",
            )
            self.events.emit(
                "assembly_canonicalization_ready",
                owners=len(snapshot.owner_index),
                symbols=len(symbols),
            )
            return request
        except Exception as error:  # noqa: BLE001 - unavailability must not break the gate
            self.events.emit(
                "assembly_canonicalization_unavailable", error=str(error)[:400]
            )
            return None

    def _maybe_run_assembly_gate(
        self,
        unit_name: str,
        *,
        candidate: UnitArtifact | None = None,
        workdir: Path | None = None,
    ) -> dict[str, Any]:
        """Run the pre-publication assembly gate for ``unit_name``.

        The candidate artifact has been materialized but is not committed,
        settled, or registry-authoritative yet. A failed gate (including an
        internal link/smoke fault) is therefore a blocking result for the
        caller. Fewer than two artifacts is an explicit no-composition-needed
        result (``passed is None``). The ledger is durable local evidence only:
        this hook never creates a product-lineage commit or push.
        """
        try:
            result = self.run_assembly_gate_now(
                assembly_window_size(), candidate=candidate, workdir=workdir
            )
            if result.get("passed") is None:
                return result  # fewer than 2 units: composition is not yet a claim
            self.events.emit(
                "assembly_gate",
                unit=unit_name,
                n=result.get("n"),
                units=result.get("units"),
                passed=result.get("passed"),
                stage=result.get("stage"),
                conflict_count=len(result.get("conflicts") or []),
            )
            if not result.get("passed"):
                self.events.emit(
                    "assembly_gate_failed",
                    unit=unit_name,
                    stage=result.get("stage"),
                    conflicts=[
                        {
                            "symbol": c.get("symbol"),
                            "class": c.get("class"),
                            "units": c.get("units"),
                        }
                        for c in (result.get("conflicts") or [])[:20]
                    ],
                    # Summarise, do not slice. A link-stage detail is emcc's
                    # failure output, whose echoed invocation is longer than any
                    # sane cap at BOTH ends -- head-slicing recorded the wasm-ld
                    # flags (auto-c0011-004) and tail-slicing recorded the -l
                    # library flags and "failed (returned 1)" (auto-c0019-000),
                    # with the real `undefined symbol:` line stranded in the
                    # middle either way. summarise_build_error already solves
                    # exactly this for per-unit builds -- its docstring cites the
                    # same bug -- so reuse it rather than inventing a worse rule
                    # here. Short canonicalize details are returned unchanged.
                    detail=summarise_build_error(result.get("detail") or ""),
                )
        except Exception as error:  # noqa: BLE001 - fail the candidate closed
            self.events.emit(
                "assembly_gate_error", unit=unit_name, error=str(error)[:400]
            )
            return {
                "passed": False,
                "n": None,
                "units": [unit_name],
                "stage": "internal",
                "conflicts": [],
                "detail": str(error)[:1200],
                "candidate": (
                    {"name": candidate.name, "sha256": candidate.sha256}
                    if candidate is not None
                    else None
                ),
            }
        return result

    # ------------------------------------------------------------------ oracle

    def _run_oracle(self, unit: dict[str, Any], wasm_path: Path) -> tuple[bool, str, str]:
        """Run the unit's oracle command. Returns (passed, summary, full_log)."""
        oracle = unit["oracle"]
        command = list(oracle["command"])
        if command and command[0] == "node":
            command[0] = resolve_node_exe()
        env = dict(os.environ)
        for key, value in (oracle.get("env") or {}).items():
            env[key] = str(value).replace("{wasm}", str(wasm_path))
        completed = subprocess.run(
            command,
            cwd=str(self.repo_root / oracle["cwd"]),
            env=env,
            capture_output=True,
            text=True,
            timeout=ORACLE_TIMEOUT_SECONDS,
         creationflags=NO_WINDOW)
        log = completed.stdout + ("\n--- stderr ---\n" + completed.stderr if completed.stderr else "")
        passed = completed.returncode == 0
        for pattern in oracle.get("success_patterns") or []:
            if not re.search(pattern, log):
                passed = False
        summary = ", ".join(re.findall(r"\d+/\d+", completed.stdout)[:4]) or (
            "pass" if passed else f"exit {completed.returncode}"
        )
        return passed, summary, log

    # --------------------------------------------------------------------- git

    def _git(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            cwd=str(self.repo_root),
            capture_output=True,
            text=True,
            timeout=300,
         creationflags=NO_WINDOW)

    def _unit_commit_spec(
        self,
        name: str,
        summary: str,
        *,
        staging: bool = False,
        extra_paths: list[str] | None = None,
    ) -> tuple[list[str], str]:
        rel = (
            f"research/decomp/port-units-staging/{name}"
            if staging
            else f"research/decomp/port-units/{name}"
        )
        paths = [rel, *(extra_paths or [])]
        message = (
            f"port-staging: {name} wasm unit LINKED (unoracled, not for integration)"
            if staging
            else f"port: {name} wasm unit green (oracle {summary})"
        )
        return paths, message

    def _prepare_unit_commit(
        self,
        transaction: PromotionTransaction,
        *,
        paths: list[str],
        message: str,
    ) -> tuple[str | None, str]:
        """Create the local commit after persisting recoverable intent."""
        head = self._git_runner("rev-parse", "HEAD")
        if head.returncode != 0:
            return None, (head.stdout + head.stderr)[-400:]
        head_preimage = head.stdout.strip()
        self._update_promotion_marker(
            transaction.attempt_dir,
            phase="commit-preparing",
            head_preimage=head_preimage,
            commit_paths=paths,
            commit_message=message,
        )
        added = self._git_runner("add", "--", *paths)
        if added.returncode != 0:
            return None, (added.stdout + added.stderr)[-400:]
        committed = self._git_runner("commit", "-m", message, "--", *paths)
        if committed.returncode != 0:
            return None, (committed.stdout + committed.stderr)[-400:]
        rev = self._git_runner("rev-parse", "HEAD")
        if rev.returncode != 0 or not rev.stdout.strip():
            return None, (rev.stdout + rev.stderr)[-400:]
        sha = rev.stdout.strip()
        self._update_promotion_marker(
            transaction.attempt_dir,
            phase="commit-prepared",
            prepared_commit=sha,
        )
        return sha, ""

    def _remote_port_staging_sha(self, *, strict: bool = False) -> str | None:
        result = self._git_runner(
            "ls-remote", "origin", "refs/heads/port-staging"
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        if not strict:
            return result.stdout.split()[0]
        matches = []
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[1] == "refs/heads/port-staging":
                matches.append(fields[0])
        if len(matches) != 1:
            return None
        if re.fullmatch(
            r"[0-9a-f]{40}|[0-9a-f]{64}", matches[0], re.I
        ) is None:
            return None
        return matches[0]

    def _push_product_sha(self, sha: str) -> subprocess.CompletedProcess[str]:
        """The ONE sanctioned product push, explicit refspec (a bare
        `git push` depends on ambient upstream config -- the gate-ledger
        bug rode exactly that).

        INTERIM (owner-ordered, 2026-08-20, pending docs/
        git-topology-design.md): artifact commits stop reaching origin/main.
        The local lineage is unchanged -- greens/promotions commit exactly
        as before on the current branch -- but the push lands it on the
        origin `port-staging` branch (created on first push, fast-forward
        thereafter since it only ever receives this same lineage). The
        port-progress branch stays journal-owned (port_progress.py pushes
        it with its own explicit refspec from its own worktree); origin
        main receives nothing. One retry for transient faults."""
        refspec = f"{sha}:refs/heads/port-staging"
        pushed = self._git_runner("push", "origin", refspec)
        if pushed.returncode != 0:
            pushed = self._git_runner("push", "origin", refspec)
        return pushed

    # -------------------------------------------------------------------- unit

    def _process_unit(self, unit: dict[str, Any], state: dict[str, Any]) -> str:
        name = unit["name"]
        record = self._unit_state(state, name)
        record["status"] = "porting"
        record["attempts"] = record.get("attempts", 0) + 1
        self._save_state(state)
        self.events.emit("wasm_unit_started", unit=name, attempts=record["attempts"])
        self._heartbeat(f"wasm_units:{name}:extract")

        workdir = self.work_root / name
        workdir.mkdir(parents=True, exist_ok=True)

        # 1. materialization: byte-faithful extraction (sha256-recorded
        # pre-transform), then the D5 fp-reinterpret transform (D5-3a).
        try:
            materialized = materialize_unit_c(self.repo_root, unit)
        except (OSError, ValueError, KeyError) as error:
            # The queue entry does not describe extractable code: retrying the
            # identical spec cannot help, so this is structural, not retryable.
            return self._fail(
                state, record, name, f"extraction: {error}",
                stage="extract", result=RESULT_STRUCTURAL_INELIGIBLE,
            )
        prelude = "\n".join(unit.get("prelude", []))
        unit_c = materialized.unit_c
        extraction_records = materialized.extraction_records
        (workdir / "unit.c").write_text(unit_c, encoding="utf-8", newline="\n")
        combined_sha = materialized.extracted_sha256

        # F-D5-2 guard: a dataflow-separated reinterpretation (u = CONCAT44
        # (...); ... (double)u) is lexically invisible to grammar G. Measured
        # zero across the whole export; a hit must page, never silently build
        # (F-D5-B: the unit blocks until G grows a dataflow rule or the unit
        # is manually dispositioned -- gate_failed keeps it schedulable only
        # on a world change, i.e. a transform/driver revision).
        if materialized.transform.get("d5_residual_risk"):
            self.events.emit(
                "d5_residual_risk",
                unit=name,
                count=materialized.transform["d5_residual_risk"],
            )
            return self._fail(
                state, record, name,
                "D5 residual-risk guard (F-D5-2 / review M3): "
                f"{materialized.transform['d5_residual_risk']} CONCAT44 "
                "site(s) the transform cannot soundly rewrite (dataflow-"
                "separated and/or comma-operand shapes); blocked pending a "
                "grammar extension or manual disposition",
                stage="extract", result=RESULT_GATE_FAILED,
            )

        # A .c that both declares a function `void` and assigns its result cannot
        # be satisfied by ANY header, so spending 8 model iterations discovering
        # that is pure waste (auto-c0000-013: ~3.6 hours to fail). Settle it here
        # from the verbatim source alone -- no model call, no retries.
        contradictions = void_result_contradictions(unit_c)
        if contradictions:
            return self._fail(
                state, record, name,
                "verbatim .c is self-contradictory: "
                f"{', '.join(contradictions)} declared void but their results are "
                "assigned; no header edit can reconcile this",
                stage="extract", result=RESULT_STRUCTURAL_INELIGIBLE,
            )

        # 2. header scaffold: reset to the seed every attempt (deterministic base)
        header_seed = self.repo_root / unit["header_seed"]
        try:
            header = header_seed.read_text(encoding="utf-8")
        except OSError as error:
            # D14 (design section 2.10): a failed READ is transient I/O -- an
            # AV lock or a network-share hiccup -- not proof the queue entry is
            # bad. Settling it structural would remove the unit from the pool
            # forever over a fault a retry can clear. Extraction-SPEC errors
            # above stay structural: the spec itself describes no extractable
            # code, so retrying the identical spec cannot help.
            return self._fail(
                state, record, name, f"header seed: {error}",
                stage="header-seed", result=RESULT_RETRYABLE,
            )
        # 2a. canonical SDK declaration sync (v2/v3 design step 1). The
        # per-unit seeds are snapshots taken before the corpus-validated
        # gnt4_* canon landed in gnt4_shim_seed.h, so on every (re)attempt
        # the seed is synchronised with the canon -- ONLY for the gnt4_*
        # symbols this unit's verbatim .c references (injected when absent,
        # superseded in place when divergent, untouched when identical;
        # idempotent, atomic seed write). Same trust class as the transform:
        # deterministic, never a model decision. Any fault degrades to the
        # unsynced seed + event -- canon warmth is optional, the attempt is
        # not blocked on it.
        record["sdk_decl_sync"] = {"injected": [], "superseded": [], "unresolved": []}
        try:
            sdk_sync = sync_sdk_declarations(
                header_seed,
                unit_c,
                self.run_root / "gnt4_shim_seed.h",
                header_text=header,
            )
            header = sdk_sync.header_text
            record["sdk_decl_sync"] = {
                "injected": sdk_sync.injected,
                "superseded": sdk_sync.superseded,
                "unresolved": sdk_sync.unresolved,
            }
            if sdk_sync.changed or sdk_sync.unresolved:
                self.events.emit(
                    "sdk_decl_sync",
                    unit=name,
                    injected=sdk_sync.injected,
                    superseded=sdk_sync.superseded,
                    unresolved=sdk_sync.unresolved,
                )
            if sdk_sync.write_error:
                self.events.emit(
                    "sdk_decl_sync_error",
                    unit=name,
                    error=f"seed write: {sdk_sync.write_error}"[:400],
                )
        except Exception as error:  # noqa: BLE001 - canon warmth is optional
            self.events.emit(
                "sdk_decl_sync_error", unit=name, error=str(error)[:400]
            )
        # 2a'. owner prototype sync (zz_*/FUN_*), same shape as 2a. Units red
        # out with owner_variant_abi_incompatible because the compile-fix
        # model invents zz_*/FUN_* prototypes from call-site rendering (the
        # Ghidra register-class fork: double where the corpus-anchored owner
        # says undefined8) -- the gate enforces the ORACLE-REGISTRY owner at
        # canonicalization, but nothing fed those prototypes into the seed,
        # so the model could only guess. This pass feeds INFORMATION only: it
        # injects/supersedes seed declarations for referenced symbols with an
        # owner prototype (excluding this unit's own definitions and gnt4_*,
        # which the SDK sync owns); it creates no new authority, and the
        # gate's contest machinery is untouched. Any fault degrades to the
        # unsynced seed + event -- warmth is optional, the attempt is not
        # blocked on it.
        record["owner_decl_sync"] = {"injected": [], "superseded": [], "unresolved": []}
        try:
            owner_sync = sync_owner_declarations(
                header_seed,
                unit_c,
                self.repo_root / "research/decomp/data/oracle-registry.json",
                unit_name=name,
                header_text=header,
            )
            header = owner_sync.header_text
            record["owner_decl_sync"] = {
                "injected": owner_sync.injected,
                "superseded": owner_sync.superseded,
                "unresolved": owner_sync.unresolved,
            }
            if owner_sync.changed or owner_sync.unresolved:
                self.events.emit(
                    "owner_decl_sync",
                    unit=name,
                    injected=owner_sync.injected,
                    superseded=owner_sync.superseded,
                    unresolved=owner_sync.unresolved,
                )
            if owner_sync.write_error:
                self.events.emit(
                    "owner_decl_sync_error",
                    unit=name,
                    error=f"seed write: {owner_sync.write_error}"[:400],
                )
        except Exception as error:  # noqa: BLE001 - owner warmth is optional
            self.events.emit(
                "owner_decl_sync_error", unit=name, error=str(error)[:400]
            )
        # D5: generated per-unit headers are seed SNAPSHOTS taken before the
        # helper landed in gnt4_shim_seed.h, so a transformed unit's header
        # must gain the seed-tier helper deterministically here (same trust
        # class as the transform; never a model decision).
        if materialized.transform["sites"]:
            header = ensure_bitcast_helper(header)

        # 2b. knowledge-registry augmentation (section 2.11, T2c [V4-1/V4-5]).
        # The unit's symbol set is recorded regardless (the section-2.8
        # relevant-delta gate needs it on reds), as are registry_version_used,
        # the holdout flag (F6) and the prompt version this attempt ran under.
        # ADVISORY BOUNDARY: augmentation only rewrites the STARTING header --
        # it never touches verdicts, never suppresses a conflict, and a
        # holdout unit starts from the cold seed untouched. Any registry
        # fault degrades to a cold seed + event; warmth is optional,
        # correctness is not.
        exports = unit["exported_functions"]
        symbols = unit_symbol_set(unit_c, exports)
        record["symbol_set"] = sorted(symbols)
        record["prompt_version"] = PROMPT_VERSION
        holdout = is_holdout(name)
        record["registry_holdout"] = holdout
        # Deviations are ATTEMPT-scoped: a stale list from a previous attempt
        # (different injection set) must never be folded into conflicts by
        # this attempt's step 5b (review F1 fold-in).
        record["registry_deviations"] = []
        authoritative_injected: list[dict[str, Any]] = []
        advisory_injected_count = 0
        registry = self._registry()
        record["registry_version_used"] = registry_version(registry)
        if not holdout and registry.get("entries"):
            try:
                prelude_decls = prelude_prototypes(prelude)
                augmented = augment_seed(
                    registry,
                    unit_name=name,
                    seed_text=header,
                    symbols=symbols,
                    prelude_declarations=prelude_decls,
                )
                header = augmented.header_text
                authoritative_injected = augmented.authoritative
                advisory_injected_count = len(augmented.advisory)
                if augmented.registry_changed:
                    # Prelude-vs-registry prototype disagreements: recorded on
                    # the entry as pending conflicts -- data, surfaced, never
                    # an injection (the prelude outranks a sibling's guess).
                    self._save_registry(registry)
                    for pending in augmented.pending_conflicts:
                        self.events.emit(
                            "registry_conflict",
                            unit=name,
                            key=pending.get("key"),
                            symbol=pending.get("symbol"),
                            entry_kind=pending.get("kind"),
                            pending=True,
                        )
                if augmented.injected_any:
                    (workdir / "seed-augmented.h").write_text(
                        header, encoding="utf-8", newline="\n"
                    )
                    self.events.emit(
                        "registry_injected",
                        unit=name,
                        registry_version=record["registry_version_used"],
                        authoritative=len(authoritative_injected),
                        advisory=advisory_injected_count,
                        skipped_contested=len(augmented.skipped_contested),
                    )
            except Exception as error:  # noqa: BLE001 - warmth is optional
                self.events.emit(
                    "registry_augment_error", unit=name, error=str(error)[:400]
                )
                header = header_seed.read_text(encoding="utf-8")
                if materialized.transform["sites"]:
                    header = ensure_bitcast_helper(header)
                authoritative_injected = []
        self._save_state(state)
        # The (augmented) seed is what the harvest diffs the winning header
        # against: anything already in it is seed-inherited, never harvested.
        augmented_seed_text = header
        (workdir / "gnt4_shim.h").write_text(header, encoding="utf-8", newline="\n")

        # 2c. targeted-symbol question (section 2.12(a), T3). On a RETRY whose
        # previous attempt's final diagnostics implicate <=5 symbols, open
        # with "declare exactly these N symbols given these call sites"
        # instead of another full-header round. The reply is merged into the
        # augmented seed and the normal loop resumes; the call REPLACES the
        # retry's first full-header round (max_iters shrinks by one), so the
        # attempt's call count does not grow. It is a different question AND
        # carries the post-mortem -- section 0.1 satisfied twice over.
        targeted_spent = False
        targeted_header_path: str | None = None
        previous_rounds = record.get("rounds") or []
        if (
            record.get("attempts", 0) >= 2
            and MAX_COMPILE_ITERS >= 2
            and previous_rounds
        ):
            symbols = targeted_question_symbols(
                previous_rounds[-1].get("diagnostics") or []
            )
            if symbols:
                self._heartbeat(f"wasm_units:{name}:targeted_question")
                post_mortem = assemble_post_mortem(record)
                diagnostics_text = "\n".join(
                    previous_rounds[-1].get("diagnostics") or []
                )
                prompt = (
                    (post_mortem + "\n\n" if post_mortem else "")
                    + "The previous attempt's final diagnostics implicate exactly "
                    + f"these symbols: {', '.join(symbols)}\n\n"
                    + f"Diagnostics:\n```\n{diagnostics_text}\n```\n\n"
                    + "The verbatim .c lines referencing them (line: text):\n"
                    + f"```c\n{referencing_lines(unit_c, symbols)}\n```\n\n"
                    + f"Declare exactly these {len(symbols)} symbol(s) for "
                    + "gnt4_shim.h given these call sites, following the typing "
                    + "rules above. Reply with ONLY the declarations/#defines "
                    + "for these symbols in a single ```c block."
                )
                try:
                    reply = self._llm_client().generate(
                        prompt=prompt,
                        system_prompt=SYSTEM_PROMPT
                        + (" /no_think" if DISABLE_THINKING else ""),
                        max_tokens=COMPILE_FIX_MAX_TOKENS,
                        phase=f"wasm_targeted_symbols:{name}",
                        stream_callback=lambda _event_type, _event: None,
                        **SAMPLING,
                        **(
                            {"chat_template_kwargs": {"enable_thinking": False}}
                            if DISABLE_THINKING
                            else {}
                        ),
                    )
                except Exception as error:  # noqa: BLE001 - same taxonomy as compile-fix
                    if self._is_context_budget_fault(error):
                        return self._fail(
                            state, record, name, f"context budget: {error}",
                            stage="context-budget", result=RESULT_GATE_FAILED,
                        )
                    if self._is_provider_fault(error):
                        return self._provider_pause(state, record, name, str(error))
                    return self._fail(
                        state, record, name, f"targeted-symbol LLM: {error}",
                        stage="targeted-question",
                    )
                targeted_spent = True
                record["model_requests"] = record.get("model_requests", 0) + 1
                self._save_state(state)
                blocks = CODE_BLOCK.findall(reply or "")
                merged = False
                if blocks:
                    header = merge_targeted_declarations(
                        header, max(blocks, key=len), symbols
                    )
                    (workdir / "gnt4_shim.h").write_text(
                        header, encoding="utf-8", newline="\n"
                    )
                    snapshot = (
                        workdir / f"header-attempt{record['attempts']}-iter0.h"
                    )
                    snapshot.write_text(header, encoding="utf-8", newline="\n")
                    targeted_header_path = str(snapshot)
                    merged = True
                self.events.emit(
                    "targeted_symbol_question",
                    unit=name,
                    symbols=symbols,
                    merged=merged,
                )

        # 3. build + LLM compile-fix loop (header-only edits; depth capped by
        #    OGHIDRA_PORT_MAX_ITERS per section 2.1, stage-aware stuck-abort
        #    per section 2.2, round-level malformed replies per section 2.5)
        model_used: str | None = None
        iterations = 0
        linked = False
        build_error = ""
        # Stuck-abort state: progress is only comparable within a stage, and
        # only across rounds where a new header was actually applied.
        previous_stage: str | None = None
        previous_fingerprint: str | None = None
        header_applied = False
        # Set when a returned header is rejected before it is applied; it is
        # appended to the NEXT round's prompt. Assigning prompt_errors directly
        # would not survive -- it is recomputed from build_error each iteration.
        header_guard_note: str | None = None
        no_new_header_rounds = 0
        # Section 2.5 [V4-9]: a SECOND consecutive no_new_header round ends
        # the attempt -- after the format-reminder re-ask has also failed, the
        # next iteration would call the model with byte-identical inputs (same
        # header, same errors, same base prompt), which is exactly the retry
        # section 0.1 forbids. Tracked separately from the total because a
        # recovered round (header applied) resets the consecutive count.
        consecutive_no_header = 0
        no_header_shapes: list[str] = []
        # Symbols already paged as registry deviations (one event per symbol
        # per attempt; the model re-emits the whole header every round).
        reported_deviations: set[str] = set()
        current_header_path = targeted_header_path or str(header_seed)
        # Section 2.12(a): a spent targeted call replaces the retry's first
        # full-header round -- the depth budget shrinks by one so the
        # attempt's total model-call count does not grow.
        max_iters = MAX_COMPILE_ITERS - (1 if targeted_spent else 0)
        # Per-round memory (section 2.3 [V4-4]): stage, error count, header
        # path, plus the NORMALIZED DIAGNOSTIC SET and its fingerprint --
        # "never cleared" is then a set intersection and cross-attempt
        # oscillation detection a fingerprint comparison. Persisted into the
        # unit state record on _fail for the post-mortem carry.
        rounds: list[dict[str, Any]] = []
        for iteration in range(1, max_iters + 1):
            iterations = iteration
            if iteration == 1 or header_applied:
                self._heartbeat(f"wasm_units:{name}:build:{iteration}")
                try:
                    linked, build_error = self._build_runner(
                        workdir, exports, unit.get("allowed_extra_imports") or None
                    )
                except (OSError, subprocess.SubprocessError) as error:
                    return self._fail(
                        state, record, name, f"build runner: {error}", stage="build",
                    )
                self.events.emit(
                    "wasm_unit_build", unit=name, iteration=iteration, linked=linked
                )
                if linked:
                    break
                # Stage + fingerprint come from the RAW build output; the
                # prompt's summary is truncated and must not feed either.
                stage = classify_build_stage(build_error)
                fingerprint = diagnostic_fingerprint(build_error)
                rounds.append(
                    {
                        "iteration": iteration,
                        "stage": stage,
                        "error_count": count_error_lines(build_error),
                        "header": current_header_path,
                        "diagnostics": normalized_diagnostics(build_error),
                        "fingerprint": fingerprint,
                    }
                )
                if is_stuck(
                    previous_stage, previous_fingerprint,
                    stage, fingerprint, header_applied,
                ):
                    return self._fail(
                        state, record, name,
                        "stuck: identical diagnostics after applied fix",
                        stage="compile-fix", extra={"rounds": rounds},
                    )
                previous_stage, previous_fingerprint = stage, fingerprint
            # else: section 2.5 exemption -- the previous round applied no new
            # header, so the previous build's result is already in hand;
            # rebuilding the identical input would yield the identical output,
            # and the fingerprint comparison is skipped for that round.
            if iteration == max_iters:
                break
            self._heartbeat(f"wasm_units:{name}:compile_fix:{iteration}")
            header_text = (workdir / "gnt4_shim.h").read_text(encoding="utf-8")
            # Section 2.4: the model sees the deduplicated summary; the raw
            # text stays in build_error for fingerprinting and the state record.
            prompt_errors = summarise_build_error(build_error, budget=2000)
            if header_guard_note:
                prompt_errors = prompt_errors + chr(10) + chr(10) + header_guard_note
                header_guard_note = None
            fixed = None
            for format_reminder in (False, True):
                try:
                    fixed = self._compile_fix(
                        unit_c, header_text, prompt_errors,
                        unit_name=name,
                        format_reminder=format_reminder,
                    )
                except Exception as error:  # noqa: BLE001
                    # A PROVIDER outage is not this unit's fault. Blaming the unit
                    # is how 19 consecutive units were marked red_retryable on
                    # 2026-08-15 for "Serving context still 32768 < required 33974"
                    # and "Custom API returned no assistant content" -- provider
                    # faults, recorded as per-unit verdicts, with the rig unable to
                    # see an outage at all because wasm mode never raised one.
                    if self._is_context_budget_fault(error):
                        # Not a provider outage and not a bad unit: this unit's
                        # prompt simply does not fit the configured serving context.
                        # Naming it as its own class makes the repeated-failure
                        # section of the README say exactly which knob to turn,
                        # instead of burying 1,500 units under "compile-fix LLM".
                        return self._fail(
                            state, record, name, f"context budget: {error}",
                            stage="context-budget", result=RESULT_GATE_FAILED,
                            extra={"rounds": rounds},
                        )
                    if self._is_provider_fault(error):
                        return self._provider_pause(state, record, name, str(error))
                    return self._fail(
                        state, record, name, f"compile-fix LLM: {error}",
                        stage="compile-fix", extra={"rounds": rounds},
                    )
                record["model_requests"] = record.get("model_requests", 0) + 1
                model_used = getattr(self._llm, "default_model", None) or model_used
                self._save_state(state)
                if fixed is not None:
                    break
                # First miss: fall through to the single format-reminder
                # re-ask (section 2.5). Second miss: handled below.
            if fixed is None:
                # Section 2.5: a malformed reply is ROUND-level, never
                # attempt-level. Record the round, skip the rebuild (the
                # header is unchanged, so the failing build result stands),
                # and give the next iteration a fresh model call.
                no_new_header_rounds += 1
                consecutive_no_header += 1
                shape = (
                    getattr(self, "_last_reply_shape", None) or "no reply captured"
                )
                no_header_shapes.append(shape)
                header_applied = False
                self.events.emit(
                    "wasm_unit_no_new_header",
                    unit=name,
                    iteration=iteration,
                    reply_shape=shape,
                )
                if consecutive_no_header >= 2:
                    # Section 2.5 [V4-9]: the first re-ask carried new
                    # information ("your reply had no code block"); a THIRD
                    # identical ask would not. Two consecutive extraction
                    # misses end the attempt -- red, retryable, and the
                    # world-changed gate (section 2.8) then governs like any
                    # other red.
                    return self._fail(
                        state, record, name,
                        "no new header: two consecutive compile-fix rounds "
                        "(ask + format-reminder re-ask each) returned no code "
                        "block; a further same-input round is forbidden "
                        "(section 0.1). Reply shapes: "
                        + " | ".join(no_header_shapes[-2:]),
                        stage="compile-fix", extra={"rounds": rounds},
                    )
                continue
            consecutive_no_header = 0
            # Section 2.11 survival check [V4-6]: SEMANTIC (normalized token
            # sequences on re-parse), and applied ONLY to oracle_green
            # authoritative entries -- advisory entries are free to be
            # ignored; that is their point [V4-1]. A deviation never aborts
            # the round (the header may still compile): it is recorded, and
            # if the unit goes green with it, harvest turns it into a
            # conflict record.
            if authoritative_injected:
                deviations = check_survival(authoritative_injected, fixed)
                for deviation in deviations:
                    if deviation.get("symbol") in reported_deviations:
                        continue
                    reported_deviations.add(deviation.get("symbol"))
                    self.events.emit(
                        "registry_deviation",
                        unit=name,
                        iteration=iteration,
                        key=deviation.get("key"),
                        symbol=deviation.get("symbol"),
                        entry_kind=deviation.get("kind"),
                        expected=deviation.get("expected"),
                        found=deviation.get("found"),
                    )
                record["registry_deviations"] = deviations
                self._save_state(state)
            # D5 [review M4]: re-ensure the seed-tier helper on EVERY
            # model-returned header -- absence becomes impossible rather than
            # loud-then-model-defined (closes the F-D5-4 "model drops or
            # redefines the helper" channel deterministically).
            if materialized.transform["sites"]:
                fixed = ensure_bitcast_helper(fixed)
            # The model's shortcut to "make it link" is to DEFINE the missing
            # callee in the header, e.g. `void FUN_801336a4(void) { }`. That is
            # not a shim: it creates a real symbol and silently replaces the ROM
            # function with an empty body. Canonicalization catches it at the
            # assembly gate, but only for symbols that have a registry owner, and
            # only after the whole compile-fix loop has been paid for. Reject it
            # here and hand the model the reason. `static` helpers are fine --
            # the seed carries two.
            # Only SDK/runtime symbols may not be defined here. This is the exact
            # complement of the import gate's rule, and the two must stay
            # complementary or they livelock: that gate tells the model a
            # non-gnt4_ symbol which became an undefined wasm import "must be
            # DEFINED in gnt4_shim.h", so rejecting THAT definition leaves the
            # model no legal move -- the header is not applied, the next
            # iteration rebuilds identical input, diagnostics repeat, and the
            # stuck detector reds the unit. Measured: every unit this guard
            # fired on went red (auto-c0035-004, auto-c0035-007, auto-c0050-005).
            # A gnt4_ symbol is different: it is always provided elsewhere, so a
            # local definition is a real duplicate. Ownerless ROM symbols are
            # left to canonicalization at the assembly gate, which is where the
            # registry-owner check actually lives.
            invented = [
                symbol
                for symbol in header_defines_external_functions(fixed)
                if symbol.startswith("gnt4_") or symbol.startswith("__gnt4_")
            ]
            if invented:
                header_guard_note = (
                    'gnt4_shim.h must DECLARE, never DEFINE, an SDK symbol. Your '
                    'reply defined ' + ', '.join(invented[:6])
                    + ". The SDK provides that symbol at link time, so a definition "
                    'here is a duplicate. Replace each with a declaration ending in '
                    "';'. A `static` helper is the only definition allowed."
                )
                self.events.emit(
                    'wasm_unit_header_defines_symbol',
                    unit=name,
                    iteration=iteration,
                    symbols=invented[:6],
                )
                # The header was NOT applied, so the next iteration must not
                # rebuild identical input -- reuse this round's build_error.
                header_applied = False
                continue
            (workdir / "gnt4_shim.h").write_text(fixed, encoding="utf-8", newline="\n")
            # Section 2.3 [V4-4]: snapshots are ATTEMPT-scoped
            # (header-attempt{A}-iter{I}.h) so a later attempt can never
            # overwrite the artifact the post-mortem carry decision needs.
            snapshot = workdir / f"header-attempt{record['attempts']}-iter{iteration}.h"
            snapshot.write_text(fixed, encoding="utf-8", newline="\n")
            current_header_path = str(snapshot)
            header_applied = True
        if not linked:
            # Concrete-type structural classifier (section 2.7, T3): a cast
            # contradiction between concrete built-in types on unit-declared
            # locals, never cleared across every applied header of this
            # attempt, is provably header-independent -- settle it instead of
            # retrying forever. Everything else stays retryable.
            final_stage = (
                rounds[-1]["stage"] if rounds else classify_build_stage(build_error)
            )
            if rounds and final_stage == STAGE_COMPILE:
                proofs = concrete_type_contradictions(unit_c, rounds)
                if proofs:
                    return self._fail(
                        state, record, name,
                        "concrete-type contradiction, header-independent "
                        "(section 2.7): " + "; ".join(proofs[:3]),
                        stage="compile-fix",
                        result=RESULT_STRUCTURAL_INELIGIBLE,
                        extra={"rounds": rounds},
                    )
            detail = f"not linked: {summarise_build_error(build_error)}"
            if no_new_header_rounds:
                detail += (
                    f" ({no_new_header_rounds} compile-fix round(s) returned "
                    "no code block: "
                    f"{getattr(self, '_last_reply_shape', None) or 'no reply captured'})"
                )
            return self._fail(
                state, record, name, detail,
                stage="wasm-link", result=RESULT_GATE_FAILED,
                extra={"rounds": rounds},
            )

        # 4. oracle gate. Tier "compile_only" (auto-generated chunk units) has no
        # oracle yet: it passes build+import gates only, lands in the STAGING
        # artifact tree with verified:false provenance, and is never wired into
        # the app. Design stage 4 (oracle before trust) still governs promotion.
        # Sidecar overlay (oracle plan section 3.4): a validated sidecar entry
        # whose exports_sha256 matches this unit's export set replaces the
        # queue spec -- a compile_only unit gains a behavioral oracle the
        # moment its spec lands, no queue regeneration involved.
        oracle_spec = self._effective_oracle(unit) or {}
        compile_only = oracle_spec.get("type") == "compile_only"
        if compile_only:
            passed, summary, oracle_log = True, "compile-only (UNVERIFIED)", (
                "compile_only tier: build + import whitelist gates only; no "
                "behavioral oracle was run. NOT for app integration."
            )
        else:
            self._heartbeat(f"wasm_units:{name}:oracle")
            try:
                passed, summary, oracle_log = self._oracle_runner(
                    {**unit, "oracle": oracle_spec}, workdir / "unit.wasm"
                )
            except (OSError, subprocess.SubprocessError, FileNotFoundError) as error:
                return self._fail(
                    state, record, name, f"oracle runner: {error}", stage="oracle",
                )
        (workdir / "oracle.log").write_text(oracle_log, encoding="utf-8", newline="\n")
        if not passed:
            return self._fail(
                state, record, name, f"oracle red: {summary}",
                stage="oracle", result=RESULT_GATE_FAILED,
                extra={"rounds": rounds},
            )

        # 5. private candidate + pre-publication T2b gate. The authoritative
        # roots remain untouched until the exact candidate name/digest passes.
        artifact_dir = (
            self.staging_root if compile_only else self.artifact_root
        ) / name
        provenance = {
            "unit": name,
            "run_id": self.run_id,
            "generated_at": utc_now(),
            "extractions": extraction_records,
            "extracted_sha256": combined_sha,
            # D5-4: "is this artifact the output of transform vN?" -- the
            # pre-transform hashes above stay the export-chain answer; for
            # site-free units transformed_sha256 == extracted_sha256 (the
            # identity case the migration census re-stamps in place).
            "transform": materialized.transform,
            "exported_functions": exports,
            "compile_iterations": iterations,
            "model": model_used,
            "model_requests": record.get("model_requests", 0),
            "verified": not compile_only,
            "tier": "compile_only" if compile_only else "oracle_green",
            "allowed_extra_imports": unit.get("allowed_extra_imports") or [],
            # F6 provenance: which registry the unit started warm from (or
            # that it was a holdout and started cold).
            "registry": {
                "version_used": record.get("registry_version_used", 0),
                "holdout": record.get("registry_holdout", False),
                "authoritative_injected": [
                    r.get("symbol") for r in authoritative_injected
                ],
                "advisory_injected": advisory_injected_count,
            },
            "oracle": (
                {"type": "compile_only", "summary": summary}
                if compile_only
                else {
                    "command": oracle_spec["command"],
                    "cwd": oracle_spec["cwd"],
                    "summary": summary,
                }
            ),
        }
        transaction = self._create_promotion_attempt(
            name=name,
            attempt=record.get("attempts", 0),
            workdir=workdir,
            provenance=provenance,
            destination=artifact_dir,
        )
        attempt_dir = transaction.attempt_dir
        candidate = transaction.candidate
        assembly_result = self._maybe_run_assembly_gate(
            name,
            candidate=candidate,
            workdir=attempt_dir / "assembly",
        )
        expected_binding = {"name": name, "sha256": candidate.sha256}
        binding_ok = assembly_result.get("candidate") == expected_binding
        if assembly_result.get("passed") is False or not binding_ok:
            assembly_evidence = {
                "passed": False,
                "n": assembly_result.get("n"),
                "units": assembly_result.get("units") or [],
                "stage": assembly_result.get("stage"),
                "conflicts": (assembly_result.get("conflicts") or [])[:20],
                "detail": (assembly_result.get("detail") or "")[:1200],
                "candidate": assembly_result.get("candidate"),
                "expected_candidate": expected_binding,
            }
            try:
                self._cleanup_promotion_attempt(attempt_dir)
                assembly_evidence["attempt_cleanup"] = "removed"
            except Exception as cleanup_error:  # noqa: BLE001 - evidence below
                assembly_evidence["attempt_cleanup"] = "failed"
                assembly_evidence["cleanup_error"] = str(cleanup_error)[:600]
                self.events.emit(
                    "promotion_attempt_cleanup_failed",
                    unit=name,
                    attempt_id=attempt_dir.name,
                    error=str(cleanup_error)[:400],
                )
            detail = assembly_evidence["detail"] or (
                f"{len(assembly_evidence['conflicts'])} conflict(s)"
            )
            if not binding_ok:
                detail = (
                    f"candidate binding mismatch: expected {expected_binding}, "
                    f"observed {assembly_result.get('candidate')}"
                )
            return self._fail(
                state,
                record,
                name,
                f"assembly gate {assembly_evidence['stage']} failed before "
                f"promotion: {detail}",
                stage="assembly",
                result=RESULT_GATE_FAILED,
                extra={"rounds": rounds, "assembly_gate": assembly_evidence},
                journal_required=True,
            )

        promotion_outcome = {
            "result": RESULT_STAGED if compile_only else RESULT_GREEN,
            "tier": "compile_only" if compile_only else "oracle_green",
            "summary": summary,
            "detail": (
                "compile-only staging artifact (UNVERIFIED, not integrated)"
                if compile_only
                else f"oracle green: {summary}"
            ),
            "model": model_used or self._model_config.model,
            "attempt": record.get("attempts", 0),
        }
        try:
            self._update_promotion_marker(attempt_dir, phase="gate-passed")
            self._update_promotion_marker(attempt_dir, phase="installing")
            install_result = self._install_promotion_candidate(transaction, record)
            self._update_promotion_marker(
                attempt_dir,
                phase="artifact-installed",
                install_result=install_result,
                artifact_postimage_sha256=unit_artifact_sha256(artifact_dir),
                outcome=promotion_outcome,
            )
            self._promotion_phase_boundary("install", transaction)
            self._verify_transaction_replacement_state(transaction)
        except Exception as install_error:  # noqa: BLE001 - refuse any overwrite
            install_marker = self._promotion_marker(attempt_dir) or {}
            replacement_authorization = install_marker.get(
                "replacement_authorization"
            )
            try:
                self._rollback_uncommitted_transaction(
                    transaction, reason="artifact-install"
                )
                rollback_detail = ""
            except Exception as rollback_error:  # noqa: BLE001 - stop safely
                rollback_detail = f"; rollback failed: {rollback_error}"
            if rollback_detail:
                self.events.emit(
                    "promotion_transaction_blocked",
                    unit=name,
                    phase="artifact-install",
                    error=f"{install_error}{rollback_detail}"[:600],
                )
                return "journal_blocked"
            if isinstance(replacement_authorization, dict):
                try:
                    current_snapshot = load_canonical_state_snapshot(self.state_path)
                except ValueError:
                    current_snapshot = None
                if (
                    current_snapshot is None
                    or current_snapshot.sha256
                    != replacement_authorization.get("canonical_state_sha256")
                ):
                    self.events.emit(
                        "promotion_transaction_blocked",
                        unit=name,
                        phase="artifact-install",
                        error="canonical state changed during replacement; "
                        "artifact restored, refusing stale verdict write",
                    )
                    return "journal_blocked"
            return self._fail(
                state,
                record,
                name,
                f"artifact install refused after assembly pass: {install_error}"
                f"{rollback_detail}",
                stage="artifact-install",
                result=RESULT_GATE_FAILED,
                extra={
                    "rounds": rounds,
                    "assembly_gate": assembly_result,
                    "candidate_sha256": candidate.sha256,
                },
                journal_required=True,
            )

        # 5b. registry harvest (section 2.11, T2c [V4-1]): mechanical, no LLM.
        # The unit's own decisions (diffed against the AUGMENTED seed, minus
        # callee stubs) enter the registry at the unit's tier; the unit's
        # independent derivation doubles as the per-entry replication
        # experiment, so a disagreement with an advisory entry is filed as a
        # conflict here -- surfaced immediately, never deferred to assembly.
        # The registry file rides the unit's own artifact commit (one push,
        # G3-preserving). A harvest fault never costs the green.
        registry_rel: str | None = None
        self._capture_registry_preimage(transaction)
        try:
            final_header = (workdir / "gnt4_shim.h").read_text(encoding="utf-8")
            registry = self._registry()
            assembly_fold = None
            if self.assembly_ledger_path.is_file():
                assembly_fold = fold_assembly_conflict_ledger(
                    registry,
                    read_stable_assembly_ledger_bytes(self.assembly_ledger_path),
                )
            harvest = harvest_unit(
                registry,
                unit_name=name,
                tier=TIER_COMPILE_ONLY if compile_only else TIER_ORACLE_GREEN,
                seed_text=augmented_seed_text,
                header_text=final_header,
                unit_c_text=unit_c,
                holdout=holdout,
            )
            # Review F1: fold SURVIVING deviations into conflicts[] -- both
            # pieces are in hand here (the round-recorded deviations and the
            # registry). check_survival fired registry_deviation during the
            # loop; a deviation the unit went green with is dissent the
            # ledger must carry, or later units keep receiving the
            # possibly-wrong authoritative line with zero recorded doubt.
            # (harvest_unit already files re-expressions it can parse; this
            # dedups against those and adds the deletion/unparseable cases.)
            deviation_fold = record_surviving_deviations(
                registry,
                unit_name=name,
                tier=TIER_COMPILE_ONLY if compile_only else TIER_ORACLE_GREEN,
                deviations=record.get("registry_deviations") or [],
            )
            if (
                (assembly_fold is not None and assembly_fold.changed)
                or harvest.changed
                or deviation_fold.changed
            ):
                self._save_registry(registry)
                registry_rel = REGISTRY_RELPATH
            if assembly_fold is not None and assembly_fold.changed:
                self.events.emit(
                    "registry_assembly_conflicts_imported",
                    unit=name,
                    registry_version=registry_version(registry),
                    imported=assembly_fold.imported,
                    ledger_sha256=assembly_fold.ledger_sha256,
                )
            for conflict in harvest.new_conflicts + deviation_fold.new_conflicts:
                payload = {
                    "unit": name,
                    "key": conflict.get("key"),
                    "symbol": conflict.get("symbol"),
                    "entry_kind": conflict.get("kind"),
                    "tier": conflict.get("tier"),
                    "against_tier": conflict.get("against_tier"),
                    "contested": conflict.get("contested"),
                    "green_green": conflict.get("green_green"),
                    "deviation": conflict.get("deviation", False),
                }
                self.events.emit("registry_conflict", **payload)
                if conflict.get("green_green"):
                    # Section 4 invariant row: two behaviourally-verified
                    # units disagreeing on one symbol's typing is a real
                    # program-semantics finding -- page the owner.
                    self.events.emit("registry_green_green_conflict", **payload)
            if harvest.changed or deviation_fold.changed:
                self.events.emit(
                    "registry_harvested",
                    unit=name,
                    registry_version=registry_version(registry),
                    added=len(harvest.added),
                    agreed=len(harvest.agreed),
                    conflicts=len(harvest.new_conflicts)
                    + len(deviation_fold.new_conflicts),
                )
        except Exception as error:  # noqa: BLE001 - harvest never fails a unit
            self.events.emit(
                "registry_harvest_error", unit=name, error=str(error)[:400]
            )
        self._record_registry_postimage(transaction)
        self._promotion_phase_boundary("registry", transaction)
        try:
            self._verify_transaction_replacement_state(transaction)
        except RuntimeError as state_error:
            try:
                self._rollback_uncommitted_transaction(
                    transaction, reason="replacement-state-changed"
                )
            except Exception as rollback_error:  # noqa: BLE001 - fail closed
                self.events.emit(
                    "promotion_transaction_blocked",
                    unit=name,
                    phase="replacement-state-rollback",
                    error=f"{state_error}; rollback failed: {rollback_error}"[:600],
                )
                return "journal_blocked"
            self.events.emit(
                "promotion_transaction_blocked",
                unit=name,
                phase="replacement-state-changed",
                error=str(state_error)[:600],
            )
            return "journal_blocked"

        paths, commit_message = self._unit_commit_spec(
            name,
            summary,
            staging=compile_only,
            extra_paths=[registry_rel] if registry_rel else None,
        )
        try:
            sha, commit_detail = self._prepare_unit_commit(
                transaction, paths=paths, message=commit_message
            )
        except (OSError, subprocess.SubprocessError) as error:
            sha, commit_detail = None, str(error)
        if sha is None:
            marker = self._promotion_marker(attempt_dir) or {}
            current = self._git_runner("rev-parse", "HEAD")
            if (
                marker.get("head_preimage")
                and current.returncode == 0
                and current.stdout.strip() != marker.get("head_preimage")
            ):
                # The commit may exist in the crash gap before its SHA reached
                # the marker. Restart validates/adopts it; never rebuild.
                self.events.emit(
                    "promotion_transaction_blocked",
                    unit=name,
                    phase="commit-preparing",
                    error=(commit_detail or "prepared commit SHA not recorded")[:600],
                )
                return "journal_blocked"
            try:
                self._rollback_uncommitted_transaction(
                    transaction, reason="commit-prepare"
                )
            except Exception as rollback_error:  # noqa: BLE001 - stop safely
                self.events.emit(
                    "promotion_transaction_blocked",
                    unit=name,
                    phase="commit-prepare-rollback",
                    error=str(rollback_error)[:600],
                )
                return "journal_blocked"
            return self._fail(
                state,
                record,
                name,
                f"product commit preparation failed: {commit_detail}",
                stage="commit",
                journal_required=True,
            )
        self._promotion_phase_boundary("local_commit", transaction)
        try:
            finalized = self._finalize_promotion_transaction(
                state,
                attempt_dir,
                self._promotion_marker(attempt_dir) or {},
                prepared_in_process=True,
            )
        except Exception as error:  # noqa: BLE001 - restart owns exact recovery
            self.events.emit(
                "promotion_transaction_blocked",
                unit=name,
                phase="finalize",
                error=str(error)[:600],
            )
            return "journal_blocked"
        if not finalized:
            self.events.emit(
                "wasm_unit_journal_blocked",
                unit=name,
                stage="commit",
                result=RESULT_STAGED if compile_only else RESULT_GREEN,
                error="promotion publication or green checkpoint remains pending",
            )
            return "journal_blocked"
        record = self._unit_state(state, name)
        self._greens_this_run += 1
        self.events.emit(
            "wasm_unit_green",
            unit=name,
            oracle_summary=summary,
            commit=sha,
            pushed=True,
            push_detail="",
        )
        # Section 4 T3 row: verified fraction falling while staged grows pages
        # (unverifiable-inventory build-up).
        self._flag_unverified_inventory(state)
        return "green"

    @staticmethod
    def _is_context_budget_fault(error: Exception) -> bool:
        """The prompt cannot fit the CONFIGURED context, so no retry can help
        until the configuration changes. Distinct from a provider outage."""
        message = str(error).lower()
        return (
            "a reload cannot help" in message
            or "context_length_exceeded" in message
            or ("exceeds the" in message and "context window" in message)
        )

    @staticmethod
    def _is_provider_fault(error: Exception) -> bool:
        """Is this the serving host failing, rather than the unit being bad?

        Uses the SAME marker list the chunk workflow's pause rule uses, plus the
        two shapes the wasm compile-fix loop actually produced live: a served
        context too small for the request, and an empty assistant response.
        """
        message = str(error).lower()
        if any(marker in message for marker in TRANSIENT_MARKERS):
            return True
        return (
            "returned no assistant content" in message
            or "serving context still" in message
        )

    def _provider_pause(
        self, state: dict[str, Any], record: dict[str, Any], name: str, detail: str
    ) -> str:
        """Hand the unit back untouched and tell the machine the provider is out.

        The unit keeps its previous status (it earned no verdict) and its
        attempt is refunded, so it does not sink behind the queue for a fault
        that was not its own.
        """
        record["attempts"] = max(0, record.get("attempts", 1) - 1)
        record["status"] = "pending"
        record["error"] = f"provider unavailable: {detail[:800]}"
        record["last_stage"] = "compile-fix"
        self._save_state(state)
        self._provider_paused_detail = detail[:600]
        self.events.emit("provider_unavailable", unit=name, error=detail[:600])
        self._checkpoint(
            state,
            UnitTransition(
                unit=name,
                result=RESULT_DEFERRED,
                stage="compile-fix",
                attempt=record.get("attempts", 0),
                detail=f"provider unavailable, unit not blamed: {detail[:400]}",
                model=self._model_config.model,
            ),
            workflow_state="provider_paused",
        )
        return "provider_paused"

    def _fail(
        self,
        state: dict[str, Any],
        record: dict[str, Any],
        name: str,
        error: str,
        *,
        stage: str = "port",
        result: str = RESULT_RETRYABLE,
        extra: dict[str, Any] | None = None,
        journal_required: bool = False,
    ) -> str:
        # Owner design: no countdown kills a unit; red units sink behind
        # less-attempted work and come around again. `structural_ineligible` is
        # the one class that is NOT a retry candidate -- the queue entry itself
        # does not describe extractable code.
        status = (
            "structural_ineligible"
            if result == RESULT_STRUCTURAL_INELIGIBLE
            else "red_retryable"
        )
        # Section 2.8 [V4-3]: every verdict records the world it was reached
        # under; section 2.3 [V4-4]: the rounds summary rides along so the
        # post-mortem is assemblable later without the workdir.
        world = self._world_version()
        payload: dict[str, Any] = dict(extra or {})
        payload["world_version"] = world
        diagnosis_eligible = stage in SOURCE_DIAGNOSIS_STAGES
        payload["failure_domain"] = (
            "source-compiler" if diagnosis_eligible else "pipeline-control"
        )
        payload["diagnosis_eligible"] = diagnosis_eligible
        transition = UnitTransition(
            unit=name,
            result=result,
            stage=stage,
            attempt=record.get("attempts", 0),
            detail=error,
            model=self._model_config.model,
            product_commit_failed=stage == "commit",
            product_commit_detail=error if stage == "commit" else "",
            extra=payload,
        )
        record_update = dict(payload)
        record_update.update(status=status, error=error[:2000], last_stage=stage)
        projected_state = self._project_record_update(state, name, record_update)
        projected_record = projected_state["units"][name]
        source_failure_id = self._source_failure_id(name, projected_record)
        if source_failure_id is not None:
            record_update["source_failure_id"] = source_failure_id
            projected_record["source_failure_id"] = source_failure_id
        else:
            projected_record.pop("source_failure_id", None)
            record_update["source_failure_id"] = None
        if status in self.SETTLED_STATUSES or journal_required:
            # Settling removes the unit from the queue permanently, and
            # `_reconcile_interrupted` only rescues units left as `porting`.
            # Assembly failures also require durable evidence before canonical
            # state advances: without it the selector could move on while the
            # only failure record was lost.
            checkpointed = self._checkpoint(projected_state, transition)
            if journal_required and not checkpointed:
                self.events.emit(
                    "wasm_unit_journal_blocked",
                    unit=name,
                    stage=stage,
                    result=result,
                    error="required progress checkpoint was not durable",
                )
                return "journal_blocked"
            record.update(record_update)
            self._save_state(state)
        else:
            record.update(record_update)
            self._save_state(state)
            self._checkpoint(state, transition)
        self.events.emit(
            "wasm_unit_red", unit=name, error=error[:600], attempts=record.get("attempts", 0),
            stage=stage, result=result,
        )
        return status

    # --------------------------------------------------------------------- run

    # Statuses that permanently take a unit out of the work pool. Anything else
    # (pending, porting, red_retryable) still counts as work: red units are
    # retried forever by design, so only these two end the queue.
    SETTLED_STATUSES = {"green", "structural_ineligible"}

    # ------------------------------------------------------------------ settle

    _SETTLE_RESULTS = {
        "structural_ineligible": RESULT_STRUCTURAL_INELIGIBLE,
        "green": RESULT_GREEN,
    }

    def settle_unit(self, unit_name: str, status: str, reason: str) -> dict[str, Any]:
        """Settle one unit verdict THROUGH the journal (section 2.9 [V4-9]).

        The only sanctioned way to hand-settle, carry, or migrate a verdict:
        backs up the state file, edits the record, emits the journal
        checkpoint and the events.jsonl event, then saves. Hand-editing
        wasm-units-state.json is forbidden (module docstring / AGENTS.md) --
        the 2026-08-20 migration wrote verdicts out-of-band and events.jsonl
        has disagreed with live state ever since.
        """
        if status not in self._SETTLE_RESULTS:
            raise ValueError(
                f"settle status must be one of {sorted(self._SETTLE_RESULTS)}, "
                f"got {status!r}"
            )
        if not (reason or "").strip():
            raise ValueError("a settle requires a non-empty reason")
        if not self.lock.acquire():
            raise RuntimeError(
                "another wasm-units driver holds wasm-units.lock; "
                "settling under a running driver would race its state writes"
            )
        try:
            state = self._load_state()
            known: set[str] = set(state.get("units", {}))
            try:
                known.update(unit["name"] for unit in self._load_queue())
            except (FileNotFoundError, json.JSONDecodeError, ValueError, OSError):
                pass  # a queue-less checkout can still settle a known record
            if unit_name not in known:
                raise ValueError(
                    f"unknown unit {unit_name!r}: not in the queue or the state file"
                )
            # Backup BEFORE any edit: a settle is permanent, and the backup is
            # what makes a mistaken one recoverable.
            backup: str | None = None
            if self.state_path.is_file():
                backup_path = self.state_path.with_name(
                    f"{self.state_path.name}.settle-backup-"
                    + utc_now().replace(":", "").replace("-", "")
                )
                shutil.copyfile(self.state_path, backup_path)
                backup = backup_path.name
            record = self._unit_state(state, unit_name)
            previous_status = record.get("status")
            transition = UnitTransition(
                unit=unit_name,
                result=self._SETTLE_RESULTS[status],
                stage="manual-settle",
                attempt=record.get("attempts", 0),
                detail=f"settled via settle-unit: {reason}",
                model=self._model_config.model,
                extra={
                    "settled_via": "settle-unit",
                    "previous_status": previous_status,
                    "world_version": self._world_version(),
                },
            )
            # Settling removes the unit from the pool permanently: record it
            # remotely BEFORE it becomes unrecoverable locally (same order as
            # _fail's settled branch).
            self._checkpoint(state, transition)
            record.update(
                status=status,
                error=reason if status == "structural_ineligible" else None,
                last_stage="manual-settle",
                settle_reason=reason,
                settled_via="settle-unit",
                world_version=self._world_version(),
            )
            self._save_state(state)
            self.events.emit(
                "verdict_settled",
                unit=unit_name,
                status=status,
                previous_status=previous_status,
                reason=reason[:600],
                via="settle-unit",
            )
            return {
                "unit": unit_name,
                "status": status,
                "previous_status": previous_status,
                "backup": backup,
                "state_file": str(self.state_path),
            }
        finally:
            self.lock.release()

    def revoke_unit(self, unit_name: str, reason: str) -> dict[str, Any]:
        """Revoke one settled verdict and requeue it through the journal.

        This is the generic recovery counterpart to ``settle_unit``. The stale
        staged artifact remains as audit evidence and is overwritten by the
        next successful attempt. No product ref is rewound or pushed; the one
        required remote write is the append-only ``port-progress`` journal.

        The transition id is deterministic for the verdict preimage + reason.
        If a crash happens after the journal checkpoint but before the
        registry/state saves, rerunning the exact command completes the same
        transition without duplicating its durable journal record.
        """
        reason = (reason or "").strip()
        if not reason:
            raise ValueError("a revocation requires a non-empty reason")
        if not self.lock.acquire():
            raise RuntimeError(
                "another wasm-units driver holds wasm-units.lock; "
                "revoking under a running driver would race its state writes"
            )
        try:
            state = self._load_state()
            known: set[str] = set(state.get("units", {}))
            try:
                known.update(unit["name"] for unit in self._load_queue())
            except (FileNotFoundError, json.JSONDecodeError, ValueError, OSError):
                pass
            if unit_name not in known:
                raise ValueError(
                    f"unknown unit {unit_name!r}: not in the queue or the state file"
                )
            record = self._unit_state(state, unit_name)
            prior_revocation = record.get("revoked") or {}
            if (
                record.get("status") == "pending"
                and prior_revocation.get("via") == "revoke-unit"
                and prior_revocation.get("reason") == reason
            ):
                return {
                    "unit": unit_name,
                    "status": "pending",
                    "previous_status": prior_revocation.get("previous_status"),
                    "transition_id": prior_revocation.get("transition_id"),
                    "backup": None,
                    "already_requeued": True,
                    "state_file": str(self.state_path),
                }
            previous_status = record.get("status")
            if previous_status not in self.SETTLED_STATUSES:
                raise ValueError(
                    f"unit {unit_name!r} has no settled verdict to revoke "
                    f"(status={previous_status!r})"
                )

            backup = self._backup_state()
            previous_tier = record.get("tier")
            previous_commit = record.get("commit")
            previous_candidate_sha256 = record.get("candidate_sha256")
            previous_record = json.loads(json.dumps(record))
            previous_record_sha256 = hashlib.sha256(
                json.dumps(
                    previous_record, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            ).hexdigest()
            transition_preimage = {
                "schema": 2,
                "unit": unit_name,
                "reason": reason,
                # The full canonical unit record is the verdict preimage. A
                # changed oracle binding, push receipt, world version, or
                # promotion identity must mint a distinct revocation even when
                # status/tier/commit happen to match.
                "previous_record": previous_record,
            }
            transition_id = "verdict-revoke-" + hashlib.sha256(
                json.dumps(
                    transition_preimage, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            ).hexdigest()
            revoked_at = utc_now()
            revoked = {
                "via": "revoke-unit",
                "at": revoked_at,
                "reason": reason,
                "previous_status": previous_status,
                "previous_tier": previous_tier,
                "previous_commit": previous_commit,
                "previous_candidate_sha256": previous_candidate_sha256,
                "previous_oracle_summary": record.get("oracle_summary"),
                "previous_record_sha256": previous_record_sha256,
                "transition_id": transition_id,
            }
            projected = self._project_record_update(
                state,
                unit_name,
                {
                    "status": "pending",
                    "error": None,
                    "last_stage": "manual-revoke",
                    "revoked": revoked,
                },
            )
            projected_record = projected["units"][unit_name]
            for stale_key in (
                "tier",
                "oracle_summary",
                "commit",
                "pushed",
                "settle_reason",
                "settled_via",
                "promotion_transaction_id",
                "promotion_transition_id",
                "candidate_sha256",
                "world_version",
            ):
                projected_record.pop(stale_key, None)

            transition = UnitTransition(
                unit=unit_name,
                result=RESULT_DEFERRED,
                stage="manual-revoke",
                attempt=record.get("attempts", 0),
                detail=f"verdict revoked and requeued: {reason}",
                model=self._model_config.model,
                extra={
                    "revoked_via": "revoke-unit",
                    "previous_status": previous_status,
                    "previous_tier": previous_tier,
                    "previous_commit": previous_commit,
                    "previous_candidate_sha256": previous_candidate_sha256,
                    "previous_record_sha256": previous_record_sha256,
                    "transition_id": transition_id,
                },
            )
            if not self._checkpoint(
                projected,
                transition,
                workflow_state="maintenance",
                driver_running=False,
                require_progress_push=True,
            ):
                raise RuntimeError(
                    "revocation was not committed and pushed to port-progress; "
                    "canonical state remains unchanged"
                )

            registry_existed = self.registry_path.is_file()
            registry_preimage = json.loads(json.dumps(self._registry()))
            registry = json.loads(json.dumps(registry_preimage))
            retier = revoke_unit_entries(registry, unit_name)
            if retier.changed:
                self._save_registry(registry)
            try:
                self._save_state(projected)
            except BaseException:
                # Keep canonical state and the registry in the same verdict
                # world on an ordinary exception. A hard process loss between
                # these two atomic writes is recovered by rerunning the same
                # deterministic transition id.
                if retier.changed:
                    if registry_existed:
                        atomic_write_json(self.registry_path, registry_preimage)
                    else:
                        self.registry_path.unlink(missing_ok=True)
                    self._registry_cache = None
                raise
            state.clear()
            state.update(projected)
            self.events.emit(
                "verdict_revoked",
                unit=unit_name,
                previous_status=previous_status,
                previous_tier=previous_tier,
                previous_commit=previous_commit,
                reason=reason[:600],
                transition_id=transition_id,
                registry_version=retier.version,
                via="revoke-unit",
            )
            return {
                "unit": unit_name,
                "status": "pending",
                "previous_status": previous_status,
                "previous_tier": previous_tier,
                "previous_commit": previous_commit,
                "transition_id": transition_id,
                "registry_changed": retier.changed,
                "backup": backup,
                "already_requeued": False,
                "state_file": str(self.state_path),
            }
        finally:
            self.lock.release()

    def invalidate_diagnosis(
        self, unit_name: str, reason: str
    ) -> dict[str, Any]:
        """Sanction removal of a misrouted diagnosis through the journal.

        The product, artifact, and registry trees are outside this maintenance
        transaction.  The exact canonical record is its preimage; the durable
        progress receipt precedes the atomic canonical-state update.
        """
        reason = (reason or "").strip()
        if not reason:
            raise ValueError("diagnosis invalidation requires a non-empty reason")
        if not self.lock.acquire():
            raise RuntimeError(
                "another wasm-units driver holds wasm-units.lock; diagnosis "
                "invalidation would race its state writes"
            )
        try:
            state = self._load_state()
            record = state.get("units", {}).get(unit_name)
            if not isinstance(record, dict):
                raise ValueError(f"unknown canonical unit {unit_name!r}")
            prior = record.get("diagnosis_invalidation")
            if (
                not record.get("diagnosis")
                and not record.get("diagnosis_malformed")
                and not record.get("f4_nominated")
            ):
                if isinstance(prior, dict) and prior.get("reason") == reason:
                    return {
                        "unit": unit_name,
                        "transition_id": prior.get("transition_id"),
                        "already_invalidated": True,
                        "backup": None,
                        "state_file": str(self.state_path),
                    }
                raise ValueError(f"unit {unit_name!r} has no diagnosis to invalidate")
            previous_record = json.loads(json.dumps(record))
            previous_record_sha256 = self._record_sha256(previous_record)
            transition_id = "diagnosis-invalidate-" + hashlib.sha256(
                json.dumps(
                    {
                        "schema": 1,
                        "unit": unit_name,
                        "reason": reason,
                        "previous_record": previous_record,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            projected = json.loads(json.dumps(state))
            projected_record = projected["units"][unit_name]
            removed = {
                key: projected_record.pop(key)
                for key in ("diagnosis", "diagnosis_malformed", "f4_nominated")
                if key in projected_record
            }
            invalidation = {
                "via": "invalidate-diagnosis",
                "reason": reason,
                "previous_record_sha256": previous_record_sha256,
                "transition_id": transition_id,
                "invalidated_stage": previous_record.get("last_stage"),
                "invalidated_source_failure_id": (
                    (previous_record.get("diagnosis") or {}).get("source_failure_id")
                    if isinstance(previous_record.get("diagnosis"), dict)
                    else None
                ),
            }
            projected_record["diagnosis_invalidation"] = invalidation
            backup = self._backup_state()
            transition = UnitTransition(
                unit=unit_name,
                result=RESULT_DEFERRED,
                stage="diagnosis-invalidate",
                attempt=record.get("attempts", 0),
                detail=f"diagnosis invalidated: {reason}",
                model=self._model_config.model,
                extra={
                    **invalidation,
                    "transition_id": transition_id,
                    "removed_keys": sorted(removed),
                },
            )
            if not self._checkpoint(
                projected,
                transition,
                workflow_state="maintenance",
                driver_running=False,
                require_progress_push=True,
            ):
                raise RuntimeError(
                    "diagnosis invalidation was not committed and pushed to "
                    "port-progress; canonical state remains unchanged"
                )
            self._save_state(projected)
            self.events.emit(
                "diagnosis_invalidated",
                unit=unit_name,
                reason=reason[:600],
                transition_id=transition_id,
                removed_keys=sorted(removed),
                via="invalidate-diagnosis",
            )
            return {
                "unit": unit_name,
                "transition_id": transition_id,
                "already_invalidated": False,
                "removed_keys": sorted(removed),
                "backup": backup,
                "state_file": str(self.state_path),
            }
        finally:
            self.lock.release()

    def backfill_artifact_digest(
        self, unit_name: str, reason: str
    ) -> dict[str, Any]:
        """Journal-first, one-unit migration for digest-less green history.

        Historical artifacts can contain ignored evidence (notably
        ``oracle.log``), so Git alone cannot authenticate the complete raw
        directory. This explicit maintenance operation proves every committed
        file against the recorded publication commit, inventories every extra
        file, journals that inventory + raw directory digest durably, and only
        then adds ``candidate_sha256`` to canonical state. It never edits an
        artifact or product ref.
        """
        reason = (reason or "").strip()
        if not reason:
            raise ValueError("artifact digest backfill requires a non-empty reason")
        if Path(unit_name).name != unit_name:
            raise ValueError("artifact digest backfill requires one plain unit name")
        if not self.lock.acquire():
            raise RuntimeError(
                "another wasm-units driver holds wasm-units.lock; digest "
                "backfill would race its state writes"
            )
        try:
            snapshot = load_canonical_state_snapshot(self.state_path)
            payload = self.state_path.read_bytes()
            if hashlib.sha256(payload).hexdigest() != snapshot.sha256:
                raise RuntimeError("canonical state changed during digest backfill")
            state = json.loads(payload.decode("utf-8-sig"))
            record = state.get("units", {}).get(unit_name)
            if not isinstance(record, dict):
                raise ValueError(f"unknown canonical unit {unit_name!r}")
            tier = record.get("tier")
            if record.get("status") != "green" or tier not in ELIGIBLE_CANONICAL_TIERS:
                raise ValueError(
                    f"unit {unit_name!r} is not a green eligible lifecycle "
                    f"(status={record.get('status')!r}, tier={tier!r})"
                )
            revoked = record.get("revoked")
            if (
                isinstance(revoked, dict)
                and revoked.get("previous_commit") == record.get("commit")
            ):
                raise ValueError(
                    f"unit {unit_name!r} has a current-lifecycle revocation"
                )
            root = self.artifact_root if tier == "oracle_green" else self.staging_root
            try:
                artifact = load_unit_artifact(root / unit_name)
            except OSError as error:
                raise ValueError(
                    f"unit {unit_name!r} artifact tree is unsafe: {error}"
                ) from error
            if artifact is None or artifact.name != unit_name or artifact.tier != tier:
                raise ValueError(
                    f"unit {unit_name!r} has no matching {tier!r} artifact"
                )
            existing_digest = record.get("candidate_sha256")
            if existing_digest is not None:
                if existing_digest != artifact.sha256:
                    raise RuntimeError(
                        f"canonical digest for {unit_name!r} does not match artifact"
                    )
                return {
                    "unit": unit_name,
                    "candidate_sha256": artifact.sha256,
                    "already_bound": True,
                    "backup": None,
                    "state_file": str(self.state_path),
                }
            remote_sha = self._remote_port_staging_sha(strict=True)
            if remote_sha is None:
                raise RuntimeError(
                    "authoritative origin/port-staging publication ref is unavailable"
                )
            binding, proof_error = prove_legacy_artifact_commit_tree(
                artifact,
                record,
                repo_root=self.repo_root,
                git_runner=self._git_runner,
                publication_ref="refs/heads/port-staging",
                publication_sha=remote_sha,
                required_committed_files=BACKFILL_REQUIRED_COMMITTED_FILES,
                allowed_ignored_extras=BACKFILL_ALLOWED_IGNORED_EVIDENCE,
            )
            if binding is None:
                raise RuntimeError(
                    f"legacy artifact commit proof failed: {proof_error}"
                )
            transition_preimage = {
                "schema": 1,
                "unit": unit_name,
                "reason": reason,
                "canonical_state_sha256": snapshot.sha256,
                "binding": binding,
            }
            transition_id = "artifact-digest-backfill-" + hashlib.sha256(
                json.dumps(
                    transition_preimage, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            ).hexdigest()
            evidence = {
                **binding,
                "via": "backfill-artifact-digest",
                "reason": reason,
                "canonical_state_sha256": snapshot.sha256,
                "transition_id": transition_id,
            }
            projected = self._project_record_update(
                state,
                unit_name,
                {
                    "candidate_sha256": artifact.sha256,
                    "artifact_digest_backfill": evidence,
                },
            )
            backup = self._backup_state()
            transition = UnitTransition(
                unit=unit_name,
                result=RESULT_STAGED if tier == "compile_only" else RESULT_GREEN,
                stage="artifact-digest-backfill",
                attempt=record.get("attempts", 0),
                detail=f"legacy artifact digest sanctioned: {reason}",
                product_commit=str(record.get("commit") or "") or None,
                product_pushed=True,
                oracle_summary=record.get("oracle_summary"),
                model=self._model_config.model,
                tier=tier,
                extra={**evidence, "transition_id": transition_id},
            )
            if not self._checkpoint(
                projected,
                transition,
                workflow_state="maintenance",
                driver_running=False,
                require_progress_push=True,
            ):
                raise RuntimeError(
                    "artifact digest backfill was not committed and pushed to "
                    "port-progress; canonical state remains unchanged"
                )
            if not verify_canonical_state_snapshot(snapshot):
                raise RuntimeError(
                    "canonical state changed after digest backfill checkpoint"
                )
            try:
                digest_after = unit_artifact_sha256(artifact.directory)
            except OSError as error:
                raise RuntimeError(
                    f"artifact became unreadable after digest checkpoint: {error}"
                ) from error
            if digest_after != artifact.sha256:
                raise RuntimeError(
                    "artifact changed after digest checkpoint; canonical state "
                    "remains unchanged"
                )
            self._save_state(projected)
            self.events.emit(
                "artifact_digest_backfilled",
                unit=unit_name,
                candidate_sha256=artifact.sha256,
                commit=record.get("commit"),
                publication_ref=binding.get("publication_ref"),
                transition_id=transition_id,
                uncommitted_files=binding.get("uncommitted_files"),
                reason=reason[:600],
                via="backfill-artifact-digest",
            )
            return {
                "unit": unit_name,
                "candidate_sha256": artifact.sha256,
                "transition_id": transition_id,
                "already_bound": False,
                "backup": backup,
                "state_file": str(self.state_path),
                "binding": binding,
            }
        finally:
            self.lock.release()

    # ------------------------------------------- D5 migration (design D5-6)

    def _backup_state(self) -> str | None:
        if not self.state_path.is_file():
            return None
        backup_path = self.state_path.with_name(
            f"{self.state_path.name}.settle-backup-"
            + utc_now().replace(":", "").replace("-", "")
        )
        shutil.copyfile(self.state_path, backup_path)
        return backup_path.name

    def d5_migrate(self, dry_run: bool = False) -> dict[str, Any]:
        """D5-6 migration steps 2-3: revoke-and-requeue every settled green
        the census predicate selects, EVALUATED NOW (never a unit list).

        Predicate per D5-4 [R2]: the staged artifact's provenance is D5-stale
        (no transform block, or version-stale with differing output) AND the
        transform on its extractions is non-identity. Site-free artifacts
        classify RESTAMP -- their verdicts STAND and the identity stamp lands
        at their next routine touch (D5-6), so this sweep records them but
        does not rewrite committed artifacts. Units without a staged
        provenance (the oracle-green PoC island in port-units -- migration
        step 4, owner decision pending) are skipped and reported.

        Every revocation goes THROUGH the journal (section 2.9 [V4-9]):
        state backup, journal checkpoint, ``verdict_revoked`` event, atomic
        state save -- and triggers the [V4-7] registry demote path
        (tombstoned where sole-sourced; re-harvest on the new green
        re-supplies them). The staged artifact directory is left in place:
        the requeued rebuild overwrites and re-commits it, and gate item 2's
        census stays visibly red until the mix drains (F-D5-8).

        Takes the driver lock; refuses while a driver is alive (same rule as
        settle_unit -- racing a live driver's state writes is a proven
        failure mode).
        """
        queue = {unit["name"]: unit for unit in self._load_queue()}
        if not dry_run and not self.lock.acquire():
            raise RuntimeError(
                "another wasm-units driver holds wasm-units.lock; "
                "migrating under a running driver would race its state writes"
            )
        try:
            state = self._load_state()
            report: dict[str, Any] = {
                "dry_run": dry_run,
                "revoked": [],
                "identity_stand": [],
                "current": [],
                "skipped": [],
                "backup": None,
            }
            registry_dirty = False
            registry = None
            for name in sorted(state.get("units", {})):
                record = state["units"][name]
                if record.get("status") != "green":
                    continue
                provenance = self._staged_provenance(name)
                if provenance is None:
                    report["skipped"].append(
                        {
                            "unit": name,
                            "why": "no staged provenance (oracle-green "
                            "island or promoted artifact; D5-6 step 4 is "
                            "out of this sweep's scope)",
                        }
                    )
                    continue
                unit = queue.get(name)
                if unit is None:
                    report["skipped"].append(
                        {"unit": name, "why": "green record not in the queue"}
                    )
                    continue
                try:
                    materialized = materialize_unit_c(self.repo_root, unit)
                except (OSError, ValueError, KeyError) as error:
                    report["skipped"].append(
                        {"unit": name, "why": f"materialization: {error}"}
                    )
                    continue
                current_sha = materialized.transform["transformed_sha256"]
                staleness = transform_staleness(provenance, current_sha)
                if staleness == D5_CURRENT:
                    report["current"].append(name)
                    continue
                if staleness == D5_RESTAMP:
                    report["identity_stand"].append(name)
                    continue
                sites = materialized.transform["sites"]
                entry = {"unit": name, "sites": sites}
                report["revoked"].append(entry)
                if dry_run:
                    continue
                if report["backup"] is None:
                    report["backup"] = self._backup_state()
                reason = (
                    "D5-6 migration: artifact predates the d5-fp-reinterpret "
                    f"transform and its extractions carry {sites} rewritable "
                    "idiom site(s); verdict revoked and unit requeued for "
                    "rebuild under the transform"
                )
                transition = UnitTransition(
                    unit=name,
                    result=RESULT_DEFERRED,
                    stage="d5-migrate",
                    attempt=record.get("attempts", 0),
                    detail=f"verdict revoked: {reason}",
                    model=self._model_config.model,
                    extra={
                        "revoked_via": "d5-migrate",
                        "previous_status": "green",
                        "world_version": self._world_version(),
                        "transform_sites": sites,
                    },
                )
                # Journal FIRST (remote record before the local verdict
                # changes -- same ordering rule as settle_unit).
                self._checkpoint(state, transition)
                previous_tier = record.get("tier")
                record.pop("tier", None)
                record.update(
                    status="pending",
                    error=None,
                    last_stage="d5-migrate",
                    revoked={
                        "via": "d5-migrate",
                        "at": utc_now(),
                        "reason": reason,
                        "previous_status": "green",
                        "previous_tier": previous_tier,
                        "transform_sites": sites,
                    },
                )
                self._save_state(state)
                self.events.emit(
                    "verdict_revoked",
                    unit=name,
                    previous_status="green",
                    previous_tier=previous_tier,
                    reason=reason[:600],
                    transform_sites=sites,
                    via="d5-migrate",
                )
                # [V4-7] demote path for the unit's harvested entries.
                try:
                    if registry is None:
                        registry = self._registry()
                    retier = revoke_unit_entries(registry, name)
                    if retier.changed:
                        registry_dirty = True
                        self.events.emit(
                            "registry_revoked",
                            unit=name,
                            demoted=retier.demoted[:20],
                            revoked=retier.revoked[:20],
                            registry_version=retier.version,
                        )
                except Exception as error:  # noqa: BLE001 - registry never blocks
                    self.events.emit(
                        "registry_revoke_error", unit=name, error=str(error)[:400]
                    )
            if registry_dirty and registry is not None:
                self._save_registry(registry)
                # Local commit only -- this sweep never pushes; the driver's
                # next sanctioned commit flow carries it outward.
                self._git_runner("add", "--", REGISTRY_RELPATH)
                self._git_runner(
                    "commit",
                    "-m",
                    "port-registry: D5-6 migration revocations "
                    "([V4-7] demote for revoked staged greens)",
                    "--",
                    REGISTRY_RELPATH,
                )
            return report
        finally:
            if not dry_run:
                self.lock.release()

    # ------------------------------------------------- diagnosis (section 2.12b)

    @staticmethod
    def _source_failure_id(name: str, record: dict[str, Any]) -> str | None:
        """Return the deterministic identity of the current source failure."""
        if (
            record.get("last_stage") not in SOURCE_DIAGNOSIS_STAGES
            or record.get("diagnosis_eligible") is not True
            or record.get("failure_domain") != "source-compiler"
        ):
            return None
        rounds = record.get("rounds") or []
        last_round = rounds[-1] if rounds and isinstance(rounds[-1], dict) else {}
        preimage = {
            "schema": 1,
            "unit": name,
            "stage": record.get("last_stage"),
            "error": str(record.get("error") or "")[:2000],
            "diagnostic_fingerprint": last_round.get("fingerprint"),
            "world_version": record.get("world_version"),
        }
        return "source-failure-" + hashlib.sha256(
            json.dumps(preimage, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    @classmethod
    def _diagnosis_is_current(cls, name: str, record: dict[str, Any]) -> bool:
        diagnosis = record.get("diagnosis")
        source_failure_id = cls._source_failure_id(name, record)
        return (
            isinstance(diagnosis, dict)
            and source_failure_id is not None
            and diagnosis.get("source_failure_id") == source_failure_id
        )

    def _diagnose_unit(
        self, unit: dict[str, Any], record: dict[str, Any], state: dict[str, Any]
    ) -> dict[str, Any] | None:
        """One section-2.12(b) diagnosis call, at most once per unit lifetime:
        "why can no header fix this? STRUCTURAL or FIXABLE with one reason."

        Consumption is conservative by construction (section 2.7): STRUCTURAL
        never settles -- it deprioritises the unit (selector penalty) and
        nominates it for the F4 replay sample, where a provable outcome
        decides; FIXABLE appends its reason to the post-mortem the next
        scheduled attempt carries. Any fault degrades to an event and leaves
        the question unconsumed."""
        name = unit["name"]
        source_failure_id = self._source_failure_id(name, record)
        if source_failure_id is None:
            self.events.emit(
                "diagnosis_skipped",
                unit=name,
                stage=record.get("last_stage"),
                failure_domain=record.get("failure_domain"),
                reason="failure domain is not source-diagnosable",
            )
            return None
        if self._diagnosis_is_current(name, record):
            return record["diagnosis"]
        try:
            # Same materialization seam as the build (F-D5-6): the diagnosis
            # prompt shows TRANSFORMED text, which is correct -- the question
            # is "why can no header fix *what compiles*".
            verbatim = materialize_unit_c(self.repo_root, unit).verbatim
            rounds = record.get("rounds") or []
            diagnostics = "\n".join(
                (rounds[-1].get("diagnostics") or []) if rounds else []
            )
            post_mortem = assemble_post_mortem(record)
            prompt = (
                (post_mortem + "\n\n" if post_mortem else "")
                + f"Final diagnostics:\n```\n{diagnostics or record.get('error', '')}\n```\n\n"
                + f"Verbatim decompiled C (read-only):\n```c\n{verbatim}\n```\n\n"
                + "Why can no header fix this? Answer STRUCTURAL or FIXABLE "
                + "with one reason."
            )
            self._heartbeat(f"wasm_units:{name}:diagnosis")
            reply = self._llm_client().generate(
                prompt=prompt,
                system_prompt=DIAGNOSIS_SYSTEM_PROMPT
                + (" /no_think" if DISABLE_THINKING else ""),
                max_tokens=512,
                phase=f"wasm_diagnosis:{name}",
                stream_callback=lambda _event_type, _event: None,
                **SAMPLING,
                **(
                    {"chat_template_kwargs": {"enable_thinking": False}}
                    if DISABLE_THINKING
                    else {}
                ),
            )
        except Exception as error:  # noqa: BLE001 - diagnosis is best-effort
            # A call that never completed (provider fault, extraction error)
            # consumed nothing and is section-2.10 transient: unmetered, and
            # the question stays askable.
            self.events.emit("diagnosis_error", unit=name, error=str(error)[:400])
            return None
        # The call COMPLETED: meter it (T3 review F5), whatever the reply shape.
        record["model_requests"] = record.get("model_requests", 0) + 1
        match = _DIAGNOSIS_VERDICT.search(reply or "")
        if not match:
            # Malformed reply: bounded re-asks only. Re-asking the same
            # near-identical question forever is the section 0.1 forbidden
            # retry, so after DIAGNOSIS_MALFORMED_LIMIT malformed replies the
            # diagnosis is recorded terminally UNPARSEABLE and never re-asked
            # (still never settles; no F4 nomination -- nothing was learned).
            malformed = int(record.get("diagnosis_malformed", 0)) + 1
            record["diagnosis_malformed"] = malformed
            self.events.emit(
                "diagnosis_error", unit=name,
                error=f"no STRUCTURAL/FIXABLE verdict in reply: {(reply or '')[:200]!r}",
            )
            if malformed >= DIAGNOSIS_MALFORMED_LIMIT:
                record["diagnosis"] = {
                    "verdict": "UNPARSEABLE",
                    "reason": f"{malformed} malformed replies; question retired",
                    "attempts_at": record.get("attempts", 0),
                    "at": utc_now(),
                    "source_stage": record.get("last_stage"),
                    "source_failure_id": source_failure_id,
                }
                self.events.emit(
                    "diagnosis_unparseable", unit=name, malformed=malformed
                )
                self._save_state(state)
                return record["diagnosis"]
            self._save_state(state)
            return None
        verdict = match.group(1)
        reason = (reply or "")[match.end():].lstrip(" :-—").strip()[:400]
        diagnosis = {
            "verdict": verdict,
            "reason": reason,
            "attempts_at": record.get("attempts", 0),
            "at": utc_now(),
            "source_stage": record.get("last_stage"),
            "source_failure_id": source_failure_id,
        }
        record["diagnosis"] = diagnosis
        if verdict == "STRUCTURAL":
            # Never settles: deprioritise + nominate for the F4 replay sample.
            record["f4_nominated"] = True
        self._save_state(state)
        self.events.emit(
            "diagnosis_question", unit=name, verdict=verdict, reason=reason[:200]
        )
        return diagnosis

    # -------------------------------------- verification queue (section 3, T3)

    def _staged_provenance(self, name: str) -> dict[str, Any] | None:
        try:
            return json.loads(
                (self.staging_root / name / "provenance.json").read_text(
                    encoding="utf-8-sig"
                )
            )
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return None

    def _verification_candidates(self, state: dict[str, Any]) -> list[str]:
        """Staged compile-only greens whose sidecar oracle spec binds to the
        STAGED artifact's provenance export set (oracle plan section 3.4: the
        wasm being verified is the one the provenance describes, never the
        current queue's export set). A candidate that already failed under
        the SAME spec is not re-run -- an oracle re-run with identical inputs
        is the section 0.1 forbidden retry."""
        sidecar = self._oracle_sidecar()
        if not sidecar:
            return []
        candidates: list[str] = []
        for name, record in state.get("units", {}).items():
            if record.get("status") != "green" or record.get("tier") != "compile_only":
                continue
            entry = sidecar.get(name)
            if not entry:
                continue
            if not (self.staging_root / name / "unit.wasm").is_file():
                continue
            provenance = self._staged_provenance(name)
            if not provenance:
                continue
            exports = provenance.get("exported_functions") or []
            if validate_oracle_entry(name, entry, exports=exports):
                self._sidecar_report_once(
                    name, "oracle_spec_invalid",
                    problems=validate_oracle_entry(name, entry, exports=exports)[:5],
                )
                continue
            if entry.get("exports_sha256") != exports_sha256(exports):
                self._sidecar_report_once(
                    name, "oracle_spec_stale", binding="staged_provenance"
                )
                continue
            previous = record.get("verify") or {}
            # T3 review F2: only a COMPLETED oracle run under this spec is
            # unrepeatable (section 0.1) -- oracle_red (and pass, defensively)
            # skip; transient faults (error, commit_failed) are section-2.10
            # territory and leave the unit a candidate.
            if (
                previous.get("status") in ("oracle_red", "pass")
                and previous.get("spec_sha256") == oracle_entry_sha(entry)
            ):
                continue  # same spec already decided; nothing new to learn
            candidates.append(name)
        return sorted(candidates)

    def _commit_paths(
        self, message: str, paths: list[str]
    ) -> tuple[str | None, bool, str]:
        """git add (pathspec, deletions included) + commit + push."""
        added = self._git_runner("add", "--", *paths)
        if added.returncode != 0:
            return None, False, (added.stdout + added.stderr)[-400:]
        committed = self._git_runner("commit", "-m", message, "--", *paths)
        if committed.returncode != 0:
            output = committed.stdout + committed.stderr
            # Idempotent resume (T3 review F1): a re-run after a crash between
            # the artifact commit and the state update re-copies byte-identical
            # files; "nothing to commit" then means the commit already exists,
            # not a failure.
            if "nothing to commit" not in output and "no changes added" not in output:
                return None, False, output[-400:]
        sha = ""
        rev = self._git_runner("rev-parse", "HEAD")
        if rev.returncode == 0:
            sha = rev.stdout.strip()
        pushed = self._push_product_sha(sha or "HEAD")
        return sha or None, pushed.returncode == 0, (
            "" if pushed.returncode == 0 else (pushed.stdout + pushed.stderr)[-400:]
        )

    def _reverify_unit_inner(self, name: str, state: dict[str, Any]) -> dict[str, Any]:
        """Oracle-only verification stage for one staged unit (section 3's
        verification queue; oracle plan section 3.4's reverify semantics).

        Rebuilds nothing: runs the sidecar oracle against the COMMITTED staged
        artifact's unit.wasm. On pass: provenance rewrite, artifact move
        staging -> port-units, registry promotion ([V4-7], with conflict
        recompute), commit, journal checkpoint + verdict_promoted event. On
        fail: the unit STAYS staged (no verdict change), the failure is
        recorded (same spec never re-runs), and [V4-7] demotion revokes/
        demotes registry entries sourced from the unit."""
        record = self._unit_state(state, name)
        staged_dir = self.staging_root / name
        provenance = self._staged_provenance(name)
        if provenance is None:
            raise ValueError(f"{name}: no readable staged provenance.json")
        exports = provenance.get("exported_functions") or []
        entry = self._oracle_sidecar().get(name)
        if not entry:
            raise ValueError(f"{name}: no oracle-commands.json sidecar entry")
        problems = validate_oracle_entry(name, entry, exports=exports)
        if problems:
            raise ValueError(f"{name}: invalid sidecar entry: {problems[:3]}")
        if entry.get("exports_sha256") != exports_sha256(exports):
            self._sidecar_report_once(
                name, "oracle_spec_stale", binding="staged_provenance"
            )
            raise ValueError(
                f"{name}: exports_sha256 does not match the staged artifact's "
                "provenance export set (section 3.4 binding rule)"
            )
        spec_sha = oracle_entry_sha(entry)
        wasm_path = staged_dir / "unit.wasm"
        self._heartbeat(f"wasm_units:{name}:reverify")
        self.events.emit("wasm_unit_reverify_started", unit=name)
        oracle = json.loads(json.dumps(entry["oracle"]))
        passed, summary, oracle_log = self._oracle_runner(
            {"name": name, "oracle": oracle}, wasm_path
        )
        if not passed:
            record["verify"] = {
                "status": "oracle_red",
                "summary": summary,
                "spec_sha256": spec_sha,
                "at": utc_now(),
            }
            self._save_state(state)
            # [V4-7] demotion: a failed oracle re-run on a staged unit
            # downgrades or removes every registry entry sourced from it.
            registry_rel: str | None = None
            try:
                registry = self._registry()
                retier = revoke_unit_entries(registry, name)
                if retier.changed:
                    self._save_registry(registry)
                    registry_rel = REGISTRY_RELPATH
                    self.events.emit(
                        "registry_revoked",
                        unit=name,
                        demoted=retier.demoted[:20],
                        revoked=retier.revoked[:20],
                        registry_version=retier.version,
                    )
            except Exception as error:  # noqa: BLE001 - registry never blocks
                self.events.emit(
                    "registry_revoke_error", unit=name, error=str(error)[:400]
                )
            if registry_rel:
                self._commit_paths(
                    f"port-registry: revoke {name} entries (staged oracle re-run failed)",
                    [registry_rel],
                )
            self.events.emit(
                "wasm_unit_reverify_red", unit=name, summary=summary
            )
            self._checkpoint(
                state,
                UnitTransition(
                    unit=name,
                    result=RESULT_GATE_FAILED,
                    stage="reverify",
                    attempt=record.get("attempts", 0),
                    detail=f"oracle red on staged artifact: {summary}",
                    model=self._model_config.model,
                    tier="compile_only",
                    extra={"verify": record["verify"]},
                ),
            )
            return {"unit": name, "promoted": False, "summary": summary}
        # PASS: crash-safe ordering (T3 review F1). The staged artifact is the
        # only durable copy until the promoted commit lands, and the
        # supervisor's NORMAL stop path is a tree-kill -- so the staging dir
        # is not touched until commit + checkpoint + state update have all
        # succeeded. Order: copy -> provenance rewrite -> registry
        # restore/promote -> COMMIT promoted copy -> journal + state -> only
        # then remove staging (its own commit; a kill in between is finished
        # by _reconcile_promoted on the next start).
        promoted_dir = self.artifact_root / name
        promoted_dir.mkdir(parents=True, exist_ok=True)
        for file_path in staged_dir.iterdir():
            if file_path.is_file():
                shutil.copyfile(file_path, promoted_dir / file_path.name)
        (promoted_dir / "oracle.log").write_text(
            oracle_log, encoding="utf-8", newline="\n"
        )
        provenance.update(
            verified=True,
            tier="oracle_green",
            previous_tier="compile_only",
            reverified_at=utc_now(),
            reverify={
                "run_id": self.run_id,
                "spec_sha256": spec_sha,
                "exports_sha256": entry["exports_sha256"],
            },
            oracle={
                "command": oracle["command"],
                "cwd": oracle["cwd"],
                "summary": summary,
            },
        )
        atomic_write_json(promoted_dir / "provenance.json", provenance)
        registry_rel = None
        try:
            registry = self._registry()
            # T3 review F3: a revoke caused by THIS unit's own failed re-run
            # is undone by its passing re-run (spec-typo scenario) -- with a
            # restored trail record, never a silent reappearance.
            restore = restore_unit_entries(registry, name)
            retier = promote_unit_entries(registry, name)
            if restore.changed or retier.changed:
                self._save_registry(registry)
                registry_rel = REGISTRY_RELPATH
            if restore.changed:
                self.events.emit(
                    "registry_restored",
                    unit=name,
                    restored=restore.restored[:20],
                    registry_version=registry_version(registry),
                )
            if retier.changed:
                self.events.emit(
                    "registry_promoted",
                    unit=name,
                    promoted=retier.promoted[:20],
                    reopened=retier.reopened[:20],
                    green_green=retier.green_green[:20],
                    registry_version=retier.version,
                )
                for key in retier.green_green:
                    # Section 2.11 conflict policy: green-green disagreement
                    # pages the owner.
                    self.events.emit(
                        "registry_green_green_conflict", unit=name, key=key
                    )
        except Exception as error:  # noqa: BLE001 - promotion never costs the pass
            self.events.emit(
                "registry_promote_error", unit=name, error=str(error)[:400]
            )
        # Commit the PROMOTED copy first; staging is untouched on any failure,
        # so the unit simply remains a verification candidate (F2) and the
        # next pass retries idempotently.
        sha, pushed, push_detail = self._commit_paths(
            f"port: {name} wasm unit promoted (oracle {summary})",
            [
                f"research/decomp/port-units/{name}",
                *([registry_rel] if registry_rel else []),
            ],
        )
        if sha is None:
            record["verify"] = {
                "status": "commit_failed",
                "summary": summary,
                "spec_sha256": spec_sha,
                "detail": push_detail,
                "at": utc_now(),
            }
            self._save_state(state)
            self.events.emit(
                "reverify_commit_failed", unit=name, detail=push_detail
            )
            return {
                "unit": name,
                "promoted": False,
                "summary": summary,
                "error": f"commit failed: {push_detail}",
            }
        # Promotion is a verdict-class operation: journal FIRST (settle-unit
        # ordering), then the local record.
        self._checkpoint(
            state,
            UnitTransition(
                unit=name,
                result=RESULT_GREEN,
                stage="reverify",
                attempt=record.get("attempts", 0),
                detail=f"staged unit promoted, oracle green: {summary}",
                product_commit=sha,
                product_pushed=pushed,
                oracle_summary=summary,
                model=self._model_config.model,
                tier="oracle_green",
            ),
        )
        record.update(
            status="green",
            tier="oracle_green",
            oracle_summary=summary,
            commit=sha,
            pushed=pushed,
            error=None,
            last_stage="reverify",
            verify={
                "status": "pass",
                "summary": summary,
                "spec_sha256": spec_sha,
                "at": utc_now(),
            },
        )
        self._save_state(state)
        self.events.emit(
            "verdict_promoted",
            unit=name,
            oracle_summary=summary,
            commit=sha,
            pushed=pushed,
            previous_tier="compile_only",
        )
        self._flag_unverified_inventory(state)
        # Only now, with the promotion durable (commit + journal + state), is
        # the staged copy redundant. Removal failure is safe: the promoted
        # tree is authoritative and _reconcile_promoted finishes the cleanup
        # on the next driver start.
        self._remove_staged_copy(name)
        return {
            "unit": name,
            "promoted": True,
            "summary": summary,
            "commit": sha,
            "pushed": pushed,
        }

    def _remove_staged_copy(self, name: str) -> bool:
        """Delete the (now redundant) staged copy and commit the deletion.
        Best-effort: any fault emits an event and leaves the reconcile path
        to finish the job -- it never un-promotes anything."""
        staged_dir = self.staging_root / name
        try:
            if staged_dir.exists():
                shutil.rmtree(staged_dir)
            sha, _pushed, detail = self._commit_paths(
                f"port: remove staged copy of promoted unit {name}",
                [f"research/decomp/port-units-staging/{name}"],
            )
            if sha is None:
                self.events.emit(
                    "staging_cleanup_failed", unit=name, detail=detail[:400]
                )
                return False
            return True
        except (OSError, subprocess.SubprocessError) as error:
            self.events.emit(
                "staging_cleanup_failed", unit=name, detail=str(error)[:400]
            )
            return False

    def _reconcile_promoted(self, state: dict[str, Any]) -> None:
        """T3 review F1: idempotent resume for a promotion interrupted after
        its commit -- the promoted artifact exists AND the staged copy is
        still present. The promotion already happened (commit + journal +
        state record all say oracle_green with a passed verify); only the
        staged-copy removal is owed. A record still compile_only with both
        dirs present needs NO branch here: staging is intact, so the unit
        simply remains a verification candidate and re-runs idempotently."""
        for name, record in state.get("units", {}).items():
            if (
                record.get("status") == "green"
                and record.get("tier") == "oracle_green"
                and (record.get("verify") or {}).get("status") == "pass"
                and (self.staging_root / name).exists()
                and (self.artifact_root / name / "provenance.json").is_file()
            ):
                if self._remove_staged_copy(name):
                    self.events.emit("reverify_reconciled", unit=name)

    def reverify_unit(self, unit_name: str) -> dict[str, Any]:
        """CLI entry (oracle plan section 3.4): promote one staged unit by
        re-running its sidecar oracle against the committed staged artifact.
        Takes the driver lock (a reverify under a running driver would race
        its state writes) and goes through the journal, like settle-unit."""
        if not self.lock.acquire():
            raise RuntimeError(
                "another wasm-units driver holds wasm-units.lock; "
                "reverifying under a running driver would race its state writes"
            )
        try:
            state = self._load_state()
            if unit_name not in state.get("units", {}):
                raise ValueError(f"unknown unit {unit_name!r}: not in the state file")
            record = state["units"][unit_name]
            if record.get("status") != "green" or record.get("tier") != "compile_only":
                raise ValueError(
                    f"{unit_name} is not a staged compile-only green "
                    f"(status={record.get('status')!r}, tier={record.get('tier')!r})"
                )
            return self._reverify_unit_inner(unit_name, state)
        finally:
            self.lock.release()

    # ------------------------------------------------- F4 recheck (section 2.7)

    def f4_recheck(self, sample_size: int = 5) -> dict[str, Any]:
        """The monthly bounded F4 recheck: replay up to ``sample_size`` units
        offline with the current loop -- diagnosis-nominated reds first
        (section 2.12(b) feeds the sample), then settled structural_ineligible
        units. Replay writes NO state, NO journal, NO commits; any SETTLED
        unit that links is the classifier-freeze signal (freeze to the
        void-result detector and reopen the class -- an owner decision, which
        is why this reports instead of acting)."""
        if not self.lock.acquire():
            raise RuntimeError(
                "another wasm-units driver holds wasm-units.lock; "
                "the F4 replay shares the model slot and the workdir tree"
            )
        try:
            state = self._load_state()
            queue = {unit["name"]: unit for unit in self._load_queue()}
            units = state.get("units", {})
            nominated = [
                name
                for name, record in units.items()
                if record.get("f4_nominated")
                and self._diagnosis_is_current(name, record)
                and (record.get("diagnosis") or {}).get("verdict") == "STRUCTURAL"
                and record.get("status") == "red_retryable"
                and name in queue
            ]
            settled = [
                name
                for name, record in units.items()
                if record.get("status") == "structural_ineligible" and name in queue
            ]
            sample = (
                nominated + [name for name in settled if name not in nominated]
            )[: max(1, sample_size)]
            results: list[dict[str, Any]] = []
            for name in sample:
                linked, detail = self._replay_unit_offline(queue[name])
                results.append(
                    {
                        "unit": name,
                        "status": units[name].get("status"),
                        "nominated": name in nominated,
                        "linked": linked,
                        "detail": (detail or "")[:400],
                    }
                )
            freeze_signal = any(
                result["linked"] and result["status"] == "structural_ineligible"
                for result in results
            )
            self.events.emit(
                "f4_recheck",
                sample=[result["unit"] for result in results],
                linked=[result["unit"] for result in results if result["linked"]],
                classifier_freeze_signal=freeze_signal,
            )
            return {"sample": results, "classifier_freeze_signal": freeze_signal}
        finally:
            self.lock.release()

    def _replay_unit_offline(self, unit: dict[str, Any]) -> tuple[bool, str]:
        """One offline replay of the compile-fix loop: extraction, (deep-copied)
        registry augmentation, build + LLM rounds with the stage-aware stuck
        rule. Touches only its own workdir -- no state, no journal, no
        registry writes, no verdicts.

        D5 migration-step-4 caution (reviewer): this replay reads the unit's
        queue ``header_seed`` -- the shared INTEGER seed lineage -- never a
        fork unit's committed union-macro header. Replaying a T2b
        double-cohort unit here therefore exercises the canonical
        integer-seed + transform world, which is exactly what step 4's
        re-materialization wants; it must never be read as evidence about
        the unit's historical union-header build."""
        name = unit["name"]
        workdir = self.work_root / "_f4" / name
        workdir.mkdir(parents=True, exist_ok=True)
        materialized = materialize_unit_c(self.repo_root, unit)  # F-D5-6: shared seam
        prelude = "\n".join(unit.get("prelude", []))
        unit_c = materialized.unit_c
        (workdir / "unit.c").write_text(unit_c, encoding="utf-8", newline="\n")
        header = (self.repo_root / unit["header_seed"]).read_text(encoding="utf-8")
        # Canonical SDK declaration sync, IN MEMORY ONLY: the replay must see
        # the same canon-synced starting header the live attempt path builds,
        # but replays never write state -- so the pure pass, never the
        # file-level sync.
        try:
            header = inject_sdk_declarations(
                header,
                unit_c,
                (self.run_root / "gnt4_shim_seed.h").read_text(encoding="utf-8"),
            ).header_text
        except Exception:  # noqa: BLE001 - canon warmth is optional in replay too
            pass
        # Owner prototype sync (zz_*/FUN_*), IN MEMORY ONLY: same rule as the
        # SDK sync above -- the replay sees the same owner-synced starting
        # header the live attempt path builds, but never writes state.
        try:
            header = inject_owner_declarations(
                header,
                unit_c,
                load_owner_prototypes(
                    self.repo_root / "research/decomp/data/oracle-registry.json"
                ),
                unit_name=name,
            ).header_text
        except Exception:  # noqa: BLE001 - owner warmth is optional in replay too
            pass
        if materialized.transform["sites"]:
            header = ensure_bitcast_helper(header)
        exports = unit["exported_functions"]
        try:
            registry = json.loads(json.dumps(self._registry()))  # replay-local copy
            if registry.get("entries") and not is_holdout(name):
                augmented = augment_seed(
                    registry,
                    unit_name=name,
                    seed_text=header,
                    symbols=unit_symbol_set(unit_c, exports),
                    prelude_declarations=prelude_prototypes(prelude),
                )
                header = augmented.header_text
        except Exception:  # noqa: BLE001 - warmth is optional in replay too
            pass
        (workdir / "gnt4_shim.h").write_text(header, encoding="utf-8", newline="\n")
        previous_stage: str | None = None
        previous_fingerprint: str | None = None
        header_applied = False
        build_error = ""
        for iteration in range(1, MAX_COMPILE_ITERS + 1):
            if iteration == 1 or header_applied:
                linked, build_error = self._build_runner(
                    workdir, exports, unit.get("allowed_extra_imports") or None
                )
                if linked:
                    return True, f"linked at replay iteration {iteration}"
                stage = classify_build_stage(build_error)
                fingerprint = diagnostic_fingerprint(build_error)
                if is_stuck(
                    previous_stage, previous_fingerprint,
                    stage, fingerprint, header_applied,
                ):
                    return False, "stuck: identical diagnostics after applied fix"
                previous_stage, previous_fingerprint = stage, fingerprint
            if iteration == MAX_COMPILE_ITERS:
                break
            header_text = (workdir / "gnt4_shim.h").read_text(encoding="utf-8")
            fixed = None
            for format_reminder in (False, True):
                fixed = self._compile_fix(
                    unit_c, header_text,
                    summarise_build_error(build_error, budget=2000),
                    unit_name=f"f4-replay:{name}",
                    format_reminder=format_reminder,
                )
                if fixed is not None:
                    break
            if fixed is None:
                return False, "no new header in replay round"
            if materialized.transform["sites"]:  # D5 [review M4]
                fixed = ensure_bitcast_helper(fixed)
            (workdir / "gnt4_shim.h").write_text(fixed, encoding="utf-8", newline="\n")
            header_applied = True
        return False, f"not linked: {summarise_build_error(build_error)[:300]}"

    def _reconcile_interrupted(self, state: dict[str, Any]) -> bool:
        """A unit left `porting` by a killed run never got a transition record.

        The supervisor kills the driver tree on player join / manual pause, so
        this is the normal path, not an exception. Reclassify as `deferred` and
        emit the checkpoint the killed run owed -- otherwise GitHub shows unit A
        as still in flight while the selector has already moved to unit B.
        """
        for name, record in list(state.get("units", {}).items()):
            if record.get("status") != "porting":
                continue
            previous_record = json.loads(json.dumps(record))
            transition_id = "interrupted-reconcile-" + hashlib.sha256(
                json.dumps(
                    {
                        "schema": 1,
                        "unit": name,
                        "previous_record": previous_record,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            refunded_attempts = max(0, int(record.get("attempts", 1)) - 1)
            interruptions = int(record.get("interruptions", 0)) + 1
            projected = self._project_record_update(
                state,
                name,
                {
                    "status": "pending",
                    "error": "interrupted before a verdict (driver killed or crashed)",
                    "attempts": refunded_attempts,
                    "interruptions": interruptions,
                    "interrupted_reconcile_transition_id": transition_id,
                },
            )
            # Refund the ATTEMPT (the unit earned no verdict, and charging it
            # would push it behind the entire queue every time the supervisor
            # kills the driver for a player join or a manual pause -- a
            # starvation machine), but COUNT the interruption. Ordering uses
            # attempts + interruptions, so a unit that keeps taking the driver
            # down with it still sinks instead of being retried forever.
            if not self._checkpoint(
                projected,
                UnitTransition(
                    unit=name,
                    result=RESULT_DEFERRED,
                    stage=previous_record.get("last_stage") or "port",
                    attempt=refunded_attempts,
                    detail="interrupted before a verdict; requeued",
                    model=self._model_config.model,
                    extra={
                        "transition_id": transition_id,
                        "reconciled_from_status": "porting",
                    },
                ),
            ):
                self.events.emit(
                    "interrupted_reconcile_blocked",
                    unit=name,
                    transition_id=transition_id,
                    reason="progress checkpoint was not durable",
                )
                return False
            # Journal first: only after the exact projected pending/refund
            # record is durable may canonical state change. A crash after the
            # checkpoint replays the same transition id from the unchanged
            # porting preimage on the next lifecycle.
            self._save_state(projected)
            state.clear()
            state.update(projected)
        return True

    def _flush_pending_progress(self) -> None:
        try:
            if self._journal.push_is_pending():
                self._journal.flush_pending_push()
        except Exception as error:  # noqa: BLE001 - telemetry is never fatal
            self.events.emit("progress_push_retry_failed", error=str(error)[:300])

    def _work_remains(self, state: dict[str, Any]) -> bool:
        return any(
            record.get("status") not in self.SETTLED_STATUSES
            for record in state.get("units", {}).values()
        )

    def _is_zero_delta_red(self, record: dict[str, Any]) -> bool:
        """Section 2.8 [V4-3]: a red whose recorded world-version equals the
        current one in EVERY component. Retrying it would feed the model the
        exact inputs that already failed -- the section 0.1 forbidden retry.
        A red with no recorded world-version predates the gate and stays
        schedulable (its world is unknown, so a delta cannot be excluded).

        The registry component is finer-grained than the other four (T2c,
        section 2.8: "skips a red whose recorded world-hash equals the
        current hash AND whose symbol set gained no registry entries"): a
        version bump alone is not a delta FOR THIS UNIT unless entries
        touching its recorded symbol set were added or changed since its
        verdict. A red without a recorded symbol set predates that capture
        and re-opens on any registry movement -- unknown, so a delta cannot
        be excluded."""
        if record.get("status") != "red_retryable":
            return False
        recorded = record.get("world_version")
        if not isinstance(recorded, dict):
            return False
        current = self._world_version()
        for component in ("config_hash", "toolchain_hash", "driver_rev", "prompt_version"):
            if recorded.get(component) != current.get(component):
                return False
        if recorded.get("registry_version") == current.get("registry_version"):
            return True
        symbols = record.get("symbol_set")
        if not isinstance(symbols, list) or not symbols:
            return False
        try:
            since = int(recorded.get("registry_version") or 0)
        except (TypeError, ValueError):
            return False
        return not relevant_delta(self._registry(), set(symbols), since)

    def _next_unit(
        self,
        queue: list[dict[str, Any]],
        state: dict[str, Any],
        processed: set[str],
    ) -> dict[str, Any] | None:
        candidates = []
        for index, unit in enumerate(queue):
            name = unit["name"]
            record = self._unit_state(state, name)
            if record.get("status") in self.SETTLED_STATUSES or name in processed:
                continue
            if self._is_zero_delta_red(record):
                # World-changed gating: not schedulable until any world-version
                # component moves. Still counted by _work_remains -- skipped,
                # never settled.
                continue
            # attempts + interruptions: a verdict and a crash both cost the
            # unit its place in line, so neither a failing unit nor a
            # driver-killing one can monopolise the selector.
            cost = int(record.get("attempts", 0)) + int(record.get("interruptions", 0))
            # Section 2.12(b) / T3 review F4: an LLM STRUCTURAL diagnosis
            # never settles -- it deprioritises as the LEADING sort component,
            # so the unit sinks behind ALL schedulable non-structural work
            # across every product_priority band, and still runs when it is
            # the only work left.
            structural = int(
                self._diagnosis_is_current(name, record)
                and (record.get("diagnosis") or {}).get("verdict") == "STRUCTURAL"
            )
            # Section 2.14 [V4-2]: product_priority leads the key (higher
            # serves first, hence negated); chunk/queue order stays the tail
            # tie-break. An absent sidecar makes every priority 0 and the
            # ordering collapses to the previous (cost, index) behaviour.
            candidates.append(
                (structural, -self._unit_priority(name), cost, index, unit)
            )
        if not candidates:
            return None
        candidates.sort(key=lambda item: (item[0], item[1], item[2], item[3]))
        return candidates[0][4]

    def _only_zero_delta_reds(self, state: dict[str, Any]) -> bool:
        """True when every unsettled unit is a zero-delta red: nothing is
        schedulable and nothing will be until the world changes."""
        reds = 0
        for record in state.get("units", {}).values():
            if record.get("status") in self.SETTLED_STATUSES:
                continue
            if not self._is_zero_delta_red(record):
                return False
            reds += 1
        return reds > 0

    def run(self) -> int:
        if not self.lock.acquire():
            print("another wasm-units driver holds wasm-units.lock; exiting")
            return EXIT_LOCKED
        try:
            try:
                queue = self._load_queue()
            except (FileNotFoundError, json.JSONDecodeError, ValueError, OSError) as error:
                print(f"wasm-units queue unusable: {error}")
                self.events.emit("wasm_queue_unusable", error=str(error)[:400])
                return EXIT_STOPPED
            state = self._load_state()
            for unit in queue:  # make every queued unit visible in state/progress
                self._unit_state(state, unit["name"])
            if not self._reconcile_orphan_promotion_attempts(state):
                self.events.emit(
                    "driver_stopped", reason="promotion_attempt_quarantine_failed"
                )
                return EXIT_STOPPED
            if not self._reconcile_interrupted(state):
                self.events.emit(
                    "driver_stopped", reason="interrupted_reconcile_not_durable"
                )
                return EXIT_STOPPED
            self._reconcile_promoted(state)
            self._save_state(state)
            self.events.emit(
                "driver_started", mode="wasm_units", units_budget=self.units_budget
            )
            # A pending progress push from a previous run is retried here, so a
            # GitHub outage that spanned a whole run still reaches the remote.
            self._flush_pending_progress()
            processed: set[str] = set()
            steps_done = 0
            while True:
                command = self._control_command()
                if command in {"stop_after_stage", "pause_after_stage"}:
                    self._write_progress(state, "stopped")
                    self.events.emit("driver_stopped", reason=f"control:{command}")
                    self._checkpoint(
                        state, None, workflow_state="stopped_at_boundary",
                        driver_running=False,
                    )
                    return EXIT_STOPPED
                # Verification lane (section 3, T3): staged compile-only
                # greens whose sidecar oracle spec has appeared are served
                # FIRST -- an oracle-only stage that converts inventory into
                # verified progress (G1) with zero model calls.
                verify_candidates = [
                    candidate
                    for candidate in self._verification_candidates(state)
                    if candidate not in processed
                ]
                if verify_candidates:
                    verify_name = verify_candidates[0]
                    self.events.emit(
                        "selection", action="wasm_unit_reverify", unit=verify_name
                    )
                    self._write_progress(state, "verifying", unit=verify_name)
                    try:
                        self._reverify_unit_inner(verify_name, state)
                    except Exception as error:  # noqa: BLE001 - never takes the run down
                        self.events.emit(
                            "reverify_error",
                            unit=verify_name,
                            error=str(error)[:400],
                        )
                        # Mark the spec as attempted so a raising candidate
                        # cannot spin the pass.
                        verify_record = self._unit_state(state, verify_name)
                        entry = self._oracle_sidecar().get(verify_name)
                        verify_record["verify"] = {
                            "status": "error",
                            "error": str(error)[:400],
                            "spec_sha256": oracle_entry_sha(entry) if entry else None,
                            "at": utc_now(),
                        }
                        self._save_state(state)
                    processed.add(verify_name)
                    steps_done += 1
                    self._write_progress(state, "running")
                    if not self.until_blocked and steps_done >= self.units_budget:
                        self.events.emit(
                            "driver_stopped", reason="units_budget_reached"
                        )
                        return EXIT_PROGRESSED
                    continue
                unit = self._next_unit(queue, state, processed)
                if unit is None:
                    work_left = self._work_remains(state)
                    if (
                        work_left
                        and steps_done == 0
                        and self._only_zero_delta_reds(state)
                    ):
                        # Terminal protocol (section 2.8 [V4-3]): the pass
                        # found only zero-delta reds and no pendings. Honest
                        # accounting: the reds still count as work, but the
                        # pass did not progress -- say so in run-state (the
                        # channel the supervisor already reads; NO new exit
                        # code) and journal the event.
                        waiting = sorted(
                            unit_name
                            for unit_name, rec in state.get("units", {}).items()
                            if rec.get("status") == "red_retryable"
                        )
                        # Terminal protocol (section 2.8 [V4-3] / 2.12(b)):
                        # each zero-delta red receives exactly one diagnosis
                        # call (once per unit lifetime, so re-entering this
                        # state later re-spends nothing), and the page carries
                        # the diagnoses -- a work order, not a stall report.
                        queue_by_name = {queued["name"]: queued for queued in queue}
                        diagnoses: list[dict[str, Any]] = []
                        for waiting_name in waiting:
                            waiting_record = self._unit_state(state, waiting_name)
                            if (
                                not self._diagnosis_is_current(
                                    waiting_name, waiting_record
                                )
                                and waiting_name in queue_by_name
                            ):
                                self._diagnose_unit(
                                    queue_by_name[waiting_name],
                                    waiting_record,
                                    state,
                                )
                            diagnosis = (
                                waiting_record.get("diagnosis") or {}
                                if self._diagnosis_is_current(
                                    waiting_name, waiting_record
                                )
                                else {}
                            )
                            diagnoses.append(
                                {
                                    "unit": waiting_name,
                                    "verdict": diagnosis.get("verdict"),
                                    "reason": (diagnosis.get("reason") or "")[:200],
                                }
                            )
                        self._write_progress(
                            state, "waiting_world_change",
                            run_state="waiting_world_change",
                        )
                        self.events.emit(
                            "waiting_world_change",
                            reds=len(waiting),
                            units=waiting[:20],
                            diagnoses=diagnoses[:20],
                            world_version=self._world_version(),
                        )
                        self.events.emit(
                            "driver_stopped", reason="waiting_world_change"
                        )
                        self._checkpoint(
                            state, None,
                            workflow_state="waiting_world_change",
                            driver_running=False,
                        )
                        return EXIT_NO_WORK
                    self._write_progress(state, "running" if work_left else "completed")
                    self.events.emit(
                        "driver_stopped",
                        reason="pass_complete" if work_left else "no_work_left",
                    )
                    self._checkpoint(
                        state, None,
                        workflow_state="running" if work_left else "complete",
                        driver_running=False,   # this run is ending right here
                    )
                    return EXIT_PROGRESSED if work_left else EXIT_NO_WORK
                self.events.emit("selection", action="wasm_unit", unit=unit["name"])
                self._write_progress(state, "porting", unit=unit["name"])
                try:
                    outcome = self._process_unit(unit, state)
                except Exception as error:  # noqa: BLE001
                    # An unexpected fault (a malformed queue entry, a copy
                    # failure, a git timeout) must still produce a transition
                    # record. Letting it escape leaves the unit stuck as
                    # `porting` with nothing on the progress branch until some
                    # later run reconciles it.
                    outcome = self._fail(
                        state, self._unit_state(state, unit["name"]), unit["name"],
                        f"unexpected fault: {error}", stage="port",
                    )
                if outcome == "provider_paused":
                    # The provider is out. Stop the pass rather than marching
                    # the rest of the queue into the same wall, and tell the
                    # machine layer in the vocabulary it already understands.
                    self._write_progress(
                        state, "paused_provider_unavailable",
                        run_state="provider_paused",
                    )
                    self.events.emit(
                        "driver_stopped", reason="provider_unavailable",
                        detail=(self._provider_paused_detail or "")[:300],
                    )
                    return EXIT_PROVIDER_PAUSED
                if outcome == "journal_blocked":
                    # Required assembly-failure evidence could not be made
                    # durable. Leave canonical state at ``porting`` so restart
                    # reconciliation cannot mistake the unit for settled, and
                    # stop before selecting any other unit.
                    self._write_progress(
                        state,
                        "stopped_journal_unavailable",
                        run_state="journal_blocked",
                    )
                    self.events.emit(
                        "driver_stopped",
                        reason="required_journal_checkpoint_failed",
                        unit=unit["name"],
                    )
                    return EXIT_STOPPED
                # Section 2.12(b) general lane (T3): after the SECOND failed
                # attempt, one diagnosis call per unit lifetime. STRUCTURAL
                # deprioritises + nominates for F4; FIXABLE feeds the
                # post-mortem. Never settles.
                if outcome == "red_retryable":
                    failed_record = self._unit_state(state, unit["name"])
                    if (
                        failed_record.get("attempts", 0) >= 2
                        and not self._diagnosis_is_current(
                            unit["name"], failed_record
                        )
                    ):
                        self._diagnose_unit(unit, failed_record, state)
                processed.add(unit["name"])
                steps_done += 1
                self._write_progress(state, "running")
                if not self.until_blocked and steps_done >= self.units_budget:
                    remaining = self._next_unit(queue, state, processed)
                    done = not self._work_remains(state) and remaining is None
                    if done:
                        self._write_progress(state, "completed")
                        self._checkpoint(
                            state, None, workflow_state="complete", driver_running=False,
                        )
                    self.events.emit("driver_stopped", reason="units_budget_reached")
                    return EXIT_NO_WORK if done else EXIT_PROGRESSED
        finally:
            self._heartbeat("wasm_units:idle")
            self.lock.release()


def main(argv: list[str] | None = None) -> int:
    """Maintenance CLI. ``settle-unit`` is the settle-through-journal path
    (section 2.9 [V4-9]): the ONLY sanctioned way to settle a verdict by hand.
    """
    import argparse

    parser = argparse.ArgumentParser(description=main.__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    settle = sub.add_parser(
        "settle-unit",
        help="settle one unit verdict through the journal (backup + edit + "
        "journal event + save); never hand-edit wasm-units-state.json",
    )
    settle.add_argument("--unit", required=True, help="queue unit name")
    settle.add_argument(
        "--status", required=True,
        choices=sorted(WasmUnitDriver._SETTLE_RESULTS),
        help="permanent status to record",
    )
    settle.add_argument(
        "--reason", required=True,
        help="why this verdict is being settled by hand (journaled verbatim)",
    )
    settle.add_argument("--repo-root", default=None, help="GotYaForce checkout root")
    revoke = sub.add_parser(
        "revoke-unit",
        help="revoke one settled verdict and requeue it through the journal; "
        "takes the driver lock, leaves the stale artifact as audit evidence, "
        "pushes only the port-progress journal, and never pushes a product ref",
    )
    revoke.add_argument("--unit", required=True, help="settled queue unit name")
    revoke.add_argument(
        "--reason", required=True,
        help="why this verdict is invalid (journaled verbatim)",
    )
    revoke.add_argument("--repo-root", default=None, help="GotYaForce checkout root")
    invalidate = sub.add_parser(
        "invalidate-diagnosis",
        help="remove one misrouted diagnosis through a lock-held, journal-first "
        "maintenance transition; never edits artifacts, registry, or product refs",
    )
    invalidate.add_argument("--unit", required=True, help="canonical unit name")
    invalidate.add_argument(
        "--reason", required=True,
        help="why the recorded diagnosis is invalid (journaled verbatim)",
    )
    invalidate.add_argument(
        "--repo-root", default=None, help="GotYaForce checkout root"
    )
    backfill = sub.add_parser(
        "backfill-artifact-digest",
        help="sanction one digest-less historical green through an exact "
        "publication-tree audit plus a durable port-progress journal receipt; "
        "takes the driver lock, never edits artifacts or product refs",
    )
    backfill.add_argument("--unit", required=True, help="one green unit name")
    backfill.add_argument(
        "--reason", required=True,
        help="operator reason for sanctioning the inventoried legacy bytes",
    )
    backfill.add_argument(
        "--repo-root", default=None, help="GotYaForce checkout root"
    )
    gate = sub.add_parser(
        "assembly-gate",
        help="run the continuous assembly gate (section 2.13) over the last N "
        "green/staged units (--all sweeps every unit: the composability "
        "backfill). Lock-free: reads committed artifacts only, writes its own "
        "workdir + the tracked ledger; emits no driver events.",
    )
    gate.add_argument(
        "--n", type=int, default=None,
        help="window size (default: OGHIDRA_PORT_ASSEMBLY_N or 5)",
    )
    gate.add_argument(
        "--all", action="store_true",
        help="assemble every green/staged unit instead of the last N",
    )
    gate.add_argument("--repo-root", default=None, help="GotYaForce checkout root")
    reverify = sub.add_parser(
        "reverify-unit",
        help="promote one staged compile-only green by re-running its "
        "oracle-commands.json sidecar oracle against the committed staged "
        "artifact (oracle plan section 3.4). Journal-emitting; takes the "
        "driver lock and refuses while a driver is alive.",
    )
    reverify.add_argument("--unit", required=True, help="staged unit name")
    reverify.add_argument("--repo-root", default=None, help="GotYaForce checkout root")
    migrate = sub.add_parser(
        "d5-migrate",
        help="D5-6 migration steps 2-3: revoke-and-requeue (through the "
        "journal, verdict_revoked) every settled green whose staged artifact "
        "the D5 census predicate selects, evaluated now. Site-free artifacts "
        "stand (identity carve-out). Takes the driver lock; refuses while a "
        "driver is alive. Never pushes.",
    )
    migrate.add_argument(
        "--dry-run", action="store_true",
        help="evaluate and report the predicate only; no lock, no writes",
    )
    migrate.add_argument(
        "--wait-seconds", type=float, default=0.0,
        help="poll this long for the driver lock instead of refusing "
        "immediately (the live driver frees it between unit runs)",
    )
    migrate.add_argument("--repo-root", default=None, help="GotYaForce checkout root")
    f4 = sub.add_parser(
        "f4-recheck",
        help="F4 bounded recheck (design section 2.7): replay up to N "
        "structural_ineligible / diagnosis-nominated units offline with the "
        "current loop. Reports; never settles or unsettles. A settled unit "
        "that links is the classifier-freeze signal (exit 1).",
    )
    f4.add_argument("--sample", type=int, default=5, help="max units to replay")
    f4.add_argument("--repo-root", default=None, help="GotYaForce checkout root")
    args = parser.parse_args(argv)
    if args.command == "settle-unit":
        driver = WasmUnitDriver(repo_root=args.repo_root)
        print(json.dumps(driver.settle_unit(args.unit, args.status, args.reason), indent=2))
        return 0
    if args.command == "revoke-unit":
        driver = WasmUnitDriver(repo_root=args.repo_root)
        print(json.dumps(driver.revoke_unit(args.unit, args.reason), indent=2))
        return 0
    if args.command == "invalidate-diagnosis":
        driver = WasmUnitDriver(repo_root=args.repo_root)
        print(json.dumps(
            driver.invalidate_diagnosis(args.unit, args.reason), indent=2
        ))
        return 0
    if args.command == "backfill-artifact-digest":
        driver = WasmUnitDriver(repo_root=args.repo_root)
        print(json.dumps(
            driver.backfill_artifact_digest(args.unit, args.reason), indent=2
        ))
        return 0
    if args.command == "assembly-gate":
        driver = WasmUnitDriver(repo_root=args.repo_root)
        window = None if args.all else (args.n or assembly_window_size())
        result = driver.run_assembly_gate_now(window, workdir_name="_assembly-manual")
        print(json.dumps(result, indent=2))
        return 0 if result.get("passed") in (True, None) else 1
    if args.command == "reverify-unit":
        driver = WasmUnitDriver(repo_root=args.repo_root)
        result = driver.reverify_unit(args.unit)
        print(json.dumps(result, indent=2))
        return 0 if result.get("promoted") else 1
    if args.command == "d5-migrate":
        driver = WasmUnitDriver(repo_root=args.repo_root)
        deadline = time.monotonic() + max(0.0, args.wait_seconds)
        while True:
            try:
                result = driver.d5_migrate(dry_run=args.dry_run)
                break
            except RuntimeError as error:
                if "wasm-units.lock" not in str(error) or (
                    time.monotonic() >= deadline
                ):
                    raise
                time.sleep(2.0)
        print(json.dumps(result, indent=2))
        return 0
    if args.command == "f4-recheck":
        driver = WasmUnitDriver(repo_root=args.repo_root)
        result = driver.f4_recheck(args.sample)
        print(json.dumps(result, indent=2))
        return 1 if result.get("classifier_freeze_signal") else 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
