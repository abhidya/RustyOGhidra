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
Use ``settle_unit`` (driver method, or the ``settle-unit`` CLI subcommand of
this module), which backs up the state file, edits the record, emits the
journal checkpoint + events.jsonl event, and saves atomically.
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
from pathlib import Path
from typing import Any

from src.port_assembly_gate import (
    ASSEMBLY_WASM,
    SMOKE_JS,
    assembly_window_size,
    gate_ledger_material,
    read_gate_ledger,
    record_gate_result,
    run_assembly_gate,
    select_recent_green_units,
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
    harvest_unit,
    is_holdout,
    load_registry,
    prelude_prototypes,
    promote_unit_entries,
    record_surviving_deviations,
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
        # Continuous assembly gate (section 2.13 [V4-11], T2b): after every
        # green, the last N green/staged units are linked in one invocation
        # and instantiation-smoked. The ledger (largest-N-passed + conflict
        # records) lives in the tracked data dir, like the priority sidecar.
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
    ) -> None:
        """Emit one remote progress checkpoint. Telemetry: never fails a unit.

        Called at EVERY unit transition, before the selector moves on -- the
        unit-transition invariant. A git/network fault degrades to a recorded
        pending push, never to a lost unit or a raised exception.
        """
        machine = MachineState(
            workflow_state=workflow_state,
            driver_status="running" if driver_running else "stopped",
            configured_model=self._model_config.model,
            active_model=self._model_config.model,
            context_length=self._model_config.max_seq_length or None,
        )
        try:
            self._journal.checkpoint(
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
        if transition is not None:
            self._previous_unit = transition.unit
            self._previous_result = transition.result

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

    def run_assembly_gate_now(
        self,
        n: int | None = None,
        *,
        workdir_name: str = "_assembly",
    ) -> dict[str, Any]:
        """One assembly-gate pass over the last n green/staged units (n=None
        sweeps everything -- the backfill form). Emits NO events and takes no
        lock: safe from the maintenance CLI while a driver is alive (it reads
        only committed artifacts and writes only its own workdir + ledger)."""
        units = select_recent_green_units(
            [self.artifact_root, self.staging_root], n
        )
        if len(units) < 2:
            return {
                "passed": None,
                "n": len(units),
                "units": [unit.name for unit in units],
                "stage": "skipped",
                "conflicts": [],
                "detail": "fewer than 2 green/staged units; nothing to compose",
            }
        result = run_assembly_gate(
            units,
            self.work_root / workdir_name,
            link_runner=self._assembly_link_runner,
            smoke_runner=self._assembly_smoke_runner,
        )
        record_gate_result(self.assembly_ledger_path, result)
        return result

    def _maybe_run_assembly_gate(self, unit_name: str) -> None:
        """Driver-side gate hook, called after every green/staged unit.

        Telemetry-with-teeth: the gate NEVER changes the unit's verdict (the
        unit already earned green), but a failure pages (assembly_gate_failed
        event, the section 4 [V4-11] invariant row) and files conflict
        records in the tracked ledger. Any internal fault degrades to an
        event, never to a lost unit."""
        try:
            material_before = gate_ledger_material(
                read_gate_ledger(self.assembly_ledger_path)
            )
            result = self.run_assembly_gate_now(assembly_window_size())
            if result.get("passed") is None:
                return  # fewer than 2 units: composition is not yet a claim
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
                    detail=(result.get("detail") or "")[:600],
                )
            # Best-effort ledger commit: the conflict records are the
            # cross-unit reconciliation report (section 3) and belong in
            # history next to the unit that surfaced them. Never fatal.
            # MATERIAL changes only (new/changed conflict identity or a new
            # largest_n_passed): record_gate_result stamps last_run/updated_at
            # on every call, so committing the raw file would mint one churn
            # commit per green. Immaterial runs leave the file updated on disk
            # but uncommitted -- safe, because every other driver commit here
            # is pathspec'd (git add <paths> + git commit -- <paths>), never a
            # tree-wide sweep. NO push: the commit rides this branch and
            # reaches the remote with the next sanctioned product push
            # (_commit_unit/_commit_paths); a bare push here was landing one
            # "port-assembly:" commit on origin/main per green.
            material_after = gate_ledger_material(
                read_gate_ledger(self.assembly_ledger_path)
            )
            if material_after != material_before:
                rel = "research/decomp/data/assembly-gate.json"
                added = self._git_runner("add", "--", rel)
                if added.returncode == 0:
                    self._git_runner(
                        "commit",
                        "-m",
                        (
                            f"port-assembly: gate N={result.get('n')} "
                            f"{'pass' if result.get('passed') else 'FAIL'} "
                            f"({len(result.get('conflicts') or [])} conflict(s)) "
                            f"after {unit_name}"
                        ),
                        "--",
                        rel,
                    )
        except Exception as error:  # noqa: BLE001 - the gate never fails a unit
            self.events.emit(
                "assembly_gate_error", unit=unit_name, error=str(error)[:400]
            )

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

    def _commit_unit(
        self,
        name: str,
        summary: str,
        *,
        staging: bool = False,
        extra_paths: list[str] | None = None,
    ) -> tuple[str | None, bool, str]:
        """git add + commit + push the unit's artifact dir. Returns
        (commit_sha or None, pushed, detail). ``extra_paths`` ride the SAME
        commit (T2c: the harvested knowledge registry lands with the unit
        that produced it -- one push, G3-preserving)."""
        rel = (
            f"research/decomp/port-units-staging/{name}"
            if staging
            else f"research/decomp/port-units/{name}"
        )
        paths = [rel, *(extra_paths or [])]
        added = self._git_runner("add", "--", *paths)
        if added.returncode != 0:
            return None, False, (added.stdout + added.stderr)[-400:]
        message = (
            f"port-staging: {name} wasm unit LINKED (unoracled, not for integration)"
            if staging
            else f"port: {name} wasm unit green (oracle {summary})"
        )
        committed = self._git_runner("commit", "-m", message, "--", *paths)
        if committed.returncode != 0:
            return None, False, (committed.stdout + committed.stderr)[-400:]
        sha = ""
        rev = self._git_runner("rev-parse", "HEAD")
        if rev.returncode == 0:
            sha = rev.stdout.strip()
        pushed = self._push_product()
        return sha or None, pushed.returncode == 0, (
            "" if pushed.returncode == 0 else (pushed.stdout + pushed.stderr)[-400:]
        )

    def _push_product(self) -> subprocess.CompletedProcess[str]:
        """The ONE sanctioned product push: current branch to its same-named
        branch on origin, explicit refspec (a bare `git push` depends on
        ambient upstream config -- the gate-ledger bug rode exactly that).
        This lands greens on GotYaForce main per the runbook invariant
        ("main should receive a push whenever a unit goes green"); the
        port-progress branch is journal-owned (port_progress.py pushes it
        with its own explicit refspec from its own worktree) and product
        history must never be pushed there. One retry for transient faults."""
        pushed = self._git_runner("push", "origin", "HEAD")
        if pushed.returncode != 0:
            pushed = self._git_runner("push", "origin", "HEAD")
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

        # 5. green: artifacts + provenance + commit-per-match
        artifact_dir = (
            self.staging_root if compile_only else self.artifact_root
        ) / name
        artifact_dir.mkdir(parents=True, exist_ok=True)
        for file_name in ("unit.c", "gnt4_shim.h", "unit.wasm", "oracle.log"):
            shutil.copyfile(workdir / file_name, artifact_dir / file_name)
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
        atomic_write_json(artifact_dir / "provenance.json", provenance)
        # 5b. registry harvest (section 2.11, T2c [V4-1]): mechanical, no LLM.
        # The unit's own decisions (diffed against the AUGMENTED seed, minus
        # callee stubs) enter the registry at the unit's tier; the unit's
        # independent derivation doubles as the per-entry replication
        # experiment, so a disagreement with an advisory entry is filed as a
        # conflict here -- surfaced immediately, never deferred to assembly.
        # The registry file rides the unit's own artifact commit (one push,
        # G3-preserving). A harvest fault never costs the green.
        registry_rel: str | None = None
        try:
            final_header = (workdir / "gnt4_shim.h").read_text(encoding="utf-8")
            registry = self._registry()
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
            if harvest.changed or deviation_fold.changed:
                self._save_registry(registry)
                registry_rel = REGISTRY_RELPATH
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
        try:
            sha, pushed, push_detail = self._commit_unit(
                name, summary, staging=compile_only,
                extra_paths=[registry_rel] if registry_rel else None,
            )
        except (OSError, subprocess.SubprocessError) as error:
            # A stalled `git push` hits the 300s timeout and raises
            # TimeoutExpired (a SubprocessError, NOT an OSError). Unguarded, it
            # escaped run() entirely and left the unit stuck as `porting` after
            # the local commit had already succeeded.
            return self._fail(
                state, record, name, f"product commit/push: {error}", stage="commit",
            )
        if sha is None:
            # The artifact never entered git history. Marking it green would
            # SETTLE it -- removing it from the queue forever with nothing in the
            # product tree, and rendering on GitHub as an ordinary green.
            return self._fail(
                state, record, name,
                f"product commit failed, unit not settled: {push_detail}",
                stage="commit",
            )
        self._checkpoint(
            state,
            UnitTransition(
                unit=name,
                result=RESULT_STAGED if compile_only else RESULT_GREEN,
                stage="commit",
                attempt=record.get("attempts", 0),
                detail=(
                    "compile-only staging artifact (UNVERIFIED, not integrated)"
                    if compile_only
                    else f"oracle green: {summary}"
                ),
                product_commit=sha,
                product_pushed=pushed,
                oracle_summary=summary,
                model=model_used or self._model_config.model,
                tier="compile_only" if compile_only else "oracle_green",
            ),
        )
        record.update(
            status="green",
            error=None,
            oracle_summary=summary,
            commit=sha,
            pushed=pushed,
            tier="compile_only" if compile_only else "oracle_green",
            last_stage="commit",
        )
        self._save_state(state)
        self._greens_this_run += 1
        self.events.emit(
            "wasm_unit_green",
            unit=name,
            oracle_summary=summary,
            commit=sha,
            pushed=pushed,
            push_detail=push_detail,
        )
        # Section 4 T3 row: verified fraction falling while staged grows pages
        # (unverifiable-inventory build-up).
        self._flag_unverified_inventory(state)
        # Continuous assembly gate (section 2.13 [V4-11]): every green feeds
        # the rolling N-unit link. Runs after the unit's own commit so a gate
        # fault can never cost a green; failures page + file conflicts.
        self._maybe_run_assembly_gate(name)
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
        if status in self.SETTLED_STATUSES:
            # Settling removes the unit from the queue permanently, and
            # `_reconcile_interrupted` only rescues units left as `porting`.
            # Record it remotely BEFORE it becomes unrecoverable locally.
            self._checkpoint(state, transition)
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
        if record.get("diagnosis"):
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
        pushed = self._push_product()
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

    def _reconcile_interrupted(self, state: dict[str, Any]) -> None:
        """A unit left `porting` by a killed run never got a transition record.

        The supervisor kills the driver tree on player join / manual pause, so
        this is the normal path, not an exception. Reclassify as `deferred` and
        emit the checkpoint the killed run owed -- otherwise GitHub shows unit A
        as still in flight while the selector has already moved to unit B.
        """
        for name, record in state.get("units", {}).items():
            if record.get("status") != "porting":
                continue
            record["status"] = "deferred"
            record["error"] = "interrupted before a verdict (driver killed or crashed)"
            # Refund the ATTEMPT (the unit earned no verdict, and charging it
            # would push it behind the entire queue every time the supervisor
            # kills the driver for a player join or a manual pause -- a
            # starvation machine), but COUNT the interruption. Ordering uses
            # attempts + interruptions, so a unit that keeps taking the driver
            # down with it still sinks instead of being retried forever.
            record["attempts"] = max(0, record.get("attempts", 1) - 1)
            record["interruptions"] = int(record.get("interruptions", 0)) + 1
            self._save_state(state)
            self._checkpoint(
                state,
                UnitTransition(
                    unit=name,
                    result=RESULT_DEFERRED,
                    stage=record.get("last_stage") or "port",
                    attempt=record.get("attempts", 0),
                    detail="interrupted before a verdict; requeued",
                    model=self._model_config.model,
                ),
            )
            # Deferred is a transient class: the unit re-enters the pool as
            # pending so `_next_unit` treats it like any other retry candidate.
            record["status"] = "pending"
            self._save_state(state)

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
                (record.get("diagnosis") or {}).get("verdict") == "STRUCTURAL"
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
            self._reconcile_interrupted(state)
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
                                not waiting_record.get("diagnosis")
                                and waiting_name in queue_by_name
                            ):
                                self._diagnose_unit(
                                    queue_by_name[waiting_name],
                                    waiting_record,
                                    state,
                                )
                            diagnosis = waiting_record.get("diagnosis") or {}
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
                # Section 2.12(b) general lane (T3): after the SECOND failed
                # attempt, one diagnosis call per unit lifetime. STRUCTURAL
                # deprioritises + nominates for F4; FIXABLE feeds the
                # post-mortem. Never settles.
                if outcome == "red_retryable":
                    failed_record = self._unit_state(state, unit["name"])
                    if (
                        failed_record.get("attempts", 0) >= 2
                        and not failed_record.get("diagnosis")
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
