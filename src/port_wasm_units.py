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
    record_gate_result,
    run_assembly_gate,
    select_recent_green_units,
)
from src.port_chunk_workflow import TRANSIENT_MARKERS, atomic_write_json, utc_now
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
PROMPT_VERSION = 1

# Knowledge-registry version component. The registry does not exist until T2c
# (design section 2.11); a constant 0 keeps the world-hash shape stable so
# verdicts recorded now stay comparable when the registry lands.
REGISTRY_VERSION = 0


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
        "registry_version": str(REGISTRY_VERSION),
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
        self._world_version_cache: dict[str, str] | None = None
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
        return self._world_version_cache

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
                "units_known": len(units),
                "model_requests_total": sum(
                    record.get("model_requests", 0) for record in units.values()
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
        bash = resolve_bash()
        emsdk = self.repo_root / "research/tools/emsdk"
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
            # history next to the unit that surfaced them. Never fatal, and
            # an unchanged ledger simply fails the commit quietly.
            rel = "research/decomp/data/assembly-gate.json"
            added = self._git_runner("add", rel)
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
                self._git_runner("push")
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
        self, name: str, summary: str, *, staging: bool = False
    ) -> tuple[str | None, bool, str]:
        """git add + commit + push the unit's artifact dir. Returns
        (commit_sha or None, pushed, detail)."""
        rel = (
            f"research/decomp/port-units-staging/{name}"
            if staging
            else f"research/decomp/port-units/{name}"
        )
        added = self._git_runner("add", rel)
        if added.returncode != 0:
            return None, False, (added.stdout + added.stderr)[-400:]
        message = (
            f"port-staging: {name} wasm unit LINKED (unoracled, not for integration)"
            if staging
            else f"port: {name} wasm unit green (oracle {summary})"
        )
        committed = self._git_runner("commit", "-m", message, "--", rel)
        if committed.returncode != 0:
            return None, False, (committed.stdout + committed.stderr)[-400:]
        sha = ""
        rev = self._git_runner("rev-parse", "HEAD")
        if rev.returncode == 0:
            sha = rev.stdout.strip()
        pushed = self._git_runner("push")
        if pushed.returncode != 0:
            pushed = self._git_runner("push", "-u", "origin", "HEAD")
        return sha or None, pushed.returncode == 0, (
            "" if pushed.returncode == 0 else (pushed.stdout + pushed.stderr)[-400:]
        )

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

        # 1. verbatim extraction (sha256-recorded)
        try:
            verbatim, extraction_records = extract_verbatim(self.repo_root, unit["extractions"])
        except (OSError, ValueError, KeyError) as error:
            # The queue entry does not describe extractable code: retrying the
            # identical spec cannot help, so this is structural, not retryable.
            return self._fail(
                state, record, name, f"extraction: {error}",
                stage="extract", result=RESULT_STRUCTURAL_INELIGIBLE,
            )
        prelude = "\n".join(unit.get("prelude", []))
        unit_c = (
            "#include \"gnt4_shim.h\"\n\n"
            + (prelude + "\n\n" if prelude else "")
            + verbatim
        )
        (workdir / "unit.c").write_text(unit_c, encoding="utf-8", newline="\n")
        combined_sha = hashlib.sha256(verbatim.encode("utf-8")).hexdigest()

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
        (workdir / "gnt4_shim.h").write_text(header, encoding="utf-8", newline="\n")

        # 3. build + LLM compile-fix loop (header-only edits; depth capped by
        #    OGHIDRA_PORT_MAX_ITERS per section 2.1, stage-aware stuck-abort
        #    per section 2.2, round-level malformed replies per section 2.5)
        exports = unit["exported_functions"]
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
        current_header_path = str(header_seed)
        # Per-round memory (section 2.3 [V4-4]): stage, error count, header
        # path, plus the NORMALIZED DIAGNOSTIC SET and its fingerprint --
        # "never cleared" is then a set intersection and cross-attempt
        # oscillation detection a fingerprint comparison. Persisted into the
        # unit state record on _fail for the post-mortem carry.
        rounds: list[dict[str, Any]] = []
        for iteration in range(1, MAX_COMPILE_ITERS + 1):
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
            if iteration == MAX_COMPILE_ITERS:
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
            (workdir / "gnt4_shim.h").write_text(fixed, encoding="utf-8", newline="\n")
            # Section 2.3 [V4-4]: snapshots are ATTEMPT-scoped
            # (header-attempt{A}-iter{I}.h) so a later attempt can never
            # overwrite the artifact the post-mortem carry decision needs.
            snapshot = workdir / f"header-attempt{record['attempts']}-iter{iteration}.h"
            snapshot.write_text(fixed, encoding="utf-8", newline="\n")
            current_header_path = str(snapshot)
            header_applied = True
        if not linked:
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
        oracle_spec = unit.get("oracle") or {}
        compile_only = oracle_spec.get("type") == "compile_only"
        if compile_only:
            passed, summary, oracle_log = True, "compile-only (UNVERIFIED)", (
                "compile_only tier: build + import whitelist gates only; no "
                "behavioral oracle was run. NOT for app integration."
            )
        else:
            self._heartbeat(f"wasm_units:{name}:oracle")
            try:
                passed, summary, oracle_log = self._oracle_runner(unit, workdir / "unit.wasm")
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
            "exported_functions": exports,
            "compile_iterations": iterations,
            "model": model_used,
            "model_requests": record.get("model_requests", 0),
            "verified": not compile_only,
            "tier": "compile_only" if compile_only else "oracle_green",
            "allowed_extra_imports": unit.get("allowed_extra_imports") or [],
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
        try:
            sha, pushed, push_detail = self._commit_unit(name, summary, staging=compile_only)
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
        schedulable (its world is unknown, so a delta cannot be excluded)."""
        if record.get("status") != "red_retryable":
            return False
        recorded = record.get("world_version")
        return isinstance(recorded, dict) and recorded == self._world_version()

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
            # Section 2.14 [V4-2]: product_priority leads the key (higher
            # serves first, hence negated); chunk/queue order stays the tail
            # tie-break. An absent sidecar makes every priority 0 and the
            # ordering collapses to the previous (cost, index) behaviour.
            candidates.append((-self._unit_priority(name), cost, index, unit))
        if not candidates:
            return None
        candidates.sort(key=lambda item: (item[0], item[1], item[2]))
        return candidates[0][3]

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
                        self._write_progress(
                            state, "waiting_world_change",
                            run_state="waiting_world_change",
                        )
                        self.events.emit(
                            "waiting_world_change",
                            reds=len(waiting),
                            units=waiting[:20],
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
    return 2


if __name__ == "__main__":
    sys.exit(main())
