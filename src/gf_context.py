"""
Gotcha Force deterministic context resolver.

Given a function's decompiled code, resolve the *literal* references it contains
against the project's structured knowledge:
  - callee addresses  -> engine/game symbol names   (research/symbols/GG4E-CSM-*.map)
  - struct offsets     -> documented borg-struct meanings (behavior-notes.md table)
  - pl#### ids         -> borg name + family          (research/symbols/NTSC_Borgs.csv)

This is the precise half of the KB (exact lookups). The fuzzy half (prose notes)
is handled by CAG semantic retrieval. Together they ground naming in real facts
instead of the malware-flavored guesses the single-shot prompt produced.
"""
import csv, json, os, re, glob, functools

# Matches a code/data address inside any Ghidra token: bare `80112f00`, `0x80112f00`,
# and underscore-joined forms like FUN_80112f00 / DAT_80439080 / PTR_FUN_80327f38 /
# FLOAT_8043908c (a plain \b never fires after `_` since both sides are word chars).
_ADDR = re.compile(r"(?:\b0x|_|\b)(80[0-9a-fA-F]{6})\b")
# zz_ map placeholders encode the address without the 0x80000000 base: zz_0112f00_ -> 80112f00.
_ZZ = re.compile(r"\bzz_([0-9a-fA-F]{7})_")
_OFF = re.compile(r"0x[0-9a-fA-F]{2,4}\b")
# Ghidra prints some struct offsets in DECIMAL, e.g. `*(short *)(param_1 + 1000)` == 0x3E8.
# Match a decimal literal used as a pointer offset (after `+ `) so those don't escape grounding.
_OFF_DEC = re.compile(r"\+\s*(\d{2,5})\b")
_PL = re.compile(r"\bpl([0-9a-fA-F]{4})\b", re.I)
# High-confidence borg-instance fields, as normalized "0xNNN" keys.
_BORG_FIELD_KEYS = {"0x544", "0x720", "0x5e0", "0x272", "0x591", "0x5aa", "0x5ac", "0x5ae", "0x1dcc"}


def _offset_keys(code):
    """All struct-offset references in the code, normalized to lowercase '0xNNN' keys,
    covering both hex (`+ 0x544`, `[0x544]`) and decimal (`+ 1000`) forms."""
    keys = set(m.group(0).lower() for m in _OFF.finditer(code or ""))
    for m in _OFF_DEC.finditer(code or ""):
        keys.add("0x%x" % int(m.group(1)))
    return keys


# Engine/SDK signatures — HAL/HSD, OS, GX, PS matrix-vector math, gnt4- boot/runtime, TRK.
_ENGINE_SIG = re.compile(
    r"\b(OS[A-Z]\w+|__OS\w+|HSD_\w+|[JADMFT]Obj\w*|gnt4[_-]\w+|PSMTX\w*|PSVEC\w*|PSQUAT\w*|QUAT\w+"
    r"|MTX\w+|VEC\w+|TRK_\w+|MetroTRK|GX[A-Z]\w+|DVD[A-Z]\w+|__init_\w+|_pow_bl|_sqrt|_cos|_sin)\b"
)


def classify_tier(code, gf_resolved=""):
    """Route a function to a prompt framing based on the evidence actually present in its own
    code (not its callers): 'borg' (touches the borg instance struct), 'engine' (HAL/HSD/OS/GX/
    PS-math/gnt4/TRK), or 'neutral' (undetermined — name it for what the code literally does)."""
    code = code or ""
    gf = gf_resolved or ""
    if (
        "BorgInstance" in code                      # param already typed BorgInstance*
        or (_offset_keys(code) & _BORG_FIELD_KEYS)  # raw borg struct offset access
        or "Borg struct fields touched" in gf       # resolver (not CAG notes) confirmed borg fields
        or "Borg character ids referenced" in gf
    ):
        return "borg"
    if _ENGINE_SIG.search(code) or "Engine/game symbols called" in gf:
        return "engine"
    return "neutral"
_NOISE_LABELS = {"FLOAT", "DOUBLE", "DAT", "GATE", "GENERIC", "PTR", "ADDR", "BYTE", "WORD", "SHORT", "VALUE", "DATA", "TABLE", "ENTRY", "ITEM", "ROW"}


# Confidence floor for surfacing an INFERRED entry into a prompt. Entries below this are
# loaded but never injected — they're still accumulating cross-session agreement.
_INFERRED_MIN_CONF = 0.60


class GFContext:
    def __init__(self, research_root):
        self.root = research_root
        self.symbols = self._load_symbol_map()          # int addr -> name
        self.offsets = self._load_struct_offsets()       # "0x544" -> meaning
        self.borgs = self._load_borgs()                  # "pl0000" -> dict
        self.data_labels = self._load_data_labels()      # int addr -> data label (deterministic)
        # Staging tier: hypotheses accumulated from prior naming sweeps (NOT authoritative).
        # Kept strictly separate from the sources above and surfaced under its own header.
        self.inferred_symbols, self.inferred_offsets = self._load_inferred_kb()

    # ---------- loaders ----------
    def _load_symbol_map(self):
        out = {}
        for mp in glob.glob(os.path.join(self.root, "symbols", "*.map")):
            for ln in open(mp, encoding="utf-8", errors="ignore"):
                m = re.match(r"^([0-9a-fA-F]{8})\s+\S+\s+\S+\s+\S+\s+(.+?)\s*$", ln)
                if m:
                    out[int(m.group(1), 16)] = m.group(2)
        return out

    def _load_struct_offsets(self):
        """Parse the borg-struct offset->meaning table in behavior-notes.md."""
        out = {}
        bn = os.path.join(self.root, "decomp", "behavior-notes.md")
        if not os.path.exists(bn):
            return out
        for ln in open(bn, encoding="utf-8", errors="ignore"):
            if not ln.strip().startswith("|"):
                continue
            cells = [c.strip() for c in ln.strip().strip("|").split("|")]
            if len(cells) < 4:
                continue
            offs = re.findall(r"0x[0-9a-fA-F]{2,4}", cells[0])
            meaning = cells[-1]
            if offs and meaning and "meaning" not in meaning.lower() and "---" not in cells[0]:
                for o in offs:
                    out[o.lower()] = f"{meaning}  [type: {cells[1]}]"
        return out

    def _load_inferred_kb(self):
        """Load the inferred-knowledge sidecar (hypotheses from prior naming sweeps).

        Returns (symbols, offsets) dicts keyed for O(1) lookup:
          symbols: {int_addr: entry}          — callee roles; addresses are globally unique
          offsets: {"borg:0xNNN": entry}       — struct-field meanings, STRUCT-SCOPED

        Only entries that (a) clear the confidence floor and (b) are not marked `negated`
        (proven-false refutations) are retained for injection. The file is produced offline
        by build_inferred_kb.py between sweeps; its absence is normal (debug, not warning)."""
        syms, offs = {}, {}
        path = os.path.join(self.root, "decomp", "data", "inferred-knowledge.json")
        if not os.path.exists(path):
            return syms, offs
        try:
            data = json.load(open(path, encoding="utf-8"))
        except Exception:
            return syms, offs

        def usable(e):
            return isinstance(e, dict) and not e.get("negated") and float(e.get("confidence", 0)) >= _INFERRED_MIN_CONF

        for addr_str, e in (data.get("symbols") or {}).items():
            if not usable(e):
                continue
            m = re.search(r"(80[0-9a-fA-F]{6})", str(addr_str))
            if m:
                syms[int(m.group(1), 16)] = e
        for key, e in (data.get("struct_offsets") or {}).items():
            # Keys are scope-qualified ("borg:0x6f6"); keep the scope so the consumer only
            # injects an offset into a prompt for the struct it was observed on.
            if usable(e) and re.match(r"^[a-z]+:0x[0-9a-fA-F]+$", str(key)):
                offs[str(key).lower()] = e
        return syms, offs

    def _load_borgs(self):
        out = {}
        for csvf in glob.glob(os.path.join(self.root, "symbols", "*orgs*.csv")):
            try:
                for row in csv.DictReader(open(csvf, encoding="utf-8", errors="ignore")):
                    fn = (row.get("filename") or "").strip().lower()
                    if re.match(r"^pl[0-9a-f]{4}$", fn):
                        out[fn] = row
            except Exception:
                pass
        return out

    def _load_data_labels(self):
        """Deterministic address -> data-label map for the decoded ROM tables.
        Addresses come from the filename suffix (`slug-<addr>.json`), from sub-keys that
        carry an address (`attackerHpCurves_804335e8`), and from `address`/`table_base`
        fields inside each table. Used to rename Ghidra DATA labels exactly (no LLM)."""
        out = {}
        fn_addr = re.compile(r"-(80[0-9a-fA-F]{6})\.json$", re.I)
        key_addr = re.compile(r"^(.*?)[_-](80[0-9a-fA-F]{6})$")

        def norm(s):
            s = re.sub(r"[^0-9a-zA-Z]+", "_", str(s)).strip("_")
            return ("gf_" + s) if s and not s.startswith("gf_") else (s or "gf_table")

        # identified-functions.json maps CODE addresses to function roles — that belongs to
        # function naming, not data labeling; skip it here so it doesn't mislabel code as data.
        SKIP = {"identified-functions.json"}
        # boot.dol data sections start at 0x802b0160; addresses below that are .text (code).
        # A table's sub-fields can contain function pointers (e.g. anim_setter), so gate
        # walk-discovered addresses to the data sections. Explicit filename table bases are
        # trusted regardless (some tables legitimately live in .text, e.g. knockback @800300bc).
        DATA_START = 0x802B0160
        bases = set()
        ddir = os.path.join(self.root, "decomp", "data")
        for jf in glob.glob(os.path.join(ddir, "*.json")):
            base = os.path.basename(jf)
            if base in SKIP:
                continue
            slug = base[:-5] if base.lower().endswith(".json") else base   # drop .json
            m = fn_addr.search(base)
            slug = re.sub(r"-80[0-9a-fA-F]{6}$", "", slug)                  # drop -<addr>
            table_label = norm(slug)
            if m:
                a = int(m.group(1), 16)
                out.setdefault(a, table_label); bases.add(a)
            try:
                obj = json.load(open(jf, encoding="utf-8"))
            except Exception:
                continue

            # Iterative walk over the JSON: harvest sub-table addresses from keys like
            # `attackerHpCurves_804335e8` and from `address`/`table_base` fields.
            stack = [obj]
            while stack:
                o = stack.pop()
                if isinstance(o, dict):
                    for k, v in o.items():
                        # Only descriptive `name_<addr>` keys (e.g. attackerHpCurves_804335e8)
                        # become labels — these are named sub-tables with unique names. We do
                        # NOT label bare `address` fields, which recur per array-entry and would
                        # produce hundreds of duplicate labels.
                        km = key_addr.match(str(k))
                        if km:
                            a = int(km.group(2), 16)
                            label_body = km.group(1)
                            # skip type markers / generic keys that recur and carry no meaning
                            if (a >= DATA_START and len(label_body) >= 3
                                    and label_body.upper() not in _NOISE_LABELS
                                    and not re.fullmatch(r"[A-Z]{3,6}", label_body)):
                                out.setdefault(a, norm(label_body))
                        stack.append(v)
                elif isinstance(o, list):
                    stack.extend(o)
        return out

    def iter_data_labels(self):
        """Yield (address_hex_str, label) for every known data table address."""
        for a, lbl in sorted(self.data_labels.items()):
            yield (f"{a:08x}", lbl)

    @staticmethod
    def is_borg_function(code):
        """True if the decompiled code dereferences a high-confidence borg struct field
        (hex or decimal offset), i.e. its first pointer param is a BorgInstance*."""
        return bool(code) and bool(_offset_keys(code) & _BORG_FIELD_KEYS)

    @staticmethod
    def first_param_name(code):
        """Extract the first parameter's name from a decompiled function signature.
        Returns None for void/no-arg functions."""
        m = re.search(r"\b[A-Za-z_]\w*\s*\(([^)]*)\)", code or "")
        if not m:
            return None
        params = m.group(1).strip()
        if not params or params.lower() == "void":
            return None
        first = params.split(",")[0].strip()
        tok = first.replace("*", " ").split()
        return tok[-1] if tok else None

    # ---------- resolve ----------
    def resolve_for_code(self, code, self_addr=None, max_syms=12, max_offs=12):
        syms, offs, borgs, tables = [], [], [], []
        inf_syms, inf_offs = [], []
        # Struct scope: inferred OFFSET meanings are struct-specific ("0x6f6" means different
        # things on BorgInstance vs a widget). Only inject borg-scoped inferred offsets when
        # this function actually touches the borg struct — same signal classify_tier uses.
        is_borg_code = bool(code) and ("BorgInstance" in code or (_offset_keys(code) & _BORG_FIELD_KEYS))

        addrs = set(int(m.group(1), 16) for m in _ADDR.finditer(code))
        addrs |= set(0x80000000 | int(m.group(1), 16) for m in _ZZ.finditer(code))
        for a in sorted(addrs):
            if self_addr is not None and a == int(self_addr, 16):
                continue
            name = self.symbols.get(a)
            if name and not name.startswith("zz_"):
                syms.append((f"0x{a:08x}", name))
            elif a in self.inferred_symbols:  # only if no authoritative name exists
                e = self.inferred_symbols[a]
                inf_syms.append((f"0x{a:08x}", e.get("role", ""), e.get("confidence", 0)))
            lbl = self.data_labels.get(a)
            if lbl:
                tables.append((f"0x{a:08x}", lbl))
        for m in sorted(_offset_keys(code)):
            if m in self.offsets:            # authoritative wins; never inject an inferred dup
                offs.append((m, self.offsets[m]))
            elif is_borg_code and f"borg:{m}" in self.inferred_offsets:
                e = self.inferred_offsets[f"borg:{m}"]
                inf_offs.append((m, e.get("meaning", ""), e.get("confidence", 0)))
        for m in sorted(set("pl" + x.group(1).lower() for x in _PL.finditer(code))):
            if m in self.borgs:
                b = self.borgs[m]
                borgs.append((m, f"{b.get('borgname','?')} ({b.get('Tribe','?')}, {b.get('Type','?')})"))
        return self._format(
            syms[:max_syms], offs[:max_offs], borgs, tables[:max_syms],
            inf_syms[:max_syms], inf_offs[:max_offs],
        )

    def _format(self, syms, offs, borgs, tables=(), inf_syms=(), inf_offs=()):
        if not (syms or offs or borgs or tables or inf_syms or inf_offs):
            return ""
        s = []
        if syms or offs or borgs or tables:
            s.append("## RESOLVED REFERENCES (exact lookups from project knowledge — authoritative)")
            if offs:
                s.append("\n**Borg struct fields touched (offset → documented meaning):**")
                s += [f"- `{o}` → {mng}" for o, mng in offs]
            if syms:
                s.append("\n**Engine/game symbols called (address → real name from symbol map):**")
                s += [f"- `{a}` → `{n}`" for a, n in syms]
            if tables:
                s.append("\n**Known ROM data tables referenced (address → decoded table):**")
                s += [f"- `{a}` → `{lbl}`" for a, lbl in tables]
            if borgs:
                s.append("\n**Borg character ids referenced:**")
                s += [f"- `{p}` → {desc}" for p, desc in borgs]
        if inf_syms or inf_offs:
            s.append(
                "\n## INFERRED REFERENCES (hypotheses from prior analysis — NOT authoritative, may be wrong)"
                "\nThese are cross-sweep guesses, not verified facts. Use them to guide investigation, "
                "but if you rely on one, tag that claim `(previously inferred)` in your Rationale and do "
                "NOT state it as established."
            )
            if inf_offs:
                s.append("\n**Borg struct fields — inferred meaning (confidence):**")
                s += [f"- `{o}` → {mng} _(conf {c:.2f})_" for o, mng, c in inf_offs]
            if inf_syms:
                s.append("\n**Called helpers — inferred role (confidence):**")
                s += [f"- `{a}` → {role} _(conf {c:.2f})_" for a, role, c in inf_syms]
        return "\n".join(s)


@functools.lru_cache(maxsize=1)
def get_gf_context(research_root=r"D:\GotYaForce\research"):
    return GFContext(research_root)


_TIER_INTRO = {
    "borg": (
        "You are reverse-engineering the GameCube game *Gotcha Force* (boot.dol), a real-time arena "
        "combat game. THIS function operates on a Borg (the collectible fighter characters) and its "
        "per-borg instance struct: state machine, attacks / hit detection, HP and the Gotcha meter, "
        "movement / flight physics, heading/facing, invincibility, status flags. Name it for its role "
        "in the Borg subsystem. This is NOT malware (no crypto/networking/registry)."
    ),
    "engine": (
        "You are reverse-engineering the GameCube game *Gotcha Force* (boot.dol), a PowerPC (Gekko) "
        "title on the HAL/HSD (Sysdolphin) engine. THIS function is engine/SDK-level: the HSD "
        "scene-graph and animation pipeline (JObj/AObj/FObj/DObj), GX graphics, OS services "
        "(cache/FPU/threads/DVD/alloc), PS/PSMTX/PSVEC/PSQUAT matrix-vector math, or the gnt4- "
        "boot/runtime layer. Name it for its ENGINE role — do NOT assume it is Borg/combat-specific "
        "unless the code clearly shows it. This is NOT malware, and it is NOT NVIDIA/ARM/x86 — it is "
        "GameCube PowerPC."
    ),
    "neutral": (
        "You are reverse-engineering the GameCube game *Gotcha Force* (boot.dol), a PowerPC (Gekko) "
        "title. This function's subsystem is NOT yet determined from the evidence. Name it for exactly "
        "what the decompiled code does — do NOT assume it is Borg/combat-related, and do not invent a "
        "subsystem. This is NOT malware (no crypto/networking/registry)."
    ),
}

_TIER_EXAMPLES = {
    "borg": (
        "EXAMPLES (Borg domain): dispatchBorgActionState (reads borg[0x544] and switches); "
        "decrementInvincibilityTimer (counts down borg[0x720]); computeBorgFacingAngle "
        "(writes borg[0x5aa/0x72]); requestBorgAnimation (calls the HSD anim helper)."
    ),
    "engine": (
        "EXAMPLES (engine/math domain): computeCubicSplineTangents (NOT computeBorgPathTangents — "
        "a generic spline solver is not Borg-specific); initializeCpuFprAndCache; multiplyMatrixVec3; "
        "advanceAObjAnimFrame; allocFromHeapArena."
    ),
    "neutral": (
        "EXAMPLES (name for what the code literally does): incrementCounterAndDispatch; "
        "copyStructFields; findEntryByIndex; clampFloatToRange. Add a subsystem word only if grounded."
    ),
}

_GROUNDING_RULES = """GROUNDING RULES (read carefully — these override the desire to sound specific):
- Base the name and analysis ONLY on this function's decompiled code, the RESOLVED REFERENCES, and any decode notes shown above.
- If a struct field, constant, or called function's purpose is NOT given by those, describe what the code DOES with it (e.g. "increments field_0x540", "adds the load base to each pointer") instead of inventing a meaning. Prefer "purpose unclear" over a plausible guess.
- Do NOT claim a caller, struct offset, hardware platform, or save/file format that is not present in the code or the shown context. A caller shown as context tells you WHO calls this, not that this function's body does what the caller does.
- Put a specific subsystem word (Borg, Attack, Camera, Menu, Save...) in the NAME only if THIS function's own code or the RESOLVED REFERENCES ground it. A generic math/util/engine routine must get a generic name even if a Borg function happens to call it.
- The INFERRED REFERENCES block (if present) contains HYPOTHESES, not facts. You MAY use them to guide investigation, but they do NOT count as grounding: if a name or claim relies on an inferred entry, keep the name conservative and tag that claim `(previously inferred)` in your Rationale. NEVER present an inferred meaning as established, and never let it upgrade a guess into a confident subsystem word.
- If a decode note, table, or sibling documents a DIFFERENT address/offset than the one in THIS code, you may cite the structural similarity but must NOT claim they are the same entity."""


def build_naming_prompt(function_name, function_decompile_result, contextual_info="", gf_resolved="", tier=None):
    """The Gotcha Force-aware, KB-grounded rename prompt used by the bulk-rename workflow.
    Framing is evidence-tiered (borg/engine/neutral) so non-Borg code isn't force-fit to Borg,
    and the grounding rules suppress confident hallucination on ungrounded internals.
    Kept here (not inline in the GUI) so the exact prompt is unit-testable and reused."""
    if tier not in _TIER_INTRO:
        tier = classify_tier(function_decompile_result, gf_resolved)
    kb_block = f"\n{gf_resolved}\n" if gf_resolved else ""
    return f"""{_TIER_INTRO[tier]}

Analyze the function '{function_name}' and provide a highly descriptive rename suggestion.

## TARGET FUNCTION: {function_name}
```c
{function_decompile_result}
```
{contextual_info}
{kb_block}
{_GROUNDING_RULES}

You MUST follow this EXACT format in your response:

**Function Analysis:**
[What the function actually does, grounded in the code + resolved references. Identify the subsystem ONLY if the evidence supports it; otherwise describe the operation. Map any resolved struct offsets / symbols to their documented meanings. Examine parameters, return values, called functions, and code patterns.]

**Behavior Summary:**
[A precise 1-4 sentence summary of the function's primary behavior and data flow.]

**Suggested Name:** [descriptiveSpecificFunctionName]
**Rationale:** [Why this name captures the function's specific purpose; cite the offsets / resolved symbols / notes you used. If you avoided a subsystem word for lack of evidence, say so.]

NAMING REQUIREMENTS:
- Be HIGHLY SPECIFIC to what the code actually does (e.g. "updateBorgHeading" not "updateAngle"; "solveTridiagonalSystem" not "processArray").
- Use precise action verbs: update, apply, dispatch, advance, spawn, resolve, compute, set, clear, request, select, decrement, accumulate, render, solve, multiply, copy, etc.
- camelCase, 2-5 words. Avoid generic terms: process, handle, manage, data, function, method, routine.
- {_TIER_EXAMPLES[tier]}

CRITICAL: Include all four sections with the exact headers. Follow the GROUNDING RULES — a correct, slightly-generic name beats a specific but invented one."""
