#!/usr/bin/env python3
"""
build_inferred_kb.py — deterministic producer for the inferred-knowledge sidecar.

Reads one or more saved OGhidra session.json files (each = one naming sweep) and
distills recurring, *cross-sweep-agreed* hypotheses about:
  - callee helper roles      (zz_XXXXXXX_ / 0x80XXXXXX -> role tag)
  - Borg struct-field meaning (+0xNNN     -> meaning tag)

into research/decomp/data/inferred-knowledge.json, which gf_context.py surfaces (below a
confidence floor, struct-scoped, clearly labelled NON-authoritative) into naming prompts.

Design guards (see the fix-3 review):
  * NO LLM. Deterministic keyword tagging against a controlled vocabulary — auditable,
    adds zero new hallucination surface, and can't be gamed by prose.
  * ECHO SUPPRESSION. OGhidra sessions are CUMULATIVE snapshots (each save is a superset of
    the last), so "distinct sessions" is degenerate — the same summary re-saved N times is
    not N independent votes. We instead dedupe every observation by (address, summary-hash):
    a re-saved identical summary collapses to ONE vote; only a genuinely re-analysed function
    (same address, DIFFERENT summary) counts again. Confidence then needs many distinct
    functions AGREEING (high dominance + clear margin over the runner-up interpretation), so
    one sweep's internal echo can't manufacture consensus.
  * STRUCT SCOPING. Offsets are emitted as `borg:0xNNN`; only summaries whose function is
    borg-scoped (BorgInstance-typed / touches a known borg field) contribute borg offsets.
  * EVIDENCE DIVERSITY. Ambiguous offsets (many competing tags) are penalised.
  * PROVEN NEGATIVES. Optional research/decomp/data/proven-negatives.json marks refuted
    hypotheses `negated` so they can never be resurrected.

Usage:
  python build_inferred_kb.py                      # newest N sessions under analysis_sessions/
  python build_inferred_kb.py <session.json> ...   # explicit files
  python build_inferred_kb.py --dry-run            # print, don't write
"""
import glob
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
RESEARCH = r"D:\GotYaForce\research"
SIDE_OUT = os.path.join(RESEARCH, "decomp", "data", "inferred-knowledge.json")
NEG_IN = os.path.join(RESEARCH, "decomp", "data", "proven-negatives.json")
SESS_DIR = os.path.join(HERE, "analysis_sessions")

CONF_FLOOR = 0.60           # matches gf_context._INFERRED_MIN_CONF
MAX_SESSIONS_DEFAULT = 8    # newest sweeps to fold in when no files given
WINDOW = 55                 # chars each side of a mention to tag (tight, to catch the CLAUSE
                            # about this offset, not ambient vocabulary two sentences away)
MIN_VOTES = 4               # distinct (addr,summary) observations required to be a candidate
MIN_AGREEMENT = 0.55        # top tag must dominate this fraction of observations
MIN_MARGIN = 0.20           # top tag must beat the runner-up by this fraction

# Borg-instance field offsets that mark a summary's function as borg-scoped. Mirrors
# gf_context._BORG_FIELD_KEYS so scoping is consistent producer<->consumer.
BORG_FIELD_KEYS = {"0x544", "0x720", "0x5e0", "0x272", "0x591", "0x5aa", "0x5ac", "0x5ae", "0x1dcc"}

# Controlled role vocabulary: tag -> (human phrase, [trigger regexes]). Order matters only
# for tie-breaking (earlier = preferred). Keep triggers specific to avoid cross-talk.
VOCAB = [
    ("timer",     "countdown / duration timer",           [r"countdown", r"duration", r"\btimer\b", r"decrement\w* .{0,20}(each frame|per frame|until (it|zero))", r"frames? remaining", r"ticks? down"]),
    ("counter",   "counter / accumulator",                [r"\bcounter\b", r"accumulat", r"increment\w* .{0,20}(each|per) frame", r"tally"]),
    ("flag",      "status bit-flag(s)",                   [r"bitmask", r"boolean flag", r"clear\w* .{0,20}\bbits?\b", r"set\w* .{0,20}\bbits?\b", r"\bbit ?flag", r"lower .{0,6}bits", r"& 0x[0-9a-f]*f[0-9a-f]"]),
    ("state",     "state-machine / phase field",          [r"state machine", r"state transition", r"\bphase\b", r"substate", r"action state", r"\bstate id"]),
    ("position",  "position / coordinate",                [r"position", r"coordinate", r"\bpos_[xyz]\b", r"world [xyz]\b", r"translation"]),
    ("velocity",  "velocity / movement vector",           [r"velocit", r"movement vector", r"momentum", r"\bdash\b", r"speed vector"]),
    ("angle",     "facing / heading angle",               [r"\bangle\b", r"heading", r"facing", r"\byaw\b", r"orientation", r"rotation"]),
    ("health",    "HP / health / damage",                 [r"\bhp\b", r"health", r"hit ?points", r"damage taken"]),
    ("meter",     "meter / gauge / charge",               [r"\bmeter\b", r"\bgauge\b", r"gotcha", r"\bcharge\b"]),
    ("animation", "animation / pose",                     [r"animation", r"\banim\b", r"\bpose\b", r"sprite"]),
    ("collision", "collision / hitbox test",              [r"collision", r"hitbox", r"overlap", r"proximity", r"intersect"]),
    ("physics",   "physics integration",                  [r"physics", r"gravity", r"integrat", r"\bscalar\b"]),
    ("input",     "input / pad state",                    [r"\binput\b", r"\bpad\b", r"button", r"controller"]),
    ("spawn",     "spawn / instantiate",                  [r"\bspawn", r"instantiat", r"respawn", r"create .{0,10}instance"]),
    ("reset",     "reset / initialize",                   [r"\breset\b", r"initializ", r"\binit\b", r"default value", r"clear state"]),
    ("dispatch",  "dispatch / indirect handler",          [r"dispatch", r"function pointer", r"indirect call", r"jump table", r"\bhandler\b"]),
]
_COMPILED = [(tag, phrase, [re.compile(p, re.I) for p in pats]) for tag, phrase, pats in VOCAB]

_ZZ = re.compile(r"\bzz_([0-9a-fA-F]{7})_")
_ADDR8 = re.compile(r"\b(80[0-9a-fA-F]{6})\b")
_OFF = re.compile(r"(?:\+\s*|field_|\[)?0x([0-9a-fA-F]{2,4})\b")


# Field NAMES the struct-typing injected into decompiles/summaries. Left in, they make the
# offset tagger measure ambient vocabulary (every function touching `status_flags` looked
# like a flag). Stripped from a window before tagging so only genuine role language counts.
_AMBIENT = re.compile(r"status_flags|field_0x[0-9a-fA-F]+|param_1|BorgInstance", re.I)


def _tags_in(window):
    """Controlled-vocab tags present in a text window (a set, so one window = one vote/tag)."""
    window = _AMBIENT.sub(" ", window)
    found = set()
    for tag, _phrase, pats in _COMPILED:
        if any(p.search(window) for p in pats):
            found.add(tag)
    return found


def _windows(text, needle_regex):
    """Yield the ±WINDOW char windows around each match of needle_regex in text."""
    for m in needle_regex.finditer(text):
        a = max(0, m.start() - WINDOW)
        b = min(len(text), m.end() + WINDOW)
        yield text[a:b]


def _is_borg_summary(text):
    if "borginstance" in text.lower() or "borg" in text.lower():
        return True
    offs = set("0x" + m.group(1).lower() for m in _OFF.finditer(text))
    return bool(offs & BORG_FIELD_KEYS)


def _phrase_for(tag):
    for t, phrase, _ in VOCAB:
        if t == tag:
            return phrase
    return tag


def _confidence(votes, agreement, margin):
    """Echo-suppressed confidence over DEDUPED observations (votes = distinct (addr,summary)
    pairs). Ships only when many distinct functions converge on ONE interpretation that
    clearly beats the runner-up. Sparse, contested, or ambiguous evidence stays below the
    floor no matter how many times it was re-saved."""
    if votes < MIN_VOTES or agreement < MIN_AGREEMENT or margin < MIN_MARGIN:
        # Record the evidence but keep it un-shippable until it firms up.
        return round(min(0.50, 0.20 + 0.10 * agreement + 0.05 * min(votes, 4)), 3)
    # Volume gives a mild boost (log-ish, capped) so a 100-function field isn't equal to a
    # 4-function one, but dominance+margin dominate — volume alone can't buy confidence.
    volume = min(0.15, 0.03 * (votes ** 0.5))
    raw = 0.45 + 0.25 * agreement + 0.20 * margin + volume
    return round(max(0.0, min(0.92, raw)), 3)


def _load_negatives():
    """Optional refutations: [{"kind":"offset|symbol","key":"borg:0x366"|"8006a474",
    "reason":"..."}]. Matching entries are emitted with negated=true so they're loaded but
    never injected — negative knowledge is knowledge."""
    if not os.path.exists(NEG_IN):
        return set()
    try:
        rows = json.load(open(NEG_IN, encoding="utf-8"))
        return set((r.get("kind"), str(r.get("key", "")).lower()) for r in rows)
    except Exception:
        return set()


def _load_sessions(paths):
    sessions = []
    for p in paths:
        try:
            d = json.load(open(p, encoding="utf-8"))
        except Exception as e:
            print(f"  skip {p}: {e}", file=sys.stderr)
            continue
        sid = (d.get("metadata") or {}).get("session_id") or os.path.basename(os.path.dirname(p)) or p
        fns = d.get("analyzed_functions") or {}
        sessions.append((sid, fns))
    return sessions


def build(paths, negatives):
    # Dedupe observations across cumulative snapshots: obs id = (address, summary-hash).
    # acc[key][tag] = set(obs)   ;   seen[key] = set(obs mentioning key at all)
    sym_acc = defaultdict(lambda: defaultdict(set))
    off_acc = defaultdict(lambda: defaultdict(set))
    sym_seen = defaultdict(set)
    off_seen = defaultdict(set)
    sym_sessions = defaultdict(set)   # provenance only (not used for confidence)
    off_sessions = defaultdict(set)
    seen_obs = set()

    for sid, fns in _load_sessions(paths):
        for addr, fd in fns.items():
            summary = fd.get("behavior_summary") or fd.get("summary") or ""
            if not isinstance(summary, str) or not summary.strip():
                continue
            obs = (addr, hash(summary))
            if obs in seen_obs:
                continue  # identical summary re-saved in a later snapshot -> one vote, not N
            seen_obs.add(obs)

            for m in set(_ZZ.findall(summary)):
                key = f"{0x80000000 | int(m, 16):08x}"
                sym_seen[key].add(obs)
                sym_sessions[key].add(sid)
                for w in _windows(summary, re.compile(r"\bzz_" + re.escape(m) + r"_")):
                    for tag in _tags_in(w):
                        sym_acc[key][tag].add(obs)

            if not _is_borg_summary(summary):
                continue
            for m in set(mm.group(1).lower() for mm in _OFF.finditer(summary)):
                okey = "0x" + m
                if okey in BORG_FIELD_KEYS:
                    continue  # already authoritative in behavior-notes
                off_seen[okey].add(obs)
                off_sessions[okey].add(sid)
                for w in _windows(summary, re.compile(r"(?:\+\s*|field_|\[)?0x" + re.escape(m) + r"\b", re.I)):
                    for tag in _tags_in(w):
                        off_acc[okey][tag].add(obs)

    symbols = _finalize(sym_acc, sym_seen, sym_sessions, ("symbol", None), negatives, scope=None)
    offsets = _finalize(off_acc, off_seen, off_sessions, ("offset", "borg:"), negatives, scope="borg")
    return symbols, offsets


def _tag_idf(acc):
    """Inverse document frequency per tag across ALL keys' observations. A tag like 'flag'
    that matches almost every window carries little information and is down-weighted; a rare,
    specific tag like 'meter' that concentrates on a few fields is boosted. This is what stops
    ambient vocabulary ('flag', 'bit', 'state') from winning every offset by ubiquity."""
    import math

    df = defaultdict(set)          # tag -> set of all obs containing it anywhere
    allobs = set()
    for tagmap in acc.values():
        for tag, obs in tagmap.items():
            df[tag] |= obs
            allobs |= obs
    n = max(1, len(allobs))
    return {tag: math.log(1 + n / max(1, len(o))) for tag, o in df.items()}


def _finalize(acc, seen, sessions, negkind, negatives, scope):
    out = {}
    kind, keyprefix = negkind
    idf = _tag_idf(acc)
    for key, tagmap in acc.items():
        if not tagmap:
            continue
        # Rank by IDF-weighted support so a specific tag beats an ambient one even with fewer
        # raw hits; margin/agreement below still use raw obs counts (interpretable as fractions).
        ranked = sorted(tagmap.items(), key=lambda kv: len(kv[1]) * idf.get(kv[0], 1.0), reverse=True)
        top_tag, top_obs = ranked[0]
        runner = len(ranked[1][1]) if len(ranked) > 1 else 0
        votes = len(seen.get(key, set())) or 1
        agreement = len(top_obs) / votes                     # dominance of winning tag
        margin = (len(top_obs) - runner) / votes             # clearance over runner-up
        diversity = len(tagmap)
        conf = _confidence(votes, agreement, margin)

        emit_key = (keyprefix + key) if keyprefix else key
        neg = (kind, emit_key.lower()) in negatives or (kind, key.lower()) in negatives
        entry = {
            "meaning" if kind == "offset" else "role": _phrase_for(top_tag),
            "top_tag": top_tag,
            "confidence": conf,
            "votes": votes,
            "agreement": round(agreement, 2),
            "margin": round(margin, 2),
            "diversity": diversity,
            "sessions": sorted(sessions.get(key, set())),
            "negated": neg,
            "sources": sorted(a for a, _h in top_obs)[:12],
        }
        if scope:
            entry["scope"] = scope
        out[emit_key] = entry
    return out


def main(argv):
    # Preview by default; persisting requires an explicit --write so a noisy sidecar can't
    # ship without a look (ideally a run of eval_inferred_kb.py) first.
    do_write = "--write" in argv
    files = [a for a in argv if a.endswith(".json") and os.path.exists(a)]
    if not files:
        cands = sorted(glob.glob(os.path.join(SESS_DIR, "session_*", "session.json")),
                       key=os.path.getmtime, reverse=True)
        files = cands[:MAX_SESSIONS_DEFAULT]
    if not files:
        print("No session files found.", file=sys.stderr)
        return 1
    print(f"Folding {len(files)} session(s):")
    for f in files:
        print("  -", os.path.relpath(f, HERE))

    negatives = _load_negatives()
    symbols, offsets = build(files, negatives)

    shipped_s = {k: v for k, v in symbols.items() if v["confidence"] >= CONF_FLOOR and not v["negated"]}
    shipped_o = {k: v for k, v in offsets.items() if v["confidence"] >= CONF_FLOOR and not v["negated"]}
    print(f"\nSymbols: {len(symbols)} inferred, {len(shipped_s)} above floor {CONF_FLOOR}")
    print(f"Offsets: {len(offsets)} inferred, {len(shipped_o)} above floor {CONF_FLOOR}")
    for k, v in sorted(shipped_o.items(), key=lambda kv: -kv[1]["confidence"])[:20]:
        print(f"  {k:14} {v['confidence']:.2f}  {v['meaning']:34}  (votes {v['votes']}, agree {v['agreement']}, margin {v['margin']}, div {v['diversity']})")

    # OFFSET INFERENCE IS GATED OFF by default: eval_inferred_kb.py --offsets scores the
    # deterministic offset tagger at ~12% vs behavior-notes.md ground truth (prose summaries
    # don't pin struct-field meaning reliably). Symbols (callee roles) are far more consistent
    # and ship. Re-enable offsets with --with-offsets only once extraction clears the eval.
    ship_offsets = "--with-offsets" in argv
    if not ship_offsets:
        print("\n[offsets withheld — failed the correctness gate; symbols only. Use --with-offsets to override.]")
    payload = {
        "version": 1,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "source_sessions": [os.path.basename(os.path.dirname(f)) for f in files],
        "confidence_floor": CONF_FLOOR,
        "symbols": symbols,                            # full set (incl. below-floor) for history
        "struct_offsets": offsets if ship_offsets else {},
    }
    if not do_write:
        print("\nPreview only (pass --write to persist). Recommended: run eval_inferred_kb.py first.")
        return 0
    os.makedirs(os.path.dirname(SIDE_OUT), exist_ok=True)
    json.dump(payload, open(SIDE_OUT, "w", encoding="utf-8"), indent=2)
    inject_o = len(shipped_o) if ship_offsets else 0
    print(f"\nWrote {SIDE_OUT}  ({len(shipped_s)} symbols + {inject_o} offsets will inject)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
