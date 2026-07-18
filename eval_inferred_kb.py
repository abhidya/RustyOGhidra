#!/usr/bin/env python3
"""
eval_inferred_kb.py — the gate for the inferred-knowledge sidecar.

Question it answers: does injecting the INFERRED REFERENCES block actually IMPROVE naming,
measured against ground truth — or does it just add plausible-looking noise?

Method (no live Ghidra needed; uses on-disk decompiles + the configured LLM endpoint):
  1. Ground truth = the GG4E-CSM symbol map's real names (non zz_/FUN_/__).
  2. Keep only functions whose decompile references a callee/offset the sidecar has an entry
     for — i.e. where WITH vs WITHOUT actually differ. Everything else is uninformative.
  3. For each, blank the function's own name, build the naming prompt twice (sidecar ON vs
     OFF), call the LLM, extract Suggested Name, score token-overlap vs the canonical name.
  4. Report mean score ON vs OFF, and how often ON changed the answer better/worse/same.

Ship the sidecar (build_inferred_kb.py --write) only if ON beats OFF here. If it doesn't
help on functions where we KNOW the answer, it doesn't help.

Usage:
  python eval_inferred_kb.py                 # default sample of 24 informative functions
  python eval_inferred_kb.py --n 40
  python eval_inferred_kb.py --list          # just list informative candidates, no LLM
"""
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RESEARCH = r"D:\GotYaForce\research"
ORGANIZED = os.path.join(RESEARCH, "decomp", "organized")
MAP_GLOB = os.path.join(RESEARCH, "symbols", "*.map")
sys.path.insert(0, HERE)


def load_env(path=os.path.join(HERE, ".env")):
    env = {}
    if os.path.exists(path):
        for ln in open(path, encoding="utf-8"):
            ln = ln.strip()
            if ln and not ln.startswith("#") and "=" in ln:
                k, v = ln.split("=", 1)
                env[k.strip()] = v.strip()
    return env


def load_canonical_names():
    """addr(int) -> canonical name, for real (non-placeholder) map symbols only."""
    out = {}
    for mp in glob.glob(MAP_GLOB):
        for ln in open(mp, encoding="utf-8", errors="ignore"):
            parts = ln.split()
            if len(parts) >= 5 and re.match(r"^80[0-9a-fA-F]{6}$", parts[0]):
                name = parts[4]
                if not name.startswith(("zz_", "FUN_", "sub_", "__", "lbl_", "loc_")):
                    out[int(parts[0], 16)] = name
    return out


def find_decompile(addr_hex):
    """Locate the on-disk decompile for an address (organized/**/<addr>_*.c)."""
    hits = glob.glob(os.path.join(ORGANIZED, "**", f"{addr_hex}_*.c"), recursive=True)
    if not hits:
        return None
    try:
        return open(hits[0], encoding="utf-8", errors="ignore").read()
    except Exception:
        return None


def tokens(name):
    """camelCase + snake_case -> lowercase token set (for overlap scoring)."""
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return set(t for t in re.split(r"[^a-zA-Z0-9]+", s.lower()) if len(t) > 1)


STOP = {"the", "and", "for", "with", "borg", "func", "function", "get", "set", "sub"}


def score(suggested, canonical):
    """Jaccard overlap of meaningful tokens (stopwords removed). 0..1."""
    a, b = tokens(suggested) - STOP, tokens(canonical) - STOP
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def extract_name(text):
    for ln in (text or "").splitlines():
        if "Suggested Name:" in ln:
            m = re.search(r"\b([a-z][a-zA-Z0-9_]{3,})\b", ln.split("Suggested Name:", 1)[1])
            if m:
                return m.group(1)
    return ""


def call_llm(env, prompt):
    import requests

    url = env.get("CUSTOM_API_URL", "http://127.0.0.1:5001/v1/chat/completions")
    payload = {
        "model": env.get("CUSTOM_API_MODEL", "local"),
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
        "max_tokens": 2048,
    }
    headers = {"Authorization": f"Bearer {env.get('CUSTOM_API_KEY', 'x')}"}
    r = requests.post(url, json=payload, headers=headers, timeout=300)
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]


def eval_offsets_vs_proven():
    """LLM-free correctness check for the OFFSET half: for every offset that behavior-notes.md
    documents (authoritative ground truth), does the deterministic tagger — run over the same
    summaries — infer an AGREEING meaning? This is the real gate for offset inference, because
    the canonical symbol map (engine-side) doesn't cover borg struct fields.

    Agreement = the controlled tag derived from the authoritative meaning text equals the tag
    the producer inferred for that offset."""
    import src.gf_context as gc
    import build_inferred_kb as b
    import glob as _glob

    gc.get_gf_context.cache_clear()
    gf = gc.get_gf_context()
    files = sorted(_glob.glob(os.path.join(b.SESS_DIR, "session_*", "session.json")),
                   key=os.path.getmtime, reverse=True)[: b.MAX_SESSIONS_DEFAULT]
    _syms, offs = b.build(files, set())  # all inferred offsets incl. below-floor

    def tag_of_text(t):
        got = b._tags_in(t)
        for tag, _phrase, _pats in b.VOCAB:  # VOCAB order = preference
            if tag in got:
                return tag
        return None

    agree = disagree = nocover = 0
    rows = []
    for okey, meaning in gf.offsets.items():          # authoritative (behavior-notes)
        truth_tag = tag_of_text(meaning)
        if truth_tag is None:
            continue                                   # meaning doesn't map to our vocab
        inf = offs.get(f"borg:{okey}")
        if not inf:
            nocover += 1
            continue
        ok = inf["top_tag"] == truth_tag
        agree += ok
        disagree += (not ok)
        rows.append((okey, truth_tag, inf["top_tag"], ok, inf["confidence"], inf["votes"]))

    print("OFFSET INFERENCE vs behavior-notes.md (authoritative):")
    for okey, tt, it, ok, c, v in sorted(rows, key=lambda r: -r[4]):
        print(f"  {okey:8} truth={tt:12} inferred={it:12} {'OK ' if ok else 'XX '} conf={c:.2f} votes={v}")
    total = agree + disagree
    if total:
        print(f"\nAgreement on covered offsets: {agree}/{total} = {agree/total:.0%}  (+{nocover} proven offsets the tagger had no evidence for)")
        print("Gate: only enable offset injection if agreement is clearly high (>~70%);")
        print("otherwise ship SYMBOLS-ONLY (offset inference is too noisy on this corpus).")
    else:
        print("No overlap between proven offsets and inferred offsets — cannot gate; ship symbols-only.")
    return 0


def main(argv):
    n = int(argv[argv.index("--n") + 1]) if "--n" in argv else 24
    list_only = "--list" in argv
    if "--offsets" in argv:
        return eval_offsets_vs_proven()

    import src.gf_context as gc

    gc.get_gf_context.cache_clear()
    gf = gc.get_gf_context()
    if not gf.inferred_symbols and not gf.inferred_offsets:
        print("Sidecar is empty/absent — run build_inferred_kb.py (no --write needed) first,")
        print("or the eval has nothing to test. Exiting.")
        return 1

    canon = load_canonical_names()
    inf_addrs = set(gf.inferred_symbols)
    inf_offkeys = set(gf.inferred_offsets)

    # Informative candidates: canonical-named, decompile on disk, and the code references a
    # sidecar symbol OR (borg code with) a sidecar offset — so ON vs OFF actually differ.
    cands = []
    for addr, name in canon.items():
        hexa = f"{addr:08x}"
        code = find_decompile(hexa)
        if not code:
            continue
        resolved = gf.resolve_for_code(code, self_addr=hexa)
        if "INFERRED REFERENCES" in resolved:
            cands.append((addr, name, code))
        if len(cands) >= n * 3:
            break

    print(f"Canonical names: {len(canon)} | informative candidates found: {len(cands)}")
    if list_only or not cands:
        for addr, name, _ in cands[:n]:
            print(f"  {addr:08x}  {name}")
        return 0

    env = load_env()
    sample = cands[:n]
    on_scores, off_scores, better, worse, same = [], [], 0, 0, 0

    for i, (addr, name, code) in enumerate(sample, 1):
        hexa = f"{addr:08x}"
        blanked = code.replace(name, f"FUN_{hexa}")
        with_inf = gf.resolve_for_code(blanked, self_addr=hexa)
        # OFF = strip the inferred block, keep authoritative resolved refs
        without_inf = with_inf.split("\n## INFERRED REFERENCES")[0]
        p_on = gc.build_naming_prompt(f"FUN_{hexa}", blanked, "", with_inf)
        p_off = gc.build_naming_prompt(f"FUN_{hexa}", blanked, "", without_inf)
        try:
            s_on = score(extract_name(call_llm(env, p_on)), name)
            s_off = score(extract_name(call_llm(env, p_off)), name)
        except Exception as e:
            print(f"  [{i}/{len(sample)}] {name}: LLM error {e}")
            continue
        on_scores.append(s_on)
        off_scores.append(s_off)
        if s_on > s_off + 1e-6:
            better += 1
        elif s_on < s_off - 1e-6:
            worse += 1
        else:
            same += 1
        print(f"  [{i}/{len(sample)}] {name:34} OFF={s_off:.2f} ON={s_on:.2f} {'↑' if s_on>s_off else ('↓' if s_on<s_off else '=')}")

    if on_scores:
        mon = sum(on_scores) / len(on_scores)
        moff = sum(off_scores) / len(off_scores)
        print("\n" + "=" * 60)
        print(f"Evaluated: {len(on_scores)} functions")
        print(f"Mean overlap  OFF={moff:.3f}   ON={mon:.3f}   delta={mon - moff:+.3f}")
        print(f"Inferred block helped: {better}  hurt: {worse}  no-change: {same}")
        verdict = "SHIP" if (mon > moff and worse <= better) else "DO NOT SHIP"
        print(f"Verdict: {verdict}  — inferred injection {'improves' if mon > moff else 'does not improve'} naming vs ground truth.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
