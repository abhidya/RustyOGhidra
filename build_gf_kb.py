"""
Build the SEMANTIC half of the Gotcha Force KB -> data/vector_db/ (CAG load path).

Corpus (research-only, NO prior LLM renames):
  - research/decomp/**/*.md,*.txt   decode / behavior notes
  - research/symbols/*orgs*.csv       borg roster (one doc per borg: name/family/stats)
  - research/decomp/index/class-map.json, cpu-ai-evidence.json  structured evidence

Writes documents.json (text/type/name schema CAG expects) + vectors.npy (nomic @1234).
The precise half (symbol/offset/borg *exact* lookups) is handled at query time by
src/gf_context.py; this file is the fuzzy semantic notes retrieved via CAG.
"""
import csv, json, os, re, glob, time
import numpy as np, requests
requests.packages.urllib3.disable_warnings()

HERE = os.path.dirname(os.path.abspath(__file__))
RROOT = r"D:\GotYaForce\research"
OUT = os.path.join(HERE, "data", "vector_db")
os.makedirs(OUT, exist_ok=True)
EMBED_URL = "http://10.0.0.205:1234/v1/embeddings"
EMBED_MODEL = "text-embedding-nomic-embed-text-v1.5"
MAX_CHARS, BATCH = 2400, 64


def chunk(text, source):
    out, cur, head = [], [], os.path.basename(source)
    for ln in text.split("\n"):
        if re.match(r"^#{1,4}\s", ln):
            b = "\n".join(cur).strip()
            if b: out.append((head, b))
            cur, head = [], ln.lstrip("# ").strip()
        cur.append(ln)
        if sum(len(x) for x in cur) > MAX_CHARS:
            b = "\n".join(cur).strip()
            if b: out.append((head, b))
            cur = []
    b = "\n".join(cur).strip()
    if b: out.append((head, b))
    return out


def load_docs():
    docs = []
    # notes — ALL research subdirs (not just decomp) + docs-site, excluding the OGhidra tool
    # itself and this project's own build artifacts.
    REPO = os.path.dirname(RROOT)  # D:\GotYaForce
    note_globs = [
        os.path.join(RROOT, "**", "*.md"), os.path.join(RROOT, "**", "*.txt"),
        os.path.join(REPO, "docs-site", "**", "*.md"),
    ]
    EXCLUDE = ("research/tools/", "research\\tools\\", "/node_modules/", "\\node_modules\\")
    files = []
    for g in note_globs:
        files += glob.glob(g, recursive=True)
    for fp in sorted(set(files)):
        rel = os.path.relpath(fp, REPO).replace("\\", "/")
        if any(x.replace("\\", "/") in ("/" + rel) or x in fp for x in EXCLUDE):
            continue
        try: txt = open(fp, encoding="utf-8", errors="ignore").read()
        except Exception: continue
        if not txt.strip():
            continue
        for head, body in chunk(txt, fp):
            docs.append({"name": head, "type": "decode_note", "source": rel,
                         "text": f"# [{rel}] {head}\n{body}"})
    # borg roster
    for csvf in glob.glob(os.path.join(RROOT, "symbols", "*orgs*.csv")):
        try:
            for row in csv.DictReader(open(csvf, encoding="utf-8", errors="ignore")):
                fn = (row.get("filename") or "").strip()
                nm = (row.get("borgname") or "").strip()
                if fn and nm:
                    body = ", ".join(f"{k}={v}" for k, v in row.items() if v)
                    docs.append({"name": f"{fn} {nm}", "type": "borg", "source": os.path.basename(csvf),
                                 "text": f"# Borg {fn} — {nm}\n{body}"})
        except Exception: pass
    # decoded ROM data tables (each bound to a source address) + curated combat data
    data_jsons = glob.glob(os.path.join(RROOT, "decomp", "data", "*.json"))
    for cand in ("common-battle-data.json", "stage-code-evidence.json", "adventure-flow-ai.json"):
        p = os.path.join(RROOT, "asset-inventory", cand)
        if os.path.exists(p):
            data_jsons.append(p)
    for jf in sorted(set(data_jsons)):
        try:
            obj = json.load(open(jf, encoding="utf-8"))
        except Exception:
            continue
        base = os.path.basename(jf)
        txt = json.dumps(obj, indent=1)[:40000]  # cap giant tables so they don't dominate
        for i in range(0, len(txt), 1800):
            docs.append({"name": base, "type": "data_table",
                         "source": os.path.relpath(jf, RROOT).replace("\\", "/"),
                         "text": f"# Data table {base} (decoded ROM, bound to source address)\n{txt[i:i+1800]}"})
    # structured evidence json (prose-bearing)
    for jf, key in [("class-map.json", "classes"), ("cpu-ai-evidence.json", None)]:
        p = os.path.join(RROOT, "decomp", "index", jf)
        if not os.path.exists(p): continue
        try: d = json.load(open(p, encoding="utf-8"))
        except Exception: continue
        items = d.get(key) if (key and isinstance(d, dict)) else (d if isinstance(d, list) else [d])
        if isinstance(items, dict): items = list(items.values())
        for it in (items or [])[:400]:
            t = json.dumps(it, indent=1)[:MAX_CHARS] if not isinstance(it, str) else it[:MAX_CHARS]
            nm = (it.get("name") or it.get("class") or it.get("address") or "item") if isinstance(it, dict) else "item"
            docs.append({"name": str(nm), "type": jf.replace(".json", ""), "source": jf, "text": t})
    return docs


def embed(texts):
    r = requests.post(EMBED_URL, json={"model": EMBED_MODEL, "input": texts}, timeout=120, verify=False)
    r.raise_for_status(); return [d["embedding"] for d in r.json()["data"]]


def main():
    t0 = time.time(); docs = load_docs()
    from collections import Counter
    print("docs:", len(docs), dict(Counter(d["type"] for d in docs)), flush=True)
    vecs = []
    for i in range(0, len(docs), BATCH):
        vecs.extend(embed([d["text"][:6000] for d in docs[i:i+BATCH]]))
        if i % (BATCH * 8) == 0: print(f"  {min(i+BATCH,len(docs))}/{len(docs)} ({time.time()-t0:.0f}s)", flush=True)
    np.save(os.path.join(OUT, "vectors.npy"), np.asarray(vecs, dtype="float32"))
    json.dump(docs, open(os.path.join(OUT, "documents.json"), "w", encoding="utf-8"))
    print(f"DONE {len(docs)} docs -> {OUT} ({time.time()-t0:.0f}s)", flush=True)


if __name__ == "__main__":
    main()
