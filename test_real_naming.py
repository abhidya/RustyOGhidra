"""Real-path A/B: old verbatim prompt vs the NEW KB-grounded build_naming_prompt.
Run FROM the OGhidra dir so .env loads (temp 0.6). Uses the real Bridge + real client."""
import os, re, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from src.config import get_config
from src.bridge import Bridge
from src.gf_context import get_gf_context, build_naming_prompt

cfg = get_config()
B = Bridge(config=cfg, include_capabilities=False, enable_cag=True)
GF = get_gf_context()

def cag_notes(code):
    try:
        vs = B.cag_manager.vector_store if getattr(B, "cag_manager", None) else None
        if vs is not None:
            n = vs.get_relevant_knowledge(code[:2500], token_limit=500)
            return ("\n\n## RELATED DECODE NOTES (semantic retrieval)\n" + n) if n and n.strip() else ""
    except Exception:
        pass
    return ""
print(f"temp={B.ollama.temperature} max_tokens(cfg)={B.ollama.max_tokens}", flush=True)

def dec(a):
    t = str(B.ghidra.decompile_function_by_address(address=a))
    return re.sub(r"^\[Total Lines:.*?\]\s*\[Showing Lines:.*?\]\s*", "", t, count=1).strip()

def ctx(addr):
    s = []
    try:
        xt = B.ghidra.get_xrefs_from(address=addr)
        addrs = re.findall(r"\b(80[0-9a-fA-F]{6})\b", str(xt))[:3]
        for a in addrs:
            c = dec(a)
            if c and not c.lower().startswith("error"):
                s.append(f"### Callee {a}:\n```c\n{c[:700]}\n```")
    except Exception:
        pass
    return ("## CALLEE FUNCTIONS:\n" + "\n".join(s)) if s else ""

OLD = """Analyze the function '{n}' and provide a highly descriptive rename suggestion.

## TARGET FUNCTION: {n}
```c
{code}
```
{ctx}

Provide the rename. Follow this EXACT format:
**Function Analysis:** [operations like memory allocation, string manipulation, network, file I/O, crypto, validation]
**Behavior Summary:** [1-4 sentences]
**Suggested Name:** [descriptiveSpecificFunctionName]
**Rationale:** [why]
- Use camelCase. Be domain-aware: crypto->crypto terms, network->network terms, file->file terms.
- Examples: parseJsonConfiguration, validateTlsCertificate, encryptAesPayload, extractRegistryKeys"""

def name_of(resp):
    for ln in resp.split("\n"):
        if "Suggested Name:" in ln:
            v = ln.split("Suggested Name:", 1)[1].replace("*", "").replace("`", "").strip()
            m = re.search(r"[A-Za-z_]\w{2,}", v)
            if m: return m.group(0)
    return "(unparsed)"

def gen(prompt, cap):
    kw = {"max_tokens": cap} if cap else {}
    t = time.time(); r = B.ollama.generate(prompt=prompt, **kw); return r, time.time() - t

targets = sys.argv[1:] or ["8005cc00", "80055c00", "8005d494"]
CAP = 1200  # cap naming output; avoids koboldcpp context-overflow resets from the 16k default
rows = []
for a in targets:
    code = dec(a)
    m = re.search(r"\b([A-Za-z_]\w+)\s*\(", code); cur = m.group(1) if m else f"FUN_{a}"
    ci = ctx(a); res = GF.resolve_for_code(code, self_addr=a) + cag_notes(code)
    print(f"\n=== {a} ({cur}) === resolved {res.count(chr(10))} lines of KB refs", flush=True)
    ob, obt = gen(OLD.format(n=cur, code=code, ctx=ci), CAP)
    nb, nbt = gen(build_naming_prompt(cur, code, ci, res), CAP)
    on, nn = name_of(ob), name_of(nb)
    print(f"  OLD (no KB) : {on}   ({obt:.0f}s)\n  NEW (KB)    : {nn}   ({nbt:.0f}s)", flush=True)
    rows.append((a, cur, on, nn, nb))

print("\n\n================ SUMMARY ================")
print(f"{'addr':10} {'current':16} {'OLD(no KB)':26} {'NEW(KB-grounded)'}")
for a, cur, on, nn, _ in rows:
    print(f"{a:10} {cur[:16]:16} {on[:26]:26} {nn}")
# dump full new rationales
with open("real_naming_out.md", "w", encoding="utf-8") as f:
    for a, cur, on, nn, nb in rows:
        f.write(f"## {a} {cur}\nOLD={on}  NEW={nn}\n\n{nb}\n\n---\n")
print("\nwrote real_naming_out.md")
