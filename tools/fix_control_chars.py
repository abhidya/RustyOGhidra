#!/usr/bin/env python3
"""fix_control_chars.py -- repair heredoc-mangled escapes in this branch's sources.

AGENTS.md, "Toolchain traps on this machine": bash/PowerShell heredocs corrupt
backslashed text. A `\\b` written into a Python regex through a heredoc arrives
as a literal BACKSPACE (0x08), so `re.finditer(r"\\breturn\\b", src)` silently
matches nothing -- no error, no warning, just a rule that never fires. That cost
a real debugging session here: the early-return detector looked correct in the
source dump and did nothing at runtime.

Scans for control characters that cannot legitimately appear in these files and
repairs the known escape manglings, then reports anything it could not fix.
"""

from __future__ import annotations

import sys
from pathlib import Path

# control char -> the escape sequence a heredoc ate to produce it
MANGLED = {
    "\x08": r"\b",
    "\x0c": r"\f",
    "\x07": r"\a",
    "\x0b": r"\v",
}

TARGETS = ["src/port_c_evidence.py", "src/port_plan_derive.py",
           "src/port_spec_emit.py", "tests/test_port_plan_derive.py",
           "tools/survey_plan_tiers.py", "tools/derive_unit.py",
           "tools/diff_against_gold.py", "tools/replay_recorded.py"]


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    problems = 0
    for relative in TARGETS:
        path = root / relative
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        fixed = text
        for char, escape in MANGLED.items():
            if char in fixed:
                count = fixed.count(char)
                fixed = fixed.replace(char, escape)
                print(f"{relative}: repaired {count} x {escape!r} "
                      f"(was raw {ord(char):#04x})")
        leftover = {c for c in fixed if ord(c) < 32 and c not in "\n\t"}
        if leftover:
            problems += 1
            print(f"{relative}: UNREPAIRED control chars "
                  f"{[hex(ord(c)) for c in leftover]}")
        if fixed != text:
            path.write_text(fixed, encoding="utf-8", newline="\n")
    print("clean" if not problems else "PROBLEMS REMAIN")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
