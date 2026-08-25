"""Tests for the canonical SDK declaration injection pass (design step 1).

All fixtures are synthetic but shaped exactly like the live seeds: an outer
include guard, Ghidra typedefs, and single-line ``extern`` declarations for
the ``gnt4_*`` SDK seam.
"""

from __future__ import annotations

import pytest

from src import port_sdk_decl_injection as sdi


CANONICAL_SEED = """\
#ifndef GNT4_SHIM_H
#define GNT4_SHIM_H

typedef unsigned long long undefined8;

/* ---- SDK seam: canonical, corpus-validated ---- */
extern void   gnt4_PSVECSubtract_bl(float *a, float *b, float *out);
extern undefined8 gnt4_PSVECAdd_bl(float *a, float *b, float *out);
extern double gnt4_PSVECMag_bl(float *v);
extern undefined8 gnt4_PSMTXConcat_bl(float *a, float *b, float *out);
extern void gnt4_memcpy(void *dest, const void *src, unsigned int n);

#endif /* GNT4_SHIM_H */
"""

UNIT_SEED = """\
#ifndef GNT4_SHIM_H
#define GNT4_SHIM_H

typedef unsigned long long undefined8;

extern void   gnt4_PSVECSubtract_bl(float *a, float *b, float *out);
extern void gnt4_PSVECAdd_bl(float *a, float *b, float *out);

#endif /* GNT4_SHIM_H */
"""

# References: Subtract (identical), Add (divergent: void vs undefined8),
# Mag (absent).  Never references PSMTXConcat or memcpy.
UNIT_C = """\
void FUN_80031634(float *a, float *b, float *out) {
  float tmp[3];
  gnt4_PSVECSubtract_bl(a, b, tmp);
  undefined8 r = gnt4_PSVECAdd_bl(tmp, b, out);
  double m = gnt4_PSVECMag_bl(out);
  (void)r; (void)m;
}
"""


# ---------------------------------------------------------------- reference scan


def test_referenced_symbols_found():
    assert sdi.referenced_gnt4_symbols(UNIT_C) == {
        "gnt4_PSVECSubtract_bl",
        "gnt4_PSVECAdd_bl",
        "gnt4_PSVECMag_bl",
    }


def test_comment_only_mention_is_not_a_reference():
    text = "/* uses gnt4_PSVECMag_bl indirectly */\nint f(void) { return 0; }\n"
    assert sdi.referenced_gnt4_symbols(text) == set()


def test_canonical_declarations_parsed():
    decls = sdi.canonical_sdk_declarations(CANONICAL_SEED)
    assert set(decls) == {
        "gnt4_PSVECSubtract_bl",
        "gnt4_PSVECAdd_bl",
        "gnt4_PSVECMag_bl",
        "gnt4_PSMTXConcat_bl",
        "gnt4_memcpy",
    }
    assert decls["gnt4_PSVECAdd_bl"] == (
        "extern undefined8 gnt4_PSVECAdd_bl(float *a, float *b, float *out);"
    )


# ---------------------------------------------------------------- core contract


def test_referenced_absent_is_injected():
    result = sdi.inject_sdk_declarations(UNIT_SEED, UNIT_C, CANONICAL_SEED)
    assert result.changed
    assert result.injected == ["gnt4_PSVECMag_bl"]
    assert "extern double gnt4_PSVECMag_bl(float *v);" in result.header_text
    assert sdi.SDK_DECL_BANNER in result.header_text
    # Injected inside the include guard: before the trailing #endif.
    lines = result.header_text.splitlines()
    decl_at = next(i for i, l in enumerate(lines) if "gnt4_PSVECMag_bl" in l)
    endif_at = max(i for i, l in enumerate(lines) if l.strip().startswith("#endif"))
    assert decl_at < endif_at


def test_referenced_divergent_is_superseded_in_place():
    result = sdi.inject_sdk_declarations(UNIT_SEED, UNIT_C, CANONICAL_SEED)
    assert result.superseded == ["gnt4_PSVECAdd_bl"]
    # The divergent void line is gone; the canonical line appears exactly once.
    assert "extern void gnt4_PSVECAdd_bl" not in result.header_text
    assert (
        result.header_text.count(
            "extern undefined8 gnt4_PSVECAdd_bl(float *a, float *b, float *out);"
        )
        == 1
    )
    # In place, not appended: the superseded line stays where the original
    # was (before the identical Subtract declaration's neighborhood, well
    # above the appended banner block).
    lines = result.header_text.splitlines()
    add_at = next(i for i, l in enumerate(lines) if "gnt4_PSVECAdd_bl" in l)
    banner_at = next(i for i, l in enumerate(lines) if l == sdi.SDK_DECL_BANNER)
    assert add_at < banner_at


def test_referenced_identical_untouched():
    # The Subtract declaration is identical (same signature, same names):
    # its original spacing survives byte-for-byte.
    result = sdi.inject_sdk_declarations(UNIT_SEED, UNIT_C, CANONICAL_SEED)
    assert "extern void   gnt4_PSVECSubtract_bl(float *a, float *b, float *out);" in (
        result.header_text
    )
    assert "gnt4_PSVECSubtract_bl" not in result.superseded
    assert "gnt4_PSVECSubtract_bl" not in result.injected


def test_identical_modulo_parameter_names_and_spacing_untouched():
    header = (
        "#ifndef GNT4_SHIM_H\n#define GNT4_SHIM_H\n"
        "extern   double gnt4_PSVECMag_bl( float * vec );\n"
        "#endif /* GNT4_SHIM_H */\n"
    )
    unit_c = "double f(float *v) { return gnt4_PSVECMag_bl(v); }\n"
    result = sdi.inject_sdk_declarations(header, unit_c, CANONICAL_SEED)
    assert not result.changed
    assert result.header_text == header


def test_unreferenced_never_added():
    result = sdi.inject_sdk_declarations(UNIT_SEED, UNIT_C, CANONICAL_SEED)
    assert "gnt4_PSMTXConcat_bl" not in result.header_text
    assert "gnt4_memcpy" not in result.header_text


def test_no_relevant_symbols_is_a_noop():
    unit_c = "int f(void) { return 1; }\n"
    result = sdi.inject_sdk_declarations(UNIT_SEED, unit_c, CANONICAL_SEED)
    assert not result.changed
    assert result.header_text == UNIT_SEED


def test_rerun_is_idempotent():
    first = sdi.inject_sdk_declarations(UNIT_SEED, UNIT_C, CANONICAL_SEED)
    assert first.changed
    second = sdi.inject_sdk_declarations(first.header_text, UNIT_C, CANONICAL_SEED)
    assert not second.changed
    assert second.header_text == first.header_text
    assert second.injected == [] and second.superseded == []
    # No duplicates accumulated.
    assert first.header_text.count("gnt4_PSVECMag_bl") == 1


def test_multiline_divergent_declaration_superseded():
    header = (
        "#ifndef GNT4_SHIM_H\n#define GNT4_SHIM_H\n"
        "extern void gnt4_PSVECAdd_bl(\n"
        "    float *a,\n"
        "    float *b,\n"
        "    float *out);\n"
        "#endif /* GNT4_SHIM_H */\n"
    )
    unit_c = "void f(float *a) { gnt4_PSVECAdd_bl(a, a, a); }\n"
    result = sdi.inject_sdk_declarations(header, unit_c, CANONICAL_SEED)
    assert result.superseded == ["gnt4_PSVECAdd_bl"]
    assert "extern void gnt4_PSVECAdd_bl(" not in result.header_text
    assert "float *b,\n" not in result.header_text  # continuation lines removed
    assert (
        "extern undefined8 gnt4_PSVECAdd_bl(float *a, float *b, float *out);"
        in result.header_text
    )


def test_definition_body_never_superseded():
    # A stub DEFINITION is not a declaration; the pass must not splice it.
    header = (
        "#ifndef GNT4_SHIM_H\n#define GNT4_SHIM_H\n"
        "extern undefined8 gnt4_PSVECAdd_bl(float *a, float *b, float *out);\n"
        "static double gnt4_PSVECMag_bl(float *v) { return 0.0; }\n"
        "#endif /* GNT4_SHIM_H */\n"
    )
    unit_c = "void f(float *a) { gnt4_PSVECAdd_bl(a, a, a); gnt4_PSVECMag_bl(a); }\n"
    result = sdi.inject_sdk_declarations(header, unit_c, CANONICAL_SEED)
    assert "static double gnt4_PSVECMag_bl(float *v) { return 0.0; }" in (
        result.header_text
    )
    assert "gnt4_PSVECMag_bl" not in result.superseded


def test_unspliceable_divergence_reported_not_duplicated():
    # A declaration the chunk parser sees but the line splicer cannot safely
    # replace (block comment spanning the declaration's lines): reported as
    # unresolved, and NOT appended as a conflicting duplicate.
    header = (
        "#ifndef GNT4_SHIM_H\n#define GNT4_SHIM_H\n"
        "extern void /* torn\n"
        "comment */ gnt4_PSVECAdd_bl(float *a);\n"
        "#endif /* GNT4_SHIM_H */\n"
    )
    unit_c = "void f(float *a) { gnt4_PSVECAdd_bl(a, a, a); }\n"
    result = sdi.inject_sdk_declarations(header, unit_c, CANONICAL_SEED)
    assert result.unresolved == ["gnt4_PSVECAdd_bl"]
    assert not result.changed
    assert "extern undefined8 gnt4_PSVECAdd_bl" not in result.header_text


# ---------------------------------------------------------------- file-level sync


def _write_fixture(tmp_path):
    seed = tmp_path / "auto-c9999-000.h"
    seed.write_text(UNIT_SEED, encoding="utf-8", newline="\n")
    canon = tmp_path / "gnt4_shim_seed.h"
    canon.write_text(CANONICAL_SEED, encoding="utf-8", newline="\n")
    return seed, canon


def test_sync_writes_seed_atomically(tmp_path):
    seed, canon = _write_fixture(tmp_path)
    result = sdi.sync_sdk_declarations(seed, UNIT_C, canon)
    assert result.changed and result.write_error is None
    on_disk = seed.read_text(encoding="utf-8")
    assert on_disk == result.header_text
    assert "extern double gnt4_PSVECMag_bl(float *v);" in on_disk
    # No temp droppings.
    assert [p.name for p in tmp_path.glob("*.tmp")] == []


def test_sync_noop_does_not_rewrite_file(tmp_path, monkeypatch):
    seed, canon = _write_fixture(tmp_path)
    sdi.sync_sdk_declarations(seed, UNIT_C, canon)  # first run: canonicalises

    calls = []
    original = sdi._atomic_write_text

    def counting(path, text):
        calls.append(path)
        return original(path, text)

    monkeypatch.setattr(sdi, "_atomic_write_text", counting)
    second = sdi.sync_sdk_declarations(seed, UNIT_C, canon)
    assert not second.changed
    assert calls == []  # idempotent re-run: the file is never touched


def test_sync_write_failure_degrades_but_keeps_memory_sync(tmp_path, monkeypatch):
    seed, canon = _write_fixture(tmp_path)

    def failing_replace(src, dst):
        raise OSError("locked by AV scan")

    monkeypatch.setattr(sdi.os, "replace", failing_replace)
    result = sdi.sync_sdk_declarations(seed, UNIT_C, canon)
    assert result.changed
    assert result.write_error and "locked" in result.write_error
    # In-memory header is synced for this attempt...
    assert "extern double gnt4_PSVECMag_bl(float *v);" in result.header_text
    # ...but the seed file is untouched and no temp file lingers.
    assert seed.read_text(encoding="utf-8") == UNIT_SEED
    assert [p.name for p in tmp_path.glob("*.tmp")] == []


def test_sync_missing_canonical_seed_raises(tmp_path):
    seed = tmp_path / "auto-c9999-000.h"
    seed.write_text(UNIT_SEED, encoding="utf-8", newline="\n")
    with pytest.raises(OSError):
        sdi.sync_sdk_declarations(seed, UNIT_C, tmp_path / "missing.h")
    assert seed.read_text(encoding="utf-8") == UNIT_SEED


def test_sync_accepts_preread_header_text(tmp_path):
    seed, canon = _write_fixture(tmp_path)
    result = sdi.sync_sdk_declarations(
        seed, UNIT_C, canon, header_text=UNIT_SEED
    )
    assert result.changed
    assert seed.read_text(encoding="utf-8") == result.header_text
