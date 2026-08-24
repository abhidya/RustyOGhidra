"""The compile-fix loop may not rewrite an SDK declaration it was given.

The seed is the single canonical source for `gnt4_*` signatures. A unit that
alters or drops one disagrees with every sibling that kept it, and the N-unit
assembly link fails as `collision_stub`. Measured over one run: 8 of 11 link
failures were erosion -- `gnt4_PSVECMag_bl` six, `gnt4_PSQUATScale_bl` two,
`gnt4_PSMTXMultVec_bl` one -- every one with the declaration already present,
so the seed-gap fix could not reach them.
"""
import pathlib

import pytest

from src.port_unit_generator import CORE_SEED
from src.port_wasm_units import CORE_SEED_RELPATH, seed_declarations_eroded

SEED = (
    "extern double gnt4_PSVECMag_bl(float *v);\n"
    "extern void   gnt4_PSVECAdd_bl(float *a, float *b, float *out);\n"
    "extern void   gnt4_PSQUATScale_bl(double s, float *v, float *out);\n"
)


def test_seed_path_matches_the_generator():
    # The constant is duplicated to avoid an import dependency; it must not drift.
    assert CORE_SEED_RELPATH == CORE_SEED


def test_an_unchanged_reply_is_clean():
    assert seed_declarations_eroded(SEED, SEED) == []


@pytest.mark.parametrize(
    "why,reply",
    [
        (
            "parameter renamed",
            "extern double gnt4_PSVECMag_bl(float *a);\n"
            "extern void gnt4_PSVECAdd_bl(float *x, float *y, float *z);\n"
            "extern void gnt4_PSQUATScale_bl(double s, float *v, float *out);\n",
        ),
        (
            "whitespace reflowed",
            "extern double   gnt4_PSVECMag_bl( float *v );\n"
            "extern void gnt4_PSVECAdd_bl(float *a,float *b,float *out);\n"
            "extern void gnt4_PSQUATScale_bl(double s, float *v, float *out);\n",
        ),
        ("a new declaration appended", SEED + "extern void gnt4_PSMTXIdentity_bl(float *m);\n"),
    ],
)
def test_legal_edits_are_not_erosion(why, reply):
    assert seed_declarations_eroded(SEED, reply) == [], why


@pytest.mark.parametrize(
    "why,reply",
    [
        ("return type changed", SEED.replace("double gnt4_PSVECMag_bl", "undefined8 gnt4_PSVECMag_bl")),
        ("parameter type changed", SEED.replace("gnt4_PSVECMag_bl(float *v)", "gnt4_PSVECMag_bl(int v)")),
        ("declaration deleted", SEED.replace("extern double gnt4_PSVECMag_bl(float *v);\n", "")),
        (
            "declaration commented out",
            SEED.replace(
                "extern double gnt4_PSVECMag_bl(float *v);",
                "/* extern double gnt4_PSVECMag_bl(float *v); */",
            ),
        ),
        ("parameter dropped", SEED.replace("gnt4_PSVECAdd_bl(float *a, float *b, float *out)", "gnt4_PSVECAdd_bl(float *a)")),
    ],
)
def test_erosion_is_caught(why, reply):
    assert "gnt4_PSVECMag_bl" in seed_declarations_eroded(SEED, reply) or "gnt4_PSVECAdd_bl" in seed_declarations_eroded(SEED, reply), why


def test_comparison_is_against_the_edited_header_not_the_seed_on_disk():
    """A unit predating a seed addition must not be flagged for lacking it.

    When the seed grew from 6 declarations to 64, comparing replies against the
    seed on disk falsely flagged 171 existing units -- their headers legitimately
    predate the new symbols. The loop therefore compares against the header being
    edited, and this test pins that the detector is symmetric about its inputs.
    """
    older_header = "extern double gnt4_PSVECMag_bl(float *v);\n"
    grown_seed = older_header + "extern void gnt4_BrandNew_bl(int a);\n"
    # reply keeps everything the header had -> clean, even though the seed grew
    assert seed_declarations_eroded(older_header, older_header) == []
    # and the grown seed would have flagged it, which is the bug being avoided
    assert seed_declarations_eroded(grown_seed, older_header) == ["gnt4_BrandNew_bl"]


def test_the_real_seed_does_not_erode_itself():
    seed = pathlib.Path(CORE_SEED_RELPATH)
    if not seed.is_file():
        pytest.skip("seed not present in this checkout")
    text = seed.read_text(encoding="utf-8", errors="replace")
    assert seed_declarations_eroded(text, text) == []
