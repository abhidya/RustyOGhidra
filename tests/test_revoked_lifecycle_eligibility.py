"""Which recorded revocations may an installed artifact be replaced against.

Regression for the D5-6 migration deadlock: 12 units rebuilt, passed the N=5
assembly gate, then were refused at artifact-install because the migration wrote
`via: "d5-migrate"` without the operator command's integrity bindings. Every
retry cost a full LLM generation plus gate on a unit that could not succeed.
"""
import pytest

from src.port_wasm_units import revoked_lifecycle_is_eligible as eligible

OPERATOR = {
    "via": "revoke-unit",
    "previous_status": "green",
    "previous_tier": "compile_only",
    "reason": "superseded",
    "transition_id": "verdict-revoke-" + "a" * 64,
    "previous_record_sha256": "b" * 64,
    "previous_commit": "c" * 40,
}
MIGRATION = {
    "via": "d5-migrate",
    "at": "2026-08-21T05:32:38.714892Z",
    "reason": "D5-6 migration: artifact predates the d5-fp-reinterpret transform",
    "previous_status": "green",
    "previous_tier": "compile_only",
    "transform_sites": 3,
}


def test_complete_operator_lifecycle_is_eligible():
    assert eligible(OPERATOR, "compile_only")


@pytest.mark.parametrize("field", ["transition_id", "previous_record_sha256", "previous_commit"])
def test_operator_lifecycle_still_requires_every_binding(field):
    assert not eligible({**OPERATOR, field: None}, "compile_only")


@pytest.mark.parametrize(
    "field,value",
    [
        ("transition_id", "verdict-revoke-nope"),
        ("previous_record_sha256", "b" * 63),
        ("previous_commit", "zz"),
        # Abbreviated commit prefixes are no longer proof-grade identity.
        ("previous_commit", "1022b6c9"),
        ("previous_commit", "c" * 39),
        ("previous_commit", "c" * 64),
    ],
)
def test_operator_bindings_must_be_well_formed(field, value):
    assert not eligible({**OPERATOR, field: value}, "compile_only")


def test_operator_lifecycle_may_carry_its_candidate_digest():
    # revoke-unit records the revoked lifecycle's candidate_sha256; carrying
    # it is genuine operator evidence, not forgery.
    assert eligible(
        {**OPERATOR, "previous_candidate_sha256": "d" * 64}, "compile_only"
    )


def test_migration_lifecycle_is_eligible_on_its_own_evidence():
    assert eligible(MIGRATION, "compile_only")


@pytest.mark.parametrize(
    "field",
    [
        "transition_id",
        "previous_record_sha256",
        "previous_commit",
        # A digest here would take the digest-only replacement branch (disk
        # digest vs self-declared digest, no commit-tree proof), so a
        # migration record carrying it is refused as forged.
        "previous_candidate_sha256",
    ],
)
def test_a_migration_record_carrying_operator_bindings_is_forged(field):
    # A genuine d5-migrate record cannot have these -- the migration never
    # computed them -- so their presence means the record was hand-written.
    assert not eligible({**MIGRATION, field: "a" * 64}, "compile_only")


@pytest.mark.parametrize("sites", [0, -1, True, None, "3", 3.0])
def test_migration_needs_a_positive_integer_transform_site_count(sites):
    assert not eligible({**MIGRATION, "transform_sites": sites}, "compile_only")


@pytest.mark.parametrize("revoked", [OPERATOR, MIGRATION])
def test_both_lifecycles_require_a_green_predecessor_and_matching_tier(revoked):
    assert not eligible({**revoked, "previous_status": "red_retryable"}, "compile_only")
    assert not eligible(revoked, "oracle_green")


@pytest.mark.parametrize("revoked", [OPERATOR, MIGRATION])
def test_both_lifecycles_require_a_nonempty_reason(revoked):
    assert not eligible({**revoked, "reason": "   "}, "compile_only")
    assert not eligible({**revoked, "reason": None}, "compile_only")


@pytest.mark.parametrize("value", [None, "revoke-unit-ish", "", "settle-unit"])
def test_an_unrecognised_issuer_is_never_eligible(value):
    assert not eligible({**OPERATOR, "via": value}, "compile_only")


@pytest.mark.parametrize("revoked", [None, "revoked", 7, [], ()])
def test_a_non_mapping_is_never_eligible(revoked):
    assert not eligible(revoked, "compile_only")
