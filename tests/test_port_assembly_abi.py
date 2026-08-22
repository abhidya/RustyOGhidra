"""Public conformance tests for the deep assembly-ABI module.

The fixture and every body in this file are synthetic.  Historical digests are
metadata only; no test treats them as reproducible candidate bytes.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import replace
from pathlib import Path

import pytest

from src import port_assembly_abi as abi


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "assembly_abi_synthetic_v1.json"
REAL_PRODUCT_ROOT = Path(r"D:\GotYaForce")


def _fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


@pytest.fixture(scope="module")
def clang_parser() -> abi.ClangDeclaratorParser:
    return abi.ClangDeclaratorParser.from_product_root(REAL_PRODUCT_ROOT)


def _function_record(row: dict) -> dict:
    template = _fixture()["owner_template"]
    return {
        "name": row["name"],
        "address": "0x" + row["marker"],
        "unit": row["unit"],
        "chunk_file": "research/decomp/ghidra-export/" + row["chunk"],
        "line_range": [1, 2],
        "loc": 2,
        "return_type": template["return_type"],
        "params": template["params"],
        "returns_value": template["returns_value"],
        "has_pointer_args": template["has_pointer_args"],
        "external_callees": {"count": 0, "list": []},
        "global_refs": [],
        "ts_citations": [],
        "citation_grade": "none",
        "citation_scan_skipped": None,
        "structural_class": template["structural_class"],
        "gap_alignment": None,
    }


def _registry(rows: list[dict]) -> dict:
    functions = sorted((_function_record(row) for row in rows), key=lambda item: (item["address"], item["name"]))
    units = sorted(item["unit"] for item in functions)
    anomalies = [
        f'{row["name"]}: name addr {row["encoded"]} != marker {row["marker"]} (marker wins)'
        for row in rows
    ]
    ranked = [
        {
            "unit": unit,
            "oracle_kind": "trace_only",
            "max_structural_class": "C",
            "fn_count": 1,
            "gap_partial_slots": 0,
            "port_citations": 0,
            "port_grade_fns": 0,
            "total_citations": 0,
            "total_loc": 2,
            "gap_family_ctors": [],
            "fully_gap_aligned": False,
        }
        for unit in units
    ]
    return {
        "oracle_registry_schema": 1,
        "meta": {
            "generated_by": "synthetic-fixture-builder",
            "inputs": {
                "queue": "research/decomp/data/synthetic-queue.json",
                "skipped": "research/decomp/data/synthetic-skipped.json",
                "chunk_index": "research/decomp/ghidra-export/_index.tsv",
                "family_coverage": "research/decomp/data/synthetic-family.json",
            },
            "conventions": {
                "address": "synthetic marker wins",
                "structural_class": "synthetic",
                "citation_grade": "synthetic",
                "gap_alignment": "synthetic",
                "ranked_units_sort": "synthetic",
                "oracle_able_units": "synthetic",
            },
        },
        "summary": {
            "functions_total": len(functions),
            "units_total": len(units),
            "excluded_total": 0,
            "excluded_reasons": {},
            "structural_class_counts": {"C": len(functions)},
            "citation_grade_counts": {"none": len(functions)},
            "class_by_citation_grade": {"C": {"none": len(functions)}},
            "gap_aligned_functions": 0,
            "gap_aligned_functions_partial_family": 0,
            "fully_gap_aligned_units": 0,
            "fully_gap_aligned_unit_names": [],
            "oracle_able_units": {
                "differential_vs_ts": 0,
                "state_diff": 0,
                "citations_no_family": 0,
                "trace_only": len(units),
            },
            "oracle_able_unit_names": {
                "differential_vs_ts": [],
                "state_diff": [],
                "citations_no_family": [],
                "trace_only": units,
            },
            "anomalies": anomalies,
        },
        "ranked_units": ranked,
        "functions": functions,
        "excluded": [],
    }


class FakeParser:
    """Deterministic injected parser; planning tests do not fake file I/O."""

    _identity_seed = hashlib.sha256(b"public-fixture-parser-v1").hexdigest()
    identity = abi.ParserIdentity(
        "D:/synthetic/clang.exe",
        _identity_seed,
        _identity_seed,
        len(b"public-fixture-parser-v1"),
    )

    @staticmethod
    def _projection(fragment: bytes, symbol: str) -> abi.DeclaratorProjection:
        text = fragment.decode("utf-8")
        if "PARSE_MISMATCH" in text:
            return abi.DeclaratorProjection.synthetic(symbol, f"int {symbol}(int);", "int", ("int",))
        if "const int *" in text:
            return abi.DeclaratorProjection.synthetic(symbol, f"void {symbol}(const int *);", "void", ("const int *",))
        if "volatile int *" in text:
            return abi.DeclaratorProjection.synthetic(symbol, f"void {symbol}(volatile int *);", "void", ("volatile int *",))
        if "int *const" in text:
            return abi.DeclaratorProjection.synthetic(symbol, f"void {symbol}(int *const);", "void", ("int *const",))
        if re.search(r"\bconst\s+int\b", text):
            return abi.DeclaratorProjection.synthetic(symbol, f"void {symbol}(const int);", "void", ("const int",))
        if re.search(rf"\b{re.escape(symbol)}\s*\(\s*\)", text):
            return abi.DeclaratorProjection.synthetic(
                symbol, f"void {symbol}();", "void", (), prototype_kind="unspecified"
            )
        if re.search(rf"\b{re.escape(symbol)}\s*\(\s*void\s*\)", text):
            return abi.DeclaratorProjection.synthetic(symbol, f"void {symbol}(void);", "void", (), prototype_kind="void")
        return abi.DeclaratorProjection.synthetic(symbol, f"void {symbol}(int);", "void", ("int",))

    def parse_definition(self, source: bytes, symbol: str) -> abi.DeclaratorProjection:
        return self._projection(source, symbol)

    def parse_declaration(self, source: bytes, symbol: str) -> abi.DeclaratorProjection:
        return self._projection(source, symbol)

    def compatibility(
        self,
        left: abi.DeclaratorProjection,
        right: abi.DeclaratorProjection,
    ) -> abi.CompatibilityProbe:
        left_type = left.abi_tuple.parameter_types
        right_type = right.abi_tuple.parameter_types
        incompatible = any("const int *" in value or "volatile int *" in value for value in (*left_type, *right_type))
        source = abi.build_compatibility_source(left.canonical_prototype, right.canonical_prototype)
        return abi.CompatibilityProbe(
            compatible=not incompatible,
            source=source,
            source_sha256=hashlib.sha256(source).hexdigest(),
            parser_identity_sha256=self.identity.sha256,
        )


def _malformed_projection(path: str, value: object) -> abi.DeclaratorProjection:
    projection = FakeParser._projection(b"void zz_00262b4_(int);", "zz_00262b4_")
    head, *tail = path.split(".")
    if head == "abi_tuple":
        if not tail:
            return replace(projection, abi_tuple=value)
        nested = copy.copy(projection.abi_tuple)
        object.__setattr__(nested, tail[0], value)
        return replace(projection, abi_tuple=nested)
    if head == "abi_probe_evidence":
        if not tail:
            return replace(projection, abi_probe_evidence=value)
        evidence = copy.copy(projection.abi_probe_evidence)
        if tail[0] == "adjusted_parameters" and len(tail) > 1:
            adjusted = abi.AdjustedParameterEvidence(0, "int *", 1, "a" * 64, "int *")
            if tail[1] == "member":
                object.__setattr__(evidence, "adjusted_parameters", (value,))
            else:
                object.__setattr__(adjusted, tail[1], value)
                object.__setattr__(evidence, "adjusted_parameters", (adjusted,))
        else:
            object.__setattr__(evidence, tail[0], value)
        return replace(projection, abi_probe_evidence=evidence)
    return replace(projection, **{head: value})


def _write_product(root: Path, *, parser: FakeParser | None = None) -> tuple[Path, FakeParser]:
    fixture = _fixture()
    rows = fixture["marker_wins"]
    for row in rows:
        path = root / "research" / "decomp" / "ghidra-export" / row["chunk"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(
            f'// ==== {row["marker"]}  {row["name"]} ====\nvoid {row["name"]}(int value) {{ (void)value; }}\n'.encode()
        )
    index = root / "research" / "decomp" / "ghidra-export" / "_index.tsv"
    index.write_text(
        "address\tname\tchunk_file\n"
        + "".join(f'{row["marker"]}\t{row["name"]}\t{row["chunk"]}\n' for row in rows),
        encoding="utf-8",
        newline="",
    )
    for name in ("synthetic-queue.json", "synthetic-skipped.json", "synthetic-family.json"):
        path = root / "research" / "decomp" / "data" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n", encoding="utf-8", newline="")
    registry_path = root / "research" / "decomp" / "data" / "oracle-registry.json"
    registry_path.write_bytes(_canonical_bytes(_registry(rows)))
    return registry_path, parser or FakeParser()


def _load_snapshot(root: Path) -> abi.OwnerSnapshot:
    registry, parser = _write_product(root)
    return abi.load_owner_snapshot(root, registry, parser)


def _bundle() -> abi.AssemblyBundle:
    items = []
    for row in _fixture()["bundle"]["objects"]:
        source = row["source"].encode()
        header = row["header"].encode()
        items.append(
            abi.BundleTranslationUnit(
                ordinal=row["ordinal"],
                unit=row["unit"],
                role=row["role"],
                source_relpath=f'{row["unit"]}/unit.c',
                source=source,
                source_sha256=hashlib.sha256(source).hexdigest(),
                header_relpath=f'{row["unit"]}/gnt4_shim.h',
                header=header,
                header_sha256=hashlib.sha256(header).hexdigest(),
                object_relpath=f'objects/{row["ordinal"]:04d}-{row["unit"]}.o',
                compile_argv=("emcc", "-std=gnu11", "-c", f'{row["unit"]}/unit.c'),
            )
        )
    fixture = _fixture()["bundle"]
    tool_world = replace(
        abi.ToolWorld.synthetic("public-five-object-world"),
        identities=tuple(
            abi.ToolIdentity(
                identity.role,
                FakeParser.identity.executable_path,
                FakeParser.identity.binary_sha256,
                FakeParser.identity.version_sha256,
            )
            if identity.role == "clang"
            else identity
            for identity in abi.ToolWorld.synthetic("public-five-object-world").identities
        ),
        compile_argv=tuple(item.compile_argv for item in items),
        inspect_argv=tuple(("llvm-nm", item.object_relpath) for item in items),
    )
    return abi.AssemblyBundle(
        unit=fixture["unit"],
        attempt=fixture["attempt"],
        behavior_tier=fixture["behavior_tier"],
        translation_units=tuple(items),
        tool_world=tool_world,
    )


def test_embedded_preamble_and_bound_argv_are_exact():
    assert len(abi.ABI_PREAMBLE_V1) == 1870
    assert hashlib.sha256(abi.ABI_PREAMBLE_V1).hexdigest() == "c08c52ac4f22928ab46312b6a42695a3ef4336d10b469ea5dd310973ab850bbf"
    assert len(abi.ABI_SPELLING_UNDEF_V1) == 273
    assert hashlib.sha256(abi.ABI_SPELLING_UNDEF_V1).hexdigest() == "d64b6528c22b9579689d2c677915eb20830b27bc465945ff7925dc0a2d65aa78"
    assert abi.json_argv("clang.exe", "__oghidra_abi_probe") == (
        "clang.exe", "--target=wasm32-unknown-emscripten", "-std=gnu11", "-x", "c", "-Xclang",
        "-ast-dump=json", "-Xclang", "-ast-dump-filter", "-Xclang", "__oghidra_abi_probe", "-fsyntax-only", "-",
    )


def test_public_fixture_payloads_and_three_sixteen_argument_vectors_are_synthetic_and_exact():
    fixture = _fixture()
    payloads = fixture["payloads"]
    candidate = payloads["candidate_bytes"].encode()
    owner = payloads["owner_bytes"].encode()
    assert len(candidate) == 29
    assert hashlib.sha256(candidate).hexdigest() == payloads["candidate_sha256"]
    assert len(owner) == 35
    assert hashlib.sha256(owner).hexdigest() == payloads["owner_sha256"]
    framed = len(b"unit.c").to_bytes(4, "big") + b"unit.cF" + len(candidate).to_bytes(8, "big") + candidate
    assert framed.hex() == (
        "00000006756e69742e6346000000000000001d"
        "696e74206669787475726528766f6964297b72657475726e20373b7d0a"
    )
    assert hashlib.sha256(framed).hexdigest() == payloads["candidate_directory_sha256"]
    assert len(fixture["conflicts"]["three_argument"]) == 3
    assert len(fixture["conflicts"]["sixteen_argument"]) == 16
    assert all(
        digest not in {payloads["candidate_sha256"], payloads["candidate_directory_sha256"]}
        for digest in fixture["historical_evidence_sha256"].values()
    )
    assert abi.print_argv("clang.exe") == (
        "clang.exe", "--target=wasm32-unknown-emscripten", "-std=gnu11", "-x", "c", "-Xclang", "-ast-print",
        "-fsyntax-only", "-",
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (abi.AbiTuple("void", ("unsigned int",), "prototype", False), "5c14caef4ae18991d24cdfd6c1f2b78a809137b287e50bc635dcf77a82b28a6d"),
        (abi.AbiTuple("unsigned int", (), "void", False), "d25e22e0761cfaa90006e18e308eccaaa492da20122ef1d33fdbd8a28efc278f"),
        (abi.AbiTuple("unsigned int", ("unsigned int",), "prototype", False), "11acd06ddd182b790b3f9703469d778442bf8874c4bc334b9acdd80ce2887e56"),
    ],
)
def test_abi_tuple_payload_and_framed_digest_vectors(value: abi.AbiTuple, expected: str):
    payload = value.canonical_bytes()
    assert payload.endswith(b"\n")
    assert value.sha256 == expected
    frame = b"OGHIDRA_ABI_TUPLE_V1\0" + len(payload).to_bytes(8, "big") + payload
    assert hashlib.sha256(frame).hexdigest() == expected


@pytest.mark.parametrize(
    ("left", "right", "size", "digest"),
    [
        ("void synthetic(int);", "void synthetic(const int);", 2101, "79f9ffd619450cc9201ee8f5f4b82e246649b30f732e0ee364b647b35c570144"),
        ("void synthetic(int *);", "void synthetic(int *const);", 2104, "297332a57a770c0eb8b8d76b658e59650f7bb54599cd92d5b3d2caec8a5b2f3b"),
        ("void synthetic(int *);", "void synthetic(int *restrict);", 2107, "2ad0833c5d3c9c7439e23eec4881ad48418e2b7e205695739c0b5e937fc3c624"),
        ("void synthetic(int *);", "void synthetic(const int *);", 2105, "13a49f7cac54fb1b6c03e662da84f7c7577e5e2710710abda68555c79b7ae35b"),
        ("void synthetic(int *);", "void synthetic(volatile int *);", 2108, "b3ca6f185440ad21f696ee78a00038bcc57651a00beb5a393dc31d16eb38671f"),
    ],
)
def test_compatibility_probe_sources_are_byte_exact(left: str, right: str, size: int, digest: str):
    source = abi.build_compatibility_source(left, right, symbol="synthetic")
    assert len(source) == size
    assert hashlib.sha256(source).hexdigest() == digest


def test_strict_v1_adapter_accepts_all_eight_marker_wins_rows(tmp_path: Path):
    snapshot = _load_snapshot(tmp_path.resolve())
    fixture = _fixture()
    assert list(snapshot.owner_index) == sorted(row["name"] for row in fixture["marker_wins"])
    assert snapshot.registry_sha256 == hashlib.sha256(snapshot.registry_bytes).hexdigest()
    assert all(len(bindings) == 1 for bindings in snapshot.owner_index.values())
    by_name = {item.symbol: item for item in snapshot.bindings}
    assert [
        (row["name"], row["encoded"], by_name[row["name"]].address[2:], by_name[row["name"]].unit)
        for row in fixture["marker_wins"]
    ] == [(row["name"], row["encoded"], row["marker"], row["unit"]) for row in fixture["marker_wins"]]


@pytest.mark.parametrize("bad_schema", [None, False, "1", 0, 2])
def test_strict_v1_adapter_rejects_absent_bool_string_and_unknown_schema(tmp_path: Path, bad_schema: object):
    registry_path, parser = _write_product(tmp_path.resolve())
    payload = json.loads(registry_path.read_text())
    if bad_schema is None:
        payload.pop("oracle_registry_schema")
    else:
        payload["oracle_registry_schema"] = bad_schema
    registry_path.write_bytes(_canonical_bytes(payload))
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.load_owner_snapshot(tmp_path.resolve(), registry_path, parser)
    assert caught.value.refusal.code == "oracle_registry_schema_invalid"


@pytest.mark.parametrize(
    ("mutator", "code"),
    [
        (lambda data: data.update(extra=True), "oracle_registry_shape_invalid"),
        (lambda data: data["functions"].append(copy.deepcopy(data["functions"][0])), "owner_ambiguous"),
        (lambda data: data["functions"][1].update(address=data["functions"][0]["address"]), "owner_address_ambiguous"),
        (lambda data: data["summary"]["anomalies"].pop(), "owner_marker_anomaly_mismatch"),
    ],
)
def test_adapter_fail_closed_registry_adversaries(tmp_path: Path, mutator, code: str):
    registry_path, parser = _write_product(tmp_path.resolve())
    payload = json.loads(registry_path.read_text())
    mutator(payload)
    registry_path.write_bytes(_canonical_bytes(payload))
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.load_owner_snapshot(tmp_path.resolve(), registry_path, parser)
    assert caught.value.refusal.code == code


def test_adapter_rejects_marker_index_range_and_parse_drift(tmp_path: Path):
    root = tmp_path.resolve()
    registry_path, parser = _write_product(root)
    first = _fixture()["marker_wins"][0]
    source = root / "research" / "decomp" / "ghidra-export" / first["chunk"]
    source.write_text(source.read_text().replace(first["marker"], "80026251"), encoding="utf-8", newline="")
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.load_owner_snapshot(root, registry_path, parser)
    assert caught.value.refusal.code == "owner_marker_mismatch"

    registry_path, parser = _write_product(root)
    index = root / "research" / "decomp" / "ghidra-export" / "_index.tsv"
    index.write_text(index.read_text().replace(first["marker"], "80026251", 1), encoding="utf-8", newline="")
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.load_owner_snapshot(root, registry_path, parser)
    assert caught.value.refusal.code == "owner_index_mismatch"

    registry_path, parser = _write_product(root)
    source.write_text(source.read_text().replace("void ", "int PARSE_MISMATCH ", 1), encoding="utf-8", newline="")
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.load_owner_snapshot(root, registry_path, parser)
    assert caught.value.refusal.code in {"owner_definition_missing", "owner_prototype_mismatch"}


def test_adapter_refuses_missing_marker_and_actual_line_range_drift(tmp_path: Path):
    root = tmp_path.resolve()
    registry_path, parser = _write_product(root)
    payload = json.loads(registry_path.read_text())
    first = payload["functions"][0]
    source = root / first["chunk_file"]
    source.write_bytes(source.read_bytes().replace(b"// ====", b"// ----", 1))
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.load_owner_snapshot(root, registry_path, parser)
    assert caught.value.refusal.code == "owner_marker_mismatch"

    registry_path, parser = _write_product(root)
    payload = json.loads(registry_path.read_text())
    payload["functions"][0]["line_range"] = [2, 2]
    payload["functions"][0]["loc"] = 1
    payload["ranked_units"][0]["total_loc"] = 1
    registry_path.write_bytes(_canonical_bytes(payload))
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.load_owner_snapshot(root, registry_path, parser)
    assert caught.value.refusal.code == "owner_marker_mismatch"


def test_owner_evidence_hashes_exact_retained_line_endings_and_lengths(tmp_path: Path):
    root = tmp_path.resolve()
    snapshot = _load_snapshot(root)
    for binding in snapshot.bindings:
        raw = (root / binding.chunk_file).read_bytes()
        lines = raw.splitlines(keepends=True)
        selected = b"".join(lines[binding.line_range[0] - 1 : binding.line_range[1]])
        assert binding.source.file_sha256 == hashlib.sha256(raw).hexdigest()
        assert binding.source.range_sha256 == hashlib.sha256(selected).hexdigest()
        assert selected.endswith(b"\n")


def test_adapter_rejects_path_escape_duplicate_json_keys_and_bool_counts(tmp_path: Path):
    root = tmp_path.resolve()
    registry_path, parser = _write_product(root)
    payload = json.loads(registry_path.read_text())
    payload["functions"][0]["chunk_file"] = "../escape.c"
    registry_path.write_bytes(_canonical_bytes(payload))
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.load_owner_snapshot(root, registry_path, parser)
    assert caught.value.refusal.code == "product_path_invalid"

    registry_path, parser = _write_product(root)
    raw = registry_path.read_bytes().replace(b'"oracle_registry_schema":1', b'"oracle_registry_schema":1,"oracle_registry_schema":1')
    registry_path.write_bytes(raw)
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.load_owner_snapshot(root, registry_path, parser)
    assert caught.value.refusal.code == "oracle_registry_json_invalid"

    registry_path, parser = _write_product(root)
    payload = json.loads(registry_path.read_text())
    payload["summary"]["functions_total"] = True
    registry_path.write_bytes(_canonical_bytes(payload))
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.load_owner_snapshot(root, registry_path, parser)
    assert caught.value.refusal.code == "oracle_registry_summary_invalid"


@pytest.mark.parametrize(
    ("mutator", "code"),
    [
        (lambda value: value["meta"].update(extra="x"), "oracle_registry_meta_invalid"),
        (lambda value: value["meta"]["inputs"].pop("queue"), "oracle_registry_meta_invalid"),
        (lambda value: value["meta"]["conventions"].update(address=""), "oracle_registry_meta_invalid"),
        (lambda value: value["summary"].pop("units_total"), "oracle_registry_summary_invalid"),
        (lambda value: value["summary"]["oracle_able_units"].update(trace_only=True), "oracle_registry_summary_invalid"),
        (lambda value: value["ranked_units"][0].update(extra=0), "oracle_registry_ranked_invalid"),
        (lambda value: value["ranked_units"][0].update(fn_count=True), "oracle_registry_ranked_invalid"),
        (lambda value: value["excluded"].append({"name": "x"}), "oracle_registry_excluded_invalid"),
        (lambda value: value["functions"][-1].update(extra=0), "oracle_registry_function_invalid"),
        (lambda value: value["functions"][-1]["external_callees"].update(count=1), "oracle_registry_function_invalid"),
        (lambda value: value["functions"][-1].update(global_refs=[{"symbol": "x", "prefix_type": "u8", "width_known": 1}]), "oracle_registry_function_invalid"),
        (lambda value: value["functions"][-1].update(ts_citations=[{"where": "x.c:1", "grade": "invented"}]), "oracle_registry_function_invalid"),
        (lambda value: value["functions"][-1].update(gap_alignment={"family_ctor": "0x80000000", "partial_slots": True, "members": []}), "oracle_registry_function_invalid"),
        (lambda value: value["functions"][-1].update(params=["void", "int"]), "oracle_registry_function_invalid"),
    ],
)
def test_strict_v1_nested_shapes_validate_every_record(tmp_path: Path, mutator, code: str):
    registry_path, parser = _write_product(tmp_path.resolve())
    payload = json.loads(registry_path.read_text())
    mutator(payload)
    registry_path.write_bytes(_canonical_bytes(payload))
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.load_owner_snapshot(tmp_path.resolve(), registry_path, parser)
    assert caught.value.refusal.code == code


@pytest.mark.parametrize("raw", [b"\xff", b'{"oracle_registry_schema":NaN}', b'{"oracle_registry_schema":Infinity}', b"null"])
def test_registry_refuses_non_utf8_nonfinite_and_null(tmp_path: Path, raw: bytes):
    registry_path, parser = _write_product(tmp_path.resolve())
    registry_path.write_bytes(raw)
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.load_owner_snapshot(tmp_path.resolve(), registry_path, parser)
    assert caught.value.refusal.code in {"oracle_registry_json_invalid", "oracle_registry_schema_invalid"}


def test_registry_refuses_duplicate_nested_key_and_extra_anomaly(tmp_path: Path):
    root = tmp_path.resolve()
    registry_path, parser = _write_product(root)
    raw = registry_path.read_bytes().replace(
        b'"generated_by":"synthetic-fixture-builder"',
        b'"generated_by":"synthetic-fixture-builder","generated_by":"duplicate"',
    )
    registry_path.write_bytes(raw)
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.load_owner_snapshot(root, registry_path, parser)
    assert caught.value.refusal.code == "oracle_registry_json_invalid"

    registry_path, parser = _write_product(root)
    payload = json.loads(registry_path.read_text())
    payload["summary"]["anomalies"].append("invented extra anomaly")
    registry_path.write_bytes(_canonical_bytes(payload))
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.load_owner_snapshot(root, registry_path, parser)
    assert caught.value.refusal.code == "owner_marker_anomaly_mismatch"


def test_registry_preserves_unspecified_vs_explicit_void(tmp_path: Path):
    root = tmp_path.resolve()
    for params, source_params, expected_kind in (([], "", "unspecified"), (["void"], "void", "void")):
        registry_path, parser = _write_product(root)
        payload = json.loads(registry_path.read_text())
        record = payload["functions"][0]
        record["params"] = params
        registry_path.write_bytes(_canonical_bytes(payload))
        source = root / record["chunk_file"]
        row = _fixture()["marker_wins"][0]
        source.write_text(
            f'// ==== {row["marker"]}  {row["name"]} ====\nvoid {row["name"]}({source_params}) {{ }}\n',
            encoding="utf-8",
            newline="",
        )
        snapshot = abi.load_owner_snapshot(root, registry_path, parser)
        assert snapshot.bindings[0].projection.prototype_kind == expected_kind


@pytest.mark.parametrize(
    "bad_path",
    [
        "../escape.c",
        "research\\decomp\\ghidra-export\\chunk_0003.c",
        "research/decomp/ghidra-export/./chunk_0003.c",
        "research/decomp/ghidra-export//chunk_0003.c",
        "C:/research/decomp/ghidra-export/chunk_0003.c",
        "//server/share/chunk_0003.c",
        "research/decomp/ghidra-export/chunk:stream.c",
        "research/decomp/ghidra-export/chunk_0003.c\x01",
        "research/decomp/other/chunk_0003.c",
        "research/decomp/ghidra-export/chunk_0003.h",
        "research/decomp/ghidra-export/cafe\u0301.c",
    ],
)
def test_owner_paths_refuse_every_noncanonical_form(tmp_path: Path, bad_path: str):
    root = tmp_path.resolve()
    registry_path, parser = _write_product(root)
    payload = json.loads(registry_path.read_text())
    payload["functions"][0]["chunk_file"] = bad_path
    registry_path.write_bytes(_canonical_bytes(payload))
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.load_owner_snapshot(root, registry_path, parser)
    assert caught.value.refusal.code == "product_path_invalid"


def test_product_root_and_exact_component_spelling_are_strict(tmp_path: Path):
    root = tmp_path.resolve()
    registry_path, parser = _write_product(root)
    for invalid_root in (Path("relative"), root / "missing", registry_path):
        with pytest.raises(abi.AssemblyAbiError) as caught:
            abi.load_owner_snapshot(invalid_root, registry_path, parser)
        assert caught.value.refusal.code in {"product_root_invalid", "product_path_escape"}
    payload = json.loads(registry_path.read_text())
    payload["functions"][0]["chunk_file"] = payload["functions"][0]["chunk_file"].replace("chunk_0003.c", "CHUNK_0003.c")
    registry_path.write_bytes(_canonical_bytes(payload))
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.load_owner_snapshot(root, registry_path, parser)
    assert caught.value.refusal.code == "product_path_spelling_mismatch"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda bundle: replace(bundle, unit=[]),
        lambda bundle: replace(bundle, attempt=True),
        lambda bundle: replace(bundle, behavior_tier=[]),
        lambda bundle: replace(bundle, translation_units=[]),
        lambda bundle: replace(bundle, translation_units=(replace(bundle.translation_units[0], source="not-bytes"), *bundle.translation_units[1:])),
        lambda bundle: replace(bundle, translation_units=(replace(bundle.translation_units[0], source_sha256=[]), *bundle.translation_units[1:])),
        lambda bundle: replace(bundle, tool_world=replace(bundle.tool_world, identities=([],))),
        lambda bundle: replace(bundle, tool_world=replace(bundle.tool_world, inspect_argv=(1,) * 5)),
        lambda bundle: replace(bundle, tool_world=replace(bundle.tool_world, environment=(([], []),))),
        lambda bundle: replace(bundle, candidate=[]),
        lambda bundle: replace(bundle, window=[]),
    ],
)
def test_caller_bundle_and_tool_world_wrong_types_refuse_without_raw_exception(tmp_path: Path, mutation):
    snapshot = _load_snapshot(tmp_path.resolve())
    refusal = abi.plan_canonicalization(mutation(_bundle()), snapshot)
    assert isinstance(refusal, abi.AssemblyAbiRefusal)
    assert refusal.code in {"bundle_shape_invalid", "tool_world_invalid"}


def test_registry_and_owner_hardlinks_are_refused(tmp_path: Path):
    root = tmp_path.resolve()
    registry_path, parser = _write_product(root)
    registry_link = registry_path.with_name("registry-hardlink.json")
    registry_link.hardlink_to(registry_path)
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.load_owner_snapshot(root, registry_path, parser)
    assert caught.value.refusal.code == "product_path_hardlinked"
    registry_link.unlink()

    registry_path, parser = _write_product(root)
    owner = root / _registry(_fixture()["marker_wins"])["functions"][0]["chunk_file"]
    owner_link = owner.with_name("owner-hardlink.c")
    owner_link.hardlink_to(owner)
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.load_owner_snapshot(root, registry_path, parser)
    assert caught.value.refusal.code == "product_path_hardlinked"


def test_registry_owner_reparse_points_and_casefold_collisions_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    root = tmp_path.resolve()
    registry_path, parser = _write_product(root)
    original_lstat = abi.os.lstat

    def with_reparse(target: Path):
        def fake_lstat(path):
            result = original_lstat(path)
            if Path(path) == target:
                class ReparseStat:
                    st_mode = result.st_mode
                    st_file_attributes = 0x400
                    st_reparse_tag = 1

                return ReparseStat()
            return result

        return fake_lstat

    monkeypatch.setattr(abi.os, "lstat", with_reparse(registry_path))
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.load_owner_snapshot(root, registry_path, parser)
    assert caught.value.refusal.code == "product_path_special"

    payload = json.loads(registry_path.read_text())
    first_path = payload["functions"][0]["chunk_file"]
    owner = root / first_path
    monkeypatch.setattr(abi.os, "lstat", with_reparse(owner))
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.load_owner_snapshot(root, registry_path, parser)
    assert caught.value.refusal.code == "product_path_special"

    monkeypatch.setattr(abi.os, "lstat", original_lstat)
    directory, filename = first_path.rsplit("/", 1)
    payload["functions"][1]["chunk_file"] = directory + "/" + filename.upper().replace(".C", ".c")
    registry_path.write_bytes(_canonical_bytes(payload))
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.load_owner_snapshot(root, registry_path, parser)
    assert caught.value.refusal.code == "product_path_casefold_collision"


@pytest.mark.parametrize("race_call", [3, 11])
def test_stable_read_identity_race_refuses_through_public_adapter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, race_call: int
):
    root = tmp_path.resolve()
    registry_path, parser = _write_product(root)
    original = abi._identity
    calls = {"count": 0}

    def racing_identity(value):
        result = original(value)
        calls["count"] += 1
        if calls["count"] == race_call:
            return replace(result, mtime_ns=result.mtime_ns + 1)
        return result

    monkeypatch.setattr(abi, "_identity", racing_identity)
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.load_owner_snapshot(root, registry_path, parser)
    assert caught.value.refusal.code == "stable_read_race"


def test_owner_snapshot_reads_each_shared_chunk_once_and_binds_one_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path.resolve()
    registry_path, parser = _write_product(root)
    document = json.loads(registry_path.read_text(encoding="utf-8"))
    first, second = document["functions"][:2]
    shared_relpath = "research/decomp/ghidra-export/shared.c"
    first["chunk_file"] = shared_relpath
    first["line_range"] = [1, 2]
    first["loc"] = 2
    second["chunk_file"] = shared_relpath
    second["line_range"] = [3, 4]
    second["loc"] = 2
    rows = _fixture()["marker_wins"]
    shared = root / shared_relpath
    shared.write_bytes(
        f'// ==== {rows[0]["marker"]}  {rows[0]["name"]} ====\nvoid {rows[0]["name"]}(int value) {{ (void)value; }}\n'
        f'// ==== {rows[1]["marker"]}  {rows[1]["name"]} ====\nvoid {rows[1]["name"]}(int value) {{ (void)value; }}\n'.encode()
    )
    index = root / "research/decomp/ghidra-export/_index.tsv"
    index.write_text(
        "address\tname\tchunk_file\n"
        + "".join(
            f'{row["marker"]}\t{row["name"]}\t{("shared.c" if ordinal < 2 else row["chunk"])}\n'
            for ordinal, row in enumerate(rows)
        ),
        encoding="utf-8",
        newline="",
    )
    registry_path.write_bytes(_canonical_bytes(document))
    original = abi._stable_read
    calls = 0

    def counting(path: Path, **kwargs):
        nonlocal calls
        if Path(path) == shared:
            calls += 1
        return original(path, **kwargs)

    monkeypatch.setattr(abi, "_stable_read", counting)
    snapshot = abi.load_owner_snapshot(root, registry_path, parser)
    assert calls == 1
    shared_bindings = [item for item in snapshot.bindings if item.chunk_file == shared_relpath]
    assert len(shared_bindings) == 2
    assert len({(item.source.file_sha256, item.source.identity) for item in shared_bindings}) == 1


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("symbol", []),
        ("spelled_function_type", []),
        ("spelled_parameter_types", []),
        ("spelled_parameter_types", ([],)),
        ("prototype_kind", []),
        ("variadic", []),
        ("canonical_prototype", []),
        ("abi_tuple", object()),
        ("abi_tuple.return_type", []),
        ("abi_tuple.parameter_types", []),
        ("abi_tuple.parameter_types", ([],)),
        ("abi_tuple.prototype_kind", []),
        ("abi_tuple.variadic", []),
        ("abi_tuple.abi_tuple_schema", []),
        ("abi_tuple.calling_convention", []),
        ("abi_probe_evidence", object()),
        ("abi_probe_evidence.parameter_source_size", []),
        ("abi_probe_evidence.parameter_source_sha256", []),
        ("abi_probe_evidence.adjusted_parameters", []),
        ("abi_probe_evidence.adjusted_parameters.member", object()),
        ("abi_probe_evidence.adjusted_parameters.ordinal", []),
        ("abi_probe_evidence.adjusted_parameters.observed_adjusted_qual_type", []),
        ("abi_probe_evidence.adjusted_parameters.source_size", []),
        ("abi_probe_evidence.adjusted_parameters.source_sha256", []),
        ("abi_probe_evidence.adjusted_parameters.desugared_qual_type", []),
        ("abi_probe_evidence.return_source_size", []),
        ("abi_probe_evidence.return_source_sha256", []),
        ("abi_probe_evidence.abi_probe_schema", []),
        ("attributes", []),
        ("attributes", ([],)),
        ("calling_convention", []),
        ("declarator_ast_schema", []),
    ],
)
def test_owner_parser_nested_projection_member_types_refuse_typed(tmp_path: Path, path: str, value: object):
    malformed = _malformed_projection(path, value)

    class MalformedParser(FakeParser):
        @staticmethod
        def _projection(fragment: bytes, symbol: str) -> abi.DeclaratorProjection:
            return malformed

    registry_path, parser = _write_product(tmp_path.resolve(), parser=MalformedParser())
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.load_owner_snapshot(tmp_path.resolve(), registry_path, parser)
    assert caught.value.refusal.code == "owner_declarator_parser_fault"


@pytest.mark.parametrize(
    ("prototype_kind", "parameter_types", "variadic"),
    [
        ("void", ("int",), False),
        ("unspecified", ("int",), False),
        ("prototype", (), False),
        ("void", (), True),
        ("unspecified", (), True),
    ],
)
def test_owner_parser_refuses_prototype_kind_arity_and_variadic_contradictions(
    tmp_path: Path,
    prototype_kind: str,
    parameter_types: tuple[str, ...],
    variadic: bool,
):
    base = FakeParser._projection(b"void zz_00262b4_(int);", "zz_00262b4_")
    tuple_value = abi.AbiTuple("void", parameter_types, prototype_kind, variadic)
    malformed = replace(
        base,
        spelled_parameter_types=parameter_types,
        prototype_kind=prototype_kind,
        variadic=variadic,
        abi_tuple=tuple_value,
    )

    class MalformedParser(FakeParser):
        @staticmethod
        def _projection(fragment: bytes, symbol: str) -> abi.DeclaratorProjection:
            return replace(malformed, symbol=symbol)

    registry_path, parser = _write_product(tmp_path.resolve(), parser=MalformedParser())
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.load_owner_snapshot(tmp_path.resolve(), registry_path, parser)
    assert caught.value.refusal.code == "owner_declarator_parser_fault"


def test_owner_parser_refuses_adjusted_parameter_evidence_that_disagrees_with_tuple(tmp_path: Path):
    base = FakeParser._projection(b"void zz_00262b4_(int);", "zz_00262b4_")
    adjusted = abi.AdjustedParameterEvidence(0, "int", 1, "a" * 64, "float *")
    malformed = replace(
        base,
        abi_probe_evidence=replace(base.abi_probe_evidence, adjusted_parameters=(adjusted,)),
    )

    class MalformedParser(FakeParser):
        @staticmethod
        def _projection(fragment: bytes, symbol: str) -> abi.DeclaratorProjection:
            return replace(malformed, symbol=symbol)

    registry_path, parser = _write_product(tmp_path.resolve(), parser=MalformedParser())
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.load_owner_snapshot(tmp_path.resolve(), registry_path, parser)
    assert caught.value.refusal.code == "owner_declarator_parser_fault"


def test_plan_is_bundle_wide_atomic_verbatim_preserving_and_deterministic(tmp_path: Path):
    snapshot = _load_snapshot(tmp_path.resolve())
    bundle = _bundle()
    first = abi.plan_canonicalization(bundle, snapshot)
    second = abi.plan_canonicalization(bundle, snapshot)
    assert isinstance(first, abi.CanonicalizationPlan)
    assert first == second
    assert first.receipt.sha256 == second.receipt.sha256
    assert len(first.translation_units) == 5
    assert len(first.compatibility_checks) == 4
    assert [item.source_relpath for item in first.compatibility_checks] == [
        "synthetic-candidate/gnt4_shim.h",
        "synthetic-candidate/unit.c",
        "synthetic-window-0/gnt4_shim.h",
        "synthetic-window-1/gnt4_shim.h",
    ]
    assert any(check.owner_abi_tuple_sha256 != check.variant_abi_tuple_sha256 and check.result == "compatible" for check in first.compatibility_checks)
    original = bundle.translation_units[-1].source
    derived = first.translation_units[-1].derived_source
    marker = b"/* ==== VERBATIM:"
    assert original[original.index(marker) :] == derived[derived.index(marker) :]
    assert b"void zz_00262b4_(int);" in derived
    assert all(plan.object_relpath.endswith(".o") for plan in first.translation_units)


@pytest.mark.parametrize(
    "mutation",
    ["compatible_type", "source_type", "source_bytes", "source_sha256", "parser_identity_sha256"],
)
def test_plan_refuses_crossed_compatibility_probe_evidence_before_receipt(tmp_path: Path, mutation: str):
    class MaliciousCompatibilityParser(FakeParser):
        def compatibility(
            self,
            left: abi.DeclaratorProjection,
            right: abi.DeclaratorProjection,
        ) -> abi.CompatibilityProbe:
            probe = super().compatibility(left, right)
            if mutation == "compatible_type":
                return replace(probe, compatible=1)
            if mutation == "source_type":
                return replace(probe, source=[])
            if mutation == "source_bytes":
                return replace(probe, source=b"x")
            if mutation == "source_sha256":
                return replace(probe, source_sha256="b" * 64)
            return replace(probe, parser_identity_sha256="c" * 64)

    registry_path, parser = _write_product(tmp_path.resolve(), parser=MaliciousCompatibilityParser())
    snapshot = abi.load_owner_snapshot(tmp_path.resolve(), registry_path, parser)
    refusal = abi.plan_canonicalization(_bundle(), snapshot)
    assert isinstance(refusal, abi.AssemblyAbiRefusal)
    assert refusal.code == "declarator_parser_fault"


@pytest.mark.parametrize(
    "mutation",
    [
        "probe_source",
        "owner_prototype",
        "variant_prototype",
        "probe_source_size",
        "probe_source_sha256",
        "parser_identity_sha256",
        "receipt_parser_identity",
        "receipt_tool_world",
    ],
)
def test_revalidation_repeats_exact_compatibility_pair_and_parser_tool_binding(tmp_path: Path, mutation: str):
    plan = abi.plan_canonicalization(_bundle(), _load_snapshot(tmp_path.resolve()))
    assert isinstance(plan, abi.CanonicalizationPlan)
    receipt = plan.receipt
    evidence = receipt.compatibility_checks[0]
    if mutation == "probe_source":
        evidence = replace(evidence, _probe_source=b"x")
    elif mutation == "owner_prototype":
        evidence = replace(evidence, _owner_prototype="void zz_00262b4_(float);")
    elif mutation == "variant_prototype":
        evidence = replace(evidence, _variant_prototype="void zz_00262b4_(float);")
    elif mutation == "probe_source_size":
        evidence = replace(evidence, probe_source_size=evidence.probe_source_size + 1)
    elif mutation == "probe_source_sha256":
        evidence = replace(evidence, probe_source_sha256="b" * 64)
    elif mutation == "parser_identity_sha256":
        evidence = replace(evidence, parser_identity_sha256="c" * 64)
    elif mutation == "receipt_parser_identity":
        receipt = replace(receipt, parser_identity=replace(receipt.parser_identity, binary_sha256="d" * 64))
    else:
        identities = tuple(
            replace(item, file_sha256="e" * 64) if item.role == "clang" else item
            for item in receipt.tool_world.identities
        )
        receipt = replace(receipt, tool_world=replace(receipt.tool_world, identities=identities))
    if mutation not in {"receipt_parser_identity", "receipt_tool_world"}:
        receipt = replace(receipt, compatibility_checks=(evidence, *receipt.compatibility_checks[1:]))
    refusal = abi.revalidate_receipt(receipt, tmp_path.resolve(), abi.ReceiptObservation.from_plan(plan))
    assert isinstance(refusal, abi.AssemblyAbiRefusal)
    assert refusal.code == "canonicalization_receipt_invalid"


def test_plan_refuses_pointee_qualifier_difference_but_accepts_top_level_qualifiers(tmp_path: Path):
    snapshot = _load_snapshot(tmp_path.resolve())
    base = _bundle()
    rewritten = []
    for item in base.translation_units:
        header = item.header.replace(b"const int", b"int *").replace(b"(int)", b"(int *)")
        source = item.source.replace(b"void zz_00262b4_(int);", b"void zz_00262b4_(int *);")
        rewritten.append(
            replace(
                item,
                header=header,
                header_sha256=hashlib.sha256(header).hexdigest(),
                source=source,
                source_sha256=hashlib.sha256(source).hexdigest(),
            )
        )
    bundle = replace(base, translation_units=tuple(rewritten))
    owner = snapshot.owner_index["zz_00262b4_"][0]
    pointer_projection = abi.DeclaratorProjection.synthetic(
        owner.symbol, f"void {owner.symbol}(int *);", "void", ("int *",)
    )
    snapshot = snapshot.with_owner(
        owner.symbol,
        (replace(owner, normalized_prototype=pointer_projection.canonical_prototype, projection=pointer_projection),),
    )
    top_level = replace(
        bundle.translation_units[0],
        header=b"extern void zz_00262b4_(int *const);\n",
        header_sha256=hashlib.sha256(b"extern void zz_00262b4_(int *const);\n").hexdigest(),
    )
    top_plan = abi.plan_canonicalization(replace(bundle, translation_units=(top_level, *bundle.translation_units[1:])), snapshot)
    assert isinstance(top_plan, abi.CanonicalizationPlan)

    pointee_bytes = b"extern void zz_00262b4_(const int *);\n"
    pointee = replace(top_level, header=pointee_bytes, header_sha256=hashlib.sha256(pointee_bytes).hexdigest())
    refusal = abi.plan_canonicalization(replace(bundle, translation_units=(pointee, *bundle.translation_units[1:])), snapshot)
    assert isinstance(refusal, abi.AssemblyAbiRefusal)
    assert refusal.code == "owner_variant_abi_incompatible"


def test_plan_refuses_zero_and_two_owner_cases_without_partial_plan(tmp_path: Path):
    snapshot = _load_snapshot(tmp_path.resolve())
    base = _bundle()
    for symbol, expected in ((_fixture()["conflicts"]["zero_owner_symbol"], "owner_missing"), (_fixture()["conflicts"]["two_owner_symbol"], "owner_ambiguous")):
        header = f"extern void {symbol}(int);\n".encode()
        changed = replace(base.translation_units[0], header=header, header_sha256=hashlib.sha256(header).hexdigest())
        current = snapshot
        if expected == "owner_ambiguous":
            owner = snapshot.bindings[0]
            current = snapshot.with_owner(symbol, (replace(owner, symbol=symbol), replace(owner, symbol=symbol, unit="other-owner")))
        refusal = abi.plan_canonicalization(replace(base, translation_units=(changed, *base.translation_units[1:])), current)
        assert isinstance(refusal, abi.AssemblyAbiRefusal)
        assert refusal.code == expected


def test_plan_discovers_body_only_reference_and_derives_every_header(tmp_path: Path):
    snapshot = _load_snapshot(tmp_path.resolve())
    bundle = _bundle()
    stripped = []
    for item in bundle.translation_units:
        source = item.source
        if abi._VERBATIM_MARKER in source:
            source = source[source.index(abi._VERBATIM_MARKER) :]
        stripped.append(
            replace(
                item,
                source=source,
                source_sha256=hashlib.sha256(source).hexdigest(),
                header=b"",
                header_sha256=hashlib.sha256(b"").hexdigest(),
            )
        )
    plan = abi.plan_canonicalization(replace(bundle, translation_units=tuple(stripped)), snapshot)
    assert isinstance(plan, abi.CanonicalizationPlan)
    assert [item.symbol for item in plan.owner_bindings] == ["zz_00262b4_"]
    assert plan.compatibility_checks == ()
    assert all(b"void zz_00262b4_(int);\n" in item.derived_header for item in plan.translation_units)


def test_plan_preserves_selected_direct_definition_and_refuses_two_definitions(tmp_path: Path):
    snapshot = _load_snapshot(tmp_path.resolve())
    bundle = _bundle()
    definition = b"void zz_00262b4_(int value) { /* exact body */ (void)value; }\n"
    first = replace(
        bundle.translation_units[0],
        source=definition,
        source_sha256=hashlib.sha256(definition).hexdigest(),
    )
    one = abi.plan_canonicalization(replace(bundle, translation_units=(first, *bundle.translation_units[1:])), snapshot)
    assert isinstance(one, abi.CanonicalizationPlan)
    assert one.translation_units[0].derived_source == definition
    assert any(item.source_relpath == first.source_relpath for item in one.compatibility_checks)

    second = replace(
        bundle.translation_units[1],
        source=definition,
        source_sha256=hashlib.sha256(definition).hexdigest(),
    )
    refusal = abi.plan_canonicalization(
        replace(bundle, translation_units=(first, second, *bundle.translation_units[2:])), snapshot
    )
    assert isinstance(refusal, abi.AssemblyAbiRefusal)
    assert refusal.code == "selected_direct_definition_ambiguous"


def test_registryless_identical_declarations_dedup_semantically_but_divergence_refuses(tmp_path: Path):
    snapshot = _load_snapshot(tmp_path.resolve())
    base = _bundle()
    identical = b"extern void ordinary_symbol(int);\n"
    units = tuple(
        replace(item, header=identical, header_sha256=hashlib.sha256(identical).hexdigest())
        if item.ordinal < 2
        else item
        for item in base.translation_units
    )
    plan = abi.plan_canonicalization(replace(base, translation_units=units), snapshot)
    assert isinstance(plan, abi.CanonicalizationPlan)
    divergent = b"extern void ordinary_symbol(const int *);\n"
    changed = replace(units[1], header=divergent, header_sha256=hashlib.sha256(divergent).hexdigest())
    refusal = abi.plan_canonicalization(replace(base, translation_units=(units[0], changed, *units[2:])), snapshot)
    assert isinstance(refusal, abi.AssemblyAbiRefusal)
    assert refusal.code == "registryless_declaration_divergence"

    sdk_a = b"extern void gnt4_external(int);\n"
    sdk_b = b"extern void gnt4_external(const int *);\n"
    exempt = (
        replace(base.translation_units[0], header=sdk_a, header_sha256=hashlib.sha256(sdk_a).hexdigest()),
        replace(base.translation_units[1], header=sdk_b, header_sha256=hashlib.sha256(sdk_b).hexdigest()),
        *base.translation_units[2:],
    )
    assert isinstance(abi.plan_canonicalization(replace(base, translation_units=exempt), snapshot), abi.CanonicalizationPlan)


def test_owner_and_relevant_catalog_digests_ignore_variants_and_unrelated_records(tmp_path: Path):
    snapshot = _load_snapshot(tmp_path.resolve())
    base = _bundle()
    first = abi.plan_canonicalization(base, snapshot)
    assert isinstance(first, abi.CanonicalizationPlan)
    top = b"extern void zz_00262b4_(const int);\n"
    changed_item = replace(base.translation_units[1], header=top, header_sha256=hashlib.sha256(top).hexdigest())
    changed = abi.plan_canonicalization(
        replace(base, translation_units=(base.translation_units[0], changed_item, *base.translation_units[2:])), snapshot
    )
    assert isinstance(changed, abi.CanonicalizationPlan)
    assert changed.owner_bindings[0].owner_binding_sha256 == first.owner_bindings[0].owner_binding_sha256
    assert changed.receipt.relevant_catalog_sha256 == first.receipt.relevant_catalog_sha256
    assert changed.receipt.tool_world_sha256 == first.receipt.tool_world_sha256
    assert changed.receipt.assembly_world_sha256 != first.receipt.assembly_world_sha256
    unused = replace(snapshot.bindings[-1], symbol="zz_0abcdef_", unit="unrelated")
    expanded = snapshot.with_owner(unused.symbol, (unused,))
    expanded_plan = abi.plan_canonicalization(base, expanded)
    assert isinstance(expanded_plan, abi.CanonicalizationPlan)
    assert expanded_plan.receipt.relevant_catalog_sha256 == first.receipt.relevant_catalog_sha256


def test_compatibility_evidence_and_discarded_variants_are_exact_and_sorted(tmp_path: Path):
    snapshot = _load_snapshot(tmp_path.resolve())
    plan = abi.plan_canonicalization(_bundle(), snapshot)
    assert isinstance(plan, abi.CanonicalizationPlan)
    keys = [(item.symbol, item.source_relpath, item.variant_prototype_sha256) for item in plan.compatibility_checks]
    assert keys == sorted(keys)
    discarded = {(item.symbol, item.source_relpath, item.prototype_sha256) for item in plan.discarded_variants}
    assert discarded == set(keys)
    assert [item.source_relpath for item in plan.compatibility_checks] == [
        "synthetic-candidate/gnt4_shim.h",
        "synthetic-candidate/unit.c",
        "synthetic-window-0/gnt4_shim.h",
        "synthetic-window-1/gnt4_shim.h",
    ]
    owner = snapshot.owner_index["zz_00262b4_"][0].projection
    for item in plan.compatibility_checks:
        assert item.compatibility_schema == 1
        assert item.result == "compatible"
        variant_text = (
            "void zz_00262b4_(const int);"
            if item.source_relpath == "synthetic-window-0/gnt4_shim.h"
            else "void zz_00262b4_(int);"
        )
        variant = snapshot.declarator_parser.parse_declaration(variant_text.encode(), "zz_00262b4_")
        probe = abi.build_compatibility_source(owner.canonical_prototype, variant.canonical_prototype)
        assert (item.probe_source_size, item.probe_source_sha256) == (len(probe), hashlib.sha256(probe).hexdigest())
        assert item.parser_identity_sha256 == snapshot.parser_identity.sha256


def test_planning_is_pure_and_refusal_has_no_filesystem_or_adapter_side_effects(tmp_path: Path):
    snapshot = _load_snapshot(tmp_path.resolve())
    bundle = _bundle()
    before = sorted((path.relative_to(tmp_path).as_posix(), path.read_bytes()) for path in tmp_path.rglob("*") if path.is_file())
    result = abi.plan_canonicalization(bundle, snapshot)
    after = sorted((path.relative_to(tmp_path).as_posix(), path.read_bytes()) for path in tmp_path.rglob("*") if path.is_file())
    assert isinstance(result, abi.CanonicalizationPlan)
    assert before == after

    invalid = replace(bundle, attempt=0)
    refused = abi.plan_canonicalization(invalid, snapshot)
    final = sorted((path.relative_to(tmp_path).as_posix(), path.read_bytes()) for path in tmp_path.rglob("*") if path.is_file())
    assert isinstance(refused, abi.AssemblyAbiRefusal)
    assert refused.code == "bundle_shape_invalid"
    assert final == before


def test_planning_refusal_precedes_parser_adapter_and_clang_identity_is_cross_bound(tmp_path: Path):
    snapshot = _load_snapshot(tmp_path.resolve())

    class ExplodingParser(FakeParser):
        def parse_definition(self, source: bytes, symbol: str) -> abi.DeclaratorProjection:
            raise AssertionError("parser adapter must not run")

        def parse_declaration(self, source: bytes, symbol: str) -> abi.DeclaratorProjection:
            raise AssertionError("parser adapter must not run")

        def compatibility(
            self, left: abi.DeclaratorProjection, right: abi.DeclaratorProjection
        ) -> abi.CompatibilityProbe:
            raise AssertionError("parser adapter must not run")

    exploding = replace(snapshot, declarator_parser=ExplodingParser())
    early = abi.plan_canonicalization(replace(_bundle(), attempt=0), exploding)
    assert isinstance(early, abi.AssemblyAbiRefusal)
    assert early.code == "bundle_shape_invalid"

    bundle = _bundle()
    for field, value in (
        ("resolved_path", "D:/synthetic/other-clang.exe"),
        ("file_sha256", "a" * 64),
        ("version_sha256", "b" * 64),
    ):
        identities = tuple(
            replace(identity, **{field: value}) if identity.role == "clang" else identity
            for identity in bundle.tool_world.identities
        )
        crossed = replace(bundle, tool_world=replace(bundle.tool_world, identities=identities))
        refusal = abi.plan_canonicalization(crossed, exploding)
        assert isinstance(refusal, abi.AssemblyAbiRefusal)
        assert refusal.code == "parser_tool_identity_mismatch"


def test_tool_world_has_no_forbidden_assembly_world_alias_or_legacy_surface():
    assert "assembly_world_sha256" not in abi.ToolWorld.__dict__
    assert not [name for name in vars(abi) if name.startswith(("_Legacy", "_legacy_"))]


def test_internal_looking_nonfunction_identifiers_do_not_trigger_owner_resolution(tmp_path: Path):
    snapshot = _load_snapshot(tmp_path.resolve())
    bundle = _bundle()
    units = []
    for item in bundle.translation_units:
        source = b"struct Holder { int zz_0000001_; };\nint ordinary(void){int zz_0000001_=1; return zz_0000001_;}\n"
        units.append(
            replace(
                item,
                source=source,
                source_sha256=hashlib.sha256(source).hexdigest(),
                header=b"",
                header_sha256=hashlib.sha256(b"").hexdigest(),
            )
        )
    plan = abi.plan_canonicalization(replace(bundle, translation_units=tuple(units)), snapshot)
    assert isinstance(plan, abi.CanonicalizationPlan)
    assert plan.owner_bindings == ()

    call = b"int ordinary(void){return zz_0000001_();}\n"
    first = replace(units[0], source=call, source_sha256=hashlib.sha256(call).hexdigest())
    refusal = abi.plan_canonicalization(replace(bundle, translation_units=(first, *units[1:])), snapshot)
    assert isinstance(refusal, abi.AssemblyAbiRefusal)
    assert refusal.code == "owner_missing"


_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_NO_RETRY = abi.RetryHistory(None, 0)


def _planned_objects(
    plan: abi.CanonicalizationPlan,
    *,
    defined: dict[int, tuple[abi.SymbolObservation, ...]] | None = None,
    imported: dict[int, tuple[abi.SymbolObservation, ...]] | None = None,
) -> tuple[abi.ObjectObservation, ...]:
    defined = defined or {}
    imported = imported or {}
    result = []
    for item in plan.translation_units:
        payload = f"object-{item.ordinal}-{item.unit}".encode()
        result.append(
            abi.ObjectObservation(
                item.ordinal,
                item.unit,
                item.object_relpath,
                len(payload),
                hashlib.sha256(payload).hexdigest(),
                defined.get(item.ordinal, ()),
                imported.get(item.ordinal, ()),
                abi.InspectorReceipt(True, True, 0, _EMPTY_SHA256, _EMPTY_SHA256, "object-inspector-v1", None, None),
            )
        )
    return tuple(result)


def _child(
    plan: abi.CanonicalizationPlan,
    objects: tuple[abi.ObjectObservation, ...],
    stage: str,
    ordinal: int,
    *,
    terminal: bool,
    state: str = "passed",
    symbol: str | None = None,
    fault_class: str | None = None,
) -> abi.StageChildReceipt:
    item = plan.translation_units[ordinal]
    execution_completed = state != "faulted"
    diagnostic = None if state == "passed" else hashlib.sha256(f"{stage}-{state}-{ordinal}".encode()).hexdigest()
    return abi.StageChildReceipt(
        ordinal,
        ordinal,
        item.unit,
        stage,
        terminal,
        item.compile_argv if stage == "compile" else plan.bundle.tool_world.inspect_argv[ordinal],
        item.object_relpath,
        item.derived_source_sha256 if stage == "compile" else objects[ordinal].object_sha256,
        objects[ordinal].object_sha256,
        state,
        execution_completed,
        0 if state == "passed" else (1 if state == "failed" else None),
        0,
        _EMPTY_SHA256,
        0,
        _EMPTY_SHA256,
        "emcc-v1" if stage == "compile" else "object-inspector-v1",
        diagnostic,
        symbol,
        fault_class,
    )


def _child_stage(stage: str, children: tuple[abi.StageChildReceipt, ...]) -> abi.StageReceipt:
    terminal = children[-1]
    return abi.StageReceipt(
        stage,
        terminal.state,
        terminal.execution_completed,
        terminal.exit_status,
        abi.stage_stream_sha256(stage, "stdout", children),
        abi.stage_stream_sha256(stage, "stderr", children),
        terminal.parser_version,
        terminal.diagnostic_sha256,
        terminal.symbol,
        tuple(item.object_relpath for item in children),
        terminal.fault_class,
        children,
        abi.stage_child_transcript_sha256(stage, children),
    )


def _single_stage(
    plan: abi.CanonicalizationPlan,
    stage: str,
    *,
    state: str = "passed",
    symbol: str | None = None,
    fault_class: str | None = None,
) -> abi.StageReceipt:
    diagnostic = None if state == "passed" else hashlib.sha256(f"{stage}-{state}".encode()).hexdigest()
    return abi.StageReceipt(
        stage,
        state,
        state != "faulted",
        0 if state == "passed" else (1 if state == "failed" else None),
        _EMPTY_SHA256 if state != "faulted" else None,
        _EMPTY_SHA256 if state != "faulted" else None,
        f"{stage}-parser-v1",
        diagnostic,
        symbol,
        tuple(item.object_relpath for item in plan.translation_units) if stage == "link" else (),
        fault_class,
    )


def _tool_outcome(
    plan: abi.CanonicalizationPlan,
    objects: tuple[abi.ObjectObservation, ...],
    *,
    terminal_stage: str | None = None,
    terminal_state: str = "failed",
    symbol: str | None = None,
    fault_class: str | None = None,
) -> abi.ToolOutcome:
    receipts = []
    stopped = False
    for stage in ("compile", "inspect", "link", "instantiate", "smoke"):
        if stopped:
            receipts.append(abi.StageReceipt.not_run(stage))
            continue
        state = terminal_state if stage == terminal_stage else "passed"
        if stage in {"compile", "inspect"}:
            limit = 1 if stage == terminal_stage else len(plan.translation_units)
            children = tuple(
                _child(
                    plan,
                    objects,
                    stage,
                    index,
                    terminal=index == limit - 1,
                    state=state if index == limit - 1 else "passed",
                    symbol=symbol if stage == terminal_stage and index == limit - 1 else None,
                    fault_class=fault_class if stage == terminal_stage and index == limit - 1 else None,
                )
                for index in range(limit)
            )
            receipts.append(_child_stage(stage, children))
        else:
            receipts.append(
                _single_stage(
                    plan,
                    stage,
                    state=state,
                    symbol=symbol if stage == terminal_stage else None,
                    fault_class=fault_class if stage == terminal_stage else None,
                )
            )
        stopped = stage == terminal_stage
    return abi.ToolOutcome(tuple(receipts))


def _precompile_check(plan: abi.CanonicalizationPlan, root: Path) -> abi.RevalidationCheck:
    checked = abi.revalidate_receipt(plan.receipt, root, abi.ReceiptObservation.from_plan(plan))
    assert isinstance(checked, abi.RevalidatedReceipt)
    return checked.check


def _finalize_draft(
    plan: abi.CanonicalizationPlan,
    draft: abi.CompositionDraft,
    root: Path,
    history: abi.RetryHistory = _NO_RETRY,
) -> abi.CompositionResult:
    precompile = _precompile_check(plan, root)
    if draft.analyzed_outcome.classification == "pass":
        checked = abi.revalidate_receipt(draft.composition_receipt, root, abi.ReceiptObservation.from_draft(draft))
        assert isinstance(checked, abi.RevalidatedReceipt)
        decision = abi.PrePublicationDecision.passed(checked.check)
    else:
        decision = abi.PrePublicationDecision.not_reached()
    return abi.finalize_composition(abi.PostAnalysisInput(draft, precompile, decision, history))


def _normative_child(stage: str, ordinal: int, state: str, terminal: bool) -> abi.StageChildReceipt:
    stdout = f"{stage}:stdout:{ordinal}:{state}\n".encode()
    stderr = f"{stage}:stderr:{ordinal}:{state}\n".encode()
    input_sha = hashlib.sha256(f"{stage}:input:{ordinal}".encode()).hexdigest()
    path = f"obj/{ordinal}.o"
    return abi.StageChildReceipt(
        ordinal,
        ordinal,
        f"synthetic-u{ordinal}",
        stage,
        terminal,
        ("emcc", "-c", f"u{ordinal}.c", "-o", path) if stage == "compile" else ("llvm-nm", path),
        path,
        input_sha,
        hashlib.sha256(f"compile:object:{ordinal}".encode()).hexdigest()
        if stage == "compile" and state == "passed"
        else (input_sha if stage == "inspect" else None),
        state,
        state != "faulted",
        0 if state == "passed" else (2 if state == "failed" else None),
        len(stdout),
        hashlib.sha256(stdout).hexdigest(),
        len(stderr),
        hashlib.sha256(stderr).hexdigest(),
        f"synthetic-{stage}-parser-v1",
        None if state == "passed" else hashlib.sha256(f"{stage}:diagnostic:{ordinal}:{state}".encode()).hexdigest(),
        None if state == "passed" else "bad_symbol",
        "timeout" if state == "faulted" else None,
    )


@pytest.mark.parametrize(
    ("stage", "states", "size", "transcript", "stdout", "stderr"),
    [
        ("compile", "passed", 793, "79c076271b1b98f935eaa39743cb853295d3b785d91b7dfe90d345f6f7479e4f", "d33a223670cffdc68f5f51af4d3b821abe3fa1fa703a485b7b7a5959c35ac27f", "b116c438f4bcea2ac63b2ebfddaa247a3e1d72eeb3564ffc5262a9072c82d970"),
        ("compile", "failed", 801, "3af9ef3f51f1a70c2550c1a5b6f48b3c2e82f3aacf81ff42b3add58f2ac225b2", "2ef81149897af5e05ba6bf4f1a697e68a07f26eb2d7dc86430583b0d3c7d576a", "f9383afa6d133c9e2c30a3d453510857fb6c0f587ab1094bb3a75dc2925cd2d6"),
        ("compile", "faulted", 811, "7b8afc5d68acf223f4ed13075a538e12853263b047800a4a5793a766217b4bd7", "48d2eca464c3b455ab6eaa0841a1e5e06883866df0928e10615429d279a3d021", "86a2506daa0b66a6c44105ff9cae49e6a7bf1594bf22639cbc2b8c09d2dd2b3f"),
        ("compile", "passed,passed", 1520, "13c20432c56b218755e17b2e57cf1dad1df16177e50afb8abd3849e412d6f80c", "387b91409407d15b6eb8425ad050fcdddd4489b665b30a760e88c2972790e15b", "6704730c1fc47c1c1b716767500a880bae53f228313af769228d2e50e52dcd38"),
        ("compile", "passed,failed", 1528, "8da406382d8272ba2a8b50367baa72977141ed365e5e8d61b7b810accbed313c", "7e3f04cb5c417c16e04458cf643be87d6c006d0b505f9e5cade8f6d4127fd111", "9aa670d5a0a5efe680d8905cc8934166c349edda99674d96513b3f10aff13e5e"),
        ("compile", "passed,faulted", 1538, "660f97017cfbf93fd805ceac8d2f0a32aaa5fe4d510bbf7d00d96aa1795d2ad8", "2c07c78ecbb1d7315d040bd5f251df6e115805d9c57dcf73e1735ca598c97808", "f6185a8b985f964e4befb06740509d581ee2173e4ef204cde557b9c7cb5fa163"),
        ("inspect", "passed", 779, "0e306c34ee6daf6b7c031d4f94b26db064e41836a22cfa022d24c3252e144ed4", "f046343904baef900e5b5279edfe4b4b0b823489a76d4c772cb43f8fe2bf6489", "8a3a35e24d043e63dec034f478051c5cae3784c838fac7cc05d4a5b64cdd1c57"),
        ("inspect", "failed", 849, "ff6ef02cf81a1c0b04b1ff65c5258c73c3df390f13797468a7c41a7ed03b300d", "f43dc2f2bbb805194e45dcf50947dd3d36fde9c7d4af3da897627b333e88c872", "f91dd727681720968f654926d7056963c7e21055e53f3c5e9994aad5fd5cd7bd"),
        ("inspect", "faulted", 859, "b1a469e9c67b44b286cabcfa78d1d7d47fdf98a9580889b912221e0bdc03abfb", "5f0939e61fb6b572e395fd18c936877f62f62fe11507195b36338bd09edfb54d", "6e25aea57e357d374b4016e5fab61b9b639dda3ad851f5e458f7b349b52c7e27"),
        ("inspect", "passed,passed", 1492, "41210c875d75be710ef3974f31083c50b1a197131f70a25e7ae3282026cb47e1", "21830a6728634ebfc130a3095fccdf463f388584fa2d48835b292bb3122ec00f", "19da7f3fb33a901ad9d4595fb9e3c8c4268479321cb4bacf2dc16c85194633ed"),
        ("inspect", "passed,failed", 1562, "26bda588a97ad331232122b4efc00502f1ec6fc456373be581dabcb64a867e19", "fb6fbf8f81ab217033a5cdaa87d5d33aac763912647f57aa64533d02c9f618de", "61481a06e7c22b650ede1dbecc148fb379e1b2ae8daacc7a26b3173677ecf91e"),
        ("inspect", "passed,faulted", 1572, "95e8fe238d044bd3da26b8b1573a1f9e117e4d529cbed356d6407e1c4f74108b", "05e648cd2fa28862a6ca4aac9d423aa4262536571917bafa2cd5f24d2c3e924e", "6026580853f11064c37617771fdfd791e1dfd4dc1aeea90486e5d938e4697bbf"),
    ],
)
def test_normative_stage_child_transcript_and_stream_vectors(stage, states, size, transcript, stdout, stderr):
    state_list = states.split(",")
    children = tuple(_normative_child(stage, index, state, index == len(state_list) - 1) for index, state in enumerate(state_list))
    transcript_bytes = _canonical_bytes(
        {"children": [item.to_dict() for item in children], "stage": stage, "stage_child_transcript_schema": 1}
    )
    assert (len(transcript_bytes), hashlib.sha256(transcript_bytes).hexdigest()) == (size, transcript)
    assert abi.stage_child_transcript_sha256(stage, children) == transcript
    assert abi.stage_stream_sha256(stage, "stdout", children) == stdout
    assert abi.stage_stream_sha256(stage, "stderr", children) == stderr
    abi._validate_stage_receipt(_child_stage(stage, children))


def test_tool_and_assembly_world_normative_vectors_and_independent_mutations():
    identities = tuple(
        abi.ToolIdentity(role, path, file_byte * 32, version_byte * 32)
        for role, path, file_byte, version_byte in (
            ("clang", "D:/synthetic/clang.exe", "11", "21"),
            ("emcc", "D:/synthetic/emcc.bat", "12", "22"),
            ("node", "D:/synthetic/node.exe", "13", "23"),
            ("object-inspector", "D:/synthetic/llvm-nm.exe", "14", "24"),
            ("smoke-script", "D:/synthetic/smoke.js", "15", "25"),
            ("wasm-ld", "D:/synthetic/wasm-ld.exe", "16", "26"),
        )
    )
    world = abi.ToolWorld(
        identities,
        (("emcc", "-c", "candidate.c", "-o", "candidate.o"),),
        (("llvm-nm", "candidate.o"),),
        ("emcc", "candidate.o", "-o", "candidate.wasm"),
        ("node", "instantiate.js", "candidate.wasm"),
        ("node", "smoke.js", "candidate.wasm"),
        (("EMSDK", "31" * 32),),
    )
    tool_bytes = _canonical_bytes(world._preimage())
    assert (len(tool_bytes), world.tool_world_sha256) == (
        1771,
        "1ce523c15a3d30aafba7e59d93848de812cb5225495175e3554fba3b8f89b5d7",
    )
    assembly = {
        "abi_probe_evidence_sha256s": [],
        "assembly_world_schema": 1,
        "candidate": {
            "artifact_relpath": "candidate/candidate.c",
            "artifact_sha256": "41" * 32,
            "artifact_size": 64,
            "header_sha256": "43" * 32,
            "source_sha256": "42" * 32,
        },
        "compatibility_checks": [],
        "implementation": {"assembly_module_revision": "synthetic-module-v1", "driver_revision": "synthetic-driver-v1"},
        "relevant_owner_bindings": [],
        "schema_versions": {
            "assembly_result_schema": 1,
            "canonicalization_schema": 1,
            "compatibility_schema": 1,
            "oracle_registry_schema": 1,
        },
        "tool_world_sha256": world.tool_world_sha256,
        "window": [],
    }
    assembly_bytes = _canonical_bytes(assembly)
    assert (len(assembly_bytes), hashlib.sha256(assembly_bytes).hexdigest()) == (
        776,
        "496bc357be857357f7377a63a012fc91491def0c3740460af6c7188792f130bc",
    )
    changed_identities = tuple(replace(item, version_sha256="27" * 32) if item.role == "node" else item for item in identities)
    changed_world = replace(world, identities=changed_identities)
    assert changed_world.tool_world_sha256 == "f8731b73c66514bf126ec2880e4ff3e4fb487d3d8314332332d1c514a0b897bf"
    changed_tool_assembly = {**assembly, "tool_world_sha256": changed_world.tool_world_sha256}
    assert hashlib.sha256(_canonical_bytes(changed_tool_assembly)).hexdigest() == "376296a0c2a54cfef787f7e9fabd5866aad97dcbbade954a87a306e3b93e27b6"
    changed_candidate = {**assembly, "candidate": {**assembly["candidate"], "artifact_sha256": "44" * 32}}
    assert hashlib.sha256(_canonical_bytes(changed_candidate)).hexdigest() == "c4ccdfaeda65f828060bb2acb693c8dc16478d85ce45018dd77a7b7f3366e059"


def test_bound_clang_hash_recheck_refuses_same_identity_different_bytes(monkeypatch: pytest.MonkeyPatch):
    identity = abi.StableFileIdentity(1, 2, 3, 1, 4, 5, 0)
    parser_identity = abi.ParserIdentity("D:/synthetic/clang.exe", "a" * 64, "b" * 64, 1)
    parser = abi.ClangDeclaratorParser(Path("D:/synthetic/clang.exe"), parser_identity, (), identity)
    changed = abi.StableBytes(b"evil", identity, "c" * 64)
    monkeypatch.setattr(abi, "_stable_read", lambda *args, **kwargs: changed)
    with pytest.raises(abi.AssemblyAbiError) as caught:
        parser.parse_declaration(b"void synthetic(void);", "synthetic")
    assert caught.value.refusal.code == "clang_identity_invalid"


@pytest.mark.parametrize(
    "receipt",
    [
        abi.InspectorReceipt(True, True, 0, _EMPTY_SHA256, _EMPTY_SHA256, "parser-v1", None, None),
        abi.InspectorReceipt(True, False, 2, _EMPTY_SHA256, _EMPTY_SHA256, "parser-v1", None, "a" * 64),
        abi.InspectorReceipt(False, False, None, None, _EMPTY_SHA256, "parser-v1", "timeout", "b" * 64),
    ],
)
def test_inspector_receipt_exact_three_member_truth_union(receipt: abi.InspectorReceipt):
    abi._validate_inspector_receipt(receipt)


@pytest.mark.parametrize(
    "receipt",
    [
        abi.InspectorReceipt(False, True, None, None, None, "parser-v1", "spawn", "a" * 64),
        abi.InspectorReceipt(True, True, 1, _EMPTY_SHA256, _EMPTY_SHA256, "parser-v1", None, None),
        abi.InspectorReceipt(True, False, 2, _EMPTY_SHA256, _EMPTY_SHA256, "parser-v1", "io", "a" * 64),
        abi.InspectorReceipt(False, False, 2, _EMPTY_SHA256, _EMPTY_SHA256, "parser-v1", "timeout", "a" * 64),
        abi.InspectorReceipt(False, False, None, None, None, "parser-v1", [], "a" * 64),
    ],
)
def test_inspector_receipt_crossed_truth_members_refuse_typed(receipt: abi.InspectorReceipt):
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi._validate_inspector_receipt(receipt)
    assert caught.value.refusal.code == "inspector_receipt_invalid"


@pytest.mark.parametrize(
    ("terminal_stage", "terminal_state"),
    [(None, "failed")]
    + [(stage, state) for stage in ("compile", "inspect", "link", "instantiate", "smoke") for state in ("failed", "faulted")],
)
def test_all_eleven_tool_outcome_state_vectors_are_closed(
    tmp_path: Path, terminal_stage: str | None, terminal_state: str
):
    plan = abi.plan_canonicalization(_bundle(), _load_snapshot(tmp_path.resolve()))
    assert isinstance(plan, abi.CanonicalizationPlan)
    objects = _planned_objects(plan)
    outcome = _tool_outcome(
        plan,
        objects,
        terminal_stage=terminal_stage,
        terminal_state=terminal_state,
        fault_class="timeout" if terminal_state == "faulted" else None,
    )
    state, terminal = abi._validate_tool_outcome(outcome, plan, {item.ordinal: item for item in objects})
    assert state == ("pass" if terminal_stage is None else terminal_state)
    assert (None if terminal is None else terminal.stage) == terminal_stage


def test_tool_outcome_complement_and_stage_child_crossings_refuse(tmp_path: Path):
    plan = abi.plan_canonicalization(_bundle(), _load_snapshot(tmp_path.resolve()))
    assert isinstance(plan, abi.CanonicalizationPlan)
    objects = _planned_objects(plan)
    passed = _tool_outcome(plan, objects)
    link_failed = _tool_outcome(plan, objects, terminal_stage="link")
    mutations = [
        abi.ToolOutcome(passed.receipts[:-1]),
        abi.ToolOutcome((*passed.receipts, passed.receipts[-1])),
        abi.ToolOutcome((passed.receipts[1], passed.receipts[0], *passed.receipts[2:])),
        abi.ToolOutcome((abi.StageReceipt.not_run("compile"), *passed.receipts[1:])),
        abi.ToolOutcome((*link_failed.receipts[:3], passed.receipts[3], link_failed.receipts[4])),
        abi.ToolOutcome((replace(passed.receipts[0], child_transcript_sha256="0" * 64), *passed.receipts[1:])),
        abi.ToolOutcome((replace(passed.receipts[0], named_object_relpaths=tuple(reversed(passed.receipts[0].named_object_relpaths))), *passed.receipts[1:])),
        abi.ToolOutcome((replace(passed.receipts[0], stdout_sha256="0" * 64), *passed.receipts[1:])),
    ]
    for outcome in mutations:
        with pytest.raises(abi.AssemblyAbiError):
            abi._validate_tool_outcome(outcome, plan, {item.ordinal: item for item in objects})


def test_compile_children_cover_exact_plan_prefix_and_cross_bind_inspected_objects(tmp_path: Path):
    plan = abi.plan_canonicalization(_bundle(), _load_snapshot(tmp_path.resolve()))
    assert isinstance(plan, abi.CanonicalizationPlan)
    objects = _planned_objects(plan)
    complete = _tool_outcome(plan, objects)

    shortened_children = complete.receipts[0].child_receipts[:-1]
    shortened = abi.ToolOutcome(
        (_child_stage("compile", tuple(replace(child, terminal=False) for child in shortened_children[:-1]) +
                      (replace(shortened_children[-1], terminal=True),)), *complete.receipts[1:])
    )

    skipped_child = replace(
        _child(plan, objects, "compile", 1, terminal=True, state="failed"),
        child_ordinal=0,
    )
    skipped = abi.ToolOutcome(
        (_child_stage("compile", (skipped_child,)),) + tuple(abi.StageReceipt.not_run(stage) for stage in abi._STAGES[1:])
    )

    crossed_children = list(complete.receipts[0].child_receipts)
    crossed_children[0] = replace(crossed_children[0], object_sha256="f" * 64)
    crossed = abi.ToolOutcome((_child_stage("compile", tuple(crossed_children)), *complete.receipts[1:]))

    object_map = {item.ordinal: item for item in objects}
    for malformed in (shortened, skipped, crossed):
        with pytest.raises(abi.AssemblyAbiError) as caught:
            abi._validate_tool_outcome(malformed, plan, object_map)
        assert caught.value.refusal.code in {"stage_receipt_invalid", "tool_outcome_invalid"}


def test_analyze_composition_attributes_two_of_five_and_fails_closed_unattributed(tmp_path: Path):
    root = tmp_path.resolve()
    plan = abi.plan_canonicalization(_bundle(), _load_snapshot(root))
    assert isinstance(plan, abi.CanonicalizationPlan)
    objects = _planned_objects(
        plan,
        defined={0: (abi.SymbolObservation("zz_00262b4_", "function", "a" * 64, "default"),)},
        imported={4: (abi.SymbolObservation("zz_00262b4_", "function", "b" * 64, "default"),)},
    )
    draft = abi.analyze_composition(
        plan, objects, _tool_outcome(plan, objects, terminal_stage="link", symbol="zz_00262b4_"), _NO_RETRY
    )
    assert isinstance(draft, abi.CompositionDraft)
    assert [(item.unit, item.role) for item in draft.analyzed_outcome.contributors] == [
        (plan.translation_units[4].unit, "import"),
        (plan.translation_units[0].unit, "definition"),
    ]
    result = _finalize_draft(plan, draft, root)
    assert result.outcome["classification"] == "deterministic_blocker"
    assert result.outcome["unattributed"] is False

    unattributed = abi.analyze_composition(
        plan, objects, _tool_outcome(plan, objects, terminal_stage="link"), _NO_RETRY
    )
    assert unattributed.analyzed_outcome.contributors == ()
    assert unattributed.analyzed_outcome.unattributed is True


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        (lambda values: values[:-1], "missing_object_observation"),
        (lambda values: (*values, values[0]), "duplicate_object_observation"),
        (lambda values: (replace(values[0], object_relpath="objects/unplanned.o"), *values[1:]), "object_observation_mismatch"),
        (lambda values: (replace(values[0], ordinal=99), *values[1:]), "unplanned_object_observation"),
    ],
)
def test_composition_classifies_missing_duplicate_and_unplanned_observations(tmp_path: Path, mutation, code: str):
    plan = abi.plan_canonicalization(_bundle(), _load_snapshot(tmp_path.resolve()))
    assert isinstance(plan, abi.CanonicalizationPlan)
    objects = _planned_objects(plan)
    draft = abi.analyze_composition(plan, tuple(mutation(objects)), _tool_outcome(plan, objects), _NO_RETRY)
    assert draft.analyzed_outcome.code == code
    assert draft.analyzed_outcome.classification == "deterministic_blocker"
    assert draft.analyzed_outcome.contributors == ()


def test_composition_pass_manifest_finalization_and_recursive_immutability(tmp_path: Path):
    root = tmp_path.resolve()
    plan = abi.plan_canonicalization(_bundle(), _load_snapshot(root))
    assert isinstance(plan, abi.CanonicalizationPlan)
    objects = _planned_objects(plan)
    draft = abi.analyze_composition(plan, tuple(reversed(objects)), _tool_outcome(plan, objects), _NO_RETRY)
    assert [item["ordinal"] for item in draft.scaffold.objects] == list(range(5))
    result = _finalize_draft(plan, draft, root)
    assert result.outcome["classification"] == "pass"
    assert result.outcome["stage"] == "smoke"
    assert len(result.document) == 13
    without_id = dict(abi._json_ready(result.document))
    without_id.pop("result_id")
    assert hashlib.sha256(_canonical_bytes(without_id)).hexdigest() == result.result_id
    assert result.canonical_bytes() == _canonical_bytes(abi._json_ready(result.document))
    with pytest.raises(TypeError):
        result.document["outcome"]["code"] = "mutated"


def test_composition_transient_retry_schedule_and_changed_fingerprint_reset(tmp_path: Path):
    root = tmp_path.resolve()
    plan = abi.plan_canonicalization(_bundle(), _load_snapshot(root))
    assert isinstance(plan, abi.CanonicalizationPlan)
    objects = _planned_objects(plan)
    outcome = _tool_outcome(plan, objects, terminal_stage="compile", terminal_state="faulted", fault_class="timeout")
    draft = abi.analyze_composition(plan, (), outcome, _NO_RETRY)
    first = _finalize_draft(plan, draft, root)
    transient_sha = first.document["retry"]["transient_fault_fingerprint"]
    assert (first.document["retry"]["transient_retry_count"], first.document["retry"]["backoff_seconds"]) == (1, 30)
    for prior, expected in ((1, (2, 120, "transient_retry")), (2, (3, 600, "transient_retry")), (3, (3, None, "assembly_transient_exhausted"))):
        history = abi.RetryHistory(transient_sha, prior)
        current = abi.analyze_composition(plan, (), outcome, history)
        result = _finalize_draft(plan, current, root, history)
        assert (
            result.document["retry"]["transient_retry_count"],
            result.document["retry"]["backoff_seconds"],
            result.document["retry"]["status"],
        ) == expected
    changed = abi.RetryHistory("f" * 64, 3)
    reset = _finalize_draft(plan, abi.analyze_composition(plan, (), outcome, changed), root, changed)
    assert (reset.document["retry"]["transient_retry_count"], reset.document["retry"]["backoff_seconds"]) == (1, 30)


def _literal_retry_scaffold() -> abi.ResultScaffold:
    bundle = _bundle()
    return abi.ResultScaffold(
        "synthetic-u",
        1,
        abi.Candidate("candidate.c", "41" * 32, 64, "42" * 32, "43" * 32),
        (),
        "compile_only",
        abi._deep_freeze({"status": "planned"}),
        (),
        bundle.tool_world,
        "61" * 32,
    )


@pytest.mark.parametrize(
    ("stage", "code", "digest"),
    [
        ("compile", "compile_timeout", "e160a4cdf08620333f62dbe127e89e7004b39401046340cc2e3f4a6dbcf66d1d"),
        ("link", "link_timeout", "4a1d5a6a7c2caf1847ed6e1bd1bf66058ec766c3f4a29e4ed6cce8672243374f"),
        ("instantiate", "instantiate_timeout", "b7ec8759bd43168f719ee347bda230df312b1b6b54453ac35eb9d3ded18590b4"),
        ("smoke", "smoke_timeout", "8c883f29210350f9773917ff34e33c2f07c9061effb297e6981d8137cb05fa2f"),
    ],
)
def test_transient_adapter_role_projection_literal_vectors(stage: str, code: str, digest: str):
    receipts = list(abi._all_not_run())
    index = ("compile", "inspect", "link", "instantiate", "smoke").index(stage)
    receipts[index] = replace(
        receipts[index],
        state="faulted",
        parser_version="parser-v1",
        diagnostic_sha256="d" * 64,
        fault_class="timeout",
    )
    outcome = abi.OutcomeProjection("transient_fault", stage, code, tuple(receipts), "d" * 64, (), True)
    projection = abi._retry_projection(_literal_retry_scaffold(), outcome, _NO_RETRY)
    assert projection["transient_fault_fingerprint"] == digest


def test_literal_revalidation_transient_and_assembly_retry_preimages():
    receipts = list(abi._all_not_run())
    receipts[0] = replace(receipts[0], child_transcript_sha256="5597071754af9bbe42a2fa65fc43043c1c59cc2153d23e8940adaf0f86ecdc87")
    receipts[1] = replace(receipts[1], child_transcript_sha256="67eb92399a94b59e58f244e30399c1f6ad1d88fb06af787a6b493fbd4c9fbf37")
    outcome = abi.OutcomeProjection(
        "transient_fault", "revalidate", "stable_read_fault", tuple(receipts), "d" * 64, (), True
    )
    projection = abi._retry_projection(_literal_retry_scaffold(), outcome, _NO_RETRY, "stable_read")
    assert projection["transient_fault_fingerprint"] == "5200c61f3b31b5b0a561bfd616c9628c0a03430f4c0a0f82826c18a755457f2a"
    assert projection["assembly_retry_fingerprint"] == "0d5e000eb991471ed939846165d13d0616275c86ca36df485d1bdd941b97c81c"
    assert abi.RetryHistory(None, 0).sha256 == "53baf513a523c322f7ddae9ac2645f8960908cc16e3e2ba808baf2754c52b7dd"
    assert abi.RetryHistory("f" * 64, 1).sha256 == "628186e9735fcefb168eab2f5cd1b508c91b21cebc0c8d94a234d07a2b3ce4a8"


def _expected_transient_fingerprint(scaffold: abi.ResultScaffold, stage: str, code: str, fault_class: str) -> str:
    return hashlib.sha256(
        _canonical_bytes(
            {
                "assembly_world_sha256": scaffold.assembly_world_sha256,
                "candidate_sha256": scaffold.candidate.artifact_sha256,
                "code": code,
                "fault_class": fault_class,
                "stage": stage,
                "tool_role": None,
                "transient_fault_fingerprint_schema": 1,
            }
        )
    ).hexdigest()


def test_predraft_transient_fault_class_is_exact_and_history_does_not_cross_advance():
    base = _literal_retry_scaffold()
    scaffold = replace(base, canonicalization=abi._deep_freeze({"status": "not_started"}))
    results = {}
    for fault_class in ("io", "lock", "stable_read"):
        failure = abi.FailureEvidence("owner", "transient_fault", "owner_read_fault", "d" * 64, fault_class)
        result = abi.finalize_composition(abi.PreDraftFailureInput(scaffold, failure, _NO_RETRY))
        fingerprint = result.document["retry"]["transient_fault_fingerprint"]
        assert fingerprint == _expected_transient_fingerprint(scaffold, "owner", "owner_read_fault", fault_class)
        results[fault_class] = fingerprint
        repeated = abi.finalize_composition(
            abi.PreDraftFailureInput(scaffold, failure, abi.RetryHistory(fingerprint, 1))
        )
        assert repeated.document["retry"]["transient_retry_count"] == 2
    assert len(set(results.values())) == 3
    crossed = abi.finalize_composition(
        abi.PreDraftFailureInput(
            scaffold,
            abi.FailureEvidence("owner", "transient_fault", "owner_read_fault", "d" * 64, "lock"),
            abi.RetryHistory(results["io"], 1),
        )
    )
    assert crossed.document["retry"]["transient_retry_count"] == 1


def test_precompile_transient_fault_class_is_exact_and_history_does_not_cross_advance():
    scaffold = replace(_literal_retry_scaffold(), canonicalization_receipt_sha256="c" * 64)
    check = abi.RevalidationCheck.create("pre-compile", "c" * 64, "e" * 64, False, "owner_read_fault")
    results = {}
    for fault_class in ("io", "lock", "stable_read"):
        failure = abi.RevalidationFailure(
            "transient_fault", "owner_read_fault", "d" * 64, check.check_sha256, fault_class
        )
        result = abi.finalize_composition(abi.PrecompileFailureInput(scaffold, failure, _NO_RETRY, check))
        fingerprint = result.document["retry"]["transient_fault_fingerprint"]
        assert fingerprint == _expected_transient_fingerprint(scaffold, "revalidate", "owner_read_fault", fault_class)
        results[fault_class] = fingerprint
    assert len(set(results.values())) == 3
    repeated = abi.finalize_composition(
        abi.PrecompileFailureInput(
            scaffold,
            abi.RevalidationFailure("transient_fault", "owner_read_fault", "d" * 64, check.check_sha256, "io"),
            abi.RetryHistory(results["io"], 1),
            check,
        )
    )
    assert repeated.document["retry"]["transient_retry_count"] == 2


def test_prepublication_transient_fault_class_is_exact_and_history_does_not_cross_advance(tmp_path: Path):
    root = tmp_path.resolve()
    plan = abi.plan_canonicalization(_bundle(), _load_snapshot(root))
    assert isinstance(plan, abi.CanonicalizationPlan)
    objects = _planned_objects(plan)
    draft = abi.analyze_composition(plan, objects, _tool_outcome(plan, objects), _NO_RETRY)
    precompile = _precompile_check(plan, root)
    results = {}
    for fault_class in ("io", "lock", "stable_read"):
        check = abi.RevalidationCheck.create(
            "pre-publication", draft.composition_receipt.sha256, "e" * 64, False, "owner_read_fault"
        )
        failure = abi.RevalidationFailure(
            "transient_fault", "owner_read_fault", "d" * 64, check.check_sha256, fault_class
        )
        result = abi.finalize_composition(
            abi.PostAnalysisInput(draft, precompile, abi.PrePublicationDecision.refused(check, failure), _NO_RETRY)
        )
        fingerprint = result.document["retry"]["transient_fault_fingerprint"]
        assert fingerprint == _expected_transient_fingerprint(
            draft.scaffold, "revalidate", "owner_read_fault", fault_class
        )
        results[fault_class] = fingerprint
    assert len(set(results.values())) == 3
    check = abi.RevalidationCheck.create(
        "pre-publication", draft.composition_receipt.sha256, "e" * 64, False, "owner_read_fault"
    )
    repeated_history = abi.RetryHistory(results["stable_read"], 1)
    repeated_draft = replace(draft, retry_history_sha256=repeated_history.sha256)
    repeated = abi.finalize_composition(
        abi.PostAnalysisInput(
            repeated_draft,
            precompile,
            abi.PrePublicationDecision.refused(
                check,
                abi.RevalidationFailure(
                    "transient_fault", "owner_read_fault", "d" * 64, check.check_sha256, "stable_read"
                ),
            ),
            repeated_history,
        )
    )
    assert repeated.document["retry"]["transient_retry_count"] == 2


@pytest.mark.parametrize(
    ("stage", "status"),
    [("owner", "not_started"), ("canonicalize", "failed"), ("materialize", "planned")],
)
def test_predraft_finalization_union_members_have_no_revalidation_or_tool_evidence(
    tmp_path: Path, stage: str, status: str
):
    plan = abi.plan_canonicalization(_bundle(), _load_snapshot(tmp_path.resolve()))
    assert isinstance(plan, abi.CanonicalizationPlan)
    base = abi._scaffold_from_plan(plan, ())
    scaffold = replace(base, canonicalization=abi._deep_freeze({**abi._json_ready(base.canonicalization), "status": status}))
    failure = abi.FailureEvidence(stage, "deterministic_blocker", f"{stage}_failed", "d" * 64, None)
    result = abi.finalize_composition(abi.PreDraftFailureInput(scaffold, failure, _NO_RETRY))
    assert result.document["revalidation"] == {"pre_compile_sha256": None, "pre_publication_sha256": None}
    assert [item["state"] for item in result.outcome["stage_receipts"]] == ["not_run"] * 5
    assert result.outcome["stage"] == stage


def test_precompile_refusal_finalizes_without_analysis_or_tool_receipts(tmp_path: Path):
    root = tmp_path.resolve()
    plan = abi.plan_canonicalization(_bundle(), _load_snapshot(root))
    assert isinstance(plan, abi.CanonicalizationPlan)
    observed = replace(abi.ReceiptObservation.from_plan(plan), bundle_sha256="0" * 64)
    refusal = abi.revalidate_receipt(plan.receipt, root, observed)
    assert isinstance(refusal, abi.AssemblyAbiRefusal)
    check = refusal.revalidation_check
    failure = abi.RevalidationFailure("deterministic_blocker", refusal.code, refusal.evidence_sha256, check.check_sha256, None)
    result = abi.finalize_composition(
        abi.PrecompileFailureInput(abi._scaffold_from_plan(plan, ()), failure, _NO_RETRY, check)
    )
    assert result.document["revalidation"] == {
        "pre_compile_sha256": check.check_sha256,
        "pre_publication_sha256": None,
    }
    assert [item["state"] for item in result.outcome["stage_receipts"]] == ["not_run"] * 5
    assert result.outcome["stage"] == "revalidate"


def test_prepublication_refusal_preserves_complete_tools_but_blames_no_object(tmp_path: Path):
    root = tmp_path.resolve()
    plan = abi.plan_canonicalization(_bundle(), _load_snapshot(root))
    assert isinstance(plan, abi.CanonicalizationPlan)
    objects = _planned_objects(plan)
    draft = abi.analyze_composition(plan, objects, _tool_outcome(plan, objects), _NO_RETRY)
    precompile = _precompile_check(plan, root)
    observed = replace(abi.ReceiptObservation.from_draft(draft), tool_world_sha256="0" * 64)
    refusal = abi.revalidate_receipt(draft.composition_receipt, root, observed)
    assert isinstance(refusal, abi.AssemblyAbiRefusal)
    check = refusal.revalidation_check
    failure = abi.RevalidationFailure("deterministic_blocker", refusal.code, refusal.evidence_sha256, check.check_sha256, None)
    result = abi.finalize_composition(
        abi.PostAnalysisInput(draft, precompile, abi.PrePublicationDecision.refused(check, failure), _NO_RETRY)
    )
    assert [item["state"] for item in result.outcome["stage_receipts"]] == ["passed"] * 5
    assert result.outcome["stage"] == "revalidate"
    assert result.outcome["contributors"] == ()
    assert result.outcome["unattributed"] is True
    assert result.document["revalidation"]["pre_publication_sha256"] == check.check_sha256


def test_finalization_union_crossed_decisions_and_history_refuse(tmp_path: Path):
    root = tmp_path.resolve()
    plan = abi.plan_canonicalization(_bundle(), _load_snapshot(root))
    assert isinstance(plan, abi.CanonicalizationPlan)
    objects = _planned_objects(plan)
    passed = abi.analyze_composition(plan, objects, _tool_outcome(plan, objects), _NO_RETRY)
    precompile = _precompile_check(plan, root)
    publication = abi.revalidate_receipt(passed.composition_receipt, root, abi.ReceiptObservation.from_draft(passed))
    assert isinstance(publication, abi.RevalidatedReceipt)
    invalid = [
        abi.PostAnalysisInput(passed, precompile, abi.PrePublicationDecision.not_reached(), _NO_RETRY),
        abi.PostAnalysisInput(passed, precompile, abi.PrePublicationDecision.passed(precompile), _NO_RETRY),
        abi.PostAnalysisInput(passed, precompile, abi.PrePublicationDecision.passed(publication.check), abi.RetryHistory("f" * 64, 1)),
    ]
    failed = abi.analyze_composition(plan, objects, _tool_outcome(plan, objects, terminal_stage="link"), _NO_RETRY)
    invalid.append(
        abi.PostAnalysisInput(failed, precompile, abi.PrePublicationDecision.passed(publication.check), _NO_RETRY)
    )
    for member in invalid:
        with pytest.raises(abi.AssemblyAbiError):
            abi.finalize_composition(member)


def test_composition_never_fabricates_abi_contributors_and_validates_visibility(tmp_path: Path):
    plan = abi.plan_canonicalization(_bundle(), _load_snapshot(tmp_path.resolve()))
    assert isinstance(plan, abi.CanonicalizationPlan)
    objects = list(_planned_objects(plan))
    missing = abi.SymbolObservation("zz_00262b4_", "function", None, "default")
    valid = abi.SymbolObservation("zz_00262b4_", "function", "a" * 64, "default")
    objects[0] = replace(objects[0], defined_symbols=(missing,))
    objects[1] = replace(objects[1], imported_symbols=(valid,))
    draft = abi.analyze_composition(
        plan, tuple(objects), _tool_outcome(plan, tuple(objects), terminal_stage="link", symbol="zz_00262b4_"), _NO_RETRY
    )
    assert draft.analyzed_outcome.code == "object-attribution-unavailable"
    assert draft.analyzed_outcome.contributors == ()
    assert draft.analyzed_outcome.unattributed is True
    objects[0] = replace(objects[0], defined_symbols=(replace(valid, visibility="public"),))
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.analyze_composition(plan, tuple(objects), _tool_outcome(plan, tuple(objects)), _NO_RETRY)
    assert caught.value.refusal.code == "object_observation_invalid"


@pytest.mark.parametrize("collection_name", ["defined_symbols", "imported_symbols"])
@pytest.mark.parametrize(
    "symbol",
    [
        object(),
        abi.SymbolObservation([], "function", "a" * 64, "default"),
        abi.SymbolObservation("bad_symbol", [], "a" * 64, "default"),
        abi.SymbolObservation("bad_symbol", "function", [], "default"),
        abi.SymbolObservation("bad_symbol", "function", "a" * 64, []),
    ],
)
def test_symbol_observation_nested_member_types_refuse_before_keying(
    tmp_path: Path, collection_name: str, symbol: object
):
    plan = abi.plan_canonicalization(_bundle(), _load_snapshot(tmp_path.resolve()))
    assert isinstance(plan, abi.CanonicalizationPlan)
    objects = list(_planned_objects(plan))
    objects[0] = replace(objects[0], **{collection_name: (symbol,)})
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.analyze_composition(plan, tuple(objects), _tool_outcome(plan, tuple(objects)), _NO_RETRY)
    assert caught.value.refusal.code == "object_observation_invalid"


@pytest.mark.parametrize(("state", "classification"), [("failed", "deterministic_blocker"), ("faulted", "transient_fault")])
def test_inspect_terminal_child_and_inspector_receipt_must_match_exactly(
    tmp_path: Path, state: str, classification: str
):
    plan = abi.plan_canonicalization(_bundle(), _load_snapshot(tmp_path.resolve()))
    assert isinstance(plan, abi.CanonicalizationPlan)
    all_objects = _planned_objects(plan)
    outcome = _tool_outcome(
        plan,
        all_objects,
        terminal_stage="inspect",
        terminal_state=state,
        fault_class="timeout" if state == "faulted" else None,
    )
    child = outcome.receipts[1].child_receipts[-1]
    receipt = abi.InspectorReceipt(
        child.execution_completed,
        False,
        child.exit_status,
        child.stdout_sha256,
        child.stderr_sha256,
        child.parser_version,
        child.fault_class,
        child.diagnostic_sha256,
    )
    attempted = (replace(all_objects[0], inspector_receipt=receipt),)
    draft = abi.analyze_composition(plan, attempted, outcome, _NO_RETRY)
    assert draft.analyzed_outcome.classification == classification
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.analyze_composition(plan, (all_objects[0],), outcome, _NO_RETRY)
    assert caught.value.refusal.code == "tool_outcome_invalid"


@pytest.mark.parametrize(
    ("state", "fault_class", "classification", "code"),
    [
        ("failed", None, "deterministic_blocker", "object-attribution-unavailable"),
        *[
            ("faulted", fault, "transient_fault", f"inspect_{fault}")
            for fault in ("spawn", "timeout", "crash", "io")
        ],
    ],
)
def test_unsuccessful_inspector_symbols_are_untrusted_and_never_contribute(
    tmp_path: Path,
    state: str,
    fault_class: str | None,
    classification: str,
    code: str,
):
    plan = abi.plan_canonicalization(_bundle(), _load_snapshot(tmp_path.resolve()))
    assert isinstance(plan, abi.CanonicalizationPlan)
    fabricated = abi.SymbolObservation("bad_symbol", "function", "a" * 64, "default")
    all_objects = _planned_objects(plan, defined={0: (fabricated,)})
    outcome = _tool_outcome(
        plan,
        all_objects,
        terminal_stage="inspect",
        terminal_state=state,
        symbol="bad_symbol",
        fault_class=fault_class,
    )
    child = outcome.receipts[1].child_receipts[-1]
    attempted = (
        replace(
            all_objects[0],
            inspector_receipt=abi.InspectorReceipt(
                child.execution_completed,
                False,
                child.exit_status,
                child.stdout_sha256,
                child.stderr_sha256,
                child.parser_version,
                child.fault_class,
                child.diagnostic_sha256,
            ),
        ),
    )
    draft = abi.analyze_composition(plan, attempted, outcome, _NO_RETRY)
    assert draft.analyzed_outcome.classification == classification
    assert draft.analyzed_outcome.code == code
    assert draft.analyzed_outcome.contributors == ()
    assert draft.analyzed_outcome.unattributed is True
    assert draft.scaffold.objects[0]["defined_symbols"] == ()


def test_receipt_revalidation_binds_registry_ranges_bundle_objects_and_tools(tmp_path: Path):
    root = tmp_path.resolve()
    plan = abi.plan_canonicalization(_bundle(), _load_snapshot(root))
    assert isinstance(plan, abi.CanonicalizationPlan)
    observed = abi.ReceiptObservation.from_plan(plan)
    first = abi.revalidate_receipt(plan.receipt, root, observed)
    second = abi.revalidate_receipt(plan.receipt, root, observed)
    assert isinstance(first, abi.RevalidatedReceipt)
    assert first == second
    assert first.check.stage == "pre-compile"

    source = root / plan.receipt.owner_files[0].chunk_file
    source.write_bytes(source.read_bytes() + b"\n")
    refusal = abi.revalidate_receipt(plan.receipt, root, observed)
    assert isinstance(refusal, abi.AssemblyAbiRefusal)
    assert refusal.code == "owner_source_drift"
    assert refusal.revalidation_check.passed is False


def test_receipt_revalidation_independently_binds_registry_bundle_tools_and_objects(tmp_path: Path):
    root = (tmp_path / "product").resolve()
    plan = abi.plan_canonicalization(_bundle(), _load_snapshot(root))
    assert isinstance(plan, abi.CanonicalizationPlan)
    precompile = abi.ReceiptObservation.from_plan(plan)
    assert abi.revalidate_receipt(plan.receipt, root, replace(precompile, bundle_sha256="0" * 64)).code == "bundle_observation_drift"
    changed_file = replace(precompile.bundle_files[0], sha256="0" * 64)
    assert abi.revalidate_receipt(
        plan.receipt, root, replace(precompile, bundle_files=(changed_file, *precompile.bundle_files[1:]))
    ).code == "bundle_observation_drift"
    assert abi.revalidate_receipt(plan.receipt, root, replace(precompile, tool_world_sha256="0" * 64)).code == "tool_world_drift"

    objects = _planned_objects(plan)
    draft = abi.analyze_composition(plan, objects, _tool_outcome(plan, objects), _NO_RETRY)
    publication = abi.ReceiptObservation.from_draft(draft)
    accepted = abi.revalidate_receipt(draft.composition_receipt, root, publication)
    assert isinstance(accepted, abi.RevalidatedReceipt)
    assert accepted.check.stage == "pre-publication"
    changed_object = replace(publication.object_bindings[0], sha256="0" * 64)
    refusal = abi.revalidate_receipt(
        draft.composition_receipt,
        root,
        replace(publication, object_bindings=(changed_object, *publication.object_bindings[1:])),
    )
    assert refusal.code == "object_observation_drift"
    wrong_receipt = abi.revalidate_receipt(plan.receipt, root, publication)
    assert wrong_receipt.code == "composition_receipt_required"
    crossed = abi.revalidate_receipt(draft.composition_receipt, root, precompile)
    assert crossed.code == "canonicalization_receipt_required"
    empty_publication = abi.revalidate_receipt(
        draft.composition_receipt, root, replace(publication, object_bindings=())
    )
    assert empty_publication.code == "composition_receipt_required"

    registry_path = root / plan.receipt.registry_relpath
    registry_path.write_bytes(registry_path.read_bytes() + b" ")
    assert abi.revalidate_receipt(plan.receipt, root, precompile).code == "owner_registry_drift"


def test_receipt_revalidation_binds_authoritative_index_identity(tmp_path: Path):
    root = tmp_path.resolve()
    plan = abi.plan_canonicalization(_bundle(), _load_snapshot(root))
    assert isinstance(plan, abi.CanonicalizationPlan)
    observed = abi.ReceiptObservation.from_plan(plan)
    index = root / plan.receipt.index_relpath
    index.write_bytes(index.read_bytes() + b"\n")
    refusal = abi.revalidate_receipt(plan.receipt, root, observed)
    assert isinstance(refusal, abi.AssemblyAbiRefusal)
    assert refusal.code == "owner_index_drift"


def test_every_public_phase_and_nested_receipt_shape_refuses_typed(tmp_path: Path):
    with pytest.raises(abi.AssemblyAbiError) as owner:
        abi.load_owner_snapshot(None, Path("registry.json"), FakeParser())
    assert owner.value.refusal.code == "product_root_invalid"
    with pytest.raises(abi.AssemblyAbiError) as registry:
        abi.load_owner_snapshot(tmp_path.resolve(), None, FakeParser())
    assert registry.value.refusal.code == "product_path_invalid"

    root = tmp_path.resolve()
    snapshot = _load_snapshot(root)
    bundle = _bundle()
    malformed_bundle = abi.plan_canonicalization(object(), snapshot)
    assert isinstance(malformed_bundle, abi.AssemblyAbiRefusal)
    assert malformed_bundle.code == "bundle_shape_invalid"
    malformed_plan = abi.plan_canonicalization(bundle, object())
    assert isinstance(malformed_plan, abi.AssemblyAbiRefusal)
    assert malformed_plan.code == "owner_snapshot_invalid"
    plan = abi.plan_canonicalization(bundle, snapshot)
    assert isinstance(plan, abi.CanonicalizationPlan)
    objects = _planned_objects(plan)
    passed = _tool_outcome(plan, objects)

    malformed_stage_values = (
        replace(passed.receipts[0], named_object_relpaths=([],)),
        replace(passed.receipts[0], child_receipts=(object(),)),
        replace(
            passed.receipts[0],
            child_receipts=(replace(passed.receipts[0].child_receipts[0], argv=([],)),),
            child_transcript_sha256=abi.stage_child_transcript_sha256(
                "compile", (replace(passed.receipts[0].child_receipts[0], argv=([],)),)
            ),
        ),
    )
    for receipt in malformed_stage_values:
        with pytest.raises(abi.AssemblyAbiError) as malformed_stage:
            abi._validate_stage_receipt(receipt, plan, {item.ordinal: item for item in objects})
        assert malformed_stage.value.refusal.code == "stage_receipt_invalid"

    with pytest.raises(abi.AssemblyAbiError) as malformed_outcome:
        abi._validate_tool_outcome(abi.ToolOutcome((object(),) * 5), plan)
    assert malformed_outcome.value.refusal.code == "tool_outcome_invalid"

    with pytest.raises(abi.AssemblyAbiError) as malformed_objects:
        abi.analyze_composition(plan, (object(),), passed, _NO_RETRY)
    assert malformed_objects.value.refusal.code == "object_observation_invalid"
    with pytest.raises(abi.AssemblyAbiError) as malformed_ordinal:
        abi.analyze_composition(plan, (replace(objects[0], ordinal=[]),), passed, _NO_RETRY)
    assert malformed_ordinal.value.refusal.code == "object_observation_invalid"
    with pytest.raises(abi.AssemblyAbiError) as malformed_analysis_plan:
        abi.analyze_composition(object(), (), passed, _NO_RETRY)
    assert malformed_analysis_plan.value.refusal.code == "canonicalization_plan_invalid"

    observed = replace(abi.ReceiptObservation.from_plan(plan), bundle_files=(object(),))
    receipt_refusal = abi.revalidate_receipt(plan.receipt, root, observed)
    assert isinstance(receipt_refusal, abi.AssemblyAbiRefusal)
    assert receipt_refusal.code == "receipt_observation_invalid"

    bad_composition = abi.CompositionReceipt(plan.receipt, (object(),), plan.receipt.tool_world_sha256)
    bad_observed = abi.ReceiptObservation(
        "pre-publication",
        plan.receipt.bundle_sha256,
        plan.receipt.bundle_files,
        (abi.BundleFileBinding("objects/0.o", "a" * 64, 1),),
        plan.receipt.tool_world_sha256,
    )
    composition_refusal = abi.revalidate_receipt(bad_composition, root, bad_observed)
    assert isinstance(composition_refusal, abi.AssemblyAbiRefusal)
    assert composition_refusal.code == "composition_receipt_invalid"
    bad_owner_file = replace(plan.receipt.owner_files[0], chunk_file=[])
    canonical_refusal = abi.revalidate_receipt(
        replace(plan.receipt, owner_files=(bad_owner_file,)),
        root,
        abi.ReceiptObservation.from_plan(plan),
    )
    assert isinstance(canonical_refusal, abi.AssemblyAbiRefusal)
    assert canonical_refusal.code == "canonicalization_receipt_invalid"
    unknown_receipt = abi.revalidate_receipt(object(), root, abi.ReceiptObservation.from_plan(plan))
    assert isinstance(unknown_receipt, abi.AssemblyAbiRefusal)
    assert unknown_receipt.code == "revalidation_receipt_invalid"

    with pytest.raises(abi.AssemblyAbiError) as malformed_finalization:
        abi.finalize_composition(abi.PreDraftFailureInput(object(), object(), object()))
    assert malformed_finalization.value.refusal.code == "finalization_input_invalid"


def test_four_normative_complete_result_ids_recompute_from_literal_spec_bytes():
    specification = (Path(__file__).parents[1] / "docs" / "assembly-abi-canonicalization-spec.md").read_text(
        encoding="utf-8"
    )
    blocks = re.findall(
        r"The complete [\d,]+-byte result is:\s*```json\n(\{.*?\})\n```",
        specification,
        flags=re.DOTALL,
    )
    expected = [
        "07a540545f0b0db883e906d7e6c456352789bc2fbfc5d9a18005af54fb04ced9",
        "2cba2aa68db75c0d464ab8e89a3e6c44104bd79bd1ab7e40190e643e30b0e389",
        "f8a525c79497bbe197d0eca0a5bfff93168ac40dc26b6106a230063a72d6154f",
        "32f2f5c141bfbd75e387e70b9e0db776c0dcd93cea0f22797da34e799b816056",
    ]
    assert len(blocks) == len(expected)
    for block, result_id in zip(blocks, expected, strict=True):
        document = json.loads(block)
        assert document.pop("result_id") == result_id
        assert hashlib.sha256(_canonical_bytes(document)).hexdigest() == result_id

    transient = json.loads(blocks[-1])
    transient.pop("result_id")
    repeated_rows = [
        (1, 30, "transient_retry", "32f2f5c141bfbd75e387e70b9e0db776c0dcd93cea0f22797da34e799b816056"),
        (2, 120, "transient_retry", "c26d66010b1990a4d36ef00434c69434c946f9bfb9b5e5c70e8b31379419dd3f"),
        (3, 600, "transient_retry", "1d8fd0422404bd67aa8e98ef213c5232e66e360d9543ba037ba906020b154170"),
        (3, None, "assembly_transient_exhausted", "e75ac59c25a4d1695cae5be22e20d3b2d273297ecaa333aa115f42b70b0d6897"),
    ]
    for count, backoff, status, result_id in repeated_rows:
        current = copy.deepcopy(transient)
        current["retry"].update(
            transient_retry_count=count,
            backoff_seconds=backoff,
            status=status,
        )
        assert hashlib.sha256(_canonical_bytes(current)).hexdigest() == result_id


def test_pinned_clang_identity_and_every_bound_argv_are_exact(clang_parser: abi.ClangDeclaratorParser):
    identity = clang_parser.identity
    assert identity.executable_path == str((REAL_PRODUCT_ROOT / "research/tools/emsdk/upstream/bin/clang.exe").resolve())
    assert identity.binary_sha256 == "633be119308de42bd096a455faf321216423427ea1bac0f7de2d790f30232a93"
    assert identity.version_sha256 == "f58b2b92936b6a2b3ba1b3f74bcfb0fc2556933478adca609626efba57fb0637"
    assert identity.version_size == 216
    assert identity.target == "wasm32-unknown-emscripten"
    assert identity.dialect == "gnu11"
    assert identity.to_dict()["json_argv"] == list(abi.json_argv(identity.executable_path))
    assert identity.to_dict()["compatibility_argv"] == list(
        abi.json_argv(identity.executable_path, "__oghidra_abi_compat_result")
    )
    assert abi.json_argv(identity.executable_path, "__oghidra_abi_return_probe")[-4:-2] == (
        "-Xclang", "__oghidra_abi_return_probe"
    )


def test_real_clang_seven_emission_rows_typedef_preamble_and_qualifier_compatibility(
    clang_parser: abi.ClangDeclaratorParser,
):
    parser = clang_parser
    rows = [
        (b"uint synthetic(uint value) { return value; }\n", "uint synthetic(uint);"),
        (b"void synthetic(int (*callback)(const char *, unsigned int)) {}\n", "void synthetic(int (*)(const char *, unsigned int));"),
        (b"void synthetic(unsigned value[4]) {}\n", "void synthetic(unsigned int[4]);"),
        (b"void synthetic() {}\n", "void synthetic();"),
        (b"void synthetic(void) {}\n", "void synthetic(void);"),
    ]
    for source, expected in rows:
        projection = parser.parse_definition(source, "synthetic")
        assert projection.canonical_prototype == expected
        assert parser.parse_declaration(expected.encode(), "synthetic").abi_tuple == projection.abi_tuple

    with pytest.raises(abi.AssemblyAbiError) as returning_pointer:
        parser.parse_definition(b"int (*synthetic(void))(int) { return 0; }\n", "synthetic")
    assert returning_pointer.value.refusal.code == "registry_shape_unrepresentable_return_declarator"
    with pytest.raises(abi.AssemblyAbiError) as attributed:
        parser.parse_definition(b"void synthetic(void) __attribute__((used)) {}\n", "synthetic")
    assert attributed.value.refusal.code == "registry_shape_unrepresentable_attribute"
    with pytest.raises(abi.AssemblyAbiError) as caller_typedef:
        parser.parse_definition(b"typedef unsigned int uint;\nuint synthetic(uint value) { return value; }\n", "synthetic")
    assert caller_typedef.value.refusal.code == "abi_preamble_unknown_or_ambiguous_type"

    preamble = parser.parse_declaration(b"FILE *synthetic(__compar_fn_t cb, wchar_t *w, undefined8 x);", "synthetic")
    assert preamble.canonical_prototype == "FILE *synthetic(__compar_fn_t, wchar_t *, undefined8);"
    assert preamble.abi_tuple.canonical_bytes() == (
        b'{"abi_tuple_schema":1,"arity":3,"calling_convention":"c","parameter_types":["int (*)(const void *, const void *)","int *","unsigned long long"],"prototype_kind":"prototype","return_type":"struct __oghidra_FILE_v1 *","variadic":false}\n'
    )
    assert preamble.abi_tuple.sha256 == "58eb175039b96ae787e5545786e27975e613f2a9dbf16c5105cffc5e9ca38edd"

    expected = [True, True, True, False, False]
    pairs = [
        ("void synthetic(int);", "void synthetic(const int);"),
        ("void synthetic(int *);", "void synthetic(int *const);"),
        ("void synthetic(int *);", "void synthetic(int *restrict);"),
        ("void synthetic(int *);", "void synthetic(const int *);"),
        ("void synthetic(int *);", "void synthetic(volatile int *);"),
    ]
    for pair, compatible in zip(pairs, expected, strict=True):
        left = parser.parse_declaration(pair[0].encode(), "synthetic")
        right = parser.parse_declaration(pair[1].encode(), "synthetic")
        assert parser.compatibility(left, right).compatible is compatible
    assert parser.parse_declaration(pairs[0][0].encode(), "synthetic").abi_tuple != parser.parse_declaration(pairs[0][1].encode(), "synthetic").abi_tuple


def test_real_clang_adjusted_array_primary_secondary_ast_and_evidence_are_exact(
    clang_parser: abi.ClangDeclaratorParser,
):
    primary = (
        abi.ABI_PREAMBLE_V1
        + b"typedef __typeof__(unsigned int[4]) __oghidra_abi_param_0000;\n"
        + b"void __oghidra_abi_probe(__oghidra_abi_param_0000);\n"
    )
    assert (len(primary), hashlib.sha256(primary).hexdigest()) == (
        1984,
        "50073f94f5ea6a2db084c0d3061af01fe373a08d065f70a143abbdd95711ef0c",
    )
    primary_ast = clang_parser._function_ast(primary, code="abi_parameter_probe_invalid")
    parameter = [item for item in primary_ast["inner"] if item.get("kind") == "ParmVarDecl"]
    assert primary_ast["type"] == {"qualType": "void (unsigned int *)"}
    assert parameter[0]["type"] == {"qualType": "unsigned int *"}
    secondary = (
        abi.ABI_PREAMBLE_V1
        + b"typedef __typeof__(unsigned int *) __oghidra_abi_adjusted_param_type_0000;\n"
        + b"__oghidra_abi_adjusted_param_type_0000 __oghidra_abi_adjusted_param_probe_0000;\n"
    )
    assert (len(secondary), hashlib.sha256(secondary).hexdigest()) == (
        2025,
        "af0eed3c64a8436bddeba4b67642910ec7af0a18c2e074dab43901338f4e7b08",
    )
    secondary_root = abi._json_value(
        clang_parser._run(
            abi.json_argv(str(clang_parser.executable), "__oghidra_abi_adjusted_param_probe_0000"),
            secondary,
            code="abi_adjusted_parameter_probe_invalid",
        ),
        code="abi_adjusted_parameter_probe_invalid",
    )
    assert secondary_root["kind"] == "VarDecl"
    assert secondary_root["name"] == "__oghidra_abi_adjusted_param_probe_0000"
    assert secondary_root["type"]["qualType"] == "__oghidra_abi_adjusted_param_type_0000"
    assert secondary_root["type"]["desugaredQualType"] == "unsigned int *"
    projection = clang_parser.parse_declaration(b"void synthetic(unsigned int[4]);", "synthetic")
    assert projection.abi_tuple.parameter_types == ("unsigned int *",)
    assert projection.abi_probe_evidence.to_dict() == {
        "abi_probe_schema": 1,
        "adjusted_parameters": [
            {
                "desugared_qual_type": "unsigned int *",
                "observed_adjusted_qual_type": "unsigned int *",
                "ordinal": 0,
                "source_sha256": "af0eed3c64a8436bddeba4b67642910ec7af0a18c2e074dab43901338f4e7b08",
                "source_size": 2025,
            }
        ],
        "parameter_source_sha256": "50073f94f5ea6a2db084c0d3061af01fe373a08d065f70a143abbdd95711ef0c",
        "parameter_source_size": 1984,
        "return_source_sha256": hashlib.sha256(abi.ABI_PREAMBLE_V1 + b"/* void return void */\n").hexdigest(),
        "return_source_size": len(abi.ABI_PREAMBLE_V1 + b"/* void return void */\n"),
    }
    typedef_array = clang_parser.parse_declaration(b"void synthetic(uint[4]);", "synthetic")
    assert typedef_array.abi_probe_evidence.parameter_source_size == 1976
    assert typedef_array.abi_probe_evidence.parameter_source_sha256 == "1ab534677857681dae3650ac3058eadf16376eb9475711f3b3116b218a03cf28"
    assert typedef_array.abi_probe_evidence.adjusted_parameters == projection.abi_probe_evidence.adjusted_parameters


def test_real_clang_bool_sources_remain_compiler_owned_and_never_rewritten(clang_parser: abi.ClangDeclaratorParser):
    parameter_source = (
        abi.ABI_PREAMBLE_V1
        + b"typedef __typeof__(_Bool) __oghidra_abi_param_0000;\n"
        + b"void __oghidra_abi_probe(__oghidra_abi_param_0000);\n"
    )
    return_source = (
        abi.ABI_PREAMBLE_V1
        + b"typedef __typeof__(_Bool) __oghidra_abi_return_type;\n"
        + b"__oghidra_abi_return_type __oghidra_abi_return_probe;\n"
    )
    assert (len(parameter_source), hashlib.sha256(parameter_source).hexdigest()) == (
        1974,
        "979dcb0e8c3b7f16df0f079eb32dc88ec29edd8aee45e6f6869bc88ffca645ee",
    )
    assert (len(return_source), hashlib.sha256(return_source).hexdigest()) == (
        1977,
        "d1ab6f90f9fd697bbab8be406c2277bea262d73f95856af612b46db5c6dab503",
    )
    parameter_ast = clang_parser._function_ast(parameter_source, code="abi_parameter_probe_invalid")
    parameter_type = [item for item in parameter_ast["inner"] if item.get("kind") == "ParmVarDecl"][0]["type"]
    assert {key: parameter_type[key] for key in ("desugaredQualType", "qualType")} == {
        "desugaredQualType": "bool",
        "qualType": "__oghidra_abi_param_0000",
    }
    return_ast = abi._json_value(
        clang_parser._run(
            abi.json_argv(str(clang_parser.executable), "__oghidra_abi_return_probe"),
            return_source,
            code="abi_return_probe_invalid",
        ),
        code="abi_return_probe_invalid",
    )
    assert {key: return_ast["type"][key] for key in ("desugaredQualType", "qualType")} == {
        "desugaredQualType": "bool",
        "qualType": "__oghidra_abi_return_type",
    }
    parameter = clang_parser.parse_declaration(b"void synthetic(_Bool);", "synthetic").abi_tuple
    returned = clang_parser.parse_declaration(b"_Bool synthetic(void);", "synthetic").abi_tuple
    assert parameter.parameter_types == ("bool",)
    assert parameter.sha256 == "1d4fc56beae25b544724f2105c503133143ef8f12b6e65598abdc1ed4ae14bd4"
    assert returned.return_type == "bool"
    assert returned.sha256 == "d53e301357f4fd5f53d2c51e68c0dd88b3dc8c61917c35752947f785fff1d85b"


def test_three_and_sixteen_argument_fixture_rows_run_through_real_clang(clang_parser: abi.ClangDeclaratorParser):
    for key, arity in (("three_argument", 3), ("sixteen_argument", 16)):
        parameters = ", ".join(_fixture()["conflicts"][key])
        projection = clang_parser.parse_declaration(f"void synthetic({parameters});".encode(), "synthetic")
        assert projection.abi_tuple.arity == arity
        assert projection.abi_probe_evidence.parameter_source_size > len(abi.ABI_PREAMBLE_V1)
        assert projection.abi_probe_evidence.parameter_source_sha256 == hashlib.sha256(
            abi.ABI_PREAMBLE_V1
            + b"".join(
                f"typedef __typeof__({parameter}) __oghidra_abi_param_{index:04d};\n".encode()
                for index, parameter in enumerate(_fixture()["conflicts"][key])
            )
            + (
                "void __oghidra_abi_probe("
                + ", ".join(f"__oghidra_abi_param_{index:04d}" for index in range(arity))
                + ");\n"
            ).encode()
        ).hexdigest()


@pytest.mark.parametrize(
    ("left", "right", "payload", "digest"),
    [
        (
            "void synthetic(uint);",
            "void synthetic(unsigned int);",
            b'{"abi_tuple_schema":1,"arity":1,"calling_convention":"c","parameter_types":["unsigned int"],"prototype_kind":"prototype","return_type":"void","variadic":false}\n',
            "5c14caef4ae18991d24cdfd6c1f2b78a809137b287e50bc635dcf77a82b28a6d",
        ),
        (
            "uint synthetic(void);",
            "unsigned int synthetic(void);",
            b'{"abi_tuple_schema":1,"arity":0,"calling_convention":"c","parameter_types":[],"prototype_kind":"void","return_type":"unsigned int","variadic":false}\n',
            "d25e22e0761cfaa90006e18e308eccaaa492da20122ef1d33fdbd8a28efc278f",
        ),
        (
            "uint synthetic(uint);",
            "unsigned int synthetic(unsigned int);",
            b'{"abi_tuple_schema":1,"arity":1,"calling_convention":"c","parameter_types":["unsigned int"],"prototype_kind":"prototype","return_type":"unsigned int","variadic":false}\n',
            "11acd06ddd182b790b3f9703469d778442bf8874c4bc334b9acdd80ce2887e56",
        ),
    ],
)
def test_real_clang_typedef_equivalence_extracts_exact_payload_before_frame(
    clang_parser: abi.ClangDeclaratorParser, left: str, right: str, payload: bytes, digest: str
):
    left_projection = clang_parser.parse_declaration(left.encode(), "synthetic")
    right_projection = clang_parser.parse_declaration(right.encode(), "synthetic")
    assert left_projection.canonical_prototype != right_projection.canonical_prototype
    assert left_projection.abi_tuple == right_projection.abi_tuple
    assert left_projection.abi_tuple.canonical_bytes() == payload
    assert right_projection.abi_tuple.canonical_bytes() == payload
    assert left_projection.abi_tuple.sha256 == digest
    assert right_projection.abi_tuple.sha256 == digest


@pytest.mark.parametrize(
    ("declaration", "expected_return", "expected_parameter"),
    [
        ("void synthetic(bool);", "void", "bool"),
        ("void synthetic(byte);", "void", "unsigned char"),
        ("void synthetic(longlong);", "void", "long long"),
        ("void synthetic(size_t);", "void", "unsigned long"),
        ("void synthetic(uint);", "void", "unsigned int"),
        ("void synthetic(ulong);", "void", "unsigned long"),
        ("void synthetic(ulonglong);", "void", "unsigned long long"),
        ("void synthetic(undefined);", "void", "unsigned char"),
        ("void synthetic(undefined1);", "void", "unsigned char"),
        ("void synthetic(undefined2);", "void", "unsigned short"),
        ("void synthetic(undefined4);", "void", "unsigned int"),
        ("void synthetic(undefined8);", "void", "unsigned long long"),
        ("void synthetic(ushort);", "void", "unsigned short"),
        ("void synthetic(wchar_t);", "void", "int"),
        ("void synthetic(FILE *);", "void", "struct __oghidra_FILE_v1 *"),
        ("void synthetic(__FILE *);", "void", "struct __oghidra_FILE_v1 *"),
        ("void synthetic(__compar_fn_t);", "void", "int (*)(const void *, const void *)"),
        ("code synthetic(void);", "void", None),
    ],
)
def test_closed_preamble_alias_vocabulary_is_recursive_and_exact(
    clang_parser: abi.ClangDeclaratorParser,
    declaration: str,
    expected_return: str,
    expected_parameter: str | None,
):
    projection = clang_parser.parse_declaration(declaration.encode(), "synthetic")
    assert projection.abi_tuple.return_type == expected_return
    assert projection.abi_tuple.parameter_types == (() if expected_parameter is None else (expected_parameter,))


@pytest.mark.parametrize(
    ("source", "code"),
    [
        (b"void synthetic(FILE value);", "abi_preamble_unknown_or_ambiguous_type"),
        (b"#include <stddef.h>\nvoid synthetic(size_t value);", "abi_preamble_unknown_or_ambiguous_type"),
        (b"#define uint float\nvoid synthetic(uint value);", "abi_preamble_unknown_or_ambiguous_type"),
        (b"void __oghidra_abi_probe(int);", "reserved_abi_identifier"),
        (b"void synthetic(struct { int x; } value);", "abi_preamble_unknown_or_ambiguous_type"),
        (b"void synthetic(int value __attribute__((vector_size(16))));", "gnu11_vector_type_unsupported"),
        (b"void synthetic(int value); void synthetic(int other);", "declaration_ambiguous"),
        (b"void synthetic(int value", "declarator_lexical_imbalance"),
    ],
)
def test_closed_preamble_and_scanner_adversaries_are_typed(
    clang_parser: abi.ClangDeclaratorParser, source: bytes, code: str
):
    with pytest.raises(abi.AssemblyAbiError) as caught:
        clang_parser.parse_declaration(source, "synthetic")
    assert caught.value.refusal.code == code


def test_scanner_ignores_symbol_text_in_comments_strings_chars_and_body(
    clang_parser: abi.ClangDeclaratorParser,
):
    source = (
        b'/* synthetic(int fake) {} */\nvoid synthetic(int value) {\n'
        b'  const char *s = "synthetic(ignored)"; char c = \'{\'; (void)s; (void)c; (void)value;\n}\n'
    )
    projection = clang_parser.parse_definition(source, "synthetic")
    assert projection.canonical_prototype == "void synthetic(int);"


@pytest.mark.parametrize(
    "location",
    [
        {},
        {"offset": 5, "tokLen": 5, "spellingLoc": {}},
        {"offset": -1, "tokLen": 5},
        {"offset": 500, "tokLen": 5},
        {"offset": 5, "tokLen": 4},
        {"offset": True, "tokLen": 5},
    ],
)
def test_parameter_name_erasure_refuses_every_invalid_ast_offset(location: dict):
    source = b"void value(int named);"
    function = {"inner": [{"kind": "ParmVarDecl", "name": "named", "loc": location}]}
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.ClangDeclaratorParser._erase_parameter_names(source, function)
    assert caught.value.refusal.code == "parameter_name_offset_invalid"


def test_parameter_name_erasure_is_byte_exact_and_rejects_overlap():
    source = b"void probe(int left, int right);"
    left, right = source.index(b"left"), source.index(b"right")
    function = {
        "inner": [
            {"kind": "ParmVarDecl", "name": "left", "loc": {"offset": left, "tokLen": 4}},
            {"kind": "ParmVarDecl", "name": "right", "loc": {"offset": right, "tokLen": 5}},
        ]
    }
    assert abi.ClangDeclaratorParser._erase_parameter_names(source, function) == b"void probe(int , int );"
    overlap = {
        "inner": [
            {"kind": "ParmVarDecl", "name": "left", "loc": {"offset": left, "tokLen": 4}},
            {"kind": "ParmVarDecl", "name": "left", "loc": {"offset": left, "tokLen": 4}},
        ]
    }
    with pytest.raises(abi.AssemblyAbiError) as caught:
        abi.ClangDeclaratorParser._erase_parameter_names(source, overlap)
    assert caught.value.refusal.code == "parameter_name_offset_invalid"


class _PrinterParser(abi.ClangDeclaratorParser):
    def __init__(self, output: bytes, baseline: bytes = b""):
        super().__init__(
            Path("clang.exe"),
            abi.ParserIdentity.synthetic("printer-adversary"),
            abi._partition_top_level_declarations(baseline),
        )
        self.output = output

    def _run(self, argv, source, *, code):
        return self.output


@pytest.mark.parametrize(
    "output",
    [
        b"void unrelated(int);\n",
        b"void __oghidra_abi_probe(int);\nvoid __oghidra_abi_probe(float);\n",
        b"void __oghidra_abi_probe(int) {}\n",
        b"#define X\nvoid __oghidra_abi_probe(int);\n",
        b"void __oghidra_abi_probe(int); trailing\n",
        b"garbage\nvoid __oghidra_abi_probe(int);\n",
    ],
)
def test_ast_printer_extraction_fails_closed(output: bytes):
    parser = _PrinterParser(output)
    with pytest.raises(abi.AssemblyAbiError) as caught:
        parser._print_canonical(b"void __oghidra_abi_probe(int);", {"inner": []}, "synthetic")
    assert caught.value.refusal.code == "declarator_emission_invalid"


def test_ast_printer_normalizes_crlf_and_selects_exact_sentinel():
    parser = _PrinterParser(
        b"typedef int unrelated;\r\nvoid __oghidra_abi_probe(int);\r\n",
        b"typedef int unrelated;\n",
    )
    assert parser._print_canonical(
        b"void __oghidra_abi_probe(int);", {"inner": []}, "synthetic"
    ) == "void synthetic(int);"


def test_mandatory_desugared_parameter_and_return_fields_have_no_fallback(
    clang_parser: abi.ClangDeclaratorParser, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(
        clang_parser,
        "_function_ast",
        lambda source, **kwargs: {"inner": [{"kind": "ParmVarDecl", "type": {"qualType": "unsigned int"}}]},
    )
    with pytest.raises(abi.AssemblyAbiError) as missing_parameter:
        clang_parser._abi_tuple("void synthetic(uint);", "synthetic")
    assert missing_parameter.value.refusal.code == "abi_parameter_probe_invalid"

    monkeypatch.setattr(clang_parser, "_function_ast", lambda source, **kwargs: {"inner": []})
    missing_return = {
        "kind": "VarDecl",
        "name": "__oghidra_abi_return_probe",
        "type": {"qualType": "unsigned int"},
    }
    monkeypatch.setattr(clang_parser, "_run", lambda *args, **kwargs: _canonical_bytes(missing_return))
    with pytest.raises(abi.AssemblyAbiError) as caught:
        clang_parser._abi_tuple("uint synthetic(void);", "synthetic")
    assert caught.value.refusal.code == "abi_return_probe_invalid"


@pytest.mark.parametrize("alias", sorted(abi._CLOSED_ALIASES - {"bool"}))
def test_every_forbidden_closed_alias_remnant_refuses_parameter_and_return(alias: str):
    parser = abi.ClangDeclaratorParser(Path("clang.exe"), abi.ParserIdentity.synthetic("alias-remnant"))
    parser._function_ast = lambda source, **kwargs: {  # type: ignore[method-assign]
        "inner": [{"kind": "ParmVarDecl", "type": {"qualType": "int", "desugaredQualType": alias}}]
    }
    with pytest.raises(abi.AssemblyAbiError) as parameter:
        parser._abi_tuple("void synthetic(int);", "synthetic")
    assert parameter.value.refusal.code == "abi_probe_alias_not_desugared"

    parser._function_ast = lambda source, **kwargs: {"inner": []}  # type: ignore[method-assign]
    parser._run = lambda *args, **kwargs: _canonical_bytes(  # type: ignore[method-assign]
        {
            "kind": "VarDecl",
            "name": "__oghidra_abi_return_probe",
            "type": {"qualType": "__oghidra_abi_return_type", "desugaredQualType": alias},
        }
    )
    with pytest.raises(abi.AssemblyAbiError) as returned:
        parser._abi_tuple("int synthetic(void);", "synthetic")
    assert returned.value.refusal.code == "abi_probe_alias_not_desugared"


def test_bool_from_unbound_fake_production_parser_refuses():
    parser = abi.ClangDeclaratorParser(Path("clang.exe"), abi.ParserIdentity.synthetic("fake-bool"))
    parser._function_ast = lambda source, **kwargs: {  # type: ignore[method-assign]
        "inner": [{"kind": "ParmVarDecl", "type": {"qualType": "int", "desugaredQualType": "bool"}}]
    }
    with pytest.raises(abi.AssemblyAbiError) as caught:
        parser._abi_tuple("void synthetic(_Bool);", "synthetic")
    assert caught.value.refusal.code == "abi_probe_alias_not_desugared"


@pytest.mark.parametrize(
    "declaration",
    [
        "void synthetic(FILE const *);",
        "void synthetic(FILE volatile *);",
        "void synthetic(FILE *restrict);",
        "void synthetic(const FILE *);",
        "void synthetic(__FILE const *);",
        "void synthetic(volatile __FILE *);",
    ],
)
def test_file_alias_allows_per_level_qualifiers_only_behind_pointer(
    clang_parser: abi.ClangDeclaratorParser, declaration: str
):
    projection = clang_parser.parse_declaration(declaration.encode(), "synthetic")
    assert "struct __oghidra_FILE_v1" in projection.abi_tuple.parameter_types[0]


@pytest.mark.parametrize(
    "secondary",
    [
        {},
        {"kind": "VarDecl", "name": "wrong", "type": {"qualType": "__oghidra_abi_adjusted_param_type_0000", "desugaredQualType": "unsigned int *"}},
        {"kind": "VarDecl", "name": "__oghidra_abi_adjusted_param_probe_0000", "type": {"qualType": "wrong", "desugaredQualType": "unsigned int *"}},
        {"kind": "VarDecl", "name": "__oghidra_abi_adjusted_param_probe_0000", "type": {"qualType": "__oghidra_abi_adjusted_param_type_0000"}},
    ],
)
def test_adjusted_array_secondary_probe_is_strict_and_never_uses_primary_qualtype(secondary: dict):
    parser = abi.ClangDeclaratorParser(Path("clang.exe"), abi.ParserIdentity.synthetic("adjusted-array"))
    parser._function_ast = lambda source, **kwargs: {  # type: ignore[method-assign]
        "inner": [{"kind": "ParmVarDecl", "type": {"qualType": "unsigned int *"}}]
    }
    parser._run = lambda *args, **kwargs: _canonical_bytes(secondary)  # type: ignore[method-assign]
    with pytest.raises(abi.AssemblyAbiError) as caught:
        parser._abi_tuple("void synthetic(unsigned int[4]);", "synthetic")
    assert caught.value.refusal.code == "abi_adjusted_parameter_probe_invalid"


class _CompatibilityParser(abi.ClangDeclaratorParser):
    def __init__(self, ast: dict):
        super().__init__(Path("clang.exe"), abi.ParserIdentity.synthetic("compatibility-adversary"))
        self.ast = ast
        self.argv = None

    def _run(self, argv, source, *, code):
        self.argv = argv
        return _canonical_bytes(self.ast)


def _compatibility_ast(value: str = "1") -> dict:
    return {
        "kind": "EnumConstantDecl",
        "name": "__oghidra_abi_compat_result",
        "type": {"qualType": "int"},
        "inner": [
            {
                "kind": "ConstantExpr",
                "type": {"qualType": "int"},
                "valueCategory": "prvalue",
                "value": value,
                "inner": [{"kind": "TypeTraitExpr"}],
            }
        ],
    }


def test_compatibility_json_projection_and_argv_are_strict():
    left = abi.DeclaratorProjection.synthetic("synthetic", "void synthetic(int);", "void", ("int",))
    right = abi.DeclaratorProjection.synthetic("synthetic", "void synthetic(const int);", "void", ("const int",))
    parser = _CompatibilityParser(_compatibility_ast())
    result = parser.compatibility(left, right)
    assert result.compatible is True
    assert parser.argv == abi.json_argv("clang.exe", "__oghidra_abi_compat_result")
    assert hashlib.sha256(result.source).hexdigest() == result.source_sha256
    for mutate in (
        lambda ast: ast.update(type={"qualType": "long"}),
        lambda ast: ast["inner"][0].update(value="2"),
        lambda ast: ast["inner"][0].update(valueCategory="lvalue"),
        lambda ast: ast["inner"][0].update(inner=[]),
        lambda ast: ast.update(inner=[]),
    ):
        malformed = _compatibility_ast()
        mutate(malformed)
        with pytest.raises(abi.AssemblyAbiError) as caught:
            _CompatibilityParser(malformed).compatibility(left, right)
        assert caught.value.refusal.code == "abi_compatibility_probe_invalid"


@pytest.mark.parametrize(
    ("source", "code"),
    [
        (b"void synthetic(a) int a; {}\n", "gnu11_knr_definition_unsupported"),
        (b"void synthetic(typeof(int) value) {}\n", "gnu11_typeof_unsupported"),
        (b"void synthetic(int value) __asm__(\"alias\") {}\n", "gnu11_asm_label_unsupported"),
        (b"void __attribute__((vectorcall)) synthetic(int value) {}\n", "registry_shape_unrepresentable_attribute"),
        (b"void synthetic(_ExtInt(17) value) {}\n", "gnu11_extended_integer_unsupported"),
        (b"void synthetic(struct missing value) {}\n", "abi_preamble_unknown_or_ambiguous_type"),
    ],
)
def test_real_clang_gnu11_refusals_are_typed(
    source: bytes, code: str, clang_parser: abi.ClangDeclaratorParser
):
    parser = clang_parser
    with pytest.raises(abi.AssemblyAbiError) as caught:
        parser.parse_definition(source, "synthetic")
    assert caught.value.refusal.code == code
