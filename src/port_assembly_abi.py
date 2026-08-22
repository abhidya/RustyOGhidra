"""Owner-derived canonicalization and composition evidence for Wasm assembly.

This is deliberately a deep, side-effect-light module.  It reads immutable
owner evidence and may invoke the injected declarator parser, but it never
writes files, runs an assembly compiler/linker/smoke test, mutates Git, or
touches the port journal/state.  Callers cross five phase-oriented seams:
``load_owner_snapshot``, ``plan_canonicalization``, ``analyze_composition``,
``revalidate_receipt``, and ``finalize_composition``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import unicodedata
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Literal, Mapping, Protocol, Sequence


ABI_PREAMBLE_V1 = b"""_Static_assert(__CHAR_BIT__ == 8, "ABI_PREAMBLE_V1 char");
_Static_assert(sizeof(_Bool) == 1, "ABI_PREAMBLE_V1 bool");
_Static_assert(__SIZEOF_SHORT__ == 2, "ABI_PREAMBLE_V1 short");
_Static_assert(__SIZEOF_INT__ == 4, "ABI_PREAMBLE_V1 int");
_Static_assert(__SIZEOF_LONG__ == 4, "ABI_PREAMBLE_V1 long");
_Static_assert(__SIZEOF_LONG_LONG__ == 8, "ABI_PREAMBLE_V1 long long");
_Static_assert(__SIZEOF_POINTER__ == 4, "ABI_PREAMBLE_V1 pointer");
_Static_assert(__SIZEOF_FLOAT__ == 4, "ABI_PREAMBLE_V1 float");
_Static_assert(__SIZEOF_DOUBLE__ == 8, "ABI_PREAMBLE_V1 double");
_Static_assert(__SIZEOF_WCHAR_T__ == 4, "ABI_PREAMBLE_V1 wchar_t");
_Static_assert(__SIZEOF_SIZE_T__ == 4, "ABI_PREAMBLE_V1 size_t");
typedef struct __oghidra_FILE_v1 FILE;
typedef struct __oghidra_FILE_v1 __FILE;
typedef int (*__compar_fn_t)(const void *, const void *);
typedef _Bool bool;
typedef unsigned char byte;
typedef void code;
typedef long long longlong;
typedef unsigned long size_t;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef unsigned long long ulonglong;
typedef unsigned char undefined;
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined4;
typedef unsigned long long undefined8;
typedef unsigned short ushort;
typedef int wchar_t;
#define FILE struct __oghidra_FILE_v1
#define __FILE struct __oghidra_FILE_v1
#define __compar_fn_t __typeof__(int (*)(const void *, const void *))
#define bool _Bool
#define byte unsigned char
#define code void
#define longlong long long
#define size_t unsigned long
#define uint unsigned int
#define ulong unsigned long
#define ulonglong unsigned long long
#define undefined unsigned char
#define undefined1 unsigned char
#define undefined2 unsigned short
#define undefined4 unsigned int
#define undefined8 unsigned long long
#define ushort unsigned short
#define wchar_t int
"""

ABI_SPELLING_UNDEF_V1 = b"""#undef FILE
#undef __FILE
#undef __compar_fn_t
#undef bool
#undef byte
#undef code
#undef longlong
#undef size_t
#undef uint
#undef ulong
#undef ulonglong
#undef undefined
#undef undefined1
#undef undefined2
#undef undefined4
#undef undefined8
#undef ushort
#undef wchar_t
"""

ABI_PREAMBLE_V1_SHA256 = hashlib.sha256(ABI_PREAMBLE_V1).hexdigest()
ABI_SPELLING_UNDEF_V1_SHA256 = hashlib.sha256(ABI_SPELLING_UNDEF_V1).hexdigest()
ABI_TARGET = "wasm32-unknown-emscripten"
ABI_DIALECT = "gnu11"
ABI_COMPATIBILITY_LINE = (
    b"enum { __oghidra_abi_compat_result = "
    b"__builtin_types_compatible_p(__typeof__(&__oghidra_abi_compat_left), "
    b"__typeof__(&__oghidra_abi_compat_right)) };\n"
)

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_IDENTIFIER_BYTES_RE = re.compile(rb"[A-Za-z_][A-Za-z0-9_]*")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_INTERNAL_RE = re.compile(r"^(?:zz_[0-9A-Fa-f]{7}_|FUN_80[0-9A-Fa-f]{6})$")
_LABEL_ADDRESS_RE = re.compile(r"^zz_([0-9A-Fa-f]{7})_$")
_FUN_ADDRESS_RE = re.compile(r"^FUN_([0-9A-Fa-f]{8})$")
_MARKER_RE = re.compile(rb"^\s*//\s*====\s*([0-9A-Fa-f]{8})\s+([A-Za-z_][A-Za-z0-9_]*)\s*====\s*$")
_VERBATIM_MARKER = b"/* ==== VERBATIM:"
_CONTROL_WORDS = {
    "if", "for", "while", "switch", "return", "sizeof", "_Alignof", "__typeof__", "typeof",
}
_EXTERNAL_PREFIXES = ("gnt4_", "emscripten_", "invoke_", "dynCall_", "__")
_CLOSED_ALIASES = frozenset(
    {
        "FILE", "__FILE", "__compar_fn_t", "bool", "byte", "code", "longlong",
        "size_t", "uint", "ulong", "ulonglong", "undefined", "undefined1",
        "undefined2", "undefined4", "undefined8", "ushort", "wchar_t",
    }
)
_FORBIDDEN_DESUGARED_ALIASES = _CLOSED_ALIASES - {"bool"}
_FAULT_CLASSES = frozenset({"spawn", "timeout", "crash", "io", "lock", "stable_read"})
_STAGES = ("compile", "inspect", "link", "instantiate", "smoke")


def _json_ready(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _json_ready(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_ready(item) for item in value]
    return value


def _deep_freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _deep_freeze(item) for key, item in value.items()})
    if isinstance(value, (tuple, list)):
        return tuple(_deep_freeze(item) for item in value)
    return value


def _canonical_bytes(value: object) -> bytes:
    return (json.dumps(_json_ready(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def _hash_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _framed_hash(label: bytes, payload: bytes) -> str:
    return _hash_bytes(label + b"\0" + len(payload).to_bytes(8, "big") + payload)


def json_argv(executable: str, filter_name: str = "__oghidra_abi_probe") -> tuple[str, ...]:
    return (
        executable,
        f"--target={ABI_TARGET}",
        f"-std={ABI_DIALECT}",
        "-x",
        "c",
        "-Xclang",
        "-ast-dump=json",
        "-Xclang",
        "-ast-dump-filter",
        "-Xclang",
        filter_name,
        "-fsyntax-only",
        "-",
    )


def print_argv(executable: str) -> tuple[str, ...]:
    return (
        executable,
        f"--target={ABI_TARGET}",
        f"-std={ABI_DIALECT}",
        "-x",
        "c",
        "-Xclang",
        "-ast-print",
        "-fsyntax-only",
        "-",
    )


@dataclass(frozen=True)
class AssemblyAbiRefusal:
    code: str
    stage: str
    detail: str
    evidence_sha256: str | None = None
    revalidation_check: object | None = None


class AssemblyAbiError(ValueError):
    def __init__(self, refusal: AssemblyAbiRefusal):
        self.refusal = refusal
        super().__init__(f"{refusal.code}: {refusal.detail}")


def _fail(code: str, stage: str, detail: str, evidence: bytes | None = None) -> None:
    raise AssemblyAbiError(AssemblyAbiRefusal(code, stage, detail, _hash_bytes(evidence) if evidence is not None else None))


@dataclass(frozen=True)
class StableFileIdentity:
    device: int
    inode: int
    mode: int
    link_count: int
    size: int
    mtime_ns: int
    reparse_tag: int

    def to_dict(self) -> dict[str, int]:
        return {
            "device": self.device,
            "inode": self.inode,
            "link_count": self.link_count,
            "mode": self.mode,
            "mtime_ns": self.mtime_ns,
            "reparse_tag": self.reparse_tag,
            "size": self.size,
        }


@dataclass(frozen=True)
class StableBytes:
    data: bytes
    identity: StableFileIdentity
    sha256: str


def _identity(value: os.stat_result) -> StableFileIdentity:
    return StableFileIdentity(
        device=int(value.st_dev),
        inode=int(value.st_ino),
        # Windows reports different permission bits for a path stat and the
        # already-open handle to the same file.  The file-kind bits are the
        # stable mode identity; reparse/type/link checks are separate.
        mode=int(stat.S_IFMT(value.st_mode)),
        link_count=int(value.st_nlink),
        size=int(value.st_size),
        mtime_ns=int(value.st_mtime_ns),
        reparse_tag=int(getattr(value, "st_reparse_tag", 0) or 0),
    )


def _is_reparse(value: os.stat_result) -> bool:
    attributes = int(getattr(value, "st_file_attributes", 0) or 0)
    flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return bool(getattr(value, "st_reparse_tag", 0) or attributes & flag)


def _stable_read(path: Path, *, code: str = "stable_read_refused") -> StableBytes:
    try:
        before_stat = os.lstat(path)
    except OSError as exc:
        _fail(code, "owner", f"cannot stat {path}: {exc}")
    if stat.S_ISLNK(before_stat.st_mode) or _is_reparse(before_stat):
        _fail("product_path_special", "owner", f"reparse/symlink path refused: {path}")
    if not stat.S_ISREG(before_stat.st_mode):
        _fail("product_path_special", "owner", f"ordinary file required: {path}")
    if before_stat.st_nlink != 1:
        _fail("product_path_hardlinked", "owner", f"hard-linked file refused: {path}")
    before = _identity(before_stat)
    try:
        with path.open("rb") as handle:
            opened = _identity(os.fstat(handle.fileno()))
            data = handle.read()
            after_handle = _identity(os.fstat(handle.fileno()))
        after = _identity(os.lstat(path))
    except OSError as exc:
        _fail(code, "owner", f"stable read failed for {path}: {exc}")
    if before != opened or opened != after_handle or after_handle != after or len(data) != before.size:
        _fail("stable_read_race", "owner", f"identity or metadata changed while reading {path}")
    return StableBytes(data, before, _hash_bytes(data))


def _validate_product_root(product_root: Path) -> Path:
    if not isinstance(product_root, (str, os.PathLike)):
        _fail("product_root_invalid", "owner", "product_root must be a path")
    root = Path(product_root)
    if not root.is_absolute():
        _fail("product_root_invalid", "owner", "product_root must be absolute")
    anchor = Path(root.anchor)
    current = anchor
    for part in root.parts[1:]:
        try:
            if [entry.name for entry in os.scandir(current) if entry.name == part] != [part]:
                _fail("product_root_invalid", "owner", f"product_root component spelling mismatch: {part!r}")
            current = current / part
            info = os.lstat(current)
        except OSError as exc:
            _fail("product_root_invalid", "owner", f"product_root is unavailable: {exc}")
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or _is_reparse(info):
            _fail("product_root_invalid", "owner", "product_root must contain only ordinary directory components")
    return root.resolve(strict=True)


def _validate_relpath(value: object, *, prefix: str | None = None, suffix: str | None = None) -> str:
    if not isinstance(value, str) or not value or value != unicodedata.normalize("NFC", value):
        _fail("product_path_invalid", "owner", f"nonempty NFC relative path required: {value!r}")
    if "\\" in value or value.startswith(("/", "//")) or re.match(r"^[A-Za-z]:", value):
        _fail("product_path_invalid", "owner", f"absolute/Windows path syntax refused: {value!r}")
    parts = value.split("/")
    if any(not item or item in {".", ".."} or ":" in item or any(ord(char) < 32 or ord(char) == 127 for char in item) for item in parts):
        _fail("product_path_invalid", "owner", f"unsafe path segment: {value!r}")
    if PurePosixPath(value).as_posix() != value:
        _fail("product_path_invalid", "owner", f"noncanonical POSIX path: {value!r}")
    if prefix is not None and not value.startswith(prefix):
        _fail("product_path_invalid", "owner", f"required prefix {prefix!r} absent: {value!r}")
    if suffix is not None and not value.endswith(suffix):
        _fail("product_path_invalid", "owner", f"required suffix {suffix!r} absent: {value!r}")
    return value


def _join_exact(root: Path, relpath: str, *, final_kind: Literal["file", "directory"] = "file") -> Path:
    current = root
    for index, part in enumerate(relpath.split("/")):
        try:
            exact = [entry.name for entry in os.scandir(current) if entry.name == part]
        except OSError as exc:
            _fail("product_path_missing", "owner", f"cannot enumerate {current}: {exc}")
        if exact != [part]:
            _fail("product_path_spelling_mismatch", "owner", f"exact path component is absent: {part!r} under {current}")
        current = current / part
        try:
            info = os.lstat(current)
        except OSError as exc:
            _fail("product_path_missing", "owner", f"cannot stat {current}: {exc}")
        if stat.S_ISLNK(info.st_mode) or _is_reparse(info):
            _fail("product_path_special", "owner", f"reparse/symlink path refused: {current}")
        is_last = index == len(relpath.split("/")) - 1
        required_directory = not is_last or final_kind == "directory"
        if required_directory and not stat.S_ISDIR(info.st_mode):
            _fail("product_path_special", "owner", f"ordinary directory required: {current}")
        if is_last and final_kind == "file" and not stat.S_ISREG(info.st_mode):
            _fail("product_path_special", "owner", f"ordinary file required: {current}")
    try:
        resolved = current.resolve(strict=True)
    except OSError as exc:
        _fail("product_path_missing", "owner", f"cannot resolve {current}: {exc}")
    try:
        resolved.relative_to(root)
    except ValueError:
        _fail("product_path_escape", "owner", f"path escaped product root: {current}")
    if os.path.commonpath((os.path.normcase(str(root)), os.path.normcase(str(resolved)))) != os.path.normcase(str(root)):
        _fail("product_path_escape", "owner", f"case-folded path escaped product root: {current}")
    return current


def _registry_relpath(root: Path, registry_path: Path) -> str:
    path = Path(registry_path)
    if not path.is_absolute():
        _fail("product_path_invalid", "owner", "registry_path must be absolute")
    try:
        rel = path.relative_to(root).as_posix()
    except ValueError:
        _fail("product_path_escape", "owner", "registry_path must be inside product_root")
    return _validate_relpath(rel)


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _parse_json(data: bytes) -> Any:
    try:
        text = data.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=_object_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(ValueError(f"invalid constant {token}")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        _fail("oracle_registry_json_invalid", "owner", f"registry JSON refused: {exc}")


def _require_keys(value: object, keys: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        _fail(code, "owner", f"expected exact keys {sorted(keys)!r}")
    return value


def _nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value) and value == unicodedata.normalize("NFC", value)


def _nonnegative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _string_count_map(value: object) -> bool:
    return isinstance(value, dict) and all(_nonempty_string(key) and _nonnegative_int(item) for key, item in value.items())


FUNCTION_KEYS = {
    "name", "address", "unit", "chunk_file", "line_range", "loc", "return_type", "params", "returns_value",
    "has_pointer_args", "external_callees", "global_refs", "ts_citations", "citation_grade", "citation_scan_skipped",
    "structural_class", "gap_alignment",
}
RANKED_KEYS = {
    "unit", "oracle_kind", "max_structural_class", "fn_count", "gap_partial_slots", "port_citations", "port_grade_fns",
    "total_citations", "total_loc", "gap_family_ctors", "fully_gap_aligned",
}
SUMMARY_KEYS = {
    "functions_total", "units_total", "excluded_total", "excluded_reasons", "structural_class_counts",
    "citation_grade_counts", "class_by_citation_grade", "gap_aligned_functions", "gap_aligned_functions_partial_family",
    "fully_gap_aligned_units", "fully_gap_aligned_unit_names", "oracle_able_units", "oracle_able_unit_names", "anomalies",
}
ORACLE_BUCKETS = {"differential_vs_ts", "state_diff", "citations_no_family", "trace_only"}


def _validate_function(record: object) -> dict[str, Any]:
    item = _require_keys(record, FUNCTION_KEYS, "oracle_registry_function_invalid")
    if not _nonempty_string(item["name"]) or _IDENTIFIER_RE.fullmatch(item["name"]) is None:
        _fail("oracle_registry_function_invalid", "owner", "function name must be a C identifier")
    if not isinstance(item["address"], str) or re.fullmatch(r"0x[0-9a-f]{8}", item["address"]) is None:
        _fail("oracle_registry_function_invalid", "owner", f"invalid address for {item['name']}")
    if not _nonempty_string(item["unit"]):
        _fail("oracle_registry_function_invalid", "owner", f"invalid unit for {item['name']}")
    _validate_relpath(item["chunk_file"], prefix="research/decomp/ghidra-export/", suffix=".c")
    lines = item["line_range"]
    if not isinstance(lines, list) or len(lines) != 2 or not all(_positive_int(number) for number in lines) or lines[0] > lines[1]:
        _fail("oracle_registry_function_invalid", "owner", f"invalid line range for {item['name']}")
    if not _positive_int(item["loc"]) or item["loc"] != lines[1] - lines[0] + 1:
        _fail("oracle_registry_function_invalid", "owner", f"loc mismatch for {item['name']}")
    if not _nonempty_string(item["return_type"]):
        _fail("oracle_registry_function_invalid", "owner", f"invalid return type for {item['name']}")
    params = item["params"]
    if not isinstance(params, list) or not all(_nonempty_string(value) for value in params):
        _fail("oracle_registry_function_invalid", "owner", f"invalid params for {item['name']}")
    if "void" in params and params != ["void"]:
        _fail("oracle_registry_function_invalid", "owner", f"void parameter placement invalid for {item['name']}")
    if any(_top_level_comma(value) for value in params):
        _fail("oracle_registry_function_invalid", "owner", f"top-level comma in parameter for {item['name']}")
    if type(item["returns_value"]) is not bool or item["returns_value"] != (item["return_type"].strip() not in {"void", "code"}):
        _fail("oracle_registry_function_invalid", "owner", f"returns_value mismatch for {item['name']}")
    if type(item["has_pointer_args"]) is not bool or item["has_pointer_args"] != any("*" in value or "[" in value for value in params):
        _fail("oracle_registry_function_invalid", "owner", f"has_pointer_args mismatch for {item['name']}")
    callees = _require_keys(item["external_callees"], {"count", "list"}, "oracle_registry_function_invalid")
    if not _nonnegative_int(callees["count"]) or not isinstance(callees["list"], list) or not all(_nonempty_string(value) for value in callees["list"]):
        _fail("oracle_registry_function_invalid", "owner", f"external callees invalid for {item['name']}")
    if callees["list"] != sorted(set(callees["list"])) or callees["count"] != len(callees["list"]):
        _fail("oracle_registry_function_invalid", "owner", f"external callee ordering/count mismatch for {item['name']}")
    refs = item["global_refs"]
    if not isinstance(refs, list):
        _fail("oracle_registry_function_invalid", "owner", f"global_refs invalid for {item['name']}")
    ref_keys: list[tuple[str, str]] = []
    for ref in refs:
        ref = _require_keys(ref, {"symbol", "prefix_type", "width_known"}, "oracle_registry_function_invalid")
        if not isinstance(ref["symbol"], str) or not isinstance(ref["prefix_type"], str) or type(ref["width_known"]) is not bool:
            _fail("oracle_registry_function_invalid", "owner", f"global ref invalid for {item['name']}")
        ref_keys.append((ref["symbol"], ref["prefix_type"]))
    if len(ref_keys) != len(set(ref_keys)):
        _fail("oracle_registry_function_invalid", "owner", f"duplicate global ref for {item['name']}")
    citations = item["ts_citations"]
    if not isinstance(citations, list):
        _fail("oracle_registry_function_invalid", "owner", f"citations invalid for {item['name']}")
    citation_keys: list[tuple[str, str]] = []
    for citation in citations:
        citation = _require_keys(citation, {"where", "grade"}, "oracle_registry_function_invalid")
        if not _nonempty_string(citation["where"]) or re.fullmatch(r"[^:]+:[1-9][0-9]*", citation["where"]) is None:
            _fail("oracle_registry_function_invalid", "owner", f"citation path invalid for {item['name']}")
        path_text = citation["where"].rsplit(":", 1)[0]
        _validate_relpath(path_text)
        if not isinstance(citation["grade"], str) or citation["grade"] not in {"port", "unported", "weak"}:
            _fail("oracle_registry_function_invalid", "owner", f"citation grade invalid for {item['name']}")
        citation_keys.append((citation["where"], citation["grade"]))
    if len(citation_keys) != len(set(citation_keys)):
        _fail("oracle_registry_function_invalid", "owner", f"duplicate citation for {item['name']}")
    if item["citation_grade"] is not None and (
        not isinstance(item["citation_grade"], str)
        or item["citation_grade"] not in {"port", "unported", "weak", "none"}
    ):
        _fail("oracle_registry_function_invalid", "owner", f"citation_grade invalid for {item['name']}")
    if item["citation_scan_skipped"] is not None and (
        not isinstance(item["citation_scan_skipped"], str)
        or item["citation_scan_skipped"] != "ambiguous_name"
    ):
        _fail("oracle_registry_function_invalid", "owner", f"citation_scan_skipped invalid for {item['name']}")
    if not isinstance(item["structural_class"], str) or item["structural_class"] not in {"A", "B", "C", "D", "E"}:
        _fail("oracle_registry_function_invalid", "owner", f"structural class invalid for {item['name']}")
    if item["gap_alignment"] is not None:
        gap = _require_keys(item["gap_alignment"], {"family_ctor", "partial_slots", "members"}, "oracle_registry_function_invalid")
        if (
            not isinstance(gap["family_ctor"], str)
            or re.fullmatch(r"0x[0-9a-f]{8}", gap["family_ctor"]) is None
            or not _nonnegative_int(gap["partial_slots"])
        ):
            _fail("oracle_registry_function_invalid", "owner", f"gap alignment invalid for {item['name']}")
        if not isinstance(gap["members"], list) or not all(_nonempty_string(value) for value in gap["members"]) or len(gap["members"]) != len(set(gap["members"])):
            _fail("oracle_registry_function_invalid", "owner", f"gap members invalid for {item['name']}")
    return item


def _validate_registry(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or "oracle_registry_schema" not in value:
        _fail("oracle_registry_schema_invalid", "owner", "oracle_registry_schema must be present and integer 1")
    top = _require_keys(
        value,
        {"oracle_registry_schema", "meta", "summary", "ranked_units", "functions", "excluded"},
        "oracle_registry_shape_invalid",
    )
    if type(top["oracle_registry_schema"]) is not int or top["oracle_registry_schema"] != 1:
        _fail("oracle_registry_schema_invalid", "owner", "oracle_registry_schema must be integer 1")
    meta = _require_keys(top["meta"], {"generated_by", "inputs", "conventions"}, "oracle_registry_meta_invalid")
    if not _nonempty_string(meta["generated_by"]):
        _fail("oracle_registry_meta_invalid", "owner", "generated_by must be nonempty")
    inputs = _require_keys(meta["inputs"], {"queue", "skipped", "chunk_index", "family_coverage"}, "oracle_registry_meta_invalid")
    for value in inputs.values():
        _validate_relpath(value)
    conventions = _require_keys(
        meta["conventions"],
        {"address", "structural_class", "citation_grade", "gap_alignment", "ranked_units_sort", "oracle_able_units"},
        "oracle_registry_meta_invalid",
    )
    if not all(_nonempty_string(item) for item in conventions.values()):
        _fail("oracle_registry_meta_invalid", "owner", "all conventions must be nonempty strings")

    if not isinstance(top["functions"], list):
        _fail("oracle_registry_function_invalid", "owner", "functions must be a list")
    functions = [_validate_function(item) for item in top["functions"]]
    names = [item["name"] for item in functions]
    addresses = [item["address"] for item in functions]
    if len(names) != len(set(names)):
        _fail("owner_ambiguous", "owner", "function names must be globally unique")
    if len(addresses) != len(set(addresses)):
        _fail("owner_address_ambiguous", "owner", "authoritative addresses must be globally unique")
    if functions != sorted(functions, key=lambda item: (item["address"], item["name"])):
        _fail("owner_records_unsorted", "owner", "function records must sort by address then name")

    if not isinstance(top["ranked_units"], list):
        _fail("oracle_registry_ranked_invalid", "owner", "ranked_units must be a list")
    for row in top["ranked_units"]:
        row = _require_keys(row, RANKED_KEYS, "oracle_registry_ranked_invalid")
        if not all(_nonempty_string(row[key]) for key in ("unit", "oracle_kind", "max_structural_class")):
            _fail("oracle_registry_ranked_invalid", "owner", "ranked string fields invalid")
        if not all(_nonnegative_int(row[key]) for key in ("fn_count", "gap_partial_slots", "port_citations", "port_grade_fns", "total_citations", "total_loc")):
            _fail("oracle_registry_ranked_invalid", "owner", "ranked counts invalid")
        if not isinstance(row["gap_family_ctors"], list) or not all(_nonempty_string(item) for item in row["gap_family_ctors"]):
            _fail("oracle_registry_ranked_invalid", "owner", "gap_family_ctors invalid")
        if type(row["fully_gap_aligned"]) is not bool:
            _fail("oracle_registry_ranked_invalid", "owner", "fully_gap_aligned must be bool")
    ranked_names = [row["unit"] for row in top["ranked_units"]]
    if len(ranked_names) != len(set(ranked_names)):
        _fail("oracle_registry_ranked_invalid", "owner", "ranked unit names must be unique")
    ranked_sort = sorted(
        top["ranked_units"],
        key=lambda row: (-row["gap_partial_slots"], -row["port_citations"], row["max_structural_class"], row["total_loc"], row["unit"]),
    )
    if top["ranked_units"] != ranked_sort:
        _fail("oracle_registry_ranked_invalid", "owner", "ranked units violate the bound sort")

    if not isinstance(top["excluded"], list):
        _fail("oracle_registry_excluded_invalid", "owner", "excluded must be a list")
    for row in top["excluded"]:
        row = _require_keys(row, {"name", "address", "chunk", "reason"}, "oracle_registry_excluded_invalid")
        if not all(_nonempty_string(row[key]) for key in row):
            _fail("oracle_registry_excluded_invalid", "owner", "excluded strings must be nonempty")

    summary = _require_keys(top["summary"], SUMMARY_KEYS, "oracle_registry_summary_invalid")
    int_fields = {
        "functions_total", "units_total", "excluded_total", "gap_aligned_functions",
        "gap_aligned_functions_partial_family", "fully_gap_aligned_units",
    }
    if not all(_nonnegative_int(summary[key]) for key in int_fields):
        _fail("oracle_registry_summary_invalid", "owner", "summary integer fields invalid")
    if not all(_string_count_map(summary[key]) for key in ("excluded_reasons", "structural_class_counts", "citation_grade_counts")):
        _fail("oracle_registry_summary_invalid", "owner", "summary count maps invalid")
    if not isinstance(summary["class_by_citation_grade"], dict) or not all(_nonempty_string(key) and _string_count_map(item) for key, item in summary["class_by_citation_grade"].items()):
        _fail("oracle_registry_summary_invalid", "owner", "class_by_citation_grade invalid")
    for key in ("fully_gap_aligned_unit_names", "anomalies"):
        if not isinstance(summary[key], list) or not all(_nonempty_string(item) for item in summary[key]):
            _fail("oracle_registry_summary_invalid", "owner", f"{key} invalid")
    if len(summary["fully_gap_aligned_unit_names"]) != len(set(summary["fully_gap_aligned_unit_names"])):
        _fail("oracle_registry_summary_invalid", "owner", "fully aligned names must be unique")
    if (
        not isinstance(summary["oracle_able_units"], dict)
        or set(summary["oracle_able_units"]) != ORACLE_BUCKETS
        or not all(_nonnegative_int(item) for item in summary["oracle_able_units"].values())
    ):
        _fail("oracle_registry_summary_invalid", "owner", "oracle_able_units invalid")
    if not isinstance(summary["oracle_able_unit_names"], dict) or set(summary["oracle_able_unit_names"]) != ORACLE_BUCKETS:
        _fail("oracle_registry_summary_invalid", "owner", "oracle_able_unit_names invalid")
    for key, values in summary["oracle_able_unit_names"].items():
        if not isinstance(values, list) or not all(_nonempty_string(item) for item in values) or values != sorted(set(values)):
            _fail("oracle_registry_summary_invalid", "owner", f"oracle bucket {key} names invalid")
        if summary["oracle_able_units"][key] != len(values):
            _fail("oracle_registry_summary_invalid", "owner", f"oracle bucket {key} count mismatch")
    units = {item["unit"] for item in functions}
    expected_class: dict[str, int] = {}
    expected_grade: dict[str, int] = {}
    expected_cross: dict[str, dict[str, int]] = {}
    for item in functions:
        grade = (
            "ambiguous_name"
            if item["citation_scan_skipped"] == "ambiguous_name"
            else item["citation_grade"] if item["citation_grade"] is not None else "none"
        )
        expected_class[item["structural_class"]] = expected_class.get(item["structural_class"], 0) + 1
        expected_grade[grade] = expected_grade.get(grade, 0) + 1
        structural = item["structural_class"]
        expected_cross.setdefault(structural, {})[grade] = expected_cross.setdefault(structural, {}).get(grade, 0) + 1
    expected_excluded: dict[str, int] = {}
    for item in top["excluded"]:
        expected_excluded[item["reason"]] = expected_excluded.get(item["reason"], 0) + 1
    expected = {
        "functions_total": len(functions),
        "units_total": len(units),
        "excluded_total": len(top["excluded"]),
        "excluded_reasons": expected_excluded,
        "structural_class_counts": expected_class,
        "citation_grade_counts": expected_grade,
        "class_by_citation_grade": expected_cross,
        "gap_aligned_functions": sum(item["gap_alignment"] is not None for item in functions),
        "gap_aligned_functions_partial_family": sum(
            item["gap_alignment"] is not None and item["gap_alignment"]["partial_slots"] > 0 for item in functions
        ),
    }
    for key, expected_value in expected.items():
        if summary[key] != expected_value:
            _fail("oracle_registry_summary_invalid", "owner", f"summary {key} does not agree with records")
    fully_names = sorted(row["unit"] for row in top["ranked_units"] if row["fully_gap_aligned"])
    if summary["fully_gap_aligned_unit_names"] != fully_names or summary["fully_gap_aligned_units"] != len(fully_names):
        _fail("oracle_registry_summary_invalid", "owner", "fully-gap-aligned summary disagrees with ranked units")
    ranked_by_unit = {row["unit"]: row for row in top["ranked_units"]}
    if set(ranked_by_unit) != units:
        _fail("oracle_registry_ranked_invalid", "owner", "ranked units must cover every function unit exactly once")
    functions_by_unit: dict[str, list[dict[str, Any]]] = {}
    for item in functions:
        functions_by_unit.setdefault(item["unit"], []).append(item)
    for unit, rows in functions_by_unit.items():
        ranked = ranked_by_unit[unit]
        exact_counts = {
            "fn_count": len(rows),
            "gap_partial_slots": sum(
                row["gap_alignment"]["partial_slots"] if row["gap_alignment"] is not None else 0 for row in rows
            ),
            "port_citations": sum(
                citation["grade"] == "port" for row in rows for citation in row["ts_citations"]
            ),
            "port_grade_fns": sum(row["citation_grade"] == "port" for row in rows),
            "total_citations": sum(len(row["ts_citations"]) for row in rows),
            "total_loc": sum(row["loc"] for row in rows),
        }
        for key, expected_value in exact_counts.items():
            if ranked[key] != expected_value:
                _fail("oracle_registry_ranked_invalid", "owner", f"ranked {key} disagrees for {unit}")
        if ranked["max_structural_class"] != max(row["structural_class"] for row in rows):
            _fail("oracle_registry_ranked_invalid", "owner", f"ranked max class disagrees for {unit}")
        family_ctors = sorted(
            {row["gap_alignment"]["family_ctor"] for row in rows if row["gap_alignment"] is not None}
        )
        if ranked["gap_family_ctors"] != family_ctors:
            _fail("oracle_registry_ranked_invalid", "owner", f"ranked gap families disagree for {unit}")
    expected_bucket_names = {key: [] for key in ORACLE_BUCKETS}
    for row in top["ranked_units"]:
        if not isinstance(row["oracle_kind"], str) or row["oracle_kind"] not in ORACLE_BUCKETS:
            _fail("oracle_registry_ranked_invalid", "owner", f"unknown oracle kind for {row['unit']}")
        expected_bucket_names[row["oracle_kind"]].append(row["unit"])
    expected_bucket_names = {key: sorted(values) for key, values in expected_bucket_names.items()}
    if summary["oracle_able_unit_names"] != expected_bucket_names:
        _fail("oracle_registry_summary_invalid", "owner", "oracle bucket names disagree with ranked units")
    return top


def _top_level_comma(text: str) -> bool:
    depth = 0
    for char in text:
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        elif char == "," and depth == 0:
            return True
    return False


@dataclass(frozen=True)
class AbiTuple:
    return_type: str
    parameter_types: tuple[str, ...]
    prototype_kind: Literal["unspecified", "void", "prototype"]
    variadic: bool
    abi_tuple_schema: int = field(default=1, init=False)
    calling_convention: Literal["c"] = field(default="c", init=False)

    @property
    def arity(self) -> int:
        return len(self.parameter_types)

    def to_dict(self) -> dict[str, object]:
        return {
            "abi_tuple_schema": 1,
            "arity": self.arity,
            "calling_convention": "c",
            "parameter_types": list(self.parameter_types),
            "prototype_kind": self.prototype_kind,
            "return_type": self.return_type,
            "variadic": self.variadic,
        }

    def canonical_bytes(self) -> bytes:
        return _canonical_bytes(self.to_dict())

    @property
    def sha256(self) -> str:
        return _framed_hash(b"OGHIDRA_ABI_TUPLE_V1", self.canonical_bytes())


@dataclass(frozen=True)
class AdjustedParameterEvidence:
    ordinal: int
    observed_adjusted_qual_type: str
    source_size: int
    source_sha256: str
    desugared_qual_type: str

    def to_dict(self) -> dict[str, object]:
        return {
            "desugared_qual_type": self.desugared_qual_type,
            "observed_adjusted_qual_type": self.observed_adjusted_qual_type,
            "ordinal": self.ordinal,
            "source_sha256": self.source_sha256,
            "source_size": self.source_size,
        }


@dataclass(frozen=True)
class AbiProbeEvidence:
    parameter_source_size: int
    parameter_source_sha256: str
    adjusted_parameters: tuple[AdjustedParameterEvidence, ...]
    return_source_size: int
    return_source_sha256: str
    abi_probe_schema: int = field(default=1, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "abi_probe_schema": 1,
            "adjusted_parameters": [item.to_dict() for item in self.adjusted_parameters],
            "parameter_source_sha256": self.parameter_source_sha256,
            "parameter_source_size": self.parameter_source_size,
            "return_source_sha256": self.return_source_sha256,
            "return_source_size": self.return_source_size,
        }

    @property
    def sha256(self) -> str:
        return _hash_bytes(_canonical_bytes(self.to_dict()))


@dataclass(frozen=True)
class ParserIdentity:
    executable_path: str
    binary_sha256: str
    version_sha256: str
    version_size: int
    baseline_print_sha256: str = field(default_factory=lambda: _hash_bytes(b""))
    baseline_declarations_sha256: str = field(default_factory=lambda: _hash_bytes(_canonical_bytes([])))
    target: str = ABI_TARGET
    dialect: str = ABI_DIALECT
    identity_schema: int = 1

    @classmethod
    def synthetic(cls, name: str) -> "ParserIdentity":
        digest = _hash_bytes(name.encode())
        return cls(f"synthetic://{name}", digest, digest, len(name.encode()))

    def to_dict(self) -> dict[str, object]:
        return {
            "binary_sha256": self.binary_sha256,
            "baseline_declarations_sha256": self.baseline_declarations_sha256,
            "baseline_print_sha256": self.baseline_print_sha256,
            "compatibility_argv": list(json_argv(self.executable_path, "__oghidra_abi_compat_result")),
            "dialect": self.dialect,
            "executable_path": self.executable_path,
            "identity_schema": self.identity_schema,
            "json_argv": list(json_argv(self.executable_path)),
            "preamble_sha256": ABI_PREAMBLE_V1_SHA256,
            "preamble_size": len(ABI_PREAMBLE_V1),
            "print_argv": list(print_argv(self.executable_path)),
            "target": self.target,
            "undef_sha256": ABI_SPELLING_UNDEF_V1_SHA256,
            "undef_size": len(ABI_SPELLING_UNDEF_V1),
            "version_sha256": self.version_sha256,
            "version_size": self.version_size,
        }

    @property
    def sha256(self) -> str:
        return _framed_hash(b"OGHIDRA_DECLARATOR_PARSER_V1", _canonical_bytes(self.to_dict()))


def _parser_identity_is_valid(identity: object) -> bool:
    return (
        isinstance(identity, ParserIdentity)
        and _nonempty_string(identity.executable_path)
        and Path(identity.executable_path).is_absolute()
        and _valid_sha(identity.binary_sha256)
        and _valid_sha(identity.version_sha256)
        and _nonnegative_int(identity.version_size)
        and _valid_sha(identity.baseline_print_sha256)
        and _valid_sha(identity.baseline_declarations_sha256)
        and identity.target == ABI_TARGET
        and identity.dialect == ABI_DIALECT
        and identity.identity_schema == 1
    )


@dataclass(frozen=True)
class DeclaratorProjection:
    symbol: str
    spelled_function_type: str
    spelled_parameter_types: tuple[str, ...]
    prototype_kind: Literal["unspecified", "void", "prototype"]
    variadic: bool
    canonical_prototype: str
    abi_tuple: AbiTuple
    abi_probe_evidence: AbiProbeEvidence
    attributes: tuple[str, ...] = ()
    calling_convention: Literal["c"] = "c"
    declarator_ast_schema: int = 1

    @classmethod
    def synthetic(
        cls,
        symbol: str,
        canonical_prototype: str,
        return_type: str,
        parameter_types: tuple[str, ...],
        *,
        prototype_kind: Literal["unspecified", "void", "prototype"] | None = None,
        variadic: bool = False,
    ) -> "DeclaratorProjection":
        kind = prototype_kind or ("void" if not parameter_types else "prototype")
        tuple_value = AbiTuple(return_type, parameter_types, kind, variadic)
        payload = canonical_prototype.encode()
        digest = _hash_bytes(payload)
        evidence = AbiProbeEvidence(len(payload), digest, (), len(payload), digest)
        return cls(
            symbol,
            f"{return_type} ({', '.join(parameter_types) if parameter_types else ('void' if kind == 'void' else '')})",
            parameter_types,
            kind,
            variadic,
            canonical_prototype,
            tuple_value,
            evidence,
        )

    @property
    def parameter_probe_sha256(self) -> str:
        return self.abi_probe_evidence.parameter_source_sha256

    @property
    def return_probe_sha256(self) -> str:
        return self.abi_probe_evidence.return_source_sha256

    @property
    def canonical_prototype_sha256(self) -> str:
        return _hash_bytes(self.canonical_prototype.encode("utf-8"))

    def spelling_dict(self) -> dict[str, object]:
        return {
            "attributes": list(self.attributes),
            "calling_convention": self.calling_convention,
            "canonical_prototype": self.canonical_prototype,
            "declarator_ast_schema": self.declarator_ast_schema,
            "prototype_kind": self.prototype_kind,
            "spelled_function_type": self.spelled_function_type,
            "spelled_parameter_types": list(self.spelled_parameter_types),
            "variadic": self.variadic,
        }


def _projection_text(value: object) -> bool:
    if not _nonempty_string(value):
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _abi_tuple_is_valid(value: object) -> bool:
    if type(value) is not AbiTuple:
        return False
    if not (
        _projection_text(value.return_type)
        and isinstance(value.parameter_types, tuple)
        and all(_projection_text(item) for item in value.parameter_types)
        and isinstance(value.prototype_kind, str)
        and value.prototype_kind in {"unspecified", "void", "prototype"}
        and type(value.variadic) is bool
        and type(value.abi_tuple_schema) is int
        and value.abi_tuple_schema == 1
        and value.calling_convention == "c"
    ):
        return False
    if value.prototype_kind in {"unspecified", "void"}:
        return not value.parameter_types and not value.variadic
    return bool(value.parameter_types)


def _adjusted_parameter_evidence_is_valid(value: object) -> bool:
    return (
        type(value) is AdjustedParameterEvidence
        and _nonnegative_int(value.ordinal)
        and _projection_text(value.observed_adjusted_qual_type)
        and _positive_int(value.source_size)
        and _valid_sha(value.source_sha256)
        and _projection_text(value.desugared_qual_type)
    )


def _abi_probe_evidence_is_valid(value: object, arity: int) -> bool:
    if type(value) is not AbiProbeEvidence:
        return False
    if (
        not _positive_int(value.parameter_source_size)
        or not _valid_sha(value.parameter_source_sha256)
        or not isinstance(value.adjusted_parameters, tuple)
        or not _positive_int(value.return_source_size)
        or not _valid_sha(value.return_source_sha256)
        or type(value.abi_probe_schema) is not int
        or value.abi_probe_schema != 1
    ):
        return False
    if not all(_adjusted_parameter_evidence_is_valid(item) for item in value.adjusted_parameters):
        return False
    ordinals = [item.ordinal for item in value.adjusted_parameters]
    return ordinals == sorted(set(ordinals)) and all(ordinal < arity for ordinal in ordinals)


def _declarator_projection_is_valid(value: object, expected_symbol: str) -> bool:
    if type(value) is not DeclaratorProjection:
        return False
    if (
        not isinstance(value.symbol, str)
        or _IDENTIFIER_RE.fullmatch(value.symbol) is None
        or value.symbol != expected_symbol
        or not _projection_text(value.spelled_function_type)
        or not isinstance(value.spelled_parameter_types, tuple)
        or not all(_projection_text(item) for item in value.spelled_parameter_types)
        or not isinstance(value.prototype_kind, str)
        or value.prototype_kind not in {"unspecified", "void", "prototype"}
        or type(value.variadic) is not bool
        or not _projection_text(value.canonical_prototype)
        or not _abi_tuple_is_valid(value.abi_tuple)
        or not isinstance(value.attributes, tuple)
        or not all(_projection_text(item) for item in value.attributes)
        or value.calling_convention != "c"
        or type(value.declarator_ast_schema) is not int
        or value.declarator_ast_schema != 1
    ):
        return False
    if (
        len(value.spelled_parameter_types) != value.abi_tuple.arity
        or value.prototype_kind != value.abi_tuple.prototype_kind
        or value.variadic != value.abi_tuple.variadic
    ):
        return False
    if not _abi_probe_evidence_is_valid(value.abi_probe_evidence, value.abi_tuple.arity):
        return False
    return all(
        item.desugared_qual_type == value.abi_tuple.parameter_types[item.ordinal]
        for item in value.abi_probe_evidence.adjusted_parameters
    )


@dataclass(frozen=True)
class CompatibilityProbe:
    compatible: bool
    source: bytes
    source_sha256: str
    parser_identity_sha256: str


def _compatibility_probe_is_valid(
    value: object,
    owner: DeclaratorProjection,
    variant: DeclaratorProjection,
    parser_identity_sha256: str,
) -> bool:
    if type(value) is not CompatibilityProbe or type(value.compatible) is not bool or not isinstance(value.source, bytes):
        return False
    expected = build_compatibility_source(
        owner.canonical_prototype,
        variant.canonical_prototype,
        symbol=owner.symbol,
    )
    return (
        value.source == expected
        and value.source_sha256 == _hash_bytes(expected)
        and value.parser_identity_sha256 == parser_identity_sha256
    )


class DeclaratorParser(Protocol):
    identity: ParserIdentity

    def parse_definition(self, source: bytes, symbol: str) -> DeclaratorProjection: ...

    def parse_declaration(self, source: bytes, symbol: str) -> DeclaratorProjection: ...

    def compatibility(self, left: DeclaratorProjection, right: DeclaratorProjection) -> CompatibilityProbe: ...


@dataclass(frozen=True)
class OwnerFileEvidence:
    chunk_file: str
    file_sha256: str
    range_sha256: str
    line_range: tuple[int, int]
    identity: StableFileIdentity

    def to_dict(self) -> dict[str, object]:
        return {
            "chunk_file": self.chunk_file,
            "file_sha256": self.file_sha256,
            "identity": self.identity.to_dict(),
            "line_range": list(self.line_range),
            "range_sha256": self.range_sha256,
        }


@dataclass(frozen=True)
class OwnerBinding:
    symbol: str
    unit: str
    address: str
    chunk_file: str
    line_range: tuple[int, int]
    normalized_prototype: str
    projection: DeclaratorProjection
    owner_binding_sha256: str
    source: OwnerFileEvidence
    record: Mapping[str, Any] = field(compare=False, repr=False)

    def public_dict(self) -> dict[str, object]:
        return {
            "chunk_file": self.chunk_file,
            "line_range": list(self.line_range),
            "normalized_prototype": self.normalized_prototype,
            "owner_binding_sha256": self.owner_binding_sha256,
            "symbol": self.symbol,
            "unit": self.unit,
        }


@dataclass(frozen=True)
class OwnerSnapshot:
    product_root: str
    registry_relpath: str
    registry_bytes: bytes
    registry_sha256: str
    registry_identity: StableFileIdentity
    index_relpath: str
    index_sha256: str
    index_identity: StableFileIdentity
    bindings: tuple[OwnerBinding, ...]
    owner_index: Mapping[str, tuple[OwnerBinding, ...]]
    parser_identity: ParserIdentity
    declarator_parser: DeclaratorParser = field(compare=False, repr=False)

    def with_owner(self, symbol: str, bindings: tuple[OwnerBinding, ...]) -> "OwnerSnapshot":
        updated = dict(self.owner_index)
        updated[symbol] = bindings
        return replace(self, owner_index=MappingProxyType(dict(sorted(updated.items()))))


def _registry_declaration(record: Mapping[str, Any]) -> bytes:
    return_type = record["return_type"].strip()
    if any(token in return_type for token in ("(", ")", "[", "]")):
        _fail(
            "registry_shape_unrepresentable_return_declarator",
            "owner",
            f"schema 1 cannot reconstruct return declarator for {record['name']}",
        )
    params = record["params"]
    body = "" if params == [] else ",".join(params)
    return f"{return_type} {record['name']}({body});".encode("utf-8")


def _encoded_address(name: str) -> str | None:
    match = _LABEL_ADDRESS_RE.fullmatch(name)
    if match:
        return "8" + match.group(1).lower()
    match = _FUN_ADDRESS_RE.fullmatch(name)
    return match.group(1).lower() if match else None


def _parse_index(data: bytes) -> dict[str, tuple[str, str]]:
    try:
        lines = data.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as exc:
        _fail("owner_index_invalid", "owner", f"index is not UTF-8: {exc}")
    if not lines or lines[0] != "address\tname\tchunk_file":
        _fail("owner_index_invalid", "owner", "index header mismatch")
    result: dict[str, tuple[str, str]] = {}
    addresses: set[str] = set()
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) != 3 or re.fullmatch(r"[0-9A-Fa-f]{8}", fields[0]) is None or _IDENTIFIER_RE.fullmatch(fields[1]) is None:
            _fail("owner_index_invalid", "owner", f"malformed index row: {line!r}")
        address, name, chunk = fields[0].lower(), fields[1], fields[2]
        if name in result or address in addresses:
            _fail("owner_index_invalid", "owner", f"duplicate index name/address: {line!r}")
        result[name] = (address, chunk)
        addresses.add(address)
    return result


def _slice_lines(data: bytes, line_range: tuple[int, int], symbol: str) -> bytes:
    lines = data.splitlines(keepends=True)
    start, end = line_range
    if start < 1 or end < start or end > len(lines):
        _fail("owner_range_invalid", "owner", f"line range outside {symbol} source")
    return b"".join(lines[start - 1 : end])


def load_owner_snapshot(
    product_root: Path,
    registry_path: Path,
    declarator_parser: DeclaratorParser,
) -> OwnerSnapshot:
    """Load and independently validate one strict schema-1 owner snapshot."""

    if not isinstance(registry_path, (str, os.PathLike)):
        _fail("product_path_invalid", "owner", "registry_path must be a path")
    identity = getattr(declarator_parser, "identity", None)
    if (
        not isinstance(identity, ParserIdentity)
        or not all(
            callable(getattr(declarator_parser, method, None))
            for method in ("parse_definition", "parse_declaration", "compatibility")
        )
        or not _parser_identity_is_valid(identity)
    ):
        _fail("owner_declarator_parser_invalid", "owner", "declarator parser identity/interface invalid")
    root = _validate_product_root(product_root)
    registry_relpath = _registry_relpath(root, Path(registry_path))
    exact_registry = _join_exact(root, registry_relpath)
    stable_registry = _stable_read(exact_registry)
    registry = _validate_registry(_parse_json(stable_registry.data))

    index_relpath = _validate_relpath(registry["meta"]["inputs"]["chunk_index"])
    index_path = _join_exact(root, index_relpath)
    stable_index = _stable_read(index_path)
    index = _parse_index(stable_index.data)

    functions: list[dict[str, Any]] = registry["functions"]
    expected_anomalies: list[str] = []
    bindings: list[OwnerBinding] = []
    seen_chunk_casefold: dict[str, str] = {}
    source_cache: dict[str, StableBytes] = {}
    for record in functions:
        chunk_file = record["chunk_file"]
        folded = chunk_file.casefold()
        prior = seen_chunk_casefold.get(folded)
        if prior is not None and prior != chunk_file:
            _fail("product_path_casefold_collision", "owner", f"chunk paths collide after case folding: {prior!r}, {chunk_file!r}")
        seen_chunk_casefold[folded] = chunk_file
        stable_source = source_cache.get(chunk_file)
        if stable_source is None:
            source_path = _join_exact(root, chunk_file)
            stable_source = _stable_read(source_path)
            source_cache[chunk_file] = stable_source
        lines = tuple(record["line_range"])
        range_bytes = _slice_lines(stable_source.data, lines, record["name"])
        first_line = range_bytes.splitlines()[0] if range_bytes.splitlines() else b""
        marker = _MARKER_RE.fullmatch(first_line)
        if marker is None or marker.group(2).decode("ascii") != record["name"]:
            _fail("owner_marker_mismatch", "owner", f"authoritative marker mismatch for {record['name']}", range_bytes)
        marker_address = marker.group(1).decode("ascii").lower()
        if record["address"] != "0x" + marker_address:
            _fail("owner_marker_mismatch", "owner", f"emitted address disagrees with marker for {record['name']}", range_bytes)
        indexed = index.get(record["name"])
        if indexed != (marker_address, PurePosixPath(chunk_file).name):
            _fail("owner_index_mismatch", "owner", f"index disagrees for {record['name']}")
        encoded = _encoded_address(record["name"])
        if encoded is not None and encoded != marker_address:
            expected_anomalies.append(
                f"{record['name']}: name addr {encoded} != marker {marker_address} (marker wins)"
            )

        try:
            owner_projection = declarator_parser.parse_definition(range_bytes, record["name"])
            registry_projection = declarator_parser.parse_declaration(_registry_declaration(record), record["name"])
        except AssemblyAbiError:
            raise
        except Exception as exc:
            _fail("owner_declarator_parser_fault", "owner", f"parser fault for {record['name']}: {exc}")
        if not _declarator_projection_is_valid(
            owner_projection, record["name"]
        ) or not _declarator_projection_is_valid(registry_projection, record["name"]):
            _fail("owner_declarator_parser_fault", "owner", f"parser returned malformed projection for {record['name']}")
        if (
            owner_projection.canonical_prototype != registry_projection.canonical_prototype
            or owner_projection.abi_tuple != registry_projection.abi_tuple
            or owner_projection.prototype_kind != registry_projection.prototype_kind
            or owner_projection.variadic != registry_projection.variadic
            or owner_projection.attributes
            or registry_projection.attributes
        ):
            _fail("owner_prototype_mismatch", "owner", f"registry and direct definition disagree for {record['name']}")
        source_evidence = OwnerFileEvidence(
            chunk_file,
            stable_source.sha256,
            _hash_bytes(range_bytes),
            lines,
            stable_source.identity,
        )
        binding_preimage = {
            "abi_tuple": owner_projection.abi_tuple.to_dict(),
            "abi_tuple_sha256": owner_projection.abi_tuple.sha256,
            "abi_probe_evidence": owner_projection.abi_probe_evidence.to_dict(),
            "abi_probe_evidence_sha256": owner_projection.abi_probe_evidence.sha256,
            "address": record["address"],
            "binding_schema": 1,
            "canonical_prototype": owner_projection.canonical_prototype,
            "chunk_file": chunk_file,
            "line_range": list(lines),
            "index_relpath": index_relpath,
            "index_sha256": stable_index.sha256,
            "owner_file": source_evidence.to_dict(),
            "parser_identity_sha256": declarator_parser.identity.sha256,
            "preamble_sha256": ABI_PREAMBLE_V1_SHA256,
            "preamble_size": len(ABI_PREAMBLE_V1),
            "record": record,
            "spelling": owner_projection.spelling_dict(),
            "symbol": record["name"],
            "undef_sha256": ABI_SPELLING_UNDEF_V1_SHA256,
            "undef_size": len(ABI_SPELLING_UNDEF_V1),
            "unit": record["unit"],
        }
        binding_sha = _framed_hash(b"OGHIDRA_OWNER_BINDING_V1", _canonical_bytes(binding_preimage))
        bindings.append(
            OwnerBinding(
                record["name"],
                record["unit"],
                record["address"],
                chunk_file,
                lines,
                owner_projection.canonical_prototype,
                owner_projection,
                binding_sha,
                source_evidence,
                MappingProxyType(copy_dict(record)),
            )
        )

    if registry["summary"]["anomalies"] != expected_anomalies:
        _fail("owner_marker_anomaly_mismatch", "owner", "summary anomalies do not exactly match marker-wins rows")
    index_map = MappingProxyType({binding.symbol: (binding,) for binding in sorted(bindings, key=lambda item: item.symbol)})
    return OwnerSnapshot(
        str(root),
        registry_relpath,
        stable_registry.data,
        stable_registry.sha256,
        stable_registry.identity,
        index_relpath,
        stable_index.sha256,
        stable_index.identity,
        tuple(bindings),
        index_map,
        declarator_parser.identity,
        declarator_parser,
    )


def copy_dict(value: Mapping[str, Any]) -> dict[str, Any]:
    """Make JSON-shaped owner records immutable without importing copy."""

    return json.loads(json.dumps(value))


@dataclass(frozen=True)
class _FunctionSlice:
    symbol_start: int
    symbol_end: int
    parameters_start: int
    parameters_end: int
    declaration_start: int
    declaration_end: int
    body_start: int | None
    body_end: int | None


def _code_mask(data: bytes) -> bytearray:
    """Return a mask for C code bytes while validating lexical closure."""

    mask = bytearray(b"\x01" * len(data))
    index = 0
    state = "code"
    while index < len(data):
        byte = data[index]
        if state == "code":
            if data[index : index + 2] == b"//":
                mask[index : index + 2] = b"\0\0"
                index += 2
                state = "line-comment"
                continue
            if data[index : index + 2] == b"/*":
                mask[index : index + 2] = b"\0\0"
                index += 2
                state = "block-comment"
                continue
            if byte == ord('"'):
                mask[index] = 0
                index += 1
                state = "string"
                continue
            if byte == ord("'"):
                mask[index] = 0
                index += 1
                state = "char"
                continue
            index += 1
            continue
        mask[index] = 0
        if state == "line-comment":
            if byte in (10, 13):
                state = "code"
                mask[index] = 1
            index += 1
            continue
        if state == "block-comment":
            if data[index : index + 2] == b"*/":
                mask[index : index + 2] = b"\0\0"
                index += 2
                state = "code"
            else:
                index += 1
            continue
        if byte == ord("\\"):
            if index + 1 >= len(data):
                _fail("declarator_lexical_imbalance", "owner", "trailing escape in literal")
            mask[index + 1] = 0
            index += 2
            continue
        terminator = ord('"') if state == "string" else ord("'")
        if byte == terminator:
            state = "code"
        index += 1
    if state not in {"code", "line-comment"}:
        _fail("declarator_lexical_imbalance", "owner", f"unterminated C lexical state {state}")
    return mask


def _skip_space(data: bytes, mask: bytearray, index: int) -> int:
    while index < len(data) and (not mask[index] or chr(data[index]).isspace()):
        index += 1
    return index


def _previous_code(data: bytes, mask: bytearray, index: int) -> int:
    index -= 1
    while index >= 0 and (not mask[index] or chr(data[index]).isspace()):
        index -= 1
    return index


def _match_balanced(data: bytes, mask: bytearray, opening: int, left: int, right: int) -> int:
    depth = 0
    for index in range(opening, len(data)):
        if not mask[index]:
            continue
        if data[index] == left:
            depth += 1
        elif data[index] == right:
            depth -= 1
            if depth == 0:
                return index
            if depth < 0:
                break
    _fail("declarator_lexical_imbalance", "owner", "unbalanced declarator/body")


def _preflight_dialect(data: bytes, symbol: str) -> None:
    if b"__oghidra_abi_" in data:
        _fail("reserved_abi_identifier", "owner", "caller fragment uses reserved __oghidra_abi_ prefix")
    mask = _code_mask(data)
    code = bytes(byte if mask[index] else 32 for index, byte in enumerate(data))
    if re.search(rb"(?m)^\s*#", code):
        _fail("abi_preamble_unknown_or_ambiguous_type", "owner", "preprocessor directives are not allowed in owner fragments")
    if re.search(rb"\b(?:typeof|__typeof__)\s*\(", code):
        _fail("gnu11_typeof_unsupported", "owner", "owner-written typeof is not schema-1 representable")
    if re.search(rb"\b(?:_ExtInt|_BitInt)\s*\(", code):
        _fail("gnu11_extended_integer_unsupported", "owner", "extended integer types are not schema-1 representable")
    if re.search(rb"\b(?:vector_size|ext_vector_type)\b", code):
        _fail("gnu11_vector_type_unsupported", "owner", "vector types are not schema-1 representable")
    if re.search(rb"\b(?:struct|union|enum)\s*\{", code):
        _fail("abi_preamble_unknown_or_ambiguous_type", "owner", "anonymous aggregates are outside the closed preamble")
    if re.search(rb"\b(?:__asm__|asm)\s*\(", code):
        _fail("gnu11_asm_label_unsupported", "owner", "asm labels are not schema-1 representable")
    if re.search(rb"\b(?:__attribute__|__declspec)\s*\(", code):
        _fail("registry_shape_unrepresentable_attribute", "owner", "function attributes are not schema-1 representable")
    for file_token in re.finditer(rb"\b(?:FILE|__FILE)\b", code):
        suffix = code[file_token.end() :]
        if re.match(rb"(?:\s+(?:const|volatile|restrict))*\s*\*", suffix) is None:
            _fail("abi_preamble_unknown_or_ambiguous_type", "owner", "FILE/__FILE incomplete tags are pointer-only")
    if re.search(rb"\b(?:__stdcall|__fastcall|__vectorcall|__thiscall)\b", code):
        _fail("gnu11_calling_convention_unsupported", "owner", "non-C calling convention refused")
    if re.search(rb"\b(?:typedef|struct|union|enum)\b", code):
        # Opaque struct names in a function declarator are allowed through
        # Clang, but definitions and caller-contributed declarations are not.
        occurrences = list(_IDENTIFIER_BYTES_RE.finditer(code))
        symbol_match = next((item for item in occurrences if item.group().decode("ascii") == symbol), None)
        before_symbol = code[: symbol_match.start()] if symbol_match else code
        if b"typedef" in before_symbol or re.search(rb"\b(?:struct|union|enum)\s+[A-Za-z_]\w*\s*\{", code):
            _fail("abi_preamble_unknown_or_ambiguous_type", "owner", "caller type/tag declarations are refused")
        if re.search(rb"\b(?:struct|union|enum)\s+(?!__oghidra_FILE_v1\b)[A-Za-z_]\w*", code):
            _fail("abi_preamble_unknown_or_ambiguous_type", "owner", "unknown/incomplete tag is outside the closed preamble")
    symbol_bytes = re.escape(symbol.encode("ascii"))
    if re.search(symbol_bytes + rb"\s*\([^)]*\)\s+[A-Za-z_]\w*(?:\s+|\s*\*)[^;{}]*;\s*\{", code, flags=re.S):
        _fail("gnu11_knr_definition_unsupported", "owner", "K&R definitions are not schema-1 representable")


def _find_function(data: bytes, symbol: str, *, definition: bool) -> _FunctionSlice:
    if _IDENTIFIER_RE.fullmatch(symbol) is None:
        _fail("declarator_symbol_invalid", "owner", f"invalid C symbol {symbol!r}")
    _preflight_dialect(data, symbol)
    mask = _code_mask(data)
    matches = [
        match
        for match in _IDENTIFIER_BYTES_RE.finditer(data)
        if match.group().decode("ascii") == symbol and all(mask[index] for index in range(match.start(), match.end()))
    ]
    candidates: list[_FunctionSlice] = []
    for match in matches:
        opening = _skip_space(data, mask, match.end())
        if opening >= len(data) or data[opening] != ord("("):
            continue
        previous = _previous_code(data, mask, match.start())
        before_pointer = _previous_code(data, mask, previous) if previous >= 0 and data[previous] == ord("*") else -1
        if previous >= 0 and data[previous] == ord("*") and before_pointer >= 0 and data[before_pointer] == ord("("):
            _fail(
                "registry_shape_unrepresentable_return_declarator",
                "owner",
                f"function-returning-pointer declarator refused for {symbol}",
            )
        closing = _match_balanced(data, mask, opening, ord("("), ord(")"))
        after = _skip_space(data, mask, closing + 1)
        if after < len(data) and data[after] == ord("("):
            _fail(
                "registry_shape_unrepresentable_return_declarator",
                "owner",
                f"function-returning-pointer declarator refused for {symbol}",
            )
        body_start: int | None = None
        body_end: int | None = None
        terminator = after
        while terminator < len(data) and data[terminator] not in b";{":
            if mask[terminator] and data[terminator] == ord("}"):
                break
            terminator += 1
        if terminator >= len(data):
            continue
        if data[terminator] == ord("{"):
            body_start = terminator
            body_end = _match_balanced(data, mask, terminator, ord("{"), ord("}"))
            declaration_end = body_end + 1
        elif data[terminator] == ord(";"):
            declaration_end = terminator + 1
        else:
            continue
        if definition and body_start is None:
            continue
        if not definition and body_start is not None:
            continue
        declaration_start = 0
        for index in range(match.start() - 1, -1, -1):
            if mask[index] and data[index] in b";}":
                declaration_start = index + 1
                break
        declaration_start = _skip_space(data, mask, declaration_start)
        candidates.append(
            _FunctionSlice(
                match.start(),
                match.end(),
                opening,
                closing,
                declaration_start,
                declaration_end,
                body_start,
                body_end,
            )
        )
    if len(candidates) == 0:
        _fail("owner_definition_missing" if definition else "declaration_missing", "owner", f"no direct {'definition' if definition else 'declaration'} for {symbol}")
    if len(candidates) != 1:
        _fail("owner_definition_ambiguous" if definition else "declaration_ambiguous", "owner", f"multiple direct {'definitions' if definition else 'declarations'} for {symbol}")
    candidate = candidates[0]
    outside = data[: candidate.declaration_start] + b" " * (candidate.declaration_end - candidate.declaration_start) + data[candidate.declaration_end :]
    outside_mask = _code_mask(outside)
    if bytes(byte for index, byte in enumerate(outside) if outside_mask[index] and not chr(byte).isspace()):
        _fail(
            "abi_preamble_unknown_or_ambiguous_type",
            "owner",
            "owner/registry fragment contributes code outside the one sentinel declarator",
        )
    between = data[candidate.parameters_end + 1 : candidate.body_start if definition else candidate.declaration_end]
    if definition and b";" in bytes(byte if value else 32 for byte, value in zip(between, _code_mask(between), strict=True)):
        _fail("gnu11_knr_definition_unsupported", "owner", "K&R definitions are not schema-1 representable")
    if b"__attribute__" in between or b"__declspec" in between:
        _fail("registry_shape_unrepresentable_attribute", "owner", "function attributes are not schema-1 representable")
    return candidate


def _replace_symbol(prototype: str, old: str, new: str) -> str:
    matches = list(re.finditer(rf"(?<![A-Za-z0-9_]){re.escape(old)}(?![A-Za-z0-9_])", prototype))
    if len(matches) != 1:
        _fail("declarator_symbol_invalid", "compatibility", f"expected one complete {old!r} token")
    match = matches[0]
    return prototype[: match.start()] + new + prototype[match.end() :]


def build_compatibility_source(left: str, right: str, *, symbol: str | None = None) -> bytes:
    if not left.endswith(";") or not right.endswith(";"):
        _fail("abi_compatibility_source_invalid", "compatibility", "canonical prototypes must end in one semicolon")
    if symbol is None:
        tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", left)
        right_tokens = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", right))
        shared = [token for token in tokens if token in right_tokens and token not in _CONTROL_WORDS]
        symbol = next((token for token in reversed(shared) if re.search(rf"\b{re.escape(token)}\s*\(", left)), None)
        if symbol is None:
            _fail("abi_compatibility_source_invalid", "compatibility", "cannot locate stable function symbol")
    left_named = _replace_symbol(left, symbol, "__oghidra_abi_compat_left")
    right_named = _replace_symbol(right, symbol, "__oghidra_abi_compat_right")
    return ABI_PREAMBLE_V1 + left_named.encode("utf-8") + b"\n" + right_named.encode("utf-8") + b"\n" + ABI_COMPATIBILITY_LINE


def _json_value(stdout: bytes, *, code: str) -> dict[str, Any]:
    try:
        text = stdout.decode("utf-8", errors="strict")
        decoder = json.JSONDecoder(object_pairs_hook=_object_pairs)
        value, end = decoder.raw_decode(text)
        if text[end:].strip():
            raise ValueError("more than one JSON value or trailing bytes")
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        _fail(code, "owner", f"Clang JSON output refused: {exc}", stdout)
    if not isinstance(value, dict):
        _fail(code, "owner", "Clang AST root must be an object", stdout)
    return value


def _ast_named(root: dict[str, Any], kind: str, name: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []

    def visit(node: object) -> None:
        if isinstance(node, dict):
            if node.get("kind") == kind and node.get("name") == name:
                found.append(node)
            for child in node.get("inner", []):
                visit(child)
        elif isinstance(node, list):
            for child in node:
                visit(child)

    visit(root)
    return found


def _split_parameters(text: str) -> tuple[list[str], bool]:
    stripped = text.strip()
    if not stripped:
        return [], False
    parts: list[str] = []
    start = 0
    depths = {"(": 0, "[": 0, "{": 0}
    pairs = {")": "(", "]": "[", "}": "{"}
    for index, char in enumerate(text):
        if char in depths:
            depths[char] += 1
        elif char in pairs:
            depths[pairs[char]] -= 1
            if depths[pairs[char]] < 0:
                _fail("declarator_lexical_imbalance", "owner", "unbalanced abstract parameter")
        elif char == "," and not any(depths.values()):
            parts.append(text[start:index].strip())
            start = index + 1
    if any(depths.values()):
        _fail("declarator_lexical_imbalance", "owner", "unbalanced abstract parameter")
    parts.append(text[start:].strip())
    variadic = bool(parts and parts[-1] == "...")
    if variadic:
        parts.pop()
    if any(not item for item in parts):
        _fail("declarator_parse_invalid", "owner", "empty parameter in prototype")
    return parts, variadic


def _canonical_parts(prototype: str, symbol: str) -> tuple[str, list[str], str, bool]:
    encoded = prototype.encode("utf-8")
    function = _find_function(encoded, symbol, definition=False)
    return_text = encoded[function.declaration_start : function.symbol_start].decode("utf-8").strip()
    return_text = re.sub(r"^(?:(?:extern|static|inline|__inline__)\s+)+", "", return_text)
    parameters_text = encoded[function.parameters_start + 1 : function.parameters_end].decode("utf-8")
    params, variadic = _split_parameters(parameters_text)
    if not params and not parameters_text.strip():
        kind = "unspecified"
    elif params == ["void"] and not variadic:
        kind = "void"
        params = []
    else:
        kind = "prototype"
    return return_text, params, kind, variadic


def _normalized_print_bytes(stdout: bytes) -> bytes:
    try:
        return stdout.decode("utf-8", errors="strict").replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
    except UnicodeDecodeError as exc:
        _fail("declarator_emission_invalid", "owner", f"printer output is not UTF-8: {exc}", stdout)


def _partition_top_level_declarations(stdout: bytes) -> tuple[bytes, ...]:
    data = _normalized_print_bytes(stdout)
    mask = _code_mask(data)
    declarations: list[bytes] = []
    start: int | None = None
    parentheses = brackets = braces = 0
    for index, byte in enumerate(data):
        if not mask[index]:
            continue
        if start is None:
            if chr(byte).isspace():
                continue
            if byte == ord("#"):
                _fail("declarator_emission_invalid", "owner", "printer directive refused", stdout)
            start = index
        if byte == ord("("):
            parentheses += 1
        elif byte == ord(")"):
            parentheses -= 1
        elif byte == ord("["):
            brackets += 1
        elif byte == ord("]"):
            brackets -= 1
        elif byte == ord("{"):
            braces += 1
        elif byte == ord("}"):
            braces -= 1
        if min(parentheses, brackets, braces) < 0:
            _fail("declarator_emission_invalid", "owner", "unbalanced printer output", stdout)
        if byte == ord(";") and parentheses == brackets == braces == 0:
            declarations.append(data[start : index + 1].strip(b" \t\r\n"))
            start = None
    if start is not None or any((parentheses, brackets, braces)):
        _fail("declarator_emission_invalid", "owner", "incomplete top-level printer bytes", stdout)
    return tuple(declarations)


def _refuse_desugared_alias(value: str, source: bytes, *, code: str) -> None:
    tokens = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", value))
    remaining = sorted(tokens & _FORBIDDEN_DESUGARED_ALIASES)
    if remaining:
        _fail("abi_probe_alias_not_desugared", "owner", f"closed alias remains in Clang ABI type: {remaining}", source)


class ClangDeclaratorParser:
    """Pinned production Clang adapter at the declarator-parser internal seam."""

    def __init__(
        self,
        executable: Path,
        identity: ParserIdentity,
        baseline_declarations: tuple[bytes, ...] = (),
        binary_identity: StableFileIdentity | None = None,
    ):
        self.executable = executable
        self.identity = identity
        self._baseline_declarations = baseline_declarations
        self._binary_identity = binary_identity

    @classmethod
    def from_product_root(cls, product_root: Path) -> "ClangDeclaratorParser":
        root = _validate_product_root(product_root)
        relpath = "research/tools/emsdk/upstream/bin/clang.exe"
        executable = _join_exact(root, relpath)
        binary = _stable_read(executable, code="clang_identity_invalid")
        argv = (str(executable), "--version")
        try:
            completed = subprocess.run(argv, capture_output=True, check=False)
        except OSError as exc:
            _fail("clang_identity_invalid", "owner", f"Clang --version spawn failed: {exc}")
        if completed.returncode != 0 or completed.stderr:
            _fail("clang_identity_invalid", "owner", "Clang --version must exit zero with empty stderr")
        after_version = _stable_read(executable, code="clang_identity_invalid")
        if after_version.identity != binary.identity or after_version.sha256 != binary.sha256:
            _fail("clang_identity_invalid", "owner", "Clang changed during --version")
        provisional = ParserIdentity(
            str(executable.resolve(strict=True)),
            binary.sha256,
            _hash_bytes(completed.stdout),
            len(completed.stdout),
        )
        parser = cls(executable, provisional, (), binary.identity)
        baseline_stdout = parser._run(
            print_argv(str(executable)),
            ABI_PREAMBLE_V1 + ABI_SPELLING_UNDEF_V1,
            code="clang_identity_invalid",
        )
        baseline = _partition_top_level_declarations(baseline_stdout)
        after_baseline = _stable_read(executable, code="clang_identity_invalid")
        if after_baseline.identity != binary.identity or after_baseline.sha256 != binary.sha256:
            _fail("clang_identity_invalid", "owner", "Clang changed during baseline printer probe")
        identity = replace(
            provisional,
            baseline_print_sha256=_hash_bytes(_normalized_print_bytes(baseline_stdout)),
            baseline_declarations_sha256=_hash_bytes(_canonical_bytes([item.decode("utf-8") for item in baseline])),
        )
        return cls(executable, identity, baseline, binary.identity)

    def _verify_bound_binary(self) -> None:
        if self._binary_identity is None:
            return
        current = _stable_read(self.executable, code="clang_identity_invalid")
        if current.identity != self._binary_identity or current.sha256 != self.identity.binary_sha256:
            _fail("clang_identity_invalid", "owner", "bound Clang identity/bytes changed across probe batch")

    def _run(self, argv: tuple[str, ...], source: bytes, *, code: str) -> bytes:
        if self._binary_identity is not None:
            try:
                before = _identity(os.lstat(self.executable))
            except OSError as exc:
                _fail("clang_identity_invalid", "owner", f"cannot recheck bound Clang: {exc}")
            if before != self._binary_identity:
                _fail("clang_identity_invalid", "owner", "bound Clang identity changed before probe")
        try:
            completed = subprocess.run(argv, input=source, capture_output=True, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            _fail(code, "owner", f"Clang execution fault: {exc}", source)
        if completed.returncode != 0 or completed.stderr:
            detail = completed.stderr.decode("utf-8", errors="replace")[:1000]
            _fail(code, "owner", f"Clang refused declarator: return={completed.returncode}, stderr={detail!r}", source)
        if self._binary_identity is not None:
            try:
                after = _identity(os.lstat(self.executable))
            except OSError as exc:
                _fail("clang_identity_invalid", "owner", f"cannot post-check bound Clang: {exc}")
            if after != self._binary_identity:
                _fail("clang_identity_invalid", "owner", "bound Clang identity changed during probe")
        return completed.stdout

    def _function_ast(self, source: bytes, *, code: str = "declarator_parse_invalid") -> dict[str, Any]:
        stdout = self._run(json_argv(str(self.executable)), source, code=code)
        root = _json_value(stdout, code=code)
        nodes = _ast_named(root, "FunctionDecl", "__oghidra_abi_probe")
        if len(nodes) != 1:
            _fail(code, "owner", "expected exactly one sentinel FunctionDecl", stdout)
        return nodes[0]

    @staticmethod
    def _erase_parameter_names(source: bytes, function: dict[str, Any]) -> bytes:
        intervals: list[tuple[int, int]] = []
        for child in function.get("inner", []):
            if not isinstance(child, dict) or child.get("kind") != "ParmVarDecl" or "name" not in child:
                continue
            name = child.get("name")
            loc = child.get("loc")
            if not isinstance(name, str) or _IDENTIFIER_RE.fullmatch(name) is None or not isinstance(loc, dict):
                _fail("parameter_name_offset_invalid", "owner", "named parameter has invalid AST location")
            if "spellingLoc" in loc or "expansionLoc" in loc:
                _fail("parameter_name_offset_invalid", "owner", "macro/spelling parameter locations are refused")
            offset, token_length = loc.get("offset"), loc.get("tokLen")
            if not _nonnegative_int(offset) or not _positive_int(token_length):
                _fail("parameter_name_offset_invalid", "owner", "parameter offset/tokLen missing or noninteger")
            end = offset + token_length
            if end > len(source) or source[offset:end] != name.encode("utf-8") or _IDENTIFIER_BYTES_RE.fullmatch(source[offset:end]) is None:
                _fail("parameter_name_offset_invalid", "owner", "parameter offset does not address its exact UTF-8 identifier")
            intervals.append((offset, end))
        ordered = sorted(intervals)
        if any(left[1] > right[0] for left, right in zip(ordered, ordered[1:])):
            _fail("parameter_name_offset_invalid", "owner", "overlapping parameter name offsets")
        result = source
        for start, end in reversed(ordered):
            result = result[:start] + result[end:]
        return result

    def _print_canonical(self, declaration_source: bytes, function: dict[str, Any], original_symbol: str) -> str:
        unnamed = self._erase_parameter_names(declaration_source, function)
        stdout = self._run(print_argv(str(self.executable)), unnamed, code="declarator_emission_invalid")
        declarations = _partition_top_level_declarations(stdout)
        sentinel = b"__oghidra_abi_probe"
        matches = [item for item in declarations if re.search(rb"(?<![A-Za-z0-9_])" + sentinel + rb"(?![A-Za-z0-9_])", item)]
        if len(matches) != 1:
            _fail("declarator_emission_invalid", "owner", "printer must emit exactly one sentinel declaration", stdout)
        non_sentinel = tuple(item for item in declarations if item is not matches[0])
        if non_sentinel != self._baseline_declarations:
            _fail("declarator_emission_invalid", "owner", "printer preamble declaration sequence changed", stdout)
        selected_bytes = matches[0]
        if b"\n" in selected_bytes or not selected_bytes.endswith(b";") or selected_bytes.count(b";") != 1 or any(
            token in selected_bytes for token in (b"{", b"}", b"#")
        ):
            _fail("declarator_emission_invalid", "owner", "selected printer declaration is incomplete or contains forbidden tokens", stdout)
        selected = selected_bytes.decode("utf-8")
        result = _replace_symbol(selected, "__oghidra_abi_probe", original_symbol)
        if result.endswith(";;") or "\n" in result:
            _fail("declarator_emission_invalid", "owner", "canonical prototype terminator invalid", stdout)
        return result

    def _abi_tuple(self, canonical: str, symbol: str) -> tuple[AbiTuple, AbiProbeEvidence]:
        return_type, parameters, prototype_kind, variadic = _canonical_parts(canonical, symbol)
        typedef_lines = b"".join(
            f"typedef __typeof__({parameter}) __oghidra_abi_param_{index:04d};\n".encode("utf-8")
            for index, parameter in enumerate(parameters)
        )
        if prototype_kind == "unspecified":
            probe_params = ""
        elif prototype_kind == "void":
            probe_params = "void"
        else:
            probe_params = ", ".join(f"__oghidra_abi_param_{index:04d}" for index in range(len(parameters)))
            if variadic:
                probe_params += (", " if probe_params else "") + "..."
        parameter_source = ABI_PREAMBLE_V1 + typedef_lines + f"void __oghidra_abi_probe({probe_params});\n".encode("utf-8")
        parameter_ast = self._function_ast(parameter_source, code="abi_parameter_probe_invalid")
        parameter_nodes = [child for child in parameter_ast.get("inner", []) if isinstance(child, dict) and child.get("kind") == "ParmVarDecl"]
        if len(parameter_nodes) != len(parameters):
            _fail("abi_parameter_probe_invalid", "owner", "synthetic parameter arity mismatch", parameter_source)
        desugared_parameters: list[str] = []
        adjusted_evidence: list[AdjustedParameterEvidence] = []
        for index, node in enumerate(parameter_nodes):
            type_info = node.get("type")
            value = type_info.get("desugaredQualType") if isinstance(type_info, dict) else None
            if not _nonempty_string(value):
                # The secondary VarDecl path is the single bounded exception
                # for Clang's adjusted *top-level array* parameter omission.
                # A bracket nested inside a parenthesized pointer declarator is
                # not that case and must not turn qualType into a fallback.
                parameter_spelling = parameters[index]
                paren_depth = 0
                adjusted_array = False
                for character in parameter_spelling:
                    if character == "(":
                        paren_depth += 1
                    elif character == ")":
                        paren_depth -= 1
                    elif character == "[" and paren_depth == 0:
                        adjusted_array = True
                        break
                if not adjusted_array or not isinstance(type_info, dict) or set(type_info) != {"qualType"}:
                    _fail("abi_parameter_probe_invalid", "owner", "mandatory ParmVarDecl desugaredQualType absent", parameter_source)
                observed = type_info["qualType"]
                if (
                    not _nonempty_string(observed)
                    or any(character in observed for character in ("\r", "\n", "\0"))
                ):
                    _fail("abi_adjusted_parameter_probe_invalid", "owner", "invalid adjusted qualType", parameter_source)
                adjusted_name = f"__oghidra_abi_adjusted_param_type_{index:04d}"
                probe_name = f"__oghidra_abi_adjusted_param_probe_{index:04d}"
                adjusted_source = (
                    ABI_PREAMBLE_V1
                    + f"typedef __typeof__({observed}) {adjusted_name};\n".encode("utf-8")
                    + f"{adjusted_name} {probe_name};\n".encode("utf-8")
                )
                adjusted_stdout = self._run(
                    json_argv(str(self.executable), probe_name),
                    adjusted_source,
                    code="abi_adjusted_parameter_probe_invalid",
                )
                adjusted_root = _json_value(adjusted_stdout, code="abi_adjusted_parameter_probe_invalid")
                if adjusted_root.get("kind") != "VarDecl" or adjusted_root.get("name") != probe_name:
                    _fail("abi_adjusted_parameter_probe_invalid", "owner", "adjusted probe root mismatch", adjusted_stdout)
                adjusted_type = adjusted_root.get("type")
                if not isinstance(adjusted_type, dict) or adjusted_type.get("qualType") != adjusted_name:
                    _fail("abi_adjusted_parameter_probe_invalid", "owner", "adjusted probe alias projection mismatch", adjusted_stdout)
                value = adjusted_type.get("desugaredQualType")
                if not _nonempty_string(value):
                    _fail("abi_adjusted_parameter_probe_invalid", "owner", "mandatory adjusted desugaredQualType absent", adjusted_stdout)
                _refuse_desugared_alias(value, adjusted_source, code="abi_adjusted_parameter_probe_invalid")
                if "bool" in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", value) and self._binary_identity is None:
                    _fail("abi_probe_alias_not_desugared", "owner", "bool ABI spelling lacks bound production-Clang evidence", adjusted_source)
                adjusted_evidence.append(
                    AdjustedParameterEvidence(index, observed, len(adjusted_source), _hash_bytes(adjusted_source), value)
                )
            else:
                _refuse_desugared_alias(value, parameter_source, code="abi_parameter_probe_invalid")
                if "bool" in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", value) and self._binary_identity is None:
                    _fail("abi_probe_alias_not_desugared", "owner", "bool ABI spelling lacks bound production-Clang evidence", parameter_source)
            desugared_parameters.append(value)

        if return_type in {"void", "code"}:
            desugared_return = "void"
            return_source = ABI_PREAMBLE_V1 + f"/* void return {return_type} */\n".encode("utf-8")
        else:
            return_source = (
                ABI_PREAMBLE_V1
                + f"typedef __typeof__({return_type}) __oghidra_abi_return_type;\n".encode("utf-8")
                + b"__oghidra_abi_return_type __oghidra_abi_return_probe;\n"
            )
            stdout = self._run(
                json_argv(str(self.executable), "__oghidra_abi_return_probe"),
                return_source,
                code="abi_return_probe_invalid",
            )
            root = _json_value(stdout, code="abi_return_probe_invalid")
            if root.get("kind") != "VarDecl" or root.get("name") != "__oghidra_abi_return_probe":
                _fail("abi_return_probe_invalid", "owner", "expected exactly one synthetic return VarDecl", stdout)
            type_info = root.get("type")
            desugared_return = type_info.get("desugaredQualType") if isinstance(type_info, dict) else None
            if not _nonempty_string(desugared_return):
                _fail("abi_return_probe_invalid", "owner", "mandatory VarDecl desugaredQualType absent", stdout)
            _refuse_desugared_alias(desugared_return, return_source, code="abi_return_probe_invalid")
            if "bool" in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", desugared_return) and self._binary_identity is None:
                _fail("abi_probe_alias_not_desugared", "owner", "bool ABI spelling lacks bound production-Clang evidence", return_source)
        evidence = AbiProbeEvidence(
            len(parameter_source),
            _hash_bytes(parameter_source),
            tuple(adjusted_evidence),
            len(return_source),
            _hash_bytes(return_source),
        )
        return (
            AbiTuple(desugared_return, tuple(desugared_parameters), prototype_kind, variadic),
            evidence,
        )

    def _parse(self, source: bytes, symbol: str, *, definition: bool) -> DeclaratorProjection:
        function_slice = _find_function(source, symbol, definition=definition)
        mutable = bytearray(source)
        sentinel = b"__oghidra_abi_probe"
        mutable[function_slice.symbol_start : function_slice.symbol_end] = sentinel
        delta = len(sentinel) - (function_slice.symbol_end - function_slice.symbol_start)
        body_start = function_slice.body_start + delta if function_slice.body_start is not None else None
        body_end = function_slice.body_end + delta if function_slice.body_end is not None else None
        declaration_end = function_slice.declaration_end + delta
        if definition:
            assert body_start is not None and body_end is not None
            declaration_fragment = bytes(mutable[:body_start] + b";" + mutable[body_end + 1 :])
            # Direct-definition status was already proven by the scanner.  A
            # declaration is the warning-free Clang spelling probe; using an
            # empty non-void body would itself emit -Wreturn-type diagnostics,
            # which this contract correctly treats as a refusal.
            ast_fragment = declaration_fragment
        else:
            ast_fragment = bytes(mutable)
            declaration_fragment = bytes(mutable)
        spelling_source = ABI_PREAMBLE_V1 + ABI_SPELLING_UNDEF_V1 + ast_fragment
        function = self._function_ast(spelling_source)
        attributes = tuple(
            child["kind"]
            for child in function.get("inner", [])
            if isinstance(child, dict) and isinstance(child.get("kind"), str) and child["kind"].endswith("Attr")
        )
        if attributes:
            _fail("registry_shape_unrepresentable_attribute", "owner", f"function attributes refused: {attributes}")
        type_info = function.get("type")
        spelled_function_type = type_info.get("qualType") if isinstance(type_info, dict) else None
        if not _nonempty_string(spelled_function_type):
            _fail("declarator_ast_invalid", "owner", "FunctionDecl qualType absent")
        parameter_nodes = [child for child in function.get("inner", []) if isinstance(child, dict) and child.get("kind") == "ParmVarDecl"]
        spelled_parameters: list[str] = []
        for node in parameter_nodes:
            node_type = node.get("type")
            qual_type = node_type.get("qualType") if isinstance(node_type, dict) else None
            if not _nonempty_string(qual_type):
                _fail("declarator_ast_invalid", "owner", "ParmVarDecl qualType absent")
            spelled_parameters.append(qual_type)
        # Offsets refer to the complete spelling source; emission uses that
        # same prefix and a body-to-semicolon replacement after all params.
        declaration_source = ABI_PREAMBLE_V1 + ABI_SPELLING_UNDEF_V1 + declaration_fragment
        canonical = self._print_canonical(declaration_source, function, symbol)
        tuple_value, probe_evidence = self._abi_tuple(canonical, symbol)
        return_type, params, kind, variadic = _canonical_parts(canonical, symbol)
        del return_type, params
        if tuple_value.prototype_kind != kind or tuple_value.variadic != variadic or len(parameter_nodes) != tuple_value.arity:
            _fail("declarator_reparse_mismatch", "owner", "spelling and ABI projections disagree")
        projection = DeclaratorProjection(
            symbol,
            spelled_function_type,
            tuple(spelled_parameters),
            kind,
            variadic,
            canonical,
            tuple_value,
            probe_evidence,
            (),
        )
        # Reparse emitted bytes through the JSON projection and independently
        # recompute ABI evidence, without re-entering the printer.
        reparse_slice = _find_function(canonical.encode(), symbol, definition=False)
        reparse_mutable = bytearray(canonical.encode())
        reparse_mutable[reparse_slice.symbol_start : reparse_slice.symbol_end] = sentinel
        reparse_source = ABI_PREAMBLE_V1 + ABI_SPELLING_UNDEF_V1 + bytes(reparse_mutable)
        reparse_ast = self._function_ast(reparse_source)
        reparse_type = reparse_ast.get("type", {}).get("qualType")
        reparse_params = tuple(
            child.get("type", {}).get("qualType")
            for child in reparse_ast.get("inner", [])
            if isinstance(child, dict) and child.get("kind") == "ParmVarDecl"
        )
        reparsed_tuple, reparsed_evidence = self._abi_tuple(canonical, symbol)
        if (
            reparse_type != spelled_function_type
            or reparse_params != tuple(spelled_parameters)
            or reparsed_tuple != tuple_value
            or reparsed_evidence != probe_evidence
        ):
            _fail("declarator_reparse_mismatch", "owner", "canonical emitted declaration did not reparse identically")
        return projection

    def parse_definition(self, source: bytes, symbol: str) -> DeclaratorProjection:
        self._verify_bound_binary()
        try:
            return self._parse(source, symbol, definition=True)
        finally:
            self._verify_bound_binary()

    def parse_declaration(self, source: bytes, symbol: str) -> DeclaratorProjection:
        self._verify_bound_binary()
        try:
            return self._parse(source, symbol, definition=False)
        finally:
            self._verify_bound_binary()

    def compatibility(self, left: DeclaratorProjection, right: DeclaratorProjection) -> CompatibilityProbe:
        self._verify_bound_binary()
        try:
            return self._compatibility_bound(left, right)
        finally:
            self._verify_bound_binary()

    def _compatibility_bound(self, left: DeclaratorProjection, right: DeclaratorProjection) -> CompatibilityProbe:
        if left.symbol != right.symbol:
            _fail("abi_compatibility_source_invalid", "compatibility", "owner and variant symbols differ")
        source = build_compatibility_source(left.canonical_prototype, right.canonical_prototype, symbol=left.symbol)
        stdout = self._run(
            json_argv(str(self.executable), "__oghidra_abi_compat_result"),
            source,
            code="abi_compatibility_probe_invalid",
        )
        root = _json_value(stdout, code="abi_compatibility_probe_invalid")
        nodes = _ast_named(root, "EnumConstantDecl", "__oghidra_abi_compat_result")
        if len(nodes) != 1:
            _fail("abi_compatibility_probe_invalid", "compatibility", "expected one compatibility EnumConstantDecl", stdout)
        node = nodes[0]
        expected_type = {"qualType": "int"}
        if node.get("type") != expected_type:
            _fail("abi_compatibility_probe_invalid", "compatibility", "compatibility enum type projection mismatch", stdout)
        inner = node.get("inner")
        if not isinstance(inner, list) or len(inner) != 1 or inner[0].get("kind") != "ConstantExpr":
            _fail("abi_compatibility_probe_invalid", "compatibility", "compatibility ConstantExpr projection mismatch", stdout)
        constant = inner[0]
        if constant.get("type") != expected_type or constant.get("valueCategory") != "prvalue" or constant.get("value") not in {"0", "1"}:
            _fail("abi_compatibility_probe_invalid", "compatibility", "compatibility ConstantExpr value projection mismatch", stdout)
        children = constant.get("inner")
        if not isinstance(children, list) or len(children) != 1 or children[0].get("kind") != "TypeTraitExpr":
            _fail("abi_compatibility_probe_invalid", "compatibility", "compatibility TypeTraitExpr projection mismatch", stdout)
        return CompatibilityProbe(constant["value"] == "1", source, _hash_bytes(source), self.identity.sha256)


@dataclass(frozen=True)
class ToolIdentity:
    role: Literal["emcc", "clang", "wasm-ld", "object-inspector", "node", "smoke-script"]
    resolved_path: str
    file_sha256: str
    version_sha256: str

    def to_dict(self) -> dict[str, str]:
        return {
            "file_sha256": self.file_sha256,
            "resolved_path": self.resolved_path,
            "role": self.role,
            "version_sha256": self.version_sha256,
        }


@dataclass(frozen=True)
class ToolWorld:
    identities: tuple[ToolIdentity, ...]
    compile_argv: tuple[tuple[str, ...], ...]
    inspect_argv: tuple[tuple[str, ...], ...]
    link_argv: tuple[str, ...]
    instantiate_argv: tuple[str, ...]
    smoke_argv: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    tool_world_schema: int = field(default=1, init=False)

    @classmethod
    def synthetic(cls, name: str) -> "ToolWorld":
        digest = _hash_bytes(name.encode())
        roles = tuple(sorted(("emcc", "clang", "wasm-ld", "object-inspector", "node", "smoke-script")))
        identities = tuple(ToolIdentity(role, f"D:/synthetic/{role}", digest, digest) for role in roles)  # type: ignore[arg-type]
        return cls(identities, (), (), ("wasm-ld",), ("node", "instantiate"), ("node", "smoke"), ())

    def _preimage(self) -> dict[str, object]:
        return {
            "argv": {
                "compile": [list(item) for item in self.compile_argv],
                "inspect": [list(item) for item in self.inspect_argv],
                "instantiate": list(self.instantiate_argv),
                "link": list(self.link_argv),
                "smoke": list(self.smoke_argv),
            },
            "environment": [{"name": name, "value_sha256": digest} for name, digest in self.environment],
            "identities": [item.to_dict() for item in self.identities],
            "tool_world_schema": 1,
        }

    @property
    def tool_world_sha256(self) -> str:
        return _hash_bytes(_canonical_bytes(self._preimage()))

    def to_result_dict(self) -> dict[str, object]:
        return {**self._preimage(), "tool_world_sha256": self.tool_world_sha256}


@dataclass(frozen=True)
class Candidate:
    artifact_relpath: str
    artifact_sha256: str
    artifact_size: int
    source_sha256: str
    header_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_relpath": self.artifact_relpath,
            "artifact_sha256": self.artifact_sha256,
            "artifact_size": self.artifact_size,
            "header_sha256": self.header_sha256,
            "source_sha256": self.source_sha256,
        }


@dataclass(frozen=True)
class WindowItem:
    ordinal: int
    unit: str
    artifact_relpath: str
    artifact_sha256: str
    artifact_size: int

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_relpath": self.artifact_relpath,
            "artifact_sha256": self.artifact_sha256,
            "artifact_size": self.artifact_size,
            "ordinal": self.ordinal,
            "unit": self.unit,
        }


@dataclass(frozen=True)
class BundleTranslationUnit:
    ordinal: int
    unit: str
    role: Literal["candidate", "window"]
    source_relpath: str
    source: bytes
    source_sha256: str
    header_relpath: str
    header: bytes
    header_sha256: str
    object_relpath: str
    compile_argv: tuple[str, ...]


@dataclass(frozen=True)
class AssemblyBundle:
    unit: str
    attempt: int
    behavior_tier: Literal["compile_only", "oracle_green"]
    translation_units: tuple[BundleTranslationUnit, ...]
    tool_world: ToolWorld
    candidate: Candidate | None = None
    window: tuple[WindowItem, ...] = ()
    assembly_module_revision: str = "port_assembly_abi-v1"
    driver_revision: str = "port_wasm_units-v1"


@dataclass(frozen=True)
class CompatibilityEvidence:
    symbol: str
    source_relpath: str
    owner_prototype_sha256: str
    variant_prototype_sha256: str
    owner_abi_tuple_sha256: str
    variant_abi_tuple_sha256: str
    probe_source_size: int
    probe_source_sha256: str
    parser_identity_sha256: str
    result: Literal["compatible", "incompatible"]
    _probe_source: bytes = field(repr=False)
    _owner_prototype: str = field(repr=False)
    _variant_prototype: str = field(repr=False)
    compatibility_schema: int = 1

    def to_dict(self) -> dict[str, object]:
        return {
            "compatibility_schema": 1,
            "owner_abi_tuple_sha256": self.owner_abi_tuple_sha256,
            "owner_prototype_sha256": self.owner_prototype_sha256,
            "parser_identity_sha256": self.parser_identity_sha256,
            "probe_source_sha256": self.probe_source_sha256,
            "probe_source_size": self.probe_source_size,
            "result": self.result,
            "source_relpath": self.source_relpath,
            "symbol": self.symbol,
            "variant_abi_tuple_sha256": self.variant_abi_tuple_sha256,
            "variant_prototype_sha256": self.variant_prototype_sha256,
        }


def _compatibility_evidence_is_valid(
    value: object,
    parser_identity_sha256: str,
    owner_bindings: Mapping[str, OwnerBinding],
) -> bool:
    if type(value) is not CompatibilityEvidence:
        return False
    if (
        not isinstance(value.symbol, str)
        or _IDENTIFIER_RE.fullmatch(value.symbol) is None
        or not isinstance(value.source_relpath, str)
        or not _projection_text(value._owner_prototype)
        or not _projection_text(value._variant_prototype)
        or not isinstance(value._probe_source, bytes)
        or not all(
            _valid_sha(digest)
            for digest in (
                value.owner_prototype_sha256,
                value.variant_prototype_sha256,
                value.owner_abi_tuple_sha256,
                value.variant_abi_tuple_sha256,
                value.probe_source_sha256,
                value.parser_identity_sha256,
            )
        )
        or not _positive_int(value.probe_source_size)
        or not isinstance(value.result, str)
        or value.result not in {"compatible", "incompatible"}
        or type(value.compatibility_schema) is not int
        or value.compatibility_schema != 1
        or value.parser_identity_sha256 != parser_identity_sha256
    ):
        return False
    owner = owner_bindings.get(value.symbol)
    if owner is None or not _declarator_projection_is_valid(owner.projection, value.symbol):
        return False
    if (
        owner.normalized_prototype != value._owner_prototype
        or owner.projection.canonical_prototype_sha256 != value.owner_prototype_sha256
        or owner.projection.abi_tuple.sha256 != value.owner_abi_tuple_sha256
        or _hash_bytes(value._owner_prototype.encode("utf-8")) != value.owner_prototype_sha256
        or _hash_bytes(value._variant_prototype.encode("utf-8")) != value.variant_prototype_sha256
    ):
        return False
    try:
        expected_source = build_compatibility_source(
            value._owner_prototype,
            value._variant_prototype,
            symbol=value.symbol,
        )
    except AssemblyAbiError:
        return False
    return (
        value._probe_source == expected_source
        and value.probe_source_size == len(expected_source)
        and value.probe_source_sha256 == _hash_bytes(expected_source)
    )


@dataclass(frozen=True)
class DiscardedVariant:
    symbol: str
    source_relpath: str
    prototype_sha256: str

    def to_dict(self) -> dict[str, str]:
        return {
            "prototype_sha256": self.prototype_sha256,
            "source_relpath": self.source_relpath,
            "symbol": self.symbol,
        }


@dataclass(frozen=True)
class TranslationUnitPlan:
    ordinal: int
    unit: str
    role: Literal["candidate", "window"]
    source_relpath: str
    source_sha256: str
    header_relpath: str
    header_sha256: str
    derived_source: bytes
    derived_source_sha256: str
    derived_header: bytes
    derived_header_sha256: str
    object_relpath: str
    compile_argv: tuple[str, ...]

    @property
    def compile_argv_sha256(self) -> str:
        return _framed_hash(b"OGHIDRA_COMPILE_ARGV_V1", _canonical_bytes(list(self.compile_argv)))

    def result_dict(self) -> dict[str, object]:
        return {
            "compile_argv_sha256": self.compile_argv_sha256,
            "derived_source_sha256": self.derived_source_sha256,
            "object_relpath": self.object_relpath,
            "ordinal": self.ordinal,
            "role": self.role,
            "source_sha256": self.source_sha256,
            "unit": self.unit,
        }


@dataclass(frozen=True)
class BundleFileBinding:
    relpath: str
    sha256: str
    size: int

    def to_dict(self) -> dict[str, object]:
        return {"relpath": self.relpath, "sha256": self.sha256, "size": self.size}


@dataclass(frozen=True)
class CanonicalizationReceipt:
    bundle_sha256: str
    derived_bundle_sha256: str
    relevant_catalog_sha256: str
    registry_relpath: str
    registry_sha256: str
    registry_identity: StableFileIdentity
    index_relpath: str
    index_sha256: str
    index_identity: StableFileIdentity
    parser_identity_sha256: str
    owner_bindings: tuple[OwnerBinding, ...]
    owner_files: tuple[OwnerFileEvidence, ...]
    compatibility_checks: tuple[CompatibilityEvidence, ...]
    discarded_variants: tuple[DiscardedVariant, ...]
    bundle_files: tuple[BundleFileBinding, ...]
    tool_world_sha256: str
    assembly_world_sha256: str
    parser_identity: ParserIdentity = field(repr=False)
    tool_world: ToolWorld = field(repr=False)
    receipt_schema: int = 1

    def to_dict(self) -> dict[str, object]:
        return {
            "bundle_files": [item.to_dict() for item in self.bundle_files],
            "bundle_sha256": self.bundle_sha256,
            "assembly_world_sha256": self.assembly_world_sha256,
            "compatibility_checks": [item.to_dict() for item in self.compatibility_checks],
            "derived_bundle_sha256": self.derived_bundle_sha256,
            "discarded_variants": [item.to_dict() for item in self.discarded_variants],
            "owner_bindings": [item.public_dict() for item in self.owner_bindings],
            "owner_files": [item.to_dict() for item in self.owner_files],
            "index_identity": self.index_identity.to_dict(),
            "index_relpath": self.index_relpath,
            "index_sha256": self.index_sha256,
            "parser_identity_sha256": self.parser_identity_sha256,
            "receipt_schema": 1,
            "registry_identity": self.registry_identity.to_dict(),
            "registry_relpath": self.registry_relpath,
            "registry_sha256": self.registry_sha256,
            "relevant_catalog_sha256": self.relevant_catalog_sha256,
            "tool_world_sha256": self.tool_world_sha256,
        }

    @property
    def sha256(self) -> str:
        return _framed_hash(b"OGHIDRA_CANONICALIZATION_RECEIPT_V1", _canonical_bytes(self.to_dict()))


@dataclass(frozen=True)
class CanonicalizationPlan:
    bundle: AssemblyBundle
    translation_units: tuple[TranslationUnitPlan, ...]
    owner_bindings: tuple[OwnerBinding, ...]
    compatibility_checks: tuple[CompatibilityEvidence, ...]
    discarded_variants: tuple[DiscardedVariant, ...]
    receipt: CanonicalizationReceipt


@dataclass(frozen=True)
class _DeclarationSite:
    symbol: str
    relpath: str
    kind: Literal["declaration", "definition"]
    fragment: bytes
    start: int
    end: int
    container: Literal["header", "source"]
    ordinal: int


def _brace_depths(data: bytes, mask: bytearray) -> list[int]:
    depth = 0
    result: list[int] = []
    for index, byte in enumerate(data):
        result.append(depth)
        if not mask[index]:
            continue
        if byte == ord("{"):
            depth += 1
        elif byte == ord("}"):
            depth -= 1
            if depth < 0:
                _fail("declarator_lexical_imbalance", "canonicalize", "unbalanced translation-unit braces")
    if depth:
        _fail("declarator_lexical_imbalance", "canonicalize", "unbalanced translation-unit braces")
    return result


def _symbol_tokens(data: bytes) -> list[tuple[str, int, int, int]]:
    mask = _code_mask(data)
    depths = _brace_depths(data, mask)
    result = []
    for match in _IDENTIFIER_BYTES_RE.finditer(data):
        if all(mask[index] for index in range(match.start(), match.end())):
            result.append((match.group().decode("ascii"), match.start(), match.end(), depths[match.start()]))
    return result


def _site_for_token(data: bytes, symbol: str, start: int, end: int, depth: int) -> tuple[str, int, int] | None:
    if depth != 0:
        return None
    mask = _code_mask(data)
    opening = _skip_space(data, mask, end)
    if opening >= len(data) or data[opening] != ord("("):
        return None
    closing = _match_balanced(data, mask, opening, ord("("), ord(")"))
    cursor = _skip_space(data, mask, closing + 1)
    while cursor < len(data) and data[cursor] not in b";{":
        cursor += 1
    if cursor >= len(data):
        return None
    kind = "definition" if data[cursor] == ord("{") else "declaration"
    if kind == "definition":
        finish = _match_balanced(data, mask, cursor, ord("{"), ord("}")) + 1
    else:
        finish = cursor + 1
    begin = 0
    for index in range(start - 1, -1, -1):
        if mask[index] and data[index] in b";}":
            begin = index + 1
            break
    begin = _skip_space(data, mask, begin)
    if kind == "declaration":
        prefix_tokens = re.findall(rb"[A-Za-z_][A-Za-z0-9_]*", data[begin:start])
        if not prefix_tokens or prefix_tokens[-1].decode("ascii") in _CONTROL_WORDS:
            return None
    return kind, begin, finish


def _bundle_preimage(bundle: AssemblyBundle) -> dict[str, object]:
    return {
        "attempt": bundle.attempt,
        "behavior_tier": bundle.behavior_tier,
        "bundle_schema": 1,
        "tool_world_sha256": bundle.tool_world.tool_world_sha256,
        "translation_units": [
            {
                "compile_argv": list(item.compile_argv),
                "header_relpath": item.header_relpath,
                "header_sha256": item.header_sha256,
                "object_relpath": item.object_relpath,
                "ordinal": item.ordinal,
                "role": item.role,
                "source_relpath": item.source_relpath,
                "source_sha256": item.source_sha256,
                "unit": item.unit,
            }
            for item in bundle.translation_units
        ],
        "unit": bundle.unit,
    }


def _bundle_candidate(bundle: AssemblyBundle) -> Candidate:
    if bundle.candidate is not None:
        return bundle.candidate
    item = next(unit for unit in bundle.translation_units if unit.role == "candidate")
    return Candidate(item.source_relpath, item.source_sha256, len(item.source), item.source_sha256, item.header_sha256)


def _bundle_window(bundle: AssemblyBundle) -> tuple[WindowItem, ...]:
    if bundle.window:
        return bundle.window
    return tuple(
        WindowItem(item.ordinal, item.unit, item.source_relpath, item.source_sha256, len(item.source))
        for item in bundle.translation_units
    )


def _validate_candidate(candidate: Candidate) -> bool:
    if not isinstance(candidate, Candidate):
        return False
    try:
        _validate_relpath(candidate.artifact_relpath)
    except AssemblyAbiError:
        return False
    return (
        _valid_sha(candidate.artifact_sha256)
        and _valid_sha(candidate.source_sha256)
        and _valid_sha(candidate.header_sha256)
        and _nonnegative_int(candidate.artifact_size)
    )


def _validate_bundle(bundle: AssemblyBundle) -> AssemblyAbiRefusal | None:
    if not isinstance(bundle, AssemblyBundle):
        return AssemblyAbiRefusal("bundle_shape_invalid", "canonicalize", "bundle record is malformed")
    if not _nonempty_string(bundle.unit) or not _positive_int(bundle.attempt) or not isinstance(bundle.behavior_tier, str) or bundle.behavior_tier not in {"compile_only", "oracle_green"}:
        return AssemblyAbiRefusal("bundle_shape_invalid", "canonicalize", "invalid unit/attempt/behavior tier")
    if not isinstance(bundle.translation_units, tuple) or not bundle.translation_units or not isinstance(bundle.tool_world, ToolWorld):
        return AssemblyAbiRefusal("bundle_shape_invalid", "canonicalize", "bundle is empty")
    if not all(isinstance(item, BundleTranslationUnit) for item in bundle.translation_units):
        return AssemblyAbiRefusal("bundle_shape_invalid", "canonicalize", "translation-unit records are malformed")
    ordinals = [item.ordinal for item in bundle.translation_units]
    if ordinals != list(range(len(ordinals))):
        return AssemblyAbiRefusal("bundle_shape_invalid", "canonicalize", "translation-unit ordinals must start at zero")
    if sum(item.role == "candidate" for item in bundle.translation_units) != 1:
        return AssemblyAbiRefusal("bundle_shape_invalid", "canonicalize", "exactly one candidate is required")
    paths: set[str] = set()
    object_paths: set[str] = set()
    for item in bundle.translation_units:
        if (
            not _nonnegative_int(item.ordinal)
            or not _nonempty_string(item.unit)
            or not isinstance(item.role, str)
            or item.role not in {"candidate", "window"}
            or not isinstance(item.source, bytes)
            or not isinstance(item.header, bytes)
            or not _valid_sha(item.source_sha256)
            or not _valid_sha(item.header_sha256)
            or not isinstance(item.compile_argv, tuple)
        ):
            return AssemblyAbiRefusal("bundle_shape_invalid", "canonicalize", "translation-unit fields are malformed")
        try:
            _validate_relpath(item.source_relpath)
            _validate_relpath(item.header_relpath)
            _validate_relpath(item.object_relpath)
        except AssemblyAbiError as exc:
            return replace(exc.refusal, stage="canonicalize")
        if item.source_relpath in paths or item.header_relpath in paths or item.object_relpath in object_paths:
            return AssemblyAbiRefusal("bundle_path_ambiguous", "canonicalize", "bundle paths must be unique")
        paths.update((item.source_relpath, item.header_relpath))
        object_paths.add(item.object_relpath)
        if item.source_sha256 != _hash_bytes(item.source) or item.header_sha256 != _hash_bytes(item.header):
            return AssemblyAbiRefusal("bundle_digest_drift", "canonicalize", f"source/header digest mismatch for {item.unit}")
        if not item.compile_argv or not all(isinstance(value, str) and value for value in item.compile_argv):
            return AssemblyAbiRefusal("compile_argv_unbound", "canonicalize", f"compile argv missing for {item.unit}")
    if not isinstance(bundle.tool_world.identities, tuple) or not all(
        isinstance(identity, ToolIdentity) for identity in bundle.tool_world.identities
    ):
        return AssemblyAbiRefusal("tool_world_invalid", "canonicalize", "tool identities are malformed")
    roles = tuple(identity.role for identity in bundle.tool_world.identities)
    expected_roles = tuple(sorted(("emcc", "clang", "wasm-ld", "object-inspector", "node", "smoke-script")))
    if roles != expected_roles:
        return AssemblyAbiRefusal("tool_world_invalid", "canonicalize", "tool identities must be role sorted")
    for identity in bundle.tool_world.identities:
        if (
            not _nonempty_string(identity.resolved_path)
            or not Path(identity.resolved_path).is_absolute()
            or not _valid_sha(identity.file_sha256)
            or not _valid_sha(identity.version_sha256)
        ):
            return AssemblyAbiRefusal("tool_world_invalid", "canonicalize", f"invalid bound tool identity for {identity.role}")
    if bundle.tool_world.compile_argv != tuple(item.compile_argv for item in bundle.translation_units):
        return AssemblyAbiRefusal("compile_argv_unbound", "canonicalize", "tool world compile argv differs from translation-unit plans")
    if not isinstance(bundle.tool_world.inspect_argv, tuple) or len(bundle.tool_world.inspect_argv) != len(bundle.translation_units) or not all(
        isinstance(item, tuple) and item and all(_nonempty_string(arg) for arg in item) for item in bundle.tool_world.inspect_argv
    ):
        return AssemblyAbiRefusal("tool_world_invalid", "canonicalize", "inspect argv must match plan order")
    if any(
        not isinstance(row, tuple) or not row or not all(_nonempty_string(arg) for arg in row)
        for row in (bundle.tool_world.link_argv, bundle.tool_world.instantiate_argv, bundle.tool_world.smoke_argv)
    ):
        return AssemblyAbiRefusal("tool_world_invalid", "canonicalize", "link/instantiate/smoke argv must be explicit")
    if not isinstance(bundle.tool_world.environment, tuple) or not all(
        isinstance(item, tuple)
        and len(item) == 2
        and _nonempty_string(item[0])
        and _valid_sha(item[1])
        for item in bundle.tool_world.environment
    ):
        return AssemblyAbiRefusal("tool_world_invalid", "canonicalize", "environment bindings are malformed")
    if tuple(name for name, _digest in bundle.tool_world.environment) != tuple(sorted(name for name, _digest in bundle.tool_world.environment)):
        return AssemblyAbiRefusal("tool_world_invalid", "canonicalize", "environment must be name sorted")
    if len({name for name, _digest in bundle.tool_world.environment}) != len(bundle.tool_world.environment) or any(
        not _nonempty_string(name) or not _valid_sha(digest) for name, digest in bundle.tool_world.environment
    ):
        return AssemblyAbiRefusal("tool_world_invalid", "canonicalize", "environment bindings are invalid")
    if bundle.candidate is not None and not isinstance(bundle.candidate, Candidate):
        return AssemblyAbiRefusal("bundle_shape_invalid", "canonicalize", "candidate binding invalid")
    if not isinstance(bundle.window, tuple) or not all(isinstance(item, WindowItem) for item in bundle.window):
        return AssemblyAbiRefusal("bundle_shape_invalid", "canonicalize", "window binding invalid")
    candidate = _bundle_candidate(bundle)
    window = _bundle_window(bundle)
    if not _validate_candidate(candidate):
        return AssemblyAbiRefusal("bundle_shape_invalid", "canonicalize", "candidate binding invalid")
    if [item.ordinal for item in window] != list(range(len(window))) or len({item.unit for item in window}) != len(window):
        return AssemblyAbiRefusal("bundle_shape_invalid", "canonicalize", "window must be uniquely ordinal sorted")
    for item in window:
        try:
            _validate_relpath(item.artifact_relpath)
        except AssemblyAbiError as exc:
            return replace(exc.refusal, stage="canonicalize")
        if not _nonempty_string(item.unit) or not _valid_sha(item.artifact_sha256) or not _nonnegative_int(item.artifact_size):
            return AssemblyAbiRefusal("bundle_shape_invalid", "canonicalize", "window binding invalid")
    if not _nonempty_string(bundle.assembly_module_revision) or not _nonempty_string(bundle.driver_revision):
        return AssemblyAbiRefusal("assembly_world_invalid", "canonicalize", "implementation revisions must be bound")
    return None


def _apply_replacements(data: bytes, replacements: Sequence[tuple[int, int, bytes]]) -> bytes:
    result = data
    ordered = sorted(replacements)
    if any(left[1] > right[0] for left, right in zip(ordered, ordered[1:])):
        _fail("canonicalization_overlap", "canonicalize", "declaration replacements overlap")
    for start, end, replacement in reversed(ordered):
        result = result[:start] + replacement + result[end:]
    return result


def plan_canonicalization(
    bundle: AssemblyBundle,
    owners: OwnerSnapshot,
) -> CanonicalizationPlan | AssemblyAbiRefusal:
    """Purely plan whole-bundle owner canonicalization or refuse atomically."""

    invalid = _validate_bundle(bundle)
    if invalid is not None:
        return invalid
    if (
        not isinstance(owners, OwnerSnapshot)
        or not _parser_identity_is_valid(owners.parser_identity)
        or not isinstance(owners.owner_index, Mapping)
        or not isinstance(owners.bindings, tuple)
        or not all(isinstance(binding, OwnerBinding) for binding in owners.bindings)
        or not _valid_sha(owners.registry_sha256)
        or not _valid_sha(owners.index_sha256)
        or not _stable_identity_is_valid(owners.registry_identity)
        or not _stable_identity_is_valid(owners.index_identity)
        or not all(
            isinstance(symbol, str)
            and _IDENTIFIER_RE.fullmatch(symbol) is not None
            and isinstance(bindings, tuple)
            and all(isinstance(binding, OwnerBinding) for binding in bindings)
            for symbol, bindings in owners.owner_index.items()
        )
    ):
        return AssemblyAbiRefusal("owner_snapshot_invalid", "owner", "owner snapshot shape is malformed")
    try:
        _validate_relpath(owners.registry_relpath)
        _validate_relpath(owners.index_relpath)
    except AssemblyAbiError:
        return AssemblyAbiRefusal("owner_snapshot_invalid", "owner", "owner snapshot paths are malformed")
    parser_identity = getattr(owners.declarator_parser, "identity", None)
    if not isinstance(parser_identity, ParserIdentity) or parser_identity != owners.parser_identity:
        return AssemblyAbiRefusal(
            "parser_tool_identity_mismatch", "canonicalize", "snapshot parser no longer matches its bound identity"
        )
    clang_identity = next(
        (identity for identity in bundle.tool_world.identities if identity.role == "clang"),
        None,
    )
    if (
        clang_identity is None
        or owners.parser_identity.executable_path != clang_identity.resolved_path
        or owners.parser_identity.binary_sha256 != clang_identity.file_sha256
        or owners.parser_identity.version_sha256 != clang_identity.version_sha256
    ):
        return AssemblyAbiRefusal(
            "parser_tool_identity_mismatch",
            "canonicalize",
            "owner parser path/binary/version must equal the ToolWorld clang identity",
        )
    parser = owners.declarator_parser
    relevant: set[str] = set()
    sites: list[_DeclarationSite] = []
    definitions: dict[str, list[_DeclarationSite]] = {}
    for item in bundle.translation_units:
        for container, relpath, data in (
            ("header", item.header_relpath, item.header),
            ("source", item.source_relpath, item.source),
        ):
            scan_data = data
            if container == "source" and _VERBATIM_MARKER in data:
                prelude_end = data.index(_VERBATIM_MARKER)
            else:
                prelude_end = len(data)
            seen_site_spans: set[tuple[int, int]] = set()
            for symbol, start, end, depth in _symbol_tokens(scan_data):
                discovered = _site_for_token(scan_data, symbol, start, end, depth)
                mask = _code_mask(scan_data)
                following = _skip_space(scan_data, mask, end)
                preceding = _previous_code(scan_data, mask, start)
                function_reference = (
                    discovered is not None
                    or (following < len(scan_data) and scan_data[following] == ord("("))
                    or (preceding >= 0 and scan_data[preceding] == ord("&"))
                )
                if function_reference and (symbol in owners.owner_index or _INTERNAL_RE.fullmatch(symbol)):
                    relevant.add(symbol)
                if discovered is None:
                    continue
                kind, site_start, site_end = discovered
                if (site_start, site_end) in seen_site_spans:
                    continue
                seen_site_spans.add((site_start, site_end))
                if container == "source" and kind == "declaration" and site_end > prelude_end:
                    continue
                site = _DeclarationSite(
                    symbol,
                    relpath,
                    kind,  # type: ignore[arg-type]
                    scan_data[site_start:site_end],
                    site_start,
                    site_end,
                    container,  # type: ignore[arg-type]
                    item.ordinal,
                )
                sites.append(site)
                if kind == "definition":
                    definitions.setdefault(symbol, []).append(site)
    relevant = {symbol for symbol in relevant if symbol in owners.owner_index or _INTERNAL_RE.fullmatch(symbol)}
    selected: dict[str, OwnerBinding] = {}
    for symbol in sorted(relevant):
        candidates = owners.owner_index.get(symbol, ())
        if not candidates:
            return AssemblyAbiRefusal("owner_missing", "owner", f"no verified owner for {symbol}")
        if len(candidates) != 1:
            return AssemblyAbiRefusal("owner_ambiguous", "owner", f"multiple verified owners for {symbol}")
        if len(definitions.get(symbol, ())) > 1:
            return AssemblyAbiRefusal("selected_direct_definition_ambiguous", "canonicalize", f"multiple selected definitions for {symbol}")
        selected[symbol] = candidates[0]

    compatibility: list[CompatibilityEvidence] = []
    discarded: list[DiscardedVariant] = []
    replacements: dict[tuple[int, str], list[tuple[int, int, bytes]]] = {}
    try:
        registryless: dict[str, set[str]] = {}
        for site in sites:
            if site.symbol in selected or _INTERNAL_RE.fullmatch(site.symbol) or site.symbol.startswith(_EXTERNAL_PREFIXES):
                continue
            if site.kind != "declaration":
                continue
            projection = parser.parse_declaration(site.fragment, site.symbol)
            if not _declarator_projection_is_valid(projection, site.symbol):
                return AssemblyAbiRefusal(
                    "declarator_parser_fault", "canonicalize", f"parser returned malformed projection for {site.symbol}"
                )
            registryless.setdefault(site.symbol, set()).add(projection.canonical_prototype)
        divergent = sorted(symbol for symbol, variants in registryless.items() if len(variants) > 1)
        if divergent:
            return AssemblyAbiRefusal(
                "registryless_declaration_divergence",
                "canonicalize",
                "ordinary absent symbols diverged: " + ", ".join(divergent),
            )
        for site in sorted(sites, key=lambda item: (item.symbol, item.relpath, item.start, item.kind)):
            if site.symbol not in selected:
                continue
            owner = selected[site.symbol]
            variant = (
                parser.parse_definition(site.fragment, site.symbol)
                if site.kind == "definition"
                else parser.parse_declaration(site.fragment, site.symbol)
            )
            if not _declarator_projection_is_valid(variant, site.symbol):
                return AssemblyAbiRefusal(
                    "declarator_parser_fault", "canonicalize", f"parser returned malformed projection for {site.symbol}"
                )
            probe = parser.compatibility(owner.projection, variant)
            if not _compatibility_probe_is_valid(
                probe,
                owner.projection,
                variant,
                owners.parser_identity.sha256,
            ):
                return AssemblyAbiRefusal(
                    "declarator_parser_fault", "canonicalize", f"parser returned malformed compatibility probe for {site.symbol}"
                )
            evidence = CompatibilityEvidence(
                site.symbol,
                site.relpath,
                owner.projection.canonical_prototype_sha256,
                variant.canonical_prototype_sha256,
                owner.projection.abi_tuple.sha256,
                variant.abi_tuple.sha256,
                len(probe.source),
                probe.source_sha256,
                probe.parser_identity_sha256,
                "compatible" if probe.compatible else "incompatible",
                probe.source,
                owner.projection.canonical_prototype,
                variant.canonical_prototype,
            )
            compatibility.append(evidence)
            if not probe.compatible:
                return AssemblyAbiRefusal(
                    "owner_variant_abi_incompatible",
                    "canonicalize",
                    f"Clang rejected {site.symbol} owner/variant pair at {site.relpath}",
                    probe.source_sha256,
                )
            if site.kind == "declaration":
                discarded.append(DiscardedVariant(site.symbol, site.relpath, variant.canonical_prototype_sha256))
                replacements.setdefault((site.ordinal, site.container), []).append(
                    (site.start, site.end, owner.normalized_prototype.encode("utf-8"))
                )
    except AssemblyAbiError as exc:
        return replace(exc.refusal, stage="canonicalize")
    except Exception as exc:
        return AssemblyAbiRefusal("declarator_parser_fault", "canonicalize", f"parser adapter fault: {exc}")

    compatibility.sort(key=lambda item: (item.symbol, item.source_relpath, item.variant_prototype_sha256))
    if len({(item.symbol, item.source_relpath, item.variant_prototype_sha256) for item in compatibility}) != len(compatibility):
        return AssemblyAbiRefusal("compatibility_evidence_ambiguous", "canonicalize", "duplicate compatibility evidence key")
    discarded.sort(key=lambda item: (item.symbol, item.source_relpath, item.prototype_sha256))
    if len({(item.symbol, item.source_relpath, item.prototype_sha256) for item in discarded}) != len(discarded):
        return AssemblyAbiRefusal("discarded_variant_ambiguous", "canonicalize", "duplicate discarded variant key")

    planned: list[TranslationUnitPlan] = []
    for item in bundle.translation_units:
        try:
            header = _apply_replacements(item.header, replacements.get((item.ordinal, "header"), ()))
            source = _apply_replacements(item.source, replacements.get((item.ordinal, "source"), ()))
            for symbol in sorted(selected):
                prototype = selected[symbol].normalized_prototype.encode("utf-8")
                if prototype not in header:
                    if header and not header.endswith(b"\n"):
                        header += b"\n"
                    header += prototype + b"\n"
        except AssemblyAbiError as exc:
            return exc.refusal
        planned.append(
            TranslationUnitPlan(
                item.ordinal,
                item.unit,
                item.role,
                item.source_relpath,
                item.source_sha256,
                item.header_relpath,
                item.header_sha256,
                source,
                _hash_bytes(source),
                header,
                _hash_bytes(header),
                item.object_relpath,
                item.compile_argv,
            )
        )
    bindings = tuple(selected[symbol] for symbol in sorted(selected))
    relevant_catalog = _framed_hash(
        b"OGHIDRA_RELEVANT_OWNER_CATALOG_V1",
        _canonical_bytes([{"owner_binding_sha256": item.owner_binding_sha256, "symbol": item.symbol} for item in bindings]),
    )
    bundle_sha = _framed_hash(b"OGHIDRA_ASSEMBLY_BUNDLE_V1", _canonical_bytes(_bundle_preimage(bundle)))
    derived_preimage = [
        {
            "derived_header_sha256": item.derived_header_sha256,
            "derived_source_sha256": item.derived_source_sha256,
            "object_relpath": item.object_relpath,
            "ordinal": item.ordinal,
            "unit": item.unit,
        }
        for item in planned
    ]
    derived_bundle_sha = _framed_hash(b"OGHIDRA_DERIVED_ASSEMBLY_BUNDLE_V1", _canonical_bytes(derived_preimage))
    owner_files_by_path: dict[str, OwnerFileEvidence] = {}
    for item in bindings:
        prior_source = owner_files_by_path.get(item.source.chunk_file)
        if prior_source is not None and (
            prior_source.file_sha256 != item.source.file_sha256 or prior_source.identity != item.source.identity
        ):
            return AssemblyAbiRefusal("stable_read_race", "canonicalize", "owner snapshot mixed source versions")
        owner_files_by_path[item.source.chunk_file] = item.source
    bundle_files = tuple(
        binding
        for item in bundle.translation_units
        for binding in (
            BundleFileBinding(item.header_relpath, item.header_sha256, len(item.header)),
            BundleFileBinding(item.source_relpath, item.source_sha256, len(item.source)),
        )
    )
    assembly_world_preimage = {
        "abi_probe_evidence_sha256s": [
            {"abi_probe_evidence_sha256": item.projection.abi_probe_evidence.sha256, "symbol": item.symbol}
            for item in bindings
        ],
        "assembly_world_schema": 1,
        "candidate": _bundle_candidate(bundle).to_dict(),
        "compatibility_checks": [item.to_dict() for item in compatibility],
        "implementation": {
            "assembly_module_revision": bundle.assembly_module_revision,
            "driver_revision": bundle.driver_revision,
        },
        "relevant_owner_bindings": [
            {"owner_binding_sha256": item.owner_binding_sha256, "symbol": item.symbol} for item in bindings
        ],
        "schema_versions": {
            "assembly_result_schema": 1,
            "canonicalization_schema": 1,
            "compatibility_schema": 1,
            "oracle_registry_schema": 1,
        },
        "tool_world_sha256": bundle.tool_world.tool_world_sha256,
        "window": [item.to_dict() for item in _bundle_window(bundle)],
    }
    assembly_world_sha = _hash_bytes(_canonical_bytes(assembly_world_preimage))
    receipt = CanonicalizationReceipt(
        bundle_sha,
        derived_bundle_sha,
        relevant_catalog,
        owners.registry_relpath,
        owners.registry_sha256,
        owners.registry_identity,
        owners.index_relpath,
        owners.index_sha256,
        owners.index_identity,
        owners.parser_identity.sha256,
        bindings,
        tuple(owner_files_by_path[path] for path in sorted(owner_files_by_path)),
        tuple(compatibility),
        tuple(discarded),
        tuple(sorted(bundle_files, key=lambda item: item.relpath)),
        bundle.tool_world.tool_world_sha256,
        assembly_world_sha,
        owners.parser_identity,
        bundle.tool_world,
    )
    return CanonicalizationPlan(bundle, tuple(planned), bindings, tuple(compatibility), tuple(discarded), receipt)


# Final composition interface (approved schema 1).


@dataclass(frozen=True)
class SymbolObservation:
    name: str
    kind: Literal["function", "global", "table", "memory", "tag"]
    abi_sha256: str | None
    visibility: Literal["default", "hidden"]

    def to_dict(self) -> dict[str, object]:
        return {"abi_sha256": self.abi_sha256, "kind": self.kind, "name": self.name, "visibility": self.visibility}


@dataclass(frozen=True)
class InspectorReceipt:
    execution_completed: bool
    success: bool
    exit_status: int | None
    stdout_sha256: str | None
    stderr_sha256: str | None
    parser_version: str
    fault_class: Literal["spawn", "timeout", "crash", "io"] | None
    diagnostic_sha256: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "diagnostic_sha256": self.diagnostic_sha256,
            "execution_completed": self.execution_completed,
            "exit_status": self.exit_status,
            "fault_class": self.fault_class,
            "parser_version": self.parser_version,
            "stderr_sha256": self.stderr_sha256,
            "stdout_sha256": self.stdout_sha256,
            "success": self.success,
        }

    @property
    def receipt_sha256(self) -> str:
        return _hash_bytes(_canonical_bytes(self.to_dict()))


@dataclass(frozen=True)
class StageChildReceipt:
    child_ordinal: int
    object_ordinal: int
    unit: str
    stage: Literal["compile", "inspect"]
    terminal: bool
    argv: tuple[str, ...]
    object_relpath: str
    input_sha256: str
    object_sha256: str | None
    state: Literal["passed", "failed", "faulted"]
    execution_completed: bool
    exit_status: int | None
    stdout_size: int
    stdout_sha256: str
    stderr_size: int
    stderr_sha256: str
    parser_version: str
    diagnostic_sha256: str | None
    symbol: str | None
    fault_class: Literal["spawn", "timeout", "crash", "io", "lock", "stable_read"] | None
    stage_child_receipt_schema: int = field(default=1, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "argv": list(self.argv),
            "child_ordinal": self.child_ordinal,
            "diagnostic_sha256": self.diagnostic_sha256,
            "execution_completed": self.execution_completed,
            "exit_status": self.exit_status,
            "fault_class": self.fault_class,
            "input_sha256": self.input_sha256,
            "object_ordinal": self.object_ordinal,
            "object_relpath": self.object_relpath,
            "object_sha256": self.object_sha256,
            "parser_version": self.parser_version,
            "stage": self.stage,
            "stage_child_receipt_schema": 1,
            "state": self.state,
            "stderr_sha256": self.stderr_sha256,
            "stderr_size": self.stderr_size,
            "stdout_sha256": self.stdout_sha256,
            "stdout_size": self.stdout_size,
            "symbol": self.symbol,
            "terminal": self.terminal,
            "unit": self.unit,
        }


def stage_child_transcript_sha256(stage: str, children: Sequence[StageChildReceipt]) -> str:
    return _hash_bytes(
        _canonical_bytes(
            {"children": [item.to_dict() for item in children], "stage": stage, "stage_child_transcript_schema": 1}
        )
    )


def stage_stream_sha256(stage: str, stream: Literal["stdout", "stderr"], children: Sequence[StageChildReceipt]) -> str:
    return _hash_bytes(
        _canonical_bytes(
            {
                "children": [
                    {
                        "child_ordinal": item.child_ordinal,
                        "sha256": item.stdout_sha256 if stream == "stdout" else item.stderr_sha256,
                        "size": item.stdout_size if stream == "stdout" else item.stderr_size,
                    }
                    for item in children
                ],
                "stage": stage,
                "stage_stream_schema": 1,
                "stream": stream,
            }
        )
    )


@dataclass(frozen=True)
class StageReceipt:
    stage: Literal["compile", "inspect", "link", "instantiate", "smoke"]
    state: Literal["not_run", "passed", "failed", "faulted"]
    execution_completed: bool
    exit_status: int | None
    stdout_sha256: str | None
    stderr_sha256: str | None
    parser_version: str | None
    diagnostic_sha256: str | None
    symbol: str | None
    named_object_relpaths: tuple[str, ...]
    fault_class: Literal["spawn", "timeout", "crash", "io", "lock", "stable_read"] | None
    child_receipts: tuple[StageChildReceipt, ...] = ()
    child_transcript_sha256: str | None = None
    stage_receipt_schema: int = field(default=1, init=False)

    @classmethod
    def not_run(cls, stage: str) -> "StageReceipt":
        return cls(stage, "not_run", False, None, None, None, None, None, None, (), None)  # type: ignore[arg-type]

    def to_dict(self) -> dict[str, object]:
        return {
            "child_receipts": [item.to_dict() for item in self.child_receipts],
            "child_transcript_sha256": self.child_transcript_sha256,
            "diagnostic_sha256": self.diagnostic_sha256,
            "execution_completed": self.execution_completed,
            "exit_status": self.exit_status,
            "fault_class": self.fault_class,
            "named_object_relpaths": list(self.named_object_relpaths),
            "parser_version": self.parser_version,
            "stage": self.stage,
            "stage_receipt_schema": 1,
            "state": self.state,
            "stderr_sha256": self.stderr_sha256,
            "stdout_sha256": self.stdout_sha256,
            "symbol": self.symbol,
        }


@dataclass(frozen=True)
class ToolOutcome:
    receipts: tuple[StageReceipt, StageReceipt, StageReceipt, StageReceipt, StageReceipt]
    tool_outcome_schema: int = field(default=1, init=False)

    def to_dict(self) -> dict[str, object]:
        return {"receipts": [item.to_dict() for item in self.receipts], "tool_outcome_schema": 1}


@dataclass(frozen=True)
class ObjectObservation:
    ordinal: int
    unit: str
    object_relpath: str
    object_size: int
    object_sha256: str
    defined_symbols: tuple[SymbolObservation, ...]
    imported_symbols: tuple[SymbolObservation, ...]
    inspector_receipt: InspectorReceipt

    def result_dict(self) -> dict[str, object]:
        return {
            "defined_symbols": [item.to_dict() for item in self.defined_symbols],
            "imported_symbols": [item.to_dict() for item in self.imported_symbols],
            "inspector_receipt_sha256": self.inspector_receipt.receipt_sha256,
            "object_relpath": self.object_relpath,
            "object_sha256": self.object_sha256,
            "object_size": self.object_size,
            "ordinal": self.ordinal,
            "unit": self.unit,
        }


@dataclass(frozen=True)
class Contributor:
    symbol: str
    unit: str
    object_relpath: str
    object_sha256: str
    role: Literal["definition", "import"]
    abi_sha256: str

    def to_dict(self) -> dict[str, str]:
        return {
            "abi_sha256": self.abi_sha256,
            "object_relpath": self.object_relpath,
            "object_sha256": self.object_sha256,
            "role": self.role,
            "symbol": self.symbol,
            "unit": self.unit,
        }


def _shape_error(code: str, detail: str) -> None:
    _fail(code, "internal", detail)


def _valid_sha(value: object, *, nullable: bool = False) -> bool:
    if value is None:
        return nullable
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _validate_inspector_receipt(receipt: InspectorReceipt) -> None:
    if not isinstance(receipt, InspectorReceipt):
        _shape_error("inspector_receipt_invalid", "inspector receipt record invalid")
    if type(receipt.execution_completed) is not bool or type(receipt.success) is not bool or not _nonempty_string(receipt.parser_version):
        _shape_error("inspector_receipt_invalid", "inspector booleans/parser invalid")
    streams = _valid_sha(receipt.stdout_sha256) and _valid_sha(receipt.stderr_sha256)
    exit_integer = isinstance(receipt.exit_status, int) and not isinstance(receipt.exit_status, bool)
    if receipt.success:
        valid = receipt.execution_completed and receipt.exit_status == 0 and streams and receipt.fault_class is None and receipt.diagnostic_sha256 is None
    elif receipt.execution_completed:
        valid = exit_integer and streams and receipt.fault_class is None and _valid_sha(receipt.diagnostic_sha256)
    else:
        valid = receipt.exit_status is None and isinstance(receipt.fault_class, str) and receipt.fault_class in {"spawn", "timeout", "crash", "io"} and _valid_sha(receipt.diagnostic_sha256)
        valid = valid and (receipt.stdout_sha256 is None or _valid_sha(receipt.stdout_sha256)) and (receipt.stderr_sha256 is None or _valid_sha(receipt.stderr_sha256))
    if not valid:
        _shape_error("inspector_receipt_invalid", "inspector truth matrix violation")


def _validate_symbol(symbol: SymbolObservation) -> None:
    if (
        not isinstance(symbol, SymbolObservation)
        or not isinstance(symbol.name, str)
        or _IDENTIFIER_RE.fullmatch(symbol.name) is None
        or not isinstance(symbol.kind, str)
        or symbol.kind not in {"function", "global", "table", "memory", "tag"}
        or not isinstance(symbol.visibility, str)
        or symbol.visibility not in {"default", "hidden"}
        or (symbol.abi_sha256 is not None and not _valid_sha(symbol.abi_sha256))
    ):
        _shape_error("object_observation_invalid", "symbol observation invalid")


def _validate_child(child: StageChildReceipt) -> None:
    if not isinstance(child, StageChildReceipt):
        _shape_error("stage_child_receipt_invalid", "child receipt record invalid")
    if not isinstance(child.argv, tuple) or not all(isinstance(item, str) for item in child.argv):
        _shape_error("stage_child_receipt_invalid", "child argv invalid")
    try:
        _validate_relpath(child.object_relpath)
    except AssemblyAbiError:
        _shape_error("stage_child_receipt_invalid", "invalid child object path")
    if (
        not _nonnegative_int(child.child_ordinal)
        or not _nonnegative_int(child.object_ordinal)
        or not _nonempty_string(child.unit)
        or not isinstance(child.stage, str)
        or child.stage not in {"compile", "inspect"}
        or type(child.terminal) is not bool
        or not child.argv
        or not all(_nonempty_string(item) for item in child.argv)
        or not _valid_sha(child.input_sha256)
        or not _nonnegative_int(child.stdout_size)
        or not _nonnegative_int(child.stderr_size)
        or not _valid_sha(child.stdout_sha256)
        or not _valid_sha(child.stderr_sha256)
        or not _nonempty_string(child.parser_version)
        or (child.symbol is not None and (not isinstance(child.symbol, str) or _IDENTIFIER_RE.fullmatch(child.symbol) is None))
    ):
        _shape_error("stage_child_receipt_invalid", "child scalar field invalid")
    if child.stage == "inspect" and child.object_sha256 != child.input_sha256:
        _shape_error("stage_child_receipt_invalid", "inspect object/input digest mismatch")
    if not isinstance(child.state, str):
        _shape_error("stage_child_receipt_invalid", "child state invalid")
    if child.state == "passed":
        valid = child.execution_completed and child.exit_status == 0 and child.diagnostic_sha256 is None and child.symbol is None and child.fault_class is None
        valid = valid and (child.stage != "compile" or _valid_sha(child.object_sha256))
    elif child.state == "failed":
        valid = child.execution_completed and isinstance(child.exit_status, int) and not isinstance(child.exit_status, bool)
        valid = valid and _valid_sha(child.diagnostic_sha256) and child.fault_class is None
    elif child.state == "faulted":
        valid = not child.execution_completed and child.exit_status is None and _valid_sha(child.diagnostic_sha256) and isinstance(child.fault_class, str) and child.fault_class in _FAULT_CLASSES
    else:
        valid = False
    if child.object_sha256 is not None and not _valid_sha(child.object_sha256):
        valid = False
    if not valid:
        _shape_error("stage_child_receipt_invalid", "child truth matrix violation")


def _validate_stage_receipt(
    receipt: StageReceipt,
    plan: CanonicalizationPlan | None = None,
    objects: Mapping[int, ObjectObservation] | None = None,
) -> None:
    if not isinstance(receipt, StageReceipt):
        _shape_error("stage_receipt_invalid", "stage receipt record invalid")
    if not isinstance(receipt.stage, str) or receipt.stage not in _STAGES or not isinstance(receipt.state, str) or receipt.state not in {"not_run", "passed", "failed", "faulted"}:
        _shape_error("stage_receipt_invalid", "stage/state invalid")
    if type(receipt.execution_completed) is not bool:
        _shape_error("stage_receipt_invalid", "execution_completed must be bool")
    if not isinstance(receipt.named_object_relpaths, tuple) or not all(
        isinstance(path, str) for path in receipt.named_object_relpaths
    ):
        _shape_error("stage_receipt_invalid", "named object paths must be a tuple of strings")
    if not isinstance(receipt.child_receipts, tuple) or not all(
        isinstance(child, StageChildReceipt) for child in receipt.child_receipts
    ):
        _shape_error("stage_receipt_invalid", "child receipt collection invalid")
    if len(receipt.named_object_relpaths) != len(set(receipt.named_object_relpaths)):
        _shape_error("stage_receipt_invalid", "object paths must be unique")
    try:
        for path in receipt.named_object_relpaths:
            _validate_relpath(path)
    except AssemblyAbiError:
        _shape_error("stage_receipt_invalid", "invalid named object path")
    if receipt.symbol is not None and (not isinstance(receipt.symbol, str) or _IDENTIFIER_RE.fullmatch(receipt.symbol) is None):
        _shape_error("stage_receipt_invalid", "invalid parsed symbol")
    if receipt.state == "not_run":
        if any(
            value is not None
            for value in (
                receipt.exit_status, receipt.stdout_sha256, receipt.stderr_sha256, receipt.parser_version,
                receipt.diagnostic_sha256, receipt.symbol, receipt.fault_class, receipt.child_transcript_sha256,
            )
        ) or receipt.execution_completed or receipt.named_object_relpaths or receipt.child_receipts:
            _shape_error("stage_receipt_invalid", "not-run receipt carries evidence")
        return
    if receipt.state == "passed":
        valid = (
            receipt.execution_completed
            and receipt.exit_status == 0
            and _valid_sha(receipt.stdout_sha256)
            and _valid_sha(receipt.stderr_sha256)
            and _nonempty_string(receipt.parser_version)
            and receipt.diagnostic_sha256 is None
            and receipt.symbol is None
            and receipt.fault_class is None
        )
    elif receipt.state == "failed":
        valid = (
            receipt.execution_completed
            and isinstance(receipt.exit_status, int)
            and not isinstance(receipt.exit_status, bool)
            and _valid_sha(receipt.stdout_sha256)
            and _valid_sha(receipt.stderr_sha256)
            and _nonempty_string(receipt.parser_version)
            and _valid_sha(receipt.diagnostic_sha256)
            and receipt.fault_class is None
        )
    else:
        valid = (
            not receipt.execution_completed
            and receipt.exit_status is None
            and (receipt.stdout_sha256 is None or _valid_sha(receipt.stdout_sha256))
            and (receipt.stderr_sha256 is None or _valid_sha(receipt.stderr_sha256))
            and _nonempty_string(receipt.parser_version)
            and _valid_sha(receipt.diagnostic_sha256)
            and isinstance(receipt.fault_class, str)
            and receipt.fault_class in _FAULT_CLASSES
        )
    if receipt.stage in {"instantiate", "smoke"} and receipt.symbol is not None:
        valid = False
    if not valid:
        _shape_error("stage_receipt_invalid", "stage truth matrix violation")

    if receipt.stage in {"compile", "inspect"}:
        children = receipt.child_receipts
        if not children or receipt.child_transcript_sha256 != stage_child_transcript_sha256(receipt.stage, children):
            _shape_error("stage_receipt_invalid", "child transcript mismatch")
        if [item.child_ordinal for item in children] != list(range(len(children))):
            _shape_error("stage_receipt_invalid", "child ordinals out of order")
        if [item.object_ordinal for item in children] != sorted({item.object_ordinal for item in children}):
            _shape_error("stage_receipt_invalid", "object ordinals duplicate/out of order")
        if [item.object_relpath for item in children] != list(receipt.named_object_relpaths):
            _shape_error("stage_receipt_invalid", "child/path aggregate mismatch")
        if [item.terminal for item in children] != [False] * (len(children) - 1) + [True]:
            _shape_error("stage_receipt_invalid", "exactly last child must be terminal")
        if any(item.state != "passed" for item in children[:-1]) or children[-1].state != receipt.state:
            _shape_error("stage_receipt_invalid", "child terminal state mismatch")
        for child in children:
            _validate_child(child)
            if child.stage != receipt.stage:
                _shape_error("stage_receipt_invalid", "child stage mismatch")
            if plan is not None:
                if child.object_ordinal >= len(plan.translation_units):
                    _shape_error("stage_receipt_invalid", "unplanned child ordinal")
                unit_plan = plan.translation_units[child.object_ordinal]
                expected_argv = unit_plan.compile_argv if receipt.stage == "compile" else plan.bundle.tool_world.inspect_argv[child.object_ordinal]
                expected_input = unit_plan.derived_source_sha256 if receipt.stage == "compile" else (
                    objects[child.object_ordinal].object_sha256 if objects and child.object_ordinal in objects else child.input_sha256
                )
                if (
                    child.unit != unit_plan.unit
                    or child.object_relpath != unit_plan.object_relpath
                    or child.argv != expected_argv
                    or child.input_sha256 != expected_input
                ):
                    _shape_error("stage_receipt_invalid", "child plan binding mismatch")
                if objects is not None and child.object_ordinal in objects:
                    observed = objects[child.object_ordinal]
                    if not isinstance(observed, ObjectObservation):
                        _shape_error("object_observation_invalid", "object map member invalid")
                    if child.object_sha256 != observed.object_sha256:
                        _shape_error("stage_receipt_invalid", "child output/object observation digest mismatch")
            elif objects is not None and child.object_ordinal in objects:
                observed = objects[child.object_ordinal]
                if not isinstance(observed, ObjectObservation) or child.object_sha256 != observed.object_sha256:
                    _shape_error("stage_receipt_invalid", "child output/object observation digest mismatch")
        if plan is not None:
            expected_ordinals = list(range(len(children)))
            if [item.object_ordinal for item in children] != expected_ordinals:
                _shape_error("stage_receipt_invalid", "children must be an exact plan prefix")
            if receipt.state == "passed" and len(children) != len(plan.translation_units):
                _shape_error("stage_receipt_invalid", "passed child stage must cover every planned object")
        terminal = children[-1]
        if (
            receipt.stdout_sha256 != stage_stream_sha256(receipt.stage, "stdout", children)
            or receipt.stderr_sha256 != stage_stream_sha256(receipt.stage, "stderr", children)
            or receipt.execution_completed != terminal.execution_completed
            or receipt.exit_status != terminal.exit_status
            or receipt.parser_version != terminal.parser_version
            or receipt.diagnostic_sha256 != terminal.diagnostic_sha256
            or receipt.symbol != terminal.symbol
            or receipt.fault_class != terminal.fault_class
        ):
            _shape_error("stage_receipt_invalid", "child aggregate projection mismatch")
    else:
        if receipt.child_receipts or receipt.child_transcript_sha256 is not None:
            _shape_error("stage_receipt_invalid", "non-child stage carries transcript")
        if plan is not None:
            expected_paths = tuple(item.object_relpath for item in plan.translation_units) if receipt.stage == "link" else ()
            if receipt.named_object_relpaths != expected_paths:
                _shape_error("stage_receipt_invalid", "stage object inventory mismatch")


def _validate_tool_outcome(
    outcome: ToolOutcome,
    plan: CanonicalizationPlan | None = None,
    objects: Mapping[int, ObjectObservation] | None = None,
) -> tuple[str, StageReceipt | None]:
    if not isinstance(outcome, ToolOutcome) or not isinstance(outcome.receipts, tuple) or not all(
        isinstance(receipt, StageReceipt) for receipt in outcome.receipts
    ):
        _shape_error("tool_outcome_invalid", "tool outcome/receipt collection invalid")
    if len(outcome.receipts) != 5 or tuple(item.stage for item in outcome.receipts) != _STAGES:
        _shape_error("tool_outcome_invalid", "tool receipt tuple order/length invalid")
    terminal: StageReceipt | None = None
    state = "passing"
    for receipt in outcome.receipts:
        _validate_stage_receipt(receipt, plan, objects)
        if state == "passing" and receipt.state == "passed":
            continue
        if state == "passing" and receipt.state in {"failed", "faulted"}:
            terminal = receipt
            state = "stopped"
            continue
        if state == "stopped" and receipt.state == "not_run":
            continue
        _shape_error("tool_outcome_invalid", "receipt tuple violates P*/one F|X/downstream N grammar")
    compile_receipt, inspect_receipt = outcome.receipts[:2]
    if inspect_receipt.state != "not_run":
        compile_outputs = {child.object_ordinal: child.object_sha256 for child in compile_receipt.child_receipts}
        for child in inspect_receipt.child_receipts:
            if compile_outputs.get(child.object_ordinal) != child.input_sha256:
                _shape_error("tool_outcome_invalid", "compile output and inspect input digest disagree")
    return ("pass" if terminal is None else terminal.state), terminal


@dataclass(frozen=True)
class RetryHistory:
    prior_transient_fingerprint: str | None
    completed_transient_attempts: int
    history_schema: int = field(default=1, init=False)

    def validate(self) -> None:
        if (
            not _nonnegative_int(self.completed_transient_attempts)
            or self.completed_transient_attempts > 3
            or (self.prior_transient_fingerprint is not None and not _valid_sha(self.prior_transient_fingerprint))
            or (self.completed_transient_attempts > 0 and self.prior_transient_fingerprint is None)
        ):
            _shape_error("retry_history_invalid", "retry history is malformed")

    def to_dict(self) -> dict[str, object]:
        return {
            "completed_transient_attempts": self.completed_transient_attempts,
            "history_schema": 1,
            "prior_transient_fingerprint": self.prior_transient_fingerprint,
        }

    @property
    def sha256(self) -> str:
        self.validate()
        return _hash_bytes(_canonical_bytes(self.to_dict()))


@dataclass(frozen=True)
class CompositionReceipt:
    canonicalization: CanonicalizationReceipt
    object_bindings: tuple[BundleFileBinding, ...]
    tool_world_sha256: str
    composition_receipt_schema: int = field(default=1, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "canonicalization_receipt_sha256": self.canonicalization.sha256,
            "composition_receipt_schema": 1,
            "object_bindings": [item.to_dict() for item in self.object_bindings],
            "tool_world_sha256": self.tool_world_sha256,
        }

    @property
    def sha256(self) -> str:
        return _hash_bytes(_canonical_bytes(self.to_dict()))


@dataclass(frozen=True)
class OutcomeProjection:
    classification: Literal["pass", "deterministic_blocker", "transient_fault"]
    stage: Literal["owner", "canonicalize", "materialize", "compile", "inspect", "link", "instantiate", "smoke", "revalidate", "internal"]
    code: str
    stage_receipts: tuple[StageReceipt, StageReceipt, StageReceipt, StageReceipt, StageReceipt]
    diagnostic_sha256: str | None
    contributors: tuple[Contributor, ...]
    unattributed: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "classification": self.classification,
            "code": self.code,
            "contributors": [item.to_dict() for item in self.contributors],
            "diagnostic_sha256": self.diagnostic_sha256,
            "stage": self.stage,
            "stage_receipts": [item.to_dict() for item in self.stage_receipts],
            "unattributed": self.unattributed,
        }


@dataclass(frozen=True)
class ResultScaffold:
    unit: str
    attempt: int
    candidate: Candidate
    window: tuple[WindowItem, ...]
    behavior_tier: Literal["compile_only", "oracle_green"]
    canonicalization: Mapping[str, object]
    objects: tuple[Mapping[str, object], ...]
    tool_world: ToolWorld
    assembly_world_sha256: str = field(repr=False)
    canonicalization_receipt_sha256: str | None = field(default=None, repr=False)
    assembly_result_schema: int = field(default=1, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "assembly_result_schema": 1,
            "attempt": self.attempt,
            "behavior_tier": self.behavior_tier,
            "candidate": self.candidate.to_dict(),
            "canonicalization": _json_ready(self.canonicalization),
            "objects": [_json_ready(item) for item in self.objects],
            "tool_world": self.tool_world.to_result_dict(),
            "unit": self.unit,
            "window": [item.to_dict() for item in self.window],
        }


def _canonicalization_projection(plan: CanonicalizationPlan) -> Mapping[str, object]:
    return _deep_freeze(
        {
            "bundle_sha256": plan.receipt.bundle_sha256,
            "canonicalization_schema": 1,
            "compatibility_checks": [item.to_dict() for item in plan.compatibility_checks],
            "discarded_variants": [item.to_dict() for item in plan.discarded_variants],
            "owner_bindings": [item.public_dict() for item in plan.owner_bindings],
            "relevant_catalog_sha256": plan.receipt.relevant_catalog_sha256,
            "status": "planned",
            "translation_units": [item.result_dict() for item in plan.translation_units],
        }
    )  # type: ignore[return-value]


def _scaffold_from_plan(plan: CanonicalizationPlan, object_docs: Sequence[Mapping[str, object]]) -> ResultScaffold:
    return ResultScaffold(
        plan.bundle.unit,
        plan.bundle.attempt,
        _bundle_candidate(plan.bundle),
        _bundle_window(plan.bundle),
        plan.bundle.behavior_tier,
        _canonicalization_projection(plan),
        tuple(_deep_freeze(item) for item in object_docs),  # type: ignore[arg-type]
        plan.bundle.tool_world,
        plan.receipt.assembly_world_sha256,
        plan.receipt.sha256,
    )


@dataclass(frozen=True)
class CompositionDraft:
    scaffold: ResultScaffold
    analyzed_outcome: OutcomeProjection
    composition_receipt: CompositionReceipt
    retry_history_sha256: str
    composition_draft_schema: int = field(default=1, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "analyzed_outcome": self.analyzed_outcome.to_dict(),
            "composition_draft_schema": 1,
            "composition_receipt": self.composition_receipt.to_dict(),
            "retry_history_sha256": self.retry_history_sha256,
            "scaffold": self.scaffold.to_dict(),
        }


def _observation_classification(
    plan: CanonicalizationPlan,
    objects: tuple[ObjectObservation, ...],
    require_complete: bool,
) -> tuple[list[Mapping[str, object]], dict[int, ObjectObservation], tuple[str, str] | None]:
    by_ordinal: dict[int, ObjectObservation] = {}
    error: tuple[str, str] | None = None
    for item in objects:
        if not isinstance(item, ObjectObservation):
            _shape_error("object_observation_invalid", "object observation record invalid")
        if (
            not _nonnegative_int(item.ordinal)
            or not _nonempty_string(item.unit)
            or not isinstance(item.object_relpath, str)
        ):
            _shape_error("object_observation_invalid", "object observation scalar invalid")
        try:
            _validate_relpath(item.object_relpath)
        except AssemblyAbiError:
            _shape_error("object_observation_invalid", "object observation path invalid")
        if item.ordinal in by_ordinal:
            error = ("duplicate_object_observation", f"duplicate object ordinal {item.ordinal}")
            continue
        by_ordinal[item.ordinal] = item
        if item.ordinal >= len(plan.translation_units):
            error = ("unplanned_object_observation", f"unplanned object ordinal {item.ordinal}")
            continue
        expected = plan.translation_units[item.ordinal]
        if item.unit != expected.unit or item.object_relpath != expected.object_relpath:
            error = ("object_observation_mismatch", f"object mapping mismatch at ordinal {item.ordinal}")
        if not _nonnegative_int(item.object_size) or not _valid_sha(item.object_sha256):
            _shape_error("object_observation_invalid", "object identity invalid")
        if not isinstance(item.defined_symbols, tuple) or not isinstance(item.imported_symbols, tuple):
            _shape_error("object_observation_invalid", "symbol collections must be tuples")
        _validate_inspector_receipt(item.inspector_receipt)
        for collection in (item.defined_symbols, item.imported_symbols):
            for symbol in collection:
                _validate_symbol(symbol)
            keys = [(symbol.name, symbol.kind) for symbol in collection]
            if keys != sorted(set(keys)):
                _shape_error("object_observation_invalid", "symbol lists must be sorted/unique")
    if require_complete and error is None and set(by_ordinal) != set(range(len(plan.translation_units))):
        error = ("missing_object_observation", "one observation per planned object is required")
    docs = []
    for key in sorted(by_ordinal):
        if key >= len(plan.translation_units):
            continue
        item = by_ordinal[key]
        document = item.result_dict()
        if not item.inspector_receipt.success:
            document = {**document, "defined_symbols": [], "imported_symbols": []}
        docs.append(document)
    return docs, by_ordinal, error


def analyze_composition(
    plan: CanonicalizationPlan,
    objects: tuple[ObjectObservation, ...],
    outcome: ToolOutcome,
    retry_history: RetryHistory,
) -> CompositionDraft:
    """Purely validate object/tool evidence and return a non-final draft."""

    if not isinstance(plan, CanonicalizationPlan):
        _shape_error("canonicalization_plan_invalid", "canonicalization plan record invalid")
    if not isinstance(objects, tuple) or not all(isinstance(item, ObjectObservation) for item in objects):
        _shape_error("object_observation_invalid", "object observation collection invalid")
    if not isinstance(outcome, ToolOutcome):
        _shape_error("tool_outcome_invalid", "tool outcome record invalid")
    if not isinstance(retry_history, RetryHistory):
        _shape_error("retry_history_invalid", "retry history record invalid")
    retry_history.validate()
    provisional_state, provisional_terminal = _validate_tool_outcome(outcome, plan)
    if provisional_terminal is not None and provisional_terminal.stage == "compile" and objects:
        _shape_error("object_observation_invalid", "compile-terminal outcome cannot carry inspector observations")
    if provisional_terminal is not None and provisional_terminal.stage == "inspect":
        expected_ordinals = tuple(child.object_ordinal for child in provisional_terminal.child_receipts)
        if tuple(sorted(item.ordinal for item in objects)) != expected_ordinals:
            _shape_error("object_observation_invalid", "inspect-terminal observations must equal attempted children")
    require_complete = provisional_terminal is None or _STAGES.index(provisional_terminal.stage) >= _STAGES.index("link")
    object_docs, by_ordinal, observation_error = _observation_classification(plan, objects, require_complete)
    # Revalidate inspect children against stable object inputs once the object map is known.
    _validate_tool_outcome(outcome, plan, by_ordinal)
    if observation_error is None:
        inspect_stage = outcome.receipts[1]
        inspect_children = {child.object_ordinal: child for child in inspect_stage.child_receipts}
        for item in objects:
            receipt = item.inspector_receipt
            child = inspect_children.get(item.ordinal)
            if child is None:
                _shape_error("tool_outcome_invalid", "object observation has no inspect child receipt")
            expected_success = child.state == "passed"
            if (
                receipt.success is not expected_success
                or receipt.execution_completed != child.execution_completed
                or receipt.exit_status != child.exit_status
                or receipt.stdout_sha256 != child.stdout_sha256
                or receipt.stderr_sha256 != child.stderr_sha256
                or receipt.parser_version != child.parser_version
                or receipt.fault_class != child.fault_class
                or receipt.diagnostic_sha256 != child.diagnostic_sha256
            ):
                _shape_error("tool_outcome_invalid", "inspector receipt contradicts child transcript")

    classification: Literal["pass", "deterministic_blocker", "transient_fault"]
    stage: str
    code: str
    diagnostic: str | None
    parsed_symbol: str | None
    if provisional_state == "pass":
        classification, stage, code, diagnostic, parsed_symbol = "pass", "smoke", "pass", None, None
    else:
        assert provisional_terminal is not None
        stage = provisional_terminal.stage
        parsed_symbol = provisional_terminal.symbol
        diagnostic = provisional_terminal.diagnostic_sha256
        if provisional_terminal.state == "faulted":
            classification = "transient_fault"
            code = f"{stage}_{provisional_terminal.fault_class}"
        else:
            classification = "deterministic_blocker"
            code = f"{stage}_failed"
    if observation_error is not None:
        classification, stage, code = "deterministic_blocker", "inspect", observation_error[0]
        diagnostic = _hash_bytes(_canonical_bytes({"code": code, "detail": observation_error[1]}))
        parsed_symbol = None

    contributors: list[Contributor] = []
    unattributed = classification != "pass"
    if classification != "pass" and parsed_symbol is not None and observation_error is None:
        inspector_unavailable = any(not item.inspector_receipt.success for item in objects)
        matching: list[tuple[ObjectObservation, str, SymbolObservation]] = []
        if not inspector_unavailable:
            for item in objects:
                matching.extend((item, "definition", symbol) for symbol in item.defined_symbols if symbol.name == parsed_symbol)
                matching.extend((item, "import", symbol) for symbol in item.imported_symbols if symbol.name == parsed_symbol)
        if provisional_terminal is not None and provisional_terminal.stage == "inspect" and provisional_terminal.state == "faulted":
            contributors = []
            unattributed = True
        elif inspector_unavailable or any(symbol.abi_sha256 is None for _item, _role, symbol in matching) or not matching:
            code = "object-attribution-unavailable"
            stage = "inspect"
            classification = "deterministic_blocker"
            contributors = []
            unattributed = True
        else:
            contributors = sorted(
                (
                    Contributor(parsed_symbol, item.unit, item.object_relpath, item.object_sha256, role, symbol.abi_sha256)
                    for item, role, symbol in matching
                    if symbol.abi_sha256 is not None
                ),
                key=lambda value: (value.symbol, value.unit, value.object_relpath, value.role),
            )
            unattributed = False

    projection = OutcomeProjection(
        classification,
        stage,  # type: ignore[arg-type]
        code,
        outcome.receipts,
        diagnostic,
        tuple(contributors),
        unattributed,
    )
    object_bindings = tuple(
        BundleFileBinding(item.object_relpath, item.object_sha256, item.object_size)
        for item in sorted(objects, key=lambda value: value.ordinal)
        if item.ordinal < len(plan.translation_units)
    )
    receipt = CompositionReceipt(plan.receipt, object_bindings, plan.bundle.tool_world.tool_world_sha256)
    return CompositionDraft(_scaffold_from_plan(plan, object_docs), projection, receipt, retry_history.sha256)


@dataclass(frozen=True)
class ReceiptObservation:
    stage: Literal["pre-compile", "pre-publication"]
    bundle_sha256: str
    bundle_files: tuple[BundleFileBinding, ...]
    object_bindings: tuple[BundleFileBinding, ...]
    tool_world_sha256: str

    @classmethod
    def from_plan(cls, plan: CanonicalizationPlan) -> "ReceiptObservation":
        return cls("pre-compile", plan.receipt.bundle_sha256, plan.receipt.bundle_files, (), plan.receipt.tool_world_sha256)

    @classmethod
    def from_draft(cls, draft: CompositionDraft) -> "ReceiptObservation":
        receipt = draft.composition_receipt
        return cls(
            "pre-publication",
            receipt.canonicalization.bundle_sha256,
            receipt.canonicalization.bundle_files,
            receipt.object_bindings,
            receipt.tool_world_sha256,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "bundle_files": [item.to_dict() for item in self.bundle_files],
            "bundle_sha256": self.bundle_sha256,
            "object_bindings": [item.to_dict() for item in self.object_bindings],
            "stage": self.stage,
            "tool_world_sha256": self.tool_world_sha256,
        }


@dataclass(frozen=True)
class RevalidationCheck:
    stage: Literal["pre-compile", "pre-publication"]
    receipt_sha256: str
    observation_sha256: str
    passed: bool
    refusal_code: str | None
    check_sha256: str

    @classmethod
    def create(
        cls,
        stage: Literal["pre-compile", "pre-publication"],
        receipt_sha256: str,
        observation_sha256: str,
        passed: bool,
        refusal_code: str | None,
    ) -> "RevalidationCheck":
        preimage = {
            "observation_sha256": observation_sha256,
            "passed": passed,
            "receipt_sha256": receipt_sha256,
            "refusal_code": refusal_code,
            "stage": stage,
        }
        return cls(stage, receipt_sha256, observation_sha256, passed, refusal_code, _hash_bytes(_canonical_bytes(preimage)))

    def validate(self) -> None:
        if (
            not isinstance(self.stage, str)
            or self.stage not in {"pre-compile", "pre-publication"}
            or not _valid_sha(self.receipt_sha256)
            or not _valid_sha(self.observation_sha256)
            or type(self.passed) is not bool
            or (self.passed and self.refusal_code is not None)
            or (not self.passed and not _nonempty_string(self.refusal_code))
            or self != self.create(self.stage, self.receipt_sha256, self.observation_sha256, self.passed, self.refusal_code)
        ):
            _shape_error("revalidation_check_invalid", "revalidation check projection invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "check_sha256": self.check_sha256,
            "observation_sha256": self.observation_sha256,
            "passed": self.passed,
            "receipt_sha256": self.receipt_sha256,
            "refusal_code": self.refusal_code,
            "stage": self.stage,
        }


@dataclass(frozen=True)
class RevalidatedReceipt:
    check: RevalidationCheck

    @property
    def revalidation_sha256(self) -> str:
        return self.check.check_sha256


def _binding_is_valid(binding: object) -> bool:
    if not isinstance(binding, BundleFileBinding):
        return False
    try:
        _validate_relpath(binding.relpath)
    except AssemblyAbiError:
        return False
    return _valid_sha(binding.sha256) and _nonnegative_int(binding.size)


def _stable_identity_is_valid(identity: object) -> bool:
    return isinstance(identity, StableFileIdentity) and all(
        _nonnegative_int(value)
        for value in (
            identity.device,
            identity.inode,
            identity.mode,
            identity.link_count,
            identity.size,
            identity.mtime_ns,
            identity.reparse_tag,
        )
    )


def _canonical_receipt_is_valid(receipt: object) -> bool:
    if not isinstance(receipt, CanonicalizationReceipt):
        return False
    scalar_hashes = (
        receipt.bundle_sha256,
        receipt.derived_bundle_sha256,
        receipt.relevant_catalog_sha256,
        receipt.registry_sha256,
        receipt.index_sha256,
        receipt.parser_identity_sha256,
        receipt.tool_world_sha256,
        receipt.assembly_world_sha256,
    )
    if (
        not all(_valid_sha(value) for value in scalar_hashes)
        or type(receipt.receipt_schema) is not int
        or receipt.receipt_schema != 1
        or not _parser_identity_is_valid(receipt.parser_identity)
        or receipt.parser_identity.sha256 != receipt.parser_identity_sha256
    ):
        return False
    try:
        _validate_tool_world(receipt.tool_world)
    except (AssemblyAbiError, AttributeError, TypeError, ValueError):
        return False
    if receipt.tool_world.tool_world_sha256 != receipt.tool_world_sha256:
        return False
    clang_identity = next(
        (identity for identity in receipt.tool_world.identities if identity.role == "clang"),
        None,
    )
    if (
        clang_identity is None
        or receipt.parser_identity.executable_path != clang_identity.resolved_path
        or receipt.parser_identity.binary_sha256 != clang_identity.file_sha256
        or receipt.parser_identity.version_sha256 != clang_identity.version_sha256
    ):
        return False
    try:
        _validate_relpath(receipt.registry_relpath)
        _validate_relpath(receipt.index_relpath)
    except AssemblyAbiError:
        return False
    if not _stable_identity_is_valid(receipt.registry_identity) or not _stable_identity_is_valid(receipt.index_identity):
        return False
    collections: tuple[tuple[object, ...], ...] = (
        receipt.owner_bindings,
        receipt.owner_files,
        receipt.compatibility_checks,
        receipt.discarded_variants,
        receipt.bundle_files,
    )
    if not all(isinstance(collection, tuple) for collection in collections):
        return False
    if not all(
        isinstance(item, OwnerBinding)
        and isinstance(item.symbol, str)
        and _IDENTIFIER_RE.fullmatch(item.symbol) is not None
        and _nonempty_string(item.unit)
        and isinstance(item.chunk_file, str)
        and isinstance(item.line_range, tuple)
        and len(item.line_range) == 2
        and all(_positive_int(value) for value in item.line_range)
        and _nonempty_string(item.normalized_prototype)
        and _valid_sha(item.owner_binding_sha256)
        for item in receipt.owner_bindings
    ):
        return False
    if not all(
        isinstance(item, OwnerFileEvidence)
        and isinstance(item.chunk_file, str)
        and _stable_identity_is_valid(item.identity)
        and _valid_sha(item.file_sha256)
        and _valid_sha(item.range_sha256)
        and isinstance(item.line_range, tuple)
        and len(item.line_range) == 2
        and all(_positive_int(value) for value in item.line_range)
        for item in receipt.owner_files
    ):
        return False
    try:
        for item in (*receipt.owner_bindings, *receipt.owner_files):
            _validate_relpath(item.chunk_file)
    except AssemblyAbiError:
        return False
    owner_binding_map = {item.symbol: item for item in receipt.owner_bindings}
    if len(owner_binding_map) != len(receipt.owner_bindings) or not all(
        _compatibility_evidence_is_valid(item, receipt.parser_identity_sha256, owner_binding_map)
        for item in receipt.compatibility_checks
    ):
        return False
    if not all(
        isinstance(item, DiscardedVariant)
        and isinstance(item.symbol, str)
        and _IDENTIFIER_RE.fullmatch(item.symbol) is not None
        and isinstance(item.source_relpath, str)
        and _valid_sha(item.prototype_sha256)
        for item in receipt.discarded_variants
    ):
        return False
    try:
        for item in (*receipt.compatibility_checks, *receipt.discarded_variants):
            _validate_relpath(item.source_relpath)
    except AssemblyAbiError:
        return False
    return all(_binding_is_valid(item) for item in receipt.bundle_files)


def _composition_receipt_is_valid(receipt: object) -> bool:
    return (
        isinstance(receipt, CompositionReceipt)
        and _canonical_receipt_is_valid(receipt.canonicalization)
        and isinstance(receipt.object_bindings, tuple)
        and all(_binding_is_valid(item) for item in receipt.object_bindings)
        and _valid_sha(receipt.tool_world_sha256)
        and receipt.composition_receipt_schema == 1
    )


def _receipt_observation_is_valid(observed: object) -> bool:
    if not isinstance(observed, ReceiptObservation):
        return False
    if (
        not isinstance(observed.stage, str)
        or observed.stage not in {"pre-compile", "pre-publication"}
        or not _valid_sha(observed.bundle_sha256)
        or not _valid_sha(observed.tool_world_sha256)
        or not isinstance(observed.bundle_files, tuple)
        or not isinstance(observed.object_bindings, tuple)
    ):
        return False
    return all(_binding_is_valid(item) for item in (*observed.bundle_files, *observed.object_bindings))


def _receipt_refusal(
    code: str,
    detail: str,
    stage: Literal["pre-compile", "pre-publication"],
    receipt_sha256: str,
    observation_sha256: str,
) -> AssemblyAbiRefusal:
    check = RevalidationCheck.create(stage, receipt_sha256, observation_sha256, False, code)
    return AssemblyAbiRefusal(code, "revalidate", detail, _hash_bytes(detail.encode("utf-8")), check)


def revalidate_receipt(
    receipt: CanonicalizationReceipt | CompositionReceipt,
    product_root: Path,
    observed: ReceiptObservation,
) -> RevalidatedReceipt | AssemblyAbiRefusal:
    """Freshly validate the closed receipt/stage matrix and all bound bytes."""

    if not isinstance(observed, ReceiptObservation):
        return AssemblyAbiRefusal("receipt_observation_invalid", "revalidate", "receipt observation record invalid")
    if not isinstance(observed.stage, str) or observed.stage not in {"pre-compile", "pre-publication"}:
        return AssemblyAbiRefusal("revalidation_stage_invalid", "revalidate", "unknown receipt stage")
    if not _receipt_observation_is_valid(observed):
        return AssemblyAbiRefusal("receipt_observation_invalid", "revalidate", "receipt observation shape invalid")
    if isinstance(receipt, CompositionReceipt):
        if not _composition_receipt_is_valid(receipt):
            return AssemblyAbiRefusal("composition_receipt_invalid", "revalidate", "composition receipt shape invalid")
    elif isinstance(receipt, CanonicalizationReceipt):
        if not _canonical_receipt_is_valid(receipt):
            return AssemblyAbiRefusal(
                "canonicalization_receipt_invalid", "revalidate", "canonicalization receipt shape invalid"
            )
    else:
        return AssemblyAbiRefusal("revalidation_receipt_invalid", "revalidate", "unknown receipt record")
    receipt_sha = receipt.sha256
    observation_sha = _hash_bytes(_canonical_bytes(observed.to_dict()))
    if observed.stage == "pre-compile":
        if not isinstance(receipt, CanonicalizationReceipt) or observed.object_bindings:
            return _receipt_refusal("canonicalization_receipt_required", "pre-compile requires canonical receipt and no objects", observed.stage, receipt_sha, observation_sha)
        canonical = receipt
    else:
        if not isinstance(receipt, CompositionReceipt) or not observed.object_bindings:
            return _receipt_refusal("composition_receipt_required", "pre-publication requires composition receipt and objects", observed.stage, receipt_sha, observation_sha)
        canonical = receipt.canonicalization
        if observed.object_bindings != receipt.object_bindings:
            return _receipt_refusal("object_observation_drift", "object bindings disagree", observed.stage, receipt_sha, observation_sha)
    try:
        root = _validate_product_root(product_root)
        registry = _stable_read(_join_exact(root, canonical.registry_relpath))
        index = _stable_read(_join_exact(root, canonical.index_relpath))
    except AssemblyAbiError as exc:
        return _receipt_refusal(exc.refusal.code, exc.refusal.detail, observed.stage, receipt_sha, observation_sha)
    if registry.sha256 != canonical.registry_sha256 or registry.identity != canonical.registry_identity:
        return _receipt_refusal("owner_registry_drift", "registry bytes or identity changed", observed.stage, receipt_sha, observation_sha)
    if index.sha256 != canonical.index_sha256 or index.identity != canonical.index_identity:
        return _receipt_refusal("owner_index_drift", "index bytes or identity changed", observed.stage, receipt_sha, observation_sha)
    for expected in canonical.owner_files:
        try:
            source = _stable_read(_join_exact(root, expected.chunk_file))
            retained = _slice_lines(source.data, expected.line_range, expected.chunk_file)
        except AssemblyAbiError as exc:
            return _receipt_refusal(exc.refusal.code, exc.refusal.detail, observed.stage, receipt_sha, observation_sha)
        if source.sha256 != expected.file_sha256 or source.identity != expected.identity or _hash_bytes(retained) != expected.range_sha256:
            return _receipt_refusal("owner_source_drift", f"owner source changed: {expected.chunk_file}", observed.stage, receipt_sha, observation_sha)
    if observed.bundle_sha256 != canonical.bundle_sha256 or observed.bundle_files != canonical.bundle_files:
        return _receipt_refusal("bundle_observation_drift", "bundle observation disagrees", observed.stage, receipt_sha, observation_sha)
    if observed.tool_world_sha256 != canonical.tool_world_sha256:
        return _receipt_refusal("tool_world_drift", "tool world observation disagrees", observed.stage, receipt_sha, observation_sha)
    check = RevalidationCheck.create(observed.stage, receipt_sha, observation_sha, True, None)
    return RevalidatedReceipt(check)


@dataclass(frozen=True)
class FailureEvidence:
    stage: Literal["owner", "canonicalize", "materialize"]
    classification: Literal["deterministic_blocker", "transient_fault"]
    code: str
    diagnostic_sha256: str
    fault_class: Literal["spawn", "timeout", "crash", "io", "lock", "stable_read"] | None

    def validate(self) -> None:
        if (
            not isinstance(self.stage, str)
            or self.stage not in {"owner", "canonicalize", "materialize"}
            or not isinstance(self.classification, str)
            or self.classification not in {"deterministic_blocker", "transient_fault"}
            or not _nonempty_string(self.code)
            or not _valid_sha(self.diagnostic_sha256)
            or (self.classification == "deterministic_blocker" and self.fault_class is not None)
            or (
                self.classification == "transient_fault"
                and (not isinstance(self.fault_class, str) or self.fault_class not in _FAULT_CLASSES)
            )
        ):
            _shape_error("failure_evidence_invalid", "early failure evidence invalid")


@dataclass(frozen=True)
class RevalidationFailure:
    classification: Literal["deterministic_blocker", "transient_fault"]
    code: str
    diagnostic_sha256: str
    check_sha256: str
    fault_class: Literal["io", "lock", "stable_read"] | None
    stage: Literal["revalidate"] = field(default="revalidate", init=False)

    def validate(self, check: RevalidationCheck) -> None:
        if (
            not isinstance(check, RevalidationCheck)
            or not isinstance(self.classification, str)
            or self.classification not in {"deterministic_blocker", "transient_fault"}
            or not _nonempty_string(self.code)
            or not _valid_sha(self.diagnostic_sha256)
            or self.check_sha256 != check.check_sha256
            or self.code != check.refusal_code
            or check.passed
            or (self.classification == "deterministic_blocker" and self.fault_class is not None)
            or (
                self.classification == "transient_fault"
                and (not isinstance(self.fault_class, str) or self.fault_class not in {"io", "lock", "stable_read"})
            )
        ):
            _shape_error("revalidation_failure_invalid", "revalidation failure/check mismatch")


@dataclass(frozen=True)
class PrePublicationDecision:
    status: Literal["not_reached", "passed", "refused"]
    check: RevalidationCheck | None
    failure: RevalidationFailure | None

    @classmethod
    def not_reached(cls) -> "PrePublicationDecision":
        return cls("not_reached", None, None)

    @classmethod
    def passed(cls, check: RevalidationCheck) -> "PrePublicationDecision":
        return cls("passed", check, None)

    @classmethod
    def refused(cls, check: RevalidationCheck, failure: RevalidationFailure) -> "PrePublicationDecision":
        return cls("refused", check, failure)

    def validate(self) -> None:
        if not isinstance(self.status, str):
            _shape_error("prepublication_decision_invalid", "pre-publication status invalid")
        if self.status == "not_reached":
            valid = self.check is None and self.failure is None
        elif self.status == "passed":
            valid = isinstance(self.check, RevalidationCheck) and self.failure is None
            if isinstance(self.check, RevalidationCheck):
                self.check.validate()
                valid = valid and self.check.passed and self.check.stage == "pre-publication"
        elif self.status == "refused":
            valid = isinstance(self.check, RevalidationCheck) and isinstance(self.failure, RevalidationFailure)
            if isinstance(self.check, RevalidationCheck) and isinstance(self.failure, RevalidationFailure):
                self.check.validate()
                self.failure.validate(self.check)
                valid = valid and not self.check.passed and self.check.stage == "pre-publication"
        else:
            valid = False
        if not valid:
            _shape_error("prepublication_decision_invalid", "crossed pre-publication decision")

    def to_dict(self) -> dict[str, object]:
        return {
            "check": None if self.check is None else self.check.to_dict(),
            "failure": None if self.failure is None else {
                "check_sha256": self.failure.check_sha256,
                "classification": self.failure.classification,
                "code": self.failure.code,
                "diagnostic_sha256": self.failure.diagnostic_sha256,
                "fault_class": self.failure.fault_class,
                "stage": "revalidate",
            },
            "status": self.status,
        }


@dataclass(frozen=True)
class PreDraftFailureInput:
    scaffold: ResultScaffold
    failure: FailureEvidence
    retry_history: RetryHistory
    pre_compile: None = None
    pre_publication: None = None
    kind: Literal["pre_draft_failure"] = field(default="pre_draft_failure", init=False)
    finalization_input_schema: int = field(default=1, init=False)


@dataclass(frozen=True)
class PrecompileFailureInput:
    scaffold: ResultScaffold
    failure: RevalidationFailure
    retry_history: RetryHistory
    pre_compile: RevalidationCheck
    pre_publication: None = None
    kind: Literal["precompile_refusal"] = field(default="precompile_refusal", init=False)
    finalization_input_schema: int = field(default=1, init=False)


@dataclass(frozen=True)
class PostAnalysisInput:
    draft: CompositionDraft
    pre_compile: RevalidationCheck
    pre_publication: PrePublicationDecision
    retry_history: RetryHistory
    kind: Literal["post_analysis"] = field(default="post_analysis", init=False)
    finalization_input_schema: int = field(default=1, init=False)


FinalizationInput = PreDraftFailureInput | PrecompileFailureInput | PostAnalysisInput


@dataclass(frozen=True)
class CompositionResult:
    document: Mapping[str, object]
    composition_receipt: CompositionReceipt | None = field(default=None, repr=False)

    @property
    def result_id(self) -> str:
        return self.document["result_id"]  # type: ignore[return-value]

    @property
    def outcome(self) -> Mapping[str, object]:
        return self.document["outcome"]  # type: ignore[return-value]

    @property
    def receipt(self) -> CompositionReceipt:
        if self.composition_receipt is None:
            raise AttributeError("pre-analysis result has no composition receipt")
        return self.composition_receipt

    def canonical_bytes(self) -> bytes:
        payload = _canonical_bytes(self.document)
        without_id = dict(_json_ready(self.document))
        result_id = without_id.pop("result_id", None)
        if result_id != _hash_bytes(_canonical_bytes(without_id)):
            _shape_error("composition_result_id_invalid", "result ID no longer matches immutable document")
        return payload


def _validate_tool_world(world: ToolWorld) -> None:
    if not isinstance(world, ToolWorld) or not isinstance(world.identities, tuple) or not all(
        isinstance(item, ToolIdentity) for item in world.identities
    ):
        _shape_error("tool_world_invalid", "tool identity collection invalid")
    roles = tuple(item.role for item in world.identities)
    if roles != tuple(sorted(("clang", "emcc", "node", "object-inspector", "smoke-script", "wasm-ld"))):
        _shape_error("tool_world_invalid", "identity roles must be exact/sorted")
    for item in world.identities:
        if not _nonempty_string(item.resolved_path) or not Path(item.resolved_path).is_absolute() or not _valid_sha(item.file_sha256) or not _valid_sha(item.version_sha256):
            _shape_error("tool_world_invalid", "tool identity invalid")
    if not isinstance(world.environment, tuple) or not all(
        isinstance(item, tuple) and len(item) == 2 and _nonempty_string(item[0]) and _valid_sha(item[1])
        for item in world.environment
    ):
        _shape_error("tool_world_invalid", "environment binding invalid")
    if tuple(name for name, _digest in world.environment) != tuple(sorted(name for name, _digest in world.environment)):
        _shape_error("tool_world_invalid", "environment is unsorted")
    if len({name for name, _digest in world.environment}) != len(world.environment):
        _shape_error("tool_world_invalid", "duplicate environment binding")
    if any(not _nonempty_string(name) or not _valid_sha(digest) for name, digest in world.environment):
        _shape_error("tool_world_invalid", "environment binding invalid")
    if not isinstance(world.compile_argv, tuple) or not isinstance(world.inspect_argv, tuple):
        _shape_error("tool_world_invalid", "nested argv invalid")
    if not all(isinstance(row, tuple) for row in (*world.compile_argv, *world.inspect_argv)):
        _shape_error("tool_world_invalid", "nested argv invalid")
    argv_groups: tuple[Sequence[Sequence[str]] | Sequence[str], ...] = (
        world.compile_argv, world.inspect_argv, world.link_argv, world.instantiate_argv, world.smoke_argv
    )
    if not all(isinstance(row, tuple) for row in (world.link_argv, world.instantiate_argv, world.smoke_argv)):
        _shape_error("tool_world_invalid", "argv invalid")
    if not world.link_argv or not world.instantiate_argv or not world.smoke_argv:
        _shape_error("tool_world_invalid", "explicit argv missing")
    if any(not _nonempty_string(arg) for rows in (world.compile_argv, world.inspect_argv) for row in rows for arg in row):
        _shape_error("tool_world_invalid", "nested argv invalid")
    if any(not _nonempty_string(arg) for row in (world.link_argv, world.instantiate_argv, world.smoke_argv) for arg in row):
        _shape_error("tool_world_invalid", "argv invalid")
    del argv_groups
    if world.tool_world_sha256 != _hash_bytes(_canonical_bytes(world._preimage())):
        _shape_error("tool_world_invalid", "tool world digest mismatch")


def _validate_scaffold(scaffold: ResultScaffold) -> None:
    if not isinstance(scaffold, ResultScaffold):
        _shape_error("result_scaffold_invalid", "scaffold record invalid")
    if not isinstance(scaffold.window, tuple) or not all(isinstance(item, WindowItem) for item in scaffold.window):
        _shape_error("result_scaffold_invalid", "window collection invalid")
    if not isinstance(scaffold.objects, tuple) or not all(isinstance(item, Mapping) for item in scaffold.objects):
        _shape_error("result_scaffold_invalid", "object manifest collection invalid")
    _validate_tool_world(scaffold.tool_world)
    if (
        not _nonempty_string(scaffold.unit)
        or not _positive_int(scaffold.attempt)
        or not isinstance(scaffold.behavior_tier, str)
        or scaffold.behavior_tier not in {"compile_only", "oracle_green"}
        or not _validate_candidate(scaffold.candidate)
        or not _valid_sha(scaffold.assembly_world_sha256)
    ):
        _shape_error("result_scaffold_invalid", "scaffold scalar binding invalid")
    if [item.ordinal for item in scaffold.window] != list(range(len(scaffold.window))):
        _shape_error("result_scaffold_invalid", "window ordinal order invalid")
    for item in scaffold.window:
        try:
            _validate_relpath(item.artifact_relpath)
        except AssemblyAbiError:
            _shape_error("result_scaffold_invalid", "window artifact path invalid")
        if (
            not _nonempty_string(item.unit)
            or not _valid_sha(item.artifact_sha256)
            or not _nonnegative_int(item.artifact_size)
        ):
            _shape_error("result_scaffold_invalid", "window item invalid")
    canonical = scaffold.canonicalization
    status = canonical.get("status") if isinstance(canonical, Mapping) else None
    if status not in {"not_started", "failed", "planned"}:
        _shape_error("result_scaffold_invalid", "canonicalization status invalid")
    for item in scaffold.objects:
        if not isinstance(item, Mapping):
            _shape_error("result_scaffold_invalid", "object manifest invalid")
    try:
        _canonical_bytes(scaffold.to_dict())
    except (AttributeError, TypeError, ValueError):
        _shape_error("result_scaffold_invalid", "scaffold is not canonical JSON data")


def _validate_outcome_projection(outcome: OutcomeProjection) -> None:
    if not isinstance(outcome, OutcomeProjection):
        _shape_error("outcome_projection_invalid", "outcome projection record invalid")
    if not isinstance(outcome.stage_receipts, tuple) or not all(
        isinstance(receipt, StageReceipt) for receipt in outcome.stage_receipts
    ):
        _shape_error("outcome_projection_invalid", "stage receipt projection invalid")
    if not isinstance(outcome.contributors, tuple) or not all(
        isinstance(contributor, Contributor) for contributor in outcome.contributors
    ):
        _shape_error("outcome_projection_invalid", "contributor projection invalid")
    if all(receipt.state == "not_run" for receipt in outcome.stage_receipts):
        if not isinstance(outcome.stage, str) or outcome.stage not in {"owner", "canonicalize", "materialize", "revalidate", "internal"}:
            _shape_error("outcome_projection_invalid", "tool-stage outcome cannot carry an all-not-run tuple")
        if tuple(receipt.stage for receipt in outcome.stage_receipts) != _STAGES:
            _shape_error("outcome_projection_invalid", "all-not-run receipt order invalid")
        for receipt in outcome.stage_receipts:
            _validate_stage_receipt(receipt)
    else:
        _validate_tool_outcome(ToolOutcome(outcome.stage_receipts))
    if (
        not isinstance(outcome.classification, str)
        or outcome.classification not in {"pass", "deterministic_blocker", "transient_fault"}
        or not isinstance(outcome.stage, str)
        or outcome.stage not in {"owner", "canonicalize", "materialize", "compile", "inspect", "link", "instantiate", "smoke", "revalidate", "internal"}
        or not _nonempty_string(outcome.code)
        or type(outcome.unattributed) is not bool
        or (outcome.classification == "pass" and (outcome.diagnostic_sha256 is not None or outcome.code != "pass" or outcome.unattributed))
        or (outcome.classification != "pass" and not _valid_sha(outcome.diagnostic_sha256))
    ):
        _shape_error("outcome_projection_invalid", "outcome projection invalid")
    for item in outcome.contributors:
        if (
            not isinstance(item.symbol, str)
            or _IDENTIFIER_RE.fullmatch(item.symbol) is None
            or not _nonempty_string(item.unit)
            or not isinstance(item.object_relpath, str)
            or item.role not in {"definition", "import"}
        ):
            _shape_error("outcome_projection_invalid", "contributor scalar invalid")
        try:
            _validate_relpath(item.object_relpath)
        except AssemblyAbiError:
            _shape_error("outcome_projection_invalid", "contributor path invalid")
    keys = [(item.symbol, item.unit, item.object_relpath, item.role) for item in outcome.contributors]
    if keys != sorted(set(keys)):
        _shape_error("outcome_projection_invalid", "contributors unsorted/duplicate")
    for item in outcome.contributors:
        if not _valid_sha(item.object_sha256) or not _valid_sha(item.abi_sha256):
            _shape_error("outcome_projection_invalid", "contributor digest invalid")


def _all_not_run() -> tuple[StageReceipt, StageReceipt, StageReceipt, StageReceipt, StageReceipt]:
    return tuple(StageReceipt.not_run(stage) for stage in _STAGES)  # type: ignore[return-value]


def _retry_projection(
    scaffold: ResultScaffold,
    outcome: OutcomeProjection,
    history: RetryHistory,
    evidence_fault_class: str | None = None,
) -> dict[str, object]:
    if not isinstance(history, RetryHistory):
        _shape_error("retry_history_invalid", "retry history record invalid")
    history.validate()
    transcript_refs = [
        {"child_transcript_sha256": receipt.child_transcript_sha256, "stage": receipt.stage}
        for receipt in outcome.stage_receipts
        if receipt.child_transcript_sha256 is not None
    ]
    transient_sha: str | None = None
    if outcome.classification == "transient_fault":
        terminal = next((item for item in outcome.stage_receipts if item.state == "faulted"), None)
        if terminal is not None:
            if evidence_fault_class is not None and evidence_fault_class != terminal.fault_class:
                _shape_error("transient_fault_invalid", "fault evidence contradicts terminal tool receipt")
            fault_class = terminal.fault_class
        else:
            fault_class = evidence_fault_class
        if fault_class not in _FAULT_CLASSES:
            _shape_error("transient_fault_invalid", "transient fault class unavailable")
        role_by_stage = {
            "owner": None, "canonicalize": None, "materialize": None, "compile": "emcc",
            "inspect": "object-inspector", "link": "emcc", "instantiate": "node",
            "smoke": "node", "revalidate": None, "internal": None,
        }
        transient_preimage = {
            "assembly_world_sha256": scaffold.assembly_world_sha256,
            "candidate_sha256": scaffold.candidate.artifact_sha256,
            "code": outcome.code,
            "fault_class": fault_class,
            "stage": outcome.stage,
            "tool_role": role_by_stage[outcome.stage],
            "transient_fault_fingerprint_schema": 1,
        }
        transient_sha = _hash_bytes(_canonical_bytes(transient_preimage))
    evidence_sha = None if outcome.classification == "pass" else (
        transient_sha if outcome.classification == "transient_fault" else outcome.diagnostic_sha256
    )
    retry_preimage = {
        "assembly_retry_fingerprint_schema": 1,
        "assembly_world_sha256": scaffold.assembly_world_sha256,
        "classification": outcome.classification,
        "code": outcome.code,
        "contributors": [item.to_dict() for item in outcome.contributors],
        "evidence_sha256": evidence_sha,
        "stage": outcome.stage,
        "stage_transcripts": transcript_refs,
        "unattributed": outcome.unattributed,
    }
    assembly_sha = _hash_bytes(_canonical_bytes(retry_preimage))
    if outcome.classification == "pass":
        retry_class, status, count, backoff = "none", "pass", 0, None
    elif outcome.classification == "deterministic_blocker":
        retry_class, status, count, backoff = "deterministic_blocker", "waiting_assembly_world_change", 0, None
        transient_sha = None
    else:
        prior = history.completed_transient_attempts if history.prior_transient_fingerprint == transient_sha else 0
        if prior == 0:
            count, backoff, status = 1, 30, "transient_retry"
        elif prior == 1:
            count, backoff, status = 2, 120, "transient_retry"
        elif prior == 2:
            count, backoff, status = 3, 600, "transient_retry"
        else:
            count, backoff, status = 3, None, "assembly_transient_exhausted"
        retry_class = "transient_fault"
    return {
        "assembly_retry_fingerprint": assembly_sha,
        "assembly_world_sha256": scaffold.assembly_world_sha256,
        "backoff_seconds": backoff,
        "class": retry_class,
        "status": status,
        "transient_fault_fingerprint": transient_sha,
        "transient_retry_count": count,
    }


def finalize_composition(finalization: FinalizationInput) -> CompositionResult:
    """Validate one closed finalization member and construct the sole final result."""

    composition_receipt: CompositionReceipt | None = None
    pre_compile_sha: str | None = None
    pre_publication_sha: str | None = None
    evidence_fault_class: str | None = None
    if isinstance(finalization, PreDraftFailureInput):
        if not isinstance(finalization.scaffold, ResultScaffold) or not isinstance(finalization.failure, FailureEvidence) or not isinstance(finalization.retry_history, RetryHistory):
            _shape_error("finalization_input_invalid", "pre-draft nested member invalid")
        scaffold = finalization.scaffold
        _validate_scaffold(scaffold)
        finalization.retry_history.validate()
        finalization.failure.validate()
        status = scaffold.canonicalization.get("status")
        expected = {"owner": "not_started", "canonicalize": "failed", "materialize": "planned"}
        if status != expected[finalization.failure.stage] or scaffold.objects:
            _shape_error("finalization_input_invalid", "pre-draft stage/canonicalization mismatch")
        outcome = OutcomeProjection(
            finalization.failure.classification,
            finalization.failure.stage,
            finalization.failure.code,
            _all_not_run(),
            finalization.failure.diagnostic_sha256,
            (),
            True,
        )
        evidence_fault_class = finalization.failure.fault_class
        history = finalization.retry_history
    elif isinstance(finalization, PrecompileFailureInput):
        if (
            not isinstance(finalization.scaffold, ResultScaffold)
            or not isinstance(finalization.failure, RevalidationFailure)
            or not isinstance(finalization.retry_history, RetryHistory)
            or not isinstance(finalization.pre_compile, RevalidationCheck)
        ):
            _shape_error("finalization_input_invalid", "precompile nested member invalid")
        scaffold = finalization.scaffold
        _validate_scaffold(scaffold)
        finalization.retry_history.validate()
        finalization.pre_compile.validate()
        finalization.failure.validate(finalization.pre_compile)
        if (
            finalization.pre_compile.stage != "pre-compile"
            or finalization.pre_compile.passed
            or scaffold.canonicalization.get("status") != "planned"
            or scaffold.objects
            or scaffold.canonicalization_receipt_sha256 != finalization.pre_compile.receipt_sha256
        ):
            _shape_error("finalization_input_invalid", "precompile refusal matrix mismatch")
        outcome = OutcomeProjection(
            finalization.failure.classification,
            "revalidate",
            finalization.failure.code,
            _all_not_run(),
            finalization.failure.diagnostic_sha256,
            (),
            True,
        )
        pre_compile_sha = finalization.pre_compile.check_sha256
        evidence_fault_class = finalization.failure.fault_class
        history = finalization.retry_history
    elif isinstance(finalization, PostAnalysisInput):
        if (
            not isinstance(finalization.draft, CompositionDraft)
            or not isinstance(finalization.pre_compile, RevalidationCheck)
            or not isinstance(finalization.pre_publication, PrePublicationDecision)
            or not isinstance(finalization.retry_history, RetryHistory)
        ):
            _shape_error("finalization_input_invalid", "post-analysis nested member invalid")
        draft = finalization.draft
        if (
            not isinstance(draft.scaffold, ResultScaffold)
            or not isinstance(draft.analyzed_outcome, OutcomeProjection)
            or not _composition_receipt_is_valid(draft.composition_receipt)
            or not _valid_sha(draft.retry_history_sha256)
            or draft.composition_draft_schema != 1
        ):
            _shape_error("finalization_input_invalid", "composition draft shape invalid")
        scaffold = draft.scaffold
        composition_receipt = draft.composition_receipt
        _validate_scaffold(scaffold)
        finalization.retry_history.validate()
        finalization.pre_compile.validate()
        finalization.pre_publication.validate()
        _validate_outcome_projection(draft.analyzed_outcome)
        if (
            finalization.retry_history.sha256 != draft.retry_history_sha256
            or finalization.pre_compile.stage != "pre-compile"
            or not finalization.pre_compile.passed
            or finalization.pre_compile.receipt_sha256 != composition_receipt.canonicalization.sha256
            or scaffold.canonicalization_receipt_sha256 != composition_receipt.canonicalization.sha256
            or composition_receipt.tool_world_sha256 != scaffold.tool_world.tool_world_sha256
        ):
            _shape_error("finalization_input_invalid", "post-analysis precompile/history binding mismatch")
        pre_compile_sha = finalization.pre_compile.check_sha256
        decision = finalization.pre_publication
        if draft.analyzed_outcome.classification == "pass":
            if decision.status not in {"passed", "refused"} or decision.check is None:
                _shape_error("finalization_input_invalid", "tool pass requires reached publication check")
            if decision.check.receipt_sha256 != composition_receipt.sha256:
                _shape_error("finalization_input_invalid", "publication check binds wrong receipt")
            pre_publication_sha = decision.check.check_sha256
            if decision.status == "refused":
                assert decision.failure is not None
                outcome = OutcomeProjection(
                    decision.failure.classification,
                    "revalidate",
                    decision.failure.code,
                    draft.analyzed_outcome.stage_receipts,
                    decision.failure.diagnostic_sha256,
                    (),
                    True,
                )
                evidence_fault_class = decision.failure.fault_class
            else:
                outcome = draft.analyzed_outcome
        else:
            if decision.status != "not_reached":
                _shape_error("finalization_input_invalid", "tool non-pass cannot reach publication")
            outcome = draft.analyzed_outcome
        history = finalization.retry_history
    else:
        _shape_error("finalization_input_invalid", "unknown finalization union member")

    _validate_outcome_projection(outcome)
    scaffold_dict = scaffold.to_dict()
    without_id = {
        **scaffold_dict,
        "outcome": outcome.to_dict(),
        "retry": _retry_projection(scaffold, outcome, history, evidence_fault_class),
        "revalidation": {
            "pre_compile_sha256": pre_compile_sha,
            "pre_publication_sha256": pre_publication_sha,
        },
    }
    result_id = _hash_bytes(_canonical_bytes(without_id))
    document = _deep_freeze({**without_id, "result_id": result_id})
    result = CompositionResult(document, composition_receipt)  # type: ignore[arg-type]
    result.canonical_bytes()
    return result
