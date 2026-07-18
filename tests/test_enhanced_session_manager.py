import json
from pathlib import Path

from src.enhanced_session_manager import EnhancedSessionManager


def function(address="80100000"):
    return {
        "address": address,
        "old_name": f"FUN_{address}",
        "new_name": "testActionPhase",
        "behavior_summary": "Literal test summary",
        "timestamp": 1.0,
    }


def test_session_ids_do_not_collide_for_same_name_and_second(tmp_path, monkeypatch):
    monkeypatch.setattr("src.enhanced_session_manager.time.time", lambda: 1234)
    manager = EnhancedSessionManager(str(tmp_path))
    first = manager.create_session("same")
    second = manager.create_session("same")
    assert first != second
    assert (tmp_path / first / "session.json").exists()
    assert (tmp_path / second / "session.json").exists()


def test_save_updates_truthful_counts_and_evidence_fields_atomically(tmp_path):
    manager = EnhancedSessionManager(str(tmp_path))
    session_id = manager.create_session("port")
    assert manager.save_current_session(
        {"80100000": function()},
        rag_vectors=[{"text": "document"}],
        evidence_artifacts=[{"tier": "authoritative", "source": "boot.dol@80100000"}],
        port_dossier={"version": 1},
        embedding_reference={"store": "data/vector_db", "documentCount": 1},
    )
    payload = json.loads((tmp_path / session_id / "session.json").read_text(encoding="utf-8"))
    assert payload["schema_version"] == 2
    assert payload["metadata"]["total_functions"] == 1
    assert payload["metadata"]["analyzed_functions_count"] == 1
    assert payload["performance_stats"]["rag_vector_count"] == 1
    assert payload["rag_payload_kind"] == "retrieval_documents"
    assert payload["port_dossier"] == {"version": 1}
    assert not list((tmp_path / session_id).glob("*.tmp"))


def test_export_without_documents_does_not_mutate_active_session(tmp_path):
    manager = EnhancedSessionManager(str(tmp_path / "sessions"))
    session_id = manager.create_session("port")
    manager.save_current_session({}, rag_vectors=[{"text": "keep"}])
    export = tmp_path / "export.json"
    assert manager.export_session(session_id, str(export), include_vectors=False)
    assert manager.current_session_data["rag_vectors"] == [{"text": "keep"}]
    assert json.loads(export.read_text(encoding="utf-8"))["session_data"]["rag_vectors"] == []


def test_legacy_session_still_loads(tmp_path):
    session_id = "session_1_legacy00"
    folder = tmp_path / session_id
    folder.mkdir()
    legacy = {
        "metadata": {"session_id": session_id, "session_name": "legacy"},
        "analyzed_functions": {"80100000": function()},
        "rag_vectors": [],
        "ui_state": {},
        "analysis_log": [],
        "performance_stats": {},
    }
    (folder / "session.json").write_text(json.dumps(legacy), encoding="utf-8")
    manager = EnhancedSessionManager(str(tmp_path))
    assert manager.load_session(session_id)["metadata"]["session_name"] == "legacy"
