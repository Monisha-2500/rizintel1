import json
import pytest


@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "test.db")
    monkeypatch.setenv("RIZINTEL_DB_PATH", db_path)
    import database as db_module
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    import importlib
    importlib.reload(db_module)
    db_module.init_db()
    yield db_module


def _make_agent(db, org="ORG-T", status="ACTIVE", caps=None):
    import secrets, hashlib
    aid = "AGENT-" + secrets.token_hex(3).upper()
    thash = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
    db.create_scanner_agent(aid, org, "T", thash, "u", json.dumps(caps or {}))
    if status == "REVOKED":
        db.revoke_scanner_agent(org, aid)
    return aid


def test_nuclei_aliases(fresh_db):
    n = fresh_db.normalize_scanner_id
    assert n("NUCLEI") == "NUCLEI"
    assert n("nuclei") == "NUCLEI"
    assert n("Nuclei") == "NUCLEI"


def test_zap_aliases(fresh_db):
    n = fresh_db.normalize_scanner_id
    assert n("ZAP") == "ZAP"
    assert n("zap") == "ZAP"
    assert n("OWASP ZAP") == "ZAP"
    assert n("OWASP_ZAP") == "ZAP"
    assert n("owasp_zap") == "ZAP"


def test_wapiti_aliases(fresh_db):
    n = fresh_db.normalize_scanner_id
    assert n("WAPITI") == "WAPITI"
    assert n("wapiti") == "WAPITI"
    assert n("Wapiti") == "WAPITI"


def test_unknown_returns_none(fresh_db):
    assert fresh_db.normalize_scanner_id("OpenVAS") is None
    assert fresh_db.normalize_scanner_id("") is None
    assert fresh_db.normalize_scanner_id(None) is None


def test_no_agents_all_unavailable(fresh_db):
    caps = fresh_db.get_active_scanner_capabilities("ORG-EMPTY")
    assert set(caps.keys()) == {"NUCLEI", "ZAP", "WAPITI"}
    assert not any(v["available"] for v in caps.values())


def test_dict_of_objects_schema(fresh_db):
    c = {"NUCLEI": {"available": True, "version": "3.3.8"}, "ZAP": {"available": True, "version": "2.16.0"}, "WAPITI": {"available": True, "version": "3.2.3"}}
    _make_agent(fresh_db, caps=c)
    r = fresh_db.get_active_scanner_capabilities("ORG-T")
    assert r["NUCLEI"]["available"] and r["NUCLEI"]["version"] == "3.3.8"
    assert r["ZAP"]["available"] and r["ZAP"]["version"] == "2.16.0"
    assert r["WAPITI"]["available"] and r["WAPITI"]["version"] == "3.2.3"


def test_legacy_list_schema(fresh_db):
    _make_agent(fresh_db, caps=["NUCLEI", "ZAP"])
    r = fresh_db.get_active_scanner_capabilities("ORG-T")
    assert r["NUCLEI"]["available"] and r["ZAP"]["available"] and not r["WAPITI"]["available"]


def test_legacy_list_aliases(fresh_db):
    _make_agent(fresh_db, caps=["OWASP ZAP", "nuclei", "Wapiti"])
    r = fresh_db.get_active_scanner_capabilities("ORG-T")
    assert r["ZAP"]["available"] and r["NUCLEI"]["available"] and r["WAPITI"]["available"]


def test_missing_available_not_true(fresh_db):
    _make_agent(fresh_db, caps={"NUCLEI": {"version": "3.3.8"}})
    assert not fresh_db.get_active_scanner_capabilities("ORG-T")["NUCLEI"]["available"]


def test_explicit_false_excluded(fresh_db):
    _make_agent(fresh_db, caps={"NUCLEI": {"available": False}, "ZAP": {"available": True}})
    r = fresh_db.get_active_scanner_capabilities("ORG-T")
    assert not r["NUCLEI"]["available"] and r["ZAP"]["available"]


def test_alias_keys_in_dict_normalized(fresh_db):
    _make_agent(fresh_db, caps={"OWASP ZAP": {"available": True}, "Nuclei": {"available": True}, "Wapiti": {"available": True}})
    r = fresh_db.get_active_scanner_capabilities("ORG-T")
    assert r["ZAP"]["available"] and r["NUCLEI"]["available"] and r["WAPITI"]["available"]


def test_revoked_agent_excluded(fresh_db):
    _make_agent(fresh_db, status="REVOKED", caps={"NUCLEI": {"available": True}, "ZAP": {"available": True}, "WAPITI": {"available": True}})
    assert not any(v["available"] for v in fresh_db.get_active_scanner_capabilities("ORG-T").values())


def test_cross_tenant_exclusion(fresh_db):
    _make_agent(fresh_db, org="ORG-EVIL", caps={"NUCLEI": {"available": True}})
    assert not fresh_db.get_active_scanner_capabilities("ORG-VICTIM")["NUCLEI"]["available"]


def test_mixed_active_revoked(fresh_db):
    _make_agent(fresh_db, status="ACTIVE", caps={"ZAP": {"available": True}})
    _make_agent(fresh_db, status="REVOKED", caps={"WAPITI": {"available": True}})
    r = fresh_db.get_active_scanner_capabilities("ORG-T")
    assert r["ZAP"]["available"] and not r["WAPITI"]["available"]


def test_heartbeat_persists_all_three(fresh_db):
    aid = _make_agent(fresh_db)
    fresh_db.update_agent_heartbeat(aid, json.dumps({"NUCLEI": {"available": True, "version": "v3.3.8"}, "ZAP": {"available": True, "version": "2.16.0"}, "WAPITI": {"available": True, "version": "3.2.3"}}))
    r = fresh_db.get_active_scanner_capabilities("ORG-T")
    assert all(v["available"] for v in r.values())


def test_heartbeat_timestamp_only_preserves_caps(fresh_db):
    aid = _make_agent(fresh_db, caps={"NUCLEI": {"available": True}})
    fresh_db.update_agent_heartbeat(aid, None)
    assert fresh_db.get_active_scanner_capabilities("ORG-T")["NUCLEI"]["available"]


def test_heartbeat_where_clause_only_updates_target(fresh_db):
    a = _make_agent(fresh_db, org="ORG-A")
    b = _make_agent(fresh_db, org="ORG-A", caps={"ZAP": {"available": True}})
    fresh_db.update_agent_heartbeat(a, None)
    assert fresh_db.get_active_scanner_capabilities("ORG-A")["ZAP"]["available"]


def test_all_three_canonical_keys_present(fresh_db):
    assert set(fresh_db.get_active_scanner_capabilities("ORG-X").keys()) == {"NUCLEI", "ZAP", "WAPITI"}


def test_full_register_heartbeat_revoke_flow(fresh_db):
    from services.agent_service import register_agent
    res = register_agent("ORG-T", "Agent", "u")
    aid = res["agent"]["agent_id"]
    fresh_db.update_agent_heartbeat(aid, json.dumps({"NUCLEI": {"available": True}, "ZAP": {"available": True}, "WAPITI": {"available": True}}))
    assert all(v["available"] for v in fresh_db.get_active_scanner_capabilities("ORG-T").values())
    fresh_db.revoke_scanner_agent("ORG-T", aid)
    assert not any(v["available"] for v in fresh_db.get_active_scanner_capabilities("ORG-T").values())
