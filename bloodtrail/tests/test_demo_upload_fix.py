"""One slow upload must not stall the single worker, and the site must offer only what the route accepts."""

import asyncio
import io
import json
import threading
import time
import zipfile

import pytest

pytest.importorskip("fastapi")
from bloodtrail.demo import app as demo


@pytest.fixture(autouse=True)
def fresh_limit():
    demo._upload_times.clear()


def _sharphound_zip(user_count: int, aces_each: int) -> bytes:
    """A SharpHound zip whose ACE principals never resolve — the worst case for a linear _resolve."""
    def sid(rid):
        return f"S-1-5-21-111-222-333-{rid}"
    users = [{"ObjectIdentifier": sid(1000 + i),
              "Properties": {"name": f"USER{i}@CORP.LOCAL", "domain": "CORP.LOCAL", "enabled": True},
              "Aces": [{"PrincipalSID": sid(900000 + j), "PrincipalType": "Group",
                        "RightName": "GenericAll", "IsInherited": False} for j in range(aces_each)]}
             for i in range(user_count)]
    groups = [{"ObjectIdentifier": sid(512), "Properties": {"name": "DOMAIN ADMINS@CORP.LOCAL", "domain": "CORP.LOCAL"},
               "Members": [{"ObjectIdentifier": sid(1000 + i), "ObjectType": "User"} for i in range(user_count)],
               "Aces": []}]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("20260101_users.json", json.dumps({"data": users, "meta": {"type": "users"}}))
        zf.writestr("20260101_groups.json", json.dumps({"data": groups, "meta": {"type": "groups"}}))
    return buf.getvalue()


def _request(client_ip):
    return demo.Request({"type": "http", "client": (client_ip, 50000), "headers": []})


def _upload(client_ip, filename, body):
    """Drive the real async route to completion, as the server would."""
    coro = demo.api_upload(_request(client_ip), demo.UploadFile(io.BytesIO(body), filename=filename))
    return asyncio.run(coro)


def test_resolve_uses_an_index_not_a_scan():
    from bloodtrail.demo import parser
    node = {"id": "user-a", "label": "User", "name": "A", "_oid": "OID-A"}
    oid_map = {"OID-A": node}
    assert parser._resolve("OID-A", oid_map) is node
    assert parser._resolve("missing", oid_map) is None


def test_large_graph_parses_without_quadratic_blowup(tmp_path):
    zip_path = tmp_path / "big.zip"
    zip_path.write_bytes(_sharphound_zip(1500, 25))
    from bloodtrail.demo.parser import parse_upload
    start = time.perf_counter()
    parsed = parse_upload(zip_path)
    elapsed = time.perf_counter() - start
    assert parsed["meta"]["node_count"] == 1501
    assert parsed["meta"]["edge_count"] == 1500  # MemberOf edges; unresolved ACE principals add none
    assert elapsed < 5.0, f"parse took {elapsed:.1f}s — _resolve is still scanning every node"


def test_upload_parsing_runs_off_the_event_loop(monkeypatch):
    seen = {}

    def fake_parse(path):
        try:
            asyncio.get_running_loop()
            seen["on_loop"] = True
        except RuntimeError:
            seen["on_loop"] = False
        seen["thread"] = threading.current_thread().name
        return {"nodes": [], "edges": [], "meta": {"chain_count": 0}, "chains": [], "quick_wins": []}

    monkeypatch.setattr(demo, "parse_upload", fake_parse)
    result = _upload("203.0.113.5", "x.zip", _sharphound_zip(1, 0))
    assert result["meta"]["chain_count"] == 0
    assert seen.get("on_loop") is False, "parse ran on the event loop, blocking every other visitor"


def test_json_is_not_accepted_and_site_wording_matches():
    assert ".json" not in demo.ALLOWED_EXTENSIONS
    with pytest.raises(demo.HTTPException) as refused:
        _upload("203.0.113.6", "data.json", b'{"data": []}')
    assert refused.value.status_code == 400

    html = (demo.DEMO_DIR / "static" / "index.html").read_text()
    assert 'accept=".zip"' in html
    assert 'accept=".zip,.json"' not in html
    assert "or JSON" not in html
    assert "['zip', 'json']" not in html
