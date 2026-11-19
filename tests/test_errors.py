"""Tests for errors.py — reuses the tracker's SQLite test DB and Spotify mock."""
from test_tracking import AUTH, spotify, client  # noqa: F401  (fixtures)

import errors


def test_requires_auth(spotify, client):
    assert client.post("/api/errors", json={"errors": []}).status_code == 401
    assert client.get("/api/errors", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_post_list_delete(spotify, client):
    r = client.post("/api/errors", headers=AUTH, json={"errors": [
        {"at": "2026-11-18T10:00:00Z", "message": "TypeError: x is undefined", "stack": "at foo", "fatal": True,
         "version": "2.0", "update": "abc", "platform": "android 15", "screen": "/wrapped"},
        {"at": "2026-11-18T11:00:00Z", "message": "Network request failed"},
        {"message": ""},           # dropped: empty
        "not a dict",              # dropped
    ]})
    assert r.status_code == 200 and r.json["saved"] == 2
    items = client.get("/api/errors", headers=AUTH).json["items"]
    assert [i["message"] for i in items] == ["Network request failed", "TypeError: x is undefined"]
    assert items[1]["fatal"] is True and items[1]["screen"] == "/wrapped"
    assert client.delete("/api/errors", headers=AUTH).json["deleted"] == 2
    assert client.get("/api/errors", headers=AUTH).json["items"] == []


def test_clips_and_caps(spotify, client, monkeypatch):
    monkeypatch.setattr(errors, "MAX_PER_USER", 3)
    big = "x" * 50_000
    batch = [{"at": f"2026-11-18T10:0{i}:00Z", "message": big} for i in range(5)]
    client.post("/api/errors", headers=AUTH, json={"errors": batch})
    items = client.get("/api/errors", headers=AUTH).json["items"]
    assert len(items) == 3                                   # oldest dropped
    assert items[0]["at"] == "2026-11-18T10:04:00Z"
    assert len(items[0]["message"]) == errors.LIMITS["message"]


def test_rejects_bad_body(spotify, client):
    assert client.post("/api/errors", headers=AUTH, json={"errors": "nope"}).status_code == 400


def test_health_needs_no_auth(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json == {"ok": True}
