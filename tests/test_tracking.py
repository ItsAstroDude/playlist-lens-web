"""Tests for tracking.py — SQLite in-memory DB, Spotify mocked. Run: pytest -q"""
import json
import os
import sys

import pytest
from cryptography.fernet import Fernet

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.update({
    "TRACKING_KEY": Fernet.generate_key().decode(),
    "CRON_SECRET": "s3cret",
    "SPOTIFY_CLIENT_ID": "id", "SPOTIFY_CLIENT_SECRET": "sec",
})

import tracking  # noqa: E402
from app import app  # noqa: E402


class Resp:
    def __init__(self, status, body):
        self.status_code, self._b, self.ok = status, body, status < 400
    def json(self):
        return self._b


def play(ts, name="Song", uri=None):
    return {"played_at": ts, "track": {
        "uri": uri or f"spotify:track:{name}", "name": name, "duration_ms": 200000,
        "artists": [{"name": "Artist"}], "album": {"name": "Album", "images": [{"url": "big"}, {"url": "small"}]},
    }}


@pytest.fixture
def spotify(monkeypatch, tmp_path):
    tracking.reset_engine_for_tests(f"sqlite:///{tmp_path}/t.db")
    tracking._id_cache.clear()
    state = {"recent": [play("2026-11-17T10:00:00.000Z", "A"), play("2026-11-17T10:04:00.000Z", "B")],
             "refresh_ok": True, "rotated": None}

    def post(url, **kw):
        if not state["refresh_ok"]:
            return Resp(400, {"error": "invalid_grant"})
        return Resp(200, {"access_token": "acc-" + kw["data"]["refresh_token"], "refresh_token": state["rotated"]})

    def get(url, headers=None, **kw):
        tok = headers["Authorization"].split()[1]
        if url.endswith("/me"):
            return Resp(200, {"id": "user1"}) if tok.startswith("acc-") or tok == "app-token" else Resp(401, {})
        if "recently-played" in url:
            return Resp(200, {"items": state["recent"]})
        return Resp(404, {})

    monkeypatch.setattr(tracking.requests, "post", post)
    monkeypatch.setattr(tracking.requests, "get", get)
    return state


@pytest.fixture
def client():
    return app.test_client()


AUTH = {"Authorization": "Bearer app-token"}


def test_enroll_backfills_and_encrypts(spotify, client):
    r = client.post("/api/tracking/enroll", json={"refresh_token": "rt1"})
    assert r.status_code == 200 and r.json["backfilled"] == 2
    with tracking.engine().connect() as c:
        enc = c.execute(tracking.text("SELECT refresh_enc FROM tracked_users")).scalar()
    assert "rt1" not in enc and tracking._decrypt(enc) == "rt1"


def test_status_and_plays_feed(spotify, client):
    client.post("/api/tracking/enroll", json={"refresh_token": "rt1"})
    s = client.get("/api/tracking/status", headers=AUTH).json
    assert s["enrolled"] and s["plays"] == 2
    items = client.get("/api/tracking/plays", headers=AUTH).json["items"]
    assert [i["name"] for i in items] == ["A", "B"]
    assert items[0]["artists"] == ["Artist"] and items[0]["image"] == "small"
    newer = client.get("/api/tracking/plays?after=2026-11-17T10:00:00.000Z", headers=AUTH).json["items"]
    assert [i["name"] for i in newer] == ["B"]


def test_poll_requires_secret_and_dedupes(spotify, client):
    client.post("/api/tracking/enroll", json={"refresh_token": "rt1"})
    assert client.post("/api/tracking/poll").status_code == 403
    spotify["recent"].append(play("2026-11-17T10:08:00.000Z", "C"))
    r = client.post("/api/tracking/poll", headers={"X-Cron-Secret": "s3cret"}).json
    assert r == {"polled": 1, "added": 1, "errors": 0}
    r = client.post("/api/tracking/poll", headers={"X-Cron-Secret": "s3cret"}).json
    assert r["added"] == 0


def test_poll_stores_rotated_refresh_token(spotify, client):
    client.post("/api/tracking/enroll", json={"refresh_token": "rt1"})
    spotify["rotated"] = "rt2"
    client.post("/api/tracking/poll", headers={"X-Cron-Secret": "s3cret"})
    with tracking.engine().connect() as c:
        enc = c.execute(tracking.text("SELECT refresh_enc FROM tracked_users")).scalar()
    assert tracking._decrypt(enc) == "rt2"


def test_revoked_user_pauses_after_repeated_failures(spotify, client):
    client.post("/api/tracking/enroll", json={"refresh_token": "rt1"})
    spotify["refresh_ok"] = False
    for _ in range(tracking.MAX_FAILS):
        client.post("/api/tracking/poll", headers={"X-Cron-Secret": "s3cret"})
    with tracking.engine().connect() as c:
        assert c.execute(tracking.text("SELECT status FROM tracked_users")).scalar() == "paused"


def test_gap_detection(spotify, client):
    client.post("/api/tracking/enroll", json={"refresh_token": "rt1"})
    spotify["recent"] = [play(f"2026-11-18T{h:02d}:{m:02d}:00.000Z", f"N{h}{m}") for h in range(1, 6) for m in range(0, 50, 5)]
    assert len(spotify["recent"]) == 50
    client.post("/api/tracking/poll", headers={"X-Cron-Secret": "s3cret"})
    assert client.get("/api/tracking/status", headers=AUTH).json["gaps"] == 1


def test_unenroll_deletes_everything(spotify, client):
    client.post("/api/tracking/enroll", json={"refresh_token": "rt1"})
    assert client.delete("/api/tracking", headers=AUTH).json["deleted"]
    with tracking.engine().connect() as c:
        assert c.execute(tracking.text("SELECT COUNT(*) FROM plays")).scalar() == 0
        assert c.execute(tracking.text("SELECT COUNT(*) FROM tracked_users")).scalar() == 0
    assert client.get("/api/tracking/status", headers=AUTH).json["enrolled"] is False


def test_disabled_without_config(spotify, client, monkeypatch):
    monkeypatch.delenv("TRACKING_KEY")
    assert client.post("/api/tracking/enroll", json={"refresh_token": "x"}).status_code == 503
    assert client.get("/api/tracking/status", headers=AUTH).json == {"available": False, "enrolled": False}


def test_any_random_string_works_as_tracking_key(spotify, client, monkeypatch):
    monkeypatch.setenv("TRACKING_KEY", "render-generated+value/with=odd chars 123")
    enc = tracking._encrypt("rt1")
    assert tracking._decrypt(enc) == "rt1"
    assert client.post("/api/tracking/enroll", json={"refresh_token": "rt1"}).status_code == 200
