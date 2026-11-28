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
    import security; security.reset_rate_limits()  # many tests enroll; the limit is 10/min
    state = {"recent": [play("2026-11-17T10:00:00.000Z", "A"), play("2026-11-17T10:04:00.000Z", "B")],
             "refresh_ok": True, "rotated": None, "refresh_status": 400, "recent_status": 200, "me_status": 200}

    def post(url, **kw):
        if not state["refresh_ok"]:
            return Resp(state["refresh_status"], {"error": "invalid_grant"})
        return Resp(200, {"access_token": "acc-" + kw["data"]["refresh_token"], "refresh_token": state["rotated"]})

    def get(url, headers=None, **kw):
        tok = headers["Authorization"].split()[1]
        if url.endswith("/me"):
            if state["me_status"] != 200:
                return Resp(state["me_status"], {})
            return Resp(200, {"id": "user1"}) if tok.startswith("acc-") or tok == "app-token" else Resp(401, {})
        if "recently-played" in url:
            return Resp(state["recent_status"], {"items": state["recent"]})
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


POLL = {"X-Cron-Secret": "s3cret"}

def _user_row():
    with tracking.engine().connect() as c:
        return c.execute(tracking.text("SELECT * FROM tracked_users")).first()


def test_spotify_outage_never_pauses(spotify, client):
    client.post("/api/tracking/enroll", json={"refresh_token": "rt1"})
    spotify["refresh_ok"], spotify["refresh_status"] = False, 503
    for _ in range(tracking.MAX_FAILS + 2):
        assert client.post("/api/tracking/poll", headers=POLL).status_code == 502  # every user failed
    u = _user_row()
    assert u.status == "active" and u.fail_count == 0


def test_rotated_token_kept_when_fetch_fails(spotify, client):
    client.post("/api/tracking/enroll", json={"refresh_token": "rt1"})
    spotify["rotated"], spotify["recent_status"] = "rt2", 429
    client.post("/api/tracking/poll", headers=POLL)
    assert tracking._decrypt(_user_row().refresh_enc) == "rt2"


def test_spotify_blip_on_me_is_502_not_401(spotify, client):
    spotify["me_status"] = 503
    assert client.get("/api/tracking/status", headers=AUTH).status_code == 502
    spotify["me_status"] = 401
    assert client.get("/api/tracking/status", headers=AUTH).status_code == 401


def test_save_plays_tolerates_a_concurrent_duplicate(spotify, client):
    client.post("/api/tracking/enroll", json={"refresh_token": "rt1"})
    dup = {"played_at": "2026-11-17T10:00:00.000Z", "track_uri": "u", "track_name": "A", "artists": "[]",
           "album": None, "album_image": None, "duration_ms": 1}
    with tracking.engine().begin() as c:
        # Simulate the other poll winning the race: the row exists but our SELECT missed it.
        c.execute(tracking.text("DELETE FROM plays"))
        c.execute(tracking.text("INSERT INTO plays (user_id, played_at) VALUES ('user1', :t)"), {"t": dup["played_at"]})
        orig = c.execute
        c.execute = lambda q, *a, **k: [] if "SELECT played_at" in str(q) else orig(q, *a, **k)
        tracking.save_plays(c, "user1", [dup])  # must not raise IntegrityError


def test_opt_out_during_poll_leaves_nothing(spotify, client, monkeypatch):
    client.post("/api/tracking/enroll", json={"refresh_token": "rt1"})
    spotify["recent"].append(play("2026-11-17T10:08:00.000Z", "C"))
    real = tracking._exchange_refresh
    def opt_out_mid_poll(rt):
        # The user taps "delete my data" (its own request + transaction) after the poll began.
        assert client.delete("/api/tracking", headers=AUTH).status_code == 200
        return real(rt)
    monkeypatch.setattr(tracking, "_exchange_refresh", opt_out_mid_poll)
    client.post("/api/tracking/poll", headers=POLL)
    with tracking.engine().connect() as c:
        assert c.execute(tracking.text("SELECT COUNT(*) FROM plays")).scalar() == 0
