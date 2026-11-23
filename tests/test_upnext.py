"""Tests for /api/playback/upnext — Spotify's queue, trimmed for the half-folded view."""
import app as app_module
from test_tracking import Resp, client  # noqa: F401  (fixture)

AUTH = {"Authorization": "Bearer tok"}


def track(n, kind="track"):
    return {"type": kind, "id": f"id{n}", "uri": f"spotify:track:id{n}", "name": f"Song {n}", "duration_ms": 1000 * n,
            "artists": [{"name": "A"}, {"name": "B"}],
            "album": {"images": [{"url": "640"}, {"url": "300"}, {"url": "64"}]}}


def fake(monkeypatch, status, body):
    seen = {}
    def request(method, url, headers=None, json=None, timeout=None):
        seen.update(method=method, url=url, auth=headers.get("Authorization"))
        return Resp(status, body)
    monkeypatch.setattr(app_module.requests, "request", request)
    return seen


def test_trims_queue_and_skips_episodes(monkeypatch, client):
    q = [track(1), track(2, "episode"), None] + [track(i) for i in range(3, 30)]
    seen = fake(monkeypatch, 200, {"currently_playing": track(0), "queue": q})
    r = client.get("/api/playback/upnext?limit=5", headers=AUTH)
    assert r.status_code == 200
    assert seen["method"] == "GET" and seen["url"].endswith("/v1/me/player/queue") and seen["auth"] == "Bearer tok"
    assert r.json["current"]["name"] == "Song 0"
    assert [t["name"] for t in r.json["queue"]] == ["Song 1", "Song 3", "Song 4", "Song 5", "Song 6"]
    first = r.json["queue"][0]
    assert first == {"id": "id1", "uri": "spotify:track:id1", "name": "Song 1", "duration_ms": 1000,
                     "artists": ["A", "B"], "image": "300"}


def test_limit_is_clamped_and_defaults_to_ten(monkeypatch, client):
    fake(monkeypatch, 200, {"currently_playing": None, "queue": [track(i) for i in range(1, 40)]})
    assert len(client.get("/api/playback/upnext", headers=AUTH).json["queue"]) == 10
    assert len(client.get("/api/playback/upnext?limit=999", headers=AUTH).json["queue"]) == 20
    assert client.get("/api/playback/upnext", headers=AUTH).json["current"] is None


def test_passes_spotify_errors_through(monkeypatch, client):
    fake(monkeypatch, 403, {"error": {"status": 403, "message": "Insufficient client scope"}})
    r = client.get("/api/playback/upnext", headers=AUTH)
    assert r.status_code == 403


def test_needs_a_token(client):
    assert client.get("/api/playback/upnext").status_code == 401
