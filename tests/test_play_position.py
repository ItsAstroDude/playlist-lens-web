"""/api/playback/play: the optional position_ms (Blind five starts a song partway in)."""
import app as app_module
from test_tracking import Resp, client  # noqa: F401  (fixture)

AUTH = {"Authorization": "Bearer tok"}


def fake(monkeypatch):
    seen = {}
    def request(method, url, headers=None, json=None, timeout=None):
        seen.update(method=method, url=url, json=json)
        return Resp(204, {})
    monkeypatch.setattr(app_module.requests, "request", request)
    return seen


def test_position_is_passed_on(monkeypatch, client):
    seen = fake(monkeypatch)
    r = client.put("/api/playback/play", json={"uris": ["spotify:track:abc"], "position_ms": 61000}, headers=AUTH)
    assert r.status_code == 200
    assert seen["method"] == "PUT" and seen["url"].endswith("/v1/me/player/play")
    assert seen["json"] == {"uris": ["spotify:track:abc"], "position_ms": 61000}


def test_no_or_bad_position_is_left_out(monkeypatch, client):
    seen = fake(monkeypatch)
    client.put("/api/playback/play", json={"uris": ["spotify:track:abc"]}, headers=AUTH)
    assert seen["json"] == {"uris": ["spotify:track:abc"]}
    client.put("/api/playback/play", json={"uris": ["spotify:track:abc"], "position_ms": "x"}, headers=AUTH)
    assert seen["json"] == {"uris": ["spotify:track:abc"]}
    client.put("/api/playback/play", json={"uris": ["spotify:track:abc"], "position_ms": -5}, headers=AUTH)
    assert seen["json"] == {"uris": ["spotify:track:abc"]}
