"""The web session keeps a refresh token Spotify rotates, and survives a bad reply."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import app as app_module  # noqa: E402
from flask import session  # noqa: E402


class Resp:
    def __init__(self, status, body):
        self.status_code, self.ok, self._b = status, status < 400, body
    def json(self):
        if self._b is None:
            raise ValueError("not json")
        return self._b


def _refresh_with(monkeypatch, resp):
    monkeypatch.setattr(app_module.requests, "post", lambda *a, **k: resp)
    with app_module.app.test_request_context():
        session["refresh_token"] = "rt1"
        ok = app_module._refresh()
        return ok, session.get("access_token"), session.get("refresh_token")


def test_rotated_refresh_token_is_kept(monkeypatch):
    assert _refresh_with(monkeypatch, Resp(200, {"access_token": "a2", "refresh_token": "rt2"})) == (True, "a2", "rt2")


def test_unrotated_keeps_the_old_one(monkeypatch):
    assert _refresh_with(monkeypatch, Resp(200, {"access_token": "a2"})) == (True, "a2", "rt1")


def test_bad_reply_is_a_failed_refresh_not_a_500(monkeypatch):
    assert _refresh_with(monkeypatch, Resp(200, None))[0] is False
    assert _refresh_with(monkeypatch, Resp(200, {}))[0] is False
