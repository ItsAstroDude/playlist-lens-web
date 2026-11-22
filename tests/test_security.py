"""Security checks: each test is one way someone might try to break playlist.lens."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import app as app_module  # noqa: E402
import security  # noqa: E402
from app import app, _safe_mobile_redirect, MOBILE_SCHEME  # noqa: E402

XSS = "<img src=x onerror=alert(1)>"


class Resp:
    def __init__(self, status, body, text=""):
        self.status_code, self._b, self.ok, self.text = status, body, status < 400, text
    def json(self):
        return self._b


@pytest.fixture
def client(monkeypatch, tmp_path):
    security.reset_rate_limits()
    monkeypatch.setattr(app_module, "_profiles", {})
    monkeypatch.setattr(app_module, "PROFILES_FILE", tmp_path / "profiles.json")
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture
def upstream(monkeypatch):
    """Record every URL the server would send to Spotify instead of sending it."""
    calls = []
    def fake(method, url, **kw):
        calls.append(url)
        return Resp(200, {"items": [], "next": None})
    monkeypatch.setattr(app_module.requests, "request", fake)
    return calls


# 1. Script in your username → stored / reflected XSS ─────────────────────────────
def test_callback_error_is_escaped(client):
    r = client.get("/callback", query_string={"error": "<script>alert(1)</script>"})
    assert r.status_code == 400
    assert b"<script>" not in r.data and b"&lt;script&gt;" in r.data


def test_token_exchange_failure_does_not_echo_spotify_body(client, monkeypatch):
    with client.session_transaction() as s:
        s["oauth_state"] = "abc"
    monkeypatch.setattr(app_module.requests, "post", lambda *a, **k: Resp(400, {}, text=XSS))
    r = client.get("/callback", query_string={"code": "x", "state": "abc"})
    assert r.status_code == 400 and b"onerror" not in r.data


def test_shared_profile_is_sanitised(client):
    evil = {"name": XSS, "trackCount": XSS, "playlistCount": {"x": 1}, "vibe": 5,
            "topArtists": [{"name": "A", "count": "<b>"}, "junk", {"count": 1}],
            "topGenres": [["pop", 3], {"genre": "rock", "count": 2}, ["x", 1, 2], 7],
            "af": {"energy": "high", "valence": 0.5, "evil": 1}, "__proto__": {"admin": True},
            "isAdmin": True}
    code = client.post("/api/profile/save", json=evil).json["code"]
    p = client.get(f"/api/profile/load/{code}").json
    assert p["trackCount"] == 0 and p["playlistCount"] == 0     # never HTML, always numbers
    assert p["name"] == XSS                                      # text is kept; the page escapes it
    assert p["vibe"] is None
    assert p["topArtists"] == [{"name": "A", "count": 0}]
    assert p["topGenres"] == [["pop", 3], {"genre": "rock", "count": 2}]
    assert p["af"] == {"valence": 0.5}
    assert "isAdmin" not in p and "__proto__" not in p


def test_profiles_saved_before_the_fix_are_cleaned_on_load(client):
    app_module._profiles["OLD-ONE"] = {"name": "x", "trackCount": XSS}
    assert client.get("/api/profile/load/OLDONE").json["trackCount"] == 0


def test_web_page_escapes_profile_numbers():
    html = open(os.path.join(os.path.dirname(app_module.__file__), "index.html"), encoding="utf-8").read()
    assert "${p.trackCount}" not in html and "${p.playlistCount}" not in html
    assert "${num(p.trackCount)}" in html


def test_real_profiles_round_trip(client):
    web = {"name": "Andrei", "trackCount": 812, "playlistCount": 14, "vibe": "🎵 Balanced mix",
           "topArtists": [{"name": "Radiohead", "count": 40}], "topGenres": [["indie", 20]],
           "af": {"danceability": 0.5, "energy": 0.6, "valence": 0.4, "acousticness": 0.2,
                  "instrumentalness": 0.1, "liveness": 0.15, "avgTempo": 121}}
    mobile = {**web, "version": 2, "artistCount": 300, "generatedAt": "2026-11-20T10:00:00Z",
              "topArtists": [{"id": "abc", "name": "Radiohead", "count": 40}],
              "topGenres": [{"genre": "indie", "count": 20}]}
    for body in (web, mobile):
        code = client.post("/api/profile/save", json=body).json["code"]
        assert client.get(f"/api/profile/load/{code}").json == body


# 2. Change the ID in the URL → smuggling extra paths/params to Spotify ───────────
@pytest.mark.parametrize("pl_id", ["..", "abc?market=US", "abc&x=1", "abc#frag", "abc%2F..%2Fme"])
def test_playlist_ids_must_be_spotify_ids(client, upstream, pl_id):
    r = client.get(f"/api/playlist/{pl_id}/tracks", headers={"Authorization": "Bearer t"})
    assert r.status_code in (400, 404) and upstream == []
    for route in ("add", "remove", "duplicate"):
        r = client.post(f"/api/playlist/{pl_id}/{route}", json={"uris": ["spotify:track:a"]},
                        headers={"Authorization": "Bearer t"})
        assert r.status_code in (400, 404) and upstream == []


def test_good_playlist_id_still_works(client, upstream):
    r = client.get("/api/playlist/37i9dQZF1DXcBWIGoYBM5M/tracks", headers={"Authorization": "Bearer t"})
    assert r.status_code == 200 and upstream[0].startswith("https://api.spotify.com/v1/playlists/37i9dQZF1DXcBWIGoYBM5M/")


def test_artist_ids_cannot_smuggle_params(client, upstream):
    h = {"Authorization": "Bearer t"}
    assert client.get("/api/artists?ids=a,b%26market=US", headers=h).status_code == 400
    assert client.get("/api/audio-features?ids=a/../../me", headers=h).status_code == 400
    assert upstream == []
    assert client.get("/api/artists?ids=abc,def", headers=h).status_code == 200


# 3/6. No admin surface to find ───────────────────────────────────────────────────
def test_no_admin_routes():
    rules = [r.rule for r in app.url_map.iter_rules()]
    assert not [r for r in rules if "admin" in r.lower() or "debug" in r.lower()]


# 11. Guess the login code ────────────────────────────────────────────────────────
def test_share_codes_use_a_secure_random():
    import inspect
    src = inspect.getsource(app_module._gen_code)
    assert "secrets.choice" in src and "random.choices" not in src


def test_guessing_share_codes_gets_rate_limited(client):
    codes = [client.get("/api/profile/load/AAA-AA%d" % (i % 10)).status_code for i in range(70)]
    assert codes[:60] == [404] * 60 and set(codes[60:]) == {429}


def test_callback_requires_the_state_this_browser_started_with(client, monkeypatch):
    """Login CSRF: an attacker's /callback link must not sign you into their account."""
    monkeypatch.setattr(app_module.requests, "post", lambda *a, **k: Resp(200, {"access_token": "AT"}))
    r = client.get("/callback", query_string={"code": "attackers-code", "state": "whatever"})
    assert r.status_code == 400
    with client.session_transaction() as s:
        assert "access_token" not in s
    # And the normal flow works: /login stores the state, /callback matches it, once.
    client.get("/login")
    with client.session_transaction() as s:
        state = s["oauth_state"]
    assert client.get("/callback", query_string={"code": "c", "state": state}).status_code == 302
    assert client.get("/callback", query_string={"code": "c", "state": state}).status_code == 400


def test_mobile_login_round_trip_keeps_its_state(client, monkeypatch):
    monkeypatch.setattr(app_module.requests, "post",
                        lambda *a, **k: Resp(200, {"access_token": "AT", "refresh_token": "RT"}))
    client.get("/login", query_string={"mobile": "true", "state": "St4te", "redirect_url": "playlistlens://callback"})
    r = client.get("/callback", query_string={"code": "c", "state": "St4te"})
    assert r.status_code == 302
    assert r.headers["Location"].startswith("playlistlens://callback?access_token=AT&refresh_token=RT&state=St4te")


# 4. API key in the browser → tokens to a stranger ────────────────────────────────
def test_expo_go_links_cannot_send_tokens_to_another_server():
    for url in ("exp://evil.example/--/callback", "exp://evil.example:8081/--/callback",
                "exp://u.expo.dev/abc", "exp://8.8.8.8:8081/--/callback", "exp://"):
        assert _safe_mobile_redirect(url) == MOBILE_SCHEME
    for url in ("exp://192.168.1.5:8081/--/callback", "exp://10.0.0.2:8081/--/callback",
                "exp://localhost:8081/--/callback", "exp://127.0.0.1:19000/--/callback"):
        assert _safe_mobile_redirect(url) == url


def test_client_secret_never_reaches_the_page(client):
    html = client.get("/").data.decode().lower()
    for leak in ("client_secret", "secret_key", "tracking_key", "cron_secret", "database_url"):
        assert leak not in html


# 7-10. Edit the price / order -1 / redeem 100 times → hostile sizes & counts ──────
def test_huge_bodies_are_refused(client, upstream):
    big = b'{"name": "x", "uris": ["' + b"x" * (3 * 1024 * 1024) + b'"]}'
    r = client.post("/api/playlist/create", data=big, content_type="application/json",
                    headers={"Authorization": "Bearer t"})
    assert r.status_code == 413 and upstream == []


def test_huge_profiles_are_refused(client):
    r = client.post("/api/profile/save", json={"name": "x" * (security.MAX_PROFILE_BYTES + 1)})
    assert r.status_code == 413


def test_profile_store_is_capped(client, monkeypatch):
    monkeypatch.setattr(app_module, "MAX_PROFILES", 3)
    codes = [client.post("/api/profile/save", json={"name": str(i)}).json["code"] for i in range(5)]
    assert list(app_module._profiles) == codes[-3:]


def test_profile_spam_gets_rate_limited(client):
    codes = [client.post("/api/profile/save", json={"name": "x"}).status_code for _ in range(22)]
    assert codes[:20] == [200] * 20 and codes[20:] == [429, 429]


@pytest.mark.parametrize("limit", ["-1", "0", "99999", "abc", "1e9"])
def test_limits_are_clamped(client, upstream, limit):
    client.get(f"/api/recently-played?limit={limit}", headers={"Authorization": "Bearer t"})
    n = int(upstream[-1].split("limit=")[1].split("&")[0])
    assert 1 <= n <= 50


def test_non_string_playlist_names_are_rejected(client, upstream):
    r = client.post("/api/playlist/create", json={"name": {"$gt": ""}}, headers={"Authorization": "Bearer t"})
    assert r.status_code == 400 and upstream == []


# 12. Query your database ─────────────────────────────────────────────────────────
def test_no_sql_built_from_strings():
    """Every query uses bound :params. Flag any f-string or % formatting near SQL."""
    import re
    here = os.path.dirname(app_module.__file__)
    for name in ("tracking.py", "errors.py", "app.py"):
        src = open(os.path.join(here, name), encoding="utf-8").read()
        assert not re.search(r'text\(\s*f["\']', src), name
        assert not re.search(r'(SELECT|INSERT|UPDATE|DELETE)[^"\']*["\']\s*%', src), name


# 13. .env in Git ─────────────────────────────────────────────────────────────────
def test_secret_files_are_gitignored():
    ignore = open(os.path.join(os.path.dirname(app_module.__file__), ".gitignore")).read().split()
    for f in (".env", "tracking.db", "profiles.json"):
        assert f in ignore


# Headers: clickjacking, sniffing, referrer leaks ──────────────────────────────────
def test_security_headers(client):
    r = client.get("/")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Referrer-Policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert client.get("/api/health").headers["Cache-Control"] == "no-store"
