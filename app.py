"""
playlist.lens — backend
Handles both web and mobile OAuth flows.
Mobile flow: redirects back to the app via deep link with tokens as query params.
"""

import base64
import json
import os
import random
import secrets
import string
import webbrowser
from pathlib import Path
from urllib.parse import urlencode

import requests
from flask import Flask, jsonify, redirect, request, session

# ── config ────────────────────────────────────────────────────
CLIENT_ID     = os.environ.get("SPOTIFY_CLIENT_ID",     "YOUR_CLIENT_ID")
CLIENT_SECRET = os.environ.get("SPOTIFY_CLIENT_SECRET", "YOUR_CLIENT_SECRET")
REDIRECT_URI  = os.environ.get("REDIRECT_URI",          "http://localhost:8888/callback")
SECRET_KEY    = os.environ.get("SECRET_KEY",             secrets.token_hex(32))
PORT          = int(os.environ.get("PORT",               8888))
IS_PRODUCTION = "RENDER" in os.environ

# Deep link scheme for the mobile app
MOBILE_SCHEME = "playlistlens://auth/callback"

SCOPES = (
    "user-read-private "
    "playlist-read-private "
    "playlist-read-collaborative "
    "user-library-read"
)

# ── app ───────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = SECRET_KEY

_tokens:   dict = {}
_profiles: dict = {}

PROFILES_FILE = Path("profiles.json")

def _load_profiles():
    if PROFILES_FILE.exists():
        try:
            return json.loads(PROFILES_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}

def _save_profiles():
    try:
        PROFILES_FILE.write_text(json.dumps(_profiles, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass

_profiles = _load_profiles()

# ── helpers ───────────────────────────────────────────────────
def _basic_header() -> str:
    return "Basic " + base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()

def _refresh() -> bool:
    rt = _tokens.get("refresh_token")
    if not rt:
        return False
    r = requests.post(
        "https://accounts.spotify.com/api/token",
        headers={"Authorization": _basic_header()},
        data={"grant_type": "refresh_token", "refresh_token": rt},
        timeout=10,
    )
    if r.ok:
        _tokens["access_token"] = r.json()["access_token"]
        return True
    return False

def _spotify_get(url: str) -> requests.Response:
    hdrs = {"Authorization": f"Bearer {_tokens.get('access_token', '')}"}
    r = requests.get(url, headers=hdrs, timeout=15)
    if r.status_code == 401 and _refresh():
        hdrs["Authorization"] = f"Bearer {_tokens['access_token']}"
        r = requests.get(url, headers=hdrs, timeout=15)
    return r

def _gen_code() -> str:
    chars = string.ascii_uppercase + string.digits
    for _ in range(100):
        raw = "".join(random.choices(chars, k=6))
        code = f"{raw[:3]}-{raw[3:]}"
        if code not in _profiles:
            return code
    raise RuntimeError("Could not generate unique code")

# ── auth ──────────────────────────────────────────────────────
@app.get("/login")
def login():
    is_mobile    = request.args.get("mobile") == "true"
    state        = request.args.get("state", secrets.token_hex(8))
    # Mobile app passes its own deep-link URL so dev builds, Expo Go, and
    # production all get redirected to the right scheme after OAuth.
    redirect_url = request.args.get("redirect_url", MOBILE_SCHEME)

    session["oauth_state"]     = state
    session["is_mobile"]       = is_mobile
    session["mobile_redirect"] = redirect_url

    qs = urlencode({
        "client_id":     CLIENT_ID,
        "response_type": "code",
        "redirect_uri":  REDIRECT_URI,
        "scope":         SCOPES,
        "state":         state,
    })
    return redirect(f"https://accounts.spotify.com/authorize?{qs}")

@app.get("/callback")
def callback():
    error = request.args.get("error")
    if error:
        return f"<h3>Auth error: {error}</h3>", 400

    code          = request.args.get("code", "")
    returned_state = request.args.get("state", "")
    is_mobile     = session.get("is_mobile", False)

    r = requests.post(
        "https://accounts.spotify.com/api/token",
        headers={"Authorization": _basic_header(), "Content-Type": "application/x-www-form-urlencoded"},
        data={"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI},
        timeout=10,
    )
    if not r.ok:
        return f"<h3>Token exchange failed: {r.text}</h3>", 400

    data = r.json()
    _tokens["access_token"]  = data["access_token"]
    _tokens["refresh_token"] = data.get("refresh_token", "")

    if is_mobile:
        # Use the deep-link URL the mobile app registered at login time
        mobile_redirect = session.get("mobile_redirect", MOBILE_SCHEME)
        params = urlencode({
            "access_token":  data["access_token"],
            "refresh_token": data.get("refresh_token", ""),
            "state":         returned_state,
        })
        return redirect(f"{mobile_redirect}?{params}")

    return redirect("/")

@app.get("/logout")
def logout():
    _tokens.clear()
    return redirect("/")

@app.get("/api/auth-status")
def auth_status():
    return jsonify({"authenticated": bool(_tokens.get("access_token"))})

# ── spotify proxy ─────────────────────────────────────────────
@app.get("/api/me")
def me():
    r = _spotify_get("https://api.spotify.com/v1/me")
    return jsonify(r.json()), r.status_code

@app.get("/api/playlists")
def playlists():
    r = _spotify_get("https://api.spotify.com/v1/me/playlists?limit=50")
    return jsonify(r.json()), r.status_code

@app.get("/api/playlist/<pl_id>/tracks")
def playlist_tracks(pl_id: str):
    if pl_id == "liked_songs":
        return _liked_tracks()
    items, url = [], f"https://api.spotify.com/v1/playlists/{pl_id}/tracks?limit=100"
    while url and len(items) < 500:
        r = _spotify_get(url)
        if not r.ok:
            return jsonify(r.json()), r.status_code
        data = r.json()
        items.extend(i for i in data.get("items", []) if i.get("track") and i["track"].get("id"))
        url = data.get("next")
    return jsonify({"items": items})

def _liked_tracks():
    items, url = [], "https://api.spotify.com/v1/me/tracks?limit=50"
    while url and len(items) < 500:
        r = _spotify_get(url)
        if not r.ok:
            return jsonify(r.json()), r.status_code
        data = r.json()
        items.extend({"track": i["track"]} for i in data.get("items", []) if i.get("track") and i["track"].get("id"))
        url = data.get("next")
    return jsonify({"items": items})

@app.get("/api/artists")
def artists():
    r = _spotify_get(f"https://api.spotify.com/v1/artists?ids={request.args.get('ids','')}")
    return jsonify(r.json()), r.status_code

@app.get("/api/audio-features")
def audio_features():
    ids = request.args.get("ids", "")
    if not ids:
        return jsonify({"audio_features": []}), 200
    r = _spotify_get(f"https://api.spotify.com/v1/audio-features?ids={ids}")
    # Spotify deprecated audio features for apps registered after Nov 2024.
    # Return an empty list so clients degrade gracefully instead of seeing a 403.
    if r.status_code == 403:
        return jsonify({"audio_features": []}), 200
    return jsonify(r.json()), r.status_code

# ── profile share ─────────────────────────────────────────────
@app.post("/api/profile/save")
def save_profile():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No data"}), 400
    code = _gen_code()
    _profiles[code] = data
    _save_profiles()
    return jsonify({"code": code})

@app.get("/api/profile/load/<code>")
def load_profile(code: str):
    normalized = code.upper().replace(" ", "")
    if "-" not in normalized and len(normalized) == 6:
        normalized = f"{normalized[:3]}-{normalized[3:]}"
    profile = _profiles.get(normalized)
    if not profile:
        return jsonify({"error": "Profile not found. Check the code and try again."}), 404
    return jsonify(profile)

# ── web frontend ──────────────────────────────────────────────
@app.get("/")
def index():
    html_path = Path("index.html")
    if not html_path.exists():
        return "<h3>Frontend not found</h3>", 404
    return html_path.read_text(encoding="utf-8"), 200, {"Content-Type": "text/html; charset=utf-8"}

# ── entry ─────────────────────────────────────────────────────
if __name__ == "__main__":
    if not IS_PRODUCTION:
        print(f"\n  playlist.lens  →  http://localhost:{PORT}\n")
        webbrowser.open(f"http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
