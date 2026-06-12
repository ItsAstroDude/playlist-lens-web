"""
playlist.lens — backend
Handles both web and mobile OAuth flows.
Mobile flow: redirects back to the app via deep link with tokens as query params.
"""

import base64
import json
import os
import random
import re
import secrets
import string
import time
import webbrowser
from datetime import date
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

# Deep link scheme for the mobile app — fallback only; the app always sends an
# explicit redirect_url (Linking.createURL('/callback')) on /login.
MOBILE_SCHEME = "playlistlens://callback"

# v1.3 batched re-auth: now-playing (user-read-currently-playing) + swipe writes
# (playlist-modify-*) granted in ONE login so users never face a second consent.
# Pre-v1.3 tokens lack the new scopes → those endpoints return 403 and the app
# shows its inline "reconnect Spotify" prompt.
SCOPES = (
    "user-read-private "
    "playlist-read-private "
    "playlist-read-collaborative "
    "user-library-read "
    "user-read-currently-playing "
    "playlist-modify-public "
    "playlist-modify-private"
)

# ── app ───────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = SECRET_KEY

# Per-user tokens live EITHER in the signed Flask session cookie (web flow) or are
# sent by the client as a Bearer header (mobile). There is deliberately NO server
# global token store — a shared global previously served the last-logged-in
# account to every visitor who didn't present their own token.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PRODUCTION,  # HTTPS-only cookie in production
)

# A STABLE SECRET_KEY is required in production now that the session cookie holds
# tokens: the per-boot random fallback (above) would silently invalidate every
# web session on each restart and across workers/instances.
if IS_PRODUCTION and not os.environ.get("SECRET_KEY"):
    print("WARNING: SECRET_KEY env var is not set — web sessions will not persist "
          "across restarts or workers. Set a fixed SECRET_KEY on Render.")

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

class _FakeResponse:
    """Mimics requests.Response so _spotify_get() callers always get .json()/.status_code."""
    def __init__(self, body: dict, status_code: int):
        self._body      = body
        self.status_code = status_code
        self.ok         = status_code < 400
    def json(self):
        return self._body

def _basic_header() -> str:
    return "Basic " + base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()

def _refresh() -> bool:
    """Refresh the WEB session's access token from its own stored refresh token."""
    rt = session.get("refresh_token")
    if not rt:
        return False
    r = requests.post(
        "https://accounts.spotify.com/api/token",
        headers={"Authorization": _basic_header()},
        data={"grant_type": "refresh_token", "refresh_token": rt},
        timeout=10,
    )
    if r.ok:
        session["access_token"] = r.json()["access_token"]
        return True
    return False

def _spotify_request(method: str, url: str, payload: dict | None = None) -> requests.Response:
    # Two ISOLATED token sources, never a shared global:
    #   • Mobile sends its own Bearer token in the Authorization header.
    #   • Web uses the per-browser token in this request's signed session cookie.
    incoming  = request.headers.get("Authorization", "")
    is_bearer = incoming.startswith("Bearer ")
    if is_bearer:
        token = incoming[len("Bearer "):].strip()
    else:
        token = (session.get("access_token") or "").strip()

    # Bail early rather than forwarding an empty token to Spotify —
    # that produces a confusing 400 instead of a clean 401.
    if not token:
        return _FakeResponse(
            {'error': {'status': 401, 'message': 'No authentication token. Please log in again.'}},
            401,
        )

    hdrs = {"Authorization": f"Bearer {token}"}
    r = requests.request(method, url, headers=hdrs, json=payload, timeout=15)

    # Only the web (session) flow can refresh here — mobile refreshes on its side.
    if r.status_code == 401 and not is_bearer and _refresh():
        hdrs["Authorization"] = f"Bearer {session['access_token']}"
        r = requests.request(method, url, headers=hdrs, json=payload, timeout=15)

    # Spotify returns 400 "Only valid bearer authentication supported" for
    # malformed/invalid tokens — normalise to 401 so mobile auto-logout fires.
    if r.status_code == 400:
        try:
            body = r.json()
            msg  = body.get("error", {}).get("message", "")
            if "bearer" in msg.lower():
                return _FakeResponse(
                    {"error": {"status": 401, "message": "Invalid token. Please log in again."}},
                    401,
                )
        except Exception:
            pass

    return r

def _spotify_get(url: str) -> requests.Response:
    return _spotify_request("GET", url)

def _json_or_error(r) -> dict:
    """Body of a (possibly Fake) response, tolerating empty/non-JSON bodies."""
    try:
        return r.json()
    except Exception:
        return {"error": {"status": r.status_code, "message": "Unexpected response from Spotify."}}

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

    if is_mobile:
        # Mobile stores its own tokens (SecureStore) and verifies the CSRF state
        # itself — the server persists nothing for the mobile flow.
        mobile_redirect = session.get("mobile_redirect", MOBILE_SCHEME)
        params = urlencode({
            "access_token":  data["access_token"],
            "refresh_token": data.get("refresh_token", ""),
            "state":         returned_state,
        })
        return redirect(f"{mobile_redirect}?{params}")

    # Web flow: tokens live ONLY in this browser's signed session cookie.
    session["access_token"]  = data["access_token"]
    session["refresh_token"] = data.get("refresh_token", "")
    return redirect("/")

@app.get("/logout")
def logout():
    session.pop("access_token", None)
    session.pop("refresh_token", None)
    return redirect("/")

@app.get("/api/auth-status")
def auth_status():
    return jsonify({"authenticated": bool(session.get("access_token"))})

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

@app.get("/api/now-playing")
def now_playing():
    """Live now-playing for the mobile bar. Requires user-read-currently-playing —
    pre-v1.3 tokens get Spotify's 403 passed through, which the app uses to show
    its "reconnect Spotify" prompt."""
    r = _spotify_get("https://api.spotify.com/v1/me/player/currently-playing")
    if r.status_code == 204:  # nothing playing / no active device — empty body
        return jsonify({"is_playing": False, "item": None}), 200
    if not r.ok:
        return jsonify(_json_or_error(r)), r.status_code
    data = _json_or_error(r)
    item = data.get("item") or {}
    album = item.get("album") or {}
    # Trimmed payload — this gets polled every few seconds.
    return jsonify({
        "is_playing":  data.get("is_playing", False),
        "progress_ms": data.get("progress_ms"),
        "type":        data.get("currently_playing_type", "track"),
        "item": {
            "id":          item.get("id"),
            "uri":         item.get("uri"),
            "name":        item.get("name"),
            "duration_ms": item.get("duration_ms"),
            "artists":     [a.get("name") for a in item.get("artists", [])],
            "album":       {"name": album.get("name"), "images": album.get("images", [])},
        } if item else None,
    })

# ── 30s preview resolver (swipe-refresh) ─────────────────────
# Spotify killed preview_url for apps registered after 2024-11-27, so snippets
# are resolved server-side: Deezer by ISRC (exact) → Spotify embed scrape (exact
# but fragile) → iTunes text search (fuzzy, last resort). Strategy lives here so
# it can change without an app update.

_preview_cache: dict = {}          # key → (expires_at, result)
_PREVIEW_TTL   = 30 * 60           # Deezer URLs expire within hours; stay well under
_PREVIEW_CACHE_MAX = 4000

def _preview_from_deezer(isrc: str):
    if not isrc:
        return None
    try:
        r = requests.get(f"https://api.deezer.com/track/isrc:{isrc}", timeout=8)
        if r.ok:
            return r.json().get("preview") or None  # not-found = {"error": …}, no "preview"
    except Exception:
        pass
    return None

def _preview_from_itunes(artist: str, title: str):
    if not title:
        return None
    try:
        r = requests.get(
            "https://itunes.apple.com/search",
            params={"term": f"{artist} {title}".strip(), "media": "music",
                    "entity": "song", "limit": 5},
            timeout=8,
        )
        if not r.ok:
            return None
        t, best = title.lower(), None
        for res in r.json().get("results", []):
            url = res.get("previewUrl")
            if not url:
                continue
            if t and t in (res.get("trackName") or "").lower():
                return url  # title actually matches — take it
            best = best or url
        return best  # text search only — best effort
    except Exception:
        return None

def _preview_from_embed(track_id: str):
    if not track_id or not re.fullmatch(r"[A-Za-z0-9]+", track_id):
        return None
    try:
        r = requests.get(
            f"https://open.spotify.com/embed/track/{track_id}",
            headers={"User-Agent": "Mozilla/5.0"}, timeout=8,
        )
        if r.ok:
            m = re.search(r'"audioPreview"\s*:\s*\{\s*"url"\s*:\s*"([^"]+)"', r.text)
            if m:
                return m.group(1)
    except Exception:
        pass
    return None

@app.get("/api/preview")
def preview():
    isrc     = request.args.get("isrc", "").strip()
    title    = request.args.get("title", "").strip()
    artist   = request.args.get("artist", "").strip()
    track_id = request.args.get("track_id", "").strip()
    if not (isrc or title or track_id):
        return jsonify({"error": "Provide isrc, title(+artist) or track_id."}), 400

    key = track_id or isrc or f"{artist}|{title}"
    now = time.time()
    cached = _preview_cache.get(key)
    if cached and cached[0] > now:
        return jsonify(cached[1])

    url, source = None, None
    for src, resolve in (("deezer",  lambda: _preview_from_deezer(isrc)),
                         ("spotify-embed", lambda: _preview_from_embed(track_id)),
                         ("itunes",  lambda: _preview_from_itunes(artist, title))):
        url = resolve()
        if url:
            source = src
            break

    result = {"preview_url": url, "source": source}  # url None = nothing found, app skips/swipes on art
    if len(_preview_cache) >= _PREVIEW_CACHE_MAX:
        _preview_cache.clear()
    _preview_cache[key] = (now + _PREVIEW_TTL, result)
    return jsonify(result)

# ── playlist writes (swipe-refresh) ──────────────────────────
# All require playlist-modify-* scopes (v1.3 re-auth); old tokens → Spotify 403,
# which the app turns into the reconnect prompt. Local files (spotify:local:…)
# can't be added via the API — they're filtered out and reported as skipped_local.

def _addable_uris(uris) -> tuple[list, int]:
    """(addable track URIs, count of skipped local-file URIs)."""
    if not isinstance(uris, list):
        return [], 0
    clean   = [u for u in uris if isinstance(u, str)]
    addable = [u for u in clean if u.startswith("spotify:track:")]
    skipped = sum(1 for u in clean if u.startswith("spotify:local:"))
    return addable, skipped

def _add_in_batches(pl_id: str, uris: list):
    """POST uris 100/call preserving order. Returns an error response or None."""
    for i in range(0, len(uris), 100):
        r = _spotify_request("POST", f"https://api.spotify.com/v1/playlists/{pl_id}/tracks",
                             {"uris": uris[i:i + 100]})
        if r.status_code not in (200, 201):
            return jsonify(_json_or_error(r)), r.status_code
    return None

@app.post("/api/playlist/create")
def playlist_create():
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Playlist name is required."}), 400
    uris, skipped_local = _addable_uris(body.get("uris") or [])

    me_r = _spotify_get("https://api.spotify.com/v1/me")
    if not me_r.ok:
        return jsonify(_json_or_error(me_r)), me_r.status_code
    user_id = me_r.json().get("id")

    cr = _spotify_request("POST", f"https://api.spotify.com/v1/users/{user_id}/playlists", {
        "name":        name,
        "public":      bool(body.get("public", False)),
        "description": body.get("description") or "Created with playlist.lens",
    })
    if cr.status_code not in (200, 201):
        return jsonify(_json_or_error(cr)), cr.status_code
    new_pl = cr.json()

    err = _add_in_batches(new_pl["id"], uris)
    if err:
        return err
    return jsonify({
        "id":            new_pl["id"],
        "name":          new_pl.get("name"),
        "url":           (new_pl.get("external_urls") or {}).get("spotify"),
        "added":         len(uris),
        "skipped_local": skipped_local,
    }), 201

@app.post("/api/playlist/<pl_id>/add")
def playlist_add(pl_id: str):
    body = request.get_json(silent=True) or {}
    uris, skipped_local = _addable_uris(body.get("uris") or [])
    if not uris:
        return jsonify({"error": "No addable track URIs."}), 400
    err = _add_in_batches(pl_id, uris)
    if err:
        return err
    return jsonify({"added": len(uris), "skipped_local": skipped_local})

@app.post("/api/playlist/<pl_id>/remove")
def playlist_remove(pl_id: str):
    body = request.get_json(silent=True) or {}
    uris = [u for u in (body.get("uris") or []) if isinstance(u, str) and u.startswith("spotify:")]
    if not uris:
        return jsonify({"error": "No track URIs to remove."}), 400
    snapshot_id = body.get("snapshot_id")
    removed = 0
    for i in range(0, len(uris), 100):
        payload = {"tracks": [{"uri": u} for u in uris[i:i + 100]]}
        if snapshot_id:
            payload["snapshot_id"] = snapshot_id
        r = _spotify_request("DELETE", f"https://api.spotify.com/v1/playlists/{pl_id}/tracks", payload)
        if r.status_code != 200:
            # Partial failure: report progress so the app can tell the user honestly.
            return jsonify({"removed": removed, **_json_or_error(r)}), r.status_code
        removed += len(payload["tracks"])
    return jsonify({"removed": removed})

@app.post("/api/playlist/<pl_id>/duplicate")
def playlist_duplicate(pl_id: str):
    """Full private backup of a playlist — used before a destructive trim, so it
    paginates the WHOLE playlist (no 500-track read cap) to never lose tracks."""
    body = request.get_json(silent=True) or {}

    meta_r = _spotify_get(f"https://api.spotify.com/v1/playlists/{pl_id}?fields=name")
    if not meta_r.ok:
        return jsonify(_json_or_error(meta_r)), meta_r.status_code
    src_name = meta_r.json().get("name") or "playlist"

    uris, skipped_local = [], 0
    url = (f"https://api.spotify.com/v1/playlists/{pl_id}/tracks"
           "?fields=items(track(uri,is_local)),next&limit=100")
    while url and len(uris) < 11000:  # Spotify playlists cap at 10k
        r = _spotify_get(url)
        if not r.ok:
            return jsonify(_json_or_error(r)), r.status_code
        data = r.json()
        for it in data.get("items", []):
            track = it.get("track") or {}
            uri = track.get("uri")
            if not uri:
                continue
            if track.get("is_local") or uri.startswith("spotify:local:"):
                skipped_local += 1
            elif uri.startswith("spotify:track:"):
                uris.append(uri)
        url = data.get("next")

    me_r = _spotify_get("https://api.spotify.com/v1/me")
    if not me_r.ok:
        return jsonify(_json_or_error(me_r)), me_r.status_code
    user_id = me_r.json().get("id")

    backup_name = (body.get("name") or "").strip() or \
        f"playlist.lens backup — {src_name} — {date.today().isoformat()}"
    cr = _spotify_request("POST", f"https://api.spotify.com/v1/users/{user_id}/playlists", {
        "name":        backup_name,
        "public":      False,
        "description": "Safety copy made by playlist.lens before trimming the original.",
    })
    if cr.status_code not in (200, 201):
        return jsonify(_json_or_error(cr)), cr.status_code
    backup = cr.json()

    err = _add_in_batches(backup["id"], uris)
    if err:
        return err
    return jsonify({
        "id":            backup["id"],
        "name":          backup.get("name"),
        "copied":        len(uris),
        "skipped_local": skipped_local,
    }), 201

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
