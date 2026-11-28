"""
Server-side listening tracker (v1.8) — stats.fm-style.

Spotify's /me/player/recently-played only remembers the last 50 plays, so to build
real weekly/monthly stats something has to save them before they roll off. This
module does that on the server, for users who opt in from the app:

  POST   /api/tracking/enroll   {refresh_token}   opt in (stores the token ENCRYPTED)
  GET    /api/tracking/status   (Bearer)          enrolled? how many plays? last poll?
  GET    /api/tracking/plays    (Bearer)          ?after=<ISO ts>&limit=N  → saved plays
  DELETE /api/tracking          (Bearer)          opt out — deletes the token + every play
  POST   /api/tracking/poll     (X-Cron-Secret)   save new plays for every enrolled user

The poll is triggered hourly by an external scheduler (.github/workflows/track.yml),
because Render's free tier sleeps — an in-process timer would sleep with it. 50
plays ≈ 2.5h of non-stop listening, so hourly never drops plays.

Configuration (all env vars; tracking is DISABLED unless the first two are set):
  TRACKING_KEY   secret encrypting stored refresh tokens — a Fernet key, or any long
                 random string (Render's "Generate" button is fine)
  CRON_SECRET    shared secret the scheduler sends as X-Cron-Secret
  DATABASE_URL   postgres://… (e.g. Neon / Supabase free tier). Falls back to a
                 local SQLite file for development — NOT durable on Render.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone

import requests
from flask import Blueprint, jsonify, request
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from security import rate_limit

bp = Blueprint("tracking", __name__)

SPOTIFY_TOKEN_URL = "https://accounts.spotify.com/api/token"
SPOTIFY_API       = "https://api.spotify.com/v1"
MAX_FAILS         = 5          # consecutive refresh failures before a user is paused
PLAYS_PAGE_MAX    = 5000


# ── config ────────────────────────────────────────────────────────────────────
def _env(name: str) -> str:
    return (os.environ.get(name) or "").strip()

def enabled() -> bool:
    return bool(_env("TRACKING_KEY") and _env("CRON_SECRET"))

def _fernet():
    """TRACKING_KEY may be a real Fernet key OR any random secret (e.g. one Render
    generated) — a non-Fernet value is stretched into a key with SHA-256. Both are
    deterministic, so the same env value always decrypts what it encrypted."""
    from cryptography.fernet import Fernet
    raw = _env("TRACKING_KEY")
    try:
        return Fernet(raw.encode())
    except ValueError:
        return Fernet(base64.urlsafe_b64encode(hashlib.sha256(raw.encode()).digest()))

def _encrypt(s: str) -> str:
    return _fernet().encrypt(s.encode()).decode()

def _decrypt(s: str) -> str:
    return _fernet().decrypt(s.encode()).decode()


# ── database ──────────────────────────────────────────────────────────────────
_engine: Engine | None = None

def engine() -> Engine:
    global _engine
    if _engine is None:
        url = _env("DATABASE_URL") or "sqlite:///tracking.db"
        # Heroku/Render-style URLs say postgres:// — SQLAlchemy wants postgresql+psycopg://
        if url.startswith("postgres://"):
            url = "postgresql+psycopg://" + url[len("postgres://"):]
        elif url.startswith("postgresql://"):
            url = "postgresql+psycopg://" + url[len("postgresql://"):]
        _engine = create_engine(url, pool_pre_ping=True, future=True)
        _migrate(_engine)
    return _engine

def reset_engine_for_tests(url: str) -> None:
    global _engine
    _engine = create_engine(url, future=True)
    _migrate(_engine)

def _migrate(e: Engine) -> None:
    with e.begin() as c:
        c.execute(text("""
            CREATE TABLE IF NOT EXISTS tracked_users (
                user_id        TEXT PRIMARY KEY,
                refresh_enc    TEXT NOT NULL,
                enrolled_at    TEXT NOT NULL,
                last_polled_at TEXT,
                status         TEXT NOT NULL DEFAULT 'active',
                fail_count     INTEGER NOT NULL DEFAULT 0,
                gaps           INTEGER NOT NULL DEFAULT 0
            )"""))
        c.execute(text("""
            CREATE TABLE IF NOT EXISTS plays (
                user_id     TEXT NOT NULL,
                played_at   TEXT NOT NULL,
                track_uri   TEXT,
                track_name  TEXT,
                artists     TEXT,
                album       TEXT,
                album_image TEXT,
                duration_ms INTEGER,
                PRIMARY KEY (user_id, played_at)
            )"""))


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ── Spotify helpers ───────────────────────────────────────────────────────────
def _basic_header() -> str:
    cid, sec = _env("SPOTIFY_CLIENT_ID"), _env("SPOTIFY_CLIENT_SECRET")
    return "Basic " + base64.b64encode(f"{cid}:{sec}".encode()).decode()

def _exchange_refresh(refresh_token: str) -> tuple[str | None, str | None, int]:
    """→ (access_token, rotated_refresh_token_or_None, http_status)."""
    r = requests.post(
        SPOTIFY_TOKEN_URL,
        headers={"Authorization": _basic_header()},
        data={"grant_type": "refresh_token", "refresh_token": refresh_token},
        timeout=10,
    )
    if not r.ok:
        return None, None, r.status_code
    d = r.json()
    return d.get("access_token"), d.get("refresh_token"), 200

def _me_id(access_token: str) -> tuple[str | None, int]:
    """→ (user_id, status). Status is 401 only when the token itself is bad; a Spotify
    outage or rate limit is 502, so the app doesn't sign the user out over it."""
    try:
        r = requests.get(f"{SPOTIFY_API}/me", headers={"Authorization": f"Bearer {access_token}"}, timeout=10)
    except requests.RequestException:
        return None, 502
    if not r.ok:
        return None, 401 if r.status_code in (400, 401, 403) else 502
    return r.json().get("id"), 200

# Bearer → Spotify user id, cached briefly so the plays feed doesn't hit /me every call.
_id_cache: dict[str, tuple[str, float]] = {}

def _caller_id() -> tuple[str | None, int]:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, 401
    token = auth[len("Bearer "):].strip()
    key = hashlib.sha256(token.encode()).hexdigest()
    hit = _id_cache.get(key)
    if hit and hit[1] > time.time():
        return hit[0], 200
    uid, status = _me_id(token)
    if uid:
        _id_cache[key] = (uid, time.time() + 600)
        if len(_id_cache) > 2000:
            _id_cache.clear()
    return uid, status

def _auth_error(st: int):
    if st == 401:
        return jsonify({"error": "Not authenticated."}), 401
    return jsonify({"error": "Spotify is unavailable — try again shortly."}), 502

def _fetch_recent(access_token: str) -> tuple[list[dict], int]:
    r = requests.get(
        f"{SPOTIFY_API}/me/player/recently-played?limit=50",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=15,
    )
    if not r.ok:
        return [], r.status_code
    out = []
    for it in r.json().get("items", []):
        tr = it.get("track") or {}
        al = tr.get("album") or {}
        imgs = al.get("images") or []
        out.append({
            "played_at":   it.get("played_at"),
            "track_uri":   tr.get("uri"),
            "track_name":  tr.get("name"),
            "artists":     json.dumps([a.get("name") for a in tr.get("artists", [])]),
            "album":       al.get("name"),
            "album_image": (imgs[-1] if imgs else {}).get("url"),   # smallest image
            "duration_ms": tr.get("duration_ms"),
        })
    return [p for p in out if p["played_at"]], 200


class UserGone(Exception):
    """The user was deleted (opted out) during their poll."""


# ── core ──────────────────────────────────────────────────────────────────────
def save_plays(conn, user_id: str, plays: list[dict]) -> int:
    """Insert plays, ignoring ones already stored. Returns how many were new."""
    if not plays:
        return 0
    existing = {
        row[0] for row in conn.execute(
            text("SELECT played_at FROM plays WHERE user_id = :u AND played_at >= :lo"),
            {"u": user_id, "lo": min(p["played_at"] for p in plays)},
        )
    }
    new = [dict(p, user_id=user_id) for p in plays if p["played_at"] not in existing]
    if new:
        conn.execute(text("""
            INSERT INTO plays (user_id, played_at, track_uri, track_name, artists, album, album_image, duration_ms)
            VALUES (:user_id, :played_at, :track_uri, :track_name, :artists, :album, :album_image, :duration_ms)
            ON CONFLICT (user_id, played_at) DO NOTHING
        """), new)
    return len(new)

def poll_user(conn, row) -> dict:
    """Refresh one user's token and save their newest plays."""
    uid = row.user_id
    try:
        rt = _decrypt(row.refresh_enc)
    except Exception:
        conn.execute(text("UPDATE tracked_users SET status='error' WHERE user_id=:u"), {"u": uid})
        return {"user": uid, "error": "decrypt"}

    access, rotated, st = _exchange_refresh(rt)
    if not access:
        # 400/401 = the user revoked access → pause after repeated failures. A Spotify
        # outage or rate limit (429/5xx) says nothing about the user, so it doesn't count.
        if st in (400, 401):
            fails = (row.fail_count or 0) + 1
            conn.execute(
                text("UPDATE tracked_users SET fail_count=:f, status=:s WHERE user_id=:u"),
                {"f": fails, "s": "paused" if fails >= MAX_FAILS else "active", "u": uid},
            )
        return {"user": uid, "error": f"refresh {st}"}

    # Store a rotated token now: the old one may already be dead if the fetch below fails.
    if rotated:
        kept = conn.execute(
            text("UPDATE tracked_users SET refresh_enc=:enc WHERE user_id=:u"),
            {"enc": _encrypt(rotated), "u": uid},
        ).rowcount
        if not kept:
            return {"user": uid, "gone": True}

    plays, st = _fetch_recent(access)
    if st != 200:
        return {"user": uid, "error": f"recent {st}"}

    # A full page whose oldest play is newer than everything we hold means plays
    # may have rolled off between polls — count it so it's visible in /status.
    newest_held = conn.execute(
        text("SELECT MAX(played_at) FROM plays WHERE user_id=:u"), {"u": uid}
    ).scalar()
    gap = bool(newest_held and len(plays) == 50 and min(p["played_at"] for p in plays) > newest_held)

    added = save_plays(conn, uid, plays)
    kept = conn.execute(text("""
        UPDATE tracked_users
           SET last_polled_at=:t, fail_count=0, status='active', gaps=gaps + :g
         WHERE user_id=:u
    """), {"t": _now_iso(), "g": 1 if gap else 0, "u": uid}).rowcount
    if not kept:
        # The user opted out while we were polling: roll back the plays we just saved.
        raise UserGone(uid)
    return {"user": uid, "added": added, "gap": gap}


# ── routes ────────────────────────────────────────────────────────────────────
def _disabled():
    return jsonify({"error": "Listening tracking isn't switched on for this server yet."}), 503

@bp.post("/api/tracking/enroll")
@rate_limit("enroll", 10, 60)
def enroll():
    if not enabled():
        return _disabled()
    body = request.get_json(silent=True) or {}
    rt = (body.get("refresh_token") or "").strip()
    if not rt:
        return jsonify({"error": "refresh_token required"}), 400
    # Identity comes from the token itself — you can only ever enroll yourself.
    access, rotated, st = _exchange_refresh(rt)
    if not access:
        return jsonify({"error": "Spotify rejected the token — reconnect and try again."}), 401
    uid, st = _me_id(access)
    if not uid:
        return jsonify({"error": "Couldn't read your Spotify profile."}), st or 502
    keep = rotated or rt
    with engine().begin() as c:
        c.execute(text("DELETE FROM tracked_users WHERE user_id=:u"), {"u": uid})
        c.execute(text("""
            INSERT INTO tracked_users (user_id, refresh_enc, enrolled_at, status, fail_count, gaps)
            VALUES (:u, :enc, :t, 'active', 0, 0)
        """), {"u": uid, "enc": _encrypt(keep), "t": _now_iso()})
        # Backfill the 50 plays Spotify still remembers, right away.
        plays, _ = _fetch_recent(access)
        added = save_plays(c, uid, plays)
        c.execute(text("UPDATE tracked_users SET last_polled_at=:t WHERE user_id=:u"), {"t": _now_iso(), "u": uid})
    return jsonify({"enrolled": True, "backfilled": added, "refresh_token": rotated})

@bp.get("/api/tracking/status")
@rate_limit("tracking", 120, 60)
def status():
    if not enabled():
        return jsonify({"available": False, "enrolled": False})
    uid, st = _caller_id()
    if not uid:
        return _auth_error(st)
    with engine().connect() as c:
        u = c.execute(text("SELECT * FROM tracked_users WHERE user_id=:u"), {"u": uid}).first()
        if not u:
            return jsonify({"available": True, "enrolled": False})
        n, first, last = c.execute(
            text("SELECT COUNT(*), MIN(played_at), MAX(played_at) FROM plays WHERE user_id=:u"), {"u": uid}
        ).first()
    return jsonify({
        "available": True, "enrolled": True, "status": u.status,
        "enrolled_at": u.enrolled_at, "last_polled_at": u.last_polled_at,
        "plays": n, "first_play": first, "last_play": last, "gaps": u.gaps,
    })

@bp.get("/api/tracking/plays")
@rate_limit("tracking", 120, 60)
def plays():
    if not enabled():
        return _disabled()
    uid, st = _caller_id()
    if not uid:
        return _auth_error(st)
    after = (request.args.get("after") or "").strip()
    try:
        limit = max(1, min(int(request.args.get("limit", PLAYS_PAGE_MAX)), PLAYS_PAGE_MAX))
    except ValueError:
        limit = PLAYS_PAGE_MAX
    with engine().connect() as c:
        rows = c.execute(text("""
            SELECT played_at, track_uri, track_name, artists, album, album_image, duration_ms
              FROM plays
             WHERE user_id=:u AND played_at > :a
             ORDER BY played_at ASC
             LIMIT :l
        """), {"u": uid, "a": after or "", "l": limit}).all()
    items = [{
        "played_at": r.played_at, "uri": r.track_uri, "name": r.track_name,
        "artists": json.loads(r.artists or "[]"), "album": r.album,
        "image": r.album_image, "duration_ms": r.duration_ms,
    } for r in rows]
    return jsonify({"items": items, "more": len(items) == limit})

@bp.delete("/api/tracking")
@rate_limit("tracking", 120, 60)
def unenroll():
    if not enabled():
        return _disabled()
    uid, st = _caller_id()
    if not uid:
        return _auth_error(st)
    with engine().begin() as c:
        c.execute(text("DELETE FROM plays WHERE user_id=:u"), {"u": uid})
        c.execute(text("DELETE FROM tracked_users WHERE user_id=:u"), {"u": uid})
    return jsonify({"enrolled": False, "deleted": True})

@bp.post("/api/tracking/poll")
def poll():
    if not enabled():
        return _disabled()
    sent = request.headers.get("X-Cron-Secret", "")
    if not hmac.compare_digest(sent, _env("CRON_SECRET")):
        return jsonify({"error": "forbidden"}), 403
    results = []
    with engine().connect() as c:
        users = c.execute(text("SELECT * FROM tracked_users WHERE status='active'")).all()
    for u in users:
        # One transaction per user, so one bad account can't roll back the rest.
        try:
            with engine().begin() as c:
                results.append(poll_user(c, u))
        except UserGone:
            results.append({"user": u.user_id, "gone": True})
        except Exception as e:  # noqa: BLE001 — log and keep polling everyone else
            results.append({"user": u.user_id, "error": type(e).__name__})
    errors = sum(1 for r in results if "error" in r)
    body = {"polled": len(results), "added": sum(r.get("added", 0) for r in results), "errors": errors}
    # Every user failing means the server or Spotify is broken: fail so the workflow shows red.
    return jsonify(body), 502 if results and errors == len(results) else 200
