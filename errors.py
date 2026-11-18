"""
App error reports (2.0) — the mobile app's crash + error log, stored next to the tracker.

  POST   /api/errors   (Bearer)   {errors: [{at, message, stack?, fatal?, version?,
                                   update?, platform?, screen?}]}  → {saved}
  GET    /api/errors   (Bearer)   ?limit=N  → your reports, newest first
  DELETE /api/errors   (Bearer)   clear your reports

Every call needs a valid Spotify Bearer token (the same check the tracker uses), so
reports are tied to a Spotify account and nobody else can write into the table. Each
user keeps at most MAX_PER_USER reports (oldest dropped). Uses tracking.engine(), i.e.
DATABASE_URL (Neon in production, a local SQLite file in development).
"""
from __future__ import annotations

import uuid

from flask import Blueprint, jsonify, request
from sqlalchemy import text

import tracking

bp = Blueprint("errors", __name__)

MAX_BATCH    = 50
MAX_PER_USER = 500
LIMITS = {"message": 2000, "stack": 8000, "version": 40, "update": 80, "platform": 40, "screen": 120}

_migrated: set[int] = set()

def _db():
    e = tracking.engine()
    if id(e) not in _migrated:
        with e.begin() as c:
            c.execute(text("""
                CREATE TABLE IF NOT EXISTS app_errors (
                    id          TEXT PRIMARY KEY,
                    user_id     TEXT NOT NULL,
                    at          TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    fatal       INTEGER NOT NULL DEFAULT 0,
                    message     TEXT NOT NULL,
                    stack       TEXT,
                    version     TEXT,
                    update_id   TEXT,
                    platform    TEXT,
                    screen      TEXT
                )"""))
            c.execute(text("CREATE INDEX IF NOT EXISTS app_errors_user_at ON app_errors (user_id, at)"))
        _migrated.add(id(e))
    return e

def _clip(v, n: int) -> str | None:
    if v is None:
        return None
    s = str(v)
    return s[:n]


@bp.post("/api/errors")
def post_errors():
    uid, status = tracking._caller_id()
    if not uid:
        return jsonify({"error": "unauthorized"}), 401 if status in (401, 403) else 502
    body = request.get_json(silent=True) or {}
    items = body.get("errors")
    if not isinstance(items, list):
        return jsonify({"error": "errors must be a list"}), 400
    rows = []
    now = tracking._now_iso()
    for it in items[:MAX_BATCH]:
        if not isinstance(it, dict) or not it.get("message"):
            continue
        rows.append({
            "id": uuid.uuid4().hex, "u": uid,
            "at": _clip(it.get("at") or now, 40), "rcv": now,
            "fatal": 1 if it.get("fatal") else 0,
            "message":  _clip(it.get("message"), LIMITS["message"]),
            "stack":    _clip(it.get("stack"), LIMITS["stack"]),
            "version":  _clip(it.get("version"), LIMITS["version"]),
            "update":   _clip(it.get("update"), LIMITS["update"]),
            "platform": _clip(it.get("platform"), LIMITS["platform"]),
            "screen":   _clip(it.get("screen"), LIMITS["screen"]),
        })
    if rows:
        with _db().begin() as c:
            c.execute(text("""
                INSERT INTO app_errors (id, user_id, at, received_at, fatal, message, stack, version, update_id, platform, screen)
                VALUES (:id, :u, :at, :rcv, :fatal, :message, :stack, :version, :update, :platform, :screen)"""), rows)
            # Keep the newest MAX_PER_USER per user.
            c.execute(text("""
                DELETE FROM app_errors WHERE user_id = :u AND id NOT IN (
                    SELECT id FROM app_errors WHERE user_id = :u ORDER BY at DESC LIMIT :keep
                )"""), {"u": uid, "keep": MAX_PER_USER})
    return jsonify({"saved": len(rows)})


@bp.get("/api/errors")
def get_errors():
    uid, status = tracking._caller_id()
    if not uid:
        return jsonify({"error": "unauthorized"}), 401 if status in (401, 403) else 502
    try:
        limit = max(1, min(int(request.args.get("limit", 100)), MAX_PER_USER))
    except ValueError:
        limit = 100
    with _db().connect() as c:
        res = c.execute(text("""
            SELECT at, fatal, message, stack, version, update_id, platform, screen
            FROM app_errors WHERE user_id = :u ORDER BY at DESC LIMIT :n"""), {"u": uid, "n": limit})
        items = [{
            "at": r[0], "fatal": bool(r[1]), "message": r[2], "stack": r[3],
            "version": r[4], "update": r[5], "platform": r[6], "screen": r[7],
        } for r in res]
    return jsonify({"items": items})


@bp.delete("/api/errors")
def delete_errors():
    uid, status = tracking._caller_id()
    if not uid:
        return jsonify({"error": "unauthorized"}), 401 if status in (401, 403) else 502
    with _db().begin() as c:
        n = c.execute(text("DELETE FROM app_errors WHERE user_id = :u"), {"u": uid}).rowcount
    return jsonify({"deleted": n})
