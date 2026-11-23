"""
Security helpers shared by the routes: rate limiting, response headers, input checks,
and the share-profile sanitiser.

Kept dependency-free on purpose. The rate limiter is in-memory, which is correct for
this deployment (one gunicorn worker, see Procfile); if that ever becomes several
workers or instances, each keeps its own counts, so limits loosen but still hold.
"""
from __future__ import annotations

import ipaddress
import math
import re
import threading
import time
from collections import deque
from functools import wraps

from flask import jsonify, request

# ── rate limiting ─────────────────────────────────────────────────────────────
# Limits are per client IP and deliberately generous: phone carriers put many people
# behind one IP (CGNAT), so these only stop scripts, never a person tapping around.
_hits: dict[tuple[str, str], deque] = {}
_lock = threading.Lock()
_MAX_KEYS = 50_000


def _client_ip() -> str:
    # With ProxyFix installed (production), remote_addr is the real client.
    return request.remote_addr or "?"


def rate_limit(bucket: str, limit: int, per_seconds: int):
    """Allow `limit` calls per `per_seconds` per client IP for this route; 429 beyond."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            key, now = (bucket, _client_ip()), time.monotonic()
            with _lock:
                q = _hits.get(key)
                if q is None:
                    if len(_hits) >= _MAX_KEYS:
                        _hits.clear()
                    q = _hits[key] = deque()
                while q and q[0] <= now - per_seconds:
                    q.popleft()
                if len(q) >= limit:
                    retry = max(1, int(q[0] + per_seconds - now) + 1)
                    resp = jsonify({"error": "Too many requests. Wait a moment and try again."})
                    resp.status_code = 429
                    resp.headers["Retry-After"] = str(retry)
                    return resp
                q.append(now)
            return fn(*a, **kw)
        return wrapper
    return deco


def reset_rate_limits() -> None:
    with _lock:
        _hits.clear()


# ── response headers ──────────────────────────────────────────────────────────
# index.html relies on inline <script> and onclick handlers, so script-src needs
# 'unsafe-inline'; the CSP still blocks framing, plugins, <base> hijacks, form posts
# to other sites, and fetch/XHR to anywhere but this server.
CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
    "style-src 'self' 'unsafe-inline'",
    "font-src 'self'",                       # fonts are self-hosted (static/fonts)
    "img-src 'self' data: https:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
])


def apply_security_headers(resp, production: bool):
    h = resp.headers
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("X-Frame-Options", "DENY")
    h.setdefault("Referrer-Policy", "no-referrer")
    h.setdefault("Content-Security-Policy", CSP)
    if production:
        h.setdefault("Strict-Transport-Security", "max-age=31536000")
    if request.path.startswith("/api/") or request.path in ("/callback", "/login"):
        h.setdefault("Cache-Control", "no-store")
    return resp


# ── input checks ──────────────────────────────────────────────────────────────
_SPOTIFY_ID_RE = re.compile(r"^[A-Za-z0-9]{1,64}$")
_ISRC_RE       = re.compile(r"^[A-Za-z0-9]{12}$")


def is_spotify_id(v: str) -> bool:
    return bool(_SPOTIFY_ID_RE.match(v or ""))


def spotify_id_list(raw: str, cap: int = 100) -> str | None:
    """'id1,id2,…' with only base-62 ids, or None if any piece isn't one."""
    parts = [p.strip() for p in (raw or "").split(",") if p.strip()]
    if not parts or len(parts) > cap or not all(is_spotify_id(p) for p in parts):
        return None
    return ",".join(parts)


def is_isrc(v: str) -> bool:
    return bool(_ISRC_RE.match(v or ""))


def is_private_host(host: str) -> bool:
    """localhost / loopback / LAN address: where an Expo Go dev server actually runs."""
    host = (host or "").strip("[]").lower()
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback


# ── share profiles ────────────────────────────────────────────────────────────
# Anyone can save a profile and anyone with the code loads it, so it's untrusted input
# served to another person. Keep only the fields the apps use, with the right types.
# The web app sends topGenres as [genre, count] pairs; mobile sends {genre, count}.
MAX_PROFILE_BYTES = 64 * 1024
_AF_KEYS = ("danceability", "energy", "valence", "acousticness",
            "instrumentalness", "liveness", "avgTempo")


def _s(v, n: int) -> str | None:
    return v[:n] if isinstance(v, str) else None


def _num(v, lo: float = 0, hi: float = 1e9) -> float | int | None:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
        return None
    v = min(hi, max(lo, v))
    return int(v) if float(v).is_integer() else v


def sanitize_profile(data) -> dict | None:
    if not isinstance(data, dict):
        return None
    out: dict = {}
    for k in ("version", "trackCount", "playlistCount", "artistCount"):
        if k in data:
            out[k] = _num(data[k]) or 0
    out["name"] = _s(data.get("name"), 80) or "Someone"
    out["vibe"] = _s(data.get("vibe"), 80)
    if "generatedAt" in data:
        out["generatedAt"] = _s(data.get("generatedAt"), 40)

    artists = []
    for a in data.get("topArtists") if isinstance(data.get("topArtists"), list) else []:
        if isinstance(a, dict) and isinstance(a.get("name"), str):
            item = {"name": a["name"][:120], "count": _num(a.get("count")) or 0}
            if isinstance(a.get("id"), str):
                item["id"] = a["id"][:64]
            artists.append(item)
        if len(artists) >= 100:
            break
    out["topArtists"] = artists

    genres: list = []
    for g in data.get("topGenres") if isinstance(data.get("topGenres"), list) else []:
        if isinstance(g, list) and len(g) == 2 and isinstance(g[0], str):
            genres.append([g[0][:80], _num(g[1]) or 0])
        elif isinstance(g, dict) and isinstance(g.get("genre"), str):
            genres.append({"genre": g["genre"][:80], "count": _num(g.get("count")) or 0})
        if len(genres) >= 100:
            break
    out["topGenres"] = genres

    af = data.get("af")
    if isinstance(af, dict):
        clean = {k: _num(af.get(k), 0, 1000) for k in _AF_KEYS if k in af}
        out["af"] = {k: v for k, v in clean.items() if v is not None} or None
    else:
        out["af"] = None
    return out
