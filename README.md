<div align="center">

```
playlist.lens
```

**Spotify playlist analytics. See what your music actually looks like.**

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.1-000000?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![Spotify API](https://img.shields.io/badge/Spotify_API-1DB954?style=flat-square&logo=spotify&logoColor=white)](https://developer.spotify.com)
[![Deployed on Render](https://img.shields.io/badge/Deployed_on-Render-46E3B7?style=flat-square&logo=render&logoColor=white)](https://playlist-lens-mobile.onrender.com)
[![License](https://img.shields.io/badge/License-MIT-090910?style=flat-square)](LICENSE)

[**→ Open the app**](https://playlist-lens-mobile.onrender.com) · [**Mobile version**](https://github.com/ItsAstroDude/playlist-lens-mobile)

</div>

---

## What it does

playlist.lens connects to your Spotify account and breaks down every playlist you own — artists, genres, decades, audio profile, popularity spread, and a computed "vibe" label. All in one dark, clean interface.

No third-party data collection. Tokens stay in your session. Analysis runs on your own Spotify data.

---

## Features

| Section | What you get |
|---|---|
| **Playlists** | Full grid of your playlists with cover art, search & sort |
| **Breakdown** | Top artists · Genre cloud · Decade distribution · Popularity buckets |
| **Audio Profile** | Danceability, energy, valence, acousticness, liveness, BPM *(where available)* |
| **Vibe label** | One-line character summary computed from audio features or genre keywords |
| **Compare** | Side-by-side stats for any two playlists |
| **Taste Profile** | Aggregate view across all your playlists combined |
| **Friends** | Share a 6-character code · Load a friend's profile without them logging in |

---

## Tech stack

```
Backend     Flask 3.1 · Python 3.11 · Gunicorn
Auth        Spotify OAuth 2.0 (PKCE-safe, CSRF state param)
Frontend    Vanilla JS · Chart.js 4 · Syne + DM Mono (Google Fonts)
Deployment  Render (free tier, auto-deploy from GitHub)
```

The entire frontend lives as a single `index.html` served by Flask — no build step, no bundler, no framework.

---

## Self-hosting

### 1. Clone & install

```bash
git clone https://github.com/ItsAstroDude/playlist-lens-web.git
cd playlist-lens-web
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Create a Spotify app

1. Go to [developer.spotify.com/dashboard](https://developer.spotify.com/dashboard)
2. Create an app — note your **Client ID** and **Client Secret**
3. Add `http://localhost:8888/callback` as a Redirect URI
4. Save

### 3. Set environment variables

```bash
export SPOTIFY_CLIENT_ID=your_client_id
export SPOTIFY_CLIENT_SECRET=your_client_secret
export REDIRECT_URI=http://localhost:8888/callback
export SECRET_KEY=any_random_string
```

### 4. Run

```bash
python app.py
# → http://localhost:8888
```

---

## Deploying to Render

1. Push this repo to GitHub
2. New Web Service → connect the repo
3. **Build command**: `pip install -r requirements.txt`
4. **Start command**: `gunicorn app:app`
5. Add environment variables in the Render dashboard:
   - `SPOTIFY_CLIENT_ID`
   - `SPOTIFY_CLIENT_SECRET`
   - `REDIRECT_URI` → set to `https://your-app.onrender.com/callback`
   - `SECRET_KEY` → any long random string
6. Add your Render callback URL to the Spotify app's Redirect URIs

> **Note:** The free Render tier spins down after inactivity — first load after a cold start takes ~10s. The app shows a "waking up" indicator during this time.

---

## API routes

| Method | Route | Description |
|---|---|---|
| `GET` | `/login` | Initiates Spotify OAuth (supports `?mobile=true`) |
| `GET` | `/callback` | OAuth callback — exchanges code for tokens |
| `GET` | `/api/me` | Returns the authenticated Spotify user |
| `GET` | `/api/playlists` | Returns all user playlists (up to 50) |
| `GET` | `/api/playlist/:id/tracks` | Returns tracks for a playlist (up to 500) |
| `GET` | `/api/artists?ids=` | Batch artist lookup (genres, metadata) |
| `GET` | `/api/audio-features?ids=` | Batch audio features (gracefully returns empty if deprecated) |
| `POST` | `/api/profile/save` | Saves a taste profile, returns a share code |
| `GET` | `/api/profile/load/:code` | Loads a saved taste profile by code |

---

## Notes

- **Audio features** (danceability, energy, etc.) are only available for Spotify apps registered before November 2024. If your app was registered after that date, the endpoint returns an empty list and playlist.lens falls back to genre-based vibe classification.
- Large playlists are capped at 500 tracks for API performance. Stats display the real Spotify total; analysis is based on the sampled tracks.

---

<div align="center">
<sub>Built with Flask · Spotify Web API · a lot of DM Mono</sub>
</div>
