"""Privacy page and self-hosted fonts: the pages must not send visitors to Google Fonts."""
import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, ROOT)

from app import app  # noqa: E402


@pytest.fixture
def client(monkeypatch):
    monkeypatch.chdir(ROOT)   # "/" and "/privacy" read their HTML relative to the cwd
    return app.test_client()


def test_privacy_page_served(client):
    r = client.get("/privacy")
    assert r.status_code == 200
    assert r.content_type.startswith("text/html")
    body = r.get_data(as_text=True)
    assert "Privacy policy" in body
    assert "github.com/ItsAstroDude/playlist-lens-web/issues" in body


def test_pages_link_to_privacy(client):
    assert 'href="/privacy"' in client.get("/").get_data(as_text=True)


@pytest.mark.parametrize("path", ["/", "/privacy"])
def test_no_google_fonts(client, path):
    body = client.get(path).get_data(as_text=True)
    assert "fonts.googleapis.com" not in body and "fonts.gstatic.com" not in body
    assert "/static/fonts/fonts.css" in body


def test_csp_has_no_google_fonts(client):
    csp = client.get("/").headers["Content-Security-Policy"]
    assert "googleapis" not in csp and "gstatic" not in csp
    assert "font-src 'self'" in csp


def test_every_font_file_in_css_is_served(client):
    css = client.get("/static/fonts/fonts.css")
    assert css.status_code == 200
    files = set(re.findall(r"url\(([^)]+\.woff2)\)", css.get_data(as_text=True)))
    assert files
    for f in files:
        assert client.get(f"/static/fonts/{f}").status_code == 200, f
