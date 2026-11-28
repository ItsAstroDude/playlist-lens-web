"""The mobile login must only hand tokens back to the family's own app schemes."""
from app import _safe_mobile_redirect, MOBILE_SCHEME


def test_app_schemes_allowed():
    for url in ("playlistlens://callback", "soundwave://callback", "exp://192.168.1.5:8081/--/callback",
                "exp+soundwave://expo-development-client/callback"):
        assert _safe_mobile_redirect(url) == url


def test_everything_else_falls_back():
    for url in ("https://evil.example/steal", "http://localhost/x", "javascript:alert(1)", "", "soundwave", "//evil",
                "exp+x://expo-development-client/?url=https://evil.example",          # someone else's dev client
                "exp+soundwave://expo-development-client/?url=https://evil.example",  # loads that server
                "exp://evil.example\\@127.0.0.1/x", "exp://evil.example@192.168.1.5/x"):
        assert _safe_mobile_redirect(url) == MOBILE_SCHEME
