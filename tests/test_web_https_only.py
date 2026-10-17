"""WARDEN's outbound calls speak https only (hidden warnings, owner 2026-10-17: bandit B310 was silenced at 15 call
sites, each with its own scheme check). warden.web holds the rule once, and after a redirect too: an opener with no
handler for file:, ftp:, data: or plain http, and loopback http only where a caller asks for it."""

from __future__ import annotations

import http.server
import threading
import urllib.error
import urllib.request

import pytest

from warden import web


@pytest.mark.parametrize("url, https_only, loopback", [
    ("https://slack.com/api/x", True, True),
    ("HTTPS://api.github.com", True, True),
    ("http://127.0.0.1:9093/api", False, True),
    ("http://localhost/x", False, True),
    ("http://[::1]:8080/x", False, True),
    ("http://hooks.example.test/x", False, False),
    ("http://127.0.0.1.example.test/x", False, False),
    ("file:///etc/passwd", False, False),
    ("ftp://files.example.test/x", False, False),
    ("data:text/plain,hello", False, False),
    ("//no-scheme.example.test", False, False),
])
def test_https_anywhere_and_plain_http_only_to_this_machine_when_asked(url, https_only, loopback):
    assert web.allowed(url) is https_only
    assert web.allowed(url, loopback_http=True) is loopback


@pytest.mark.parametrize("url", ["file:///etc/passwd", "http://hooks.example.test/x", "ftp://f.example.test/x",
                                 "data:text/plain,hello"])
def test_anything_but_https_is_refused_before_any_connection(monkeypatch, url):
    opened = []
    monkeypatch.setattr(web._HTTPS, "open", lambda *a, **k: opened.append(a))
    with pytest.raises(urllib.error.URLError, match="refused"):
        web.urlopen(url, timeout=1)
    with pytest.raises(urllib.error.URLError, match="refused"):
        web.urlopen(urllib.request.Request(url), timeout=1)
    assert opened == []


def test_the_openers_have_no_handler_for_another_scheme():
    for opener in (web._HTTPS, web._LOOPBACK):
        for url in ("file:///etc/passwd", "ftp://files.example.test/x", "data:text/plain,hello"):
            with pytest.raises(urllib.error.URLError, match="unknown url type"):
                opener.open(url, timeout=1)
    with pytest.raises(urllib.error.URLError, match="unknown url type"):
        web._HTTPS.open("http://127.0.0.1:9/x", timeout=1)


class _Local(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/away":
            self.send_response(302)
            self.send_header("Location", "http://hooks.example.test/landed")
            self.end_headers()
            return
        if self.path == "/here":
            self.send_response(302)
            self.send_header("Location", "/ok")
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


@pytest.fixture
def local():
    server = http.server.HTTPServer(("127.0.0.1", 0), _Local)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def test_loopback_http_is_spoken_where_asked_and_a_redirect_off_this_machine_is_refused(local, monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setattr(web, "_LOOPBACK", web._opener(loopback_http=True))  # with the NO_PROXY above
    with web.urlopen_loopback(f"{local}/ok", timeout=5) as resp:
        assert resp.read() == b"ok"
    with web.urlopen_loopback(f"{local}/here", timeout=5) as resp:  # a redirect on this machine is followed
        assert resp.read() == b"ok"
    with pytest.raises(urllib.error.HTTPError, match="redirect away from https was refused"):
        web.urlopen_loopback(f"{local}/away", timeout=5)
    with pytest.raises(urllib.error.URLError, match="refused"):
        web.urlopen(f"{local}/ok", timeout=5)  # the https-only opener never speaks plain http, even here


def test_no_outbound_call_in_warden_or_its_scripts_uses_urllibs_own_opener():
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[1]
    files = [*(root / "src" / "warden").rglob("*.py"), root / "scripts" / "bench_approve.py",
             root / "scripts" / "datadog_setup.py"]
    used = [f"{f.relative_to(root)}:{n}" for f in files if f.name != "web.py"
            for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1)
            if re.search(r"\burlopen\s*\(|=\s*urllib\.request\.urlopen\b", line) and "web.urlopen" not in line]
    assert used == []
