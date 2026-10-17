"""WARDEN's own outbound HTTP calls - Slack, GitHub, Datadog, Grafana, AWS's documentation, a deployment package, a
webhook - through openers that can only speak https.

`urllib.request.urlopen` opens whatever scheme it is handed - `file:`, `ftp:`, `data:` - and follows a redirect from
https to plain http or ftp (bandit B310). Every caller checked its own URL first, each its own way; the checks now live
here, once, and they hold after a redirect too:

- `urlopen`: https only. An opener with no handler for any other scheme, whose redirects go to https only.
- `urlopen_loopback`: also plain http to this machine (127.0.0.1, localhost, ::1) - a local relay, an Alertmanager on
  the same host, a test's local server - and nowhere else.

Anything else is refused before a connection is made, as `urllib.error.URLError` (an `OSError`), which every caller
already handles as a failed call. Proxies are honoured as urllib's own opener honours them (HTTPS_PROXY, NO_PROXY).
"""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from typing import Any

LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1"})


def allowed(url: str, *, loopback_http: bool = False) -> bool:
    """https anywhere; plain http only to this machine, and only when `loopback_http`."""
    parts = urllib.parse.urlsplit(url)
    scheme = parts.scheme.lower()
    return scheme == "https" or (loopback_http and scheme == "http" and parts.hostname in LOOPBACK)


class _Redirects(urllib.request.HTTPRedirectHandler):
    """A redirect is followed only to an address the first one could have been."""

    def __init__(self, loopback_http: bool) -> None:
        self.loopback_http = loopback_http

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not allowed(newurl, loopback_http=self.loopback_http):
            raise urllib.error.HTTPError(req.full_url, code, "a redirect away from https was refused", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _opener(loopback_http: bool) -> urllib.request.OpenerDirector:
    opener = urllib.request.OpenerDirector()
    handlers: list[urllib.request.BaseHandler] = [
        urllib.request.ProxyHandler(), urllib.request.UnknownHandler(), urllib.request.HTTPSHandler(),
        urllib.request.HTTPDefaultErrorHandler(), _Redirects(loopback_http), urllib.request.HTTPErrorProcessor()]
    if loopback_http:
        handlers.append(urllib.request.HTTPHandler())
    for handler in handlers:
        opener.add_handler(handler)
    return opener


_HTTPS = _opener(loopback_http=False)
_LOOPBACK = _opener(loopback_http=True)


def _url(request: str | urllib.request.Request) -> str:
    return request.full_url if isinstance(request, urllib.request.Request) else request


def urlopen(request: str | urllib.request.Request, *, timeout: float) -> Any:
    """`urllib.request.urlopen` for an https address only; anything else is a URLError before any connection."""
    if not allowed(_url(request)):
        raise urllib.error.URLError("refused: not an https address")
    return _HTTPS.open(request, timeout=timeout)


def urlopen_loopback(request: str | urllib.request.Request, *, timeout: float) -> Any:
    """As `urlopen`, and also plain http to this machine."""
    if not allowed(_url(request), loopback_http=True):
        raise urllib.error.URLError("refused: neither https nor this machine")
    return _LOOPBACK.open(request, timeout=timeout)
