"""WARDEN's outbound HTTP calls - GitHub, Slack, Datadog, Grafana, SonarCloud, AWS's documentation, a deployment
package, a webhook, Alertmanager - through openers that speak https only and whose redirects cannot carry a
credential to another host.

`urllib.request.urlopen` opens whatever scheme it is handed - `file:`, `ftp:`, `data:` (bandit B310) - and follows a
3xx to wherever it points, and CPython's `HTTPRedirectHandler.redirect_request` copies every request header to the new
address except Content-Length and Content-Type: the Authorization or DD-API-KEY header goes along, whatever the new
host. A misconfigured address, a compromised or spoofed endpoint, or a proxy in the path that answers with a redirect
would receive the credential. So here:

- `urlopen`: https only. A non-https address is refused before any connection, as `urllib.error.URLError`. The
  opener has no handler for any other scheme.
- `urlopen_loopback`: as `urlopen`, and also plain http to this machine (127.0.0.1, localhost, ::1) - a local relay,
  an Alertmanager on the same host, a test's local server - and nowhere else.
- A redirect is followed only to the same scheme, host and port: the server the call was made to. Any other redirect
  - another host, another port, plain http - is refused as `urllib.error.HTTPError` with the redirect's own status,
  which every caller already reads as a failed read ("not read"), never as a success. The header is never stripped
  and the redirect followed anyway: a call answered from somewhere else did not reach what it was meant for.

A credential in a POST body is not carried by a redirect: CPython follows a POST only on 301/302/303, as a GET without
the body, and refuses 307/308. Proxies are honoured as urllib's own opener honours them (HTTPS_PROXY, NO_PROXY).
"""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from typing import Any

_HTTPS_PORT = 443
_HTTP_PORT = 80
LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1"})
REFUSED = "a redirect to another host, port or scheme was refused"


def allowed(url: str, *, loopback_http: bool = False) -> bool:
    """https anywhere; plain http only to this machine, and only when `loopback_http`."""
    parts = urllib.parse.urlsplit(url)
    scheme = parts.scheme.lower()
    return scheme == "https" or (loopback_http and scheme == "http" and parts.hostname in LOOPBACK)


def _origin(url: str) -> tuple[str, str, int]:
    parts = urllib.parse.urlsplit(url)  # .hostname is lowercased; .port raises ValueError on a malformed port
    scheme = parts.scheme.lower()
    default = _HTTP_PORT if scheme == "http" else _HTTPS_PORT
    return scheme, parts.hostname or "", default if parts.port is None else parts.port


def same_origin(url: str, other: str, *, loopback_http: bool = False) -> bool:
    """Both https, to the same host and port (443 when none is named) - or, when `loopback_http`, both plain http to
    the same port on the same loopback name (80 when none is named)."""
    try:
        first, second = _origin(url), _origin(other)
    except ValueError:
        return False
    if first != second or not first[1]:
        return False
    return first[0] == "https" or (loopback_http and first[0] == "http" and first[1] in LOOPBACK)


class _Redirects(urllib.request.HTTPRedirectHandler):
    """A redirect is followed only to the server the request was made to, over the same scheme; any other is
    refused."""

    def __init__(self, loopback_http: bool = False) -> None:
        self.loopback_http = loopback_http

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # `newurl` is already absolute here: urllib joins a relative Location to the request's URL before this call.
        if not same_origin(req.full_url, newurl, loopback_http=self.loopback_http):
            raise urllib.error.HTTPError(req.full_url, code, REFUSED, headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _opener(loopback_http: bool = False) -> urllib.request.OpenerDirector:
    """urllib's own handlers for https (and plain http when `loopback_http`), with the redirect handler above and no
    handler for any other scheme."""
    opener = urllib.request.OpenerDirector()
    handlers: list[urllib.request.BaseHandler] = [
        urllib.request.ProxyHandler(), urllib.request.UnknownHandler(), urllib.request.HTTPSHandler(),
        urllib.request.HTTPDefaultErrorHandler(), _Redirects(loopback_http), urllib.request.HTTPErrorProcessor()]
    if loopback_http:
        handlers.append(urllib.request.HTTPHandler())
    for handler in handlers:
        opener.add_handler(handler)
    return opener


_HTTPS = _opener()
_LOOPBACK = _opener(loopback_http=True)


def _url(request: str | urllib.request.Request) -> str:
    return request.full_url if isinstance(request, urllib.request.Request) else request


def urlopen(request: str | urllib.request.Request, *, timeout: float) -> Any:
    """`urllib.request.urlopen` for an https address only, whose redirects stay on that server."""
    if not allowed(_url(request)):
        raise urllib.error.URLError("refused: not an https address")
    return _HTTPS.open(request, timeout=timeout)


def urlopen_loopback(request: str | urllib.request.Request, *, timeout: float) -> Any:
    """As `urlopen`, and also plain http to this machine; its redirects stay on that server too."""
    if not allowed(_url(request), loopback_http=True):
        raise urllib.error.URLError("refused: neither https nor this machine")
    return _LOOPBACK.open(request, timeout=timeout)
