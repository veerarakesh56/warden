"""WARDEN's credentialed outbound HTTP calls - GitHub, Slack, Datadog, Grafana - through one opener whose redirects
cannot carry a credential to another host.

`urllib.request.urlopen` follows a 3xx to wherever it points, and CPython's `HTTPRedirectHandler.redirect_request`
copies every request header to the new address except Content-Length and Content-Type: the Authorization or
DD-API-KEY header goes along, whatever the new host. A misconfigured address, a compromised or spoofed endpoint, or a
proxy in the path that answers with a redirect would receive the credential. So here:

- `urlopen`: https only. A non-https address is refused before any connection, as `urllib.error.URLError`.
- A redirect is followed only to the same scheme, host and port: https, to the server the call was made to. Any other
  redirect - another host, another port, plain http - is refused as `urllib.error.HTTPError` with the redirect's own
  status, which every caller already reads as a failed read ("not read"), never as a success. The header is never
  stripped and the redirect followed anyway: a call answered from somewhere else did not reach what it was meant for.

A credential in a POST body is not carried by a redirect: CPython follows a POST only on 301/302/303, as a GET without
the body, and refuses 307/308. Proxies are honoured as urllib's own opener honours them (HTTPS_PROXY, NO_PROXY).
"""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from typing import Any

_HTTPS_PORT = 443
REFUSED = "a redirect to another host, port or scheme was refused"


def allowed(url: str) -> bool:
    """https only."""
    return urllib.parse.urlsplit(url).scheme.lower() == "https"


def _origin(url: str) -> tuple[str, str, int]:
    parts = urllib.parse.urlsplit(url)  # .hostname is lowercased; .port raises ValueError on a malformed port
    return parts.scheme.lower(), parts.hostname or "", _HTTPS_PORT if parts.port is None else parts.port


def same_origin(url: str, other: str) -> bool:
    """Both https, to the same host and port (443 when none is named)."""
    try:
        first, second = _origin(url), _origin(other)
    except ValueError:
        return False
    return first[0] == "https" and bool(first[1]) and first == second


class _Redirects(urllib.request.HTTPRedirectHandler):
    """A redirect is followed only to the server the request was made to, over https; any other is refused."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # `newurl` is already absolute here: urllib joins a relative Location to the request's URL before this call.
        if not same_origin(req.full_url, newurl):
            raise urllib.error.HTTPError(req.full_url, code, REFUSED, headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _opener() -> urllib.request.OpenerDirector:
    """urllib's own handlers for https, with the redirect handler above and no handler for any other scheme."""
    opener = urllib.request.OpenerDirector()
    for handler in (urllib.request.ProxyHandler(), urllib.request.UnknownHandler(), urllib.request.HTTPSHandler(),
                    urllib.request.HTTPDefaultErrorHandler(), _Redirects(), urllib.request.HTTPErrorProcessor()):
        opener.add_handler(handler)
    return opener


_HTTPS = _opener()


def _url(request: str | urllib.request.Request) -> str:
    return request.full_url if isinstance(request, urllib.request.Request) else request


def urlopen(request: str | urllib.request.Request, *, timeout: float) -> Any:
    """`urllib.request.urlopen` for an https address only, whose redirects stay on that server."""
    if not allowed(_url(request)):
        raise urllib.error.URLError("refused: not an https address")
    return _HTTPS.open(request, timeout=timeout)
