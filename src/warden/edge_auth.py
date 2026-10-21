"""The approval site's gate at the edge (owner, 2026-10-21; Sonar terraform:S6333 on frontdoor.tf): an API Gateway
Lambda REQUEST authorizer in front of the routes whose function already refuses a request without what it checks here.
It adds a layer and changes nothing the function accepts: whatever passes here is checked again behind it, by the same
code (slack_login.remembered, approval_page.signed_link_approver).

  GET /r, GET /r/{incident}           the reader's Slack sign-in cookie (`warden_who`, slack_login.remember): sealed
  GET /p, POST /p/{step}              with a key made from the Slack app's secret (HMAC-SHA256, compared in constant
                                      time), and not past its time
  GET|POST /e/{token}[/{step}]        an enrolment link, signed by the approver's own Ed25519 key for this purpose, not
                                      expired, not made to last longer than a link does
  GET|POST /k/{token}[/{step}]        a kill switch reset's link, likewise
  GET|POST /x/{token}[/{step}]        a kill switch stop's link, likewise

Open on purpose, and why (also in docs/DESIGN-DECISIONS.md, "The approval site's gate at the gateway"):
  /a/{token}[/{step}]  the passkey sign-in's start: an approval link's token is random (256 bits) and lives only in the
                       audit database, so checking it here would put that database, and a grant to read it, in front of
                       the page. The function refuses an unknown or expired token with one answer, every step after the
                       page needs Slack's sign-in for this link and then the approver's passkey; /a/signed/* is an
                       Ed25519 signature over the body, which an authorizer never sees.
  /s/...               Slack's sign-in itself: a browser has nothing to show yet. /s/r[/{incident}] and /s/p are where
                       a records or pages link lands (straight on to /r or /p when the browser is already signed in);
                       /s/callback checks Slack's state against this site's own cookie.
  POST /s/interact     Slack's note of a button click, answered with nothing read and nothing decided (ack.py).

The gateway calls this with payload format 2.0 and simple responses: {"isAuthorized": bool}, no identity source and
no cached answer (TTL 0), so every request is checked on its own. A route it does not know, a forged, cut, expired or
foreign token or cookie is a refusal. A failure to read its settings or the approver list is raised: the gateway then
refuses the request too (500), and the Lambda's error count pages a person (paging.tf) - a gate that silently refused
every approver would hide that the approval site is down.
"""
from __future__ import annotations

import re
import time
from datetime import UTC, datetime
from typing import Any

SIGNED_IN = frozenset({"GET /r", "GET /r/{incident}", "GET /p", "POST /p/{step}"})
# The routes of a signed link, by the purpose its signature is for (approval_page.INVITE / RESET_INVITE / STOP_INVITE).
SIGNED_LINKS = {"e": "INVITE", "k": "RESET_INVITE", "x": "STOP_INVITE"}
GATED = SIGNED_IN | frozenset(f"{method} /{kind}/{{token}}{step}" for kind in SIGNED_LINKS
                              for method, step in (("GET", ""), ("POST", "/{step}")))
_WHO = "warden_who"  # approval_page._WHO: the cookie slack_login.remember seals (a test holds the two equal)
_TOKEN = re.compile(r"[A-Za-z0-9_-]{1,4096}\.[A-Za-z0-9_-]{1,512}")


def _cookie(cookies: Any, name: str) -> str:
    return next((c.split("=", 1)[1] for c in cookies or () if isinstance(c, str) and c.startswith(name + "=")), "")


def _signed_in(event: dict[str, Any], client_secret: str, clock: float) -> bool:
    """The sign-in cookie, read exactly as the page reads it (slack_login.remembered)."""
    if not client_secret:
        return False  # no Slack app: the records and pages have nobody to show them to (approval_page)
    from .slack_login import SlackLogin, remembered

    value = _cookie(event.get("cookies"), _WHO)
    return bool(value) and bool(remembered(SlackLogin("", client_secret, clock=lambda: clock), value))


def _signed_link(route: str, event: dict[str, Any], policy: Any, clock: float) -> bool:
    """A signed link's token, checked exactly as the page checks it (approval_page.signed_link_approver)."""
    from . import approval_page

    kind = route.split(" ", 1)[1].split("/")[1]
    token = str((event.get("pathParameters") or {}).get("token") or "")
    if not _TOKEN.fullmatch(token):
        return False
    approvers = policy() if callable(policy) else policy
    return approval_page.signed_link_approver(approvers, token, getattr(approval_page, SIGNED_LINKS[kind]),
                                              datetime.fromtimestamp(clock, UTC)) is not None


def decide(event: dict[str, Any], *, client_secret: str, policy: Any, now: float | None = None) -> bool:
    """True only when the request carries what its route's function would also demand. `policy` is the approver list
    (approvals.ApproverPolicy), or a callable returning it, read only for a signed link."""
    route = str(event.get("routeKey") or "")
    clock = time.time() if now is None else now
    if route in SIGNED_IN:
        return _signed_in(event, client_secret, clock)
    if route in GATED:
        return _signed_link(route, event, policy, clock)
    return False


_LOADED: set[str] = set()


def handler(event: dict[str, Any], context: Any = None) -> dict[str, bool]:
    """The Lambda: this environment's Slack app secret (settings, lambda-edge-auth; once per container, as the approval
    function reads it in lambdas._configure) and approver list (SSM, read for each signed link: a passkey enrolled a
    minute ago signs the next link). No decision is remembered between requests."""
    import os

    from . import runtime_base, settings

    if not _LOADED:
        settings.load(only=settings.loadable_for("lambda-edge-auth"))
        _LOADED.add("settings")
    return {"isAuthorized": decide(event, client_secret=os.environ.get("WARDEN_SLACK_CLIENT_SECRET", "").strip(),
                                   policy=runtime_base.approver_policy)}
