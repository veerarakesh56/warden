"""Sign in with Slack, for the approval page: WHICH person is at the page, said by Slack - never typed.

Owner, 2026-10-12: "it should automatically be linked to the Slack user id plus this passkey, so the tracking, the
authentication and the authorisation are all in place". A passkey proves that a present person holds the enrolled
key and approves exactly this plan; it does not say which colleague that is. A name or a member id typed into the
approver list proves nothing ("if they wanted to, they would write a different name"). Slack's OpenID Connect
sign-in gives the member id from Slack itself; the page then requires it to be the approver the link was made for,
before the passkey.

Slack's endpoints and claims as its own page gives them (docs.slack.dev/authentication/sign-in-with-slack, read
2026-10-12): the authorize URL, the token method, the `https://slack.com/user_id` and `https://slack.com/team_id`
claims, state and nonce. The ID token is read from the token endpoint's own TLS response and its issuer, audience,
expiry and nonce are checked; its signature is not - OpenID Connect Core 3.1.3.7 allows the TLS server's identity in
place of it for a token received directly from the token endpoint, which is the only way this code gets one.

Off unless the runtime has a client id (WARDEN_SLACK_CLIENT_ID) and its secret (WARDEN_SLACK_CLIENT_SECRET, in
Secrets Manager, read by the approval Lambda only).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

AUTHORIZE = "https://slack.com/openid/connect/authorize"
TOKEN = "https://slack.com/api/openid.connect.token"
ISSUER = "https://slack.com"
USER_CLAIM = "https://slack.com/user_id"
TEAM_CLAIM = "https://slack.com/team_id"
_TIMEOUT_S = 8.0
# How long a browser that signed in is remembered (owner, 2026-10-12: "why do I see that Slack thing again and
# again"). Slack is asked once in that time, not once per link; the passkey is still asked for every decision.
REMEMBER_S = 12 * 3600


class SlackLoginError(ValueError):
    pass


def _post(url: str, form: dict[str, str]) -> dict[str, Any]:
    request = urllib.request.Request(url, data=urllib.parse.urlencode(form).encode(), method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(request, timeout=_TIMEOUT_S) as answer:  # nosec B310 - a fixed https API
        return json.loads(answer.read().decode("utf-8"))


@dataclass(frozen=True)
class SlackLogin:
    client_id: str
    client_secret: str
    post: Callable[[str, dict[str, str]], dict[str, Any]] = _post
    clock: Callable[[], float] = time.time

    def authorize_url(self, *, redirect_uri: str, state: str, nonce: str) -> str:
        return AUTHORIZE + "?" + urllib.parse.urlencode({
            "response_type": "code", "scope": "openid profile", "client_id": self.client_id, "state": state,
            "nonce": nonce, "redirect_uri": redirect_uri})

    def member(self, code: str, *, redirect_uri: str, nonce: str) -> dict[str, str]:
        """The Slack member this sign-in is: {"user", "team"} - or SlackLoginError, whatever was wrong with it."""
        try:
            answer = self.post(TOKEN, {"client_id": self.client_id, "client_secret": self.client_secret, "code": code,
                                       "redirect_uri": redirect_uri, "grant_type": "authorization_code"})
        except Exception as exc:  # noqa: BLE001 - Slack unreachable is a sign-in that did not happen
            raise SlackLoginError(f"Slack could not be reached ({type(exc).__name__})") from None
        if not isinstance(answer, dict) or answer.get("ok") is not True or not isinstance(answer.get("id_token"), str):
            raise SlackLoginError("Slack did not confirm the sign-in")
        try:
            body = answer["id_token"].split(".")[1]
            claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        except Exception:  # noqa: BLE001
            raise SlackLoginError("Slack's answer could not be read") from None
        audience = claims.get("aud")
        if claims.get("iss") != ISSUER or self.client_id not in (audience if isinstance(audience, list) else [audience]):
            raise SlackLoginError("the sign-in was not issued by Slack for this app")
        if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] <= self.clock():
            raise SlackLoginError("the sign-in has expired")
        if not nonce or claims.get("nonce") != nonce:
            raise SlackLoginError("the sign-in does not belong to this page")
        user, team = claims.get(USER_CLAIM) or claims.get("sub"), claims.get(TEAM_CLAIM)
        if not isinstance(user, str) or not user:
            raise SlackLoginError("Slack named no member")
        return {"user": user, "team": str(team or "")}


def _mac(secret: str, text: str) -> str:
    key = hmac.new(secret.encode(), b"warden-slack-session:v1", hashlib.sha256).digest()
    return hmac.new(key, text.encode(), hashlib.sha256).hexdigest()


def remember(login: SlackLogin, member: str) -> str:
    """A cookie value that says, for REMEMBER_S, that Slack named this member in this browser - sealed with a key
    made from the app's secret, so only this runtime can have written it."""
    text = f"{member}.{int(login.clock()) + REMEMBER_S}"
    return f"{text}.{_mac(login.client_secret, text)}"


def remembered(login: SlackLogin, value: str) -> str:
    """The member a `remember` value names, or "" - forged, cut, or past its time."""
    text, _, mac = value.rpartition(".")
    member, _, until = text.partition(".")
    if not member or not until.isdigit() or not hmac.compare_digest(mac, _mac(login.client_secret, text)):
        return ""
    return member if int(until) > login.clock() else ""


def from_environment() -> SlackLogin | None:
    client, secret = (os.environ.get(n, "").strip() for n in ("WARDEN_SLACK_CLIENT_ID", "WARDEN_SLACK_CLIENT_SECRET"))
    return SlackLogin(client, secret) if client and secret else None
