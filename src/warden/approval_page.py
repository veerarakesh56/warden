"""The approval page (decision D14; registers H6, R28, R58; times per R4).

A Slack button (register R28) opens `/a/<token>`: an unguessable link for one approver and one workflow, valid
15 minutes, used once. The page holds two passkey ceremonies:

1. **Who are you.** The approver's passkey answers a challenge bound to this link. Only then does the page show the
   plan - its entry, target, tier, environment, values and times - so a link forwarded or leaked from a chat shows
   nothing.
2. **Approve this plan.** For T2 and T3 the approver types the target (register H1), then the passkey signs a
   challenge that IS the plan (passkeys.py). The page sends the assertion to the workflow, which re-verifies it with
   its own activity; the page's own check only gives the person a quick answer.

Framework-free on purpose: one function from (method, path, body) to (status, headers, body), so the same code runs
in tests and behind API Gateway and Lambda (G6). The stores - links, pending challenges - are mappings handed in:
in memory here, the runtime's database in G6. Every response carries a strict Content-Security-Policy (no
third-party script, nothing framed), HSTS, no caching and no referrer. The relying-party id is configuration
(WARDEN_APPROVAL_RP_ID: a subdomain of the owner's domain, decision D17), never a literal.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from . import passkeys
from .approvals import ApproverPolicy, PasskeyAssertion
from .environments import both_times

LINK_TTL = timedelta(minutes=15)
TYPED_TIERS = frozenset({"T2", "T3"})
VIEW = "view"  # the tier and plan hash of the who-are-you challenge: no plan is ever "view"


@dataclass
class Link:
    workflow_id: str
    approver: str
    expires_at: datetime
    viewed: bool = False


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    body: str


class MemoryLinkStore:
    """Links and passkey challenges in this process: one long-running server, or a test."""

    def __init__(self) -> None:
        self.links: dict[str, Link] = {}
        self.pending: dict[str, passkeys.Pending] = {}

    def add_link(self, token: str, link: Link) -> None:
        self.links[token] = link

    def link(self, token: str) -> Link | None:
        return self.links.get(token)

    def mark_viewed(self, token: str) -> None:
        self.links[token].viewed = True

    def use_link(self, token: str) -> None:
        self.links.pop(token, None)

    def put_challenge(self, key: str, pending: passkeys.Pending) -> None:
        self.pending[key] = pending

    def challenge(self, key: str) -> passkeys.Pending | None:
        return self.pending.get(key)

    def take_challenge(self, key: str) -> passkeys.Pending | None:
        return self.pending.pop(key, None)


class AuditLinkStore:
    """Links and challenges as rows of the shared audit (G6): the page runs as a Lambda, and one invocation's memory
    is gone by the next. Append-only - a link viewed or used, a challenge taken, is a later row - and every token is
    kept only as its SHA-256, so the record never holds a live link."""

    def __init__(self, log: Any, clock: Callable[[], datetime] | None = None) -> None:
        self.log = log
        self.clock = clock or (lambda: datetime.now(UTC))

    @staticmethod
    def _key(token: str) -> str:
        import hashlib

        return hashlib.sha256(token.encode()).hexdigest()

    def _rows(self, kind: str, key: str) -> list[dict]:
        since = self.clock() - LINK_TTL - timedelta(hours=1)
        return [e["body"] for e in self.log.entries(kinds=(kind,), since=since) if e["body"].get("key") == key]

    def add_link(self, token: str, link: Link) -> None:
        self.log.append(link.workflow_id, "approval.link", {"key": self._key(token), "workflow_id": link.workflow_id,
                                                             "approver": link.approver,
                                                             "expires_at": link.expires_at.isoformat()})

    def link(self, token: str) -> Link | None:
        key = self._key(token)
        made = self._rows("approval.link", key)
        if not made or self._rows("approval.link_used", key):
            return None
        b = made[-1]
        return Link(b["workflow_id"], b["approver"], datetime.fromisoformat(b["expires_at"]),
                    viewed=bool(self._rows("approval.link_viewed", key)))

    def mark_viewed(self, token: str) -> None:
        link = self.link(token)
        self.log.append(link.workflow_id if link else "approval", "approval.link_viewed", {"key": self._key(token)})

    def use_link(self, token: str) -> None:
        link = self.link(token)
        self.log.append(link.workflow_id if link else "approval", "approval.link_used", {"key": self._key(token)})

    def put_challenge(self, key: str, pending: passkeys.Pending) -> None:
        self.log.append(pending.workflow_id, "approval.challenge", {
            "key": self._key(key), "workflow_id": pending.workflow_id, "plan_hash": pending.plan_hash,
            "tier": pending.tier, "nonce": pending.nonce, "expires_at": pending.expires_at.isoformat(),
            "challenge": pending.challenge})

    def challenge(self, key: str) -> passkeys.Pending | None:
        hashed = self._key(key)
        put = self._rows("approval.challenge", hashed)
        if not put:
            return None
        b = put[-1]
        # A challenge is used once: one taken after this one was issued closes it.
        taken = [t for t in self._rows("approval.challenge_taken", hashed) if t.get("nonce") == b["nonce"]]
        if taken:
            return None
        return passkeys.Pending(workflow_id=b["workflow_id"], plan_hash=b["plan_hash"], tier=b["tier"],
                                nonce=b["nonce"], expires_at=datetime.fromisoformat(b["expires_at"]),
                                challenge=b["challenge"])

    def take_challenge(self, key: str) -> passkeys.Pending | None:
        pending = self.challenge(key)
        if pending is not None:
            self.log.append(pending.workflow_id, "approval.challenge_taken", {"key": self._key(key),
                                                                              "nonce": pending.nonce})
        return pending


@dataclass
class ApprovalPage:
    rp_id: str
    policy: ApproverPolicy
    plan_of: Callable[[str], Any]  # workflow id -> its Plan, or None (a Temporal query in the runtime)
    signal: Callable[[str, PasskeyAssertion], None]  # workflow id, assertion -> sent
    # Where links and challenges live: memory for one long-running server, the audit for the Lambda (AuditLinkStore).
    store: Any = field(default_factory=MemoryLinkStore)
    # workflow id, Denial -> sent (requirement R28); None: this page offers no deny.
    deny: Callable[[str, Any], None] | None = None
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))

    @property
    def origin(self) -> str:
        return f"https://{self.rp_id}"

    def new_link(self, workflow_id: str, approver: str) -> str:
        token = secrets.token_urlsafe(32)
        self.store.add_link(token, Link(workflow_id, approver, self.clock() + LINK_TTL))
        return token

    # ------------------------------------------------------------------ routing

    def handle(self, method: str, path: str, body: str = "") -> Response:
        parts = path.strip("/").split("/")
        if len(parts) < 2 or parts[0] != "a":
            return _json(404, {"error": "not found"})
        token, action = parts[1], (parts[2] if len(parts) > 2 else "")
        link = self.store.link(token)
        if link is None or self.clock() >= link.expires_at:
            # One answer for unknown, expired and used: a link reveals nothing about which it is.
            return _json(404, {"error": "this approval link is not valid"})
        try:
            data = json.loads(body) if body else {}
        except ValueError:
            return _json(400, {"error": "the request is not JSON"})
        routes = {("GET", ""): self._shell, ("POST", "login-options"): self._login_options,
                  ("POST", "login"): self._login, ("POST", "approve-options"): self._approve_options,
                  ("POST", "approve"): self._approve, ("POST", "deny-options"): self._deny_options,
                  ("POST", "deny"): self._deny}
        route = routes.get((method.upper(), action))
        return route(token, link, data) if route else _json(404, {"error": "not found"})

    # ------------------------------------------------------------------ steps

    def _credentials(self, approver: str) -> list[passkeys.Credential]:
        entry = self.policy.approvers.get(approver)
        return [passkeys.Credential(approver, c.credential_id, c.public_key, c.sign_count, c.device_bound)
                for c in (entry.passkeys if entry else [])]

    def _shell(self, token: str, link: Link, data: dict) -> Response:
        nonce = secrets.token_urlsafe(16)
        return Response(200, _headers(nonce, "text/html; charset=utf-8"), _PAGE.replace("{{NONCE}}", nonce))

    def _login_options(self, token: str, link: Link, data: dict) -> Response:
        options, pending = passkeys.approval_options(rp_id=self.rp_id, credentials=self._credentials(link.approver),
                                                     workflow_id=link.workflow_id,
                                                     # The link's hash, never the link: challenges are recorded (G6).
                                                     plan_hash=f"{VIEW}:{AuditLinkStore._key(token)}",
                                                     tier=VIEW, now=self.clock())
        self.store.put_challenge(f"{token}:{VIEW}", pending)
        return _json(200, {"options": json.loads(options)})

    def _verify(self, key: str, link: Link, response: Any) -> list[str]:
        pending = self.store.take_challenge(key)
        if pending is None or not isinstance(response, dict):
            return ["no challenge is waiting for this answer"]
        credential = next((c for c in self._credentials(link.approver) if c.credential_id == response.get("id")), None)
        if credential is None:
            return ["this passkey is not one the approver enrolled"]
        _, problems = passkeys.verify_approval(response, pending=pending, credential=credential, rp_id=self.rp_id,
                                               origin=self.origin, now=self.clock(), used_nonces=set())
        return problems

    def _login(self, token: str, link: Link, data: dict) -> Response:
        problems = self._verify(f"{token}:{VIEW}", link, data.get("response"))
        if problems:
            return _json(403, {"error": "the passkey was not accepted", "problems": problems})
        plan = self.plan_of(link.workflow_id)
        if plan is None or plan.problems:
            return _json(409, {"error": "this plan is no longer waiting for an approval"})
        self.store.mark_viewed(token)
        return _json(200, {"plan": {
            "entry": plan.entry, "target": plan.target, "tier": plan.tier, "environment": plan.environment,
            "values": plan.params, "plan_hash": plan.plan_hash, "made": both_times(plan.created_at),
            "link_expires": both_times(link.expires_at), "type_the_target": plan.tier in TYPED_TIERS}})

    def _approve_options(self, token: str, link: Link, data: dict) -> Response:
        plan = self.plan_of(link.workflow_id)
        if not link.viewed or plan is None:
            return _json(403, {"error": "show the plan first"})
        options, pending = passkeys.approval_options(rp_id=self.rp_id, credentials=self._credentials(link.approver),
                                                     workflow_id=plan.workflow_id, plan_hash=plan.plan_hash,
                                                     tier=plan.tier, now=self.clock())
        self.store.put_challenge(f"{token}:approve", pending)
        return _json(200, {"options": json.loads(options)})

    def _deny_options(self, token: str, link: Link, data: dict) -> Response:
        plan = self.plan_of(link.workflow_id)
        if self.deny is None or not link.viewed or plan is None:
            return _json(403, {"error": "show the plan first"})
        options, pending = passkeys.approval_options(rp_id=self.rp_id, credentials=self._credentials(link.approver),
                                                     workflow_id=plan.workflow_id, plan_hash=f"deny:{plan.plan_hash}",
                                                     tier="deny", now=self.clock())
        self.store.put_challenge(f"{token}:deny", pending)
        return _json(200, {"options": json.loads(options)})

    def _deny(self, token: str, link: Link, data: dict) -> Response:
        """The approver says no, with their passkey (requirement R28): the plan ends denied, nothing changed."""
        from .approvals import Denial

        plan = self.plan_of(link.workflow_id)
        if self.deny is None or not link.viewed or plan is None:
            return _json(403, {"error": "show the plan first"})
        problems = self._verify(f"{token}:deny", link, data.get("response"))
        if problems:
            return _json(403, {"error": "the passkey was not accepted", "problems": problems})
        reason = str(data.get("reason") or "")[:200]
        self.deny(plan.workflow_id, Denial(approver=link.approver, workflow_id=plan.workflow_id,
                                           plan_hash=plan.plan_hash, reason=reason))
        self.store.use_link(token)  # used once, either way
        return _json(200, {"sent": True, "note": "The plan is denied; nothing will change."})

    def _approve(self, token: str, link: Link, data: dict) -> Response:
        plan = self.plan_of(link.workflow_id)
        if not link.viewed or plan is None:
            return _json(403, {"error": "show the plan first"})
        if plan.tier in TYPED_TIERS and data.get("typed_target") != plan.target:
            return _json(400, {"error": f"a {plan.tier} approval needs the target typed exactly"})
        pending = self.store.challenge(f"{token}:approve")
        problems = self._verify(f"{token}:approve", link, data.get("response"))
        if problems or pending is None:
            return _json(403, {"error": "the passkey was not accepted", "problems": problems})
        self.signal(plan.workflow_id, PasskeyAssertion(
            approver=link.approver, workflow_id=pending.workflow_id, plan_hash=pending.plan_hash, tier=pending.tier,
            nonce=pending.nonce, expires_at=pending.expires_at, challenge=pending.challenge, response=data["response"]))
        self.store.use_link(token)  # used once
        return _json(200, {"sent": True, "note": "WARDEN re-checks this approval before anything changes."})


def _headers(nonce: str, content_type: str) -> dict[str, str]:
    return {
        "Content-Type": content_type,
        "Content-Security-Policy": (f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
                                    "connect-src 'self'; img-src 'none'; base-uri 'none'; form-action 'none'; "
                                    "frame-ancestors 'none'"),
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "no-store",
    }


def _json(status: int, payload: dict) -> Response:
    return Response(status, _headers(secrets.token_urlsafe(8), "application/json"), json.dumps(payload))


# The page: no plan in it - the plan arrives only after the first passkey ceremony. Labelled controls, keyboard
# order, text status (never colour alone), and nothing loaded from anywhere else.
_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>WARDEN approval</title>
<style nonce="{{NONCE}}">body{font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem}
dt{font-weight:600}button{font:inherit;padding:.5rem 1rem}[hidden]{display:none}</style></head>
<body><main>
<h1>WARDEN approval</h1>
<p id="status" role="status" aria-live="polite">Confirm it is you to see the plan.</p>
<button id="who" type="button">Show the plan with my passkey</button>
<section id="plan" hidden aria-labelledby="plan-h"><h2 id="plan-h">The plan</h2><dl id="facts"></dl>
<p><label for="typed">Type the target exactly to approve it</label><br><input id="typed" autocomplete="off"></p>
<button id="ok" type="button">Approve this plan with my passkey</button>
<p><label for="why">Or deny it (optional reason)</label><br><input id="why" maxlength="200" autocomplete="off"></p>
<button id="no" type="button">Deny this plan with my passkey</button></section>
</main>
<script nonce="{{NONCE}}">
const base = location.pathname.replace(/\\/$/, "");
const b2a = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
const a2b = s => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
const say = t => { document.getElementById("status").textContent = t; };
async function post(step, body) {
  const r = await fetch(base + "/" + step, {method: "POST", headers: {"Content-Type": "application/json"},
                                            body: JSON.stringify(body || {})});
  return [r.ok, await r.json()];
}
async function passkey(step) {
  const [ok, d] = await post(step); if (!ok) { throw new Error(d.error); }
  const o = d.options; o.challenge = a2b(o.challenge);
  o.allowCredentials = (o.allowCredentials || []).map(c => ({...c, id: a2b(c.id)}));
  const c = await navigator.credentials.get({publicKey: o});
  return {id: c.id, rawId: b2a(c.rawId), type: c.type, response: {
    clientDataJSON: b2a(c.response.clientDataJSON), authenticatorData: b2a(c.response.authenticatorData),
    signature: b2a(c.response.signature), userHandle: c.response.userHandle ? b2a(c.response.userHandle) : null}};
}
document.getElementById("who").addEventListener("click", async () => {
  try {
    const [ok, d] = await post("login", {response: await passkey("login-options")});
    if (!ok) { say(d.error); return; }
    const dl = document.getElementById("facts"); dl.textContent = "";
    for (const [k, v] of Object.entries(d.plan)) {
      const dt = document.createElement("dt"); dt.textContent = k.replace(/_/g, " ");
      const dd = document.createElement("dd"); dd.textContent = typeof v === "string" ? v : JSON.stringify(v);
      dl.append(dt, dd);
    }
    document.getElementById("plan").hidden = false; say("Read the plan, then approve it or close this page.");
  } catch (e) { say("Not confirmed: " + e.message); }
});
document.getElementById("ok").addEventListener("click", async () => {
  try {
    const response = await passkey("approve-options");
    const [ok, d] = await post("approve", {response, typed_target: document.getElementById("typed").value});
    say(ok ? "Sent. " + d.note : d.error);
  } catch (e) { say("Not approved: " + e.message); }
});
document.getElementById("no").addEventListener("click", async () => {
  try {
    const response = await passkey("deny-options");
    const [ok, d] = await post("deny", {response, reason: document.getElementById("why").value});
    say(ok ? d.note : d.error);
  } catch (e) { say("Not denied: " + e.message); }
});
</script></body></html>
"""

__all__ = ["LINK_TTL", "ApprovalPage", "Link", "Response"]
