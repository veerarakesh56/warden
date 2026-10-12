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

Enrolling a passkey is `/e/<token>`: a link the approver's own Ed25519 key signed (`warden enrol`, made where that key
is and opened there, never printed), valid 15 minutes, used once. The page runs the ceremony and shows the approver list with the new passkey in it.
The page cannot write that list: the passkey approves nothing until a person saves the list where WARDEN reads it.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import yaml
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

from . import approvals, passkeys
from .approvals import ApproverPolicy, PasskeyAssertion, PasskeyCredential
from .environments import both_times

LINK_TTL = timedelta(minutes=15)
TYPED_TIERS = frozenset({"T2", "T3"})
VIEW = "view"  # the tier and plan hash of the who-are-you challenge: no plan is ever "view"
ENROL = "enrol"  # likewise for an enrolment's challenge
INVITE = b"warden-enrol:v1:"
RESET_INVITE = b"warden-killswitch:v1:"  # a link signed for one purpose opens nothing of the other
KILLSWITCH = "killswitch"  # the workflow id a reset is an approval of (bounds.reset)


def invite(key: Any, approver: str, *, now: datetime, purpose: bytes = INVITE) -> str:
    """A link's token, signed by the approver's own Ed25519 key for 15 minutes: "add a passkey for me" (enrolment), or
    "let me reset the kill switch" (RESET_INVITE)."""
    claim = json.dumps({"approver": approver, "expires_at": (now + LINK_TTL).isoformat(),
                        "nonce": secrets.token_urlsafe(16)}, sort_keys=True, separators=(",", ":")).encode()
    return f"{bytes_to_base64url(claim)}.{bytes_to_base64url(key.sign(purpose + claim))}"


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
        self.spent: set[str] = set()

    def add_link(self, token: str, link: Link) -> None:
        self.links[token] = link

    def link(self, token: str) -> Link | None:
        return self.links.get(token)

    def mark_viewed(self, token: str) -> None:
        self.links[token].viewed = True

    def use_link(self, token: str) -> None:
        self.links.pop(token, None)
        self.spent.add(token)

    def used(self, token: str) -> bool:
        return token in self.spent

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
        # Who confirmed who they are and was shown which plan, on the record (owner, 2026-10-12: "tracked, so that
        # later we can look at who did it").
        link = self.link(token)
        self.log.append(link.workflow_id if link else "approval", "approval.link_viewed", {
            "key": self._key(token), **({"approver": link.approver, "workflow_id": link.workflow_id} if link else {})})

    def use_link(self, token: str) -> None:
        link = self.link(token)
        self.log.append(link.workflow_id if link else "approval", "approval.link_used", {"key": self._key(token)})

    def used(self, token: str) -> bool:
        return bool(self._rows("approval.link_used", self._key(token)))

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
    # The audit, for the kill switch's reset (the trips it shows and the reset it records); None: no reset here.
    log: Any = None

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
        if len(parts) >= 2 and parts[0] == "e":
            return self._enrol(method.upper(), parts[1], parts[2] if len(parts) > 2 else "", body)
        if len(parts) >= 2 and parts[0] == "k":
            return self._reset(method.upper(), parts[1], parts[2] if len(parts) > 2 else "", body)
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

    # ------------------------------------------------------------------ enrolment

    def _invited(self, token: str, purpose: bytes = INVITE) -> str | None:
        """The approver a signed link names - when their own key signed it for this purpose, it has not expired, it
        was not made to last longer than a link does, and it has not been used."""
        try:
            claim, signature = (base64url_to_bytes(part) for part in token.split("."))
            said = json.loads(claim)
            approver, expires = str(said["approver"]), datetime.fromisoformat(said["expires_at"])
            self.policy.key_of(approver).verify(signature, purpose + claim)
            now = self.clock()
            return approver if now < expires <= now + LINK_TTL and not self.store.used(token) else None
        except Exception:  # noqa: BLE001 - whatever is wrong with a link, it invites nobody
            return None

    def _enrol(self, method: str, token: str, step: str, body: str) -> Response:
        approver = self._invited(token)
        if approver is None:
            return _json(404, {"error": "this enrolment link is not valid"})
        key = f"{token}:{ENROL}"
        if (method, step) == ("GET", ""):
            nonce = secrets.token_urlsafe(16)
            return Response(200, _headers(nonce, "text/html; charset=utf-8"), _ENROL.replace("{{NONCE}}", nonce))
        if (method, step) == ("POST", "options"):
            options, challenge = passkeys.registration_options(rp_id=self.rp_id, rp_name="WARDEN", approver=approver)
            self.store.put_challenge(key, passkeys.Pending(
                workflow_id=ENROL, plan_hash=f"{ENROL}:{approver}", tier=ENROL, nonce=secrets.token_urlsafe(16),
                expires_at=self.clock() + LINK_TTL, challenge=bytes_to_base64url(challenge)))
            return _json(200, {"options": json.loads(options)})
        if (method, step) != ("POST", "finish"):
            return _json(404, {"error": "not found"})
        pending = self.store.take_challenge(key)
        if pending is None or self.clock() >= pending.expires_at:
            return _json(403, {"error": "no challenge is waiting for this answer"})
        try:
            made = passkeys.finish_registration(json.loads(body)["response"], approver=approver,
                                                challenge=base64url_to_bytes(pending.challenge), rp_id=self.rp_id,
                                                origin=self.origin)
        except Exception:  # noqa: BLE001 - a ceremony that does not verify enrols nothing, whatever the reason
            return _json(403, {"error": "the passkey was not accepted"})
        listed = self.policy.model_copy(deep=True)
        if any(c.credential_id == made.credential_id for c in listed.approvers[approver].passkeys):
            return _json(409, {"error": "this passkey is already enrolled"})
        listed.approvers[approver].passkeys.append(PasskeyCredential(
            credential_id=made.credential_id, public_key=made.public_key, sign_count=made.sign_count,
            device_bound=made.device_bound))
        self.store.use_link(token)  # used once
        return _json(200, {"approver": approver, "device_bound": made.device_bound,
                           "approvers": yaml.safe_dump(listed.model_dump(), sort_keys=False)})

    # ------------------------------------------------------------------ the kill switch's reset

    def _reset(self, method: str, token: str, step: str, body: str) -> Response:
        """Resetting the kill switch where the audit is (first live trip, 2026-10-12: the only reset was a command
        that needs the audit database, which no laptop reaches in the cloud runtime). The link is signed by the
        approver's own key; the reset is their passkey over exactly the trips shown - the riskiest tier's rules
        (bounds.reset_by_passkey): a device-bound passkey, an approver of T3, and the wait after the latest trip."""
        from . import bounds

        approver = self._invited(token, RESET_INVITE) if self.log is not None else None
        if approver is None:
            return _json(404, {"error": "this reset link is not valid"})
        key, now = f"{token}:reset", self.clock()
        if (method, step) == ("GET", ""):
            nonce = secrets.token_urlsafe(16)
            return Response(200, _headers(nonce, "text/html; charset=utf-8"), _RESET.replace("{{NONCE}}", nonce))
        if (method, step) == ("POST", "trips"):
            rows = bounds.trips(self.log)
            if bounds.killswitch(self.log) is None or not rows:
                return _json(200, {"on": False})
            options, pending = passkeys.approval_options(
                rp_id=self.rp_id, credentials=self._credentials(approver), workflow_id=KILLSWITCH,
                plan_hash=bounds.trips_hash(self.log), tier="T3", now=now)
            self.store.put_challenge(key, pending)
            ready = rows[-1]["at"] + timedelta(minutes=self.policy.cooling_off_minutes.get("T3", 0))
            return _json(200, {"on": True, "options": json.loads(options), "wait": both_times(ready) if ready > now else "",
                               "trips": [{"at": both_times(r["at"]), "reason": str(r["body"].get("reason", ""))[:600]}
                                         for r in rows]})
        if (method, step) != ("POST", "reset"):
            return _json(404, {"error": "not found"})
        pending = self.store.take_challenge(key)
        try:
            response = json.loads(body)["response"]
        except Exception:  # noqa: BLE001 - an answer that cannot be read resets nothing
            response = None
        credential = next((c for c in self._credentials(approver)
                           if isinstance(response, dict) and c.credential_id == response.get("id")), None)
        if pending is None or credential is None:
            return _json(403, {"error": "the passkey was not accepted"})
        verified, problems = passkeys.verify_approval(response, pending=pending, credential=credential,
                                                      rp_id=self.rp_id, origin=self.origin, now=now, used_nonces=set())
        if verified is not None:
            problems = bounds.reset_by_passkey(self.log, verified, policy=self.policy, now=now)
        if problems:
            return _json(403, {"error": "the kill switch was not reset", "problems": problems})
        self.store.use_link(token)  # used once
        self.log.checkpoint()  # the reset signed the record; the link's last row is signed too
        return _json(200, {"reset": True})

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
        from . import catalog

        return _json(200, {"approver": self.policy.shown(link.approver),
                           # For the page's countdown: a person read the plan past its link's end and was told only
                           # "not valid", while a fresh link was already waiting in the channel (live, 2026-10-12).
                           "link_seconds": max(0, int((link.expires_at - self.clock()).total_seconds())), "plan": {
            # First: what changes, before and after (G9-D) - then the plan's facts.
            "change": "; ".join(catalog.change_of(plan.entry, plan.params, plan.snapshot)),
            "entry": plan.entry, "target": plan.target, "tier": plan.tier,
            "risk": approvals.TIER_MEANS.get(plan.tier, ""), "environment": plan.environment,
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


# ------------------------------------------------------------------ the pages
# One look for both pages (owner, 2026-10-12: "they look like some poor pages"). Everything is in the page: the
# Content-Security-Policy admits no font, image, frame or script from anywhere, and no style attribute - so the system
# font, classes only, and a nonce on the one style and the one script. Light and dark follow the device. Depth says
# what is what: the plan lies on a raised sheet, the old value is pressed in and the new one raised, the one button
# that sends a decision can be pressed. Labelled controls, keyboard order, a status always in words (never colour
# alone), readable at 200% and at a phone's width.
_STYLE = """
:root{color-scheme:light dark;
--bg:oklch(0.965 0.006 85);--bg2:oklch(0.925 0.01 85);--sheet:oklch(0.995 0.003 85);--well:oklch(0.958 0.007 85);
--line:oklch(0.875 0.008 85);--ink:oklch(0.24 0.012 265);--muted:oklch(0.46 0.012 265);
--accent:oklch(0.47 0.19 265);--accent-hi:oklch(0.42 0.19 265);--accent-edge:oklch(0.33 0.15 265);
--accent-ink:oklch(0.985 0.005 265);--glow:oklch(0.47 0.19 265/.26);
--ok:oklch(0.43 0.11 150);--warn:oklch(0.46 0.12 65);--bad:oklch(0.47 0.18 27);
--in:inset 0 1px 2px oklch(0.2 0.02 265/.10);--lift:0 1px 0 oklch(1 0 0/.6) inset,0 2px 6px oklch(0.2 0.02 265/.14);
--shadow:0 1px 1px oklch(0.2 0.02 265/.05),0 6px 14px oklch(0.2 0.02 265/.06),0 22px 48px oklch(0.2 0.02 265/.10)}
@media (prefers-color-scheme:dark){:root{
--bg:oklch(0.205 0.013 265);--bg2:oklch(0.15 0.014 265);--sheet:oklch(0.235 0.013 265);--well:oklch(0.195 0.013 265);
--line:oklch(0.33 0.014 265);--ink:oklch(0.95 0.006 85);--muted:oklch(0.74 0.01 85);
--accent:oklch(0.74 0.13 265);--accent-hi:oklch(0.8 0.11 265);--accent-edge:oklch(0.52 0.14 265);
--accent-ink:oklch(0.17 0.02 265);--glow:oklch(0.74 0.13 265/.22);
--ok:oklch(0.8 0.13 150);--warn:oklch(0.83 0.12 80);--bad:oklch(0.76 0.15 27);
--in:inset 0 1px 2px oklch(0 0 0/.45);--lift:0 1px 0 oklch(1 0 0/.07) inset,0 2px 8px oklch(0 0 0/.4);
--shadow:0 1px 0 oklch(1 0 0/.05) inset,0 14px 40px oklch(0 0 0/.5)}}
*{box-sizing:border-box}
html{font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;-webkit-text-size-adjust:100%}
body{margin:0;min-height:100vh;color:var(--ink);
background:radial-gradient(120% 55% at 50% -8%,var(--bg) 0,var(--bg2) 100%) fixed var(--bg2)}
.page{max-width:36rem;margin:0 auto;padding:1.25rem 1rem 3rem}
.top{display:flex;align-items:baseline;gap:.625rem;padding:.25rem .25rem 1rem}
.mark{font-weight:700;letter-spacing:.14em;font-size:.8125rem}
.where,.foot{color:var(--muted);font-size:.8125rem}
.foot{margin:1rem .25rem 0}
.sheet{background:var(--sheet);border:1px solid var(--line);border-radius:1rem;box-shadow:var(--shadow);overflow:hidden}
.steps{list-style:none;margin:0;padding:.875rem 1.25rem;display:flex;flex-wrap:wrap;gap:.5rem 1.125rem;counter-reset:s;
border-bottom:1px solid var(--line);background:var(--well);font-size:.8125rem;color:var(--muted)}
.steps li{counter-increment:s;display:flex;align-items:center;gap:.4375rem}
.steps li::before{content:counter(s);display:grid;place-items:center;width:1.375rem;height:1.375rem;border-radius:50%;
border:1px solid var(--line);background:var(--sheet);font-weight:600;font-size:.75rem}
.steps li[aria-current]{color:var(--ink);font-weight:600}
.steps li[aria-current]::before{background:var(--accent);border-color:var(--accent);color:var(--accent-ink)}
.steps li.done::before{content:"✓";color:var(--ok);border-color:currentColor}
h1{font-size:1.375rem;line-height:1.25;letter-spacing:-.01em;margin:1.375rem 1.25rem .5rem}
p{margin:0 0 1rem}
.lede{margin:0 1.25rem 1.25rem;color:var(--muted);max-width:60ch}
.me{margin:0 1.25rem;font-weight:600;color:var(--ok)}
.left{margin:.25rem 1.25rem 0;font-size:.875rem;color:var(--muted)}
.eyebrow{margin:1.25rem 1.25rem .625rem;font-size:.75rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;
color:var(--muted)}
.mono,.change{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.mono{font-size:.875rem}
.change{margin:0 1.25rem;display:grid;gap:.5rem}
.change .line{display:grid;justify-items:start;gap:.4375rem;padding:.875rem 1rem;border-radius:.75rem;
background:var(--well);box-shadow:var(--in);overflow-wrap:anywhere}
.change .what{font-weight:600}
.change .pair{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem .625rem}
.change .was{color:var(--muted);padding:.3125rem .6875rem;border-radius:.5rem;border:1px dashed var(--line);
text-decoration:line-through}
.change .to{font:600 .6875rem/1 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;letter-spacing:.1em;
text-transform:uppercase;color:var(--muted)}
.change .now{font-weight:700;padding:.3125rem .6875rem;border-radius:.5rem;background:var(--sheet);
border:1px solid var(--line);box-shadow:var(--lift)}
.facts{margin:1.25rem 1.25rem 0;display:grid;grid-template-columns:minmax(7.5rem,max-content) 1fr}
.facts dt,.facts dd{margin:0;padding:.625rem 0;border-top:1px solid var(--line)}
.facts dt{color:var(--muted);font-size:.875rem;padding-right:1rem}
.facts dd{overflow-wrap:anywhere}
.risk{font-weight:600}.risk.t1{color:var(--ok)}.risk.t2{color:var(--warn)}.risk.t3{color:var(--bad)}
.pad{padding:0 1.25rem}
.bar{position:relative;overflow:hidden;margin-top:1.25rem;padding:1rem 1.25rem 1.25rem;border-top:1px solid var(--line);
background:var(--well)}
.bar::before{content:"";position:absolute;left:0;top:0;height:2px;width:30%;background:var(--accent);opacity:0;
transform:translateX(-100%)}
body[data-busy="1"] .bar::before{opacity:1;animation:run 1.1s cubic-bezier(.22,1,.36,1) infinite}
@keyframes run{to{transform:translateX(340%)}}
#status{margin:0 0 .875rem;font-weight:500}
#status[data-kind="bad"]{color:var(--bad)}#status[data-kind="ok"]{color:var(--ok)}
label{display:block;font-size:.875rem;font-weight:600;margin-bottom:.375rem}
input,textarea{width:100%;font:inherit;color:inherit;background:var(--sheet);border:1px solid var(--line);
border-radius:.625rem;padding:.625rem .75rem;box-shadow:var(--in)}
textarea{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.8125rem;line-height:1.45;
resize:vertical}
.hint{display:block;margin-top:.375rem;font-size:.8125rem;font-weight:400;color:var(--muted)}
button{width:100%;font:inherit;font-weight:600;border-radius:.75rem;padding:.75rem 1rem;border:1px solid transparent;
cursor:pointer;transition:transform .16s cubic-bezier(.22,1,.36,1),box-shadow .16s cubic-bezier(.22,1,.36,1),
background-color .16s}
.primary{color:var(--accent-ink);background:var(--accent);
box-shadow:inset 0 1px 0 oklch(1 0 0/.22),0 3px 0 var(--accent-edge),0 10px 22px var(--glow)}
.primary:hover{background:var(--accent-hi)}
.primary:active{transform:translateY(2px);box-shadow:inset 0 1px 0 oklch(1 0 0/.22),0 1px 0 var(--accent-edge),
0 4px 10px var(--glow)}
.danger{color:var(--bad);background:var(--sheet);border-color:currentColor}
.danger:active{transform:translateY(1px)}
button:disabled{opacity:.55;cursor:progress;transform:none}
:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
.deny{margin-top:1.25rem;padding-top:1rem;border-top:1px solid var(--line)}
.deny p{margin:0 0 .75rem}
[hidden]{display:none!important}
@media (max-width:26rem){.facts{grid-template-columns:1fr}.facts dt{padding-bottom:0}
.facts dd{border-top:0;padding-top:.125rem}}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
"""

# What both pages' scripts share: the passkey encodings, the status line, the step marker, the POST.
_JS = """
const base = location.pathname.endsWith("/") ? location.pathname.slice(0, -1) : location.pathname;
const $ = id => document.getElementById(id);
const b2a = b => btoa(String.fromCharCode(...new Uint8Array(b))).split("+").join("-").split("/").join("_")
  .split("=").join("");
const a2b = s => Uint8Array.from(atob(s.split("-").join("+").split("_").join("/")), c => c.charCodeAt(0));
const say = (t, kind) => { const s = $("status"); s.textContent = t; s.dataset.kind = kind || "info";
                           s.scrollIntoView({block: "nearest"}); };
const busy = on => { document.body.dataset.busy = on ? "1" : "0";
                     for (const b of document.querySelectorAll("button")) { b.disabled = on; } };
const step = n => { [...document.querySelectorAll(".steps li")].forEach((li, i) => {
  li.classList.toggle("done", i < n);
  if (i === n) { li.setAttribute("aria-current", "step"); } else { li.removeAttribute("aria-current"); }
  li.setAttribute("aria-label", li.textContent + (i < n ? ", done" : "")); }); };
async function post(name, body) {
  const r = await fetch(base + "/" + name, {method: "POST", headers: {"Content-Type": "application/json"},
                                            body: JSON.stringify(body || {})});
  return [r.ok, await r.json()];
}
"""

_SHELL = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{TITLE}}</title>
<style nonce="{{NONCE}}">{{STYLE}}</style></head>
<body data-busy="0"><div class="page">
<header class="top"><span class="mark">WARDEN</span><span class="where">{{WHERE}}</span></header>
<main class="sheet">{{MAIN}}</main>
<p class="foot">{{FOOT}}</p>
</div>
<script nonce="{{NONCE}}">{{JS}}{{SCRIPT}}</script></body></html>
"""


def _page(title: str, where: str, main: str, foot: str, script: str) -> str:
    return (_SHELL.replace("{{TITLE}}", title).replace("{{WHERE}}", where).replace("{{MAIN}}", main)
            .replace("{{FOOT}}", foot).replace("{{STYLE}}", _STYLE).replace("{{JS}}", _JS).replace("{{SCRIPT}}", script))


# The enrolment page: one button, then the approver list to save.
_ENROL = _page("WARDEN passkey", "Passkey", """
<ol class="steps" aria-label="Steps"><li class="done">Open your link</li><li aria-current="step">Create the passkey</li>
<li>Save the approver list</li></ol>
<h1 id="title">Add a passkey for approvals</h1>
<p id="only" class="lede">You confirm it with your fingerprint, face or PIN each time you approve a plan. Nobody else
can use it.</p>
<section id="done" hidden aria-labelledby="done-h"><h2 id="done-h" class="eyebrow">The approver list, with this passkey</h2>
<div class="pad"><label for="list">Save this as WARDEN's approver list. The passkey approves nothing until it is saved
there.</label>
<textarea id="list" rows="14" readonly></textarea></div></section>
<div class="bar"><p id="status" role="status" aria-live="polite" data-kind="info">Create a passkey on this device to
approve plans with it.</p>
<button id="make" class="primary" type="button">Create my passkey</button>
<button id="copy" class="primary" type="button" hidden>Copy the list</button></div>
""", "The page cannot save the list: a person does, where WARDEN reads it.", """
$("make").addEventListener("click", async () => {
  busy(true);
  try {
    say("Confirm with your device.", "work");
    const [ok, d] = await post("options"); if (!ok) { say(d.error, "bad"); return; }
    const o = d.options; o.challenge = a2b(o.challenge); o.user.id = a2b(o.user.id);
    o.excludeCredentials = (o.excludeCredentials || []).map(c => ({...c, id: a2b(c.id)}));
    const c = await navigator.credentials.create({publicKey: o});
    say("Checking the new passkey.", "work");
    const [done, r] = await post("finish", {response: {id: c.id, rawId: b2a(c.rawId), type: c.type, response: {
      clientDataJSON: b2a(c.response.clientDataJSON), attestationObject: b2a(c.response.attestationObject)}}});
    if (!done) { say(r.error, "bad"); return; }
    $("list").value = r.approvers; $("done").hidden = false; $("only").hidden = true;
    $("make").hidden = true; $("copy").hidden = false; $("title").textContent = "Passkey created"; step(2);
    say(r.device_bound ? "Passkey created on this device. Save the list shown above."
      : "Passkey created. It is synced between your devices, so it cannot approve the riskiest tier. Save the list shown above.",
      "ok");
  } catch (e) { say("Not created: " + e.message, "bad"); } finally { busy(false); }
});
$("copy").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText($("list").value); say("Copied. Save it as the approver list.", "ok"); }
  catch (e) { $("list").select(); say("Select the list and copy it."); }
});
""")

# The approval page: no plan in it - the plan arrives only after the first passkey ceremony.
_PAGE = _page("WARDEN approval", "Approval", """
<ol class="steps" aria-label="Steps"><li aria-current="step">Confirm it is you</li><li>Read the plan</li>
<li>Decide</li></ol>
<h1 id="title">A plan is waiting for your approval</h1>
<p id="only" class="lede">This link was made for one approver. Only that person can open it, with their own passkey;
anyone else sees nothing here and cannot approve the plan.</p>
<p id="me" class="me" hidden></p>
<p id="left" class="left" hidden></p>
<section id="plan" hidden aria-labelledby="plan-h"><h2 id="plan-h" class="eyebrow">What will change</h2>
<p id="change" class="change"></p>
<dl id="facts" class="facts"></dl></section>
<div class="bar"><p id="status" role="status" aria-live="polite" data-kind="info">Confirm it is you to see the plan.</p>
<button id="who" class="primary" type="button">Show the plan with my passkey</button>
<div id="acts" hidden><p id="typed-p" hidden><label for="typed">Type the target exactly to approve it
<span class="hint">It is shown above, beside Target.</span></label>
<input id="typed" class="mono" autocomplete="off" autocapitalize="off" spellcheck="false"></p>
<button id="ok" class="primary" type="button">Approve this plan with my passkey</button>
<div class="deny"><p><label for="why">Or deny it: your reason (optional)</label>
<input id="why" maxlength="200" autocomplete="off"></p>
<button id="no" class="danger" type="button">Deny this plan with my passkey</button></div></div></div>
""", "WARDEN checks every approval again, against this exact plan, before anything changes.", """
const LABELS = {entry: "Action", target: "Target", environment: "Environment", values: "Exact values",
                plan_hash: "Plan fingerprint", made: "Plan made", link_expires: "Link expires"};
const MONO = ["entry", "target", "values", "plan_hash"];
const el = (tag, cls, text) => { const e = document.createElement(tag); e.className = cls; e.textContent = text;
                                 return e; };
let me = "";
function show(plan, approver) {
  me = String(approver || "");
  if (me) { $("me").textContent = "Confirmed with your passkey: you are " + me + "."; $("me").hidden = false; }
  const change = $("change"); change.textContent = "";
  for (const line of String(plan.change || "").split("; ")) {
    const at = line.lastIndexOf(" -> ");
    const row = el("span", "line", at < 0 ? line : "");
    if (at >= 0) {
      const was = line.slice(0, at), colon = was.lastIndexOf(": ");
      const pair = el("span", "pair", "");
      pair.append(el("span", "was", colon < 0 ? was : was.slice(colon + 2)), el("span", "to", "becomes"),
                  el("span", "now", line.slice(at + 4)));
      if (colon >= 0) { row.append(el("span", "what", was.slice(0, colon))); }
      row.append(pair);
    }
    change.append(row);
  }
  const dl = $("facts"); dl.textContent = "";
  dl.append(el("dt", "", "Risk"), el("dd", "risk " + String(plan.tier).toLowerCase(),
                                     plan.risk ? plan.tier + ": " + plan.risk : String(plan.tier)));
  for (const [k, v] of Object.entries(plan)) {
    if (["change", "tier", "risk", "type_the_target"].includes(k)) { continue; }
    dl.append(el("dt", "", LABELS[k] || k.split("_").join(" ")),
              el("dd", MONO.includes(k) ? "mono" : "", typeof v === "string" ? v : JSON.stringify(v)));
  }
  $("typed-p").hidden = !plan.type_the_target;
  $("only").hidden = true; $("who").hidden = true; $("plan").hidden = false; $("acts").hidden = false;
  $("title").textContent = "Read the plan, then decide"; step(1);
}
const GONE = "This link has expired or was already used; nothing was decided with it. If the plan is still " +
             "waiting, the newest WARDEN message in the channel has a fresh link.";
let ticking = 0;
function countdown(seconds) {
  const end = Date.now() + seconds * 1000;
  const tick = () => {
    const left = Math.max(0, Math.round((end - Date.now()) / 1000));
    $("left").textContent = "This link works for " + Math.floor(left / 60) + " min " + (left % 60) + " s more.";
    $("left").hidden = false;
    if (left === 0) { clearInterval(ticking); $("acts").hidden = true; $("left").hidden = true; say(GONE, "bad"); }
  };
  tick(); ticking = setInterval(tick, 1000);
}
const sent = t => { clearInterval(ticking); $("left").hidden = true; $("acts").hidden = true; $("title").textContent = "Done"; $("plan-h").textContent = "The plan";
                    step(3);
                    say(t + " You can close this page.", "ok"); };
async function passkey(name) {
  say("Confirm with your passkey.", "work");
  const [ok, d] = await post(name);
  if (!ok) { throw new Error(d.error === "this approval link is not valid" ? GONE : d.error); }
  const o = d.options; o.challenge = a2b(o.challenge);
  o.allowCredentials = (o.allowCredentials || []).map(c => ({...c, id: a2b(c.id)}));
  const c = await navigator.credentials.get({publicKey: o});
  return {id: c.id, rawId: b2a(c.rawId), type: c.type, response: {
    clientDataJSON: b2a(c.response.clientDataJSON), authenticatorData: b2a(c.response.authenticatorData),
    signature: b2a(c.response.signature), userHandle: c.response.userHandle ? b2a(c.response.userHandle) : null}};
}
$("who").addEventListener("click", async () => {
  busy(true);
  try {
    const [ok, d] = await post("login", {response: await passkey("login-options")});
    if (!ok) { say(d.error, "bad"); return; }
    show(d.plan, d.approver); say("Approve it, deny it, or close this page to leave it waiting.");
    if (typeof d.link_seconds === "number") { countdown(d.link_seconds); }
  } catch (e) {
    say("Not confirmed: " + e.message + " If this link was not made for you, you cannot approve this plan.", "bad");
  } finally { busy(false); }
});
$("ok").addEventListener("click", async () => {
  busy(true);
  try {
    const response = await passkey("approve-options");
    say("Sending your approval. This takes a few seconds; do not click again.", "work");
    const [ok, d] = await post("approve", {response, typed_target: $("typed").value});
    if (ok) { sent("Approval sent" + (me ? " as " + me : "") + ". " + d.note); } else { say(d.error, "bad"); }
  } catch (e) { say("Not approved: " + e.message, "bad"); } finally { busy(false); }
});
$("no").addEventListener("click", async () => {
  busy(true);
  try {
    const response = await passkey("deny-options");
    say("Sending your denial. This takes a few seconds; do not click again.", "work");
    const [ok, d] = await post("deny", {response, reason: $("why").value});
    if (ok) { sent("Denied" + (me ? " as " + me : "") + ". " + d.note); } else { say(d.error, "bad"); }
  } catch (e) { say("Not denied: " + e.message, "bad"); } finally { busy(false); }
});
""")

# The kill switch's reset: why it is on, then one passkey ceremony over exactly those trips.
_RESET = _page("WARDEN kill switch", "Kill switch", """
<ol class="steps" aria-label="Steps"><li class="done">Open your link</li><li aria-current="step">Read why it is on</li>
<li>Reset it</li></ol>
<h1 id="title">Every automatic fix is stopped</h1>
<p id="only" class="lede">The kill switch goes on when a fix leaves something in a state WARDEN cannot vouch for.
Read each reason below, look at what it names, and reset the switch only when that is settled.</p>
<section id="plan" hidden aria-labelledby="plan-h"><h2 id="plan-h" class="eyebrow">Why it is on</h2>
<dl id="facts" class="facts"></dl></section>
<div class="bar"><p id="status" role="status" aria-live="polite" data-kind="info">Show why the kill switch is on.</p>
<button id="who" class="primary" type="button">Show the reasons</button>
<button id="ok" class="primary" type="button" hidden>Reset the kill switch with my passkey</button></div>
""", "A reset is the riskiest tier's decision: a passkey that stays on one device, and only after a short wait.", """
const el = (tag, cls, text) => { const e = document.createElement(tag); e.className = cls; e.textContent = text;
                                 return e; };
let options = null;
$("who").addEventListener("click", async () => {
  busy(true);
  try {
    const [ok, d] = await post("trips"); if (!ok) { say(d.error, "bad"); return; }
    if (!d.on) { $("title").textContent = "The kill switch is off"; $("who").hidden = true; $("only").hidden = true;
                 step(3); say("Nothing to reset: automatic fixes are running.", "ok"); return; }
    const dl = $("facts"); dl.textContent = "";
    for (const t of d.trips) { dl.append(el("dt", "", t.at), el("dd", "", t.reason)); }
    options = d.options; $("plan").hidden = false; $("who").hidden = true; $("ok").hidden = false; step(2);
    say(d.wait ? "It can be reset from " + d.wait + "." : "Reset it when what the reasons name is settled.");
  } catch (e) { say("Not shown: " + e.message, "bad"); } finally { busy(false); }
});
$("ok").addEventListener("click", async () => {
  busy(true);
  try {
    say("Confirm with your passkey.", "work");
    const o = JSON.parse(JSON.stringify(options)); o.challenge = a2b(o.challenge);
    o.allowCredentials = (o.allowCredentials || []).map(c => ({...c, id: a2b(c.id)}));
    const c = await navigator.credentials.get({publicKey: o});
    say("Resetting the kill switch.", "work");
    const [ok, d] = await post("reset", {response: {id: c.id, rawId: b2a(c.rawId), type: c.type, response: {
      clientDataJSON: b2a(c.response.clientDataJSON), authenticatorData: b2a(c.response.authenticatorData),
      signature: b2a(c.response.signature), userHandle: c.response.userHandle ? b2a(c.response.userHandle) : null}}});
    if (!ok) { say(d.error + (d.problems ? ": " + d.problems.join("; ") : ""), "bad"); return; }
    $("ok").hidden = true; $("title").textContent = "The kill switch is off"; step(3);
    say("Reset. Automatic fixes run again. You can close this page.", "ok");
  } catch (e) { say("Not reset: " + e.message, "bad"); } finally { busy(false); }
});
""")

__all__ = ["LINK_TTL", "ApprovalPage", "Link", "Response"]
