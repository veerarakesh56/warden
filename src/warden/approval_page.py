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
import os
import re
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

LINK_TTL = timedelta(minutes=15)  # an enrolment's or a reset's link, and the least an approval link lasts
# An approval link lasts as long as its plan waits (activities._approval_links): at most a week, so that far back
# the Lambda's store looks for it.
LINK_LIFE_MAX = timedelta(days=8)
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

    def note_slack(self, token: str, approver: str, member: dict[str, str]) -> None:
        self.slack = {**getattr(self, "slack", {}), token: member["user"]}

    def slack_of(self, token: str) -> str:
        return getattr(self, "slack", {}).get(token, "")

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
        since = self.clock() - LINK_LIFE_MAX
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

    def note_slack(self, token: str, approver: str, member: dict[str, str]) -> None:
        # Who Slack said was at the page for this link, on the record with the approver it was made for.
        self.log.append("approval", "approval.slack_verified", {
            "key": self._key(token), "approver": approver, "slack_user": member["user"], "team": member.get("team", ""),
            "via": member.get("via", "sign-in")})

    def slack_of(self, token: str) -> str:
        rows = self._rows("approval.slack_verified", self._key(token))
        return str(rows[-1].get("slack_user", "")) if rows else ""

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
    # Sign in with Slack (slack_login.SlackLogin), when the runtime has a Slack app: then a link opens only for the
    # Slack member its approver is, before the passkey. None: the passkey alone, as before.
    slack: Any = None
    # workflow id, SignedApproval -> sent: a LIMITED approver's signed approval (the bench approver, owner
    # 2026-10-15). None: this page takes no signed approval.
    signed: Callable[[str, Any], None] | None = None

    @property
    def origin(self) -> str:
        return f"https://{self.rp_id}"

    def new_link(self, workflow_id: str, approver: str) -> str:
        token = secrets.token_urlsafe(32)
        self.store.add_link(token, Link(workflow_id, approver, self.clock() + LINK_TTL))
        return token

    # ------------------------------------------------------------------ routing

    def handle(self, method: str, path: str, body: str = "", query: str = "", cookies: Any = ()) -> Response:
        parts = path.strip("/").split("/")
        if parts[0] == "s":
            return self._slack(method.upper(), parts[1:], query, cookies)
        if parts[0] == "r":
            return self._records(method.upper(), parts[1:], cookies, query)
        if self.slack is not None and len(parts) >= 2:
            self._recognise(parts[0], parts[1], cookies)
        if len(parts) >= 2 and parts[0] == "e":
            return self._enrol(method.upper(), parts[1], parts[2] if len(parts) > 2 else "", body)
        if len(parts) >= 2 and parts[0] == "k":
            return self._reset(method.upper(), parts[1], parts[2] if len(parts) > 2 else "", body)
        if len(parts) < 2 or parts[0] != "a":
            return _json(404, {"error": "not found"})
        if parts[1] == "signed" and len(parts) == 3 and method.upper() == "POST":
            return self._signed_request(parts[2], body)
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
        if route not in (None, self._shell) and not self._signed_in(token, link.approver):
            return _json(403, {"error": "sign in with Slack first"})
        return route(token, link, data) if route else _json(404, {"error": "not found"})

    # ------------------------------------------------------------------ a limited approver's signed approval

    def _signed_request(self, step: str, body: str) -> Response:
        """`/a/signed/plan` and `/a/signed/approve`: an approver limited to some environments (the bench approver,
        owner 2026-10-15) asks for an incident's waiting plan with a signed request, then sends a signed approval of
        it. Every check of approvals.check runs here and again in the workflow; an approver with no environment list
        - a person - never uses this path. `/a/signed/record`: that approver reads the record of an incident in its
        environments, read only (owner, 2026-10-15: access to WARDEN's incidents and records, for dev)."""
        if (self.log is None or step not in ("plan", "approve", "record", "deny")
                or (step in ("plan", "approve") and self.signed is None) or (step == "deny" and self.deny is None)):
            return _json(404, {"error": "not found"})
        try:
            data = json.loads(body) if body else {}
        except ValueError:
            return _json(400, {"error": "the request is not JSON"})
        approver = self.policy.approvers.get(str(data.get("approver", "")))
        if approver is None or not approver.environments:
            return _json(403, {"error": "not an approver this path is for"})
        if step == "plan":
            return self._signed_plan(str(data["approver"]), data)
        if step == "record":
            return self._signed_record(str(data["approver"]), data)
        if step == "deny":
            return self._signed_deny(str(data["approver"]), data)
        try:
            approval = approvals.SignedApproval.model_validate(data)
        except Exception:  # noqa: BLE001 - a malformed approval is refused whole
            return _json(400, {"error": "not a signed approval"})
        plan = self.plan_of(approval.workflow_id)
        if plan is None:
            return _json(404, {"error": "no plan is waiting under that id"})
        used = {e["body"].get("nonce") for e in self.log.entries(kinds=("approval.accepted",))}
        problems = approvals.check(approval, policy=self.policy, workflow_id=plan.workflow_id, plan_hash=plan.plan_hash,
                                   tier=plan.tier, plan_created_at=plan.created_at, used_nonces=used,
                                   now=self.clock(), environment=plan.environment)
        if problems:
            return _json(403, {"error": "; ".join(problems)})
        self.signed(plan.workflow_id, approval)
        return _json(202, {"sent": plan.workflow_id})

    def _signature_refused(self, name: str, data: dict, message: bytes) -> Response | None:
        """None when `name` signed `message` in the last five minutes; else the refusal, the same for every cause."""
        try:
            at = datetime.fromisoformat(str(data.get("issued_at", "")))
            self.policy.key_of(name).verify(bytes.fromhex(str(data.get("signature", ""))), message)
        except Exception:  # noqa: BLE001 - an unparsable time, an unknown key or a bad signature: refused the same
            return _json(403, {"error": "the request is not signed by that approver"})
        if abs(self.clock() - at) > timedelta(minutes=5):
            return _json(403, {"error": "the request is too old"})
        return None

    def _signed_deny(self, name: str, data: dict) -> Response:
        """A waiting plan denied, with its reason, by the limited approver who signed `deny-request|approver|workflow|
        plan hash|reason|time` in the last five minutes - only a plan in an environment and a tier it may approve. A
        denial can only end a plan with nothing changed; the workflow takes it for this exact plan only."""
        wid, ph, reason = (str(data.get(k, "")) for k in ("workflow_id", "plan_hash", "reason"))
        refused = self._signature_refused(name, data, approvals.deny_request(name, wid, ph, reason,
                                                                            str(data.get("issued_at", ""))))
        if refused:
            return refused
        plan = self.plan_of(wid) if wid else None
        approver = self.policy.approvers[name]
        if (plan is None or plan.plan_hash != ph or plan.environment not in approver.environments
                or plan.tier not in approver.tiers):
            return _json(404, {"error": "no plan this approver may deny is waiting under that id and hash"})
        try:
            denial = approvals.Denial(approver=name, workflow_id=wid, plan_hash=ph, reason=reason)
        except Exception:  # noqa: BLE001 - a reason past NOTE_MAX, or a malformed name: refused whole
            return _json(400, {"error": "not a denial"})
        self.deny(wid, denial)
        return _json(202, {"denied": wid})

    def _signed_record(self, name: str, data: dict) -> Response:
        """An incident's record - or, with no incident, the latest RECORD_LIST of them - to the limited approver who
        signed `record-request|approver|incident|time` in the last five minutes: only incidents in an environment it
        may approve in. Read only; the same rows the records page shows a signed-in reader."""
        from . import records

        incident = str(data.get("incident", ""))
        refused = self._signature_refused(name, data, approvals.record_request(name, incident,
                                                                              str(data.get("issued_at", ""))))
        if refused:
            return refused
        allowed = set(self.policy.approvers[name].environments)
        if not incident:
            listed = []
            for i in records.incident_ids(self.log)[:RECORD_SCAN]:
                r = records.record(self.log, i, self.policy, light=True)
                if r is not None and r.environment in allowed:
                    listed.append({"id": r.id, "first": r.first.isoformat(), "environment": r.environment,
                                   "service": r.service, "alarm": r.alarm, "status": r.status, "verdict": r.verdict})
                if len(listed) >= RECORD_LIST:
                    break
            return _json(200, {"incidents": listed})
        r = records.record(self.log, incident, self.policy)
        if r is None or r.environment not in allowed:
            return _json(404, {"error": "no record this approver may read"})
        return _json(200, json.loads(json.dumps({
            "id": r.id, "first": r.first, "last": r.last, "alarm": r.alarm, "environment": r.environment,
            "service": r.service, "severity": r.severity, "status": r.status, "hypothesis": r.hypothesis,
            "confidence": r.confidence, "action": r.action, "target": r.target, "verdict": r.verdict,
            "policies": r.policies, "plan": r.plan, "no_plan": r.no_plan, "decisions": r.decisions, "also": r.also,
            "report": r.report}, default=str)))

    def _signed_plan(self, name: str, data: dict) -> Response:
        """The incident's waiting plan, to the limited approver who signed `plan-request|approver|incident|time` in
        the last five minutes - only a plan in an environment and a tier it may approve."""
        incident, issued = str(data.get("incident", "")), str(data.get("issued_at", ""))
        refused = self._signature_refused(name, data, approvals.plan_request(name, incident, issued))
        if refused:
            return refused
        rows = self.log.entries(incident, kinds=("remediation.plan",))
        wid = str((rows[-1]["body"] if rows else {}).get("workflow_id", ""))
        plan = self.plan_of(wid) if wid else None
        approver = self.policy.approvers[name]
        if plan is None or plan.environment not in approver.environments or plan.tier not in approver.tiers:
            return _json(404, {"error": "no plan this approver may approve is waiting for that incident"})
        return _json(200, {"workflow_id": plan.workflow_id, "plan_hash": plan.plan_hash, "tier": plan.tier,
                           "environment": plan.environment, "entry": plan.entry, "target": plan.target})

    # ------------------------------------------------------------------ sign in with Slack

    def _signed_in(self, token: str, approver: str, enrolling: bool = False) -> bool:
        """Has Slack said that the member at the page for this link is the approver it was made for? True where the
        runtime has no Slack app. An approver with no Slack member in the list cannot approve where it has one - but
        can enrol: the enrolment writes the member Slack named into the list it hands back."""
        if self.slack is None:
            return True
        member, entry = self.store.slack_of(token), self.policy.approvers.get(approver)
        if not member or entry is None:
            return False
        return member == entry.slack or (enrolling and not entry.slack)

    def _approver_of(self, kind: str, token: str) -> str | None:
        """The approver a link of this kind was made for - an approval's (a), an enrolment's (e), a kill switch
        reset's (k) - or None: not a link, not valid now, or no such kind."""
        if kind == "a":
            link = self.store.link(token)
            return link.approver if link is not None and self.clock() < link.expires_at else None
        purpose = {"e": INVITE, "k": RESET_INVITE}.get(kind)
        return self._invited(token, purpose) if purpose else None

    def _recognise(self, kind: str, token: str, cookies: Any) -> None:
        """A browser Slack already named in the last hours (slack_login.remember) is not sent to Slack again for
        each link: its member is noted for this link, on the record as `via: remembered`, when it is the member the
        link's approver is. Never for an approver with no Slack member yet - that link is made at a real sign-in."""
        from .slack_login import remembered

        value = next((c.split("=", 1)[1] for c in cookies if isinstance(c, str) and c.startswith(_WHO + "=")), "")
        member = remembered(self.slack, value) if value else ""
        if not member or self.store.slack_of(token):
            return
        approver = self._approver_of(kind, token)
        entry = self.policy.approvers.get(approver) if approver else None
        if entry is not None and entry.slack and entry.slack == member:
            self.store.note_slack(token, approver, {"user": member, "team": "", "via": "remembered"})

    def _slack(self, method: str, parts: list[str], query: str, cookies: Any) -> Response:
        """`/s/a/<token>`, `/s/e/<token>` and `/s/k/<token>` send the browser to Slack's sign-in; `/s/callback` takes
        its answer. The link's token never goes to Slack: it stays in a cookie of this site, and Slack carries only
        that cookie's hash as the state."""
        import hashlib
        import urllib.parse

        from .slack_login import REMEMBER_S, SlackLoginError, remember

        if (method, parts) == ("POST", ["interact"]):
            # Slack tells an app of every button click, a link button's too, and marks the button as failed unless
            # that is answered. Answered, unread: the click opened the page, and nothing is decided here.
            return Response(200, {"Content-Type": "text/plain", "Cache-Control": "no-store"}, "")
        if self.slack is None or method != "GET":
            return _json(404, {"error": "not found"})
        redirect = f"{self.origin}/s/callback"
        if parts == ["r"] or (len(parts) == 2 and parts[0] == "r" and _INCIDENT_ID.fullmatch(parts[1])):
            # The records: no link, the reader's own sign-in (records.py) - and the incident to come back to, if any.
            nonce = secrets.token_urlsafe(16)
            value = f"r/{parts[1] if len(parts) == 2 else 'records'}.{nonce}"
            state = hashlib.sha256(value.encode()).hexdigest()
            return Response(302, {"Location": self.slack.authorize_url(redirect_uri=redirect, state=state, nonce=nonce),
                                  "Set-Cookie": f"{_COOKIE}={value}; Max-Age=600; Path=/s; Secure; HttpOnly; SameSite=Lax",
                                  "Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}, "")
        if len(parts) == 2 and parts[0] in ("a", "e", "k"):
            kind, token = parts
            if self._approver_of(kind, token) is None:
                return _notice(404, "This link is not valid.")
            nonce = secrets.token_urlsafe(16)
            value = f"{kind}/{token}.{nonce}"
            state = hashlib.sha256(value.encode()).hexdigest()
            return Response(302, {"Location": self.slack.authorize_url(redirect_uri=redirect, state=state, nonce=nonce),
                                  "Set-Cookie": f"{_COOKIE}={value}; Max-Age=600; Path=/s; Secure; HttpOnly; SameSite=Lax",
                                  "Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}, "")
        if parts != ["callback"]:
            return _json(404, {"error": "not found"})
        asked = urllib.parse.parse_qs(query)
        value = next((c.split("=", 1)[1] for c in cookies if isinstance(c, str) and c.startswith(_COOKIE + "=")), "")
        code, state = (asked.get(k, [""])[0] for k in ("code", "state"))
        if not value or not code or hashlib.sha256(value.encode()).hexdigest() != state or "." not in value:
            return _notice(400, "This sign-in did not start on this page. Open the link from the message again.")
        where, nonce = value.rsplit(".", 1)
        kind, _, token = where.partition("/")
        if kind == "r":
            try:
                member = self.slack.member(code, redirect_uri=redirect, nonce=nonce)
            except SlackLoginError as exc:
                return _notice(403, f"Slack sign-in failed: {exc}.")
            if not self._may_read(member["user"]):
                from .records import refused_page

                return self._served_html(403, refused_page())
            back = token if token != "records" and _INCIDENT_ID.fullmatch(token) else ""
            return Response(302, {"Location": f"/r/{back}" if back else "/r", "Cache-Control": "no-store",
                                  "Set-Cookie": (f"{_WHO}={remember(self.slack, member['user'])}; Max-Age={REMEMBER_S}; "
                                                 "Path=/; Secure; HttpOnly; SameSite=Lax")}, "")
        approver = self._approver_of(kind, token)
        if approver is None or approver not in self.policy.approvers:
            return _notice(404, "This link is not valid.")
        try:
            member = self.slack.member(code, redirect_uri=redirect, nonce=nonce)
        except SlackLoginError as exc:
            return _notice(403, f"Slack sign-in failed: {exc}.")
        wanted = self.policy.approvers[approver].slack
        if (wanted and member["user"] != wanted) or (not wanted and kind != "e"):
            # Not said which approver the link is for: a link shows nothing of that before the passkey.
            return _notice(403, "This Slack account is not the approver this link was made for. Nothing was shown or "
                                "decided." if wanted else
                                "The approver this link was made for has no Slack identity in the approver list yet. "
                                "Enrol a passkey again: the enrolment links it.")
        self.store.note_slack(token, approver, member)
        # This browser is remembered, so the next link does not ask Slack again; the sign-in's own cookie ends by
        # itself in ten minutes and opens nothing alone (its code is spent).
        return Response(302, {"Location": f"/{kind}/{token}", "Cache-Control": "no-store",
                              "Set-Cookie": (f"{_WHO}={remember(self.slack, member['user'])}; Max-Age={REMEMBER_S}; "
                                             "Path=/; Secure; HttpOnly; SameSite=Lax")}, "")

    # ------------------------------------------------------------------ records

    def _may_read(self, member: str) -> bool:
        """WARDEN's records are for its approvers and the people on its viewer list (WARDEN_RECORD_VIEWERS, Slack
        member ids): the record names resources, people and what they wrote."""
        viewers = {v.strip() for v in os.environ.get("WARDEN_RECORD_VIEWERS", "").split(",") if v.strip()}
        return bool(member) and (member in viewers or any(a.slack == member for a in self.policy.approvers.values()))

    def _records(self, method: str, parts: list[str], cookies: Any, query: str = "") -> Response:
        """`/r`: every incident of the last 30 days; `/r/<incident>`: one, whole (records.py). For a reader Slack
        named in this browser who may read them; anyone else is asked to sign in, and is not shown that an incident
        exists."""
        from . import records
        from .slack_login import remembered

        if method != "GET" or len(parts) > 1:
            return _json(404, {"error": "not found"})
        if self.slack is None:
            # The records have no passkey behind them: with no Slack sign-in to say who is reading, nobody reads them
            # (independent check, 2026-10-14: they were open to anyone where the runtime had no Slack app).
            return self._served_html(503, records.unavailable_page())
        value = next((c.split("=", 1)[1] for c in cookies if isinstance(c, str) and c.startswith(_WHO + "=")), "")
        member = remembered(self.slack, value) if value else ""
        if not member:
            # Back to the page the reader opened after Slack's sign-in, not to the list (2026-10-15: a report's "Full
            # record" button landed on every incident once signed in). Only an incident id's shape travels.
            back = parts[0] if parts and _INCIDENT_ID.fullmatch(parts[0] or "") else ""
            return self._served_html(200, records.signed_out_page(f"/s/r/{back}" if back else "/s/r"))
        if not self._may_read(member):
            return self._served_html(403, records.refused_page())
        if self.log is None:
            return _json(503, {"error": "the record cannot be read here"})
        if not parts or not parts[0]:
            import urllib.parse

            ids = records.incident_ids(self.log)
            pages = max(1, -(-len(ids) // records.PER_PAGE))
            asked = urllib.parse.parse_qs(query).get("page", ["1"])[0]
            page = min(max(int(asked) if asked.isdigit() else 1, 1), pages)
            shown = ids[(page - 1) * records.PER_PAGE:page * records.PER_PAGE]
            found = [records.record(self.log, i, self.policy, light=True) for i in shown]
            return self._served_html(200, records.list_page([r for r in found if r is not None], page=page,
                                                            pages=pages, total=len(ids)))
        one = records.record(self.log, parts[0], self.policy) if not parts[0].startswith("discuss-") else None
        if one is None:
            return self._served_html(404, records.missing_page())
        approver = self._approver_for(member, one)
        if "approve=1" in query.split("&"):
            # The record's own button: a fresh link for this reader and this plan, the same the Slack message gives -
            # it opens the plan; the decision is still the approver's passkey (`?approve=1`: API Gateway routes only
            # GET /r/{incident}).
            if not approver:
                return _json(404, {"error": "nothing here for you to approve"})
            token = self.new_link(str(one.plan["workflow_id"]), approver)
            return Response(303, {"Location": f"/a/{token}", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
                            "")
        return self._served_html(200, records.incident_page(one, approve=f"/r/{one.id}?approve=1" if approver else ""))

    def _approver_for(self, member: str, r: Any) -> str:
        """The approver this Slack member is, when the incident's plan waits for an approval their tier allows and
        they have a passkey to give it; otherwise ''."""
        if r.status != "Waiting for approval" or not r.plan.get("workflow_id"):
            return ""
        tier = str(r.plan.get("tier") or "")
        return next((a for a, e in sorted(self.policy.approvers.items())
                     if e.slack and e.slack == member and tier in e.tiers and e.passkeys), "")

    def _served_html(self, status: int, page: str) -> Response:
        nonce = secrets.token_urlsafe(16)
        return Response(status, _headers(nonce, "text/html; charset=utf-8"), page.replace("{{NONCE}}", nonce))

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
            return self._served(_ENROL, not self._signed_in(token, approver, enrolling=True))
        if not self._signed_in(token, approver, enrolling=True):
            return _json(403, {"error": "sign in with Slack first"})
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
        if self.slack is not None and not listed.approvers[approver].slack:
            # The member Slack itself named at this enrolment: linked in the list handed back, never typed.
            listed.approvers[approver].slack = self.store.slack_of(token)
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
            return self._served(_RESET, not self._signed_in(token, approver))
        if not self._signed_in(token, approver):
            return _json(403, {"error": "sign in with Slack first"})
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

    def _served(self, page: str, slack_first: bool) -> Response:
        nonce = secrets.token_urlsafe(16)
        return Response(200, _headers(nonce, "text/html; charset=utf-8"),
                        page.replace("{{NONCE}}", nonce).replace("{{SLACK}}", "1" if slack_first else "0"))

    def _shell(self, token: str, link: Link, data: dict) -> Response:
        return self._served(_PAGE, not self._signed_in(token, link.approver))

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
        self.deny(plan.workflow_id, Denial(approver=link.approver, workflow_id=plan.workflow_id,
                                           plan_hash=plan.plan_hash, reason=approvals.note(data.get("note"), incoming=True)))
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
            nonce=pending.nonce, expires_at=pending.expires_at, challenge=pending.challenge, response=data["response"],
            note=approvals.note(data.get("note"), incoming=True)))
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


_COOKIE = "warden_s"  # holds the link while the browser is at Slack: this site's only, ten minutes, /s alone
# A limited approver's signed read (/a/signed/record): the latest this many incidents in its environments, found among
# the newest RECORD_SCAN on the record.
RECORD_LIST, RECORD_SCAN = 20, 200
_WHO = "warden_who"  # the member Slack named in this browser, sealed (slack_login.remember): no script can read it
# An incident id's shape (chatops: the "Full record" link's): all that travels through Slack's sign-in, and back.
_INCIDENT_ID = re.compile(r"[A-Za-z0-9._-]{1,120}")


def _notice(status: int, text: str) -> Response:
    """A page that only says something: where the Slack sign-in ends without a link to go back to."""
    nonce = secrets.token_urlsafe(16)
    return Response(status, _headers(nonce, "text/html; charset=utf-8"),
                    _NOTICE.replace("{{NONCE}}", nonce).replace("{{SLACK}}", "0").replace("{{TEXT}}", text))


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
a.slack{display:block;text-align:center;text-decoration:none;font-weight:600;border-radius:.75rem;padding:.75rem 1rem}
#note{font:inherit;line-height:1.5}
#clear{margin-top:.75rem;color:var(--ink);background:var(--sheet);border-color:var(--line)}
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
if (document.body.dataset.slack === "1") {
  for (const b of document.querySelectorAll("button")) { b.hidden = true; }
  const go = document.createElement("a");
  go.className = "primary slack"; go.textContent = "Sign in with Slack";
  go.href = "/s" + base;  /* this site's own address for the link, which sends the browser on to Slack */
  document.querySelector(".bar").append(go);
  say("First, sign in with Slack: it says which person you are. Then your passkey.");
}
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
<body data-busy="0" data-slack="{{SLACK}}"><div class="page">
<header class="top"><span class="mark">WARDEN</span><span class="where">{{WHERE}}</span></header>
<main class="sheet">{{MAIN}}</main>
<p class="foot">{{FOOT}}</p>
</div>
<script nonce="{{NONCE}}">{{JS}}{{SCRIPT}}</script></body></html>
"""


def _page(title: str, where: str, main: str, foot: str, script: str) -> str:
    return (_SHELL.replace("{{TITLE}}", title).replace("{{WHERE}}", where).replace("{{MAIN}}", main)
            .replace("{{FOOT}}", foot).replace("{{STYLE}}", _STYLE).replace("{{JS}}", _JS).replace("{{SCRIPT}}", script))


_NOTICE = _page("WARDEN", "Sign-in", """
<h1 id="title">Sign-in</h1>
<p class="lede">{{TEXT}}</p>
<div class="bar"><p id="status" role="status" aria-live="polite" data-kind="info">You can close this page.</p></div>
""", "WARDEN asks Slack who you are, then your passkey that you are here.", "")

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
<textarea id="list" rows="14" readonly></textarea>
<span class="hint">It holds the passkey's public half only: the key itself never leaves your device. T1, T2 and T3 in
it are the risk levels this approver may decide: T1 low (one small, bounded change to one resource), T2 medium (a
reversible change to a service's settings or version), T3 high (hard to undo, or it changes access, the network or
infrastructure).</span></div></section>
<div class="bar"><p id="status" role="status" aria-live="polite" data-kind="info">Create a passkey on this device to
approve plans with it.</p>
<button id="make" class="primary" type="button">Create my passkey</button>
<button id="copy" class="primary" type="button" hidden>Copy the list</button>
<button id="clear" type="button" hidden>Done: clear this page</button></div>
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
  $("clear").hidden = false;
});
/* Nothing of the list stays on a page left open, or comes back with the browser's Back button. */
const wipe = () => { $("list").value = ""; $("done").hidden = true; $("copy").hidden = true; $("clear").hidden = true; };
$("clear").addEventListener("click", () => {
  wipe(); $("title").textContent = "Done"; step(3);
  say("Cleared. Save the copied list as the approver list, then close this tab.", "ok");
});
window.addEventListener("pagehide", wipe);
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
<p><label for="note">A note with your decision (optional)
<span class="hint">Kept on the record and shown with your name in the message, whether you approve or deny. Not a place
for a password or a key.</span></label>
<textarea id="note" rows="3" maxlength="2000" autocomplete="off"></textarea></p>
<button id="ok" class="primary" type="button">Approve this plan with my passkey</button>
<div class="deny"><p>Or deny it: nothing will change.</p>
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
    const h = Math.floor(left / 3600), m = Math.floor(left % 3600 / 60);
    $("left").textContent = "This link works for " + (h ? h + " h " + m + " min" : m + " min " + (left % 60) + " s") +
                            " more.";
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
    const [ok, d] = await post("approve", {response, typed_target: $("typed").value, note: $("note").value});
    if (ok) { sent("Approval sent" + (me ? " as " + me : "") + ". " + d.note); } else { say(d.error, "bad"); }
  } catch (e) { say("Not approved: " + e.message, "bad"); } finally { busy(false); }
});
$("no").addEventListener("click", async () => {
  busy(true);
  try {
    const response = await passkey("deny-options");
    say("Sending your denial. This takes a few seconds; do not click again.", "work");
    const [ok, d] = await post("deny", {response, note: $("note").value});
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
