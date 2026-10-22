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

import hashlib
import json
import os
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

import yaml
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

from . import approvals, passkeys
from .approvals import ApproverPolicy, PasskeyAssertion, PasskeyCredential
from .brand import FAVICON_LINK, LOGO_SVG
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
STOP_INVITE = b"warden-killswitch-on:v1:"  # a link to turn the switch ON
KILLSWITCH_ON = "killswitch-on"  # the workflow id a passkey's "stop" is signed for
STOP_REASON_MAX = 300


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


class LinkStore(Protocol):
    """Where an approval page keeps its links, who Slack said was at the page for each, and passkey challenges."""

    def add_link(self, token: str, link: Link) -> None: ...

    def link(self, token: str) -> Link | None: ...

    def mark_viewed(self, token: str) -> None: ...

    def use_link(self, token: str) -> None: ...

    def used(self, token: str) -> bool: ...

    # Who Slack said was at the page for this link (`member`), for the approver the link was made for.
    def note_slack(self, token: str, approver: str, member: dict[str, str]) -> None: ...

    def slack_of(self, token: str) -> str: ...

    def put_challenge(self, key: str, pending: passkeys.Pending) -> None: ...

    def challenge(self, key: str) -> passkeys.Pending | None: ...

    def take_challenge(self, key: str) -> passkeys.Pending | None: ...


class MemoryLinkStore(LinkStore):
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


class AuditLinkStore(LinkStore):
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
        if not made or self._rows(_LINK_USED, key):
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
        self.log.append(link.workflow_id if link else "approval", _LINK_USED, {"key": self._key(token)})

    def used(self, token: str) -> bool:
        return bool(self._rows(_LINK_USED, self._key(token)))

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
    store: LinkStore = field(default_factory=MemoryLinkStore)
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
    # WARDEN's own pages (paging.S3Pages): the ones the pager repeats, and an approver's acknowledgement. None: no `/p`.
    pages: Any = None

    @property
    def origin(self) -> str:
        return f"https://{self.rp_id}"

    def new_link(self, workflow_id: str, approver: str) -> str:
        token = secrets.token_urlsafe(32)
        self.store.add_link(token, Link(workflow_id, approver, self.clock() + LINK_TTL))
        return token

    # ------------------------------------------------------------------ routing

    def handle(self, method: str, path: str, body: str = "", query: str = "", cookies: Any = ()) -> Response:
        parts, verb = path.strip("/").split("/"), method.upper()
        if parts[0] == "s":
            return self._slack(verb, parts[1:], query, cookies)
        if parts[0] == "r":
            return self._records(verb, parts[1:], cookies, query, body)
        if parts[0] == "p":
            return self._pages(verb, parts[1:], body, cookies)
        if self.slack is not None and len(parts) >= 2:
            self._recognise(parts[0], parts[1], cookies)
        if len(parts) < 2:
            return _json(404, {"error": _NOT_FOUND})
        # A signed link's own step: an enrolment (e), a kill switch reset (k) or stop (x).
        invited = {"e": self._enrol, "k": self._reset, "x": self._stop}.get(parts[0])
        if invited is not None:
            return invited(verb, parts[1], parts[2] if len(parts) > 2 else "", body)
        if parts[0] != "a":
            return _json(404, {"error": _NOT_FOUND})
        return self._approval(verb, parts, body)

    def _approval(self, verb: str, parts: list[str], body: str) -> Response:
        """`/a/<token>[/<step>]`: an approval link's page and its steps; `/a/signed/<step>`: a limited approver's."""
        if parts[1] == "signed" and len(parts) == 3 and verb == "POST":
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
        route = routes.get((verb, action))
        if route not in (None, self._shell) and not self._signed_in(token, link.approver):
            return _json(403, {"error": _SIGN_IN_FIRST})
        return route(token, link, data) if route else _json(404, {"error": _NOT_FOUND})

    # ------------------------------------------------------------------ a limited approver's signed approval

    def _signed_request(self, step: str, body: str) -> Response:
        """`/a/signed/plan` and `/a/signed/approve`: an approver limited to some environments (the bench approver,
        owner 2026-10-15) asks for an incident's waiting plan with a signed request, then sends a signed approval of
        it. Every check of approvals.check runs here and again in the workflow; an approver with no environment list
        - a person - never uses this path. `/a/signed/record`: that approver reads the record of an incident in its
        environments, read only (owner, 2026-10-15: access to WARDEN's incidents and records, for dev)."""
        if (self.log is None or step not in ("plan", "approve", "record", "deny")
                or (step in ("plan", "approve") and self.signed is None) or (step == "deny" and self.deny is None)):
            return _json(404, {"error": _NOT_FOUND})
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
        except Exception:  # noqa: BLE001 - an unparsable time; an unknown key or a bad signature: refused the same
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
                or approvals.environment_refusal(name, approver, plan.environment) or plan.tier not in approver.tiers):
            return _json(404, {"error": "no plan this approver may deny is waiting under that id and hash"})
        try:
            denial = approvals.Denial(approver=name, workflow_id=wid, plan_hash=ph, reason=reason)
        except Exception:  # noqa: BLE001 - a reason past NOTE_MAX; or a malformed name: refused whole
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
            "report": r.report, "audit_head": r.head, "signed_ok": r.signed_ok, "unsigned": r.unsigned,
            "broken": r.broken}, default=str)))

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
        reset's (k), a kill switch stop's (x) - or None: not a link, not valid now, or no such kind."""
        if kind == "a":
            link = self.store.link(token)
            return link.approver if link is not None and self.clock() < link.expires_at else None
        purpose = {"e": INVITE, "k": RESET_INVITE, "x": STOP_INVITE}.get(kind)
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
        if (method, parts) == ("POST", ["interact"]):
            # Slack tells an app of every button click, a link button's too, and marks the button as failed unless
            # that is answered. Answered, unread: the click opened the page, and nothing is decided here.
            return Response(200, {"Content-Type": "text/plain", "Cache-Control": "no-store"}, "")
        if self.slack is None or method != "GET":
            return _json(404, {"error": _NOT_FOUND})
        redirect = f"{self.origin}/s/callback"
        started = self._slack_start(parts, redirect)
        if started is not None:
            return started
        if parts != ["callback"]:
            return _json(404, {"error": _NOT_FOUND})
        return self._slack_callback(query, cookies, redirect)

    def _slack_start(self, parts: list[str], redirect: str) -> Response | None:
        """To Slack's sign-in, for WARDEN's own pages, the records or a link; None where `parts` names none of them."""
        if parts == ["p"]:
            # WARDEN's own pages: no link, the reader's own sign-in, then back to `/p`.
            return self._to_slack(redirect, "p/pages")
        if parts == ["r"] or (len(parts) == 2 and parts[0] == "r" and _INCIDENT_ID.fullmatch(parts[1])):
            # The records: no link, the reader's own sign-in (records.py) - and the incident to come back to, if any.
            return self._to_slack(redirect, f"r/{parts[1] if len(parts) == 2 else 'records'}")
        if len(parts) == 2 and parts[0] in ("a", "e", "k", "x"):
            kind, token = parts
            if self._approver_of(kind, token) is None:
                return _notice(404, "This link is not valid.")
            return self._to_slack(redirect, f"{kind}/{token}")
        return None

    def _to_slack(self, redirect: str, where: str) -> Response:
        """The browser to Slack's sign-in: `where` to come back to, with a fresh nonce, in this site's cookie for ten
        minutes - and only that cookie's hash to Slack, as the state."""
        nonce = secrets.token_urlsafe(16)
        value = f"{where}.{nonce}"
        state = hashlib.sha256(value.encode()).hexdigest()
        return Response(302, {"Location": self.slack.authorize_url(redirect_uri=redirect, state=state, nonce=nonce),
                              "Set-Cookie": f"{_COOKIE}={value}; Max-Age=600; Path=/s; Secure; HttpOnly; SameSite=Lax",
                              "Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}, "")

    def _slack_callback(self, query: str, cookies: Any, redirect: str) -> Response:
        """Slack's answer: only for the sign-in this browser started here (its cookie's hash is the state), and for a
        link only when Slack names the member its approver is."""
        import urllib.parse

        from .slack_login import SlackLoginError

        asked = urllib.parse.parse_qs(query)
        value = next((c.split("=", 1)[1] for c in cookies if isinstance(c, str) and c.startswith(_COOKIE + "=")), "")
        code, state = (asked.get(k, [""])[0] for k in ("code", "state"))
        if not value or not code or hashlib.sha256(value.encode()).hexdigest() != state or "." not in value:
            return _notice(400, "This sign-in did not start on this page. Open the link from the message again.")
        where, nonce = value.rsplit(".", 1)
        kind, _, token = where.partition("/")
        if kind in ("r", "p"):
            return self._reader_signed_in(kind, token, code, redirect, nonce)
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
        return self._remembered(f"/{kind}/{token}", member)

    def _reader_signed_in(self, kind: str, token: str, code: str, redirect: str, nonce: str) -> Response:
        """A reader of the records (r) or of WARDEN's own pages (p) Slack named: back to where they were going, when
        they may read it."""
        from .slack_login import SlackLoginError

        try:
            member = self.slack.member(code, redirect_uri=redirect, nonce=nonce)
        except SlackLoginError as exc:
            return _notice(403, f"Slack sign-in failed: {exc}.")
        if not self._may_read(member["user"]):
            from .records import refused_page

            return self._served_html(403, refused_page())
        back = token if kind == "r" and token != "records" and _INCIDENT_ID.fullmatch(token) else ""
        to = f"/r/{back}" if back else "/r"
        if kind == "p":
            to = "/p"
        return self._remembered(to, member)

    def _remembered(self, to: str, member: dict[str, str]) -> Response:
        """On to `to`, with this browser remembered as the member Slack named (slack_login.remember)."""
        from .slack_login import REMEMBER_S, remember

        return Response(302, {"Location": to, "Cache-Control": "no-store",
                              "Set-Cookie": (f"{_WHO}={remember(self.slack, member['user'])}; Max-Age={REMEMBER_S}; "
                                             "Path=/; Secure; HttpOnly; SameSite=Lax")}, "")

    # ------------------------------------------------------------------ records

    def _may_read(self, member: str) -> bool:
        """WARDEN's records are for its approvers and the people on its viewer list (WARDEN_RECORD_VIEWERS, Slack
        member ids): the record names resources, people and what they wrote."""
        return bool(member) and (member in self._viewers()
                                 or any(a.slack == member for a in self.policy.approvers.values()))

    def _records(self, method: str, parts: list[str], cookies: Any, query: str = "", body: str = "") -> Response:
        """`/r`: every incident of the last 30 days; `/r/<incident>`: one, whole (records.py); `/r/<incident>/masked`:
        its masked values and their reveal (reveal.py). For a reader Slack named in this browser who may read them;
        anyone else is asked to sign in, and is not shown that an incident exists."""
        from . import records

        masked = parts[1:] == ["masked"]
        if not _records_route(method, parts, masked):
            return _json(404, {"error": _NOT_FOUND})
        if self.slack is None:
            # The records have no passkey behind them: with no Slack sign-in to say who is reading, nobody reads them
            # (independent check, 2026-10-14: they were open to anyone where the runtime had no Slack app).
            return self._served_html(503, records.unavailable_page())
        member = self._reader(cookies)
        if not member:
            return self._signed_out(parts)
        if not self._may_read(member):
            return self._served_html(403, records.refused_page())
        if self.log is None:
            return _json(503, {"error": "the record cannot be read here"})
        allowed = self._environments_for(member)
        if parts and parts[0] == records.PILOT:
            return self._pilot(query, allowed)
        if not parts or not parts[0]:
            return self._record_list(query, allowed)
        one = self._readable(parts[0], allowed)
        if one is None:
            # One answer for "none" and "not yours": a reader limited to some environments is not told of the others.
            return self._served_html(404, records.missing_page())
        if masked:
            return self._masked(one, member, _who_cookie(cookies), method, body)
        return self._record_page(one, member, allowed, query)

    def _reader(self, cookies: Any) -> str:
        """The member Slack named in this browser in the last hours (slack_login.remember) - or ''."""
        from .slack_login import remembered

        value = _who_cookie(cookies)
        return remembered(self.slack, value) if value else ""

    def _signed_out(self, parts: list[str]) -> Response:
        """The way to sign in, for a reader Slack has not named in this browser."""
        from . import records

        # Back to the page the reader opened after Slack's sign-in, not to the list (2026-10-15: a report's "Full
        # record" button landed on every incident once signed in). Only an incident id's shape travels.
        back = parts[0] if parts and _INCIDENT_ID.fullmatch(parts[0] or "") else ""
        return self._served_html(200, records.signed_out_page(f"/s/r/{back}" if back else "/s/r"))

    def _record_list(self, query: str, allowed: set[str] | None) -> Response:
        """`/r`: one page of the list, as the query reads it - only the incidents in `allowed` (None: every one)."""
        from . import records

        asked = records.parse_query(query)
        if asked is None:
            return self._served_html(400, records.bad_query_page())
        ids, loaded, seen = records.matching(self.log, asked, allowed, self.policy)
        pages = max(1, -(-len(ids) // asked.size))
        page = min(asked.page, pages)  # past the end: the last page
        shown = ids[(page - 1) * asked.size:page * asked.size]
        found = [loaded.get(i) or records.record(self.log, i, self.policy, light=True) for i in shown]
        return self._served_html(200, records.list_page(
            [r for r in found if r is not None], page=page, pages=pages, total=seen, matched=len(ids),
            asked=asked, envs=self._environment_choices(allowed)), form=True)

    def _readable(self, incident: str, allowed: set[str] | None) -> Any:
        """The incident's record when this reader may read it (its environment in `allowed`; None: every one), else
        None. A discussion's own reading of an incident is not one of its own."""
        from . import records

        one = records.record(self.log, incident, self.policy) if not incident.startswith("discuss-") else None
        return None if one is None or (allowed is not None and one.environment not in allowed) else one

    def _record_page(self, one: Any, member: str, allowed: set[str] | None, query: str) -> Response:
        """`/r/<incident>`: one incident, whole - and, with `?approve=1`, a fresh link to its plan for this reader."""
        from . import records, reveal

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
        asked = records.parse_query(query)
        if asked is None:
            return self._served_html(400, records.bad_query_page())
        ids, _, _ = records.matching(self.log, asked, allowed, self.policy)
        # The masked values' link for those who may reveal them only (approvers; review, 2026-10-21).
        link = reveal.link(self.log, one.id) if self._may_reveal(member, one) else ""
        return self._served_html(200, records.incident_page(one, approve=f"/r/{one.id}?approve=1" if approver else "",
                                                            near=records.neighbours(ids, one.id, asked) + link))

    def _may_reveal(self, member: str, one: Any) -> bool:
        """An approver who may approve in the incident's environment - approvals.environment_refusal, the one rule
        every approval path uses: the approver's own environment list and the bench approver's nonprod-only limit
        (review, PR 119). A viewer (WARDEN_RECORD_VIEWERS) may read the record and never reveal a masked value
        (owner-safe default, review 2026-10-21; a passkey step-up is an open owner decision)."""
        env = str(one.environment or "")
        return any(a.slack == member and approvals.environment_refusal(name, a, env) is None
                   for name, a in self.policy.approvers.items() if a.slack)

    def _masked(self, one: Any, member: str, cookie: str, method: str, body: str) -> Response:
        """An incident's masked values, and their reveal for this reader (reveal.py): its own form, POSTed to itself
        - the reason and the choice travel in the body, never in an address."""
        import urllib.parse

        from . import reveal

        status, page = reveal.reveal(self.log, one.id, member=member, cookie=cookie,
                                     form=body if method == "POST" else None, environment=str(one.environment or ""),
                                     approver=self._may_reveal(member, one))
        nonce = secrets.token_urlsafe(16)
        action = f"{self.origin}/r/{urllib.parse.quote(one.id, safe='')}/masked"
        return Response(status, _headers(nonce, _HTML, action), page.replace(_NONCE, nonce))

    def _pilot(self, query: str, allowed: set[str] | None) -> Response:
        """`/r/pilot`: the pilot metrics (pilot.py) of the incidents this reader may read, from rows whose signatures
        check out against the audit's own signing key - none shown when this runtime cannot check them."""
        from . import pilot, records

        since = records.pilot_since(query)
        if since is None:
            return self._served_html(400, records.bad_query_page())
        try:
            checked = pilot.read(self.log, self.log.key.public_key())
        except Exception:  # noqa: BLE001 - no signing key or an unreadable record so no number is shown unchecked
            return self._served_html(503, records.pilot_unchecked_page())
        return self._served_html(200, records.pilot_page(pilot.report(checked, since, allowed=allowed)))

    @staticmethod
    def _viewers() -> set[str]:
        return {v.strip() for v in os.environ.get("WARDEN_RECORD_VIEWERS", "").split(",") if v.strip()}

    def _environments_for(self, member: str) -> set[str] | None:
        """The environments a reader may read the records of: None for every one - a viewer, or an approver with no
        environment list - else those of the approver entries this member is, every one of them limited (the bench
        approver, owner 2026-10-15: dev only)."""
        mine = [a for a in self.policy.approvers.values() if a.slack and a.slack == member]
        if member in self._viewers() or not mine or any(not a.environments for a in mine):
            return None
        return {e for a in mine for e in a.environments}

    @staticmethod
    def _environment_choices(allowed: set[str] | None) -> tuple[str, ...]:
        """The environments the list's filter offers: the reader's own when limited, else every configured one."""
        if allowed is not None:
            return tuple(sorted(allowed))
        try:
            from .environments import default_environment_policies

            return tuple(default_environment_policies().known_environments)
        except Exception:  # noqa: BLE001 - no configuration here: the filter offers "Any" and what the address asked
            return ()

    def _approver_for(self, member: str, r: Any) -> str:
        """The approver this Slack member is, when the incident's plan waits for an approval their tier allows and
        they have a passkey to give it; otherwise ''."""
        if r.status != "Waiting for approval" or not r.plan.get("workflow_id"):
            return ""
        tier = str(r.plan.get("tier") or "")
        return next((a for a, e in sorted(self.policy.approvers.items())
                     if e.slack and e.slack == member and tier in e.tiers and e.passkeys), "")

    def _served_html(self, status: int, page: str, *, form: bool = False) -> Response:
        nonce = secrets.token_urlsafe(16)
        return Response(status, _headers(nonce, _HTML,
                                         f"{self.origin}/r" if form else "'none'"), page.replace(_NONCE, nonce))

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
        except Exception:  # noqa: BLE001 - whatever is wrong with a link; it invites nobody
            return None

    def _enrol(self, method: str, token: str, step: str, body: str) -> Response:
        approver = self._invited(token)
        if approver is None:
            return _json(404, {"error": "this enrolment link is not valid"})
        key = f"{token}:{ENROL}"
        if (method, step) == ("GET", ""):
            return self._served(_ENROL, not self._signed_in(token, approver, enrolling=True))
        if not self._signed_in(token, approver, enrolling=True):
            return _json(403, {"error": _SIGN_IN_FIRST})
        if (method, step) == ("POST", "options"):
            options, challenge = passkeys.registration_options(rp_id=self.rp_id, rp_name="WARDEN", approver=approver)
            self.store.put_challenge(key, passkeys.Pending(
                workflow_id=ENROL, plan_hash=f"{ENROL}:{approver}", tier=ENROL, nonce=secrets.token_urlsafe(16),
                expires_at=self.clock() + LINK_TTL, challenge=bytes_to_base64url(challenge)))
            return _json(200, {"options": json.loads(options)})
        if (method, step) != ("POST", "finish"):
            return _json(404, {"error": _NOT_FOUND})
        pending = self.store.take_challenge(key)
        if pending is None or self.clock() >= pending.expires_at:
            return _json(403, {"error": "no challenge is waiting for this answer"})
        try:
            made = passkeys.finish_registration(json.loads(body)["response"], approver=approver,
                                                challenge=base64url_to_bytes(pending.challenge), rp_id=self.rp_id,
                                                origin=self.origin)
        except Exception:  # noqa: BLE001 - a ceremony that does not verify enrols nothing; whatever the reason
            return _json(403, {"error": _NOT_ACCEPTED})
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
            return _json(403, {"error": _SIGN_IN_FIRST})
        if (method, step) == ("POST", "trips"):
            return self._reset_trips(approver, key, now)
        if (method, step) != ("POST", "reset"):
            return _json(404, {"error": _NOT_FOUND})
        pending = self.store.take_challenge(key)
        try:
            response = json.loads(body)["response"]
        except Exception:  # noqa: BLE001 - an answer that cannot be read resets nothing
            response = None
        credential = next((c for c in self._credentials(approver)
                           if isinstance(response, dict) and c.credential_id == response.get("id")), None)
        if pending is None or credential is None:
            return _json(403, {"error": _NOT_ACCEPTED})
        verified, problems = passkeys.verify_approval(response, pending=pending, credential=credential,
                                                      rp_id=self.rp_id, origin=self.origin, now=now, used_nonces=set())
        if verified is not None:
            problems = bounds.reset_by_passkey(self.log, verified, policy=self.policy, now=now)
        if problems:
            return _json(403, {"error": "the kill switch was not reset", "problems": problems})
        self.store.use_link(token)  # used once
        self.log.checkpoint()  # the reset signed the record; the link's last row is signed too
        return _json(200, {"reset": True})

    def _reset_trips(self, approver: str, key: str, now: datetime) -> Response:
        """The trips a reset would clear, and the passkey challenge over exactly them - or that the switch is off."""
        from . import bounds

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

    # ------------------------------------------------------------------ the kill switch's stop

    def _stop(self, method: str, token: str, step: str, body: str) -> Response:
        """Turning the kill switch ON where the audit is (live, 2026-10-16: `warden killswitch on` on a laptop wrote a
        local file and printed ON while the cloud runtime kept applying - no person could stop it). Stopping is the
        safe direction, so any approver may, with any of their passkeys; the passkey signs the reason they typed, and
        the trip names them. Resetting stays the riskiest tier's decision (`_reset`)."""
        from . import bounds

        approver = self._invited(token, STOP_INVITE) if self.log is not None else None
        if approver is None:
            return _json(404, {"error": "this stop link is not valid"})
        key, now = f"{token}:stop", self.clock()
        if (method, step) == ("GET", ""):
            return self._served(_STOP, not self._signed_in(token, approver))
        if not self._signed_in(token, approver):
            return _json(403, {"error": _SIGN_IN_FIRST})
        try:
            reason = " ".join(str(json.loads(body or "{}").get("reason", "")).split())
        except Exception:  # noqa: BLE001 - a request that cannot be read stops nothing
            reason = ""
        if not reason or len(reason) > STOP_REASON_MAX:
            return _json(400, {"error": f"say why you are stopping WARDEN, in 1 to {STOP_REASON_MAX} characters"})
        signed_for = hashlib.sha256(reason.encode()).hexdigest()
        if (method, step) == ("POST", "options"):
            options, pending = passkeys.approval_options(
                rp_id=self.rp_id, credentials=self._credentials(approver), workflow_id=KILLSWITCH_ON,
                plan_hash=signed_for, tier="T1", now=now)
            self.store.put_challenge(key, pending)
            return _json(200, {"options": json.loads(options), "already": bounds.killswitch(self.log) is not None})
        if (method, step) != ("POST", "on"):
            return _json(404, {"error": _NOT_FOUND})
        pending = self.store.take_challenge(key)
        try:
            response = json.loads(body)["response"]
        except Exception:  # noqa: BLE001 - an answer that cannot be read stops nothing
            response = None
        credential = next((c for c in self._credentials(approver)
                           if isinstance(response, dict) and c.credential_id == response.get("id")), None)
        if pending is None or credential is None or pending.plan_hash != signed_for:
            # The reason recorded is the one the passkey signed, never one sent after it.
            return _json(403, {"error": _NOT_ACCEPTED})
        verified, problems = passkeys.verify_approval(response, pending=pending, credential=credential,
                                                      rp_id=self.rp_id, origin=self.origin, now=now, used_nonces=set())
        if verified is None:
            return _json(403, {"error": "the kill switch was not turned on", "problems": problems})
        bounds.trip(self.log, "operator", f"turned on by {approver} with their passkey: {reason}")
        self.store.use_link(token)  # used once
        return _json(200, {"on": True})

    # ------------------------------------------------------------------ WARDEN's own pages

    def _page_approvers(self, member: str) -> list[str]:
        """Who may acknowledge WARDEN's own pages here: an approver with a passkey and no environment list - a person
        over the whole runtime, never an approver limited to some environments (the bench approver) - and only the
        approver entries the Slack member signed in here is."""
        return [a for a, e in sorted(self.policy.approvers.items()) if e.passkeys and not e.environments
                and bool(member) and e.slack == member]

    def _pages(self, method: str, parts: list[str], body: str, cookies: Any) -> Response:
        """`/p`: the pages the pager repeats every 15 minutes (paging.py), and an approver's passkey acknowledging
        exactly those shown (owner, 2026-10-16). Acknowledging stops the repeats and nothing else: the kill switch
        stays on, an alarm stays in ALARM. On the record, signed, before the pager is told."""
        from .slack_login import remembered

        if self.pages is None or self.log is None:
            return _json(404, {"error": _NOT_FOUND})
        if self.slack is None:
            # The pages name WARDEN's own faults and have no link behind them: with no Slack sign-in to say who is
            # reading, nobody reads them, as the records (CodeRabbit, PR 43: anyone could list them).
            return _json(503, {"error": "WARDEN's pages are acknowledged after Slack's sign-in, and this runtime "
                                        "has none: acknowledge them where it does, or end what they name"})
        value = next((c.split("=", 1)[1] for c in cookies if isinstance(c, str) and c.startswith(_WHO + "=")), "")
        member = remembered(self.slack, value) if value else ""
        if (method, parts) == ("GET", []):
            return self._served(_ACK, not member)
        if not member:
            return _json(403, {"error": _SIGN_IN_FIRST})
        approvers = self._page_approvers(member)
        if not approvers:
            return _json(403, {"error": "only an approver with a passkey acknowledges WARDEN's pages"})
        credentials = [c for a in approvers for c in self._credentials(a)]
        if (method, parts) == ("POST", ["pages"]):
            return self._pages_shown(credentials, member)
        if (method, parts) != ("POST", ["ack"]):
            return _json(404, {"error": _NOT_FOUND})
        return self._pages_ack(credentials, member, body)

    def _pages_shown(self, credentials: list[passkeys.Credential], member: str) -> Response:
        """The open pages, and a passkey challenge over exactly those - under an id of its own, so one look never
        replaces or takes another's challenge (CodeRabbit, PR 43)."""
        from . import paging

        shown = paging.open_pages(self.pages)
        if not shown:
            return _json(200, {"open": []})
        options, pending = passkeys.approval_options(rp_id=self.rp_id, credentials=credentials,
                                                     workflow_id=paging.WORKFLOW, plan_hash=paging.signed_for(shown),
                                                     tier="T1", now=self.clock())
        ask = secrets.token_urlsafe(16)
        self.store.put_challenge(f"pages:{member}:{ask}", pending)
        return _json(200, {"options": json.loads(options), "ask": ask, "open": [
            {"key": p["key"], "why": str(p.get("why", ""))[:600], "sent": _count(p.get("sent")),
             "opened": _opened(p.get("opened_at"))} for p in shown]})

    def _pages_ack(self, credentials: list[passkeys.Credential], member: str, body: str) -> Response:
        """The passkey's answer: checked, then on the record, then in the bucket - only for the pages it signed."""
        from . import paging

        now = self.clock()
        try:
            got = json.loads(body)
            response, ask = got["response"], str(got["ask"])
        except Exception:  # noqa: BLE001 - an answer that cannot be read acknowledges nothing
            response, ask = None, ""
        credential = next((c for c in credentials if isinstance(response, dict) and c.credential_id == response.get("id")),
                          None)
        # The challenge is taken only for an answer that names one of this member's passkeys (CodeRabbit, PR 43): a
        # malformed or foreign answer leaves the look it names open.
        pending = (self.store.take_challenge(f"pages:{member}:{ask}")
                   if credential is not None and _ASK.fullmatch(ask) else None)
        if pending is None or credential is None:
            return _json(403, {"error": _NOT_ACCEPTED})
        used = {e["body"].get("nonce") for e in self.log.entries(kinds=(paging.ACK,))}
        verified, problems = passkeys.verify_approval(response, pending=pending, credential=credential,
                                                      rp_id=self.rp_id, origin=self.origin, now=now, used_nonces=used)
        if verified is None:
            return _json(403, {"error": "the pages were not acknowledged", "problems": problems})
        shown = paging.open_pages(self.pages)
        if not shown or paging.signed_for(shown) != pending.plan_hash:
            return _json(409, {"error": "the pages changed since you looked (one opened, or another approver "
                                        "acknowledged them): look again"})
        paging.acknowledge(self.pages, self.log, shown, approver=credential.approver, nonce=pending.nonce,
                           credential_id=credential.credential_id, at=now)
        return _json(200, {"acknowledged": len(shown)})

    # ------------------------------------------------------------------ steps

    def _credentials(self, approver: str) -> list[passkeys.Credential]:
        entry = self.policy.approvers.get(approver)
        return [passkeys.Credential(approver, c.credential_id, c.public_key, c.sign_count, c.device_bound)
                for c in (entry.passkeys if entry else [])]

    def _served(self, page: str, slack_first: bool) -> Response:
        nonce = secrets.token_urlsafe(16)
        return Response(200, _headers(nonce, _HTML),
                        page.replace(_NONCE, nonce).replace("{{SLACK}}", "1" if slack_first else "0"))

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
            return _json(403, {"error": _NOT_ACCEPTED, "problems": problems})
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
            "risk": approvals.TIER_MEANS.get(plan.tier, ""),
            # U3-2: what can go wrong if it is approved, from the catalogue - beside the plan, before the decision.
            "risks_if_approved": "; ".join(catalog.risks_of(plan.entry)) or "none named", "environment": plan.environment,
            "values": plan.params, "plan_hash": plan.plan_hash, "made": both_times(plan.created_at),
            "link_expires": both_times(link.expires_at), "type_the_target": plan.tier in TYPED_TIERS,
            # Eldane's review and the plan's autonomy level (autonomy.py), from the record - said to be an AI.
            **self._ai_review(plan)}})

    def _ai_review(self, plan: Any) -> dict[str, str]:
        if self.log is None:
            return {}
        from . import autonomy

        rows = [e["body"] for e in self.log.entries(plan.incident_id, kinds=(autonomy.VERDICT,))
                if e["body"].get("workflow_id") == plan.workflow_id and e["body"].get("plan_hash") == plan.plan_hash]
        if not rows:
            return {"autonomy": f"at most {autonomy.ceiling(plan.environment)} in {plan.environment}; Eldane, the AI "
                                "critic, has not reviewed this plan"}
        v = rows[-1]
        if v.get("skipped"):
            return {"ai_critic": f"{approvals.AI_LABEL} (an AI) did not review it: {v['skipped']}"}
        why = autonomy.reasons_said(v)  # a debate-won "yes" (never approving) shows why it said no, not why it agreed
        won = " (it agreed only after WARDEN's answers, which never approves)" if autonomy.debate_won(v) else ""
        return {"ai_critic": f"{approvals.AI_LABEL} (an AI) {'agrees' if v.get('agree') else 'does not agree'}{won}"
                             + (f": {why}" if why else ""), "autonomy": str(v.get("level_said", ""))}

    def _approve_options(self, token: str, link: Link, data: dict) -> Response:
        plan = self.plan_of(link.workflow_id)
        if not link.viewed or plan is None:
            return _json(403, {"error": _PLAN_FIRST})
        options, pending = passkeys.approval_options(rp_id=self.rp_id, credentials=self._credentials(link.approver),
                                                     workflow_id=plan.workflow_id, plan_hash=plan.plan_hash,
                                                     tier=plan.tier, now=self.clock())
        self.store.put_challenge(f"{token}:approve", pending)
        return _json(200, {"options": json.loads(options)})

    def _deny_options(self, token: str, link: Link, data: dict) -> Response:
        plan = self.plan_of(link.workflow_id)
        if self.deny is None or not link.viewed or plan is None:
            return _json(403, {"error": _PLAN_FIRST})
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
            return _json(403, {"error": _PLAN_FIRST})
        problems = self._verify(f"{token}:deny", link, data.get("response"))
        if problems:
            return _json(403, {"error": _NOT_ACCEPTED, "problems": problems})
        self.deny(plan.workflow_id, Denial(approver=link.approver, workflow_id=plan.workflow_id,
                                           plan_hash=plan.plan_hash, reason=approvals.note(data.get("note"), incoming=True)))
        self.store.use_link(token)  # used once, either way
        return _json(200, {"sent": True, "note": "The plan is denied; nothing will change."})

    def _approve(self, token: str, link: Link, data: dict) -> Response:
        plan = self.plan_of(link.workflow_id)
        if not link.viewed or plan is None:
            return _json(403, {"error": _PLAN_FIRST})
        if plan.tier in TYPED_TIERS and data.get("typed_target") != plan.target:
            return _json(400, {"error": f"a {plan.tier} approval needs the target typed exactly"})
        pending = self.store.challenge(f"{token}:approve")
        problems = self._verify(f"{token}:approve", link, data.get("response"))
        if problems or pending is None:
            return _json(403, {"error": _NOT_ACCEPTED, "problems": problems})
        self.signal(plan.workflow_id, PasskeyAssertion(
            approver=link.approver, workflow_id=pending.workflow_id, plan_hash=pending.plan_hash, tier=pending.tier,
            nonce=pending.nonce, expires_at=pending.expires_at, challenge=pending.challenge, response=data["response"],
            note=approvals.note(data.get("note"), incoming=True)))
        self.store.use_link(token)  # used once
        return _json(200, {"sent": True, "note": "WARDEN re-checks this approval before anything changes."})


def _headers(nonce: str, content_type: str, form_action: str = "'none'") -> dict[str, str]:
    """`form_action`: 'none' everywhere but the records list, whose filters are a plain form that works with no
    script - there, that one address of this site (owner, 2026-10-16)."""
    return {
        "Content-Type": content_type,
        "Content-Security-Policy": (f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
                                    f"connect-src 'self'; img-src data:; base-uri 'none'; form-action {form_action}; "
                                    "frame-ancestors 'none'"),
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "no-store",
    }


# Words and values the page says in more than one place.
_LINK_USED = "approval.link_used"
_NOT_FOUND = "not found"
_SIGN_IN_FIRST = "sign in with Slack first"
_NOT_ACCEPTED = "the passkey was not accepted"
_PLAN_FIRST = "show the plan first"
_HTML = "text/html; charset=utf-8"
_NONCE = "{{NONCE}}"


def _who_cookie(cookies: Any) -> str:
    """The sealed member cookie this browser sent (slack_login.remember), or ''."""
    return next((c.split("=", 1)[1] for c in cookies if isinstance(c, str) and c.startswith(_WHO + "=")), "")


def _records_route(method: str, parts: list[str], masked: bool) -> bool:
    """A records address this page serves: GET of `/r` or `/r/<incident>`, and GET or POST (the reveal's form) of
    `/r/<incident>/masked`."""
    if masked:
        return method in ("GET", "POST") and bool(parts[0])
    return method == "GET" and len(parts) <= 1
_COOKIE = "warden_s"  # holds the link while the browser is at Slack: this site's only, ten minutes, /s alone
# A limited approver's signed read (/a/signed/record): the latest this many incidents in its environments, found among
# the newest RECORD_SCAN on the record.
RECORD_LIST, RECORD_SCAN = 20, 200
_WHO = "warden_who"  # the member Slack named in this browser, sealed (slack_login.remember): no script can read it
# An incident id's shape (chatops: the "Full record" link's): all that travels through Slack's sign-in, and back.
_INCIDENT_ID = re.compile(r"[A-Za-z0-9._-]{1,120}")
_ASK = re.compile(r"[A-Za-z0-9_-]{16,64}")  # a `/p` challenge's own id (secrets.token_urlsafe)


def _count(value: Any) -> int:
    """A page's count of times said, as shown: one the pager wrote badly is shown as 0, never a failed page."""
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return 0


def _opened(value: Any) -> str:
    """A page's opening time, as shown; one that cannot be read says so (CodeRabbit, PR 43)."""
    try:
        return both_times(datetime.fromisoformat(str(value)))
    except (TypeError, ValueError):
        return "a time that cannot be read"


def _notice(status: int, text: str) -> Response:
    """A page that only says something: where the Slack sign-in ends without a link to go back to."""
    import html

    nonce = secrets.token_urlsafe(16)
    # Escaped: a sign-in's failure can quote what Slack said.
    shown = html.escape(text, quote=False).replace("{", "&#123;").replace("}", "&#125;")
    return Response(status, _headers(nonce, _HTML),
                    _NOTICE.replace(_NONCE, nonce).replace("{{SLACK}}", "0").replace("{{TEXT}}", shown))


def _json(status: int, payload: dict) -> Response:
    return Response(status, _headers(secrets.token_urlsafe(8), "application/json"), json.dumps(payload))


# ------------------------------------------------------------------ the pages
# One look for every page (owner, 2026-10-12: "they look like some poor pages"; 2026-10-16: themes, a sci-fi
# background, a wave on touch). Everything is in the page: the Content-Security-Policy admits no font, image, frame or
# script from anywhere, and no style attribute - so the system font, classes only, and a nonce on the one style and
# the one script. Colours are custom properties, light and dark, chosen by the reader (remembered in this browser) or
# by the device; every pair of text and ground passes WCAG 2.2 AA (tests/test_pages_ux.py measures them). The
# background - a slow aurora, a faint grid, a drifting constellation - lies behind solid panels, holds still for
# reduced motion and pauses in a hidden tab. Labelled controls, keyboard order, a visible focus, a status always in
# words (never colour alone), targets of 24px and more, readable at 200% and at a phone's width.
_LIGHT = (
    "--bg:oklch(0.985 0.006 250);--bg2:oklch(0.935 0.018 255);--sheet:oklch(0.995 0.003 250);"
    "--panel:oklch(0.995 0.003 250/.9);--well:oklch(0.968 0.008 255);--line:oklch(0.87 0.016 258);"
    "--ink:oklch(0.22 0.03 265);--muted:oklch(0.45 0.03 262);"
    "--accent:oklch(0.5 0.17 255);--accent-hi:oklch(0.44 0.17 255);--accent-edge:oklch(0.36 0.14 255);"
    "--accent-ink:oklch(0.99 0.004 255);--glow:oklch(0.6 0.17 245/.24);"
    "--ok:oklch(0.47 0.12 155);--warn:oklch(0.5 0.12 62);--bad:oklch(0.5 0.19 25);"
    "--in:inset 0 1px 2px oklch(0.25 0.04 265/.1);"
    "--lift:0 1px 0 oklch(1 0 0/.7) inset,0 2px 6px oklch(0.25 0.04 265/.14);"
    "--shadow:0 1px 1px oklch(0.25 0.04 265/.05),0 8px 20px oklch(0.25 0.04 265/.07),"
    "0 28px 60px oklch(0.25 0.06 270/.12);"
    "--aur1:oklch(0.82 0.1 215/.55);--aur2:oklch(0.8 0.11 295/.45);--aur3:oklch(0.86 0.08 180/.4);"
    "--grid:oklch(0.45 0.08 265/.07);--dot:oklch(0.45 0.14 268/.55)")
_DARK = (
    "--bg:oklch(0.2 0.035 272);--bg2:oklch(0.13 0.03 272);--sheet:oklch(0.205 0.03 270);"
    "--panel:oklch(0.205 0.03 270/.88);--well:oklch(0.175 0.028 270);--line:oklch(0.34 0.04 268);"
    "--ink:oklch(0.95 0.01 250);--muted:oklch(0.76 0.03 255);"
    "--accent:oklch(0.82 0.13 210);--accent-hi:oklch(0.88 0.11 205);--accent-edge:oklch(0.56 0.12 220);"
    "--accent-ink:oklch(0.17 0.03 260);--glow:oklch(0.8 0.14 210/.3);"
    "--ok:oklch(0.82 0.15 155);--warn:oklch(0.85 0.13 85);--bad:oklch(0.77 0.15 25);"
    "--in:inset 0 1px 2px oklch(0 0 0/.45);--lift:0 1px 0 oklch(1 0 0/.08) inset,0 2px 8px oklch(0 0 0/.45);"
    "--shadow:0 1px 0 oklch(1 0 0/.06) inset,0 18px 50px oklch(0 0 0/.55);"
    "--aur1:oklch(0.5 0.15 230/.42);--aur2:oklch(0.45 0.2 300/.36);--aur3:oklch(0.5 0.12 180/.26);"
    "--grid:oklch(0.8 0.08 220/.055);--dot:oklch(0.86 0.09 215/.75)")
_MONO = "ui-monospace,SFMono-Regular,Menlo,Consolas,monospace"
_STYLE = ("""
:root{color-scheme:light;LIGHT}
:root[data-theme=dark]{color-scheme:dark;DARK}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){color-scheme:dark;DARK}}
*{box-sizing:border-box}
html{font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;-webkit-text-size-adjust:100%}
body{margin:0;min-height:100vh;color:var(--ink);font-variant-numeric:tabular-nums;
background:radial-gradient(130% 75% at 50% -10%,var(--bg) 0,var(--bg2) 75%) fixed var(--bg2)}
body::before,body::after{content:"";position:fixed;z-index:-2;pointer-events:none}
body::before{inset:-25vmax;background:radial-gradient(38vmax 28vmax at 22% 28%,var(--aur1),transparent 70%),
radial-gradient(34vmax 26vmax at 80% 18%,var(--aur2),transparent 70%),
radial-gradient(44vmax 30vmax at 62% 86%,var(--aur3),transparent 70%);
animation:aurora 56s ease-in-out infinite alternate;will-change:transform}
@keyframes aurora{50%{transform:translate3d(3vmax,-2vmax,0) rotate(5deg) scale(1.04)}
to{transform:translate3d(-2vmax,2vmax,0) rotate(-4deg) scale(1.08)}}
body::after{inset:0;background:linear-gradient(var(--grid) 1px,transparent 1px) 0 0/44px 44px,
linear-gradient(90deg,var(--grid) 1px,transparent 1px) 0 0/44px 44px;
-webkit-mask-image:radial-gradient(120% 85% at 50% 0,black 25%,transparent 100%);
mask-image:radial-gradient(120% 85% at 50% 0,black 25%,transparent 100%)}
#sky{position:fixed;inset:0;width:100%;height:100%;z-index:-1;pointer-events:none}
.page{position:relative;max-width:38rem;margin:0 auto;padding:1rem 1rem 3rem}
.top{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem .75rem;padding:.25rem .125rem 1rem}
.mark{display:inline-flex;align-items:center;gap:.5rem;font-weight:750;letter-spacing:.18em;font-size:.875rem}
.logo{flex:none;filter:drop-shadow(0 0 7px oklch(0.8 0.15 165/.5))}
.where{color:var(--muted);font-size:.6875rem;font-weight:650;letter-spacing:.08em;text-transform:uppercase;
padding:.125rem .5rem;border:1px solid var(--line);border-radius:999px;background:var(--panel)}
.theme{margin-left:auto;display:inline-flex;gap:2px;padding:3px;border:1px solid var(--line);border-radius:999px;
background:var(--panel)}
.theme[hidden]{display:none!important}
.theme button{width:2rem;height:2rem;padding:0;display:grid;place-items:center;border:0;border-radius:999px;
background:none;color:var(--muted);box-shadow:none}
.theme button:hover{color:var(--ink)}
.theme button[aria-pressed=true]{background:var(--accent);color:var(--accent-ink)}
.theme svg{width:1rem;height:1rem}
.vh{position:absolute!important;width:1px;height:1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap}
.where,.foot{color:var(--muted)}
.foot{margin:1rem .25rem 0;font-size:.8125rem}
.sheet{position:relative;background:var(--panel);border:1px solid var(--line);border-radius:1.125rem;
box-shadow:var(--shadow);overflow:hidden}
.sheet::before{content:"";position:absolute;inset:0 0 auto;height:1px;pointer-events:none;opacity:.75;
background:linear-gradient(90deg,transparent,var(--accent) 50%,transparent)}
@media (hover:hover) and (pointer:fine){.sheet,.where,.theme{-webkit-backdrop-filter:blur(14px) saturate(1.3);
backdrop-filter:blur(14px) saturate(1.3)}}
.steps{list-style:none;margin:0;padding:.875rem 1.25rem;display:flex;flex-wrap:wrap;gap:.5rem 1.125rem;counter-reset:s;
border-bottom:1px solid var(--line);background:var(--well);font-size:.8125rem;color:var(--muted)}
.steps li{counter-increment:s;display:flex;align-items:center;gap:.4375rem}
.steps li::before{content:counter(s);display:grid;place-items:center;width:1.375rem;height:1.375rem;border-radius:50%;
border:1px solid var(--line);background:var(--sheet);font-weight:600;font-size:.75rem}
.steps li[aria-current]{color:var(--ink);font-weight:600}
.steps li[aria-current]::before{background:var(--accent);border-color:var(--accent);color:var(--accent-ink);
box-shadow:0 0 0 4px var(--glow)}
.steps li.done::before{content:"✓";color:var(--ok);border-color:currentColor}
h1{font-size:1.5rem;line-height:1.2;letter-spacing:-.015em;margin:1.375rem 1.25rem .5rem}
p{margin:0 0 1rem}
.lede{margin:0 1.25rem 1.25rem;color:var(--muted);max-width:62ch}
.me{margin:0 1.25rem;font-weight:600;color:var(--ok)}
.left{margin:.25rem 1.25rem 0;font-size:.875rem;color:var(--muted)}
.eyebrow{margin:1.25rem 1.25rem .625rem;font-size:.75rem;font-weight:650;letter-spacing:.1em;text-transform:uppercase;
color:var(--muted)}
.mono,.change{font-family:MONO}
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
border:1px solid var(--accent);box-shadow:var(--lift),0 0 0 3px var(--glow)}
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
input,textarea,select{width:100%;min-height:2.75rem;font:inherit;color:inherit;background:var(--sheet);
border:1px solid var(--line);border-radius:.625rem;padding:.625rem .75rem;box-shadow:var(--in)}
input:hover,textarea:hover,select:hover{border-color:var(--muted)}
textarea{font-family:MONO;font-size:.8125rem;line-height:1.45;resize:vertical}
.hint{display:block;margin-top:.375rem;font-size:.8125rem;font-weight:400;color:var(--muted)}
button{width:100%;font:inherit;font-weight:600;color:var(--ink);border-radius:.75rem;padding:.75rem 1rem;
border:1px solid transparent;cursor:pointer;transition:transform .16s cubic-bezier(.22,1,.36,1),
box-shadow .16s cubic-bezier(.22,1,.36,1),background-color .16s,color .16s}
.primary{color:var(--accent-ink);background:var(--accent);
box-shadow:inset 0 1px 0 oklch(1 0 0/.22),0 3px 0 var(--accent-edge),0 10px 24px var(--glow)}
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
summary:focus-visible{outline-offset:-3px}
.deny{margin-top:1.25rem;padding-top:1rem;border-top:1px solid var(--line)}
.deny p{margin:0 0 .75rem}
[hidden]{display:none!important}
button,.primary,a.button,.chip,a.step,summary{position:relative;overflow:hidden;isolation:isolate}
.rip{position:absolute;left:var(--x);top:var(--y);width:var(--d);height:var(--d);margin:calc(var(--d)/-2) 0 0
calc(var(--d)/-2);border-radius:50%;background:currentColor;opacity:.22;transform:scale(0);pointer-events:none;
z-index:-1;animation:rip .7s cubic-bezier(.2,.8,.3,1) forwards}
@keyframes rip{to{transform:scale(1);opacity:0}}
@media (max-width:26rem){.facts{grid-template-columns:1fr}.facts dt{padding-bottom:0}
.facts dd{border-top:0;padding-top:.125rem}.where{display:none}.mark{letter-spacing:.14em}}
@media (prefers-reduced-motion:reduce){*,::before,::after{transition:none!important;animation:none!important}
.rip{display:none}}
@media print{body::before,body::after,#sky,.theme{display:none}}
""".replace("LIGHT", _LIGHT).replace("DARK", _DARK).replace("MONO", _MONO))

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

# What every page's script ends with: the theme toggle, the wave on a press, the sky. Wrapped whole, and last: nothing
# here can stop a page's own script, which has already run. No address, no inline handler; under reduced motion no
# wave, and the sky drawn once, still.
_UI_JS = """
(() => { try {
const R = document.documentElement, KEY = "warden-theme", MODES = ["system", "light", "dark"];
const calm = matchMedia("(prefers-reduced-motion: reduce)"), night = matchMedia("(prefers-color-scheme: dark)");
let sky = () => {};
const mode = v => {
  if (!MODES.includes(v)) { v = "system"; }
  if (v === "system") { delete R.dataset.theme; } else { R.dataset.theme = v; }
  try { if (v === "system") { localStorage.removeItem(KEY); } else { localStorage.setItem(KEY, v); } } catch (e) {}
  for (const b of document.querySelectorAll("#theme button")) { b.setAttribute("aria-pressed", String(b.dataset.mode === v)); }
  sky();
};
let saved = "system";
try { saved = localStorage.getItem(KEY) || "system"; } catch (e) {}
const box = document.getElementById("theme");
if (box) {
  box.hidden = false;
  for (const b of box.querySelectorAll("button")) { b.hidden = false; b.addEventListener("click", () => mode(b.dataset.mode)); }
}
const HOST = "button,.primary,a.button,.chip,a.step,summary";
const wave = (t, x, y) => {
  if (calm.matches || t.disabled) { return; }
  const b = t.getBoundingClientRect(), s = document.createElement("span");
  s.className = "rip"; s.setAttribute("aria-hidden", "true");
  s.style.setProperty("--x", x - b.left + "px"); s.style.setProperty("--y", y - b.top + "px");
  s.style.setProperty("--d", Math.hypot(b.width, b.height) * 2 + "px");
  t.append(s); setTimeout(() => s.remove(), 750);
};
const host = e => e.target && e.target.closest ? e.target.closest(HOST) : null;
document.addEventListener("pointerdown", e => { const t = host(e); if (t) { wave(t, e.clientX, e.clientY); } },
                          {passive: true});
document.addEventListener("keydown", e => {
  const t = (e.key === "Enter" || e.key === " ") && host(e);
  if (t) { const b = t.getBoundingClientRect(); wave(t, b.left + b.width / 2, b.top + b.height / 2); }
});
SKY
mode(saved);
} catch (e) {} })();
"""
# The sky alone, under 3 KB: points that drift and join when near, and lean away from the pointer. The pixel ratio is
# capped, the count follows the screen's size, and nothing is drawn while the tab is hidden.
_SKY_JS = """
const c = document.getElementById("sky"), g = c && c.getContext && c.getContext("2d");
if (g) {
  let w = 0, h = 0, pts = [], px = -9e3, py = -9e3, run = 0;
  const fit = () => {
    const d = Math.min(devicePixelRatio || 1, 1.5), nw = innerWidth;
    h = innerHeight; c.width = nw * d; c.height = h * d; g.setTransform(d, 0, 0, d, 0, 0);
    if (nw !== w) {
      w = nw;
      pts = Array.from({length: Math.min(70, Math.round(w * h / 20000))}, () => ({x: Math.random() * w,
        y: Math.random() * h, vx: (Math.random() - .5) * .16, vy: (Math.random() - .5) * .16, r: Math.random() * 1.3 + .5}));
    }
  };
  const draw = () => {
    g.clearRect(0, 0, w, h); g.lineWidth = .7;
    for (const p of pts) {
      if (calm.matches) { continue; }
      p.x = (p.x + p.vx + w) % w; p.y = (p.y + p.vy + h) % h;
      const dx = p.x - px, dy = p.y - py, q = Math.hypot(dx, dy);
      if (q < 160 && q > 1) { p.x += dx / q * (1 - q / 160) * .6; p.y += dy / q * (1 - q / 160) * .6; }
    }
    for (let i = 0; i < pts.length; i++) {
      const a = pts[i];
      g.globalAlpha = .9; g.beginPath(); g.arc(a.x, a.y, a.r, 0, 7); g.fill();
      for (let j = i + 1; j < pts.length; j++) {
        const q = (a.x - pts[j].x) ** 2 + (a.y - pts[j].y) ** 2;
        if (q < 14400) { g.globalAlpha = (1 - q / 14400) * .4; g.beginPath(); g.moveTo(a.x, a.y);
                         g.lineTo(pts[j].x, pts[j].y); g.stroke(); }
      }
      const q = (a.x - px) ** 2 + (a.y - py) ** 2;
      if (q < 32400) { g.globalAlpha = (1 - q / 32400) * .55; g.beginPath(); g.moveTo(a.x, a.y); g.lineTo(px, py);
                       g.stroke(); }
    }
    g.globalAlpha = 1;
  };
  const loop = () => { draw(); run = requestAnimationFrame(loop); };
  sky = () => {
    cancelAnimationFrame(run); run = 0;
    g.fillStyle = g.strokeStyle = getComputedStyle(R).getPropertyValue("--dot").trim() || "gray";
    if (calm.matches) { px = py = -9e3; draw(); } else if (!document.hidden) { loop(); }
  };
  const away = () => { px = py = -9e3; };
  addEventListener("resize", () => { fit(); sky(); });
  addEventListener("pointermove", e => { px = e.clientX; py = e.clientY; }, {passive: true});
  addEventListener("pointerup", e => { if (e.pointerType !== "mouse") { away(); } }, {passive: true});
  R.addEventListener("pointerleave", away);
  document.addEventListener("visibilitychange", sky);
  for (const m of [calm, night]) { if (m.addEventListener) { m.addEventListener("change", sky); } }
  fit();
}
"""
_UI_JS = _UI_JS.replace("SKY", _SKY_JS)

_ICONS = {
    "system": '<circle cx="12" cy="12" r="8" fill="none" stroke="currentColor" stroke-width="2"/>'
              '<path d="M12 4a8 8 0 0 1 0 16z" fill="currentColor"/>',
    "light": '<circle cx="12" cy="12" r="4" fill="currentColor"/><path d="M12 2.5v2.5M12 19v2.5M2.5 12H5M19 12h2.5'
             'M5.3 5.3l1.8 1.8M16.9 16.9l1.8 1.8M5.3 18.7l1.8-1.8M16.9 7.1l1.8-1.8" stroke="currentColor"'
             ' stroke-width="2" stroke-linecap="round"/>',
    "dark": '<path d="M20 14.6A8.2 8.2 0 0 1 9.4 4a8.2 8.2 0 1 0 10.6 10.6z" fill="currentColor"/>',
}
# Shown by the script only: with no script the device's own theme holds, and a toggle would do nothing.
_THEME = ('<div id="theme" class="theme" role="group" aria-label="Colour theme" hidden>' + "".join(
    f'<button type="button" data-mode="{m}" aria-pressed="{"true" if m == "system" else "false"}" title="{t}">'
    f'<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">{_ICONS[m]}</svg><span class="vh">{t}</span>'
    "</button>" for m, t in (("system", "Theme as the device"), ("light", "Light theme"), ("dark", "Dark theme")))
    + "</div>")

_SHELL = ("""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{TITLE}}</title>""" + FAVICON_LINK + """
<style nonce="{{NONCE}}">{{STYLE}}</style></head>
<body data-busy="0" data-slack="{{SLACK}}"><canvas id="sky" aria-hidden="true"></canvas><div class="page">
<header class="top"><span class="mark">""" + LOGO_SVG + """<span>WARDEN</span></span><span class="where">{{WHERE}}</span>"""
          + _THEME + """</header>
<main class="sheet">{{MAIN}}</main>
<p class="foot">{{FOOT}}</p>
</div>
<script nonce="{{NONCE}}">{{JS}}{{SCRIPT}}""" + _UI_JS + """</script></body></html>
""")


def _page(title: str, where: str, main: str, foot: str, script: str) -> str:
    return (_SHELL.replace("{{TITLE}}", title).replace("{{WHERE}}", where).replace("{{MAIN}}", main)
            .replace("{{FOOT}}", foot).replace("{{STYLE}}", _STYLE).replace("{{JS}}", _JS).replace("{{SCRIPT}}", script))


_NOTICE = _page("WARDEN", "Sign-in", """
<h1 id="title">Sign-in</h1>
<p class="lede">{{TEXT}}</p>
<div class="bar"><p id="status" role="status" aria-live="polite" data-kind="info">You can close this page.</p></div>
""", "WARDEN asks Slack who you are, then your passkey that you are here.", "")

# WARDEN's own pages: what is open and why, then one passkey ceremony over exactly those.
_ACK = _page("WARDEN pages", "Pages", """
<ol class="steps" aria-label="Steps"><li aria-current="step">Read what is paging</li><li>Acknowledge</li></ol>
<h1 id="title">WARDEN is paging</h1>
<p id="only" class="lede">These pages repeat every 15 minutes, in Slack and by email, until a person acknowledges them.
Acknowledging stops the repeats and nothing else: an alarm stays in ALARM, the kill switch stays on, until what they
name is dealt with.</p>
<section id="plan" hidden aria-labelledby="plan-h"><h2 id="plan-h" class="eyebrow">Open pages</h2>
<dl id="facts" class="facts"></dl></section>
<div class="bar"><p id="status" role="status" aria-live="polite" data-kind="info">Show what is paging.</p>
<button id="who" class="primary" type="button">Show the pages</button>
<button id="ok" class="primary" type="button" hidden>Acknowledge with my passkey</button></div>
""", "Any approver may acknowledge, with any of their passkeys; who did is kept on the record.", """
const el = (tag, cls, text) => { const e = document.createElement(tag); e.className = cls; e.textContent = text;
                                 return e; };
let options = null, ask = "";
$("who").addEventListener("click", async () => {
  busy(true);
  try {
    const [ok, d] = await post("pages"); if (!ok) { say(d.error, "bad"); return; }
    if (!d.open.length) { $("title").textContent = "Nothing is paging"; $("who").hidden = true; $("only").hidden = true;
                          step(2); say("No page is waiting for a person.", "ok"); return; }
    const dl = $("facts"); dl.textContent = "";
    for (const p of d.open) { dl.append(el("dt", "", p.key + " - since " + p.opened + ", said " + p.sent + " times"),
                                        el("dd", "", p.why)); }
    options = d.options; ask = d.ask; $("plan").hidden = false; $("who").hidden = true; $("ok").hidden = false; step(1);
    say("Acknowledge when a person is on it.");
  } catch (e) { say("Not shown: " + e.message, "bad"); } finally { busy(false); }
});
$("ok").addEventListener("click", async () => {
  busy(true);
  try {
    say("Confirm with your passkey.", "work");
    const o = JSON.parse(JSON.stringify(options)); o.challenge = a2b(o.challenge);
    o.allowCredentials = (o.allowCredentials || []).map(c => ({...c, id: a2b(c.id)}));
    const c = await navigator.credentials.get({publicKey: o});
    say("Acknowledging.", "work");
    const [ok, d] = await post("ack", {ask: ask, response: {id: c.id, rawId: b2a(c.rawId), type: c.type, response: {
      clientDataJSON: b2a(c.response.clientDataJSON), authenticatorData: b2a(c.response.authenticatorData),
      signature: b2a(c.response.signature), userHandle: c.response.userHandle ? b2a(c.response.userHandle) : null}}});
    if (!ok) { say(d.error + (d.problems ? ": " + d.problems.join("; ") : ""), "bad"); return; }
    $("ok").hidden = true; $("title").textContent = "Acknowledged"; step(2);
    say("Acknowledged: the repeats stop within five minutes. You can close this page.", "ok");
  } catch (e) { say("Not acknowledged: " + e.message, "bad"); } finally { busy(false); }
});
""")

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

# The kill switch's stop: why, then one passkey ceremony over exactly that reason.
_STOP = _page("WARDEN kill switch", "Kill switch", """
<ol class="steps" aria-label="Steps"><li class="done">Open your link</li><li aria-current="step">Say why</li>
<li>Stop WARDEN</li></ol>
<h1 id="title">Stop every automatic fix</h1>
<p id="only" class="lede">Turning the kill switch on stops WARDEN from applying any fix, approved or not, until an
approver resets it. Diagnoses and reports go on. Say why: your reason is signed with your passkey and kept on the
record.</p>
<label for="why">Why you are stopping WARDEN</label>
<textarea id="why" rows="3" maxlength="300" required aria-describedby="why-h"></textarea>
<p id="why-h" class="hint">1 to 300 characters. Name what you saw.</p>
<div class="bar"><p id="status" role="status" aria-live="polite" data-kind="info">Write your reason, then stop.</p>
<button id="ok" class="primary" type="button">Stop WARDEN with my passkey</button></div>
""", "Stopping is the safe direction: any approver may, with any of their passkeys.", """
$("ok").addEventListener("click", async () => {
  const reason = $("why").value.trim();
  if (!reason) { say("Write why you are stopping WARDEN first.", "bad"); $("why").focus(); return; }
  busy(true);
  try {
    const [ok1, d1] = await post("options", {reason}); if (!ok1) { say(d1.error, "bad"); return; }
    say("Confirm with your passkey.", "work");
    const o = JSON.parse(JSON.stringify(d1.options)); o.challenge = a2b(o.challenge);
    o.allowCredentials = (o.allowCredentials || []).map(c => ({...c, id: a2b(c.id)}));
    const c = await navigator.credentials.get({publicKey: o});
    say("Turning the kill switch on.", "work");
    const [ok, d] = await post("on", {reason, response: {id: c.id, rawId: b2a(c.rawId), type: c.type, response: {
      clientDataJSON: b2a(c.response.clientDataJSON), authenticatorData: b2a(c.response.authenticatorData),
      signature: b2a(c.response.signature), userHandle: c.response.userHandle ? b2a(c.response.userHandle) : null}}});
    if (!ok) { say(d.error + (d.problems ? ": " + d.problems.join("; ") : ""), "bad"); return; }
    $("ok").hidden = true; $("why").disabled = true; $("title").textContent = "The kill switch is on"; step(3);
    say("Stopped. WARDEN applies nothing until an approver resets it. You can close this page.", "ok");
  } catch (e) { say("Not stopped: " + e.message, "bad"); } finally { busy(false); }
});
""")

__all__ = ["LINK_TTL", "ApprovalPage", "Link", "Response"]
