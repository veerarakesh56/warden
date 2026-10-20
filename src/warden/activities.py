"""The activities of the remediation workflow: every step that touches the world or the audit log.

The workflow (workflows.py) is deterministic orchestration only. Everything with a side effect or a
clock is here, and every step writes an audit row.

A `Platform` is how an activity reads and changes one kind of system (Lambda, ECS, Kubernetes, a
database). Phase 2 ships only a fake for tests; the real AWS ones come with the JIT roles in
Phase 4, so no activity here holds a credential yet.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import logging
import os
import re
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from pydantic import BaseModel, Field, field_validator
from temporalio import activity
from temporalio.exceptions import ApplicationError

from . import approvals, audit, bounds, catalog, datadog, environments, freeze, landed, locks
from . import symptom as symptoms
from .approvals import Plan  # lives there: the approval page reads a plan without this module
from .audit import AuditLog
from .models import Alert, ContextBundle, CostRecord, RemediationProposal, RootCause, Verdict
from .observability import _safe_error

MAX_APPROVAL_TTL_MINUTES = environments.MAX_APPROVAL_WAIT_HOURS * 60  # a week: one timer, whatever its length
MAX_RECOVER_WITHIN_MINUTES = 120


_LOG = logging.getLogger("warden.incident")


def _note(text: str) -> None:
    """One line on the worker's own log for whoever operates WARDEN: what it decided. The audit is the record; this
    is so a decision can be seen without the database or the chat (live window, 2026-10-11: the only sign of an
    incident in the log was the model's HTTP request). WARDEN's own words only - a status, policy ids, an entry's
    name, its own refusal - on one line, cut short, through the logging gate like every other line."""
    _LOG.info("%s", " ".join(text.split())[:300])


OFFERED_UNDO = "WARDEN's own offer: the undo of the change the proposal left unaddressed"
# How an approved plan went, said to the people who approved it (owner's first live approvals, 2026-10-12: one fix
# was refused by AWS, one applied and verified, and Slack said nothing after "waiting for an approval").
OUTCOME = {
    "verified": ("WARDEN applied `{entry}` on `{target}` and it passed its health checks. WARDEN keeps re-checking it "
                 "and says so if it fails again."),
    "recovered": "WARDEN's fix `{entry}` on `{target}` held through its re-checks: it is verified.",
    "relapsed": ("WARDEN's fix `{entry}` on `{target}` worked, then failed again. WARDEN does not undo a fix that had "
                 "worked: a person decides what happens next. The alarm that fired again is diagnosed afresh as a new "
                 "incident - what changed, by whom, why - and its report follows here."),
    "rolled_back": "WARDEN's fix `{entry}` on `{target}` did not work, so WARDEN undid it. The incident is still open.",
    "not_recovered": ("WARDEN's fix `{entry}` on `{target}` did not work, and WARDEN did not undo it: there was "
                      "nothing for it to undo. A person takes over."),
    "rollback_failed": ("WARDEN's fix `{entry}` on `{target}` did not work and undoing it FAILED: the target's state is "
                        "unknown."),
    "refused_at_apply": "WARDEN did not apply the approved plan `{entry}` on `{target}`: nothing was changed.",
    "apply_failed": "Applying `{entry}` on `{target}` failed part-way: the target's state is unknown.",
    # Live, 2026-10-16: a plan voided by a WARDEN deploy was said as "`target` changed" - the target had not. What
    # changed is said by the reason that follows ("Why: ..."), never assumed here.
    "drifted": ("Something the plan `{entry}` on `{target}` was made against changed before it could be applied (the "
                "reason is below), so WARDEN did not apply it: nothing was changed."),
    "denied": "The plan `{entry}` on `{target}` was denied: nothing was changed.",
    "refused": "WARDEN could not make the plan `{entry}` on `{target}`: nothing was changed.",
    "blocked": "WARDEN's own limits stopped the plan `{entry}` on `{target}`: nothing was changed.",
    "mitigated": "WARDEN applied `{entry}` on `{target}`: the harm is held, not fixed. A person finishes it.",
    "side_effects": ("WARDEN's fix `{entry}` on `{target}` passed its own checks, but other alarms in the same "
                     "environment started after it. WARDEN does not call it fixed, and does not undo it on its own: "
                     "they may be unrelated. Each is diagnosed as its own incident with this fix beside its evidence, "
                     "and its report says whether they are connected; a person decides what happens to this fix."),
}


class FixRequest(BaseModel):
    incident_id: str
    # A catalogue entry name, never free text: an agent-supplied entry was printed raw by `warden
    # status` (independent review 2026-09-28). The catalogue itself decides whether it exists.
    entry: str = Field(pattern=r"^[a-z][a-z0-9_]{1,60}$")
    params: dict[str, Any]
    # The environment the incident is in. A label anyone sending an alert can write: the target's own
    # environment must match it (P18, register S6), and it is part of the plan hash and the workflow id.
    environment: str
    service: str
    # Bounded (register O3): every verify check is a timer and an activity in the workflow's history, and Temporal
    # caps a history at 50k events / 50 MB. The longest verify window allowed here stays near 2k events.
    approval_ttl_minutes: int = Field(30, ge=1, le=MAX_APPROVAL_TTL_MINUTES)
    recover_within_minutes: int = Field(5, ge=1, le=MAX_RECOVER_WITHIN_MINUTES)
    # How many times this fix has been planned again after the target or WARDEN itself changed under an approved plan
    # (decision D7: re-plan and ask again, at most REPLAN_MAX times; workflows.RemediationWorkflow).
    replans: int = Field(0, ge=0, le=2)

    @field_validator("environment")
    @classmethod
    def _known_environment(cls, v: str) -> str:
        try:
            environments.names(v)
        except environments.EnvironmentPolicyError as exc:
            raise ValueError(str(exc)) from None
        return v


APPLY_REFUSED = "ApplyRefused"
ROLLBACK_FAILED = "RollbackFailed"


def _run_id() -> str:
    """The Temporal run this activity belongs to. Every remediation row records it, and apply counts only
    rows of its own run: a workflow id (`rem-<env>-<target hash>`) is reused, and a replay of an earlier run's approval and
    results applied a later run nobody approved (third review, 2026-09-30). Empty outside an activity."""
    try:
        return activity.info().workflow_run_id or ""
    except RuntimeError:  # called directly (tests, tools), not by a worker
        return ""


class ApprovalResult(BaseModel):
    problems: list[str]
    enough: bool = False
    # A passkey approval, once verified, recorded in the same shape as a signed one for the quorum.
    accepted: approvals.SignedApproval | None = None


class Recorded(BaseModel):
    """The verdict of a remediation, as WARDEN's own audit shows it, and the run it belongs to."""
    run_id: str
    ok: bool


# Ends that leave the target in a state nobody knows: the kill switch goes on (bounds.trip).
PERSON_TAKES_OVER = frozenset({"rollback_failed", "apply_failed", "cancelled_after_apply", "failed_after_apply"})
# Said on WARDEN's records page only (records.py): nobody has to act on them. Every other end - expired, undone,
# failed, relapsed - still comes to the channel, because a person does.
RECORDED_ONLY = frozenset({"approved", "denied", "verified", "recovered"})
HELD_BACK = "The outbound gate held this message back; the decision itself is on the record above."


def slack_summary(markdown: str) -> str:
    """A report's top for the channel: its title, the alert, the next step, the summary and who acts - the rest is on
    the incident's record page, behind the message's "Full record" button."""
    cut = markdown.find("\n## What WARDEN read")
    return (markdown[:cut] if cut > 0 else markdown[:2400]).rstrip()


# Owner, 2026-10-15: a fix can break something else. WARDEN's own fixes applied in an alarm's environment this long
# before it are put beside its evidence as changes, like a person's deploy: the diagnosis weighs them - cites one as
# the cause, or finds another - and nothing is assumed either way.
OWN_FIX_WINDOW = timedelta(minutes=int(os.environ.get("WARDEN_OWN_FIX_WINDOW_MIN", "60")))
_OWN_FIX = "by WARDEN (its own fix "


def _when_iso(text: str) -> datetime | None:
    try:
        when = datetime.fromisoformat(text)
    except ValueError:
        return None
    return when if when.tzinfo else when.replace(tzinfo=UTC)


def _tried(text: str) -> str:
    """What the person's words tried, said beside them - or nothing, for ordinary words (approvals.note_tries)."""
    tries = approvals.note_tries(approvals.note(text))
    return f" WARDEN noticed in it: {'; '.join(tries)}." if tries else ""


def _words(text: str) -> str:
    """An approver's own words in a message: data, never markup. One line inside a code span, nothing Slack or HTML
    would act on (reporting.untrusted_inline), no mark that could become someone's mention; the outbound gate and
    the redactor then see it as they see all text that leaves. Whole, up to what is kept (approvals.NOTE_MAX)."""
    from .reporting import untrusted_inline

    return untrusted_inline(approvals.note(text).replace("@@", "@ @"), limit=approvals.NOTE_MAX)


_ISO_TIME = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?\+00:00")


class FixOutcome(BaseModel):
    status: str
    reasons: list[str] = Field(default_factory=list)
    checklist: dict[str, bool]
    plan_hash: str = ""


class Platform(Protocol):
    def live(self, entry: str, params: dict[str, Any]) -> dict[str, Any]:
        """What WARDEN reads before acting: allowed values for each `ref` parameter (sets), the
        current values relative limits need, and `state` - a JSON snapshot of the target."""

    def apply(self, entry: str, params: dict[str, Any]) -> str: ...

    def healthy(self, service: str) -> bool: ...

    def rollback(self, entry: str, params: dict[str, Any], snapshot: dict[str, Any]) -> str: ...


def _utc(t: datetime) -> datetime:
    return t if t.tzinfo else t.replace(tzinfo=UTC)


def _parsed(raw: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(raw or ""))
    except ValueError:
        return None


def _env(method: Any, environment: str) -> dict[str, str]:
    """`environment=` for a platform method that takes it (the AWS platform reads and writes per environment)."""
    return {"environment": environment} if "environment" in inspect.signature(method).parameters else {}


def plan_hash(entry: str, params: dict[str, Any], snapshot: dict[str, Any], basis: dict[str, str] | None = None) -> str:
    # A value that moves on its own (a dead-letter queue's depth) is shown, not hashed: else every precheck drifts.
    snapshot = {k: v for k, v in snapshot.items() if k not in catalog.VOLATILE.get(entry, ())}
    material = json.dumps([entry, params, snapshot, *([basis] if basis else [])], sort_keys=True,
                          separators=(",", ":"), default=str)
    return hashlib.sha256(material.encode()).hexdigest()


def code_version() -> str:
    """WARDEN's own code and policy data, as one hash: a plan is applied only by the code it was made and approved
    under - a worker deployed mid-approval refuses it (register O5)."""
    return audit.code_version()


def _environment_problems(env: str, entry: catalog.Entry, params: dict[str, Any], live: dict[str, Any]) -> list[str]:
    """P18 ENV-MISMATCH (register S6): the incident's environment is a label an alert sender writes. The target's
    OWN environment - its tag or label, as the platform read it - must be that environment, and a name carrying
    another environment's prefix (`warden-prod-orders` for a dev incident) is refused too. Unknown is a mismatch."""
    problems = []
    runtime = environments.default_environment_policies().runtime_environment
    named = {environments.env_of_name(str(params.get(p, ""))) for p in entry.target_params}
    if runtime and runtime in {env, live.get("environment"), *named}:
        # P22 SELF-TARGET (register N7): WARDEN never changes its own components, whatever the approval.
        problems.append(f"P22 SELF-TARGET: the target is in WARDEN's own runtime environment {runtime!r}; a person "
                        "changes it, never WARDEN")
    own = live.get("environment")
    if own != env:
        problems.append(f"P18 ENV-MISMATCH: the target's own environment is {own!r}, not the incident's {env!r}")
    for p in dict.fromkeys([*entry.target_params, *(k for k, v in entry.params.items() if v.kind == "ref")]):
        value = str(params.get(p, ""))
        # A load balancer is named `app/<name>/<id>` (review-e L6): its name is the part that carries a prefix.
        named = environments.env_of_name(value.split("/")[1] if value.count("/") == 2 else value)
        if named and named != env:
            problems.append(f"P18 ENV-MISMATCH: {p} {params.get(p)!r} is named for {named!r}, not {env!r}")
    return problems


def _deadline(plan: Plan) -> datetime:
    """Until when this plan waits for its approval. A plan recorded before it carried its own wait: the old half hour."""
    return plan.created_at + timedelta(minutes=plan.approval_ttl_minutes or 30)


def _basis_now(plan: Plan) -> dict[str, str]:
    return {**plan.basis, "catalog": catalog.fingerprint(), "code": code_version()}


class AuditThreads:
    """Which Slack thread each incident has (register H3), kept in the audit so every worker continues the same one:
    a `chatops.thread` row per incident, the latest wins: {ts, channel} - the channel it is in (chatops.SlackBotSink);
    a row from before 2026-10-16 has only its ts."""

    def __init__(self, audit: AuditLog) -> None:
        self.audit = audit

    def get(self, incident: str, default: dict | None = None) -> dict | None:
        rows = self.audit.entries(incident, kinds=("chatops.thread",))
        return dict(rows[-1]["body"]) if rows else default

    def __setitem__(self, incident: str, thread: dict) -> None:
        self.audit.append(incident, "chatops.thread", {"ts": thread["ts"], "channel": thread["channel"]})


def _environment_of(log: AuditLog, incident: str) -> str:
    """The incident's environment as its record says (records.record: its alarm, else its intake); "" for none."""
    from . import records

    r = records.record(log, incident, light=True)
    return r.environment if r else ""


def _send(log: AuditLog, incident: str, report: Any) -> list[Any]:
    """chatops.notify, threaded through the audit; a message withheld for want of its environment's Slack channel
    (WARDEN_SLACK_CHANNELS) is a row of its own, so the record says it was never posted and why."""
    from . import chatops

    sent = chatops.notify(report, threads=AuditThreads(log))
    for n in sent:
        if n.detail.startswith(chatops.WITHHELD):
            log.append(incident, "chatops.withheld", {"run_id": _run_id(), "sink": n.sink, "detail": n.detail[:200]})
    return sent


class RemediationActivities:
    def __init__(self, *, audit: AuditLog, policy: approvals.ApproverPolicy, platform: Platform,
                 limits: bounds.Limits = bounds.DEFAULT_LIMITS, changes: Any = None) -> None:
        self.audit, self.policy, self.platform, self.limits = audit, policy, platform, limits
        self.changes = changes  # register O9: where an applied change is recorded (changes.GitHubIssues), if anywhere

    @activity.defn
    def resolve_plan(self, req: FixRequest, workflow_id: str) -> Plan:
        entry = catalog.CATALOG.get(req.entry)
        live = self.platform.live(req.entry, req.params, **_env(self.platform.live, req.environment))
        problems = catalog.validate(req.entry, req.params, live)
        target = req.params.get(entry.target_param) if entry else None
        if entry and target != req.service:
            # The health check keys on `service`: it must be what the fix changes (sixth review, 2026-10-01: a
            # scale of `payments` filed under `orders` was judged by `orders`).
            problems.append(f"the fix changes {entry.target_param} {target!r}, not the service {req.service!r} "
                            "its health would be judged by")
        if entry:
            problems += _environment_problems(req.environment, entry, req.params, live)
        snapshot = live.get("state", {})
        basis = {"environment": req.environment, "catalog": catalog.fingerprint(), "code": code_version(),
                 "evidence": self.audit.head(req.incident_id)}
        key = f"{req.environment}/{catalog.target_key(req.entry, req.params)}" if entry else ""
        plan = Plan(workflow_id=workflow_id, incident_id=req.incident_id, entry=req.entry,
                    tier=entry.tier if entry else "", params=req.params, snapshot=snapshot,
                    plan_hash=plan_hash(req.entry, req.params, snapshot, basis), created_at=datetime.now(UTC),
                    problems=problems, target=key, environment=req.environment, basis=basis,
                    approval_ttl_minutes=req.approval_ttl_minutes)
        self.audit.append(req.incident_id, "remediation.plan",
                          {"workflow_id": workflow_id, "run_id": _run_id(), "entry": req.entry, "tier": plan.tier,
                           "environment": req.environment, "service": req.service,  # intake matches alarms on these (C1)
                           "params": req.params, "target": key, "basis": basis, "plan_hash": plan.plan_hash,
                           "problems": problems})
        return plan

    @activity.defn
    def gate(self, plan: Plan, service: str) -> list[str]:
        # The bounds key on the target the plan changes, not on `service` (audit A-B-M4); _not_approved re-checks
        # the target against the plan row before apply.
        reasons = self._blocked(plan)
        # Register H1: approval fatigue. Past this many requests for approval in an hour, a person approving is
        # stamping, not reading - the next plan waits.
        asked = {e["body"].get("workflow_id") for e in self.audit.entries(kinds=("remediation.plan",),
                                                                          since=datetime.now(UTC) - timedelta(hours=1))}
        asked.discard(plan.workflow_id)
        if len(asked) >= MAX_PLANS_PER_HOUR:
            reasons.append(f"H1: {len(asked)} other plans asked for approval in the last hour; the cap is "
                           f"{MAX_PLANS_PER_HOUR} (WARDEN_MAX_PLANS_PER_HOUR)")
        self.audit.append(plan.incident_id, "remediation.gate", {"workflow_id": plan.workflow_id, "run_id": _run_id(),
                                                                  "blocked": reasons})
        return reasons

    @activity.defn
    def announce(self, plan: Plan, what: str) -> list[str]:
        """Tell a person where a plan stands (register H10): `waiting` for an approval, `expired` with nothing
        changed, `verified` once the fix passed its checks, or `ended` - how the run ended, read from this run's own
        signed end row, never from the caller. Through the outbound gate, with the incident and its audit head
        (register S17)."""
        from .reporting import Report

        actions = self._approval_links(plan) if what in ("opening", "waiting") else ()
        opening = what == "opening"
        if opening:
            # With no approval domain the request still goes, without its buttons: the incident's one message is
            # never nothing (independent check, 2026-10-14).
            what = "waiting"
        why: list[str] = []
        whole: list[str] = []
        ended_at = None
        if what == "ended":
            ends = [e for e in self.audit.entries(plan.incident_id, kinds=("workflow.end",))
                    if e["body"].get("workflow_id") == plan.workflow_id and e["body"].get("run_id") == _run_id()]
            if not ends:
                return []
            body, ended_at = ends[-1]["body"], ends[-1]["at"]
            whole = [str(r) for r in (body.get("reasons") or [])[:3]]  # a denial's reason is said whole, below
            what, why = str(body.get("status")), [r[:300] for r in whole]
        self.audit.checkpoint()
        head = self.audit.head(plan.incident_id)
        tier = f"{plan.tier} - {approvals.TIER_MEANS[plan.tier]}" if plan.tier in approvals.TIER_MEANS else plan.tier
        shown = (catalog.shown_target(plan.environment, plan.entry, plan.params) if plan.entry in catalog.CATALOG
                 else plan.target)
        # Who may approve this tier, and who did (owner, 2026-10-12: "anyone in the channel can click it, and nobody
        # can see who approved"). Both from WARDEN's own record: the approver list, and this run's accepted approvals.
        need = self.policy.required.get(plan.tier, 1)
        gave = [b for b in (e["body"] for e in self.audit.entries(plan.incident_id, kinds=("approval.accepted",)))
                if b.get("workflow_id") == plan.workflow_id and b.get("run_id") == _run_id()
                and b.get("plan_hash") == plan.plan_hash]
        did = sorted({f"{self.policy.said(str(b.get('approver')))} (with their "
                      f"{'passkey' if b.get('method') == 'passkey' else 'signing key'})" for b in gave})
        # What each wrote with their approval, in their own words - inert, one line each (_words).
        notes = [(str(b.get("approver")), str(b["note"])) for b in gave if b.get("note")]
        noted = "".join((f" Their note: {_words(n)}" if len(gave) == 1 else f" Note from {self.policy.said(a)}: {_words(n)}")
                        + _tried(n) for a, n in notes)
        words = noted if what == "approved" else ""  # the person's own words in this message, if any
        # The plan's id, for whoever looks it up - not a command to type, in a message most readers act on by its
        # button (owner's bar, 2026-10-12: no unexplained jargon).
        said = {"waiting": (f"WARDEN's plan `{plan.entry}` on `{shown}` ({tier}) is waiting for an approval "
                            f"(plan `{plan.workflow_id}`). It waits until "
                            f"{environments.both_times(_deadline(plan), seconds=False)}; unapproved by then, it expires "
                            "and nothing is changed. "
                            + (f"{catalog.lasts(plan.entry)} " if catalog.lasts(plan.entry) else "")
                            + "Only an enrolled approver of this risk level can approve it"
                            + (f", and {need} different approvers are needed" if need > 1 else "")
                            + ": the link opens for nobody else, and who decided is said here when they have."),
                "approved": (f"WARDEN's plan `{plan.entry}` on `{shown}` was approved by {' and '.join(did)} at "
                             f"{environments.both_times(datetime.now(UTC))}. WARDEN checks the target once more, then "
                             "applies it." + noted),
                "expired": (f"WARDEN's plan `{plan.entry}` on `{shown}` expired without an approval. No action "
                            "was taken; the incident is still open.")}.get(what) or OUTCOME.get(
            what, "WARDEN's plan `{entry}` on `{target}` ended `" + what + "`.").format(entry=plan.entry,
                                                                                      target=shown)
        if what == "approved" and not did:
            return []  # nothing on the record says who: nothing is claimed
        if what == "denied":
            # Who said no, how and when - said as an approval is (2026-10-14: a denial did not show
            # who denied it; the message read "was denied ... Why: denied by owner"). A denial reaches the
            # workflow only from the approval page, after the approver's passkey over this exact plan
            # (approval_page._deny); who it was is this run's own signed end row.
            who = next((n for n in self.policy.approvers
                        if any(w == f"denied by {n}" or w.startswith(f"denied by {n}: ") for w in why)), "")
            if who and ended_at is not None:
                reason = next((w[len(f"denied by {who}: "):] for w in whole if w.startswith(f"denied by {who}: ")), "")
                words = f" Their reason: {_words(reason)}{_tried(reason)}" if reason else ""
                said = (f"WARDEN's plan `{plan.entry}` on `{shown}` was denied by {self.policy.said(who)} (with "
                        f"their passkey) at {environments.both_times(ended_at)}: nothing was changed." + words)
                why = []
        if what == "waiting":
            import contextlib

            from . import history

            # WARDEN's own earlier fix beside this incident's evidence: said, with whether this diagnosis named it the
            # cause - the approver decides knowing both (owner, 2026-10-15).
            said += self._own_fix_said(plan.incident_id)

            # The same fix, on the same target, that ended badly in the last day: said before the decision. A record
            # that cannot be read does not hold an approval request back.
            with contextlib.suppress(Exception):
                said += history.warning(history.plans(self.audit), entry=plan.entry, target=plan.target,
                                        plan_hash=plan.plan_hash)
        if did and what in OUTCOME:
            said += f" Approved by {' and '.join(did)}."
        if what in PERSON_TAKES_OVER:
            # The command in full (2026-10-16 audit: without --approver and --key it failed as written).
            said += (" Every automatic fix is stopped until an approver resets the kill switch: `warden killswitch "
                     "link --approver YOU --key YOUR.pem` opens the page that shows why it is on and resets it.")
        # The person's own words go only where the gate lets the whole message go: should it hold them back, the
        # decision is still said - who, how, when - and only their words are not (live, 2026-10-14: a whole denial
        # message was withheld for the note in it).
        if words:
            from .gate import enforce

            if enforce(said).verdict == "BLOCK":
                said = said.replace(words, " Their note is not shown here: the outbound gate held it back. It is on "
                                           "WARDEN's record.")
        if why:
            # A reason's own timestamp, in UTC and the display zone like every other time in a message.
            why = [_ISO_TIME.sub(lambda m: environments.both_times(datetime.fromisoformat(m.group(0)), seconds=False), w)
                   for w in why]
            # The record's reason names the approver by the list's id; a reader gets the person (their mark).
            for name in self.policy.approvers:
                why = [w.replace(f"denied by {name}", f"denied by {self.policy.said(name)}") for w in why]
            said += " Why: " + "; ".join(why)
        footer = (f"\n\n---\nWARDEN · incident `{plan.incident_id}` · audit head `{audit.short(head)}` · check it on "
                  "its Full record page, which shows the same head with its signatures checked. Approvals are signed out "
                  "of band, never given in chat.")
        if actions:
            said += " Approve with your passkey on the page below; it shows the exact plan first."
        # The incident's summary leads the first message about it that reaches the channel - the request for approval,
        # or how the run ended if it ended first (independent check, 2026-10-14: a refused or blocked run sent one
        # line, and the incident's summary never reached anyone).
        reports = [e["body"].get("markdown", "") for e in self.audit.entries(plan.incident_id, kinds=("incident.report",))]
        owed = bool(what not in RECORDED_ONLY and reports and reports[-1] and not self._summary_said(plan.incident_id))
        if owed:
            said = slack_summary(str(reports[-1])) + "\n\n**Fix plan:** " + said
        actions = (*actions, *IncidentActivities._record_link(plan.incident_id))
        # Who approved is mentioned where the message says so. A request for an approval names and mentions nobody.
        message = Report(markdown=said + footer, data={"alert": {"id": plan.incident_id, "environment": plan.environment}},
                         promotion=(), actions=actions, people=self.policy.people())
        if what in RECORDED_ONLY:
            # Approved, denied, fixed: written as ever, through the same gate, and kept for WARDEN's records page -
            # who, how, when and their note - not sent as another message in the channel (owner, 2026-10-14: "i
            # dont want that records coming here in slack everytime").
            from .chatops import name_people
            from .gate import enforce

            kept = enforce(said, alert_id=plan.incident_id)
            self.audit.append(plan.incident_id, "remediation.announce", {
                "workflow_id": plan.workflow_id, "run_id": _run_id(), "what": what, "head": head, "delivered": [],
                "recorded_only": True, "said": name_people(kept.text, self.policy.people(), slack=False)
                if kept.verdict != "BLOCK" else HELD_BACK})
            self.audit.checkpoint()
            return []
        sent = _send(self.audit, plan.incident_id, message)
        delivered = [n.sink for n in sent if n.delivered]
        self.audit.append(plan.incident_id, "remediation.announce", {"workflow_id": plan.workflow_id,
                                                                     "run_id": _run_id(), "what": what,
                                                                     "head": head, "delivered": delivered,
                                                                     "summary": owed})
        if what in OUTCOME or why:
            self.audit.checkpoint()  # said after the end row: a run's record still ends signed
        return delivered

    def _own_fix_said(self, incident: str) -> str:
        """One sentence per earlier fix of WARDEN's put beside this incident's evidence (IncidentActivities._own_fixes),
        and whether the diagnosis cited it. Empty: none, or a record that cannot be read."""
        try:
            steps = [e["body"] for e in self.audit.entries(incident, kinds=("incident.own_fixes",))]
            diag = [e["body"] for e in self.audit.entries(incident, kinds=("incident.diagnose",))]
        except Exception:  # noqa: BLE001 - the request goes out without it
            return ""
        if not steps:
            return ""
        fixes, items = steps[-1].get("fixes") or [], set(steps[-1].get("items") or [])
        cited = set(diag[-1].get("cited") or []) if diag else set()
        said = "; ".join(f"`{f.get('entry')}` on `{f.get('on')}` (incident `{f.get('incident')}`), "
                         f"{f.get('minutes_before')} min before this alarm started" for f in fixes[:3])
        verdict = ("This diagnosis cites that change as part of the cause." if items & cited else
                   "This diagnosis does not cite it: it found another cause. Connected or not, check that fix's record "
                   "before deciding.")
        return f" Before you decide: WARDEN's own fix was applied in this environment shortly before - {said}. {verdict}"

    def _summary_said(self, incident: str) -> bool:
        """The incident's summary already reached someone: in its report's own message, or at the top of one about
        its plan."""
        rows = self.audit.entries(incident, kinds=("incident.notify", "remediation.announce"))
        return any(e["body"].get("summary") and e["body"].get("delivered") for e in rows)

    @activity.defn
    def side_effects(self, plan: Plan) -> list[str]:
        """Other alarms intake recorded as starting in this fix's environment after this run applied it (intake.side_
        effect, kept under the fix's workflow id) - from the record, never from the signal that said so. Each is a
        failure for the breaker: they may be unrelated, and an alarm anyone can raise must not trip the kill switch
        (security review, 2026-10-16). The fix is counted as failed only when a later incident's diagnosis cites it
        (IncidentActivities._connected). Recorded once per run. Empty: none on the record."""
        from .reporting import untrusted_inline

        run = _run_id()
        applied = [e["at"] for e in self.audit.entries(plan.incident_id, kinds=(bounds.APPLIED,))
                   if e["body"].get("workflow_id") == plan.workflow_id and e["body"].get("run_id", "") == run
                   and e["body"].get("plan_hash") == plan.plan_hash]
        if not applied:
            return []
        rows = [e["body"] for e in self.audit.entries(plan.workflow_id, kinds=("intake.side_effect",), since=applied[-1])]
        if not rows:
            return []
        if not any(e["body"].get("workflow_id") == plan.workflow_id and e["body"].get("run_id") == run
                   for e in self.audit.entries(plan.incident_id, kinds=("remediation.side_effects",))):
            self.audit.append(plan.incident_id, "remediation.side_effects", {
                "workflow_id": plan.workflow_id, "run_id": run, "plan_hash": plan.plan_hash,
                "incidents": [str(r.get("incident", "")) for r in rows]})
        # An alarm's name is its author's text: said as inert, quoted words (security review M2, 2026-10-16).
        return [f"alarm {untrusted_inline(str(r.get('rule', '')), limit=120)} started at {r.get('at')}, diagnosed as "
                f"incident `{str(r.get('incident', '')).removeprefix('inc-')}`" for r in rows[:5]]

    @activity.defn
    def again_alert(self, incident_id: str, why: str) -> dict[str, Any]:
        """The incident's alarm as on the record, as a new incident from now - as an approver's "new plan" makes one
        (discuss_replan) - after WARDEN's fix of it failed a re-check with no alarm to start one. Empty: no alarm on the
        record. Recorded."""
        rows = self.audit.entries(incident_id, kinds=("incident.alert",))
        if not rows:
            return {}
        # One generation only (security review M3, 2026-10-16): a fix made from a re-diagnosis that fails again goes to
        # a person, never into another automatic diagnosis - no chain of fixes on fixes.
        if any(e["body"].get("new") == incident_id for e in self.audit.entries(kinds=("remediation.rediagnose",))):
            self.audit.append(incident_id, "remediation.rediagnose", {"run_id": _run_id(), "new": "",
                                                                      "why": why[:300], "refused": "already a re-diagnosis"})
            return {}
        now = datetime.now(UTC)
        new = f"{incident_id.split('-')[0]}-{now:%Y%m%dT%H%M%SZ}"
        self.audit.append(incident_id, "remediation.rediagnose", {"run_id": _run_id(), "new": new, "why": why[:300]})
        alert = Alert.model_validate(rows[0]["body"]["alert"]).model_copy(
            update={"alert_id": new, "started_at": now.isoformat()})
        return {"alert": alert.model_dump(mode="json"), "new": new}

    @activity.defn
    def summary_owed(self, incident_id: str, status: str) -> list[str]:
        """The incident's one message, when its fix run ended in a way that tells nobody (failed, cancelled, or before
        a plan was made) and no message has carried its summary yet (independent check, 2026-10-14: the channel was
        left with nothing at all)."""
        from .reporting import Report

        reports = [e["body"].get("markdown", "") for e in self.audit.entries(incident_id, kinds=("incident.report",))]
        if not reports or not reports[-1] or self._summary_said(incident_id):
            return []
        self.audit.checkpoint()
        head = self.audit.head(incident_id)
        said = (slack_summary(str(reports[-1])) + f"\n\n**Fix plan:** WARDEN's fix plan for this incident ended "
                f"`{status}` before it reached a decision. A person decides what happens next; its full record says why."
                f"\n\n---\nWARDEN · incident `{incident_id}` · audit head `{audit.short(head)}` · check it on its "
                "Full record page, which shows the same head with its signatures checked. Approvals are signed out of "
                "band, never given in chat.")
        sent = _send(self.audit, incident_id, Report(
            markdown=said, data={"alert": {"id": incident_id, "environment": _environment_of(self.audit, incident_id)}},
            promotion=(), actions=IncidentActivities._record_link(incident_id)))
        delivered = [n.sink for n in sent if n.delivered]
        self.audit.append(incident_id, "remediation.announce", {"run_id": _run_id(), "what": status, "head": head,
                                                                "delivered": delivered, "summary": True})
        return delivered

    def _approval_links(self, plan: Plan) -> tuple[tuple[str, str], ...]:
        """One approval-page link per approver who may approve this tier and has a passkey enrolled (registers H6,
        R28), each valid for as long as the plan waits and recorded in the audit by its hash only - a link shows and
        does nothing without the approver's passkey, so its life is the plan's. None without an approval domain
        (WARDEN_APPROVAL_RP_ID)."""
        import secrets as _secrets

        from .approval_page import LINK_TTL, AuditLinkStore, Link
        from .chatops import LINK_LABEL

        rp = os.environ.get("WARDEN_APPROVAL_RP_ID", "").strip()
        if not rp:
            return ()
        store, now, out = AuditLinkStore(self.audit), datetime.now(UTC), []
        who = [name for name, approver in sorted(self.policy.approvers.items())
               if plan.tier in approver.tiers and approver.passkeys]
        for name in who:
            token = _secrets.token_urlsafe(32)
            store.add_link(token, Link(plan.workflow_id, name, max(_deadline(plan), now + LINK_TTL)))
            # A request names nobody (owner, 2026-10-12: "it should not ask like this: Approve as owner ... only the
            # person when approved"): who decided is said when they have. Only where several approvers each have
            # their own link does a label say whose it is - a link opens for nobody else.
            out.append((LINK_LABEL + (f" (link of {name})" if len(who) > 1 else ""), f"https://{rp}/a/{token}"))
        return tuple(out)

    @activity.defn
    def check_approval(self, plan: Plan, approval: approvals.SignedApproval,
                       accepted: list[approvals.SignedApproval]) -> ApprovalResult:
        used = {e["body"]["nonce"] for e in self.audit.entries(kinds=("approval.accepted",))}
        problems = approvals.check(approval, policy=self.policy, workflow_id=plan.workflow_id,
                                   plan_hash=plan.plan_hash, tier=plan.tier, plan_created_at=plan.created_at,
                                   used_nonces=used, environment=plan.environment)
        if any(a.approver == approval.approver for a in accepted):
            problems.append(f"{approval.approver} has already approved this plan")
        kind = "approval.refused" if problems else "approval.accepted"
        # Register H1: how long the approver had the plan before signing. Under HASTY_S is recorded as hasty - read
        # by the person who audits approvals, and by the catch trials (G7).
        latency = (approval.issued_at - plan.created_at).total_seconds()
        self.audit.append(plan.incident_id, kind, {"workflow_id": plan.workflow_id, "run_id": _run_id(),
                                                   "latency_s": round(latency, 1), "hasty": latency < HASTY_S,
                                                   "approver": approval.approver,
                                                   "approver_list": self.policy.fingerprint(),
                                                   "nonce": approval.nonce, "plan_hash": plan.plan_hash,
                                                   # Requirement R50: how many different people this tier needs.
                                                   "required": self.policy.required.get(plan.tier, 1),
                                                   "problems": problems})
        valid = accepted + ([approval] if not problems else [])
        return ApprovalResult(problems=problems, enough=approvals.enough(valid, plan.tier, self.policy))

    @activity.defn
    def check_passkey(self, plan: Plan, assertion: approvals.PasskeyAssertion,
                      accepted: list[approvals.SignedApproval]) -> ApprovalResult:
        """A passkey approval (decision D14, register H6), re-verified here whatever the page that sent it checked:
        the approver may approve this tier, the assertion answers THIS plan's challenge, with their enrolled passkey,
        user-verified, once, unexpired, its counter past every one the audit has seen, and device-bound for T3."""
        from . import passkeys

        now = datetime.now(UTC)
        problems: list[str] = []
        approver = self.policy.approvers.get(assertion.approver)
        if approver is None:
            problems.append(f"{assertion.approver!r} is not an approver")
        elif plan.tier not in approver.tiers:
            problems.append(f"{assertion.approver} may not approve {plan.tier}")
        elif refusal := approvals.environment_refusal(assertion.approver, approver, plan.environment):
            problems.append(refusal)
        if (assertion.workflow_id, assertion.plan_hash, assertion.tier) != (plan.workflow_id, plan.plan_hash, plan.tier):
            problems.append("the passkey approval is for a different plan")
        cooling = timedelta(minutes=self.policy.cooling_off_minutes.get(plan.tier, 0))
        if now < plan.created_at + cooling:
            problems.append(f"{plan.tier} needs the plan to exist for {cooling} before it is approved")
        if any(a.approver == assertion.approver for a in accepted):
            problems.append(f"{assertion.approver} has already approved this plan")
        enrolled = next((c for c in (approver.passkeys if approver else [])
                         if c.credential_id == assertion.response.get("id")), None)
        if approver is not None and enrolled is None:
            problems.append(f"the passkey used is not one {assertion.approver} enrolled")
        rp_id = os.environ.get("WARDEN_APPROVAL_RP_ID", "")
        if not rp_id:
            problems.append("no approval domain is configured (WARDEN_APPROVAL_RP_ID)")
        seen = self.audit.entries(kinds=("approval.accepted",))
        verified = None
        if enrolled is not None and rp_id:  # every reason is reported, not only the first
            counts = [e["body"].get("sign_count", 0) for e in seen if e["body"].get("credential_id") == enrolled.credential_id]
            verified, found = passkeys.verify_approval(
                assertion.response, credential=passkeys.Credential(
                    assertion.approver, enrolled.credential_id, enrolled.public_key,
                    max([enrolled.sign_count, *counts]), enrolled.device_bound),
                pending=passkeys.Pending(plan.workflow_id, plan.plan_hash, plan.tier, assertion.nonce,
                                         assertion.expires_at, assertion.challenge),
                rp_id=rp_id, origin=f"https://{rp_id}", now=now, used_nonces={e["body"]["nonce"] for e in seen})
            problems += found
        latency = (now - plan.created_at).total_seconds()
        self.audit.append(plan.incident_id, "approval.refused" if problems else "approval.accepted", {
            "workflow_id": plan.workflow_id, "run_id": _run_id(), "method": "passkey", "latency_s": round(latency, 1),
            "hasty": latency < HASTY_S, "approver": assertion.approver, "nonce": assertion.nonce,
            "approver_list": self.policy.fingerprint(),
            "plan_hash": plan.plan_hash, "required": self.policy.required.get(plan.tier, 1),
            "credential_id": enrolled.credential_id if enrolled else "",
            "sign_count": verified.new_sign_count if verified else None, "problems": problems,
            # The approver's own words, as the page kept them (approvals.note): on the record with the decision.
            **({"note": approvals.note(assertion.note)} if assertion.note else {})})
        if problems:
            return ApprovalResult(problems=problems)
        record = approvals.SignedApproval(approver=assertion.approver, workflow_id=plan.workflow_id,
                                          plan_hash=plan.plan_hash, tier=plan.tier, issued_at=now,
                                          expires_at=assertion.expires_at, nonce=assertion.nonce,
                                          signature=f"passkey:{enrolled.credential_id}")
        return ApprovalResult(problems=[], accepted=record,
                              enough=approvals.enough([*accepted, record], plan.tier, self.policy))

    @activity.defn
    def precheck(self, plan: Plan) -> list[str]:
        """Read live state again right before acting: a plan approved against a state that no longer
        exists is not the plan that was approved."""
        live = self.platform.live(plan.entry, plan.params, **_env(self.platform.live, plan.environment))
        problems = catalog.validate(plan.entry, plan.params, live)
        if _basis_now(plan) != plan.basis:
            problems.append("WARDEN's code or catalogue changed after the plan was made; it needs a new plan")
        elif plan_hash(plan.entry, plan.params, live.get("state", {}), plan.basis) != plan.plan_hash:
            problems.append("the target changed after the plan was made; it needs a new plan")
        if entry := catalog.CATALOG.get(plan.entry):
            problems += _environment_problems(plan.environment, entry, plan.params, live)
        self.audit.append(plan.incident_id, "remediation.precheck",
                          {"workflow_id": plan.workflow_id, "run_id": _run_id(), "plan_hash": plan.plan_hash,
                           "problems": problems})
        return problems

    def _not_approved(self, plan: Plan, service: str) -> list[str]:
        """Why `plan` may not be applied, from WARDEN's OWN audit log - never from what the workflow
        says, and only rows of THIS run (a replayed or forged activity result can carry a workflow past
        any of its steps: second and third reviews, 2026-09-30):
        - the plan resolve_plan made for this workflow and run, same entry and parameters, no problems;
        - as many distinct approvers of that plan hash, in this run, as its tier needs;
        - a clean precheck of that plan hash, in this run, AFTER the approvals (drift);
        - bounds and the kill switch, checked again now - the gate ran before the approval wait."""
        run = _run_id()

        def rows(kind: str) -> list[dict[str, Any]]:
            return [e for e in self.audit.entries(plan.incident_id, kinds=(kind,))
                    if e["body"].get("workflow_id") == plan.workflow_id and e["body"].get("run_id", "") == run
                    and e["body"].get("plan_hash") == plan.plan_hash]

        made = [e["body"] for e in rows("remediation.plan")]
        if (not made or made[-1].get("problems") or made[-1].get("entry") != plan.entry
                or made[-1].get("params") != plan.params or made[-1].get("target") != plan.target
                or made[-1].get("basis") != plan.basis):
            return ["no such plan was made for this workflow run"]
        if _basis_now(plan) != plan.basis:  # a worker deployed after the precheck (register O5)
            return ["WARDEN's code or catalogue changed after the plan was made"]
        approved = rows("approval.accepted")
        need = self.policy.required.get(made[-1].get("tier", ""), 1)
        if len({e["body"].get("approver") for e in approved}) < need:
            return [f"{len({e['body'].get('approver') for e in approved})} of {need} approval(s) recorded for this plan"]
        last_approval = max(e["seq"] for e in approved)
        checks = [e for e in rows("remediation.precheck") if e["seq"] > last_approval]
        if not checks or checks[-1]["body"].get("problems"):
            return ["no clean precheck of this plan after its approval"]
        return self._blocked(plan)

    def _who(self, plan: Plan, run: str) -> dict[str, Any]:
        """Who approved this plan in this run, from the audit's own rows - never from a caller (audit A-P-5): the
        actor session that makes the change names them."""
        approvers = {e["body"].get("approver") for e in self.audit.entries(plan.incident_id, kinds=("approval.accepted",))
                     if e["body"].get("workflow_id") == plan.workflow_id and e["body"].get("run_id", "") == run
                     and e["body"].get("plan_hash") == plan.plan_hash}
        return {"incident": plan.incident_id, "plan_hash": plan.plan_hash, "approvers": sorted(a for a in approvers if a)}

    def _blocked(self, plan: Plan) -> list[str]:
        """The kill switch, the bounds and the change freezes (register C6, P19), at the gate and again right
        before apply: a freeze that starts while a plan waits for its approval still holds."""
        now = datetime.now(UTC)
        return (bounds.blocked(self.audit, service=plan.target, action_class=plan.entry, now=now, limits=self.limits)
                + freeze.active(plan.environment, now))

    def _refuse(self, plan: Plan, run: str, why: list[str]) -> None:
        """Apply refused before anything was touched: on the record, and raised as its own type - the workflow reports
        "nothing was changed", not "may be half-made" (fourth review). Never retried."""
        self.audit.append(plan.incident_id, "remediation.refused", {"workflow_id": plan.workflow_id, "run_id": run,
                                                                   "plan_hash": plan.plan_hash, "why": why})
        raise ApplicationError("apply refused: " + "; ".join(why), type=APPLY_REFUSED, non_retryable=True)

    @activity.defn
    def apply(self, plan: Plan, service: str) -> str:
        run = _run_id()
        refused = self._not_approved(plan, service)
        if refused:
            self._refuse(plan, run, refused)
        done = [e for e in self.audit.entries(plan.incident_id, kinds=(bounds.APPLIED,))
                if e["body"].get("plan_hash") == plan.plan_hash and e["body"].get("workflow_id") == plan.workflow_id
                and e["body"].get("run_id", "") == run]
        if done:  # idempotent WITHIN this run: a retried activity never applies twice. Scoped to the run
            return "already applied"  # (fourth review): a later approved run of the same plan applied nothing
        # B20: one writer per target, across every worker - taken here, held until this run's end row (locks.py).
        locked = locks.take(self.audit, plan.incident_id, plan.target, workflow_id=plan.workflow_id, run_id=run,
                            plan_hash=plan.plan_hash, now=datetime.now(UTC))
        if locked:
            self._refuse(plan, run, [locked])
        self.audit.append(plan.incident_id, "remediation.intent", {"workflow_id": plan.workflow_id,
                                                                   "run_id": run, "plan_hash": plan.plan_hash})
        try:
            # The approved snapshot goes to a platform that can hold the write to it (sixth review: a count that
            # moved after the precheck was stepped from).
            takes = inspect.signature(self.platform.apply).parameters
            extra = {k: v for k, v in (("snapshot", plan.snapshot), ("who", self._who(plan, run)),
                                       ("environment", plan.environment)) if k in takes}
            detail = self.platform.apply(plan.entry, plan.params, **extra)
        except Exception as exc:
            if not getattr(exc, "nothing_changed", False):
                raise  # the change may be half-made: the workflow says so, and a person decides
            self._refuse(plan, run, [f"the platform refused before changing anything: {_safe_error(exc)}"])
        bounds.record_applied(self.audit, plan.incident_id, service=plan.target, action_class=plan.entry,
                              plan_hash=plan.plan_hash, detail=detail, workflow_id=plan.workflow_id, run_id=run)
        return detail

    @activity.defn
    def check_success(self, plan: Plan, service: str) -> bool:
        # Asked of the platform that made the change, when it can route by entry: a database of the same name
        # must not judge a Deployment (sixth review).
        routed = getattr(self.platform, "healthy_for", None)
        # When this run applied the fix: a health check judges what came after it (live, 2026-10-16).
        run = _run_id()
        applied = [e["at"] for e in self.audit.entries(plan.incident_id, kinds=(bounds.APPLIED,))
                   if e["body"].get("workflow_id") == plan.workflow_id and e["body"].get("run_id", "") == run
                   and e["body"].get("plan_hash") == plan.plan_hash]
        params = {**plan.params, **({catalog.APPLIED_AT: applied[-1].isoformat()} if applied else {})}
        if routed and "params" in inspect.signature(routed).parameters:
            healthy = bool(routed(plan.entry, service, params=params, **_env(routed, plan.environment)))
        else:
            healthy = bool(routed(plan.entry, service) if routed else self.platform.healthy(service))
        # Success is the symptom gone, not only the change landed (research 2026-10-15, item 12): the CloudWatch
        # alarm that opened the incident, read live, must not still be in ALARM. Read only when the fix's own check
        # passed; a state that cannot be read, or INSUFFICIENT_DATA, keeps the check's verdict - a good fix is never
        # rolled back for want of a reading. CloudWatch's intake forwards ALARM transitions only, so the record
        # holds no OK: the alarm itself is asked.
        alarm, state = self._incident_alarm(plan.incident_id), None
        read = getattr(self.platform, "alarm_state", None)
        if healthy and alarm and read:
            try:
                state = read(alarm, **_env(read, plan.environment))
            except Exception:  # noqa: BLE001 - unknown keeps the fix's own verdict
                state = None
            if state == "ALARM":
                healthy = False
        # And the symptom itself gone (B13): the alarm's own metric no worse for N periods since the fix, and no new
        # error class - for a Datadog monitor too. "present" fails the check; "unknown" keeps its verdict.
        healthy, symptom = self._symptom_check(plan, applied, healthy)
        # Every real check is on the record with its run: the verdict is taken from these rows, never from
        # what an activity result or the workflow claims (fourth review, 2026-09-30: run 1's "healthy"
        # replayed into run 2 marked a fix verified with no health check made).
        self.audit.append(plan.incident_id, "remediation.check",
                          {"workflow_id": plan.workflow_id, "run_id": _run_id(), "plan_hash": plan.plan_hash,
                           "healthy": healthy, **({"alarm": alarm, "alarm_state": state} if alarm else {}),
                           **symptom})
        return healthy

    def _symptom_check(self, plan: Plan, applied: list[datetime], healthy: bool) -> tuple[bool, dict[str, Any]]:
        """(the verdict, the audit row's `symptom` field): read only after this run applied the fix and its own check
        passed."""
        if not (healthy and applied):
            return healthy, {}
        row = self._symptom(plan, applied[-1])
        return row.get("state") != symptoms.PRESENT, ({"symptom": row} if row else {})

    def _symptom(self, plan: Plan, applied: datetime) -> dict[str, Any]:
        """The symptom check's reading of the incident's own alarm (symptom.py), as its audit row; {} when the
        incident came from no alarm WARDEN can read again. A read that fails is "unknown", said so."""
        alert = self._incident_alert(plan.incident_id)
        labels = alert.get("labels") or {}
        applied = _utc(applied)
        alert_at = _utc(_parsed(alert.get("started_at")) or applied)
        n, now = symptoms.periods(), symptoms.now()
        source = "datadog" if labels.get("via") == "datadog" else "cloudwatch"
        try:
            found = self._symptom_read(plan, source, alert, alert_at=alert_at, applied=applied, now=now, n=n)
        except symptoms.READ_ERRORS as exc:
            found = symptoms.Reading(source=source, periods=n, why=f"not read: {type(exc).__name__}")
        return found.row() if found else {}

    def _symptom_read(self, plan: Plan, source: str, alert: dict[str, Any], **when: Any) -> symptoms.Reading | None:
        labels = alert.get("labels") or {}
        if source == "datadog":
            if not (labels.get("datadog_monitor") and datadog.configured()):
                return None
            return symptoms.datadog(datadog.DatadogReader()._ask, str(labels["datadog_monitor"]),
                                    str(alert.get("service") or ""), **when)
        reader = getattr(self.platform, "reader", None)
        if not (labels.get("via") == "cloudwatch" and labels.get("alarm") and reader):
            return None
        read = reader(**_env(reader, plan.environment))
        return symptoms.cloudwatch(read, str(labels["alarm"]), labels, **when) if read else None

    def _incident_alert(self, incident_id: str) -> dict[str, Any]:
        """The alert that opened the incident, as its record holds it; {} for none."""
        rows = self.audit.entries(incident_id, kinds=("incident.alert",))
        return (rows[-1]["body"].get("alert") or {}) if rows else {}

    def _incident_alarm(self, incident_id: str) -> str:
        """The CloudWatch alarm that opened the incident, from the incident's own record (intake sets `via` last, so
        a sender's label never says it); "" for any other source."""
        rows = self.audit.entries(incident_id, kinds=("incident.alert",))
        labels = ((rows[-1]["body"].get("alert") or {}).get("labels") or {}) if rows else {}
        return str(labels.get("alarm", "")) if labels.get("via") == "cloudwatch" else ""

    @activity.defn
    def record_result(self, plan: Plan, service: str, ok: bool, consecutive: int = 1) -> Recorded:
        run = _run_id()
        checks = [e["body"] for e in self.audit.entries(plan.incident_id, kinds=("remediation.check",))
                  if e["body"].get("workflow_id") == plan.workflow_id and e["body"].get("run_id", "") == run
                  and e["body"].get("plan_hash") == plan.plan_hash]
        # Verified only if THIS run applied the plan: a replayed apply result let a run with nothing applied
        # end "recovered" and write a success row (fifth review, 2026-10-01).
        applied = any(e["body"].get("workflow_id") == plan.workflow_id and e["body"].get("run_id", "") == run
                      and e["body"].get("plan_hash") == plan.plan_hash
                      for e in self.audit.entries(plan.incident_id, kinds=(bounds.APPLIED,)))
        # The last `consecutive` checks of this run, all healthy (register C18a): one good reading is not recovery.
        need = max(1, int(consecutive))
        verified = applied and len(checks) >= need and all(c.get("healthy") is True for c in checks[-need:])
        if verified != ok:
            self.audit.append(plan.incident_id, "remediation.result_mismatch",
                              {"workflow_id": plan.workflow_id, "run_id": run, "claimed": ok, "recorded": verified})
        bounds.record_result(self.audit, plan.incident_id, service=plan.target, ok=verified, now=datetime.now(UTC),
                             limits=self.limits, workflow_id=plan.workflow_id, run_id=run,
                             plan_hash=plan.plan_hash)
        return Recorded(run_id=run, ok=verified)

    def _landed_since(self, plan: Plan, run: str, row: dict[str, Any]) -> str:
        """B21: why the fix is not undone - something landed on the target after it, or a source that would say so
        could not be read (landed.py) - or "" to go on. What was read is a row either way."""
        applied = [e["at"] for e in self.audit.entries(plan.incident_id, kinds=(bounds.APPLIED,))
                   if e["body"].get("workflow_id") == plan.workflow_id and e["body"].get("run_id", "") == run
                   and e["body"].get("plan_hash") == plan.plan_hash]
        reader = getattr(self.platform, "writes_reader", None)
        found, unread, unchecked = landed.since_fix(
            entry=plan.entry, params=plan.params, target=plan.target, incident=plan.incident_id,
            workflow_id=plan.workflow_id, environment=plan.environment, applied_at=applied[-1], now=datetime.now(UTC),
            log=self.audit, writes=reader(plan.entry, plan.environment) if reader else None)
        self.audit.append(plan.incident_id, "remediation.landed", {
            **row, "since": applied[-1].isoformat(), "unread": unread, "unchecked": unchecked,
            "landed": landed.shown(found[:10])})
        if not found and not unread:
            return ""
        detail = landed.said(found, unread)
        self.audit.append(plan.incident_id, "remediation.rollback", {**row, "detail": detail})
        return detail

    @activity.defn
    def rollback(self, plan: Plan) -> str:
        run = _run_id()
        row = {"workflow_id": plan.workflow_id, "run_id": run, "plan_hash": plan.plan_hash}
        # Only what THIS run applied is undone: after a replayed apply result, a run that changed nothing
        # rolled the target back anyway (sixth review, 2026-10-01).
        if not any(e["body"].get("workflow_id") == plan.workflow_id and e["body"].get("run_id", "") == run
                   and e["body"].get("plan_hash") == plan.plan_hash
                   for e in self.audit.entries(plan.incident_id, kinds=(bounds.APPLIED,))):
            detail = "nothing to roll back: this run applied nothing"
            self.audit.append(plan.incident_id, "remediation.rollback", {**row, "detail": detail})
            return detail
        # B20: the target's lock taken again, in one step with the check (locks.take): this run's own hold goes on, a
        # lapsed one is taken anew, and while another run holds the target the undo would write over its change.
        locked = locks.take(self.audit, plan.incident_id, plan.target, workflow_id=plan.workflow_id, run_id=run,
                            plan_hash=plan.plan_hash, now=datetime.now(UTC))
        if locked:
            detail = f"not rolled back: {locked}; undoing this fix could undo that run's change too - a person decides"
            self.audit.append(plan.incident_id, "remediation.rollback", {**row, "detail": detail})
            return detail
        if why := self._landed_since(plan, run, row):
            return why
        try:
            takes = inspect.signature(self.platform.rollback).parameters
            extra = {k: v for k, v in (("who", self._who(plan, run)), ("environment", plan.environment)) if k in takes}
            detail = self.platform.rollback(plan.entry, plan.params, plan.snapshot, **extra)
        except Exception as exc:  # noqa: BLE001 - every failure is the same fact: WARDEN's change may still be there
            if getattr(exc, "nothing_changed", False) and getattr(exc, "own_check", False):
                # WARDEN's own check refused the undo before any write: the target is no longer as the fix left it
                # (someone changed it since - or put it back). Nothing is half-made and nothing is unknown, so this is
                # not a failed rollback and the kill switch stays off: a person takes over (first live rollback,
                # 2026-10-12: a rule already switched off again was reported "undoing it FAILED, state unknown").
                detail = f"not rolled back: {_safe_error(exc)}"
                self.audit.append(plan.incident_id, "remediation.rollback", {**row, "detail": detail})
                return detail
            reason = f"rollback failed: {_safe_error(exc)}"
            self.audit.append(plan.incident_id, "remediation.rollback_failed", {**row, "why": reason})
            # A change WARDEN made may still be in place: no further fix runs until a person resets the switch.
            bounds.trip(self.audit, plan.incident_id, reason, workflow_id=plan.workflow_id, run_id=_run_id())
            raise ApplicationError(reason, type=ROLLBACK_FAILED, non_retryable=True) from None
        # Whether the target was really changed back: WARDEN's own undo is a change beside a later alarm's evidence, as
        # its fix is (live, 2026-10-16: the undo broke checkout again, and the next diagnosis never saw it).
        undone = not str(detail).startswith(("nothing to roll back", "not rolled back"))
        self.audit.append(plan.incident_id, "remediation.rollback", {**row, "detail": detail, "undone": undone})
        return detail

    @activity.defn
    def finish(self, incident_id: str, workflow_id: str, outcome: FixOutcome) -> None:
        # The signed end row states what THIS run's audit rows show, not what the workflow claims (fourth
        # review: a refused apply was recorded with approved and prechecked True).
        run = _run_id()
        # Once per run: Temporal retries this activity when a step after the end row fails, and a second end row
        # was written (eighth review, 2026-10-01).
        if run and any(e["body"].get("workflow_id") == workflow_id and e["body"].get("run_id") == run
                       for e in self.audit.entries(incident_id, kinds=("workflow.end",))):
            # Signed even when this try only finds the row: the try that wrote it may have failed before its
            # checkpoint (register R9-O4), and the end of a run must not stay unsigned.
            self.audit.checkpoint()
            return

        def ours(kind: str) -> list[dict[str, Any]]:
            return [e["body"] for e in self.audit.entries(incident_id, kinds=(kind,))
                    if e["body"].get("workflow_id") == workflow_id and e["body"].get("run_id", "") == run
                    and (not outcome.plan_hash or e["body"].get("plan_hash") == outcome.plan_hash)]

        recorded = dict(outcome.checklist)
        # Approved means the tier's quorum of different approvers, as the workflow requires - one signature
        # of two was recorded as approved (fifth review, 2026-10-01).
        plans = ours("remediation.plan")
        tier = plans[-1].get("tier", "") if plans else ""
        approvers = {b.get("approver") for b in ours("approval.accepted")}
        recorded["approved"] = bool(plans) and len(approvers) >= self.policy.required.get(tier, 1)
        recorded["prechecked"] = any(not b.get("problems") for b in ours("remediation.precheck"))
        recorded["applied"] = bool(ours(bounds.APPLIED))
        results = ours(bounds.RESULT)
        recorded["verified"] = bool(results) and results[-1].get("ok") is True
        body = {"workflow_id": workflow_id, "run_id": run, **outcome.model_dump(), "checklist": recorded,
                # Requirement R50: who approved, how many the tier required, and - said, not implied - whether one
                # person alone decided this change.
                "approvers": sorted(a for a in approvers if a), "required": self.policy.required.get(tier, 1),
                "single_approver": recorded["approved"] and len(approvers) == 1}
        if recorded != outcome.checklist:
            body["claimed_checklist"] = outcome.checklist
        # A run that leaves a target in an unknown state stops every automatic fix until a person resets the
        # switch - whatever ended it. Only the rollback activity's own failure tripped it: a rollback past its
        # timeout, or on a worker that died, ended rollback_failed with the switch off (seventh review, 2026-10-01).
        # Before the end row, and once per run: the rollback may have tripped it already.
        if outcome.status in PERSON_TAKES_OVER and not any(
                t["body"].get("workflow_id") == workflow_id and t["body"].get("run_id") == run
                for t in bounds.trips(self.audit)):
            bounds.trip(self.audit, incident_id, f"{workflow_id} ended {outcome.status}: {'; '.join(outcome.reasons)}",
                        workflow_id=workflow_id, run_id=run)
        self.audit.append(incident_id, "workflow.end", body)
        self.audit.checkpoint()
        # How every plan ended, in the worker's log beside how it opened: a denied or expired plan left no line, and
        # only the audit could say (live, 2026-10-12). The status and who approved - never a typed reason.
        _note(f"{incident_id} fix plan {workflow_id} ended {outcome.status} approvers={','.join(body['approvers']) or '-'}")
        if outcome.status == "recovered":
            # Decision D13: the fix is verified, so the incident's page is resolved - and the resolve is on the record.
            from .chatops import page_resolve

            resolved = page_resolve(incident_id)
            if resolved is not None:
                self.audit.append(incident_id, "page.resolved", {"workflow_id": workflow_id, "run_id": run,
                                                                 "delivered": resolved.delivered,
                                                                 "detail": resolved.detail})
        if recorded["applied"] and self.changes is not None and plans:
            # Register O9: a change to a live system is recorded where the team looks for changes - once per run,
            # after the signed end row it cites. A record that could not be written is itself recorded.
            from .changes import issue_text

            title, text = issue_text(incident_id=incident_id, end=body, plan=plans[-1],
                                     head=self.audit.head(incident_id), at=datetime.now(UTC))
            url, detail = self.changes.open(title, text)
            self.audit.append(incident_id, "change.recorded", {"workflow_id": workflow_id, "run_id": run,
                                                               "url": url, "detail": detail})
            self.audit.checkpoint()


# --------------------------------------------------------------------------- incident


class EvidencePack(BaseModel):
    """What leaves the read side: everything already redacted. The redaction map is not here - it
    stays inside `prepare`, so it never enters Temporal's history."""
    alert: Alert
    context: ContextBundle
    redacted_logs: list[str] = Field(default_factory=list)
    redacted_deploys: list[dict[str, str]] = Field(default_factory=list)
    prompt: str
    masked: int
    steps: list[dict[str, Any]] = Field(default_factory=list)
    # The evidence source the read side used. The report names it, and it is rendered in another zone, whose own
    # WARDEN_BACKEND is unset: live reads were labelled "a recorded demo incident (fixture)" (2026-10-09).
    backend: str = "fixture"


class Diagnosed(BaseModel):
    # The resources the model asked to read before deciding (G9-B); empty when it decided.
    need_evidence: list[dict[str, str]] = Field(default_factory=list)
    root_cause: RootCause
    proposal: RemediationProposal
    cost: CostRecord
    steps: list[dict[str, Any]] = Field(default_factory=list)
    model_unavailable: str = ""  # why the model was not used: verify then escalates (register M19)


# A cap across incidents (registers M18, A-P-4): a storm of incidents, each within its own budget, still spent without
# end. Counted from the audit over the last 24 hours, reservations of unfinished calls included.
MAX_PLANS_PER_HOUR = int(os.environ.get("WARDEN_MAX_PLANS_PER_HOUR", "6"))
HASTY_S = 10.0  # an approval signed this soon after the plan was made was not read (register H1)
DAILY_MAX_USD = float(os.environ.get("WARDEN_DAILY_MAX_USD", "10.00"))
DAILY_MAX_TOKENS = int(os.environ.get("WARDEN_DAILY_MAX_TOKENS", "2000000"))


class Verified(BaseModel):
    verdict: Verdict
    halted_reason: str | None = None
    steps: list[dict[str, Any]] = Field(default_factory=list)


class IncidentActivities:
    """The diagnosis pipeline (graph.py's nodes, unchanged), split where the trust zones split:
    `prepare` reads and redacts, `diagnose` is the only model call, `verify` has no model."""

    def __init__(self, *, audit: AuditLog, backend: Any = None,
                 llm_factory: Callable[[], Any] | None = None, platform: Any = None, policy: Any = None) -> None:
        self.policy = policy  # the approver list, for how the report names who approved an earlier plan
        self.audit, self.backend = audit, backend
        self.llm_factory = llm_factory
        self.platform = platform  # requirement R38: the AWS platform's CloudTrail reads for the change timeline

    def _record(self, alert_id: str, steps: list[dict[str, Any]]) -> None:
        for step in steps:
            self.audit.append(alert_id, f"incident.{step.get('node', 'step')}", step)

    @activity.defn
    def prepare(self, alert: Alert) -> EvidencePack:
        from . import graph

        state: dict[str, Any] = {"alert": alert, "backend": self.backend}
        steps: list[dict[str, Any]] = []
        for node in (graph.node_ingest, graph.node_gather, graph.node_redact, graph.node_tripwire):
            steps += graph.apply_node(state, node(state))
            if node is graph.node_gather:
                # Before redaction, so the line is masked with the rest of the evidence, one map.
                own = self._own_fixes(alert)
                if own:
                    state["context"] = state["context"].model_copy(
                        update={"logs": [*state["context"].logs, *(line for line, _ in own)]})
                    steps.append({"node": "own_fixes", "fixes": [link for _, link in own]})
        prompt = graph._evidence_blob(state)  # built HERE, with the map, which then goes out of scope
        own_step = next((s for s in steps if s.get("node") == "own_fixes"), None)
        if own_step is not None:
            from . import evidence

            # The ids the model is shown them by, so a citation of one can be told from a citation of anything else - each
            # fix's own trusted (C) item only: an application's log line that copies the words is not WARDEN's (review L2).
            items = [i for i in evidence.index(state["context"]).values() if i.id.startswith("C") and _OWN_FIX in i.text]
            for fix in own_step["fixes"]:
                # A fix and its undo share the workflow id: each is matched to its own line.
                fix["item"] = next((i.id for i in items if f"{_OWN_FIX}{fix['workflow_id']} " in i.text
                                    and (" warden undo of " in i.text) == bool(fix.get("undo"))), "")
            own_step["items"] = [f["item"] for f in own_step["fixes"] if f["item"]]
        if os.environ.get("WARDEN_HISTORY_IN_PROMPT", "").strip() == "1":
            # Past fix plans on the alert's resources, as fixed-vocabulary facts from the signed record (history.
            # prompt_facts) - off unless measured to help; a record that cannot be read adds nothing.
            from . import history

            try:
                shown = history.for_prompt(history.past(alert, self.audit), self.audit)
                past = history.prompt_facts(shown)
            except Exception:  # noqa: BLE001 - the diagnosis goes on without it
                shown, past = [], ""
            if past:
                prompt = f"{prompt}\n\n{past}"
                # Which past runs the model was shown, on the record beside its diagnosis (research 2026-10-15): a
                # wrong diagnosis that followed history can be traced to the rows that led it.
                steps.append({"node": "history_shown", "seqs": [s for r in shown for s in r["seqs"]]})
        self._record(alert.alert_id, steps)
        # The alarm as it came in, so the incident can be discussed later from its own evidence (discuss.py). Its
        # free text redacted, as everything on the record is.
        from .redaction import redact

        self.audit.append(alert.alert_id, "incident.alert", {"run_id": _run_id(), "alert": alert.model_copy(
            update={"summary": redact(alert.summary).text, "name": redact(alert.name).text}).model_dump(mode="json")})
        # The evidence exactly as the model is shown it - redacted, its untrusted text quarantined, scanned by the
        # tripwire - kept with the incident, so a question about it later is answered from these same items (the
        # same ids the diagnosis cited) without reading everything again (owner, 2026-10-14: "why read evidence
        # again, it should be memory"). Nothing writes into it but this step; the model never does.
        # ponytail: in the audit row itself (Aurora, encrypted at rest); a separate store if packs grow past ~1 MB.
        self.audit.append(alert.alert_id, "incident.evidence", {
            "run_id": _run_id(), "prompt": prompt, "sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest()})
        return EvidencePack(alert=state["alert"], context=state["context"], prompt=prompt,
                            backend=str(getattr(self.backend, "name", None) or "fixture"),
                            redacted_logs=state.get("redacted_logs", []),
                            redacted_deploys=state.get("redacted_deploys", []),
                            masked=len(state.get("redaction_map", {})), steps=steps)

    def _own_fixes(self, alert: Alert) -> list[tuple[str, dict[str, str]]]:
        """WARDEN's fixes applied in this alarm's environment in the OWN_FIX_WINDOW before it started: one CHANGE line
        each, as aws_stack writes a person's write (verifier._CHANGE_LINE reads it the same way), and the link both
        records keep. A record that cannot be read adds nothing."""
        from .aws_stack import _safe
        from .resolver import named_resources

        started = _when_iso(alert.started_at) or datetime.now(UTC)
        out = []
        try:
            applied = self.audit.entries(kinds=(bounds.APPLIED,), since=started - OWN_FIX_WINDOW)
            # WARDEN's own undos too (live, 2026-10-16): each is told with the fix it undid, at the time of the undo.
            undos = []
            for r in self.audit.entries(kinds=("remediation.rollback",), since=started - OWN_FIX_WINDOW):
                if r["body"].get("undone") is not True:
                    continue
                fix = next((e for e in self.audit.entries(r["correlation_id"], kinds=(bounds.APPLIED,))
                            if e["body"].get("workflow_id") == r["body"].get("workflow_id")
                            and e["body"].get("run_id", "") == r["body"].get("run_id", "")), None)
                if fix is not None:
                    undos.append({**fix, "at": r["at"], "undo": True})
            for e in [*applied, *undos]:
                b, at, undo = e["body"], e["at"], bool(e.get("undo"))
                if str(b.get("service", "")).partition("/")[0] != alert.environment or at > started:
                    continue
                if e["correlation_id"] == alert.alert_id:
                    continue  # this incident's own fix
                plan = next((p["body"] for p in self.audit.entries(e["correlation_id"], kinds=("remediation.plan",))
                             if p["body"].get("workflow_id") == b.get("workflow_id")), {})
                on = _safe(str(plan.get("service") or "").strip() or "?")
                wid, inc = _safe(b.get("workflow_id")), _safe(e["correlation_id"])
                minutes = int((started - at).total_seconds() // 60)
                where = ("the same resource as this alarm" if on in named_resources(alert)
                         else "a different resource from this alarm's")
                did = "undo of " if undo else ""
                line = (f"CHANGE {at.astimezone(UTC):%Y-%m-%dT%H:%M:%S}Z warden {did}{_safe(b.get('action_class'))} on "
                        f"{on} {_OWN_FIX}{wid} for incident {inc}, "
                        f"{'undone' if undo else 'applied'} {minutes} min before this alarm started, on {where})")
                link = {"incident": str(e["correlation_id"]), "workflow_id": str(b.get("workflow_id") or ""),
                        "entry": str(b.get("action_class") or ""), "on": on, "minutes_before": str(minutes),
                        **({"undo": "1"} if undo else {})}
                out.append((line, link))
                # The earlier fix's own record says a later alarm was looked at beside it, and which - once.
                if not any(r["body"].get("incident") == alert.alert_id and r["body"].get("workflow_id") == link["workflow_id"]
                           for r in self.audit.entries(str(e["correlation_id"]), kinds=("incident.later_alarm",))):
                    self.audit.append(str(e["correlation_id"]), "incident.later_alarm", {
                        "run_id": _run_id(), "workflow_id": link["workflow_id"], "incident": alert.alert_id,
                        "minutes_after": link["minutes_before"]})
        except Exception:  # noqa: BLE001 - the diagnosis goes on without it
            return out
        return out

    @activity.defn
    def diagnose(self, pack: EvidencePack, escalate_only: str = "") -> Diagnosed:
        from . import graph
        from .llm import LLMClient

        try:
            llm, refused = (self.llm_factory or LLMClient)(), ""
        except Exception as exc:  # noqa: BLE001 - any model that cannot be built is the rules-only diagnosis
            # Live, 2026-10-15: the runtime named a model that was no longer qualified (register M20 refused it, as it
            # must) - and the incident failed here, before any path that tells a person, so it reached nobody. Now it
            # is the degraded, rules-only diagnosis with the reason said (register M19); no model is asked.
            llm, refused = LLMClient(mock=True), f"no qualified model could be used ({_safe_error(exc)})"
            _note(f"ERROR {pack.alert.alert_id}: {refused} - rules-only diagnosis (security review L4)")
        # One budget per incident, across its runs. A FAILED run may run again (ALLOW_DUPLICATE_FAILED_ONLY) - also
        # one that failed because it spent its budget - and each run built a fresh client: five restarts spent
        # $3.00 against a $0.50 cap (seventh review, 2026-10-01). Every run records what it spent, failed or not,
        # and the next one's client starts from the incident's total, so the USD and call ceilings hold. What
        # carries is what may have been billed: answered and timed-out calls, not requests that reached no model -
        # carrying those let a provider outage use up the ceiling and lock the incident (eighth review).
        before = self._spent(pack.alert.alert_id)
        llm.cost = before.model_copy()
        today = self._spent_since(datetime.now(UTC) - timedelta(hours=24))
        over = (today.usd + max(llm.max_usd - before.usd, 0.0) > DAILY_MAX_USD
                or today.input_tokens + today.output_tokens >= DAILY_MAX_TOKENS)
        if over or escalate_only or refused:
            reason = escalate_only or refused or (f"the daily model cap is reached (${today.usd:.2f} of ${DAILY_MAX_USD:.2f}, "
                                       f"{today.input_tokens + today.output_tokens} of {DAILY_MAX_TOKENS} tokens in 24 h)")
            state = {"alert": pack.alert, "context": pack.context, "llm": llm, "model_unavailable": reason}
            steps = graph.apply_node(state, graph.node_diagnose(state))
            self._record(pack.alert.alert_id, steps)
            return Diagnosed(root_cause=state["root_cause"], proposal=state["proposal"], cost=llm.cost, steps=steps,
                             model_unavailable=reason)
        # Reserved BEFORE the call (register R8-O1): what is left of the incident's budget, under an id that this
        # run's spend row settles. A run cancelled, terminated or killed mid-call wrote its spend late or never, and
        # the next run started as if nothing had been spent. Now an unsettled reservation counts as spent: the next
        # run of a killed one has no budget left, and the incident goes to a person - not to a second paid call.
        attempt = secrets.token_hex(8)
        self.audit.append(pack.alert.alert_id, "incident.llm_reserve", {
            "run_id": _run_id(), "attempt": attempt, "usd": max(llm.max_usd - before.usd, 0.0),
            "calls": max(llm.max_calls - before.calls, 0)})
        try:
            state = {"alert": pack.alert, "context": pack.context, "redacted_logs": pack.redacted_logs,
                     "redacted_deploys": pack.redacted_deploys, "prompt": pack.prompt, "llm": llm}
            steps = graph.apply_node(state, graph.node_diagnose(state))
        finally:
            now, unanswered = llm.cost, int(getattr(llm, "unanswered", 0) or 0)
            self.audit.append(pack.alert.alert_id, "incident.llm_spend", {
                "run_id": _run_id(), "attempt": attempt, "usd": now.usd - before.usd, "calls": now.calls - before.calls - unanswered,
                "unanswered": unanswered, "input_tokens": now.input_tokens - before.input_tokens,
                "output_tokens": now.output_tokens - before.output_tokens})
        self._record(pack.alert.alert_id, steps)
        return Diagnosed(root_cause=state["root_cause"], proposal=state["proposal"], cost=llm.cost, steps=steps,
                         model_unavailable=state.get("model_unavailable", ""),
                         need_evidence=list(state.get("need_evidence") or []))

    @activity.defn
    def plan_fix(self, alert: Alert, diagnosed: Diagnosed, verified: Verified) -> dict[str, Any]:
        """The fix plan request for a proposal the verifier passed for a person (G9-D1), or {} and why, audited. In
        the read zone: the reference parameters come from the platform's live read, in the environment's reader role
        (resolver.py). `alert` is the alarm's own, before any investigation widened it: a resource the model asked to
        read never becomes a target (independent review 2026-10-10, F6). The plan still waits for a signed human
        approval."""
        from . import resolver
        from .models import VerdictStatus

        alert_id = alert.alert_id
        why, req = "", None
        held_by = (set(verified.verdict.policy_ids) if verified.verdict.status == VerdictStatus.escalated else None)
        p6_only = held_by == {"P6-BLAST-RADIUS"}
        # Held by P31 alone: the fix passed every other policy and left a person's recent change to the alert's own
        # resource unaddressed. WARDEN offers the undo of THAT change instead - same target, the platform's live read
        # decides which change and whether it may be undone, a person approves it. (First live fault, 2026-10-11: a
        # cut table got "raise the capacity", P31 held it, and the person received no plan although the undo has an
        # entry; held-out g10-135 the same.) The model's own proposal stays in the report as it was.
        offer = held_by == {"P31-UNADDRESSED-CHANGE"}
        proposal = diagnosed.proposal
        if offer:
            from .models import ActionKind

            proposal = proposal.model_copy(update={"action": ActionKind.revert_change})
        if verified.verdict.status != VerdictStatus.approved_for_human and not p6_only and not offer:
            why = f"the verdict is {verified.verdict.status.value}"
        elif self.platform is None:
            why = "this worker reads no platform"
        else:
            def live(entry: str, params: dict[str, Any]) -> dict[str, Any]:
                return self.platform.live(entry, params, **_env(self.platform.live, alert.environment))

            try:
                req, why = resolver.request_for(alert, proposal, live)
            except Exception as exc:  # noqa: BLE001 - a failed live read plans nothing; the person was told
                req, why = None, f"the live read failed ({type(exc).__name__})"
        if req:
            req["workflow_id"] = resolver.workflow_id(req)
        self.audit.append(alert_id, "incident.plan_fix", {
            "run_id": _run_id(), "planned": bool(req), "why": why, **({"offered": OFFERED_UNDO} if offer else {}),
            **({"entry": req["entry"], "params": req["params"], "workflow_id": req["workflow_id"]} if req else {})})
        _note(f"{alert_id} fix plan " + (f"opened: {req['entry']}" if req else f"not opened: {why}")
              + (f" ({OFFERED_UNDO})" if offer else ""))
        return req or {}

    @activity.defn
    def no_plan(self, alert_id: str, why: str = "") -> list[str]:
        """Tell a person that the fix their report holds for approval has no plan to approve, and why (owner's live
        run, 2026-10-12: the report said "held for approval", the plan was never opened, and nothing said so). `why`:
        the workflow's own reason; else this run's plan_fix row gives it. Nothing to say when a plan was opened."""
        from .reporting import Report

        if not why:
            rows = [e["body"] for e in self.audit.entries(alert_id, kinds=("incident.plan_fix",))
                    if e["body"].get("run_id") == _run_id()]
            why = str(rows[-1].get("why") or "") if rows and not rows[-1].get("planned") else ""
        if not why:
            return []
        self.audit.checkpoint()
        head = self.audit.head(alert_id)
        said = (f"WARDEN opened no fix plan for this incident: {why[:300]}. There is nothing to approve, and nothing "
                "changes unless a person acts on the report."
                f"\n\n---\nWARDEN · incident `{alert_id}` · audit head `{audit.short(head)}` · check it on its "
                "Full record page, which shows the same head with its signatures checked. Approvals are signed out of "
                "band, never given in chat.")
        sent = _send(self.audit, alert_id, Report(
            markdown=said, data={"alert": {"id": alert_id, "environment": _environment_of(self.audit, alert_id)}},
            promotion=(), actions=self._record_link(alert_id)))
        delivered = [n.sink for n in sent if n.delivered]
        self.audit.append(alert_id, "incident.no_plan", {"run_id": _run_id(), "why": why[:300], "head": head,
                                                         "delivered": delivered})
        return delivered

    @activity.defn
    def after_hold(self, alert: Alert, held: str) -> bool | None:
        """An alarm intake held as expected down (expected.py), when its cover has ended: is it still firing? The
        alarm's own state where the backend reads one, else the last transition intake recorded for it. None: neither
        says - and unknown is not cleared."""
        read = getattr(self.backend, "alarm_firing", None)
        try:
            firing = read(alert) if read else None
        except Exception:  # noqa: BLE001 - a failed read leaves the record to say
            firing = None
        if firing is None:
            seen = self.audit.entries(f"intake-{alert.alert_id.rsplit('-', 1)[0]}", kinds=("intake.event",))
            firing = seen[-1]["body"].get("state") == "ALARM" if seen else None
        self.audit.append(alert.alert_id, "incident.after_hold", {"run_id": _run_id(), "held": held, "firing": firing,
                                                                  "first_fired": alert.started_at})
        _note(f"{alert.alert_id} held as expected down; looked at again when the hold ended: "
              + {True: "still firing - an incident now", False: "cleared - no incident"}.get(firing,
                                                                                        "unknown - an incident now"))
        return firing

    @activity.defn
    def investigate(self, pack: EvidencePack, requests: list[dict[str, str]]) -> EvidencePack:
        """The resources the model asked to read (G9-B), added to the alert's and read again as one evidence pack -
        one read, one redaction map. Only a name the alert's labels or a trusted, structured evidence item already
        holds is read: a name from a log line, an event or the model's own words is refused and audited, so text an
        application wrote cannot choose what WARDEN reads."""
        from . import investigation

        alert, accepted, refused = investigation.widen(pack.alert, pack.context, requests)
        self.audit.append(pack.alert.alert_id, "incident.investigate", {
            "run_id": _run_id(), "accepted": accepted, "refused": refused})
        if not accepted:
            return pack
        return self.prepare(alert)

    @activity.defn
    def reread(self, pack: EvidencePack) -> EvidencePack:
        """The incident's evidence read again, once, because a source answered with nothing right after the alert
        (research 2026-10-15, item 3). Which sources the second read filled and the alert's age at it go on the
        record: the measured lag of each source, where a later "nothing found" can be weighed against it."""
        again = self.prepare(pack.alert)
        before, after = set(pack.context.empty_reads), set(again.context.empty_reads)
        age = (datetime.now(UTC) - datetime.fromisoformat(pack.alert.started_at)).total_seconds() \
            if pack.alert.started_at else None
        self.audit.append(pack.alert.alert_id, "incident.reread", {
            "run_id": _run_id(), "empty_first": sorted(before), "filled": sorted(before - after),
            "still_empty": sorted(after), "alert_age_s": None if age is None else round(age)})
        return again

    def _spent_since(self, since: datetime) -> CostRecord:
        """What every incident spent on the model since `since`, reservations of unfinished calls included."""
        total = CostRecord()
        spent = self.audit.entries(kinds=("incident.llm_spend",), since=since)
        for e in spent:
            b = e["body"]
            total.input_tokens += int(b.get("input_tokens", 0))
            total.output_tokens += int(b.get("output_tokens", 0))
            total.usd += float(b.get("usd", 0.0))
        settled = {e["body"].get("attempt") for e in self.audit.entries(kinds=("incident.llm_spend",))}
        for e in self.audit.entries(kinds=("incident.llm_reserve",), since=since):
            if e["body"].get("attempt") not in settled:
                total.usd += float(e["body"].get("usd", 0.0))
        return total

    def _spent(self, alert_id: str) -> CostRecord:
        """What every earlier run of this incident spent on the model, from the audit - and, for a run whose spend
        was never written (killed mid-call), everything it had reserved."""
        total = CostRecord()
        spent = self.audit.entries(alert_id, kinds=("incident.llm_spend",))
        for e in spent:
            b = e["body"]
            total.input_tokens += int(b.get("input_tokens", 0))
            total.output_tokens += int(b.get("output_tokens", 0))
            total.usd += float(b.get("usd", 0.0))
            total.calls += int(b.get("calls", 0))
        settled = {e["body"].get("attempt") for e in spent}
        for e in self.audit.entries(alert_id, kinds=("incident.llm_reserve",)):
            if e["body"].get("attempt") not in settled:
                total.usd += float(e["body"].get("usd", 0.0))
                total.calls += int(e["body"].get("calls", 0))
        return total

    @activity.defn
    def notify(self, pack: EvidencePack, diagnosed: Diagnosed, verified: Verified, mode: str = "") -> list[str]:
        """The incident's report to the configured sinks, through the outbound gate (register S17). Its footer names
        the incident and the head of its audit record - signed first - so a reader can check that a message claiming
        to be WARDEN's is one: its Full record page shows the same hash, its signatures checked. Returns the sinks it
        reached.

        `mode` (one message per incident, G10-46): the whole report is recorded for WARDEN's records page, and Slack
        gets its summary once - "plan": not here, the plan's request for approval carries it; "none": here, with why
        no plan was opened and the record's link. "" (a run begun before): the whole report, as before."""
        import dataclasses

        from .reporting import build_report

        alert_id = pack.alert.alert_id
        self.audit.checkpoint()
        head = self.audit.head(alert_id)
        report = build_report(pack.alert, root_cause=diagnosed.root_cause, proposal=diagnosed.proposal,
                              verdict=verified.verdict, context=pack.context, show_identifiers=False,
                              backend=pack.backend)
        footer = (f"\n\n---\nWARDEN · incident `{alert_id}` · audit head `{audit.short(head)}` · check it on its "
                  "Full record page, which shows the same head with its signatures checked. WARDEN never asks for an "
                  "approval in chat: approvals are signed out of band.")
        # Requirement R38: the changes near the alert, for the people reading it - suspects, never the cause.
        from . import timeline

        changes, unread = timeline.recent(pack.alert, log=self.audit, platform=self.platform)
        changes = timeline.with_evidence(changes, pack.context.logs, pack.alert)
        self.audit.append(alert_id, "incident.changes", {"run_id": _run_id(), "found": len(changes), "unread": unread,
                                                         "sources": sorted({c["source"] for c in changes})})
        # What WARDEN's own record says was done to this resource before (history.py): facts, for the people reading.
        from . import history

        try:
            before = history.past(pack.alert, self.audit)
        except Exception:  # noqa: BLE001 - a record that cannot be read is not a report that cannot be sent
            before = []
        # Before the report's closing line, not after it (owner, 2026-10-12, reading a live message: "things are not
        # right in place" - both sections stood under "WARDEN proposes and gates").
        from .reporting import CLOSING

        body, closed = report.markdown.removesuffix(CLOSING), report.markdown.endswith(CLOSING)
        markdown = (body.rstrip("\n") + "\n" + timeline.section(changes, unread) + history.section(before)
                    + ("\n\n" + CLOSING if closed else "") + footer)
        # An alarm held while its resource was expected down, and still firing when that ended, says so under the
        # title: when it first fired, what held it, and that it is an incident from now (register G10-39's limit).
        held = [e["body"] for e in self.audit.entries(alert_id, kinds=("incident.after_hold",))
                if e["body"].get("firing") is not False]
        if held:
            first = _when_iso(str(held[-1].get("first_fired", "")))
            why = str(held[-1].get("held", "")).split(": looked at again")[0]
            title, _, rest = markdown.partition("\n")
            markdown = (f"{title}\n\n**Held first:** this alarm fired"
                        + (f" at {environments.both_times(first, seconds=False)}" if first else "")
                        + f" while it was {why}; it was still firing when that ended, so it is an incident from "
                        f"{environments.both_times(_when_iso(pack.alert.started_at) or datetime.now(UTC), seconds=False)}."
                        f"\n{rest}")
        # Fixed before and failing again (owner, 2026-10-15): said under the title, so the channel's message carries it.
        said_again = history.again(before)
        if said_again:
            title, _, rest = markdown.partition("\n")
            markdown = f"{title}\n\n{said_again}\n{rest}"
        people = self.policy.people() if self.policy is not None else ()
        if mode:
            from .gate import enforce

            kept = enforce(markdown, alert_id=alert_id)
            withheld = []
            if kept.verdict == "BLOCK":
                from .gate import where_withheld

                # Where and what kind, never the value: a withheld report is diagnosable from its own record.
                withheld = where_withheld(markdown)
                _note(f"{alert_id}: the report was withheld by the outbound gate ({'; '.join(kept.reasons)}) - at "
                      f"{withheld or 'no single line (a value spans lines)'}")
            self.audit.append(alert_id, "incident.report", {"run_id": _run_id(), "markdown": (
                kept.text if kept.verdict != "BLOCK" else "The report was held back by the outbound gate.")[:60000],
                **({"withheld": withheld, "gate_reasons": kept.reasons} if kept.verdict == "BLOCK" else {})})
            if mode == "plan":
                return []
            rows = [e["body"] for e in self.audit.entries(alert_id, kinds=("incident.plan_fix",))
                    if e["body"].get("run_id") == _run_id()]
            why = str(rows[-1].get("why") or "") if rows and not rows[-1].get("planned") else ""
            no = (f"\n\n**No fix plan:** {why[:300]}. There is nothing to approve; nothing changes unless a person acts."
                  if why else "")
            if why:
                # The on-call line was written for a plan to approve; with none, it must not say there is a button
                # (fs-07, live, 2026-10-15: "approve or deny ... with the button in this message" above "No fix plan").
                markdown = markdown.replace(
                    "approve or deny the fix plan with the button in this message - or, where there is none, read why "
                    "here", "no fix plan could be opened (why below): decide what to do; WARDEN runs nothing here")
            markdown = slack_summary(markdown) + no + footer
            report = dataclasses.replace(report, actions=self._record_link(alert_id))
        sent = _send(self.audit, alert_id, dataclasses.replace(report, markdown=markdown, people=people))
        self.audit.append(alert_id, "incident.notify", {"run_id": _run_id(), "head": head,
                                                        "sinks": [n.sink for n in sent],
                                                        "delivered": [n.sink for n in sent if n.delivered],
                                                        "summary": mode == "none"})
        return [n.sink for n in sent if n.delivered]

    @staticmethod
    def _record_link(incident: str) -> tuple[tuple[str, str], ...]:
        from .chatops import ALL_LABEL, RECORD_LABEL

        rp = os.environ.get("WARDEN_APPROVAL_RP_ID", "").strip()
        return ((RECORD_LABEL, f"https://{rp}/r/{incident}"), (ALL_LABEL, f"https://{rp}/r")) if rp else ()

    def _connected(self, alert_id: str, diagnosed: Diagnosed) -> None:
        """An earlier fix of WARDEN's that this diagnosis cites as part of the cause is counted as a failed result of that
        fix, once (owner, 2026-10-15: investigate and link; security review M1: never for an alarm merely starting)."""
        try:
            steps = [e["body"] for e in self.audit.entries(alert_id, kinds=("incident.own_fixes",))]
        except Exception:  # noqa: BLE001 - nothing to link
            return
        cited = {c.id for c in diagnosed.root_cause.citations}
        for fix in (steps[-1].get("fixes") or []) if steps else []:
            if not fix.get("item") or fix["item"] not in cited or fix.get("undo"):
                continue  # an undo cited as the cause is not its fix failing: the fix had held until it was undone
            plan = next((p["body"] for p in self.audit.entries(fix["incident"], kinds=("remediation.plan",))
                         if p["body"].get("workflow_id") == fix["workflow_id"]), None)
            if plan is None or any(r["body"].get("connected_by") == alert_id
                                   for r in self.audit.entries(fix["incident"], kinds=(bounds.RESULT,))):
                continue
            bounds.record_result(self.audit, fix["incident"], service=str(plan.get("target", "")), ok=False,
                                 now=datetime.now(UTC), workflow_id=fix["workflow_id"], connected_by=alert_id)

    @activity.defn
    def verify(self, pack: EvidencePack, diagnosed: Diagnosed) -> Verified:
        from . import graph

        self._connected(pack.alert.alert_id, diagnosed)

        state = {"alert": pack.alert, "context": pack.context, "root_cause": diagnosed.root_cause,
                 "proposal": diagnosed.proposal, "model_unavailable": diagnosed.model_unavailable}
        steps = graph.apply_node(state, graph.node_verify(state))
        route = {"halt": graph.node_halt, "escalate": graph.node_escalate,
                 "await_approval": graph.node_await_approval, "record_safe": graph.node_record_safe}
        steps += graph.apply_node(state, route[graph.route_after_verify(state)](state))
        self._record(pack.alert.alert_id, steps)
        self.audit.checkpoint()
        verdict = state["verdict"]
        _note(f"{pack.alert.alert_id} alarm={pack.alert.labels.get('alarm', '-')} action={diagnosed.proposal.action.value} "
              f"verdict={verdict.status.value} policies={','.join(verdict.policy_ids) or '-'}")
        return Verified(verdict=state["verdict"], halted_reason=state.get("halted_reason"), steps=steps)

    @activity.defn
    def second_opinion(self, pack: EvidencePack, first: Diagnosed, second: Diagnosed, verified: Verified) -> Verified:
        """The first answer's verdict, kept only when a second, independent diagnosis of the same evidence names the
        same action on the same target (owner, 2026-10-15). Otherwise - or when no second answer could be had - the
        fix is escalated under SECOND_OPINION: a person decides, and nothing is offered for approval. Both answers go
        on the record."""
        a, b = first.proposal, second.proposal
        agree = not second.model_unavailable and a.action == b.action and _same_target(a.target, b.target)
        self.audit.append(pack.alert.alert_id, "incident.second_opinion", {
            "run_id": _run_id(), "agree": agree, "first": {"action": a.action.value, "target": a.target},
            "second": ({"action": b.action.value, "target": b.target} if not second.model_unavailable
                       else {"unavailable": str(second.model_unavailable)[:200]})})
        if agree:
            return verified
        why = (f"no second opinion could be had ({str(second.model_unavailable)[:120]})" if second.model_unavailable
               else f"two independent diagnoses disagree: `{a.action.value}` on `{a.target}`, then "
                    f"`{b.action.value}` on `{b.target}`")
        from .models import VerdictStatus

        verdict = verified.verdict.model_copy(update={
            "status": VerdictStatus.escalated, "requires_approval": True,
            "policy_ids": [*verified.verdict.policy_ids, SECOND_OPINION],
            "reasons": [*verified.verdict.reasons, f"{why}: a person decides, and no fix is offered for approval."]})
        _note(f"{pack.alert.alert_id} second opinion: {'unavailable' if second.model_unavailable else 'differs'} - "
              "escalated")
        return verified.model_copy(update={"verdict": verdict})


# The policy a disagreement of two independent diagnoses escalates under (IncidentActivities.second_opinion).
SECOND_OPINION = "P32-SECOND-OPINION-DIFFERS"


def _same_target(a: str, b: str) -> bool:
    return " ".join(str(a).lower().split()) == " ".join(str(b).lower().split())


class DiscussActivities:
    """The steps of a discussion of an incident in Slack (discuss.py), each in the zone that holds what it needs: the
    thread is read and the reply posted in notify (the bot's token), the evidence is read in read (the reader roles),
    the answer is the model's in llm (the model's key). Every step leaves a row on the incident's discussion record."""

    def __init__(self, *, audit: AuditLog, incident: IncidentActivities, policy: Any = None) -> None:
        self.audit, self.incident, self.policy = audit, incident, policy

    @activity.defn
    def discuss_thread(self, turn: Any) -> Any:
        """The thread the mention is in, as people wrote it - its first message and the latest ones, the mention itself
        always among them - and the incident it is about. Past today's limit for that incident, `over` says so before
        anything is read for it."""
        from . import chatops
        from .discuss import DAILY_CALLS, MAX_MESSAGES, Thread, Turn, incident_in

        turn = Turn.model_validate(turn)
        token = os.environ.get("WARDEN_SLACK_BOT_TOKEN", "").strip()
        got = me = None
        if token:
            got, _ = chatops._slack_call("conversations.replies", {"channel": turn.channel, "ts": turn.thread_ts,
                                                                   "limit": 200}, token, form=True)
            me, _ = chatops._slack_call("auth.test", {}, token, form=True)
        messages = [m for m in (got or {}).get("messages") or [] if isinstance(m, dict)]
        # A thread comes back oldest first, and some installs get only its first 15: the mention is always kept.
        if turn.ts not in {str(m.get("ts")) for m in messages}:
            messages.append({"user": turn.user, "text": turn.text, "ts": turn.ts})
        kept = messages[:1] + messages[1:][-(MAX_MESSAGES - 1):]
        bot = (me or {}).get("user_id")  # WARDEN's own replies by its id - another app's words never pass as WARDEN's

        def who(m: dict[str, Any]) -> str:
            return "WARDEN" if bot and m.get("user") == bot else "an app" if m.get("bot_id") else "a person"

        lines = [f"{who(m)}: {' '.join(str(m.get('text', '')).split())[:800]}" for m in kept]
        incident = incident_in(turn.text, *(str(m.get("text", "")) for m in kept))
        key = f"discuss-{incident or 'unknown'}"
        # An environment's channel discusses only its own incidents (WARDEN_DISCUSS_CHANNELS): another's, or one with no
        # environment on the record, is refused here, before anything of it is read - every later step reads only
        # the incident this returns.
        elsewhere = bool(incident and turn.environment and _environment_of(self.audit, incident) != turn.environment)
        self.audit.append(key, "discuss.turn", {
            "run_id": _run_id(), "channel": turn.channel, "thread_ts": turn.thread_ts, "ts": turn.ts,
            "user": turn.user, "incident": incident, "chars": len(turn.text), "environment": turn.environment,
            "refused": "another environment's incident" if elsewhere else ""})
        if elsewhere:
            return Thread(incident="", elsewhere=True)
        turns = len(self.audit.entries(key, kinds=("discuss.turn",), since=datetime.now(UTC) - timedelta(hours=24)))
        approver = bool(self.policy) and any(a.slack == turn.user for a in self.policy.approvers.values())
        return Thread(incident=incident, lines=lines, over=bool(incident) and turns > DAILY_CALLS, approver=approver)

    @activity.defn
    def discuss_replan(self, turn: Any, incident: str) -> dict[str, Any]:
        """An approver's "new plan": the incident's alarm as on the record, as a new incident from now - or why not.
        Nothing a person wrote goes into it. Recorded either way."""
        from .discuss import REPLAN_EVERY, Turn

        turn = Turn.model_validate(turn)
        key = f"discuss-{incident}"
        rows = self.audit.entries(incident, kinds=("incident.alert",))
        approver = bool(self.policy) and any(a.slack == turn.user for a in self.policy.approvers.values())
        recent = self.audit.entries(key, kinds=("discuss.replan",),
                                    since=datetime.now(UTC) - timedelta(seconds=REPLAN_EVERY))
        why = ("not an approver" if not approver else "no alarm on the record" if not rows
               else "asked again within the hour" if any(e["body"].get("started") for e in recent) else "")
        now = datetime.now(UTC)
        new = f"{incident.split('-')[0]}-{now:%Y%m%dT%H%M%SZ}"
        self.audit.append(key, "discuss.replan", {"run_id": _run_id(), "user": turn.user, "ts": turn.ts,
                                                  "started": "" if why else new, "why": why})
        if why:
            return {"why": why}
        alert = Alert.model_validate(rows[0]["body"]["alert"]).model_copy(
            update={"alert_id": new, "started_at": now.isoformat()})
        return {"alert": alert.model_dump(mode="json"), "new": new}

    @activity.defn
    def discuss_evidence(self, incident: str, fresh: bool) -> Any:
        """The incident's evidence read again, as the diagnosis read it - or around now, when the question is about now
        - with WARDEN's record of what it decided. None: no alarm on the record by that id."""
        rows = self.audit.entries(incident, kinds=("incident.alert",))
        if not rows:
            return None
        kept = [e["body"] for e in self.audit.entries(incident, kinds=("incident.evidence",))]
        good = [b for b in kept if hashlib.sha256(str(b.get("prompt", "")).encode("utf-8")).hexdigest() == b.get("sha256")]
        if fresh or not good:  # about now, or an incident from before its evidence was kept: read it again
            alert = Alert.model_validate(rows[0]["body"]["alert"]).model_copy(update={"alert_id": f"discuss-{incident}"})
            if fresh:
                alert = alert.model_copy(update={"started_at": datetime.now(UTC).isoformat()})
            prompt = self.incident.prepare(alert).prompt
        else:
            prompt = str(good[-1]["prompt"])
        said = [f"{e['kind'].split('.')[-1]}: " + ", ".join(f"{k}={str(v)[:300]}" for k, v in e["body"].items()
                                                            if k in ("hypothesis", "action", "target", "confidence",
                                                                     "status", "policies"))
                for e in self.audit.entries(incident, kinds=("incident.diagnose", "incident.verify"))]
        # And what WARDEN's record says of the incidents like it (history.similar): the model compares with them and
        # says what to do now - facts, never a past diagnosis's prose.
        from . import history

        try:
            seen = history.similar_text(history.similar(self.audit, incident))
        except Exception:  # noqa: BLE001 - the answer goes ahead on this incident's own record
            seen = ""
        return {"evidence": prompt, "diagnosis": ("\n".join(said)[-3000:] + ("\n\n" + seen[:3000] if seen else ""))}

    @activity.defn
    def discuss_facts(self, incident: str) -> str:
        """WARDEN's record of the incident and of the incidents like it - what was done, how it ended, whether it held,
        the pattern - posted in the thread at once, before the model's answer (owner, 2026-10-15: "the responses from
        WARDEN in discussions should be immediate ... within 1 or 2 seconds"). No model: facts from the signed record."""
        from . import history

        rp = os.environ.get("WARDEN_APPROVAL_RP_ID", "").strip()
        return history.similar_text(history.similar(self.audit, incident,
                                                    link=(lambda i: f"https://{rp}/r/{i}") if rp else None))

    @activity.defn
    def discuss_answer(self, turn: Any, thread: Any, evidence: dict[str, str], fresh: bool) -> str:
        """The model's answer to the mention, as the reply to post. Capped per incident per day and by the daily cap
        every incident shares; the people's words are data to it (discuss.SYSTEM)."""
        from . import discuss
        from .llm import LLMClient

        turn, thread = discuss.Turn.model_validate(turn), discuss.Thread.model_validate(thread)
        key = f"discuss-{thread.incident}"
        approver = thread.approver
        since = datetime.now(UTC) - timedelta(hours=24)
        calls = sum(int(e["body"].get("calls", 0)) for e in self.audit.entries(key, kinds=("incident.llm_spend",),
                                                                                since=since))
        today = self.incident._spent_since(since)
        if calls >= discuss.DAILY_CALLS or today.usd >= DAILY_MAX_USD:
            return discuss.LIMIT
        llm = (self.incident.llm_factory or LLMClient)()
        attempt = secrets.token_hex(8)
        self.audit.append(key, "incident.llm_reserve", {"run_id": _run_id(), "attempt": attempt, "usd": llm.max_usd,
                                                        "calls": 1})
        before = llm.cost.model_copy()
        answer = None
        try:
            answer = llm.structured(system=discuss.SYSTEM, schema=discuss.Answer,
                                    user=discuss.prompt(turn.text, thread, evidence.get("evidence", ""),
                                                        evidence.get("diagnosis", ""), approver=approver),
                                    mock_factory=lambda: discuss.Answer(answer="(a test answer)", cites=[]))
        except Exception as exc:  # noqa: BLE001 - whatever stopped the model, the person is told, never left waiting
            _note(f"discuss {thread.incident}: no answer from the model ({type(exc).__name__})")
        finally:
            now, unanswered = llm.cost, int(getattr(llm, "unanswered", 0) or 0)
            self.audit.append(key, "incident.llm_spend", {
                "run_id": _run_id(), "attempt": attempt, "usd": now.usd - before.usd,
                "calls": now.calls - before.calls - unanswered, "unanswered": unanswered,
                "input_tokens": now.input_tokens - before.input_tokens,
                "output_tokens": now.output_tokens - before.output_tokens})
        if answer is None:
            return discuss.NO_ANSWER
        self.audit.append(key, "discuss.answer", {"run_id": _run_id(), "ts": turn.ts, "cites": answer.cites[:20],
                                                  "asks_for_change": answer.asks_for_change, "approver": approver})
        return discuss.said(answer, approver=approver, fresh=fresh)

    @activity.defn
    def discuss_reply(self, turn: Any, text: str, incident: str) -> bool:
        """The reply, posted in the thread through the outbound gate and the redactor, like every message WARDEN sends."""
        from .chatops import SlackThreadSink, notify
        from .discuss import Turn
        from .reporting import Report

        turn = Turn.model_validate(turn)
        token = os.environ.get("WARDEN_SLACK_BOT_TOKEN", "").strip()
        if not token:
            return False
        sink = SlackThreadSink(token, turn.channel, turn.thread_ts, live=os.environ.get("WARDEN_CHATOPS_LIVE") == "1")
        [sent] = notify(Report(markdown=text, data={"alert": {"id": incident or "discussion"}}, promotion=()),
                        sinks=[sink])
        self.audit.append(f"discuss-{incident or 'unknown'}", "discuss.reply", {
            "run_id": _run_id(), "ts": turn.ts, "delivered": sent.delivered, "detail": sent.detail[:200]})
        return sent.delivered
