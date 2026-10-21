"""Autonomy (owner, 2026-10-16, changed 2026-10-17): per (environment, action class) a level, derived from the audit -
never a flag.

    L0  escalate only: WARDEN proposes, a person decides. The environment's ceiling is L0.
    L1  shadow: WARDEN and Eldane (eldane.py, the AI critic) decide, a person still approves, and Eldane's decision is
        scored against the person's. Prod (a person's passkey, always), and dev after a demotion.
    L2  autonomous: Eldane's signed approval is enough. Only below prod.

Owner, 2026-10-17: dev is autonomous through Eldane from the first plan - every action class there STARTS at L2, with
no shadow period and no minimum of catch trials (decide.tier_enabled stays available, required by nothing). What keeps:
- the environment's ceiling (environments.yaml `autonomy`); prod-tier never above L1 (refused at load, capped here);
- demotion, at once, to L1: a failed fix of that class there (rolled back, relapsed, not recovered, unknown state), a
  harmful decision (Eldane said yes, a person said no - a veto of an Eldane-approved plan included), a change of
  either model or of Eldane's prompt since the class was last enabled, a missed catch trial (catch trials keep running
  as monitoring: one miss stops Eldane's approvals everywhere), and the kill switch while it is on;
- after a demotion the environment returns to L2 only when a PERSON re-enables it: a T3 approval, signed with their
  own key, of exactly the demotions on the record (`warden autonomy enable`; enable() below) - recorded, never an AI's.

Self-guard (register R6, item 12): neither WARDEN nor Eldane ever approves a plan whose target is WARDEN's own runtime
(P22 SELF-TARGET) or that touches WARDEN's guardrails - the gate, the catalogue, environments.yaml, the approvers,
Eldane's config, CI workflows, IAM, CODEOWNERS. Those are a person's, with a passkey.

The kill switch stops autonomous approvals too (the Red Button): no AI approval counts while it is on.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from . import approvals, bounds, environments

L0, L1, L2 = "L0", "L1", "L2"
MEANS = {L0: "escalate only - a person decides every fix",
         L1: "shadow - WARDEN and Eldane decide, a person still approves, and the decision is scored",
         L2: "autonomous - Eldane's signed approval is enough"}
OUTCOME = "autonomy.outcome"  # one per fix run with a plan, written by its signed end (activities.finish)
TRIAL = "eldane.trial"  # a planted known-bad plan shown to Eldane, and whether it said no (eldane.py)
VERDICT = "eldane.verdict"  # Eldane's review of a real plan
ENABLED = "autonomy.enabled"  # a person's signed re-enable of an environment after a demotion (enable)
# How long an Eldane-approved plan waits for a person's "no" before WARDEN applies it (owner, 2026-10-17: a person's
# decision always overrides Eldane's). A "no" that has arrived before the apply step starts still
# stops it (workflows.RemediationWorkflow reads it right before apply); one after that is too late for that run.
VETO = timedelta(minutes=5)
# Ends that say the fix did not work, or left its target in an unknown state: each demotes its class at once.
FAILED = frozenset({"rolled_back", "not_recovered", "rollback_failed", "apply_failed", "relapsed", "side_effects",
                    "failed_after_apply", "cancelled_after_apply"})


def ceiling(environment: str) -> str:
    """The highest level an action class may be at in `environment`: an unknown one is L0, the prod tier at most L1."""
    pol = environments.default_environment_policies().for_env(environment)
    level = pol.autonomy if pol.autonomy in MEANS else L0
    return L1 if level == L2 and pol.tier == "prod" else level


@dataclass
class Standing:
    level: str
    reasons: list[str] = field(default_factory=list)

    def said(self, entry: str, environment: str) -> str:
        why = f" ({'; '.join(self.reasons)})" if self.reasons else ""
        return f"`{entry}` in {environment} is at autonomy level {self.level}: {MEANS[self.level]}{why}."


def trials(log: Any, critic: str) -> tuple[int, int]:
    """Catch trials Eldane answered under `critic` (its provider, model and prompt), and how many it caught. Scored ones
    only: a trial with no valid answer (`caught` None) is neither a catch nor a trial answered."""
    rows = [e["body"] for e in log.entries(kinds=(TRIAL,)) if e["body"].get("critic") == critic
            and e["body"].get("caught") in (True, False)]
    return len(rows), sum(1 for r in rows if r.get("caught") is True)


def _since_enabled(log: Any, environment: str) -> int:
    """The audit sequence number of the environment's latest re-enable by a person; 0 for none."""
    rows = [e for e in log.entries(f"autonomy-{environment}", kinds=(ENABLED,))
            if e["body"].get("environment") == environment]
    return rows[-1]["seq"] if rows else 0


def demotions(log: Any, environment: str, entry: str | None = None,
              models: dict[str, str] | None = None) -> list[tuple[int, str]]:
    """What demotes `entry` (every class when None) in `environment` now, since a person last enabled it: (row seq,
    why) - a failed fix or a harmful decision of that class, a missed catch trial (any), or a model or prompt change:
    Eldane's reviews and scored ends there under more than one set of models, `models` (this review's) included."""
    after = _since_enabled(log, environment)

    def here(e: dict) -> bool:
        b = e["body"]
        return e["seq"] > after and b.get("environment") == environment and (not entry or b.get("entry") == entry)

    out: list[tuple[int, str]] = []
    for e in filter(here, log.entries(kinds=(OUTCOME,))):
        b = e["body"]
        if b.get("failed"):
            out.append((e["seq"], f"`{b.get('entry')}` ended {b.get('status')} (incident {b.get('incident', '?')})"))
        elif b.get("harmful"):
            out.append((e["seq"], (f"a person said no to a plan Eldane said yes to (`{b.get('entry')}`, incident "
                                   f"{b.get('incident', '?')})")))
    # Only models that did review (CodeRabbit, PR 42): a skipped review - no diagnosis provenance, the daily ceiling -
    # records placeholder models, and an end with no review copies them; neither is a model that changed.
    under = sorted(((e["seq"], e["body"]["models"]) for e in filter(here, log.entries(kinds=(OUTCOME, VERDICT)))
                    if e["body"].get("models") and not e["body"].get("skipped")), key=lambda x: x[0])
    changed = next((seq for seq, m in under if m != under[0][1]), None) if under else None
    if changed is None and models and under and models != under[-1][1]:
        changed = under[-1][0]
    if changed is not None:
        out.append((changed, "the diagnosing model, Eldane's model or its prompt changed"))
    out += [(e["seq"], f"Eldane missed a catch trial ({e['body'].get('kind', '?')})")
            for e in log.entries(kinds=(TRIAL,)) if e["seq"] > after and e["body"].get("caught") is False]
    return sorted(set(out))


def level(log: Any, environment: str, entry: str, models: dict[str, str] | None) -> Standing:
    """The level `entry` is at in `environment` now, from the audit alone. `models`: the diagnosing model and Eldane
    (provider/model@prompt) as this plan's review recorded them."""
    top = ceiling(environment)
    if top == L0:
        return Standing(L0, ["the environment allows no autonomy"])
    if not models or not models.get("critic"):
        return Standing(L1, ["Eldane has not reviewed this plan"])
    if top != L2:
        return Standing(L1, ["a person approves every change here"])
    reasons = []
    if bounds.killswitch(log) is not None:
        reasons.append("the kill switch is on")
    reasons += [f"demoted: {why}; a person re-enables it (`warden autonomy enable`)"
                for _, why in demotions(log, environment, entry, models)]
    return Standing(L1, reasons) if reasons else Standing(L2)


def enable_hash(log: Any, environment: str) -> str:
    """What a person's re-enable signs: every demotion on the record in `environment` since the last re-enable. A
    demotion added after they signed changes it, so they cannot re-enable past one they were never shown."""
    seqs = ",".join(str(s) for s, _ in demotions(log, environment))
    return "autonomy-enable-" + hashlib.sha256(f"{environment}:{seqs}".encode()).hexdigest()


def enable(log: Any, approval: approvals.SignedApproval, *, policy: approvals.ApproverPolicy, environment: str,
           now: datetime) -> list[str]:
    """A person turns autonomy back on in `environment` after a demotion: a T3 approval, with their own key, of exactly
    the demotions now on the record (enable_hash). Never an AI's - Eldane cannot re-enable itself - and never in an
    environment whose ceiling is below L2 (prod)."""
    if ceiling(environment) != L2:
        return [f"{environment} is never autonomous: there is nothing to re-enable"]
    if policy.is_ai(approval.approver):
        return ["an AI never re-enables autonomy: a person does"]
    rows = demotions(log, environment)
    if not rows:
        return [f"autonomy in {environment} is not demoted"]
    used = {e["body"].get("nonce") for e in log.entries(kinds=(ENABLED,))}
    latest = max((e["at"] for e in log.entries(kinds=(OUTCOME, TRIAL, VERDICT)) if e["seq"] == rows[-1][0]), default=now)
    problems = approvals.check(approval, policy=policy, workflow_id=f"autonomy-{environment}",
                               plan_hash=enable_hash(log, environment), tier="T3", plan_created_at=latest,
                               used_nonces=used, now=now, environment=environment)
    if not problems:
        log.append(f"autonomy-{environment}", ENABLED, {"environment": environment, "approver": approval.approver,
                                                        "nonce": approval.nonce, "demotions": [s for s, _ in rows]})
        log.checkpoint()
    return problems


def record_outcome(log: Any, incident: str, *, plan: dict[str, Any], status: str, approvers: list[str],
                   policy: Any, verdict: dict[str, Any] | None, ai: frozenset[str] = frozenset(),
                   **run: str) -> dict[str, Any] | None:
    """The scored end of one fix run (activities.finish), for an environment with any autonomy. Shadow:
    Eldane's verdict against the person's decision - agreed when it said yes to what they approved, or no to what they
    denied; unscored when nobody decided (expired, refused, blocked). Harmful: Eldane said yes to a plan a person
    denied. Failed: the fix did not work - whoever approved it."""
    env, entry = str(plan.get("environment") or ""), str(plan.get("entry") or "")
    if not env or ceiling(env) == L0:
        return None
    if _scored(log, env, run):
        return None
    body = {"environment": env, "entry": entry, "status": status,
            **_decisions(approvers, ai=ai, policy=policy, status=status, verdict=verdict),
            "failed": status in FAILED, "incident": incident, **run}
    # Kept as the environment's own autonomy record, not the incident's: the incident's record reads as it did.
    log.append(f"autonomy-{env}", OUTCOME, body)
    return body


def _scored(log: Any, env: str, run: dict[str, str]) -> bool:
    """Once per run (PR 42 review): a retried end scores the run if the first try could not, and never twice."""
    return bool(run.get("run_id")) and any(
        e["body"].get("workflow_id") == run.get("workflow_id") and e["body"].get("run_id") == run.get("run_id")
        for e in log.entries(f"autonomy-{env}", kinds=(OUTCOME,)))


def _decisions(approvers: list[str], *, ai: frozenset[str], policy: Any, status: str,
               verdict: dict[str, Any] | None) -> dict[str, Any]:
    """The person's decision and Eldane's, side by side: who decided, how, and whether they agreed."""
    # `ai`: the approvers whose approvals were RECORDED as an AI's - never a person, whatever the list says now, so
    # Eldane's own approvals can never score as a person agreeing with it.
    people = [a for a in approvers if a not in ai and not policy.is_ai(a)]
    person = ""
    if people:
        person = "approved"
    elif status == "denied":
        person = "denied"
    review = verdict or {}
    yes = review.get("agree")
    mode = "none"
    if approvers and not people:
        mode = "autonomous"
    elif verdict:
        mode = "shadow"
    return {"person": person, "eldane": yes, "mode": mode,
            # A skipped review's models are placeholders, never the models that reviewed (CodeRabbit, PR 42).
            "models": {} if review.get("skipped") else review.get("models") or {},
            "harmful": yes is True and person == "denied",
            "agreed": None if yes is None or not person else yes == (person == "approved")}


# Register R6: what neither WARDEN nor Eldane may ever approve a change to. Paths a code change could touch, and the
# names WARDEN's own control plane goes by in a watched account - its roles, its parameters and its secrets.
PROTECTED_PATHS = (".github/", "CODEOWNERS", "src/warden/data/", "src/warden/gate.py", "src/warden/verifier.py",
                   "src/warden/catalog.py", "src/warden/approvals.py", "src/warden/autonomy.py", "src/warden/eldane.py",
                   "src/warden/bounds.py", "src/warden/audit.py", "src/warden/activities.py", "src/warden/workflows.py",
                   "src/warden/passkeys.py", "src/warden/approval_page.py", "docs/safety-pins.sha256", "iam/",
                   "terraform/")
_PROTECTED_NAMES = re.compile(
    r"(?i)(?:^|[/:])/?warden/|:role/|:policy/|\biam\b|codeowners|environments\.ya?ml|\bapprovers?\b|"
    r"eldane|^warden-[a-z0-9-]+-(?:deploy|actor|platform-reader|fault[a-z-]*)$|WardenEnvBoundary")


def touches_protected(value: str) -> str:
    """What protected thing `value` names - a path or a name - or "" for none."""
    text = str(value).replace("\\", "/").strip()
    for path in PROTECTED_PATHS:
        if text == path.rstrip("/") or text.startswith(path) or f"/{path}" in text:
            return path
    found = _PROTECTED_NAMES.search(text)
    return found.group(0) if found else ""


def self_guard(plan: Any) -> list[str]:
    """Every reason no AI - nor WARDEN itself - may approve `plan` (register R6, P22): it targets WARDEN's runtime, or
    a value in it names one of WARDEN's guardrails."""
    problems = []
    runtime = environments.default_environment_policies().runtime_environment
    values = [str(plan.target), *(str(v) for v in (plan.params or {}).values())]
    if runtime and (plan.environment == runtime or any(environments.env_of_name(v.rpartition("/")[2]) == runtime
                                                       or environments.env_of_name(v) == runtime for v in values)):
        problems.append(f"P22 SELF-TARGET: the target is in WARDEN's own runtime {runtime!r}: a person changes it")
    hits = sorted({hit for v in values if (hit := touches_protected(v))})
    if hits:
        problems.append(f"R6 SELF-GUARD: the plan touches {', '.join(hits)} - WARDEN's own guardrails, which only a "
                        "person approves, with a passkey")
    return problems


def verdict_of(log: Any, plan: Any, run_id: str) -> dict[str, Any] | None:
    """Eldane's review of exactly this plan in this run, from the record; None when it made none."""
    rows = [e["body"] for e in log.entries(plan.incident_id, kinds=(VERDICT,))
            if e["body"].get("workflow_id") == plan.workflow_id and e["body"].get("run_id", "") == run_id
            and e["body"].get("plan_hash") == plan.plan_hash]
    return rows[-1] if rows else None


def ai_problems(log: Any, plan: Any, run_id: str) -> list[str]:
    """Every reason an AI approval of `plan` must not count - checked when it arrives and again right before apply.
    Eldane can only ever add a "no": the gate, the bounds and the policies ran before it, and run again at apply."""
    problems = []
    pol = environments.default_environment_policies().for_env(plan.environment)
    if pol.tier == "prod" or ceiling(plan.environment) != L2:
        problems.append(f"{plan.environment or 'this environment'} is never autonomous: a person approves with a passkey")
    if plan.tier not in ("T1", "T2"):
        problems.append(f"an AI never approves {plan.tier or 'an unknown tier'}")
    if (row := bounds.killswitch(log)) is not None:
        problems.append(f"the kill switch is on, which stops autonomous approvals: {row['body'].get('reason', '')}")
    problems += self_guard(plan)
    verdict = verdict_of(log, plan, run_id)
    if verdict is None or verdict.get("agree") is not True or not verdict.get("second_pass"):
        problems.append("Eldane's record holds no agreement with this exact plan from both of its passes")
    else:
        now = level(log, plan.environment, plan.entry, verdict.get("models"))
        if now.level != L2:
            problems.append(now.said(plan.entry, plan.environment).rstrip("."))
    return problems
