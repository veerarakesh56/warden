"""The remediation report — the artifact a human uses to promote a fix to the higher environments.

The owner's flow: WARDEN auto-resolves in staging/qa-staging, then produces a report so whoever has
access to prod can apply the same fix there. This module builds that report from the pieces of one
run and renders it two ways — Markdown (for a human / ChatOps) and a JSON dict (for machines).

Two things this module guarantees:
  1. Everything it emits is REDACTED. The report is the thing that leaves the building (to Slack,
     Teams, a ticket), so it runs through `redact()` before it is handed back. A report is the last
     place a raw secret should be allowed to surface.
  2. The PROMOTION PLAN is derived from the environment policy, not guessed: it lists exactly the
     higher-tier environments where the same action is permitted, and what each one requires
     (a human approval, an authorised principal), so nobody has to re-derive the rules by hand.
"""

from __future__ import annotations

from dataclasses import dataclass

from .environments import EnvironmentPolicies, default_environment_policies
from .knowledge import SignatureMatch
from .models import Alert, RemediationProposal, RootCause, Verdict
from .redaction import redact
from .remediation import RemediationResult

# Tier ordering for "what is higher than here". Unknown is off the ladder (never a promotion target).
_TIER_RANK = {"nonprod": 0, "preprod": 1, "prod": 2}


@dataclass(frozen=True)
class PromotionTarget:
    environment: str
    tier: str
    requires_human_approval: bool
    auto_remediates: bool
    note: str
    credentials_ref: str | None = None


@dataclass(frozen=True)
class Report:
    """A built report. `markdown` and `data` are both already redacted."""

    markdown: str
    data: dict
    promotion: tuple[PromotionTarget, ...]


def _promotion_targets(
    alert: Alert, proposal: RemediationProposal, policies: EnvironmentPolicies
) -> list[PromotionTarget]:
    """Higher-tier environments where this same action is permitted — the places to replay the fix."""
    here = policies.for_env(alert.environment)
    here_rank = _TIER_RANK.get(here.tier, -1)
    targets: list[PromotionTarget] = []
    for name in policies.known_environments:
        p = policies.for_env(name)
        rank = _TIER_RANK.get(p.tier, -1)
        if rank <= here_rank or rank < 0:
            continue
        if not p.permits(proposal.action):
            continue  # the action isn't allowed there at all — not a promotion target
        note = (
            "WARDEN can auto-apply after approval"
            if p.auto_remediate
            else "a human applies this fix"
        )
        targets.append(
            PromotionTarget(
                environment=name,
                tier=p.tier,
                requires_human_approval=p.require_human_approval,
                auto_remediates=p.auto_remediate,
                note=note,
                credentials_ref=p.credentials_ref,
            )
        )
    targets.sort(key=lambda t: (_TIER_RANK.get(t.tier, 99), t.environment))
    return targets


def build_report(
    alert: Alert,
    *,
    root_cause: RootCause | None = None,
    proposal: RemediationProposal | None = None,
    verdict: Verdict | None = None,
    remediation: RemediationResult | None = None,
    signatures: list[SignatureMatch] | None = None,
    policies: EnvironmentPolicies | None = None,
) -> Report:
    """Assemble a redacted remediation report from one run."""
    pol = policies or default_environment_policies()
    signatures = signatures or []

    promotion = _promotion_targets(alert, proposal, pol) if proposal else []

    # ---- structured data (redacted field-by-field where it carries free text) ----
    data: dict = {
        "alert": {
            "id": alert.alert_id,
            "name": alert.name,
            "severity": alert.severity.value,
            "service": alert.service,
            "environment": alert.environment,
            "summary": redact(alert.summary).text,
        },
        "matched_signatures": [
            {"id": m.signature.id, "title": m.signature.title, "score": m.score,
             "category": m.signature.category, "maturity": m.signature.maturity}
            for m in signatures
        ],
        "root_cause": None,
        "proposal": None,
        "verdict": None,
        "remediation": None,
        "promotion": [
            {"environment": t.environment, "tier": t.tier,
             "requires_human_approval": t.requires_human_approval,
             "auto_remediates": t.auto_remediates, "note": t.note,
             "credentials_ref": t.credentials_ref}
            for t in promotion
        ],
    }
    if root_cause:
        data["root_cause"] = {
            "hypothesis": redact(root_cause.hypothesis).text,
            "confidence": root_cause.confidence,
        }
    if proposal:
        data["proposal"] = {
            "action": proposal.action.value,
            "target": redact(proposal.target).text,
            "blast_radius": proposal.blast_radius,
            "reversible": proposal.reversible,
            "expected_effect": redact(proposal.expected_effect).text,
        }
    if verdict:
        data["verdict"] = {
            "status": verdict.status.value,
            "policy_ids": verdict.policy_ids,
            "reasons": [redact(r).text for r in verdict.reasons],
        }
    if remediation:
        data["remediation"] = {
            "outcome": remediation.outcome.value,
            "detail": redact(remediation.detail).text,
            "applied_change": redact(remediation.applied_change).text if remediation.applied_change else None,
            "principal": remediation.principal,
        }

    markdown = _render_markdown(data)
    # Final belt-and-braces sweep: redact the whole rendered document, so nothing assembled from a
    # field we forgot to scrub can leave. redact() is idempotent over already-masked placeholders.
    markdown = redact(markdown).text
    return Report(markdown=markdown, data=data, promotion=tuple(promotion))


def _render_markdown(d: dict) -> str:
    a = d["alert"]
    lines: list[str] = []
    lines.append(f"# WARDEN incident report - {a['id']} - {a['name']}")
    lines.append("")
    lines.append(f"- **Service**: {a['service']}")
    lines.append(f"- **Environment**: {a['environment']}")
    lines.append(f"- **Severity**: {a['severity']}")
    lines.append(f"- **Summary**: {a['summary']}")
    lines.append("")

    if d["matched_signatures"]:
        lines.append("## Known patterns that fit the evidence")
        for s in d["matched_signatures"]:
            lines.append(f"- `{s['id']}` **{s['title']}** ({s['category']}/{s['maturity']}, score {s['score']})")
        lines.append("")

    if d["root_cause"]:
        rc = d["root_cause"]
        lines.append("## Hypothesis")
        lines.append(f"{rc['hypothesis']}  \n_confidence {rc['confidence']:.2f}_")
        lines.append("")

    if d["proposal"]:
        p = d["proposal"]
        lines.append("## Proposed action")
        lines.append(f"- **Action**: `{p['action']}` -> `{p['target']}`")
        lines.append(f"- **Blast radius**: {p['blast_radius']} - reversible: {p['reversible']}")
        lines.append(f"- **Expected effect**: {p['expected_effect']}")
        lines.append("")

    if d["verdict"]:
        v = d["verdict"]
        lines.append("## Verdict (deterministic gate)")
        lines.append(f"- **Status**: `{v['status']}`")
        if v["policy_ids"]:
            lines.append(f"- **Policies fired**: {', '.join(v['policy_ids'])}")
        for r in v["reasons"]:
            lines.append(f"  - {r}")
        lines.append("")

    if d["remediation"]:
        r = d["remediation"]
        lines.append("## Remediation")
        lines.append(f"- **Outcome**: `{r['outcome']}`")
        lines.append(f"- {r['detail']}")
        if r["applied_change"]:
            lines.append(f"- {r['applied_change']}")
        lines.append("")

    lines.append("## Promotion - apply this fix to the higher environments")
    if d["promotion"]:
        for t in d["promotion"]:
            approval = "human approval required" if t["requires_human_approval"] else "no separate approval"
            creds = f" - account `{t['credentials_ref']}`" if t.get("credentials_ref") else ""
            lines.append(f"- **{t['environment']}** ({t['tier']}): {t['note']} - {approval}{creds}")
    else:
        lines.append("- _No higher environment permits this action; nothing to promote._")
    lines.append("")
    lines.append("---")
    lines.append("_WARDEN proposes and gates. Nothing was executed against production by this tool._")
    return "\n".join(lines)
