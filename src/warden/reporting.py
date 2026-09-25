"""The remediation report — the artifact a human uses to act on an incident and promote the fix.

The owner's flow: WARDEN auto-resolves in staging/qa-staging, then produces a report so whoever has
access to prod can apply the same fix there. This module builds that report from the pieces of one
run and renders it two ways — Markdown (for a human / ChatOps) and a JSON dict (for machines).

What the report must let the reader do WITHOUT opening another tool: see what WARDEN actually read
(metrics, the log lines that matter, deploys, what it could NOT read), who and what is affected
(pods, PIDs, hosts, tenants, users), when things happened, and the exact commands to check, fix,
confirm and undo. A report that carries only the model's conclusion asks the reader to trust it;
one that carries the evidence lets them check it. (Until 2026-09-24 it carried only the conclusion:
the model's own cited evidence, the whole evidence bundle and every identifier were dropped.)

Three things this module guarantees:
  1. Everything it emits is REDACTED, with ONE mapping across the whole report so the same tenant
     is the same placeholder everywhere. The report is the thing that leaves the building (to
     Slack, Teams, a ticket).
  2. IDENTIFIERS CAN BE SHOWN TO THE HUMAN, SECRETS NEVER. With WARDEN_REPORT_SHOW_IDENTIFIERS=true
     an operator's own channel gets real tenant ids, user emails and IP addresses back - the things
     you search logs for. Passwords, keys, tokens, JWTs, connection-string credentials, card
     numbers, UUIDs (which is also the shape of many API keys) and AWS account ids stay masked
     regardless. Off by default: turning a redacting tool into one that posts customer
     identifiers to a third party is a decision for whoever owns that channel.
  3. The PROMOTION PLAN is derived from the environment policy, not guessed, and the RUNBOOK from a
     fixed table (runbook.py) - the model never writes a command a human will paste.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import os
import re
from collections import Counter
from dataclasses import dataclass

from .environments import EnvironmentPolicies, default_environment_policies
from .knowledge import SignatureMatch
from .models import Alert, ContextBundle, RemediationProposal, RootCause, Verdict
from .playbook import detect as detect_patterns
from .redaction import redact
from .remediation import RemediationResult
from .runbook import build_runbook
from .verifier import symptoms

# Tier ordering for "what is higher than here". Unknown is off the ladder (never a promotion target).
_TIER_RANK = {"nonprod": 0, "preprod": 1, "prod": 2}

# Placeholder labels (redaction.py) an operator may see in their own channel. Everything else -
# SECRET, APIKEY, JWT, URLCRED, ARN, ACCOUNTID, UUID, CREDITCARD, IBAN, PHONE, ... - stays masked.
REVEALABLE = frozenset({"EMAIL", "TENANT", "IPV4", "IPV6"})

_KEY_LINES = 10
_LINE_MAX = 220
_IMPORTANT = re.compile(
    r"(?i)\b(error|exception|fatal|panic|fail(ed|ure)?|oom\w*|killed|timeout|timed out|refused|denied|"
    r"unavailable|back-?off|crash\w*|idle in transaction|exhausted|could not|unable|forbidden|evicted)\b"
)
_TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?")
# key=value identifiers worth listing as "affected". Order is the order they are shown in.
_AFFECTED_KEYS = ("tenant_id", "org_id", "organization_id", "customer_id", "user", "user_id",
                  "src", "client", "host", "db", "node", "trace", "trace_id", "request_id")
_KV = re.compile(r"\b(" + "|".join(_AFFECTED_KEYS) + r")=([^\s,;\"']+)")
_PID = re.compile(r"(?i)\bpid[ =:]+(\d+)")
_POD = re.compile(r"\bPod/([a-z0-9][a-z0-9.\-]*)|^([a-z0-9][a-z0-9\-]*-[a-z0-9]{5,10}-[a-z0-9]{5})/")


def show_identifiers_enabled() -> bool:
    return os.environ.get("WARDEN_REPORT_SHOW_IDENTIFIERS", "").strip().lower() in ("1", "true", "yes")


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


# --------------------------------------------------------------------------- evidence extraction


def _key_log_lines(logs: list[str]) -> list[str]:
    """The lines worth a human's attention: events, WARDEN's own read failures, anything that looks
    like an error - in their original order. Padded with the newest lines if there are too few."""
    picked = [ln for ln in logs if ln.startswith(("EVENT", "NODE-EVENT", "PARTIAL")) or _IMPORTANT.search(ln)]
    if len(picked) < 4:
        picked += [ln for ln in logs[-(4 - len(picked)):] if ln not in picked]
    if len(picked) > _KEY_LINES:
        # Keep the first error (when it started) and the most recent ones (what it is doing now).
        picked = picked[:2] + ["..."] + picked[-(_KEY_LINES - 3):]
    return [ln if len(ln) <= _LINE_MAX else ln[:_LINE_MAX] + " ..." for ln in picked]


def _checked(logs: list[str]) -> tuple[dict[str, list[str]], list[str]]:
    """Split out what WARDEN checked itself (k8s_backend: container status, the crashed containers'
    own output, rollout history) from the ordinary log lines, so the report can show the RESULTS of
    those checks as such - and not also repeat them among the key log lines."""
    checked: dict[str, list[str]] = {"status": [], "previous": [], "rollout": []}
    rest: list[str] = []
    for line in logs:
        if line.startswith("STATUS "):
            checked["status"].append(line[len("STATUS "):])
        elif line.startswith("ROLLOUT "):
            checked["rollout"].append(line[len("ROLLOUT "):])
        elif " (previous) " in line:
            checked["previous"].append(line)
        else:
            rest.append(line)
    return checked, rest


def _affected(logs: list[str]) -> dict[str, list[tuple[str, int]]]:
    """Identifiers that appear in the evidence, with how many lines mention each."""
    found: dict[str, Counter] = {}
    for line in logs:
        for key, value in _KV.findall(line):
            found.setdefault(key, Counter())[value] += 1
        for pid in _PID.findall(line):
            found.setdefault("pid", Counter())[pid] += 1
        for a, b in _POD.findall(line):
            found.setdefault("pod", Counter())[a or b] += 1
    order = ("pod", "pid", *_AFFECTED_KEYS)
    # Shown as the top 5 per key, with a count of the rest. The FULL list stays available: the runbook
    # needs every pid, not the five most mentioned (see build_report).
    return {k: found[k].most_common() for k in order if k in found}


def _parse_ts(text: str) -> dt.datetime | None:
    m = _TS.search(text)
    if not m:
        return None
    raw = m.group(0).replace("Z", "+00:00")
    try:
        t = dt.datetime.fromisoformat(raw)
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=dt.UTC)


def _timeline(alert: Alert, ctx: ContextBundle) -> list[tuple[str, str]]:
    events: list[tuple[dt.datetime, str]] = []
    started = _parse_ts(alert.started_at or "")
    if started:
        events.append((started, f"alert `{alert.name}` fired"))
    for d in ctx.recent_deploys:
        at = _parse_ts(d.get("at", ""))
        what = d.get("sha") or d.get("image") or d.get("task_definition") or d.get("revision") or "?"
        prev = d.get("previous_image") or d.get("previous") or ""
        who = d.get("by", "")
        label = f"deploy of `{d.get('service') or d.get('deployment') or alert.service}` -> `{what}`"
        if prev:
            label += f" (was `{prev}`)"
        if who:
            label += f" by {who}"
        if at:
            events.append((at, label))
    errors = [(t, ln) for ln in ctx.logs if _IMPORTANT.search(ln) and (t := _parse_ts(ln))]
    if errors:
        errors.sort(key=lambda e: e[0])
        events.append((errors[0][0], "first error in the evidence"))
        if len(errors) > 1:
            events.append((errors[-1][0], f"latest error ({len(errors)} error lines in total)"))
    events.sort(key=lambda e: e[0])
    return [(t.strftime("%Y-%m-%d %H:%M:%SZ"), what) for t, what in events]


# --------------------------------------------------------------------------- scrubbing


def _scrub(obj, mapping: dict[str, str]):
    """Redact every string in a nested structure with one shared mapping. Returns (obj, mapping)."""
    if isinstance(obj, str):
        r = redact(obj, mapping=mapping)
        return r.text, r.mapping
    if isinstance(obj, list):
        out = []
        for item in obj:
            item, mapping = _scrub(item, mapping)
            out.append(item)
        return out, mapping
    if isinstance(obj, tuple):
        items, mapping = _scrub(list(obj), mapping)
        return tuple(items), mapping
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            value, mapping = _scrub(value, mapping)
            out[key] = value
        return out, mapping
    return obj, mapping


def reveal_identifiers(obj, mapping: dict[str, str]):
    """Put back ONLY the identifier placeholders (REVEALABLE) found in `mapping`; secrets stay masked.

    The one place this decision is made. build_report and chatops.notify both call it, because
    notify re-redacts the finished report before it leaves the process - and until 2026-09-25 that
    re-redaction silently re-masked every identifier the operator had asked to see, so
    WARDEN_REPORT_SHOW_IDENTIFIERS did nothing at all in Slack.
    """
    reveal = {p: v for p, v in mapping.items() if p[1:].rsplit("_", 1)[0] in REVEALABLE}
    # The model sometimes drops the angle brackets and writes `EMAIL_1`. Those bare forms are
    # revealed too - whole words only, identifier labels only, so `<SECRET_1>` stays masked.
    reveal.update({p[1:-1]: v for p, v in list(reveal.items())})
    return _reveal(obj, reveal) if reveal else obj


def _reveal(obj, reveal: dict[str, str]):
    if isinstance(obj, str):
        # Bracketed placeholders first, then bare ones on word boundaries: `EMAIL_1` must not match
        # inside `EMAIL_12`, and must not eat the middle of an already-bracketed token.
        for placeholder, original in sorted(reveal.items(), key=lambda kv: (not kv[0].startswith("<"), -len(kv[0]))):
            if placeholder.startswith("<"):
                obj = obj.replace(placeholder, original)
            else:
                obj = re.sub(rf"(?<![<\w]){re.escape(placeholder)}(?![\w>])", lambda _m, o=original: o, obj)
        return obj
    if isinstance(obj, list):
        return [_reveal(x, reveal) for x in obj]
    if isinstance(obj, tuple):
        return tuple(_reveal(x, reveal) for x in obj)
    if isinstance(obj, dict):
        return {k: _reveal(v, reveal) for k, v in obj.items()}
    return obj


# --------------------------------------------------------------------------- evidence sources


def _sources(alert: Alert, backend: str | None) -> list[str]:
    """Where the evidence came from and over what window - said in every report.

    The windows are the backends' own constants, imported rather than restated, so this cannot drift
    from what was actually read. Added after the owner asked whether WARDEN reads CloudWatch "around
    those timestamps": for ECS it does; for Kubernetes and PostgreSQL it does not, and a report that
    leaves that unsaid lets a reader assume it did.
    """
    name = (backend or os.environ.get("WARDEN_BACKEND") or "fixture").lower()
    started = _parse_ts(alert.started_at or "")
    if name in ("aws", "ecs"):
        from .aws_backend import LOG_LOOKBACK, METRIC_WINDOW, RECENT_DEPLOY_WINDOW

        group = alert.labels.get("log_group", f"/ecs/{alert.labels.get('ecs_service', alert.service)}")
        if started:
            span = (f"{(started - LOG_LOOKBACK):%H:%M} to {(started + LOG_LOOKBACK):%H:%M} UTC on "
                    f"{started:%Y-%m-%d}")
        else:
            span = f"alert time ± {int(LOG_LOOKBACK.total_seconds() // 60)} min"
        return [
            f"CloudWatch Logs `{group}`: {span} (alert time ± {int(LOG_LOOKBACK.total_seconds() // 60)} min).",
            f"CloudWatch metrics: alert time ± {int(METRIC_WINDOW.total_seconds() // 60)} min.",
            (f"ECS service state and deployments; task-definition changes in the last "
            f"{int(RECENT_DEPLOY_WINDOW.total_seconds() // 3600)} h."),
        ]
    if name in ("k8s", "kubernetes"):
        from .k8s_backend import LOG_MAX_PODS, LOG_TAIL_LINES, RECENT_DEPLOY_WINDOW

        return [
            (f"Kubernetes API: pod status, events, and the last {LOG_TAIL_LINES} log lines per container "
            f"(up to {LOG_MAX_PODS} pods), read when the alert was handled."),
            ("Also run by WARDEN, read-only: each restarted container's exit reason and code, its "
            "previous (crashed) log, the rollout history, and any autoscaler that owns the replica count."),
            (f"Deployment and ReplicaSets: image changes in the last "
            f"{int(RECENT_DEPLOY_WINDOW.total_seconds() // 3600)} h."),
            "Not read: CloudWatch, Container Insights, node metrics, control-plane logs.",
        ]
    if name in ("postgres", "postgresql", "mysql", "redis", "mongo", "mongodb", "mssql", "database"):
        return [
            ("The database's own session views (for PostgreSQL: pg_stat_activity, pg_locks), as a "
            "snapshot taken when the alert was handled."),
            "Not read: database logs, CloudWatch, Performance Insights, CPU/memory/IOPS.",
        ]
    return ["A recorded demo incident (fixture) - not read from a live system."]


_NEXT_STEP = {
    "rejected": "Blocked by the gate - nothing will run. A person has to look at this.",
    "escalated": "Escalated - a person decides. Nothing runs until then.",
    "approved_for_human": "Held for approval - the fix below runs only if a person approves it.",
    "auto_safe": "No change proposed - recorded, nothing to run.",
}


# --------------------------------------------------------------------------- build


def build_report(
    alert: Alert,
    *,
    root_cause: RootCause | None = None,
    proposal: RemediationProposal | None = None,
    verdict: Verdict | None = None,
    remediation: RemediationResult | None = None,
    signatures: list[SignatureMatch] | None = None,
    policies: EnvironmentPolicies | None = None,
    context: ContextBundle | None = None,
    redaction_map: dict[str, str] | None = None,
    backend: str | None = None,
    show_identifiers: bool | None = None,
) -> Report:
    """Assemble a redacted remediation report from one run.

    `context` is the RAW evidence bundle and `redaction_map` the pipeline's placeholder map (so the
    whole report is redacted once, consistently, with the placeholders the model saw). Both are
    optional: without them the report still renders, just without the evidence sections.
    """
    pol = policies or default_environment_policies()
    signatures = signatures or []
    ctx = context or ContextBundle()
    reveal_ids = show_identifiers_enabled() if show_identifiers is None else show_identifiers

    promotion = _promotion_targets(alert, proposal, pol) if proposal else []
    affected = _affected(ctx.logs)
    checked, ordinary_logs = _checked(ctx.logs)
    patterns = detect_patterns(alert, ctx)

    data: dict = {
        "alert": {
            "id": alert.alert_id,
            "name": alert.name,
            "severity": alert.severity.value,
            "service": alert.service,
            "environment": alert.environment,
            "summary": alert.summary,
            "started_at": alert.started_at,
        },
        "sources": _sources(alert, backend),
        "impact": symptoms(ctx),
        "error_lines": sum(1 for ln in ctx.logs if _IMPORTANT.search(ln)),
        "matched_signatures": [
            {"id": m.signature.id, "title": m.signature.title, "score": m.score,
             "category": m.signature.category, "maturity": m.signature.maturity,
             "root_cause": m.signature.root_cause}
            for m in signatures
        ],
        "patterns": [dataclasses.asdict(p) for p in patterns],
        "root_cause": None,
        "evidence": {
            "metrics": dict(ctx.metrics),
            "tool_errors": list(ctx.tool_errors),
            "key_log_lines": _key_log_lines(ordinary_logs),
            "checked": checked,
            "log_lines_read": len(ctx.logs),
            "recent_deploys": [dict(d) for d in ctx.recent_deploys],
            "timeline": _timeline(alert, ctx),
            "affected": {k: [[v, n] for v, n in vals] for k, vals in affected.items()},
        },
        "proposal": None,
        "verdict": None,
        "remediation": None,
        "runbook": None,
        "promotion": [
            {"environment": t.environment, "tier": t.tier,
             "requires_human_approval": t.requires_human_approval,
             "auto_remediates": t.auto_remediates, "note": t.note,
             "credentials_ref": t.credentials_ref}
            for t in promotion
        ],
        "identifiers_shown": reveal_ids,
    }
    if root_cause:
        data["root_cause"] = {
            "hypothesis": root_cause.hypothesis,
            "confidence": root_cause.confidence,
            "evidence": list(root_cause.evidence),
            "ruled_out": list(root_cause.ruled_out),
        }
    if proposal:
        data["proposal"] = {
            "action": proposal.action.value,
            "target": proposal.target,
            # ⚠ CLAIM vs ENFORCED, and both are published. The first two are what the MODEL said;
            # the next two are what the gate actually used (models.py::ACTION_FACTS). Keeping the
            # raw claims is deliberate: they are evidence about the model, and the benchmark's
            # scorer measures how often it contradicts itself about the same action. An auditor
            # must be able to see where the claim and the enforced value disagree.
            "blast_radius": proposal.blast_radius,
            "reversible": proposal.reversible,
            "blast_radius_effective": proposal.effective_blast_radius,
            "reversible_by_table": proposal.table_reversible,
            "claim_contradicts_table": proposal.claim_contradicts_table,
            "expected_effect": proposal.expected_effect,
        }
        # ⛔ EVERY pid in the evidence, not the five the "Affected" section displays. With twelve
        # stuck sessions the first version terminated five and left seven holding the pool.
        pids = [p for p, _ in affected.get("pid", [])]
        rb = build_runbook(alert, proposal.action, backend=backend, pids=pids, context=ctx)
        data["runbook"] = dataclasses.asdict(rb)
    if verdict:
        data["verdict"] = {
            "status": verdict.status.value,
            "policy_ids": verdict.policy_ids,
            "reasons": list(verdict.reasons),
        }
    if remediation:
        data["remediation"] = {
            "outcome": remediation.outcome.value,
            "detail": remediation.detail,
            "applied_change": remediation.applied_change,
            "principal": remediation.principal,
        }

    # ⛔ ONE redaction pass over everything, SEEDED WITH THE PIPELINE'S OWN MAP - then, and only
    # then, the operator's identifiers may be put back. Seeded, not restored-and-re-redacted: the
    # model's text already carries the pipeline's placeholders, and an earlier version put the real
    # values back into it and redacted again. That leaked. The model wrote `tenant_<TENANT_1>`, it
    # was restored to `tenant_initech-4`, and the TENANT pattern only knows `tenant_id=...`, so the
    # tenant id went out unmasked. Seeded, every value the pipeline already knows is masked
    # wherever and however it appears (redact()'s literal sweep), with the same placeholder the
    # model used. Never reveal before redacting: a secret next to a tenant id would ride along.
    data, mapping = _scrub(data, dict(redaction_map or {}))
    markdown = _render_markdown(data)
    final = redact(markdown, mapping=mapping)  # belt and braces: anything assembled unscrubbed
    markdown, mapping = final.text, final.mapping
    if reveal_ids:
        data = reveal_identifiers(data, mapping)
        markdown = reveal_identifiers(markdown, mapping)
    return Report(markdown=markdown, data=data, promotion=tuple(promotion))


# --------------------------------------------------------------------------- render


def _code(lines: list[str], items: list[str]) -> None:
    lines.append("```")
    lines.extend(items)
    lines.append("```")


def _render_markdown(d: dict) -> str:
    a = d["alert"]
    ev = d["evidence"]
    v = d.get("verdict")
    p = d.get("proposal")
    rb = d.get("runbook")
    lines: list[str] = []

    lines.append(f"# WARDEN incident report - {a['name']} - {a['service']} ({a['environment']})")
    lines.append(f"Severity **{a['severity']}** | alert `{a['id']}` | started {a.get('started_at') or 'unknown'}")
    if v:
        lines.append(f"**Next step: {_NEXT_STEP.get(v['status'], v['status'])}**")
    lines.append("")

    # ---- summary
    lines.append("## Summary")
    lines.append(f"- **Alert**: {a['summary']}")
    if d["impact"]:
        lines.append("- **Impact seen in the evidence**: " + "; ".join(d["impact"]) + ".")
    elif ev["tool_errors"] and not ev["metrics"]:
        lines.append("- **Impact**: unknown - WARDEN could not read the system (see below).")
    elif d.get("error_lines"):
        # ⚠ inc-001 said "no failing component" above four HTTP 500 lines until 2026-09-25. Errors are
        # impact; they are just not a COUNTED broken object (crashed, unready, saturated).
        lines.append(f"- **Impact seen in the evidence**: {d['error_lines']} error line(s); no crashed, "
                     "unready or saturated component counted.")
    else:
        lines.append("- **Impact seen in the evidence**: no errors and no failing component in what "
                     "WARDEN read.")
    if d["root_cause"]:
        lines.append(f"- **Diagnosis** (confidence {d['root_cause']['confidence']:.2f}): "
                     f"{d['root_cause']['hypothesis']}")
    if p:
        lines.append(f"- **Proposed**: `{p['action']}` on `{p['target']}`"
                     + (f" - gate: `{v['status']}`" if v else ""))
    lines.append("")

    # ---- what was read
    lines.append("## What WARDEN read")
    lines.extend(f"- {s}" for s in d["sources"])
    if ev["tool_errors"]:
        lines.append("")
        lines.append("**⚠ What WARDEN could NOT read** - the diagnosis was made without this:")
        lines.extend(f"- `{e}`" for e in ev["tool_errors"])
    lines.append("")

    # ---- diagnosis
    if d["root_cause"]:
        rc = d["root_cause"]
        lines.append(f"## What WARDEN thinks happened  (model, confidence {rc['confidence']:.2f})")
        lines.append(rc["hypothesis"])
        if rc["evidence"]:
            lines.append("")
            lines.append("**Based on:**")
            lines.extend(f"- {e}" for e in rc["evidence"])
        if rc["ruled_out"]:
            lines.append("")
            lines.append("**Ruled out:**")
            lines.extend(f"- {r}" for r in rc["ruled_out"])
        lines.append("")

    if d["patterns"]:
        lines.append("## Patterns detected in the evidence  (fixed checks, not the model)")
        for pat in d["patterns"]:
            lines.append(f"- **{pat['title']}** - seen: `{pat['seen']}`")
            lines.append(f"  {pat['likely_cause']}")
        lines.append("")

    if d["matched_signatures"]:
        lines.append("## Known incident signatures that fit")
        for s in d["matched_signatures"]:
            lines.append(f"- `{s['id']}` **{s['title']}** ({s['category']}, score {s['score']}): {s['root_cause']}")
        lines.append("")

    # ---- the read-only checks WARDEN ran itself
    chk = ev.get("checked") or {}
    if any(chk.values()):
        lines.append("## Checked by WARDEN  (read-only, at alert time)")
        if chk["status"]:
            lines.append("**Container status** - how each failing container last died, and what it waits on now")
            lines.extend(f"- `{c}`" for c in chk["status"])
        if chk["previous"]:
            lines.append("**The crashed containers' own last output** (`logs --previous`)")
            _code(lines, chk["previous"][-12:])
        if chk["rollout"]:
            lines.append("**Rollout history** - newest first")
            lines.extend(f"- `{r}`" for r in chk["rollout"])
        lines.append("")

    # ---- the evidence itself
    if ev["metrics"]:
        lines.append("## Metrics at the time")
        lines.append(" | ".join(f"`{k}` = **{_num(val)}**" for k, val in sorted(ev["metrics"].items())))
        lines.append("")
    if ev["timeline"]:
        lines.append("## Timeline (UTC)")
        lines.extend(f"- `{t}` {what}" for t, what in ev["timeline"])
        lines.append("")
    if ev["affected"]:
        lines.append("## Affected - as named in the evidence")
        for key, values in ev["affected"].items():
            shown = ", ".join(f"`{val}` ({n} line{'s' if n != 1 else ''})" for val, n in values[:5])
            if len(values) > 5:
                shown += f" and {len(values) - 5} more"
            lines.append(f"- **{key}**: {shown}")
        if not d.get("identifiers_shown"):
            lines.append("_Identifiers are masked. Set `WARDEN_REPORT_SHOW_IDENTIFIERS=true` to show "
                         "tenant ids, emails and IPs in your own channel; secrets stay masked either way._")
        lines.append("")
    if ev["key_log_lines"]:
        lines.append(f"## Key log lines  ({len(ev['key_log_lines'])} of {ev['log_lines_read']} read)")
        _code(lines, ev["key_log_lines"])
        lines.append("")

    # ---- proposal and gate
    if p:
        lines.append("## Proposed action")
        lines.append(f"- **Action**: `{p['action']}` -> `{p['target']}`")
        lines.append(f"- **Expected effect** (model): {p['expected_effect']}")
        lines.append(
            f"- **Blast radius**: {p['blast_radius_effective']} (enforced; the model claimed "
            f"{p['blast_radius']}) - reversible: {p['reversible_by_table']} per WARDEN's action "
            f"table (the model claimed {p['reversible']})"
        )
        lines.append("")
    if v:
        lines.append("## Gate verdict  (deterministic)")
        lines.append(f"- **Status**: `{v['status']}`" + (f" - policies: {', '.join(v['policy_ids'])}"
                                                           if v["policy_ids"] else ""))
        lines.extend(f"  - {r}" for r in v["reasons"])
        lines.append("")

    # ---- risk BEFORE steps, then the runbook
    if rb and (rb["check"] or rb["fix"] or rb["note"]):
        contradiction = [r for r, pid in zip(v["reasons"], v["policy_ids"], strict=False)
                         if pid == "P11-ACTION-CONTRADICTS-EVIDENCE"] if v else []
        if rb["risk"] or contradiction:
            lines.append("## ⚠ Before you act")
            # The gate's own finding first: a runbook for an action the gate says cannot work must
            # not read as a recommendation. The steps stay - a person may still decide to run them.
            for reason in contradiction:
                lines.append(f"- ⛔ **The gate found this action cannot fix what the evidence shows.** {reason} "
                             "The follow-ups below say what would.")
            lines.extend(f"- {r}" for r in rb["risk"])
            if rb["fix"] and v and v["status"] != "auto_safe":
                lines.append("- The gate did not clear this action on its own: a person decides whether to run the fix.")
            lines.append("")
        lines.append(f"## Runbook - {rb['platform']}  ({rb['basis']})")
        if rb["note"]:
            lines.append(f"_{rb['note']}_")
        check_title = ("1. Re-check right before acting - WARDEN ran the diagnostics above at alert time; "
                       "state may have moved since" if rb.get("checked_by_warden")
                       else "1. Check - read-only, confirm the diagnosis first")
        for title, key in ((check_title, "check"), ("2. Fix", "fix"),
                           ("3. Confirm it worked", "confirm"), ("4. If it made things worse", "undo")):
            if rb[key]:
                lines.append(f"**{title}**")
                _code(lines, rb[key])
            elif key == "fix" and rb["confirm"]:
                # Steps stay numbered 1-2-3: a runbook that jumped from 1 to 3 read as a lost page.
                lines.append(f"**{title}** - no command printed; see the note at the top of this runbook.")
        lines.append("")

    # ---- follow-ups by team
    teams = (("On-call - now", "oncall"), ("Developers", "developers"),
             ("Platform / DevOps", "platform"), ("DBA", "dba"), ("Prevention", "prevention"))
    if d["patterns"]:
        lines.append("## Follow-ups by team")
        many = len(d["patterns"]) > 1
        for title, key in teams:
            items = [(pat["title"], item) for pat in d["patterns"] for item in pat[key]]
            if items:
                lines.append(f"**{title}**")
                seen: set[str] = set()
                for source, item in items:
                    if item not in seen:
                        seen.add(item)
                        lines.append(f"- {item}" + (f"  _({source})_" if many else ""))
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


def _num(v: float) -> str:
    return f"{v:.4g}" if isinstance(v, float) else str(v)
