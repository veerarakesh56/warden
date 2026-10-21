"""The incident report — what a person reads to understand an incident and decide on WARDEN's fix plan.

This module builds that report from the pieces of one run and renders it two ways — Markdown (for a
human / ChatOps) and a JSON dict (for machines).

What the report must let the reader do WITHOUT opening another tool: see what WARDEN actually read
(metrics, the log lines that matter, deploys, what it could NOT read), who and what is affected
(pods, PIDs, hosts, tenants, users), when things happened, and who should act next. A report that
carries only the model's conclusion asks the reader to trust it; one that carries the evidence lets
them check it. (Until 2026-09-24 it carried only the conclusion: the model's own cited evidence, the
whole evidence bundle and every identifier were dropped.)

⛔ NO COMMANDS (2026-10-16). The report used to print exact aws, kubectl and SQL commands to check,
fix, confirm and undo - a second, unaudited way to make the change, outside the signed approval, the
bounds, the kill switch and the audit, and printed even under a rejected verdict. A fix now goes
only through a catalogue plan and a signed approval, which WARDEN applies itself; the report says
what to look at and who acts, in words.

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
  3. The PROMOTION targets (data only) are derived from the environment policy, not guessed.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import os
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

from .environments import EnvironmentPolicies, both_times, default_environment_policies
from .gate import hedge
from .knowledge import SignatureMatch
from .models import ActionKind, Alert, ContextBundle, RemediationProposal, RootCause, Verdict
from .playbook import detect as detect_patterns
from .redaction import redact
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
# ⛔ A pid only from the fixed prefix WARDEN's own database reads write (database.py), never from
# anywhere in a line: the query text follows that prefix, and `/* pid=1 pid=77 */` in a query put
# pids 1 and 77 into the printed terminate statement (2026-09-27 audit).
_PID = re.compile(r"^\w+ (?:stuck connection|long-running query|blocked session): pid=(\d+)\b")
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
    # (label, url) approval links WARDEN itself minted (register H6): delivered after the gate, never through it, and
    # only in the exact shape chatops.approval_links accepts.
    actions: tuple[tuple[str, str], ...] = ()
    # (approver id, Slack member id, name) rows WARDEN itself read from the approver list: each approver's mark in
    # the text becomes Slack's mention of that member, or the name (chatops.name_people) - never taken from a
    # message's text.
    people: tuple[tuple[str, str, str], ...] = ()


_LOCAL_ONLY = frozenset({ActionKind.revert_change, ActionKind.revert_config, ActionKind.resume_flow,
                         ActionKind.pause_flow})


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


# A dated write as WARDEN's own readers record it (aws_stack._read_changes): when, what on what, by whom.
_CHANGE = re.compile(r"^CHANGE (\d{4}-\d\d-\d\dT[\d:]{8}Z) \S+ (\S+ on \S+ by \S+)")
_TIMELINE_CHANGES_S = 3600  # the hour before the alert: what changed then belongs on its timeline


def _key_log_lines(logs: list[str]) -> list[str]:
    """The lines worth a human's attention: events, WARDEN's own read failures, anything that looks
    like an error - in their original order. Padded with the newest lines if there are too few."""
    picked = [ln for ln in logs if ln.startswith(("EVENT", "NODE-EVENT", "PARTIAL")) or _IMPORTANT.search(ln)]
    if len(picked) < 4:
        # The newest recorded changes first (their timestamps sort as text): a report padded from the end of the
        # list showed changes five hours old and not the one that caused the alarm (live, 2026-10-12).
        changes = sorted((ln for ln in logs if _CHANGE.match(ln) and ln not in picked), reverse=True)
        rest = [ln for ln in reversed(logs) if ln not in picked and ln not in changes]
        picked += (changes[:3] + rest + changes[3:])[:4 - len(picked)]  # and a line of the state itself
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
    # Shown as the top 5 per key, with a count of the rest; the data keeps the FULL list.
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


_PLACEHOLDER_TOKEN = re.compile(r"(<[A-Z][A-Z0-9]*_\d+>)")


def untrusted_inline(text: str, limit: int = 300) -> str:
    """Text WARDEN did not write, as inert markdown (audit A-C-1): one line, no backtick to break out
    of the code span, no `<...>` Slack or HTML would act on, capped. A forged "approved fix" block in
    an alert summary renders as the words it is, not as a heading and a command."""
    one = " ".join(str(text).split())
    parts = _PLACEHOLDER_TOKEN.split(one)  # odd indices are whole `<KIND_n>` placeholders: kept as-is
    one = "".join(part if i % 2 else
                  part.replace("`", "\u02cb").replace("<", "\u2039").replace(">", "\u203a")
                  for i, part in enumerate(parts))
    if len(one) > limit:
        one = one[:limit] + "\u2026"
    return f"`{one}`" if one else "`(empty)`"


def _timeline(alert: Alert, ctx: ContextBundle) -> list[tuple[str, str]]:
    events: list[tuple[dt.datetime, str]] = []
    started = _parse_ts(alert.started_at or "")
    if started:
        events.append((started, f"alert {untrusted_inline(alert.name)} fired"))
    for d in ctx.recent_deploys:
        at = _parse_ts(d.get("at", ""))
        what = d.get("sha") or d.get("image") or d.get("task_definition") or d.get("revision") or "?"
        prev = d.get("previous_image") or d.get("previous") or ""
        who = d.get("by", "")
        label = f"deploy of {_c(d.get('service') or d.get('deployment') or alert.service)} -> {_c(what)}"
        if prev:
            label += f" (was {_c(prev)})"
        if who:
            label += f" by {who}"
        if at:
            events.append((at, label))
    # What WARDEN's own readers recorded as changed in the hour before the alert: the timeline held only "alert
    # fired" beside a diagnosis that cited a change made nine minutes earlier (live, 2026-10-12).
    for line in ctx.logs:
        m = _CHANGE.match(line)
        at = _parse_ts(m.group(1)) if m else None
        if at and started and 0 <= (started - at).total_seconds() <= _TIMELINE_CHANGES_S:
            events.append((at, f"change recorded: {untrusted_inline(m.group(2))}"))
    errors = [(t, ln) for ln in ctx.logs if _IMPORTANT.search(ln) and (t := _parse_ts(ln))]
    if errors:
        errors.sort(key=lambda e: e[0])
        events.append((errors[0][0], "first error in the evidence"))
        if len(errors) > 1:
            events.append((errors[-1][0], f"latest error ({len(errors)} error lines in total)"))
    events.sort(key=lambda e: e[0])
    return [(both_times(t), what) for t, what in events]


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


# What each stack reader reads (docs/FULLSTACK-LAB.md section 4), keyed by the alert label that names it.
_STACK_READERS = (
    ("lambda", ("lambda",), ("configuration, concurrency, aliases and versions, event source mappings, CloudWatch "
                           "Errors/Throttles/Invocations/Duration, /aws/lambda logs, and the deployed source of a "
                           "traceback frame")),
    ("sqs", ("sqs",), "queue and DLQ attributes, age of the oldest message"),
    ("dynamodb", ("dynamodb_table",), "table description, CloudWatch throttles and consumed capacity"),
    ("elasticache", ("elasticache",), "replication group, nodes and events, CloudWatch memory/evictions/connections"),
    ("aurora", ("aurora_cluster",), ("cluster, instances and events, CloudWatch, and pg_stat_activity on the writer "
                                   "and reader as a pg_monitor user")),
    ("alb", ("alb_target_group",), "target health and reasons, CloudWatch 5xx/unhealthy hosts/response time"),
    ("apigw", ("apigw",), "API and integrations, CloudWatch 5xx/4xx/latency"),
    ("ecs", ("ecs_service", "ecs_cluster"), "service, deployments, stopped tasks, task definitions, CloudWatch Logs"),
    ("k8s", ("deployment", "namespace"), "pod status, events, container logs and previous logs, rollout history"),
    ("secret", ("secret",), "secret METADATA only (last changed / rotated), never the value"),
    ("sns", ("sns_topic",), "topic attributes, subscriptions, CloudWatch failed/delivered notifications"),
    ("eventbridge", ("eventbridge_rule",), "rule state and schedule, invocations"),
)


def _items_of(context: ContextBundle | None) -> dict[str, Any]:
    """The evidence items a citation may name; none when there is no context or its view cannot be built."""
    from . import evidence

    try:
        return evidence.view(context) if context is not None else {}
    except Exception:  # noqa: BLE001  # a view that cannot be built checks nothing: all unchecked and every count 0
        return {}


def _ruled_out(root_cause: Any, context: ContextBundle | None) -> list[dict[str, Any]]:
    """Each cause the model ruled out, its reason, and whether that reason holds against the evidence."""
    from types import SimpleNamespace

    from .grounding import hypothesis_score, ruled_out_checked

    items = _items_of(context)
    rows = [{"cause": hedge(r.cause), "why": hedge(r.why), "cites": [c.id for c in r.citations],
             "checked": ruled_out_checked(r, items)} for r in root_cause.ruled_out]
    # Item 7: the hypotheses that lost, each with why, the evidence against it (what rules it out) and WARDEN's count.
    for h in (root_cause.hypotheses or [])[1:]:
        against = SimpleNamespace(citations=h.against)
        rows.append({"cause": hedge(h.cause), "why": hedge(h.why_rejected), "cites": [c.id for c in h.against],
                     "checked": ruled_out_checked(against, items), "count": hypothesis_score(h, items),
                     "for": [c.id for c in h.supporting]})
    return rows


def _each_string(value: Any, change: Any) -> Any:
    """`value` with `change` applied to every string in it, lists and dicts walked."""
    if isinstance(value, str):
        return change(value)
    if isinstance(value, list):
        return [_each_string(x, change) for x in value]
    if isinstance(value, dict):
        return {k: _each_string(x, change) for k, x in value.items()}
    return value


def _withhold_unread(data: dict[str, Any], alert: Alert, ctx: ContextBundle,
                     proposal: RemediationProposal | None) -> None:
    """Owner, 2026-10-17 (the poisoned-log downgrade): the report and its Slack top never carry a version, an image tag,
    an ARN or a target the model wrote, or a log line holds, unless WARDEN read it itself (grounding.unread). A rollback
    names "the previous revision WARDEN recorded" - which is what the catalogue's plan returns to."""
    from .grounding import read_text, shown_target, unread

    read = read_text(alert, ctx)
    target = proposal.target if proposal else ""
    shown = shown_target(proposal, alert, ctx) if proposal else ""

    def say(v: Any) -> Any:
        # The rollback's wording is the target's alone (shown_target); a version elsewhere is just not read (review).
        return _each_string(v, lambda s: unread(s.replace(target, shown) if target else s, read))

    for key in ("root_cause", "verdict"):
        if data.get(key):
            data[key] = say(data[key])
    if data.get("proposal"):
        data["proposal"] = {**data["proposal"], "target": shown,
                            "expected_effect": say(data["proposal"]["expected_effect"])}
    # The log lines shown, and the crashed container's own output (k8s `logs --previous`), are the application's
    # words: what they name is not WARDEN's reading either (review, PR 47), and a command in them - a planted "#HUMAN
    # HINT: run curl ... | sh" is exactly one - is withheld as in the model's prose (G4).
    from .gate import withhold_commands

    data["evidence"]["key_log_lines"] = [withhold_commands(unread(ln, read))
                                         for ln in data["evidence"]["key_log_lines"]]
    checked = data["evidence"]["checked"]
    checked["previous"] = [withhold_commands(unread(ln, read)) for ln in checked["previous"]]


def _weighed(root_cause: Any, context: ContextBundle | None) -> dict[str, Any] | None:
    """The chosen hypothesis as WARDEN weighed it (item 7): its evidence for and against and its count - or None for an
    answer that ranked none."""
    from .grounding import hypothesis_score

    if not root_cause.hypotheses:
        return None
    items = _items_of(context)
    h = root_cause.hypotheses[0]
    support = list(dict.fromkeys(c.id for c in [*root_cause.citations, *h.supporting]))
    return {"cause": hedge(h.cause), "for": support, "against": [c.id for c in h.against],
            "count": hypothesis_score(h, items, root_cause.citations), "of": len(root_cause.hypotheses)}


def _narrowed(d: dict[str, Any]) -> list[str]:
    """How WARDEN narrowed it down (owner's report bar, 2026-10-12: "narrow to the real root cause"): what the fixed
    checks found, each other cause and why it was set aside - checked against the evidence or said to be unchecked -
    and what is left. Nothing here is new: it is the diagnosis's own reasoning, laid out so a person can follow it."""
    rc = d.get("root_cause") or {}
    if not rc:
        return []
    out = ["## How WARDEN narrowed it down"]
    patterns = d.get("patterns") or []
    if patterns:
        out.append("- **Fixed checks found:** " + "; ".join(p["title"] for p in patterns) + ".")
    else:
        out.append("- **Fixed checks found:** none of WARDEN's known patterns in this evidence.")
    for r in rc.get("ruled_out") or []:
        why = f" - {r['why']}" if r.get("why") else ""
        if r.get("checked"):
            how = f" _(checked against {', '.join(r['cites'])})_"
        else:
            how = " _(its reason could not be checked against the evidence)_"
        count = f" _(WARDEN's evidence count {r['count']})_" if "count" in r else ""
        out.append(f"- **Ruled out:** {r['cause']}{why}{how}{count}")
    if not rc.get("ruled_out"):
        out.append("- **Ruled out:** the diagnosis named no other cause it considered.")
    cited = ", ".join(c["id"] for c in rc.get("citations") or [])
    weighed = rc.get("weighed")
    count = (f" _(WARDEN's evidence count {weighed['count']}: for {', '.join(weighed['for']) or 'nothing'}, "
             f"against {', '.join(weighed['against']) or 'nothing'})_") if weighed else ""
    if weighed and weighed["cause"] != rc.get("hypothesis"):
        # The count is the first ranked hypothesis's: when the model worded it differently, both are shown (review,
        # PR 47), so a count is never read as belonging to words it was not computed for.
        count += f" - the count is for the cause it ranked first: {weighed['cause']}"
    out.append(f"- **Left:** {rc.get('hypothesis', '')}" + (f" _(cited: {cited})_" if cited else "") + count
               + ("" if rc.get("grounded", True) else " - **not grounded**: its citations did not hold."))
    out.append("")
    return out


def _stack_sources(alert: Alert, ctx: ContextBundle) -> list[str]:
    """Each component read, and each reader that failed (a failed reader is never silence - P8)."""
    from .aws_backend import LOG_LOOKBACK, METRIC_WINDOW, RECENT_DEPLOY_WINDOW

    errors = [e.removeprefix("TOOL-PARTIAL ") for e in ctx.tool_errors]
    errors += [ln.removeprefix("TOOL-PARTIAL ") for ln in ctx.logs if ln.startswith("TOOL-PARTIAL ")]
    out = [(f"Full-stack backend: one isolated reader per component the alert names. Logs: alert time ± "
            f"{int(LOG_LOOKBACK.total_seconds() // 60)} min; CloudWatch metrics: alert time ± "
            f"{int(METRIC_WINDOW.total_seconds() // 60)} min; deploys and secret changes: the last "
            f"{int(RECENT_DEPLOY_WINDOW.total_seconds() // 3600)} h.")]
    for reader, labels, what in _STACK_READERS:
        names = ", ".join(f"{_c(alert.labels[k])}" for k in labels if alert.labels.get(k))
        if not names:
            continue
        # Reader names as the stack backend writes them: `lambda/<fn> logs`, `aurora-db-writer`, `sqs/<q>`.
        failed = [e for e in errors if re.match(rf"{reader}\b", e)]
        out.append(f"{reader} {names}: {what}" + (f" - **FAILED**: {_c(failed[0][:160])}" if failed else " - read."))
    # What WARDEN could not read, said only for what this alert names (owner, 2026-10-14: a schedule's alarm said
    # "Not read: Redis itself ..."): plain words, nothing for a component the incident does not involve.
    unread = []
    if alert.labels.get("elasticache"):
        unread.append("the data inside the Redis cache itself (it is reachable only inside its private network; WARDEN "
                      "reads the cache's settings, events and metrics instead)")
    if any(alert.labels.get(k) for k in ("ecs_service", "ecs_cluster", "deployment")):
        unread.append("the program code inside the container images (WARDEN does not download images)")
    if unread:
        out.append("Not read: " + "; ".join(unread) + ".")
    return out


def _returned(ctx: ContextBundle) -> list[str]:
    """What each read actually returned (register N1), from the gathered record rather than the backend's
    settings: the sources say where WARDEN looks, this says what came back - including nothing, and failure."""
    failed = {e.split(":", 1)[0] for e in ctx.tool_errors}
    out = []
    for name, got, unit in (("logs", len(ctx.logs), "line(s)"), ("metrics", len(ctx.metrics), "value(s)"),
                            ("recent_deploys", len(ctx.recent_deploys), "deploy(s)")):
        if name in failed and not got:
            out.append(f"{name}: could not be read")
        elif name in ctx.empty_reads:
            out.append(f"{name}: returned nothing - unknown, not healthy")
        else:
            out.append(f"{name}: {got} {unit}" + (" (partly unread)" if name in failed else ""))
    return out


def _sources(alert: Alert, backend: str | None, ctx: ContextBundle | None = None) -> list[str]:
    """Where the evidence came from and over what window - said in every report.

    The windows are the backends' own constants, imported rather than restated, so this cannot drift
    from what was actually read. Added after the owner asked whether WARDEN reads CloudWatch "around
    those timestamps": for ECS it does; for Kubernetes and PostgreSQL it does not, and a report that
    leaves that unsaid lets a reader assume it did.
    """
    name = (backend or os.environ.get("WARDEN_BACKEND") or "fixture").lower()
    if name == "stack":
        return _stack_sources(alert, ctx or ContextBundle())
    started = _parse_ts(alert.started_at or "")
    if name in ("aws", "ecs"):
        from .aws_backend import LOG_LOOKBACK, METRIC_WINDOW, RECENT_DEPLOY_WINDOW

        group = alert.labels.get("log_group", f"/ecs/{alert.labels.get('ecs_service', alert.service)}")
        if started:
            span = (f"{both_times(started - LOG_LOOKBACK, seconds=False)} to "
                    f"{both_times(started + LOG_LOOKBACK, seconds=False)}")
        else:
            span = f"alert time ± {int(LOG_LOOKBACK.total_seconds() // 60)} min"
        return [
            f"CloudWatch Logs {_c(group)}: {span} (alert time ± {int(LOG_LOOKBACK.total_seconds() // 60)} min).",
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


_CODE = re.compile(r"CODE (\S+) (\S+?):(\d+) in (\S+): (.*)")


def _code_findings(logs: list[str]) -> list[dict]:
    """Traceback frames the stack backend resolved into the deployed source (CODE + SOURCE lines)."""
    found = []
    for line in logs:
        mt = _CODE.match(line)
        if not mt:
            continue
        fn, path, lineno, func, exc = mt.groups()
        prefix = f"SOURCE {fn} {path}:"
        found.append({"function": fn, "file": path, "line": int(lineno), "in": func, "exception": exc,
                      "source": [ln[len(prefix):] for ln in logs if ln.startswith(prefix)]})
    return found


# A resource of one of these kinds is the data team's to own; any other the alarm names, the platform team's.
_DATA_KINDS = frozenset({"aurora_cluster", "rds_instance", "dynamodb_table", "docdb_cluster", "docdb_instance",
                         "elasticache_node", "elasticache_serverless", "memorydb", "opensearch", "redshift"})
_OFFERED_UNDO = {"P31-UNADDRESSED-CHANGE"}  # held by this policy alone, WARDEN offers the undo itself (activities)


# What would stop it happening again, by the kind of fix WARDEN proposed (owner, 2026-10-15: "what are the counter
# measures"). Fixed words for a class of cause, never the model's prose; a person still judges them.
_PREVENT = {
    "revert_config": "check configuration values before they ship (the service refused this one), and roll config out "
                     "in stages so a bad value reaches one replica first",
    "rollback_deploy": "add a pre-release check or canary that would have caught this version, and keep automatic "
                       "rollback on for the service",
    "revert_change": "make changes to this resource through reviewed infrastructure code, not by hand",
    "scale_up": "size the service from its measured peak, with an alarm before it runs out of headroom",
    "raise_limit": "set the limit from measured peak use, with an alarm at 80% of it",
    "restart_pods": "find what wedges the process (memory, connections, a lock) - a restart only clears it for now",
    "terminate_connections": "set idle and idle-in-transaction timeouts, and size the connection pool to the database",
    "cancel_query": "set a statement timeout, and review the query and its indexes",
    "redrive_messages": "fix the consumer's error before redriving, and alarm on the dead-letter queue's depth",
    "resume_flow": "alarm when a consumer or trigger is disabled, and limit who may disable it",
    "pause_flow": "fix what the paused consumer or trigger did before resuming it",
    "failover_replica": "check the replica's health and lag regularly, so a failover finds it ready",
    "shift_traffic": "keep enough capacity in each zone to take a zone's traffic",
    "clear_cache": "find what filled or poisoned the cache, and bound its size and entry lifetime",
    "freeze_changes": "find the change that broke it before releasing again",
}
# A write CloudTrail recorded before the alert (aws_stack._read_changes): when, what, on which resource, by whom - the
# principal by kind and an administrator-set name, never a session name.
_CHANGE_LINE = re.compile(r"^CHANGE (\S+) \S+ ([A-Za-z0-9]+) on (\S+) by (\S+)")


def _changed_by(logs: list[str]) -> str:
    """The newest write before the alert, as "Event on resource at time by principal" - or ""."""
    found = sorted((m.groups() for m in map(_CHANGE_LINE.match, logs) if m), reverse=True)
    if not found:
        return ""
    at, event, on, by = found[0]
    return f"`{event}` on `{on}` at {at} by `{by}`"


def _who_acts(alert: Alert, data: dict) -> list[list[str]]:
    """Who has something to do about this incident now, and what - on every report (owner, 2026-10-12: "I see only
    Platform / DevOps here", and only when a fixed pattern had fired). From what the report already holds: the gate's
    verdict, the kind of resource the alarm names, and whether the evidence points at code or a deploy."""
    from .resolver import _QUALIFIERS
    from .resources import LABEL_KEYS

    verdict = data.get("verdict") or {}
    status, held_by = verdict.get("status"), set(verdict.get("policy_ids") or [])
    if (data.get("proposal") or {}).get("action") == "escalate_to_human" and status == "auto_safe":
        oncall = "look at this incident: WARDEN proposes no change and could not name a cause"
    elif status == "approved_for_human":
        oncall = ("approve or deny the fix plan with the button in this message - or, where there is none, read why "
                  "here")
    elif status == "escalated" and held_by == _OFFERED_UNDO:
        oncall = ("decide: WARDEN held the proposed fix because a recent change was left unaddressed, and offers the "
                  "undo of that change as a plan to approve or deny")
    elif status in ("escalated", "rejected"):
        oncall = "decide what to do: WARDEN runs nothing here (the gate verdict below says why)"
    else:
        oncall = "nothing to run; check that the alarm clears"
    out = [["On-call", oncall]]
    # The labels that name a resource - not the ones that only qualify one (a namespace, a cluster, a stage).
    kinds = {k for k in alert.labels if k in LABEL_KEYS and k not in _QUALIFIERS}
    named = sorted({v.strip() for k in kinds for v in str(alert.labels[k]).split(",") if v.strip()})
    if named:
        team = "DBA / data" if kinds & _DATA_KINDS else "Platform / DevOps"
        prevent = _PREVENT.get(str((data.get("proposal") or {}).get("action") or ""))
        out.append([team, f"owns {', '.join(named[:3])}: confirm the cause, then stop it happening again"
                    + (f" - {prevent}" if prevent else "")])
    changed = data.get("changed_by") or ""
    if changed:
        out.append(["Who changed it", (f"the newest change before the alert was {changed}: that person or "
                                       "pipeline should look first")])
    if data.get("code") or (data.get("evidence") or {}).get("recent_deploys"):
        out.append(["Developers", "the evidence holds a code finding or a recent deploy: review that change"])
    return out


_NEXT_STEP = {
    "rejected": "Blocked by the gate - nothing will run. A person has to look at this.",
    "escalated": "Escalated - a person decides. Nothing runs until then.",
    "approved_for_human": "Held for approval - WARDEN applies its fix plan only if an approver approves it.",
    "auto_safe": "No change proposed - recorded, nothing to run.",
}
_HANDED_OVER = "Handed to a person - WARDEN proposes no change and could not name a cause. Someone should look."


# --------------------------------------------------------------------------- build


# The report's last lines. What is added to a report after it is built goes before them (activities.notify).
# A13 (2026-10-16): it said "Nothing was executed against production by this tool" - untrue since WARDEN applies
# approved plans itself (D16).
CLOSING = ("---\n_WARDEN proposes and gates. It changes nothing except by applying a catalogue fix plan an approver "
           "approved._")


def build_report(
    alert: Alert,
    *,
    root_cause: RootCause | None = None,
    proposal: RemediationProposal | None = None,
    verdict: Verdict | None = None,
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

    # Undoing or pausing something in THIS environment is no change to replay in the higher ones: a report on a
    # dev-only rule someone disabled listed pre-prod and prod as places to "apply this fix" (live, 2026-10-12).
    promotion = _promotion_targets(alert, proposal, pol) if proposal and proposal.action not in _LOCAL_ONLY else []
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
            "via": alert.labels.get("via", ""),
        },
        "sources": _sources(alert, backend, ctx),
        "impact": symptoms(ctx),
        "error_lines": sum(1 for ln in ctx.logs if _IMPORTANT.search(ln)),
        "matched_signatures": [
            {"id": m.signature.id, "title": m.signature.title, "score": m.score,
             "category": m.signature.category, "maturity": m.signature.maturity,
             "root_cause": m.signature.root_cause}
            for m in signatures
        ],
        "patterns": [dataclasses.asdict(p) for p in patterns],
        "code": _code_findings(ctx.logs),
        "root_cause": None,
        "evidence": {
            "metrics": dict(ctx.metrics),
            "tool_errors": list(ctx.tool_errors),
            "key_log_lines": _key_log_lines(ordinary_logs),
            "checked": checked,
            "log_lines_read": len(ctx.logs),
            "returned": _returned(ctx),
            "recent_deploys": [dict(d) for d in ctx.recent_deploys],
            "timeline": _timeline(alert, ctx),
            "affected": {k: [[v, n] for v, n in vals] for k, vals in affected.items()},
        },
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
        "identifiers_shown": reveal_ids,
    }
    if root_cause:
        # Model-written text goes through the gate's G2: a claim WARDEN cannot verify ("no customer
        # impact", "resolved") is marked where it stands. The citations are the model's too, and the
        # verdict says whether they held (P13).
        data["root_cause"] = {
            "hypothesis": hedge(root_cause.hypothesis),
            "confidence": root_cause.confidence,
            "evidence": [hedge(e) for e in root_cause.evidence],
            "ruled_out": _ruled_out(root_cause, context),
            "weighed": _weighed(root_cause, context),
            "citations": [{"id": c.id, "quote": c.quote} for c in root_cause.citations],
            "grounded": not (verdict and "P13-UNGROUNDED" in verdict.policy_ids),
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
            "expected_effect": hedge(proposal.expected_effect),
        }
    if verdict:
        data["verdict"] = {
            "status": verdict.status.value,
            "policy_ids": verdict.policy_ids,
            "reasons": list(verdict.reasons),
            "observed": list(verdict.observed),
        }
    _withhold_unread(data, alert, ctx, proposal)
    data["changed_by"] = _changed_by(list(ctx.logs))
    data["who_acts"] = _who_acts(alert, data)

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


_FENCE_RUN = re.compile(r"`{3,}|~{3,}")


def _unfenced(text: str) -> str:
    """Break every run of 3+ backticks or tildes with zero-width spaces, so no line inside a code
    block can close it. `.replace("```", ...)` left a run of three in a run of four (independent
    review 2026-09-28)."""
    return _FENCE_RUN.sub(lambda m: "\u200b".join(m.group(0)), text)


def _code(lines: list[str], items: list[str]) -> None:
    # ⛔ An item holding ``` (a planted log line) would CLOSE the fence, and everything after it would
    # render as live markdown. The run of backticks is broken, and the line still reads the same.
    lines.append("```")
    lines.extend(_unfenced(item) for item in items)
    lines.append("```")


ALERT_SOURCES = {"cloudwatch": "CloudWatch alarm", "datadog": "Datadog monitor", "alertmanager": "Prometheus Alertmanager",
                 "aws-event": "AWS service event", "aws-health": "AWS Health"}


def _render_markdown(d: dict) -> str:
    a = d["alert"]
    ev = d["evidence"]
    v = d.get("verdict")
    p = d.get("proposal")
    lines: list[str] = []

    lines.append(f"# WARDEN incident report - {a['service']} ({a['environment']})")
    lines.append(f"Alert name {untrusted_inline(a['name'])}")
    # Where the alert came from (owner, 2026-10-15: "i dont know whats their sources are i mean datadog or grafana or
    # xray"): only WARDEN's own intake words, never a value a sender chose.
    if a.get("via") in ALERT_SOURCES:
        lines.append(f"Source **{ALERT_SOURCES[a['via']]}**")
    started = _parse_ts(a.get("started_at") or "")
    lines.append(f"Severity **{a['severity']}** | alert {_c(a['id'])} | started "
                 f"{both_times(started) if started else a.get('started_at') or 'unknown'}")
    if v:
        # A hand-off the gate lets stand is not "nothing to run": a person was asked to look (the runtime's first
        # report on today's code read "No change proposed - recorded, nothing to run" over an escalation, 2026-10-11).
        handed = bool(p) and p.get("action") == "escalate_to_human" and v["status"] == "auto_safe"
        offered = v["status"] == "escalated" and set(v.get("policy_ids") or []) == _OFFERED_UNDO
        lines.append("**Next step: " + (
            _HANDED_OVER if handed else
            "Held - a recent change was left unaddressed. WARDEN offers the undo of that change as a plan for a "
            "person to approve; nothing runs until then." if offered else
            _NEXT_STEP.get(v['status'], v['status'])) + "**")
    lines.append("")

    # ---- summary
    lines.append("## Summary")
    lines.append(f"- **Alert** (as written in the alert rule): {untrusted_inline(a['summary'])}")
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
    # The gate before the model's prose (register N4).
    if p:
        lines.append(f"- **Proposed**: {_c(p['action'])} on {_c(p['target'])}"
                     + (f" - gate: {_c(v['status'])}" if v else ""))
    if d["root_cause"]:
        lines.append(f"- **Diagnosis** (model, confidence {d['root_cause']['confidence']:.2f}): "
                     f"{d['root_cause']['hypothesis']}")
    lines.append("")

    # ---- who acts: on every report, before anything a person has to read to find it
    if d.get("who_acts"):
        lines.append("## Who acts now")
        lines.extend(f"- **{team}**: {what}." for team, what in d["who_acts"])
        lines.append("")

    # ---- what was read
    lines.append("## What WARDEN read")
    lines.extend(f"- {s}" for s in d["sources"])
    if ev.get("returned"):
        lines.append("- **Returned**: " + "; ".join(ev["returned"]) + ".")
    if ev["tool_errors"]:
        lines.append("")
        lines.append("**⚠ What WARDEN could NOT read** - the diagnosis was made without this:")
        lines.extend(f"- {_c(e)}" for e in ev["tool_errors"])
    lines.append("")

    # ---- the gate, before the model's text (register N4): read what the rules found first
    if v:
        lines.append("## Gate verdict  (deterministic)")
        lines.append(f"- **Status**: {_c(v['status'])}" + (f" - policies: {', '.join(v['policy_ids'])}"
                                                           if v["policy_ids"] else ""))
        lines.extend(f"  - {r}" for r in v["reasons"])
        if v.get("observed"):
            lines.append("- **Observed only, not enforced** (policies being measured before they decide anything):")
            lines.extend(f"  - {_c(o)}" for o in v["observed"])
        lines.append("")

    # ---- diagnosis
    if d["root_cause"]:
        rc = d["root_cause"]
        lines.append(f"## What WARDEN thinks happened  (model, confidence {rc['confidence']:.2f})")
        lines.append(rc["hypothesis"])
        if not rc["grounded"]:
            lines.append("")
            lines.append("**⚠ Not grounded** - the gate could not match this diagnosis to the evidence "
                         "(P13, reasons under the verdict). Read it as a guess.")
        if rc["citations"]:
            lines.append("")
            lines.append("**Cited evidence** (evidence id: quoted span):")
            _code(lines, [f"{c['id']}: {c['quote']}" for c in rc["citations"]])
        # A bare evidence id the citations above already show with its quote says nothing a second time: a report's
        # "Based on" was the four ids "C2, C18, M9, C1" and no word of reasoning (live, 2026-10-12).
        shown = {c["id"] for c in rc["citations"]}
        based_on = [e for e in rc["evidence"] if not (re.fullmatch(r"[A-Z]\d{1,4}", e.strip()) and e.strip() in shown)]
        if based_on:
            lines.append("")
            lines.append("**Based on:**")
            lines.extend(f"- {e}" for e in based_on)
        lines.append("")
        lines.extend(_narrowed(d))

    if d["patterns"]:
        lines.append("## Patterns detected in the evidence  (fixed checks, not the model)")
        for pat in d["patterns"]:
            lines.append(f"- **{pat['title']}** - seen: {_c(pat['seen'])}")
            lines.append(f"  {pat['likely_cause']}")
        lines.append("")

    for c in d.get("code") or []:
        lines.append(f"## Code-level finding  ({c['function']}, from its deployed package)")
        lines.append(f"- **{_c(str(c['file']) + ':' + str(c['line']))}** in {_c(c['in'])}: {_c(c['exception'])}")
        if c["source"]:
            lines.append("```python")
            # A source line is text from the deployed package; one holding ``` would end the block
            # and put what follows outside it (audit A-C-9).
            lines.extend(_unfenced(ln) for ln in c["source"])
            lines.append("```")
        lines.append(f"- **Developers**: start at {_c(str(c['file']) + ':' + str(c['line']))} in {_c(c['in'])} ({c['function']})"
                     + (" - the line marked `>|` is the one that raised." if c["source"] else "."))
        lines.append("")

    if d["matched_signatures"]:
        lines.append("## Known incident signatures that fit")
        for s in d["matched_signatures"]:
            lines.append(f"- {_c(s['id'])} **{s['title']}** ({s['category']}, score {s['score']}): {s['root_cause']}")
        lines.append("")

    # ---- the read-only checks WARDEN ran itself
    chk = ev.get("checked") or {}
    if any(chk.values()):
        lines.append("## Checked by WARDEN  (read-only, at alert time)")
        if chk["status"]:
            lines.append("**Container status** - how each failing container last died, and what it waits on now")
            lines.extend(f"- {_c(c)}" for c in chk["status"])
        if chk["previous"]:
            lines.append("**The crashed containers' own last output** (`logs --previous`)")
            _code(lines, chk["previous"][-12:])
        if chk["rollout"]:
            lines.append("**Rollout history** - newest first")
            lines.extend(f"- {_c(r)}" for r in chk["rollout"])
        lines.append("")

    # ---- the evidence itself
    if ev["metrics"]:
        lines.append("## Metrics at the time")
        lines.append(" | ".join(f"{_c(k)} = **{_num(val)}**" for k, val in sorted(ev["metrics"].items())))
        lines.append("")
    if ev["timeline"]:
        lines.append("## Timeline (UTC, local time in brackets)")
        lines.extend(f"- {_c(t)} {what}" for t, what in ev["timeline"])
        lines.append("")
    if ev["affected"]:
        lines.append("## Affected - as named in the evidence")
        for key, values in ev["affected"].items():
            shown = ", ".join(f"{_c(val)} ({n} line{'s' if n != 1 else ''})" for val, n in values[:5])
            if len(values) > 5:
                shown += f" and {len(values) - 5} more"
            lines.append(f"- **{key}**: {shown}")
        if not d.get("identifiers_shown"):
            # A9 (2026-10-16): it told every reader to set the variable, and the cloud runtime ignores it
            # (activities.notify passes show_identifiers=False).
            lines.append("_Identifiers are masked; secrets stay masked either way. A local `warden run` can show "
                         "tenant ids, emails and IPs with `WARDEN_REPORT_SHOW_IDENTIFIERS=true`._")
        lines.append("")
    if ev["key_log_lines"]:
        lines.append(f"## Key log lines  ({len(ev['key_log_lines'])} of {ev['log_lines_read']} read)")
        _code(lines, ev["key_log_lines"])
        lines.append("")

    # ---- proposal and gate
    if p:
        lines.append("## Proposed action")
        lines.append(f"- **Action**: {_c(p['action'])} -> {_c(p['target'])}")
        lines.append(f"- **Expected effect** (model): {p['expected_effect']}")
        lines.append(
            f"- **Blast radius**: {p['blast_radius_effective']} (enforced; the model claimed "
            f"{p['blast_radius']}) - reversible: {p['reversible_by_table']} per WARDEN's action "
            f"table (the model claimed {p['reversible']})"
        )
        lines.append("")

    # ---- the gate's own finding, before the follow-ups: an action the gate says cannot work must not read as a
    # recommendation. (The runbook and its risks that stood here printed commands; gone 2026-10-16.)
    contradiction = [r for r, pid in zip(v["reasons"], v["policy_ids"], strict=False)
                     if pid == "P11-ACTION-CONTRADICTS-EVIDENCE"] if v and p else []
    if contradiction:
        lines.append("## ⚠ Before you act")
        for reason in contradiction:
            lines.append(f"- ⛔ **The gate found this action cannot fix what the evidence shows.** {reason} "
                         "The follow-ups below say what would.")
        lines.append("")

    # ---- follow-ups by team
    teams = (("On-call - now", "oncall"), ("Developers", "developers"),
             ("Platform / DevOps", "platform"), ("DBA", "dba"), ("Prevention", "prevention"))
    # Only where a pattern has a follow-up for some team: a heading with nothing under it was printed once the one
    # follow-up a report had was left out (live, 2026-10-12).
    if any(pat[key] for pat in d["patterns"] for _, key in teams):
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
        lines.append(f"- **Outcome**: {_c(r['outcome'])}")
        lines.append(f"- {r['detail']}")
        if r["applied_change"]:
            lines.append(f"- {r['applied_change']}")
        lines.append("")

    # A10 (2026-10-16): a "Promotion - apply this fix to the higher environments" section stood here, pointing a
    # person at a manual replay with each environment's deploy role. WARDEN watches and fixes only the environments it
    # is installed in, through approved plans; the targets stay in the data for whoever plans a release.
    lines.append(CLOSING)
    return "\n".join(lines)


def _num(v: float) -> str:
    return f"{v:.4g}" if isinstance(v, float) else str(v)


_c = untrusted_inline  # every value rendered in inline code (independent review 2026-09-28, A-C-9)
