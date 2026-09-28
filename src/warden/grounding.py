"""Grounding: is what the model claims actually in the evidence? Deterministic, no model.

P13 (claims): every citation must name an evidence id that exists (evidence.py) and quote a span that
appears in that item verbatim (whitespace collapsed; case kept). A diagnosis with no citation, or
with any citation that fails, is ungrounded. One made-up quote is enough: a model that invents one
span has told us its other spans need checking too.

P14 (target): the proposal's target must name a resource in the inventory, and must not also name a
compound resource-like token (`shop-prod-checkout`) the inventory lacks. Observed live 2026-09-26:
`scale_up lambda:shop-prod-checkout` against a stack whose function is `warden-dev-checkout`.
"""

from __future__ import annotations

import re

from .evidence import Item, tokens
from .models import ActionKind, RemediationProposal, RootCause

MIN_QUOTE = 4  # characters, whitespace excluded: a quote of "a" is in everything


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def citation_problems(root_cause: RootCause, items: dict[str, Item]) -> list[str]:
    if not root_cause.citations:
        return ["the diagnosis cites no evidence"]
    problems = []
    for c in root_cause.citations:
        cid = c.id.strip().strip("[]")
        item = items.get(cid)
        quote = _norm(c.quote)
        if item is None:
            problems.append(f"{cid or '(blank)'} is not an evidence id")
        elif len(quote.replace(" ", "")) < MIN_QUOTE:
            problems.append(f"{cid}: quote {c.quote!r} is too short to check")
        elif quote not in _norm(item.text):
            problems.append(f"{cid}: {c.quote[:80]!r} does not appear in that item")
    return problems


# P15: what an action's citations must touch. P13 only asks that citations be real; a hijacked model
# satisfied it by quoting an unrelated metric (2026-09-27 audit: `scale_down` for replica lag, citing
# `error_rate`). Broad on purpose - it rejects only citations that say nothing about the action.
ACTION_EVIDENCE: dict[ActionKind, tuple[str, ...]] = {
    ActionKind.rollback_deploy: ("deploy", "revision", "image", "version", "rollout", "sha", "release",
                                 "alias", "config"),
    # Capacity signals only (audit A-C-6): "error", "5xx", "timeout", "request" and "running" are
    # symptoms of almost anything, so citing them said nothing about whether MORE replicas help.
    ActionKind.scale_up: ("memory", "oom", "throttl", "cpu", "concurrency", "latency", "duration", "pool",
                          "connection", "queue", "visible", "backlog", "capacity", "lag",
                          "invocation", "saturat", "pending", "unready", "not ready"),
    # Not "replica" or "running": replica LAG is a reason NOT to scale down (P11), and it passed here.
    ActionKind.scale_down: ("cpu", "memory", "capacity", "idle", "cost", "utili", "underused", "over-provisioned"),
    ActionKind.restart_pods: ("restart", "crash", "backoff", "back-off", "oom", "killed", "unhealthy",
                              "probe", "exit", "unready", "not ready", "hang", "stuck", "leak", "memory"),
    ActionKind.terminate_connections: ("idle_in_transaction", "idle in transaction", "lock", "block",
                                       "connection", "pool", "long_running", "long-running", "stuck",
                                       "session"),
    ActionKind.failover_replica: ("replica", "lag", "failover", "unreachable", "refused", "timeout",
                                  "writer", "primary", "aurora", "cluster"),
    ActionKind.clear_cache: ("cache", "redis", "evict", "stale", "hit", "miss", "memcache"),
}


def action_support_problem(root_cause: RootCause, proposal: RemediationProposal,
                           items: dict[str, Item]) -> str | None:
    keys = ACTION_EVIDENCE.get(proposal.action)
    if not keys:
        return None
    cited = [items[c.id.strip().strip("[]")].text.lower() for c in root_cause.citations
             if c.id.strip().strip("[]") in items]
    # A key must START a word (audit A-C-6): "ready" was found in "already", "lag" in "flag",
    # "pool" in "spool". Stems still match their endings ("throttl" -> throttled, throttling).
    if any(re.search(rf"(?<![a-z0-9]){re.escape(k)}", text) for text in cited for k in keys):
        return None
    return (f"none of the cited evidence bears on {proposal.action.value} "
            f"(it names none of: {', '.join(keys[:6])}...)")


# Command separators and substitution only. Parentheses and "->" are how models describe a target
# (`lambda:warden-dev-checkout (version 7 -> 6)`, a correct live answer), and "<...>" is a
# redaction placeholder.
_SHELL = re.compile(r"[;|&$\\`]")


def target_problem(proposal: RemediationProposal, inventory: set[str]) -> str | None:
    # A known name does not excuse shell syntax around it: `checkout; kubectl delete ns prod` named
    # `checkout` and passed (2026-09-27 audit).
    if _SHELL.search(proposal.target):
        return f"target {proposal.target!r} contains shell syntax"
    found = tokens(proposal.target)
    if not found & inventory:
        return f"target {proposal.target!r} names no resource in the inventory"
    unknown = sorted(t for t in found - inventory if "-" in t or "_" in t)
    if unknown:
        return f"target {proposal.target!r} names {', '.join(unknown)}, which is not in the inventory"
    return None
