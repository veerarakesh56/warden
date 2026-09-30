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
import unicodedata

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
    # Not "config": every CONFIG line starts with it, so any config line supported a rollback.
    ActionKind.rollback_deploy: ("deploy", "revision", "image", "version", "rollout", "sha", "release",
                                 "alias"),
    # Capacity signals only (audit A-C-6): "error", "5xx", "timeout", "request", "running",
    # "latency", "duration" and "lag" are symptoms of almost anything - a routine Lambda REPORT line
    # has a duration - so citing them said nothing about whether MORE replicas help.
    ActionKind.scale_up: ("memory", "oom", "throttl", "cpu", "concurrency", "pool", "connection", "queue",
                          "visible", "backlog", "capacity", "invocation", "saturat", "pending", "unready",
                          "not ready"),
    # Not "replica" or "running": replica LAG is a reason NOT to scale down (P11), and it passed here.
    ActionKind.scale_down: ("cpu", "memory", "capacity", "idle", "cost", "utili", "underused", "over-provisioned"),
    ActionKind.restart_pods: ("restart", "crash", "backoff", "back-off", "oom", "killed", "unhealthy",
                              "probe", "exit", "unready", "not ready", "hang", "stuck", "leak", "out of memory"),
    ActionKind.terminate_connections: ("idle_in_transaction", "idle in transaction", "lock", "deadlock", "block",
                                       "connection", "pool", "long_running", "long-running", "stuck",
                                       "session"),
    ActionKind.failover_replica: ("replica", "lag", "failover", "unreachable", "refused", "timeout",
                                  "writer", "primary", "aurora"),
    ActionKind.clear_cache: ("cache", "redis", "evict", "stale", "hit", "miss", "memcache"),
}


# A measurement that says "none": zero, false, none, no. The key's word group may run on before the
# `=` - after the camelCase split `restartCount=0` reads `restart count=0` (third review, 2026-09-30:
# 18 of 24 zero-valued quotes supported an action again).
_NOTHING = re.compile(r"[\w ]{0,30}?\s*[=:]\s*(?:0+(?:\.0+)?|false|none|no|null)(?![\w.])")
# ... or a negation just before it: "no OOMKilled events", "without restarts", "0 crash loops".
_NEGATED = re.compile(r"(?:^|[^\w])(?:no|not|zero|without|0)\s+(?:[\w-]+\s+){0,2}$")


def _supports(quote: str, key: str) -> bool:
    """`key` starts a word in `quote` (audit A-C-6: "ready" in "already", "lag" in "flag"), a short key
    also ends one (review 2026-09-28: "miss" in "missing"), and a measurement or a phrase that says
    "none" does not count (`crashloop_containers=0`, `OOMKilled=false`, "no OOMKilled events" are
    evidence of NO such thing)."""
    end = r"(?:s|es|ed)?(?![a-z])" if len(key) <= 4 else ""
    for m in re.finditer(rf"(?<![a-z0-9]){re.escape(key)}{end}", quote):
        if key.startswith("not "):
            if not _NEGATED.search(quote[:m.start()]):
                return True
        elif not _NOTHING.match(quote[m.end():]) and not _NEGATED.search(quote[:m.start()]):
            return True
    return False


_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def action_support_problem(root_cause: RootCause, proposal: RemediationProposal,
                           items: dict[str, Item]) -> str | None:
    keys = ACTION_EVIDENCE.get(proposal.action)
    if not keys:
        return None
    # The QUOTED span, not the whole item: the model must quote the words that support the action
    # (P13 checks the quote is really in the item). Not a T item: WARDEN's own "connection failed"
    # wording supported scale_up and terminate_connections (independent review 2026-09-28).
    # Words split at camelCase first: WARDEN's own facts spell codes `OOMKilled`, `exitCode=137`,
    # `CPUUtilization`, and none of those "contained" oom, exit or cpu (second review, 2026-09-30).
    quotes = [_CAMEL.sub(" ", c.quote).lower() for c in root_cause.citations
              if c.id.strip().strip("[]") in items and not c.id.strip().strip("[]").startswith("T")]
    if any(_supports(q, k) for q in quotes for k in keys):
        return None
    return (f"none of the cited evidence bears on {proposal.action.value} "
            f"(it names none of: {', '.join(keys[:6])}...)")


# Command separators and substitution only. Parentheses and "->" are how models describe a target
# (`lambda:warden-dev-checkout (version 7 -> 6)`, a correct live answer), and "<...>" is a
# redaction placeholder.
_LEADING = re.compile(r"^[\s\u200b-\u200f\ufeff]+")
# A flag anywhere in the target - at the start or after a space - with any dash a CLI or a person
# might read as one (review 2026-09-28: `orders --all`, `orders -A`, and U+2010-2015, U+2212, U+FE63,
# U+FF0D before a letter).
# Every Unicode dash (category Pd) and the minus signs a person might read as one (third review:
# U+02D7 and U+2E3A passed).
_DASHES = "".join(sorted({chr(c) for c in range(0x10000) if unicodedata.category(chr(c)) == "Pd"}
                         | {"\U00010ead", "\u2212", "\u02d7", "\u2796", "\ufe63", "\uff0d"}))
# ... after a space, a quote, a bracket or a comma (third review: `orders "--all"`, `(-A)`, `orders,--all`).
_FLAGLIKE = re.compile(r"(?:^|[\s\"'`(\[{,;<])[" + re.escape(_DASHES) + r"]{1,2}[A-Za-z]")
# Characters a resource name never holds and a reader may not see: format, combining and private-use
# marks, and the blank "letters" (Hangul fillers, braille blank) - third review: U+3164, U+115F,
# U+034F, U+FE0F and U+2800 hid a flag once only Cf was removed.
_BLANKS = frozenset("\u115f\u1160\u3164\uffa0\u2800")


def _invisible(ch: str) -> bool:
    return unicodedata.category(ch) in ("Cf", "Mn", "Me", "Co", "Cn", "Cc", "Zl", "Zp") or ch in _BLANKS
_SHELL = re.compile(r"[;|&$\\`]")
_RESOURCE_KINDS = frozenset({"deployment", "namespace", "service", "statefulset", "daemonset", "pod", "function",
                             "lambda", "cluster", "table", "queue", "topic", "rule", "instance", "database", "db"})


def target_problem(proposal: RemediationProposal, inventory: set[str]) -> str | None:
    # A known name does not excuse shell syntax around it: `checkout; kubectl delete ns prod` named
    # `checkout` and passed (2026-09-27 audit).
    if _SHELL.search(proposal.target):
        return f"target {proposal.target!r} contains shell syntax"
    # A target is a resource name. `-n kube-system` or `--all` would be read by a CLI as a flag, and
    # `x=y` as an assignment or a selector (audit A-C-25).
    # models.inert() prefixes a leading "-" with a zero-width space so no CLI reads it as a flag;
    # the name is still not a resource name, so look past that prefix.
    # Invisible format characters go first: a soft hyphen or U+180E before `-n` hid the flag
    # (second review, 2026-09-30). `kind=name` with a resource kind is a name, as models write it
    # (`deployment=checkout (namespace=shop)`); any other `x=y` is a selector or an assignment.
    # models.inert() puts a zero-width space before a leading "-": that one is looked past (it is
    # still a flag). Any other invisible character refuses the target outright.
    unprefixed = _LEADING.sub("", proposal.target)
    if any(_invisible(ch) for ch in unprefixed):
        return f"target {proposal.target!r} contains invisible characters"
    plain = unprefixed
    assigned = re.findall(r"([\w.-]+)=", plain)
    if (_FLAGLIKE.search(plain) or plain.count("=") != len(assigned)
            or any(k.lower() not in _RESOURCE_KINDS for k in assigned)):
        return f"target {proposal.target!r} looks like a flag or an assignment, not a resource name"
    # One named resource, not a pattern or a list (third review: `pod=orders-*`, `namespace=*`,
    # `deployment=orders,payments`), and not a whole namespace or cluster (`namespace=warden-pg`).
    if re.search(r"[*?]", plain) or re.search(r"=[^\s()=]*,", plain):
        return f"target {proposal.target!r} is a pattern or a list, not one resource"
    if re.match(r"\s*(?:namespace|cluster)\s*=", plain, re.IGNORECASE):
        return f"target {proposal.target!r} names a whole namespace or cluster"
    found = tokens(proposal.target)
    if not found & inventory:
        return f"target {proposal.target!r} names no resource in the inventory"
    unknown = sorted(t for t in found - inventory if "-" in t or "_" in t)
    if unknown:
        return f"target {proposal.target!r} names {', '.join(unknown)}, which is not in the inventory"
    return None
