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


# What a key reports. Fourth review (2026-09-30, C-4): the zero rule hid real support 22 of 36 times
# (`restarts: 0 -> 6`, "could not obtain lock", "no free memory", "no response from primary") and still
# let 16 of 37 zeros support (`"restartCount": 0`, `== 0`, `(0)`, "never restarted", `exit code 0`).
# A key's value may follow a separator, quotes or brackets; a transition's LAST value is the one that
# counts; a zero, a false or a "never" says the thing did not happen.
_VALUE = r"(-?\d+(?:\.\d+)?(?:/\d+)?(?![\d.:])|(?:zero|none|false|no|null|never)(?![a-z]))"
_FIRST = re.compile(r"([\w \-\"']{0,30}?)\s*(?:==|=>|->|\u2192|=|:|\(|\bis\b)?\s*[\"'\[(]*\s*" + _VALUE)
_NEXT = re.compile(r"\s*[\"'\])]*\s*(?:\((?:was|from)[^)]{0,20}\)\s*)?,?\s*(?:->|=>|\u2192|\bnow\b|\bto\b|\bthen\b)"
                   r"\s*[\"'\[(]*\s*" + _VALUE)
_WORD_AFTER = re.compile(r"[\s\"'\])]*([a-z]+)(?![a-z_]*\s*[=:])")
# A zero that says WHEN, not how many: "restarted 0s ago" is a restart (fifth review, 2026-10-01).
_AGO = re.compile(r"\s*(?:s|sec|secs|seconds?|m|min|mins|minutes?|h|hrs?|hours?)?\s*ago\b")
# For scale_down a zero of USE is its evidence: "cpu: 0%" is an idle service (fifth review).
_USE = frozenset({"cpu", "memory", "utili"})
# A zero of something good is a shortage, not an absence: "0/3 passing", "cache hit: 0%", "no free
# memory", "0 free connection slots", "no spare capacity". Not for scale_down, whose evidence is spare
# capacity: "idle=0" is no reason to remove replicas.
_GOOD = frozenset({"pass", "passing", "passed", "ready", "healthy", "available", "free", "idle", "spare",
                   "up", "hit", "hits", "success", "successful", "succeeded", "ok", "alive", "remaining",
                   "left", "headroom", "live"})
_NEGATORS = frozenset({"no", "not", "zero", "without", "none", "never", "0"})
# A negation does not reach past a clause or a preposition: "could not connect then restarted", "no
# response from primary". "or" and "and" do not break it: "no restarts or OOM kills".
_BREAK = frozenset({"then", "but", "after", "before", "since", "from", "because", "so", "while", "when",
                    "for", "of", "in", "on", "at", "by", "with", "to", "via", "until"})


def _negated(before: str, key: str, shortage: bool) -> bool:
    """A negator right before the key - "not" only immediately ("not responding pod restarted" is a
    restart), the others across up to two words ("no pod restarts", "0 pods OOMKilled"). A number or a
    time is one word ("2.0 cpu", "at 12:00 replica lag" hold no "0")."""
    between: list[str] = []
    for w in reversed(re.findall(r"\d[\d.:/]*|\w[\w.-]*|[^\w\s]", before)[-3:]):
        if w in _NEGATORS or re.fullmatch(r"0+(?:\.0+)?", w):
            # "not" reaches only the next word, or past an article: "not a single restart" is none (fifth
            # review), "not responding pod restarted" is a restart.
            if w == "not" and any(b not in ("a", "an", "the", "single", "one", "any") for b in between):
                return False
            return not (shortage and (key in _GOOD or any(b in _GOOD for b in between)))
        if not re.fullmatch(r"[\w-]+", w) or w in _BREAK:
            return False
        between.append(w)
    return False


def _reports_none(after: str, key: str, shortage: bool) -> bool:
    """The key is followed by a value, and that value (the last of a transition) says none."""
    m = _FIRST.match(after)
    if not m:
        return False
    phrase, value, pos = m.group(1), m.group(2), m.end()
    if _AGO.match(after, pos):
        return False
    if not shortage and key in _USE and not _GOOD & set(re.findall(r"[a-z]+", phrase)):
        return False  # "cpu: 0%" is idle; "cpu idle: 0" is not
    while nxt := _NEXT.match(after, pos):
        value, pos = nxt.group(1), nxt.end()
    word = _WORD_AFTER.match(after, pos)
    # A good word after the value counts only after a fraction ("0/3 passing"): after a plain zero it is
    # another field ("restarts: 0 ok") - fifth review, 2026-10-01.
    if shortage and (key in _GOOD or _GOOD & set(re.findall(r"[a-z]+", phrase))
                     or (word and word.group(1) in _GOOD and "/" in value)):
        return False
    number = value.split("/")[0]
    return float(number) == 0 if number[-1].isdigit() else True


def _supports(quote: str, key: str, shortage: bool = True) -> bool:
    """`key` starts a word in `quote` (audit A-C-6: "ready" in "already", "lag" in "flag"), a short key
    also ends one (review 2026-09-28: "miss" in "missing"), and a measurement or a phrase that says
    "none" does not count (`crashloop_containers=0`, `OOMKilled=false`, "no OOMKilled events" are
    evidence of NO such thing)."""
    end = r"(?:s|es|ed)?(?![a-z])" if len(key) <= 4 else ""
    for m in re.finditer(rf"(?<![a-z0-9]){re.escape(key)}{end}", quote):
        if _negated(quote[:m.start()], key, shortage):
            continue
        if key.startswith("not ") or not _reports_none(quote[m.end():], key, shortage):
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
    shortage = proposal.action is not ActionKind.scale_down
    if any(_supports(q, k, shortage) for q in quotes for k in keys):
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
# ... after anything but a letter or digit (third review: `orders "--all"`, `(-A)`, `orders,--all`;
# fourth review, 2026-09-30, C-6: `deployment=-A`, `orders/--all`, `orders:-A`, `orders@-A`).
_FLAGLIKE = re.compile(r"(?:^|[^\w])[" + re.escape(_DASHES) + r"]{1,2}[A-Za-z]")
# Characters a resource name never holds and a reader may not see: format, combining and private-use
# marks, and the blank "letters" (Hangul fillers, braille blank) - third review: U+3164, U+115F,
# U+034F, U+FE0F and U+2800 hid a flag once only Cf was removed.
_BLANKS = frozenset("\u115f\u1160\u3164\uffa0\u2800")


def _invisible(ch: str) -> bool:
    return unicodedata.category(ch) in ("Cf", "Mn", "Me", "Co", "Cn", "Cc", "Zl", "Zp") or ch in _BLANKS
# Characters ordinary model prose puts in a target - dashes, curly quotes, x, >=, <=, an arrow, an ellipsis
# (fifth review, 2026-10-01: "checkout \u2014 revert to revision 6" was refused). A dash before a letter is
# still a flag (_FLAGLIKE).
_PROSE = frozenset("\u2014\u2013\u2019\u2018\u201c\u201d\u00d7\u2265\u2264\u2192\u2026")
_SHELL = re.compile(r"[;|&$\\`<>]")
# Arrows and redaction placeholders are how targets are written; any other `<` or `>` is a redirect.
_NOT_SHELL = re.compile(r"<[A-Z][A-Z0-9]*_\d+>|->|=>")
# A namespace or cluster that qualifies a resource: `(namespace=shop)`, `namespace warden-pg`, `ns/x`.
_SCOPE = re.compile(r"[\s,(]*\b(?:namespace|ns|cluster)\b\s*[=:/ ]\s*[\"']?[\w.-]+[\"']?\s*\)?\s*,?", re.IGNORECASE)
# Words that describe a resource rather than name one: a second of these is not a second resource.
_DESCRIPTORS = frozenset({
    "ecs", "ecs-service", "eks", "k8s", "service", "svc", "deploy", "sts", "rds", "aurora", "sqs", "sns",
    "dynamodb", "redis", "elasticache", "postgres", "postgresql", "mysql", "version", "revision",
    "prod", "staging", "dev"})
# A command inside a target is a second instruction, whatever resource it also names:
# "orders kubectl delete ns warden-pg".
# Whole words only: `public.ecr.aws` in an image name is not the aws CLI.
_COMMAND_WORDS = re.compile(r"(?:^|\s)(?:kubectl|aws|gcloud|az|helm|psql|redis-cli|mysql|rm|delete|drop|truncate|"
                            r"curl|wget|sh|bash|sudo|exec|eval)(?=\s|$)", re.IGNORECASE)
_RESOURCE_KINDS = frozenset({"deployment", "namespace", "service", "statefulset", "daemonset", "pod", "function",
                             "lambda", "cluster", "table", "queue", "topic", "rule", "instance", "database", "db"})


def target_problem(proposal: RemediationProposal, inventory: set[str],
                   scopes: frozenset[str] | set[str] = frozenset()) -> str | None:
    """`scopes`: the incident's namespace and cluster names. A target that names only one of them
    names a whole namespace or cluster, not a resource."""
    # A known name does not excuse shell syntax around it: `checkout; kubectl delete ns prod` named
    # `checkout` and passed (2026-09-27 audit). Redirects too (fourth review: `orders > /tmp/x`).
    if _SHELL.search(_NOT_SHELL.sub(" ", proposal.target)):
        return f"target {proposal.target!r} contains shell syntax"
    # Resource names are ASCII. Characters outside every dash category still read as one (fourth
    # review, 2026-09-30, C-6: U+2043, U+2500, U+30FC, U+4E00, U+02C9, U+FF70 before `A` or `all`).
    if any(ord(ch) > 127 and ch not in _PROSE and not _invisible(ch) for ch in _LEADING.sub("", proposal.target)):
        return f"target {proposal.target!r} holds characters a resource name never does"
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
    # `deployment=orders,payments`; fourth review: `orders-.+`, `orders-%`, `{orders,payments}`,
    # `orders payments`, `orders and payments`), and not a whole namespace or cluster
    # (`namespace=warden-pg`, `namespace/warden-pg`, `(namespace=warden-pg)`, "all pods in warden-pg").
    # A namespace or cluster that only qualifies a resource is looked past: `deployment=checkout,
    # namespace=shop` and `namespace=shop deployment=checkout` name one deployment.
    if re.search(r"[*?%{}]|\.[+*]|\[[^\]]*\]", plain):
        return f"target {proposal.target!r} is a pattern or a list, not one resource"
    if _COMMAND_WORDS.search(plain):
        return f"target {proposal.target!r} holds a command, not one resource"
    rest = _SCOPE.sub(" ", plain)
    # What stands after an arrow is the state to return to (`checkout -> revert to <image>`), not a
    # second resource; what is in parentheses describes the one named.
    outside = re.split(r"->|=>|\u2192", re.sub(r"\([^)]*\)", " ", rest))[0]
    if re.search(r"\ball\b|\bevery\b", plain, re.IGNORECASE):
        return f"target {proposal.target!r} names a whole namespace or cluster"
    named = {t for t in tokens(outside) & inventory
             if not t.isdigit() and t.lower() not in _RESOURCE_KINDS | _DESCRIPTORS and t not in scopes}
    if not named and (rest != plain or tokens(plain) & set(scopes)):
        return f"target {proposal.target!r} names a whole namespace or cluster"
    if re.search(r",|\band\b|=\s*[(\[]", outside, re.IGNORECASE) or re.search(r"=\s*[(\[]", rest) or len(named) > 1:
        return f"target {proposal.target!r} is a pattern or a list, not one resource"
    found = tokens(proposal.target)
    if not found & inventory:
        return f"target {proposal.target!r} names no resource in the inventory"
    unknown = sorted(t for t in found - inventory if "-" in t or "_" in t)
    if unknown:
        return f"target {proposal.target!r} names {', '.join(unknown)}, which is not in the inventory"
    return None
