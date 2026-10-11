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

from .evidence import PATH, Item, tokens
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
    # G9-D. Never a trusted line's own first word (CONFIG, STATE, SECRET, RULE, QUEUE, ...): every such line would
    # support the action. CHANGE is kept for the two actions about changes: a change line does bear on them.
    # Only words about a configuration or a flag (independent review 2026-10-10, review-e H1: "version" and CHANGE
    # matched a Lambda deploy line, and a days-old configuration was reverted).
    ActionKind.revert_config: ("appconfig", "feature flag", "feature-flag", "configuration profile", "toggle"),
    # Not "loop" (CrashLoopBackOff), not "stopped" (an ECS task stopped): neither says a flow is the harm or is off
    # (independent review 2026-10-10, H1).
    ActionKind.pause_flow: ("poison", "recurs", "storm", "runaway", "flood", "redeliver", "receive count",
                            "dead-letter", "dlq", "duplicat", "cascad", "overload"),
    ActionKind.resume_flow: ("disabled", "paused", "inactive", "suspended", "not enabled"),
    ActionKind.shift_traffic: ("zone", "zonal", "az", "impair", "unhealthy host", "unhealthyhost", "outage"),
    ActionKind.redrive_messages: ("dlq", "dead-letter", "deadletter", "redriv", "maxreceive", "receive count"),
    # Not "query" or "statement" alone: a DynamoDB Query line is no runaway (review H1).
    ActionKind.cancel_query: ("long_running", "long-running", "runaway", "running for", "queued", "workgroup", "athena",
                              "scanned"),
    # Not "limit" (a container's memory limit, a database's connection limit), not "rate" (it matched inside
    # error_rate), "exceeded" or "too many" ("too many connections"): none of them is a request throttle (qualification
    # 2026-10-10 and review H1).
    ActionKind.raise_limit: ("throttl", "quota", "429", "burst"),
    ActionKind.freeze_changes: ("deploy", "release", "pipeline", "commit", "change", "rollout"),
    # G10-D: the recorded write itself - a CHANGE line's event name. Never "change": every CHANGE line begins with it.
    ActionKind.revert_change: ("revoke", "authorize", "disable", "modifysecuritygrouprules", "deleteroute",
                               "replaceroute", "updateservice", "putfunctionconcurrency", "deletefunctionconcurrency",
                               "setdesiredcapacity", "updateautoscalinggroup", "updatestage", "deregistertargets",
                               "updatefunctionconfiguration", "setqueueattributes",
                               "decreasestreamretentionperiod"),
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
_AGO = re.compile(r"\s*(?:ms|s|sec|secs|seconds?|m|min|mins|minutes?|h|hrs?|hours?|d|days?|w|weeks?)?\s*ago\b")
# For scale_down a zero of USE is its evidence: "cpu: 0%" is an idle service (fifth review).
_USE = frozenset({"cpu", "memory", "utili"})
# A zero of something good is a shortage, not an absence: "0/3 passing", "cache hit: 0%", "no free
# memory", "0 free connection slots", "no spare capacity". Not for scale_down, whose evidence is spare
# capacity: "idle=0" is no reason to remove replicas.
_GOOD = frozenset({"pass", "passing", "passed", "ready", "healthy", "available", "free", "idle", "spare",
                   "up", "hit", "hits", "success", "successful", "succeeded", "ok", "alive", "remaining",
                   "left", "headroom", "live"})
# After a plain zero, these say how much of the measure is left - a shortage ("connections: 0 free"); a
# status word after it ("restarts: 0 ok") is another field (sixth review, 2026-10-01). Only of a measure that is
# capacity: "queue: 0 remaining" and "restarts: 0 left" are none of a bad thing, and "connections: 0 idle" none
# idle (seventh review, 2026-10-01: all three supported an action).
_QUANTITY = frozenset({"free", "available", "left", "remaining", "spare", "headroom", "passing", "passed"})
_CAPACITY = ("memory", "cpu", "concurrency", "pool", "connection", "capacity", "probe", "slot")
# Words that make a measure a count of something bad, whatever capacity word it holds: "blocked connections: 0
# remaining" is no blocked connection, "probe failures: 0 left" no failure (eighth review, 2026-10-01).
# By stem, so every inflection counts: `leaked`, `throttling`, `timed out`, `failing`, `evictions` named no bad
# thing as whole words (register R9-O3).
_BAD_STEMS = ("block", "fail", "error", "erroring", "leak", "kill", "oom", "deadlock", "throttl", "reject", "drop",
              "timeout", "timed", "wait", "stuck", "refus", "lost", "crash", "evict", "pending", "queued")


def _bad(words: set[str]) -> bool:
    return any(w.startswith(_BAD_STEMS) for w in words)
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
    words = re.findall(r"\d[\d.:/]*%?|\w[\w.-]*|[^\w\s]", before)
    for i, w in enumerate(reversed(words[-5:])):
        if w in _NEGATORS or re.fullmatch(r"0+(?:\.0+)?%?", w):  # "0% idle" is no idle
            # "not" reaches past a determiner and the words after it - "not a single pod restarted", "not even
            # one restart" are none (fifth and sixth reviews) - but no further than the next word otherwise:
            # "not responding pod restarted" is a restart. The others reach across two words.
            if w == "not":
                if between and between[-1] not in ("a", "an", "the", "single", "one", "any", "even", "lone"):
                    return False
            elif i > 2:
                return False
            return not (shortage and (key in _GOOD or any(b in _GOOD for b in between)))
        if not re.fullmatch(r"[\w-]+", w) or w in _BREAK:
            return False
        between.append(w)
    return False


def _reports_none(after: str, key: str, shortage: bool, before: str = "", idle_short: bool = False) -> bool:
    """The key is followed by a value, and that value (the last of a transition) says none."""
    m = _FIRST.match(after)
    if not m:
        return False
    phrase, value, pos = m.group(1), m.group(2), m.end()
    if _AGO.match(after, pos):
        return False
    if not shortage and key in _USE and not _GOOD & set(re.findall(r"[a-z]+", phrase)):
        # A numeric zero of USE is scale_down's evidence ("cpu: 0%"); a missing value ("cpu: null", "no data")
        # or headroom ("0 MiB free") is not (sixth review, 2026-10-01).
        following = set(re.findall(r"[a-z]+", after[pos:pos + 24])[:3])  # "0 MiB free" reads "0 mi b free"
        return not (value[:1].isdigit() and float(value.split("/")[0]) == 0 and not _GOOD & following)
    while nxt := _NEXT.match(after, pos):
        # After "then", a number followed by another word is another field ("0, then 2 replicas added"), unless
        # the word is the key itself ("0, then 6 restarts") - sixth review, 2026-10-01.
        later = re.match(r"[\s\"'\])]*([a-z]+)", after[nxt.end():])
        if re.search(r"\bthen\b", nxt.group(0)) and later and not later.group(1).startswith(key[:4]):
            break
        value, pos = nxt.group(1), nxt.end()
    word = _WORD_AFTER.match(after, pos)
    # A good word after the value: after a fraction it is a shortage ("0/3 passing"); after a plain zero only a
    # quantity word is ("0 free"), a status word is another field ("restarts: 0 ok") - fifth and sixth reviews.
    after_word = word.group(1) if word else ""
    # A quantity word after a zero is a shortage only of a measure of capacity - the key, or a capacity word
    # between it and the value ("queue slots: 0 free") - with no bad thing named beside it; "idle" only where an
    # idle pool is the shortage (scale_up), not where idle sessions are the fault (eighth review).
    measured = set(re.findall(r"[a-z]+", f"{before} {phrase}"))
    capacity = key.startswith(_CAPACITY) or any(w.startswith(_CAPACITY) for w in re.findall(r"[a-z]+", phrase))
    quantity = after_word in _QUANTITY or (idle_short and after_word == "idle")
    if shortage and (key in _GOOD or _GOOD & set(re.findall(r"[a-z]+", phrase))
                     or (after_word in _GOOD and "/" in value)
                     or (quantity and capacity and not _bad(measured))):
        return False
    number = value.split("/")[0]
    return float(number) == 0 if number[-1].isdigit() else True


def _supports(quote: str, key: str, shortage: bool = True, idle_short: bool = False) -> bool:
    """`key` starts a word in `quote` (audit A-C-6: "ready" in "already", "lag" in "flag"), a short key
    also ends one (review 2026-09-28: "miss" in "missing"), and a measurement or a phrase that says
    "none" does not count (`crashloop_containers=0`, `OOMKilled=false`, "no OOMKilled events" are
    evidence of NO such thing)."""
    end = r"(?:s|es|ed)?(?![a-z])" if len(key) <= 4 else ""
    for m in re.finditer(rf"(?<![a-z0-9]){re.escape(key)}{end}", quote):
        if _negated(quote[:m.start()], key, shortage):
            continue
        # The words naming the measure: the two before the key and the word the key starts ("blocked") - in the
        # key's own clause: "errors: 12, connections: 0 free" is a shortage of connections (register R9-O3).
        clause = re.split(r"[,;()\[\]|]", quote[:m.start()])[-1]
        before = " ".join([*re.findall(r"[a-z]+", clause)[-2:], re.match(r"[a-z]*", quote[m.start():])[0]])
        if key.startswith("not ") or not _reports_none(quote[m.end():], key, shortage, before, idle_short):
            return True
    return False


_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
# A CHANGE line as aws_stack._read_changes writes it: when, which event, on what.
_CHANGE_AT = re.compile(r"^CHANGE (\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ) \S+ (\S+) on (\S+) by ")


def _changed_again(supporting: list[str], items: dict[str, Item]) -> str | None:
    """WARDEN undoes only the LATEST change to a resource: a cited change the evidence shows written over since - a new
    version published after a configuration change, say (G10 held-out, 2026-10-10, g10-082) - is not one. Tag writes
    beside the resource do not count."""
    lines = [m.groups() for i in items.values() if (m := _CHANGE_AT.match(i.text))]
    why = None
    for cid in supporting:  # the cited changes that support the revert: one that is the latest is enough
        m = _CHANGE_AT.match(items[cid].text)
        if not m:
            return None  # not a CHANGE line WARDEN can date: as before
        at, _, resource = m.groups()
        later = [e for t, e, r in lines if r == resource and t > at and not e.startswith(("TagResource", "UntagResource"))]
        if not later:
            return None
        why = f"{resource} was changed again after the cited change ({later[0]}): only the latest change is undone"
    return why


# The fields a revert family undoes, for the events whose request may set others: a CHANGE line names the request's
# fields (aws_stack._request_fields), and a revert is supported only when one of these is among them.
REVERT_FIELDS = {"updateservice": ("desiredcount",), "setdesiredcapacity": ("desiredcapacity",),
                 "updateautoscalinggroup": ("desiredcapacity", "minsize", "maxsize"),
                 "updatefunctionconfiguration": ("timeout", "memorysize", "ephemeralstorage"),
                 "putfunctionconcurrency": ("reservedconcurrentexecutions",), "setqueueattributes": ("attributes",)}
# The CloudTrail events that are a deploy - what a rollback undoes.
_DEPLOY_EVENTS = ("updatefunctioncode", "publishversion", "updatealias", "createdeployment", "registertaskdefinition")
_REQUEST_NAMED = re.compile(r" request=([A-Za-z0-9,]{1,600})$")
# A CloudTrail event name as a CHANGE line writes it: CamelCase words, and the API version Lambda and CloudFront append.
_EVENT_NAME = re.compile(r"(?<![A-Za-z0-9])(?:[A-Z][a-z]+){2,}[A-Za-z0-9_]*(?![A-Za-z0-9])")


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
    cited = [c.quote for c in root_cause.citations
             if c.id.strip().strip("[]") in items and not c.id.strip().strip("[]").startswith("T")]
    if proposal.action is ActionKind.revert_change:
        # An API's name, never a measure (G10 held-out baseline, 2026-10-10: the keys are run-together event names, but
        # quotes were split at camelCase first, and the "none" rule read `sg-0d4c` as a zero - P15 held back every
        # revert WARDEN can carry out). A CamelCase word in the quote holding a family's key supports it.
        ok = []
        for c in root_cause.citations:
            item = items.get(c.id.strip().strip("[]"))
            if item is None or c.id.strip().strip("[]").startswith("T"):
                continue
            named = _REQUEST_NAMED.search(item.text)
            fields = set(named.group(1).lower().split(",")) if named else None
            for w in (w.lower() for w in _EVENT_NAME.findall(c.quote)):
                key = next((k for k in keys if k in w), None)
                # The request's fields, when the line holds them, must include one the family undoes: a forced
                # redeploy's UpdateService names no desiredCount (G10 held-out, 2026-10-10).
                if key and (fields is None or key not in REVERT_FIELDS or fields & set(REVERT_FIELDS[key])):
                    ok.append(c.id.strip().strip("[]"))
        if not ok:
            return f"none of the cited evidence names a write revert_change undoes (none of: {', '.join(keys[:6])}...)"
        return _changed_again(list(dict.fromkeys(ok)), items)
    if proposal.action is ActionKind.rollback_deploy and any(
            c.id.strip().strip("[]").startswith("D") and c.id.strip().strip("[]") in items for c in root_cause.citations):
        return None  # WARDEN's own record of the deploy in the window (G10 held-out: `previous=41` quoted from it)
    if proposal.action is ActionKind.rollback_deploy and any(
            w.lower().startswith(_DEPLOY_EVENTS) for q in cited for w in _EVENT_NAME.findall(q)):
        return None  # the deploy's own CloudTrail event (`UpdateFunctionCode20150331v2`)
    if proposal.action is ActionKind.revert_config and any(
            i is not None and i.id.startswith("C") and i.text.startswith("CONFIG appconfig ")
            for i in (items.get(c.id.strip().strip("[]")) for c in root_cause.citations)):
        # WARDEN's own read of the AppConfig environment whose monitors name this alarm, whichever part of the line
        # was quoted (G10 held-out, 2026-10-11: `deployment=14 state=COMPLETE version=9` holds no word above).
        return None
    quotes = [_CAMEL.sub(" ", q).lower() for q in cited]
    shortage = proposal.action is not ActionKind.scale_down
    idle_short = proposal.action is ActionKind.scale_up
    if any(_supports(q, k, shortage, idle_short) for q in quotes for k in keys):
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
_SCOPE = re.compile(r"[\s,(]*\b(?:namespace|ns|cluster)\b\s*[=:/ ]\s*[\"'\u201c\u201d\u2018\u2019]?[\w.-]+[\"'\u201c\u201d\u2018\u2019]?\s*\)?\s*,?", re.IGNORECASE)
# Words that describe a resource rather than name one: a second of these is not a second resource.
_DESCRIPTORS = frozenset({
    "ecs", "ecs-service", "eks", "k8s", "service", "svc", "deploy", "sts", "rds", "aurora", "sqs", "sns",
    "dynamodb", "redis", "elasticache", "postgres", "postgresql", "mysql", "version", "revision",
    "prod", "staging", "dev", "appconfig"})
# A command inside a target is a second instruction, whatever resource it also names:
# "orders kubectl delete ns warden-pg".
# Whole words only: `public.ecr.aws` in an image name is not the aws CLI.
# After anything but a name character (fifth review, 2026-10-01: `orders (kubectl/delete/ns/x)`, `orders(rm)`
# passed): still not inside a name - `public.ecr.aws` is no aws CLI.
# A trailing period ends the word, it does not continue a name: "orders (rm.)" (sixth review, 2026-10-01).
_COMMAND_WORDS = re.compile(r"(?<![\w.-])(?:kubectl|aws|gcloud|az|helm|psql|redis-cli|mysql|rm|delete|drop|truncate|"
                            r"curl|wget|sh|bash|sudo|exec|eval|kill|pkill|killall|terraform|shutdown|reboot|"
                            r"eksctl|systemctl)(?![\w-]|\.(?!(?:exe|sh|bat|cmd|ps1)\b)\w)", re.IGNORECASE)
# An image reference with a real tag or digest (`python:3.12-alpine`, `repo/app@sha256:...`): the state a
# rollback returns to, not a second resource. A word after a colon (`x:payments`) is not a tag.
_IMAGE = re.compile(r"[\w.-]+(?:/[\w.-]+)*(?::(?:v?\d[\w.-]*|latest)\b|@sha256:[0-9a-f]{12,})", re.IGNORECASE)
_RESOURCE_KINDS = frozenset({"deployment", "namespace", "service", "statefulset", "daemonset", "pod", "function",
                             "lambda", "cluster", "table", "queue", "topic", "rule", "instance", "database", "db"})


# Actions whose target can only be a database or a cache: it sits in no namespace and no compute cluster.
DATA_ONLY = frozenset({ActionKind.failover_replica, ActionKind.clear_cache, ActionKind.terminate_connections})


def target_problem(proposal: RemediationProposal, inventory: set[str],
                   scopes: frozenset[str] | set[str] = frozenset(),
                   containers: frozenset[str] | set[str] = frozenset()) -> str | None:
    """`scopes`: the incident's namespace and cluster names. A target that names only one of them
    names a whole namespace or cluster, not a resource. `containers`: its namespaces and compute clusters,
    never a failover's target."""
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
    if re.search(r"\ball\b|\bevery(?:thing|one)?\b|\beach\b|\bentire\b", plain, re.IGNORECASE):
        return f"target {proposal.target!r} names a whole namespace or cluster"

    def resources(text: str) -> set[str]:
        found = {t for t in tokens(text) & inventory
                 if not t.isdigit() and t.lower() not in _RESOURCE_KINDS | _DESCRIPTORS and t not in scopes}
        # A name WARDEN's own reads write as a path - a load balancer's `app/web/3f8a1c0d`, an AppConfig
        # `application/environment` - is one resource, not a list of its parts (G10 held-out, 2026-10-11: the targets
        # of a zonal shift and of a configuration revert were refused as lists). Never a path through a namespace or
        # a cluster: that one still names a scope.
        for path in PATH.findall(text):
            if path in inventory and not tokens(path) & set(scopes):
                found = found - tokens(path) | {path}
        return found

    named = resources(outside)
    wide = set(scopes) | set(containers)
    # A database or a cache sits in no namespace or compute cluster: one named anywhere in its target - with a kind
    # word or without, named beside it or alone - is a second target or the wrong one (ninth review: `aurora ->
    # cluster=warden-dev-ecs` and `redis, namespace=shop` passed, the kind word cut as a qualifier; a failover of
    # `shop`, the recorded alert's namespace named like its service, passed because a resource was named).
    if proposal.action in DATA_ONLY and tokens(plain) & set(containers):
        return f"target {proposal.target!r} names a namespace or a compute cluster, not a database or cache"
    # One resource, and beside it a whole namespace or cluster - after an arrow, a comma or "and" - is a second
    # target (eighth review: `warden-pg-fs-aurora -> warden-pg-fs-ecs` passed once the database was no longer a
    # scope). One that qualifies it - `deployment=x (namespace=shop)`, `cluster/service` (an ECS service's ARN
    # path), `service (cluster)`, `service on cluster` - is not (ninth review: those were refused).
    if named:
        after = re.split(r"->|=>|\u2192", re.sub(r"\([^)]*\)", " ", rest), maxsplit=1)[1:]
        beside = re.split(r",|\band\b", outside, flags=re.IGNORECASE)[1:]
        if tokens(" ".join(after + beside)) & wide - named:
            return f"target {proposal.target!r} names a resource and a whole namespace or cluster"
    if not named and proposal.action is ActionKind.failover_replica:
        # A failover's target IS a cluster: `cluster=warden-dev-aurora` names it, it does not scope it - even
        # when the alert labels that cluster (fifth and sixth reviews). A namespace is never one.
        # The word on its own, not inside a name (`orders-ns-db` is a cluster), and plural too; and never a name
        # the alert gives a namespace or a compute cluster (seventh review: `payments`, `warden-dev-ecs` passed).
        if re.search(r"(?<![\w-])(?:namespaces?|ns)(?![\w-])", plain, re.IGNORECASE):
            return f"target {proposal.target!r} names a namespace; a failover's target is a database cluster"
        if tokens(plain) & set(containers):
            return f"target {proposal.target!r} names a namespace or a compute cluster, not a database cluster"
        named = {t for t in tokens(plain) & inventory
                 if not t.isdigit() and t.lower() not in _RESOURCE_KINDS | _DESCRIPTORS}
    if not named and (rest != plain or tokens(plain) & set(scopes)):
        return f"target {proposal.target!r} names a whole namespace or cluster"
    # Parentheses and what follows an arrow describe the one resource; another resource named there is a
    # second target (fifth review, 2026-10-01: `orders (payments)`, `orders -> payments`,
    # `app in (orders,payments)` passed).
    if (re.search(r",|\band\b|=\s*[(\[]", outside, re.IGNORECASE) or re.search(r"=\s*[(\[]", rest)
            or len(named | resources(_IMAGE.sub(" ", rest))) > 1):
        return f"target {proposal.target!r} is a pattern or a list, not one resource"
    found = tokens(proposal.target)
    if not found & inventory:
        return f"target {proposal.target!r} names no resource in the inventory"
    unknown = sorted(t for t in found - inventory if "-" in t or "_" in t)
    if unknown:
        return f"target {proposal.target!r} names {', '.join(unknown)}, which is not in the inventory"
    return None
