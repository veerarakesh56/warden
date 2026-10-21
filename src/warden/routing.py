"""Which Claude model answers (owner, 2026-10-17): Claude Sonnet 5.5 by default, Claude Opus 5.5 only for a HARD case.

"Hard" is decided by WARDEN's own checkable signals - never by what a model says of itself (its confidence, its tone,
its own claim that a case is difficult). Each signal is computed from data WARDEN holds and can show:

    risk tier         the proposed fix's catalogue tier is one of HARD_TIERS (T2, T3)
    prod              the incident's environment is of the prod tier (environments.yaml)
    disagreement      the two independent diagnoses of the same evidence name another action or another target
    too close         WARDEN's count of the top two hypotheses' held citations (grounding.hypothesis_score) differs by
                      less than grounding.MARGIN - the count and margin P35 escalates on
    weak evidence     fewer than MIN_OWN_READS of the diagnosis's held citations are WARDEN's own reads (a metric,
                      a deploy, a configuration or state read), or the gathered evidence is thin by P9's own count
    re-investigation  a person asked for one in the discussion channel: a "new plan" (the new incident's alarm is on
                      the record as started from the chat), or a question with DEEP_QUESTION's words

One signal is enough; with none, the default model answers. Every choice goes on the signed audit with the signals,
their values and the rule each was held to (`incident.route`, `discuss.route`). Where it is applied:

- diagnosis: before the first answer, on what is known then (prod, re-investigation, gathered evidence); after the
  answer is verified, on all of them - and when the case turns out hard, Opus takes the diagnosis over (activities,
  workflows). A takeover's answer is checked like any answer; it never lifts an escalation the disagreement caused;
- Eldane, the AI critic, always uses the OTHER model than the one that made the incident's diagnosis (other_model);
- the discussion channel: a simple question gets the default model, a deep re-investigation the hard one.

The models are configuration (data/providers.yaml `routing`), and each must still be qualified (register M20) to be
used: a hard case whose model is not qualified is answered by the default model, and the record says so. Opus costs
twice Sonnet per token (providers.yaml `prices`); the incident's USD and call ceilings (llm.py) count every call at its
own model's price, so a takeover the budget cannot pay for is not made, and the earlier answer stands.
"""

from __future__ import annotations

import inspect
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

# The tiers that make a case hard (catalog.py: T1 one small reversible change; T2 service-level; T3 irreversible).
HARD_TIERS = ("T2", "T3")
# The environment tier that makes a case hard (environments.yaml `tier`).
PROD_TIER = "prod"
# Weak evidence: fewer held citations than this of WARDEN's own reads. Fixed before any measurement, never tuned on one.
MIN_OWN_READS = 2
# WARDEN's own reads, by evidence id kind (evidence.index): a metric, a deploy, a configuration or state read. A typed
# fact from log lines (F) is what the log's writer chose to write, and a failed read (T) says "unknown".
OWN_READ_KINDS = frozenset("MDC")
# A question in the discussion channel that asks WARDEN to look again in depth, not to say what it already found.
DEEP_QUESTION = re.compile(
    r"(?i)\b(?:re-?investigat\w*|investigat\w*|dig\s+(?:deeper|into)|deep(?:er)?\s+(?:look|dive)|look\s+(?:again|"
    r"deeper|closer)|re-?check|check\s+again|root\s+cause|diagnos\w*\s+again|re-?diagnos\w*|new\s+plan|re-?plan)\b")
# How far back a "new plan" from the chat is looked for: it starts the incident it asked for at once.
REPLAN_LOOKBACK = timedelta(days=2)

DEFAULT, HARD, TAKEOVER, FIXED = "default", "hard", "takeover", "fixed"
# What a model is used for (data/providers.yaml `roles`). Only `diagnose` leads to a fix, so only it is held to the
# replay set (register M20); a critic can only add a "no", and a chat answer changes nothing (owner, 2026-10-17).
DIAGNOSE, CRITIC, CHAT = "diagnose", "critic", "chat"
ROLES = (DIAGNOSE, CRITIC, CHAT)


@dataclass(frozen=True)
class Signal:
    """One checkable fact about the case, the value it was computed from, and the rule it was held to."""

    name: str
    fired: bool
    value: dict[str, Any]
    rule: str


@dataclass(frozen=True)
class Route:
    """The model chosen, why, and what was weighed. `model` "" is the configured provider's own model (no routing)."""

    model: str
    choice: str  # DEFAULT, HARD, TAKEOVER (the hard model, asked after the first answer) or FIXED (no routing)
    signals: tuple[Signal, ...] = ()
    why: str = ""
    fallback: str = ""  # the hard model could not be used, and why
    take_over: bool = False  # after an answer: the hard model should take the diagnosis over
    extra: dict[str, Any] = field(default_factory=dict)
    role: str = DIAGNOSE  # what the model is used for (ROLES)

    @property
    def fired(self) -> list[str]:
        return [s.name for s in self.signals if s.fired]

    def record(self) -> dict[str, Any]:
        """As the audit keeps it."""
        return {"model": self.model, "role": self.role, "choice": self.choice, "why": self.why, "fallback": self.fallback,
                "take_over": self.take_over, "fired": self.fired, "signals": [asdict(s) for s in self.signals],
                # Owner, 2026-10-17: a hard case the hard model could not answer (not qualified) is never left to an
                # AI alone - a person approves its fix, and Eldane on the other model still reviews it.
                "needs_person": self.role == DIAGNOSE and self.choice == HARD and bool(self.fallback), **self.extra}


# --------------------------------------------------------------------------- the models


def provider_name() -> str:
    return (os.environ.get("WARDEN_PROVIDER") or "anthropic").strip().lower()


def models(provider: str | None = None) -> tuple[str, str] | None:
    """(default, hard) for the provider, from data/providers.yaml `routing`; None when it routes nothing - a provider
    with no row, or WARDEN_MODEL pinning a model that is neither (an operator's explicit choice is kept)."""
    from .providers import load_qualified

    row = (load_qualified().get("routing") or {}).get(provider or provider_name()) or {}
    default, hard = row.get("default"), row.get("hard")
    if not (isinstance(default, str) and isinstance(hard, str) and default and hard and default != hard):
        return None
    pinned = os.environ.get("WARDEN_MODEL", "").strip()
    if pinned and pinned not in (default, hard):
        return None
    return default, hard


@dataclass(frozen=True)
class _Unbuilt:
    """A provider by its name and model only, as qualified() reads one: never asked anything."""

    name: str
    model: str

    def complete(self, *, system: str, user: str, schema: Any = None) -> Any:
        raise NotImplementedError("a qualification check, never a model call")


def is_qualified(model: str, provider: str | None = None) -> bool:
    """May `model` diagnose (register M20)? Read from data/providers.yaml alone: no client, no key."""
    from .providers import ProviderError, qualified

    try:
        qualified(_Unbuilt(name=provider or provider_name(), model=model))
    except ProviderError:
        return False
    return True


def roles(model: str) -> frozenset[str]:
    """What data/providers.yaml `roles` lets `model` be used for; nothing for a model it does not list."""
    from .providers import load_qualified

    listed = (load_qualified().get("roles") or {}).get(model) or ()
    return frozenset(r for r in listed if r in ROLES) if isinstance(listed, list) else frozenset()


def usable(model: str, role: str, provider: str | None = None) -> bool:
    """May `model` be used for `role`? Its role listed in providers.yaml - and, to diagnose, its qualification too."""
    return role in roles(model) and (role != DIAGNOSE or is_qualified(model, provider))


def other_model(model: str, provider: str | None = None) -> str:
    """The routing model that is not `model` (Eldane's: never the diagnosis's own); "" when there is none."""
    pair = models(provider)
    if not pair or model not in pair:
        return ""
    return pair[1] if model == pair[0] else pair[0]


def client(model: str, *, factory: Any = None, role: str = DIAGNOSE) -> Any:
    """An LLMClient for `model`: the test's or worker's factory when one is given (handed the model when it takes
    one), else the configured provider for exactly that model. To diagnose it is held to its qualification (M20); for
    an advisory role (critic, chat) to that role in providers.yaml instead. "" - no routing - is the provider's
    configured model, as before."""
    if factory is not None:
        return factory(model=model) if "model" in inspect.signature(factory).parameters else factory()
    from .llm import LLMClient

    if os.environ.get("WARDEN_MOCK") == "1" or not model:
        return LLMClient()
    from . import providers

    built = providers._REGISTRY[provider_name()](model=providers.pinned(model))
    if role == DIAGNOSE:
        return LLMClient(provider=providers.qualified(built))
    if role not in roles(model):
        raise providers.ProviderError(f"{model} is not listed for {role!r} in data/providers.yaml `roles`")
    return LLMClient(provider=built)


# --------------------------------------------------------------------------- the signals


def prod_signal(environment: str) -> Signal:
    from .environments import default_environment_policies

    tier = default_environment_policies().for_env(environment).tier
    return Signal("prod", tier == PROD_TIER, {"environment": environment, "tier": tier},
                  f"the environment's tier is {PROD_TIER}")


_TIER_ORDER = {"T1": 1, "T2": 2, "T3": 3}


def proposal_tier(alert: Any, proposal: Any) -> tuple[str, list[str]]:
    """The proposed fix's catalogue tier: the entry for the platform its target names, else the highest tier of any
    entry that can carry out the action (the cautious reading); ("", []) for an action no entry carries out."""
    from . import catalog, resolver

    found = resolver._platform(alert, proposal.target)
    entry = catalog.for_action(proposal.action, found[0]) if found else None
    names = [entry.name] if entry else list(catalog.FOR_ACTION.get(proposal.action, {}).values())
    tiers = [catalog.CATALOG[n].tier for n in names]
    return (max(tiers, key=lambda t: _TIER_ORDER.get(t, 0)) if tiers else ""), names


def tier_signal(alert: Any, proposal: Any) -> Signal:
    tier, entries = proposal_tier(alert, proposal)
    return Signal("risk_tier", tier in HARD_TIERS, {"action": proposal.action.value, "tier": tier,
                                                     "entries": entries},
                  f"the proposed fix's tier is one of {', '.join(HARD_TIERS)}")


def weak_evidence_signal(context: Any, root_cause: Any = None) -> Signal:
    """P9's own count of what was gathered, and - once there is an answer - how many of its citations that hold are
    WARDEN's own reads."""
    from . import evidence, verifier
    from .grounding import _held, chosen_support

    substantial = verifier._evidence_is_substantial(context)
    value: dict[str, Any] = {"substantial": substantial, "logs": len(context.logs), "metrics": len(context.metrics),
                             "deploys": len(context.recent_deploys)}
    weak = not substantial
    rule = (f"P9's floor ({verifier.MIN_LOG_LINES} log lines, {verifier.MIN_METRICS} metrics, a deploy: two kinds)")
    if root_cause is not None:
        items = evidence.view(context)
        # The chosen cause's support (PR 47): the diagnosis's citations and its first hypothesis's, each that holds once.
        held = sorted(_held(chosen_support(root_cause), items))
        own = [i for i in held if i[:1] in OWN_READ_KINDS]
        value.update(held_citations=held, own_reads=own)
        weak = weak or len(own) < MIN_OWN_READS
        rule += f"; at least {MIN_OWN_READS} held citations of WARDEN's own reads ({', '.join(sorted(OWN_READ_KINDS))})"
    return Signal("weak_evidence", weak, value, rule)


def too_close_signal(root_cause: Any, context: Any) -> Signal:
    """The top two ranked hypotheses by WARDEN's own count of their held citations (grounding.hypothesis_score, PR 47:
    an own read weighs 2, a log fact 1, evidence against subtracts), never the model's confidence. Fires when the chosen
    cause leads its best rival by less than grounding.MARGIN - the same count and margin P35 escalates on. An answer
    recorded before ranked hypotheses (None) or with no rival has nothing to compare: not fired."""
    from . import evidence
    from .grounding import MARGIN, hypothesis_score

    rule = f"the chosen cause leads its best rival by at least {MARGIN} in WARDEN's count of held citations"
    hypotheses = getattr(root_cause, "hypotheses", None)
    if not hypotheses or len(hypotheses) < 2:
        return Signal("too_close", False, {"hypotheses": len(hypotheses or [])}, rule)
    items = evidence.view(context)
    top = hypothesis_score(hypotheses[0], items, root_cause.citations)
    rival = max(hypotheses[1:], key=lambda h: hypothesis_score(h, items))
    second = hypothesis_score(rival, items)
    return Signal("too_close", top - second < MARGIN, {"hypotheses": len(hypotheses), "chosen": top, "rival": second,
                                                        "gap": top - second, "margin": MARGIN}, rule)


def disagreement_signal(first: Any, second: Any) -> Signal:
    """Two independent answers on the same evidence: another action, or another target. No second answer is not a
    disagreement (the second opinion escalates it on its own)."""
    if second is None:
        return Signal("disagreement", False, {"second": "none"}, "two diagnoses name the same action and target")
    a, b = first.proposal, second.proposal
    differ = a.action != b.action or " ".join(a.target.lower().split()) != " ".join(b.target.lower().split())
    return Signal("disagreement", differ, {"first": {"action": a.action.value, "target": a.target},
                                           "second": {"action": b.action.value, "target": b.target}},
                  "two diagnoses name the same action and target")


def replan_signal(log: Any, alert_id: str) -> Signal:
    """A person's "new plan" in the discussion channel started this incident: its id is on the record as started."""
    rows = log.entries(kinds=("discuss.replan",), since=datetime.now(UTC) - REPLAN_LOOKBACK) if log else []
    asked = next((r for r in rows if r["body"].get("started") == alert_id), None)
    return Signal("reinvestigation", asked is not None,
                  {"from": "discussion: new plan", **({"asked_in": asked["correlation_id"]} if asked else {})},
                  "a person asked for a new plan in the discussion channel")


def question_signal(text: str) -> Signal:
    words = sorted({m.group(0).lower() for m in DEEP_QUESTION.finditer(text or "")})
    return Signal("reinvestigation", bool(words), {"from": "discussion: question", "words": words},
                  "the question asks WARDEN to look again in depth (routing.DEEP_QUESTION)")


# --------------------------------------------------------------------------- the choice


def choose(signals: list[Signal] | tuple[Signal, ...], provider: str | None = None, *,
           role: str = DIAGNOSE) -> Route:
    """The default model unless a signal fired; then the hard one - if it may be used for `role` (usable: listed for
    it, and qualified to diagnose), else the default, with why."""
    signals = tuple(signals)
    pair = models(provider)
    if pair is None:
        return Route(model="", choice=FIXED, signals=signals, role=role,
                     why="no routing for this provider, or WARDEN_MODEL pins another model: its configured model")
    default, hard = pair
    fired = [s.name for s in signals if s.fired]
    if not fired:
        return Route(model=default, choice=DEFAULT, signals=signals, role=role, why="no signal marks the case hard")
    why = "hard: " + ", ".join(fired)
    if not usable(hard, role, provider):
        said = ("has not passed WARDEN's replay set (register M20)" if role in roles(hard)
                else f"is not listed for {role} in providers.yaml `roles`")
        return Route(model=default, choice=HARD, signals=signals, role=role, why=why,
                     fallback=f"{hard} {said}: {default} answers")
    return Route(model=hard, choice=HARD, signals=signals, role=role, why=why)


def for_diagnosis(log: Any, pack: Any) -> Route:
    """Before an answer: what is known then. A pack that names a model (a takeover) is answered by that model."""
    if getattr(pack, "model", ""):
        return Route(model=pack.model, choice=TAKEOVER, why="WARDEN's checks found the case hard after the first "
                                                            "answer (incident.route, stage verify)")
    return choose([prod_signal(pack.alert.environment), replan_signal(log, pack.alert.alert_id),
                   weak_evidence_signal(pack.context)])


def after_answer(log: Any, pack: Any, diagnosed: Any, second: Any = None) -> Route:
    """After an answer is verified (and, with `second`, a second opinion given): every signal. take_over when the
    case is hard, the answer was the default model's, and the hard model may be used."""
    signals = [prod_signal(pack.alert.environment), replan_signal(log, pack.alert.alert_id),
               weak_evidence_signal(pack.context, diagnosed.root_cause),
               tier_signal(pack.alert, diagnosed.proposal), too_close_signal(diagnosed.root_cause, pack.context),
               disagreement_signal(diagnosed, second)]
    route = choose(signals)
    made_by = (getattr(diagnosed, "route", None) or {}).get("choice")
    take = (route.choice == HARD and not route.fallback and made_by == DEFAULT
            and not getattr(diagnosed, "model_unavailable", ""))
    return Route(model=route.model, choice=route.choice, signals=route.signals, why=route.why,
                 fallback=route.fallback, take_over=take, extra={"answered_by": made_by or ""})


def needs_person(log: Any, incident_id: str) -> bool:
    """Does any of the incident's routing records say a hard case was answered by the default model because the hard
    one is not qualified? Then no AI or test identity approves its fix alone: a person does."""
    return any(r["body"].get("needs_person") is True for r in log.entries(incident_id, kinds=("incident.route",)))


def for_question(text: str) -> Route:
    """The discussion channel: a simple question gets the default model, a deep re-investigation the hard one."""
    return choose([question_signal(text)], role=CHAT)


def for_critic(diagnosis_model: str, provider: str | None = None) -> Route:
    """Eldane's model (owner, 2026-10-17): always the other one from the model that made the incident's diagnosis, if
    providers.yaml lists it for the critic role; else none, with why - its review is then not independent."""
    model = other_model(diagnosis_model, provider)
    if not model:
        return Route(model="", choice=FIXED, role=CRITIC,
                     why=f"no routing model other than the diagnosis's ({diagnosis_model or 'none recorded'})")
    if not usable(model, CRITIC, provider):
        return Route(model="", choice=FIXED, role=CRITIC, why=f"{model} is not listed for critic in providers.yaml `roles`")
    return Route(model=model, choice=DEFAULT, role=CRITIC, why=f"the other model from the diagnosis's ({diagnosis_model})")
