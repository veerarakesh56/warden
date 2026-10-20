"""Model routing (owner, 2026-10-17; src/warden/routing.py): Claude Sonnet 5.5 by default, Claude Opus 5.5 only when
one of WARDEN's own checkable signals marks the case hard - and only when providers.yaml says Opus is qualified.

Each signal alone flips the choice; with none, the default answers; the model's own confidence never does; every
choice is on the signed record with its signals and their values."""

from __future__ import annotations

import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden import audit, discuss, providers, routing
from warden.activities import (
    STILL_HELD,
    Diagnosed,
    EvidencePack,
    IncidentActivities,
    Verified,
    still_held,
)
from warden.cli import DEMO_ALERTS
from warden.llm import BudgetExceeded, LLMClient, model_prices
from warden.models import ActionKind, Alert, Verdict, VerdictStatus
from warden.providers import Completion

SONNET, OPUS = "claude-sonnet-5-5", "claude-opus-5-5"
SHIPPED = providers.load_qualified()


def _opus_qualified(monkeypatch, qualified: bool) -> None:
    """providers.yaml as it would read with (or without) a passing Opus row on today's prompt."""
    doc = copy.deepcopy(SHIPPED)
    doc["qualified"] = [e for e in doc["qualified"] if e.get("model") != OPUS]
    if qualified:
        row = next(e for e in SHIPPED["qualified"] if e.get("model") == SONNET)
        doc["qualified"].append({**row, "model": OPUS})
    monkeypatch.setattr(providers, "load_qualified", lambda: doc)


@pytest.fixture
def world(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_MOCK", "1")
    for name in ("WARDEN_PROVIDER", "WARDEN_MODEL", "WARDEN_QUALIFYING"):
        monkeypatch.delenv(name, raising=False)
    _opus_qualified(monkeypatch, True)
    log = audit.AuditLog(tmp_path / "audit.db", key=Ed25519PrivateKey.generate())
    asked: list[str] = []

    def factory(model: str = "") -> LLMClient:
        asked.append(model)
        return LLMClient(mock=True)

    acts = IncidentActivities(audit=log, llm_factory=factory)
    # inc-001 in dev: a rollback (T2) with a deploy and a metric cited, two own reads, rich evidence.
    pack = acts.prepare(Alert(**{**DEMO_ALERTS["inc-001"], "environment": "dev"}))
    diagnosed = acts.diagnose(pack)
    # The easy case every signal is flipped from: the same answer, its fix a T1 restart.
    easy = diagnosed.model_copy(update={"proposal": diagnosed.proposal.model_copy(
        update={"action": ActionKind.restart_pods})})
    return {"log": log, "acts": acts, "pack": pack, "diagnosed": diagnosed, "easy": easy, "asked": asked}


def _route(world, diagnosed=None, pack=None, second=None) -> routing.Route:
    return routing.after_answer(world["log"], pack or world["pack"], diagnosed or world["easy"], second)


# ------------------------------------------------------------------ none, then each signal alone


def test_with_no_signal_the_default_model_answers(world):
    route = _route(world)
    assert route.choice == routing.DEFAULT
    assert route.model == SONNET
    assert route.fired == []
    assert not route.take_over
    assert route.why == 'no signal marks the case hard'
    assert {s.name for s in route.signals} == {"prod", "reinvestigation", "weak_evidence", "risk_tier", "too_close",
                                               "disagreement"}


def test_a_t2_or_t3_fix_alone_makes_the_case_hard(world):
    for action, tier in ((ActionKind.rollback_deploy, "T2"), (ActionKind.failover_replica, "T3")):
        d = world["easy"].model_copy(update={"proposal": world["easy"].proposal.model_copy(update={"action": action})})
        route = _route(world, d)
        assert route.fired == ['risk_tier'], action
        assert route.model == OPUS, action
        assert route.take_over, action
        assert next(s for s in route.signals if s.name == "risk_tier").value["tier"] == tier
    # A T1 fix does not; an action no entry carries out has no tier.
    assert routing.proposal_tier(world["pack"].alert, world["easy"].proposal)[0] == "T1"
    esc = world["easy"].proposal.model_copy(update={"action": ActionKind.escalate_to_human})
    assert routing.proposal_tier(world["pack"].alert, esc) == ("", [])


def test_prod_alone_makes_the_case_hard(world):
    prod = world["pack"].model_copy(update={"alert": world["pack"].alert.model_copy(update={"environment": "prod"})})
    route = _route(world, pack=prod)
    assert route.fired == ['prod']
    assert route.model == OPUS
    assert next(s for s in route.signals if s.name == "prod").value == {"environment": "prod", "tier": "prod"}


def test_two_diagnoses_disagreeing_alone_makes_the_case_hard(world):
    other = world["easy"].model_copy(update={"proposal": world["easy"].proposal.model_copy(
        update={"target": "another-service"})})
    route = _route(world, second=other)
    assert route.fired == ['disagreement']
    assert route.model == OPUS
    assert next(s for s in route.signals if s.name == "disagreement").value["second"]["target"] == "another-service"
    # The same action on the same target (case and spacing aside) is agreement.
    same = world["easy"].model_copy(update={"proposal": world["easy"].proposal.model_copy(
        update={"target": " Checkout "})})
    assert _route(world, second=same).fired == []


def test_weak_evidence_alone_makes_the_case_hard(world):
    rc = world["easy"].root_cause
    one = world["easy"].model_copy(update={"root_cause": rc.model_copy(update={"citations": rc.citations[:1]})})
    route = _route(world, one)
    assert route.fired == ['weak_evidence']
    assert route.model == OPUS
    value = next(s for s in route.signals if s.name == "weak_evidence").value
    assert len(value['own_reads']) == routing.MIN_OWN_READS - 1
    assert value['substantial'] is True
    # A citation that does not hold counts for nothing (P13's own test).
    bad = rc.citations[1].model_copy(update={"quote": "words that are not in the item"})
    forged = world["easy"].model_copy(update={"root_cause": rc.model_copy(update={"citations": [rc.citations[0], bad]})})
    assert _route(world, forged).fired == ["weak_evidence"]
    # Thin gathered evidence (P9's own count) alone, before any answer.
    thin = world["pack"].model_copy(update={"context": world["pack"].context.model_copy(update={"logs": [], "metrics": {}})})
    assert routing.weak_evidence_signal(thin.context).fired


def test_a_reinvestigation_asked_in_chat_alone_makes_the_case_hard(world):
    world["log"].append("discuss-earlier", "discuss.replan", {"started": world["pack"].alert.alert_id, "why": ""})
    route = _route(world)
    assert route.fired == ['reinvestigation']
    assert route.model == OPUS
    # Before the first answer too: the diagnosis a person asked for in chat starts on the hard model.
    assert routing.for_diagnosis(world["log"], world["pack"]).fired == ["reinvestigation"]
    # Another incident's "new plan" is not this one's.
    assert not routing.replan_signal(world["log"], "another-incident").fired


def test_too_close_is_recorded_as_not_available_until_ranked_hypotheses_exist(world):
    signal = routing.too_close_signal(world["easy"].root_cause, world["pack"].context)
    assert signal.fired is False
    assert signal.value['available'] is False


def test_the_models_own_confidence_never_moves_the_choice(world):
    for confidence in (0.0, 0.5, 1.0):
        rc = world["easy"].root_cause.model_copy(update={"confidence": confidence})
        assert _route(world, world["easy"].model_copy(update={"root_cause": rc})).model == SONNET


# ------------------------------------------------------------------ qualification, from providers.yaml


def test_opus_answers_a_hard_case_only_when_providers_yaml_says_it_is_qualified(world, monkeypatch):
    prod = world["pack"].model_copy(update={"alert": world["pack"].alert.model_copy(update={"environment": "prod"})})
    assert _route(world, pack=prod).model == OPUS
    _opus_qualified(monkeypatch, False)
    route = _route(world, pack=prod)
    assert route.choice == routing.HARD
    assert route.model == SONNET
    assert not route.take_over
    assert "has not passed WARDEN's replay set" in route.fallback
    assert route.record()['needs_person'] is True
    assert _route(world).record()["needs_person"] is False
    # The shipped file today: Opus 5.5 is not qualified, Sonnet 5.5 is.
    monkeypatch.setattr(providers, "load_qualified", lambda: SHIPPED)
    assert not routing.is_qualified(OPUS)
    assert routing.is_qualified(SONNET)
    assert routing.models() == (SONNET, OPUS)


def test_no_routing_for_another_provider_or_a_model_an_operator_pinned(world, monkeypatch):
    monkeypatch.setenv("WARDEN_PROVIDER", "gemini")
    assert routing.choose([]).choice == routing.FIXED
    assert routing.choose([]).model == ''
    monkeypatch.setenv("WARDEN_PROVIDER", "anthropic")
    monkeypatch.setenv("WARDEN_MODEL", "claude-some-other-model")
    assert routing.models() is None
    monkeypatch.setenv("WARDEN_MODEL", SONNET)
    assert routing.models() == (SONNET, OPUS)


def test_eldane_always_gets_the_other_model():
    assert routing.other_model(SONNET) == OPUS
    assert routing.other_model(OPUS) == SONNET
    assert routing.other_model("claude-unknown") == ""


# ------------------------------------------------------------------ on the record, and in the activities


def test_each_diagnosis_and_each_verified_answer_records_its_route(world):
    acts, pack = world["acts"], world["pack"]
    rows = [e["body"] for e in world["log"].entries(pack.alert.alert_id, kinds=("incident.route",))]
    assert rows[-1]['stage'] == 'diagnose'
    assert rows[-1]['model'] == SONNET
    assert world['asked'][-1] == SONNET
    assert world["diagnosed"].route["choice"] == routing.DEFAULT
    verified = acts.verify(pack, world["diagnosed"])  # the rollback: T2
    row = [e["body"] for e in world["log"].entries(pack.alert.alert_id, kinds=("incident.route",))][-1]
    assert row['stage'] == 'verify'
    assert row['take_over'] is True
    assert row['fired'] == ['risk_tier']
    assert verified.route == {k: v for k, v in row.items() if k not in ("run_id", "stage")}
    # The takeover's own diagnosis is asked of the hard model, and is never taken over again.
    again = acts.diagnose(pack.model_copy(update={"model": OPUS}))
    assert world['asked'][-1] == OPUS
    assert again.route['choice'] == routing.TAKEOVER
    assert acts.verify(pack, again).route["take_over"] is False


def test_an_answer_without_a_model_is_not_routed(world):
    rules_only = world["diagnosed"].model_copy(update={"model_unavailable": "the budget is spent"})
    assert world["acts"].verify(world["pack"], rules_only).route == {}


def test_the_second_opinion_adds_the_disagreement_signal(world):
    acts, pack, first = world["acts"], world["pack"], world["easy"]
    approved = Verified(verdict=Verdict(status=VerdictStatus.approved_for_human, policy_ids=[], reasons=["ok"]))
    other = first.model_copy(update={"proposal": first.proposal.model_copy(update={"target": "another-service"})})
    held = acts.second_opinion(pack, first, other, approved)
    assert held.route['fired'] == ['disagreement']
    assert held.route['take_over'] is True
    assert acts.second_opinion(pack, first, first, approved).route["fired"] == []


def test_a_takeover_never_lifts_the_escalation_a_disagreement_caused():
    before = Verified(verdict=Verdict(status=VerdictStatus.escalated, policy_ids=["P32-SECOND-OPINION-DIFFERS"],
                                      reasons=["x"]), route={"fired": ["disagreement"]})
    after = Verified(verdict=Verdict(status=VerdictStatus.approved_for_human, policy_ids=[], reasons=["ok"]))
    kept = still_held(after, before)
    assert kept.verdict.status == VerdictStatus.escalated
    assert STILL_HELD in kept.verdict.reasons
    # A takeover for any other signal is judged on its own checks.
    other = Verified(verdict=Verdict(status=VerdictStatus.approved_for_human, policy_ids=[], reasons=["ok"]),
                     route={"fired": ["risk_tier"]})
    assert still_held(after, other) is after


# ------------------------------------------------------------------ the discussion channel


@pytest.mark.parametrize(("question", "model"), [
    ("why did it fire?", SONNET), ("what does C2 say?", SONNET), ("is it still down now?", SONNET),
    ("please investigate the deploy", OPUS), ("can you dig deeper into the pool?", OPUS),
    ("re-check the root cause", OPUS), ("look again at the metrics", OPUS)])
def test_a_simple_question_gets_sonnet_and_a_deep_reinvestigation_opus(question, model, monkeypatch):
    monkeypatch.delenv("WARDEN_MODEL", raising=False)
    monkeypatch.delenv("WARDEN_PROVIDER", raising=False)
    _opus_qualified(monkeypatch, True)
    assert routing.for_question(question).model == model


def test_the_discussion_answer_is_asked_of_the_routed_model_and_recorded(world):
    from warden.activities import DiscussActivities

    channel, user = "C" + "0" * 3 + "DISCUSS1", "U" + "0" * 3 + "PERSON1"
    acts = DiscussActivities(audit=world["log"], incident=world["acts"])
    thread = discuss.Thread(incident="abc", lines=["a person: q"])
    for text, model in (("why?", SONNET), ("investigate it again", OPUS)):
        turn = discuss.Turn(channel=channel, thread_ts="1760000000.000100", ts="1760000000.000100", user=user, text=text)
        acts.discuss_answer(turn, thread, {"evidence": "e", "diagnosis": "d"}, False)
        row = [e["body"] for e in world["log"].entries("discuss-abc", kinds=("discuss.route",))][-1]
        assert world['asked'][-1] == model
        assert row['model'] == model


# ------------------------------------------------------------------ cost


class _Priced:
    name = "anthropic"

    def __init__(self, model: str) -> None:
        self.model = model

    def complete(self, *, system, user, schema=None):
        return Completion('{"answer": "x"}', 100_000, 10_000)


def test_opus_is_charged_at_its_own_price_and_the_incident_ceiling_still_holds(monkeypatch):
    for name in ("WARDEN_PRICE_IN", "WARDEN_PRICE_OUT", "WARDEN_MOCK"):
        monkeypatch.delenv(name, raising=False)
    (s_in, s_out), (o_in, o_out) = model_prices(SONNET), model_prices(OPUS)
    assert (o_in, o_out) == (2 * s_in, 2 * s_out)
    # One call of 100k in / 10k out: Sonnet $0.30, Opus $0.60. Under a $0.50 ceiling only Sonnet's fits.
    LLMClient(provider=_Priced(SONNET), max_usd=0.5).structured(system="s", user="u", schema=discuss.Answer)
    opus = LLMClient(provider=_Priced(OPUS), max_usd=0.5)
    with pytest.raises(BudgetExceeded):
        opus.structured(system="s", user="u", schema=discuss.Answer)


# ------------------------------------------------------------------ the workflow (Temporal: runs in CI)


def _takeover_run(tmp_path, monkeypatch, *, opus_qualified: bool):
    import asyncio
    import os
    from concurrent.futures import ThreadPoolExecutor

    from temporalio import activity
    from temporalio.testing import WorkflowEnvironment
    from temporalio.worker import Worker

    from warden import codec
    from warden.workflows import IncidentWorkflow

    monkeypatch.setenv("WARDEN_MOCK", "1")
    for name in ("WARDEN_PROVIDER", "WARDEN_MODEL", "WARDEN_QUALIFYING"):
        monkeypatch.delenv(name, raising=False)
    _opus_qualified(monkeypatch, opus_qualified)
    approved = Verdict(status=VerdictStatus.approved_for_human, policy_ids=[], reasons=["ok"])
    asked: list[str] = []

    def factory(model: str = "") -> LLMClient:
        asked.append(model)
        return LLMClient(mock=True)

    class _Acts(IncidentActivities):
        @activity.defn(name="verify")
        def verify(self, pack: EvidencePack, diagnosed: Diagnosed) -> Verified:
            return super().verify(pack, diagnosed).model_copy(update={"verdict": approved})

    async def main():
        log = audit.AuditLog(tmp_path / "audit.db", key=Ed25519PrivateKey.generate())
        acts = _Acts(audit=log, llm_factory=factory)
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        alert = Alert(**{**DEMO_ALERTS["inc-001"], "environment": "dev"})  # a rollback: T2
        async with env, Worker(env.client, task_queue="q", workflows=[IncidentWorkflow],
                               activities=[acts.prepare, acts.investigate, acts.diagnose, acts.verify,
                                           acts.second_opinion, acts.notify, acts.plan_fix],
                               activity_executor=ThreadPoolExecutor(2)):
            handle = await env.client.start_workflow(IncidentWorkflow.run, alert, id="inc-route", task_queue="q")
            report = await asyncio.wait_for(handle.result(), 120)
        rows = [e["body"] for e in log.entries(alert.alert_id, kinds=("incident.route",))]
        return report, rows

    report, rows = asyncio.run(main())
    return report, rows, asked


def test_the_workflow_hands_a_hard_case_to_opus_when_it_is_qualified(tmp_path, monkeypatch):
    report, rows, asked = _takeover_run(tmp_path, monkeypatch, opus_qualified=True)
    # Sonnet answers and gives the second opinion; the T2 fix makes the case hard; Opus answers and gives its own.
    assert asked == [SONNET, SONNET, OPUS, OPUS], asked
    assert [r['stage'] for r in rows if r['stage'] == 'diagnose']
    diagnosed = [r for r in rows if r['stage'] == 'diagnose']
    assert [r['model'] for r in diagnosed] == [SONNET, SONNET, OPUS, OPUS], diagnosed
    assert diagnosed[-1]['choice'] == routing.TAKEOVER
    assert any(r["stage"] == "second_opinion" and r["take_over"] for r in rows)
    assert report.verdict.status == VerdictStatus.approved_for_human


def test_the_workflow_keeps_sonnet_when_opus_is_not_qualified(tmp_path, monkeypatch):
    _, rows, asked = _takeover_run(tmp_path, monkeypatch, opus_qualified=False)
    assert asked == [SONNET, SONNET], asked
    assert not any(r['take_over'] for r in rows)
    assert any(r.get('needs_person') for r in rows)


# ------------------------------------------------------------------ review fixes (PR 74)


def _bench_check(tmp_path, needs_person: bool, name: str = "bench") -> list[str]:
    from datetime import UTC, datetime, timedelta

    from cryptography.hazmat.primitives import serialization

    from warden import approvals
    from warden.activities import RemediationActivities

    key = Ed25519PrivateKey.generate()
    pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    nonprod = next(e for e, tier in routing_envs() if tier == "nonprod")
    policy = approvals.ApproverPolicy(approvers={name: approvals.Approver(
        name="the owner" if name != "bench" else "", public_key=pem, tiers=["T1", "T2"], environments=[nonprod])})
    log = audit.AuditLog(tmp_path / f"{name}-{needs_person}.db", key=Ed25519PrivateKey.generate())
    log.append("inc-1", "incident.route", {"stage": "verify", "needs_person": needs_person})
    now = datetime.now(UTC)
    plan = approvals.Plan(workflow_id="rem-1", incident_id="inc-1", entry="events_enable_rule", tier="T1", params={},
                          plan_hash="h", created_at=now - timedelta(minutes=5), environment=nonprod)
    signed = approvals.sign(key, approver=name, workflow_id="rem-1", plan_hash="h", tier="T1", now=now)
    acts = RemediationActivities(audit=log, policy=policy, platform=None)
    return acts.check_approval(plan, signed, []).problems


def routing_envs() -> list[tuple[str, str]]:
    from warden.environments import default_environment_policies

    policies = default_environment_policies()
    return [(e, policies.for_env(e).tier) for e in policies.known_environments]


def test_the_bench_approver_never_approves_a_hard_case_its_hard_model_could_not_answer(tmp_path):
    held = _bench_check(tmp_path, needs_person=True)
    assert any("a person approves its fix" in p for p in held), held
    assert _bench_check(tmp_path, needs_person=False) == []
    # A person's approval is not held by it.
    assert _bench_check(tmp_path, needs_person=True, name="owner") == []


def test_a_routing_failure_is_the_rules_only_diagnosis_with_why(world, monkeypatch):
    def broken(*_a, **_k):
        raise RuntimeError("no data file")

    monkeypatch.setattr(routing, "for_diagnosis", broken)
    d = world["acts"].diagnose(world["pack"])
    assert d.model_unavailable.startswith("no qualified model could be used")
    assert d.route["choice"] == routing.FIXED
    assert "could not be chosen" in d.route["why"]


def test_a_second_opinion_escalation_alone_is_also_kept_after_a_takeover():
    before = Verified(verdict=Verdict(status=VerdictStatus.escalated, policy_ids=["P32-SECOND-OPINION-DIFFERS"],
                                      reasons=["x"]), route={"fired": []})
    after = Verified(verdict=Verdict(status=VerdictStatus.approved_for_human, policy_ids=[], reasons=["ok"]))
    assert still_held(after, before).verdict.status == VerdictStatus.escalated
