"""G9-D2: the generic fix classes. Every action the model may propose has the gate's facts, the words its
citations must bear, a place in the environments that need a signed approval, and - where an entry carries it out -
a catalogue mapping the resolver can reach from the alarm's own labels."""

from __future__ import annotations

import re

from warden import catalog, evidence, resolver
from warden.environments import default_environment_policies
from warden.grounding import ACTION_EVIDENCE
from warden.models import ACTION_FACTS, ActionKind, Alert, RemediationProposal, Severity

PASSIVE = {ActionKind.no_action, ActionKind.escalate_to_human}
NEW = {ActionKind.revert_config, ActionKind.pause_flow, ActionKind.resume_flow, ActionKind.shift_traffic,
       ActionKind.redrive_messages, ActionKind.cancel_query, ActionKind.raise_limit, ActionKind.freeze_changes}


def test_every_action_names_the_evidence_it_needs():
    """A missing entry skipped P15 for that action: any citation would have supported it."""
    assert set(ACTION_EVIDENCE) == set(ActionKind) - PASSIVE


def test_no_evidence_word_is_a_trusted_lines_own_first_word():
    """Every CONFIG, STATE, SECRET... line starts with its kind: such a key would let any trusted line support the
    action. The few kept are named, each with its reason."""
    prefixes = {w.lower() for w in re.findall(r"[A-Z]{2,}", evidence._CONFIG.pattern)}
    assert prefixes >= {"config", "state", "secret", "rule", "queue", "change"}
    allowed = {ActionKind.freeze_changes: {"change", "rollout"},
               ActionKind.rollback_deploy: {"rollout"},  # a ROLLOUT line is a deploy's own state
               # Kept on purpose: "queue at 900", "queue slots: 0 free" are real support (reviews 4 and 8).
               ActionKind.scale_up: {"queue"}}
    for action, keys in ACTION_EVIDENCE.items():
        assert not (set(keys) & prefixes) - allowed.get(action, set()), action


def test_what_cannot_be_undone_is_not_called_reversible_and_a_zonal_shift_is_never_narrow():
    """A redrive's moved messages and a cancelled query are not undone - P2 keeps
    both a person's in production."""
    assert {a for a in NEW if not ACTION_FACTS[a][0]} == {ActionKind.redrive_messages, ActionKind.cancel_query}
    assert ACTION_FACTS[ActionKind.shift_traffic][1] == "multi_service"


def test_the_new_classes_are_allowed_wherever_a_person_approves():
    """In prod every one (P2 then keeps the two irreversible ones a person's). Dev is not of the prod tier, so P2 does
    not reach it, and it denies those two itself (dev is run as production)."""
    policies = default_environment_policies()
    assert all(policies.for_env("prod").permits(a) for a in NEW)
    dev = policies.for_env("dev")
    assert {a for a in NEW if dev.permits(a)} == {a for a in NEW if ACTION_FACTS[a][0]}
    assert not any(policies.for_env("unknown-env").permits(a) for a in NEW)


def _alert(**labels):
    return Alert(alert_id="a1", name="n", service="warden-dev-nightly", environment="dev", severity=Severity.high,
                 summary="", started_at="2026-10-10T00:00:00+00:00", labels=labels)


def test_a_disabled_rule_is_resumed_through_its_entry():
    req, why = resolver.request_for(
        _alert(eventbridge_rule="warden-dev-nightly"),
        RemediationProposal(action=ActionKind.resume_flow, target="warden-dev-nightly", reasoning="r",
                            expected_effect="e", blast_radius="single_service", reversible=True),
        lambda e, p: {"rule": {"warden-dev-nightly"}})
    assert why == ""
    assert req["entry"] == "events_enable_rule"
    assert req["params"] == {"rule": "warden-dev-nightly"}
    # Review H1 closed raise_limit's weak evidence words; G10-B maps it to the reserved concurrency again.
    assert catalog.for_action(ActionKind.raise_limit, "lambda").name == "lambda_set_reserved_concurrency"
    assert catalog.for_action(ActionKind.scale_up, "lambda").name == "lambda_set_reserved_concurrency"
    assert catalog.for_action(ActionKind.raise_limit, "apigw").name == "apigw_raise_stage_throttle"


def test_raise_limit_is_never_a_memory_limit():
    """In qualification, raise_limit for an OOM after a config change lowered a container's memory limit was
    allowed. The model is told what the action means; the gate rejects it next to an OOM kill, and "memory limit" is
    no longer support for it."""
    from warden.graph import Diagnosis
    from warden.models import ContextBundle
    from warden.verifier import _contradiction

    schema = str(Diagnosis.model_json_schema())
    assert "never a container's CPU or memory limit" in schema
    ctx = ContextBundle(logs=["LOG k8s/shop/orders OOMKilled exit code 137"])
    prop = RemediationProposal(action=ActionKind.raise_limit, target="orders", reasoning="r", expected_effect="e",
                               blast_radius="single_service", reversible=True)
    assert "out-of-memory" in (_contradiction(prop, ctx) or "")
    assert "limit" not in ACTION_EVIDENCE[ActionKind.raise_limit]


def test_an_answer_cut_off_at_the_output_cap_is_charged_said_plainly_and_not_asked_again():
    """In qualification, an answer cut off at 1500 output tokens read as "invalid JSON" three times. Raised
    inside the provider it was billed but counted as $0, and still retried."""
    import types

    import pytest

    from warden import providers
    from warden.graph import Diagnosis
    from warden.llm import LLMClient, ModelRefused

    p = providers.AnthropicProvider.__new__(providers.AnthropicProvider)
    p.model, p.name, p.version, p.effort = "claude-sonnet-5-5", "anthropic", "test", "medium"
    sent = []
    resp = types.SimpleNamespace(content=[types.SimpleNamespace(type="text", text='{"root_cause": {')],
                                 stop_reason="max_tokens", usage=types.SimpleNamespace(input_tokens=1000,
                                                                                       output_tokens=4096))
    p._client = types.SimpleNamespace(messages=types.SimpleNamespace(create=lambda **kw: sent.append(kw) or resp))
    assert p.complete(system="s", user="u").cut_off is True
    sent.clear()
    client = LLMClient(provider=p, mock=False)
    with pytest.raises(ModelRefused, match="cut off"):
        client.structured(system="s", user="u", schema=Diagnosis)
    assert len(sent) == 1  # asked once, and charged
    assert client.cost.usd > 0
    assert sent[0]["max_tokens"] == providers.MAX_OUTPUT_TOKENS >= 16384  # room for thinking and the answer
    # The model's own price: Sonnet 5.5 at $2 in / $10 out per million, not one price for every model.
    assert client.cost.usd == pytest.approx(1000 / 1e6 * 2.0 + 4096 / 1e6 * 10.0)
    # The stated thinking effort is sent, so a comparison of two models compares the models.
    assert sent[0]["extra_body"] == {"output_config": {"effort": "medium"}}


def test_each_claude_model_has_its_own_price_and_effort_and_a_thinking_models_time(monkeypatch):
    import pytest

    from warden import llm, providers

    monkeypatch.delenv("WARDEN_PRICE_IN", raising=False)
    monkeypatch.delenv("WARDEN_PRICE_OUT", raising=False)
    monkeypatch.delenv("WARDEN_MODEL_EFFORT", raising=False)
    assert llm.model_prices("claude-sonnet-5-5") == (2.0, 10.0)
    assert llm.model_prices("claude-opus-5-5") == (4.0, 20.0)
    # Sonnet 5.5 qualified at effort high; Opus 5.5 is not qualified and keeps the shared medium.
    assert (providers.model_effort("claude-sonnet-5-5"), providers.model_effort("claude-opus-5-5")) == ("high", "medium")
    assert providers.AnthropicProvider.default_timeout_s >= 240
    monkeypatch.setenv("WARDEN_MODEL_EFFORT", "max")
    with pytest.raises(providers.ProviderError):
        providers.model_effort("claude-opus-5-5")
