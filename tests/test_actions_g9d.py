"""G9-D2 (2026-10-10): the generic fix classes. Every action the model may propose has the gate's facts, the words its
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
    """Independent review 2026-10-10, M4: a redrive's moved messages and a cancelled query are not undone - P2 keeps
    both a person's in production."""
    assert {a for a in NEW if not ACTION_FACTS[a][0]} == {ActionKind.redrive_messages, ActionKind.cancel_query}
    assert ACTION_FACTS[ActionKind.shift_traffic][1] == "multi_service"


def test_the_new_classes_are_allowed_wherever_a_person_approves():
    policies = default_environment_policies()
    for name in ("staging", "qa-staging", "pre-prod", "qa-prod", "prod"):
        assert all(policies.for_env(name).permits(a) for a in NEW), name
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
    assert why == "" and req["entry"] == "events_enable_rule" and req["params"] == {"rule": "warden-dev-nightly"}
    # Review H1 closed raise_limit's weak evidence words; G10-B maps it to the reserved concurrency again.
    assert catalog.for_action(ActionKind.raise_limit, "lambda").name == "lambda_set_reserved_concurrency"
    assert catalog.for_action(ActionKind.scale_up, "lambda").name == "lambda_set_reserved_concurrency"
    assert catalog.for_action(ActionKind.raise_limit, "apigw").name == "apigw_raise_stage_throttle"


def test_raise_limit_is_never_a_memory_limit():
    """Qualification 2026-10-10: raise_limit for an OOM after a config change lowered a container's memory limit was
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
    """Qualification 2026-10-10: an answer cut off at 1500 output tokens read as "invalid JSON" three times. Review M7:
    raised inside the provider it was billed but counted as $0, and still retried."""
    import types

    import pytest

    from warden import providers
    from warden.graph import Diagnosis
    from warden.llm import LLMClient, ModelRefused

    p = providers.AnthropicProvider.__new__(providers.AnthropicProvider)
    p.model, p.name, p.version = "claude-sonnet-5", "anthropic", "test"
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
    assert len(sent) == 1 and client.cost.usd > 0  # asked once, and charged
    assert sent[0]["max_tokens"] == providers.MAX_OUTPUT_TOKENS >= 4096
