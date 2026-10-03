"""Register N2 / audit A-N-2: an empty or errored read taken as healthy. A read that failed is P8; a read that
succeeded and returned nothing is recorded and, under "nothing to do", is P23-EMPTY-READ."""

from __future__ import annotations

from test_verifier import _alert, _ctx, _prop, _rc
from warden.models import ActionKind, VerdictStatus
from warden.tools import gather
from warden.verifier import verify


class _Backend:
    name = "stub"

    def __init__(self, logs=("err 500",) * 3, metrics=None, deploys=(), fail=()):
        self._logs, self._metrics, self._deploys, self._fail = list(logs), metrics or {}, list(deploys), fail

    def _read(self, what, value):
        if what in self._fail:
            raise TimeoutError("Rate exceeded")
        return value

    def logs(self, alert):
        return self._read("logs", self._logs)

    def metrics(self, alert):
        return self._read("metrics", self._metrics)

    def deploys(self, alert):
        return self._read("deploys", self._deploys)


def test_a_read_that_returns_nothing_is_recorded_as_empty_and_a_quiet_deploy_window_is_not():
    bundle = gather(_alert(), _Backend(metrics={}))
    assert bundle.empty_reads == ["metrics"] and bundle.tool_errors == []
    bundle = gather(_alert(), _Backend(logs=(), metrics={"error_rate": 0.0}))
    assert bundle.empty_reads == ["logs"]
    full = gather(_alert(), _Backend(metrics={"error_rate": 0.0}, deploys=[{"sha": "abc"}]))
    assert full.empty_reads == []


def test_nothing_to_do_over_an_empty_read_goes_to_a_person():
    proposal = _prop(action=ActionKind.no_action, target="checkout")
    quiet = verify(_alert(), _ctx(empty_reads=["metrics"]), _rc(confidence=0.95), proposal)
    assert "P23-EMPTY-READ" in quiet.policy_ids and quiet.status is not VerdictStatus.auto_safe
    assert "metrics" in " ".join(quiet.reasons)
    read = verify(_alert(), _ctx(), _rc(confidence=0.95), proposal)
    assert "P23-EMPTY-READ" not in read.policy_ids


def test_nothing_to_do_over_an_errored_read_goes_to_a_person():
    bundle = gather(_alert(), _Backend(metrics={"error_rate": 0.0}, deploys=[{"sha": "abc"}], fail=("metrics",)))
    assert bundle.tool_errors and "metrics" in bundle.tool_errors[0]
    v = verify(_alert(), _ctx(tool_errors=bundle.tool_errors), _rc(confidence=0.95),
               _prop(action=ActionKind.no_action, target="checkout"))
    assert "P8-PARTIAL-CONTEXT" in v.policy_ids and v.status is not VerdictStatus.auto_safe


class _AllClear:
    """A model that reads the evidence as healthy and proposes nothing."""

    name, model = "calm", "c-1"

    def complete(self, *, system, user, schema=None):
        import json

        from warden.providers import Completion

        body = {"root_cause": {"hypothesis": "transient", "confidence": 0.95, "evidence": ["quiet"]},
                "proposal": {"action": "no_action", "target": "checkout", "reasoning": "all clear",
                             "expected_effect": "none", "blast_radius": "single_service", "reversible": True}}
        return Completion(json.dumps(body), 10, 10)


def test_through_the_whole_pipeline_an_empty_metrics_read_is_not_all_clear():
    from warden.cli import DEMO_ALERTS
    from warden.graph import run
    from warden.llm import LLMClient
    from warden.models import Alert
    from warden.tools import FixtureBackend

    class _NoMetrics(FixtureBackend):
        def metrics(self, alert):
            return {}

    alert = Alert(**DEMO_ALERTS["inc-001"])
    empty = run(alert, llm=LLMClient(provider=_AllClear(), mock=False), backend=_NoMetrics())
    assert empty.context.empty_reads == ["metrics"]
    assert "P23-EMPTY-READ" in empty.verdict.policy_ids and empty.verdict.status is not VerdictStatus.auto_safe
    full = run(alert, llm=LLMClient(provider=_AllClear(), mock=False))
    assert "P23-EMPTY-READ" not in full.verdict.policy_ids
