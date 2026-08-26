"""The incident knowledge base: it loads, it validates loudly, and it matches deterministically."""

from __future__ import annotations

import pytest

from warden.knowledge import KnowledgeBase, KnowledgeError, default_knowledge_base
from warden.models import ActionKind, Alert, ContextBundle, Severity


def _alert(name="PodOOMKilled", sev=Severity.high, summary=""):
    return Alert(
        alert_id="t", name=name, severity=sev, service="checkout",
        environment="staging", summary=summary, started_at="2026-08-23T00:00:00Z",
    )


# ------------------------------------------------------------------ the shipped catalog

def test_bundled_catalog_loads_and_is_internally_valid():
    kb = default_knowledge_base()
    assert len(kb.signatures) >= 20
    # Every suggested action across the whole catalog is a real ActionKind (the loader enforces it;
    # this proves the shipped file actually passes that gate, not just that the gate exists).
    for sig in kb.signatures:
        assert sig.suggested_actions, f"{sig.id} has no actions"
        for a in sig.suggested_actions:
            assert isinstance(a.kind, ActionKind)


def test_catalog_covers_the_full_maturity_curriculum():
    kb = default_knowledge_base()
    maturities = {s.maturity for s in kb.signatures}
    assert {"basic", "intermediate", "advanced"} <= maturities


def test_ids_are_unique():
    # default_knowledge_base would raise on load if not; assert the property directly too.
    kb = default_knowledge_base()
    ids = [s.id for s in kb.signatures]
    assert len(ids) == len(set(ids))


# ------------------------------------------------------------------ loud validation

def _kb_from(signatures):
    """Build a KB from in-memory signature dicts, through the real parser/validator."""
    return KnowledgeBase([KnowledgeBase._parse_signature(s) for s in signatures])


_GOOD = dict(
    id="X-1", category="memory", maturity="basic", title="t", root_cause="rc",
    detect={"log_contains": ["boom"]},
    suggested_actions=[{"kind": "restart_pods", "rationale": "r"}],
    remediation_risk="low",
)


def test_a_fake_action_kind_is_rejected_at_load():
    bad = dict(_GOOD)
    bad["suggested_actions"] = [{"kind": "delete_database", "rationale": "r"}]
    with pytest.raises(KnowledgeError, match="not a valid ActionKind"):
        _kb_from([bad])


def test_an_unknown_detect_key_is_rejected_at_load():
    bad = dict(_GOOD)
    bad["detect"] = {"lgo_contains": ["typo"]}  # misspelled key -> would silently never fire
    with pytest.raises(KnowledgeError, match="unknown detect key"):
        _kb_from([bad])


def test_a_bad_maturity_is_rejected():
    bad = dict(_GOOD)
    bad["maturity"] = "expert"
    with pytest.raises(KnowledgeError, match="maturity"):
        _kb_from([bad])


def test_a_signature_with_no_actions_is_rejected():
    bad = dict(_GOOD)
    bad["suggested_actions"] = []
    with pytest.raises(KnowledgeError, match="at least one"):
        _kb_from([bad])


def test_a_bad_regex_is_rejected():
    bad = dict(_GOOD)
    bad["detect"] = {"name_matches": "("}  # unbalanced
    with pytest.raises(KnowledgeError, match="regex"):
        _kb_from([bad])


# ------------------------------------------------------------------ matching

def test_oom_incident_ranks_oom_signature():
    kb = default_knowledge_base()
    ctx = ContextBundle(
        logs=["pod checkout OOMKilled", "memory cgroup out of memory"],
        metrics={"oom_killed_count": 3, "restart_count": 2},
    )
    top = kb.match(_alert(name="PodOOMKilled", summary="memory at 94%"), ctx, limit=3)
    assert top, "expected at least one match"
    assert top[0].signature.id == "K8S-OOM-001"
    assert ActionKind.scale_up in [a.kind for a in top[0].signature.suggested_actions]


def test_severity_guard_excludes_low_severity_from_a_critical_only_signature():
    kb = default_knowledge_base()
    # CASCADE-001 declares severity_in: [critical, high]. A low alert with the same words must not match it.
    ctx = ContextBundle(logs=["circuit breaker open", "cascading failure"])
    low = kb.match(_alert(name="CascadingFailure", sev=Severity.low), ctx)
    assert all(m.signature.id != "CASCADE-001" for m in low)
    high = kb.match(_alert(name="CascadingFailure", sev=Severity.critical), ctx)
    assert any(m.signature.id == "CASCADE-001" for m in high)


def test_no_signal_means_no_match():
    kb = default_knowledge_base()
    ctx = ContextBundle(logs=["everything is completely fine and nominal"])
    assert kb.match(_alert(name="AllGood", summary="nominal"), ctx) == []


def test_score_counts_signals_and_orders_by_it():
    kb = default_knowledge_base()
    ctx = ContextBundle(
        logs=["OOMKilled", "cgroup out of memory"],
        metrics={"oom_killed_count": 1},
    )
    top = kb.match(_alert(name="PodOOMKilled"), ctx, limit=1)[0]
    assert top.score == len(top.signals) >= 2
