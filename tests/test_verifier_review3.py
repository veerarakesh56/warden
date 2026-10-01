"""Third independent review (2026-09-30), area C: P15, P5, P14, replica-lag names, provider settings."""

from __future__ import annotations

import pytest

from warden import evidence
from warden.grounding import action_support_problem, target_problem
from warden.models import ActionKind as A
from warden.models import Citation, ContextBundle, RemediationProposal, RootCause
from warden.providers import OpenAICompatProvider, ProviderError, resolve
from warden.verifier import replica_lag_s, verify


def _prop(action, target="orders"):
    return RemediationProposal(action=action, target=target, reasoning="r", expected_effect="e",
                               blast_radius="single_service", reversible=True)


def _support(action, quote):
    rc = RootCause(hypothesis="h", confidence=0.9, citations=[Citation(id="C1", quote=quote)])
    return action_support_problem(rc, _prop(action), {"C1": evidence.Item(id="C1", text=quote)})


@pytest.mark.parametrize("action, quote", [
    (A.restart_pods, "restartCount=0"), (A.restart_pods, "restartCount: 0"), (A.restart_pods, "exitCode=0"),
    (A.restart_pods, "OOMKilled=false"), (A.restart_pods, "no OOMKilled events"), (A.restart_pods, "oomKilled: 0"),
    (A.scale_up, "CPUUtilization=0.0"), (A.scale_up, "memoryUsage=0"), (A.scale_up, "pendingCount=0"),
    (A.scale_up, "cpuThrottled=0"), (A.scale_up, "queueDepth=0"), (A.scale_up, "connectionCount=0"),
    (A.terminate_connections, "lockWaits=0"), (A.terminate_connections, "idleInTransaction=0"),
    (A.terminate_connections, "blockedSessions=0"), (A.failover_replica, "replicaLag=0"),
    (A.failover_replica, "ReplicaLag: 0"), (A.clear_cache, "cacheEvictions=0"),
    (A.restart_pods, "crashloop_containers=0"), (A.restart_pods, "restart_count=0"),
    (A.scale_up, "oom_killed_containers=0"), (A.restart_pods, "oom_killed_containers=0"),
    (A.restart_pods, "without restarts"),
])
def test_a_quote_that_says_none_supports_no_action(action, quote):
    """The camelCase split (45773cb) turned `restartCount=0` into `restart count=0`, and the zero
    check no longer saw the zero: 18 of these 24 supported an action again."""
    assert _support(action, quote) is not None, (action, quote)


@pytest.mark.parametrize("action, quote", [
    (A.scale_up, "CPUUtilization=99.2"), (A.restart_pods, "exitCode=137"), (A.restart_pods, "OOMKilled=true"),
    (A.restart_pods, "3 pods not ready"), (A.restart_pods, "restartCount=6"), (A.failover_replica, "replicaLag=47"),
])
def test_a_quote_that_measures_something_still_supports(action, quote):
    assert _support(action, quote) is None, (action, quote)


CITE = "deploy revision 7"


def _p5(service, deployed, target):
    from test_verifier_review import ALERT

    alert = ALERT.model_copy(update={"service": service})
    ctx = ContextBundle(logs=[f"CONFIG {CITE}", "x ERROR a", "x ERROR b"], metrics={"error_rate": 0.1},
                        recent_deploys=[{"kind": "lambda", "service": deployed, "at": "2026-09-28T09:59:00Z"}])
    rc = RootCause(hypothesis="h", confidence=0.9, citations=[Citation(id="C1", quote=CITE)])
    return "P5-NO-DEPLOY-TO-ROLL-BACK" in verify(alert, ctx, rc, _prop(A.rollback_deploy, target)).policy_ids


@pytest.mark.parametrize("service, deployed, target", [
    ("orders", "payments-orders", "orders (payments-orders version 7 -> 6)"),
    ("orders", "orders-canary", "orders (orders-canary)"),
    ("api", "billing-api", "api (billing-api revision 3 -> 2)"),
    ("db", "orders-db", "db orders-db"),
])
def test_another_service_sharing_a_name_part_is_not_the_one_deployed(service, deployed, target):
    assert _p5(service, deployed, target)


def test_the_service_behind_its_environment_prefix_is_the_one_deployed():
    assert not _p5("checkout", "warden-dev-checkout", "checkout (lambda warden-dev-checkout, version 7 -> 6)")


INVENTORY = {"orders", "checkout", "shop", "payments", "warden-pg"}


@pytest.mark.parametrize("target", [
    'orders "--all"', "orders '-A'", "orders (-A)", "orders,--all", "orders [-n] shop",
    "orders \u3164-A", "orders\u115f -A", "orders \u034f-A", "orders\ufe0f -A", "orders \u2800-A",
    "orders \u02d7\u02d7all", "orders \u2e3a\u2e3aall",
    "namespace=*", "pod=orders-*", "deployment=orders,payments", "namespace=warden-pg", "orders?",
])
def test_a_flag_a_pattern_or_a_whole_namespace_is_not_a_target(target):
    assert target_problem(_prop(A.restart_pods, target), INVENTORY) is not None, target


@pytest.mark.parametrize("target", ["orders", "deployment=checkout (namespace=shop)",
                                    "checkout (version 7 -> 6)", "\u200b-orders"])
def test_a_plain_resource_name_is_still_a_target(target):
    problem = target_problem(_prop(A.restart_pods, target), INVENTORY)
    # models.inert() writes a leading "-" behind a zero-width space: that stays a flag, refused as one
    assert (problem is None) == (not target.startswith("\u200b")), (target, problem)


@pytest.mark.parametrize("name, value, seconds", [
    ("replica_lag_seconds_max", 40, 40), ("replica_lag_msec", 40000, 40), ("replica_lag_seconds_orders", 40, 40),
    ("aurora_replica_lag_ms", 5000, 5), ("replica_lag", 12, 12), ("replica_lag_seconds__payments_msvc", 47, 47),
])
def test_every_replica_lag_name_is_read_in_seconds(name, value, seconds):
    assert replica_lag_s({name: value}) == seconds


@pytest.mark.parametrize("name, value, seconds", [
    ("replica_lag_p99_ms", 40000, 40), ("replica_lag_ms_p99", 40000, 40), ("aurora_replica_lag_maximum_ms", 40000, 40),
    ("replica_lag_us", 40_000_000, 40), ("replica_lag_minutes", 2, 120), ("replica_lag_sec_avg", 40, 40),
    ("replication_lag_bytes", 5_000_000, None), ("replica_lag_count", 3, None), ("replica_lag_alarm", 1, None),
    ("max_replica_lag_seconds_threshold", 30, None), ("replica_lag_seconds_ms", 40000, None),
    ("replica_lag_h", 1, 3600), ("replica_lag_min", 2, None),
])
def test_a_replica_lag_unit_is_read_only_from_a_whitelist(name, value, seconds):
    """Fourth review (2026-09-30, C-7): any suffix was read as seconds; a unit after an aggregate was not
    read at all."""
    got = replica_lag_s({name: value})
    assert got == (None if seconds is None else pytest.approx(seconds)), (name, got)


def test_custom_openai_headers_never_go_to_another_host(monkeypatch):
    """The OpenAI SDK reads OPENAI_CUSTOM_HEADERS itself and sends them - Authorization included - to
    every host it talks to."""
    monkeypatch.setenv("OPENAI_CUSTOM_HEADERS", "X-Team: t")
    monkeypatch.setenv("GROQ_API_KEY", "g")
    monkeypatch.delenv("WARDEN_BASE_URL", raising=False)
    with pytest.raises(ProviderError, match="OPENAI_CUSTOM_HEADERS"):
        resolve("groq")
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    assert OpenAICompatProvider()._client is not None  # OpenAI itself may have them


def test_the_gemini_transport_is_never_swapped_by_the_environment(monkeypatch, tmp_path):
    """GOOGLE_GENAI_CLIENT_MODE=replay answered from files on disk; record wrote prompts to disk."""
    monkeypatch.setenv("GEMINI_API_KEY", "fake-key-for-construction-only")
    monkeypatch.setenv("GOOGLE_GENAI_CLIENT_MODE", "replay")
    monkeypatch.setenv("GOOGLE_GENAI_REPLAYS_DIRECTORY", str(tmp_path))
    monkeypatch.setenv("GOOGLE_GENAI_REPLAY_ID", "canned")
    api = resolve("gemini")._client._api_client
    assert "Replay" not in type(api).__name__, type(api).__name__


@pytest.mark.parametrize("name, value, seconds", [
    ("replica_lag_millisecond", 500, 0.5), ("replica_lag_msecs", 500, 0.5), ("replica_lag_millisec", 500, 0.5),
    ("replica_lag_microsecond", 2_000_000, 2), ("replica_lag_usecs", 2_000_000, 2),
    ("replica_lag_" + "nano" + "seconds", 5e8, 0.5), ("replica_lag_ns", 5e8, 0.5),
    ("replica_lag_hours", 2, 7200), ("replica_lag_hrs", 2, 7200),
    ("ReplicaLag", 40, 40), ("AuroraReplicaLag", 40000, 40), ("ReplicationLag", 12, 12),
    ("replica_lag_kilobytes", 900, None), ("replica_lag_mebibytes", 9, None), ("replica_lag_lsn", 77, None),
    ("replica_lag_pages", 30, None), ("replica_lag_txns", 31, None), ("replica_lag_samples", 32, None),
])
def test_more_lag_units_are_converted_and_more_non_lag_names_refused(name, value, seconds):
    """Fifth review (2026-10-01): any spelling outside the whitelist was read as seconds, hours were ignored,
    and CloudWatch's own names were not read at all."""
    got = replica_lag_s({name: value})
    assert got == (None if seconds is None else pytest.approx(seconds)), (name, got)
