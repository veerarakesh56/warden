"""P15 reads what a key reports (fourth review, 2026-09-30, C-4; the reviewer's tables). A transition's
last value counts, a zero said any way supports nothing, a negation reaches only its own clause, and a
zero of something good is a shortage."""

from __future__ import annotations

import pytest

from warden import evidence
from warden.grounding import action_support_problem
from warden.models import ActionKind as A
from warden.models import Citation, RemediationProposal, RootCause


def _supports(action, quote):
    rc = RootCause(hypothesis="h", confidence=0.9, citations=[Citation(id="C1", quote=quote)])
    p = RemediationProposal(action=action, target="orders", reasoning="r", expected_effect="e",
                            blast_radius="single_service", reversible=True)
    return action_support_problem(rc, p, {"C1": evidence.Item(id="C1", text=quote)}) is None


# Real support: each must support.
REAL = [
    (A.restart_pods, "0 errors before, then OOMKilled"),
    (A.restart_pods, "0 errors then OOMKilled"),
    (A.restart_pods, "0 errors, then OOMKilled"),
    (A.restart_pods, "restarted 0 -> 6"),
    (A.restart_pods, "restarts: 0 -> 6"),
    (A.restart_pods, "restartCount: 0 -> 6"),
    (A.restart_pods, "restart_count=0 -> 6"),
    (A.restart_pods, "Restart Count: 0 (was 0), now 6"),
    (A.restart_pods, "OOMKilled: 0 -> 3"),
    (A.restart_pods, "could not connect then restarted"),
    (A.restart_pods, "readiness probe: 0/3 passing"),
    (A.restart_pods, "last restart: 00:03:12 ago"),
    (A.restart_pods, "no response for 30s, container restarted"),
    (A.restart_pods, "not responding, pod restarted"),
    (A.restart_pods, "not responding pod restarted"),
    (A.restart_pods, "no heartbeat since container hang"),
    (A.restart_pods, "no progress, worker stuck"),
    (A.scale_up, "could not allocate memory"),
    (A.scale_up, "not enough memory"),
    (A.scale_up, "ApproximateNumberOfMessagesVisible: 0 -> 1200"),
    (A.scale_up, "pending pods: 0 -> 12"),
    (A.scale_up, "0 idle workers, queue at 900"),
    (A.scale_up, "0 free connection slots"),
    (A.scale_up, "no free memory"),
    (A.scale_up, "no spare capacity"),
    (A.scale_up, "cpu: 0.0 -> 0.98"),
    (A.terminate_connections, "could not obtain lock on row in relation orders"),
    (A.terminate_connections, "no free connection in pool"),
    (A.terminate_connections, "not releasing connection after commit"),
    (A.failover_replica, "replica not reachable"),
    (A.failover_replica, "primary not responding: connection refused"),
    (A.failover_replica, "no response from primary"),
    (A.clear_cache, "0 hits, all misses"),
    (A.clear_cache, "cache hit ratio: 0.00"),
    (A.clear_cache, "cache hit: 0%"),
    (A.clear_cache, "not evicting stale keys, cache full"),
]
REAL += [
    (A.scale_up, "container used 2.0 cpu cores at its limit"),
    (A.rollback_deploy, "Rolled out v2.0 image"),
    (A.rollback_deploy, "canary at 10.0 release"),
    (A.restart_pods, "after 30.0 seconds liveness probe failed"),
    (A.failover_replica, "at 12:00 replica lag rising"),
]
# A zero, a false, a never: each must support nothing.
NONE = [
    (A.restart_pods, '"restartCount": 0'),
    (A.restart_pods, '{"restartCount":0}'),
    (A.restart_pods, "restartCount == 0"),
    (A.restart_pods, "restart count 0"),
    (A.restart_pods, "OOMKilled count is 0"),
    (A.restart_pods, "OOMKilled (0)"),
    (A.restart_pods, "restarts=[0]"),
    (A.restart_pods, "restarts: zero"),
    (A.restart_pods, "restarts: 0/5"),
    (A.restart_pods, "restarts: 0,"),
    (A.restart_pods, "restarts -> 0"),
    (A.restart_pods, "oom_killed=\"false\""),
    (A.restart_pods, "OOMKilled: False"),
    (A.restart_pods, "never restarted"),
    (A.restart_pods, "no restarts or OOM kills"),
    (A.restart_pods, "no pod restarts"),
    (A.restart_pods, "no container restarts in the last hour"),
    (A.restart_pods, "zero crash loops"),
    (A.restart_pods, "none OOMKilled"),
    (A.restart_pods, "0 pods OOMKilled"),
    (A.restart_pods, "restarts\t=\t0"),
    (A.restart_pods, "restarts =0.000"),
    (A.restart_pods, "exit code 0"),
    (A.restart_pods, "exited 0"),
    (A.scale_up, "cpu=0%"),
    (A.scale_up, "memory: 0 MiB"),
    (A.scale_up, "throttles: 0.0"),
    (A.scale_up, "throttled=0 cpu=0"),
    (A.scale_up, "CPU utilization 0.0%"),
    (A.failover_replica, "replica lag 0s"),
    (A.failover_replica, "replica_lag_seconds=0"),
    (A.failover_replica, "lag: 0 ms"),
    (A.clear_cache, "evictions: 0"),
    (A.clear_cache, "0 evictions"),
    (A.terminate_connections, "0 sessions idle in transaction"),
    (A.terminate_connections, "locks_waiting=0"),
    (A.terminate_connections, "idle_in_transaction: 0"),
]
NONE += [
    (A.scale_down, "idle_in_transaction=0"),
    (A.scale_down, "no idle capacity"),
    (A.scale_down, "cpu idle: 0"),
]


@pytest.mark.parametrize(("action", "quote"), REAL)
def test_real_support_is_not_hidden(action, quote):
    assert _supports(action, quote)


@pytest.mark.parametrize(("action", "quote"), NONE)
def test_a_zero_supports_nothing(action, quote):
    assert not _supports(action, quote)


# Fifth review (2026-10-01): the next field read as "what was counted", "not a single", time-ago zeros,
# "then" transitions, and a zero of USE as scale_down's evidence.
FIFTH_NONE = [
    (A.restart_pods, "pod=orders restarts=0 ready=1/1"),
    (A.restart_pods, "restarts=0 healthy=true"),
    (A.restart_pods, "OOMKilled=0 live=1"),
    (A.restart_pods, "restart_count=0 up=3"),
    (A.restart_pods, "restarts: 0 ok"),
    (A.restart_pods, "not a single restart"),
    (A.scale_up, "throttled=0 available=3"),
    (A.scale_up, "cpu=0 idle=3"),
]
FIFTH_REAL = [
    (A.restart_pods, "container restarted 0s ago"),
    (A.restart_pods, "OOMKilled 0 seconds ago"),
    (A.restart_pods, "restarts: 0, then 6"),
    (A.scale_down, "cpu: 0%"),
    (A.scale_down, "cpu utilization: 0.0%"),
    (A.scale_down, "memory used: 0 MiB"),
]


@pytest.mark.parametrize(("action", "quote"), FIFTH_NONE)
def test_the_next_field_or_a_not_a_single_supports_nothing(action, quote):
    assert not _supports(action, quote)


@pytest.mark.parametrize(("action", "quote"), FIFTH_REAL)
def test_a_time_ago_a_then_and_zero_use_for_scale_down_support(action, quote):
    assert _supports(action, quote)
