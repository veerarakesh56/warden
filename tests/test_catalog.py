"""The catalogue: the only writes, every parameter from live state or clamped against it."""

from __future__ import annotations

import pytest

from warden import catalog
from warden.approvals import TIERS
from warden.models import ActionKind


def test_every_entry_is_well_formed_and_nothing_forbidden_is_in_it():
    for name, entry in catalog.CATALOG.items():
        assert entry.tier in TIERS and entry.params and entry.restores
        assert not any(bad in name for bad in catalog.EXCLUDED)
    assert catalog.CATALOG["aurora_failover"].tier == "T3"
    assert catalog.CATALOG["infra_restore_baseline"].tier == "T3"


@pytest.mark.parametrize("name", sorted(catalog.EXCLUDED))
def test_excluded_actions_are_refused_by_name(name):
    assert catalog.validate(name, {}, {}) == [f"{name!r} is not in the catalogue"]


def test_a_target_must_be_one_warden_read_from_live_state():
    live = {"namespace": {"shop"}, "deployment": {"checkout", "orders"}}
    assert catalog.validate("k8s_restart", {"namespace": "shop", "deployment": "checkout"}, live) == []
    for bad in ("payments", "checkout; kubectl delete ns shop", "checkout\n", ""):
        problems = catalog.validate("k8s_restart", {"namespace": "shop", "deployment": bad}, live)
        assert problems == [f"deployment={bad!r} is not something WARDEN read from live state"]


def test_nothing_read_means_nothing_allowed():
    assert catalog.validate("k8s_restart", {"namespace": "shop", "deployment": "checkout"}, {}) == [
        "namespace='shop' is not something WARDEN read from live state",
        "deployment='checkout' is not something WARDEN read from live state"]


def test_missing_and_unexpected_parameters_are_refused():
    live = {"namespace": {"shop"}, "deployment": {"checkout"}}
    assert catalog.validate("k8s_restart", {"namespace": "shop", "deployment": "checkout", "command": "x"},
                            live) == ["unexpected parameter 'command'"]
    assert catalog.validate("k8s_restart", {"namespace": "shop"}, live) == ["missing parameter 'deployment'"]


def test_scaling_is_up_only_and_by_at_most_two():
    live = {"namespace": {"shop"}, "deployment": {"checkout"}, "current_replicas": 3}
    ok = {"namespace": "shop", "deployment": "checkout"}
    assert catalog.validate("k8s_scale", {**ok, "replicas": 5}, live) == []
    assert catalog.validate("k8s_scale", {**ok, "replicas": 6}, live) == ["replicas must be above 3 and at most 5"]
    assert catalog.validate("k8s_scale", {**ok, "replicas": 2}, live) == ["replicas must be above 3 and at most 5"]
    assert catalog.validate("k8s_scale", {**ok, "replicas": True}, live) == ["replicas=True is outside 1..50"]
    no_read = {k: v for k, v in live.items() if k != "current_replicas"}
    assert catalog.validate("k8s_scale", {**ok, "replicas": 5}, no_read) == ["the current replica count was not read"]


def test_capacity_at_most_doubles_and_concurrency_respects_the_account():
    live = {"table": {"orders"}, "current_capacity": 10}
    assert catalog.validate("dynamodb_raise_capacity", {"table": "orders", "capacity": 20}, live) == []
    assert catalog.validate("dynamodb_raise_capacity", {"table": "orders", "capacity": 21}, live) == [
        "capacity must be above 10 and at most 20"]
    live = {"function": {"fn"}, "current_concurrency": 10, "unreserved_account_concurrency": 150}
    assert catalog.validate("lambda_set_reserved_concurrency", {"function": "fn", "concurrency": 60}, live) == []
    assert catalog.validate("lambda_set_reserved_concurrency", {"function": "fn", "concurrency": 61}, live) == [
        "the account has no room for that increase; escalate"]
    assert catalog.validate("lambda_set_reserved_concurrency", {"function": "fn", "concurrency": 5}, live) == [
        "reserved concurrency may only be raised"]


def test_idle_session_termination_is_clamped():
    live = {"database": {"shop"}}
    ok = {"database": "shop", "min_idle_seconds": 300, "max_sessions": 20}
    assert catalog.validate("db_terminate_idle_in_tx", ok, live) == []
    assert catalog.validate("db_terminate_idle_in_tx", {**ok, "min_idle_seconds": 10}, live) == [
        "min_idle_seconds=10 is outside 300..86400"]


def test_proposals_map_to_entries_per_platform_and_the_rest_is_advice():
    assert catalog.for_action(ActionKind.rollback_deploy, "ecs").name == "ecs_rollback_service"
    assert catalog.for_action(ActionKind.rollback_deploy, "lambda").name == "lambda_move_alias"
    for advice in (ActionKind.scale_down, ActionKind.clear_cache, ActionKind.no_action, ActionKind.escalate_to_human):
        assert catalog.for_action(advice, "k8s") is None
    assert catalog.for_action(ActionKind.restart_pods, "ecs") is None
    for per_platform in catalog.FOR_ACTION.values():
        assert set(per_platform.values()) <= set(catalog.CATALOG)
