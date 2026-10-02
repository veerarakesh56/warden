"""Register C10: a restart goes through the target's own rolling settings, and those must keep most pods serving."""

from __future__ import annotations

import types

import pytest

from warden import catalog
from warden.platforms.k8s import _at_once

OK = {"namespace": "shop", "deployment": "orders"}


def _dep(replicas, kind="RollingUpdate", max_unavailable="25%"):
    rolling = types.SimpleNamespace(max_unavailable=max_unavailable) if kind == "RollingUpdate" else None
    strategy = types.SimpleNamespace(type=kind, rolling_update=rolling) if kind else None
    return types.SimpleNamespace(spec=types.SimpleNamespace(replicas=replicas, strategy=strategy))


@pytest.mark.parametrize(("dep", "expected"), [
    (_dep(4, "Recreate"), 4), (_dep(4), 1), (_dep(3, max_unavailable="50%"), 1), (_dep(5, max_unavailable=2), 2),
    (_dep(4, kind=None), None), (_dep(4, max_unavailable=None), None), (_dep(4, max_unavailable="lots"), None)])
def test_how_many_pods_a_restart_takes_down_is_read_from_the_strategy(dep, expected):
    assert _at_once(dep) == expected


@pytest.mark.parametrize(("replicas", "at_once", "refused"), [
    (4, 3, True), (4, 2, False), (4, None, True), (1, 1, False), (3, 2, True), (3, 1, False)])
def test_a_restart_that_would_take_most_pods_down_is_refused(replicas, at_once, refused):
    live = {"namespace": {"shop"}, "deployment": {"orders"}, "current_replicas": replicas, "at_once": at_once}
    problems = catalog.validate("k8s_restart", OK, live)
    assert any(p.startswith("C10") for p in problems) is refused, problems
