"""A deploy counts only if it reached production in the window before the alert started (audit A-B-M10)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from warden import tools
from warden.models import Alert, Severity

AT = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
ALERT = Alert(alert_id="a", name="n", severity=Severity.high, service="s", environment="dev", summary="x",
              started_at=AT.isoformat())


@pytest.mark.parametrize("at, counts", [
    (AT - timedelta(minutes=10), True), (AT - timedelta(hours=5, minutes=59), True),
    (AT + timedelta(minutes=1), True),               # clock skew between monitor and control plane
    (AT - timedelta(hours=7), False),                 # older than the window
    (AT + timedelta(minutes=30), False),              # after the alert: often the first fix attempt
    (datetime.now(UTC), False),                       # a replay long after: "recent" from now took it
    (None, False),
])
def test_a_deploy_counts_only_in_the_window_before_the_alert(at, counts):
    assert tools.deploy_in_window(ALERT, at, timedelta(hours=6)) is counts


@pytest.mark.parametrize("minutes, found", [(-10, 1), (30, 0)])
def test_ecs_and_kubernetes_date_a_deploy_from_the_alert(minutes, found):
    from test_aws_backend import FakeEcs, _service
    from test_aws_backend import _backend as aws
    from test_k8s_backend import ALERT_AT, FakeApps, _rs
    from test_k8s_backend import _alert as k8s_alert
    from test_k8s_backend import _backend as k8s

    deployments = [{"status": "PRIMARY", "createdAt": AT + timedelta(minutes=minutes),
                    "taskDefinition": "arn:aws:ecs:eu-west-1:1:task-definition/checkout:7"}]
    ecs = FakeEcs(services=[_service(deployments=deployments)], task_defs={"checkout:7": ["v2"], "checkout:6": ["v1"]})
    assert len(aws(ecs=ecs).deploys(ALERT.model_copy(update={"labels": {"cluster": "c"}}))) == found
    rs = [_rs(1, ["a:1"], created=ALERT_AT - timedelta(days=2)),
          _rs(2, ["a:2"], created=ALERT_AT + timedelta(minutes=minutes))]
    assert len(k8s(apps=FakeApps(replicasets=rs)).deploys(k8s_alert())) == found
