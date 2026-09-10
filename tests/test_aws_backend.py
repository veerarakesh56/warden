"""AwsBackend, against a stubbed boto3 API.

The live path is proven by `scripts/aws_proof.sh` against a real account (ECS + CloudWatch, with
EKS covered by the k8s backend and RDS by the database backend). These tests exist for the failure
modes that are expensive or slow to stage on a real account, and for the properties that must never
regress.

The load-bearing one is `test_iam_policy_grants_exactly_what_the_code_calls`: the Terraform task
role and this module are checked against each other, so a policy can neither fall behind the code
(a runtime AccessDenied during an incident) nor drift ahead of it (a standing grant nothing uses).
"""

from __future__ import annotations

import ast
import inspect
import pathlib
import re
from datetime import UTC, datetime, timedelta

import pytest

from warden import aws_backend
from warden.aws_backend import AwsBackend, _family_revision
from warden.models import Alert, Severity
from warden.tools import PARTIAL_PREFIX, ToolError, gather, resolve_backend

ROOT = pathlib.Path(__file__).resolve().parents[1]
NOW = datetime.now(UTC)


# --------------------------------------------------------------------------- fakes


def _alert(**labels):
    labels.setdefault("cluster", "prod-cluster")
    return Alert(
        alert_id="aws-1", name="EcsServiceUnhealthy", severity=Severity.high, service="checkout",
        environment="prod", summary="tasks flapping",
        started_at=NOW.isoformat(), labels=labels,
    )


class FakeLogs:
    def __init__(self, events=None, raises=None):
        self._events, self._raises, self.calls = events or [], raises, []

    def filter_log_events(self, **kwargs):
        self.calls.append(kwargs)
        if self._raises:
            raise self._raises
        return {"events": self._events}


class FakeCloudWatch:
    def __init__(self, results=None, raises=None):
        self._results, self._raises, self.calls = results, raises, []

    def get_metric_data(self, **kwargs):
        self.calls.append(kwargs)
        if self._raises:
            raise self._raises
        if self._results is None:
            return {"MetricDataResults": [
                {"Id": "m0", "Values": [61.5, 40.0]},
                {"Id": "m1", "Values": [88.25]},
            ]}
        return {"MetricDataResults": self._results}


class FakeEcs:
    def __init__(self, *, services=None, failures=None, task_defs=None):
        self._services = services
        self._failures = failures or []
        self._task_defs = task_defs or {}
        self.calls = []

    def describe_services(self, **kwargs):
        self.calls.append(("describe_services", kwargs))
        return {"services": self._services or [], "failures": self._failures}

    def describe_task_definition(self, **kwargs):
        self.calls.append(("describe_task_definition", kwargs))
        key = kwargs["taskDefinition"]
        value = self._task_defs.get(key)
        if value is None:
            raise RuntimeError(f"ClientError: task definition {key} not found")
        return {"taskDefinition": {"containerDefinitions": [{"image": i} for i in value]}}


def _service(*, running=2, desired=3, pending=1, deployments=None, status="ACTIVE"):
    if deployments is None:
        deployments = [{
            "status": "PRIMARY",
            "rolloutState": "COMPLETED",
            "createdAt": NOW - timedelta(minutes=5),
            "taskDefinition": "arn:aws:ecs:eu-west-1:111122223333:task-definition/checkout:7",
        }]
    return {
        "serviceName": "checkout", "status": status,
        "runningCount": running, "desiredCount": desired, "pendingCount": pending,
        "deployments": deployments,
        "taskDefinition": "arn:aws:ecs:eu-west-1:111122223333:task-definition/checkout:7",
    }


def _backend(*, logs=None, cw=None, ecs=None):
    return AwsBackend(
        logs=logs or FakeLogs(),
        cloudwatch=cw or FakeCloudWatch(),
        ecs=ecs or FakeEcs(services=[_service()], task_defs={
            "checkout:7": ["repo/checkout:v2"],
            "checkout:6": ["repo/checkout:v1"],
        }),
    )


# --------------------------------------------------------------------------- wiring


def test_resolve_backend_knows_aws(monkeypatch):
    # A region, but deliberately no credentials: boto3 resolves credentials lazily at call time,
    # so constructing the backend must work on a laptop with an empty ~/.aws.
    monkeypatch.setenv("WARDEN_AWS_REGION", "eu-west-1")
    backend = resolve_backend("aws")
    assert backend.name == "aws"
    assert isinstance(backend, AwsBackend)


def test_resolve_backend_accepts_the_aliases(monkeypatch):
    monkeypatch.setenv("WARDEN_AWS_REGION", "eu-west-1")
    for name in ("aws", "cloudwatch", "ecs", "AWS"):
        assert resolve_backend(name).name == "aws"


def test_no_region_is_a_readable_error_not_a_botocore_traceback(monkeypatch):
    for var in ("WARDEN_AWS_REGION", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(pathlib.Path(__file__).parent / "no-such-config"))
    with pytest.raises(ToolError, match="credentials or region"):
        AwsBackend()


def test_unknown_backend_error_lists_aws():
    with pytest.raises(ToolError, match="aws"):
        resolve_backend("nonsense")


def test_missing_cluster_is_an_error_not_a_guessed_default():
    """'default' is a real ECS cluster name. Guessing it would point the investigation at a real
    thing that is not the one under investigation, and still return data."""
    alert = Alert(
        alert_id="a", name="n", severity=Severity.high, service="checkout", environment="prod",
        summary="s", started_at=NOW.isoformat(), labels={},
    )
    with pytest.raises(ToolError, match="WARDEN_AWS_CLUSTER"):
        _backend().metrics(alert)


def test_cluster_comes_from_the_environment_when_the_label_is_absent(monkeypatch):
    monkeypatch.setenv("WARDEN_AWS_CLUSTER", "from-env")
    alert = Alert(
        alert_id="a", name="n", severity=Severity.high, service="checkout", environment="prod",
        summary="s", started_at=NOW.isoformat(), labels={},
    )
    ecs = FakeEcs(services=[_service()], task_defs={"checkout:7": ["i"], "checkout:6": ["i"]})
    _backend(ecs=ecs).metrics(alert)
    assert ecs.calls[0][1]["cluster"] == "from-env"


# --------------------------------------------------------------------------- logs


def test_logs_are_formatted_with_stream_and_timestamp():
    ts = int(NOW.timestamp() * 1000)
    logs = FakeLogs(events=[
        {"logStreamName": "ecs/checkout/abc", "timestamp": ts, "message": "OOM killed\n"},
        {"logStreamName": "ecs/checkout/abc", "timestamp": ts, "message": "   "},
    ])
    lines = _backend(logs=logs).logs(_alert())
    assert len(lines) == 1, "a whitespace-only event is not a log line"
    assert lines[0].startswith("ecs/checkout/abc ")
    assert lines[0].endswith("OOM killed")


def test_log_group_defaults_to_the_ecs_convention_and_labels_win():
    logs = FakeLogs()
    _backend(logs=logs).logs(_alert())
    assert logs.calls[0]["logGroupName"] == "/ecs/checkout"

    logs = FakeLogs()
    _backend(logs=logs).logs(_alert(log_group="/custom/group"))
    assert logs.calls[0]["logGroupName"] == "/custom/group"


def test_log_read_is_bounded_in_time_and_count():
    logs = FakeLogs()
    _backend(logs=logs).logs(_alert())
    call = logs.calls[0]
    assert call["limit"] == aws_backend.LOG_EVENT_LIMIT
    assert call["endTime"] > call["startTime"], "an unbounded read blows the tool budget"


def test_a_missing_log_group_is_a_partial_failure_not_a_crash_and_not_silence():
    """A log group that does not exist must reach tool_errors, where policy P8 reads it. Silence
    would look like a service that simply logged nothing."""
    logs = FakeLogs(raises=RuntimeError("ResourceNotFoundException: log group does not exist"))
    lines = _backend(logs=logs).logs(_alert())
    assert len(lines) == 1 and lines[0].startswith(PARTIAL_PREFIX)


def test_log_truncation_announces_itself_as_a_partial():
    ts = int(NOW.timestamp() * 1000)
    many = [{"logStreamName": "s", "timestamp": ts, "message": f"line {i}"} for i in range(500)]
    lines = _backend(logs=FakeLogs(events=many)).logs(_alert())
    partials = [x for x in lines if x.startswith(PARTIAL_PREFIX)]
    assert partials, "silent truncation hides that the picture is incomplete"
    assert len([x for x in lines if not x.startswith(PARTIAL_PREFIX)]) == aws_backend.LOG_MAX_LINES


def test_gather_routes_the_partial_into_tool_errors():
    """End to end: the in-band prefix must actually land where the verifier looks."""
    logs = FakeLogs(raises=RuntimeError("ResourceNotFoundException: nope"))
    bundle = gather(_alert(), backend=_backend(logs=logs))
    assert any("logs:" in e for e in bundle.tool_errors)
    assert bundle.logs == []


# --------------------------------------------------------------------------- metrics


def test_metrics_report_exact_task_counts_and_sampled_utilisation():
    out = _backend().metrics(_alert())
    assert out["tasks_running"] == 2.0
    assert out["tasks_desired"] == 3.0
    assert out["tasks_pending"] == 1.0
    assert out["cpu_utilization_pct"] == 61.5, "the peak in the window, not the first sample"
    assert out["memory_utilization_pct"] == 88.25


def test_a_missing_service_raises_rather_than_returning_zeroes():
    """The k8s backend learned this the hard way: a typo used to yield zeroed metrics that the
    verifier read as 'inspected, fine'. ECS answers a missing service with HTTP 200 + `failures`."""
    ecs = FakeEcs(services=[], failures=[{"arn": "checkout", "reason": "MISSING"}])
    with pytest.raises(ToolError, match="MISSING"):
        _backend(ecs=ecs).metrics(_alert())


def test_an_inactive_service_counts_as_missing():
    ecs = FakeEcs(services=[_service(status="INACTIVE")])
    with pytest.raises(ToolError):
        _backend(ecs=ecs).metrics(_alert())


def test_a_failed_rollout_is_counted():
    deployments = [
        {"status": "PRIMARY", "rolloutState": "FAILED", "createdAt": NOW,
         "taskDefinition": "arn:aws:ecs:eu-west-1:1:task-definition/checkout:7"},
        {"status": "ACTIVE", "rolloutState": "COMPLETED", "createdAt": NOW,
         "taskDefinition": "arn:aws:ecs:eu-west-1:1:task-definition/checkout:6"},
    ]
    out = _backend(ecs=FakeEcs(services=[_service(deployments=deployments)])).metrics(_alert())
    assert out["deployments_failed"] == 1.0
    assert out["deployments_in_flight"] == 2.0


def test_utilisation_is_omitted_never_zeroed_when_cloudwatch_has_no_datapoint():
    """A service that has published nothing is not a service at 0% CPU, and the difference decides
    whether the verifier sees evidence or an absence."""
    cw = FakeCloudWatch(results=[{"Id": "m0", "Values": []}, {"Id": "m1", "Values": []}])
    out = _backend(cw=cw).metrics(_alert())
    assert "cpu_utilization_pct" not in out
    assert "memory_utilization_pct" not in out


def test_losing_cloudwatch_does_not_lose_the_exact_task_counts():
    cw = FakeCloudWatch(raises=RuntimeError("ThrottlingException: rate exceeded"))
    out = _backend(cw=cw).metrics(_alert())
    assert out["tasks_running"] == 2.0
    assert "cpu_utilization_pct" not in out


def test_metric_query_is_scoped_to_this_cluster_and_service():
    cw = FakeCloudWatch()
    _backend(cw=cw).metrics(_alert())
    dims = cw.calls[0]["MetricDataQueries"][0]["MetricStat"]["Metric"]["Dimensions"]
    assert {d["Name"]: d["Value"] for d in dims} == {
        "ClusterName": "prod-cluster", "ServiceName": "checkout"
    }


# --------------------------------------------------------------------------- deploys


def test_a_real_image_change_is_reported_as_a_deploy():
    out = _backend().deploys(_alert())
    assert len(out) == 1
    assert out[0]["image"] == "repo/checkout:v2"
    assert out[0]["previous_image"] == "repo/checkout:v1"
    assert out[0]["revision"] == "7"
    assert out[0]["by"] == "ecs"


def test_force_new_deployment_is_not_a_deploy():
    """`aws ecs update-service --force-new-deployment` is ECS's `kubectl rollout restart`: a new
    deployment record with the same task definition. Counting it would satisfy policy P5's
    evidence for a rollback that cannot possibly help."""
    ecs = FakeEcs(services=[_service()], task_defs={
        "checkout:7": ["repo/checkout:v2"],
        "checkout:6": ["repo/checkout:v2"],
    })
    assert _backend(ecs=ecs).deploys(_alert()) == []


def test_container_reordering_is_not_a_deploy():
    ecs = FakeEcs(services=[_service()], task_defs={
        "checkout:7": ["repo/app:v1", "repo/sidecar:v3"],
        "checkout:6": ["repo/sidecar:v3", "repo/app:v1"],
    })
    assert _backend(ecs=ecs).deploys(_alert()) == []


def test_an_unreadable_previous_revision_reports_a_gap_and_NO_deploy():
    """The branch that matters. Without the previous revision we cannot tell a deploy from a
    restart; reporting it anyway would let P5 approve a rollback on a restart. Report the gap."""
    ecs = FakeEcs(services=[_service()], task_defs={"checkout:7": ["repo/checkout:v2"]})
    out = _backend(ecs=ecs).deploys(_alert())
    assert len(out) == 1
    assert isinstance(out[0], str) and out[0].startswith(PARTIAL_PREFIX)
    assert "cannot prove" in out[0]
    assert not any(isinstance(x, dict) for x in out), "no deploy may be reported"


def test_the_unprovable_deploy_reaches_tool_errors_and_leaves_no_deploy_behind():
    ecs = FakeEcs(services=[_service()], task_defs={"checkout:7": ["repo/checkout:v2"]})
    bundle = gather(_alert(), backend=_backend(ecs=ecs))
    assert bundle.recent_deploys == []
    assert any("recent_deploys:" in e for e in bundle.tool_errors)


def test_the_first_revision_is_a_deploy_with_no_previous_image():
    arn = "arn:aws:ecs:eu-west-1:1:task-definition/checkout:1"
    deployments = [{"status": "PRIMARY", "createdAt": NOW, "taskDefinition": arn}]
    ecs = FakeEcs(services=[_service(deployments=deployments)],
                  task_defs={"checkout:1": ["repo/checkout:v1"]})
    out = _backend(ecs=ecs).deploys(_alert())
    assert len(out) == 1 and out[0]["previous_image"] == ""


def test_an_old_deployment_is_outside_the_window():
    old = NOW - aws_backend.RECENT_DEPLOY_WINDOW - timedelta(hours=1)
    deployments = [{
        "status": "PRIMARY", "createdAt": old,
        "taskDefinition": "arn:aws:ecs:eu-west-1:1:task-definition/checkout:7",
    }]
    ecs = FakeEcs(services=[_service(deployments=deployments)], task_defs={
        "checkout:7": ["v2"], "checkout:6": ["v1"],
    })
    assert _backend(ecs=ecs).deploys(_alert()) == []


def test_a_naive_datetime_from_a_stub_does_not_raise():
    """boto3 returns tz-aware datetimes; nothing should explode if something else does not."""
    deployments = [{
        "status": "PRIMARY", "createdAt": datetime.now(),  # noqa: DTZ005 - deliberate
        "taskDefinition": "arn:aws:ecs:eu-west-1:1:task-definition/checkout:7",
    }]
    ecs = FakeEcs(services=[_service(deployments=deployments)], task_defs={
        "checkout:7": ["v2"], "checkout:6": ["v1"],
    })
    assert len(_backend(ecs=ecs).deploys(_alert())) == 1


@pytest.mark.parametrize(
    "arn,expected",
    [
        ("arn:aws:ecs:eu-west-1:111122223333:task-definition/checkout:7", ("checkout", 7)),
        ("checkout:12", ("checkout", 12)),
        ("arn:aws:ecs:eu-west-1:1:task-definition/checkout", ("", 0)),
        ("", ("", 0)),
        ("checkout:notanumber", ("", 0)),
    ],
)
def test_family_revision_parsing(arn, expected):
    assert _family_revision(arn) == expected


def test_an_unparseable_task_definition_is_a_partial_not_a_traceback():
    deployments = [{"status": "PRIMARY", "createdAt": NOW, "taskDefinition": "garbage"}]
    ecs = FakeEcs(services=[_service(deployments=deployments)])
    out = _backend(ecs=ecs).deploys(_alert())
    assert out and isinstance(out[0], str) and out[0].startswith(PARTIAL_PREFIX)


# --------------------------------------------------------------------------- the boundary


def _dotted(node) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _api_calls() -> set[tuple[str, str]]:
    """(client attribute, boto3 method) for every AWS call this module makes, read off the AST."""
    src = pathlib.Path(inspect.getsourcefile(aws_backend)).read_text(encoding="utf-8")
    found: set[tuple[str, str]] = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            target = _dotted(node.func.value)
            if target.startswith("self._") and target != "self._images":
                found.add((target.split(".", 1)[1], node.func.attr))
    return found


def test_backend_cannot_write_checked_on_the_ast_not_the_text():
    """A tripwire, not the boundary. The task role in terraform/ is the boundary, and this test
    says so. Walked on the AST rather than grepped, so prose in a docstring cannot trip it and a
    `getattr` cannot slip past it."""
    src = pathlib.Path(inspect.getsourcefile(aws_backend)).read_text(encoding="utf-8")
    tree = ast.parse(src)

    write_shaped = re.compile(
        r"^(create|delete|update|put|register|deregister|run|start|stop|terminate|modify|"
        r"reboot|restore|attach|detach|tag|untag|set|associate|disassociate|execute|invoke)_"
    )
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _dotted(node.func)
            leaf = name.rsplit(".", 1)[-1]
            if write_shaped.match(leaf):
                offenders.append(f"write-shaped call {name}")
            if leaf in ("system", "popen", "run", "Popen", "check_output", "make_api_call"):
                offenders.append(f"escape hatch {name}")
            if leaf == "getattr" and node.args and _dotted(node.args[0]).startswith("self._"):
                offenders.append("dynamic lookup on an AWS client")
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            mods = [a.name for a in node.names] + (
                [node.module] if isinstance(node, ast.ImportFrom) else []
            )
            for m in mods:
                if m and m.split(".")[0] in ("subprocess", "shlex", "pty"):
                    offenders.append(f"import {m}")
    assert not offenders, f"aws_backend.py must not be able to write; found: {offenders}"


# boto3 client attribute -> the IAM service prefix it speaks.
_CLIENT_PREFIX = {"_logs": "logs", "_cw": "cloudwatch", "_ecs": "ecs"}


def _iam_action(client_attr: str, method: str) -> str:
    """`self._ecs.describe_services(...)` -> `ecs:DescribeServices`.

    boto3 method names are the snake_case of the API action by construction, so this mapping is
    mechanical rather than a hand-maintained table that can rot.
    """
    action = "".join(part.title() for part in method.split("_"))
    return f"{_CLIENT_PREFIX[client_attr]}:{action}"


def _terraform_task_actions() -> set[str]:
    text = (ROOT / "terraform" / "main.tf").read_text(encoding="utf-8")
    block = re.search(
        r'data "aws_iam_policy_document" "task_readonly".*?\n}\n', text, re.DOTALL
    )
    assert block, "task_readonly policy document not found in terraform/main.tf"
    actions = re.search(r"actions\s*=\s*\[(.*?)\]", block.group(0), re.DOTALL)
    assert actions, "no actions list in task_readonly"
    return set(re.findall(r'"([^"]+)"', actions.group(1)))


def test_iam_policy_grants_exactly_what_the_code_calls():
    """The load-bearing test. Checked in BOTH directions on purpose.

    Under-granting is an AccessDenied discovered during a real incident, which is the worst moment
    to discover it. Over-granting is a standing permission on a production account that nothing
    uses — the shape every least-privilege review actually finds. Asserting equality means the
    Terraform cannot drift from the code in either direction without CI going red.
    """
    called = {_iam_action(attr, method) for attr, method in _api_calls()}
    granted = _terraform_task_actions()

    assert called, "the AST walk found no AWS calls at all - the test itself has rotted"
    assert called == granted, (
        f"IAM policy and code disagree.\n"
        f"  code calls but policy does not grant: {sorted(called - granted)}\n"
        f"  policy grants but code never calls:   {sorted(granted - called)}"
    )


def test_every_call_the_code_makes_is_a_read():
    """Independent of the policy: the four actions must each be a Describe/Get/Filter/List."""
    for attr, method in _api_calls():
        action = _iam_action(attr, method)
        verb = action.split(":", 1)[1]
        assert verb.startswith(("Describe", "Get", "List", "Filter", "Lookup")), action


def test_the_task_definition_declares_the_aws_backend():
    """The Terraform grants CloudWatch/ECS read actions. If the container does not run with
    WARDEN_BACKEND=aws it reads shipped fixtures instead, and the whole role is decoration."""
    text = (ROOT / "terraform" / "main.tf").read_text(encoding="utf-8")
    env_block = re.search(r"environment\s*=\s*\[(.*?)\]", text, re.DOTALL)
    assert env_block, "no environment block in the task definition"
    assert re.search(
        r'name\s*=\s*"WARDEN_BACKEND".*?value\s*=\s*var\.backend', env_block.group(1), re.DOTALL
    ), "the task must set WARDEN_BACKEND, or it runs on fixtures with a live IAM role"


def test_readme_documents_the_aws_backend():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "WARDEN_BACKEND=aws" in text


# --------------------------------------------------------------------------- what to compare with
#
# ⛔ Found by running against a real AWS account, not by a fixture.
#
# `deploys()` used to compare revision N with revision N-1, assuming the previously REGISTERED
# revision is the previously DEPLOYED one. A real account breaks that constantly: CI registers
# revisions that never ship, a rollback leaves a gap, and a benchmark wave registers one variant per
# scenario. Seven scenarios in a row deployed checkout:7 to checkout:13, so each was compared with
# the PREVIOUS SCENARIO's variant instead of with what was running. Same image, so WARDEN reported
# NO DEPLOY for a genuine deploy - and P5-NO-DEPLOY-TO-ROLL-BACK then rejected the correct rollback.
#
# ECS already answers this: during a rollout describe_services returns the PRIMARY deployment
# alongside the ACTIVE one it is replacing.


def _rollout(primary_rev: int, active_rev: int) -> list[dict]:
    base = "arn:aws:ecs:eu-west-1:111122223333:task-definition/checkout:"
    return [
        {"status": "PRIMARY", "createdAt": NOW, "taskDefinition": f"{base}{primary_rev}"},
        {"status": "ACTIVE", "createdAt": NOW - timedelta(minutes=30),
         "taskDefinition": f"{base}{active_rev}"},
    ]


def test_a_deploy_is_compared_with_what_was_running_not_with_revision_minus_one():
    """checkout:13 replacing checkout:2. Revision 12 happens to carry the same image as 13 - as it
    did in the real wave - so comparing against it reports no deploy and hides a real change."""
    ecs = FakeEcs(services=[_service(deployments=_rollout(13, 2))], task_defs={
        "checkout:13": ["repo/checkout:broken"],
        "checkout:12": ["repo/checkout:broken"],   # the previous SCENARIO's variant
        "checkout:2": ["repo/checkout:healthy"],   # what was actually running
    })
    out = _backend(ecs=ecs).deploys(_alert())
    assert len(out) == 1, "a genuine deploy was reported as no deploy"
    assert out[0]["image"] == "repo/checkout:broken"
    assert out[0]["previous_image"] == "repo/checkout:healthy"


def test_a_restart_is_still_not_a_deploy():
    """The property that must survive the fix. A force-new-deployment moves the deployment record
    without changing the task definition, and calling that a deploy would hand P5 the evidence it
    needs to approve a rollback that could not possibly help."""
    ecs = FakeEcs(services=[_service(deployments=_rollout(7, 7))], task_defs={
        "checkout:7": ["repo/checkout:v2"],
        "checkout:6": ["repo/checkout:v1"],
    })
    assert _backend(ecs=ecs).deploys(_alert()) == [], "a restart was reported as a deploy"


def test_it_falls_back_to_the_previous_revision_when_the_service_is_steady():
    """After a rollout completes there is only a PRIMARY deployment, so there is nothing else to
    compare with and revision-1 is the best available answer. Keeping this is what stops the fix
    from blinding WARDEN to a deploy it used to see."""
    deployments = [{
        "status": "PRIMARY", "createdAt": NOW,
        "taskDefinition": "arn:aws:ecs:eu-west-1:111122223333:task-definition/checkout:7",
    }]
    ecs = FakeEcs(services=[_service(deployments=deployments)], task_defs={
        "checkout:7": ["repo/checkout:v2"], "checkout:6": ["repo/checkout:v1"],
    })
    out = _backend(ecs=ecs).deploys(_alert())
    assert len(out) == 1 and out[0]["previous_image"] == "repo/checkout:v1"
