"""The post-destroy sweep, against a stubbed account.

⛔ The one that matters most is `test_a_revision_tagged_for_another_project_is_never_removed`. This
script deletes things, and `checkout` is an ordinary family name that could exist for real in
somebody's account. A cleanup tool that removes resources it merely *guessed* were its own is how a
benchmark harness becomes an incident.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import teardown_sweep as ts

BASE = "arn:aws:ecs:ap-south-2:111122223333:task-definition/"


class FakeEcs:
    def __init__(self, active=(), inactive=(), tags=None, running=(), cluster_status="INACTIVE"):
        self.active, self.inactive = list(active), list(inactive)
        self.tags = tags or {}
        self.running, self.cluster_status = list(running), cluster_status
        self.deregistered: list[str] = []
        self.deleted_batches: list[list[str]] = []

    def list_task_definitions(self, *, familyPrefix, status, nextToken=None):
        pool = self.active if status == "ACTIVE" else self.inactive
        return {"taskDefinitionArns": [BASE + r for r in pool if r.startswith(familyPrefix)]}

    def describe_task_definition(self, *, taskDefinition, include=None):
        rev = taskDefinition.rsplit("/", 1)[-1]
        tag = self.tags.get(rev)
        return {"tags": [{"key": "Project", "value": tag}] if tag else []}

    def deregister_task_definition(self, *, taskDefinition):
        rev = taskDefinition.rsplit("/", 1)[-1]
        self.deregistered.append(rev)
        self.active.remove(rev)
        self.inactive.append(rev)

    def delete_task_definitions(self, *, taskDefinitions):
        self.deleted_batches.append(list(taskDefinitions))
        for arn in taskDefinitions:
            rev = arn.rsplit("/", 1)[-1]
            if rev in self.inactive:
                self.inactive.remove(rev)

    def list_tasks(self, *, cluster):
        return {"taskArns": self.running}

    def describe_clusters(self, *, clusters):
        return {"clusters": [{"status": self.cluster_status}]}


class Throttled(Exception):
    """Shaped like botocore's ClientError: the code is read off `.response`."""

    def __init__(self, code="ThrottlingException"):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


def test_a_throttled_deregister_is_waited_out_not_abandoned():
    """⛔ The first real sweep deregistered 38 of 45 revisions, hit ThrottlingException and died,
    leaving 7 ACTIVE revisions and a traceback instead of a verdict."""
    calls, waits = [], []
    ecs = FakeEcs(active=["checkout:1"], inactive=[])
    real = ecs.deregister_task_definition

    def flaky(*, taskDefinition):
        calls.append(taskDefinition)
        if len(calls) < 3:
            raise Throttled()
        return real(taskDefinition=taskDefinition)

    ecs.deregister_task_definition = flaky
    ts.apply(ecs, FakeLogs(groups=()), {"deregister": [BASE + "checkout:1"], "delete": [],
                                        "log_groups": []}, sleep=waits.append)
    assert len(calls) == 3 and ecs.deregistered == ["checkout:1"], "it must retry until it lands"
    assert waits == [1, 2], "and back off between tries"


def test_a_permission_error_is_never_retried_into_looking_like_success():
    ecs = FakeEcs(active=["checkout:1"], inactive=[])

    def denied(*, taskDefinition):
        raise Throttled(code="AccessDeniedException")

    ecs.deregister_task_definition = denied
    with pytest.raises(Throttled):
        ts.apply(ecs, FakeLogs(groups=()), {"deregister": [BASE + "checkout:1"], "delete": [],
                                            "log_groups": []}, sleep=lambda _s: None)


class FakeLogs:
    def __init__(self, groups=("/ecs/checkout",)):
        self.groups = list(groups)
        self.deleted: list[str] = []

    def describe_log_groups(self, *, logGroupNamePrefix):
        return {"logGroups": [{"logGroupName": g} for g in self.groups
                              if g.startswith(logGroupNamePrefix)]}

    def delete_log_group(self, *, logGroupName):
        self.deleted.append(logGroupName)
        self.groups.remove(logGroupName)


class FakeTagging:
    def __init__(self, arns=()):
        self.arns = list(arns)

    def get_resources(self, **_):
        return {"ResourceTagMappingList": [{"ResourceARN": a} for a in self.arns]}


class Session:
    def __init__(self, ecs, logs, tagging):
        self._c = {"ecs": ecs, "logs": logs, "resourcegroupstaggingapi": tagging}

    def client(self, name):
        return self._c[name]


def _run(ecs, logs=None, tagging=None, *extra):
    logs = logs or FakeLogs()
    tagging = tagging or FakeTagging()
    return ts.main(["--cluster", "warden-pg-x", *extra], session=Session(ecs, logs, tagging))


# --------------------------------------------------------------------------- safety


def test_a_dry_run_removes_nothing():
    ecs = FakeEcs(active=["checkout:2", "checkout:9"], tags={"checkout:2": "warden-proving-ground"})
    logs = FakeLogs()
    assert _run(ecs, logs) == 0
    assert ecs.deregistered == [] and ecs.deleted_batches == [] and logs.deleted == []


def test_a_revision_tagged_for_another_project_is_never_removed():
    """⛔ Load-bearing. `checkout` could be a real family in a real account."""
    ecs = FakeEcs(active=["checkout:2", "checkout:5"],
                  tags={"checkout:2": "warden-proving-ground", "checkout:5": "payments-prod"})
    _run(ecs, FakeLogs(), FakeTagging(), "--apply")
    assert "checkout:5" not in ecs.deregistered
    assert not any("checkout:5" in a for batch in ecs.deleted_batches for a in batch)


def test_a_similarly_named_family_is_not_swept_up():
    """`familyPrefix` is a PREFIX: 'checkout' also matches 'checkout-legacy'."""
    ecs = FakeEcs(active=["checkout:2", "checkout-legacy:4"])
    _run(ecs, FakeLogs(), FakeTagging(), "--apply")
    assert "checkout-legacy:4" not in ecs.deregistered
    assert not any("checkout-legacy" in a for b in ecs.deleted_batches for a in b)


# --------------------------------------------------------------------------- doing the job


def test_apply_removes_untagged_benchmark_revisions_and_the_recreated_log_group():
    """The resources Terraform never knew about - the reason this script exists."""
    ecs = FakeEcs(active=["checkout:2", "checkout:9"], inactive=["checkout:7"],
                  tags={"checkout:2": "warden-proving-ground"})
    logs = FakeLogs()
    assert _run(ecs, logs, FakeTagging(), "--apply") == 0
    assert sorted(ecs.deregistered) == ["checkout:2", "checkout:9"]
    assert ecs.active == [] and ecs.inactive == []
    assert logs.deleted == ["/ecs/checkout"]


def test_deletes_are_batched_at_ten():
    """DeleteTaskDefinitions accepts at most 10 per call; an 11th would fail the whole call."""
    ecs = FakeEcs(inactive=[f"checkout:{i}" for i in range(4, 27)])
    _run(ecs, FakeLogs(), FakeTagging(), "--apply")
    assert all(len(b) <= 10 for b in ecs.deleted_batches)
    assert sum(len(b) for b in ecs.deleted_batches) == 23


# --------------------------------------------------------------------------- the verdict


def test_anything_left_running_is_not_clean():
    ecs = FakeEcs(running=["arn:aws:ecs:ap-south-2:111122223333:task/x"])
    assert _run(ecs, FakeLogs(groups=()), FakeTagging(), "--apply") == 1


def test_a_tagged_leftover_is_not_clean():
    tagging = FakeTagging(arns=["arn:aws:ec2:ap-south-2:111122223333:vpc/vpc-1"])
    assert _run(FakeEcs(), FakeLogs(groups=()), tagging, "--apply") == 1


def test_an_inactive_cluster_record_is_not_counted_as_left_behind():
    """It cannot be removed any further and costs nothing. Counting it would make the sweep
    permanently red for something no action can fix - and a check that is always red gets ignored."""
    tagging = FakeTagging(arns=["arn:aws:ecs:ap-south-2:111122223333:cluster/warden-pg-x"])
    assert _run(FakeEcs(cluster_status="INACTIVE"), FakeLogs(groups=()), tagging, "--apply") == 0


def test_an_active_cluster_is_counted():
    tagging = FakeTagging(arns=["arn:aws:ecs:ap-south-2:111122223333:cluster/warden-pg-x"])
    assert _run(FakeEcs(cluster_status="ACTIVE"), FakeLogs(groups=()), tagging, "--apply") == 1


@pytest.mark.parametrize("arg", ["--apply", None])
def test_it_never_claims_to_remove_the_ecs_service_linked_role(capsys, arg):
    _run(FakeEcs(), FakeLogs(groups=()), FakeTagging(), *([arg] if arg else []))
    assert "kept on purpose: AWSServiceRoleForECS" in capsys.readouterr().out
