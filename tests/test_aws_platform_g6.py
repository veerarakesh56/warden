"""G6: the AWS platform behind the RemediationWorkflow. Each entry reads what the catalogue checks, writes only through
an actor session minted for that one plan (naming its approvers - audit A-P-5 - and allowing only that entry's
action on that resource), refuses when the resource moved since the approval, restores its snapshot on rollback, and
calls a target healthy only on a positive signal."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from warden import catalog
from warden.platforms import RoutedPlatform
from warden.platforms.aws import AwsPlatform, AwsPlatformError, AwsPlatformRefused

NOW = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)
ACCT = "0" * 12  # a placeholder account, built from parts (no account id in the repo)
FN = "warden-dev-checkout"
FN_ARN = f"arn:aws:lambda:test-region-1:{ACCT}:function:{FN}"
WHO = {"incident": "inc-7", "plan_hash": "c" * 64, "approvers": ["owner"]}


class _Err(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class Fake:
    """Read-side AWS clients over one dict of state; writes are recorded per actor session."""

    def __init__(self):
        self.alias = {"FunctionVersion": "9", "RevisionId": "r1"}
        self.versions = [{"Version": "$LATEST"}] + [
            {"Version": str(v), "LastModified": "2026-10-03T11:00:00.000+0000"} for v in range(1, 10)]
        self.served = {"3": 500.0, "8": 0.0}  # version 8 is the numerically previous one; 3 served the traffic
        self.reserved = 0
        self.free = 900
        self.esm = {"UUID": "u-1", "FunctionArn": FN_ARN, "State": "Disabled"}
        self.rule = {"Name": "warden-dev-reconcile-5m", "Arn": f"arn:aws:events:test-region-1:{ACCT}:rule/warden-dev-reconcile-5m",
                     "State": "DISABLED"}
        self.table = {"TableName": "warden-dev-carts", "TableArn": f"arn:aws:dynamodb:test-region-1:{ACCT}:table/warden-dev-carts",
                      "TableStatus": "ACTIVE", "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
                      "BillingModeSummary": {"BillingMode": "PROVISIONED"}}
        self.scaled = []
        self.service = {"serviceName": "orders", "serviceArn": f"arn:aws:ecs:test-region-1:{ACCT}:service/c1/orders",
                        "taskDefinition": "arn:td/orders:12", "deployments": [{"rolloutState": "COMPLETED"}],
                        "desiredCount": 2, "runningCount": 2, "tags": [{"key": "Environment", "value": "dev"}]}
        self.history = [  # newest first by finish time once sorted; the running one is the newest success
            {"targetServiceRevisionArn": "rev-12", "finishedAt": NOW - timedelta(minutes=5)},
            {"targetServiceRevisionArn": "rev-11", "finishedAt": NOW - timedelta(days=2)},
            {"targetServiceRevisionArn": "rev-10", "finishedAt": NOW - timedelta(days=9)}]
        self.revisions = {"rev-12": "arn:td/orders:12", "rev-11": "arn:td/orders:9", "rev-10": "arn:td/orders:8"}
        self.metrics = {"Invocations": 40.0, "Errors": 0.0, "Throttles": 0.0, "ConsumedWriteCapacityUnits": 3.0,
                        "WriteThrottleEvents": 0.0}
        self.partial = False
        self.writes = []
        self.sessions = []
        self.fail_write = None

    # --- lambda
    def get_function_configuration(self, FunctionName):
        return {"FunctionArn": FN_ARN, "FunctionName": FN}

    def get_alias(self, FunctionName, Name):
        return {**self.alias}

    def list_versions_by_function(self, FunctionName, **kw):
        return {"Versions": self.versions}

    def list_tags(self, Resource):
        return {"Tags": {"Environment": "dev"}}

    def get_function_concurrency(self, FunctionName):
        return {"ReservedConcurrentExecutions": self.reserved} if self.reserved is not None else {}

    def get_account_settings(self):
        return {"AccountLimit": {"UnreservedConcurrentExecutions": self.free}}

    def get_event_source_mapping(self, UUID):
        return {**self.esm}

    # --- cloudwatch
    def get_metric_data(self, MetricDataQueries, StartTime, EndTime):
        out = []
        for q in MetricDataQueries:
            dims = {d["Name"]: d["Value"] for d in q["MetricStat"]["Metric"]["Dimensions"]}
            if "ExecutedVersion" in dims:
                out.append({"Id": q["Id"], "Values": [self.served.get(dims["ExecutedVersion"], 0.0)]})
            else:
                out.append({"Id": q["Id"], "StatusCode": "PartialData" if self.partial else "Complete",
                            "Values": [self.metrics[q["MetricStat"]["Metric"]["MetricName"]]]})
        return {"MetricDataResults": out}

    # --- events
    def describe_rule(self, Name):
        return {**self.rule}

    def list_tags_for_resource(self, ResourceARN):
        return {"Tags": [{"Key": "Environment", "Value": "dev"}]}

    # --- dynamodb
    def describe_table(self, TableName):
        return {"Table": {**self.table}}

    def list_tags_of_resource(self, ResourceArn):
        return {"Tags": [{"Key": "Environment", "Value": "dev"}]}

    def describe_scalable_targets(self, **kw):
        return {"ScalableTargets": self.scaled}

    # --- ecs
    def describe_services(self, cluster, services, include=None):
        return {"services": [{**self.service}]}

    def list_service_deployments(self, **kw):
        return {"serviceDeployments": list(reversed(self.history))}  # order not promised: sorted by WARDEN

    def describe_service_revisions(self, serviceRevisionArns):
        return {"serviceRevisions": [{"serviceRevisionArn": a, "taskDefinition": self.revisions[a]}
                                     for a in serviceRevisionArns]}

    # --- the actor's clients
    def actor(self, who, actions, resources, condition):
        self.sessions.append({"who": who, "actions": actions, "resources": resources, "condition": condition})
        fake = self

        class Writer:
            def __getattr__(self, name):
                def call(**kw):
                    if fake.fail_write:
                        raise fake.fail_write
                    fake.writes.append((name, kw))
                return call
        return lambda service: Writer()


@pytest.fixture
def aws():
    f = Fake()
    return f, AwsPlatform(reader=lambda service: f, actor=f.actor, clock=lambda: NOW)


def _ok(entry, params, live):
    return catalog.validate(entry, params, live)


def test_the_alias_goes_back_to_the_version_that_served_traffic_not_the_numerically_previous(aws):
    f, p = aws
    live = p.live("lambda_move_alias", {"function": FN, "alias": "live"})
    assert live["to_version"] == {"3"} and live["environment"] == "dev" and live["rollout"] == "complete"
    params = {"function": FN, "alias": "live", "to_version": "3"}
    assert _ok("lambda_move_alias", params, live) == []
    assert _ok("lambda_move_alias", {**params, "to_version": "8"}, live)  # the Wave 4 mistake is refused
    out = p.apply("lambda_move_alias", params, snapshot=live["state"], who=WHO)
    assert f.writes == [("update_alias", {"FunctionName": FN, "Name": "live", "FunctionVersion": "3", "RevisionId": "r1"})]
    [s] = f.sessions
    assert s["who"] == WHO and s["actions"] == ["lambda:UpdateAlias"] and s["resources"] == [FN_ARN]
    assert "from version 9 to 3" in out


def test_a_moved_alias_or_a_canary_is_refused_and_nothing_is_written(aws):
    f, p = aws
    live = p.live("lambda_move_alias", {"function": FN, "alias": "live"})
    f.alias = {"FunctionVersion": "10", "RevisionId": "r2"}
    with pytest.raises(AwsPlatformRefused, match="changed since|serves version 10"):
        p.apply("lambda_move_alias", {"function": FN, "alias": "live", "to_version": "3"}, snapshot=live["state"], who=WHO)
    assert f.writes == [] and f.sessions == []
    f.alias = {"FunctionVersion": "9", "RevisionId": "r1", "RoutingConfig": {"AdditionalVersionWeights": {"8": 0.1}}}
    live = p.live("lambda_move_alias", {"function": FN, "alias": "live"})
    assert any("P21" in x for x in _ok("lambda_move_alias", {"function": FN, "alias": "live", "to_version": "3"}, live))


def test_the_rollback_returns_the_alias_to_the_snapshot(aws):
    f, p = aws
    params = {"function": FN, "alias": "live", "to_version": "3"}
    snap = p.live("lambda_move_alias", params)["state"]
    f.alias = {"FunctionVersion": "3", "RevisionId": "r2"}
    p.rollback("lambda_move_alias", params, snap, who=WHO)
    assert f.writes[-1] == ("update_alias", {"FunctionName": FN, "Name": "live", "FunctionVersion": "9", "RevisionId": "r2"})


def test_no_write_without_approvers(aws):
    f, p = aws
    params = {"function": FN, "alias": "live", "to_version": "3"}
    snap = p.live("lambda_move_alias", params)["state"]
    for who in (None, {**WHO, "approvers": []}):
        with pytest.raises(AwsPlatformRefused, match="approvers"):
            p.apply("lambda_move_alias", params, snapshot=snap, who=who)
    assert f.writes == []


def test_concurrency_is_only_ever_raised_from_an_existing_reservation_within_the_account(aws):
    f, p = aws
    f.reserved = None
    live = p.live("lambda_set_reserved_concurrency", {"function": FN})
    assert live["current_concurrency"] is None  # a new reservation would cap the function: never created
    assert _ok("lambda_set_reserved_concurrency", {"function": FN, "concurrency": 5}, live)
    f.reserved = 0
    live = p.live("lambda_set_reserved_concurrency", {"function": FN})
    assert _ok("lambda_set_reserved_concurrency", {"function": FN, "concurrency": 5}, live) == []
    p.apply("lambda_set_reserved_concurrency", {"function": FN, "concurrency": 5}, snapshot=live["state"], who=WHO)
    assert f.writes == [("put_function_concurrency", {"FunctionName": FN, "ReservedConcurrentExecutions": 5})]
    f.free = 50  # the account has no room left above AWS's 100 unreserved
    with pytest.raises(AwsPlatformRefused, match="outside the bound"):
        p.apply("lambda_set_reserved_concurrency", {"function": FN, "concurrency": 5}, snapshot=live["state"], who=WHO)


def test_an_event_source_mapping_is_enabled_under_its_functions_exact_arn(aws):
    f, p = aws
    live = p.live("lambda_enable_esm", {"mapping": "u-1"})
    assert live["mapping"] == {"u-1"} and _ok("lambda_enable_esm", {"mapping": "u-1"}, live) == []
    p.apply("lambda_enable_esm", {"mapping": "u-1"}, snapshot=live["state"], who=WHO)
    assert f.writes == [("update_event_source_mapping", {"UUID": "u-1", "Enabled": True})]
    esm_arn = f"arn:aws:lambda:test-region-1:{ACCT}:event-source-mapping:u-1"
    assert f.sessions[0]["resources"] == [esm_arn] and f.sessions[0]["condition"] == {"ArnEquals": {"lambda:FunctionArn": FN_ARN}}
    f.esm["State"] = "Enabled"
    assert p.live("lambda_enable_esm", {"mapping": "u-1"})["mapping"] == set()  # nothing to enable
    with pytest.raises(AwsPlatformRefused, match="already enabled"):
        p.apply("lambda_enable_esm", {"mapping": "u-1"}, snapshot=live["state"], who=WHO)


def test_a_rule_is_enabled_and_its_rollback_disables_it(aws):
    f, p = aws
    live = p.live("events_enable_rule", {"rule": f.rule["Name"]})
    p.apply("events_enable_rule", {"rule": f.rule["Name"]}, snapshot=live["state"], who=WHO)
    assert f.writes == [("enable_rule", {"Name": f.rule["Name"]})] and f.sessions[0]["resources"] == [f.rule["Arn"]]
    f.rule["State"] = "ENABLED"
    p.rollback("events_enable_rule", {"rule": f.rule["Name"]}, live["state"], who=WHO)
    assert f.writes[-1] == ("disable_rule", {"Name": f.rule["Name"]}) and f.sessions[-1]["actions"] == ["events:DisableRule"]


def test_table_write_capacity_at_most_doubles_and_an_autoscaled_table_is_left_alone(aws):
    f, p = aws
    live = p.live("dynamodb_raise_capacity", {"table": "warden-dev-carts"})
    assert _ok("dynamodb_raise_capacity", {"table": "warden-dev-carts", "capacity": 10}, live) == []
    assert _ok("dynamodb_raise_capacity", {"table": "warden-dev-carts", "capacity": 11}, live)
    with pytest.raises(AwsPlatformRefused, match="at most double"):  # the platform re-checks, not only the catalogue
        p.apply("dynamodb_raise_capacity", {"table": "warden-dev-carts", "capacity": 11}, snapshot=live["state"], who=WHO)
    p.apply("dynamodb_raise_capacity", {"table": "warden-dev-carts", "capacity": 10}, snapshot=live["state"], who=WHO)
    assert f.writes == [("update_table", {"TableName": "warden-dev-carts",
                                          "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": 10}})]
    f.scaled = [{"ResourceId": "table/warden-dev-carts"}]
    live = p.live("dynamodb_raise_capacity", {"table": "warden-dev-carts"})
    assert any("C4" in x for x in _ok("dynamodb_raise_capacity", {"table": "warden-dev-carts", "capacity": 10}, live))
    f.table["BillingModeSummary"] = {"BillingMode": "PAY_PER_REQUEST"}
    assert p.live("dynamodb_raise_capacity", {"table": "warden-dev-carts"})["current_capacity"] is None


def test_an_ecs_service_goes_back_to_its_last_steady_task_definition_from_ecs_history(aws):
    f, p = aws
    live = p.live("ecs_rollback_service", {"cluster": "c1", "service": "orders"})
    # orders:9 was the last success before the running :12 - not :11, the "revision minus one" (audit A-B-M6).
    assert live["to_task_definition"] == {"arn:td/orders:9"}
    params = {"cluster": "c1", "service": "orders", "to_task_definition": "arn:td/orders:9"}
    assert _ok("ecs_rollback_service", params, live) == []
    p.apply("ecs_rollback_service", params, snapshot=live["state"], who=WHO)
    assert f.writes == [("update_service", {"cluster": "c1", "service": "orders", "taskDefinition": "arn:td/orders:9"})]
    f.revisions["rev-12"] = "arn:td/orders:13"  # the running one is not the last success: a person reads the history
    assert p.live("ecs_rollback_service", {"cluster": "c1", "service": "orders"})["to_task_definition"] == set()


def test_health_is_a_positive_signal_and_unknown_is_not_healthy(aws):
    f, p = aws
    assert p.healthy(FN, entry="lambda_move_alias") is True
    f.metrics["Invocations"] = 0.0  # a dead function errs nothing: no traffic is not healthy
    assert p.healthy(FN, entry="lambda_move_alias") is False
    f.metrics["Invocations"], f.partial = 40.0, True
    assert p.healthy(FN, entry="lambda_move_alias") is False
    f.partial = False
    assert p.healthy("orders", entry="ecs_rollback_service", params={"cluster": "c1"}) is True
    f.service["deployments"] = [{"rolloutState": "COMPLETED"}, {"rolloutState": "IN_PROGRESS"}]
    assert p.healthy("orders", entry="ecs_rollback_service", params={"cluster": "c1"}) is False
    assert p.healthy(FN) is False and p.knows(FN) is False  # never judged by a bare name


def test_a_refused_call_changed_nothing_and_an_unknown_failure_may_be_half_made(aws):
    f, p = aws
    params = {"function": FN, "alias": "live", "to_version": "3"}
    snap = p.live("lambda_move_alias", params)["state"]
    f.fail_write = _Err("AccessDeniedException")
    with pytest.raises(AwsPlatformRefused) as refused:
        p.apply("lambda_move_alias", params, snapshot=snap, who=WHO)
    assert refused.value.nothing_changed
    f.fail_write = _Err("ServiceException")
    with pytest.raises(AwsPlatformError) as half:
        p.apply("lambda_move_alias", params, snapshot=snap, who=WHO)
    assert not getattr(half.value, "nothing_changed", False)


def test_the_router_hands_the_platform_the_approvers_and_the_targets_parameters(aws):
    f, p = aws
    r = RoutedPlatform(**{"lambda": p, "events": p, "dynamodb": p, "ecs": p})
    params = {"function": FN, "alias": "live", "to_version": "3"}
    snap = r.live("lambda_move_alias", params)["state"]
    r.apply("lambda_move_alias", params, snapshot=snap, who=WHO)
    assert f.sessions[0]["who"] == WHO
    assert r.healthy_for("ecs_rollback_service", "orders", params={"cluster": "c1"}) is True


def test_the_approvers_reach_the_platform_from_this_runs_audit_rows(tmp_path):
    """The `who` a platform gets is read from the audit's approval rows for this workflow run and plan - the
    workflow cannot be handed one (audit A-P-5). The rollback of an approved change carries the same names."""
    from test_remediation_workflow import FakePlatform, _approve_with, _run
    from test_remediation_workflow import owner as owner_fixture
    from test_remediation_workflow import world as world_fixture

    class Says(FakePlatform):
        def __init__(self):
            super().__init__(healthy_after=None)  # never recovers: the rollback runs too
            self.who = []

        def apply(self, entry, params, snapshot=None, who=None):
            self.who.append(who)
            return super().apply(entry, params)

        def rollback(self, entry, params, snapshot, who=None):
            self.who.append(who)
            return super().rollback(entry, params, snapshot)

    key = owner_fixture.__wrapped__()
    world = world_fixture.__wrapped__(tmp_path, key)
    world["platform"] = Says()
    out = _run(world, _approve_with(key))
    assert out.status == "rolled_back"
    applied, rolled = world["platform"].who
    assert applied == rolled and applied["approvers"] == ["owner"] and applied["incident"] == "inc-42"
    assert len(applied["plan_hash"]) == 64
