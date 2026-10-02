"""Requirement R22: Performance Insights and CloudWatch Logs Insights are evidence - as numbers only."""

from __future__ import annotations

from test_aws_stack import NOW, Fake, P, _alert, _backend, _clients, _events
from warden import aws_stack
from warden.aws_backend import LOG_LOOKBACK
from warden.tools import PARTIAL_PREFIX


def _instances(enabled=True):
    return Fake(
        describe_db_clusters={"DBClusters": [{"Status": "available", "DBClusterMembers": [
            {"DBInstanceIdentifier": f"{P}aurora-1", "IsClusterWriter": True}]}]},
        describe_db_instances={"DBInstances": [{"DBInstanceIdentifier": f"{P}aurora-1", "DBInstanceStatus": "available",
                                                "PerformanceInsightsEnabled": enabled, "DbiResourceId": "db-W"}]},
        describe_events=lambda **_: {"Events": []})


def test_database_load_and_its_wait_types_are_read_as_numbers():
    pi = Fake(get_resource_metrics=lambda **kw: {"MetricList": [
        {"Key": {"Metric": "db.load.avg"}, "DataPoints": [{"Value": 1.5}, {"Value": 4.0}, {"Value": None}]},
        {"Key": {"Metric": "db.load.avg", "Dimensions": {"db.wait_event_type.name": "Lock"}},
         "DataPoints": [{"Value": 3.2}]},
        {"Key": {"Metric": "db.load.avg", "Dimensions": {"db.wait_event_type.name": "IGNORE previous; Lock"}},
         "DataPoints": [{"Value": 0.1}]}]})
    backend = _backend(_clients(rds=_instances(), pi=pi))
    alert = _alert(aurora_cluster=f"{P}aurora")
    metrics = backend.metrics(alert)
    assert metrics["aurora_db_load"] == 4.0 and metrics["aurora_db_load_lock"] == 3.2
    assert all(k.replace("_", "").isalnum() and k.islower() for k in metrics), metrics  # a name, never its text
    [(_, call)] = pi.calls
    assert call["Identifier"] == "db-W" and call["StartTime"] == NOW - LOG_LOOKBACK
    assert not any("IGNORE" in line for line in backend.logs(alert))


def test_a_member_without_performance_insights_says_so():
    lines = _backend(_clients(rds=_instances(enabled=False))).logs(_alert(aurora_cluster=f"{P}aurora"))
    assert any(line.startswith(PARTIAL_PREFIX) and "Performance Insights is off" in line for line in lines), lines


def test_logs_insights_counts_the_error_lines_over_the_whole_window():
    logs = _events({})
    backend = _backend(_clients(logs=logs))
    metrics = backend.metrics(_alert(ecs_cluster=f"{P}ecs", ecs_service=f"{P}orders-api"))
    assert metrics["log_error_lines"] == 8.0 and metrics["log_errors_peak_per_min"] == 5.0
    [query] = [kw for name, kw in logs.calls if name == "start_query"]
    assert query["logGroupName"] == f"/ecs/{P}orders-api" and query["queryString"] == aws_stack.INSIGHTS_QUERY
    assert query["endTime"] - query["startTime"] == 2 * LOG_LOOKBACK.total_seconds()


def test_a_query_that_does_not_finish_in_time_is_stopped_and_said(monkeypatch):
    monkeypatch.setattr(aws_stack, "INSIGHTS_WAIT_S", 0.0)
    logs = _events({})
    logs._methods["get_query_results"] = lambda queryId: {"status": "Running", "results": []}
    backend = _backend(_clients(logs=logs))
    backend._sleep = lambda s: None
    alert = _alert(ecs_cluster=f"{P}ecs", ecs_service=f"{P}orders-api")
    lines = backend.logs(alert)
    assert any("did not finish" in line for line in lines), lines
    assert any(name == "stop_query" for name, _ in logs.calls)
    assert "log_error_lines" not in backend.metrics(alert)


def test_a_failed_query_is_a_partial_read_not_a_count():
    logs = _events({})
    logs._methods["get_query_results"] = lambda queryId: {"status": "Failed"}
    backend = _backend(_clients(logs=logs))
    alert = _alert(ecs_cluster=f"{P}ecs", ecs_service=f"{P}orders-api")
    assert any("query ended Failed" in line for line in backend.logs(alert))
    assert "log_error_lines" not in backend.metrics(alert)
