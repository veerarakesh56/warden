"""U3-3: each main AWS service's key health signals, read as evidence when an alarm names the resource."""

from __future__ import annotations

import pathlib
import re

import pytest
from tests.reader_iam import granted as reader_granted
from tests.test_aws_stack import Fake, _alert, _backend, _clients

from warden import aws_stack, health_signals, resources
from warden.knowledge import default_knowledge_base
from warden.models import Alert, ContextBundle, Severity


def _cw_by_metric(values: dict[str, list[float]], seen: list[dict]):
    """get_metric_data answering by MetricName, recording every query asked."""

    def get_metric_data(MetricDataQueries, **_):
        seen.extend(MetricDataQueries)
        return {"MetricDataResults": [
            {"Id": q["Id"], "Values": list(values.get(q["MetricStat"]["Metric"]["MetricName"], []))}
            for q in MetricDataQueries]}

    return Fake(get_metric_data=get_metric_data)


def _read(values: dict[str, list[float]], **labels) -> tuple[dict[str, float], list[dict]]:
    seen: list[dict] = []
    backend = _backend(_clients(cloudwatch=_cw_by_metric(values, seen)))
    alert = _alert(**labels)
    return backend.metrics(alert), seen


def _asked(seen: list[dict], metric: str) -> dict:
    found = [q["MetricStat"] for q in seen if q.get("MetricStat", {}).get("Metric", {}).get("MetricName") == metric]
    assert len(found) == 1, f"{metric} asked {len(found)} times"
    return found[0]


# --------------------------------------------------------------------------- the table


def test_every_label_is_a_resource_label_and_every_stat_is_known():
    assert set(health_signals.TABLE) <= resources.LABEL_KEYS
    for label, service in health_signals.TABLE.items():
        assert service.namespace in resources.NAMESPACES, label
        assert service.signals, label
        for s in service.signals:
            assert s.stat in health_signals.STATS, (label, s)
            assert re.fullmatch(r"[a-z][a-z0-9_]*", s.key), s.key


def test_every_key_is_unique_and_not_another_readers():
    keys = [s.key for service in health_signals.TABLE.values() for s in service.signals]
    assert len(keys) == len(set(keys))
    # No key spelled by another reader in aws_stack.py: two readers writing one key would overwrite each other.
    text = pathlib.Path(aws_stack.__file__).read_text(encoding="utf-8")
    assert not [k for k in keys if re.search(rf"[\"']{re.escape(k)}[\"'{{]", text)]


def test_the_first_named_signals_are_there():
    nat = {s.metric: s for s in health_signals.TABLE["nat_gateway"].signals}
    efs = {s.metric: s for s in health_signals.TABLE["efs"].signals}
    assert nat["ErrorPortAllocation"].stat == "Sum"
    assert nat["PacketsDropCount"].stat == "Sum"
    # A balance: the LOWEST of the window says the credits ran out; the highest would hide it.
    assert efs["BurstCreditBalance"].stat == "Minimum/min"
    assert efs["PercentIOLimit"].stat == "Maximum"


def test_the_reader_role_already_grants_the_one_read_it_needs():
    # Every signal is one cloudwatch:GetMetricData call; OpenSearch's ClientId comes from sts:GetCallerIdentity.
    assert "cloudwatch:GetMetricData" in reader_granted()


# --------------------------------------------------------------------------- the fold


@pytest.mark.parametrize(("stat", "values", "want"), [
    ("Sum", [1.0, 2.0, 3.0], 6.0),
    ("Maximum", [1.0, 5.0, 3.0], 5.0),
    ("Average", [1.0, 5.0, 3.0], 5.0),
    ("Minimum/min", [9.0, 0.0, 4.0], 0.0),
    ("Average/min", [100.0, 40.0, 100.0], 40.0),
])
def test_a_window_folds_by_its_stat(stat, values, want):
    assert aws_stack._fold(stat, values) == want


def test_sum_per_second_is_the_busiest_period():
    assert aws_stack._fold("Sum/s", [60.0, 600.0]) == 600.0 / aws_stack.METRIC_PERIOD_S


# --------------------------------------------------------------------------- the reads


def test_nat_gateway_port_allocation_errors_are_read_and_summed():
    metrics, seen = _read({"ErrorPortAllocation": [3.0, 4.0], "PacketsDropCount": [0.0, 2.0]},
                                 nat_gateway="nat-0abc")
    assert metrics["nat_error_port_allocation"] == 7.0
    assert metrics["nat_packets_drop_count"] == 2.0
    asked = _asked(seen, "ErrorPortAllocation")
    assert asked["Metric"]["Namespace"] == "AWS/NATGateway"
    assert asked["Metric"]["Dimensions"] == [{"Name": "NatGatewayId", "Value": "nat-0abc"}]
    assert asked["Stat"] == "Sum"


def test_efs_burst_credits_are_the_lowest_of_the_window():
    metrics, seen = _read({"BurstCreditBalance": [2.0e12, 0.0, 5.0e11], "PercentIOLimit": [40.0, 100.0]},
                             efs="fs-0abc")
    assert metrics["efs_burst_credit_balance_bytes"] == 0.0
    assert metrics["efs_percent_io_limit"] == 100.0
    asked = _asked(seen, "BurstCreditBalance")
    assert asked["Stat"] == "Minimum"  # the "/min" fold is WARDEN's, CloudWatch is asked for the plain statistic
    assert asked["Metric"]["Dimensions"] == [{"Name": "FileSystemId", "Value": "fs-0abc"}]


def test_a_signal_with_no_datapoint_is_absent_not_zero():
    metrics, _ = _read({}, efs="fs-0abc")
    assert "efs_burst_credit_balance_bytes" not in metrics
    assert "efs_percent_io_limit" not in metrics


def test_opensearch_carries_the_account_as_client_id():
    _, seen = _read({"ClusterStatus.red": [1.0]}, opensearch="search")
    dims = {d["Name"]: d["Value"] for d in _asked(seen, "ClusterStatus.red")["Metric"]["Dimensions"]}
    assert dims == {"DomainName": "search", "ClientId": "1"}


def test_cloudfront_reads_the_global_region_dimension():
    _, seen = _read({"5xxErrorRate": [2.5]}, cloudfront="E2ABC")
    dims = {d["Name"]: d["Value"] for d in _asked(seen, "5xxErrorRate")["Metric"]["Dimensions"]}
    assert dims == {"DistributionId": "E2ABC", "Region": "Global"}


def test_a_failed_health_read_is_a_partial_and_the_others_still_read():
    clients = _clients(cloudwatch=Fake(get_metric_data=RuntimeError("throttled")))
    backend = _backend(clients)
    alert = _alert(nat_gateway="nat-0abc", secret="warden-dev-db-app")
    lines = backend.logs(alert)
    assert any(ln.startswith("TOOL-PARTIAL") and "nat-gateway health" in ln for ln in lines), lines
    assert any("secret" in ln.lower() for ln in lines if not ln.startswith("TOOL-PARTIAL"))


def test_no_label_reads_no_health_signal():
    _, seen = _read({}, secret="warden-dev-db-app")
    assert not seen


# --------------------------------------------------------------------------- the signatures


def _match(metrics: dict[str, float]) -> list[str]:
    alert = Alert(alert_id="h", name="ResourceAlarm", severity=Severity.high, service="svc", environment="dev",
                  summary="", started_at="2026-10-21T00:00:00+00:00", labels={})
    return [m.signature.id for m in default_knowledge_base().match(alert, ContextBundle(metrics=metrics), limit=10)]


@pytest.mark.parametrize(("metrics", "sig"), [
    ({"nat_error_port_allocation": 3.0}, "NAT-PORT-001"),
    ({"efs_burst_credit_balance_bytes": 0.0}, "EFS-BURST-001"),
    ({"efs_percent_io_limit": 100.0}, "EFS-IO-LIMIT-001"),
    ({"ebs_burst_balance_pct": 0.0}, "EBS-BURST-001"),
    ({"ec2_status_check_failed_system": 1.0}, "EC2-STATUS-001"),
    ({"kinesis_write_throttled_records": 12.0}, "KINESIS-THROTTLE-001"),
    ({"opensearch_cluster_red": 1.0}, "OPENSEARCH-RED-001"),
    ({"redshift_health_status": 0.0}, "REDSHIFT-UNHEALTHY-001"),
    ({"msk_offline_partitions": 2.0}, "MSK-PARTITIONS-001"),
])
def test_each_signal_names_its_failure(metrics, sig):
    assert sig in _match(metrics)


def test_healthy_values_name_nothing():
    healthy = {"nat_error_port_allocation": 0.0, "nat_packets_drop_count": 0.0,
               "efs_burst_credit_balance_bytes": 2.0e12, "efs_percent_io_limit": 35.0, "ebs_burst_balance_pct": 98.0,
               "ec2_status_check_failed_instance": 0.0, "ec2_status_check_failed_system": 0.0,
               "kinesis_write_throttled_records": 0.0, "opensearch_cluster_red": 0.0,
               "opensearch_index_writes_blocked": 0.0, "redshift_health_status": 1.0, "msk_offline_partitions": 0.0}
    assert _match(healthy) == []
