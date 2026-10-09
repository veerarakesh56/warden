"""Owner requirement R10: every paid item is flagged with its cost. Each AWS call the evidence readers make is either
free or billed, and every billed one has its price in docs/SYSTEM-COMPONENTS.md - a new call must be classified."""

from __future__ import annotations

import pathlib
import re

from test_aws_stack import _api_calls

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Billed per call (or per data scanned), and the cost-table row that prices it (read 2026-10-03).
BILLED = {
    ("_cw", "get_metric_data"): "CloudWatch GetMetricData",
    ("_logs", "start_query"): "CloudWatch Logs Insights",
    ("_pi", "get_resource_metrics"): "RDS Performance Insights (API)",
    ("_sm", "describe_secret"): "Secrets Manager",
    ("_sqs", "get_queue_attributes"): "SQS requests",
    ("_sqs", "get_queue_url"): "SQS requests",
    ("_sns", "list_subscriptions_by_topic"): "SNS requests",
    # The universal alarm reader (G9-A2a): 1 million CloudWatch API requests a month free, then billed (read 2026-10-10).
    ("_cw", "list_metrics"): "CloudWatch API requests",
    ("_cw", "describe_alarms"): "CloudWatch API requests",
}
# Control-plane reads AWS does not bill, and the halves of a billed query (results, cancel) the query already pays for.
FREE = {
    ("_apigw", "get_apis"), ("_ddb", "describe_table"), ("_ec", "describe_cache_clusters"), ("_ec", "describe_events"),
    ("_ec", "describe_replication_groups"), ("_ec2", "describe_security_groups"), ("_ecs", "describe_services"),
    ("_ecs", "describe_task_definition"), ("_eks", "describe_cluster"), ("_elb", "describe_target_groups"),
    ("_elb", "describe_target_health"), ("_events", "describe_rule"), ("_lambda", "get_alias"),
    ("_lambda", "get_function"), ("_lambda", "get_function_concurrency"), ("_lambda", "get_function_configuration"),
    ("_lambda", "list_event_source_mappings"), ("_lambda", "list_versions_by_function"),
    ("_logs", "filter_log_events"), ("_logs", "get_query_results"), ("_logs", "stop_query"),
    ("_rds", "describe_db_clusters"), ("_rds", "describe_db_instances"), ("_rds", "describe_events"),
    ("_sts", "get_caller_identity"),
    ("_ct", "lookup_events"),  # CloudTrail event history: free (read 2026-10-10)
}


def _priced_rows() -> dict[str, str]:
    text = (ROOT / "docs" / "SYSTEM-COMPONENTS.md").read_text(encoding="utf-8")
    table = text[text.index("| Component | Price | Notes |"):]
    rows = {}
    for line in table.splitlines()[2:]:
        if not line.startswith("| "):
            break
        name, price = (c.strip() for c in line.split("|")[1:3])
        rows[name] = price
    return rows


def test_every_aws_call_the_readers_make_is_classified_free_or_billed():
    calls = set(_api_calls())
    unclassified = calls - FREE - set(BILLED)
    assert not unclassified, f"classify these as free or billed (R10), with a price row if billed: {sorted(unclassified)}"


def test_every_billed_call_has_a_price_in_the_cost_table():
    rows = _priced_rows()
    for call, row in BILLED.items():
        assert row in rows, f"{call}: no '{row}' row in SYSTEM-COMPONENTS.md"
        assert re.search(r"\$\d|free", rows[row]), f"'{row}' has no price: {rows[row]!r}"
