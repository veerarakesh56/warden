"""G6: the runtime module (terraform/modules/warden-runtime), held to the code it serves. Register C13: the alarm on
missing heartbeats reads the exact metric the worker publishes, and reads silence as failure."""

from __future__ import annotations

import pathlib
import re

from warden import runtime

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "terraform" / "modules" / "warden-runtime"


def _block(text: str, kind: str, name: str) -> str:
    start = text.index(f'resource "{kind}" "{name}"')
    return text[start:text.index("\n}\n", start)]


def test_the_heartbeat_alarm_reads_the_workers_metric_and_pages_on_silence():
    alarm = _block((MODULE / "heartbeat.tf").read_text(encoding="utf-8"), "aws_cloudwatch_metric_alarm", "heartbeat")
    assert re.search(r'treat_missing_data\s*=\s*"breaching"', alarm)
    assert re.search(r'comparison_operator\s*=\s*"LessThanThreshold"', alarm) and re.search(r"threshold\s*=\s*1\b", alarm)
    assert re.search(rf'metric_name\s*=\s*"{runtime.HEARTBEAT_METRIC}"', alarm)
    assert re.search(rf'dimensions\s*=\s*\{{ TaskQueue = "{runtime.TASK_QUEUE}" \}}', alarm)
    assert 'namespace           = "WARDEN/${var.environment}"' in alarm
    assert "alarm_actions       = [var.page_topic_arn]" in alarm


def test_the_alarm_period_is_the_workers_beat():
    variables = (MODULE / "variables.tf").read_text(encoding="utf-8")
    block = variables[variables.index('variable "heartbeat_period_seconds"'):]
    default = int(re.search(r"default\s*=\s*(\d+)", block).group(1))
    assert default == runtime.HEARTBEAT_EVERY.total_seconds()


def test_the_synthetic_alarm_pages_after_a_day_without_a_pass():
    alarm = _block((MODULE / "heartbeat.tf").read_text(encoding="utf-8"), "aws_cloudwatch_metric_alarm", "synthetic")
    assert re.search(rf'metric_name\s*=\s*"{runtime.SYNTHETIC_METRIC}"', alarm)
    assert re.search(r'treat_missing_data\s*=\s*"breaching"', alarm)
    period = int(re.search(r"period\s*=\s*(\d+)", alarm).group(1))
    periods = int(re.search(r"evaluation_periods\s*=\s*(\d+)", alarm).group(1))
    assert int(re.search(r"datapoints_to_alarm\s*=\s*(\d+)", alarm).group(1)) == periods
    # Longer than the synthetic's own day, within CloudWatch's seven-day limit for hourly periods (PutMetricAlarm).
    assert runtime.SYNTHETIC_EVERY.total_seconds() < period * periods <= 7 * 86400 and period >= 3600
