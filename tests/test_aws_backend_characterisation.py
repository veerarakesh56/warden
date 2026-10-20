"""Characterisation of AwsBackend.logs/.deploys and aws_describe.appconfig_for_alarm/_value, written BEFORE their
cognitive-complexity refactor (Sonar python:S3776) and passing on the code as it was: the refactor must not change one
returned line, one call made, or the order of either."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from test_aws_backend import NOW, FakeEcs, FakeLogs, _alert, _backend, _service
from warden import aws_backend, aws_describe
from warden.tools import PARTIAL_PREFIX

TS = int(NOW.timestamp() * 1000)
ARN = "arn:aws:ecs:eu-west-1:1:task-definition/checkout:{}"


# --------------------------------------------------------------------------- logs


def test_the_stream_prefix_label_is_sent_on_every_page():
    logs = FakeLogs()
    _backend(logs=logs).logs(_alert(log_stream_prefix="ecs/checkout"))
    assert [c["logStreamNamePrefix"] for c in logs.calls] == ["ecs/checkout", "ecs/checkout"]
    no_prefix = FakeLogs()
    _backend(logs=no_prefix).logs(_alert())
    assert all("logStreamNamePrefix" not in c for c in no_prefix.calls)


def test_the_two_windows_are_read_newest_first_with_the_same_base_arguments():
    logs = FakeLogs()
    _backend(logs=logs).logs(_alert())
    near = TS - int(aws_backend.LOG_NEAR.total_seconds() * 1000)
    start = TS - int(aws_backend.LOG_LOOKBACK.total_seconds() * 1000)
    end = TS + int(aws_backend.LOG_LOOKBACK.total_seconds() * 1000)
    assert [(c["startTime"], c["endTime"]) for c in logs.calls] == [(near, end), (start, near - 1)]
    assert {c["logGroupName"] for c in logs.calls} == {"/ecs/checkout"}


class _FailsLater(FakeLogs):
    """One page with a token, then the read fails."""

    def filter_log_events(self, **kwargs):
        self.calls.append(kwargs)
        if len(self.calls) > 1:
            raise RuntimeError("ThrottlingException: slow down")
        return {"events": [{"logStreamName": "s", "timestamp": TS, "message": "first page"}], "nextToken": "t"}


def test_a_read_failing_after_some_pages_keeps_what_was_read_and_says_so_last():
    logs = _FailsLater()
    lines = _backend(logs=logs).logs(_alert())
    assert lines[0].startswith("LOG s ")
    assert lines[0].endswith(" first page")
    assert lines[1:] == [f"{PARTIAL_PREFIX}logs: /ecs/checkout: {aws_backend.failure(RuntimeError('ThrottlingException: slow down'))}"]
    assert logs.calls[1]["nextToken"] == "t"


class _Endless(FakeLogs):
    def filter_log_events(self, **kwargs):
        self.calls.append(kwargs)
        return {"events": [{"logStreamName": "s", "timestamp": kwargs["startTime"] + 1, "message": "x"}],
                "nextToken": f"t{len(self.calls)}"}


def test_one_window_out_of_pages_says_it_stopped_before_the_alert_time(monkeypatch):
    # LOG_NEAR beyond the lookback: one window only, read oldest-first.
    monkeypatch.setattr(aws_backend, "LOG_NEAR", aws_backend.LOG_LOOKBACK + timedelta(minutes=1))
    logs = _Endless()
    lines = _backend(logs=logs).logs(_alert())
    assert len(logs.calls) == aws_backend.LOG_MAX_PAGES
    assert lines[-1] == (f"{PARTIAL_PREFIX}logs: [output truncated] stopped after {aws_backend.LOG_MAX_PAGES} pages, "
                         "before reaching the alert time (raise WARDEN_AWS_LOG_MAX_PAGES to read the rest of the window)")
    assert len(lines) == aws_backend.LOG_MAX_PAGES + 1


def test_two_windows_out_of_pages_say_the_alert_time_lines_were_read_first():
    logs = _Endless()
    lines = _backend(logs=logs).logs(_alert())
    assert len(logs.calls) == aws_backend.LOG_MAX_PAGES
    assert {c["startTime"] for c in logs.calls} == {logs.calls[0]["startTime"]}, "the budget ran out in window one"
    assert lines[-1] == (f"{PARTIAL_PREFIX}logs: [output truncated] stopped after {aws_backend.LOG_MAX_PAGES} pages, "
                         "the alert-time lines read first (raise WARDEN_AWS_LOG_MAX_PAGES to read the rest of the window)")


class _ShortThenEndless(FakeLogs):
    """Three pages in the alert-time window, then the older window never ends."""

    def filter_log_events(self, **kwargs):
        self.calls.append(kwargs)
        first = kwargs["startTime"] == self.calls[0]["startTime"]
        n = len(self.calls)
        more = {} if first and n == 3 else {"nextToken": f"t{n}"}
        return {"events": [{"logStreamName": "s", "timestamp": kwargs["startTime"] + n, "message": "x"}], **more}


def test_the_page_budget_is_shared_by_both_windows():
    logs = _ShortThenEndless()
    lines = _backend(logs=logs).logs(_alert())
    assert len(logs.calls) == aws_backend.LOG_MAX_PAGES, "one budget for the whole read, not one per window"
    assert sum(c["startTime"] == logs.calls[0]["startTime"] for c in logs.calls) == 3
    assert lines[-1].endswith("pages, the alert-time lines read first "
                              "(raise WARDEN_AWS_LOG_MAX_PAGES to read the rest of the window)")
    assert "nextToken" not in logs.calls[3], "the older window starts with no token"


def test_lines_are_sorted_by_time_and_the_cut_note_counts_exactly(monkeypatch):
    monkeypatch.setattr(aws_backend, "LOG_MAX_LINES", 3)
    monkeypatch.setattr(aws_backend, "LOG_ERROR_EXTRA", 1)
    events = [{"logStreamName": "s", "timestamp": TS - 10 + i, "message": m}
              for i, m in enumerate(["ERROR one", "ok two", "ERROR three", "ok four", "ok five", "ok six", "ok seven"])]
    events.reverse()  # arrives out of order
    lines = _backend(logs=FakeLogs(events=events)).logs(_alert())
    assert [ln.rsplit(" ", 2)[-2:] for ln in lines[:-1]] == [["ERROR", "three"], ["ok", "five"], ["ok", "six"],
                                                            ["ok", "seven"]]
    assert lines[-1] == (f"{PARTIAL_PREFIX}logs: [output truncated] kept the newest 3 lines and 1 older error line(s), "
                         "dropped 3 (raise WARDEN_AWS_LOG_MAX_LINES to see more)")


def test_an_event_with_no_timestamp_sorts_first():
    events = [{"logStreamName": "s", "timestamp": TS, "message": "timed"}, {"logStreamName": "s", "message": "untimed"}]
    lines = _backend(logs=FakeLogs(events=events)).logs(_alert())
    assert [ln.split(" ")[-1] for ln in lines] == ["untimed", "timed"]


# --------------------------------------------------------------------------- deploys


def test_a_service_with_no_deployment_has_no_deploy():
    ecs = FakeEcs(services=[_service(deployments=[])], task_defs={"checkout:7": ["v2"]})
    assert _backend(ecs=ecs).deploys(_alert()) == []
    assert [c[0] for c in ecs.calls] == ["describe_services"]


def test_with_no_primary_the_first_deployment_is_the_one_read():
    deployments = [{"status": "ACTIVE", "createdAt": NOW, "taskDefinition": ARN.format(7)}]
    ecs = FakeEcs(services=[_service(deployments=deployments)], task_defs={"checkout:7": ["v2"], "checkout:6": ["v1"]})
    [d] = _backend(ecs=ecs).deploys(_alert())
    assert (d["task_definition"], d["previous_task_definition"], d["image"], d["previous_image"]) == (
        "checkout:7", "checkout:6", "v2", "v1")


def test_an_unreadable_current_revision_is_a_partial():
    ecs = FakeEcs(services=[_service()], task_defs={"checkout:6": ["v1"]})
    out = _backend(ecs=ecs).deploys(_alert())
    reason = aws_backend.failure(RuntimeError("ClientError: task definition checkout:7 not found"))
    assert out == [f"{PARTIAL_PREFIX}deploys: checkout:7: {reason}"]


def test_the_exact_record_of_an_image_deploy():
    [d] = _backend().deploys(_alert())
    assert d == {"service": "checkout", "revision": "7", "image": "repo/checkout:v2",
                 "previous_image": "repo/checkout:v1", "task_definition": "checkout:7",
                 "previous_task_definition": "checkout:6", "at": (NOW - timedelta(minutes=5)).isoformat(), "by": "ecs"}


def _rollout(new, old):
    return [{"status": "PRIMARY", "createdAt": NOW, "taskDefinition": ARN.format(new)},
            {"status": "ACTIVE", "createdAt": NOW - timedelta(hours=1), "taskDefinition": ARN.format(old)}]


def test_a_rollback_whose_broken_revision_is_unreadable_still_reports_the_rollback():
    ecs = FakeEcs(services=[_service(deployments=_rollout(6, 7))], task_defs={"checkout:6": ["healthy"]})
    [d] = _backend(ecs=ecs).deploys(_alert())
    assert d == {"service": "checkout", "revision": "6", "image": "healthy", "previous_image": "",
                 "task_definition": "checkout:6", "previous_task_definition": "", "at": NOW.isoformat(), "by": "ecs",
                 "rolled_back_from": "checkout:7"}


def test_a_replaced_deployment_of_another_family_is_compared_with():
    deployments = [{"status": "PRIMARY", "createdAt": NOW, "taskDefinition": ARN.format(7)},
                   {"status": "ACTIVE", "taskDefinition": "arn:aws:ecs:eu-west-1:1:task-definition/other:9"}]
    ecs = FakeEcs(services=[_service(deployments=deployments)], task_defs={"checkout:7": ["v2"], "other:9": ["o"]})
    [d] = _backend(ecs=ecs).deploys(_alert())
    assert (d["previous_task_definition"], d["previous_image"]) == ("other:9", "o")


def test_an_older_replaced_revision_of_the_same_family_is_the_previous_one():
    ecs = FakeEcs(services=[_service(deployments=_rollout(7, 4))], task_defs={"checkout:7": ["v2"], "checkout:4": ["v0"]})
    [d] = _backend(ecs=ecs).deploys(_alert())
    assert (d["previous_task_definition"], d["previous_image"]) == ("checkout:4", "v0")
    assert "rolled_back_from" not in d


class _Registered(FakeEcs):
    def describe_task_definition(self, **kwargs):
        resp = super().describe_task_definition(**kwargs)
        resp["taskDefinition"]["registeredAt"] = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
        return resp


def test_the_registration_time_is_carried_beside_the_deploy_time():
    ecs = _Registered(services=[_service()], task_defs={"checkout:7": ["v2"], "checkout:6": ["v1"]})
    [d] = _backend(ecs=ecs).deploys(_alert())
    assert d["registered_at"] == "2026-10-01T12:00:00+00:00"
    assert list(d)[-1] == "registered_at"


def test_a_config_change_record_keeps_its_key_order():
    from test_aws_backend import _RichEcs, _td

    ecs = _RichEcs({"checkout:7": _td(["run", "--big"]), "checkout:6": _td(["run"])})
    [d] = _backend(ecs=ecs).deploys(_alert())
    assert list(d) == ["service", "revision", "image", "previous_image", "task_definition",
                       "previous_task_definition", "at", "by", "kind", "changed"]
    assert d["changed"] == "app.command"


# --------------------------------------------------------------------------- aws_describe


class _AppConfig:
    """list_applications / list_environments with pages, refusals and failures."""

    def __init__(self, apps_pages, envs, raises=None):
        self.apps_pages, self.envs, self.raises, self.calls = apps_pages, envs, raises or {}, []

    def list_applications(self, **kw):
        self.calls.append(("apps", kw))
        return self.apps_pages[int(kw.get("NextToken") or 0)]

    def list_environments(self, **kw):
        self.calls.append(("envs", kw))
        app = kw["ApplicationId"]
        if app in self.raises:
            raise self.raises[app]
        pages = self.envs.get(app, [{"Items": []}])
        return pages[int(kw.get("NextToken") or 0)]


class _ClientError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


ALARM = "arn:aws:cloudwatch:eu-west-1:0:alarm:a"
GUARD = {"Id": "e1", "Monitors": [{"AlarmArn": ALARM}]}


def test_appconfig_reads_every_page_and_returns_the_guarded_environments():
    client = _AppConfig([{"Items": [{"Id": "a1"}], "NextToken": "1"}, {"Items": [{"Id": "a2"}]}],
                        {"a1": [{"Items": [{"Id": "x", "Monitors": []}], "NextToken": "1"}, {"Items": [GUARD]}],
                         "a2": [{"Items": [{"Id": "y"}]}]})
    out, complete = aws_describe.appconfig_for_alarm(client, ALARM)
    assert out == [({"Id": "a1"}, GUARD)]
    assert complete is True
    assert client.calls == [("apps", {"MaxResults": 50}), ("apps", {"MaxResults": 50, "NextToken": "1"}),
                            ("envs", {"ApplicationId": "a1", "MaxResults": 50}),
                            ("envs", {"ApplicationId": "a1", "MaxResults": 50, "NextToken": "1"}),
                            ("envs", {"ApplicationId": "a2", "MaxResults": 50})]


def test_appconfig_stops_at_three_pages_and_is_then_partial():
    apps = [{"Items": [{"Id": f"a{i}"}], "NextToken": str(i + 1)} for i in range(4)]
    client = _AppConfig(apps, {})
    out, complete = aws_describe.appconfig_for_alarm(client, ALARM)
    assert (out, complete) == ([], False)
    assert [c for c in client.calls if c[0] == "apps"][-1] == ("apps", {"MaxResults": 50, "NextToken": "2"})
    envs = _AppConfig([{"Items": [{"Id": "a"}]}], {"a": [{"Items": [GUARD], "NextToken": str(i + 1)} for i in range(4)]})
    out, complete = aws_describe.appconfig_for_alarm(envs, ALARM)
    assert (out, complete) == ([({"Id": "a"}, GUARD)] * 3, False)


def test_appconfig_reads_at_most_the_cap_of_applications(monkeypatch):
    monkeypatch.setattr(aws_describe, "APPCONFIG_APPS", 2)
    client = _AppConfig([{"Items": [{"Id": "a"}, {"Id": "b"}, {"Id": "c"}]}], {"c": [{"Items": [GUARD]}]})
    assert aws_describe.appconfig_for_alarm(client, ALARM) == ([], False)
    assert [c[1]["ApplicationId"] for c in client.calls if c[0] == "envs"] == ["a", "b"]


@pytest.mark.parametrize(("exc", "complete"), [
    (_ClientError("AccessDeniedException"), True),
    (_ClientError("Forbidden"), True),
    (_ClientError("ThrottlingException"), False),
    (RuntimeError("boom"), False),
    (PermissionError("x"), False),
])
def test_appconfig_a_refused_application_is_not_ours_and_any_other_failure_is_partial(exc, complete):
    client = _AppConfig([{"Items": [{"Id": "a"}, {"Id": "b"}]}], {"b": [{"Items": [GUARD]}]}, raises={"a": exc})
    assert aws_describe.appconfig_for_alarm(client, ALARM) == ([({"Id": "b"}, GUARD)], complete)


class _NamedDenied(Exception):
    pass


def test_appconfig_an_error_with_no_code_is_judged_by_its_class_name():
    client = _AppConfig([{"Items": [{"Id": "a"}]}], {}, raises={"a": _NamedDenied()})
    assert aws_describe.appconfig_for_alarm(client, ALARM) == ([], True)


@pytest.mark.parametrize(("value", "token"), [
    (True, "true"), (False, "false"),
    (datetime(2026, 10, 1, 12, 0, tzinfo=UTC), aws_describe._z(datetime(2026, 10, 1, 12, 0, tzinfo=UTC))),
    (1_000_000_000, "1_000_000_000"), (-1_000_000_000, "-1_000_000_000"), (999_999_999, "999999999"),
    ([{"State": "running"}, {"State": "stopped"}, {"State": "running"}], "3(running:2,stopped:1)"),
    ([{"Status": "ok"}, {"JobRunState": "FAILED"}, {"HealthStatus": "Healthy"}], "3(FAILED:1,Healthy:1,ok:1)"),
    ([{"StatusReport": {"Status": "Failure: timed out"}}], "1(Failure:1)"),
    ([{"Other": 1}, {"State": ""}], "2"),
    (["REGIONAL", "EDGE"], "REGIONAL+EDGE"),
    (["x" * 25], "1"), ([], "0"), ((1, 2), "2"),
    ({"b": 1, "a": 2}, "a+b"), ({}, "none"),
    ("plain", aws_describe._safe("plain")), (3.5, aws_describe._safe(3.5)), (None, aws_describe._safe(None)),
])
def test_value_is_one_token(value, token):
    assert aws_describe._value(value) == token
