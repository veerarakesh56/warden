"""B17: lambda_restore_config, a real executor. A function's unpublished settings ($LATEST) changed after its newest
published version, with the same code: they go back to that version's - timeout, memory, storage, handler, runtime,
layers, tracing - through an actor session allowing UpdateFunctionConfiguration on that one function, conditioned on its
revision; undone to what they were; judged on the settings AND the function serving without errors. Refused when the
code differs, or the environment (by digest - no value is read into the plan), role or network changed too."""

from __future__ import annotations

import json

import pytest

from test_aws_platform_g6 import FN, FN_ARN, WHO, Fake
from warden import catalog
from warden.models import ActionKind
from warden.platforms.aws import AwsPlatform, AwsPlatformRefused

BASE = {"FunctionArn": FN_ARN, "FunctionName": FN, "CodeSha256": "c0de", "Timeout": 30, "MemorySize": 512,
        "EphemeralStorage": {"Size": 512}, "Handler": "app.handler", "Runtime": "python3.13",
        "Layers": [{"Arn": "arn:aws:lambda:test-region-1:000000000000:layer:deps:3"}], "TracingConfig": {"Mode": "Active"},
        "Role": "arn:aws:iam::000000000000:role/fn", "Environment": {"Variables": {"MODE": "x"}},
        "RevisionId": "r1", "LastUpdateStatus": "Successful"}


class LambdaFake(Fake):
    def __init__(self):
        super().__init__()
        self.latest = {**BASE, "Timeout": 3, "MemorySize": 128}  # someone cut both after version 7
        self.published = {"7": dict(BASE), "6": {**BASE, "Timeout": 9}}

    def get_function_configuration(self, FunctionName, Qualifier=None):
        conf = self.latest if Qualifier in (None, "$LATEST") else self.published[Qualifier]
        return json.loads(json.dumps(conf))

    def list_versions_by_function(self, FunctionName, **kw):
        return {"Versions": [{"Version": "$LATEST"}] + [{"Version": v} for v in sorted(self.published)]}


@pytest.fixture
def aws():
    f = LambdaFake()
    return f, AwsPlatform(reader=lambda service: f, actor=f.actor, sleep=lambda s: None)


def _plan(p):
    live = p.live("lambda_restore_config", {"function": FN})
    params = {"function": FN, "from_version": "7"}
    return live, params


def test_the_settings_go_back_to_the_newest_versions_through_one_exact_session(aws):
    f, p = aws
    live, params = _plan(p)
    assert live["from_version"] == {"7"}
    assert live["refused"] == ""
    assert catalog.validate("lambda_restore_config", params, live) == []
    out = p.apply("lambda_restore_config", params, snapshot=live["state"], who=WHO)
    [(call, kw)] = f.writes
    assert call == "update_function_configuration"
    assert kw == {"FunctionName": FN, "RevisionId": "r1", "Timeout": 30, "MemorySize": 512}  # only what differs
    [s] = f.sessions
    assert s["actions"] == ["lambda:UpdateFunctionConfiguration"]
    assert s["resources"] == [FN_ARN]
    assert "version 7's" in out


def test_the_undo_puts_back_what_the_settings_were(aws):
    f, p = aws
    live, params = _plan(p)
    f.latest = {**f.latest, "Timeout": 30, "MemorySize": 512, "RevisionId": "r2"}  # as the fix left it
    p.rollback("lambda_restore_config", params, live["state"], who=WHO)
    assert f.writes[-1] == ("update_function_configuration",
                            {"FunctionName": FN, "RevisionId": "r2", "Timeout": 3, "MemorySize": 128})


def test_settings_that_moved_since_the_plan_are_not_written(aws):
    f, p = aws
    live, params = _plan(p)
    f.latest = {**f.latest, "Timeout": 60}
    with pytest.raises(AwsPlatformRefused, match="not the ones the plan saw"):
        p.apply("lambda_restore_config", params, snapshot=live["state"], who=WHO)
    assert f.writes == []


@pytest.mark.parametrize(("change", "why"), [
    ({"CodeSha256": "other"}, "runs other code"),
    ({"Environment": {"Variables": {"MODE": "y"}}}, "environment also changed"),
    ({"Role": "arn:aws:iam::000000000000:role/other"}, "role also changed"),
    ({"VpcConfig": {"SubnetIds": ["subnet-1"]}}, "network also changed"),
    ({"Timeout": 30, "MemorySize": 512}, "already"),
], ids=["code", "environment", "role", "network", "nothing-to-restore"])
def test_only_a_settings_change_with_the_same_code_is_restored(aws, change, why):
    f, p = aws
    f.latest = {**f.latest, **change}
    live = p.live("lambda_restore_config", {"function": FN})
    assert live["from_version"] == set()
    assert why in live["refused"]
    assert catalog.validate("lambda_restore_config", {"function": FN, "from_version": "7"}, live)


def test_no_environment_value_enters_the_plan(aws):
    f, p = aws
    f.latest["Environment"] = f.published["7"]["Environment"] = {"Variables": {"TOKEN": "s3cr3t-value"}}
    live, _ = _plan(p)
    assert "s3cr3t-value" not in json.dumps(live["state"])


def test_healthy_means_the_settings_landed_and_the_function_serves(aws):
    f, p = aws
    params = {"function": FN, "from_version": "7"}
    assert p.healthy(FN, entry="lambda_restore_config", params=params) is False  # not restored yet
    f.latest = {**f.latest, "Timeout": 30, "MemorySize": 512}
    assert p.healthy(FN, entry="lambda_restore_config", params=params) is True
    f.metrics["Errors"] = 2.0
    assert p.healthy(FN, entry="lambda_restore_config", params=params) is False


def test_the_catalogue_carries_a_lambda_config_revert_and_says_the_change():
    assert catalog.for_action(ActionKind.revert_config, "lambda").name == "lambda_restore_config"
    [said] = catalog.change_of("lambda_restore_config", {"function": FN, "from_version": "7"},
                               {"now": {"Timeout": 3}, "to": {"Timeout": 30}})
    assert said == (f"$LATEST settings of {FN}: Timeout=3 -> Timeout=30 (version 7's; same code; the environment, "
                    "role and network are unchanged)")
