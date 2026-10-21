"""B17: lambda_restore_config, a real executor. A function's unpublished settings ($LATEST) changed after its newest
published version, with the same code: they go back to that version's - timeout, memory, storage, handler, runtime,
layers, tracing - through an actor session allowing UpdateFunctionConfiguration on that one function, conditioned on its
revision; undone to what they were; judged on the settings AND the function serving without errors. Refused when the
code differs, or the environment (by digest - no value is read into the plan), role or network changed too."""

from __future__ import annotations

import json

import pytest

from test_aws_platform_g6 import ACCT, FN, FN_ARN, WHO, Fake
from warden import catalog
from warden.models import ActionKind
from warden.platforms.aws import UNDO_POLLS, AwsPlatform, AwsPlatformError, AwsPlatformRefused

BASE = {"FunctionArn": FN_ARN, "FunctionName": FN, "CodeSha256": "c0de", "Timeout": 30, "MemorySize": 512,
        "EphemeralStorage": {"Size": 512}, "Handler": "app.handler", "Runtime": "python3.13",
        "Layers": [{"Arn": f"arn:aws:lambda:test-region-1:{ACCT}:layer:deps:3"}], "TracingConfig": {"Mode": "Active"},
        "Role": f"arn:aws:iam::{ACCT}:role/fn", "Environment": {"Variables": {"MODE": "x"}},
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
    ({"Role": f"arn:aws:iam::{ACCT}:role/other"}, "role also changed"),
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


def _alert():
    from warden.models import Alert, Severity

    return Alert(alert_id="a1", name="n", service=FN, environment="dev", severity=Severity.high, summary="",
                 started_at="2026-10-20T00:00:00+00:00", labels={"lambda": FN, "alarm": "warden-dev-errors"})


def _prop():
    from warden.models import RemediationProposal

    return RemediationProposal(action=ActionKind.revert_config, target=FN, reasoning="r", expected_effect="e",
                               blast_radius="single_service", reversible=True)


def test_a_config_revert_of_the_labelled_function_is_planned_through_the_catalogue(aws):
    from warden import resolver

    _, p = aws
    assert resolver.no_fix_path(_alert(), _prop()) == ""
    request, why = resolver.request_for(_alert(), _prop(), p.live)
    assert why == ""
    assert request["entry"] == "lambda_restore_config"
    assert request["params"] == {"function": FN, "from_version": "7"}


def test_layers_are_said_by_name_and_version_never_by_arn():
    layer = f"arn:aws:lambda:test-region-1:{ACCT}:layer:deps:3"
    [said] = catalog.change_of("lambda_restore_config", {"function": FN, "from_version": "7"},
                               {"now": {"Layers": []}, "to": {"Layers": [layer]}})
    assert "Layers=deps:3" in said
    assert ACCT not in said


def test_an_environment_that_cannot_be_read_is_refused(aws):
    f, p = aws
    f.latest = {**f.latest, "Environment": {"Error": {"ErrorCode": "KMSAccessDenied"}}}
    f.published["7"]["Environment"] = {"Error": {"ErrorCode": "KMSAccessDenied"}}
    live = p.live("lambda_restore_config", {"function": FN})
    assert live["from_version"] == set()
    assert "could not be read" in live["refused"]


@pytest.mark.parametrize("change", [{"CodeSha256": "new-code"}, {"Environment": {"Variables": {"MODE": "z"}}}],
                         ids=["code", "environment"])
def test_a_function_that_stopped_qualifying_after_the_approval_is_not_written(aws, change):
    f, p = aws
    live, params = _plan(p)
    f.latest = {**f.latest, **change}
    with pytest.raises(AwsPlatformRefused):
        p.apply("lambda_restore_config", params, snapshot=live["state"], who=WHO)
    assert f.writes == []


def test_an_appconfig_target_named_as_one_stays_appconfigs(aws):
    from warden import resolver

    _, p = aws
    proposal = _prop().model_copy(update={"target": f"appconfig:{FN}"})
    request, _ = resolver.request_for(_alert(), proposal, p.live)
    assert request is None or request["entry"] != "lambda_restore_config"


def test_an_undo_after_the_role_changed_is_not_written(aws):
    f, p = aws
    live, params = _plan(p)
    f.latest = {**f.latest, "Timeout": 30, "MemorySize": 512, "Role": f"arn:aws:iam::{ACCT}:role/other"}
    with pytest.raises(AwsPlatformRefused, match="changed since"):
        p.rollback("lambda_restore_config", params, live["state"], who=WHO)
    assert f.writes == []


def test_the_layer_order_is_a_setting_of_its_own(aws):
    f, p = aws
    a, b = (f"arn:aws:lambda:test-region-1:{ACCT}:layer:{n}:1" for n in ("a", "b"))
    f.published["7"]["Layers"] = [{"Arn": a}, {"Arn": b}]
    f.latest = {**f.latest, "Timeout": 30, "MemorySize": 512, "Layers": [{"Arn": b}, {"Arn": a}]}
    live, params = _plan(p)
    assert live["from_version"] == {"7"}
    p.apply("lambda_restore_config", params, snapshot=live["state"], who=WHO)
    assert f.writes[-1][1]["Layers"] == [a, b]


def test_a_changed_environment_key_is_a_changed_environment(aws):
    f, p = aws
    f.latest = {**f.latest, "KMSKeyArn": f"arn:aws:kms:test-region-1:{ACCT}:key/other"}
    assert "environment also changed" in p.live("lambda_restore_config", {"function": FN})["refused"]


def test_an_update_not_known_to_have_finished_is_not_healthy(aws):
    f, p = aws
    f.latest = {**f.latest, "Timeout": 30, "MemorySize": 512, "LastUpdateStatus": None}
    assert p.healthy(FN, entry="lambda_restore_config", params={"function": FN, "from_version": "7"}) is False


class UpdatingFake(LambdaFake):
    """$LATEST's LastUpdateStatus as Lambda reports it on each read after the undo's write."""

    def __init__(self, statuses):
        super().__init__()
        self.statuses = list(statuses)

    def get_function_configuration(self, FunctionName, Qualifier=None):
        conf = super().get_function_configuration(FunctionName, Qualifier)
        if Qualifier is None and self.writes and self.statuses:
            conf["LastUpdateStatus"] = self.statuses.pop(0)
        return conf


def _undo(statuses):
    f = UpdatingFake(statuses)
    naps = []
    p = AwsPlatform(reader=lambda service: f, actor=f.actor, sleep=naps.append)
    live, params = _plan(p)
    f.latest = {**f.latest, "Timeout": 30, "MemorySize": 512, "RevisionId": "r2"}  # as the fix left it
    return f, p, live, params, naps


def test_an_undo_is_done_only_when_lambda_says_its_update_finished():
    f, p, live, params, naps = _undo(["InProgress", "InProgress", "Successful"])
    p.rollback("lambda_restore_config", params, live["state"], who=WHO)
    assert f.writes[-1][0] == "update_function_configuration"
    assert len(naps) == 2  # waited twice, then Lambda said Successful


@pytest.mark.parametrize(("statuses", "said"), [(["InProgress", "Failed"], "Failed"),
                                                (["InProgress"] * (UNDO_POLLS + 1), "did not finish")],
                         ids=["failed", "never-finished"])
def test_an_undo_whose_update_failed_or_never_finished_is_not_reported_done(statuses, said):
    f, p, live, params, _ = _undo(statuses)
    with pytest.raises(AwsPlatformError, match=said) as raised:
        p.rollback("lambda_restore_config", params, live["state"], who=WHO)
    assert not isinstance(raised.value, AwsPlatformRefused)  # the write was sent: not "nothing changed"
    assert f.writes  # it was sent
