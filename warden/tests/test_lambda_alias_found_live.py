"""fs-01, live, 2026-10-15: the checkout function's Errors alarm names the function only (FunctionName). The diagnosis
was right - version 4, now live, broke it - and proposed rollback_deploy, but no plan was opened: "the alarm names no
Lambda alias to move". The function's own aliases are now read live: exactly one is the one moved back (to the version
that served before, as ever); more than one, and WARDEN does not choose."""

from __future__ import annotations

from test_aws_platform_g6 import FN, aws  # noqa: F401 - the fixture
from warden import catalog, resolver
from warden.models import ActionKind, Alert, RemediationProposal, Severity


def test_a_function_with_one_alias_is_planned_on_it(aws):  # noqa: F811
    f, p = aws
    f.list_aliases = lambda FunctionName, **kw: {"Aliases": [{"Name": "live"}]}
    live = p.live("lambda_move_alias", {"function": FN})
    assert live["alias"] == {"live"}
    assert live["to_version"] == {"3"}
    assert catalog.validate("lambda_move_alias", {"function": FN, "alias": "live", "to_version": "3"}, live) == []


def test_a_function_with_several_aliases_and_none_named_is_refused(aws):  # noqa: F811
    f, p = aws
    f.list_aliases = lambda FunctionName, **kw: {"Aliases": [{"Name": "live"}, {"Name": "beta"}]}
    live = p.live("lambda_move_alias", {"function": FN})
    assert live["alias"] == set()
    assert live["refused"] == f"{FN} has 2 aliases and the alarm names none of them"


def _alert(**labels):
    return Alert(alert_id="a", name="warden-dev-checkout-errors", service=FN, environment="dev", severity=Severity.high,
                 summary="s", started_at="2026-10-15T19:33:45+00:00",
                 labels={"alarm": "warden-dev-checkout-errors", "lambda": FN, **labels})


def _proposal():
    return RemediationProposal(action=ActionKind.rollback_deploy, target=FN, reasoning="r", expected_effect="e",
                               blast_radius="single_service", reversible=True)


def test_the_resolver_asks_the_live_read_for_the_alias_when_the_alarm_names_none(aws):  # noqa: F811
    f, p = aws
    f.list_aliases = lambda FunctionName, **kw: {"Aliases": [{"Name": "live"}]}
    req, why = resolver.request_for(_alert(), _proposal(), lambda e, params: p.live(e, params))
    assert why == ""
    assert req["entry"] == "lambda_move_alias"
    assert req["params"]["alias"] == "live"
    assert req["params"]["to_version"] == "3"
    req, why = resolver.request_for(_alert(lambda_qualifier="7"), _proposal(), lambda e, params: p.live(e, params))
    assert req is None
    assert "names a Lambda version, not an alias" in why
