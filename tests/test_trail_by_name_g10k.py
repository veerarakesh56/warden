"""A recorded change is looked up by its event NAME, never by the whole service (register G10-25).

In a live run, the lab producer's timeout was cut, the diagnosis was right, and no plan was opened - "more than one
kind of recorded change". The cause was the lookup: by event source `lambda.amazonaws.com` it read every Lambda call
in the account for six hours (271, mostly a deploy's reads), passed the 200 WARDEN reads, and both Lambda undo
families refused. A working account passes that in minutes, so no Lambda change could ever be undone."""

from __future__ import annotations

import pathlib

from test_revert_config_history_g10d3 import ALARM, FN, LAM, Settings, _lambda_fake, _p, _trail
from warden import resolver
from warden.models import ActionKind, Alert, RemediationProposal, Severity
from warden.platforms import aws


class Busy:
    """CloudTrail as a working account answers: a service's events never end; an event name's are the few there are."""

    def lookup_events(self, LookupAttributes, **kw):
        self.asked.append((LookupAttributes[0]["AttributeKey"], LookupAttributes[0]["AttributeValue"]))
        key, value = self.asked[-1]
        if key == "EventName":
            return {"Events": [e for e in self.events if e["EventName"] == value]}
        reads = [_trail("GetFunction20150331v2", {"functionName": FN}, eid=f"r-{len(self.asked)}-{i}",
                        source="lambda.amazonaws.com") for i in range(50)]
        return {"Events": reads, "NextToken": "more"}


class BusySettings(Busy, Settings):
    def __init__(self):
        super().__init__()
        self.asked = []


def test_a_cut_timeout_is_found_in_an_account_whose_lambda_calls_never_end():
    f = BusySettings()
    live = _p(f).live("lambda_restore_settings", LAM)
    assert live["event"] == {"f-1"}, live.get("refused")
    assert not live.get("refused"), live.get("refused")
    assert f.asked
    assert {key for key, _ in f.asked} == {"EventName"}
    assert {name for _, name in f.asked} == set(aws.LAMBDA_SETTINGS_WRITES)
    f.asked.clear()
    assert "no recorded concurrency change" in _p(f).live("lambda_restore_concurrency", LAM)["refused"]
    assert {name for _, name in f.asked} == set(aws.LAMBDA_CONCURRENCY_WRITES)


def test_the_undo_of_the_one_recorded_kind_is_planned_there():
    alert = Alert(alert_id="a1", name="n", service="checkout", environment="dev", severity=Severity.high, summary="",
                  started_at="2026-10-10T08:00:00+00:00", labels={"lambda": FN, "alarm": ALARM})
    proposal = RemediationProposal(action=ActionKind.revert_change, target=FN, reasoning="r", expected_effect="e",
                                   blast_radius="single_service", reversible=True)
    f = BusySettings()
    req, why = resolver.request_for(alert, proposal, lambda e, params: _p(f).live(e, params))
    assert why == "", why
    assert req["entry"] == "lambda_restore_settings", why


def test_an_event_answered_under_two_names_is_still_one_change():
    f = _lambda_fake()  # its CloudTrail answers every lookup with the same recorded event
    live = _p(f).live("lambda_restore_concurrency", LAM)
    assert len(aws.LAMBDA_CONCURRENCY_WRITES) == 2, live.get("refused")
    assert live["event"] == {"l-1"}, live.get("refused")


def test_no_undo_family_reads_a_whole_services_events():
    src = pathlib.Path(aws.__file__).read_text(encoding="utf-8")
    assert '"EventSource"' not in src
    assert "AttributeKey=EventSource" not in src
    assert src.count("self._trail_named(") >= 3
    assert src.count("def _trail_named(") == 1
