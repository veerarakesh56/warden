"""A queue's own alarm reaches the queue's consumer (first live run of the lab, 2026-10-12, register G10-23).

The lab's consumer mapping was switched off; the alarm named only the queue. WARDEN read the queue's counters and
nothing of who reads the queue, the model proposed a restart, and no plan was opened. Now the reader shows the event
source mappings AWS holds for exactly that queue, and `resume_flow` on the queue is planned as switching its ONE
switched-off mapping back on - found by the queue's ARN in the platform's live read, never from a name in a line."""

from __future__ import annotations

from test_aws_fixes_g9d import QUEUE_ARN, More
from test_aws_platform_g6 import ACCT, FN, FN_ARN, NOW
from test_aws_stack import Fake as StackFake
from test_aws_stack import P, _backend, _clients, _lambda
from test_aws_stack import _alert as _stack_alert
from test_holds_g10e import _alert, _prop
from warden import catalog, evidence, resolver
from warden.models import ActionKind
from warden.platforms.aws import AwsPlatform

QUEUE = QUEUE_ARN.rsplit(":", 1)[-1]
JOBS_ARN = f"arn:aws:sqs:test-region-1:{ACCT}:{P}jobs"
CONSUMER_ARN = f"arn:aws:lambda:test-region-1:{ACCT}:function:{P}consumer"


def _jobs_queue():
    attrs = {"ApproximateNumberOfMessages": "65", "ApproximateNumberOfMessagesNotVisible": "0",
             "VisibilityTimeout": "60", "QueueArn": JOBS_ARN}
    return StackFake(get_queue_url=lambda QueueName: {"QueueUrl": f"https://sqs/{QueueName}"},
                     get_queue_attributes=lambda QueueUrl, AttributeNames: {
                         "Attributes": {k: v for k, v in attrs.items() if k in AttributeNames}})


def _mappings(state="Disabled", arn=CONSUMER_ARN):
    one = {"UUID": "u-7", "FunctionArn": arn, "EventSourceArn": JOBS_ARN, "State": state, "BatchSize": 10,
           "LastProcessingResult": "No records processed"}
    return lambda **kw: {"EventSourceMappings": [one] if kw.get("EventSourceArn", JOBS_ARN) == JOBS_ARN else []}


def test_a_queue_alarm_shows_who_reads_the_queue_and_that_it_is_switched_off():
    lam = _lambda(list_event_source_mappings=_mappings())
    b = _backend(_clients(**{"lambda": lam, "sqs": _jobs_queue()}))
    a = _stack_alert(sqs=f"{P}jobs")
    line = f"ESM {P}consumer <- {P}jobs State=Disabled BatchSize=10 LastProcessingResult=No records processed"
    assert line in b.logs(a)
    assert b.metrics(a)["sqs_consumers_enabled"] == 0
    assert evidence._kind(line) == "C"  # WARDEN's own read: the model may cite it, and it names a real resource
    assert ("list_event_source_mappings", {"EventSourceArn": JOBS_ARN}) in lam.calls  # this queue's, by its ARN
    on = _backend(_clients(**{"lambda": _lambda(list_event_source_mappings=_mappings("Enabled")), "sqs": _jobs_queue()}))
    assert on.metrics(a)["sqs_consumers_enabled"] == 1


def test_a_function_the_alert_names_is_not_listed_twice_and_a_failed_listing_is_said():
    lam = _lambda(list_event_source_mappings=_mappings())
    both = _stack_alert(sqs=f"{P}jobs", **{"lambda": f"{P}consumer"})
    lines = _backend(_clients(**{"lambda": lam, "sqs": _jobs_queue()})).logs(both)
    assert sum(ln.startswith("ESM ") for ln in lines) == 1  # the function's own reader wrote it
    qualified = _lambda(list_event_source_mappings=_mappings(arn=CONSUMER_ARN + ":live"))
    lines = _backend(_clients(**{"lambda": qualified, "sqs": _jobs_queue()})).logs(_stack_alert(sqs=f"{P}jobs"))
    assert any(ln.startswith(f"ESM {P}consumer <- {P}jobs ") for ln in lines)  # the function, not its alias
    down = _lambda(list_event_source_mappings=RuntimeError("boom"))
    lines = _backend(_clients(**{"lambda": down, "sqs": _jobs_queue()})).logs(_stack_alert(sqs=f"{P}jobs"))
    assert any(f"sqs/{P}jobs consumers: " in ln for ln in lines)
    assert any(ln.startswith("QUEUE ") for ln in lines)


class Queue(More):
    """The queue's mapping u-1 and the same function's stream mapping u-2, both switched off."""

    def __init__(self):
        super().__init__()
        for m in self.mappings:
            m["State"] = "Disabled"

    def list_event_source_mappings(self, **kw):
        by = kw.get("EventSourceArn")
        return {"EventSourceMappings": [dict(m) for m in self.mappings if by is None or m["EventSourceArn"] == by]}

    def get_queue_attributes(self, QueueUrl, AttributeNames):
        return {"Attributes": {"QueueArn": QUEUE_ARN, "MessageRetentionPeriod": self.retention}}


def _platform(fake):
    return AwsPlatform(reader=lambda service: fake, actor=fake.actor, clock=lambda: NOW, sleep=lambda s: None)


def test_the_live_read_finds_the_queues_one_switched_off_mapping_and_never_chooses():
    f = Queue()
    live = _platform(f).live("lambda_enable_esm", {"queue": QUEUE})
    assert live["function"] == {FN}
    assert live["mapping"] == {"u-1"}  # not u-2: that one reads a stream
    f.mappings.append({"UUID": "u-3", "FunctionArn": FN_ARN.replace(FN, "another"), "State": "Disabled",
                       "EventSourceArn": QUEUE_ARN})
    assert _platform(f).live("lambda_enable_esm", {"queue": QUEUE}) == {}  # two are off: a person decides
    on = Queue()
    on.mappings[0]["State"] = "Enabled"
    assert _platform(on).live("lambda_enable_esm", {"queue": QUEUE}) == {}  # nothing is switched off
    assert _platform(Queue()).live("lambda_disable_esm", {"queue": QUEUE}) == {}  # a pause is never led by a queue


def test_resume_flow_on_the_alarms_queue_is_planned_as_switching_its_mapping_on():
    f = Queue()
    alert, proposal = _alert(sqs=QUEUE, alarm="jobs-age"), _prop(ActionKind.resume_flow, QUEUE)
    assert resolver.no_fix_path(alert, proposal) == ""
    req, why = resolver.request_for(alert, proposal, lambda e, params: _platform(f).live(e, params))
    assert why == ""
    assert req["entry"] == "lambda_enable_esm"
    assert req["params"] == {"function": FN, "mapping": "u-1"}
    assert req["service"] == "u-1"
    # The plan is the entry's own: the same checks, snapshot and session as one led by the function.
    state = _platform(f).live("lambda_enable_esm", req["params"])
    assert catalog.validate("lambda_enable_esm", req["params"], state) == []
    assert state["state"]["source"] == QUEUE_ARN
    f.mappings.append({"UUID": "u-3", "FunctionArn": FN_ARN.replace(FN, "another"), "State": "Disabled",
                       "EventSourceArn": QUEUE_ARN})
    req, why = resolver.request_for(alert, proposal, lambda e, params: _platform(f).live(e, params))
    assert req is None
    assert "no single known-good" in why
    # Independent review 2026-10-10, F6: what the model names never becomes a target. A function it names on a queue's
    # alarm leads to no plan of its own: when that function IS the queue's one switched-off consumer (fs-07, live,
    # 2026-10-15), the plan is exactly the queue's - read by the queue's ARN, the same entry, function and mapping as
    # the queue-named proposal above; any other function, nothing.
    queue_plan = resolver.request_for(alert, proposal, lambda e, params: _platform(Queue()).live(e, params))[0]
    req, why = resolver.request_for(alert, _prop(ActionKind.resume_flow, FN), lambda e, params: _platform(Queue()).live(e, params))
    assert why == ""
    assert req == queue_plan
    req, why = resolver.request_for(alert, _prop(ActionKind.resume_flow, "warden-dev-another-fn"),
                                    lambda e, params: _platform(Queue()).live(e, params))
    assert req is None
    assert "is not warden-dev-another-fn" in why
