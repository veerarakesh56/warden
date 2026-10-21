"""End to end (owner, 2026-10-20): the bundled incidents' evidence - which carries real-looking emails, addresses,
tenant and account ids on purpose - through the diagnosis prompt, the report, every chat sink, a page and the change
record: no raw value reaches any outbound payload or any log line, and an identifier shown "for the operator" is
refused at Slack's door.

Every request a sink makes goes through a stand-in for urllib's opener that runs egress.check_request on exactly the
bytes the sink built, then answers 200 - nothing leaves the test."""

from __future__ import annotations

import json
import logging
import pathlib
import urllib.request

import pytest

from warden import changes, chatops, egress, graph, web
from warden.cli import DEMO_ALERTS
from warden.egress import EgressBlocked
from warden.llm import LLMClient
from warden.models import Alert
from warden.reporting import build_report

ROOT = pathlib.Path(__file__).resolve().parents[1]
SLACK_HOOK = "https://hooks.slack.com/" + "services/T0/B0/canaryhook"
TEAMS_HOOK = "https://example.webhook.office.com/" + "webhookb2/canary"


class _Answer:
    def __init__(self, body: bytes = b'{"ok": true, "ts": "1.2", "html_url": "https://github.com/o/r/issues/1"}'):
        self._body = body

    def getcode(self):
        return 200

    def read(self, *_a):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


@pytest.fixture
def wire(monkeypatch):
    """Every urllib request, checked as the hook checks it, recorded when it passes."""
    sent: list[tuple[str, str]] = []

    def urlopen(req, *_a, **_k):
        data = req.data.decode() if isinstance(req.data, bytes) else str(req.data or "")
        egress.check_request(req.full_url, req.data, dict(req.header_items()), req.get_method())
        sent.append((req.full_url, data))
        return _Answer()

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(web, "urlopen", urlopen)  # the one https opener every sink uses since #168
    monkeypatch.setenv("WARDEN_CHATOPS_LIVE", "1")
    return sent


def _raw_values(report) -> list[str]:
    """The values the pipeline masked in this incident, long enough to mean something on their own."""
    return sorted({v for v in report.redaction_map.values() if len(v) >= 6})


@pytest.mark.parametrize("incident", sorted(DEMO_ALERTS))
def test_no_raw_value_of_an_incident_reaches_a_prompt_a_payload_or_a_log(incident, wire, caplog):
    alert = Alert(**DEMO_ALERTS[incident])
    with caplog.at_level(logging.DEBUG):
        report = graph.run(alert, llm=LLMClient(mock=True))
        raw = _raw_values(report)
        if incident == "inc-001":
            assert raw, "the fixture carries values to mask"
        # What the model is shown, as the llm zone would send it - through the egress check of every provider.
        state = {"alert": alert}
        for node in (graph.node_ingest, graph.node_gather, graph.node_redact):
            graph.apply_node(state, node(state))
        prompt = graph._evidence_blob(state)
        egress.guard_model(type("P", (), {"name": "anthropic", "model": "m"})(), graph.SYSTEM_DIAGNOSE, prompt)
        built = build_report(alert, root_cause=report.root_cause, proposal=report.proposal, verdict=report.verdict,
                             context=report.context, redaction_map=report.redaction_map, show_identifiers=False)
        sinks = [chatops.SlackWebhookSink(SLACK_HOOK, live=True),
                 chatops.SlackBotSink("xoxb-" + "canary-token", "C0123456", live=True),
                 chatops.TeamsWebhookSink(TEAMS_HOOK, live=True),
                 chatops.PagerDutySink("r" * 32, live=True)]
        notes = chatops.notify(built, sinks=sinks)
        issue = changes.GitHubIssues("o/r", "ghs_" + "canarytoken").open(f"Change on {incident}", built.markdown)
    assert all(n.delivered for n in notes), notes
    assert issue[0]
    assert {url.split("/")[2] for url, _ in wire} == {"hooks.slack.com", "slack.com", "example.webhook.office.com",
                                                     "events.pagerduty.com", "api.github.com"}
    for text in [prompt, *(body for _, body in wire), caplog.text]:
        leaked = [v for v in raw if v in text]
        assert not leaked, leaked


def test_an_identifier_shown_for_the_operator_is_refused_at_slacks_door(wire):
    """WARDEN_REPORT_SHOW_IDENTIFIERS puts tenants, emails and addresses back into the report (for a terminal); G5
    lets them through as showable. The egress check does not: nothing is sent to Slack with one in it."""
    alert = Alert(**DEMO_ALERTS["inc-001"])
    report = graph.run(alert, llm=LLMClient(mock=True))
    built = build_report(alert, root_cause=report.root_cause, proposal=report.proposal, verdict=report.verdict,
                         context=report.context, redaction_map=report.redaction_map, show_identifiers=True)
    assert "priya.nair@corp.io" in built.markdown  # shown, as the operator asked
    [note] = chatops.notify(built, sinks=[chatops.SlackWebhookSink(SLACK_HOOK, live=True)])
    assert not note.delivered
    assert not any("priya.nair" in body for _, body in wire)


def test_a_discussion_question_with_a_pasted_value_reaches_the_model_masked():
    from warden import discuss

    thread = discuss.Thread(incident="inc-1", lines=["what about " + "canary.person" + "@" + "example.org" + "?"],
                            approver=False)
    prompt = discuss.prompt("is " + "203.0.113." + "77" + " the attacker?", thread, "", "", approver=False)
    egress.guard_model(type("P", (), {"name": "anthropic", "model": "m"})(), discuss.SYSTEM, prompt)
    assert "canary.person" not in prompt
    assert "203.0.113.77" not in prompt


def test_the_check_would_have_caught_a_leak_in_the_same_path(wire):
    """The plant inside the test: the same sink, a raw value in its text - refused, and nothing recorded as sent."""
    sink = chatops.SlackWebhookSink(SLACK_HOOK, live=True)
    note = sink.send("user " + "canary.person" + "@" + "example.org", {})
    assert not note.delivered
    assert wire == []
    body = json.dumps({"text": "user " + "canary.person" + "@" + "example.org"}).encode()
    with pytest.raises(EgressBlocked):
        egress.check_request(SLACK_HOOK, body, {"Content-Type": "application/json"}, "POST")


def test_the_lab_agent_sends_the_incidents_logs_to_datadog_masked():
    """The other way a value could leave: the lab's apps' own logs, shipped by the Datadog agent (owner, 2026-10-21).
    Every log line of every bundled incident, through the agent's global mask_sequences (helm/datadog/values.yaml):
    none of the values WARDEN masks in that incident reaches Datadog raw. (Host names under .local/.internal are
    left to Kubernetes and AWS by the agent's rules - the values file says why - and so are not counted here.)"""
    import re

    import yaml

    values = yaml.safe_load((ROOT / "helm" / "datadog" / "values.yaml").read_text(encoding="utf-8"))
    [env] = [e for e in values["datadog"]["env"] if e["name"] == "DD_LOGS_CONFIG_PROCESSING_RULES"]
    rules = json.loads(env["value"])
    for incident in sorted(DEMO_ALERTS):
        alert = Alert(**DEMO_ALERTS[incident])
        report = graph.run(alert, llm=LLMClient(mock=True))
        state = {"alert": alert}
        graph.apply_node(state, graph.node_gather(state))
        # A UUID (a trace or request id) is masked for the model but not at the agent: Datadog joins a log to its trace
        # by it, and it names no person - not one of the owner's classes.
        raw = [v for p, v in report.redaction_map.items()
               if len(v) >= 6 and not p.startswith(("<HOSTNAME_", "<UUID_"))]
        for line in state["context"].logs:
            for rule in rules:
                line = re.sub(rule["pattern"], rule["replace_placeholder"], line)
            leaked = [v for v in raw if v in line]
            assert not leaked, (incident, leaked, line)
