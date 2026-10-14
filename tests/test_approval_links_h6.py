"""Registers H6 and R28: approving from chat. As a plan's wait for an approval opens, each approver who may approve its
tier and has a passkey gets a link to the approval page - minted by WARDEN, recorded in the audit by its hash only,
and delivered beside the gated text, because the gate removes every URL a model or an alert could have written.
Only a link of the exact shape https://<the approval domain>/a/<token> gets through."""

from __future__ import annotations

import pytest

from warden import approvals, chatops
from warden.reporting import Report

RP = "approve.example.test"
TOKEN = "A" * 43


@pytest.fixture
def rp(monkeypatch):
    monkeypatch.setenv("WARDEN_APPROVAL_RP_ID", RP)


def test_only_an_approval_link_of_the_exact_shape_gets_through(rp):
    label = chatops.LINK_LABEL
    good = (label, f"https://{RP}/a/{TOKEN}")
    whose = (f"{label} (link of second)", f"https://{RP}/a/{TOKEN}")  # only where several approvers have a link
    bad = [(label, f"https://evil.example/a/{TOKEN}"), (label, f"https://{RP}/a/{TOKEN}/x"),
           (label, f"http://{RP}/a/{TOKEN}"), (label, f"https://{RP}.evil.example/a/{TOKEN}"),
           ("Click <here>", f"https://{RP}/a/{TOKEN}"), (label, f"https://{RP}/a/{TOKEN[:-1]}"),
           (f"{label} (link of <!channel>)", f"https://{RP}/a/{TOKEN}"), ("Approve as owner", f"https://{RP}/a/{TOKEN}")]
    assert chatops.approval_links((good, whose, *bad)) == [good, whose]
    assert label == "Open the plan to approve or deny"  # it names nobody


def test_no_link_leaves_without_an_approval_domain(monkeypatch):
    monkeypatch.delenv("WARDEN_APPROVAL_RP_ID", raising=False)
    assert chatops.approval_links(((chatops.LINK_LABEL, f"https://{RP}/a/{TOKEN}"),)) == []


class _Sink:
    name = "test"

    def __init__(self):
        self.sent = []

    def send(self, text, data):
        self.sent.append(text)
        return chatops.Notification(sink=self.name, delivered=True, detail="")


def test_the_links_go_beside_the_gated_text(rp):
    sink = _Sink()
    report = Report(markdown=f"A plan waits. See https://{RP}/a/{TOKEN} or https://evil.example/x", data={"alert": {"id": "inc-1"}},
                    promotion=(), actions=((chatops.LINK_LABEL, f"https://{RP}/a/{TOKEN}"),))
    chatops.notify(report, sinks=[sink])
    [text] = sink.sent
    body, links = text.rsplit("\n\n", 1)
    assert "https://" not in body  # the gate removed both URLs the text carried
    assert links == f"{chatops.LINK_LABEL}: https://{RP}/a/{TOKEN}"


def test_in_slack_the_link_is_a_button_and_its_address_is_not_printed(rp, monkeypatch):
    """Owner, 2026-10-12: "the link should be hidden under a button"."""
    posted = []
    monkeypatch.setattr(chatops, "_post_json", lambda url, payload, name: posted.append(payload) or chatops.Notification(
        sink=name, delivered=True, detail="ok"))
    link = f"https://{RP}/a/{TOKEN}"
    report = Report(markdown="A plan waits for an approval.", data={"alert": {"id": "inc-1"}}, promotion=(),
                    actions=((chatops.LINK_LABEL, link), ("Click <here>", link), (chatops.LINK_LABEL, "https://evil.example/x")))
    chatops.notify(report, sinks=[chatops.SlackWebhookSink("https://hooks.example.test/x", live=True)])
    [message] = posted
    assert "https://" not in message["text"] and message["unfurl_links"] is False
    section, actions = message["blocks"]
    assert section == {"type": "section", "text": {"type": "mrkdwn", "text": message["text"]}}
    assert actions == {"type": "actions", "elements": [{"type": "button", "style": "primary", "url": link,
                                                        "text": {"type": "plain_text", "text": chatops.LINK_LABEL}}]}
    # A text too long for a section keeps its parts as they are; the button is its own message after them.
    long = chatops.slack_messages(["x" * (chatops.SLACK_SECTION_CHARS + 1)], {"links": [[chatops.LINK_LABEL, link]]})
    assert [sorted(m) for m in long] == [["text"], ["blocks", "text"]] and long[1]["blocks"][0]["type"] == "actions"
    assert chatops.slack_messages(["one", "two"], {}) == [{"text": "one"}, {"text": "two"}]  # no link: no blocks
    # Several approvers, each their own link: each button says whose, and none is the primary one.
    two = chatops.slack_messages(["t"], {"links": [[f"{chatops.LINK_LABEL} (link of a)", link],
                                                   [f"{chatops.LINK_LABEL} (link of b)", link]]})
    assert [e["text"]["text"][-11:] for e in two[0]["blocks"][1]["elements"]] == ["(link of a)", "(link of b)"]
    assert not any("style" in e for e in two[0]["blocks"][1]["elements"])


def test_slack_is_told_its_note_of_a_button_click_arrived_and_nothing_is_done_with_it():
    """Slack sends an app a note of every button click, a link button's too, and marks the button as failed unless
    it is answered (docs.slack.dev, button element, read 2026-10-12)."""
    import pathlib

    from test_approval_page import setup as page_setup  # noqa: F401
    from warden.approval_page import ApprovalPage

    page = ApprovalPage(rp_id=RP, policy=_policy(), plan_of=lambda wf: None, signal=lambda wf, a: None)
    answered = page.handle("POST", "/s/interact", "payload=%7B%22type%22%3A%22block_actions%22%7D")
    assert (answered.status, answered.body) == (200, "")
    assert page.handle("GET", "/s/interact").status == 404
    tf = (pathlib.Path(__file__).resolve().parents[1] / "terraform" / "modules" / "warden-runtime" / "frontdoor.tf")
    assert '"POST /s/interact"' in tf.read_text(encoding="utf-8")


def _policy(with_passkeys=("owner",), tiers=("T1", "T2")):
    key = "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----\n"
    cred = approvals.PasskeyCredential(credential_id="c", public_key="p", sign_count=0, device_bound=True)
    return approvals.ApproverPolicy(approvers={
        "owner": approvals.Approver(public_key=key, tiers=list(tiers), passkeys=[cred] if "owner" in with_passkeys else []),
        "second": approvals.Approver(public_key=key, tiers=["T1"], passkeys=[cred]),
        "nokey": approvals.Approver(public_key=key, tiers=list(tiers))})


def test_a_link_for_each_approver_who_may_approve_the_tier_and_has_a_passkey(rp, tmp_path):
    import json

    from test_approval_page import PLAN
    from warden import audit
    from warden.activities import RemediationActivities
    from warden.approval_page import AuditLinkStore

    log = audit.AuditLog(tmp_path / "a.db")
    acts = RemediationActivities(audit=log, policy=_policy(), platform=None)
    links = acts._approval_links(PLAN)  # a T2 plan: "second" may approve T1 only, "nokey" has no passkey
    assert [label for label, _ in links] == [chatops.LINK_LABEL]  # one approver has a link: it names nobody
    both = RemediationActivities(audit=log, policy=_policy(tiers=("T1",)), platform=None)._approval_links(
        PLAN.model_copy(update={"tier": "T1"}))
    assert [label for label, _ in both] == [f"{chatops.LINK_LABEL} (link of owner)", f"{chatops.LINK_LABEL} (link of second)"]
    token = links[0][1].rsplit("/", 1)[1]
    assert chatops.approval_links(links) and AuditLinkStore(log).link(token).approver == "owner"
    assert token not in json.dumps([e["body"] for e in log.entries()])


def test_without_an_approval_domain_no_link_is_minted(monkeypatch, tmp_path):
    from test_approval_page import PLAN
    from warden import audit
    from warden.activities import RemediationActivities

    monkeypatch.delenv("WARDEN_APPROVAL_RP_ID", raising=False)
    log = audit.AuditLog(tmp_path / "a.db")
    assert RemediationActivities(audit=log, policy=_policy(), platform=None)._approval_links(PLAN) == ()
    assert log.entries() == []


def test_the_wait_opens_with_the_links_and_without_a_domain_says_nothing_new(rp, monkeypatch, tmp_path):
    from test_remediation_workflow import _no_approval, _run
    from test_remediation_workflow import owner as owner_fixture
    from test_remediation_workflow import world as world_fixture

    sent = []
    monkeypatch.setattr(chatops, "resolve_sinks", lambda threads=None: [_Sink()])
    real_notify = chatops.notify
    monkeypatch.setattr(chatops, "notify", lambda report, sinks=None, threads=None: sent.append(report) or real_notify(
        report, sinks, threads))
    world = world_fixture.__wrapped__(tmp_path, owner_fixture.__wrapped__())
    world["policy"] = _policy()
    _run(world, _no_approval)
    with_links = [r for r in sent if r.actions]
    # As the wait opens, and again at the halfway reminder: two messages carry links, each its own fresh one.
    assert len(with_links) == 2 and all(r.actions[0][0] == chatops.LINK_LABEL for r in with_links)
    assert with_links[0].actions[0][1] != with_links[1].actions[0][1]
    kinds = [e["kind"] for e in world["log"].entries("inc-42")]
    assert kinds.index("remediation.announce") < kinds.index("workflow.end")

    monkeypatch.delenv("WARDEN_APPROVAL_RP_ID")
    sent.clear()
    (tmp_path / "b").mkdir()
    world2 = world_fixture.__wrapped__(tmp_path / "b", owner_fixture.__wrapped__())
    world2["policy"] = _policy()
    _run(world2, _no_approval)
    assert not any(r.actions for r in sent)


def test_the_note_is_answered_by_a_function_with_nothing_in_it_and_no_permission():
    """Measured 2026-10-12: the approval function, started cold, answered Slack's note in 2.7 s with nothing loaded -
    a container image in the VPC - against Slack's limit of three. The answer is its own few lines."""
    import importlib.util
    import pathlib
    import re
    import zipfile

    module = pathlib.Path(__file__).resolve().parents[1] / "terraform" / "modules" / "warden-runtime"
    source = (module / "ack" / "ack.py").read_bytes().replace(b"\r\n", b"\n")
    with zipfile.ZipFile(module / "ack.zip") as z:  # what is deployed is exactly the reviewed source, and only it
        assert z.namelist() == ["ack.py"] and z.read("ack.py") == source
    assert b"import" not in source  # it reads nothing and calls nothing
    spec = importlib.util.spec_from_file_location("ack", module / "ack" / "ack.py")
    ack = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ack)
    answered = ack.handler({"body": "payload=%7B%22type%22%3A%22block_actions%22%7D"}, None)
    assert (answered["statusCode"], answered["body"]) == (200, "")
    tf = (module / "frontdoor.tf").read_text(encoding="utf-8")
    fn = tf[tf.index('resource "aws_lambda_function" "ack"'):tf.index('resource "aws_apigatewayv2_integration" "ack"')]
    assert 'handler          = "ack.handler"' in fn and "vpc_config" not in fn and "environment {" not in fn
    assert 'source_code_hash = filebase64sha256("${path.module}/ack.zip")' in fn and "role             = aws_iam_role.ack.arn" in fn
    every = "".join(p.read_text(encoding="utf-8") for p in module.glob("*.tf"))
    assert not re.search(r"role\s*=\s*aws_iam_role\.ack\.(id|name)", every)       # no policy is given to its role
    assert "permissions_boundary = var.permissions_boundary_arn" in tf[tf.index('resource "aws_iam_role" "ack"'):tf.index(fn[:40])]
    assert 'each.key == "POST /s/interact" ? aws_apigatewayv2_integration.ack.id' in tf  # the one route it serves
    assert 'source_arn    = "${aws_apigatewayv2_api.front.execution_arn}/*/POST/s/interact"' in tf


def test_in_slack_the_footer_is_the_small_line_under_the_message_with_no_rule():
    """Owner, 2026-10-14, of the "---" between a message and its footer: "it doesn't look good"."""
    link = f"https://{RP}/a/{TOKEN}"
    foot = "WARDEN · incident `inc-1` · audit head `abc` · check it with `warden audit show inc-1`."
    text = "The plan was denied by <@" + "U" + "0" * 3 + "ABCDEFG> (with their passkey): nothing was changed.\n\n---\n" + foot
    [plain] = chatops.slack_messages([text], {})
    section, context = plain["blocks"]
    assert plain["text"] == text  # whole, for a notification and for a client that shows no blocks
    assert section == {"type": "section", "text": {"type": "mrkdwn", "text": text.split("\n\n---\n")[0]}}
    assert context == {"type": "context", "elements": [{"type": "mrkdwn", "text": foot}]}
    assert "---" not in json_dumps(plain["blocks"])
    # With WARDEN's link: the message, its button, then the footer.
    [asked] = chatops.slack_messages([text], {"links": [[chatops.LINK_LABEL, link]]})
    assert [b["type"] for b in asked["blocks"]] == ["section", "actions", "context"]
    # Only the last part of a long report carries it, and only the last rule is the footer's.
    report = "part one\n---\nnot a footer"
    parts = chatops.slack_messages([report, "part two\n\n---\n_closing line_\n\n---\n" + foot], {})
    assert "blocks" not in parts[0] and parts[1]["blocks"][0]["text"]["text"].endswith("_closing line_")
    assert parts[1]["blocks"][-1]["elements"][0]["text"] == foot
    # Nothing to set apart, or too long for one block: the text as it is.
    assert chatops.slack_messages(["no footer here"], {}) == [{"text": "no footer here"}]
    long = "x" * (chatops.SLACK_SECTION_CHARS + 1) + "\n\n---\n" + foot
    assert chatops.slack_messages([long], {}) == [{"text": long}]
    assert chatops.slack_messages(["\n---\n" + foot], {}) == [{"text": "\n---\n" + foot}]


def json_dumps(value):
    import json

    return json.dumps(value)
