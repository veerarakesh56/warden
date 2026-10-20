"""Owner, 2026-10-17 (U3-2): Eldane's typed objections and WARDEN's answers, its read-only tools, and a fix's
"risks if approved" said before anyone decides.

Each guard here has a test that fails when the guard is removed (scripts/mutation_check.py plants them)."""

from __future__ import annotations

import ast
import json
import pathlib
from datetime import UTC, datetime

import pytest

import test_eldane_autonomy as base
from warden import autonomy, catalog, critique, eldane
from warden.activities import RemediationActivities
from warden.providers import Completion

ROOT = pathlib.Path(__file__).resolve().parents[1]
world = base.world  # the Eldane tests' own world, shared: a test names it as its argument
OPUS, SONNET = "claude-opus-5-5", "claude-sonnet-5-5"  # the diagnosis is Sonnet's (base.DIAGNOSER): Eldane is Opus


class Scripted:
    """A model that answers from a script, in order, and keeps every question it was asked."""

    def __init__(self, *answers):
        self.answers, self.asked = list(answers), []

    def complete(self, *, system, user, schema=None):
        self.asked.append(user)
        reply = self.answers.pop(0) if self.answers else {"agree": False, "reasons": []}
        return Completion(json.dumps(reply), 10, 10)


def _yes(*ids):
    return {"agree": True, "reasons": [{"text": "the evidence shows it", "evidence": list(ids) or ["M1"]}]}


def _no(kind="wrong_target", ids=("M1",), read_again=()):
    return {"agree": False, "reasons": [], "read_again": list(read_again),
            "objections": [{"kind": kind, "text": f"{kind} - see the evidence", "evidence": list(ids)}]}


def _answer(concede=False, ids=("C1",)):
    return {"rebuttals": [{"objection": 0, "concede": concede, "text": "revision 7 broke it", "evidence": list(ids)}]}


def _sides(world, eldane_model, warden_model):
    """The critic with each side scripted: Eldane on Opus, WARDEN's answers on Sonnet (the diagnosis's model)."""
    def provider_for(model):
        return {OPUS: eldane_model, SONNET: warden_model}[model]
    world["critic"] = eldane.Critic(provider_for=provider_for, models=(OPUS, SONNET), key=world["critic"].key)


def _review(world, plan=None):
    return eldane.review(world["log"], world["policy"], plan or base._plan(), world["critic"], run_id="",
                         chance=lambda n: n - 1)  # never a catch trial


def _rows(world, kind):
    return [e["body"] for e in world["log"].entries(base.INC, kinds=(kind,))]


# ----------------------------------------------------------------------------- objections and WARDEN's answers

def test_an_objection_answered_with_evidence_can_end_in_agreement(world):
    eldane_side, warden_side = Scripted(_no(), _yes("M1", "C1")), Scripted(_answer())
    _sides(world, eldane_side, warden_side)
    signed = _review(world)
    assert signed is not None  # dev, L2: Eldane agreed after WARDEN's answer, from a pass that saw its reasoning
    [objection] = _rows(world, critique.OBJECTION)
    assert (objection["round"], objection["kind"], objection["by"]) == (1, "wrong_target", "eldane")
    [rebuttal] = _rows(world, critique.REBUTTAL)
    assert (rebuttal["round"], rebuttal["concede"], rebuttal["by"]) == (1, False, "warden")
    verdict = _rows(world, autonomy.VERDICT)[-1]
    assert verdict["rounds"] == 1
    assert verdict["second_pass"] is True
    # Eldane was shown WARDEN's answer, as data, in its second question.
    assert "<<DEBATE>>" in eldane_side.asked[-1]
    assert "revision 7 broke it" in eldane_side.asked[-1]
    # WARDEN was shown the objection, numbered, as data.
    assert "<<OBJECTIONS>>" in warden_side.asked[0]
    assert "0. (wrong_target)" in warden_side.asked[0]


def test_warden_conceding_an_objection_ends_the_debate_and_a_person_decides(world):
    eldane_side, warden_side = Scripted(_no("cause_not_addressed"), _yes()), Scripted(_answer(concede=True))
    _sides(world, eldane_side, warden_side)
    assert _review(world) is None
    assert len(eldane_side.asked) == 1  # never asked again: the objection holds
    verdict = _rows(world, autonomy.VERDICT)[-1]
    assert verdict["agree"] is False
    assert verdict["rounds"] == 1


def test_at_most_three_rounds_then_a_person_decides(world):
    eldane_side = Scripted(*[_no("evidence_thin")] * 5)
    warden_side = Scripted(*[_answer()] * 5)
    _sides(world, eldane_side, warden_side)
    assert _review(world) is None
    assert len(warden_side.asked) == critique.MAX_ROUNDS
    assert len(eldane_side.asked) == 1 + critique.MAX_ROUNDS
    assert {r["round"] for r in _rows(world, critique.OBJECTION)} == {1, 2, 3}
    assert _rows(world, autonomy.VERDICT)[-1]["rounds"] == critique.MAX_ROUNDS


def test_an_answer_resting_on_evidence_that_is_not_there_concedes(world):
    eldane_side, warden_side = Scripted(_no(), _yes()), Scripted(_answer(ids=("Z9",)))
    _sides(world, eldane_side, warden_side)
    assert _review(world) is None
    [rebuttal] = _rows(world, critique.REBUTTAL)
    assert rebuttal["concede"] is True
    assert "counts as conceded" in rebuttal["text"]


def test_no_readable_answer_from_warden_concedes_every_objection(world):
    class Silent:
        def complete(self, **kw):
            return Completion("not json at all", 1, 1)
    eldane_side = Scripted(_no(), _yes())
    _sides(world, eldane_side, Silent())
    assert _review(world) is None
    assert all(r["concede"] for r in _rows(world, critique.REBUTTAL))


def test_an_objection_of_a_kind_not_on_the_list_is_an_unreadable_answer(world):
    eldane_side = Scripted({"agree": True, "reasons": [{"text": "ok", "evidence": ["M1"]}],
                            "objections": [{"kind": "vibes", "text": "x", "evidence": []}]})
    _sides(world, eldane_side, Scripted())
    assert _review(world) is None
    assert not _rows(world, critique.OBJECTION)


def test_an_objection_citing_what_is_not_on_the_record_makes_the_answer_a_no(world):
    eldane_side = Scripted({"agree": True, "reasons": [{"text": "ok", "evidence": ["M1"]}],
                            "objections": [{"kind": "other", "text": "x", "evidence": ["Q7"]}]}, _yes())
    _sides(world, eldane_side, Scripted(_answer(concede=True)))
    assert _review(world) is None


# ----------------------------------------------------------------------------- read-only tools

def test_eldane_may_read_evidence_again_in_full_and_is_told_what_is_not_there(world):
    eldane_side = Scripted(_no(read_again=["F1", "Z9"]), _yes())
    eldane_side.answers[0]["objections"] = []  # only wants to read more
    _sides(world, eldane_side, Scripted())
    assert _review(world) is not None
    second = eldane_side.asked[1]
    assert "<<READ AGAIN>>" in second
    assert "[F1] orders: ImportError in revision 7" in second
    assert "[Z9] is not on the record" in second


def test_the_tools_read_only_what_is_recorded():
    tools = critique.EvidenceTools(base.EVIDENCE, {"revision": "7"})
    assert tools.ids() == {"M1", "C1", "F1"}
    assert tools.item("C1").startswith("[C1] DEPLOY orders revision 7")
    assert tools.item("Z9") == ""
    assert json.loads(tools.live_state()) == {"revision": "7"}
    public = {n for n in dir(tools) if not n.startswith("_")}
    assert public == {"ids", "item", "live_state", "read_again"}  # reads, and nothing else


# Modules that read a live system, or change one: never reachable from Eldane's code.
LIVE = ("platforms", "identity", "actor_use", "remediation", "aws_stack", "aws_backend", "aws_describe", "k8s_backend",
        "database", "tools", "investigation", "resolver", "boto3", "botocore", "kubernetes", "psycopg", "pymysql",
        "redis", "urllib", "requests", "httpx", "socket", "subprocess")


@pytest.mark.parametrize("module", ["critique.py", "eldane.py"])
def test_eldane_reaches_no_live_system_by_construction(module):
    tree = ast.parse((ROOT / "src" / "warden" / module).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported |= {(node.module or "").split(".")[0], *(a.name for a in node.names)}
    assert not imported & set(LIVE), imported & set(LIVE)


def test_the_critic_zone_holds_no_reader_or_actor_credentials():
    from warden import settings

    held = settings.ZONE_SECRETS["critic"]
    assert not {s for s in held if any(w in s for w in ("ROLE", "DSN", "K8S", "AWS", "GITHUB", "SLACK"))}


# ----------------------------------------------------------------------------- risks if approved

def test_every_fix_in_the_catalogue_names_its_risks():
    assert set(catalog.RISKS) == set(catalog.CATALOG)
    for entry, risks in catalog.RISKS.items():
        assert 1 <= len(risks) <= 3, entry
        assert all(0 < len(r) <= 160 for r in risks), entry
    assert catalog.risks_of("not_an_entry") == ()


def test_the_request_in_the_channel_says_the_risks_if_approved(world, monkeypatch):
    sent = []
    monkeypatch.setattr("warden.activities._send", lambda log, incident, report: sent.append(report.markdown) or [])
    plan = base._plan()
    acts = RemediationActivities(audit=world["log"], policy=world["policy"], platform=None)
    acts.announce(plan, "opening")
    [said] = sent
    assert "Risks if approved: " + "; ".join(catalog.risks_of(plan.entry)) in said


def test_the_approval_page_shows_the_risks_if_approved():
    from test_approval_page import _show

    page, device, _, _ = _page()
    token = page.new_link("rem-dev-1", "owner")
    plan = json.loads(_show(page, device, token).body)["plan"]
    assert plan["risks_if_approved"] == "; ".join(catalog.risks_of("k8s_restart"))
    assert "owner" not in json.dumps(plan)  # a request names nobody


def _page():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from test_approval_page import RP, _Clock, _enrol
    from test_passkeys_h6 import SoftAuthenticator
    from warden import approvals
    from warden.approval_page import ApprovalPage

    plan = approvals.Plan(workflow_id="rem-dev-1", incident_id="inc-9", entry="k8s_restart", tier="T1",
                          params={"namespace": "shop", "deployment": "orders"}, plan_hash="p" * 64,
                          created_at=datetime(2026, 10, 3, 9, tzinfo=UTC), target="dev/k8s/shop/orders",
                          environment="dev")
    device = SoftAuthenticator()
    cred = _enrol(device)
    pem = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    policy = approvals.ApproverPolicy(approvers={"owner": approvals.Approver(
        public_key=pem, tiers=["T1", "T2"], passkeys=[approvals.PasskeyCredential(
            credential_id=cred.credential_id, public_key=cred.public_key, sign_count=0, device_bound=True)])})
    page = ApprovalPage(rp_id=RP, policy=policy, plan_of=lambda wf: plan if wf == plan.workflow_id else None,
                        signal=lambda wf, a: None, clock=_Clock())
    return page, device, None, None


def test_eldane_is_shown_the_risks_too(world):
    eldane_side = Scripted(_yes(), _yes())
    _sides(world, eldane_side, Scripted())
    _review(world)
    assert "risks if approved: " + "; ".join(catalog.risks_of("k8s_rollout_undo")) in eldane_side.asked[0]


def test_a_review_counts_its_debate_against_the_daily_ceiling(world, monkeypatch):
    monkeypatch.setattr(eldane, "DAILY_CALLS", eldane.CALLS_PER_REVIEW - 1)
    _sides(world, Scripted(_yes(), _yes()), Scripted())
    assert _review(world) is None
    assert "daily ceiling" in _rows(world, autonomy.VERDICT)[-1]["skipped"]


def test_an_item_read_again_past_the_cut_may_be_cited_and_only_then(world, monkeypatch):
    """With the ids limited to the evidence Eldane is shown (PR 42), an item it read again in full is shown too."""
    monkeypatch.setattr(eldane, "MAX_EVIDENCE", len(base.EVIDENCE))
    world["log"].append(base.INC, "incident.evidence", {"prompt": base.EVIDENCE + "\n[L37] orders 5xx from rev 7"})
    cites_l37 = {"agree": True, "reasons": [{"text": "it", "evidence": ["L37"]}]}
    eldane_side = Scripted(_no(read_again=["L37"]), cites_l37)
    eldane_side.answers[0]["objections"] = []
    _sides(world, eldane_side, Scripted())
    assert _review(world) is not None
    assert "[L37] orders 5xx from rev 7" in eldane_side.asked[1]
