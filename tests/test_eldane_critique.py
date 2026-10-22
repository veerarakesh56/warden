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
from warden import approvals, autonomy, catalog, critique, egress, eldane, llm
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

def test_a_blind_no_argued_into_a_yes_by_wardens_own_model_never_signs(world):
    """Finding 1a (review of #166): the debate is WARDEN's own diagnosing model arguing for its plan - the
    self-preference the blind pass exists to stop. Its "yes" is recorded and said, and never signs."""
    eldane_side, warden_side = Scripted(_no(), _yes("M1", "C1")), Scripted(_answer())
    _sides(world, eldane_side, warden_side)
    assert _review(world) is None  # dev, L2, a signing key: still no signature
    [objection] = _rows(world, critique.OBJECTION)
    assert (objection["round"], objection["kind"], objection["by"]) == (1, "wrong_target", "eldane")
    [rebuttal] = _rows(world, critique.REBUTTAL)
    assert (rebuttal["round"], rebuttal["concede"], rebuttal["by"]) == (1, False, "warden")
    verdict = _rows(world, autonomy.VERDICT)[-1]
    assert verdict["agree"] is False
    assert verdict["debate_agree"] is True
    assert verdict["rounds"] == 1
    assert verdict["second_pass"] is False
    assert autonomy.ai_problems(world["log"], base._plan(), "")  # nothing on the record lets it approve later
    said = eldane.said(world["log"], base._plan(), "")
    assert "does not agree with this plan" in said
    assert "agreement won in that debate never approves" in said
    # Eldane was shown WARDEN's answer, as data, in its second question.
    assert "<<DEBATE>>" in eldane_side.asked[-1]
    assert "revision 7 broke it" in eldane_side.asked[-1]
    # WARDEN was shown the objection, numbered, as data.
    assert "<<OBJECTIONS>>" in warden_side.asked[0]
    assert "0. (wrong_target)" in warden_side.asked[0]


def test_a_yes_with_an_objection_is_a_no_and_never_signs(world):
    """CodeRabbit, PR 166: "agree" with an objection, grounded, on both passes signed - the debate runs only on a no,
    so the objection was never answered. It counts as a no, and the debate takes the objection up."""
    torn = {"agree": True, "reasons": [{"text": "the evidence shows it", "evidence": ["M1"]}],
            "objections": [{"kind": "not_reversible", "text": "it cannot be undone", "evidence": ["M1"]}]}
    _sides(world, Scripted(torn, torn), Scripted(_answer(concede=True)))
    assert _review(world) is None
    verdict = _rows(world, autonomy.VERDICT)[-1]
    assert verdict["agree"] is False
    assert "it agreed and objected at once, so it counts as a no" in [r["text"] for r in verdict["passes"][0]["reasons"]]
    [objection] = _rows(world, critique.OBJECTION)  # the debate answered it
    assert objection["kind"] == "not_reversible"


def _debate_won(world):
    """A review Eldane said no to blind, then yes to after WARDEN's answer: the debate was won, nothing signed."""
    blind_no = _no()
    blind_no["reasons"] = [{"text": "the blind no: the target differs", "evidence": ["M1"]}]
    _sides(world, Scripted(blind_no, {"agree": True, "reasons": [{"text": "the debate yes", "evidence": ["C1"]}]}),
           Scripted(_answer()))
    assert _review(world) is None


def test_the_record_shows_why_eldane_said_no_not_its_debate_yes(world):
    """CodeRabbit, PR 166: the record showed the debate's "yes" reasons under "Did not agree with the plan"."""
    from warden import records

    _debate_won(world)
    [said] = [d for d in records.record(world["log"], base.INC).decisions if d["who"] == approvals.AI_LABEL]
    assert said["what"].startswith("Did not agree with the plan")
    assert said["note"] == "the blind no: the target differs"


def test_the_approval_page_shows_why_eldane_said_no_not_its_debate_yes(world):
    """CodeRabbit, PR 166: the approver's page showed the debate's "yes" reasons under "does not agree"."""
    from warden.approval_page import ApprovalPage

    _debate_won(world)
    page = ApprovalPage(rp_id="approve.example.test", policy=world["policy"], plan_of=lambda wf: None,
                        signal=lambda *a: None, log=world["log"])
    shown = page._ai_review(base._plan())["ai_critic"]
    assert "does not agree" in shown
    assert "never approves" in shown
    assert shown.endswith(": the blind no: the target differs")
    assert "the debate yes" not in shown


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

def _read_only(answer):
    answer["objections"] = []  # it only wants to read more
    return answer


def test_eldane_may_read_evidence_again_in_full_still_blind_and_is_told_what_is_not_there(world):
    eldane_side = Scripted(_read_only(_no(read_again=["F1", "Z9"])), _yes(), _yes())
    _sides(world, eldane_side, Scripted())
    assert _review(world) is not None  # a blind yes after reading, then a yes with WARDEN's reasoning
    blind_again, informed = eldane_side.asked[1], eldane_side.asked[2]
    assert "<<READ AGAIN>>" in blind_again
    assert "[F1] orders: ImportError in revision 7" in blind_again
    assert "[Z9] is not on the record" in blind_again
    assert "<<WARDEN'S REASONING>>" not in blind_again  # the re-read is a blind pass
    assert "<<WARDEN'S REASONING>>" in informed
    assert "[F1] orders: ImportError in revision 7" in informed  # still shown: it stays citable


class Reasoned(Scripted):
    """Eldane as a self-preferring judge: "no" until it is shown WARDEN's reasoning, then "yes"."""

    def __init__(self, blind):
        super().__init__()
        self.blind = blind

    def complete(self, *, system, user, schema=None):
        self.asked.append(user)
        return Completion(json.dumps(_yes("M1") if "<<WARDEN'S REASONING>>" in user else self.blind), 10, 10)


def test_a_blind_no_that_only_asked_to_read_more_never_signs_on_a_yes_with_reasoning(world):
    """Finding 1b (review of #166): a blind "no" that asked to read items again was asked again WITH WARDEN's
    reasoning, and that pass's "yes" alone approved. The re-read is blind; only a blind yes lets pass two count."""
    eldane_side = Reasoned(_read_only(_no(read_again=["F1"])))
    _sides(world, eldane_side, Scripted())
    assert _review(world) is None
    verdict = _rows(world, autonomy.VERDICT)[-1]
    assert verdict["agree"] is False
    assert [p["agree"] for p in verdict["passes"]] == [False, False]  # blind, blind again: never shown the reasoning
    assert not any("<<WARDEN'S REASONING>>" in q for q in eldane_side.asked)


def test_a_blind_yes_then_a_no_with_reasoning_argued_back_to_yes_never_signs(world):
    """Pass two said no with an objection; WARDEN's answer turned it. Both passes did not agree: no signature."""
    eldane_side, warden_side = Scripted(_yes(), _no("cause_not_addressed"), _yes("M1", "C1")), Scripted(_answer())
    _sides(world, eldane_side, warden_side)
    assert _review(world) is None
    verdict = _rows(world, autonomy.VERDICT)[-1]
    assert (verdict["agree"], verdict["debate_agree"], verdict["rounds"]) == (False, True, 1)


def test_the_tools_read_only_what_is_recorded():
    tools = critique.EvidenceTools(base.EVIDENCE)
    assert tools.ids() == {"M1", "C1", "F1"}
    assert tools.item("C1").startswith("[C1] DEPLOY orders revision 7")
    assert tools.item("Z9") == ""
    public = {n for n in dir(tools) if not n.startswith("_")}
    assert public == {"ids", "item", "read_again"}  # reads of the recorded evidence, and nothing else


def test_items_read_in_an_earlier_round_stay_in_front_of_eldane(world, monkeypatch):
    """Finding 5 (review of #166): an item read again in round one stays citable, so every later question shows it."""
    monkeypatch.setattr(eldane, "MAX_EVIDENCE", len(base.EVIDENCE))  # L37 is past the cut: shown only when read
    world["log"].append(base.INC, "incident.evidence", {"prompt": base.EVIDENCE + "\n[L37] orders 5xx from rev 7"})
    eldane_side = Scripted(_no(read_again=["L37"]), _no("evidence_thin"), _no("evidence_thin"))
    _sides(world, eldane_side, Scripted(_answer(), _answer()))
    assert _review(world) is None
    assert "<<END EVIDENCE>>\n" in eldane_side.asked[0]
    assert "[L37] orders 5xx from rev 7" not in eldane_side.asked[0]
    for later in eldane_side.asked[1:]:  # after rounds one and two: L37 was asked for in the blind pass only
        assert "[L37] orders 5xx from rev 7" in later


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

    # Its own Slack token (B2, eldane_slack.py) is the one Slack credential it holds: it posts with it, never WARDEN's.
    held = settings.ZONE_SECRETS["critic"] - {"WARDEN_ELDANE_SLACK_TOKEN"}
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


def test_the_cost_doc_says_how_many_calls_a_review_makes_and_who_answers():
    """Finding 4 (review of #166): docs/COST.md said "two passes per plan"."""
    cost = (ROOT / "docs" / "COST.md").read_text(encoding="utf-8")
    assert f"`CALLS_PER_REVIEW` = {eldane.CALLS_PER_REVIEW} model calls per plan" in cost
    assert "a rebuttal from **the diagnosing model**" in cost
    assert "two passes per plan" not in cost


def test_an_item_read_again_past_the_cut_may_be_cited_and_only_then(world, monkeypatch):
    """With the ids limited to the evidence Eldane is shown (PR 42), an item it read again in full is shown too."""
    monkeypatch.setattr(eldane, "MAX_EVIDENCE", len(base.EVIDENCE))
    world["log"].append(base.INC, "incident.evidence", {"prompt": base.EVIDENCE + "\n[L37] orders 5xx from rev 7"})
    cites_l37 = {"agree": True, "reasons": [{"text": "it", "evidence": ["L37"]}]}
    eldane_side = Scripted(_read_only(_no(read_again=["L37"])), cites_l37, cites_l37)
    _sides(world, eldane_side, Scripted())
    assert _review(world) is not None
    assert "[L37] orders 5xx from rev 7" in eldane_side.asked[1]


# ----------------------------------------------------------------------------- WARDEN's answers: fail closed, costed

class APIStatusError(Exception):
    """A provider SDK's own error class: not a ValueError, a RuntimeError nor an OSError."""


class Failing:
    model = "test-model"

    def complete(self, **kw):
        raise APIStatusError("overloaded")


def _answer_with(world, provider):
    log = world["log"]
    return critique.answer(log, base.INC, provider, "evidence", [critique.Objection(kind="other", text="x")], {"M1"},
                           model_call=eldane._model_call, fallback=eldane._fallback, run_id="run-7")


def test_any_provider_error_in_wardens_answer_concedes_and_is_costed(world):
    """Finding 2 (review of #166): eldane.ask treats any provider error as a "no"; WARDEN's answer did not, so an SDK
    error crashed the review activity. And a rebuttal's spend was on no cost row."""
    [r] = _answer_with(world, Failing())
    assert r.concede is True
    [call] = _rows(world, llm.CALL)
    assert (call["where"], call["ok"], call["run_id"]) == ("eldane", False, "run-7")
    [fell] = _rows(world, llm.FALLBACK)
    assert fell["where"] == "eldane"
    assert fell["reason"] in llm.FALLBACK_REASONS
    [asked] = _rows(world, eldane.CALL)
    assert (asked["ok"], asked["purpose"], asked["error"]) == (False, "rebuttal", "APIStatusError")


def test_a_read_answer_from_warden_writes_its_cost_row(world):
    warden_side = Scripted(_answer(ids=("M1",)))
    warden_side.model = "test-model"
    [r] = _answer_with(world, warden_side)
    assert r.concede is False
    [call] = _rows(world, llm.CALL)
    assert (call["where"], call["ok"], call["prompt_tokens"], call["completion_tokens"]) == ("eldane", True, 10, 10)
    assert not _rows(world, llm.FALLBACK)


def test_an_unreadable_answer_from_warden_is_a_fallback(world):
    warden_side = Scripted("not an answer")
    [r] = _answer_with(world, warden_side)
    assert r.concede is True
    assert [f["reason"] for f in _rows(world, llm.FALLBACK)] == [llm.MODEL_REFUSED]
    assert len(_rows(world, llm.CALL)) == 1


def test_a_review_whose_rebuttal_call_fails_ends_with_no_signature_and_no_crash(world):
    _sides(world, Scripted(_no(), _yes()), Failing())
    assert _review(world) is None
    assert _rows(world, autonomy.VERDICT)[-1]["agree"] is False
    assert [c["where"] for c in _rows(world, llm.CALL)] == ["eldane", "eldane"]  # Eldane's blind pass, the rebuttal


# ----------------------------------------------------------------------------- egress: the real model guard

ACCOUNT = "4321" + "0987" + "6543"  # an account id's shape, built from parts (tests/fakes.py)
REGION = "eu" + "-west-1"


def _snapshots():
    ecs_arn = f"arn:aws:ecs:{REGION}:{ACCOUNT}:service/shop/orders"
    fn_arn = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:orders"
    # The shapes platforms/aws.py records as the plan's `state`: an ARN and "<account>/<Region>" each.
    return {
        "ecs_rollback_service": ({"cluster": "shop", "service": "orders", "to_task_definition": "orders:6"},
                                 {"cluster": "shop", "service": "orders", "arn": ecs_arn, "task_definition": "orders:7",
                                  "where": f"{ACCOUNT}/{REGION}", "strategy": "ROLLING"}),
        "lambda_move_alias": ({"function": "orders", "alias": "live", "to_version": "6"},
                              {"function": "orders", "alias": "live", "version": "7", "revision": "r-7",
                               "where": f"{ACCOUNT}/{REGION}", "arn": fn_arn}),
    }


def _guarded(cls):
    """`cls` behind the real egress guard, as every registered provider is (providers._REGISTRY)."""
    return egress.guard_provider(type(f"Guarded{cls.__name__}", (cls,), {"name": "test", "model": "test-model"}))


@pytest.mark.parametrize("entry", sorted(_snapshots()))
def test_reading_again_sends_no_raw_snapshot_through_the_real_guard(world, entry):
    """Finding 3 (review of #166): read_again sent the plan's snapshot raw - ARNs and the account id. The real guard
    refused that prompt; the snapshot is no longer sent at all (the plan already says its change from it)."""
    params, snapshot = _snapshots()[entry]
    assert egress.kinds_in(json.dumps(snapshot))  # the guard does refuse this snapshot
    plan = approvals.Plan(workflow_id="rem-1", incident_id=base.INC, entry=entry, tier="T2", params=params,
                          plan_hash="h1", created_at=datetime.now(UTC), target="", environment="dev",
                          snapshot=snapshot)
    eldane_side = _guarded(Scripted)(_read_only(_no(read_again=["F1"])), _yes(), _yes())
    _sides(world, eldane_side, _guarded(Scripted)())
    assert _review(world, plan) is not None
    assert len(eldane_side.asked) == 3  # blind, blind again with F1, with reasoning: every one passed the guard
    assert not any(ACCOUNT in q for q in eldane_side.asked)
    assert all(p["agree"] for p in _rows(world, autonomy.VERDICT)[-1]["passes"][1:])


def test_a_question_to_eldane_the_guard_refuses_is_a_no_and_never_a_crash(world):
    world["log"].append(base.INC, "incident.evidence", {"prompt": base.EVIDENCE + f"\n[L9] owner account {ACCOUNT}"})
    eldane_side = _guarded(Scripted)(_yes(), _yes())
    _sides(world, eldane_side, _guarded(Scripted)())
    assert _review(world) is None
    verdict = _rows(world, autonomy.VERDICT)[-1]
    assert verdict["agree"] is False
    assert "EgressBlocked" in verdict["passes"][-1]["reasons"][0]["text"]
    assert eldane_side.asked == []  # the refused prompt never reached the model


def test_an_answer_from_warden_the_guard_refuses_concedes_and_never_crashes(world):
    objection = _no()
    objection["objections"][0]["text"] = f"the target is in account {ACCOUNT}, not this one"  # Eldane echoed a value
    warden_side = _guarded(Scripted)(_answer())
    _sides(world, Scripted(objection, _yes()), warden_side)
    assert _review(world) is None
    assert warden_side.asked == []
    [rebuttal] = _rows(world, critique.REBUTTAL)
    assert rebuttal["concede"] is True
    assert [c.get("error") for c in _rows(world, eldane.CALL) if c.get("purpose") == "rebuttal"] == ["EgressBlocked"]
    assert [f["reason"] for f in _rows(world, llm.FALLBACK)] == [llm.EGRESS_BLOCKED]
