"""B2 (owner, 2026-10-17): Eldane in Slack - its review of a fix plan as a conversation in the discussion channel,
always labelled an AI, at most three rounds, its own Slack token in a slot only the critic zone reads, and only what is
on the record, redacted, ever posted. Each guard here has a test that fails when the guard is removed (plant checks in
the PR)."""

from __future__ import annotations

import ast
import json
import pathlib

import pytest

import fakes
import test_eldane_autonomy as base
import test_eldane_critique as debate
from warden import approvals, critique, eldane_slack, settings

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "warden"
world = base.world  # the Eldane tests' own world, shared: a test names it as its argument
CHANNEL = "C0DEVDISC1"
ELDANE_TOKEN = "xo" + "xb-eldane-test"  # built from parts (tests/fakes.py): no token-shaped literal in the file
WARDEN_TOKEN = "xo" + "xb-warden-test"


class FakeSlack:
    """Slack's Web API as chatops._slack_call reaches it: every call kept, with the token it came with."""

    def __init__(self):
        self.calls: list[tuple[str, dict, str]] = []

    def __call__(self, method, payload, token, *, form=False):
        self.calls.append((method, dict(payload), token))
        return {"ok": True, "ts": f"1700000000.{len(self.calls):06d}"}, "ok"


@pytest.fixture
def slack(monkeypatch):
    from warden import chatops

    fake = FakeSlack()
    monkeypatch.setattr(chatops, "_slack_call", fake)
    monkeypatch.setenv("WARDEN_DISCUSS_CHANNELS", f"dev={CHANNEL}")
    monkeypatch.delenv("WARDEN_DISCUSS_CHANNEL", raising=False)
    monkeypatch.setenv(eldane_slack.ELDANE_BOT_ENV, ELDANE_TOKEN)
    monkeypatch.setenv("WARDEN_SLACK_BOT_TOKEN", WARDEN_TOKEN)
    return fake


def _debate(world, *eldane_answers, warden_answers=()):
    """A review of the plan on the record: Eldane's answers in order, WARDEN's to each round."""
    debate._sides(world, debate.Scripted(*eldane_answers), debate.Scripted(*warden_answers))
    debate._review(world)
    return base._plan()


def _say_all(world, plan):
    """What the workflow does (RemediationWorkflow._eldane_in_slack), step by step, outside Temporal."""
    log = world["log"]
    said = eldane_slack.eldane_says(log, plan, "", eldane_slack.OPENING)
    for n in range(1, min(said, critique.MAX_ROUNDS) + 1):
        eldane_slack.eldane_says(log, plan, "", n)
        eldane_slack.warden_says(log, plan, "", n)
    eldane_slack.eldane_says(log, plan, "", eldane_slack.CLOSING)
    return said


def _texts(slack):
    return [(p.get("text", ""), token, p.get("thread_ts")) for _, p, token in slack.calls]


# ----------------------------------------------------------------------------- the conversation

def test_a_debate_is_posted_in_order_each_side_with_its_own_token(world, slack):
    plan = _debate(world, debate._no(), debate._yes("M1", "C1"), warden_answers=(debate._answer(),))
    assert _say_all(world, plan) == 1
    posted = _texts(slack)
    assert [m for m, _, _ in slack.calls] == ["chat.postMessage"] * 4
    (_, t0, root), (objs, t1, th1), (ans, t2, th2), (end, t3, th3) = posted
    assert root is None  # Eldane opens the thread
    assert {th1, th2, th3} == {"1700000000.000001"}  # and every message is in that one thread
    assert (t0, t1, t2, t3) == (ELDANE_TOKEN, ELDANE_TOKEN, WARDEN_TOKEN, ELDANE_TOKEN)
    assert {p["channel"] for _, p, _ in slack.calls} == {CHANNEL}  # dev's own discussion channel
    assert "round 1 of at most 3" in objs
    assert "(wrong_target)" in objs
    assert "[evidence: M1]" in objs
    assert ans.startswith(eldane_slack.WARDEN)
    assert "revision 7 broke it" in ans
    # #166: Eldane's "yes" came only after WARDEN's answers, so it signs nothing and the thread says why.
    assert "does not agree with this plan" in end
    thread = eldane_slack.thread_of(world["log"], plan, "")
    assert thread == {"channel": CHANNEL, "ts": "1700000000.000001"}


def test_every_message_eldane_posts_says_it_is_an_ai(world, slack):
    """EU AI Act Art. 50 (approvals.AI_LABEL): whatever its Slack app is named, each of its messages starts with it."""
    plan = _debate(world, debate._no(), debate._no("evidence_thin"), warden_answers=(debate._answer(),))
    _say_all(world, plan)
    eldane = [text for text, token, _ in _texts(slack) if token == ELDANE_TOKEN]
    assert len(eldane) == 4  # the opening, two rounds' objections, the end
    for text in eldane:
        assert text.startswith(f"*{approvals.AI_LABEL}*"), text
    assert "an AI, not a person" in eldane[0]
    warden = [text for text, token, _ in _texts(slack) if token == WARDEN_TOKEN]
    assert warden
    assert all(t.startswith(eldane_slack.WARDEN) for t in warden)


def test_at_most_three_rounds_are_posted_whatever_the_record_holds(world, slack):
    plan = _debate(world, *[debate._no("evidence_thin")] * 5, warden_answers=[debate._answer()] * 5)
    log = world["log"]
    # A fourth round's rows on the record - written by anything - are never posted.
    row = {"workflow_id": plan.workflow_id, "run_id": "", "plan_hash": plan.plan_hash}
    log.append(plan.incident_id, critique.OBJECTION, {**row, "round": 4, "index": 0, "kind": "other",
                                                      "text": "a fourth round", "evidence": [], "by": "eldane"})
    assert eldane_slack.rounds(log, plan, "") == critique.MAX_ROUNDS
    assert eldane_slack.objections(log, plan, "", 4) == ""
    assert eldane_slack.answers(log, plan, "", 4) == ""
    _say_all(world, plan)
    texts = [t for t, _, _ in _texts(slack)]
    assert sum("round " in t and "of at most 3" in t for t in texts) == 3
    assert not any("a fourth round" in t for t in texts)
    assert "a person decides" in texts[-1]


def test_a_message_already_delivered_is_not_posted_again(world, slack):
    plan = _debate(world, debate._no(), debate._yes(), warden_answers=(debate._answer(),))
    _say_all(world, plan)
    first = len(slack.calls)
    _say_all(world, plan)  # a retried activity, a replayed step
    assert len(slack.calls) == first


def test_no_review_on_the_record_says_nothing(world, slack):
    assert eldane_slack.eldane_says(world["log"], base._plan(), "", eldane_slack.OPENING) == eldane_slack.NOTHING
    assert slack.calls == []


def test_without_its_token_or_a_channel_nothing_is_posted(world, slack, monkeypatch):
    plan = _debate(world, debate._yes(), debate._yes())
    monkeypatch.delenv(eldane_slack.ELDANE_BOT_ENV)
    _say_all(world, plan)
    assert slack.calls == []
    monkeypatch.setenv(eldane_slack.ELDANE_BOT_ENV, ELDANE_TOKEN)
    monkeypatch.setenv("WARDEN_DISCUSS_CHANNELS", "prod=C0PRODDISC")  # no channel for dev
    _say_all(world, plan)
    assert slack.calls == []


def test_warden_never_opens_eldanes_thread(world, slack, monkeypatch):
    """With no thread Eldane opened (no token of its own), WARDEN's answers go nowhere - even with a channel and
    WARDEN's own token: nothing it posts can pass for Eldane's thread."""
    plan = _debate(world, debate._no(), debate._yes(), warden_answers=(debate._answer(),))
    monkeypatch.delenv(eldane_slack.ELDANE_BOT_ENV)
    _say_all(world, plan)
    assert eldane_slack.answers(world["log"], plan, "", 1)  # there is an answer to post...
    assert eldane_slack.warden_says(world["log"], plan, "", 1) is False  # ...and nowhere to post it
    assert slack.calls == []


def test_what_eldane_says_is_redacted_inert_and_gated(world, slack):
    """Model text from the record goes out as one inert line, a write command withheld (G4), and through chatops.notify:
    redacted again, and withheld by the outbound gate if a secret is still in it."""
    secret = fakes.AWS_ACCESS_KEY_ID  # an access-key shape, built from parts
    command = "kubectl delete deployment orders -n shop"
    plan = _debate(world, {"agree": False, "reasons": [], "objections": [
        {"kind": "other", "text": f"`{command}` with key {secret}\n```run me```", "evidence": ["M1"]}]},
        warden_answers=(debate._answer(concede=True),))
    _say_all(world, plan)
    texts = [t for t, _, _ in _texts(slack)]
    assert texts
    assert not any(secret in t for t in texts)
    assert not any(command in t for t in texts)
    [said] = [t for t in texts if "round 1" in t]
    assert "`" not in said  # no code span or fence from the model's words
    assert "\n" not in said.split("\n", 1)[1]  # the objection is one line


def test_the_model_s_words_are_one_inert_line_with_commands_withheld(world):
    """Before anything leaves: each objection and answer is one line, with no code mark, and a write command in it is
    withheld (gate G4) - so a hijacked model cannot put a runnable command or a code block in the channel."""
    command = "kubectl delete deployment orders -n shop"
    plan = _debate(world, {"agree": False, "reasons": [], "objections": [
        {"kind": "other", "text": f"run `{command}`\n```\nrm -rf /data\n```", "evidence": ["M1"]}]},
        warden_answers=({"rebuttals": [{"objection": 0, "concede": False, "text": f"no: `{command}`\nsecond line",
                                        "evidence": ["C1"]}]},))
    for said in (eldane_slack.objections(world["log"], plan, "", 1), eldane_slack.answers(world["log"], plan, "", 1)):
        _, line = said.split("\n")
        assert "`" not in line
        assert command not in line
        assert "[command withheld (G4)]" in line


def test_the_workflow_never_asks_for_more_than_three_rounds():
    """The loop in RemediationWorkflow._eldane_in_slack is bounded by MAX_ROUNDS, whatever the critic zone answers."""
    import inspect

    from warden import workflows

    source = inspect.getsource(workflows.RemediationWorkflow._eldane_in_slack)
    assert "for n in range(1, min(said, MAX_ROUNDS) + 1):" in source
    assert workflows.MAX_ROUNDS == critique.MAX_ROUNDS == 3


def test_a_message_the_gate_withholds_is_not_posted_under_eldanes_name(world, slack, monkeypatch):
    """The outbound gate replaces a message it withholds with a notice; that notice never goes out as Eldane's - an
    unlabelled message under its name (EU AI Act Art. 50) - nor as WARDEN's."""
    from warden import chatops
    from warden.gate import GateResult

    plan = _debate(world, debate._no(), debate._yes(), warden_answers=(debate._answer(),))
    eldane_slack.eldane_says(world["log"], plan, "", eldane_slack.OPENING)  # the thread, as usual
    monkeypatch.setattr(chatops, "enforce", lambda *a, **k: GateResult("BLOCK", "A WARDEN message was withheld", ["G5"]))
    before = len(slack.calls)
    eldane_slack.eldane_says(world["log"], plan, "", 1)
    eldane_slack.warden_says(world["log"], plan, "", 1)
    assert len(slack.calls) == before
    posted = [e["body"] for e in world["log"].entries(plan.incident_id, kinds=(eldane_slack.POSTED,))]
    assert [(p["step"], p["delivered"]) for p in posted[-2:]] == [("objections-1", False), ("answers-1", False)]


# ----------------------------------------------------------------------------- it posts, it never reads (R12)

def _slack_methods(path: pathlib.Path) -> set[str]:
    """Every Slack Web API method name a module's source holds (a string like `chat.postMessage`)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)
            and n.value.split(".")[0] in ("chat", "conversations", "users", "auth", "reactions", "files", "search")
            and "." in n.value and " " not in n.value}


def test_eldane_only_posts_and_never_reads_the_channel():
    """Register R12: anyone can write in the discussion channel, so nothing said there reaches Eldane - it holds no
    Slack method that reads, and what it is asked is still only eldane.READS."""
    from warden import eldane

    assert _slack_methods(SRC / "eldane_slack.py") == {"chat.postMessage"}
    assert eldane.READS == ("incident.evidence", "incident.diagnose")
    for name in ("eldane.py", "critique.py"):
        assert _slack_methods(SRC / name) == set(), name


# ----------------------------------------------------------------------------- its own token, the critic zone's alone

def test_its_token_is_a_secret_only_the_critic_zone_reads():
    name = eldane_slack.ELDANE_BOT_ENV
    assert name in settings.SECRETS
    assert name in settings.LOADABLE
    assert {z for z, held in settings.ZONE_SECRETS.items() if name in held} == {"critic"}
    assert settings.secret_id("dev", name, "critic") == "warden/dev/eldane-slack-token"
    # ...and the critic zone holds none of WARDEN's own Slack credentials.
    assert not {"WARDEN_SLACK_BOT_TOKEN", "WARDEN_SLACK_APP_TOKEN", "WARDEN_SLACK_WEBHOOK"} & settings.ZONE_SECRETS["critic"]
    assert name not in settings.loadable_for("worker", "notify")
    assert name in settings.loadable_for("worker", "critic")
    for lam in settings.LAMBDA_SECRETS:
        assert name not in settings.loadable_for(f"lambda-{lam}")


def test_each_side_speaks_from_its_own_zone():
    from warden import workflows

    assert workflows._ZONE_OF["critic_say"] == "critic"  # Eldane's token
    assert workflows._ZONE_OF["debate_reply"] == "notify"  # WARDEN's token


# ----------------------------------------------------------------------------- no masked value can be reached

_MODEL_FACING = ("eldane_slack", "eldane", "critique")
_NEVER = {"vault", "reveal"}


def _imports(module: str, *, top_only: bool) -> set[str]:
    path = SRC / f"{module}.py"
    if not path.exists():
        return set()
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = set()
    for node in tree.body if top_only else ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 1:
            out |= {node.module} if node.module else {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and (node.module or "").startswith("warden."):
            out.add(node.module.removeprefix("warden."))
        elif isinstance(node, ast.Import):
            out |= {a.name.removeprefix("warden.") for a in node.names if a.name.startswith("warden.")}
    return {m.split(".")[0] for m in out}


def test_no_eldane_code_path_imports_the_vault_or_its_reveal():
    """Owner's privacy rule: Eldane sees placeholders and stable ids, never a real value - no code it runs imports the
    people-only vault or reveal (lane PV), directly or through what those modules load."""
    for module in _MODEL_FACING:
        direct = _imports(module, top_only=False)
        assert not direct & _NEVER, module
        seen, todo = set(), [module, *direct]
        while todo:
            m = todo.pop()
            if m not in seen:
                seen.add(m)
                todo += list(_imports(m, top_only=True))
        assert not seen & _NEVER, (module, seen & _NEVER)


# ----------------------------------------------------------------------------- through the workflow (Temporal, CI)

def test_the_workflow_posts_the_debate_in_the_discussion_channel(world, slack):
    debate._sides(world, debate.Scripted(debate._no(), debate._yes("M1", "C1")), debate.Scripted(debate._answer()))
    world["platform"] = base.Platform()
    out = base._run(world, base._nobody, approval_ttl_minutes=1)
    # #166: a "yes" won in the debate never signs - nobody approved, so nothing is applied and the plan expires.
    assert out.status == "expired"
    assert world["platform"].applied == []
    tokens = [token for _, _, token in slack.calls]
    assert tokens == [ELDANE_TOKEN, ELDANE_TOKEN, WARDEN_TOKEN, ELDANE_TOKEN]
    assert all(t.startswith(f"*{approvals.AI_LABEL}*") for t, tok, _ in _texts(slack) if tok == ELDANE_TOKEN)


# ----------------------------------------------------------------------------- after #166 (review of #171)

def test_a_debate_won_yes_is_said_as_never_approving(world, slack):
    """#166: Eldane argued into a "yes" by WARDEN's own model does not sign; the thread says so, not "agrees"."""
    plan = _debate(world, debate._no(), debate._yes("M1", "C1"), warden_answers=(debate._answer(),))
    _say_all(world, plan)
    end = _texts(slack)[-1][0]
    assert "does not agree with this plan" in end
    assert "an agreement won in a debate never approves a plan" in end


class _Answer:
    """Slack's answer as urllib returns it."""

    def __init__(self, ts):
        self._body = json.dumps({"ok": True, "ts": ts}).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._body


def test_every_slack_request_eldane_and_warden_send_passes_the_real_egress_check(world, monkeypatch):
    """Each request the thread makes, built by the real chatops code, through egress.check_request: Slack's API host,
    the bot token in its header (never the body), the thread's ts (digits, never read as a phone number), the
    channel id and the model's redacted words - no value the guard refuses."""
    from warden import chatops, egress

    sent = []

    def urlopen(req, timeout=None):
        egress.check_request(req.full_url, req.data, dict(req.header_items()), req.get_method())
        sent.append(req)
        return _Answer(f"1700000000.{len(sent):06d}")

    monkeypatch.setattr(chatops.web, "urlopen", urlopen)
    monkeypatch.setenv("WARDEN_DISCUSS_CHANNELS", f"dev={CHANNEL}")
    monkeypatch.delenv("WARDEN_DISCUSS_CHANNEL", raising=False)
    monkeypatch.setenv(eldane_slack.ELDANE_BOT_ENV, ELDANE_TOKEN)
    monkeypatch.setenv("WARDEN_SLACK_BOT_TOKEN", WARDEN_TOKEN)
    objection = debate._no("wrong_target")
    objection["objections"][0]["text"] = "the 5xx are on <HOST_1>, not on orders - see [M1]"
    plan = _debate(world, objection, debate._yes("M1", "C1"), warden_answers=(debate._answer(),))
    assert _say_all(world, plan) == 1
    assert len(sent) == 4  # open, objections, answers, close: every one passed the check
    assert all(r.full_url.startswith("https://slack.com/api/chat.postMessage") for r in sent)
    assert all(ELDANE_TOKEN not in r.data.decode() and WARDEN_TOKEN not in r.data.decode() for r in sent)
    assert "thread_ts" in sent[1].data.decode()


def _with_slack_hung(world, workflow_cls, *, sandboxed=True):
    """A dev plan Eldane does not approve, run under `workflow_cls`, with Eldane's first Slack step hung. The stage the
    plan reached within 5 s, and the outcome once the owner says no."""
    import asyncio
    import threading
    import uuid
    from concurrent.futures import ThreadPoolExecutor

    from temporalio import activity
    from temporalio.testing import WorkflowEnvironment
    from temporalio.worker import UnsandboxedWorkflowRunner, Worker

    from warden.activities import FixRequest, RemediationActivities
    from warden.workflows import RemediationWorkflow

    release = threading.Event()
    # A workflow class made inside a test cannot be loaded by the sandbox: the plant check's runs unsandboxed.
    runner = {} if sandboxed else {"workflow_runner": UnsandboxedWorkflowRunner()}

    class HungSlack(RemediationActivities):
        @activity.defn(name="critic_say")
        def critic_say(self, plan, step):
            release.wait(20)  # Slack that does not answer
            return -1

    debate._sides(world, debate.Scripted(debate._no(), debate._yes("M1", "C1")), debate.Scripted(debate._answer()))
    world["platform"] = base.Platform()

    async def main():
        env = await WorkflowEnvironment.start_time_skipping(data_converter=base.CONVERTER)
        acts = HungSlack(audit=world["log"], policy=world["policy"], platform=world["platform"], critic=world["critic"])
        methods = [acts.resolve_plan, acts.gate, acts.announce, acts.approval_wait, acts.check_approval,
                   acts.check_passkey, acts.precheck, acts.apply, acts.check_success, acts.record_result, acts.rollback,
                   acts.finish, acts.again_alert, acts.side_effects, acts.critic_review, acts.autonomy_state,
                   acts.critic_say, acts.debate_reply]
        async with env, Worker(env.client, task_queue="eldane-test", workflows=[workflow_cls], activities=methods,
                               activity_executor=ThreadPoolExecutor(6), **runner):
            handle = await env.client.start_workflow(workflow_cls.run, FixRequest(**base.REQ),
                                                     id=f"rem-{uuid.uuid4().hex[:12]}", task_queue="eldane-test")
            stage = ""
            for _ in range(100):  # 5 s: far less than one Slack step may take (SAY)
                stage = await handle.query(RemediationWorkflow.stage)
                if stage == "awaiting_approval":
                    break
                await asyncio.sleep(0.05)
            release.set()
            for _ in range(600):
                if await handle.query(RemediationWorkflow.stage) == "awaiting_approval":
                    break
                await asyncio.sleep(0.05)
            plan = await handle.query(RemediationWorkflow.plan)
            await handle.signal(RemediationWorkflow.deny, approvals.Denial(
                approver="owner", workflow_id=handle.id, plan_hash=plan.plan_hash, reason="not now"))
            return stage, await handle.result()

    return asyncio.run(main())


def test_a_hung_slack_never_delays_the_persons_request(world, slack):
    """Review of #171: Eldane's conversation in Slack runs beside the plan. With its first step hung, the person is
    still asked at once and the plan waits for them - nothing in the decision path waits for Slack."""
    from warden.workflows import RemediationWorkflow

    stage, out = _with_slack_hung(world, RemediationWorkflow)
    assert stage == "awaiting_approval"  # asked while Slack still hung
    assert out.status == "denied"
    assert world["platform"].applied == []
    said = [e["body"].get("what") for e in world["log"].entries(base.INC, kinds=("remediation.announce",))]
    assert "opening" in said


def test_the_check_above_catches_a_conversation_awaited_in_the_decision_path(world, slack):
    """The plant check of the test above, run where Temporal runs (CI): the order before the review of #171 - the
    conversation awaited before the person is asked - never reaches the approval wait while Slack hangs."""
    from temporalio import workflow

    from warden.workflows import RemediationWorkflow

    @workflow.defn(name="RemediationWorkflowSlackInline")
    class Inline(RemediationWorkflow):
        @workflow.run
        async def run(self, req):
            return await super().run(req)

        async def _critic(self, req, acts, plan, accepted):
            got = await super()._critic(req, acts, plan, accepted)
            if self._eldane_said is not None:
                await self._eldane_said  # the old order: every Slack step finishes before the person is asked
            return got

    stage, out = _with_slack_hung(world, Inline, sandboxed=False)
    assert stage != "awaiting_approval"
    assert out.status == "denied"
