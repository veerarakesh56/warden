"""scripts/eldane_bench.py (owner item 4, 2026-10-21): Eldane measured on the G10 held-out set.

Guards, each planted (PR body): the scorer's exact rates from stored fake answers; the paid run refuses any key but
the cloud runtime's, before a model is built; the cost cap stops the run before a call whose worst case would pass it;
the prompt is Eldane's production blind pass, word for word; a dry run calls nothing and reads no key.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import sys
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden import approvals, audit, eldane
from warden.providers import Completion

ROOT = pathlib.Path(__file__).resolve().parents[1]
FAKE_KEY = "not-a-real-" + "key-for-tests"
MODEL = "claude-opus-5-5"
PRICES = (4.0, 20.0)
EVIDENCE = "[M1] error_rate orders 41% since 10:02Z\n[C1] DEPLOY orders revision 7 at 10:01Z by ci"


def _script():
    sys.path.insert(0, str(ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location(
        "eldane_bench", ROOT / "scripts" / "eldane_bench.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["eldane_bench"] = mod  # its dataclasses look their module up
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def bench():
    return _script()


def _verdict(agree: bool, *cited: str) -> str:
    return json.dumps({"agree": agree, "reasons": [{"text": "because", "evidence": list(cited)}]})


# Stored fake Eldane answers, one per plan, and what each one is:
ANSWERS = {
    "r1": _verdict(True, "M1"),  # right, approved
    "r2": _verdict(True, "M1", "C1"),  # right, approved
    "r3": _verdict(False, "M1"),  # right, blocked (a readable no)
    "r4": _verdict(
        True, "Z9"
    ),  # right, its yes cites what is not there: refused by the check -> blocked
    "r5": "not json at all",  # right, unreadable -> unanswered
    "h1": _verdict(False, "C1"),  # harmful, caught
    "h2": _verdict(True, "M1"),  # harmful, missed and let through
    "h3": _verdict(True),  # harmful, a yes citing nothing: missed, but the check refuses it
    "w1": _verdict(False, "M1"),  # wrong, caught
    "w2": _verdict(False, "Q7"),  # wrong, a no citing what is not there: unscored
    "w3": _verdict(False, "C1"),  # wrong, caught
}


class StoredEldane:
    """Answers each plan with its stored answer; records every prompt, so a test sees every call."""

    def __init__(self, input_tokens=1000, output_tokens=500):
        self.asked: list[str] = []
        self.tokens = (input_tokens, output_tokens)

    def complete(self, *, system, user, schema=None):
        assert system == eldane.SYSTEM
        self.asked.append(user)
        name = user.split("ID=", 1)[1].split()[0]
        return Completion(ANSWERS[name], *self.tokens)


def _prepared(bench, names=ANSWERS):
    out = []
    for name in names:
        label = {"r": "right", "h": "harmful", "w": "wrong"}[name[0]]
        plan = bench.Plan(
            name,
            label,
            "test",
            "k8s_restart",
            {"namespace": "shop", "deployment": "orders"},
            "T1",
            "dev",
        )
        out.append(
            bench.Prepared(
                plan, f"<<EVIDENCE>>\n{EVIDENCE}\n<<END EVIDENCE>>\nID={name} ", {"M1", "C1"}
            )
        )
    return out


def test_the_scorer_gives_exact_rates_from_stored_fake_answers(bench):
    rows, spent = bench.run(
        _prepared(bench), StoredEldane(), PRICES, cap_usd=10.0, log=lambda _: None
    )
    m = bench.score(rows)
    assert (m["right_asked"], m["right_approved"], m["right_blocked"], m["right_unanswered"]) == (
        5,
        2,
        2,
        1,
    )
    assert (m["approve_rate"], m["false_block_rate"]) == (0.4, 0.4)
    assert (
        m["bad_asked"],
        m["bad_caught"],
        m["bad_missed"],
        m["bad_unscored"],
        m["bad_let_through"],
    ) == (6, 3, 2, 1, 1)
    assert m["catch_rate"] == 0.5
    assert (m["harmful_n"], m["harmful_caught"], m["harmful_catch_rate"]) == (3, 1, 0.3333)
    assert (m["wrong_n"], m["wrong_caught"], m["wrong_catch_rate"]) == (3, 2, 0.6667)
    assert m["not_asked"] == 0
    assert spent == pytest.approx(11 * (1000 * 4.0 + 500 * 20.0) / 1e6)


def test_the_cap_stops_the_run_before_a_call_whose_worst_case_would_pass_it(bench):
    prepared = _prepared(bench)
    one = bench.worst_usd(prepared[0].bytes, PRICES)
    model = StoredEldane(
        input_tokens=10, output_tokens=16384
    )  # every answer uses the whole output cap
    rows, spent = bench.run(prepared, model, PRICES, cap_usd=2.5 * one, log=lambda _: None)
    assert len(model.asked) == 2  # the third call's worst case would pass the cap
    assert [r["asked"] for r in rows] == [True, True] + [False] * 9
    assert spent <= 2.5 * one
    m = bench.score(rows)
    assert (m["not_asked"], m["right_asked"], m["bad_asked"]) == (9, 2, 0)


def test_a_failed_call_is_counted_at_its_worst_case(bench):
    class Down:
        def complete(self, **kw):
            raise TimeoutError

    prepared = _prepared(bench, ["r1", "r2", "r3"])
    one = bench.worst_usd(prepared[0].bytes, PRICES)
    rows, spent = bench.run(prepared, Down(), PRICES, cap_usd=2.5 * one, log=lambda _: None)
    assert [r["asked"] for r in rows] == [True, True, False]
    assert spent == pytest.approx(2 * one, abs=1e-4)
    assert bench.score(rows)["right_unanswered"] == 2


class FakeSecrets:
    def __init__(self, value=FAKE_KEY, error=None):
        self.value, self.error, self.asked = value, error, []

    def get_secret_value(self, SecretId):
        self.asked.append(SecretId)
        if self.error:
            raise self.error
        return {"SecretString": self.value}


def test_a_key_set_in_a_local_shell_is_refused(bench):
    env = {"ANTHROPIC_API_KEY": FAKE_KEY}
    secrets = FakeSecrets()
    with pytest.raises(bench.Refused, match="not a cloud runtime task"):
        bench.runtime_key(env, secrets)
    assert secrets.asked == []


def test_a_key_in_another_environment_s_task_is_refused(bench):
    env = {
        "ANTHROPIC_API_KEY": FAKE_KEY,
        "ECS_CONTAINER_METADATA_URI_V4": "http://169.254.170.2/v4/x",
        "WARDEN_ENV": "not-the-runtime",
    }
    secrets = FakeSecrets()
    with pytest.raises(bench.Refused):
        bench.runtime_key(env, secrets)


def test_the_runtime_task_s_own_key_is_used(bench):
    env = {
        "ANTHROPIC_API_KEY": FAKE_KEY,
        "ECS_CONTAINER_METADATA_URI_V4": "http://169.254.170.2/v4/x",
        "WARDEN_ENV": bench.runtime_environment(),
    }
    secrets = FakeSecrets()
    bench.runtime_key(env, secrets)
    assert secrets.asked == []
    assert env["ANTHROPIC_API_KEY"] == FAKE_KEY


def test_the_key_is_read_from_the_runtime_s_slot_and_never_said(bench):
    env: dict[str, str] = {}
    secrets = FakeSecrets()
    said = bench.runtime_key(env, secrets)
    assert secrets.asked == [f"warden/{bench.runtime_environment()}/anthropic-api-key"]
    assert env["ANTHROPIC_API_KEY"] == FAKE_KEY
    assert said is None


@pytest.mark.parametrize(
    "secrets", [FakeSecrets(error=PermissionError("denied")), FakeSecrets(value="  ")]
)
def test_no_runtime_key_no_run(bench, secrets):
    env: dict[str, str] = {}
    with pytest.raises(bench.Refused):
        bench.runtime_key(env, secrets)
    assert "ANTHROPIC_API_KEY" not in env


def _small_set(bench, n=3):
    cases = bench.load_set()
    return lambda: {c: cases[c] for c in sorted(cases)[:n]}


def test_the_paid_run_refuses_outside_the_runtime_before_any_model_is_built(
    bench, monkeypatch, tmp_path, capsys
):
    built = []
    from warden import providers

    monkeypatch.setitem(providers._REGISTRY, "anthropic", lambda **kw: built.append(kw))
    monkeypatch.setattr(bench, "load_set", _small_set(bench, 5))
    monkeypatch.setenv("ANTHROPIC_API_KEY", FAKE_KEY)
    monkeypatch.delenv("ECS_CONTAINER_METADATA_URI_V4", raising=False)
    code = bench.main(["--model", MODEL, "--cap-usd", "5", "--out", str(tmp_path / "out")])
    said = capsys.readouterr()
    assert code == 2
    assert built == []
    assert "not a cloud runtime task" in said.err
    assert FAKE_KEY not in said.out + said.err


def test_a_dry_run_calls_nothing_and_reads_no_key(bench, monkeypatch, capsys):
    from warden import providers

    monkeypatch.setitem(
        providers._REGISTRY, "anthropic", lambda **kw: pytest.fail("a dry run built a model")
    )
    monkeypatch.setattr(bench, "runtime_key", lambda *a, **k: pytest.fail("a dry run read a key"))
    monkeypatch.setattr(bench, "load_set", _small_set(bench, 5))
    assert bench.main(["--model", MODEL, "--dry-run"]) == 0
    assert "Nothing was called" in capsys.readouterr().out


def test_a_paid_run_needs_a_cap_and_a_critic_model(bench):
    with pytest.raises(SystemExit):
        bench.main(["--model", MODEL])
    with pytest.raises(SystemExit):
        bench.main(["--model", "some-other-model", "--dry-run"])
    with pytest.raises(SystemExit):
        bench.main(["--model", MODEL, "--cap-usd", "500"])


def test_the_prompt_is_eldane_s_production_blind_pass_word_for_word(bench, tmp_path):
    """eldane.review, on the same evidence and plan, sends exactly what the bench sends."""
    log = audit.AuditLog(tmp_path / "audit.db", key=Ed25519PrivateKey.generate())
    log.append("inc-1", "incident.evidence", {"prompt": EVIDENCE})
    log.append(
        "inc-1",
        "incident.diagnose",
        {
            "hypothesis": "h",
            "confidence": 0.5,
            "cited": ["M1"],
            "action": "restart_pods",
            "target": "orders",
            "provenance": {
                "provider": "anthropic",
                "model": "claude-sonnet-5-5",
                "system_sha256": "ab" * 32,
            },
        },
    )
    params = {"namespace": "shop", "deployment": "orders", "to_revision": "6"}
    sent: list[str] = []

    class Capture:
        def complete(self, *, system, user, schema=None):
            sent.append(user)
            return Completion(_verdict(False, "M1"), 1, 1)

    critic = eldane.Critic(provider_for=lambda m: Capture(), models=(MODEL, "claude-sonnet-5-5"))
    plan = approvals.Plan(
        workflow_id="w",
        incident_id="inc-1",
        entry="k8s_rollout_undo",
        tier="T2",
        params=params,
        created_at=datetime.now(UTC),
        target="dev/k8s/shop/orders",
        environment="dev",
        snapshot={"revision": "7"},
    )
    policy = approvals.ApproverPolicy(approvers={})
    eldane.review(log, policy, plan, critic, run_id="", chance=lambda n: n - 1)
    mine, ids = bench.blind_prompt(
        EVIDENCE,
        bench.Plan("inc-1", "right", "t", "k8s_rollout_undo", params, "T2", "dev"),
        snapshot={"revision": "7"},
    )
    assert sent[0] == mine
    assert ids == {"M1", "C1"}


def test_every_plan_is_from_the_catalogue_and_no_value_is_invented(bench):
    from warden import catalog

    cases = bench.load_set()
    plans, extra = bench.all_plans({c: cases[c] for c in sorted(cases)[:40]})
    assert plans
    assert {p.label for p in plans} == {"right", "harmful", "wrong"}
    for p in plans:
        assert p.entry in catalog.CATALOG
        spec = catalog.CATALOG[p.entry].params
        assert set(p.params) == set(spec)
        assert all(
            v in (bench.READ_LIVE, bench.STEP_LIVE)
            for k, v in p.params.items()
            if k in bench.LIVE_NUMBERS and spec[k].kind == "int"
        )
    assert len({p.key() for p in plans}) == len(plans)  # never one plan twice
    assert all(m["label"] in ("right", "harmful") for m in extra["unplannable"])


def test_a_right_plan_is_never_also_counted_harmful_or_wrong(bench):
    a = bench.Plan(
        "c", "right", "x", "k8s_restart", {"namespace": "n", "deployment": "d"}, "T1", "dev"
    )
    b = bench.Plan(
        "c", "wrong", "other:y", "k8s_restart", {"namespace": "n", "deployment": "d"}, "T1", "dev"
    )
    c = bench.Plan(
        "c", "harmful", "z", "k8s_scale", {"namespace": "n", "deployment": "d"}, "T1", "dev"
    )
    d = bench.Plan(
        "c", "wrong", "other:z", "k8s_scale", {"namespace": "n", "deployment": "d"}, "T1", "dev"
    )
    kept, dropped = bench.dedupe([a, b, c, d])
    assert kept == [a]
    assert [x["why"] for x in dropped] == ["both harmful and wrong"]


def _result(bench, **over):
    rows = [
        {"label": "right", "said_yes": True, "grounded": True, "agree": True},
        {"label": "harmful", "said_yes": False, "grounded": True, "agree": False},
    ]
    doc = {
        "measured_at": "2026-10-22T09:30Z",
        "model": MODEL,
        "effort": "medium",
        "eldane_prompt": "0123456789ab",
        "complete": True,
        "spent_usd": 3.21,
        "cap_usd": 25.0,
        "metrics": bench.score(rows),
    }
    return {**doc, **over}


def _checkout(bench, root):
    (root / "docs").mkdir()
    (root / "docs" / "BENCHMARKS.md").write_text(
        f"x\n{bench.BENCH_BEGIN}\n| not yet measured - run it | |\n{bench.BENCH_END}\ny\n",
        encoding="utf-8",
    )
    (root / "README.md").write_text(
        f"a\n{bench.README_BEGIN}\n- not yet measured\n{bench.README_END}\nb\n", encoding="utf-8"
    )


def test_record_replaces_the_not_yet_measured_row_and_the_readme_line(bench, tmp_path, monkeypatch):
    root = tmp_path / "checkout"
    root.mkdir()
    _checkout(bench, root)
    monkeypatch.setattr(bench, "ROOT", root)  # the checkout whose two files it may write
    path = tmp_path / "eldane-bench-2026-10-22T0930Z.json"
    path.write_text(json.dumps(_result(bench)), encoding="utf-8")
    assert bench.record(path) == 0
    text = (root / "docs" / "BENCHMARKS.md").read_text(encoding="utf-8")
    assert "not yet measured" not in text
    row = "| 2026-10-22T09:30Z | claude-opus-5-5 (medium) | `0123456789ab` | 1 of 1 (100%) | 1 of 1 (100%) |"
    assert row in text
    readme = (root / "README.md").read_text(encoding="utf-8")
    assert "1 of 1 (100%) right fixes, caught 1 of 1 (100%)" in readme


@pytest.mark.parametrize(
    "over",
    [
        {"model": "someone@example.invalid"},
        {"measured_at": "yesterday"},
        {"eldane_prompt": "not a hash"},
    ],
)
def test_record_writes_only_numbers_a_date_a_hash_and_a_listed_model(bench, tmp_path, over):
    doc = _result(bench, **over)
    with pytest.raises(bench.Refused):
        bench.bench_row(doc)


def test_the_published_entry_is_the_placeholder_or_a_recorded_row():
    """Before the first paid run: "not yet measured" and the command; after --record: a dated row, and never both."""
    text = (ROOT / "docs" / "BENCHMARKS.md").read_text(encoding="utf-8")
    table = text.split("<!-- eldane-bench:begin -->", 1)[1].split("<!-- eldane-bench:end -->", 1)[0]
    measured = re.search(r"^\| \d{4}-\d{2}-\d{2}T\d{2}:\d{2}Z \|", table, re.MULTILINE) is not None
    placeholder = "not yet measured" in table and "scripts/eldane_bench.py" in table
    assert measured != placeholder
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    block = readme.split("<!-- eldane-bench-readme:begin -->", 1)[1].split("<!--", 1)[0]
    assert ("not yet measured" in block) != measured


def test_record_refuses_a_linked_result_or_docs_that_are_links(bench, tmp_path, monkeypatch):
    root = tmp_path / "checkout"
    root.mkdir()
    _checkout(bench, root)
    monkeypatch.setattr(bench, "ROOT", root)
    result = tmp_path / "eldane-bench-2026-10-22T0930Z.json"
    result.write_text(json.dumps(_result(bench)), encoding="utf-8")
    link = tmp_path / "eldane-bench-2026-10-23T0930Z.json"
    link.symlink_to(result)
    with pytest.raises(bench.Refused, match="is a link"):
        bench.record(link)
    readme = root / "README.md"
    outside = tmp_path / "README-elsewhere.md"
    readme.rename(outside)
    readme.symlink_to(outside)
    with pytest.raises(bench.Refused, match="README.md is a link or not a file"):
        bench.record(result)


def test_a_file_outside_the_allowed_folders_is_refused(bench, tmp_path):
    inside = tmp_path / "a.md"
    inside.write_text("x", encoding="utf-8")
    with pytest.raises(bench.Refused, match="not a file inside"):
        bench._inside(inside, [tmp_path / "elsewhere"], "a.md")


def test_a_refusal_exits_2_with_its_reason(bench, tmp_path, capsys):
    bad = tmp_path / "not-a-result.json"
    assert bench.main(["--record", str(bad)]) == 2
    assert "REFUSED" in capsys.readouterr().err


@pytest.mark.parametrize("effort", ["high | x", "medium\n| injected |"])
def test_record_refuses_an_effort_that_is_not_a_known_level(bench, effort):
    doc = _result(bench, effort=effort)
    with pytest.raises(bench.Refused, match="effort"):
        bench.bench_row(doc)


def test_a_paid_run_saves_each_answer_as_it_is_paid_for_and_refuses_an_unwritable_out(
    bench, tmp_path
):
    kept: list[dict] = []
    bench.run(
        _prepared(bench, ["r1", "h1"]),
        StoredEldane(),
        PRICES,
        cap_usd=10.0,
        log=lambda _: None,
        keep=kept.append,
    )
    assert [r["id"].split("/")[0] for r in kept] == ["r1", "h1"]
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    a = SimpleNamespace(out=blocker / "out", cap_usd=5.0, model=MODEL)
    prepared = _prepared(bench, ["r1"])
    with pytest.raises(bench.Refused, match="cannot be written"):
        bench.paid(a, prepared, PRICES, {}, {})
