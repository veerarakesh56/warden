"""B11: a model that declines to answer (stop_reason "refusal") is treated like an answer cut off at the output cap.

The Messages API returns a refusal as an ordinary HTTP 200 whose stop_reason is "refusal" (platform.claude.com,
"Handling stop reasons", read 2026-10-17); `claude -p --output-format json` reports the same stop_reason on its result
object (Agent SDK docs, "Handle the result"). Before B11 both read as "invalid JSON": retried twice more - three
charged refusals - and then reported as a generic failure. Now: charged once, never asked again, and the incident is
escalated to a person on the evidence alone, saying why.
"""

from __future__ import annotations

import json
import subprocess
import types

import pytest

from warden import providers
from warden.graph import Diagnosis
from warden.llm import LLMClient, ModelDeclined, ModelRefused

# --------------------------------------------------------------------------- the SDK path


def _sdk(stop_reason, *, category=None, text='{"root_cause": {'):
    """An AnthropicProvider whose client answers once with `stop_reason`; the list records each request sent."""
    p = providers.AnthropicProvider.__new__(providers.AnthropicProvider)
    p.model, p.name, p.version, p.effort = "claude-sonnet-5-5", "anthropic", "test", ""
    details = types.SimpleNamespace(type="refusal", category=category, explanation="x") if category else None
    resp = types.SimpleNamespace(content=[types.SimpleNamespace(type="text", text=text)], stop_reason=stop_reason,
                                 stop_details=details,
                                 usage=types.SimpleNamespace(input_tokens=1000, output_tokens=20))
    sent: list[dict] = []
    p._client = types.SimpleNamespace(messages=types.SimpleNamespace(create=lambda **kw: sent.append(kw) or resp))
    return p, sent


def test_a_refusal_from_the_api_is_flagged_with_its_category():
    p, _ = _sdk("refusal", category="cyber")
    done = p.complete(system="s", user="u")
    assert done.refused is True
    assert done.refusal_category == "cyber"
    assert done.cut_off is False


def test_an_ordinary_answer_is_neither_refused_nor_cut_off():
    p, _ = _sdk("end_turn", text='{"a": 1}')
    done = p.complete(system="s", user="u")
    assert (done.refused, done.cut_off, done.refusal_category) == (False, False, "")


def test_a_refusal_is_asked_once_charged_and_escalated_not_retried():
    p, sent = _sdk("refusal", category="bio")
    client = LLMClient(provider=p, mock=False)
    with pytest.raises(ModelRefused, match=r"declined to answer \(refusal, category bio\)"):
        client.structured(system="s", user="u", schema=Diagnosis)
    assert len(sent) == 1  # never asked again: the same prompt would be declined again
    assert client.cost.usd > 0  # a refusal is billed like any answer, and counts against the incident's ceiling


def test_a_refusal_without_a_category_still_says_it_was_a_refusal():
    p, _ = _sdk("refusal")
    client = LLMClient(provider=p, mock=False)
    with pytest.raises(ModelRefused, match="category not named"):
        client.structured(system="s", user="u", schema=Diagnosis)


def test_the_context_window_stop_is_a_cut_off_too():
    """The docs: model_context_window_exceeded - "treat the response as truncated"."""
    p, sent = _sdk("model_context_window_exceeded")
    assert p.complete(system="s", user="u").cut_off is True
    sent.clear()
    client = LLMClient(provider=p, mock=False)
    with pytest.raises(ModelRefused, match="cut off"):
        client.structured(system="s", user="u", schema=Diagnosis)
    assert len(sent) == 1


def test_the_declined_error_is_a_cut_off_so_every_cut_off_path_handles_it():
    from warden.llm import ModelCutOff

    assert issubclass(ModelDeclined, ModelCutOff)


def test_a_refused_diagnosis_escalates_to_a_person_on_the_evidence_alone(tmp_path):
    """Through the incident activities: the rules-only diagnosis (register M19) - an escalation, never a guess - with
    the refusal named as the reason in the audit, and the gate never approves it."""
    from warden import audit
    from warden.activities import IncidentActivities
    from warden.cli import DEMO_ALERTS
    from warden.models import ActionKind, Alert

    p, sent = _sdk("refusal", category="cyber")
    log = audit.AuditLog(tmp_path / "a.db", key=None)
    acts = IncidentActivities(audit=log, llm_factory=lambda: LLMClient(provider=p, mock=False))
    pack = acts.prepare(Alert(**DEMO_ALERTS["inc-002"]))
    out = acts.diagnose(pack)
    assert len(sent) == 1
    assert out.proposal.action is ActionKind.escalate_to_human
    assert "declined to answer (refusal, category cyber)" in out.model_unavailable
    row = log.entries(pack.alert.alert_id, kinds=("incident.diagnose",))[-1]["body"]
    assert "refusal" in row["degraded"]
    assert acts.verify(pack, out).verdict.status.value != "approved_for_human"


# --------------------------------------------------------------------------- the claude CLI path


def _envelope(**over):
    """The `claude -p --output-format json` result object, shaped as CLI 2.1.302 printed it (2026-10-17)."""
    body = {"type": "result", "subtype": "success", "is_error": False, "stop_reason": "end_turn",
            "result": '{"answer": "yes"}', "usage": {"input_tokens": 10, "output_tokens": 5}, "num_turns": 1}
    body.update(over)
    body["result"] = body.pop("result")  # last, where the CLI prints it
    return json.dumps(body)


class _Run:
    def __init__(self, stdout, returncode=0, stderr=""):
        self.stdout, self.returncode, self.stderr, self.cmd = stdout, returncode, stderr, None

    def __call__(self, cmd, **_kw):
        self.cmd = cmd
        return subprocess.CompletedProcess(cmd, self.returncode, self.stdout, self.stderr)


@pytest.fixture
def cli(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/claude")
    monkeypatch.delenv("WARDEN_MODEL", raising=False)
    return providers.ClaudeCliProvider()


def _complete(cli, run, monkeypatch):
    monkeypatch.setattr(subprocess, "run", run)
    return cli.complete(system="sys", user="usr")


def test_the_cli_is_asked_for_its_result_as_json(cli, monkeypatch):
    run = _Run(_envelope())
    _complete(cli, run, monkeypatch)
    at = run.cmd.index("--output-format")
    assert run.cmd[at + 1] == "json"


def test_the_cli_answer_is_the_result_text_not_the_envelope(cli, monkeypatch):
    done = _complete(cli, _Run(_envelope()), monkeypatch)
    assert done.text == '{"answer": "yes"}'
    assert (done.refused, done.cut_off) == (False, False)


@pytest.mark.parametrize("code", [0, 1])
def test_a_cli_refusal_is_flagged_whatever_the_exit_code(cli, monkeypatch, code):
    out = _envelope(stop_reason="refusal", result="", stop_details={"type": "refusal", "category": "cyber"})
    done = _complete(cli, _Run(out, returncode=code), monkeypatch)
    assert done.refused is True
    assert done.refusal_category == "cyber"


def test_a_cli_refusal_is_asked_once_and_escalated(cli, monkeypatch):
    run = _Run(_envelope(stop_reason="refusal", result="I can't help with that."))
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: calls.append(cmd) or run(cmd, **kw))
    client = LLMClient(provider=cli, mock=False)
    with pytest.raises(ModelRefused, match="declined to answer"):
        client.structured(system="s", user="u", schema=Diagnosis)
    assert len(calls) == 1


def test_a_cli_answer_cut_off_at_the_cap_is_flagged(cli, monkeypatch):
    done = _complete(cli, _Run(_envelope(stop_reason="max_tokens", result='{"root_cause": {')), monkeypatch)
    assert done.cut_off is True


def test_a_cli_error_result_with_exit_zero_is_still_an_error(cli, monkeypatch):
    out = _envelope(is_error=True, stop_reason="stop_sequence", api_error_status=404,
                    result="There's an issue with the selected model (x). It may not exist.")
    run = _Run(out, returncode=0)
    with pytest.raises(providers.ProviderError, match="issue with the selected model") as caught:
        _complete(cli, run, monkeypatch)
    assert caught.value.status_code == 404


def test_a_usage_limit_in_the_json_result_is_still_exhaustion(cli, monkeypatch):
    """The reason is the result text, which the CLI prints LAST in the object: reading the first 400 characters of
    the JSON would have lost it."""
    pad = {f"k{i}": "x" * 40 for i in range(20)}
    out = _envelope(is_error=True, result="You've hit your session limit · resets 7:40pm", **pad)
    run = _Run(out, returncode=1)
    with pytest.raises(providers.ProviderExhausted):
        _complete(cli, run, monkeypatch)


def test_the_models_own_json_is_never_mistaken_for_the_cli_envelope(cli, monkeypatch):
    """An older CLI (or plain text output) prints the answer itself: an object without type "result" is the answer."""
    done = _complete(cli, _Run('{"type": "answer", "stop_reason": "refusal"}'), monkeypatch)
    assert done.refused is False
    assert done.text == '{"type": "answer", "stop_reason": "refusal"}'


def test_a_reason_past_the_first_400_characters_is_still_recognised(cli, monkeypatch):
    """PR 65 review: the checks read the cut message, so a usage limit after a long stderr was a plain error."""
    run = _Run("x" * 500, returncode=1, stderr="Claude AI usage limit reached")
    with pytest.raises(providers.ProviderExhausted):
        _complete(cli, run, monkeypatch)
    run = _Run("y" * 500, returncode=1, stderr="API Error: 529 Overloaded | ECONNREFUSED")
    with pytest.raises(providers.ProviderError) as caught:
        _complete(cli, run, monkeypatch)
    assert caught.value.status_code == 529
    assert caught.value.sent is False
