"""Requirement R16: the Bedrock provider (decision D12), proven against a stub of the Converse API. The live call is
W-B's: the Bedrock model access request, the quota, and qualification on the replay set (register M20)."""

from __future__ import annotations

import json

import pytest

from warden import providers
from warden.cli import DEMO_ALERTS
from warden.graph import Diagnosis, run
from warden.llm import LLMClient
from warden.models import Alert
from warden.providers import BedrockProvider, ProviderError, ProviderExhausted

PROFILE = "in.anthropic.claude-sonnet-5"


class _Converse:
    """Answers like Converse does when a tool is forced: one toolUse block holding the input."""

    def __init__(self, answer=None, error=None):
        self.requests, self.answer, self.error = [], answer, error

    def converse(self, **request):
        self.requests.append(request)
        if self.error:
            raise self.error
        return {"output": {"message": {"role": "assistant", "content": [
                    {"toolUse": {"toolUseId": "t-1", "name": request["toolConfig"]["toolChoice"]["tool"]["name"],
                                 "input": self.answer}}]}},
                "usage": {"inputTokens": 1234, "outputTokens": 56}, "stopReason": "tool_use"}


class _ClientError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code, "Message": "x"}}


ANSWER = {"root_cause": {"hypothesis": "bad deploy", "confidence": 0.8, "evidence": ["5xx"]},
          "proposal": {"action": "escalate_to_human", "target": "checkout", "reasoning": "unclear",
                       "expected_effect": "a person looks", "blast_radius": "single_service", "reversible": True}}


def test_the_answer_is_forced_through_one_tool_whose_schema_is_the_answer_schema():
    stub = _Converse(ANSWER)
    out = BedrockProvider(model=PROFILE, client=stub).complete(system="sys", user="evidence", schema=Diagnosis)
    req = stub.requests[0]
    assert req["modelId"] == PROFILE and req["system"] == [{"text": "sys"}]
    assert req["messages"] == [{"role": "user", "content": [{"text": "evidence"}]}]
    tool = req["toolConfig"]["tools"][0]["toolSpec"]
    assert req["toolConfig"]["toolChoice"] == {"tool": {"name": tool["name"]}}
    assert tool["inputSchema"]["json"] == Diagnosis.model_json_schema()
    assert json.loads(out.text) == ANSWER and (out.input_tokens, out.output_tokens) == (1234, 56)


def test_a_whole_incident_runs_through_bedrock_and_its_answer_is_typed():
    stub = _Converse(ANSWER)
    report = run(Alert(**DEMO_ALERTS["inc-001"]), llm=LLMClient(provider=BedrockProvider(model=PROFILE, client=stub),
                                                                  mock=False))
    assert len(stub.requests) == 1 and report.proposal.action.value == "escalate_to_human"


def test_throttling_waits_and_other_errors_are_failures():
    with pytest.raises(ProviderExhausted):
        BedrockProvider(model=PROFILE, client=_Converse(error=_ClientError("ThrottlingException"))).complete(
            system="s", user="u", schema=Diagnosis)
    with pytest.raises(ProviderError) as denied:
        BedrockProvider(model=PROFILE, client=_Converse(error=_ClientError("AccessDeniedException"))).complete(
            system="s", user="u", schema=Diagnosis)
    assert not isinstance(denied.value, ProviderExhausted) and "AccessDeniedException" in str(denied.value)


def test_a_model_must_be_named_exactly_and_pass_qualification(monkeypatch):
    monkeypatch.delenv("WARDEN_BEDROCK_MODEL", raising=False)
    with pytest.raises(ProviderError, match="WARDEN_BEDROCK_MODEL"):
        BedrockProvider(client=_Converse())
    with pytest.raises(ProviderError, match="alias"):
        BedrockProvider(model="sonnet", client=_Converse())
    monkeypatch.setenv("WARDEN_BEDROCK_MODEL", PROFILE)
    monkeypatch.setattr(providers, "BedrockProvider", lambda: BedrockProvider(client=_Converse()))
    monkeypatch.setitem(providers._REGISTRY, "bedrock", providers.BedrockProvider)
    monkeypatch.delenv("WARDEN_QUALIFYING", raising=False)
    with pytest.raises(ProviderError, match="(?i)qualif"):
        providers.resolve("bedrock")
