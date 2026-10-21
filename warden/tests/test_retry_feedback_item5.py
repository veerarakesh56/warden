"""Owner item 5 (2026-10-21): a retry after an answer that failed validation tells the model what failed, instead of
sending the same prompt again - within the same number of calls and the same budget, and never with a value from the
answer (it echoes redacted evidence; a validation error can quote it). Only field paths and error types go back."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator
from pydantic_core import PydanticCustomError

from warden import llm
from warden.cli import DEMO_ALERTS
from warden.graph import run
from warden.llm import RETRY_FEEDBACK, BudgetExceeded, LLMClient, ModelRefused, validation_feedback
from warden.models import Alert
from warden.providers import Completion

ROOT = pathlib.Path(__file__).resolve().parents[2]
# Values a wrong answer carries: none may reach the next prompt. Built from parts, so no file holds a value of the
# kind the answer would echo.
PLANTED = "evidence-" + "value-7741"
PLANTED_KEY = "made_up_" + "key_5512"
PLANTED_NUMBER = 98765
FEEDBACK_HEAD = RETRY_FEEDBACK.split("{errors}")[0]


class Inner(BaseModel):
    model_config = ConfigDict(extra="forbid")
    level: int
    counts: dict[str, int] = {}


class Answer(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cause: str
    inner: Inner

    @field_validator("cause")
    @classmethod
    def _plain(cls, v: str) -> str:
        if "-" in v:
            raise ValueError(f"cause {v!r} has a dash")  # a validator's own message quotes the value
        return v


GOOD = json.dumps({"cause": "a deploy", "inner": {"level": 1}})
# A made-up key is answer text too: in a dict field (inner.counts) and as an extra field.
BAD = json.dumps({"cause": PLANTED, "inner": {"level": PLANTED, "counts": {PLANTED_KEY: PLANTED}},
                  PLANTED_KEY: PLANTED_NUMBER})


class Scripted:
    """Answers from a script and keeps every prompt it was sent."""

    name, model = "scripted", "scripted-1"

    def __init__(self, *texts: str) -> None:
        self.texts, self.users = list(texts), []

    def complete(self, *, system, user, schema=None):
        self.users.append(user)
        return Completion(self.texts.pop(0), 10, 10)


def _ask(provider, **kw) -> Answer:
    client = LLMClient(provider=provider, mock=False, max_usd=1.0, max_calls=kw.pop("max_calls", 8))
    return client.structured(system="sys", user="the evidence", schema=Answer, **kw)


def test_a_retry_names_what_failed_and_the_first_attempt_does_not():
    p = Scripted(BAD, GOOD)
    assert _ask(p).cause == "a deploy"
    assert FEEDBACK_HEAD not in p.users[0]
    assert p.users[1].startswith(p.users[0])  # the same prompt, with the feedback after it
    fed = p.users[1][len(p.users[0]):]
    assert FEEDBACK_HEAD in fed
    for path in ("cause (value_error)", "inner.level (int_parsing)", "inner.counts.* (int_parsing)", "* (extra_forbidden)"):
        assert path in fed


def test_no_value_of_the_answer_is_fed_back():
    p = Scripted(BAD, BAD, GOOD)
    _ask(p)
    for retry in p.users[1:]:
        for value in (PLANTED, PLANTED_KEY, str(PLANTED_NUMBER), "dash"):
            assert value not in retry


def test_feedback_holds_only_paths_and_error_types():
    with pytest.raises(ValidationError) as caught:
        Answer.model_validate_json(BAD)
    assert PLANTED in str(caught.value)  # what pydantic's own text would have leaked
    fed = validation_feedback(caught.value, Answer)
    assert PLANTED not in fed
    assert PLANTED_KEY not in fed


def test_many_errors_are_counted_not_listed():
    class Wide(BaseModel):
        a: int
        b: int
        c: int
        d: int
        e: int
        f: int
        g: int
        h: int
        i: int
        j: int

    with pytest.raises(ValidationError) as caught:
        Wide.model_validate({})
    fed = validation_feedback(caught.value, Wide)
    assert "; and 2 more" in fed
    assert "i (missing)" not in fed


def test_text_with_no_json_object_is_named_without_quoting_it():
    p = Scripted(f"I think it is {PLANTED}", GOOD)
    _ask(p)
    assert "no JSON object was found in it" in p.users[1]
    assert PLANTED not in p.users[1]


def test_a_json_error_gives_only_the_parsers_fixed_words():
    try:
        json.loads('{"cause": ' + PLANTED)
    except json.JSONDecodeError as exc:
        fed = validation_feedback(exc, Answer)
    assert "not valid JSON (Expecting value, line 1 column 11)" in fed
    assert PLANTED not in fed


class Typed(BaseModel):
    cause: str

    @field_validator("cause")
    @classmethod
    def _named(cls, v: str) -> str:
        raise PydanticCustomError(v, "custom")  # a validator that names its error type after the value


@pytest.mark.parametrize("value", [PLANTED, "secretword"])  # a plain lowercase word too (review, PR 132)
def test_an_error_type_that_is_not_pydantics_own_is_not_echoed(value):
    with pytest.raises(ValidationError) as caught:
        Typed.model_validate({"cause": value})
    fed = validation_feedback(caught.value, Typed)
    assert "cause (invalid)" in fed
    assert value not in fed


def test_the_call_cap_is_kept():
    p = Scripted(BAD, BAD, BAD, BAD)
    with pytest.raises(ModelRefused, match="after 3 attempts"):
        _ask(p, retries=2)
    assert len(p.users) == 3  # retries + 1, never one more for the feedback


def test_the_call_ceiling_still_refuses_a_retry_with_feedback():
    p = Scripted(BAD, GOOD)
    with pytest.raises(BudgetExceeded):
        _ask(p, max_calls=1)
    assert len(p.users) == 1


def test_a_retry_is_priced_with_its_feedback(monkeypatch):
    seen: list[float] = []
    real = LLMClient._before_a_call

    def spy(self, est_usd):
        seen.append(est_usd)
        return real(self, est_usd)

    monkeypatch.setattr(LLMClient, "_before_a_call", spy)
    _ask(Scripted(BAD, GOOD))
    assert len(seen) == 2
    assert seen[1] > seen[0]


def test_feedback_that_would_pass_the_prompt_ceiling_is_left_out(monkeypatch):
    p = Scripted(BAD, GOOD)
    client = LLMClient(provider=p, mock=False, max_usd=1.0, max_calls=8)
    schema_text = json.dumps(Answer.model_json_schema())
    base = len("sys") + len("the evidence") + len(schema_text) + 60
    monkeypatch.setattr(llm, "MAX_PROMPT_TOKENS", base // 4 + 1)  # the prompt fits; the prompt with feedback does not
    client.structured(system="sys", user="the evidence", schema=Answer)
    assert p.users[1] == p.users[0]


def test_the_retry_text_is_part_of_the_qualified_prompt(monkeypatch):
    spec = importlib.util.spec_from_file_location("qualify_provider_item5", ROOT / "warden" / "scripts" / "qualify_provider.py")
    qualify = importlib.util.module_from_spec(spec)
    sys.modules["qualify_provider_item5"] = qualify
    spec.loader.exec_module(qualify)
    before = qualify.prompt_fingerprint()
    monkeypatch.setattr(llm, "RETRY_FEEDBACK", RETRY_FEEDBACK + " ")
    assert qualify.prompt_fingerprint() != before


# ------------------------------------------------------------------ ModelRefused's text (PR 132, coordinator 2026-10-21)
# graph.node_diagnose puts str(ModelRefused) (first 200 characters) into the diagnose audit row ("degraded"), the
# rules-only root cause the report and Slack show, and the workflow's ApplicationError. pydantic's own text quoted the
# answer's values there.


def test_a_refusal_names_paths_and_types_never_values():
    p = Scripted(BAD, BAD, BAD)
    with pytest.raises(ModelRefused) as caught:
        _ask(p)
    text = str(caught.value)
    assert "after 3 attempts: 4 validation errors for Answer: " in text
    assert "cause (value_error)" in text
    for value in (PLANTED, PLANTED_KEY, str(PLANTED_NUMBER), "input_value"):
        assert value not in text


def test_a_refusal_for_any_other_reason_keeps_its_words():
    assert llm.refusal_reason(RuntimeError("status 503"), Answer) == "status 503"


def test_an_answer_that_never_validates_leaves_no_value_in_the_audit_or_the_report():
    # One error only, so pydantic's text would quote the value well inside the 200 characters node_diagnose keeps.
    proposal = {"action": "escalate_to_human", "target": "checkout", "reasoning": "r", "expected_effect": "e",
                "blast_radius": "single_service", "reversible": True}
    bad = json.dumps({"root_cause": {"hypothesis": "h", "confidence": PLANTED}, "proposal": proposal})
    report = run(Alert(**DEMO_ALERTS["inc-001"]), llm=LLMClient(provider=Scripted(bad, bad, bad), mock=False))
    degraded = next(s["degraded"] for s in report.audit if s.get("node") == "diagnose")
    assert degraded.startswith("ModelRefused: Diagnosis not produced after 3 attempts")
    assert "input_value" not in degraded  # pydantic's text quoted the value here, cut at 200 characters
    assert PLANTED not in json.dumps(report.audit)
    assert PLANTED not in report.root_cause.hypothesis


def test_the_rendered_retry_is_part_of_the_qualified_prompt(monkeypatch):
    """Review, PR 132: the hash covers the retry as a model receives it - its paths and error types - not only the
    template."""
    spec = importlib.util.spec_from_file_location("qualify_provider_item5b", ROOT / "warden" / "scripts" / "qualify_provider.py")
    qualify = importlib.util.module_from_spec(spec)
    sys.modules["qualify_provider_item5b"] = qualify
    spec.loader.exec_module(qualify)
    before = qualify.prompt_fingerprint()
    monkeypatch.setattr(llm, "_error_type", lambda error: "changed")
    assert qualify.prompt_fingerprint() != before
