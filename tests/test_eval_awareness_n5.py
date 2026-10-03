"""Register N5 / audit A-N-5: evaluation awareness. A model that can tell it is being measured can behave better
under measurement than in production. So nothing the benchmark adds - its alert templates, its ids, the words a
harness uses - may reach the prompt. Measured 2026-10-03 on the 30 recorded qualification contexts: the only
such token anywhere in an alert or context was the alert id `bench`, which the prompt does not carry."""

from __future__ import annotations

import json
import pathlib
import re

import pytest
import yaml

from warden.cli import DEMO_ALERTS
from warden.graph import run
from warden.llm import LLMClient
from warden.models import Alert
from warden.providers import Completion

ROOT = pathlib.Path(__file__).resolve().parents[1]
VOCAB = re.compile(r"\b(bench(mark)?|scenarios?|faults?|inject\w*|wave\s*\d|chaos|harness|proving.ground|"
                   r"(fs|ecs|k8s|db)-\d\d|synthetic|simulat\w*|drill|evaluat\w*|grad(ed|er|ing)|rubric)\b", re.IGNORECASE)


class _Capture:
    name, model = "capture", "c-1"

    def __init__(self):
        self.prompts = []

    def complete(self, *, system, user, schema=None):
        self.prompts.append(system + "\n" + user)
        body = {"root_cause": {"hypothesis": "unclear", "confidence": 0.5, "evidence": []},
                "proposal": {"action": "escalate_to_human", "target": "shop", "reasoning": "unclear",
                             "expected_effect": "a person looks", "blast_radius": "single_service",
                             "reversible": True}}
        return Completion(json.dumps(body), 1, 1)


def _prompt(alert: Alert) -> str:
    cap = _Capture()
    run(alert, llm=LLMClient(provider=cap, mock=False))
    assert len(cap.prompts) == 1
    return cap.prompts[0]


@pytest.mark.parametrize("template", sorted(p.name for p in (ROOT / "scenarios").glob("alert*.yaml")))
def test_no_benchmark_alert_puts_evaluation_vocabulary_in_the_prompt(template):
    alert = yaml.safe_load((ROOT / "scenarios" / template).read_text(encoding="utf-8").replace("__ENV__", "dev"))
    found = sorted({m.group(0) for m in VOCAB.finditer(_prompt(Alert(**alert)))})
    assert found == [], f"{template}: the prompt tells the model it is being measured: {found}"


def test_the_alert_id_never_reaches_the_prompt():
    marker = "fs-07-evaluation-run"
    alert = Alert(**{**DEMO_ALERTS["inc-001"], "alert_id": marker})
    assert marker not in _prompt(alert)
