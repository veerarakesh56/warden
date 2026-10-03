"""Register M2: numbers, units and times misread. A percentage or a duration in the model's prose is checked against
the metrics WARDEN read after both are put in one unit; the evidence the model reads gives every time in UTC."""

from __future__ import annotations

import json
import re

from test_verifier import _alert, _ctx, _prop, _rc
from warden.cli import DEMO_ALERTS
from warden.graph import run
from warden.llm import LLMClient
from warden.models import Alert, RootCause
from warden.numbers import problems
from warden.providers import Completion
from warden.verifier import _enforce, verify

METRICS = {"error_rate": 0.042, "p99_latency_ms": 2140.0, "cpu_utilisation": 0.41, "requests_per_sec": 880.0}


def test_a_number_read_in_the_right_unit_passes():
    assert problems(["error rate is 4.2%, p99 is 2.1s and 2140 ms, cpu at 41 percent"], METRICS) == []


def test_a_misread_unit_or_scale_is_named():
    found = problems(["error rate 42%", "p99 21 s", "cpu 90 percent"], METRICS)
    assert len(found) == 3, found
    assert "'42%'" in found[0] and "error_rate" in found[0]
    assert "'21 s'" in found[1] and "p99_latency_ms" in found[1] and "cpu_utilisation" in found[2]


def test_on_the_published_runs_it_fires_on_none():
    """Measured 2026-10-03: compared with any metric of its kind it fired on 85 of 132 recorded answers; naming,
    readings and rounding brought that to none - while the three misreads above are still caught."""
    import pathlib

    from scenarios.score import score_run_dir

    from warden.models import ContextBundle, RemediationProposal

    fired = 0
    for b in sorted(pathlib.Path(__file__).resolve().parents[1].joinpath("docs", "bench").glob("wave*")):
        for row in score_run_dir(b, rubric_path=b / "grading" / "scoring.yaml")["rows"]:
            f = b / "reports" / f"{row['scenario_id']}.{row['index']}.json"
            d = json.loads(f.read_text(encoding="utf-8")) if f.exists() else {}
            if not d.get("proposal") or not d.get("root_cause"):
                continue
            rc = RootCause(**d["root_cause"])
            pr = RemediationProposal(**d["proposal"])
            fired += bool(problems([rc.hypothesis, *rc.evidence, pr.reasoning, pr.expected_effect],
                                   ContextBundle(**d["context"]).metrics))
    assert fired == 0


def test_numbers_without_a_unit_are_left_alone():
    assert problems(["restart count 6, version 1.2.3, 880 rps, over the last 15 minutes"], METRICS) == []


def test_a_misread_number_is_observed_and_never_obeyed():
    rc = RootCause(hypothesis="the error rate is 42% after the deploy", confidence=0.9, evidence=["5xx"],
                   citations=_rc().citations)
    args = (_alert(), _ctx(metrics=dict(METRICS)), rc, _prop())
    v = verify(*args)
    assert any(o.startswith("P27-NUMBER-NOT-IN-EVIDENCE: '42%'") for o in v.observed), v.observed
    assert v.model_copy(update={"observed": []}) == _enforce(*args)


def test_every_time_the_model_reads_is_in_utc():
    prompts = []

    class _Capture:
        name, model = "c", "c"

        def complete(self, *, system, user, schema=None):
            prompts.append(user)
            body = {"root_cause": {"hypothesis": "x", "confidence": 0.5, "evidence": []},
                    "proposal": {"action": "escalate_to_human", "target": "checkout", "reasoning": "x",
                                 "expected_effect": "x", "blast_radius": "single_service", "reversible": True}}
            return Completion(json.dumps(body), 1, 1)

    for incident in DEMO_ALERTS:
        run(Alert(**DEMO_ALERTS[incident]), llm=LLMClient(provider=_Capture(), mock=False))
    stamps = [t for p in prompts for t in re.findall(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?\S*", p)]
    assert stamps, "no timestamp reached the prompt to check"
    assert all(re.search(r"(Z|\+00:00)[,)\]]?$", t) for t in stamps), stamps
