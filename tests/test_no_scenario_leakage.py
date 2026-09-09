"""The anti-cheating tripwire for the scenario benchmark.

The accusation this benchmark has to survive is: *"you wrote the bug and you wrote the expected
answer, so of course it passes."* The published answer to that is this file, and it has to be a
test rather than a paragraph, because a paragraph cannot fail CI.

What it enforces:

1. **No scenario knowledge inside the tool.** No scenario id and no fault-class name may appear
   anywhere under `src/warden/`. If a future change ever special-cases `ecs-03-oom-new-revision`,
   or branches on `fault_class == "image_pull_failure"`, this goes red.
2. **The tool cannot read the answers.** Nothing under `src/warden/` may reference `scenarios/`,
   the ground-truth directory, or the rubric.
3. **The catalog contains no expected answers.** A scenario entry may not carry a hypothesis, an
   expected action or an expected verdict — that would move the rubric into the fixture, where it
   could be tuned per scenario without anyone noticing.
4. **The rubric covers the catalog, and the prose matches the data.** Every fault class used by a
   scenario must be graded by `scoring.yaml`, and must also be documented in `SCORING.md`, so the
   human-readable rubric cannot quietly drift from the machine-readable one.

⚠ These are tripwires, not proofs. A determined author could still write a scenario that is
trivially easy. What defeats *that* is publishing every result including the failures, and the two
negative controls in Wave 1 (`healthy_control`, `log_group_deleted`). This file only guarantees that
the tool and the answer sheet stay separated.
"""

from __future__ import annotations

import pathlib
import re

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "warden"
SCENARIOS = ROOT / "scenarios"
CATALOG = SCENARIOS / "catalog"

pytestmark = pytest.mark.skipif(
    not CATALOG.exists(), reason="scenario catalog not present in this checkout"
)


def _catalog_files() -> list[pathlib.Path]:
    return sorted(CATALOG.glob("*.yaml"))


def _scenarios() -> list[dict]:
    out: list[dict] = []
    for path in _catalog_files():
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for scenario in doc.get("scenarios") or []:
            scenario["_file"] = path.name
            out.append(scenario)
    return out


def _src_files() -> list[pathlib.Path]:
    return [p for p in SRC.rglob("*.py") if "__pycache__" not in p.parts]


def _src_text() -> dict[pathlib.Path, str]:
    return {p: p.read_text(encoding="utf-8") for p in _src_files()}


# --------------------------------------------------------------------------- 1. no leakage in


def test_the_catalog_is_not_empty():
    """A vacuous pass is the easiest way for a tripwire to stop working."""
    scenarios = _scenarios()
    assert len(scenarios) >= 10, f"only {len(scenarios)} scenarios found - has the catalog moved?"


def test_no_scenario_id_appears_in_the_tool():
    ids = {s["id"] for s in _scenarios()}
    offenders: list[str] = []
    for path, text in _src_text().items():
        for scenario_id in ids:
            if scenario_id in text:
                offenders.append(f"{path.relative_to(ROOT)} mentions {scenario_id}")
    assert not offenders, (
        "WARDEN must know nothing about individual scenarios; found:\n  " + "\n  ".join(offenders)
    )


def test_no_fault_class_appears_in_the_tool():
    """The stricter half. An id is an obvious tell; a fault-class branch is the subtle one."""
    classes = {s["fault_class"] for s in _scenarios()}
    offenders: list[str] = []
    for path, text in _src_text().items():
        for fault_class in classes:
            # Word-boundary: `healthy_control` must not match, but a plain English sentence that
            # happens to contain the words should not be able to hide a branch either, so the
            # underscore form is what is searched for.
            if re.search(rf"\b{re.escape(fault_class)}\b", text):
                offenders.append(f"{path.relative_to(ROOT)} mentions {fault_class}")
    assert not offenders, (
        "WARDEN must not branch on fault classes; found:\n  " + "\n  ".join(offenders)
    )


# --------------------------------------------------------------------------- 2. no reading out


def test_the_tool_cannot_read_the_answer_sheet():
    forbidden = ("scenarios/", "scenarios\\", "ground-truth", "ground_truth", "scoring.yaml")
    offenders: list[str] = []
    for path, text in _src_text().items():
        for needle in forbidden:
            if needle in text:
                offenders.append(f"{path.relative_to(ROOT)} references {needle!r}")
    assert not offenders, (
        "the tool under test must not be able to reach the ground truth; found:\n  "
        + "\n  ".join(offenders)
    )


# --------------------------------------------------------------------------- 3. no answers in


def test_the_catalog_carries_no_expected_answers():
    """A scenario declares what to BREAK and what evidence must be READ. Never what to conclude.

    Grading lives in scoring.yaml, one entry per fault class, so it cannot be tuned per scenario.
    """
    banned = {
        "expected_action", "expected_verdict", "expected_hypothesis", "expect_action",
        "hypothesis", "root_cause", "answer", "correct_action", "verdict",
    }
    offenders: list[str] = []
    for scenario in _scenarios():
        for key in scenario:
            if key.lower() in banned:
                offenders.append(f"{scenario['id']} carries '{key}'")
    assert not offenders, "expected answers must not live in the catalog:\n  " + "\n  ".join(offenders)


def test_every_scenario_declares_its_fidelity():
    """`real` or `approximated`. An approximated scenario must say what the difference is, because
    describing a StopTask as a Spot interruption is a small lie, and small lies are the ones a
    hostile reader finds first."""
    problems: list[str] = []
    for scenario in _scenarios():
        fidelity = scenario.get("fidelity")
        if fidelity not in ("real", "approximated"):
            problems.append(f"{scenario['id']}: fidelity={fidelity!r}")
        elif fidelity == "approximated" and not str(scenario.get("fidelity_note", "")).strip():
            problems.append(f"{scenario['id']}: approximated with no fidelity_note")
    assert not problems, "\n  ".join(problems)


def test_every_scenario_asserts_some_evidence():
    """A scenario with no evidence assertion cannot distinguish 'the backend read the fault' from
    'the backend read nothing at all', and would let a broken backend score well."""
    thin = [s["id"] for s in _scenarios() if not (s.get("evidence_assertions") or [])]
    assert not thin, f"scenarios with no evidence assertions: {thin}"


def test_every_injected_scenario_declares_how_to_put_it_back():
    """Except the two that need no revert: the healthy control injects nothing, and a stopped task
    is replaced by ECS itself."""
    problems = [
        s["id"] for s in _scenarios()
        if (s.get("inject") or []) and not (s.get("revert") or [])
        and s["fault_class"] not in ("spot_interruption",)
    ]
    assert not problems, f"scenarios that break something with no way back: {problems}"


def test_scenario_ids_are_unique():
    ids = [s["id"] for s in _scenarios()]
    dupes = {i for i in ids if ids.count(i) > 1}
    assert not dupes, f"duplicate scenario ids: {sorted(dupes)}"


# --------------------------------------------------------------------------- 4. rubric coverage


def _rubric() -> dict:
    return yaml.safe_load((SCENARIOS / "scoring.yaml").read_text(encoding="utf-8"))


def test_every_fault_class_used_is_graded():
    rubric = _rubric()["fault_classes"]
    used = {s["fault_class"] for s in _scenarios()}
    missing = sorted(used - set(rubric))
    assert not missing, f"fault classes with no entry in scoring.yaml: {missing}"


def test_the_rubric_only_names_real_action_kinds():
    """A typo in the rubric would silently make an action ungradeable, and it would look like a
    model failure rather than a rubric bug."""
    from warden.models import ActionKind

    known = {a.value for a in ActionKind}
    rubric = _rubric()
    problems: list[str] = []
    for name, entry in rubric["fault_classes"].items():
        for field in ("correct", "harmful"):
            for action in entry.get(field) or []:
                if action not in known:
                    problems.append(f"{name}.{field}: {action!r} is not an ActionKind")
    for field, actions in rubric["action_kinds"].items():
        for action in actions:
            if action not in known:
                problems.append(f"action_kinds.{field}: {action!r} is not an ActionKind")
    assert not problems, "\n  ".join(problems)


def test_the_rubric_only_names_real_verdicts():
    from warden.models import VerdictStatus

    known = {v.value for v in VerdictStatus}
    gate = _rubric()["gate"]
    named = set(gate["allowed"]) | set(gate["refused"])
    assert named <= known, f"unknown verdicts in scoring.yaml: {sorted(named - known)}"
    assert named == known, (
        "every VerdictStatus must be classified as allowed or refused, or a real run will produce "
        f"an ungraded verdict: {sorted(known - named)}"
    )


def test_correct_and_harmful_never_overlap():
    problems = [
        f"{name}: {sorted(set(e.get('correct') or []) & set(e.get('harmful') or []))}"
        for name, e in _rubric()["fault_classes"].items()
        if set(e.get("correct") or []) & set(e.get("harmful") or [])
    ]
    assert not problems, "an action cannot be both the right answer and a harmful one:\n  " + "\n  ".join(problems)


def test_every_fault_class_has_at_least_one_correct_answer():
    """Including the classes no ActionKind can fix — for those the correct answer is
    escalate_to_human, which is what makes escalation gradeable rather than a free pass."""
    empty = [n for n, e in _rubric()["fault_classes"].items() if not (e.get("correct") or [])]
    assert not empty, f"fault classes with no achievable correct answer: {empty}"


def test_every_fault_class_explains_itself():
    thin = [
        n for n, e in _rubric()["fault_classes"].items()
        if len(str(e.get("why", "")).strip()) < 40
    ]
    assert not thin, f"fault classes with no real justification in scoring.yaml: {thin}"


def test_the_prose_rubric_documents_every_fault_class():
    """SCORING.md is what a reader actually reads. If it drifts from scoring.yaml, the published
    rubric stops describing the one that was used."""
    prose = (SCENARIOS / "SCORING.md").read_text(encoding="utf-8")
    missing = [n for n in _rubric()["fault_classes"] if n not in prose]
    assert not missing, f"fault classes graded but not documented in SCORING.md: {missing}"
