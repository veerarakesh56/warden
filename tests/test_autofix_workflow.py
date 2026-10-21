"""CI · autofix (register B4, phase 4): the workflow that re-checks a code-fix pull request is read-only and takes the
event's values only through its environment."""

from __future__ import annotations

import pathlib

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_the_ci_job_is_read_only_and_takes_event_values_from_its_environment():
    flow = (ROOT / ".github" / "workflows" / "autofix-regression.yml").read_text(encoding="utf-8")
    doc = yaml.safe_load(flow)
    assert doc["permissions"] == {"contents": "read"}
    (job,) = doc["jobs"].values()
    assert list(doc["jobs"]) == ["autofix-regression"]
    runs = [s.get("run", "") for s in job["steps"]]
    assert not any("${{" in r for r in runs)  # template values only through env
    assert any("scripts/autofix_check.py" in r for r in runs)
    assert job["steps"][0]["with"]["persist-credentials"] is False



# The checks no workflow file in this repository makes: SonarCloud's app and CodeQL's default setup run on every
# pull request into main.
_APPS = {"SonarCloud Code Analysis", "Analyze (python)"}


def _runs_on_an_app_change(trigger: dict | None) -> bool:
    """A pull_request trigger that a change under scenarios/fullstack/app/ starts."""
    paths, ignored = (trigger or {}).get("paths"), (trigger or {}).get("paths-ignore") or []
    if any(p.startswith("scenarios/fullstack") for p in ignored):
        return False
    return paths is None or any(p.startswith("scenarios/fullstack") for p in paths)


def _check_names(doc: dict) -> set[str]:
    names = set()
    for job_id, job in doc["jobs"].items():
        caller = job.get("name", job_id)
        uses = str(job.get("uses", ""))
        if uses.startswith(("./.github/workflows/", "$/.github/workflows/")):  # a reusable workflow of this repo
            called = yaml.safe_load((ROOT / uses[2:]).read_text(encoding="utf-8"))
            names |= {f"{caller} / {j.get('name', jid)}" for jid, j in called["jobs"].items()}
        else:
            names.add(caller)
    return names


def test_every_required_check_runs_on_a_code_fix_pull_request():
    """A required check that a code fix's pull request (application files only) never starts would hold every merge
    for a day, then hand it to a person (CodeRabbit, PR 145: `check / validate` watches terraform only)."""
    from warden.code_fix import default_merge_checks

    made = set()
    for wf in (ROOT / ".github" / "workflows").glob("*.yml"):
        doc = yaml.safe_load(wf.read_text(encoding="utf-8"))
        triggers = doc.get(True) or {}
        if "pull_request" in triggers and _runs_on_an_app_change(triggers["pull_request"]):
            made |= _check_names(doc)
    assert set(default_merge_checks()) - _APPS <= made
