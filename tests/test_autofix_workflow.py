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

