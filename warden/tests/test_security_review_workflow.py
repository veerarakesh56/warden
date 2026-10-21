"""The optional Claude security review (owner, 2026-10-17; .github/workflows/security-review.yml): off unless the owner
turns it on, never on a fork's code with the key, least privilege, Anthropic's own action pinned by a full commit."""

from __future__ import annotations

import pathlib
import re

import yaml

FLOWS = pathlib.Path(__file__).resolve().parents[2] / ".github" / "workflows"
NAME = "security-review.yml"
ACTION = "anthropics/claude-code-security-review"


def _flow() -> tuple[str, dict]:
    text = (FLOWS / NAME).read_text(encoding="utf-8")
    return text, yaml.safe_load(text)


def test_it_runs_only_when_switched_on_and_only_on_this_repositorys_own_pull_requests():
    """It spends the owner's API key: off unless WARDEN_SECURITY_REVIEW is "on". The action is not hardened against
    prompt injection, so a fork's pull request - code nobody here wrote - never runs it with the key: the trigger is
    pull_request (a fork gets no secrets there), never pull_request_target, and the job also requires the head branch
    to be this repository's."""
    _, wf = _flow()
    assert set(wf[True]) == {"pull_request"}  # YAML 1.1 reads `on` as True
    assert wf[True]["pull_request"] == {"types": ["opened", "synchronize", "reopened", "ready_for_review"],
                                        "branches": ["main"]}
    (job,) = wf["jobs"].values()
    condition = " ".join(job["if"].split())
    assert "vars.WARDEN_SECURITY_REVIEW == 'on'" in condition
    assert "github.event.pull_request.head.repo.full_name == github.repository" in condition
    assert "github.event.pull_request.draft == false" in condition  # a draft runs no CI (owner, 2026-10-21)
    assert condition.count("&&") == 3  # every clause must hold; none is an alternative


def test_it_holds_only_what_it_needs():
    """No permission at the workflow level; the job reads the code and comments on the pull request. No cloud
    identity, no token left in the checkout, and the API key is its own secret, used by the action alone."""
    text, wf = _flow()
    assert wf["permissions"] == {}
    (job,) = wf["jobs"].values()
    assert job["permissions"] == {"contents": "read", "pull-requests": "write"}
    assert "id-token" not in text
    assert "aws-actions" not in text
    checkout = job["steps"][0]
    assert checkout["uses"].startswith("actions/checkout@")
    assert checkout["with"]["persist-credentials"] is False
    assert re.findall(r"secrets\.(\w+)", text) == ["SECURITY_REVIEW_ANTHROPIC_API_KEY"]
    assert job["timeout-minutes"] <= 30


def test_anthropics_action_is_pinned_by_a_full_commit_and_names_its_model():
    _, wf = _flow()
    (job,) = wf["jobs"].values()
    (review,) = [s for s in job["steps"] if str(s.get("uses", "")).startswith(ACTION + "@")]
    assert re.fullmatch(rf"{re.escape(ACTION)}@[0-9a-f]{{40}}", review["uses"])
    # The action's own default is an older model; the model is named, and the owner can change it with a variable.
    assert review["with"]["claude-model"] == "${{ vars.WARDEN_SECURITY_REVIEW_MODEL || 'claude-opus-5-5' }}"
    assert review["with"]["claude-api-key"] == "${{ secrets.SECURITY_REVIEW_ANTHROPIC_API_KEY }}"


def test_the_owner_has_the_steps_to_turn_it_on_and_its_cost():
    ops = (FLOWS.parents[1] / "warden" / "docs" / "OPERATIONS.md").read_text(encoding="utf-8")
    section = " ".join(ops[ops.index("## Optional: Claude's security review"):].split())  # line breaks are spaces
    for needed in ("WARDEN_SECURITY_REVIEW", "SECURITY_REVIEW_ANTHROPIC_API_KEY", "WARDEN_SECURITY_REVIEW_MODEL",
                   "Require approval for all external contributors", "per pull request"):
        assert needed in section, needed
