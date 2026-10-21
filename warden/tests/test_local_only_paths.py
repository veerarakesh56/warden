"""Nothing that belongs on one machine is ever tracked: working notes, reports, assistant settings, handoffs,
secrets-shaped files, Terraform state and raw benchmark runs. The deny-list is held here, apart from .gitignore,
so deleting an ignore line, or a `git add -f`, still fails CI."""

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]

DENY = [re.compile(p) for p in (
    r"^research_notes/", r"^reports/", r"^\.claude/", r"^\.review/", r"^notes/", r"^scratch/",
    r"(^|/)NEXT-SESSION-PROMPT\.txt$", r"HANDOFF[^/]*\.md$", r"FIXLIST",
    r"(^|/)\.env(\.(?!example$)[^/]+)?$", r"\.(pem|key|p12|pfx)$", r"(^|/)id_rsa", r"\.local\.(json|ya?ml)$",
    r"\.tfstate(\.|$)", r"\.tfvars$", r"(^|/)tfplan", r"\.tfplan",
    r"(^|/)(\.venv|__pycache__|\.pytest_cache|\.ruff_cache|\.mypy_cache|\.hypothesis|\.terraform|\.vscode|\.idea)/",
    r"(^|/)(\.DS_Store|Thumbs\.db|desktop\.ini)$", r"(^|/)\.coverage(\.|$)",
    r"^fault-lab/docs/bench/.*/runs/", r"^fault-lab/docs/bench/.*runner[^/]*\.log$",
)]


def denied(path: str) -> bool:
    return any(p.search(path) for p in DENY)


def _tracked() -> list[str]:
    if not shutil.which("git") or not (ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    return [p for p in out.decode("utf-8").split("\0") if p]


def test_no_tracked_path_is_local_only():
    tracked = _tracked()
    assert len(tracked) > 500, len(tracked)
    assert [p for p in tracked if denied(p)] == []


def test_no_tracked_path_is_one_gitignore_excludes():
    _tracked()
    out = subprocess.run(["git", "ls-files", "-ci", "--exclude-standard"], cwd=ROOT, capture_output=True,
                         text=True, check=True).stdout
    assert out.split() == []


def test_gitignore_keeps_the_local_only_lines():
    lines = set((ROOT / ".gitignore").read_text(encoding="utf-8").splitlines())
    assert {"/research_notes/", "/reports/", "/.claude/", "*HANDOFF*.md", ".env.*", "*.pem", "*.key",
            "**/*.local.json", "*.tfstate", "*.tfvars"} <= lines


@pytest.mark.parametrize("path", [
    "research_notes/x/notes.md", "reports/a.md", ".claude/settings.local.json", "docs/SESSION-HANDOFF-2026-09-09.md",
    ".env", ".env.prod", "keys/deploy.pem", "a/b.key", "infra/iam/dev/trust.local.json", "terraform/x/terraform.tfstate",
    "terraform/x/terraform.tfvars", "terraform/x/tfplan", "src/__pycache__/a.pyc", ".vscode/settings.json",
    "fault-lab/docs/bench/heldout-g10-2026-10-10/runs/a.json", "fault-lab/docs/bench/w/runner-1.log", "NEXT-SESSION-PROMPT.txt",
])
def test_each_local_only_shape_is_denied(path):
    assert denied(path)


@pytest.mark.parametrize("path", [
    "README.md", "docs/SETUP.md", ".env.example", "terraform/x/terraform.tfvars.example", "warden/src/warden/keys.py",
    "fault-lab/docs/bench/heldout-g10-2026-10-10/incidents/a.json", "warden/tests/fixtures/bench/w/reports/a.json",
    "infra/iam/dev/trust.json", "warden/docs/governance/RACI.md",
])
def test_published_shapes_are_not_denied(path):
    assert not denied(path)
