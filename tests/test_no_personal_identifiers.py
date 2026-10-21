"""The repository ships to other organisations, so no tracked file may name a person or a personal account, or point
at one person's resources: GitHub handles, personal e-mail addresses, a container registry under a literal account,
or local working-notes paths and files. Configuration names these per installation (environments.yaml placeholders,
WARDEN_GITHUB_* and WARDEN_CHANGE_REPO, `github.repository_owner` in workflows); a literal one in the tree is a leak.

The forbidden values are assembled from parts, so this file does not itself contain them."""

from __future__ import annotations

import pathlib
import re
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]

# A handle that once owned this repository. Parts only, never the whole literal.
_HANDLES = ("veera" + "rakesh" + "56",)
# Files allowed to name a handle until the repository changes hands, each with its reason.
_HANDLE_ALLOWED = {
    # GitHub resolves code owners only from real accounts or teams; a placeholder would leave the protected paths with
    # no required reviewer. Swapped for the receiving organisation's team at hand-over.
    ".github/CODEOWNERS",
}
_FORBIDDEN = [
    ("a local working-notes path", re.compile(re.escape("/tmp/" + "claude-"))),
    ("an internal notes file", re.compile(r"\b(?:" + "RULES" + r"|MERGE-" + "QUEUE" + r"|OWNER-[A-Z][A-Z-]*|" + "MEMORY"
                                          + r")\.md\b")),
    ("a registry path under a literal account",
     re.compile(r"ghcr\.io/(?!\$)[\w.-]+/warden-mirror\b")),
    ("a personal e-mail address", re.compile(
        r"(?i)\b[\w.%+-]{1,64}@(?:gmail|googlemail|outlook|hotmail|live|msn|yahoo|ymail|icloud|me|mac|aol|proton|"
        r"protonmail|pm|gmx|zoho|yandex|rediffmail|qq|163|126)\.(?:com|net|org|me|in|co\.uk|de|fr|ch)\b")),
]
# Files whose purpose is to show the shape of a value to fill in.
_EXAMPLE = re.compile(r"\.example$|\.example\.[a-z]+$")


def _tracked() -> list[str]:
    try:
        out = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"], cwd=ROOT,
                             capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    return [line for line in out.splitlines() if line and (ROOT / line).is_file()]


def _findings(paths: list[str], root: pathlib.Path = ROOT) -> list[str]:
    found = []
    handle = re.compile("|".join(map(re.escape, _HANDLES)), re.IGNORECASE)
    for rel in paths:
        text = (root / rel).read_bytes().decode("utf-8", "replace")
        if rel not in _HANDLE_ALLOWED and handle.search(text):
            found.append(f"{rel}: a personal GitHub handle")
        for what, rx in _FORBIDDEN:
            if what == "a personal e-mail address" and _EXAMPLE.search(rel):
                continue
            if rx.search(text):
                found.append(f"{rel}: {what}")
    return found


def test_no_tracked_file_names_a_person_or_a_personal_resource():
    assert _findings(_tracked()) == []


def test_the_handle_allowlist_is_still_needed():
    """An allowlisted file that no longer names a handle must leave the list, so the list cannot hide a new one."""
    handle = re.compile("|".join(map(re.escape, _HANDLES)), re.IGNORECASE)
    stale = [rel for rel in _HANDLE_ALLOWED
             if not (ROOT / rel).is_file() or not handle.search((ROOT / rel).read_text(encoding="utf-8"))]
    assert stale == []


@pytest.mark.parametrize("planted, what", [
    (_HANDLES[0].upper() + "/warden", "a personal GitHub handle"),
    ("see " + "/tmp/" + "claude-0" + "/notes", "a local working-notes path"),
    ("per " + "MERGE-" + "QUEUE" + ".md", "an internal notes file"),
    ("ghcr.io/" + "someone" + "/warden-mirror/python:3", "a registry path under a literal account"),
    ("mail " + "someone" + "@" + "gmail" + ".com", "a personal e-mail address"),
])
def test_each_kind_of_identifier_is_caught(tmp_path, planted, what):
    (tmp_path / "f.txt").write_text(f"x {planted} y\n", encoding="utf-8")
    assert _findings(["f.txt"], tmp_path) == [f"f.txt: {what}"]


def test_workflow_expressions_and_example_files_are_not_findings(tmp_path):
    (tmp_path / "ci.yml").write_text("image: ghcr.io/${{ github.repository_owner }}/warden-mirror/x:1\n", encoding="utf-8")
    (tmp_path / "terraform.tfvars.example").write_text('email = "' + "you" + "@" + "gmail" + '.com"\n', encoding="utf-8")
    assert _findings(["ci.yml", "terraform.tfvars.example"], tmp_path) == []
