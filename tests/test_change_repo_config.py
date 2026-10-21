"""Which repository WARDEN reads deploy commits and pull-request findings from is configuration: WARDEN_CHANGE_REPO,
else this repository's own name (WARDEN_GITHUB_REPOSITORY, else environments.yaml `github.repository`). The shipped
environments.yaml holds a placeholder, so an installation that turns the readers on without naming a repository must
hear about it: each incident's evidence carries a TOOL-PARTIAL line naming the setting, and the worker logs it -
never an empty read that looks like "no recent change"."""

from __future__ import annotations

import logging
import pathlib

import pytest

from warden import environments, tools
from warden.findings import FindingsReader
from warden.timeline import CommitReader

REPO = "example-org" + "/" + "shop"


class _Base:
    name = "aws"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for name in ("WARDEN_CHANGE_REPO", "WARDEN_GITHUB_REPOSITORY", "WARDEN_GITHUB_SUBJECT", "WARDEN_COMMITS",
                 "WARDEN_FINDINGS", "WARDEN_EVIDENCE_TOOLS", "WARDEN_XRAY", "WARDEN_QUOTAS", "WARDEN_ENV_POLICY_PATH"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(environments, "_DEFAULT", None)


def _github_readers(monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return [r for r in tools.evidence_tools(_Base()) if r.source in ("github", "findings")]


def test_the_shipped_configuration_names_no_repository():
    cfg = environments.EnvironmentPolicies.load()
    assert cfg.github["repository"] == environments.GITHUB_PLACEHOLDERS["repository"]
    assert environments.github_identity(cfg, "repository") == ""
    assert environments.github_identity(cfg, "subject") == ""
    assert tools._change_repo() == ""


@pytest.mark.parametrize("switch, source", [("WARDEN_COMMITS", "github"), ("WARDEN_FINDINGS", "findings")])
def test_a_reader_asked_for_without_a_repository_refuses_and_says_which_setting(monkeypatch, caplog, switch, source):
    with caplog.at_level(logging.WARNING, logger="warden.incident"):
        [reader] = _github_readers(monkeypatch, **{switch: "1"})
    assert isinstance(reader, tools.RepositoryNotConfigured)
    assert reader.source == source
    [line] = reader.logs(object())
    assert line.startswith(tools.PARTIAL_PREFIX + source + ": no repository configured")
    assert "WARDEN_CHANGE_REPO" in line and "WARDEN_GITHUB_REPOSITORY" in line
    assert reader.traces(object()) == [] and reader.metrics(object()) == {}
    assert any("WARDEN_CHANGE_REPO" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("setting", ["WARDEN_CHANGE_REPO", "WARDEN_GITHUB_REPOSITORY"])
def test_either_setting_names_the_repository_the_readers_use(monkeypatch, setting):
    commits, findings = _github_readers(monkeypatch, WARDEN_COMMITS="1", WARDEN_FINDINGS="1", **{setting: REPO})
    assert isinstance(commits, CommitReader) and commits.repo == REPO
    assert isinstance(findings, FindingsReader) and findings.repo == REPO


def test_warden_change_repo_wins_over_this_repositorys_own_name(monkeypatch):
    other = "example-org" + "/" + "warden"
    [commits] = _github_readers(monkeypatch, WARDEN_COMMITS="1", WARDEN_CHANGE_REPO=REPO, WARDEN_GITHUB_REPOSITORY=other)
    assert commits.repo == REPO


@pytest.mark.parametrize("setting", ["WARDEN_CHANGE_REPO", "WARDEN_GITHUB_REPOSITORY"])
def test_a_malformed_repository_is_refused_not_used(monkeypatch, caplog, setting):
    with caplog.at_level(logging.WARNING):
        [reader] = _github_readers(monkeypatch, WARDEN_COMMITS="1", **{setting: "not a repository"})
    assert isinstance(reader, tools.RepositoryNotConfigured)
    assert caplog.records


def test_readers_not_asked_for_are_not_added(monkeypatch):
    assert _github_readers(monkeypatch) == []


def test_an_installation_may_name_its_repository_in_environments_yaml(tmp_path):
    text = (pathlib.Path(__file__).resolve().parents[1] / "src" / "warden" / "data" / "environments.yaml").read_text(
        encoding="utf-8")
    doc = tmp_path / "environments.yaml"
    doc.write_text(text.replace("  repository: <GITHUB_REPOSITORY>", f"  repository: {REPO}")
                   .replace("  subject: <GITHUB_SUBJECT>", "  subject: example-org@" + "1" * 6 + "/shop@" + "2" * 6),
                   encoding="utf-8")
    cfg = environments.EnvironmentPolicies.load(doc)
    assert environments.github_identity(cfg, "repository") == REPO
