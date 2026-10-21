"""scripts/check_iam_actions.py, offline: AWS's action list is stubbed, so every outcome the check reports - an unknown
service, a wildcard that matches or matches nothing, a confirmed action, a known-unlisted one, a near miss - and its
exit code are pinned (characterisation before the cognitive-complexity split of main)."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("check_iam_actions", ROOT / "scripts" / "check_iam_actions.py")
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)

KNOWN = {"s3": {"GetObject", "PutObject", "ListBucket"}, "rds": {"DescribeDBClusters"},
         "budgets": {"ViewBudget", "ModifyBudget"}}


def _policy(tmp_path: pathlib.Path, name: str, statements: list[dict]) -> None:
    (tmp_path / name).write_text(json.dumps({"Statement": statements}), encoding="utf-8")


def _run(monkeypatch, tmp_path, fetch=lambda: KNOWN, glob="p*.json"):
    monkeypatch.setattr(mod, "ROOT", tmp_path)
    monkeypatch.setattr(mod, "fetch_actions", fetch)
    monkeypatch.setattr(sys, "argv", ["check_iam_actions.py", "--glob", glob])
    return mod.main()


def test_every_kind_of_finding_is_reported_in_order_and_the_run_fails(monkeypatch, tmp_path, capsys):
    _policy(tmp_path, "p1.json", [
        {"Sid": "Read", "Action": ["s3:GetObject", "s3:Get*", "s3:Zap*", "nosuch:Thing"]},
        {"Sid": "Budget", "Action": "budgets:DescribeBudget"},
    ])
    _policy(tmp_path, "p2.json", [{"NotAction": ["rds:EnableInternetAccessGateway", "s3:GetObject"]}])
    assert _run(monkeypatch, tmp_path) == 1
    assert capsys.readouterr().out == (
        "  rds:EnableInternetAccessGateway: not in AWS's list yet - known and proven (see KNOWN_UNLISTED)\n"
        "  wildcard s3:Get* matches 1 action(s)\n"
        "\n2 file(s), 6 distinct actions, 1 confirmed against AWS's list of 6\n"
        "\n3 to check by hand:\n"
        "  budgets:DescribeBudget: not in AWS's list. closest: nothing similar   [p1.json::Budget]\n"
        "  nosuch:Thing: unknown service prefix 'nosuch'   [p1.json::Read]\n"
        "  s3:Zap*: wildcard matches NOTHING   [p1.json::Read]\n"
        "\nThis list can lag the Service Authorization Reference, so a finding means 'verify', not "
        "'definitely wrong'. The IAM console's validator is the last word.\n")


def test_a_near_miss_names_the_closest_real_actions(monkeypatch, tmp_path, capsys):
    _policy(tmp_path, "p.json", [{"Sid": "S", "Action": "s3:PutObjects"}])
    assert _run(monkeypatch, tmp_path) == 1
    assert "  s3:PutObjects: not in AWS's list. closest: ['PutObject']   [p.json::S]\n" in capsys.readouterr().out


def test_only_real_actions_is_a_clean_run(monkeypatch, tmp_path, capsys):
    _policy(tmp_path, "p.json", [{"Action": ["s3:GetObject", "s3:ListBucket"]}])
    assert _run(monkeypatch, tmp_path) == 0
    assert capsys.readouterr().out == ("\n1 file(s), 2 distinct actions, 2 confirmed against AWS's list of 6\n"
                                       "no invalid actions found\n")


def test_no_policy_file_is_a_failure_not_a_pass(monkeypatch, tmp_path, capsys):
    assert _run(monkeypatch, tmp_path, glob="none*.json") == 1
    assert capsys.readouterr().out == "no policy files matched 'none*.json'\n"


def test_no_network_is_exit_2_not_a_policy_failure(monkeypatch, tmp_path, capsys):
    _policy(tmp_path, "p.json", [{"Action": "s3:GetObject"}])

    def offline():
        raise OSError("no route")

    assert _run(monkeypatch, tmp_path, fetch=offline) == 2
    assert capsys.readouterr().out == ("could not fetch AWS's action list (OSError: no route).\n"
                                       "This check needs network. The offline structural checks are in the test "
                                       "suite.\n")


def test_a_bare_service_wildcard_counts_every_action(monkeypatch, tmp_path, capsys):
    _policy(tmp_path, "p.json", [{"Action": "s3:*"}])
    assert _run(monkeypatch, tmp_path) == 0
    assert "  wildcard s3:* matches 3 action(s)\n" in capsys.readouterr().out
