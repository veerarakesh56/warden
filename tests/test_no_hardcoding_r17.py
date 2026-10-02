"""Owner requirements R17 and R32: the AWS region is configuration (environments.yaml `aws_region`), never a literal in
code - not in Python, not in Terraform, not in the IAM templates."""

from __future__ import annotations

import ast
import pathlib
import re

import pytest

from warden import environments

ROOT = pathlib.Path(__file__).resolve().parents[1]
REGION = re.compile(r"\b[a-z]{2}-(?:north|south|east|west|central|northeast|southeast|northwest|southwest)-\d\b")
# AWS serves its global services (IAM, CloudFront, region discovery) from us-east-1: AWS's fixed choice, named once as
# scripts/account_sweep.py AWS_GLOBAL_REGION - never where WARDEN or an application runs.
AWS_GLOBAL = "us-east-1"


def _docstrings(tree: ast.AST) -> set[int]:
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                ids.add(id(first.value))
    return ids


def _literals(path: pathlib.Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    skip = _docstrings(tree)
    return [n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in skip]


def test_no_python_string_in_the_tool_the_scripts_or_the_harness_names_a_region():
    offenders = [f"{p.relative_to(ROOT)}: {m}" for top in ("src/warden", "scripts", "scenarios")
                 for p in (ROOT / top).rglob("*.py") for text in _literals(p) for m in REGION.findall(text)
                 if not (m == AWS_GLOBAL and p.name == "account_sweep.py")]
    assert not offenders, offenders


def test_no_terraform_line_and_no_iam_template_names_a_region():
    offenders = []
    for p in (ROOT / "terraform").rglob("*.tf"):
        if ".terraform" in p.parts:
            continue
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            code = line.split("#", 1)[0]
            offenders += [f"{p.relative_to(ROOT)}:{i}" for _ in REGION.findall(code)]
    for p in (ROOT / "iam" / "templates").glob("*.json"):
        offenders += [str(p.relative_to(ROOT))] * len(REGION.findall(p.read_text(encoding="utf-8")))
    assert not offenders, offenders


def test_the_region_comes_from_the_config_and_aws_region_overrides_it(monkeypatch):
    monkeypatch.delenv("AWS_REGION", raising=False)
    configured = environments.default_environment_policies().aws_region
    assert configured and environments.region() == configured == environments.names("dev").region
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    assert environments.region() == "eu-west-1"
    monkeypatch.setenv("AWS_REGION", "not a region; rm -rf /")
    with pytest.raises(environments.EnvironmentPolicyError):
        environments.region()
