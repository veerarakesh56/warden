"""Audit, 2026-10-16 (proven with IAM's own policy simulator): two paths to full account admin.

1. The harness role (no permissions boundary) could write an inline policy on any `warden-<env>-*` role - itself
   included - so whoever held its session could make it an administrator. Its IAM writes now reach only the three roles
   the faults edit, and only while each carries the environment's boundary.
2. The deploy roles could rewrite or delete the roles that carry no boundary (actor, platform reader, harness; in the
   runtime, the operator). A separate guard policy on each deploy role denies that, and denies policies on any role that
   is not bounded - Terraform's own bounded roles stay editable."""

from __future__ import annotations

import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
IAM = ROOT / "infra" / "iam"
WRITES = {"iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:AttachRolePolicy", "iam:DetachRolePolicy"}
FAULT_ROLES = {"checkout", "ecs-exec", "orders-api-task"}


def _statements(path: pathlib.Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))["Statement"]


def _list(v) -> list:
    return v if isinstance(v, list) else [v]


def test_the_harness_writes_iam_only_on_the_bounded_fault_roles():
    for path in [p for p in IAM.glob("*/harness.json") if p.parent.name != "templates"]:
        env = path.parent.name
        for s in _statements(path):
            writes = WRITES & set(_list(s.get("Action", [])))
            if not writes or s["Effect"] != "Allow":
                continue
            assert sorted(_list(s["Resource"])) == sorted(f"arn:aws:iam::*:role/warden-{env}-{r}" for r in FAULT_ROLES), path
            assert s["Condition"] == {"ArnLike": {"iam:PermissionsBoundary": f"arn:aws:iam::*:policy/WardenEnvBoundary-{env}"}}
            assert not any("*" in r.rsplit("/", 1)[-1] for r in _list(s["Resource"]))


def test_every_deploy_role_has_a_guard_for_the_roles_without_a_boundary():
    for env_dir in [d for d in IAM.iterdir() if (d / "deploy.json").exists() and d.name != "templates"]:
        guard = env_dir / "deploy-guard.json"
        assert guard.exists(), env_dir.name
        stmts = _statements(guard)
        assert all(s["Effect"] == "Deny" for s in stmts)
        unbounded = next(s for s in stmts if s["Sid"] == "NeverTouchTheHandMadeRoles")
        assert {"iam:PutRolePolicy", "iam:DeleteRole", "iam:UpdateAssumeRolePolicy"} <= set(unbounded["Action"])
        bounded_only = next(s for s in stmts if s["Sid"] == "OnlyBoundedRolesGetPolicies")
        assert bounded_only["Condition"] == {"ArnNotLike": {"iam:PermissionsBoundary":
                                                           f"arn:aws:iam::*:policy/WardenEnvBoundary-{env_dir.name}"}}
        assert len(json.dumps(json.loads(guard.read_text(encoding="utf-8")), separators=(",", ":"))) <= 6144


def test_the_licence_notice_names_its_author_and_ships_with_the_package():
    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
    assert "Copyright 2026 Veera Rakesh Kethari" in notice
    assert "Copyright 2026 Veera Rakesh Kethari" in (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert 'license-files = ["LICENSE", "NOTICE"]' in (ROOT / "warden" / "pyproject.toml").read_text(encoding="utf-8")
