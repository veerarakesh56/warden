"""Per-environment IAM (v2 Phase 1.5): one boundary, deploy policy and trust policy per environment,
rendered from iam/templates/ by scripts/render_env_iam.py and committed.

What must hold for every environment: the committed files are exactly the templates' render; each
fits IAM's limit; no file names another environment; parameters and buckets are only its own; the
deploy policy fits inside its boundary; new roles must carry its boundary; and only GitHub's
environment of the same name (or the operator) may assume the deploy role.
"""

from __future__ import annotations

import fnmatch
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import render_env_iam as r  # after the sys.path line above

ENVS = r.environments()
LIMIT = 6144


def _load(env, kind):
    return json.loads((ROOT / "iam" / env / f"{kind}.json").read_text(encoding="utf-8"))


def _list(x):
    return [x] if isinstance(x, str) else list(x or [])


def _allows(doc):
    return [a for st in doc["Statement"] if st["Effect"] == "Allow" for a in _list(st["Action"])]


def test_every_environment_has_its_files_and_nothing_else_exists():
    dirs = {p.name for p in (ROOT / "iam").iterdir() if p.is_dir()} - {"templates"}
    assert dirs == set(ENVS)
    assert len(ENVS) == 6


@pytest.mark.parametrize("env", ENVS)
def test_committed_files_are_exactly_the_render(env):
    for kind, text in r.render(env).items():
        committed = (ROOT / "iam" / env / f"{kind}.json").read_text(encoding="utf-8")
        assert committed == text, f"iam/{env}/{kind}.json drifted: run scripts/render_env_iam.py"


@pytest.mark.parametrize("env", ENVS)
def test_each_file_fits_iams_limit(env):
    for kind in r.KINDS:
        size = len("".join(json.dumps(_load(env, kind), separators=(",", ":")).split()))
        assert size <= LIMIT, f"{env}/{kind}: {size} > {LIMIT}"


@pytest.mark.parametrize("env", ENVS)
def test_no_file_names_another_environment(env):
    for kind in r.KINDS:
        text = json.dumps(_load(env, kind))
        for other in ENVS:
            if other != env:
                assert f"warden-{other}-" not in text and f"/warden/{other}/" not in text and \
                    f"WardenEnvBoundary-{other}\"" not in text, f"{env}/{kind} names {other}"


@pytest.mark.parametrize("env", ENVS)
def test_parameters_and_buckets_are_only_its_own(env):
    for kind in ("boundary", "deploy"):
        for st in _load(env, kind)["Statement"]:
            for res in _list(st.get("Resource")):
                if ":ssm:" in res:
                    assert f":parameter/warden/{env}/" in res, (kind, res)
                if res.startswith("arn:aws:s3:::"):
                    assert res.startswith(f"arn:aws:s3:::warden-{env}-"), (kind, res)
    ceiling = _load(env, "boundary")["Statement"][0]
    assert not any(a.startswith(("ssm:", "s3:", "secretsmanager:Get")) for a in _list(ceiling["Action"])), \
        "the region-wide ceiling must not grant parameters, buckets or secrets of every environment"


@pytest.mark.parametrize("env", ENVS)
def test_the_deploy_policy_fits_inside_its_boundary(env):
    boundary, deploy = _load(env, "boundary"), _load(env, "deploy")
    ceiling = _allows(boundary)
    flat_denies = [a for st in boundary["Statement"] if st["Effect"] == "Deny" and "Condition" not in st
                   and st.get("Resource") == "*" for a in _list(st["Action"])]
    for action in _allows(deploy):
        assert any(fnmatch.fnmatchcase(action.lower(), p.lower()) for p in ceiling), f"{env}: {action} outside the ceiling"
        assert not any(fnmatch.fnmatchcase(action.lower(), p.lower()) for p in flat_denies), \
            f"{env}: {action} granted but flatly denied"


@pytest.mark.parametrize("env", ENVS)
def test_the_boundary_holds_every_environment_to_itself(env):
    st = {s["Sid"]: s for s in _load(env, "boundary")["Statement"]}
    assert st["DenyRoleWithoutThisBoundary"]["Condition"]["ArnNotLike"]["iam:PermissionsBoundary"] == \
        f"arn:aws:iam::*:policy/WardenEnvBoundary-{env}"
    assert st["DenySelfEdit"]["Resource"] == f"arn:aws:iam::*:role/warden-{env}-deploy"
    # Data that is not this environment's is never destroyed, even untagged: rds:* is region-wide
    # in the ceiling (RDS is addressed by id), so this deny is what protects a foreign database.
    destroy = st["DenyDestroyingOthers"]
    assert {"rds:DeleteDBCluster", "dynamodb:DeleteTable", "secretsmanager:DeleteSecret"} <= set(destroy["Action"])
    assert all(f"warden-{env}-" in r for r in destroy["NotResource"])
    for sid, key in (("DenyOtherEnvResources", "aws:ResourceTag/Environment"),
                     ("DenyOtherEnvTags", "aws:RequestTag/Environment")):
        cond = st[sid]["Condition"]
        assert st[sid]["Effect"] == "Deny" and st[sid]["Action"] == "*"
        assert cond["StringNotEquals"] == {key: env}
        # Only when the tag EXISTS: an IfExists form would deny every untagged resource.
        assert cond["Null"] == {key: "false"} and "StringNotEqualsIfExists" not in cond


@pytest.mark.parametrize("env", ENVS)
def test_only_the_same_named_github_environment_may_assume(env):
    doc = _load(env, "trust")
    [gh] = doc["Statement"]  # deploys run only in GitHub Actions: nothing and nobody else is trusted
    cond = gh["Condition"]
    assert list(cond) == ["StringEquals"], "exact match only - no StringLike, no wildcards"
    assert cond["StringEquals"] == {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                                    "token.actions.githubusercontent.com:sub":
                                        f"repo:veerarakesh56/warden:environment:{env}"}
    assert gh["Principal"]["Federated"].endswith(":oidc-provider/token.actions.githubusercontent.com")
    assert "*" not in json.dumps(doc), "no wildcard anywhere in a trust policy"


def test_templates_use_only_the_two_placeholders():
    import re

    for kind in r.KINDS:
        text = (r.TEMPLATES / f"{kind}.json").read_text(encoding="utf-8")
        assert set(re.findall(r"\$\{(\w+)\}", text)) <= {"env", "account"}, kind
