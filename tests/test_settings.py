"""v2 Phase 1.5: per-environment names and the SSM loader (settings.py)."""

from __future__ import annotations

import os

import pytest

from warden import settings
from warden.environments import EnvironmentPolicyError, names
from warden.settings import LOADABLE, SECRETS, load, load_from_ssm, secret_id


class _FakeSSM:
    """get_parameters_by_path over a dict, paginated two per page like the real API can be."""

    def __init__(self, params: dict[str, str]):
        self.params = params
        self.paths: list[str] = []

    def get_paginator(self, op):
        assert op == "get_parameters_by_path"
        return self

    def paginate(self, *, Path, Recursive, WithDecryption):
        assert WithDecryption is True and Recursive is False
        self.paths.append(Path)
        items = [{"Name": k, "Value": v} for k, v in self.params.items() if k.startswith(Path)]
        for i in range(0, len(items), 2):
            yield {"Parameters": items[i:i + 2]}


class _FakeSecrets:
    """get_secret_value over a dict of secret ids; a missing one raises as the real API does."""

    def __init__(self, secrets: dict[str, str]):
        self.secrets, self.asked = secrets, []

    def get_secret_value(self, *, SecretId):
        from botocore.exceptions import ClientError

        self.asked.append(SecretId)
        if SecretId not in self.secrets:
            raise ClientError({"Error": {"Code": "ResourceNotFoundException"}}, "GetSecretValue")
        return {"SecretString": self.secrets[SecretId]}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """The loader writes os.environ directly, so the whole environment is restored afterwards."""
    import os

    saved = dict(os.environ)
    for name in (*LOADABLE, "WARDEN_REMEDIATION", "WARDEN_CHATOPS_LIVE", "WARDEN_ENV_POLICY_PATH",
                 "WARDEN_BASE_URL", "WARDEN_ENV", "AWS_PROFILE"):
        monkeypatch.delenv(name, raising=False)
    yield
    os.environ.clear()
    os.environ.update(saved)


def test_every_name_derives_from_the_environment():
    n = names("qa-staging")
    assert (n.prefix, n.ssm, n.role, n.boundary) == (
        "warden-qa-staging", "/warden/qa-staging/", "warden-qa-staging-deploy", "WardenEnvBoundary-qa-staging")
    assert n.tags == {"Project": "warden", "Environment": "qa-staging"}


def test_an_unknown_environment_raises_rather_than_becoming_an_aws_name():
    with pytest.raises(EnvironmentPolicyError, match="unknown environment 'prd'"):
        names("prd")


def test_loads_only_allowlisted_names_of_this_environment():
    import os

    fake = _FakeSSM({
        "/warden/staging/env/WARDEN_MODEL": "claude-sonnet-5",
        "/warden/staging/env/WARDEN_AWS_CLUSTER": "c1",
        "/warden/staging/env/WARDEN_REMEDIATION": "live",       # arming: never from a store
        "/warden/staging/env/WARDEN_CHATOPS_LIVE": "1",
        "/warden/staging/env/WARDEN_BASE_URL": "https://evil.example",
        "/warden/staging/env/AWS_PROFILE": "admin",
        "/warden/prod/env/WARDEN_MODEL": "other",
    })
    secrets = _FakeSecrets({"warden/staging/slack-webhook": "https://hooks.example/one",
                            "warden/prod/slack-webhook": "https://hooks.example/prod"})
    assert load("staging", ssm=fake, secrets=secrets) == ["WARDEN_AWS_CLUSTER", "WARDEN_MODEL", "WARDEN_SLACK_WEBHOOK"]
    assert fake.paths == ["/warden/staging/env/"]
    assert os.environ["WARDEN_SLACK_WEBHOOK"] == "https://hooks.example/one"
    assert all(a.startswith("warden/staging/") for a in secrets.asked)
    for never in ("WARDEN_REMEDIATION", "WARDEN_CHATOPS_LIVE", "WARDEN_BASE_URL", "AWS_PROFILE"):
        assert never not in os.environ


def test_a_secret_comes_only_from_secrets_manager_never_from_ssm():
    """Decision D5 / requirement R32: a secret parked in SSM is not loaded; each secret has its own id."""
    import os

    fake = _FakeSSM({f"/warden/dev/env/{n}": "from-ssm" for n in SECRETS})
    assert load("dev", ssm=fake, secrets=_FakeSecrets({})) == []
    assert not any(n in os.environ for n in SECRETS)
    assert secret_id("dev", "WARDEN_SLACK_WEBHOOK") == "warden/dev/slack-webhook"
    assert secret_id("ops", "GEMINI_API_KEY") == "warden/ops/gemini-api-key"
    assert len({secret_id("dev", n) for n in SECRETS}) == len(SECRETS)


def test_a_real_environment_variable_wins_over_the_store(monkeypatch):
    import os

    monkeypatch.setenv("WARDEN_SLACK_WEBHOOK", "https://hooks.example/explicit")
    monkeypatch.setenv("WARDEN_MODEL", "explicit")
    secrets = _FakeSecrets({"warden/dev/slack-webhook": "https://hooks.example/store"})
    assert load("dev", ssm=_FakeSSM({"/warden/dev/env/WARDEN_MODEL": "store"}), secrets=secrets) == []
    assert os.environ["WARDEN_SLACK_WEBHOOK"] == "https://hooks.example/explicit"
    assert os.environ["WARDEN_MODEL"] == "explicit" and "warden/dev/slack-webhook" not in secrets.asked


def test_without_warden_env_nothing_happens_and_no_client_is_built(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("an AWS client was built with no WARDEN_ENV")

    monkeypatch.setattr("boto3.client", boom)
    assert load_from_ssm() == []


def test_nothing_that_arms_or_redirects_is_loadable():
    assert not LOADABLE & {"WARDEN_REMEDIATION", "WARDEN_CHATOPS_LIVE", "WARDEN_MOCK", "WARDEN_DB_DRY_RUN",
                           "WARDEN_BASE_URL", "WARDEN_PROVIDER", "WARDEN_ENV_POLICY_PATH"}
    assert not any(n.endswith("_PATH") or n.startswith("AWS_") for n in LOADABLE)


def test_the_cli_stops_on_an_unknown_environment(monkeypatch, capsys):
    from warden.cli import main

    monkeypatch.setenv("WARDEN_ENV", "prd")
    assert main(["run", "--incident", "inc-001"]) == 2  # stopped, before anything ran
    assert "unknown environment" in capsys.readouterr().err


def test_the_cli_loads_the_environment_before_running(monkeypatch, capsys):
    from warden.cli import main

    fake = _FakeSSM({"/warden/dev/env/WARDEN_MODEL": "m-1"})
    monkeypatch.setattr(settings, "load", lambda **kw: load("dev", ssm=fake, secrets=_FakeSecrets({}), **kw))
    monkeypatch.setenv("WARDEN_ENV", "dev")
    assert main(["run", "--incident", "inc-001"]) == 0
    assert "loaded WARDEN_MODEL (SSM, Secrets Manager)" in capsys.readouterr().err


def test_any_environments_prefix_is_stripped_longest_first():
    from warden.environments import strip_prefix

    assert strip_prefix("warden-dev-checkout") == "checkout"
    assert strip_prefix("warden-qa-staging-order-processor") == "order-processor"
    assert strip_prefix("warden-prod-orders") == "orders"
    assert strip_prefix("some-other-fn") == "some-other-fn"


def test_a_command_loads_only_the_secrets_it_uses(monkeypatch):
    """Audit A-B-L17: every process loaded every allowed secret - the MCP server and a diagnosis run held the
    terminate role's DSN and the audit key's passphrase they never use."""
    params = {secret_id("dev", n): "x" for n in ("WARDEN_DB_ADMIN_DSN", "WARDEN_AUDIT_KEY_PASSPHRASE",
                                                 "WARDEN_TEMPORAL_KEY", "WARDEN_SLACK_WEBHOOK")}
    by_id = {secret_id("dev", n): n for n in SECRETS}
    for command, expected in (("run", ["WARDEN_SLACK_WEBHOOK"]),
                              ("mcp", ["WARDEN_SLACK_WEBHOOK", "WARDEN_TEMPORAL_KEY"]),
                              ("approve", ["WARDEN_AUDIT_KEY_PASSPHRASE", "WARDEN_SLACK_WEBHOOK", "WARDEN_TEMPORAL_KEY"]),
                              ("worker", sorted(by_id[i] for i in params))):
        for i in params:
            monkeypatch.delenv(by_id[i], raising=False)
        loaded = load("dev", ssm=_FakeSSM({}), secrets=_FakeSecrets(params), only=settings.loadable_for(command))
        assert loaded == expected, (command, loaded)


def test_a_diagnosis_run_never_loads_the_terminate_roles_dsn(monkeypatch):
    """Audit A-B-L17, wired: the CLI loads per command, after parsing it."""
    from warden.cli import main

    fake = _FakeSSM({"/warden/dev/env/WARDEN_MODEL": "m-1"})
    secrets = _FakeSecrets({"warden/dev/db-admin-dsn": "postgresql://terminator@db/x"})
    monkeypatch.setattr(settings, "load", lambda **kw: load("dev", ssm=fake, secrets=secrets, **kw))
    monkeypatch.setenv("WARDEN_ENV", "dev")
    monkeypatch.delenv("WARDEN_DB_ADMIN_DSN", raising=False)
    monkeypatch.delenv("WARDEN_MODEL", raising=False)
    assert main(["run", "--incident", "inc-001"]) == 0
    assert os.environ.get("WARDEN_MODEL") == "m-1" and "WARDEN_DB_ADMIN_DSN" not in os.environ
