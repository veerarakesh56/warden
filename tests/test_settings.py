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
        assert WithDecryption is True
        assert Recursive is False
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
    n = names("prod")
    assert (n.prefix, n.ssm, n.role, n.boundary) == (
        "warden-prod", "/warden/prod/", "warden-prod-deploy", "WardenEnvBoundary-prod")
    assert n.tags == {"Project": "warden", "Environment": "prod"}


def test_an_unknown_environment_raises_rather_than_becoming_an_aws_name():
    with pytest.raises(EnvironmentPolicyError, match="unknown environment 'prd'"):
        names("prd")


def test_loads_only_allowlisted_names_of_this_environment():
    import os

    fake = _FakeSSM({
        "/warden/dev/env/WARDEN_MODEL": "claude-sonnet-5",
        "/warden/dev/env/WARDEN_AWS_CLUSTER": "c1",
        "/warden/dev/env/WARDEN_REMEDIATION": "live",       # arming: never from a store
        "/warden/dev/env/WARDEN_CHATOPS_LIVE": "1",
        "/warden/dev/env/WARDEN_BASE_URL": "https://evil.example",
        "/warden/dev/env/AWS_PROFILE": "admin",
        "/warden/prod/env/WARDEN_MODEL": "other",
    })
    secrets = _FakeSecrets({"warden/dev/slack-webhook": "https://hooks.example/one",
                            "warden/prod/slack-webhook": "https://hooks.example/prod"})
    assert load("dev", ssm=fake, secrets=secrets) == ["WARDEN_AWS_CLUSTER", "WARDEN_MODEL", "WARDEN_SLACK_WEBHOOK"]
    assert fake.paths == ["/warden/dev/env/"]
    assert os.environ["WARDEN_SLACK_WEBHOOK"] == "https://hooks.example/one"
    assert all(a.startswith("warden/dev/") for a in secrets.asked)
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
    assert os.environ["WARDEN_MODEL"] == "explicit"
    assert "warden/dev/slack-webhook" not in secrets.asked


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


def test_any_environments_prefix_is_stripped_longest_first(tmp_path, monkeypatch):
    from warden import environments
    from warden.environments import strip_prefix

    assert strip_prefix("warden-dev-checkout") == "checkout"
    assert strip_prefix("warden-prod-orders") == "orders"
    assert strip_prefix("some-other-fn") == "some-other-fn"
    # Two names where one starts the other (the shipped dev and prod do not, since 2026-10-16): the longer wins.
    doc = tmp_path / "environments.yaml"
    doc.write_text("environments:\n  qa: {}\n  qa-staging: {}\n", encoding="utf-8")
    monkeypatch.setattr(environments, "_DEFAULT", environments.EnvironmentPolicies.load(doc))
    assert strip_prefix("warden-qa-staging-order-processor") == "order-processor"
    assert strip_prefix("warden-qa-order-processor") == "order-processor"
    assert environments.env_of_name("warden-qa-staging-x") == "qa-staging"


def test_a_command_loads_only_the_secrets_it_uses():
    """Audit A-B-L17: every process loaded every allowed secret - the MCP server and a diagnosis run held the
    terminate role's DSN and the audit key's passphrase they never use."""
    params = {secret_id("dev", n): "x" for n in ("WARDEN_DB_TERMINATE_DSN", "WARDEN_AUDIT_KEY_PASSPHRASE",
                                                 "WARDEN_TEMPORAL_KEY", "WARDEN_SLACK_WEBHOOK")}
    by_id = {secret_id("dev", n): n for n in SECRETS}
    for command, expected in (("run", ["WARDEN_SLACK_WEBHOOK"]),
                              ("mcp", ["WARDEN_SLACK_WEBHOOK", "WARDEN_TEMPORAL_KEY"]),
                              ("approve", ["WARDEN_AUDIT_KEY_PASSPHRASE", "WARDEN_SLACK_WEBHOOK", "WARDEN_TEMPORAL_KEY"]),
                              ("worker", sorted(by_id[i] for i in params))):
        for i in params:
            # Not monkeypatch.delenv: the previous command's load wrote these into os.environ, so monkeypatch would
            # put them back after _clean_env had restored the environment - a passphrase left for later tests.
            os.environ.pop(by_id[i], None)
        loaded = load("dev", ssm=_FakeSSM({}), secrets=_FakeSecrets(params), only=settings.loadable_for(command))
        assert loaded == expected, (command, loaded)


def test_a_diagnosis_run_never_loads_the_terminate_roles_dsn(monkeypatch):
    """Audit A-B-L17, wired: the CLI loads per command, after parsing it."""
    from warden.cli import main

    fake = _FakeSSM({"/warden/dev/env/WARDEN_MODEL": "m-1"})
    secrets = _FakeSecrets({"warden/dev/db-admin-dsn": "postgresql://terminator@db/x"})
    monkeypatch.setattr(settings, "load", lambda **kw: load("dev", ssm=fake, secrets=secrets, **kw))
    monkeypatch.setenv("WARDEN_ENV", "dev")
    monkeypatch.delenv("WARDEN_DB_TERMINATE_DSN", raising=False)
    monkeypatch.delenv("WARDEN_MODEL", raising=False)
    assert main(["run", "--incident", "inc-001"]) == 0
    assert os.environ.get("WARDEN_MODEL") == "m-1"
    assert "WARDEN_DB_TERMINATE_DSN" not in os.environ


def test_the_secrets_are_fetched_at_the_same_time_and_a_failure_of_any_still_raises():
    """Measured 2026-10-14: five secrets fetched one after another were 1.3 s of the approval page's cold start."""
    import os
    import threading
    import time

    from botocore.exceptions import ClientError

    from warden import settings

    class Slow(_FakeSecrets):
        def __init__(self, secrets, refuse=""):
            super().__init__(secrets)
            self.refuse, self.inside, self.most, self.lock = refuse, 0, 0, threading.Lock()

        def get_secret_value(self, *, SecretId):
            with self.lock:
                self.inside += 1
                self.most = max(self.most, self.inside)
            time.sleep(0.05)
            with self.lock:
                self.inside -= 1
            if SecretId == self.refuse:
                raise ClientError({"Error": {"Code": "AccessDeniedException"}}, "GetSecretValue")
            return super().get_secret_value(SecretId=SecretId)

    only = frozenset({"WARDEN_SLACK_WEBHOOK", "WARDEN_TEAMS_WEBHOOK", "WARDEN_AUDIT_DSN", "OPENAI_API_KEY"})
    held = {settings.secret_id("dev", "WARDEN_SLACK_WEBHOOK"): "hook", settings.secret_id("dev", "WARDEN_AUDIT_DSN"): "dsn"}
    slow = Slow(held)
    loaded = settings.load("dev", only=only, ssm=_FakeSSM({}), secrets=slow)
    assert loaded == ["WARDEN_AUDIT_DSN", "WARDEN_SLACK_WEBHOOK"]
    assert slow.most > 1  # together; the missing two skipped
    assert os.environ["WARDEN_SLACK_WEBHOOK"] == "hook"
    assert "OPENAI_API_KEY" not in os.environ
    assert sorted(slow.asked) == sorted(settings.secret_id("dev", n) for n in only)  # each asked once, its own call
    for name in only:
        os.environ.pop(name, None)
    ssm = _FakeSSM({})
    refusing = Slow(held, refuse=settings.secret_id("dev", "WARDEN_TEAMS_WEBHOOK"))
    with pytest.raises(ClientError):  # a refusal is not "not there": it raises, as before
        settings.load("dev", only=only, ssm=ssm, secrets=refusing)


def test_the_never_revert_list_reaches_the_cloud_runtime_from_parameter_store(monkeypatch):
    """Gap audit, 2026-10-14: WARDEN_NEVER_REVERT_PRINCIPALS was read by the revert check but not loadable, so the cloud
    runtime could never be told whose changes it must never undo. It is a plain setting, loaded from Parameter Store."""
    from warden.platforms import aws

    monkeypatch.delenv("WARDEN_NEVER_REVERT_PRINCIPALS", raising=False)
    fake = _FakeSSM({"/warden/ops/env/WARDEN_NEVER_REVERT_PRINCIPALS": "security-oncall, break-glass"})
    assert "WARDEN_NEVER_REVERT_PRINCIPALS" in load("ops", ssm=fake, secrets=_FakeSecrets({}))
    assert aws.never_revert() == frozenset({"security-oncall", "break-glass"})
    monkeypatch.delenv("WARDEN_NEVER_REVERT_PRINCIPALS", raising=False)
