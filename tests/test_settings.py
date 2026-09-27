"""v2 Phase 1.5: per-environment names and the SSM loader (settings.py)."""

from __future__ import annotations

import pytest

from warden import settings
from warden.environments import EnvironmentPolicyError, names
from warden.settings import LOADABLE, load_from_ssm


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
        "/warden/staging/env/WARDEN_SLACK_WEBHOOK": "https://hooks.example/one",
        "/warden/staging/env/WARDEN_DB_DSN": "postgresql://x",
        "/warden/staging/env/WARDEN_REMEDIATION": "live",       # arming: never from a store
        "/warden/staging/env/WARDEN_CHATOPS_LIVE": "1",
        "/warden/staging/env/WARDEN_BASE_URL": "https://evil.example",
        "/warden/staging/env/AWS_PROFILE": "admin",
        "/warden/prod/env/WARDEN_SLACK_WEBHOOK": "https://hooks.example/prod",
    })
    assert load_from_ssm("staging", client=fake) == ["WARDEN_DB_DSN", "WARDEN_SLACK_WEBHOOK"]
    assert fake.paths == ["/warden/staging/env/"]
    assert os.environ["WARDEN_SLACK_WEBHOOK"] == "https://hooks.example/one"
    for never in ("WARDEN_REMEDIATION", "WARDEN_CHATOPS_LIVE", "WARDEN_BASE_URL", "AWS_PROFILE"):
        assert never not in os.environ


def test_a_real_environment_variable_wins_over_the_store(monkeypatch):
    import os

    monkeypatch.setenv("WARDEN_SLACK_WEBHOOK", "https://hooks.example/explicit")
    fake = _FakeSSM({"/warden/dev/env/WARDEN_SLACK_WEBHOOK": "https://hooks.example/store"})
    assert load_from_ssm("dev", client=fake) == []
    assert os.environ["WARDEN_SLACK_WEBHOOK"] == "https://hooks.example/explicit"


def test_without_warden_env_nothing_happens_and_no_client_is_built(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("an AWS client was built with no WARDEN_ENV")

    monkeypatch.setattr("boto3.client", boom)
    assert load_from_ssm() == []


def test_nothing_that_arms_or_redirects_is_loadable():
    assert not LOADABLE & {"WARDEN_REMEDIATION", "WARDEN_CHATOPS_LIVE", "WARDEN_MOCK", "WARDEN_DB_DRY_RUN",
                           "WARDEN_BASE_URL", "WARDEN_PROVIDER", "WARDEN_ENV_POLICY_PATH"}
    assert not any(n.endswith("_PATH") or n.startswith("AWS_") for n in LOADABLE)


def test_the_cli_stops_on_an_unknown_environment(monkeypatch):
    from warden.cli import main

    monkeypatch.setenv("WARDEN_ENV", "prd")
    with pytest.raises(SystemExit, match="unknown environment"):
        main(["run", "--incident", "inc-001"])


def test_the_cli_loads_the_environment_before_running(monkeypatch, capsys):
    from warden.cli import main

    fake = _FakeSSM({"/warden/dev/env/WARDEN_MODEL": "m-1"})
    monkeypatch.setattr(settings, "load_from_ssm", lambda: load_from_ssm("dev", client=fake))
    monkeypatch.setenv("WARDEN_ENV", "dev")
    assert main(["run", "--incident", "inc-001"]) == 0
    assert "loaded WARDEN_MODEL from SSM" in capsys.readouterr().err


def test_any_environments_prefix_is_stripped_longest_first():
    from warden.environments import strip_prefix

    assert strip_prefix("warden-dev-checkout") == "checkout"
    assert strip_prefix("warden-qa-staging-order-processor") == "order-processor"
    assert strip_prefix("warden-prod-orders") == "orders"
    assert strip_prefix("some-other-fn") == "some-other-fn"
