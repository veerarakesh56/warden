"""scripts/observability_setup.py: from the owner's broader setup keys, WARDEN's narrow Datadog credentials made and
stored - again and again without a second of anything, and never printed. The runtime and the test stack's agent each
hold an API key of their own (secrets audit, 2026-10-16)."""

from __future__ import annotations

import importlib.util
import io
import itertools
import pathlib
import sys
import urllib.parse

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
API_KEY = "dd-api-" + "a" * 12
AGENT_KEY = "dd-agent-" + "e" * 12
ADMIN_APP = "dd-admin-" + "b" * 12
SITE = "ap1.datadoghq.com"
ids = itertools.count(1)


def _setup():
    spec = importlib.util.spec_from_file_location("observability_setup", ROOT / "scripts" / "observability_setup.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class AwsError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class Aws:
    """Secrets Manager and SSM as the script uses them, with AWS's refusals: no value into a missing secret, no second
    secret of a name, no tags with Overwrite, no overwrite without it."""

    def __init__(self):
        self.secrets = {f"warden/ops/{n}": "" for n in ("datadog-api-key", "datadog-app-key")}
        self.params, self.tags = {}, {}

    def __call__(self, service):
        return self

    def put_secret_value(self, SecretId, SecretString):
        if SecretId not in self.secrets:
            raise AwsError("ResourceNotFoundException")
        self.secrets[SecretId] = SecretString

    def create_secret(self, Name, SecretString, Tags):
        if Name in self.secrets:
            raise AwsError("ResourceExistsException")
        self.secrets[Name], self.tags[Name] = SecretString, Tags

    def put_parameter(self, Name, Value, Type, Overwrite=False, Tags=None):
        assert Type == "String"
        if Tags and Overwrite:
            raise AwsError("ValidationException")
        if Name in self.params and not Overwrite:
            raise AwsError("ParameterAlreadyExists")
        self.params[Name] = Value
        if Tags:
            self.tags[Name] = Tags


class DD:
    def __init__(self):
        self.keys = {}

    def __call__(self, method, url, body):
        assert url.startswith(f"https://api.{SITE}/api/v2/current_user/application_keys"), url
        path, _, query = url.partition("?")
        if method == "POST":
            kid = f"k{next(ids)}"
            value = "dd-made-" + kid + "-" + "d" * 12
            self.keys[kid] = {"name": body["data"]["attributes"]["name"],
                              "scopes": body["data"]["attributes"]["scopes"], "key": value}
            return {"data": {"id": kid, "attributes": {**self.keys[kid]}}}
        if method == "GET":
            want = urllib.parse.parse_qs(query)["filter"][0]
            return {"data": [{"id": k, "attributes": {"name": v["name"]}} for k, v in self.keys.items()
                             if want in v["name"]]}
        if method == "DELETE":
            del self.keys[path.rsplit("/", 1)[1]]
            return {}
        raise AssertionError(method)


ARGS = ["--env", "ops", "--stack", "dev", "--site", SITE]


def _piped(monkeypatch, *lines):
    monkeypatch.setattr(sys, "stdin", io.StringIO("".join(f"{v}\n" for v in lines)))


def _keys(monkeypatch):
    """The three keys, piped one per line from the secret store, as a run reads them."""
    _piped(monkeypatch, API_KEY, ADMIN_APP, AGENT_KEY)
    return list(ARGS)


def test_makes_and_stores_every_credential_once_and_prints_none(monkeypatch, capsys):
    mod, aws, dd = _setup(), Aws(), DD()
    secrets_seen = {API_KEY, ADMIN_APP, AGENT_KEY}
    for run in (1, 2):
        _piped(monkeypatch, API_KEY, ADMIN_APP, AGENT_KEY)
        assert mod.main(ARGS, aws=aws, dd_call=dd) == 0
        # One warden-read key, read scopes exactly, its value the one stored.
        [key] = dd.keys.values()
        assert key["name"] == "warden-read"
        assert key["scopes"] == ["logs_read_data", "logs_read_index_data", "apm_read", "timeseries_query", "events_read", "monitors_read"]
        assert aws.secrets["warden/ops/datadog-app-key"] == key["key"]
        # The runtime reads with its key; the agent sends with its own.
        assert aws.secrets["warden/ops/datadog-api-key"] == API_KEY
        assert aws.secrets["warden-dev-datadog-api-key"] == AGENT_KEY
        secrets_seen |= {key["key"]}
        out = capsys.readouterr().out
        assert not [s for s in secrets_seen if s in out]
        assert ("created" if run == 1 else "updated") in out
    # No Grafana anything (owner, 2026-10-16: Datadog only).
    assert not [n for n in [*aws.secrets, *aws.params] if "grafana" in n.lower()]
    assert aws.params == {
        "/warden/ops/env/WARDEN_DATADOG_SITE": SITE, "/warden/dev/tf/datadog_site": SITE,
        "/warden/ops/env/WARDEN_XRAY": "1", "/warden/ops/env/WARDEN_COMMITS": "1"}
    dev_tags = [{"Key": "Project", "Value": "warden"}, {"Key": "Environment", "Value": "dev"}]
    assert aws.tags["warden-dev-datadog-api-key"] == aws.tags["/warden/dev/tf/datadog_site"] == dev_tags


def test_one_api_key_for_both_is_refused_and_nothing_is_stored(monkeypatch):
    """Secrets audit, 2026-10-16: the same key went into the runtime's slot and the agent's; a key leaked from the test
    stack's cluster was the runtime's too."""
    mod, aws, dd = _setup(), Aws(), DD()
    _piped(monkeypatch, API_KEY, ADMIN_APP, API_KEY)
    with pytest.raises(SystemExit, match="is the runtime's"):
        mod.main(ARGS, aws=aws, dd_call=dd)
    assert aws.secrets == {"warden/ops/datadog-api-key": "", "warden/ops/datadog-app-key": ""} and not aws.params
    assert dd.keys == {}


def test_refuses_a_site_that_is_not_datadogs(monkeypatch):
    mod = _setup()
    args = _keys(monkeypatch)
    aws, dd, argv = Aws(), DD(), [*args[:4], "--site", "evil.example", *args[6:]]
    with pytest.raises(SystemExit):
        mod.main(argv, aws=aws, dd_call=dd)


def test_the_setup_keys_are_asked_for_never_read_from_disk(tmp_path, monkeypatch, capsys):
    """Naming audit item 24 (2026-10-16): the admin keys were plaintext files in ~/.warden, which outlived the
    "revoke after" step whenever it was forgotten. Nothing is read from disk: each key is typed at a prompt that does
    not echo it, or piped one per line on stdin from the secret store. The deprecated --keys-dir folder is gone (owner
    B28): naming it is a usage error, and no file in it is read."""
    mod = _setup()
    monkeypatch.setattr(pathlib.Path, "home", lambda: tmp_path / "home")  # a stray ~/.warden must not be read
    _piped(monkeypatch, API_KEY, ADMIN_APP, AGENT_KEY)
    aws = Aws()
    assert mod.main(ARGS, aws=aws, dd_call=DD()) == 0
    assert aws.secrets["warden/ops/datadog-api-key"] == API_KEY and "WARNING" not in capsys.readouterr().err

    class _Tty(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(sys, "stdin", _Tty())
    typed = iter([API_KEY, ADMIN_APP, AGENT_KEY])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(typed))
    assert mod.main(ARGS, aws=Aws(), dd_call=DD()) == 0
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "  ")
    aws, dd = Aws(), DD()
    with pytest.raises(SystemExit, match="the Datadog API key the runtime reads with was not given"):
        mod.main(ARGS, aws=aws, dd_call=dd)

    for name, value in (("datadog-api-key", API_KEY), ("datadog-app-key", ADMIN_APP)):
        (tmp_path / f"{name}.txt").write_text(value + "\n", encoding="utf-8")
    aws, dd, argv = Aws(), DD(), [*ARGS, "--keys-dir", str(tmp_path)]
    with pytest.raises(SystemExit) as stopped:
        mod.main(argv, aws=aws, dd_call=dd)
    assert stopped.value.code == 2
    assert "unrecognized arguments: --keys-dir" in capsys.readouterr().err
    assert aws.secrets == Aws().secrets  # nothing stored
    assert not aws.params
