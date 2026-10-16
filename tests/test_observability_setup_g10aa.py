"""scripts/observability_setup.py: from the owner's broader setup keys, WARDEN's narrow Datadog and Grafana
credentials made and stored - again and again without a second of anything, and never printed."""

from __future__ import annotations

import importlib.util
import itertools
import pathlib
import urllib.parse
from datetime import UTC, datetime

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
API_KEY = "dd-api-" + "a" * 12
ADMIN_APP = "dd-admin-" + "b" * 12
ADMIN_GRAFANA = "glc_" + "c" * 16
SITE = "ap1.datadoghq.com"
WHEN = datetime(2026, 10, 14, 7, 0, tzinfo=UTC)
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
        self.secrets = {f"warden/ops/{n}": "" for n in ("datadog-api-key", "datadog-app-key", "grafana-read-token")}
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


STACK = {"id": 4321, "slug": "shop", "regionSlug": "prod-ap-south-1",
         "hmInstancePromUrl": "https://prometheus-prod-1-prod-ap-south-1.grafana.net", "hmInstancePromId": 111,
         "hlInstanceUrl": "https://logs-prod-1.grafana.net", "hlInstanceId": 222,
         "htInstanceUrl": "https://tempo-prod-1-prod-ap-south-1.grafana.net", "htInstanceId": 333}


class Grafana:
    def __init__(self, stacks=(STACK,)):
        self.stacks, self.policies, self.tokens = list(stacks), {}, {}

    def __call__(self, method, url, body):
        assert url.startswith("https://grafana.com/api/"), url
        path, _, query = url.removeprefix("https://grafana.com/api").partition("?")
        q = {k: v[0] for k, v in urllib.parse.parse_qs(query).items()}
        if path == "/instances":
            return {"items": self.stacks}
        if path.endswith("/connections"):
            return {"otlpHttpUrl": "https://otlp-gateway-prod-ap-south-1.grafana.net"}
        assert q["region"] == "prod-ap-south-1"
        if path == "/v1/accesspolicies" and method == "GET":
            return {"items": [p for p in self.policies.values() if p["name"] == q["name"]]}
        if path == "/v1/accesspolicies" and method == "POST":
            pid = f"p{next(ids)}"
            self.policies[pid] = {**body, "id": pid}
            return self.policies[pid]
        if path.startswith("/v1/accesspolicies/") and method == "POST":
            pid = path.rsplit("/", 1)[1]
            self.policies[pid] = {**self.policies[pid], **body}
            return self.policies[pid]
        if path == "/v1/tokens" and method == "POST":
            tid = f"t{next(ids)}"
            self.tokens[tid] = {**body, "id": tid, "token": "glc_made" + tid + "e" * 12}
            return self.tokens[tid]
        if path == "/v1/tokens" and method == "GET":
            return {"items": [t for t in self.tokens.values() if t["accessPolicyId"] == q["accessPolicyId"]]}
        if path.startswith("/v1/tokens/") and method == "DELETE":
            del self.tokens[path.rsplit("/", 1)[1]]
            return {}
        raise AssertionError((method, path))


def _keys(tmp_path):
    for name, value in (("datadog-api-key", API_KEY), ("datadog-app-key", ADMIN_APP),
                        ("grafana-admin-token", ADMIN_GRAFANA)):
        (tmp_path / f"{name}.txt").write_text(value + "\n", encoding="utf-8-sig")  # as Notepad saves it
    return ["--env", "ops", "--stack", "dev", "--site", SITE, "--keys-dir", str(tmp_path)]


def test_makes_and_stores_every_credential_once_and_prints_none(tmp_path, capsys):
    mod, aws, dd, gf = _setup(), Aws(), DD(), Grafana()
    args = _keys(tmp_path)
    secrets_seen = {API_KEY, ADMIN_APP, ADMIN_GRAFANA}
    for run in (1, 2):
        assert mod.main(args, aws=aws, dd_call=dd, grafana_call=gf, now=WHEN) == 0
        # Datadog: one warden-read key, read scopes exactly, its value the one stored.
        [key] = dd.keys.values()
        assert key["name"] == "warden-read"
        assert key["scopes"] == ["logs_read_data", "logs_read_index_data", "apm_read", "timeseries_query", "events_read", "monitors_read"]
        assert aws.secrets["warden/ops/datadog-app-key"] == key["key"]
        assert aws.secrets["warden/ops/datadog-api-key"] == aws.secrets["warden-dev-datadog-api-key"] == API_KEY
        # Grafana: two policies on the stack, one live token each, the read one stored, the write one for OTLP.
        assert sorted((p["name"], tuple(p["scopes"])) for p in gf.policies.values()) == [
            ("warden-read", ("metrics:read", "logs:read", "traces:read")),
            ("warden-write", ("metrics:write", "logs:write", "traces:write"))]
        assert all(p["realms"] == [{"type": "stack", "identifier": "4321", "labelPolicies": []}]
                   for p in gf.policies.values())
        by_policy = {gf.policies[t["accessPolicyId"]]["name"]: t for t in gf.tokens.values()}
        assert len(gf.tokens) == 2 and set(by_policy) == {"warden-read", "warden-write"}
        assert by_policy["warden-read"]["expiresAt"] == "2027-01-12T07:00:00Z"
        assert aws.secrets["warden/ops/grafana-read-token"] == by_policy["warden-read"]["token"]
        assert aws.secrets["warden-dev-grafana-otlp-auth"] == "4321:" + by_policy["warden-write"]["token"]
        secrets_seen |= {key["key"]} | {t["token"] for t in gf.tokens.values()}
        out = capsys.readouterr().out
        assert not [s for s in secrets_seen if s in out]
        assert ("created" if run == 1 else "updated") in out
    assert aws.params == {
        "/warden/ops/env/WARDEN_DATADOG_SITE": SITE, "/warden/dev/tf/datadog_site": SITE,
        "/warden/ops/env/WARDEN_GRAFANA_METRICS_URL": "https://prometheus-prod-1-prod-ap-south-1.grafana.net/api/prom",
        "/warden/ops/env/WARDEN_GRAFANA_METRICS_USER": "111",
        "/warden/ops/env/WARDEN_GRAFANA_LOGS_URL": "https://logs-prod-1.grafana.net",
        "/warden/ops/env/WARDEN_GRAFANA_LOGS_USER": "222",
        "/warden/ops/env/WARDEN_GRAFANA_TRACES_URL": "https://tempo-prod-1-prod-ap-south-1.grafana.net/tempo",
        "/warden/ops/env/WARDEN_GRAFANA_TRACES_USER": "333",
        "/warden/dev/tf/grafana_otlp_url": "https://otlp-gateway-prod-ap-south-1.grafana.net/otlp",
        "/warden/ops/env/WARDEN_XRAY": "1", "/warden/ops/env/WARDEN_COMMITS": "1"}
    dev_tags = [{"Key": "Project", "Value": "warden"}, {"Key": "Environment", "Value": "dev"}]
    assert aws.tags["warden-dev-datadog-api-key"] == aws.tags["warden-dev-grafana-otlp-auth"] == dev_tags
    assert aws.tags["/warden/dev/tf/datadog_site"] == dev_tags


def test_refuses_a_site_that_is_not_datadogs_and_an_org_without_one_stack(tmp_path):
    mod = _setup()
    args = _keys(tmp_path)
    with pytest.raises(SystemExit):
        mod.main([*args[:-4], "--site", "evil.example", *args[-2:]], aws=Aws(), dd_call=DD(), grafana_call=Grafana())
    aws = Aws()
    with pytest.raises(SystemExit):
        mod.main(args, aws=aws, dd_call=DD(), grafana_call=Grafana(stacks=(STACK, {**STACK, "id": 9})), now=WHEN)
    assert aws.secrets["warden/ops/grafana-read-token"] == ""  # nothing of Grafana's stored


def test_the_setup_keys_are_asked_for_not_read_from_disk_and_an_old_key_file_warns(tmp_path, monkeypatch, capsys):
    """Naming audit item 24 (2026-10-16): the admin keys were plaintext files in ~/.warden, which outlived the
    "revoke after" step whenever it was forgotten. Without --keys-dir nothing is read from disk: each key is typed at
    a prompt that does not echo it, or piped one per line on stdin; a named folder of the old files still reads, with
    a warning."""
    import io
    import sys

    mod = _setup()
    monkeypatch.setattr(pathlib.Path, "home", lambda: tmp_path / "home")  # a stray ~/.warden must not be read
    piped = io.StringIO(f"{API_KEY}\n{ADMIN_APP}\n{ADMIN_GRAFANA}\n")
    monkeypatch.setattr(sys, "stdin", piped)
    aws, dd, gf = Aws(), DD(), Grafana()
    assert mod.main(["--env", "ops", "--stack", "dev", "--site", SITE], aws=aws, dd_call=dd, grafana_call=gf,
                    now=WHEN) == 0
    assert aws.secrets["warden/ops/datadog-api-key"] == API_KEY and "WARNING" not in capsys.readouterr().err

    class _Tty(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(sys, "stdin", _Tty())
    typed = iter([API_KEY, ADMIN_APP, ADMIN_GRAFANA])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(typed))
    assert mod.main(["--env", "ops", "--stack", "dev", "--site", SITE], aws=Aws(), dd_call=DD(), grafana_call=Grafana(),
                    now=WHEN) == 0
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "  ")
    with pytest.raises(SystemExit, match="the Datadog API key was not given"):
        mod.main(["--env", "ops", "--stack", "dev", "--site", SITE], aws=Aws(), dd_call=DD(), grafana_call=Grafana())

    assert mod.main(_keys(tmp_path), aws=Aws(), dd_call=DD(), grafana_call=Grafana(), now=WHEN) == 0
    err = capsys.readouterr().err
    assert "is read from the plaintext file" in err and "grafana-admin-token.txt" in err
    assert ADMIN_APP not in err and ADMIN_GRAFANA not in err
