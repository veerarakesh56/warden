"""Audit A-I-13: the proving ground's public HTTP API takes a bearer token on POST /checkout. The token is made at
apply by an ephemeral random_password and written through Secrets Manager's write-only argument (in no plan and no
state); the checkout Lambda refuses a call without it, and the traffic Lambda - the only caller - sends it."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import types

ROOT = pathlib.Path(__file__).resolve().parents[1]
LAMBDAS = ROOT / "scenarios" / "fullstack" / "lambdas"
TOKEN = "t" * 48


class _Boto:
    def __init__(self):
        self.sent = []

    def client(self, name, **kw):
        outer = self

        class C:
            def get_secret_value(self, SecretId):
                assert SecretId == "arn:secret:api-token"
                return {"SecretString": TOKEN}

            def publish(self, **kw):
                outer.sent.append(kw)

            def send_message(self, **kw):
                outer.sent.append(kw)
        return C()

    def resource(self, name, **kw):
        outer = self
        return types.SimpleNamespace(Table=lambda n: types.SimpleNamespace(put_item=lambda **kw: outer.sent.append(kw)))


def _load(name, monkeypatch):
    boto = _Boto()
    monkeypatch.setitem(sys.modules, "boto3", boto)
    monkeypatch.setenv("API_TOKEN_SECRET", "arn:secret:api-token")
    monkeypatch.setenv("TOPIC_ARN", "arn:topic")
    spec = importlib.util.spec_from_file_location(f"fs_{name}", LAMBDAS / name / "app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod, boto


def _post(auth=None):
    headers = {"content-type": "application/json", **({"authorization": auth} if auth is not None else {})}
    return {"routeKey": "POST /checkout", "headers": headers,
            "body": json.dumps({"cart_id": "c1", "items": [{"sku": "sku-1", "qty": 1}]})}


def test_checkout_refuses_a_call_without_the_token_and_health_stays_open(monkeypatch):
    app, boto = _load("checkout", monkeypatch)
    assert app.handler({"routeKey": "GET /health"}, None)["statusCode"] == 200
    for auth in (None, "", "Bearer wrong", f"bearer {TOKEN}", TOKEN):
        assert app.handler(_post(auth), None)["statusCode"] == 401, auth
    assert boto.sent == []  # nothing written for a refused call
    assert app.handler(_post(f"Bearer {TOKEN}"), None)["statusCode"] == 201
    assert boto.sent


def test_the_traffic_lambda_sends_the_token(monkeypatch):
    app, _ = _load("traffic", monkeypatch)
    seen = []
    monkeypatch.setattr(app, "_call", lambda method, url, body=None, headers=None: seen.append((url, headers)) or 200)
    monkeypatch.setenv("API_URL", "https://api.example")
    monkeypatch.setenv("ALB_URL", "http://alb.example")
    monkeypatch.setenv("ORDERS_QUEUE_URL", "q")
    monkeypatch.setenv("CHECKOUTS_PER_MIN", "1")
    monkeypatch.setenv("ORDERS_PER_MIN", "0")
    app.handler({}, None)
    assert ("https://api.example/checkout", {"Authorization": f"Bearer {TOKEN}"}) in seen


def test_the_token_is_in_no_plan_or_state_and_only_its_two_lambdas_read_it():
    tf = (ROOT / "terraform" / "fullstack" / "api_auth.tf").read_text(encoding="utf-8")
    assert 'ephemeral "random_password" "api_token"' in tf
    assert "secret_string_wo         = ephemeral.random_password.api_token.result" in tf
    assert "secret_string =" not in tf and "secret_string=" not in tf
    lam = (ROOT / "terraform" / "fullstack" / "lambda.tf").read_text(encoding="utf-8")
    assert lam.count("aws_secretsmanager_secret.api_token.arn") == 4  # two env values, two grants
