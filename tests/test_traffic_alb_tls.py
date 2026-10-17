"""The traffic Lambda's calls to the internal ALB trust the ALB's own certificate and nothing else (Sonar terraform:S5332,
2026-10-17: the ALB answers HTTPS only, with a self-signed certificate the stack makes - terraform/fullstack/ecs.tf).
The handshake itself is tested in tests/test_iac_leftovers_sonar.py; this runs in the apps lane, without cryptography."""

from __future__ import annotations

import importlib.util
import pathlib
import re
import ssl
import sys
import types

import botocore

ROOT = pathlib.Path(__file__).resolve().parents[1]
# One real certificate to stand for the ALB's: the first in botocore's bundle (any PEM certificate will do).
_BUNDLE = (pathlib.Path(botocore.__file__).parent / "cacert.pem").read_text(encoding="ascii")
ONE_CERT = re.search(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----\n", _BUNDLE, re.DOTALL).group(0)


def _traffic(monkeypatch):
    monkeypatch.setitem(sys.modules, "boto3", types.SimpleNamespace(client=lambda *a, **k: None))
    spec = importlib.util.spec_from_file_location(
        "fs_traffic_pin", ROOT / "scenarios" / "fullstack" / "lambdas" / "traffic" / "app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_an_alb_call_trusts_exactly_the_albs_certificate_and_checks_its_name(monkeypatch):
    app = _traffic(monkeypatch)
    monkeypatch.setenv("ALB_URL", "https://internal-alb.example")
    monkeypatch.setenv("ALB_CA_PEM", ONE_CERT)
    ctx = app._tls_for("https://internal-alb.example/orders")
    assert isinstance(ctx, ssl.SSLContext)
    assert len(ctx.get_ca_certs()) == 1  # that one certificate - not the system's trust store
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    assert app._tls_for("https://internal-alb.example/orders") is ctx  # built once per container


def test_any_other_call_keeps_the_systems_trust(monkeypatch):
    app = _traffic(monkeypatch)
    monkeypatch.setenv("ALB_URL", "https://internal-alb.example")
    monkeypatch.setenv("ALB_CA_PEM", ONE_CERT)
    # The API, and a host that only starts like the ALB's name, get the default context (None).
    for url in ("https://api.example/checkout", "https://internal-alb.example.evil/orders"):
        assert app._tls_for(url) is None, url
    # Without the certificate (the code deployed before the stack moved to HTTPS) nothing changes either.
    monkeypatch.delenv("ALB_CA_PEM")
    assert app._tls_for("https://internal-alb.example/orders") is None
