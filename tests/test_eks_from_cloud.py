"""The cloud runtime reads an EKS cluster in the incident's own reader role (2026-10-15: every pod, event and log read
there failed "credentials rejected or missing" - no kubeconfig and no in-cluster identity in a Fargate task)."""

from __future__ import annotations

import base64
import urllib.parse

import boto3
from botocore.credentials import Credentials

from warden import aws_stack, k8s_backend
from warden.models import Alert, Severity

CA = base64.b64encode(b"-----BEGIN CERTIFICATE-----\nnot-a-real-ca\n-----END CERTIFICATE-----\n").decode()


def _sts():
    s = boto3.Session(region_name="ap-south-2")
    sts = s.client("sts", region_name="ap-south-2")
    sts._request_signer._credentials = Credentials("AKIA" + "X" * 16, "s" * 40)
    return sts


def test_the_token_is_a_presigned_caller_identity_that_names_the_cluster():
    token = k8s_backend.eks_token(_sts(), "warden-dev-eks")
    assert token.startswith("k8s-aws-v1.")
    raw = token.removeprefix("k8s-aws-v1.")
    url = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode()
    q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert q["Action"] == ["GetCallerIdentity"]
    assert q["X-Amz-Expires"] == ["60"]
    assert "x-k8s-aws-id" in q["X-Amz-SignedHeaders"][0]


class _Eks:
    def describe_cluster(self, name):
        return {"cluster": {"endpoint": f"https://{name}.example.test", "certificateAuthority": {"data": CA}}}


def test_the_backend_talks_to_the_clusters_own_endpoint_and_verifies_its_ca():
    b = k8s_backend.eks_backend(_Eks(), _sts(), "warden-dev-eks")
    cfg = b._core.api_client.configuration
    assert cfg.host == "https://warden-dev-eks.example.test"
    assert cfg.verify_ssl
    import pathlib

    assert pathlib.Path(cfg.ssl_ca_cert).read_bytes().startswith(b"-----BEGIN CERTIFICATE-----")
    assert cfg.api_key["authorization"].startswith("Bearer k8s-aws-v1.")


def test_an_alert_that_names_no_cluster_is_read_in_its_environments(monkeypatch):
    monkeypatch.setenv("WARDEN_EKS_CLUSTERS", "staging=warden-staging-eks, dev=warden-dev-eks,qa=bad;name")
    assert aws_stack.eks_cluster_of("dev") == "warden-dev-eks"
    assert aws_stack.eks_cluster_of("qa") == ""
    assert aws_stack.eks_cluster_of("prod") == ""
    monkeypatch.delenv("WARDEN_EKS_CLUSTERS")
    assert aws_stack.eks_cluster_of("dev") == ""


def test_the_stack_reader_uses_it_only_when_the_alert_names_a_cluster(monkeypatch):
    made = []

    class _Fake:
        def logs(self, a):
            return []

        def metrics(self, a):
            return {}

        def deploys(self, a):
            return []

    monkeypatch.setattr(k8s_backend, "eks_backend", lambda eks, sts, c: made.append(c) or _Fake())
    b = aws_stack.StackBackend.__new__(aws_stack.StackBackend)
    b._clients, b._k8s_factory = {"eks": object(), "sts": object()}, aws_stack._default_k8s
    alert = Alert(alert_id="a", name="n", service="catalog-api", environment="dev", severity=Severity.high, summary="",
                  started_at="2026-10-15T00:00:00+00:00", labels={"eks_cluster": "warden-dev-eks"})
    b._read_k8s(aws_stack._Out(), alert, "shop", "catalog-api", "")
    assert made == ["warden-dev-eks"]
    b._k8s_factory = lambda: _Fake()  # the harness's own factory is always kept
    b._read_k8s(aws_stack._Out(), alert, "shop", "catalog-api", "")
    assert made == ["warden-dev-eks"]

