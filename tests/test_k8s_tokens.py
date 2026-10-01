"""No service-account token is mounted where nothing calls the API (audit A-I-26): a token in a pod is a
credential any process there - or anyone who gets in - can use against the cluster."""
from __future__ import annotations

import pathlib

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
# The one pod that reads the cluster: WARDEN's own Job, bound to its read-only role.
NEEDS_A_TOKEN = {("job.yaml", "Job")}


def _docs():
    for path in sorted((ROOT / "k8s").rglob("*.yaml")):
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if doc:
                yield path, doc


def test_no_service_account_mounts_its_token_by_default():
    accounts = [(p.name, d) for p, d in _docs() if d["kind"] == "ServiceAccount"]
    assert len(accounts) >= 4, accounts
    loose = [(name, d["metadata"]["name"]) for name, d in accounts if d.get("automountServiceAccountToken") is not False]
    assert not loose, loose


def test_every_pod_says_whether_it_gets_a_token_and_only_the_job_does():
    pods = []
    for path, doc in _docs():
        kind = doc["kind"]
        spec = doc["spec"]["template"]["spec"] if kind in ("Deployment", "StatefulSet", "DaemonSet", "Job") else \
            doc["spec"] if kind == "Pod" else None
        if spec is not None:
            pods.append(((path.name, kind), spec.get("automountServiceAccountToken")))
    assert len(pods) >= 7, pods
    assert {p for p, mount in pods if mount is True} == NEEDS_A_TOKEN, pods
    assert not [p for p, mount in pods if mount is None], pods
