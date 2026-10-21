"""The runbook's stop-the-worker step names the cluster and service Terraform really makes (2026-10-16: it said
cluster `warden-ops`, which does not exist - the cluster is `warden-<env>-runtime`)."""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[2]


def test_the_runbook_stops_the_act_worker_on_the_cluster_terraform_makes():
    compute = (ROOT / "infra/terraform/modules/warden-runtime/compute.tf").read_text(encoding="utf-8")
    block = compute.split('resource "aws_ecs_cluster" "runtime" {', 1)[1].split("\n}", 1)[0]
    cluster = re.search(r'^\s*name\s*=\s*"([^"]+)"', block, re.MULTILINE).group(1)
    runbook = (ROOT / "warden/docs/RUNBOOK-WARDEN-INCIDENT.md").read_text(encoding="utf-8")
    named = set(re.findall(r"cluster[ `]+(warden-[a-z0-9-]+)", runbook))
    assert named, "the runbook names no cluster"
    assert named == {cluster.replace("${var.environment}", "ops")}, named
    assert "--service warden-ops-act --desired-count 0" in runbook
