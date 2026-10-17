"""SonarCloud's IaC findings of 2026-10-16, fixed in the stacks and manifests: logs kept long enough to investigate an
incident found days later, EKS nodes that never take a public address, the lab database encrypted at rest, and every
container's resources declared - the negative Pod Security test too."""

from __future__ import annotations

import pathlib
import re

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _code(text: str) -> str:
    return re.sub(r"#.*", "", text)


def _blocks(stack: str, kind: str):
    for tf in sorted((ROOT / "terraform" / stack).glob("*.tf")):
        text = _code(tf.read_text(encoding="utf-8"))
        for m in re.finditer(rf'^resource "{kind}" "(\w+)" \{{', text, re.MULTILINE):
            end = re.search(r"^\}", text[m.end():], re.MULTILINE)
            yield f"{tf.relative_to(ROOT).as_posix()}:{m.group(1)}", text[m.end():m.end() + end.start()]


def test_every_log_group_of_the_dev_stack_the_runtime_and_the_undo_lab_keeps_14_days_or_more():
    found = 0
    for stack in ("fullstack", "undo-lab", "modules/warden-runtime"):
        for name, body in _blocks(stack, "aws_cloudwatch_log_group"):
            found += 1
            days = re.search(r"retention_in_days\s*=\s*(\d+)", body)
            assert days and int(days.group(1)) >= 14, name
    assert found >= 8, found


def test_the_eks_nodes_never_take_a_public_address_and_keep_the_cluster_security_group():
    lt = dict(_blocks("fullstack", "aws_launch_template"))["terraform/fullstack/eks.tf:nodes"]
    nic = re.search(r"network_interfaces \{(.*?)\}", lt, re.DOTALL).group(1)
    assert re.search(r"associate_public_ip_address\s*=\s*false", nic)
    assert re.search(r"security_groups\s*=\s*\[aws_eks_cluster\.this\.vpc_config\[0\]\.cluster_security_group_id\]", nic)


def test_the_lab_database_is_encrypted_at_rest():
    db = dict(_blocks("proving-ground", "aws_db_instance"))["terraform/proving-ground/rds.tf:this"]
    assert re.search(r"storage_encrypted\s*=\s*true", db)


def test_every_container_of_the_flagged_manifests_declares_its_resources():
    for rel in ("k8s/job.yaml", "k8s/test/oom-workload.yaml", "k8s/test/posture-probe.yaml",
                "k8s/proving-ground/namespace.yaml", "k8s/test/privileged-must-fail.yaml"):
        for doc in yaml.safe_load_all((ROOT / rel).read_text(encoding="utf-8")):
            spec = (doc or {}).get("spec", {})
            spec = spec.get("template", {}).get("spec", spec) if doc.get("kind") != "Pod" else spec
            for c in spec.get("containers", []):
                requests = c["resources"]["requests"]
                assert {"cpu", "memory", "ephemeral-storage"} <= set(requests), (rel, c["name"])
                assert "memory" in c["resources"]["limits"], (rel, c["name"])
