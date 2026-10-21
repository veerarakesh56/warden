"""SonarCloud's IaC findings of 2026-10-16, fixed in the stacks and manifests: logs kept long enough to investigate an
incident found days later, EKS nodes that never take a public address, the lab database encrypted at rest, and every
container's resources declared - the negative Pod Security test too."""

from __future__ import annotations

import pathlib
import re

import pytest
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
            assert days, name
            assert int(days.group(1)) >= 14, name
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
    import json
    import subprocess
    import sys

    # The negative Pod Security test's pod is built when it runs (scripts/negative_pod.py), never kept as a file.
    built = subprocess.run([sys.executable, str(ROOT / "scripts" / "negative_pod.py")], capture_output=True, text=True,
                           check=True).stdout
    sources = {rel: (ROOT / rel).read_text(encoding="utf-8") for rel in (
        "k8s/job.yaml", "k8s/test/oom-workload.yaml", "k8s/test/posture-probe.yaml", "k8s/proving-ground/namespace.yaml")}
    sources["scripts/negative_pod.py"] = json.dumps(json.loads(built))
    for rel, text in sources.items():
        for doc in yaml.safe_load_all(text):
            spec = (doc or {}).get("spec", {})
            spec = spec.get("template", {}).get("spec", spec) if doc.get("kind") != "Pod" else spec
            for c in spec.get("containers", []):
                requests = c["resources"]["requests"]
                assert {"cpu", "memory", "ephemeral-storage"} <= set(requests), (rel, c["name"])
                assert "memory" in c["resources"]["limits"], (rel, c["name"])


# Owner B28: the shop's application security groups allow the least egress their code needs, not everything.
# Derived from the code (scenarios/fullstack): orders-api and the in-VPC Lambdas call AWS's APIs over HTTPS, read
# Aurora in express configuration (outside the VPC, through the NAT) over PostgreSQL, and the cache over Redis; the
# traffic Lambda also calls the internal load balancer, over HTTPS since main's listener moved to 443. Nothing else - no "all protocols" rule, no range.
SHOP_MAIN = ROOT / "terraform" / "fullstack" / "main.tf"
SHOP_APPS = ROOT / "scenarios" / "fullstack"


def _shop_group(name: str) -> str:
    text = SHOP_MAIN.read_text(encoding="utf-8")
    m = re.search(rf'^resource "aws_security_group" "{name}" \{{\n(.*?)^\}}', text, re.DOTALL | re.MULTILINE)
    assert m, name
    return m.group(1)


def _shop_egress(name: str) -> list[dict[str, str]]:
    rules = []
    for body in re.findall(r"^  egress \{\n(.*?)\n  \}", _shop_group(name), re.DOTALL | re.MULTILINE):
        rule = dict(re.findall(r"^\s*(\w+)\s*=\s*(.+?)\s*$", body, re.MULTILINE))
        rules.append(rule)
    return rules


EVERYWHERE = '["0.0.0.0/0"]'
REDIS = "[aws_security_group.redis.id]"
SHOP_EGRESS = {
    "ecs": {("443", EVERYWHERE), ("5432", EVERYWHERE), ("6379", REDIS)},
    "lambda": {("443", EVERYWHERE), ("5432", EVERYWHERE), ("6379", REDIS)},
}


@pytest.mark.parametrize("name", sorted(SHOP_EGRESS))
def test_each_app_group_allows_exactly_the_egress_its_code_needs(name):
    rules = _shop_egress(name)
    for r in rules:
        assert r["protocol"] == '"tcp"', (name, r)
        assert r["from_port"] == r["to_port"], (name, r)  # one port, never a range
        # One destination per rule: the provider accepts both keys in one block and opens both (review, PR 129).
        assert ("cidr_blocks" in r) != ("security_groups" in r), (name, r)
    got = {(r["from_port"], r.get("cidr_blocks") or r.get("security_groups")) for r in rules}
    assert got == SHOP_EGRESS[name], (name, got)
    assert len(rules) == len(got), (name, rules)


def test_the_ports_are_the_ones_the_apps_use():
    """The allowed ports come from the code, so a new destination in an app shows up here, not as a silent timeout."""
    code = "\n".join(p.read_text(encoding="utf-8") for p in sorted(SHOP_APPS.rglob("*.py")))
    assert "port=5432" in code
    assert "port=6379" in code
    assert 'os.environ["ALB_URL"]' in code
    lambdas_tf = (ROOT / "terraform" / "fullstack" / "lambda.tf").read_text(encoding="utf-8")
    # The traffic Lambda reaches the internal ALB over HTTPS (main moved the listener to 443): the 443 rule covers it.
    assert '"https://${aws_lb.orders.dns_name}"' in lambdas_tf
    assert "http://${aws_lb.orders.dns_name}" not in lambdas_tf
    other = sorted(set(re.findall(r"port=(\d+)", code)) - {"5432", "6379"})
    assert other == [], f"an app connects to a port its security group does not allow: {other}"
