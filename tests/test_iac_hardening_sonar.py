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
# Owner decision 2026-10-21 (PR 129): AWS's APIs through interface endpoints, so the internet is left only where no
# endpoint can serve: 5432 to Aurora express (no VPC, no security group), 443 for orders-api's placeholder image on
# public.ecr.aws, and 443 for the traffic Lambda's calls to the PUBLIC HTTP API, in a group of its own.
SHOP_EGRESS = {
    "ecs": {("443", EVERYWHERE), ("5432", EVERYWHERE), ("6379", REDIS)},
    "lambda": {("5432", EVERYWHERE), ("6379", REDIS)},
    "traffic": {("443", EVERYWHERE)},
}
# The groups whose HTTPS to AWS goes to the endpoints, by a separate rule (the groups name each other).
TO_ENDPOINTS = {"ecs", "lambda"}


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


def test_https_to_aws_goes_to_the_endpoints_and_only_the_in_vpc_groups_reach_them():
    text = SHOP_MAIN.read_text(encoding="utf-8")
    egress = re.search(r'^resource "aws_vpc_security_group_egress_rule" "to_endpoints" \{\n(.*?)^\}', text,
                       re.DOTALL | re.MULTILINE)
    assert egress, "no egress rule to the endpoints"
    body = egress.group(1)
    assert set(re.findall(r"(\w+) = aws_security_group\.\1\.id", body)) == TO_ENDPOINTS
    assert "referenced_security_group_id = aws_security_group.endpoints.id" in body
    assert re.search(r"from_port\s*=\s*443", body)
    assert re.search(r"to_port\s*=\s*443", body)
    assert "cidr" not in body
    ingress = re.search(r'^resource "aws_vpc_security_group_ingress_rule" "endpoints" \{\n(.*?)^\}', text,
                        re.DOTALL | re.MULTILINE)
    assert ingress, "no ingress rule on the endpoints"
    assert set(re.findall(r"(\w+) = aws_security_group\.\1\.id", ingress.group(1))) == TO_ENDPOINTS | {"traffic"}
    assert "cidr" not in ingress.group(1)
    group = _shop_group("endpoints")
    assert "egress" not in group
    assert "ingress" not in group
    endpoint = re.search(r'^resource "aws_vpc_endpoint" "interface" \{\n(.*?)^\}', text, re.DOTALL | re.MULTILINE)
    assert endpoint, "no interface endpoints"
    for line in ("private_dns_enabled = true", "subnet_ids          = aws_subnet.private[*].id",
                 "security_group_ids  = [aws_security_group.endpoints.id]"):
        assert line in endpoint.group(1), line


# boto3 service name -> its interface endpoint; a client of a service not here fails the test below until it is
# mapped (and given an endpoint, or shown to make no network call).
_ENDPOINT_OF = {"secretsmanager": "secretsmanager", "sqs": "sqs", "sns": "sns", "dynamodb": "dynamodb",
                "rds": "rds"}


def _in_vpc_functions() -> set[str]:
    lambdas = (ROOT / "terraform" / "fullstack" / "lambda.tf").read_text(encoding="utf-8")
    return set(re.findall(r"^    ([\w-]+) = \{\n(?:(?!^    \}).)*?in_vpc\s*=\s*true", lambdas, re.DOTALL | re.MULTILINE))


def test_every_aws_call_the_in_vpc_code_makes_has_an_interface_endpoint():
    """Derived from the code: the boto3 clients of orders-api and of every in-VPC Lambda, plus what Fargate itself
    fetches for orders-api (its image from ECR, its logs, its secrets). A client whose only call is local - the RDS
    client signs IAM database tokens, no request - needs none; DynamoDB and S3 have gateway endpoints."""
    in_vpc = _in_vpc_functions()
    assert in_vpc == {"order-processor", "reconciler", "traffic", "ops"}, in_vpc
    sources = [SHOP_APPS / "app" / "app.py"] + [SHOP_APPS / "lambdas" / fn / "app.py" for fn in sorted(in_vpc)]
    needed = set()
    for src in sources:
        code = src.read_text(encoding="utf-8")
        for service in re.findall(r'boto3\.(?:client|resource)\("([a-z0-9-]+)"', code):
            assert service in _ENDPOINT_OF, (src.name, service)
            if service == "rds":  # only ever generate_db_auth_token, which signs locally
                assert set(re.findall(r"\b(?:rds|RDS)\.(\w+)\(", code)) == {"generate_db_auth_token"}, src
                continue
            needed.add(_ENDPOINT_OF[service])
    ecs = (ROOT / "terraform" / "fullstack" / "ecs.tf").read_text(encoding="utf-8")
    assert '"awslogs-group"' in ecs
    needed.add("logs")
    assert "aws_ecr_repository" in ecs
    needed |= {"ecr.api", "ecr.dkr"}  # the APPS pipeline's image; its layers through the S3 gateway endpoint
    apps = (ROOT / "scripts" / "deploy_fullstack_apps.py").read_text(encoding="utf-8")
    assert '"valueFrom": f"{secret}:' in apps  # orders-api's task secrets, which Fargate reads through the task ENI
    needed.add("secretsmanager")
    text = SHOP_MAIN.read_text(encoding="utf-8")
    listed = re.search(r'interface_endpoints = toset\(\[([^\]]*)\]\)', text)
    assert listed, "no interface endpoint list"
    have = set(re.findall(r'"([a-z0-9.-]+)"', listed.group(1)))
    gateway = re.search(r'resource "aws_vpc_endpoint" "gateway" \{\n\s*for_each\s*=\s*toset\(\[([^\]]*)\]\)', text)
    assert gateway, "no gateway endpoints"
    free = set(re.findall(r'"([a-z0-9.-]+)"', gateway.group(1)))
    assert free == {"s3", "dynamodb"}
    assert needed - free == have, (sorted(needed - free), sorted(have))  # nothing missing, nothing paid for unused


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
    # The stack's README says the same (review, PR 129): no HTTP 80 path to the load balancer is left to document.
    readme = (ROOT / "terraform" / "fullstack" / "README.md").read_text(encoding="utf-8")
    assert "HTTP 80" not in readme
    assert "internal load balancer over HTTPS 443" in readme
    other = sorted(set(re.findall(r"port=(\d+)", code)) - {"5432", "6379"})
    assert other == [], f"an app connects to a port its security group does not allow: {other}"
