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
SHOP_TF = ROOT / "terraform" / "fullstack"
SHOP_APPS = ROOT / "scenarios" / "fullstack"


def _shop_group(name: str) -> str:
    text = SHOP_MAIN.read_text(encoding="utf-8")
    m = re.search(rf'^resource "aws_security_group" "{name}" \{{\n(.*?)^\}}', text, re.DOTALL | re.MULTILINE)
    assert m, name
    return m.group(1)


def _owners(body: str) -> list[str]:
    """The security groups a separate rule belongs to: its `security_group_id`, or every group of its for_each map."""
    own = re.search(r"^\s*security_group_id\s*=\s*(.+?)\s*$", body, re.MULTILINE)
    assert own, body
    if own.group(1) == "each.value":
        each = re.search(r"for_each\s*=\s*\{(.*?)\}", body, re.DOTALL)
        assert each, body
        return re.findall(r"aws_security_group\.(\w+)\.id", each.group(1))
    return re.findall(r"aws_security_group\.(\w+)\.id", own.group(1))


def _shop_egress() -> dict[str, list[dict[str, str]]]:
    """Every separate egress rule of the shop stack, by the group it belongs to."""
    rules: dict[str, list[dict[str, str]]] = {}
    for where, body in _blocks("fullstack", "aws_vpc_security_group_egress_rule"):
        attrs = dict(re.findall(r"^\s*(\w+)\s*=\s*(.+?)\s*$", body, re.MULTILINE))
        for group in _owners(body):
            rules.setdefault(group, []).append({"where": where, **attrs})
    return rules


EVERYWHERE = '"0.0.0.0/0"'
REDIS = "aws_security_group.redis.id"
ENDPOINTS = "aws_security_group.endpoints.id"
# Owner decision 2026-10-21 (PR 129): AWS's APIs through interface endpoints, so the internet is left only where no
# endpoint can serve: 5432 to Aurora express (no VPC, no security group), 443 for orders-api's placeholder image on
# public.ecr.aws, and 443 for the traffic Lambda's calls to the PUBLIC HTTP API, in a group of its own.
SHOP_EGRESS = {
    "ecs": {("443", ENDPOINTS), ("443", EVERYWHERE), ("5432", EVERYWHERE), ("6379", REDIS)},
    "lambda": {("443", ENDPOINTS), ("5432", EVERYWHERE), ("6379", REDIS)},
    "traffic": {("443", EVERYWHERE)},
}
# The groups whose HTTPS to AWS goes to the endpoints, by a separate rule (the groups name each other).
TO_ENDPOINTS = {"ecs", "lambda"}
DESTINATIONS = ("cidr_ipv4", "cidr_ipv6", "prefix_list_id", "referenced_security_group_id")


@pytest.mark.parametrize("name", sorted(SHOP_EGRESS))
def test_each_app_group_allows_exactly_the_egress_its_code_needs(name):
    assert not re.search(r"^\s*egress\s*[{=]", _shop_group(name), re.MULTILINE), f"{name}: inline egress"
    rules = _shop_egress().get(name, [])
    for r in rules:
        assert r["ip_protocol"] == '"tcp"', r
        assert r["from_port"] == r["to_port"], r  # one port, never a range
        # One destination per rule (review, PR 129), and only the two kinds this stack uses.
        assert [d for d in DESTINATIONS if d in r] in (["cidr_ipv4"], ["referenced_security_group_id"]), r
    got = {(r["from_port"], r.get("cidr_ipv4") or r.get("referenced_security_group_id")) for r in rules}
    assert got == SHOP_EGRESS[name], (name, got)
    assert len(rules) == len(got), (name, rules)


def _stacks() -> list[str]:
    tf = ROOT / "terraform"
    return sorted({p.parent.relative_to(tf).as_posix() for p in tf.rglob("*.tf") if ".terraform" not in p.parts})


def _separate_rule_owners(stack: str, direction: str) -> set[str]:
    owners = set()
    for _, body in _blocks(stack, f"aws_vpc_security_group_{direction}_rule"):
        owners.update(_owners(body))
    for _, body in _blocks(stack, "aws_security_group_rule"):
        if re.search(rf'^\s*type\s*=\s*"{direction}"', body, re.MULTILINE):
            owners.update(_owners(body))
    return owners


@pytest.mark.parametrize("stack", _stacks())
def test_no_security_group_mixes_inline_rules_with_separate_ones(stack):
    """With inline `egress {}` / `ingress {}` blocks the group resource owns the whole set: on the next apply it revokes
    every rule its blocks do not list, so a separate rule on the same group vanishes and comes back on alternate
    applies (the AWS provider's documentation; review, PR 129)."""
    for direction in ("egress", "ingress"):
        separate = _separate_rule_owners(stack, direction)
        for where, body in _blocks(stack, "aws_security_group"):
            name = where.rsplit(":", 1)[1]
            inline = re.search(rf"^\s*{direction}\s*[{{=]", body, re.MULTILINE)
            assert not (inline and name in separate), f"{where}: inline {direction} and separate {direction} rules"


def _in_vpc_groups() -> set[str]:
    """The security groups the stack's in-VPC compute runs with, read from where each is attached: the Lambdas'
    vpc_config, the ECS service, and the EKS nodes' launch template (the cluster security group, pods included)."""
    lambdas = (SHOP_TF / "lambda.tf").read_text(encoding="utf-8")
    vpc = re.search(r"^\s*security_group_ids\s*=\s*(.+)$", lambdas, re.MULTILINE)
    assert vpc, "no Lambda vpc_config"
    groups = set(re.findall(r"aws_security_group\.(\w+)\.id", vpc.group(1)))
    ecs = (SHOP_TF / "ecs.tf").read_text(encoding="utf-8")
    service = re.search(r"network_configuration \{(.*?)\}", ecs, re.DOTALL)
    assert service, "no ECS network_configuration"
    groups |= set(re.findall(r"aws_security_group\.(\w+)\.id", service.group(1)))
    eks = (SHOP_TF / "eks.tf").read_text(encoding="utf-8")
    nodes = re.search(r"network_interfaces \{(.*?)\}", eks, re.DOTALL)
    assert nodes, "no node network_interfaces"
    assert "aws_eks_cluster.this.vpc_config[0].cluster_security_group_id" in nodes.group(1)
    return groups | {"eks"}


def test_https_to_aws_goes_to_the_endpoints_and_every_in_vpc_caller_reaches_them():
    """Private DNS answers for the whole VPC: every group in-VPC compute runs with must be let in, or its calls to
    those services time out - the EKS nodes' image pulls and the Container Insights agent as much as the apps."""
    text = SHOP_MAIN.read_text(encoding="utf-8")
    egress = re.search(r'^resource "aws_vpc_security_group_egress_rule" "to_endpoints" \{\n(.*?)^\}', text,
                       re.DOTALL | re.MULTILINE)
    assert egress, "no egress rule to the endpoints"
    body = egress.group(1)
    assert set(_owners(body)) == TO_ENDPOINTS
    assert f"referenced_security_group_id = {ENDPOINTS}" in body
    assert re.search(r"from_port\s*=\s*443", body)
    assert re.search(r"to_port\s*=\s*443", body)
    assert "cidr" not in body
    ingress = re.search(r'^resource "aws_vpc_security_group_ingress_rule" "endpoints" \{\n(.*?)^\}', text,
                        re.DOTALL | re.MULTILINE)
    assert ingress, "no ingress rule on the endpoints"
    each = re.search(r"for_each\s*=\s*\{(.*?)\}", ingress.group(1), re.DOTALL)
    assert each, "the endpoint ingress names no groups"
    admitted = dict(re.findall(r"^\s*(\w+)\s*=\s*(\S+)\s*$", each.group(1), re.MULTILINE))
    assert set(admitted) == _in_vpc_groups()
    assert admitted["eks"] == "aws_eks_cluster.this.vpc_config[0].cluster_security_group_id"
    for key, ref in admitted.items():
        assert key == "eks" or ref == f"aws_security_group.{key}.id", (key, ref)
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


def _eks_needs() -> set[str]:
    """What the EKS nodes and pods fetch from the endpoints' services, read from eks.tf and the shop's deploy path."""
    eks = (SHOP_TF / "eks.tf").read_text(encoding="utf-8")
    needed = set()
    # The nodes pull the add-ons' images (vpc-cni, kube-proxy, coredns, ...) from AWS's regional ECR registry.
    assert 'resource "aws_eks_node_group"' in eks
    assert 'resource "aws_eks_addon"' in eks
    needed |= {"ecr.api", "ecr.dkr"}
    # ... and the shop's image from this stack's ECR (Argo CD sets shop-app to the image deploy pushed there).
    assert '"shop-app=__IMAGE__"' in (ROOT / "k8s" / "argocd" / "shop.yaml").read_text(encoding="utf-8")
    assert "stack['ecr_repository_url']" in (ROOT / "scripts" / "deploy_fullstack_apps.py").read_text(encoding="utf-8")
    # Container Insights: the observability agent writes its records to CloudWatch Logs (the pod alarms read them).
    if "amazon-cloudwatch-observability" in eks:
        assert "/aws/containerinsights/" in eks
        needed.add("logs")
    return needed


def test_every_aws_call_the_in_vpc_code_makes_has_an_interface_endpoint():
    """Derived from the code: the boto3 clients of orders-api and of every in-VPC Lambda, plus what Fargate itself
    fetches for orders-api (its image from ECR, its logs, its secrets), plus what the EKS nodes and pods fetch (images
    from ECR, Container Insights logs). A client whose only call is local - the RDS client signs IAM database tokens,
    no request - needs none; DynamoDB and S3 have gateway endpoints."""
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
    needed |= _eks_needs()
    text = SHOP_MAIN.read_text(encoding="utf-8")
    listed = re.search(r'interface_endpoints = toset\(\[([^\]]*)\]\)', text)
    assert listed, "no interface endpoint list"
    have = set(re.findall(r'"([a-z0-9.-]+)"', listed.group(1)))
    gateway = re.search(r'resource "aws_vpc_endpoint" "gateway" \{\n\s*for_each\s*=\s*toset\(\[([^\]]*)\]\)', text)
    assert gateway, "no gateway endpoints"
    free = set(re.findall(r'"([a-z0-9.-]+)"', gateway.group(1)))
    assert free == {"s3", "dynamodb"}
    assert needed - free == have, (sorted(needed - free), sorted(have))  # nothing missing, nothing paid for unused


def test_the_smoke_test_after_a_network_apply_checks_every_path():
    """A missing rule or endpoint is a silent timeout, found later. The stack README's steps after the apply exercise
    each path anew (review, PR 129): drift, the endpoints, new ECS tasks on the ECR image, Lambda cold starts, fresh EKS
    pulls, Container Insights."""
    readme = (SHOP_TF / "README.md").read_text(encoding="utf-8")
    for step in ("terraform plan -detailed-exitcode", "Name=vpc-endpoint-type,Values=Interface", "--force-new-deployment",
                 "ecr_repository_url", "update-function-configuration", "rollout restart deployment/catalog-api",
                 "ImagePullBackOff", "/aws/containerinsights/", "revoke-security-group-egress"):
        assert step in readme, step


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
