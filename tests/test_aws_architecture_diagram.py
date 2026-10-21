"""The AWS architecture diagram (docs/diagrams/aws-architecture.drawio) is drawn from the code.

- Every AWS name it gives (warden-<env>-*, alias/..., /warden/<env>/... paths) is made or read by the code or a setup
  document, and every file or directory it cites exists. Cells for open pull requests (ids starting "pr") are exempt:
  their names live on the pull request's branch, and each says "open PR #n".
- Nothing is missing: every resource type the deployed stacks declare is either shown (by a phrase the diagram must
  contain) or listed below with the reason it is left out, and the counts the diagram states are the code's counts.
- Its SVG and PNG are exports of this source on a white page: tests/test_diagram_exports.py, for every diagram.
"""

from __future__ import annotations

import html
import pathlib
import re
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]
DIAGRAMS = ROOT / "docs" / "diagrams"
SOURCE = DIAGRAMS / "aws-architecture.drawio"
TF = ROOT / "terraform"
# The stacks a pipeline applies: terraform/runtime (runtime.yml) with its module, and terraform/fullstack and
# terraform/undo-lab (_infra-deploy.yml). terraform/proving-ground and the terraform/ root module are validated in CI
# and applied by no pipeline; the diagram's footer says so.
DEPLOYED = ("runtime", "modules/warden-runtime", "fullstack", "undo-lab")
NOT_DEPLOYED = ("proving-ground", ".")

# Every resource type of the deployed stacks: shown by a phrase the diagram contains, or left out, and why.
SHOWN = {
    "aws_apigatewayv2_api": "API Gateway warden-ops-front",
    "aws_apigatewayv2_api_mapping": "domain: the approval domain",
    "aws_apigatewayv2_domain_name": "domain: the approval domain",
    "aws_apigatewayv2_route": "/a /e /k /x /r /s",
    "aws_apigatewayv2_stage": "throttled",
    "aws_budgets_budget": "Budgets warden-dev-guard",
    "aws_cloudtrail": "CloudTrail warden-ops-witness",
    "aws_cloudwatch_event_rule": "EventBridge rules (default bus)",
    "aws_cloudwatch_log_group": "CloudWatch Logs",
    "aws_cloudwatch_metric_alarm": "CloudWatch alarms (WARDEN's own)",
    "aws_db_instance": "one RDS PostgreSQL db.t4g.micro instead",
    "aws_dynamodb_table": "DynamoDB warden-dev-carts",
    "aws_ecr_lifecycle_policy": "keeps the last 10 images",
    "aws_ecr_repository": "ECR warden-dev-app",
    "aws_ecs_cluster": "ECS cluster warden-ops-runtime",
    "aws_ecs_cluster_capacity_providers": "Fargate",
    "aws_ecs_service": "service warden-dev-orders-api",
    "aws_ecs_task_definition": "one service and task role per trust zone",
    "aws_eip": "Elastic IP",
    "aws_eks_access_entry": "access entry",
    "aws_eks_access_policy_association": "AmazonEKSViewPolicy",
    "aws_eks_addon": "add-ons vpc-cni",
    "aws_eks_cluster": "EKS warden-dev-eks",
    "aws_eks_node_group": "node group warden-dev-eks-ng",
    "aws_eks_pod_identity_association": "Pod Identity warden-dev-catalog-pod",
    "aws_elasticache_replication_group": "warden-dev-redis",
    "aws_iam_role": "IAM roles",
    "aws_iam_role_policy": "reads only its own",
    "aws_internet_gateway": "Internet gateway warden-ops-runtime",
    "aws_kms_alias": "KMS alias/warden-ops-audit",
    "aws_kms_key": "Ed25519 (SIGN_VERIFY)",
    "aws_lambda_alias": "alias live",
    "aws_lambda_event_source_mapping": "→ order-processor",
    "aws_lambda_function": "warden-ops-alarm",
    "aws_launch_template": "launch template warden-dev-eks-nodes",
    "aws_lb": "ALB warden-dev-alb",
    "aws_lb_listener": "HTTPS 443",
    "aws_acm_certificate": "ACM certificate",
    "aws_apigatewayv2_authorizer": "authorizer",
    "aws_cloudwatch_log_metric_filter": "a metric filter",
    "aws_s3_bucket_logging": "server access logs",
    "aws_s3_bucket_lifecycle_configuration": "90 days",
    "aws_lb_target_group": "orders, HTTPS 8080, /health",
    "aws_nat_gateway": "NAT gateway warden-ops-nat-0",
    "aws_rds_cluster": "Aurora PostgreSQL warden-ops-audit",
    "aws_rds_cluster_instance": "2 instances",
    "aws_route": "route tables",
    "aws_route_table": "route tables",
    "aws_route_table_association": "route tables",
    "aws_s3_bucket": "S3 warden-ops-anchors-*",
    "aws_s3_bucket_object_lock_configuration": "Object Lock (COMPLIANCE)",
    "aws_s3_bucket_versioning": "versioned",
    "aws_s3_bucket_public_access_block": "no public access",
    "aws_s3_bucket_server_side_encryption_configuration": "encrypted",
    "aws_s3_bucket_policy": "TLS only",
    "aws_secretsmanager_secret": "Secrets Manager warden/ops/<name>",
    "aws_security_group": "security groups warden-ops-runtime-*",
    "aws_sns_topic": "SNS warden-dev-order-events",
    "aws_sns_topic_subscription": "→ the notifications queue",
    "aws_sqs_queue": "SQS warden-ops-alarm-dlq",
    "aws_subnet": "Private subnets warden-ops-private-0, -1",
    "aws_vpc": "VPC warden-ops-runtime",
    "aws_vpc_endpoint": "S3 gateway endpoint",
    "aws_vpc_security_group_ingress_rule": "6379 from the app",
}
LEFT_OUT = {
    "aws_apigatewayv2_integration": "the wiring from a route to its Lambda: the route and the Lambda are shown",
    "aws_cloudwatch_event_target": "the wiring from a rule to its target: the arrow from the rule is shown",
    "aws_db_subnet_group": "placement only: the database is drawn in its private subnets",
    "aws_ec2_tag": "tags on the EKS cluster's own security group; no resource of its own",
    "aws_elasticache_subnet_group": "placement only: the cache is drawn in its private subnets",
    "aws_iam_role_policy_attachment": "an AWS-managed policy on a role that is shown",
    "aws_lambda_permission": "lets a rule or the HTTP API invoke a Lambda: the arrow is shown",
    "aws_secretsmanager_secret_version": "a secret's value, never drawn",
    "aws_sqs_queue_policy": "who may send to a queue that is shown",
}


def _cells() -> list[ET.Element]:
    return ET.parse(SOURCE).getroot().findall(".//mxCell")


def _plain(value: str) -> str:
    text = re.sub(r"<br\s*/?>", "\n", value or "")
    return html.unescape(re.sub(r"<[^>]+>", "", text))


def _texts(*, with_prs: bool = True) -> list[str]:
    """Each cell's words, as plain text."""
    return [_plain(c.get("value", "")) for c in _cells() if with_prs or not c.get("id", "").startswith("pr")]


def _diagram_text(*, with_prs: bool = True) -> str:
    return "\n".join(_texts(with_prs=with_prs))


def _resource_types(stack: str) -> set[str]:
    d = TF / stack
    return {m for f in d.glob("*.tf") for m in re.findall(r'^resource "(aws_[a-z0-9_]+)"', f.read_text(), re.MULTILINE)}


ENV = r"(?:ops|dev|prod|<env>)"


def _normal(text: str) -> str:
    """Every way of writing an environment's prefix made one: warden-<env>-."""
    text = text.replace("${count.index}", "0")
    return re.sub(r"warden-(?:\$\{[^}]+\}|\{[^}]+\}|ops|dev|prod|<env>|<ENV>)-", "warden-<env>-", text)


def _corpus() -> list[str]:
    """The repository's own words: one entry per Terraform stack (its .tf and .py files together), one per other file."""
    parts = []
    for d in TF.rglob("*"):
        if d.is_dir() and any(d.glob("*.tf")):
            files = list(d.glob("*.tf")) + list(d.glob("*.py"))
            body = "\n".join(f.read_text(encoding="utf-8") for f in files)
            local = re.search(r'^\s+name\s*=\s*"(warden-\$\{local\.env\}[^"]*)"', body, re.MULTILINE)
            if local:  # ${local.name} is the stack's prefix (terraform/fullstack, terraform/undo-lab)
                body = body.replace("${local.name}", local.group(1))
            parts.append(body)
    globs = ("iam/**/*.json", "src/**/*.py", "src/**/*.yaml", "scripts/*.py", "scenarios/**/*.py", "k8s/**/*.yaml",
             "manifests/**/*.yaml", "helm/**/*.yaml", ".github/workflows/*.yml", "docs/*.md")
    parts += [f.read_text(encoding="utf-8") for g in globs for f in ROOT.glob(g)]
    return [_normal(t) for t in parts]


def _known(name: str, corpus: list[str]) -> bool:
    """A whole name the code writes (a name ending in * is a prefix), or a for_each name whose template and key are in
    the same stack: warden-<env>-${each.key}<rest>, and the key as a map's key or a set's element there."""
    wild = name.endswith("*")
    norm = re.sub(rf"warden-{ENV}-", "warden-<env>-", name).rstrip("*")
    whole = re.compile(re.escape(norm) + ("" if wild else r"(?![a-z0-9-])"))
    if any(whole.search(text) for text in corpus):
        return True
    suffix = norm.removeprefix("warden-<env>-")
    for i in range(1, len(suffix) + 1):
        key, rest = suffix[:i], suffix[i:]
        if rest and not rest.startswith("-"):
            continue
        template = f"warden-<env>-${{each.key}}{rest}\""
        # A map's key (`key = {`, `key = jsonencode(`, `key = 120`) or a set's element (`toset(["key", ...])`); an
        # attribute (`name = "..."`) is neither.
        as_key = re.compile(rf'^\s+"?{re.escape(key)}"?\s*=\s*(?:\{{|jsonencode\(|\d)|toset\(\[[^\]]*"{re.escape(key)}"',
                            re.MULTILINE)
        if any(template in text and as_key.search(text) for text in corpus):
            return True
    return False


def _names(*, with_prs: bool = False) -> set[str]:
    """Full names, and the short forms after one in the same cell (`warden-ops-ecs-events, -rds-events` names
    warden-ops-rds-events)."""
    names: set[str] = set()
    pattern = re.compile(rf"(?<![\w-])(warden-{ENV}-)([a-z][a-z0-9*-]*[a-z0-9*])|(?<![\w/<>-])-([a-z][a-z0-9-]*[a-z0-9])")
    for text in _texts(with_prs=with_prs):
        prefix = None
        for m in pattern.finditer(text):
            if m.group(1):
                prefix = m.group(1)
                names.add(m.group(1) + m.group(2))
            elif prefix:
                names.add(prefix + m.group(3))
    return names


def test_the_source_is_uncompressed_drawio_with_a_white_page():
    root = ET.parse(SOURCE).getroot()
    model = root.find("./diagram/mxGraphModel")
    assert model is not None, "save the .drawio uncompressed (File > Properties > untick Compressed)"
    assert model.get("background") == "#FFFFFF"
    assert len(_cells()) > 150


def test_every_name_the_diagram_gives_is_made_or_read_by_the_code():
    corpus = _corpus()
    names = _names()
    assert len(names) > 80
    assert sorted(n for n in names if not _known(n, corpus)) == []
    for path in re.findall(r"/warden/(?:ops|dev|<env>)/[a-z_/]+[a-z_]", _diagram_text(with_prs=False)):
        norm = re.sub(r"^/warden/[^/]+/", "/warden/<env>/", path)
        stem = norm.removeprefix("/warden/<env>/").split("/")[0]
        joined = "\n".join(corpus)
        assert re.search(rf"/warden/(?:<env>|\$\{{[^}}]+\}}|ops|dev|\{{[a-z_]+\}})/{stem}\b", joined), path


def test_every_setting_it_cites_is_read():
    runtime = (TF / "runtime" / "main.tf").read_text(encoding="utf-8") + (TF / "fullstack" / "main.tf").read_text()
    for key in re.findall(r"tf/([a-z_]+)", _diagram_text(with_prs=False)):
        assert f'"{key}"' in runtime or f"/tf/{key}" in runtime, key


def test_every_file_and_directory_it_cites_exists():
    text = _diagram_text()
    for path in re.findall(r"(?<![\w/.-])((?:terraform|iam|k8s|manifests|helm|scripts|src|docs)/[\w./<>-]*[\w>]/?)", text):
        target = ROOT / path.replace("<env>", "dev")
        assert target.exists(), path
    tracked = [ROOT / d for d in ("src", "scripts", "scenarios", "terraform", "docs", ".github", "k8s", "manifests")]
    for name in set(re.findall(r"\b[\w-]+\.(?:py|tf|yml|yaml|drawio)\b", text)):
        assert any(any(d.rglob(name)) for d in tracked), name


def test_every_resource_type_of_the_deployed_stacks_is_shown_or_left_out_with_a_reason():
    declared = set().union(*(_resource_types(s) for s in DEPLOYED))
    assert not set(SHOWN) & set(LEFT_OUT)
    assert declared == set(SHOWN) | set(LEFT_OUT), "a new resource type: draw it, or say here why it is left out"
    text = _diagram_text(with_prs=False)
    assert sorted(t for t, phrase in SHOWN.items() if phrase not in text) == []


def test_the_stacks_it_leaves_out_are_applied_by_no_pipeline():
    deploy = (ROOT / ".github" / "workflows" / "_infra-deploy.yml").read_text(encoding="utf-8")
    stacks = re.search(r'case "\$STACK" in ([\w|-]+)\)', deploy)
    assert stacks, "_infra-deploy.yml no longer names its stacks in one case statement"
    assert set(stacks.group(1).split("|")) == {"fullstack", "undo-lab"}
    assert "terraform -chdir=terraform/runtime apply" in (ROOT / ".github" / "workflows" / "runtime.yml").read_text()
    for wf in (ROOT / ".github" / "workflows").glob("*.yml"):
        for line in wf.read_text(encoding="utf-8").splitlines():
            # -chdir=terraform, "terraform/proving-ground/", 'terraform' ...: quoted or not, with or without a slash.
            if re.search(r"""-chdir=["']?terraform(/proving-ground)?/?["']?(\s|$)""", line):
                assert re.search(r"\b(init|validate|fmt)\b", line), (wf.name, line)
            assert not re.search(r"""working-directory:\s*["']?(\./)?terraform(/proving-ground)?/?["']?\s*$""", line), \
                (wf.name, line)
    assert all((TF / s).is_dir() for s in NOT_DEPLOYED)


def _keys(block: str) -> list[str]:
    return re.findall(r"^\s{4}([a-z][a-z0-9-]*)\s*=\s*\{", block, re.MULTILINE)


def test_every_function_rule_alarm_and_zone_of_the_runtime_is_on_it():
    text = _diagram_text(with_prs=False)
    names = _names()
    module = TF / "modules" / "warden-runtime"
    front = (module / "frontdoor.tf").read_text(encoding="utf-8")
    front_doors = _keys(front.split("front_doors = {", 1)[1].split("\n  }", 1)[0])
    assert set(front_doors) == {"alarm", "alertmanager", "approval", "actor-use"}
    for fn in [*front_doors, "ack", "migrate"]:
        assert f"warden-ops-{fn}" in names, fn
    events = _keys(front.split("service_events = {", 1)[1].split("\n  }", 1)[0])
    for rule in ["alarm-changes", *[f"{e}-events" for e in events], "actor-use", "approvers-changed"]:
        assert f"warden-ops-{rule}" in names, rule
    body = "\n".join(f.read_text(encoding="utf-8") for f in module.glob("*.tf"))
    for alarm in re.findall(r'alarm_name\s*=\s*"warden-\$\{var\.environment\}-([a-z-]+)"', body):
        assert f"warden-ops-{alarm}" in names, alarm
    iam = (module / "iam.tf").read_text(encoding="utf-8")
    zones = _keys(iam.split("  zones = {", 1)[1].split("\n  }", 1)[0])
    assert zones == ["core", "read", "llm", "notify", "act", "critic"]
    for zone in zones:
        assert f"warden-ops-{zone}" in names, zone
    assert f"warden-ops-<zone> ({len(zones)})" in text
    assert f"{len(zones)} task queues" in text  # one per zone, on Temporal Cloud
    lambdas = _keys(iam.split("front_door_access = {", 1)[1].split("\n  }", 1)[0])
    assert f"warden-ops-<name>-lambda ({len(lambdas)})" in text
    secrets = (module / "secrets.tf").read_text(encoding="utf-8").split("toset([", 1)[1].split("])", 1)[0]
    slots = len(re.findall(r'"[a-z0-9-]+"', secrets))
    assert f"{slots} empty slots" in text


def test_every_function_and_alarm_of_the_full_stack_and_the_undo_lab_is_on_it():
    text = _diagram_text(with_prs=False)
    names = _names()
    lam = (TF / "fullstack" / "lambda.tf").read_text(encoding="utf-8")
    functions = _keys(lam.split("  lambdas = {", 1)[1].split("\n  }\n", 1)[0])
    assert len(functions) == 6
    for fn in functions:
        assert f"warden-dev-{fn}" in names, fn
    for schedule in re.findall(r"^\s{4}([a-z0-9-]+)\s*=\s*\{ fn =", lam, re.MULTILINE):
        assert f"warden-dev-{schedule}" in names, schedule
    alarms = (TF / "fullstack" / "alarms.tf").read_text(encoding="utf-8")
    count = len(re.findall(r"\bdesc\s*=", alarms))
    assert f"{count} alarms warden-dev-*" in text
    lab = (TF / "undo-lab" / "main.tf").read_text(encoding="utf-8")
    lab_alarms = lab.count('resource "aws_cloudwatch_metric_alarm"')
    assert f"{lab_alarms} alarms" in text
    for name in re.findall(r'\b(?:name|function_name)\s*=\s*"\$\{local\.name\}-([a-z-]+)"', lab):
        assert f"warden-dev-lab-{name}" in names, name


def test_open_pull_requests_are_marked_and_never_drawn_as_built():
    for cell in _cells():
        cid = cell.get("id", "")
        if cid.startswith("pr") and not cid.endswith("-i"):
            value = _plain(cell.get("value", ""))
            if cell.get("vertex") == "1" and not cid.endswith("-w"):
                assert re.search(r"open PR #\d+", value), cid
                assert "not built" in value, cid
            elif cid.endswith("-w"):
                assert re.search(r"open PR #\d+", value), cid
            if cell.get("edge") == "1":
                assert "dashed=1" in cell.get("style", ""), cid
    assert "designed, not built" in _plain(next(c for c in _cells() if c.get("id") == "planned-prod").get("value"))


def test_the_footer_names_the_commit_it_was_drawn_from():
    assert re.search(r"Drawn from origin/main [0-9a-f]{7,40} \(\d{4}-\d{2}-\d{2}\)", _diagram_text())


def test_the_readmes_show_and_explain_it():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "docs/diagrams/aws-architecture.svg" in readme
    assert "aws-architecture.drawio" in (DIAGRAMS / "README.md").read_text(encoding="utf-8")
