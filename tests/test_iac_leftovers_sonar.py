"""SonarCloud's IaC findings PR 46 left open (2026-10-17), each fixed with an equivalent that costs nothing, or kept by
design with the reason held here:

- S6258: the runtime's anchors and witness buckets log every access; the dev stack's ALB logs every request.
- S6327: the order-events topic is encrypted with the AWS-managed key, and its one publisher may use it through SNS.
- S5332: the internal ALB answers over HTTPS only, with the stack's own certificate (its caller's side, a real
  handshake included, is tests/test_traffic_alb_tls.py, in the apps lane).
- S6413: the proving ground keeps its logs 14 days.
- By design, owner to review: the lab database's public endpoint (S8793) and its backups (S6364), the runtime image's
  shared /tmp (docker S2612), the webhook routes (S6333) and the negative Pod Security test (S6428).
"""

from __future__ import annotations

import json
import pathlib
import re

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "terraform" / "modules" / "warden-runtime"
FULLSTACK = ROOT / "terraform" / "fullstack"
LAB = ROOT / "terraform" / "proving-ground"


def _code(text: str) -> str:
    return re.sub(r"(?m)^\s*#.*$|\s#.*$", "", text)


def _block(path: pathlib.Path, kind: str, name: str) -> str:
    """The body of `resource "<kind>" "<name>"` (or `data`), comments removed, braces counted."""
    text = _code(path.read_text(encoding="utf-8"))
    m = re.search(rf'^(?:resource|data) "{kind}" "{name}" \{{', text, re.MULTILINE)
    assert m, (path.name, kind, name)
    depth, i = 1, m.end()
    while depth:
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        i += 1
    return text[m.end():i - 1]


def _flat(body: str) -> str:
    return " ".join(body.split())


def _iam(env: str, kind: str) -> dict:
    return json.loads((ROOT / "iam" / env / f"{kind}.json").read_text(encoding="utf-8"))


def _assert_private_tls_only_bucket(path: pathlib.Path, name: str, keep_days: int) -> str:
    """A log bucket as every bucket here: versioned, never public, SSE-S3 (the only encryption log delivery accepts),
    TLS only, its logs expired after `keep_days`. Returns the bucket policy's body."""
    assert 'status = "Enabled"' in _flat(_block(path, "aws_s3_bucket_versioning", name))
    pab = _block(path, "aws_s3_bucket_public_access_block", name)
    for flag in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"):
        assert re.search(rf"{flag}\s*=\s*true", pab), (name, flag)
    assert 'sse_algorithm = "AES256"' in _flat(_block(path, "aws_s3_bucket_server_side_encryption_configuration", name))
    life = _flat(_block(path, "aws_s3_bucket_lifecycle_configuration", name))
    assert f"expiration {{ days = {keep_days} }}" in life
    assert "noncurrent_days = 1" in life
    policy = _block(path, "aws_s3_bucket_policy", name)
    assert '"aws:SecureTransport" = "false"' in policy
    assert 'Effect    = "Deny"' in policy
    return policy


# ----------------------------------------------------------------- S6258: access logs


def test_the_anchors_and_the_witness_log_every_access_to_a_bucket_only_s3_logging_writes():
    anchors, witness = RUNTIME / "anchors.tf", RUNTIME / "witness.tf"
    # Each bucket's logging is in the bucket's own file (Sonar reads one file at a time, and so does a reviewer).
    for path, name in ((anchors, "anchors"), (witness, "witness")):
        logging = _flat(_block(path, "aws_s3_bucket_logging", name))
        assert f"bucket = aws_s3_bucket.{name}.id" in logging
        assert f'target_bucket = aws_s3_bucket.access_logs.id target_prefix = "{name}/"' in logging
    # The target is a bucket of its own: an Object Lock bucket cannot receive server access logs.
    assert "object_lock_enabled" not in _block(anchors, "aws_s3_bucket", "access_logs")
    policy = _flat(_assert_private_tls_only_bucket(anchors, "access_logs", keep_days=90))
    # Only S3's logging service writes, only under the two prefixes, only for these two buckets of this account.
    assert 'Principal = { Service = "logging.s3.amazonaws.com" } Action = "s3:PutObject"' in policy
    assert ('Resource = [for prefix in ["anchors", "witness", "s3-access"] : '
            '"${aws_s3_bucket.access_logs.arn}/${prefix}/*"]') in policy
    assert ('"aws:SourceArn" = [aws_s3_bucket.anchors.arn, aws_s3_bucket.witness.arn, aws_s3_bucket.access_logs.arn]'
            ) in policy
    # The log bucket logs itself too (a read of the logs leaves a trace), in its own file as Sonar reads it.
    own = _flat(_block(anchors, "aws_s3_bucket_logging", "access_logs"))
    assert own.startswith("bucket = aws_s3_bucket.access_logs.id target_bucket = aws_s3_bucket.access_logs.id")
    assert '"aws:SourceAccount" = local.account' in policy
    assert policy.count("Effect = \"Allow\"") == 1


def test_the_runtime_boundary_lets_a_bucket_policy_be_written_on_its_three_buckets_only():
    boundary = _iam("ops", "boundary")
    deny = next(st for st in boundary["Statement"] if st.get("Sid") == "DenyBucketPolicy")
    assert deny["Effect"] == "Deny"
    assert set(deny["Action"]) == {"s3:PutBucketPolicy", "s3:Put*PublicAccessBlock"}
    assert sorted(deny["NotResource"]) == sorted(f"arn:aws:s3:::warden-ops-{b}-*" for b in ("anchors", "witness",
                                                                                           "access-logs"))
    # And on those three only the deploy role (terraform) writes them: no role the runtime makes, whatever it is granted.
    by_deploy = next(st for st in boundary["Statement"] if st.get("Sid") == "BucketPolicyByDeployOnly")
    assert by_deploy["Effect"] == "Deny"
    assert by_deploy["Resource"] == "*"
    assert set(by_deploy["Action"]) == set(deny["Action"])
    assert by_deploy["Condition"] == {"ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/warden-ops-deploy"}}


def test_the_dev_stacks_alb_logs_every_request_into_a_bucket_only_elb_and_s3_logging_write():
    ecs = FULLSTACK / "ecs.tf"
    alb = _flat(_block(ecs, "aws_lb", "orders"))
    assert "access_logs { bucket = aws_s3_bucket.alb_logs.id enabled = true }" in alb
    assert "internal = true" in alb
    assert "force_destroy = true" in _block(ecs, "aws_s3_bucket", "alb_logs")  # the stack is destroyed regularly
    policy = _flat(_assert_private_tls_only_bucket(ecs, "alb_logs", keep_days=14))
    assert ('Principal = { Service = "logdelivery.elasticloadbalancing.amazonaws.com" } Action = "s3:PutObject" '
            'Resource = "${aws_s3_bucket.alb_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"'
            ) in policy
    assert 'Principal = { Service = "logging.s3.amazonaws.com" }' in policy
    assert '"aws:SourceArn" = aws_s3_bucket.alb_logs.arn' in policy
    assert policy.count('Effect = "Allow"') == 2
    own = _flat(_block(ecs, "aws_s3_bucket_logging", "alb_logs"))
    assert own == ("bucket = aws_s3_bucket.alb_logs.id target_bucket = aws_s3_bucket.alb_logs.id "
                   'target_prefix = "s3-access/" depends_on = [aws_s3_bucket_policy.alb_logs]')


def test_the_environments_may_write_the_policy_of_their_alb_log_bucket_and_no_other():
    for env in ("dev", "prod"):
        boundary = _iam(env, "boundary")
        denies = [st for st in boundary["Statement"] if st["Effect"] == "Deny"
                  and {"s3:Put*Policy", "s3:Put*Public*"} & set(st["Action"])]
        assert len(denies) == 1, denies
        assert denies[0]["NotResource"] == f"arn:aws:s3:::warden-{env}-alb-logs-*", denies
        grant = next(st for st in _iam(env, "deploy-ec2")["Statement"] if st.get("Sid") == "AlbLogsBucket")
        assert grant["Resource"] == [f"arn:aws:s3:::warden-{env}-alb-logs-*", f"arn:aws:s3:::warden-{env}-alb-logs-*/*"]


# ----------------------------------------------------------------- S6327: the order-events topic


def test_the_order_events_topic_is_encrypted_and_its_publisher_may_use_the_key_through_sns_only():
    lam = FULLSTACK / "lambda.tf"
    assert 'kms_master_key_id = "alias/aws/sns"' in _block(lam, "aws_sns_topic", "order_events")
    text = lam.read_text(encoding="utf-8")
    grants = re.findall(r'\{ Sid = "EncryptOrderEvents".*\}', text)
    assert len(grants) == 1
    assert ('Action = ["kms:GenerateDataKey*", "kms:Decrypt"], Resource = ["arn:aws:kms:${local.region}:'
            '${data.aws_caller_identity.current.account_id}:key/*"], Condition = { StringEquals = { "kms:ViaService" = '
            '"sns.${local.region}.amazonaws.com" } }') in grants[0]
    # Granted to checkout - the topic's one publisher - and to no other function.
    checkout = text[text.index("    checkout = ["):text.index("    order-processor = [")]
    assert "EncryptOrderEvents" in checkout
    assert "PublishOrderEvents" in checkout
    for env in ("dev", "prod"):
        ceiling = next(st for st in _iam(env, "boundary")["Statement"] if st.get("Sid") == "CeilingKms")
        via = ceiling["Condition"]["StringEquals"]["kms:ViaService"]
        assert any(v.startswith("sns.") for v in via)
        assert ceiling["Resource"] == "*"


# ----------------------------------------------------------------- S5332: HTTPS to the internal ALB


def test_the_internal_alb_answers_https_only_with_the_stacks_own_certificate():
    ecs, main = FULLSTACK / "ecs.tf", FULLSTACK / "main.tf"
    text = _code(ecs.read_text(encoding="utf-8"))
    assert len(re.findall(r'^resource "aws_lb_listener"', text, re.MULTILINE)) == 1
    https = _flat(_block(ecs, "aws_lb_listener", "https"))
    assert 'port = 443 protocol = "HTTPS" ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"' in https
    assert "certificate_arn = aws_acm_certificate.alb.arn" in https
    assert "moved { from = aws_lb_listener.http to = aws_lb_listener.https }" in _flat(text)  # in place, not replaced
    cert = _flat(_block(ecs, "tls_self_signed_cert", "alb"))
    assert "dns_names = [aws_lb.orders.dns_name]" in cert
    assert '"server_auth"' in cert
    assert 'algorithm = "ECDSA" ecdsa_curve = "P256"' in _flat(_block(ecs, "tls_private_key", "alb"))
    imported = _flat(_block(ecs, "aws_acm_certificate", "alb"))
    assert "certificate_body = tls_self_signed_cert.alb.cert_pem" in imported
    assert "create_before_destroy = true" in imported
    assert "validation_method" not in imported  # imported, never a requested (public) certificate
    sg = _flat(_block(main, "aws_security_group", "alb"))
    assert "from_port = 443 to_port = 443" in sg
    assert not re.search(r"from_port = 80\b", sg)
    lam = (FULLSTACK / "lambda.tf").read_text(encoding="utf-8")
    assert 'ALB_URL           = "https://${aws_lb.orders.dns_name}"' in lam
    assert "ALB_CA_PEM        = tls_self_signed_cert.alb.cert_pem" in lam
    assert 'value = "https://${aws_lb.orders.dns_name}"' in (FULLSTACK / "outputs.tf").read_text(encoding="utf-8")
    for env in ("dev", "prod"):
        own = next(st for st in _iam(env, "deploy-ec2")["Statement"] if st.get("Sid") == "AlbCertificateOwn")
        assert own["Condition"]["StringEquals"]["aws:ResourceTag/Environment"] == env
        assert "acm:ImportCertificate" in own["Action"]  # the in-place re-import at renewal sends no request tags
        regional = next(st for st in _iam(env, "boundary")["Statement"] if st.get("Sid") == "CeilingRegional")
        assert [a for a in regional["Action"] if a.startswith("acm:")] == ["acm:*Certificate"]  # never acm:*
        imp = next(st for st in _iam(env, "deploy-ec2")["Statement"] if st.get("Sid") == "AlbCertificateImport")
        assert imp["Condition"]["StringEquals"]["aws:RequestTag/Environment"] == env


# ----------------------------------------------------------------- the proving ground (not deployed; R52)


def test_the_lab_keeps_its_logs_14_days_at_no_cost():
    body = _block(LAB / "ecs.tf", "aws_cloudwatch_log_group", "service")
    assert re.search(r"retention_in_days\s*=\s*14\b", body)


def test_the_lab_database_is_public_by_design_and_reachable_from_one_address_over_tls_only():
    """S8793 kept (owner to review): WARDEN on the operator's laptop reaches it directly; private would need a billed
    NAT Gateway or bastion. What stands in for private is checked here, point by point."""
    rds, variables = LAB / "rds.tf", (LAB / "variables.tf").read_text(encoding="utf-8")
    db = _block(rds, "aws_db_instance", "this")
    assert "count = var.enable_rds ? 1 : 0" in _flat(db)
    assert re.search(r'variable "enable_rds" \{[^}]*default\s*=\s*false', variables)  # off unless asked for
    sg = _flat(_block(rds, "aws_security_group", "db"))
    assert sg.count("ingress {") == 1
    assert "from_port = 5432 to_port = 5432" in sg
    assert "cidr_blocks = [var.my_ip_cidr]" in sg
    assert "egress" not in sg
    # One address: the variable refuses anything but a /32 (and so 0.0.0.0/0).
    rule = re.search(r'variable "my_ip_cidr" \{.*?condition\s*=\s*(.+?)\n', variables, re.DOTALL).group(1)
    assert 'endswith(var.my_ip_cidr, "/32")' in rule
    assert "can(cidrnetmask(var.my_ip_cidr))" in rule  # IPv4 only: an IPv6 /32 is a huge range
    # TLS only: PostgreSQL 16, whose RDS default parameter group sets rds.force_ssl = 1 (15 and later), unchanged.
    assert int(re.search(r'engine_version\s*=\s*"(\d+)"', db).group(1)) >= 15
    assert "parameter_group_name" not in db
    assert "length(var.db_password) >= 16" in db
    assert re.search(r"publicly_accessible\s*=\s*true", db)  # the one finding this test explains


def test_the_lab_database_keeps_no_backups_because_the_free_plan_refuses_the_rules_seven_days():
    """S6364 kept (owner to review): the Free plan caps automated backups at 1 day, so 7 cannot be set; 0 leaves no
    backup behind a destroy."""
    raw = (LAB / "rds.tf").read_text(encoding="utf-8")
    assert "FreeTierRestrictionError" in raw
    assert "S6364" in raw
    db = _flat(_block(LAB / "rds.tf", "aws_db_instance", "this"))
    assert "backup_retention_period = 0" in db
    assert "skip_final_snapshot = true" in db


# ----------------------------------------------------------------- docker S2612: /tmp


def test_no_image_grants_write_to_others_and_the_runtimes_tmp_stays_debians_sticky_1777():
    """S2612 kept by design (owner to review): the runtime image also runs the front-door Lambdas under a user id
    Lambda chooses, so /tmp cannot belong to one user. Nothing grants it - Debian's own mode is checked at build -
    the root filesystem is read-only, the worker runs as one non-root user, and /tmp is a volume gone with the task."""
    chmod = re.compile(r"chmod\s+(?:-\S+\s+)*(?:[0-7]?[0-7][0-7][2367]|\S*o[+=]\S*w)\b")
    for dockerfile in [ROOT / "Dockerfile", ROOT / "Dockerfile.runtime", *ROOT.glob("scenarios/**/Dockerfile")]:
        text = _code(dockerfile.read_text(encoding="utf-8"))
        assert not chmod.search(text), dockerfile
        assert "--chmod" not in text, dockerfile
    runtime = (ROOT / "Dockerfile.runtime").read_text(encoding="utf-8")
    assert 'RUN test "$(stat -c \'%a %U\' /tmp)" = "1777 root"\nVOLUME ["/tmp"]\nUSER warden' in runtime
    compute = _flat(_block(RUNTIME / "compute.tf", "aws_ecs_task_definition", "zone"))
    assert 'user = "10001" readonlyRootFilesystem = true' in compute
    assert 'mountPoints = [{ sourceVolume = "tmp", containerPath = "/tmp", readOnly = false }]' in compute
    ci = (ROOT / ".github" / "workflows" / "ci-tool.yml").read_text(encoding="utf-8")
    assert "docker run --rm --read-only --entrypoint /opt/warden/bin/python warden-runtime:ci" in ci


# ----------------------------------------------------------------- by design: S6333 and S6428


def test_the_only_routes_without_an_authorizer_are_the_webhooks_and_the_approval_page():
    """S6333 kept (owner to review): the webhooks check a bearer secret in constant time before anything else, and
    the approval page needs the approver's passkey. No other route may be added without one."""
    front = (RUNTIME / "frontdoor.tf").read_text(encoding="utf-8")
    routes = re.findall(r'^resource "aws_apigatewayv2_route" "(\w+)"', front, re.MULTILINE)
    assert sorted(routes) == ["alertmanager", "approval", "datadog"]
    assert 'route_key = "POST /alertmanager"' in front
    assert 'route_key = "POST /datadog"' in front
    assert "S6333" in front
    from warden import webhooks
    assert not webhooks.authorized(None, ["s" * 32])
    assert not webhooks.authorized("Bearer " + "x" * 32, ["s" * 32])
    assert webhooks.authorized("Bearer " + "s" * 32, ["s" * 32])
    assert not webhooks.authorized("Bearer ", [""])


def test_the_privileged_pod_is_only_ever_dry_run_where_admission_must_refuse_it():
    """S6428 kept (owner to review): the negative Pod Security test. It is never applied for real anywhere."""
    pod = yaml.safe_load((ROOT / "k8s" / "test" / "privileged-must-fail.yaml").read_text(encoding="utf-8"))
    assert pod["metadata"]["namespace"] == "warden"
    assert pod["spec"]["containers"][0]["securityContext"]["privileged"]
    namespace = yaml.safe_load((ROOT / "k8s" / "namespace.yaml").read_text(encoding="utf-8"))
    assert namespace["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] == "restricted"
    uses = [line.strip() for p in [*ROOT.glob(".github/workflows/*.yml"), *ROOT.glob("scripts/*")] if p.is_file()
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines()
            if "privileged-must-fail" in line and not line.strip().startswith("#")]
    assert uses, uses
    assert all("--dry-run=server" in u for u in uses), uses
    kustomization = yaml.safe_load((ROOT / "k8s" / "kustomization.yaml").read_text(encoding="utf-8"))
    assert not any("test" in r for r in kustomization.get("resources", []))
    assert "S6428" in (ROOT / "k8s" / "test" / "privileged-must-fail.yaml").read_text(encoding="utf-8")
