"""SonarCloud's IaC findings PR 46 left open (2026-10-17), each fixed - with an equivalent that costs nothing where
there is one (owner, 2026-10-20: none stays open by design):

- S6258: the runtime's anchors and witness buckets log every access; the dev stack's ALB logs every request.
- S6327: the order-events topic is encrypted with the AWS-managed key, and its one publisher may use it through SNS.
- S5332: the internal ALB answers over HTTPS only, with the stack's own certificate (its caller's side, a real
  handshake included, is warden/tests/test_traffic_alb_tls.py, in the apps lane).
- S6413: the proving ground keeps its logs 14 days.
- S6364: the lab database keeps 7 days of backups, deleted with it.
- S2612: no image grants write to others; the runtime image checks Debian's sticky /tmp at build.
- S6333: the webhook routes pass the gateway only with their bearer secret (a Lambda REQUEST authorizer).
- S6428: the negative Pod Security test's pod is built when the test runs, never kept as a manifest.
- S8793 (the lab database's public endpoint): private, reached through an SSM port-forward via a t4g.nano that exists
  only with the database - no key, no inbound rule, no public address (owner, 2026-10-21).
"""

from __future__ import annotations

import json
import pathlib
import re

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
RUNTIME = ROOT / "infra" / "terraform" / "modules" / "warden-runtime"
FULLSTACK = ROOT / "infra" / "terraform" / "fullstack"
LAB = ROOT / "infra" / "terraform" / "proving-ground"


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
    return json.loads((ROOT / "infra" / "iam" / env / f"{kind}.json").read_text(encoding="utf-8"))


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
    by_deploy = next(st for st in boundary["Statement"] if st.get("Sid") == "PolicyByDeploy")
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
        assert "s3:*" not in grant["Action"]  # what the bucket's resources and force_destroy use, nothing more
        assert grant["Resource"] == f"arn:aws:s3:::warden-{env}-alb-logs-*"  # the bucket: its settings, never an object
        assert not [a for a in grant["Action"] if a in ("s3:Get*", "s3:GetObject", "s3:List*")]  # CodeRabbit, PR 62
        empty = next(st for st in _iam(env, "deploy-ec2")["Statement"] if st.get("Sid") == "AlbLogsEmptiedAtDestroy")
        assert empty["Action"] == ["s3:DeleteObject", "s3:DeleteObjectVersion"]  # force_destroy's, and no read
        assert empty["Resource"] == f"arn:aws:s3:::warden-{env}-alb-logs-*/*"


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
        # A new import only: ACM refuses tags on a re-import, so a request carrying the tag cannot overwrite an
        # existing certificate; re-import and retagging need the certificate's own Environment tag (AlbCertificateOwn).
        assert imp["Action"] == "acm:ImportCertificate"
        assert "acm:AddTagsToCertificate" in own["Action"]


# ----------------------------------------------------------------- the proving ground (not deployed; R52)


def test_the_lab_keeps_its_logs_14_days_at_no_cost():
    body = _block(LAB / "ecs.tf", "aws_cloudwatch_log_group", "service")
    assert re.search(r"retention_in_days\s*=\s*14\b", body)


def test_the_lab_database_is_private_and_reachable_only_from_the_ssm_tunnel_over_tls():
    """S8793 (owner, 2026-10-21): no public endpoint. PostgreSQL 16 (rds.force_ssl = 1 by default from 15 on, the
    parameter group unchanged), 5432 from the tunnel's security group only, the DSN through the local tunnel."""
    rds, variables = LAB / "rds.tf", (LAB / "variables.tf").read_text(encoding="utf-8")
    db = _block(rds, "aws_db_instance", "this")
    assert "count = var.enable_rds ? 1 : 0" in _flat(db)
    assert re.search(r'variable "enable_rds" \{[^}]*default\s*=\s*false', variables)  # off unless asked for
    assert re.search(r"publicly_accessible\s*=\s*false", db)
    assert int(re.search(r'engine_version\s*=\s*"(\d+)"', db).group(1)) >= 15
    assert "parameter_group_name" not in db
    assert "length(var.db_password) >= 16" in db
    sg = _flat(_block(rds, "aws_security_group", "db"))
    assert sg.count("ingress {") == 1
    assert "egress" not in sg
    assert "from_port = 5432 to_port = 5432 protocol = \"tcp\" security_groups = [aws_security_group.db_tunnel[0].id]" in sg
    assert "cidr" not in sg
    outputs = _flat((LAB / "outputs.tf").read_text(encoding="utf-8"))
    assert "@127.0.0.1:${var.db_tunnel_local_port}/${aws_db_instance.this[0].db_name}?sslmode=require" in outputs
    assert "--document-name AWS-StartPortForwardingSessionToRemoteHost" in outputs
    assert "--parameters host=${aws_db_instance.this[0].address},portNumber=5432," in outputs


def _lab_resources(path: pathlib.Path) -> list[tuple[str, str, str]]:
    text = _code(path.read_text(encoding="utf-8"))
    return [(kind, name, _flat(_block(path, kind, name)))
            for kind, name in re.findall(r'^(?:resource|data) "(\w+)" "(\w+)" \{', text, re.MULTILINE)]


def test_the_tunnel_exists_only_while_the_database_does():
    """Nothing of the tunnel is billed or reachable while enable_rds = false: every resource is counted on it."""
    found = _lab_resources(LAB / "db_tunnel.tf")
    assert {kind for kind, _, _ in found} >= {"aws_instance", "aws_vpc_endpoint", "aws_security_group", "aws_iam_role"}
    for kind, name, body in found:
        if kind == "aws_iam_policy_document":
            continue  # a data source computed locally, nothing in AWS
        assert body.startswith(("count = var.enable_rds ? 1 : 0",
                                "for_each = var.enable_rds ? local.db_tunnel_endpoints : toset([])")), (kind, name)


def test_the_tunnel_box_is_a_nano_with_no_key_no_inbound_and_no_public_address():
    box = _flat(_block(LAB / "db_tunnel.tf", "aws_instance", "db_tunnel"))
    assert 'instance_type = "t4g.nano"' in box
    assert "associate_public_ip_address = false" in box  # Sonar terraform:S6329
    for absent in ("key_name", "user_data", "ipv6"):
        assert absent not in box, absent
    assert 'http_endpoint = "enabled" http_tokens = "required" http_put_response_hop_limit = 1' in box  # IMDSv2
    assert 'volume_type = "gp3" volume_size = 8 encrypted = true delete_on_termination = true' in box
    assert "vpc_security_group_ids = [aws_security_group.db_tunnel[0].id]" in box
    tunnel_sg = _flat(_block(LAB / "db_tunnel.tf", "aws_security_group", "db_tunnel"))
    assert "ingress" not in tunnel_sg  # every rule is its own resource, checked below
    assert "egress" not in tunnel_sg
    # The role: AWS's SSM core policy and nothing else, under the lab's boundary.
    role = _flat(_block(LAB / "db_tunnel.tf", "aws_iam_role", "db_tunnel"))
    assert "permissions_boundary = local.permissions_boundary" in role
    attached = re.findall(r'policy_arn = "([^"]+)"', (LAB / "db_tunnel.tf").read_text(encoding="utf-8"))
    assert attached == ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]
    assert "aws_iam_role_policy" not in (LAB / "db_tunnel.tf").read_text(encoding="utf-8").replace(
        "aws_iam_role_policy_attachment", "")


def test_the_tunnel_talks_only_to_systems_manager_and_the_database():
    """No rule anywhere lets anything in to the box; out, 443 to the SSM endpoints' group and 5432 to the database's;
    the endpoints take 443 from the box only."""
    rules = [(kind, name, body) for tf in sorted(LAB.glob("*.tf")) for kind, name, body in _lab_resources(tf)
             if kind in ("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule",
                         "aws_security_group_rule")]
    tunnel = [(kind, name, body) for kind, name, body in rules
              if re.search(r"(?<!referenced_)security_group_id = aws_security_group\.db_tunnel\[0\]\.id", body)]
    assert sorted((kind, name) for kind, name, _ in tunnel) == [
        ("aws_vpc_security_group_egress_rule", "db_tunnel_db"), ("aws_vpc_security_group_egress_rule", "db_tunnel_ssm")]
    bodies = {name: body for _, name, body in tunnel}
    assert "referenced_security_group_id = aws_security_group.db_tunnel_endpoints[0].id from_port = 443 to_port = 443" \
        in bodies["db_tunnel_ssm"]
    assert "referenced_security_group_id = aws_security_group.db[0].id from_port = 5432 to_port = 5432" \
        in bodies["db_tunnel_db"]
    endpoint_rules = [body for _, _, body in rules if re.search(
        r"(?<!referenced_)security_group_id = aws_security_group\.db_tunnel_endpoints\[0\]\.id", body)]
    assert len(endpoint_rules) == 1
    assert "referenced_security_group_id = aws_security_group.db_tunnel[0].id from_port = 443 to_port = 443" \
        in endpoint_rules[0]
    assert "cidr" not in " ".join(body for _, _, body in tunnel) + endpoint_rules[0]
    endpoints = _flat(_block(LAB / "db_tunnel.tf", "aws_vpc_endpoint", "db_tunnel"))
    assert 'vpc_endpoint_type = "Interface"' in endpoints
    assert "private_dns_enabled = true" in endpoints
    assert 'toset(["ssm", "ssmmessages", "ec2messages"])' in (LAB / "db_tunnel.tf").read_text(encoding="utf-8")


def _statements(name: str) -> list[dict]:
    return json.loads((LAB / name).read_text(encoding="utf-8"))["Statement"]


def test_the_operator_may_start_only_a_nano_and_end_only_the_labs_own_instances():
    boundary = {st["Sid"]: st for st in _statements("operator-policy-boundary.json")}
    nano = boundary["DenyInstancesButANano"]
    assert nano["Effect"] == "Deny"
    assert nano["Action"] == "ec2:RunInstances"
    assert nano["Resource"] == "arn:aws:ec2:*:*:instance/*"
    assert nano["Condition"] == {"StringNotEquals": {"ec2:InstanceType": "t4g.nano"}}
    for name in ("operator-policy.json", "operator-policy-rds-eks.json"):
        for st in _statements(name):
            actions = st["Action"] if isinstance(st["Action"], list) else [st["Action"]]
            if st["Effect"] == "Allow" and {"ec2:TerminateInstances", "ec2:StopInstances"} & set(actions):
                assert st["Condition"]["StringEquals"]["aws:ResourceTag/Stack"] == "warden-proving-ground", st["Sid"]


def test_the_proof_run_reaches_the_database_through_the_tunnel_and_closes_it():
    script = (ROOT / "fault-lab" / "scripts" / "aws_proof.sh").read_text(encoding="utf-8")
    section = script[script.index("# ---------------------------------------------------------------------------"
                                  " E: RDS"):script.index("# --------------------------------------------------"
                                                          "------------------------- the bundle")]
    assert "command -v session-manager-plugin" in section
    assert "$(terraform -chdir=\"$TF_DIR\" output -raw db_tunnel_command)" in section
    assert '/dev/tcp/127.0.0.1/$TUNNEL_PORT' in section  # waits for the local port before using the DSN
    assert section.index("TUNNEL_PID=$!") < section.index("warden.cli run --incident inc-005")
    assert section.index("warden.cli run --incident inc-005") < section.rindex('kill "$TUNNEL_PID"')
    trap = script[script.index("teardown() {"):script.index("trap teardown EXIT")]
    assert 'kill "$TUNNEL_PID"' in trap  # an aborted run closes the tunnel too
    cost = _flat((LAB / "outputs.tf").read_text(encoding="utf-8"))
    assert "(var.enable_rds ? 0.0210 + 0.0428 : 0)" in cost


def test_the_lab_database_keeps_seven_days_of_backups_and_leaves_none_behind_a_destroy():
    """S6364 (owner, 2026-10-20: fixed, not kept): the rule's 7 days. Free: backup storage up to the database's size
    costs nothing, and a destroy deletes the automated backups with the instance and takes no final snapshot."""
    db = _flat(_block(LAB / "rds.tf", "aws_db_instance", "this"))
    retention = int(re.search(r"backup_retention_period = (\d+)", db).group(1))
    assert retention >= 7
    assert "delete_automated_backups = true" in db
    assert "skip_final_snapshot = true" in db


# ----------------------------------------------------------------- docker S2612: /tmp


def test_no_image_grants_write_to_others_and_the_runtimes_tmp_stays_debians_sticky_1777():
    """S2612 fixed: no Dockerfile grants write to others. The runtime image also runs the front-door Lambdas under a user
    id Lambda chooses, so /tmp stays Debian's sticky 1777, checked at build - the root filesystem is read-only, the
    worker runs as one non-root user, and /tmp is a volume gone with the task."""
    chmod = re.compile(r"chmod\s+(?:-\S+\s+)*(?:[0-7]?[0-7][0-7][2367]|\S*o[+=]\S*w)\b")
    for dockerfile in [ROOT / "warden" / "Dockerfile", ROOT / "warden" / "Dockerfile.runtime", *ROOT.glob("demo-app/app/**/Dockerfile")]:
        text = _code(dockerfile.read_text(encoding="utf-8"))
        assert not chmod.search(text), dockerfile
        assert "--chmod" not in text, dockerfile
    runtime = (ROOT / "warden" / "Dockerfile.runtime").read_text(encoding="utf-8")
    assert ('RUN useradd --create-home --uid 10001 warden \\\n'
            '    && test "$(stat -c \'%a %U\' /tmp)" = "1777 root"\nVOLUME ["/tmp"]\nUSER warden') in runtime
    compute = _flat(_block(RUNTIME / "compute.tf", "aws_ecs_task_definition", "zone"))
    assert 'user = "10001" readonlyRootFilesystem = true' in compute
    assert 'mountPoints = [{ sourceVolume = "tmp", containerPath = "/tmp", readOnly = false }]' in compute
    ci = (ROOT / ".github" / "workflows" / "warden-ci.yml").read_text(encoding="utf-8")
    assert "docker run --rm --read-only --entrypoint /opt/warden/bin/python warden-runtime:ci" in ci


# ----------------------------------------------------------------- S6333 and S6428


def test_the_webhook_routes_pass_the_gateway_only_with_their_bearer_secret():
    """S6333 (owner, 2026-10-20: fixed, not kept): /alertmanager and /datadog carry a Lambda REQUEST authorizer that
    checks the route's bearer secret at the gateway; the function keeps its own check. The approval page's routes keep
    their own gate - Slack sign-in and the approver's passkey - which an authorizer could not express."""
    front = (RUNTIME / "frontdoor.tf").read_text(encoding="utf-8")
    routes = re.findall(r'^resource "aws_apigatewayv2_route" "(\w+)"', front, re.MULTILINE)
    assert sorted(routes) == ["alertmanager", "approval", "datadog"]
    for name, key in (("alertmanager", "POST /alertmanager"), ("datadog", "POST /datadog")):
        route = _flat(_block(RUNTIME / "frontdoor.tf", "aws_apigatewayv2_route", name))
        assert f'route_key = "{key}"' in route
        assert 'authorization_type = "CUSTOM" authorizer_id = aws_apigatewayv2_authorizer.webhook.id' in route
    gate = _flat(_block(RUNTIME / "frontdoor.tf", "aws_apigatewayv2_authorizer", "webhook"))
    for setting in ('authorizer_type = "REQUEST"', "authorizer_uri = aws_lambda_function.webhook_auth.invoke_arn",
                    'authorizer_payload_format_version = "2.0"', "enable_simple_responses = true",
                    'identity_sources = ["$request.header.Authorization"]', "authorizer_result_ttl_in_seconds = 0"):
        assert setting in gate, setting
    fn = _flat(_block(RUNTIME / "frontdoor.tf", "aws_lambda_function", "webhook_auth"))
    assert 'handler = "webhook_auth.handler"' in fn
    assert "vpc_config" not in fn
    allow = _flat(_block(RUNTIME / "frontdoor.tf", "aws_iam_role_policy", "webhook_auth"))
    assert '["alertmanager-token", "alertmanager-token-previous", "datadog-webhook-token"]' in allow
    assert allow.count('Effect = "Allow"') == 2  # those three secrets, and its own log group
    invoke = _flat(_block(RUNTIME / "frontdoor.tf", "aws_lambda_permission", "webhook_auth"))
    assert "/authorizers/${aws_apigatewayv2_authorizer.webhook.id}" in invoke
    from warden import webhooks
    assert not webhooks.authorized("Bearer " + "x" * 32, ["s" * 32])  # the function's own check is still there
    assert webhooks.authorized("Bearer " + "s" * 32, ["s" * 32])


def _webhook_gate(monkeypatch, stored: dict, calls: list):
    """The authorizer, its zip checked against its source, with Secrets Manager played by `stored`."""
    import importlib.util
    import sys
    import types
    import zipfile

    class ClientError(Exception):
        """botocore's, as far as the gate uses it (the workflow scan's lane has no botocore)."""

        def __init__(self, error_response, operation_name):
            super().__init__(operation_name)
            self.response = error_response

    monkeypatch.setitem(sys.modules, "botocore", types.ModuleType("botocore"))
    monkeypatch.setitem(sys.modules, "botocore.exceptions", types.SimpleNamespace(
        ClientError=ClientError, BotoCoreError=type("BotoCoreError", (Exception,), {})))

    source = (RUNTIME / "webhook_auth" / "webhook_auth.py").read_bytes()
    with zipfile.ZipFile(RUNTIME / "webhook_auth.zip") as z:  # what is deployed is exactly the reviewed source
        assert z.namelist() == ["webhook_auth.py"]
        assert z.read("webhook_auth.py") == source

    def get_secret_value(SecretId):
        calls.append(SecretId)
        if SecretId not in stored:
            raise ClientError({"Error": {"Code": "ResourceNotFoundException"}}, "GetSecretValue")
        return {"SecretString": stored[SecretId]}

    monkeypatch.setitem(sys.modules, "boto3", types.SimpleNamespace(
        client=lambda name: types.SimpleNamespace(get_secret_value=get_secret_value)))
    monkeypatch.setenv("WARDEN_ENV", "ops")
    spec = importlib.util.spec_from_file_location("webhook_auth", RUNTIME / "webhook_auth" / "webhook_auth.py")
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    return gate


def test_the_webhook_gate_admits_the_routes_secret_only_and_fails_closed(monkeypatch):
    am, am_old, dd = "a" * 40, "b" * 40, "d" * 40
    calls: list = []
    gate = _webhook_gate(monkeypatch, {"warden/ops/alertmanager-token": am, "warden/ops/alertmanager-token-previous":
                                       am_old, "warden/ops/datadog-webhook-token": dd}, calls)

    def ask(route, header):
        return gate.handler({"routeKey": route, "headers": {} if header is None else {"authorization": header}},
                            None)["isAuthorized"]

    assert ask("POST /alertmanager", f"Bearer {am}") is True
    assert ask("POST /alertmanager", f"Bearer {am_old}") is True  # during a rotation
    assert ask("POST /datadog", f"Bearer {dd}") is True
    assert ask("POST /datadog", f"Bearer {am}") is False  # each route its own secret
    assert ask("POST /alertmanager", f"Bearer {dd}") is False
    for header in (None, "", am, f"bearer {am}", f"Basic {am}", "Bearer ", f"Bearer {am}x"):
        assert ask("POST /alertmanager", header) is False, header
    assert ask("GET /a/token", f"Bearer {am}") is False  # no other route is opened by it
    assert set(calls) == {"warden/ops/alertmanager-token", "warden/ops/alertmanager-token-previous",
                          "warden/ops/datadog-webhook-token"}


def test_the_webhook_gate_with_no_secret_admits_nothing(monkeypatch):
    calls: list = []
    gate = _webhook_gate(monkeypatch, {}, calls)
    assert gate.handler({"routeKey": "POST /datadog", "headers": {"authorization": "Bearer "}}, None) == {
        "isAuthorized": False}
    assert gate.handler({"routeKey": "POST /datadog", "headers": {"authorization": "Bearer x"}}, None) == {
        "isAuthorized": False}
    assert gate.handler({"routeKey": "POST /datadog", "headers": {"authorization": "Bearer x"}}, None) == {
        "isAuthorized": False}
    assert calls.count("warden/ops/datadog-webhook-token") == 3  # a missing secret is asked again, never remembered


def test_a_secret_rotated_out_stops_opening_its_route_at_once(monkeypatch):
    """CodeRabbit (PR 62): nothing is remembered between requests, so the old token fails on the very next request."""
    old, new = "o" * 40, "n" * 40
    stored, calls = {"warden/ops/datadog-webhook-token": old}, []
    gate = _webhook_gate(monkeypatch, stored, calls)

    def ask(token):
        return gate.handler({"routeKey": "POST /datadog", "headers": {"authorization": f"Bearer {token}"}}, None)

    assert ask(old) == {"isAuthorized": True}
    stored["warden/ops/datadog-webhook-token"] = new
    assert ask(old) == {"isAuthorized": False}
    assert ask(new) == {"isAuthorized": True}
    assert len(calls) == 3


def test_the_privileged_pod_is_built_only_to_be_refused_by_a_dry_run():
    """S6428 (owner, 2026-10-20: fixed, not kept by design): the negative Pod Security test is unchanged, but its pod is
    built when the test runs (fault-lab/scripts/negative_pod.py) - no manifest in the tree asks for a privileged container, so
    nothing applies one by mistake and no linter needs a skip. It only ever goes to a server-side dry run."""
    import json
    import subprocess
    import sys

    built = subprocess.run([sys.executable, str(ROOT / "fault-lab" / "scripts" / "negative_pod.py")], capture_output=True, text=True,
                           check=True).stdout
    pod = json.loads(built)
    assert pod["metadata"]["namespace"] == "warden"
    context = pod["spec"]["containers"][0]["securityContext"]
    assert context["privileged"] is True
    assert context["runAsUser"] == 0
    namespace = yaml.safe_load((ROOT / "infra" / "k8s" / "namespace.yaml").read_text(encoding="utf-8"))
    assert namespace["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] == "restricted"
    # No manifest anywhere asks for a privileged container any more.
    manifests = [p for p in ROOT.rglob("*.y*ml") if ".venv" not in p.parts and ".git" not in p.parts
                 and "node_modules" not in p.parts]
    assert manifests
    assert not [p for p in manifests if "privileged: true" in p.read_text(encoding="utf-8", errors="replace")]
    # Everything that builds it pipes it into a server-side dry run, and checks Pod Security's own reason.
    uses = [line.strip() for p in [*ROOT.glob(".github/workflows/*.yml"), *ROOT.glob("fault-lab/scripts/*.sh")]
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines()
            if "negative_pod.py" in line and not line.strip().startswith("#")]
    assert len(uses) == 2, uses
    ci = (ROOT / ".github" / "workflows" / "warden-ci.yml").read_text(encoding="utf-8")
    assert "python3 fault-lab/scripts/negative_pod.py | kubectl apply --dry-run=server -f - 2>err.txt" in ci
    assert 'grep -q "violates PodSecurity" err.txt' in ci
    # The proof run builds it on its own first (a generator failure stops the run, never reads as a refusal), sends
    # it to the same dry run and reports enforcement only on Pod Security's own reason (CodeRabbit, PR 62).
    proof = (ROOT / "fault-lab" / "scripts" / "aws_proof.sh").read_text(encoding="utf-8")
    assert '"$PY" "$HERE/scripts/negative_pod.py" > "$OUT/privileged-pod.json" || die' in proof
    assert 'kubectl apply --dry-run=server -f "$OUT/privileged-pod.json"' in proof
    lines = [line.strip() for line in proof.splitlines()]
    at = lines.index('if kubectl apply --dry-run=server -f "$OUT/privileged-pod.json" 2>"$OUT/reports/D-privileged-rejected.txt"; then')
    assert lines[at + 1].startswith('note "⛔ EKS ACCEPTED')
    assert lines[at + 2] == 'elif grep -q "violates PodSecurity" "$OUT/reports/D-privileged-rejected.txt"; then'
    assert lines[at + 3].startswith('note "✅ EKS rejected')
    assert lines[at + 4] == "else"
    assert "Pod Security NOT shown" in lines[at + 5]


# ----------------------------------------------------------------- the shop's own HTTPS (owner row 25)

def test_the_alb_reaches_the_orders_tasks_over_https_and_checks_their_health_over_https():
    """Sonar python:S5332 (row 25): the tasks serve HTTPS themselves (warden/tests/test_shop_https_s5332.py), so the target
    group and its health check speak HTTPS to them - the placeholder too, before the first deploy."""
    ecs = FULLSTACK / "ecs.tf"
    tg = _flat(_block(ecs, "aws_lb_target_group", "orders"))
    assert 'port = 8080 protocol = "HTTPS"' in tg
    assert re.search(r'health_check \{ protocol = "HTTPS" path = "/health"', tg), tg
    task = _flat(_block(ecs, "aws_ecs_task_definition", "orders_api"))
    assert "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256" in task
    assert "c.minimum_version = ssl.TLSVersion.TLSv1_2" in task
    assert "s.socket = c.wrap_socket(s.socket, server_side=True)" in task
    # The placeholder runs on Debian's slim Python, which carries openssl (Debian's ca-certificates needs it).
    assert 'image = "public.ecr.aws/docker/library/python:3.12-slim@sha256:' in task


def test_nothing_reaches_the_alb_or_the_orders_tasks_except_through_their_own_security_groups():
    """The tasks' certificate is unverified by design of the ALB, so nothing but the ALB may reach them, and nothing
    but the in-VPC Lambdas the ALB: no CIDR on either group, inline or in a separate rule in any .tf file
    (CodeRabbit, via lane H). Rules that only *name* these groups as a source (redis_apps) are fine."""
    main = FULLSTACK / "main.tf"
    alb, ecs = _flat(_block(main, "aws_security_group", "alb")), _flat(_block(main, "aws_security_group", "ecs"))
    for body in (alb, ecs):
        ingress = re.findall(r"ingress \{(.*?)\}", body)
        assert ingress
        assert not [rule for rule in ingress if "cidr" in rule], ingress
        assert not [rule for rule in ingress if "prefix_list" in rule], ingress
    assert "security_groups = [aws_security_group.lambda.id]" in alb
    assert "security_groups = [aws_security_group.alb.id]" in ecs
    for tf in sorted(ROOT.joinpath("infra", "terraform").rglob("*.tf")):
        text = _code(tf.read_text(encoding="utf-8"))
        for kind in ("aws_vpc_security_group_ingress_rule", "aws_security_group_rule"):
            for name in re.findall(rf'^resource "{kind}" "(\w+)"', text, re.MULTILINE):
                body = _flat(_block(tf, kind, name))
                target = re.search(r"security_group_id = (\S+)", body)
                assert not (target and re.search(r"aws_security_group\.(alb|ecs)\b", target.group(1))), \
                    (tf.name, name, "a separate rule opens the ALB or the orders tasks")
