"""Wave 4 infrastructure, checked offline: terraform/fullstack, the policies, k8s/fullstack, the
apps' handlers, the bootstrap SQL and the two pipeline workflows.

What `terraform validate` cannot see: names outside the prefix the boundary scopes IAM to, a role
without the boundary (CreateRole would be denied at apply), an alarm description that gives WARDEN
the answer, a manifest the restricted Pod Security level rejects, a policy over the size limit.
"""
from __future__ import annotations

import fnmatch
import json
import pathlib
import py_compile
import re

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
TF = ROOT / "terraform" / "fullstack"
TF_FILES = sorted(TF.glob("*.tf"))
K8S = ROOT / "k8s" / "fullstack"
APPS = ROOT / "scenarios" / "fullstack"
BOUNDARY = ROOT / "terraform" / "proving-ground" / "operator-policy-boundary.json"
OPERATOR_FS = TF / "operator-policy-fullstack.json"
POLICY_LIMIT = 6144  # managed policy, whitespace not counted

pytestmark = pytest.mark.skipif(not TF_FILES, reason="terraform/fullstack not in this checkout")


def _blocks(kind: str) -> list[tuple[str, str, str]]:
    """(type, name, body) of every top-level `resource "<kind>"` block (or all, kind='')."""
    out = []
    for tf in TF_FILES:
        text = tf.read_text(encoding="utf-8")
        for m in re.finditer(r'^resource "(\w+)" "(\w+)" \{\n(.*?)^\}', text, re.DOTALL | re.MULTILINE):
            if not kind or m.group(1) == kind:
                out.append((m.group(1), m.group(2), m.group(3)))
    return out


# --------------------------------------------------------------------------- terraform

NAME_ATTRS = ("name", "identifier", "cluster_identifier", "replication_group_id", "function_name",
              "cluster_name", "node_group_name", "family", "alarm_name")
# Names that are not AWS resource names: a stage called $default, an alias, an inline policy.
NOT_A_RESOURCE_NAME = {"aws_apigatewayv2_stage", "aws_lambda_alias", "aws_iam_role_policy"}


def test_the_name_prefix_is_the_one_the_boundary_scopes():
    main = (TF / "main.tf").read_text(encoding="utf-8")
    assert re.search(r'^\s+name\s+=\s+"warden-pg-fs"$', main, re.MULTILINE)
    assert re.search(r'Project\s+=\s+"warden-fullstack"', main)


def test_every_resource_name_carries_the_warden_pg_fs_prefix():
    checked, bad = 0, []
    for rtype, rname, body in _blocks(""):
        if rtype in NOT_A_RESOURCE_NAME:
            continue
        for attr, value in re.findall(r'^  (\w+)\s*=\s*"(.*)"\s*$', body, re.MULTILINE):
            if attr not in NAME_ATTRS:
                continue
            checked += 1
            if not ("warden-pg-fs-" in value or "${local.name}" in value
                    or re.search(r"\$\{aws_\w+\.\w+\.name\}", value)):
                bad.append(f"{rtype}.{rname}.{attr} = {value!r}")
    assert checked > 30, "the parser found almost no names - it is broken, not the terraform"
    assert not bad, "\n".join(bad)


def test_every_iam_role_carries_the_permissions_boundary():
    roles = _blocks("aws_iam_role")
    assert len(roles) >= 7  # lambda (six), ecs exec + task, eks cluster + node, catalog pod, reader
    missing = [name for _, name, body in roles if not re.search(r"^\s+permissions_boundary\s*=", body, re.MULTILINE)]
    assert not missing, f"roles without a permissions boundary (CreateRole is denied): {missing}"
    variables = (TF / "variables.tf").read_text(encoding="utf-8")
    assert re.search(r'variable "permissions_boundary_name".*?default\s*=\s*"WardenProvingGroundBoundary"',
                     variables, re.DOTALL)


def _tf_text() -> str:
    return "".join(f.read_text(encoding="utf-8") for f in TF_FILES)


def test_aurora_is_not_terraform_and_no_database_password_exists():
    """2026-09-26: the Free plan creates Aurora only in express configuration, which the provider
    cannot do and which has IAM authentication only (aurora_express.py creates it)."""
    text = _tf_text()
    for gone in ('resource "aws_rds_cluster', 'resource "aws_db_subnet_group"', 'resource "random_password"',
                 'resource "aws_security_group" "aurora"', 'variable "db_master_password"', "master_password"):
        assert gone not in text, gone
    assert not re.search(r"(?i)\w*password\w*\s*=", text), "a password attribute in terraform"
    alarms = (TF / "alarms.tf").read_text(encoding="utf-8")
    assert alarms.count("DBClusterIdentifier = local.aurora_cluster") == 2
    assert 'aurora_cluster = "${local.name}-aurora"' in (TF / "data.tf").read_text(encoding="utf-8")


def test_the_node_type_is_free_tier_eligible():
    eks = (TF / "eks.tf").read_text(encoding="utf-8")
    assert re.findall(r"instance_types\s*=\s*\[(.*?)\]", eks) == ['"m7i-flex.large"']


def test_catalog_api_gets_its_role_through_pod_identity():
    eks = (TF / "eks.tf").read_text(encoding="utf-8")
    assert "eks-pod-identity-agent = null" in eks
    assoc = next(b for _, n, b in _blocks("aws_eks_pod_identity_association") if n == "catalog")
    assert 'namespace       = "shop"' in assoc and 'service_account = "catalog-api"' in assoc
    assert "aws_iam_role.catalog_pod.arn" in assoc
    role = next(b for _, n, b in _blocks("aws_iam_role") if n == "catalog_pod")
    assert 'Principal = { Service = "pods.eks.amazonaws.com" }' in role and "sts:TagSession" in role
    sa = next(d for d in _k8s_docs() if d["kind"] == "ServiceAccount" and d["metadata"]["name"] == "catalog-api")
    assert sa["metadata"]["namespace"] == "shop"
    dep = next(d for d in _k8s_docs() if d["kind"] == "Deployment" and d["metadata"]["name"] == "catalog-api")
    assert dep["spec"]["template"]["spec"]["serviceAccountName"] == "catalog-api"


def test_rds_db_connect_is_scoped_to_one_database_user_per_identity():
    text = _tf_text()
    assert "dbuser:*/${u}" in text and 'for u in ["app", "catalog"]' in text
    assert text.count('"rds-db:connect"') == 5, "one grant per identity: processor, reconciler, task, pod, reader"
    assert not re.search(r"dbuser:[^\s\"]*/\*", text), "a grant for every database user"
    lam = (TF / "lambda.tf").read_text(encoding="utf-8")
    assert re.search(r'Sid = "ConnectAsApp".*local\.dbuser_arn\["app"\]', lam)
    assert re.search(r'Sid = "ConnectAsCatalog".*local\.dbuser_arn\["catalog"\]', lam)
    grants = {n: b for _, n, b in _blocks("aws_iam_role_policy") if "rds-db:connect" in b}
    assert 'local.dbuser_arn["app"]' in grants["ecs_task_db"]
    assert 'local.dbuser_arn["catalog"]' in grants["catalog_pod_db"]
    reader = (TF / "reader.tf").read_text(encoding="utf-8")
    assert 'dbuser:*/warden_ro"]' in reader and reader.count('"rds-db:connect"') == 1


def test_one_nat_gateway_gives_the_private_subnets_their_way_out():
    main = (TF / "main.tf").read_text(encoding="utf-8")
    assert len(_blocks("aws_nat_gateway")) == 1 and len(_blocks("aws_eip")) == 1
    nat = _blocks("aws_nat_gateway")[0][2]
    assert "subnet_id     = aws_subnet.public[0].id" in nat and "aws_eip.nat.id" in nat
    private = next(b for _, n, b in _blocks("aws_route_table") if n == "private")
    assert 'cidr_block     = "0.0.0.0/0"' in private and "nat_gateway_id = aws_nat_gateway.this.id" in private
    assert "single-AZ" in main  # the known weakness is said where the NAT is


def test_code_fields_belong_to_the_apps_pipeline():
    lam = (TF / "lambda.tf").read_text(encoding="utf-8")
    assert re.search(r"ignore_changes = \[filename, source_code_hash", lam)
    assert re.search(r"ignore_changes = \[function_version\]", lam)
    ecs = (TF / "ecs.tf").read_text(encoding="utf-8")
    assert re.search(r"ignore_changes = \[task_definition", ecs)
    assert not list(TF.glob("*kubernetes*")) and 'resource "kubernetes_' not in "".join(
        t.read_text(encoding="utf-8") for t in TF_FILES), "k8s objects belong to the apps pipeline"


EC2_DESCRIPTION = re.compile(r"^[0-9A-Za-z_ .:/()#,@\[\]+=&;{}!$*-]*$")


def test_security_group_descriptions_are_ones_ec2_accepts():
    found = []
    for rtype, _, body in _blocks(""):
        if rtype.startswith(("aws_security_group", "aws_vpc_security_group")):
            found += re.findall(r'^\s+description\s*=\s*"(.*)"\s*$', body, re.MULTILINE)
    assert len(found) >= 8
    bad = [d for d in found if not EC2_DESCRIPTION.match(d.replace("${each.key}", "x")) or len(d) > 255]
    assert not bad, bad


# Words that would name a fault's CAUSE (docs/WAVE4-FULLSTACK.md section 7). The symptom may be
# named ("5xx", "memory usage", "not ready"); the cause may not.
CAUSE_WORDS = ["reserved concurrency", "concurrency", "keyerror", "health path", "healthz", "timeout",
               "timed out", "iam", "permission", "accessdenied", "access denied", "poison", "disabled",
               "event source", "mapping", "queue policy", "provisioned", "rcu", "wcu", "security group",
               "filler", "failover", "lock", "index", "read-only", "reader endpoint", "image", "tag",
               "secret", "password", "rotat", "oom", "out of memory", "config", "readiness", "probe",
               "port", "requests", "unschedul", "cpu request", "crashloop", "rule", "regression",
               "deploy", "version", "alias", "env", "table name", "throttl", "capacity"]


def _alarms() -> dict[str, str]:
    text = (TF / "alarms.tf").read_text(encoding="utf-8")
    return dict(re.findall(r'^    ([a-z0-9-]+) = \{.*?desc\s*=\s*"([^"]+)"', text, re.DOTALL | re.MULTILINE))


def test_there_is_an_alarm_for_every_symptom_family():
    alarms = _alarms()
    assert len(alarms) >= 18, sorted(alarms)
    catalog = ROOT / "scenarios" / "catalog" / "wave4-fullstack.yaml"
    if catalog.exists():  # every alarm the harness polls must exist
        polled = set(re.findall(r"^\s+alarm: warden-pg-fs-([a-z0-9-]+)", catalog.read_text(encoding="utf-8"), re.MULTILINE))
        assert polled and polled <= set(alarms), sorted(polled - set(alarms))


@pytest.mark.parametrize("name,desc", sorted(_alarms().items()) if TF_FILES else [])
def test_alarm_descriptions_name_the_symptom_never_the_cause(name, desc):
    words = re.findall(r"[a-z0-9-]+", desc.lower())
    text = " ".join(words)
    leaked = [w for w in CAUSE_WORDS if (f" {w} " in f" {text} " if " " in w or len(w) <= 4
                                         else any(x.startswith(w) for x in words))]
    assert not leaked, f"{name}: {desc!r} names a cause: {leaked}"


def test_no_account_id_or_email_in_any_file():
    files = TF_FILES + [OPERATOR_FS, BOUNDARY, TF / "README.md", TF / "terraform.tfvars.example"]
    files += [p for p in list(K8S.rglob("*")) + list(APPS.rglob("*")) if p.is_file() and "__pycache__" not in p.parts]
    for f in files:
        text = f.read_text(encoding="utf-8")
        assert not re.search(r"(?<![\d.])\d{12}(?![\d.])", text), f"12-digit number in {f}"
        assert not re.search(r"[\w.+-]+@(?!example\.com)[\w-]+\.[\w.]+", text), f"email in {f}"


# --------------------------------------------------------------------------- policies

def _stmts(path):
    return json.loads(path.read_text(encoding="utf-8"))["Statement"]


def _list(v):
    return [v] if isinstance(v, str) else list(v or [])


OPERATOR = ROOT / "terraform" / "proving-ground" / "operator-policy.json"


@pytest.mark.parametrize("path", [BOUNDARY, OPERATOR_FS, OPERATOR], ids=lambda p: p.name)
def test_policy_is_valid_and_under_the_managed_policy_limit(path):
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["Version"] == "2012-10-17"
    size = len("".join(path.read_text(encoding="utf-8").split()))
    assert size <= POLICY_LIMIT, f"{path.name}: {size} chars > {POLICY_LIMIT}"
    sids = [s["Sid"] for s in doc["Statement"]]
    assert len(sids) == len(set(sids))


def _denied(action: str, resource: str) -> bool:
    for st in _stmts(BOUNDARY):
        if st["Effect"] != "Deny" or "Condition" in st:
            continue
        if not any(fnmatch.fnmatchcase(action.lower(), a.lower()) for a in _list(st.get("Action"))):
            continue
        if "Resource" in st and any(fnmatch.fnmatchcase(resource, r) for r in _list(st["Resource"])):
            return True
        if "NotResource" in st and not any(fnmatch.fnmatchcase(resource, r) for r in _list(st["NotResource"])):
            return True
    return False


GUARDED = {
    "secretsmanager:DeleteSecret": "arn:aws:secretsmanager:ap-south-2:111122223333:secret:{}-AbCdEf",
    "secretsmanager:PutSecretValue": "arn:aws:secretsmanager:ap-south-2:111122223333:secret:{}-AbCdEf",
    "dynamodb:DeleteTable": "arn:aws:dynamodb:ap-south-2:111122223333:table/{}",
    "rds:DeleteDBCluster": "arn:aws:rds:ap-south-2:111122223333:cluster:{}",
}


@pytest.mark.parametrize("action", sorted(GUARDED))
def test_the_boundary_still_denies_destroying_data_that_is_not_ours(action):
    for name in ("prod-db", "warden-pg-other", "billing"):
        assert _denied(action, GUARDED[action].format(name)), f"{action} on {name} is no longer denied"
    assert not _denied(action, GUARDED[action].format("warden-pg-fs-thing")), \
        f"{action} on warden-pg-fs-* is still denied - the stack could not be destroyed"


def test_the_boundary_still_denies_key_deletion_everywhere():
    assert _denied("kms:ScheduleKeyDeletion", "arn:aws:kms:ap-south-2:111122223333:key/x")
    assert _denied("rds:DeleteDBClusterSnapshot", "arn:aws:rds:ap-south-2:111122223333:cluster-snapshot:warden-pg-fs-x")


def test_the_boundary_allows_the_new_services_only_on_our_names():
    st = next(s for s in _stmts(BOUNDARY) if s["Sid"] == "CeilingFullstackServicesOnWardenPgFsOnly")
    for r in _list(st["Resource"]):
        assert "warden-pg-fs-" in r or r.endswith(("parametergroup:default.*", "/apis*", "/tags/*")), r
    slr = next(s for s in _stmts(BOUNDARY) if s["Sid"] == "CeilingServiceLinkedRolesForTheseServicesOnly")
    assert "elasticache.amazonaws.com" in slr["Condition"]["StringEquals"]["iam:AWSServiceName"]


def test_only_the_operator_may_log_in_as_postgres_and_the_ceiling_allows_it():
    """bootstrap-db and the harness's admin connection sign a token as the master user with the
    operator's own credentials. Nothing else in the repository may be granted that login."""
    st = next(s for s in _stmts(OPERATOR) if s["Sid"] == "AuroraIamLoginAsPostgres")
    assert (st["Effect"], st["Action"], st["Resource"]) == (
        "Allow", "rds-db:connect", "arn:aws:rds-db:ap-south-2:*:dbuser:*/postgres")
    assert len(json.dumps(json.loads(OPERATOR.read_text(encoding="utf-8")), separators=(",", ":"))) <= POLICY_LIMIT
    assert any("rds-db:connect" in _list(s["Action"]) for s in _stmts(BOUNDARY) if s["Effect"] == "Allow")
    assert "dbuser:*/postgres" not in _tf_text()


def test_the_fullstack_operator_policy_can_build_the_nat_and_pass_the_pod_role():
    actions = {a for s in _stmts(OPERATOR_FS) if s["Effect"] == "Allow" for a in _list(s["Action"])}
    assert {"ec2:AllocateAddress", "ec2:CreateNatGateway", "ec2:DeleteNatGateway", "ec2:ReleaseAddress"} <= actions
    passed = next(s for s in _stmts(OPERATOR_FS) if s["Sid"] == "PassWardenPgFsRolesOnlyToTheseServices")
    assert "pods.eks.amazonaws.com" in passed["Condition"]["StringEquals"]["iam:PassedToService"]


def test_the_fullstack_operator_policy_fits_inside_the_boundary():
    ceiling = [a for s in _stmts(BOUNDARY) if s["Effect"] == "Allow" for a in _list(s["Action"])]
    outside = [a for s in _stmts(OPERATOR_FS) if s["Effect"] == "Allow" for a in _list(s["Action"])
               if not any(fnmatch.fnmatchcase(a.lower(), c.lower()) or a.lower() == c.lower() for c in ceiling)
               and not any(fnmatch.fnmatchcase(c.lower(), a.lower()) for c in ceiling)]
    assert not outside, f"granted but outside the ceiling: {outside}"


def test_the_fullstack_operator_policy_never_widens_iam():
    for st in _stmts(OPERATOR_FS):
        for a in _list(st["Action"]):
            if a.startswith(("iam:", "sts:AssumeRole")) and a not in ("iam:CreateServiceLinkedRole", "iam:GetRole"):
                assert all("warden-pg-fs-" in r for r in _list(st["Resource"])), (st["Sid"], a)
            assert a not in ("iam:*", "*", "iam:CreatePolicy", "iam:AttachUserPolicy"), a


# --------------------------------------------------------------------------- kubernetes

def _k8s_docs() -> list[dict]:
    docs = []
    for f in sorted(K8S.glob("*.yaml")):
        docs += [d for d in yaml.safe_load_all(f.read_text(encoding="utf-8")) if d]
    return docs


def test_the_kustomization_lists_every_manifest():
    kust = yaml.safe_load((K8S / "kustomization.yaml").read_text(encoding="utf-8"))
    assert sorted(kust["resources"]) == sorted(p.name for p in K8S.glob("*.yaml") if p.name != "kustomization.yaml")


def test_the_namespace_enforces_restricted_pod_security():
    ns = next(d for d in _k8s_docs() if d["kind"] == "Namespace")
    assert ns["metadata"]["name"] == "shop"
    assert ns["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] == "restricted"
    assert ns["metadata"]["labels"]["project"] == "warden-fullstack"


@pytest.mark.parametrize("name,replicas", [("catalog-api", 2), ("cart-worker", 1)])
def test_deployments_pass_restricted_pod_security(name, replicas):
    dep = next(d for d in _k8s_docs() if d["kind"] == "Deployment" and d["metadata"]["name"] == name)
    assert dep["metadata"]["namespace"] == "shop" and dep["spec"]["replicas"] == replicas
    # WARDEN selects pods by app=<deployment name>.
    assert dep["spec"]["selector"]["matchLabels"] == {"app": name}
    pod = dep["spec"]["template"]["spec"]
    assert dep["spec"]["template"]["metadata"]["labels"]["app"] == name
    assert pod["securityContext"]["runAsNonRoot"] is True
    assert pod["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
    assert not pod.get("hostNetwork") and not pod.get("hostPID") and not pod.get("hostIPC")
    assert all("hostPath" not in v for v in pod.get("volumes", []))
    for c in pod["containers"]:
        sc = c["securityContext"]
        assert sc["allowPrivilegeEscalation"] is False and sc["readOnlyRootFilesystem"] is True
        assert sc["capabilities"]["drop"] == ["ALL"] and not sc.get("privileged")
        assert c["resources"]["requests"] and c["resources"]["limits"]
        assert "livenessProbe" in c
        assert c["image"] == "__IMAGE__"


def test_secret_is_a_template_with_no_real_value():
    secret = next(d for d in _k8s_docs() if d["kind"] == "Secret")
    assert secret["metadata"]["name"] == "catalog-secret"
    assert all(re.fullmatch(r"__[A-Z_]+__", v) for v in secret["stringData"].values())
    assert "data" not in secret
    # No password (IAM login); the one key is what catalog-api refuses to start without (fs-23).
    assert list(secret["stringData"]) == ["CATALOG_SIGNING_KEY"]
    assert '"CATALOG_SIGNING_KEY"' in (APPS / "app" / "app.py").read_text(encoding="utf-8")
    manifests = "".join(f.read_text(encoding="utf-8") for f in K8S.glob("*.yaml"))
    assert not re.search(r"(?i)password", re.sub(r"#[^\n]*", "", manifests))


def test_hpa_pdb_and_readiness():
    docs = _k8s_docs()
    hpa = next(d for d in docs if d["kind"] == "HorizontalPodAutoscaler")
    assert (hpa["spec"]["minReplicas"], hpa["spec"]["maxReplicas"]) == (2, 4)
    assert hpa["spec"]["metrics"][0]["resource"]["target"]["averageUtilization"] == 70
    assert any(d["kind"] == "PodDisruptionBudget" for d in docs)
    catalog = next(d for d in docs if d["kind"] == "Deployment" and d["metadata"]["name"] == "catalog-api")
    assert catalog["spec"]["template"]["spec"]["containers"][0]["readinessProbe"]["httpGet"]["port"] == 8080


def test_warden_is_bound_in_shop_only_to_the_real_read_only_clusterrole():
    docs = _k8s_docs()
    rb = next(d for d in docs if d["kind"] == "RoleBinding")
    assert rb["metadata"]["namespace"] == "shop"
    assert rb["subjects"] == [{"kind": "ServiceAccount", "name": "warden", "namespace": "shop"}]
    rbac = [d for d in yaml.safe_load_all((ROOT / "k8s" / "rbac.yaml").read_text(encoding="utf-8")) if d]
    role = next(d for d in rbac if d["kind"] == "ClusterRole")
    assert rb["roleRef"] == {"kind": "ClusterRole", "name": role["metadata"]["name"],
                             "apiGroup": "rbac.authorization.k8s.io"}
    assert not any(d["kind"] == "ClusterRoleBinding" for d in docs)
    assert all(set(r["verbs"]) <= {"get", "list"} for r in role["rules"])


# --------------------------------------------------------------------------- apps

def _terraform_lambdas() -> list[str]:
    text = (TF / "lambda.tf").read_text(encoding="utf-8")
    block = text[text.index("  lambdas = {"):text.index("  lambda_statements")]
    return re.findall(r"^    ([a-z-]+) = \{$", block, re.MULTILINE)


def test_every_terraform_lambda_has_a_handler():
    names = _terraform_lambdas()
    assert sorted(names) == ["checkout", "notifier", "ops", "order-processor", "reconciler", "traffic"]
    assert 'handler          = "app.handler"' in (TF / "lambda.tf").read_text(encoding="utf-8")
    for fn in names:
        src = (APPS / "lambdas" / fn / "app.py").read_text(encoding="utf-8")
        assert re.search(r"^def handler\(event, context\):", src, re.MULTILINE), fn


def test_every_app_file_compiles(tmp_path):
    files = [p for p in APPS.rglob("*.py")]
    assert len(files) >= 7
    for f in files:
        py_compile.compile(str(f), cfile=str(tmp_path / "x.pyc"), doraise=True)


# The fault flags scenarios/ops_fullstack.py flips must exist at their baseline value from the start,
# so a variable NAME never appears only during a fault.
BASELINE_FLAGS = {"checkout": {"CHECKOUT_PAYLOAD_SCHEMA": "v1", "DDB_EXTRA_LATENCY_MS": "0"},
                  "reconciler": {"RECONCILE_LOOKUP": "by_id"}}


def test_fault_flags_are_set_to_their_baseline_and_read_by_the_code():
    lam = (TF / "lambda.tf").read_text(encoding="utf-8")
    for fn, flags in BASELINE_FLAGS.items():
        src = (APPS / "lambdas" / fn / "app.py").read_text(encoding="utf-8")
        for name, base in flags.items():
            assert re.search(rf'{name}\s*=\s*"{base}"', lam), f"{fn} {name} baseline not set in terraform"
            assert f'"{name}"' in src, f"{fn} never reads {name}"
    checkout = (APPS / "lambdas" / "checkout" / "app.py").read_text(encoding="utf-8")
    assert 'item["sku_id"]' in checkout  # fs-01: v2 reads a field real payloads do not carry
    assert "ALLOC_MB" in (APPS / "app" / "app.py").read_text(encoding="utf-8")


def test_the_slow_index_is_the_one_the_harness_drops():
    sql = (APPS / "sql" / "bootstrap.sql").read_text(encoding="utf-8")
    assert "CREATE INDEX IF NOT EXISTS orders_customer_id_idx ON orders (customer_id)" in sql
    assert "customer_id = c.customer_id" in (APPS / "lambdas" / "reconciler" / "app.py").read_text(encoding="utf-8")


def test_the_bootstrap_gives_warden_ro_pg_monitor_and_nothing_more():
    text = (APPS / "sql" / "bootstrap.sql").read_text(encoding="utf-8")
    code = re.sub(r"--[^\n]*", "", text)
    mentions = [" ".join(s.split()) for s in re.split(r";", code) if "warden_ro" in s]
    allowed = [r"^GRANT pg_monitor TO warden_ro$", r"^GRANT rds_iam TO app, catalog, warden_ro$"]
    grants = [m for m in mentions if m.upper().startswith(("GRANT", "ALTER"))]
    assert "GRANT pg_monitor TO warden_ro" in grants
    assert all(any(re.match(a, g) for a in allowed) for g in grants), grants
    assert "CREATE ROLE warden_ro LOGIN" in code


# --------------------------------------------------------------------------- pipelines

def _workflow(name: str) -> dict:
    doc = yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8"))
    doc["on"] = doc.pop(True, doc.get("on"))  # PyYAML reads the key `on` as True
    return doc


def test_infra_workflow_triggers_only_on_terraform_and_applies_only_on_dispatch():
    wf = _workflow("infra.yml")
    # The infra pipeline's own test file counts as infra: the tool CI skips infra-only changes.
    assert all(p.startswith(("terraform/fullstack/", ".github/workflows/infra.yml", "tests/test_fullstack_infra.py"))
               for p in wf["on"]["push"]["paths"] + wf["on"]["pull_request"]["paths"])
    assert wf["on"]["workflow_dispatch"]["inputs"]["action"]["options"] == ["plan", "apply", "destroy"]
    assert wf["jobs"]["run"]["if"] == "github.event_name == 'workflow_dispatch'"
    assert wf["jobs"]["run"]["permissions"]["id-token"] == "write"
    text = (ROOT / ".github" / "workflows" / "infra.yml").read_text(encoding="utf-8")
    assert "aws-access-key-id" not in text and "AWS_SECRET_ACCESS_KEY" not in text


def test_apps_workflow_triggers_only_on_app_code_and_deploys_only_on_dispatch():
    wf = _workflow("apps.yml")
    paths = wf["on"]["push"]["paths"]
    assert not any(p.startswith("terraform/") for p in paths)
    assert "scenarios/fullstack/**" in paths and "k8s/fullstack/**" in paths
    assert wf["jobs"]["deploy"]["if"] == "github.event_name == 'workflow_dispatch'"
    text = (ROOT / ".github" / "workflows" / "apps.yml").read_text(encoding="utf-8")
    assert not re.search(r"^\s*(- run: |run: )?terraform ", text, re.MULTILINE), "the apps pipeline calls terraform"
    assert "aws-access-key-id" not in text


def test_bootstrap_sql_has_no_password_and_no_placeholder():
    """2026-09-26: IAM authentication only. Every role gets rds_iam; no PASSWORD clause and no
    placeholder of any kind remains (the file is sent as it is)."""
    text = (ROOT / "scenarios" / "fullstack" / "sql" / "bootstrap.sql").read_text(encoding="utf-8")
    code = re.sub(r"--[^\n]*", "", text)
    assert "{" not in text and "}" not in text and "__" not in code
    assert not re.search(r"(?i)\bpassword\b", code)
    assert "GRANT rds_iam TO app, catalog, warden_ro" in code
    for role in ("app", "catalog", "warden_ro"):
        assert f"CREATE ROLE {role} LOGIN" in code


def test_the_stack_carries_its_own_budget_alarm():
    """The proving ground's budget went with its teardown; a ~USD 0.50/h stack must not run unwatched."""
    tf = (ROOT / "terraform" / "fullstack" / "main.tf").read_text(encoding="utf-8")
    assert 'resource "aws_budgets_budget" "guard"' in tf and 'name         = "${local.name}-guard"' in tf
    assert 'type = "FORECASTED"' in tf and 'type = "ACTUAL"' in tf
    pol = json.loads((ROOT / "terraform" / "fullstack" / "operator-policy-fullstack.json").read_text(encoding="utf-8"))
    budget = [s for s in pol["Statement"] if any(a.startswith("budgets:") for a in s["Action"])]
    assert budget and all(s["Resource"] == "arn:aws:budgets::*:budget/warden-pg-fs-*" for s in budget)
    wf = (ROOT / ".github" / "workflows" / "infra.yml").read_text(encoding="utf-8")
    assert "TF_VAR_budget_email: ${{ secrets.WARDEN_FS_BUDGET_EMAIL }}" in wf


# --------------------------------------------------------------------------- aurora_express.py
#
# The Free plan's Aurora is created by a script, not by terraform. These run it against a fake RDS
# client: the calls it makes, idempotency, the guard, and what lands in the secret and stack.json.


def _aurora():
    import importlib.util

    spec = importlib.util.spec_from_file_location("aurora_express", TF / "aurora_express.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _NotFound(Exception):
    pass


class FakeRds:
    """Just enough RDS: a cluster, its instances, waiters that settle the state at once."""

    def __init__(self, cluster=None):
        self.cluster, self.instances, self.calls = cluster, {}, []
        self.exceptions = type("E", (), {"DBClusterNotFoundFault": _NotFound})

    def _log(self, name, **kw):
        self.calls.append((name, kw))

    def describe_db_clusters(self, DBClusterIdentifier):
        if self.cluster is None:
            raise _NotFound(DBClusterIdentifier)
        members = [{"DBInstanceIdentifier": i, "IsClusterWriter": d["writer"]} for i, d in self.instances.items()]
        return {"DBClusters": [{**self.cluster, "DBClusterMembers": members}]}

    def describe_db_instances(self, Filters):
        return {"DBInstances": [{"DBInstanceIdentifier": i, "DBInstanceStatus": d["status"],
                                 "AvailabilityZone": d["az"], "Endpoint": {"Address": f"{i}.x.rds.example"}}
                                for i, d in self.instances.items()]}

    def create_db_cluster(self, **kw):
        self._log("create_db_cluster", **kw)
        self.cluster = {"DBClusterIdentifier": kw["DBClusterIdentifier"], "Status": "creating",
                        "Endpoint": "warden-pg-fs-aurora.cluster-x.rds.example",
                        "ReaderEndpoint": "warden-pg-fs-aurora.cluster-ro-x.rds.example",
                        "AvailabilityZones": ["az-a", "az-b", "az-c"]}
        self.instances["warden-pg-fs-aurora-instance-1"] = {"writer": True, "status": "creating", "az": "az-a"}

    def modify_db_cluster(self, **kw):
        self._log("modify_db_cluster", **kw)
        if "ServerlessV2ScalingConfiguration" in kw:
            self.cluster["ServerlessV2ScalingConfiguration"] = kw["ServerlessV2ScalingConfiguration"]
        if "DeletionProtection" in kw:
            self.cluster["DeletionProtection"] = kw["DeletionProtection"]

    def create_db_instance(self, **kw):
        self._log("create_db_instance", **kw)
        self.instances[kw["DBInstanceIdentifier"]] = {"writer": False, "status": "creating", "az": kw.get("AvailabilityZone")}

    def delete_db_instance(self, **kw):
        self._log("delete_db_instance", **kw)
        self.instances[kw["DBInstanceIdentifier"]]["status"] = "deleting"

    def delete_db_cluster(self, **kw):
        self._log("delete_db_cluster", **kw)
        self.cluster["Status"] = "deleting"

    def get_waiter(self, name):
        rds = self

        class W:
            def wait(self, **kw):
                rds._log("wait:" + name, **kw)
                if name == "db_cluster_available":
                    rds.cluster["Status"] = "available"
                elif name == "db_instance_available":
                    for d in rds.instances.values():
                        d["status"] = "available"
                elif name == "db_instance_deleted":
                    rds.instances.pop(kw["DBInstanceIdentifier"], None)
                elif name == "db_cluster_deleted":
                    rds.cluster = None
        return W()


class FakeSm:
    def __init__(self):
        self.puts = []

    def put_secret_value(self, SecretId, SecretString):
        self.puts.append((SecretId, json.loads(SecretString)))


def _wrapped_stack(tmp_path):
    path = tmp_path / "stack.json"
    path.write_text(json.dumps({"region": {"value": "ap-south-2", "sensitive": False, "type": "string"}}),
                    encoding="utf-8")
    return path


def test_aurora_create_makes_an_express_cluster_with_a_reader_and_records_it(tmp_path):
    ax, rds, sm, stack = _aurora(), FakeRds(), FakeSm(), _wrapped_stack(tmp_path)
    found = ax.create(rds, sm, stack, log=lambda *_: None)
    create = next(kw for n, kw in rds.calls if n == "create_db_cluster")
    assert create == {"DBClusterIdentifier": "warden-pg-fs-aurora", "Engine": "aurora-postgresql",
                      "WithExpressConfiguration": True, "DatabaseName": "shop", "Tags": ax.TAGS}
    assert {"Key": "Project", "Value": "warden-fullstack"} in ax.TAGS
    assert ("modify_db_cluster", {"DBClusterIdentifier": "warden-pg-fs-aurora", "ApplyImmediately": True,
                                  "ServerlessV2ScalingConfiguration": {"MinCapacity": 0.5, "MaxCapacity": 2.0}}) in rds.calls
    reader = next(kw for n, kw in rds.calls if n == "create_db_instance")
    assert reader["DBInstanceIdentifier"] == "warden-pg-fs-aurora-2" and reader["PromotionTier"] == 1
    assert reader["DBInstanceClass"] == "db.serverless" and reader["AvailabilityZone"] == "az-b"  # not the writer's
    assert not any("Password" in k for _, kw in rds.calls for k in kw), "express has no password"
    assert found["aurora_writer_instance"] == "warden-pg-fs-aurora-instance-1"  # whatever express named it
    assert sm.puts == [("warden-pg-fs-db-app", {
        "username": "app", "dbname": "shop", "port": 5432,
        "host": "warden-pg-fs-aurora.cluster-x.rds.example", "reader": "warden-pg-fs-aurora.cluster-ro-x.rds.example"})]
    raw = json.loads(stack.read_text(encoding="utf-8"))
    assert raw["region"]["value"] == "ap-south-2"   # kept, in the file's own (wrapped) format
    assert raw["aurora_writer_endpoint"]["value"] == "warden-pg-fs-aurora.cluster-x.rds.example"
    assert raw["aurora_instance_endpoints"]["value"] == {
        "warden-pg-fs-aurora-instance-1": "warden-pg-fs-aurora-instance-1.x.rds.example",
        "warden-pg-fs-aurora-2": "warden-pg-fs-aurora-2.x.rds.example"}
    assert (raw["db_name"]["value"], raw["db_master_username"]["value"]) == ("shop", "postgres")


def test_aurora_create_twice_changes_nothing_and_refreshes_the_records(tmp_path):
    ax, rds, stack = _aurora(), FakeRds(), _wrapped_stack(tmp_path)
    ax.create(rds, FakeSm(), stack, log=lambda *_: None)
    rds.calls.clear()
    stack.write_text("{}", encoding="utf-8")   # e.g. `terraform output -json` rewrote it
    sm = FakeSm()
    ax.create(rds, sm, stack, log=lambda *_: None)
    assert not [n for n, _ in rds.calls if n.startswith(("create", "modify", "delete"))], rds.calls
    assert json.loads(stack.read_text(encoding="utf-8"))["aurora_cluster"] == "warden-pg-fs-aurora"
    assert len(sm.puts) == 1


def test_aurora_destroy_deletes_instances_then_the_cluster_without_a_snapshot():
    ax, rds = _aurora(), FakeRds()
    rds.create_db_cluster(DBClusterIdentifier="warden-pg-fs-aurora")
    rds.create_db_instance(DBInstanceIdentifier="warden-pg-fs-aurora-2")
    rds.cluster.update(Status="available", DeletionProtection=True)
    rds.calls.clear()
    ax.destroy(rds, log=lambda *_: None)
    names = [n for n, _ in rds.calls]
    assert names.index("modify_db_cluster") < names.index("delete_db_instance")
    assert names.count("delete_db_instance") == 2
    assert max(i for i, n in enumerate(names) if n == "wait:db_instance_deleted") < names.index("delete_db_cluster")
    assert ("delete_db_cluster", {"DBClusterIdentifier": "warden-pg-fs-aurora", "SkipFinalSnapshot": True}) in rds.calls
    assert names[-1] == "wait:db_cluster_deleted" and rds.cluster is None
    rds.calls.clear()
    ax.destroy(rds, log=lambda *_: None)   # already gone: nothing to do
    assert rds.calls == []


@pytest.mark.parametrize("cmd", ["create", "status", "destroy"])
def test_aurora_script_refuses_a_cluster_outside_the_stack(cmd, tmp_path):
    ax, rds = _aurora(), FakeRds()
    with pytest.raises(SystemExit, match="refusing"):
        ax.main([cmd, "--cluster", "prod-db", "--stack", str(tmp_path / "s.json")],
                clients={"rds": rds, "secretsmanager": FakeSm()})
    with pytest.raises(SystemExit, match="refusing"):
        getattr(ax, cmd)(rds, *([FakeSm(), tmp_path / "s.json"] if cmd == "create" else []), "prod-db")
    assert rds.calls == []


def test_aurora_status_says_whether_the_cluster_is_up():
    ax, rds = _aurora(), FakeRds()
    lines = []
    assert ax.status(rds, log=lines.append) is False and "does not exist" in lines[0]
    rds.create_db_cluster(DBClusterIdentifier="warden-pg-fs-aurora")
    rds.cluster["Status"] = "available"
    assert ax.status(rds, log=lines.append) is True


def test_the_infra_pipeline_creates_aurora_after_apply_and_destroys_it_first():
    text = (ROOT / ".github" / "workflows" / "infra.yml").read_text(encoding="utf-8")
    assert text.index("terraform/fullstack apply") < text.index("aurora_express.py create") < text.index("aws s3 cp")
    assert text.index("aurora_express.py destroy") < text.index("terraform/fullstack destroy")
    assert "MASTER_PASSWORD" not in text and "db_master_password" not in text


def test_aurora_create_waits_until_the_capacity_change_has_landed(tmp_path, monkeypatch):
    """The available-waiter can answer before the modify starts; adding the reader then fails."""
    ax, rds, sm = _aurora(), FakeRds(), FakeSm()
    monkeypatch.setattr(ax.time, "sleep", lambda _s: None)
    real_modify, polls = rds.modify_db_cluster, {"n": 0}

    def modify(**kw):
        real_modify(**kw)
        rds.cluster["Status"] = "modifying"
    rds.modify_db_cluster = modify
    real_describe = rds.describe_db_clusters

    def describe(DBClusterIdentifier):
        if rds.cluster and rds.cluster.get("Status") == "modifying":
            polls["n"] += 1
            if polls["n"] >= 3:
                rds.cluster["Status"] = "available"
        return real_describe(DBClusterIdentifier)
    rds.describe_db_clusters = describe
    ax.create(rds, sm, _wrapped_stack(tmp_path), log=lambda *_: None)
    names = [n for n, _ in rds.calls]
    assert polls["n"] >= 3 and names.index("modify_db_cluster") < names.index("create_db_instance")


def test_aurora_reader_is_named_after_the_cluster_it_joins(tmp_path):
    ax, rds, sm = _aurora(), FakeRds(), FakeSm()
    ax.create(rds, sm, _wrapped_stack(tmp_path), cluster="warden-pg-fs-other", log=lambda *_: None)
    created = [kw for n, kw in rds.calls if n == "create_db_instance"]
    assert created and created[0]["DBInstanceIdentifier"] == "warden-pg-fs-other-2"
    assert created[0]["DBClusterIdentifier"] == "warden-pg-fs-other"


def test_aurora_destroy_waits_for_an_instance_still_being_created():
    """An interrupted create leaves an instance in `creating`; RDS refuses to delete it until it settles."""
    ax, rds = _aurora(), FakeRds()
    rds.create_db_cluster(DBClusterIdentifier="warden-pg-fs-aurora")
    rds.create_db_instance(DBInstanceIdentifier="warden-pg-fs-aurora-2")   # still "creating"
    rds.cluster.update(Status="available")
    rds.calls.clear()
    ax.destroy(rds, log=lambda *_: None)
    names = [n for n, _ in rds.calls]
    assert names.index("wait:db_instance_available") < names.index("delete_db_instance")
