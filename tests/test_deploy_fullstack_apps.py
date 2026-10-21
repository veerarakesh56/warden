"""scripts/deploy_fullstack_apps.py with fakes: no network, no docker, no AWS, no cluster."""
from __future__ import annotations

import base64
import importlib.util
import json
import pathlib
import zipfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("deploy_fullstack_apps", ROOT / "scripts" / "deploy_fullstack_apps.py")
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

STACK = {
    "region": "ap-south-2",
    "lambda_functions": {"checkout": "warden-dev-checkout", "notifier": "warden-dev-notifier"},
    "checkout_alias": "live",
    "ecr_repository_url": "111122223333.dkr.ecr.ap-south-2.amazonaws.com/warden-dev-app",
    "ecs_task_family": "warden-dev-orders-api",
    "ecs_execution_role_arn": "arn:aws:iam::111122223333:role/warden-dev-ecs-exec",
    "ecs_log_group": "/ecs/warden-dev-orders-api",
    "ecs_cluster": "warden-dev-ecs",
    "ecs_service": "warden-dev-orders-api",
    "db_app_secret_arn": "arn:aws:secretsmanager:ap-south-2:111122223333:secret:warden-dev-db-app-AbC",
    "db_app_secret_name": "warden-dev-db-app",
    "db_name": "shop", "environment": "dev",
    "db_users": {"app": "warden_dev_app", "catalog": "warden_dev_catalog", "ro": "warden_dev_ro",
                 "terminate": "warden_dev_terminate"},
    "db_master_username": "postgres",
    "ecs_task_role_arn": "arn:aws:iam::111122223333:role/warden-dev-orders-api-task",
    "redis_primary_endpoint": "redis.internal",
    "aurora_writer_endpoint": "writer.internal",
    "aurora_reader_endpoint": "reader.internal",
    "eks_cluster_name": "warden-dev-eks",
    "catalog_signing_key_secret_name": "warden-dev-catalog-signing-key",
}
# B25: the catalog signing key's Secrets Manager versions, as describe_secret answers.
KEY_VERSION = "0a1b2c3d-0000-4000-8000-00000000000" + "1"
KEY_STAGES = {"describe_secret": {"VersionIdsToStages": {KEY_VERSION: ["AWSCURRENT"], "old-version": ["AWSPREVIOUS"]}}}


class Fake:
    """Records every call; any method returns what `returns` says (or {})."""

    def __init__(self, returns=None):
        self.calls, self.returns = [], returns or {}

    def __getattr__(self, name):
        def call(*args, **kwargs):
            self.calls.append((name, kwargs))
            value = self.returns.get(name, {})
            return value(*args, **kwargs) if callable(value) else value
        return call

    def get_waiter(self, name):
        self.calls.append(("waiter", {"name": name}))
        return Fake()


# The pushed image's digest, as ECR's describe_images answers (built from parts: a fake, not a real image).
DIGEST = "sha256:" + "0123456789abcdef" * 4
ECR_IMAGE = {"describe_images": {"imageDetails": [{"imageDigest": DIGEST, "imageTags": ["abc123"]}]}}


def aws_factory(clients):
    return lambda service: clients.setdefault(service, Fake(ECR_IMAGE if service == "ecr" else None))


class Runner:
    def __init__(self, outputs=None):
        self.cmds, self.inputs, self.outputs = [], [], outputs or {}

    def __call__(self, cmd, *, input=None):
        self.cmds.append(cmd)
        self.inputs.append(input)
        return next((v for k, v in self.outputs.items() if k in " ".join(cmd)), "")


def test_load_stack_unwraps_terraform_output_json(tmp_path):
    p = tmp_path / "stack.json"
    p.write_text(json.dumps({"region": {"value": "ap-south-2", "sensitive": False, "type": "string"}}))
    assert tool.load_stack(p) == {"region": "ap-south-2"}


def test_build_lambdas_zips_every_function_deterministically(tmp_path):
    run = Runner()
    first = tool.build_lambdas(tmp_path / "a", run)
    second = tool.build_lambdas(tmp_path / "b", run)
    assert set(first) == {"checkout", "order-processor", "notifier", "reconciler", "traffic", "ops"}
    for fn, path in first.items():
        assert zipfile.ZipFile(path).namelist() == ["app.py"]
        assert path.read_bytes() == second[fn].read_bytes(), f"{fn} zip is not reproducible"
    pips = [c for c in run.cmds if "pip" in c]
    assert pips
    assert all("manylinux2014_x86_64" in c and "--only-binary=:all:" in c for c in pips)


def test_deploy_lambdas_publishes_and_moves_the_alias_for_checkout_only(tmp_path):
    (tmp_path / "lambda").mkdir()
    for fn in STACK["lambda_functions"]:
        (tmp_path / "lambda" / f"{fn}.zip").write_bytes(b"zip")
    clients = {"lambda": Fake({"publish_version": {"Version": "7"}})}
    done = tool.deploy_lambdas(STACK, tmp_path, aws_factory(clients))
    assert done == {"checkout": "7", "notifier": "$LATEST"}
    names = [c[0] for c in clients["lambda"].calls]
    assert names.count("update_function_code") == 2
    assert names.count("publish_version") == 1
    assert ("update_alias", {"FunctionName": "warden-dev-checkout", "Name": "live", "FunctionVersion": "7"}) \
        in clients["lambda"].calls


def test_deploy_ecs_records_the_baseline_revision_in_stack_json(tmp_path):
    (tmp_path / "stack.json").write_text(json.dumps({k: {"value": v, "sensitive": False} for k, v in STACK.items()}))
    (tmp_path / "image-tag.txt").write_text("abc123")
    token = base64.b64encode(b"AWS:pw").decode()
    clients = {
        "ecr": Fake({"get_authorization_token": {"authorizationData": [
            {"authorizationToken": token, "proxyEndpoint": "https://registry"}]}, **ECR_IMAGE}),
        "ecs": Fake({"register_task_definition": {"taskDefinition": {"taskDefinitionArn": "arn:td:4"}}}),
    }
    assert tool.main(["--out", str(tmp_path), "deploy", "ecs"], aws=aws_factory(clients), runner=Runner()) == 0
    assert tool.load_stack(tmp_path / "stack.json")["ecs_baseline_task_definition"] == "arn:td:4"


def test_out_inside_the_repo_is_refused():
    args = ["--out", str(ROOT / "build-here"), "build", "--skip-image"]
    with pytest.raises(SystemExit):
        tool.main(args)


def test_ecs_task_definition_logs_in_with_the_task_role_and_still_resolves_a_secret():
    td = tool.task_definition(STACK, "repo:tag")
    c = td["containerDefinitions"][0]
    assert c["image"] == "repo:tag"
    assert td["family"] == STACK["ecs_task_family"]
    assert td["taskRoleArn"] == STACK["ecs_task_role_arn"]   # signs the IAM tokens; fs-21 revokes it
    env = {e["name"]: e["value"] for e in c["environment"]}
    assert (env["DB_HOST"], env["DB_NAME"], env["AWS_REGION"]) == ("writer.internal", "shop", "ap-south-2")
    # The execution role still resolves one value at task start, so fs-18 still stops the task.
    assert c["secrets"] == [{"name": "DB_USER", "valueFrom": STACK["db_app_secret_arn"] + ":username::"}]
    assert "PASSWORD" not in json.dumps(td)
    assert {"name": "ORDERS_FF_1", "value": "0"} in c["environment"]
    assert c["logConfiguration"]["options"]["awslogs-group"] == "/ecs/warden-dev-orders-api"


def test_deploy_ecs_logs_in_over_stdin_and_updates_the_service():
    token = base64.b64encode(b"AWS:ecr-pw-SENTINEL").decode()
    clients = {
        "ecr": Fake({"get_authorization_token": {"authorizationData": [
            {"authorizationToken": token, "proxyEndpoint": "https://111122223333.dkr.ecr.ap-south-2.amazonaws.com"}]},
            **ECR_IMAGE}),
        "ecs": Fake({"register_task_definition": {"taskDefinition": {"taskDefinitionArn": "arn:td:9"}}}),
    }
    run = Runner()
    assert tool.deploy_ecs(STACK, "abc123", aws_factory(clients), run) == "arn:td:9"
    assert all("ecr-pw-SENTINEL" not in " ".join(c) for c in run.cmds)
    assert "ecr-pw-SENTINEL" in run.inputs
    assert ["docker", "push", STACK["ecr_repository_url"] + ":abc123"] in run.cmds
    # B26: the task runs the pushed image by its digest, not by the mutable tag.
    td = next(kw for name, kw in clients["ecs"].calls if name == "register_task_definition")
    assert td["containerDefinitions"][0]["image"] == f"{STACK['ecr_repository_url']}@{DIGEST}"
    assert ("describe_images", {"repositoryName": "warden-dev-app", "imageIds": [{"imageTag": "abc123"}]}) \
        in clients["ecr"].calls
    assert ("update_service", {"cluster": "warden-dev-ecs", "service": "warden-dev-orders-api",
                               "taskDefinition": "arn:td:9"}) in clients["ecs"].calls


REV = "0123456789abcdef0123456789abcdef01234567"


def _pipeline_render():
    """What `kubectl kustomize k8s/shop-pipeline` prints: its files, placeholders unfilled."""
    return "\n---\n".join(p.read_text(encoding="utf-8") for p in sorted((ROOT / "k8s" / "shop-pipeline").glob("*.yaml"))
                           if p.name != "kustomization.yaml")


def _synced(revision=REV, sync="Synced", health="Healthy", phase="Succeeded"):
    return json.dumps({"status": {"sync": {"revision": revision, "status": sync}, "health": {"status": health},
                                  "operationState": {"phase": phase, "message": "sync of the commit"}}})


def test_deploy_k8s_fills_every_placeholder_and_keeps_the_signing_key_off_argv(tmp_path, monkeypatch):
    import yaml

    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/warden")
    run = Runner({"kustomize": _pipeline_render(), "get application shop": _synced()})
    clients = {"secretsmanager": Fake(KEY_STAGES)}
    tool.deploy_k8s(STACK, "abc123", tmp_path, aws_factory(clients), run, revision=REV, sleep=lambda s: None)
    # catalog-api logs in with an IAM token (Pod Identity). Secrets Manager is asked for Datadog's agent key, which this
    # stack does not have - so no agent - and for the signing key's VERSION only (B25: ESO copies the key itself).
    assert set(clients) <= {"secretsmanager", "ssm", "ecr"}  # ecr: the image's digest (B26)
    assert [(name, kw) for name, kw in clients["secretsmanager"].calls] == [
        ("get_secret_value", {"SecretId": "warden-dev-datadog-api-key"}),
        ("describe_secret", {"SecretId": "warden-dev-catalog-signing-key"})]
    assert not [c for c in clients["secretsmanager"].calls if c[0] == "get_secret_value"
                and "signing" in c[1]["SecretId"]]
    assert not any(c[:1] == ["helm"] and "datadog" in " ".join(c) for c in run.cmds)  # no key: no agent
    assert any(c[:4] == ["helm", "upgrade", "--install", "argocd"] for c in run.cmds)  # Argo CD always (2026-10-16)
    applied = next(i for c, i in zip(run.cmds, run.inputs) if "apply" in c and i and "kind: ClusterRole" in i)
    assert not tool.PLACEHOLDER.search(applied)
    assert "kind: ClusterRole" in applied
    assert "name: warden-readonly" in applied
    docs = [d for d in yaml.safe_load_all(applied) if d]
    assert not [d for d in docs if d["kind"] == "Secret"]  # no key in this run: ESO writes catalog-secret
    external = next(d for d in docs if d["kind"] == "ExternalSecret")
    assert external["spec"]["data"][0]["remoteRef"]["key"] == "warden-dev-catalog-signing-key"
    assert external["spec"]["target"]["template"]["metadata"]["annotations"]["warden.dev/key-version"] == KEY_VERSION
    assert next(d for d in docs if d["kind"] == "SecretStore")["spec"]["provider"]["aws"]["region"] == "ap-south-2"
    config = next(d for d in docs if d["kind"] == "ConfigMap" and d["metadata"]["name"] == "shop-infra")["data"]
    assert (config["DB_USER"], config["DB_HOST"], config["AWS_REGION"]) == (
        "warden_dev_catalog", "reader.internal", "ap-south-2")
    assert next(d for d in docs if d["kind"] == "Namespace")["metadata"]["labels"]["environment"] == "dev"
    # ESO and Reloader, from their checked packages, before the pipeline's ExternalSecret that needs ESO's CRDs.
    helms = [c[3] for c in run.cmds if c[:3] == ["helm", "upgrade", "--install"]]
    assert helms.index("external-secrets") < helms.index("reloader")
    # The shop namespace exists before ESO and Reloader put their Roles into it (CodeRabbit, PR 118).
    namespace_at = next(n for n, i in enumerate(run.inputs) if i and "kind: Namespace\nmetadata:\n  name: shop" in i)
    assert namespace_at < next(n for n, c in enumerate(run.cmds) if c[3:4] == ["external-secrets"])
    assert "environment: dev" in run.inputs[namespace_at]
    reloader_at = next(n for n, c in enumerate(run.cmds) if c[3:4] == ["reloader"])
    external_at = next(n for n, (c, i) in enumerate(zip(run.cmds, run.inputs))
                       if "apply" in c and i and "kind: ExternalSecret" in i)
    assert reloader_at < external_at
    # The shop's workloads are Argo CD's: the Application, pinned to this commit and its image, then a wait for it.
    app_in = next(i for i in run.inputs if i and "kind: Application" in i)
    app = next(d for d in yaml.safe_load_all(app_in) if d and d["kind"] == "Application")
    src = app["spec"]["source"]
    assert (src["repoURL"], src["targetRevision"], src["path"]) == ("https://github.com/owner/warden", REV,
                                                                    "manifests/shop/dev")
    # B26: by digest - the repository's tags are mutable, the digest names exactly the bytes built.
    assert src["kustomize"]["images"] == [f"shop-app={STACK['ecr_repository_url']}@{DIGEST}"]
    assert app["spec"]["syncPolicy"]["automated"] == {"enabled": True, "prune": True, "selfHeal": True}
    assert not tool.PLACEHOLDER.search(app_in)
    assert any("get application shop" in " ".join(c) for c in run.cmds)
    assert sum("rollout" in c for c in run.cmds) == 1  # the collector's; the apps' health is Argo CD's


def test_datadogs_agent_goes_on_first_with_its_key_over_stdin_and_a_pinned_chart(tmp_path, monkeypatch):
    """Owner, 2026-10-14: Datadog beside AWS. Its agent is installed before the collector and the apps (it receives
    their OpenTelemetry data and collects their logs), its key read from the persistent secret and sent to the cluster
    over stdin, never on a command line; the chart pinned; a site that is not Datadog's installs nothing."""
    import base64

    key = "dd" + "0123456789abcdef" * 2
    clients = {"secretsmanager": Fake({"get_secret_value": {"SecretString": key + "\n"}, **KEY_STAGES}),
               "ssm": Fake({"get_parameter": {"Parameter": {"Value": "ap1.datadoghq.com"}}})}
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/warden")
    run = Runner({"kustomize": _pipeline_render(), "get application shop": _synced()})
    tool.deploy_k8s(STACK, "abc123", tmp_path, aws_factory(clients), run, revision=REV, sleep=lambda s: None)
    assert all(key not in " ".join(c) for c in run.cmds)  # never on argv
    assert {"Name": "/warden/dev/tf/datadog_site"} in [kw for _, kw in clients["ssm"].calls]  # the deploy role's path
    secret_in = next(i for c, i in zip(run.cmds, run.inputs) if i and "datadog-secret" in i)
    assert base64.b64encode(key.encode()).decode() in secret_in
    assert "namespace: datadog" in secret_in
    helm = next(c for c in run.cmds if c[:3] == ["helm", "upgrade", "--install"])
    assert helm[helm.index("--version") + 1] == tool.DATADOG_CHART == "3.250.3"
    for value in ("datadog.site=ap1.datadoghq.com", "datadog.apiKeyExistingSecret=datadog-secret",
                  "datadog.logs.containerCollectAll=true", "datadog.otlp.receiver.protocols.grpc.enabled=true",
                  # The monitors filter on env and status:error: the env tag, and logs with their severity (OTLP).
                  f"datadog.tags[0]=env:{STACK['environment']}", "datadog.otlp.logs.enabled=true"):
        assert value in helm, value
    # The apps are traced once, by OpenTelemetry, for every tool alike - no Datadog-only instrumentation beside it.
    assert not any("apm.instrumentation" in v for v in helm)
    apps = next(n for n, (c, i) in enumerate(zip(run.cmds, run.inputs)) if i and "kind: ClusterRole" in i)
    assert run.cmds.index(helm) < apps  # the agent first: the apps' pods start traced
    clients["ssm"] = Fake({"get_parameter": {"Parameter": {"Value": "evil.example"}}})
    assert tool.deploy_datadog(STACK, "k", aws_factory(clients), Runner()) is False


def test_render_refuses_a_leftover_placeholder():
    with pytest.raises(SystemExit):
        tool.render("image: __IMAGE__\nhost: __NEW_THING__", {"IMAGE": "x"})


def _bootstrap(db_exists: bool):
    """Run bootstrap_db against fake connections; return (connections opened, statements per db)."""
    opened, statements = [], {}

    class Conn:
        def __init__(self, db):
            self.db = db

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, query, params=None):
            text = query if isinstance(query, str) else query.as_string(None)
            statements.setdefault(self.db, []).append(text)
            return type("R", (), {"fetchone": lambda _self: (1,) if db_exists else None})()

    def connect(**kw):
        opened.append(kw)
        return Conn(kw["dbname"])

    clients = {"rds": Fake({"generate_db_auth_token": "token-SENTINEL"})}
    tool.bootstrap_db(STACK, aws_factory(clients), connect=connect)
    assert clients["rds"].calls == [("generate_db_auth_token", {
        "DBHostname": "writer.internal", "Port": 5432, "DBUsername": "postgres", "Region": "ap-south-2"})]
    assert "secretsmanager" not in clients
    return opened, statements


def test_bootstrap_db_logs_in_as_postgres_with_an_iam_token_and_sends_the_file_as_is():
    """No password exists (Aurora express configuration): the token is signed with the operator's
    credentials, and bootstrap.sql is sent to the application database with the environment's users in it."""
    opened, statements = _bootstrap(db_exists=True)
    assert [kw["dbname"] for kw in opened] == ["postgres", STACK["db_name"]]
    for kw in opened:
        assert kw["user"] == "postgres"
        assert kw["password"] == "token-SENTINEL"
        assert kw["host"] == "writer.internal"
        assert kw["sslmode"] == "require"
    assert not any("CREATE DATABASE" in q for q in statements["postgres"])
    sent = statements[STACK["db_name"]]
    assert sent == [tool.bootstrap_sql(STACK["db_users"])]
    assert "CREATE ROLE warden_dev_app LOGIN" in sent[0]
    assert "__" not in sent[0].replace("____", "")


def test_bootstrap_db_creates_the_database_express_could_not():
    """Aurora express refuses an initial database name (seen 2026-09-26), so bootstrap creates it."""
    pytest.importorskip("psycopg")  # the apps pipeline installs it; the tool CI does not
    _, statements = _bootstrap(db_exists=False)
    assert any(q.startswith("CREATE DATABASE") and STACK["db_name"] in q for q in statements["postgres"])


def test_run_decodes_tool_output_as_utf8_not_the_locale(monkeypatch):
    """docker's build output is UTF-8; decoding it as cp1252 crashed a real build (2026-09-26)."""
    seen = {}

    def fake_run(cmd, **kw):
        seen.update(kw)
        return tool.subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")
    monkeypatch.setattr(tool.subprocess, "run", fake_run)
    tool.run(["docker", "build"])
    assert seen.get("encoding") == "utf-8"
    assert seen.get("errors") == "replace"


def _dist(target, name, requires=()):
    d = target / f"{name}-1.0.dist-info"
    d.mkdir()
    lines = ["Metadata-Version: 2.1", f"Name: {name}", "Version: 1.0", *[f"Requires-Dist: {r}" for r in requires]]
    (d / "METADATA").write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_a_dependency_skipped_for_the_building_python_fails_the_build(tmp_path):
    """Built on 3.13, psycopg's `typing-extensions; python_version < "3.13"` was skipped and both database
    Lambdas died on import in AWS. The check evaluates markers for the Lambda's 3.12."""
    _dist(tmp_path, "psycopg", ['typing-extensions>=4.6; python_version < "3.13"', 'tzdata; sys_platform == "win32"'])
    assert tool.missing_dependencies(tmp_path) == ["typing-extensions"]
    _dist(tmp_path, "typing_extensions")
    assert tool.missing_dependencies(tmp_path) == []   # tzdata is Windows-only: not required on Lambda


def test_the_task_definition_revision_carries_project_and_environment_tags():
    td = tool.task_definition(STACK, "repo:tag")
    assert td["tags"] == [{"key": "Project", "value": "warden"}, {"key": "Environment", "value": "dev"}]


def test_an_extra_the_lambda_asks_for_is_checked(tmp_path):
    """Fifth review (2026-10-01): `psycopg[binary]` without psycopg-binary passed the check, and the Lambda would
    die on import."""
    _dist(tmp_path, "psycopg", ['psycopg-binary==3.3.5; extra == "binary"', 'psycopg-pool; extra == "pool"'])
    assert tool.missing_dependencies(tmp_path) == []
    assert tool.missing_dependencies(tmp_path, extras={"psycopg": {"binary"}}) == ["psycopg-binary"]


def test_the_build_reads_the_extras_each_lambda_asks_for():
    asked = {fn: tool.requested_extras(tool.LAMBDA_SRC / fn / "requirements.in") for fn in tool.lambda_names()
             if (tool.LAMBDA_SRC / fn / "requirements.in").is_file()}
    assert any(extras.get("psycopg") == {"binary"} for extras in asked.values()), asked


@pytest.mark.parametrize("users", [None, {"app": "app", "catalog": "warden_dev_catalog", "ro": "warden_dev_ro"},
                                   {"app": "warden_dev_app; DROP TABLE orders", "catalog": "x", "ro": "y"},
                                   {"app": "warden_dev_app", "catalog": "warden_dev_catalog"},
                                   # seventh review: another environment's users, one name for all three
                                   {"app": "warden_prod_app", "catalog": "warden_dev_catalog", "ro": "warden_dev_ro"},
                                   {"app": "warden_dev_app", "catalog": "warden_dev_app", "ro": "warden_dev_app"}])
def test_the_database_users_must_be_the_environments_own(users):
    """Audit A-I-2: users carry the environment, and nothing that is not a plain user name reaches the SQL."""
    stack = {**STACK, "db_users": users} if users is not None else {k: v for k, v in STACK.items() if k != "db_users"}
    with pytest.raises(SystemExit):
        tool.db_users(stack)


def test_an_extra_a_requirement_asks_for_is_followed(tmp_path):
    """Register R7-O4: `boto3[crt]` asks botocore for its `crt` extra; only the Lambda's own extras were checked, so
    botocore's `awscrt` was never required."""
    _dist(tmp_path, "boto3", ['botocore[crt]>=1.40; extra == "crt"', "botocore>=1.40"])
    _dist(tmp_path, "botocore", ['awscrt==0.27; extra == "crt"'])
    assert tool.missing_dependencies(tmp_path) == []
    assert tool.missing_dependencies(tmp_path, extras={"boto3": {"crt"}}) == ["awscrt"]
    _dist(tmp_path, "awscrt")
    assert tool.missing_dependencies(tmp_path, extras={"boto3": {"crt"}}) == []


def test_one_collector_sends_to_datadog_or_else_xray_before_the_apps_start(tmp_path):
    """One OpenTelemetry collector: Datadog when its agent is on the cluster, else X-Ray (by the pod's IAM role) - not
    both (cost plan, 2026-10-17: nothing read the X-Ray copy). No Grafana (owner, 2026-10-16: Datadog only), and so no
    key in the collector at all."""
    import yaml

    full = tool.otel_config("ap-south-2", datadog=True)
    assert full["service"]["pipelines"]["traces"]["exporters"] == ["otlp/datadog"]
    # Logs to Datadog with their severity (Datadog would file the apps' stdout lines as info).
    assert full["service"]["pipelines"]["logs"]["exporters"] == ["otlp/datadog"]
    assert full["service"]["pipelines"]["metrics"]["exporters"] == ["otlp/datadog"]
    assert "awsxray" not in full["exporters"]
    alone = tool.otel_config("ap-south-2")
    assert alone["exporters"]["awsxray"] == {"region": "ap-south-2"}
    assert alone["service"]["pipelines"] == {"traces": {"receivers": ["otlp"], "processors": ["memory_limiter", "batch"],
                                                        "exporters": ["awsxray"]}}
    run = Runner()
    config = tool.deploy_otel(STACK, "k", True, run)
    assert set(config["exporters"]) == {"otlp/datadog"}
    assert {p: v["exporters"] for p, v in config["service"]["pipelines"].items()} == {
        "traces": ["otlp/datadog"], "metrics": ["otlp/datadog"], "logs": ["otlp/datadog"]}
    docs = list(yaml.safe_load_all(run.inputs[0]))
    assert not [d for d in docs if d["kind"] == "Secret"]
    assert "grafana" not in run.inputs[0].lower()
    dep = next(d for d in docs if d["kind"] == "Deployment")
    assert dep["spec"]["template"]["spec"]["containers"][0]["image"] == tool.OTEL_IMAGE.replace(":v", ":v")
    assert tool.OTEL_IMAGE.endswith(":v0.50.0")
    k8s = (ROOT / "manifests" / "shop" / "base" / "config.yaml").read_text(encoding="utf-8")
    assert 'OTEL_EXPORTER_OTLP_ENDPOINT: "http://otel-collector.observability.svc.cluster.local:4318"' in k8s
    assert "OTEL_SDK_DISABLED=true" in (ROOT / "scenarios" / "fullstack" / "app" / "Dockerfile").read_text(encoding="utf-8")


def test_the_collector_sends_in_plaintext_only_to_the_agent_on_its_own_node():
    """Naming audit item 19 (2026-10-16): `tls: insecure` is right only for the node-local hop to the Datadog agent's
    OTLP receiver. HOST_IP must be the pod's own node, and every other exporter keeps TLS."""
    import yaml

    full = tool.otel_config("ap-south-2", datadog=True)
    plain = {name: e for name, e in full["exporters"].items() if e.get("tls", {}).get("insecure")}
    assert plain == {"otlp/datadog": {"endpoint": "${env:HOST_IP}:4317", "tls": {"insecure": True}}}
    run = Runner()
    tool.deploy_otel(STACK, "k", True, run)
    dep = next(d for d in yaml.safe_load_all(run.inputs[0]) if d["kind"] == "Deployment")
    [env] = [e for e in dep["spec"]["template"]["spec"]["containers"][0]["env"] if e["name"] == "HOST_IP"]
    assert env["valueFrom"] == {"fieldRef": {"fieldPath": "status.hostIP"}}


@pytest.fixture(autouse=True)
def _no_chart_download(monkeypatch):
    """No test downloads a chart: the package is a stand-in whose sha256 is the pinned one for that test."""
    import hashlib

    monkeypatch.setattr(tool, "_fetch_chart", lambda url: b"argo-cd chart package")
    monkeypatch.setattr(tool, "ARGOCD_CHART_SHA256", hashlib.sha256(b"argo-cd chart package").hexdigest())
    for pin in ("ESO_CHART_SHA256", "RELOADER_CHART_SHA256"):  # B25: the same stand-in package
        monkeypatch.setattr(tool, pin, hashlib.sha256(b"argo-cd chart package").hexdigest())


def test_argocd_is_installed_from_the_checked_package_with_its_settings(tmp_path):
    """Owner, 2026-10-16: GitOps for the cluster. Argo CD v3.5.5 (chart 10.10.5, B26) from the argo-helm release's own
    package - installed only if its sha256 is the pinned one - with helm/argo-cd/values.yaml."""
    run = Runner({})
    tool.deploy_argocd("kc", tmp_path, run)
    helm = next(c for c in run.cmds if c[:3] == ["helm", "upgrade", "--install"])
    assert helm[3] == "argocd"
    assert helm[4] == str(tmp_path / f"argo-cd-{tool.ARGOCD_CHART}.tgz")
    assert helm[helm.index("--namespace") + 1] == "argocd"
    assert helm[helm.index("--values") + 1] == str(tool.ARGOCD_VALUES)
    assert (tmp_path / f"argo-cd-{tool.ARGOCD_CHART}.tgz").read_bytes() == b"argo-cd chart package"
    assert tool.ARGOCD_CHART == "10.10.5"
    assert tool.ARGOCD_CHART_URL.startswith("https://github.com/argoproj/argo-helm/")
    # The pinned bytes of argo-cd-10.10.5.tgz (downloaded and hashed 2026-10-20); the test above patches the constant.
    assert 'ARGOCD_CHART_SHA256 = "ba6447eeed42bc41d1f0527721047b236304e97669a7b6286d02be4a1644ba7a"' in \
        (ROOT / "scripts" / "deploy_fullstack_apps.py").read_text(encoding="utf-8")


def test_a_chart_package_that_is_not_the_pinned_one_installs_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(tool, "_fetch_chart", lambda url: b"something else")
    run = Runner({})
    with pytest.raises(SystemExit, match="not the pinned one"):
        tool.deploy_argocd("kc", tmp_path, run)
    assert not any(c[:1] == ["helm"] for c in run.cmds)


def test_argocd_settings_name_no_login_no_load_balancer_and_deny_by_default():
    import yaml

    v = yaml.safe_load(tool.ARGOCD_VALUES.read_text(encoding="utf-8"))
    assert v["configs"]["cm"]["admin.enabled"] is False
    assert v["dex"]["enabled"] is False
    assert v["configs"]["cm"]["exec.enabled"] is False
    assert v["configs"]["rbac"]["policy.default"] == ""
    assert v["server"]["service"]["type"] == "ClusterIP"
    assert v["notifications"]["enabled"] is False
    for part in ("controller", "repoServer", "server", "applicationSet", "redis"):
        assert v[part]["resources"]["requests"], part
        assert v[part]["resources"]["limits"]["memory"], part


def test_a_sync_that_failed_or_never_reached_the_commit_fails_the_deploy(monkeypatch):
    """Dev is run as production (owner, 2026-10-16): the deploy says why Argo CD did not deploy the commit, and fails."""
    failed = Runner({"get application shop": _synced(phase="Failed", health="Degraded")})
    with pytest.raises(SystemExit, match="sync of 0123456789ab failed"):
        tool.wait_synced("kc", REV, failed, sleep=lambda s: None)
    elsewhere = Runner({"get application shop": _synced(revision="f" * 40)})
    with pytest.raises(SystemExit, match="did not sync 0123456789ab to Healthy"):
        tool.wait_synced("kc", REV, elsewhere, sleep=lambda s: None)
    tool.wait_synced("kc", REV, Runner({"get application shop": _synced()}), sleep=lambda s: None)  # synced: returns


def test_the_shops_workloads_render_for_dev_with_no_placeholder_and_the_hpa_owns_catalogs_replicas():
    import shutil
    import subprocess

    import yaml

    if not shutil.which("kubectl"):
        pytest.skip("kubectl renders kustomize")
    out = subprocess.run(["kubectl", "kustomize", str(ROOT / "manifests" / "shop" / "dev")], capture_output=True,
                         text=True, check=True).stdout
    assert not tool.PLACEHOLDER.search(out)
    assert "unset" not in out
    docs = {(d["kind"], d["metadata"]["name"]): d for d in yaml.safe_load_all(out) if d}
    catalog, worker = docs[("Deployment", "catalog-api")], docs[("Deployment", "cart-worker")]
    assert "replicas" not in catalog["spec"]
    assert worker["spec"]["replicas"] == 2
    for dep in (catalog, worker):
        assert dep["metadata"]["labels"]["environment"] == "dev"  # WARDEN reads it before any change (P18)
        assert dep["spec"]["template"]["metadata"]["labels"]["tags.datadoghq.com/env"] == "dev"
        c = dep["spec"]["template"]["spec"]["containers"][0]
        assert c["image"] == "shop-app:set-by-argocd"
        assert {e["configMapRef"]["name"] for e in c["envFrom"]} == {"catalog-config", "shop-infra", "otel-config"}
    assert docs[("ConfigMap", "otel-config")]["data"]["OTEL_RESOURCE_ATTRIBUTES"] == "deployment.environment=dev"
    assert not any(k == "Secret" or k == "Namespace" for k, _ in docs)  # the pipeline's, never Git's


def test_the_applications_image_override_leaves_only_the_digest_and_never_the_bases_tag(tmp_path):
    """The base names `shop-app:set-by-argocd` (a tag, Sonar kubernetes:S6596); Argo CD's kustomize override
    `shop-app=<repository>@<digest>` (B26) must replace name AND tag, so the pod runs exactly the bytes built."""
    import shutil
    import subprocess

    import yaml

    if not shutil.which("kubectl"):
        pytest.skip("kubectl renders kustomize")
    shutil.copytree(ROOT / "manifests" / "shop", tmp_path / "shop")
    dev = tmp_path / "shop" / "dev" / "kustomization.yaml"
    repo = STACK["ecr_repository_url"]
    dev.write_text(dev.read_text(encoding="utf-8") + yaml.safe_dump(
        {"images": [{"name": "shop-app", "newName": repo, "digest": DIGEST}]}), encoding="utf-8")
    out = subprocess.run(["kubectl", "kustomize", str(dev.parent)], capture_output=True, text=True,
                         check=True).stdout
    images = sorted(c["image"] for d in yaml.safe_load_all(out) if d and d["kind"] == "Deployment"
                    for c in d["spec"]["template"]["spec"]["containers"])
    assert images == [f"{repo}@{DIGEST}", f"{repo}@{DIGEST}"]


@pytest.mark.parametrize("found", [{}, {"imageDetails": []}, {"imageDetails": [{"imageDigest": "latest"}]}])
def test_an_image_without_a_sha256_digest_is_never_deployed(found):
    """B26: no digest, no deploy - never a fall back to the mutable tag."""
    aws = aws_factory({"ecr": Fake({"describe_images": found})})
    with pytest.raises(SystemExit, match="with a sha256 digest"):
        tool.image_by_digest(STACK, "abc123", aws)


def test_ecs_runs_the_digest_the_push_answered_not_one_read_back_by_the_tag():
    """CodeRabbit (PR 90): between the push and a read-back the mutable tag could move; the push's own digest is used."""
    pushed = "sha256:" + "fedcba9876543210" * 4
    token = base64.b64encode(b"AWS:pw").decode()
    clients = {"ecr": Fake({"get_authorization_token": {"authorizationData": [
                   {"authorizationToken": token, "proxyEndpoint": "https://registry"}]}, **ECR_IMAGE}),
               "ecs": Fake({"register_task_definition": {"taskDefinition": {"taskDefinitionArn": "arn:td:5"}}})}
    run = Runner({"docker push": f"abc123: digest: {pushed} size: 1234"})
    tool.deploy_ecs(STACK, "abc123", aws_factory(clients), run, wait=False)
    td = next(kw for name, kw in clients["ecs"].calls if name == "register_task_definition")
    assert td["containerDefinitions"][0]["image"] == f"{STACK['ecr_repository_url']}@{pushed}"
    assert not [c for c in clients["ecr"].calls if c[0] == "describe_images"]


def test_a_venv_symlink_is_ignored_too():
    """PR 90: `.venv/` matches a directory only; a `.venv` symlink was committed and CI's `uv venv` failed."""
    lines = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert ".venv" in lines


@pytest.mark.parametrize("release, pin", [("external-secrets", "ESO_CHART_SHA256"), ("reloader", "RELOADER_CHART_SHA256")])
def test_eso_and_reloader_install_only_their_pinned_packages(tmp_path, monkeypatch, release, pin):
    """B25: a package whose bytes are not the pinned ones installs nothing - and stops before the next."""
    monkeypatch.setattr(tool, pin, "0" * 64)
    run = Runner({})
    with pytest.raises(SystemExit, match=f"the {release} chart package is not the pinned one"):
        tool.deploy_secret_sync("kc", tmp_path, run)
    assert release not in [c[3] for c in run.cmds if c[:1] == ["helm"]]


def test_the_charts_are_their_releases_own_and_their_images_by_digest():
    import re

    import yaml

    assert tool.ESO_CHART_URL == ("https://github.com/external-secrets/external-secrets/releases/download/"
                                  "helm-chart-2.13.0/external-secrets-2.13.0.tgz")
    assert tool.RELOADER_CHART_URL == "https://stakater.github.io/stakater-charts/reloader-2.2.18.tgz"
    eso = yaml.safe_load(tool.ESO_VALUES.read_text(encoding="utf-8"))
    assert re.fullmatch(r"v2\.13\.0@sha256:[0-9a-f]{64}", eso["image"]["tag"])
    reloader = yaml.safe_load(tool.RELOADER_VALUES.read_text(encoding="utf-8"))
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", reloader["image"]["digest"])


def test_eso_and_reloader_reach_the_shop_namespace_only():
    """B25, least privilege: namespaced RBAC in shop, no cluster-wide stores, pushes, generators, webhooks or token
    minting; Reloader watches shop's Secrets only."""
    import yaml

    eso = yaml.safe_load(tool.ESO_VALUES.read_text(encoding="utf-8"))
    assert (eso["scopedNamespace"], eso["scopedRBAC"]) == ("shop", True)
    assert not any(eso[k] for k in ("processClusterExternalSecret", "processClusterPushSecret", "processClusterStore",
                                    "processClusterGenerator", "processPushSecret"))
    assert not any(eso["crds"].values())
    assert eso["rbac"]["serviceAccountTokenCreate"] is False
    assert eso["webhook"]["create"] is False
    assert eso["certController"]["create"] is False
    assert eso["serviceAccount"]["name"] == "external-secrets"
    reloader = yaml.safe_load(tool.RELOADER_VALUES.read_text(encoding="utf-8"))["reloader"]
    assert (reloader["watchGlobally"], reloader["namespaces"], reloader["ignoreConfigMaps"]) == (False, ["shop"], True)
    assert reloader["reloadStrategy"] == "annotations"
    assert reloader["autoReloadAll"] is False


def test_a_rotation_changes_the_externalsecret_and_nothing_else_does(tmp_path, monkeypatch):
    """Owner decision 2026-10-20 (option B): the ExternalSecret changes when - and only when - the key's Secrets Manager
    version changes, so ESO copies a rotated key and never re-syncs an unchanged one."""
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/warden")

    def external(stages):
        run = Runner({"kustomize": _pipeline_render(), "get application shop": _synced()})
        clients = {"secretsmanager": Fake({"describe_secret": {"VersionIdsToStages": stages}})}
        tool.deploy_k8s(STACK, "abc123", tmp_path, aws_factory(clients), run, revision=REV, sleep=lambda s: None)
        return next(i for i in run.inputs if i and "kind: ExternalSecret" in i)

    first = external({"v1": ["AWSCURRENT"]})
    assert external({"v1": ["AWSCURRENT"]}) == first  # a deploy with no rotation changes nothing ESO reacts to
    rotated = external({"v2": ["AWSCURRENT"], "v1": ["AWSPREVIOUS"]})
    assert rotated != first
    assert 'warden.dev/key-version: "v2"' in rotated


def test_a_status_that_cannot_be_read_never_hides_the_wait_failure():
    """CodeRabbit (PR 118): both failures are said - the wait's first."""
    class BothFail(Runner):
        def __call__(self, cmd, *, input=None):
            self.cmds.append(cmd)
            raise tool.CommandFailed("kubectl exited 1: " + ("timed out" if "wait" in cmd else "connection refused"))

    both_fail = BothFail()
    with pytest.raises(SystemExit, match="could not be read either: kubectl exited 1: connection refused.*"
                                         "the wait said: kubectl exited 1: timed out"):
        tool.catalog_secret_synced("kc", both_fail)


def test_no_current_key_version_stops_the_deploy_before_eso_and_the_externalsecret(tmp_path, monkeypatch):
    """CodeRabbit (PR 118): through deploy_k8s - no AWSCURRENT version, no ESO install and no ExternalSecret."""
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/warden")
    clients = {"secretsmanager": Fake({"describe_secret": {"VersionIdsToStages": {"v1": ["AWSPREVIOUS"]}}})}
    run = Runner({"kustomize": _pipeline_render(), "get application shop": _synced()})
    aws = aws_factory(clients)
    with pytest.raises(SystemExit, match="has no current version"):
        tool.deploy_k8s(STACK, "abc123", tmp_path, aws, run, revision=REV, sleep=lambda s: None)
    assert "external-secrets" not in [c[3] for c in run.cmds if c[:3] == ["helm", "upgrade", "--install"]]
    assert not [i for i in run.inputs if i and "kind: ExternalSecret" in i]


def test_an_externalsecret_that_does_not_sync_stops_the_deploy_with_its_status(tmp_path, monkeypatch):
    """CodeRabbit (PR 118): said at the step, by name, with ESO's own conditions."""
    class Failing(Runner):
        def __call__(self, cmd, *, input=None):
            if "wait" in cmd and "externalsecret/catalog-secret" in cmd:
                self.cmds.append(cmd)
                raise tool.CommandFailed("kubectl exited 1")
            return super().__call__(cmd, input=input)

    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/warden")
    run = Failing({"kustomize": _pipeline_render(), "jsonpath={.status.conditions}": '[{"reason":"SecretSyncedError"}]'})
    aws = aws_factory({"secretsmanager": Fake(KEY_STAGES)})
    with pytest.raises(SystemExit, match="catalog-secret was not synced by ESO .*SecretSyncedError"):
        tool.deploy_k8s(STACK, "abc123", tmp_path, aws, run, revision=REV, sleep=lambda s: None)
    assert not [i for i in run.inputs if i and "kind: Application" in i]  # the shop is not synced over it


class _NoSuchSecret(Exception):
    pass


def test_a_stack_json_from_before_b25_or_a_deleted_secret_says_apply_first():
    """CodeRabbit (PR 118): the guidance, not a KeyError or a raw ResourceNotFoundException."""
    old_stack = {k: v for k, v in STACK.items() if k != "catalog_signing_key_secret_name"}
    with pytest.raises(SystemExit, match="names no catalog_signing_key_secret_name: apply the stack first"):
        tool.signing_key_version(old_stack, aws_factory({}))

    class Gone(Fake):
        exceptions = type("E", (), {"ResourceNotFoundException": _NoSuchSecret})

        def describe_secret(self, SecretId):
            raise _NoSuchSecret(SecretId)

    aws = aws_factory({"secretsmanager": Gone()})
    with pytest.raises(SystemExit, match="warden-dev-catalog-signing-key does not exist: apply the stack first"):
        tool.signing_key_version(STACK, aws)


def test_a_failed_command_still_ends_the_run():
    """run() raises CommandFailed, a SystemExit: unhandled, it still stops the deploy as before."""
    assert issubclass(tool.CommandFailed, SystemExit)

