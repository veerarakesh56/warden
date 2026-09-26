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
    "lambda_functions": {"checkout": "warden-pg-fs-checkout", "notifier": "warden-pg-fs-notifier"},
    "checkout_alias": "live",
    "ecr_repository_url": "111122223333.dkr.ecr.ap-south-2.amazonaws.com/warden-pg-fs-app",
    "ecs_task_family": "warden-pg-fs-orders-api",
    "ecs_execution_role_arn": "arn:aws:iam::111122223333:role/warden-pg-fs-ecs-exec",
    "ecs_log_group": "/ecs/warden-pg-fs-orders-api",
    "ecs_cluster": "warden-pg-fs-ecs",
    "ecs_service": "warden-pg-fs-orders-api",
    "db_app_secret_arn": "arn:aws:secretsmanager:ap-south-2:111122223333:secret:warden-pg-fs-db-app-AbC",
    "db_app_secret_name": "warden-pg-fs-db-app",
    "db_name": "shop",
    "db_master_username": "postgres",
    "ecs_task_role_arn": "arn:aws:iam::111122223333:role/warden-pg-fs-orders-api-task",
    "redis_primary_endpoint": "redis.internal",
    "aurora_writer_endpoint": "writer.internal",
    "aurora_reader_endpoint": "reader.internal",
    "eks_cluster_name": "warden-pg-fs-eks",
}


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


def aws_factory(clients):
    return lambda service: clients.setdefault(service, Fake())


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
    assert pips and all("manylinux2014_x86_64" in c and "--only-binary=:all:" in c for c in pips)


def test_deploy_lambdas_publishes_and_moves_the_alias_for_checkout_only(tmp_path):
    (tmp_path / "lambda").mkdir()
    for fn in STACK["lambda_functions"]:
        (tmp_path / "lambda" / f"{fn}.zip").write_bytes(b"zip")
    clients = {"lambda": Fake({"publish_version": {"Version": "7"}})}
    done = tool.deploy_lambdas(STACK, tmp_path, aws_factory(clients))
    assert done == {"checkout": "7", "notifier": "$LATEST"}
    names = [c[0] for c in clients["lambda"].calls]
    assert names.count("update_function_code") == 2 and names.count("publish_version") == 1
    assert ("update_alias", {"FunctionName": "warden-pg-fs-checkout", "Name": "live", "FunctionVersion": "7"}) \
        in clients["lambda"].calls


def test_deploy_ecs_records_the_baseline_revision_in_stack_json(tmp_path):
    (tmp_path / "stack.json").write_text(json.dumps({k: {"value": v, "sensitive": False} for k, v in STACK.items()}))
    (tmp_path / "image-tag.txt").write_text("abc123")
    token = base64.b64encode(b"AWS:pw").decode()
    clients = {
        "ecr": Fake({"get_authorization_token": {"authorizationData": [
            {"authorizationToken": token, "proxyEndpoint": "https://registry"}]}}),
        "ecs": Fake({"register_task_definition": {"taskDefinition": {"taskDefinitionArn": "arn:td:4"}}}),
    }
    assert tool.main(["--out", str(tmp_path), "deploy", "ecs"], aws=aws_factory(clients), runner=Runner()) == 0
    assert tool.load_stack(tmp_path / "stack.json")["ecs_baseline_task_definition"] == "arn:td:4"


def test_out_inside_the_repo_is_refused():
    with pytest.raises(SystemExit):
        tool.main(["--out", str(ROOT / "build-here"), "build", "--skip-image"])


def test_ecs_task_definition_logs_in_with_the_task_role_and_still_resolves_a_secret():
    td = tool.task_definition(STACK, "repo:tag")
    c = td["containerDefinitions"][0]
    assert c["image"] == "repo:tag" and td["family"] == STACK["ecs_task_family"]
    assert td["taskRoleArn"] == STACK["ecs_task_role_arn"]   # signs the IAM tokens; fs-21 revokes it
    env = {e["name"]: e["value"] for e in c["environment"]}
    assert (env["DB_HOST"], env["DB_NAME"], env["AWS_REGION"]) == ("writer.internal", "shop", "ap-south-2")
    # The execution role still resolves one value at task start, so fs-18 still stops the task.
    assert c["secrets"] == [{"name": "DB_USER", "valueFrom": STACK["db_app_secret_arn"] + ":username::"}]
    assert "PASSWORD" not in json.dumps(td)
    assert {"name": "ALLOC_MB", "value": "0"} in c["environment"]
    assert c["logConfiguration"]["options"]["awslogs-group"] == "/ecs/warden-pg-fs-orders-api"


def test_deploy_ecs_logs_in_over_stdin_and_updates_the_service():
    token = base64.b64encode(b"AWS:ecr-pw-SENTINEL").decode()
    clients = {
        "ecr": Fake({"get_authorization_token": {"authorizationData": [
            {"authorizationToken": token, "proxyEndpoint": "https://111122223333.dkr.ecr.ap-south-2.amazonaws.com"}]}}),
        "ecs": Fake({"register_task_definition": {"taskDefinition": {"taskDefinitionArn": "arn:td:9"}}}),
    }
    run = Runner()
    assert tool.deploy_ecs(STACK, "abc123", aws_factory(clients), run) == "arn:td:9"
    assert all("ecr-pw-SENTINEL" not in " ".join(c) for c in run.cmds)
    assert "ecr-pw-SENTINEL" in run.inputs
    assert ["docker", "push", STACK["ecr_repository_url"] + ":abc123"] in run.cmds
    assert ("update_service", {"cluster": "warden-pg-fs-ecs", "service": "warden-pg-fs-orders-api",
                               "taskDefinition": "arn:td:9"}) in clients["ecs"].calls


def test_deploy_k8s_fills_every_placeholder_and_keeps_the_signing_key_off_argv(tmp_path):
    import yaml

    rendered = "\n---\n".join(p.read_text(encoding="utf-8") for p in sorted((ROOT / "k8s" / "fullstack").glob("*.yaml"))
                              if p.name != "kustomization.yaml")
    run = Runner({"kustomize": rendered})
    clients = {}
    tool.deploy_k8s(STACK, "abc123", tmp_path, aws_factory(clients), run)
    assert clients == {}, "no secret is read: catalog-api logs in with an IAM token (Pod Identity)"
    applied = next(i for c, i in zip(run.cmds, run.inputs) if "apply" in c)
    assert not tool.PLACEHOLDER.search(applied)
    assert STACK["ecr_repository_url"] + ":abc123" in applied
    assert "kind: ClusterRole" in applied and "name: warden-readonly" in applied
    docs = [d for d in yaml.safe_load_all(applied) if d]
    key = next(d for d in docs if d["kind"] == "Secret")["stringData"]["CATALOG_SIGNING_KEY"]
    config = next(d for d in docs if d["kind"] == "ConfigMap")["data"]
    assert len(key) == 64 and (config["DB_USER"], config["DB_HOST"], config["AWS_REGION"]) == (
        "catalog", "reader.internal", "ap-south-2")
    assert all(key not in " ".join(c) for c in run.cmds)
    assert sum("rollout" in c for c in run.cmds) == 2


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
    credentials, and bootstrap.sql is sent unchanged to the application database."""
    opened, statements = _bootstrap(db_exists=True)
    assert [kw["dbname"] for kw in opened] == ["postgres", STACK["db_name"]]
    for kw in opened:
        assert kw["user"] == "postgres" and kw["password"] == "token-SENTINEL"
        assert kw["host"] == "writer.internal" and kw["sslmode"] == "require"
    assert not any("CREATE DATABASE" in q for q in statements["postgres"])
    assert statements[STACK["db_name"]] == [
        (ROOT / "scenarios" / "fullstack" / "sql" / "bootstrap.sql").read_text(encoding="utf-8")]


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
    assert seen.get("encoding") == "utf-8" and seen.get("errors") == "replace"
