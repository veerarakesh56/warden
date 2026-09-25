"""The APPS pipeline of the Wave 4 stack: build and deploy the code that runs on it.

    python scripts/deploy_fullstack_apps.py build   [--skip-image] [--tag TAG]
    python scripts/deploy_fullstack_apps.py deploy  lambdas|ecs|k8s|all
    python scripts/deploy_fullstack_apps.py bootstrap-db

Three pipelines, each usable alone: INFRA (terraform/fullstack) produces stack.json; this tool reads
it and never calls terraform; WARDEN's own CI is a third. Everything lands OUTSIDE the repo, in
--out (default ~/warden-fullstack-build): lambda/<fn>.zip, image-tag.txt, kubeconfig.

  build         Lambda zips (manylinux wheels via pip --platform, python zipfile) and the
                container image (docker build).
  deploy lambdas  update-function-code for each function; checkout also gets publish-version +
                update-alias live.
  deploy ecs    ECR login + push, register a task definition revision (DB credentials injected
                from Secrets Manager), update-service, wait until stable. Records the revision in
                stack.json as `ecs_baseline_task_definition` - the revision the harness reverts to.
  deploy k8s    kubectl kustomize k8s/fullstack, fill the placeholders from stack.json and the
                app secret (over stdin, never argv), apply with the ClusterRole from k8s/rbac.yaml,
                wait for both rollouts.
  deploy all    build, then lambdas, ecs, k8s.
  bootstrap-db  scenarios/fullstack/sql/bootstrap.sql as the master user. The master password
                comes from WARDEN_FS_DB_MASTER_PASSWORD (or TF_VAR_db_master_password).

stack.json is `terraform output -json` with the sensitive entries removed (README).
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
APPS = ROOT / "scenarios" / "fullstack"
K8S = ROOT / "k8s" / "fullstack"
DEFAULT_OUT = pathlib.Path.home() / "warden-fullstack-build"
LAMBDA_SRC = APPS / "lambdas"
IMAGE = "warden-pg-fs-app"
PLACEHOLDER = re.compile(r"__[A-Z_]+__")
ZIP_DATE = (2026, 1, 1, 0, 0, 0)  # fixed, so an unchanged function builds a byte-identical zip


def run(cmd: list[str], *, input: str | None = None) -> str:
    """Run a command; stdin carries anything secret. Only the command is echoed."""
    print("+", " ".join(cmd), flush=True)
    done = subprocess.run(cmd, input=input, text=True, capture_output=True, check=False)
    if done.returncode:
        raise SystemExit(f"{cmd[0]} exited {done.returncode}:\n{done.stderr[-2000:]}")
    return done.stdout


def boto_factory(region: str):
    import boto3

    session = boto3.Session(region_name=region)
    return session.client


def load_stack(path: pathlib.Path) -> dict:
    raw = json.loads(path.read_text(encoding="utf-8"))
    # `terraform output -json` wraps each value: {"name": {"value": ..., "sensitive": ..., "type": ...}}
    return {k: (v["value"] if isinstance(v, dict) and "value" in v else v) for k, v in raw.items()}


# --------------------------------------------------------------------------- build

def lambda_names() -> list[str]:
    return sorted(p.name for p in LAMBDA_SRC.iterdir() if (p / "app.py").is_file())


def build_lambdas(out: pathlib.Path, run=run) -> dict[str, pathlib.Path]:
    dest = out / "lambda"
    dest.mkdir(parents=True, exist_ok=True)
    built = {}
    for fn in lambda_names():
        src = LAMBDA_SRC / fn
        with tempfile.TemporaryDirectory() as tmp:
            stage = pathlib.Path(tmp)
            req = src / "requirements.txt"
            if req.is_file():
                run([sys.executable, "-m", "pip", "install", "--quiet", "-r", str(req), "--target", str(stage),
                     "--platform", "manylinux2014_x86_64", "--only-binary=:all:",
                     "--implementation", "cp", "--python-version", "3.12"])
            for py in src.glob("*.py"):
                shutil.copy2(py, stage / py.name)
            zpath = dest / f"{fn}.zip"
            with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
                for f in sorted(p for p in stage.rglob("*") if p.is_file() and "__pycache__" not in p.parts):
                    info = zipfile.ZipInfo(f.relative_to(stage).as_posix(), ZIP_DATE)
                    info.external_attr = 0o644 << 16
                    info.compress_type = zipfile.ZIP_DEFLATED
                    zf.writestr(info, f.read_bytes())
        built[fn] = zpath
    return built


def default_tag(run=run) -> str:
    return run(["git", "-C", str(ROOT), "describe", "--always", "--dirty"]).strip()


def build_image(out: pathlib.Path, tag: str, run=run) -> str:
    run(["docker", "build", "-t", f"{IMAGE}:{tag}", str(APPS / "app")])
    (out / "image-tag.txt").write_text(tag, encoding="utf-8")
    return tag


# --------------------------------------------------------------------------- deploy

def deploy_lambdas(stack: dict, out: pathlib.Path, aws) -> dict[str, str]:
    lam = aws("lambda")
    done = {}
    for fn, name in sorted(stack["lambda_functions"].items()):
        zpath = out / "lambda" / f"{fn}.zip"
        if not zpath.is_file():
            raise SystemExit(f"{zpath} missing - run `build` first")
        lam.update_function_code(FunctionName=name, ZipFile=zpath.read_bytes())
        lam.get_waiter("function_updated_v2").wait(FunctionName=name)
        done[fn] = "$LATEST"
        if fn == "checkout":
            version = lam.publish_version(FunctionName=name)["Version"]
            lam.update_alias(FunctionName=name, Name=stack["checkout_alias"], FunctionVersion=version)
            done[fn] = version
        print(f"deployed {name} -> {done[fn]}", flush=True)
    return done


def push_image(stack: dict, tag: str, aws, run=run) -> str:
    auth = aws("ecr").get_authorization_token()["authorizationData"][0]
    user, password = base64.b64decode(auth["authorizationToken"]).decode().split(":", 1)
    registry = auth["proxyEndpoint"].removeprefix("https://")
    run(["docker", "login", "--username", user, "--password-stdin", registry], input=password)
    remote = f"{stack['ecr_repository_url']}:{tag}"
    run(["docker", "tag", f"{IMAGE}:{tag}", remote])
    run(["docker", "push", remote])
    return remote


def task_definition(stack: dict, image: str) -> dict:
    secret = stack["db_app_secret_arn"]
    return {
        "family": stack["ecs_task_family"],
        "requiresCompatibilities": ["FARGATE"],
        "networkMode": "awsvpc",
        "cpu": "256",
        "memory": "512",
        "executionRoleArn": stack["ecs_execution_role_arn"],
        "containerDefinitions": [{
            "name": "orders-api",
            "image": image,
            "essential": True,
            "portMappings": [{"containerPort": 8080, "protocol": "tcp"}],
            "environment": [
                {"name": "APP_ROLE", "value": "orders-api"},
                {"name": "REDIS_HOST", "value": stack["redis_primary_endpoint"]},
                {"name": "DB_NAME", "value": stack["db_name"]},
                # Fault flag at its baseline value (scenarios/ops_fullstack.py FLAGS, fs-20).
                {"name": "ALLOC_MB", "value": "0"},
            ],
            # Resolved by the EXECUTION role at task start (fs-18 removes that grant).
            "secrets": [
                {"name": "DB_HOST", "valueFrom": f"{secret}:host::"},
                {"name": "DB_USER", "valueFrom": f"{secret}:username::"},
                {"name": "DB_PASSWORD", "valueFrom": f"{secret}:password::"},
            ],
            "logConfiguration": {"logDriver": "awslogs", "options": {
                "awslogs-group": stack["ecs_log_group"],
                "awslogs-region": stack["region"],
                "awslogs-stream-prefix": "orders-api",
            }},
        }],
    }


def deploy_ecs(stack: dict, tag: str, aws, run=run, wait: bool = True) -> str:
    image = push_image(stack, tag, aws, run)
    ecs = aws("ecs")
    arn = ecs.register_task_definition(**task_definition(stack, image))["taskDefinition"]["taskDefinitionArn"]
    ecs.update_service(cluster=stack["ecs_cluster"], service=stack["ecs_service"], taskDefinition=arn)
    print(f"ecs service -> {arn}", flush=True)
    if wait:
        ecs.get_waiter("services_stable").wait(cluster=stack["ecs_cluster"], services=[stack["ecs_service"]])
    return arn


def record_in_stack(path: pathlib.Path, key: str, value: str) -> None:
    """Add one apps-pipeline fact to stack.json, in the file's own (wrapped or flat) format."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    wrapped = any(isinstance(v, dict) and "value" in v for v in raw.values())
    raw[key] = {"value": value, "sensitive": False, "type": "string"} if wrapped else value
    path.write_text(json.dumps(raw, indent=1), encoding="utf-8")


def secret_json(aws, name: str) -> dict:
    return json.loads(aws("secretsmanager").get_secret_value(SecretId=name)["SecretString"])


def render(manifest: str, values: dict[str, str]) -> str:
    for key, value in values.items():
        manifest = manifest.replace(f"__{key}__", value)
    left = sorted(set(PLACEHOLDER.findall(manifest)))
    if left:
        raise SystemExit(f"unfilled placeholders in k8s/fullstack: {left}")
    return manifest


def cluster_role() -> str:
    import yaml

    docs = yaml.safe_load_all((ROOT / "k8s" / "rbac.yaml").read_text(encoding="utf-8"))
    role = next(d for d in docs if d and d.get("kind") == "ClusterRole")
    return yaml.safe_dump(role, sort_keys=False)


def deploy_k8s(stack: dict, tag: str, out: pathlib.Path, aws, run=run) -> None:
    kubeconfig = str(out / "kubeconfig")
    run(["aws", "eks", "update-kubeconfig", "--name", stack["eks_cluster_name"],
         "--region", stack["region"], "--kubeconfig", kubeconfig])
    # catalog-api reads with its own user (see terraform/fullstack/data.tf db_catalog).
    creds = secret_json(aws, stack["db_catalog_secret_name"])
    manifest = render(run(["kubectl", "--kubeconfig", kubeconfig, "kustomize", str(K8S)]), {
        "IMAGE": f"{stack['ecr_repository_url']}:{tag}",
        "REDIS_HOST": stack["redis_primary_endpoint"],
        "DB_READER_HOST": stack["aurora_reader_endpoint"],
        "DB_NAME": stack["db_name"],
        "DB_USER": creds["username"],
        "DB_PASSWORD": creds["password"],
    })
    run(["kubectl", "--kubeconfig", kubeconfig, "apply", "-f", "-"], input=cluster_role() + "---\n" + manifest)
    for deployment in ("catalog-api", "cart-worker"):
        run(["kubectl", "--kubeconfig", kubeconfig, "-n", "shop", "rollout", "status",
             f"deployment/{deployment}", "--timeout=300s"])


def bootstrap_db(stack: dict, aws, connect=None) -> None:
    # The password first: a missing one is refused before any driver is needed or any secret is read.
    master = os.environ.get("WARDEN_FS_DB_MASTER_PASSWORD") or os.environ.get("TF_VAR_db_master_password")
    if not master:
        raise SystemExit("set WARDEN_FS_DB_MASTER_PASSWORD (or TF_VAR_db_master_password)")
    from psycopg import sql

    if connect is None:
        import psycopg

        connect = psycopg.connect
    app = secret_json(aws, stack["db_app_secret_name"])
    ro = secret_json(aws, stack["db_warden_ro_secret_name"])
    catalog = secret_json(aws, stack["db_catalog_secret_name"])
    text = (APPS / "sql" / "bootstrap.sql").read_text(encoding="utf-8")
    query = sql.SQL(text).format(app_password=sql.Literal(app["password"]),
                                 ro_password=sql.Literal(ro["password"]),
                                 catalog_password=sql.Literal(catalog["password"]))
    with connect(host=stack["aurora_writer_endpoint"], dbname=stack["db_name"],
                 user=stack["db_master_username"], password=master, port=5432,
                 sslmode="require", connect_timeout=10, autocommit=True) as conn:
        conn.execute(query)
    print("bootstrap.sql applied", flush=True)


# --------------------------------------------------------------------------- cli

def main(argv: list[str] | None = None, *, aws=None, runner=run) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", type=pathlib.Path, default=DEFAULT_OUT)
    p.add_argument("--stack", type=pathlib.Path, help="default: <out>/stack.json")
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--skip-image", action="store_true")
    b.add_argument("--tag")
    d = sub.add_parser("deploy")
    d.add_argument("target", choices=["lambdas", "ecs", "k8s", "all"])
    d.add_argument("--tag", help="image tag (default: <out>/image-tag.txt from build)")
    d.add_argument("--no-wait", action="store_true")
    sub.add_parser("bootstrap-db")
    args = p.parse_args(argv)

    out = args.out.expanduser().resolve()
    if out == ROOT or ROOT in out.parents:
        raise SystemExit(f"--out {out} is inside the repository; build output must live outside it")
    out.mkdir(parents=True, exist_ok=True)

    if args.cmd == "build" or (args.cmd == "deploy" and args.target == "all"):
        build_lambdas(out, runner)
        if not getattr(args, "skip_image", False):
            build_image(out, getattr(args, "tag", None) or default_tag(runner), runner)
        if args.cmd == "build":
            return 0

    stack_path = args.stack or out / "stack.json"
    stack = load_stack(stack_path)
    aws = aws or boto_factory(stack["region"])
    if args.cmd == "bootstrap-db":
        bootstrap_db(stack, aws)
        return 0

    targets = ["lambdas", "ecs", "k8s"] if args.target == "all" else [args.target]
    tag = None
    if {"ecs", "k8s"} & set(targets):
        tag = args.tag or (out / "image-tag.txt").read_text(encoding="utf-8").strip()
    for target in targets:
        if target == "lambdas":
            deploy_lambdas(stack, out, aws)
        elif target == "ecs":
            arn = deploy_ecs(stack, tag, aws, runner, wait=not args.no_wait)
            record_in_stack(stack_path, "ecs_baseline_task_definition", arn)
        else:
            deploy_k8s(stack, tag, out, aws, runner)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
