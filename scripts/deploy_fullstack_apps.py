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
  deploy ecs    ECR login + push, register a task definition revision (the task role that signs
                IAM database tokens as user app; DB_USER injected from the metadata secret),
                update-service, wait until stable. Records the revision in stack.json as
                `ecs_baseline_task_definition` - the revision the harness reverts to.
  deploy k8s    the agents and Argo CD; then what the pipeline owns (k8s/shop-pipeline: the
                namespace, the Secret with a generated signing key over stdin, the infrastructure's
                endpoints from stack.json) with the ClusterRole from k8s/rbac.yaml; then the shop
                Application (k8s/argocd/shop.yaml) pinned to this commit and its image, and waits
                until Argo CD has synced exactly that commit and the shop is Healthy.
  deploy all    build, then lambdas, ecs, k8s.
  bootstrap-db  scenarios/fullstack/sql/bootstrap.sql as the master user postgres, logged in with
                an IAM token signed by YOUR credentials (rds-db:connect on dbuser:*/postgres,
                terraform/proving-ground/operator-policy.json). There is no database password.

stack.json is `terraform output -json` with the sensitive entries removed (README).
"""
from __future__ import annotations

import argparse
import base64
import json
import pathlib
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
APPS = ROOT / "scenarios" / "fullstack"
# The shop's workloads are in Git (manifests/shop, synced by Argo CD); the pipeline applies only what it owns.
MANIFESTS = ROOT / "manifests" / "shop"
K8S_PIPELINE = ROOT / "k8s" / "shop-pipeline"
SHOP_APP = ROOT / "k8s" / "argocd" / "shop.yaml"
SYNC_TIMEOUT_S, SYNC_POLL_S = 600, 10
DEFAULT_OUT = pathlib.Path.home() / "warden-fullstack-build"
LAMBDA_SRC = APPS / "lambdas"
IMAGE = "warden-fullstack-app"  # the local build tag; the pushed image is named by the stack's own repository
PLACEHOLDER = re.compile(r"__[A-Z_]+__")
ZIP_DATE = (2026, 1, 1, 0, 0, 0)  # fixed, so an unchanged function builds a byte-identical zip


def run(cmd: list[str], *, input: str | None = None) -> str:
    """Run a command; stdin carries anything secret. Only the command is echoed."""
    print("+", " ".join(cmd), flush=True)
    # ⛔ UTF-8, not the locale: on Windows `text=True` decodes as cp1252 and docker's build output
    # (progress glyphs) crashed the reader thread mid-build (2026-09-26).
    done = subprocess.run(cmd, input=input, capture_output=True, check=False,
                          encoding="utf-8", errors="replace")
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


LAMBDA_PYTHON = "3.12"  # the runtime terraform/fullstack/lambda.tf declares


def requested_extras(requirements: pathlib.Path) -> dict[str, set[str]]:
    """The extras each top-level requirement asks for: `psycopg[binary]` -> {"psycopg": {"binary"}}."""
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name

    out: dict[str, set[str]] = {}
    for line in requirements.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            req = Requirement(line)
            out.setdefault(canonicalize_name(req.name), set()).update(req.extras)
    return out


def missing_dependencies(target: pathlib.Path, python_version: str = LAMBDA_PYTHON,
                         extras: dict[str, set[str]] | None = None) -> list[str]:
    """Requirements of the packages in `target` that are not themselves in `target`, with environment
    markers evaluated for the LAMBDA's Python.

    ⛔ Why: pip evaluates markers for the interpreter RUNNING it. Built on Python 3.13, psycopg's
    `typing-extensions; python_version < "3.13"` was skipped and both database Lambdas died on import in
    AWS (Runtime.ImportModuleError, 2026-09-26). This makes that a build failure instead.
    """
    from importlib.metadata import PathDistribution

    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name

    env = {"python_version": python_version, "python_full_version": f"{python_version}.0",
           "sys_platform": "linux", "platform_system": "Linux", "os_name": "posix",
           "platform_machine": "x86_64", "implementation_name": "cpython",
           "platform_python_implementation": "CPython", "extra": ""}
    dists = {canonicalize_name(PathDistribution(d).metadata["Name"]): PathDistribution(d)
             for d in target.glob("*.dist-info")}
    missing = set()
    # The extras the Lambda asks for count too: without `psycopg-binary` a `psycopg[binary]` Lambda dies on import,
    # and an extra's requirements were never checked (fifth review, 2026-10-01). And the extras those requirements
    # ask for in turn - `boto3[crt]` asks botocore for its `crt` extra (register R7-O4): followed to the end.
    asked = {canonicalize_name(k): set(v) for k, v in (extras or {}).items()}
    queue, done = list(dists), set()
    while queue:
        name = queue.pop()
        for extra in ("", *sorted(asked.get(name, ()))):
            if (name, extra) in done:
                continue
            done.add((name, extra))
            for raw in dists[name].requires or []:
                req = Requirement(raw)
                if req.marker is not None and not req.marker.evaluate({**env, "extra": extra}):
                    continue
                dep = canonicalize_name(req.name)
                if dep not in dists:
                    missing.add(req.name)
                elif set(req.extras) - asked.get(dep, set()):
                    asked.setdefault(dep, set()).update(req.extras)
                    queue.append(dep)
    return sorted(missing)


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
                # requirements.txt is compiled for the Lambda (3.12, x86_64 Linux) and holds every package with
                # its hash, so pip installs exactly it: --no-deps, because pip evaluates dependency markers
                # for THIS machine, and on Windows psycopg's `tzdata; sys_platform == "win32"` - absent from
                # the file - stopped the hash-checked install (2026-10-01).
                run([sys.executable, "-m", "pip", "install", "--quiet", "--no-deps", "--require-hashes", "-r", str(req),
                     "--target", str(stage), "--platform", "manylinux2014_x86_64", "--only-binary=:all:",
                     "--implementation", "cp", "--python-version", LAMBDA_PYTHON])
                wanted = src / "requirements.in"
                missing = missing_dependencies(stage, extras=requested_extras(wanted) if wanted.is_file() else {})
                if missing:
                    raise SystemExit(f"{fn}: the package lacks {missing} - a dependency whose marker pip "
                                     f"evaluated for THIS Python, not the Lambda's {LAMBDA_PYTHON}. Pin it "
                                     f"in {req.relative_to(ROOT).as_posix()}.")
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
        # Signs orders-api's IAM database tokens (rds-db:connect as app; fs-21 removes it).
        "taskRoleArn": stack["ecs_task_role_arn"],
        "tags": [{"key": "Project", "value": "warden"},
                 {"key": "Environment", "value": stack["environment"]}],
        "containerDefinitions": [{
            "name": "orders-api",
            "image": image,
            "essential": True,
            "portMappings": [{"containerPort": 8080, "protocol": "tcp"}],
            "environment": [
                {"name": "APP_ROLE", "value": "orders-api"},
                {"name": "REDIS_HOST", "value": stack["redis_primary_endpoint"]},
                {"name": "DB_HOST", "value": stack["aurora_writer_endpoint"]},
                {"name": "DB_NAME", "value": stack["db_name"]},
                {"name": "AWS_REGION", "value": stack["region"]},
                # Fault flag at its baseline value (scenarios/ops_fullstack.py FLAGS, fs-20).
                {"name": "ORDERS_FF_1", "value": "0"},
            ],
            # DB_USER (= app) comes from the metadata secret on purpose: no password exists any
            # more, but the EXECUTION role must still resolve a secret at task start, or fs-18
            # (that grant removed) would no longer stop anything.
            "secrets": [
                {"name": "DB_USER", "valueFrom": f"{secret}:username::"},
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


def render(manifest: str, values: dict[str, str]) -> str:
    for key, value in values.items():
        manifest = manifest.replace(f"__{key}__", value)
    left = sorted(set(PLACEHOLDER.findall(manifest)))
    if left:
        raise SystemExit(f"unfilled placeholders: {left}")
    return manifest


def cluster_role() -> str:
    import yaml

    docs = yaml.safe_load_all((ROOT / "k8s" / "rbac.yaml").read_text(encoding="utf-8"))
    role = next(d for d in docs if d and d.get("kind") == "ClusterRole")
    return yaml.safe_dump(role, sort_keys=False)


# Datadog's agent on the test cluster (owner, 2026-10-14: Datadog as the observability tool WARDEN reads beside AWS):
# logs from every container, Kubernetes metrics, and APM traces by single-step instrumentation in the shop namespace -
# no code change in the apps. Chart 3.250.3, released 2026-09-29 (github.com/DataDog/helm-charts), two weeks old when
# pinned; its values as docs.datadoghq.com documents them for single-step APM (read 2026-10-14).
DATADOG_CHART = "3.250.3"
DATADOG_SITES = frozenset({"datadoghq.com", "us3.datadoghq.com", "us5.datadoghq.com", "datadoghq.eu",
                           "ap1.datadoghq.com", "ap2.datadoghq.com", "uk1.datadoghq.com", "ddog-gov.com",
                           "us2.ddog-gov.com"})


# Argo CD (owner, 2026-10-16: GitOps for the cluster - the shop is synced from manifests/ in this repository). The
# chart's own package, fetched from the argo-helm release and installed only if its bytes are these: a pinned version
# number alone would install whatever the repository serves under it. Settings: helm/argo-cd/values.yaml (why each).
ARGOCD_CHART = "10.9.7"  # Argo CD v3.5.4 - the oldest release fixing the Critical advisories of 2026-10-07
ARGOCD_CHART_URL = f"https://github.com/argoproj/argo-helm/releases/download/argo-cd-{ARGOCD_CHART}/argo-cd-{ARGOCD_CHART}.tgz"
ARGOCD_CHART_SHA256 = "c3c595b857a5a4a76e622b36cfacd4127120202bcfa6536fc65f01382a10f035"
ARGOCD_VALUES = ROOT / "helm" / "argo-cd" / "values.yaml"


def _fetch_chart(url: str) -> bytes:
    import urllib.request

    if not url.startswith("https://"):
        raise SystemExit(f"a chart is fetched over https only, not {url!r}")
    with urllib.request.urlopen(url, timeout=60) as resp:  # nosec B310 - https only (above); its bytes are checked after
        return resp.read()


def deploy_argocd(kubeconfig: str, out: pathlib.Path, run=run) -> None:
    """Install or upgrade Argo CD in namespace argocd, from the checked chart package, and wait for it."""
    import hashlib

    package = _fetch_chart(ARGOCD_CHART_URL)
    got = hashlib.sha256(package).hexdigest()
    if got != ARGOCD_CHART_SHA256:
        raise SystemExit(f"the Argo CD chart package is not the pinned one (sha256 {got}): nothing installed")
    chart = out / f"argo-cd-{ARGOCD_CHART}.tgz"
    chart.write_bytes(package)
    run(["helm", "upgrade", "--install", "argocd", str(chart), "--namespace", "argocd", "--create-namespace",
         "--kubeconfig", kubeconfig, "--values", str(ARGOCD_VALUES), "--wait", "--timeout", "10m"])


def deploy_datadog(stack: dict, kubeconfig: str, aws, run=run) -> bool:
    """Install Datadog's agent before the apps roll out, so their pods start traced. Its API key is the persistent
    secret `warden-<env>-datadog-api-key` (pasted once by the owner; never in Terraform state), its site the plain
    setting `/warden/<env>/tf/datadog_site` (the deploy role reads that path alone). Neither set: nothing is installed, and it says so."""
    import base64

    env = stack["environment"]
    try:
        key = aws("secretsmanager").get_secret_value(SecretId=f"warden-{env}-datadog-api-key")["SecretString"].strip()
        site = aws("ssm").get_parameter(Name=f"/warden/{env}/tf/datadog_site")["Parameter"]["Value"].strip()
    except Exception as exc:  # noqa: BLE001 - no key or no site: the stack runs without Datadog
        print(f"Datadog agent not installed: its key or site is not set ({type(exc).__name__})", flush=True)
        return False
    if not key or site not in DATADOG_SITES:
        print("Datadog agent not installed: the key is empty or the site is not one of Datadog's", flush=True)
        return False
    secret = (f"apiVersion: v1\nkind: Namespace\nmetadata:\n  name: datadog\n---\napiVersion: v1\nkind: Secret\n"
              f"metadata:\n  name: datadog-secret\n  namespace: datadog\ntype: Opaque\ndata:\n"
              f"  api-key: {base64.b64encode(key.encode()).decode()}\n")
    run(["kubectl", "--kubeconfig", kubeconfig, "apply", "-f", "-"], input=secret)  # the key over stdin only
    run(["helm", "repo", "add", "datadog", "https://helm.datadoghq.com", "--force-update"])
    run(["helm", "upgrade", "--install", "datadog-agent", "datadog/datadog", "--version", DATADOG_CHART,
         "--namespace", "datadog", "--kubeconfig", kubeconfig, "--wait", "--timeout", "10m",
         "--set", f"datadog.site={site}", "--set", f"datadog.clusterName={stack['eks_cluster_name']}",
         "--set", "datadog.apiKeyExistingSecret=datadog-secret",
         "--set", "datadog.logs.enabled=true", "--set", "datadog.logs.containerCollectAll=true",
         # Every metric and log from this agent carries the stack's env (the monitors filter on it); the pods' own
         # tags.datadoghq.com labels (manifests/shop) give env and service per workload.
         "--set", f"datadog.tags[0]=env:{stack['environment']}",
         # The apps' OpenTelemetry data, from the collector on the same node (deploy_otel): every tool gets the same
         # spans, so the comparison is fair - no second, Datadog-only instrumentation.
         "--set", "datadog.otlp.receiver.protocols.grpc.enabled=true",
         "--set", "datadog.otlp.receiver.protocols.grpc.endpoint=0.0.0.0:4317",
         # The apps' OpenTelemetry logs too, with their severity: the apps log to stdout, which Datadog files as info,
         # so without these no log is ever status:error (both checked against chart 3.250.3's values, 2026-10-14).
         "--set", "datadog.otlp.logs.enabled=true"])
    return True


# The OpenTelemetry collector: AWS's distribution, v0.50.0 (released 2026-08-31, github.com/aws-observability/
# aws-otel-collector; its awsxray, otlp and otlphttp exporters unchanged in it, read 2026-10-14).
OTEL_IMAGE = "public.ecr.aws/aws-observability/aws-otel-collector:v0.50.0"


def otel_config(region: str, *, datadog: bool = False) -> dict:
    """The collector's configuration for the tools that are set up: Datadog when its agent is on the cluster, else
    X-Ray (traces, by the pod's IAM role). No Grafana (owner, 2026-10-16: Datadog only).

    Not both (cost plan, 2026-10-17: the owner's last ~USD 104 of credits): with Datadog on, the X-Ray copy cost about
    USD 8.5 a month in stored traces (USD 3 more of Application Signals, expected to stop with them), and nothing read it - the runtime's
    WARDEN_EVIDENCE_TOOLS names datadog and github, which leaves X-Ray's reader out (tools.evidence_tools). The X-Ray
    arm of scripts/compare_evidence.py needs the apps deployed without Datadog."""
    exporters: dict = {} if datadog else {"awsxray": {"region": region}}
    traces, metrics, logs = list(exporters), [], []
    if datadog:
        # Plaintext gRPC on purpose (2026-10-16, naming audit item 19): HOST_IP is the collector pod's own node,
        # and 4317 there is the Datadog agent's OTLP receiver on its hostPort, so the hop never leaves the node.
        # The agent has no TLS listener to offer: chart 3.250.3 exposes only `enabled`, `endpoint` and
        # `useHostPort` for that receiver (its values.yaml, read 2026-10-16). TLS on it would mean configuring the
        # agent's embedded OTLP receiver directly and issuing it a certificate the collector trusts. The agent
        # sends on to Datadog over TLS itself.
        exporters["otlp/datadog"] = {"endpoint": "${env:HOST_IP}:4317", "tls": {"insecure": True}}
        traces.append("otlp/datadog")
        metrics.append("otlp/datadog")
        logs.append("otlp/datadog")
    pipelines = {"traces": {"receivers": ["otlp"], "processors": ["memory_limiter", "batch"], "exporters": traces}}
    if metrics:
        pipelines["metrics"] = {"receivers": ["otlp"], "processors": ["memory_limiter", "batch"], "exporters": metrics}
    if logs:
        pipelines["logs"] = {"receivers": ["otlp"], "processors": ["memory_limiter", "batch"], "exporters": logs}
    return {"receivers": {"otlp": {"protocols": {"grpc": {"endpoint": "0.0.0.0:4317"},
                                                 "http": {"endpoint": "0.0.0.0:4318"}}}},
            "processors": {"memory_limiter": {"check_interval": "1s", "limit_percentage": 80,
                                              "spike_limit_percentage": 20}, "batch": {}},
            "exporters": exporters, "service": {"pipelines": pipelines}}


def deploy_otel(stack: dict, kubeconfig: str, datadog: bool, run=run) -> dict:
    """The collector in the observability namespace, before the apps roll out. It holds no key: X-Ray by the pod's
    IAM role, Datadog through the agent on its node."""
    import yaml

    config = otel_config(stack["region"], datadog=datadog)
    ns = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "observability"}}
    sa = {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "otel-collector", "namespace": "observability"}}
    cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "otel-collector", "namespace": "observability"},
          "data": {"config.yaml": yaml.safe_dump(config, sort_keys=False)}}
    docs = [ns, sa, cm]
    env_vars = [{"name": "HOST_IP", "valueFrom": {"fieldRef": {"fieldPath": "status.hostIP"}}}]
    labels = {"app": "otel-collector"}
    docs.append({"apiVersion": "apps/v1", "kind": "Deployment",
                 "metadata": {"name": "otel-collector", "namespace": "observability", "labels": labels},
                 "spec": {"replicas": 1, "selector": {"matchLabels": labels}, "template": {
                     "metadata": {"labels": labels},
                     "spec": {"serviceAccountName": "otel-collector",
                              "containers": [{"name": "collector", "image": OTEL_IMAGE,
                                              "args": ["--config=/conf/config.yaml"], "env": env_vars,
                                              "ports": [{"containerPort": 4317}, {"containerPort": 4318}],
                                              "resources": {"requests": {"cpu": "100m", "memory": "200Mi"},
                                                            "limits": {"memory": "400Mi"}},
                                              "volumeMounts": [{"name": "conf", "mountPath": "/conf"}]}],
                              "volumes": [{"name": "conf", "configMap": {"name": "otel-collector"}}]}}}})
    docs.append({"apiVersion": "v1", "kind": "Service", "metadata": {"name": "otel-collector", "namespace": "observability"},
                 "spec": {"selector": labels, "ports": [{"name": "grpc", "port": 4317}, {"name": "http", "port": 4318}]}})
    run(["kubectl", "--kubeconfig", kubeconfig, "apply", "-f", "-"], input=yaml.safe_dump_all(docs, sort_keys=False))
    run(["kubectl", "--kubeconfig", kubeconfig, "-n", "observability", "rollout", "status", "deployment/otel-collector",
         "--timeout=300s"])
    return config


def deploy_k8s(stack: dict, tag: str, out: pathlib.Path, aws, run=run, revision: str | None = None,
               sleep=None) -> None:
    kubeconfig = str(out / "kubeconfig")
    run(["aws", "eks", "update-kubeconfig", "--name", stack["eks_cluster_name"],
         "--region", stack["region"], "--kubeconfig", kubeconfig])
    datadog = deploy_datadog(stack, kubeconfig, aws, run)
    deploy_otel(stack, kubeconfig, datadog, run)
    deploy_argocd(kubeconfig, out, run=run)
    # What the pipeline owns. catalog-api logs in as user catalog with an IAM token (EKS Pod Identity); the one Secret
    # value is its signing key, generated here and sent over stdin. fs-23 removes it.
    manifest = render(run(["kubectl", "--kubeconfig", kubeconfig, "kustomize", str(K8S_PIPELINE)]), {
        "REDIS_HOST": stack["redis_primary_endpoint"],
        "DB_READER_HOST": stack["aurora_reader_endpoint"],
        "DB_NAME": stack["db_name"],
        "REGION": stack["region"],
        "ENVIRONMENT": stack["environment"],
        "DB_USER_CATALOG": db_users(stack)["catalog"],
        "CATALOG_SIGNING_KEY": secrets.token_hex(32),
    })
    run(["kubectl", "--kubeconfig", kubeconfig, "apply", "-f", "-"], input=cluster_role() + "---\n" + manifest)
    # The workloads: Argo CD syncs manifests/shop/<env> at exactly this commit, with this commit's image.
    rev = revision or commit()
    app = render(SHOP_APP.read_text(encoding="utf-8"), {
        "REPO_URL": repo_url(), "REVISION": rev, "IMAGE": f"{stack['ecr_repository_url']}:{tag}",
        "ENVIRONMENT": stack["environment"]})
    run(["kubectl", "--kubeconfig", kubeconfig, "apply", "-f", "-"], input=app)
    wait_synced(kubeconfig, rev, run, sleep=sleep)


_SHA = re.compile(r"[0-9a-f]{40}")


def commit() -> str:
    """The full commit being deployed: CI's own, else this checkout's HEAD. Argo CD syncs exactly it."""
    import os

    sha = os.environ.get("GITHUB_SHA") or run(["git", "-C", str(ROOT), "rev-parse", "HEAD"]).strip()
    if not _SHA.fullmatch(sha):
        raise SystemExit(f"not a commit id: {sha!r}")
    return sha


def repo_url() -> str:
    """This repository's https URL, which Argo CD reads (public: no credential): CI's own, else the origin remote."""
    import os

    if os.environ.get("GITHUB_REPOSITORY"):
        return f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/{os.environ['GITHUB_REPOSITORY']}"
    url = run(["git", "-C", str(ROOT), "remote", "get-url", "origin"]).strip().removesuffix(".git")
    if url.startswith("git@github.com:"):
        url = "https://github.com/" + url.removeprefix("git@github.com:")
    if not re.fullmatch(r"https://github\.com/[\w.-]+/[\w.-]+", url):
        raise SystemExit(f"the origin remote is not a GitHub https or ssh URL: {url!r}")
    return url


def wait_synced(kubeconfig: str, revision: str, run=run, sleep=None) -> None:
    """Until Argo CD has synced exactly `revision` and the shop is Healthy - or say why not. A sync that failed is not
    waited out; one that never reaches the commit fails the deploy (a commit not pushed, a repository Argo CD cannot
    read), as it would in production."""
    import json
    import time

    sleep = sleep or time.sleep
    seen = "no status yet"
    for _ in range(SYNC_TIMEOUT_S // SYNC_POLL_S):
        raw = run(["kubectl", "--kubeconfig", kubeconfig, "-n", "argocd", "get", "application", "shop", "-o", "json"])
        status = (json.loads(raw) if raw.strip() else {}).get("status") or {}
        sync, health = status.get("sync") or {}, status.get("health") or {}
        phase = (status.get("operationState") or {}).get("phase", "")
        seen = (f"revision {sync.get('revision', '?')[:12]}, sync {sync.get('status', '?')}, health "
                f"{health.get('status', '?')}, operation {phase or '-'}")
        if sync.get("revision") == revision and phase in ("Failed", "Error"):
            raise SystemExit(f"Argo CD's sync of {revision[:12]} failed: {seen}: "
                             f"{(status.get('operationState') or {}).get('message', '')[:400]}")
        if sync.get("revision") == revision and sync.get("status") == "Synced" and health.get("status") == "Healthy":
            print(f"Argo CD: shop synced at {revision[:12]} and Healthy", flush=True)
            return
        sleep(SYNC_POLL_S)
    raise SystemExit(f"Argo CD did not sync {revision[:12]} to Healthy in {SYNC_TIMEOUT_S} s: {seen}")


_DB_USER = re.compile(r"warden_[a-z0-9_]{1,40}_(?:app|catalog|ro)")


def db_users(stack: dict) -> dict[str, str]:
    """The environment's database users from stack.json (Terraform's `db_users`; audit A-I-2), each checked to
    be a plain identifier before it goes into SQL or a manifest."""
    users = stack.get("db_users")
    if not isinstance(users, dict) or set(users) != {"app", "catalog", "ro"}:
        raise SystemExit("stack.json has no db_users: write it from `terraform output -json` (README)")
    bad = [u for u in users.values() if not (isinstance(u, str) and _DB_USER.fullmatch(u))]
    if bad:
        raise SystemExit(f"stack.json db_users holds a name that is not a database user: {bad}")
    # Exactly the names Terraform derives for THIS stack's environment: a shape check accepted another
    # environment's users, or one name for all three - the read-only user merged into the app's (seventh review).
    env = stack.get("environment")
    want = {k: f"warden_{str(env).replace('-', '_')}_{k}" for k in users}
    if not env or users != want:
        raise SystemExit(f"stack.json db_users are not environment {env!r}'s own: {users} (expected {want})")
    return users


def bootstrap_sql(users: dict[str, str]) -> str:
    """bootstrap.sql with the environment's users in place of __APP__ / __CATALOG__ / __RO__."""
    text = (APPS / "sql" / "bootstrap.sql").read_text(encoding="utf-8")
    for key, name in (("APP", users["app"]), ("CATALOG", users["catalog"]), ("RO", users["ro"])):
        text = text.replace(f"__{key}__", name)
    if PLACEHOLDER.search(text):
        raise SystemExit(f"unfilled placeholders in bootstrap.sql: {sorted(set(PLACEHOLDER.findall(text)))}")
    return text


def bootstrap_db(stack: dict, aws, connect=None) -> None:
    """bootstrap.sql as the master user, with an IAM token signed by the operator's credentials."""
    host, user = stack["aurora_writer_endpoint"], stack["db_master_username"]
    # Local signing, no API call: a missing rds-db:connect grant shows as PAM authentication failed.
    token = aws("rds").generate_db_auth_token(DBHostname=host, Port=5432, DBUsername=user,
                                              Region=stack["region"])
    if connect is None:
        import psycopg

        connect = psycopg.connect
    text = bootstrap_sql(db_users(stack))
    # Aurora express cannot create an initial database, so it is created here - from the always-present
    # `postgres` database, idempotently (CREATE DATABASE has no IF NOT EXISTS).
    with connect(host=host, dbname="postgres", user=user, password=token, port=5432,
                 sslmode="require", connect_timeout=10, autocommit=True) as conn:
        exists = conn.execute("SELECT 1 FROM pg_database WHERE datname = %s", (stack["db_name"],)).fetchone()
        if not exists:
            from psycopg import sql

            conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(stack["db_name"])))
            print(f"created database {stack['db_name']}", flush=True)
    with connect(host=host, dbname=stack["db_name"], user=user, password=token, port=5432,
                 sslmode="require", connect_timeout=10, autocommit=True) as conn:
        conn.execute(text)
    print("bootstrap.sql applied", flush=True)


# --------------------------------------------------------------------------- cli

def main(argv: list[str] | None = None, *, aws=None, runner=run) -> int:
    # ⛔ FIRST, before argparse can print: a Windows console is cp1252 and this output carries ⛔/⚠.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
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
