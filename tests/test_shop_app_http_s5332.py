"""Why the demo shop's own server may speak plain HTTP (Sonar python:S5332 on scenarios/fullstack/app/app.py, kept for
the owner to review, 2026-10-17). The comment at the server names four facts; each is held here, so the day one stops
being true this fails and the server needs TLS:

1. a request carries nothing the server reads - it answers GET only and never reads a header or a body;
2. on ECS only the load balancer reaches the port, and only the in-VPC Lambdas reach the load balancer;
3. the load balancer is internal;
4. on EKS the shop is a ClusterIP Service: no Ingress, Gateway, LoadBalancer or NodePort exposes it."""

from __future__ import annotations

import ast
import pathlib
import re

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = ROOT / "scenarios" / "fullstack" / "app" / "app.py"
TF = ROOT / "terraform" / "fullstack"
MANIFESTS = [ROOT / "manifests" / "shop", ROOT / "k8s"]


def _resource(kind: str, name: str) -> str:
    text = "".join(p.read_text(encoding="utf-8") for p in sorted(TF.glob("*.tf")))
    found = re.search(rf'^resource "{kind}" "{name}" \{{\n(.*?)^\}}', text, re.DOTALL | re.MULTILINE)
    assert found, f"{kind}.{name} is gone: re-check why the shop may serve plain HTTP"
    return found.group(1)


def _ingress(body: str) -> list[str]:
    return re.findall(r"^  ingress \{\n(.*?)^  \}", body, re.DOTALL | re.MULTILINE)


def test_the_server_answers_get_only_and_reads_nothing_a_client_sends():
    tree = ast.parse(APP.read_text(encoding="utf-8"))
    handler = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Handler")
    verbs = sorted(n.name for n in handler.body if isinstance(n, ast.FunctionDef) and n.name.startswith("do_"))
    assert verbs == ["do_GET"]
    read = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not read & {"headers", "rfile"}, "the server reads a header or a body now: a credential could ride on it"


def test_on_ecs_only_the_internal_load_balancer_reaches_the_port():
    assert re.search(r"^\s+internal\s+=\s+true$", _resource("aws_lb", "orders"), re.MULTILINE)
    (task_rule,) = _ingress(_resource("aws_security_group", "ecs"))
    assert "security_groups = [aws_security_group.alb.id]" in task_rule
    assert "cidr" not in task_rule
    (alb_rule,) = _ingress(_resource("aws_security_group", "alb"))
    assert "security_groups = [aws_security_group.lambda.id]" in alb_rule
    assert "cidr" not in alb_rule
    assert not _ingress(_resource("aws_security_group", "lambda"))
    text = "".join(p.read_text(encoding="utf-8") for p in TF.glob("*.tf"))
    for sg in ("ecs", "alb"):  # no rule added beside the inline ones
        assert not re.search(rf"security_group_id\s*=\s*aws_security_group\.{sg}\.id", text), sg


def test_on_eks_the_shop_is_reached_from_inside_the_cluster_only():
    docs = [d for base in MANIFESTS for p in sorted(base.rglob("*.yaml"))
            for d in yaml.safe_load_all(p.read_text(encoding="utf-8")) if isinstance(d, dict)]
    assert any(d.get("kind") == "Service" and d["metadata"]["name"] == "catalog-api" for d in docs)
    for doc in docs:
        assert doc.get("kind") not in {"Ingress", "Gateway", "HTTPRoute"}, doc["metadata"]["name"]
        if doc.get("kind") == "Service":
            assert doc.get("spec", {}).get("type", "ClusterIP") == "ClusterIP", doc["metadata"]["name"]
