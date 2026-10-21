"""The load Lambdas pick carts, SKUs, customers and order ids with the operating system's CSPRNG (Sonar python:S2245,
2026-10-20): random.SystemRandom, which cannot be seeded, instead of the module's Mersenne Twister."""

from __future__ import annotations

import ast
import importlib.util
import pathlib
import random
import sys
import types

ROOT = pathlib.Path(__file__).resolve().parents[2]
LAMBDAS = ROOT / "demo-app" / "lambdas"
LOADERS = ("traffic", "reconciler")


def _calls_on_random_module(tree: ast.AST) -> list[str]:
    return [node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "random"]


def test_every_load_pick_comes_from_one_unseeded_system_random():
    for name in LOADERS:
        tree = ast.parse((LAMBDAS / name / "app.py").read_text(encoding="utf-8"))
        # The random module is called for one thing only: building the SystemRandom instance.
        assert _calls_on_random_module(tree) == ["SystemRandom"], name
        rng_users = [node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call)
                     and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
                     and node.func.value.id == "_RNG"]
        assert rng_users, name
        assert "seed" not in rng_users, name
        assert "setstate" not in rng_users, name


def test_the_traffic_lambda_draws_its_load_from_the_system_random(monkeypatch):
    monkeypatch.setitem(sys.modules, "boto3", types.SimpleNamespace(client=lambda *a, **k: types.SimpleNamespace(
        send_message=lambda **kw: None, get_secret_value=lambda **kw: {"SecretString": "t" * 48})))
    spec = importlib.util.spec_from_file_location("fs_traffic_rng", LAMBDAS / "traffic" / "app.py")
    app = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app)
    assert isinstance(app._RNG, random.SystemRandom)

    drawn = []

    class Recording(random.SystemRandom):
        def randint(self, a, b):
            drawn.append(("randint", a, b))
            return super().randint(a, b)

        def choice(self, seq):
            drawn.append(("choice", len(seq)))
            return super().choice(seq)

    monkeypatch.setattr(app, "_RNG", Recording())
    monkeypatch.setattr(app, "_call", lambda method, url, body=None, headers=None: 200)
    for name, value in {"API_URL": "https://api.example", "ALB_URL": "https://alb.example", "ORDERS_QUEUE_URL": "q",
                        "CHECKOUTS_PER_MIN": "1", "ORDERS_PER_MIN": "1", "API_TOKEN_SECRET": "arn"}.items():
        monkeypatch.setenv(name, value)
    app.handler({}, None)
    # One checkout (cart, SKU, quantity) and one order (cart, customer, SKU, quantity), every pick from it.
    assert [d[0] for d in drawn] == ["randint", "choice", "randint", "randint", "randint", "choice", "randint"]
