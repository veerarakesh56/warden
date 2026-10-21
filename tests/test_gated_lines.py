"""Two Lambda lines were printed past the log gate, and the discussion listener's handler
shadowed the module's own description of an event, so every event was logged as a coroutine that never ran."""

from __future__ import annotations

import ast
import pathlib

from warden import discuss
from warden.observability import gated

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_a_printed_line_goes_out_as_the_log_gate_lets_it():
    key = "AK" + "IA" + "ABCDEFGHIJKLMNOP"  # built from parts
    out = gated(f'{{"by": "someone", "key": "{key}"}}\x07')
    assert key not in out
    assert "\x07" not in out


def test_every_print_in_the_lambdas_is_gated():
    tree = ast.parse((ROOT / "src" / "warden" / "lambdas.py").read_text(encoding="utf-8"))
    prints = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "print"]
    assert prints, "the walk found no print - the test itself has rotted"
    for call in prints:
        inner = call.args[0] if call.args else None
        assert isinstance(inner, ast.Call), ast.unparse(call)
        assert getattr(inner.func, "id", "") == "gated", ast.unparse(call)


def test_no_function_inside_listen_shadows_one_of_the_module():
    tree = ast.parse((ROOT / "src" / "warden" / "discuss.py").read_text(encoding="utf-8"))
    module = {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    listen = next(n for n in tree.body if isinstance(n, ast.AsyncFunctionDef) and n.name == "listen")
    inner = {n.name for n in ast.walk(listen) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))} - {"listen"}
    assert inner, inner & module
    assert not inner & module, inner & module
    assert discuss.heard({"type": "app_mention", "channel": "C1"}, {"C1": ""}).startswith("discuss: heard app_mention")
