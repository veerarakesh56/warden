"""scripts/preflight_db_ops.py runs only live, against the real database, so no unit test ever executes its calls of
the baseline gate. This reads them instead: every call of `check_baseline_db` and `_settle_to_baseline` in the script
must bind to the function's signature as the script imports it, each variable passed by position to the parameter of
its own name. Two branches that each change one side (the gate's
parameters, or the helpers the calls move into) merge cleanly and would otherwise fail only on the next live run."""

from __future__ import annotations

import ast
import importlib.util
import inspect
import pathlib

import pytest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "preflight_db_ops.py"
CHECKED = ("check_baseline_db", "_settle_to_baseline")


def _module():
    """Imported, not run: the script reaches AWS only from main()."""
    spec = importlib.util.spec_from_file_location("preflight_db_ops", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _calls() -> list[ast.Call]:
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    return [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in CHECKED
    ]


def _binds(signature: inspect.Signature, call: ast.Call) -> str | None:
    """None when the call's arguments fit the signature, else why not."""
    if any(isinstance(a, ast.Starred) for a in call.args) or any(
        k.arg is None for k in call.keywords
    ):
        return "a *args or **kwargs call cannot be checked here"
    try:
        signature.bind(*range(len(call.args)), **{k.arg: None for k in call.keywords})
    except TypeError as exc:
        return str(exc)
    # A count alone is not enough: `_settle_to_baseline(clients, target)` against `(clients, seconds=30)` binds,
    # with the target as the seconds. A variable passed by position must land on the parameter of its own name.
    names = list(signature.parameters)
    misplaced = [
        f"passes {a.id} as {names[i]}"
        for i, a in enumerate(call.args)
        if isinstance(a, ast.Name) and i < len(names) and a.id != names[i]
    ]
    return "; ".join(misplaced) or None


def test_the_script_calls_both_functions():
    assert {c.func.id for c in _calls()} == set(CHECKED)


@pytest.mark.parametrize("name", CHECKED)
def test_every_call_fits_the_functions_signature(name):
    signature = inspect.signature(getattr(_module(), name))
    wrong = [
        f"line {c.lineno}: {name}{signature} - {why}"
        for c in _calls()
        if c.func.id == name and (why := _binds(signature, c))
    ]
    assert wrong == []
