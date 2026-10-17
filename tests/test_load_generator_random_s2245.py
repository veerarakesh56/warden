"""The load generators use `random`, not `secrets`, by design (Sonar python:S2245 x9 in the traffic and reconciler
Lambdas, kept for the owner to review, 2026-10-17). Their numbers only pick synthetic load - which cart, SKU, quantity,
customer or seeded order to send or look up - and nothing guesses, signs or trusts them. This holds that claim: every
use of `random` in those files is a randint/choice inside the handler that becomes one of those load values, and none
reaches the code that handles a credential (the API's bearer token, the database's IAM token)."""

from __future__ import annotations

import ast
import pathlib

import pytest

LAMBDAS = pathlib.Path(__file__).resolve().parents[1] / "scenarios" / "fullstack" / "lambdas"
FILES = {"traffic": LAMBDAS / "traffic" / "app.py", "reconciler": LAMBDAS / "reconciler" / "app.py"}
# What a random number may become: an id with one of these prefixes, an SKU from the list, or a quantity.
ID_PREFIXES = ("cart-", "cust-", "seed-")
LOAD_KEYS = {"sku", "qty"}


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}


def _what_it_becomes(call: ast.Call, up: dict[ast.AST, ast.AST]) -> str | None:
    """The load value a random call ends up in, or None when it is used for anything else."""
    parent = up[call]
    if isinstance(parent, ast.FormattedValue) and isinstance(up[parent], ast.JoinedStr):
        head = up[parent].values[0]
        if isinstance(head, ast.Constant) and str(head.value).startswith(ID_PREFIXES):
            return str(head.value)
    if isinstance(parent, ast.Dict):
        key = parent.keys[parent.values.index(call)]
        if isinstance(key, ast.Constant) and key.value in LOAD_KEYS:
            return key.value
    return None


def _random_calls(tree: ast.AST) -> list[ast.Call]:
    return [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and isinstance(n.func.value, ast.Name) and n.func.value.id == "random"]


@pytest.mark.parametrize("name", sorted(FILES))
def test_every_random_number_only_picks_synthetic_load(name):
    source = FILES[name].read_text(encoding="utf-8")
    tree = ast.parse(source)
    up = _parents(tree)
    calls = _random_calls(tree)
    assert calls, "no random call left: drop this test and the by-design entry"
    # `random` is only ever called as random.randint/choice: never stored, aliased or passed on.
    uses = [n for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id == "random"]
    assert len(uses) == len(calls), "`random` is used other than as random.randint(...) / random.choice(...)"
    for call in calls:
        assert call.func.attr in {"randint", "choice"}, call.func.attr
        where = up[call]
        while not isinstance(where, ast.FunctionDef):
            where = up[where]
        assert where.name == "handler", f"random used in {where.name}(), not only to pick the load"
        assert _what_it_becomes(call, up), f"line {call.lineno}: a random value used for something other than load"
    assert "`random`, not `secrets`, on purpose (Sonar python:S2245" in source


@pytest.mark.parametrize("name", sorted(FILES))
def test_the_credentials_never_meet_a_random_number(name):
    """The functions that fetch or build a credential (_bearer, _token, _meta) call no random function; in the handler a
    random number only ever becomes a load value (above), so none reaches a token or a password."""
    tree = ast.parse(FILES[name].read_text(encoding="utf-8"))
    for fn in (n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name != "handler"):
        assert not _random_calls(fn), fn.name
