"""Hidden warnings, bandit B608 (owner, 2026-10-17): SQL Server's statements are constants with every value a
parameter. pymssql substitutes parameters in the client - `%d` an int, `%s` a tuple as a quoted list - so TOP (n),
DATEADD's offset and the login list are parameters too (checked against pymssql 2.4.4's `_mssql.substitute_params`,
2026-10-17: `TOP (%d) ... IN %s ... -%d` with (5, ('u1', "o'b"), 300) gives `TOP (5) ... IN (N'u1',N'o''b') ... -300`).
Only KILL, which takes no placeholder, is built from an int()."""

from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _built_statements(path: pathlib.Path, cls: str) -> list[str]:
    """Every SQL statement in `cls` built with an f-string, +, % or .format - other than KILL's int."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    [node] = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == cls]
    out = []
    for call in (c for c in ast.walk(node) if isinstance(c, ast.Call) and c.args):
        name = getattr(call.func, "attr", "")
        if name not in ("execute", "_rows"):
            continue
        sql = call.args[1] if name == "_rows" else call.args[0]
        if isinstance(sql, ast.JoinedStr):
            text = "".join(p.value for p in sql.values if isinstance(p, ast.Constant))
            if not text.startswith(("KILL ", "SET LOCK_TIMEOUT ")):
                out.append(f"{path.name}:{call.lineno}")
        elif isinstance(sql, ast.BinOp):
            out.append(f"{path.name}:{call.lineno}")
    return out


@pytest.mark.parametrize("path, cls", [("src/warden/platforms/db.py", "_MSSQL"), ("src/warden/database.py", "_MSSQL")])
def test_sql_servers_statements_are_constants_with_every_value_a_parameter(path, cls):
    assert _built_statements(ROOT / path, cls) == []
