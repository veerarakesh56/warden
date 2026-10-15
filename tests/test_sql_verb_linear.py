"""CodeQL py/redos, alert 21 (2026-10-15): the SQL statement's kind was read with a regex that backtracked
exponentially on a `/*` followed by many `*//*` - and the text is whatever a database client sent, so any client could
stall WARDEN's reader. The kind is now read in one linear pass, with the same answers."""

from __future__ import annotations

import re
import time

from warden.aws_stack import _sql_verb, sql_shape

_OLD = re.compile(r"^\s*(?:/\*.*?\*/\s*)*([A-Za-z]+)", re.DOTALL)  # the replaced regex, for its answers only


def test_the_same_answers_as_before_on_ordinary_statements():
    for sql in ("SELECT 1", "  select * from t", "/* hint */ UPDATE t SET a=1", "/* a */ /* b */\n INSERT INTO x",
                "/*multi\nline*/DELETE FROM y", "", "   ", "123", "/* never closed", "/**/WITH q AS (SELECT 1)",
                "/* x */ 42", "\tVACUUM"):
        old = m.group(1) if (m := _OLD.match(sql)) else ""
        assert _sql_verb(sql) == old, sql
    assert sql_shape("/* app=x */ SELECT * FROM orders o JOIN carts c ON 1=1") == "kind=SELECT tables=carts,orders"


def test_a_hostile_statement_is_read_in_linear_time():
    hostile = "/*" + "*//*" * 50_000  # what made the old regex backtrack
    started = time.perf_counter()
    assert _sql_verb(hostile) == ""
    assert sql_shape(hostile + " x") == "kind=other"
    assert time.perf_counter() - started < 1.0
