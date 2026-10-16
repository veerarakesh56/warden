"""CodeQL py/redos, alert 21 (2026-10-15): the SQL statement's kind was read with a regex that backtracked
exponentially on a `/*` followed by many `*//*` - and the text is whatever a database client sent, so any client could
stall WARDEN's reader. The kind is now read in one linear pass, with the same answers - recorded once from the old
regex, which this file does not keep (a copy of it here was CodeQL alert 22)."""

from __future__ import annotations

import time

import pytest

from warden.aws_stack import _sql_verb, sql_shape

# What the replaced regex answered, read from it on 2026-10-16 before it was removed.
OLD_ANSWERS = [
    ("SELECT 1", "SELECT"), ("  select * from t", "select"), ("/* hint */ UPDATE t SET a=1", "UPDATE"),
    ("/* a */ /* b */\n INSERT INTO x", "INSERT"), ("/*multi\nline*/DELETE FROM y", "DELETE"), ("", ""), ("   ", ""),
    ("123", ""), ("/* never closed", ""), ("/**/WITH q AS (SELECT 1)", "WITH"), ("/* x */ 42", ""),
    ("\tVACUUM", "VACUUM"),
]


@pytest.mark.parametrize(("sql", "verb"), OLD_ANSWERS)
def test_the_same_answers_as_before_on_ordinary_statements(sql, verb):
    assert _sql_verb(sql) == verb


def test_the_shape_names_the_kind_and_the_tables():
    assert sql_shape("/* app=x */ SELECT * FROM orders o JOIN carts c ON 1=1") == "kind=SELECT tables=carts,orders"


def test_a_hostile_statement_is_read_in_linear_time():
    hostile = "/*" + "*//*" * 50_000  # what made the old regex backtrack
    started = time.perf_counter()
    assert _sql_verb(hostile) == ""
    assert sql_shape(hostile + " x") == "kind=other"
    assert time.perf_counter() - started < 1.0
