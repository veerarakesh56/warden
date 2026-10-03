"""Register R51: WARDEN never creates database indexes - a slow query is escalated to a person, never "fixed" with
DDL. Nothing in WARDEN's code issues schema changes to a database it watches; the one CREATE TABLE is its own
audit store."""
from __future__ import annotations

import pathlib
import re

from warden import catalog

SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "warden"
DDL = re.compile(r"\b(?:CREATE|ALTER|DROP)\s+(?:UNIQUE\s+)?(?:INDEX|TABLE|SCHEMA|VIEW|DATABASE)\b|\bREINDEX\b",
                 re.IGNORECASE)
# WARDEN's own audit store (SQLite, or PostgreSQL through `audit migrate`) creates its own tables and indexes; the
# runbook prints, for a person, one ALTER DATABASE that sets a session timeout - text, never executed.
OWN = {("audit.py", "CREATE TABLE"), ("audit.py", "CREATE INDEX"), ("runbook.py", "ALTER DATABASE")}


def test_no_code_issues_schema_changes_to_a_watched_database():
    found = [(path.name, m.group(0).upper().split()[0] + " " + m.group(0).upper().split()[-1], n)
             for path in sorted(SRC.rglob("*.py"))
             for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
             for m in DDL.finditer(line)]
    assert [f for f in found if (f[0], f[1]) not in OWN] == [], found


def test_no_catalogue_entry_changes_a_schema():
    for name in catalog.CATALOG:
        assert not re.search(r"index|schema|ddl|alter|create", name, re.IGNORECASE), name
