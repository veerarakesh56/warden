"""The database and its roles as the server lists them. Once the real cause -
the application's database and roles had never been created - was in no evidence item."""

from __future__ import annotations

from warden.database import DatabaseBackend, _Postgres
from warden.evidence import _kind
from warden.tools import PARTIAL_PREFIX


class _Conn:
    """Answers the catalog queries: login roles, then each database with the roles that may connect."""

    def __init__(self, roles, dbs):
        self.answers = [("from pg_roles where rolcanlogin", [(r,) for r in roles]), ("from pg_database", dbs)]
        self.sql = []

    def cursor(self):
        conn = self

        class Cur:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def execute(self, sql, params=()):
                conn.sql.append((sql, params))
                self.rows = next((rows for frag, rows in conn.answers if frag in sql.lower()), [])

            def fetchall(self):
                return self.rows

        return Cur()


def test_a_missing_database_and_who_may_connect_are_stated_as_trusted_facts():
    conn = _Conn(["app", "warden_dev_ro", "evil name; DROP"], [("postgres", "app,warden_dev_ro"), ("orders", "")])
    lines = _Postgres.access(conn)
    assert lines == ["STATE postgres login_roles=app,warden_dev_ro",
                     "STATE postgres database postgres connect_roles=app,warden_dev_ro",
                     "STATE postgres database orders connect_roles=(none)"]
    assert all(_kind(line) == "C" for line in lines)  # trusted configuration, citable as such
    # The role names are the catalog's, bound as a parameter - never spliced into the SQL.
    assert ["app", "warden_dev_ro"] in [list(p[0]) for _, p in conn.sql if p and isinstance(p[0], list)]


def test_a_failed_catalog_read_is_a_partial_and_costs_nothing_else():
    class _Broken(_Postgres):
        @classmethod
        def access(cls, conn):
            raise RuntimeError("permission denied for pg_roles")

        @classmethod
        def problem_ops(cls, conn, idle_secs):
            return []

        @classmethod
        def activity(cls, conn):
            return ["postgres long-running query: pid=1"]

    lines = DatabaseBackend._logs(_Broken, object())
    assert lines[0] == "postgres long-running query: pid=1"
    assert lines[1].startswith(f"{PARTIAL_PREFIX}access: ")
