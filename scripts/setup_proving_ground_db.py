"""Create the sentinel table that marks a database as the Wave 3 proving ground. Run once.

    export WARDEN_BENCH_DB_DSN="$(terraform -chdir=terraform/proving-ground output -raw db_dsn)"
    python scripts/setup_proving_ground_db.py            # say what it would do
    python scripts/setup_proving_ground_db.py --apply    # create it

⛔ WHY THIS IS A SEPARATE, DELIBERATE STEP AND NOT PART OF THE HARNESS.

`ops_db._guard_database` refuses to inject anything unless `warden_proving_ground` exists in the
database it is pointed at. That table is the entire reason the injectors cannot be aimed at
something real: they open dozens of sessions, take an ACCESS EXCLUSIVE lock and revoke a security
group, and a Postgres reachable from this laptop could be anyone's.

If the harness created the sentinel when it was missing, the guard would mean nothing - it would
bless whatever database it was given, which is precisely the database you did not mean to point it
at. So creation lives here, needs `--apply`, and a human has to run it against a DSN they chose.

⚠ The table itself is trivial and deliberately so: the injectors only ever `SELECT count(*)` from
it and `LOCK TABLE` it. Its contents are irrelevant; its EXISTENCE is the claim.
"""

from __future__ import annotations

import argparse
import os
import sys
import urllib.parse

SENTINEL = "warden_proving_ground"
EXPECTED_DATABASE = "warden"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--apply", action="store_true",
                        help="actually create it; default says what it would do")
    parser.add_argument("--database", default=EXPECTED_DATABASE,
                        help=f"the database that may be marked (default: {EXPECTED_DATABASE})")
    args = parser.parse_args(argv)

    sys.stdout.reconfigure(encoding="utf-8")  # a Windows console is cp1252 and cannot print ⛔

    dsn = os.environ.get("WARDEN_BENCH_DB_DSN", "").strip()
    if not dsn:
        return _fail("set WARDEN_BENCH_DB_DSN first (terraform output -raw db_dsn)")

    parsed = urllib.parse.urlparse(dsn)
    named = (parsed.path or "/").lstrip("/")
    host = parsed.hostname or "?"
    # Refused on the DSN before connecting: the cheapest place to catch a DSN pasted from the wrong
    # terminal is before a connection to it exists.
    if named != args.database:
        return _fail(
            f"the DSN points at database {named!r}, not {args.database!r} - refusing.\n"
            "  If that really is the proving ground, pass --database explicitly."
        )

    try:
        import psycopg
    except ImportError:
        return _fail("needs the driver: pip install -e '.[postgres]'")

    print(f"{'APPLYING' if args.apply else 'DRY RUN'}")
    print(f"  host      {host}")
    print(f"  database  {named}")
    print(f"  table     {SENTINEL}")

    with psycopg.connect(dsn, connect_timeout=10, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("SELECT current_database()")
        live = cur.fetchone()[0]
        # Checked AGAIN against the server's own answer, not just the DSN's text: a DSN can name one
        # database and land somewhere else entirely through a connection-pooler or a search_path.
        if live != args.database:
            return _fail(f"connected to database {live!r}, not {args.database!r} - refusing")

        cur.execute(f"SELECT to_regclass('{SENTINEL}')")
        if cur.fetchone()[0] is not None:
            print(f"\n{SENTINEL} already exists - nothing to do. This database is the proving ground.")
            return 0

        if not args.apply:
            print("\ndry run - nothing was created. Re-run with --apply.")
            return 0

        cur.execute(
            f"CREATE TABLE {SENTINEL} ("
            "  id int PRIMARY KEY,"
            "  note text NOT NULL,"
            "  created_at timestamptz NOT NULL DEFAULT now())"
        )
        cur.execute(
            f"INSERT INTO {SENTINEL} (id, note) VALUES (1, %s)",
            ("this database is a WARDEN benchmark proving ground and is broken on purpose",),
        )

    print(f"\ncreated. {named} on {host} is now injectable by the Wave 3 harness.")
    return 0


def _fail(message: str) -> int:
    print(f"\n⛔ {message}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
