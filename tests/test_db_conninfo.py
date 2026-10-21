"""The database platform reads a libpq key=value DSN as libpq does (platforms/db.py _conninfo): keys with an
underscore, quoted values, and a backslash that takes the next character as it is - checked against libpq's own
reading through psycopg."""

from __future__ import annotations

import pytest
from psycopg.conninfo import conninfo_to_dict

from warden.platforms.db import _conninfo

DSNS = [
    "host=db.example.test port=5432 dbname=shop",
    "host=db.example.test connect_timeout=5 application_name=warden",
    "host = 'db example' user=app",
    r"host=db.example.test application_name='it\'s'",
    r"host=db\ one.example.test user=app",
]


@pytest.mark.parametrize("dsn", DSNS)
def test_a_dsn_reads_as_libpq_reads_it(dsn):
    assert _conninfo(dsn) == {k: str(v) for k, v in conninfo_to_dict(dsn).items()}


def test_a_key_holds_its_underscore():
    assert _conninfo("connect_timeout=5") == {"connect_timeout": "5"}


def test_a_backslash_keeps_the_quote_it_escapes():
    assert _conninfo(r"application_name='a\'b' host=h") == {"application_name": "a'b", "host": "h"}


def test_a_value_is_never_searched_for_keys():
    assert _conninfo("user=app.host=evil") == {"user": "app.host=evil"}
