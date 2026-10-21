"""A dry run hands WARDEN DSNs of the live shape (Sonar python:S2115, 2026-10-16): the user, a password - live, an IAM
token or the master password - and a host that never resolves. They were URLs with no password, which no live run has."""

from __future__ import annotations

import urllib.parse


def test_the_dry_runs_dsns_have_the_live_shape():
    from scenarios import fullstack_cli, runner

    env = fullstack_cli.dry_env().assume_reader()
    for name in ("WARDEN_STACK_DB_PRIMARY_RO_DSN", "WARDEN_STACK_DB_REPLICA_RO_DSN"):
        url = urllib.parse.urlsplit(env[name])
        assert (url.username, url.hostname) == (fullstack_cli.RO_USER, "dry.invalid"), name
        assert url.password, name
        assert "sslmode=require" in url.query
    db = urllib.parse.urlsplit(runner._db_dry_harness().target.dsn)
    assert (db.username, db.hostname, db.path) == ("warden", "dry-run.invalid", "/" + runner.DB_DATABASE)
    assert db.password
