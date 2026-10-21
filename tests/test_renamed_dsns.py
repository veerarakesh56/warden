"""Naming audit items 6-7 (2026-10-16): each database DSN is named for the one grant it carries - the terminate role,
and read-only logins to the Aurora primary and replica. The old names were "admin", "writer" and "reader"; an old name
set in the environment is still read for one release, with a WARNING naming the new one, and the deployed Secrets
Manager slots keep their old names until the runtime module renames them."""

from __future__ import annotations

import logging

import pytest

from test_settings import _FakeSecrets, _FakeSSM
from warden import aws_stack, settings
from warden.platforms import db

RENAMES = [("WARDEN_DB_ADMIN_DSN", "WARDEN_DB_TERMINATE_DSN", "db-terminate-dsn"),  # its slot renamed too (B24)
           ("WARDEN_STACK_DB_WRITER_DSN", "WARDEN_STACK_DB_PRIMARY_RO_DSN", "stack-db-writer-dsn"),
           ("WARDEN_STACK_DB_READER_DSN", "WARDEN_STACK_DB_REPLICA_RO_DSN", "stack-db-reader-dsn")]


def _unset(monkeypatch, *names):
    for name in names:  # set first, so the teardown removes whatever a test (or settings.load) leaves behind
        monkeypatch.setenv(name, "x")
        monkeypatch.delenv(name)


@pytest.mark.parametrize(("old", "new", "slot"), RENAMES)
def test_an_old_name_still_reads_for_one_release_and_warns_with_the_new_one(old, new, slot, monkeypatch, caplog):
    _unset(monkeypatch, old, new)
    assert settings.RENAMED[old] == new and old not in settings.LOADABLE and new in settings.SECRETS
    assert settings.getenv(new) == ""
    monkeypatch.setenv(old, "postgresql://old@h/x")
    with caplog.at_level(logging.WARNING, logger="warden.settings"):
        assert settings.getenv(new) == "postgresql://old@h/x"
    assert f"{old} is deprecated: set {new} instead" in caplog.text
    caplog.clear()
    monkeypatch.setenv(new, "postgresql://new@h/x")
    with caplog.at_level(logging.WARNING, logger="warden.settings"):
        assert settings.getenv(new) == "postgresql://new@h/x"
    assert caplog.text == ""
    # The slot a deployed runtime already holds, and its task roles may read (terraform/modules/warden-runtime).
    assert settings.secret_id("dev", new) == f"warden/dev/{slot}"


def test_the_store_fills_the_new_name_and_an_old_name_set_by_hand_still_wins(monkeypatch):
    """A real environment variable wins over the store - under its old name too."""
    _unset(monkeypatch, "WARDEN_DB_ADMIN_DSN", "WARDEN_DB_TERMINATE_DSN")
    store = _FakeSecrets({"warden/dev/db-admin-dsn": "postgresql://store@h/x"})
    only = frozenset({"WARDEN_DB_TERMINATE_DSN"})
    assert settings.load("dev", ssm=_FakeSSM({}), secrets=store, only=only) == ["WARDEN_DB_TERMINATE_DSN"]
    assert settings.getenv("WARDEN_DB_TERMINATE_DSN") == "postgresql://store@h/x"
    _unset(monkeypatch, "WARDEN_DB_TERMINATE_DSN")
    monkeypatch.setenv("WARDEN_DB_ADMIN_DSN", "postgresql://by-hand@h/x")
    assert settings.load("dev", ssm=_FakeSSM({}), secrets=store, only=only) == []
    assert settings.getenv("WARDEN_DB_TERMINATE_DSN") == "postgresql://by-hand@h/x"


def test_the_terminate_platform_and_the_stack_reader_read_through_the_alias(monkeypatch, caplog):
    _unset(monkeypatch, *(n for old, new, _ in RENAMES for n in (old, new)))
    monkeypatch.setenv("WARDEN_DB_ADMIN_DSN", "postgresql://terminate@h/x")
    with caplog.at_level(logging.WARNING, logger="warden.settings"):
        assert db.DatabasePlatform(conn=object())._dsn == "postgresql://terminate@h/x"
    assert "set WARDEN_DB_TERMINATE_DSN instead" in caplog.text

    seen = []

    class _Db:
        def metrics(self, alert):
            return {}

        def logs(self, alert):
            return []

    b = aws_stack.StackBackend.__new__(aws_stack.StackBackend)
    b._rds, b._db_factory = None, lambda dsn: seen.append(dsn) or _Db()
    monkeypatch.delenv("WARDEN_STACK_DB_IAM_AUTH", raising=False)
    monkeypatch.setenv("WARDEN_STACK_DB_READER_DSN", "postgresql://warden_ro@replica/shop")
    b._read_db(aws_stack._Out(), "WARDEN_STACK_DB_REPLICA_RO_DSN", "reader_", None)
    assert seen == ["postgresql://warden_ro@replica/shop"]


def test_the_terminate_dsns_slot_is_renamed_and_the_old_slot_still_reads_for_one_release(monkeypatch, caplog):
    """B24 (2026-10-20): "admin" out of every name - the slot is db-terminate-dsn, named for its one grant. Where the
    new slot does not exist yet, db-admin-dsn is read, with a WARNING naming the new one; the new one wins."""
    _unset(monkeypatch, "WARDEN_DB_ADMIN_DSN", "WARDEN_DB_TERMINATE_DSN")
    only = frozenset({"WARDEN_DB_TERMINATE_DSN"})
    old = _FakeSecrets({"warden/dev/db-admin-dsn": "postgresql://old-slot@h/x"})
    with caplog.at_level(logging.WARNING, logger="warden.settings"):
        assert settings.load("dev", ssm=_FakeSSM({}), secrets=old, only=only) == ["WARDEN_DB_TERMINATE_DSN"]
    assert settings.getenv("WARDEN_DB_TERMINATE_DSN") == "postgresql://old-slot@h/x"
    assert "the db-admin-dsn slot is deprecated: move its value to the db-terminate-dsn slot" in caplog.text
    assert "old-slot@h" not in caplog.text  # never a value, with or without its scheme
    assert "postgresql" not in caplog.text
    caplog.clear()
    _unset(monkeypatch, "WARDEN_DB_TERMINATE_DSN")
    both = _FakeSecrets({"warden/dev/db-admin-dsn": "postgresql://old-slot@h/x",
                         "warden/dev/db-terminate-dsn": "postgresql://new-slot@h/x"})
    with caplog.at_level(logging.WARNING, logger="warden.settings"):
        assert settings.load("dev", ssm=_FakeSSM({}), secrets=both, only=only) == ["WARDEN_DB_TERMINATE_DSN"]
    assert settings.getenv("WARDEN_DB_TERMINATE_DSN") == "postgresql://new-slot@h/x"
    assert caplog.text == ""
    # The stack's read-only DSNs keep the slots Terraform holds (secrets.tf); only the terminate slot moved.
    assert settings.secret_id("dev", "WARDEN_STACK_DB_PRIMARY_RO_DSN") == "warden/dev/stack-db-writer-dsn"


def test_the_new_slot_the_warning_names_is_the_one_secret_id_reads():
    assert settings.secret_id("dev", "WARDEN_DB_TERMINATE_DSN") == f"warden/dev/{settings._NEW_SLOT['WARDEN_DB_TERMINATE_DSN']}"

