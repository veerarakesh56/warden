"""Naming audit item 4 (2026-10-16): a signing key is encrypted at rest unless its maker explicitly says otherwise.
`warden audit keygen` wrote the key in the clear whenever no passphrase was set, and only said so; the bench approver's
key was always in the clear. Both now refuse without a passphrase unless told --unencrypted, and create the file
exclusively (never over another, mode 0600 on POSIX)."""

from __future__ import annotations

import importlib.util
import io
import os
import pathlib
import sys

import pytest

from warden import audit, cli

ROOT = pathlib.Path(__file__).resolve().parents[1]
ENCRYPTED = b"-----BEGIN ENCRYPTED PRIVATE KEY-----"


def _keygen(folder, *extra):
    folder.mkdir(exist_ok=True)
    priv, pub = folder / "alice.pem", folder / "alice.pub"
    return cli.main(["audit", "keygen", "--private", str(priv), "--public", str(pub), *extra]), priv, pub


class _Tty(io.StringIO):
    def isatty(self):
        return True


def test_keygen_refuses_a_clear_key_without_a_passphrase_or_unencrypted(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("WARDEN_AUDIT_KEY_PASSPHRASE", raising=False)
    monkeypatch.setattr(sys, "stdin", io.StringIO())  # no terminal to type one at
    code, priv, pub = _keygen(tmp_path)
    assert code == 1 and not priv.exists() and not pub.exists()
    assert "no passphrase, so no key was written" in capsys.readouterr().err


def test_keygen_encrypts_with_the_environments_or_a_typed_passphrase(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("WARDEN_AUDIT_KEY_PASSPHRASE", "correct horse")
    code, priv, _ = _keygen(tmp_path / "env")
    assert code == 0 and priv.read_bytes().startswith(ENCRYPTED)
    audit.load_private_key(priv, b"correct horse")
    monkeypatch.delenv("WARDEN_AUDIT_KEY_PASSPHRASE")
    monkeypatch.setattr(sys, "stdin", _Tty())
    typed = iter(["battery staple", "battery staple"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(typed))
    code, priv, _ = _keygen(tmp_path / "typed")
    assert code == 0 and priv.read_bytes().startswith(ENCRYPTED)
    audit.load_private_key(priv, b"battery staple")
    differ = iter(["one", "two"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(differ))
    code, priv, _ = _keygen(tmp_path / "differ")
    assert code == 1 and not priv.exists() and "the two passphrases differ" in capsys.readouterr().err


def test_keygen_writes_a_clear_key_only_when_told_and_says_why_loudly(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("WARDEN_AUDIT_KEY_PASSPHRASE", "ignored when told --unencrypted")
    code, priv, _ = _keygen(tmp_path, "--unencrypted")
    assert code == 0 and priv.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")
    audit.load_private_key(priv)
    assert "--unencrypted: the private key is written IN THE CLEAR" in capsys.readouterr().err


def test_a_private_key_is_created_exclusively_and_owner_only(tmp_path):
    path = tmp_path / "k.pem"
    audit.write_private_key(path, b"one")
    with pytest.raises(FileExistsError):
        audit.write_private_key(path, b"two")
    assert path.read_bytes() == b"one"
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600


def _bench(monkeypatch, path):
    spec = importlib.util.spec_from_file_location("bench_approve", ROOT / "scripts" / "bench_approve.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setenv("WARDEN_BENCH_KEY", str(path))
    return mod


def test_the_bench_key_is_encrypted_unless_told_and_an_old_clear_one_still_loads_with_a_warning(tmp_path, monkeypatch,
                                                                                                capsys):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    mod = _bench(monkeypatch, tmp_path / "a" / "bench.pem")
    monkeypatch.delenv(mod.PASSPHRASE_ENV, raising=False)
    with pytest.raises(SystemExit, match="no key was written"):
        mod.new_key("dev")
    assert not (tmp_path / "a" / "bench.pem").exists()
    monkeypatch.setenv(mod.PASSPHRASE_ENV, "bench pass")
    mod.new_key("dev")
    assert (tmp_path / "a" / "bench.pem").read_bytes().startswith(ENCRYPTED)
    assert isinstance(mod.load_key(), Ed25519PrivateKey) and capsys.readouterr().err == ""
    monkeypatch.delenv(mod.PASSPHRASE_ENV)
    with pytest.raises(SystemExit, match="is encrypted: set WARDEN_BENCH_KEY_PASSPHRASE"):
        mod.load_key()

    # A key made before 2026-10-16, in the clear: still read, with a warning that says how to replace it.
    old = tmp_path / "old.pem"
    old.write_bytes(Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    mod = _bench(monkeypatch, old)
    monkeypatch.setenv(mod.PASSPHRASE_ENV, "set, but the old key has none")
    assert isinstance(mod.load_key(), Ed25519PrivateKey)
    assert f"WARNING: {old} is not encrypted" in capsys.readouterr().err

    mod = _bench(monkeypatch, tmp_path / "b" / "bench.pem")
    monkeypatch.delenv(mod.PASSPHRASE_ENV)
    mod.new_key("dev", unencrypted=True)
    assert (tmp_path / "b" / "bench.pem").read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")
    assert "IN THE CLEAR" in capsys.readouterr().err
