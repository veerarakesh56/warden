"""Key files are written only inside the key folder (Sonar pythonsecurity:S8707, 2026-10-16): the paths come from a
command line an agent can drive, so no path may reach a file outside it - by `..`, by an absolute path, or through a
symlink - and no key write ever replaces an existing file (the public key's write_bytes used to)."""

from __future__ import annotations

import os

import pytest

from warden import audit


def test_a_key_is_written_inside_the_folder(tmp_path):
    audit.generate_key(tmp_path / "a.pem", tmp_path / "a.pub", b"pass", base=tmp_path)
    assert (tmp_path / "a.pem").exists() and (tmp_path / "a.pub").exists()


@pytest.mark.parametrize("where", ["outside", "dotdot", "the folder itself"])
def test_a_path_that_leaves_the_folder_is_refused_and_nothing_is_written(tmp_path, where):
    base = tmp_path / "keys"
    base.mkdir()
    (tmp_path / "elsewhere").mkdir()
    path = {"outside": tmp_path / "elsewhere" / "k.pem", "dotdot": base / ".." / "elsewhere" / "k.pem",
            "the folder itself": base}[where]
    with pytest.raises(ValueError, match="outside"):
        audit.write_private_key(path, b"secret", base)
    assert not (tmp_path / "elsewhere" / "k.pem").exists()


def test_a_symlink_is_never_written_through(tmp_path):
    base = tmp_path / "keys"
    base.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    link = base / "k.pem"
    try:
        os.symlink(victim, link)
    except (OSError, NotImplementedError):
        pytest.skip("this account cannot create symlinks")
    with pytest.raises(ValueError, match="symlink"):
        audit.write_private_key(link, b"secret", base)
    assert victim.read_text() == "keep me"


def test_neither_key_file_is_ever_replaced(tmp_path):
    (tmp_path / "taken.pub").write_text("someone's file")
    with pytest.raises(FileExistsError):
        audit.generate_key(tmp_path / "new.pem", tmp_path / "taken.pub", b"pass", base=tmp_path)
    assert (tmp_path / "taken.pub").read_text() == "someone's file"
    assert not (tmp_path / "new.pem").exists()  # refused before the private key was made


def test_one_path_for_both_files_is_refused_and_nothing_is_left(tmp_path):
    with pytest.raises(ValueError, match="same file"):
        audit.generate_key(tmp_path / "k.pem", tmp_path / "k.pem", b"pass", base=tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_a_failed_public_write_leaves_no_private_key(tmp_path, monkeypatch):
    real_create = audit._create

    def fail_on_public(real, data, mode):
        if real.suffix == ".pub":
            raise OSError("disk full")
        real_create(real, data, mode)

    monkeypatch.setattr(audit, "_create", fail_on_public)
    with pytest.raises(OSError, match="disk full"):
        audit.generate_key(tmp_path / "k.pem", tmp_path / "k.pub", b"pass", base=tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_a_dangling_symlink_for_the_public_key_is_refused_before_anything_is_written(tmp_path):
    link = tmp_path / "k.pub"
    try:
        os.symlink(tmp_path / "nowhere", link)
    except (OSError, NotImplementedError):
        pytest.skip("this account cannot create symlinks")
    with pytest.raises(ValueError, match="symlink"):
        audit.generate_key(tmp_path / "k.pem", link, b"pass", base=tmp_path)
    assert not (tmp_path / "k.pem").exists()


def test_the_default_folder_is_warden_key_dir(tmp_path, monkeypatch):
    monkeypatch.setenv(audit.KEY_DIR_ENV, str(tmp_path / "mine"))
    audit.write_private_key(tmp_path / "mine" / "k.pem", b"x")
    assert (tmp_path / "mine" / "k.pem").read_bytes() == b"x"
    with pytest.raises(ValueError, match="outside"):
        audit.write_private_key(tmp_path / "k.pem", b"x")


def test_the_cli_refuses_a_path_outside_and_writes_nothing(tmp_path, monkeypatch, capsys):
    from warden import cli

    monkeypatch.setenv(audit.KEY_DIR_ENV, str(tmp_path / "keys"))
    monkeypatch.setenv("WARDEN_AUDIT_KEY_PASSPHRASE", "pass")
    code = cli.main(["audit", "keygen", "--private", str(tmp_path / "out.pem"), "--public", str(tmp_path / "out.pub")])
    assert code == 1 and "no key was written" in capsys.readouterr().err
    assert not (tmp_path / "out.pem").exists() and not (tmp_path / "out.pub").exists()
