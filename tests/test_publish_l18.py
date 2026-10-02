"""Audit A-B-L18: the publish tooling's gaps."""

from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import aws_proof_bundle  # after the sys.path line above
import check_publishable
import publish_bench_run

FIRST, SECOND = "1111" + "22223333", "4444" + "55556666"


def test_every_account_of_a_run_is_found(tmp_path):
    (tmp_path / "ground-truth").mkdir()
    (tmp_path / "manifest.json").write_text(json.dumps({"role": f"arn:aws:iam::{FIRST}:role/x"}), encoding="utf-8")
    (tmp_path / "ground-truth" / "a.json").write_text(json.dumps({"arn": f"arn:aws:iam::{SECOND}:role/y"}),
                                                      encoding="utf-8")
    found = publish_bench_run._account_from(tmp_path)
    assert set(found.split("|")) == {FIRST, SECOND}
    redacted = aws_proof_bundle._redact(f"x{FIRST}y and {SECOND}", found)
    assert FIRST not in redacted and SECOND not in redacted


def test_a_password_holding_an_at_sign_is_masked_whole():
    pw = "p" + "@ss" + "word"
    out = aws_proof_bundle._redact(f"postgresql://app:{pw}@db.example:5432/x", "")
    assert "ss" + "word" not in out and out == "postgresql://app:" + "*" * 8 + "@db.example:5432/x", out


def test_into_must_stay_inside_the_repository(tmp_path, monkeypatch):
    run = tmp_path / "run"
    (run / "ground-truth").mkdir(parents=True)
    calls = []
    monkeypatch.setattr(publish_bench_run.shutil, "rmtree", lambda p: calls.append(p))
    monkeypatch.setattr(publish_bench_run.shutil, "copytree", lambda a, b: calls.append(b))
    for bad in (str(tmp_path / "elsewhere"), "../outside", "docs/../../outside"):
        monkeypatch.setattr(sys, "argv", ["publish_bench_run.py", "--run", str(run), "--into", bad])
        assert publish_bench_run.main() == 2, bad
    assert calls == [], "nothing outside the repository may be removed or written"


def test_a_database_file_may_never_be_tracked_and_a_binary_one_is_scanned(tmp_path):
    db = tmp_path / "audit.db"
    db.write_bytes(b"SQLite format 3\x00" + b"\x00" * 32)
    assert any("must never be tracked" in f for f in check_publishable.scan([db], root=tmp_path))
    blob = tmp_path / "bundle.bin"
    blob.write_bytes(b"\x00\x01\xff" + b"AKIA" + b"Q3RZ7XKM2PLW5NBT" + b"\x00")
    assert check_publishable.scan([blob], root=tmp_path), "a key inside a binary file went unscanned"
