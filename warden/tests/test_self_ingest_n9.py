"""Register N9 / audit A-N-9: WARDEN's own output never flows back into what it knows. Its knowledge - signatures,
environments, providers, freeze windows, approvers - is the package's data/ directory, changed only by a reviewed
commit. Nothing WARDEN runs may write there. conftest.py also holds the whole test run to it."""

from __future__ import annotations

from data_snapshot import snapshot
from test_remediation_workflow import _approve_with, _run, owner, world  # noqa: F401
from warden.cli import main


def test_a_snapshot_shows_a_file_added_changed_or_removed(tmp_path):
    (tmp_path / "a.yaml").write_text("x", encoding="utf-8")
    before = snapshot(tmp_path)
    (tmp_path / "a.yaml").write_text("y", encoding="utf-8")
    assert snapshot(tmp_path) != before
    (tmp_path / "a.yaml").write_text("x", encoding="utf-8")
    (tmp_path / "b.yaml").write_text("", encoding="utf-8")
    assert snapshot(tmp_path) != before
    (tmp_path / "b.yaml").unlink()
    assert snapshot(tmp_path) == before


def test_diagnosing_every_incident_and_applying_a_fix_writes_nothing_into_data(world, owner, capsys):  # noqa: F811
    before = snapshot()
    assert before, "the package's data directory was not found"
    assert main(["demo"]) == 0
    assert _run(world, _approve_with(owner)).status == "recovered"
    capsys.readouterr()
    assert snapshot() == before
