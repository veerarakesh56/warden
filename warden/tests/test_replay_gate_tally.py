"""warden/scripts/replay_gate.py's tally of every report (split out of main for S3776): one row per report replayed, the
old -> new verdict counts, the reports it could not read - and a printed line for each verdict that changed."""

from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "warden" / "scripts"))
import replay_gate as rg  # after the sys.path line above

ANSWERS = {"a.json": ("allowed", "refused", ["P3"]), "b.json": ("allowed", "allowed", []),
           "c.json": ("refused", "refused", ["P1"])}


def _replay_one(path: pathlib.Path):
    if path.name == "old.json":
        raise KeyError("citations")
    return ANSWERS[path.name]


def test_every_report_is_a_row_a_count_or_a_skip(monkeypatch, capsys):
    monkeypatch.setattr(rg, "replay_one", _replay_one)
    files = [pathlib.Path(n) for n in ("a.json", "old.json", "b.json", "c.json")]
    rows, matrix, skipped = rg._replay_all(files)
    assert rows == [{"report": n, "old": o, "new": w, "policies": p} for n, (o, w, p) in ANSWERS.items()]
    assert dict(matrix) == {("allowed", "refused"): 1, ("allowed", "allowed"): 1, ("refused", "refused"): 1}
    assert skipped == ["old.json: KeyError: 'citations'"]
    assert capsys.readouterr().out.split() == ["a.json", "allowed", "->", "refused", "P3"]
