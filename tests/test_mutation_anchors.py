"""Every mutation in scripts/mutation_check.py must still find its anchor.

The mutation check is slow, so CI does not run it. On 2026-09-27 approval became a digest and the
approval-gate mutation's anchor stopped existing, so that mutation silently stopped being tested.
This fast test runs in CI and fails as soon as any anchor goes stale.
"""

from __future__ import annotations

import importlib.util
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("mutation_check", ROOT / "scripts" / "mutation_check.py")
mutation_check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mutation_check)


@pytest.mark.parametrize("label,filename,find,replace,why", mutation_check.MUTATIONS,
                         ids=[m[0] for m in mutation_check.MUTATIONS])
def test_every_mutation_anchor_exists_exactly_once(label, filename, find, replace, why):
    text = (mutation_check.SRC / filename).read_text(encoding="utf-8")
    assert text.count(find) == 1, f"{label}: anchor found {text.count(find)} times in {filename}"
    assert replace != find


@pytest.mark.parametrize("label,filename,find,replace,why", mutation_check.MUTATIONS,
                         ids=[m[0] for m in mutation_check.MUTATIONS])
def test_every_mutation_applies_to_the_file_as_it_is_on_disk(label, filename, find, replace, why):
    """What the script really does: bytes in, bytes out, in the checkout's own line endings. A
    Windows checkout (CRLF) reported every multi-line anchor missing while the check above passed."""
    original = (mutation_check.SRC / filename).read_bytes()
    mutated = mutation_check.mutate(original, find, replace)
    assert mutated is not None and mutated != original, label
    assert (b"\r\n" in original) == (b"\r\n" in mutated), "line endings changed"


def test_a_multi_line_anchor_is_found_in_a_crlf_file():
    mutated = mutation_check.mutate(b"a\r\nb\r\nc\r\n", "a\nb", "x\ny")
    assert mutated == b"x\r\ny\r\nc\r\n"


def test_an_interrupted_run_stops_its_workers(monkeypatch):
    """Sixth review (2026-10-01): on Ctrl-C the run - in its own session on POSIX - kept its workers going while
    the mutated file was restored under them."""
    stopped = []

    class Run:
        pid = 4242

        def wait(self, timeout=None):
            raise KeyboardInterrupt

    monkeypatch.setattr(mutation_check.subprocess, "Popen", lambda *a, **k: Run())
    monkeypatch.setattr(mutation_check, "_kill_tree", stopped.append)
    with pytest.raises(KeyboardInterrupt):
        mutation_check.run_suite(["tests/test_x.py"], limit=5)
    assert len(stopped) == 1


def test_a_file_a_killed_run_left_mutated_is_restored_by_the_next(tmp_path, monkeypatch):
    """Register R7-O4: a run stopped by TerminateProcess or SIGKILL never reached its `finally`, and left the mutated
    source behind. The journal written before each mutation lets the next run put it back, byte for byte."""
    import base64
    import json

    original = b"guard = True\r\n"
    target = tmp_path / "src" / "x.py"
    target.parent.mkdir()
    target.write_bytes(b"guard = False\r\n")
    monkeypatch.setattr(mutation_check, "ROOT", tmp_path)
    monkeypatch.setattr(mutation_check, "JOURNAL", tmp_path / ".mutation-restore.json")
    mutation_check.JOURNAL.write_text(json.dumps({"path": "src/x.py", "original": base64.b64encode(original).decode()}),
                                      encoding="utf-8")
    assert mutation_check.recover() == "src/x.py"
    assert target.read_bytes() == original and not mutation_check.JOURNAL.exists()
    assert mutation_check.recover() is None


def test_sigterm_ends_a_run_the_way_ctrl_c_does():
    """Register R7-O4: Ctrl-C stopped the workers and restored the file; SIGTERM (a CI cancel) did neither."""
    with pytest.raises(KeyboardInterrupt):
        mutation_check._terminate_like_ctrl_c(15, None)
    source = (ROOT / "scripts" / "mutation_check.py").read_text(encoding="utf-8")
    assert "signal.signal(signal.SIGTERM, _terminate_like_ctrl_c)" in source
