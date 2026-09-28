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
