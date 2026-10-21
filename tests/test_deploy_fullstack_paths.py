"""scripts/deploy_fullstack_apps.py's checked paths (split out of main for S3776): build output inside the
repository is refused with its reason, before any folder is made."""

from __future__ import annotations

import importlib.util
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("deploy_fullstack_paths", ROOT / "scripts" / "deploy_fullstack_apps.py")
tool = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tool)


@pytest.mark.parametrize("inside", [ROOT, ROOT / "build-here-never-made"])
def test_out_in_the_repository_is_refused_before_anything_is_made(inside):
    with pytest.raises(SystemExit, match="is inside the repository; build output must live outside it"):
        tool.main(["--out", str(inside), "build", "--skip-image"])
    assert not (ROOT / "build-here-never-made").exists()


def test_the_default_stack_file_is_the_one_in_out(tmp_path):
    out, stack = tool._checked_paths(tmp_path / "build", None)
    assert out == (tmp_path / "build").resolve()
    assert stack == out / "stack.json"
