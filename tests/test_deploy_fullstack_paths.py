"""scripts/deploy_fullstack_apps.py's helpers split out for S3776: the checked paths (build output inside the
repository is refused with its reason, before any folder is made), the deploy loop's image tag, and when one Argo CD
status counts as synced."""

from __future__ import annotations

import argparse
import importlib.util
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("deploy_fullstack_paths", ROOT / "scripts" / "deploy_fullstack_apps.py")
tool = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tool)


@pytest.mark.parametrize("inside", [ROOT, ROOT / "build-here-never-made"])
def test_out_in_the_repository_is_refused_before_anything_is_made(inside, monkeypatch):
    monkeypatch.chdir(ROOT)  # the checked paths lie under the working directory: the repository, wherever pytest runs
    argv = ["--out", str(inside), "build", "--skip-image"]
    with pytest.raises(SystemExit, match="is inside the repository; build output must live outside it"):
        tool.main(argv)
    assert not (ROOT / "build-here-never-made").exists()


def test_the_default_stack_file_is_the_one_in_out(tmp_path):
    out, stack = tool._checked_paths(tmp_path / "build", None)
    assert out == (tmp_path / "build").resolve()
    assert stack == out / "stack.json"


@pytest.mark.parametrize(("given", "used"), [("given-tag", "given-tag"), (None, "built-tag")])
def test_deploy_uses_the_tag_given_else_the_one_the_build_wrote(tmp_path, monkeypatch, given, used):
    (tmp_path / "image-tag.txt").write_text("built-tag\n", encoding="utf-8")
    tags: list = []
    monkeypatch.setattr(tool, "deploy_k8s", lambda stack, tag, out, aws, runner: tags.append(tag))
    args = argparse.Namespace(target="k8s", tag=given, no_wait=False)
    tool._deploy(args, tmp_path, tmp_path / "stack.json", {}, None, None)
    assert tags == [used]


REV = "0123456789ab" + "c" * 28


@pytest.mark.parametrize(("health", "done"), [("Healthy", True), ("Progressing", False), ("Degraded", False)])
def test_synced_counts_only_when_the_shop_is_also_healthy(health, done):
    status = {"sync": {"revision": REV, "status": "Synced"}, "health": {"status": health}}
    assert tool._sync_state(status, REV) == (done, f"revision 0123456789ab, sync Synced, health {health}, operation -")
