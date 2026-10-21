"""stack.json is read and written back only where the tools work (Sonar pythonsecurity:S2083 on
aurora_express.merge_stack and deploy_fullstack_apps.record_in_stack, 2026-10-17). --stack and --out come from the
command line, which an agent can drive: a path outside the checkout, the temp folder (RUNNER_TEMP) and
~/warden-fullstack-build is refused before anything is read, created or written (warden.paths)."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import shutil
import uuid

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
# Under the home directory, in none of the tools' folders, with a name no one else has: a regression writes only here.
OUTSIDE_DIR = pathlib.Path.home() / f".warden-test-outside-{uuid.uuid4().hex}"


@pytest.fixture(autouse=True)
def _nothing_left_outside():
    yield
    written = OUTSIDE_DIR.exists()
    shutil.rmtree(OUTSIDE_DIR, ignore_errors=True)
    assert not written, f"a test wrote into {OUTSIDE_DIR}"


def _load(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


aurora = _load("aurora_express_s2083", ROOT / "terraform" / "fullstack" / "aurora_express.py")
apps = _load("deploy_fullstack_apps_s2083", ROOT / "scripts" / "deploy_fullstack_apps.py")


class _NoCall:
    def __getattr__(self, name):
        raise AssertionError(f"AWS called ({name}) for a refused path")


@pytest.mark.parametrize("cmd", ["create", "status", "destroy"])
def test_aurora_refuses_a_stack_outside_the_places_the_tools_work(cmd, monkeypatch):
    monkeypatch.setenv("WARDEN_ENV", "dev")
    argv = [cmd, "--stack", str(OUTSIDE_DIR / "stack.json")]
    clients = {"rds": _NoCall(), "secretsmanager": _NoCall()}
    with pytest.raises(SystemExit, match="refused: .* is outside the places"):
        aurora.main(argv, clients=clients)


def test_aurora_writes_the_checked_path(tmp_path, monkeypatch):
    """The guard passes a stack in the temp folder (RUNNER_TEMP in the deploy job) and create merges into it there."""
    monkeypatch.setenv("WARDEN_ENV", "dev")
    seen = []
    monkeypatch.setattr(aurora, "create", lambda rds, sm, stack, cluster, log=print: seen.append(stack))
    stack = tmp_path / "s.json"
    assert aurora.main(["create", "--stack", str(stack), "--region", "r"], clients={"rds": None, "secretsmanager": None}) == 0
    assert seen == [stack.resolve()]


@pytest.mark.parametrize("flags", [["--out", "{out}"], ["--out", "{tmp}", "--stack", "{out}/stack.json"]],
                         ids=["--out", "--stack"])
def test_apps_refuses_an_out_or_stack_outside_the_places_the_tools_work(flags, tmp_path):
    argv = [f.format(out=OUTSIDE_DIR, tmp=tmp_path) for f in flags] + ["deploy", "ecs"]
    with pytest.raises(SystemExit, match="refused: .* is outside the places"):
        apps.main(argv, aws=lambda service: _NoCall(), runner=lambda *a, **k: "")


def test_apps_records_into_the_checked_stack(tmp_path, monkeypatch):
    stack = tmp_path / "elsewhere" / "stack.json"
    stack.parent.mkdir()
    stack.write_text(json.dumps({"region": "r", "ecs_cluster": "c", "ecs_service": "s"}))
    (tmp_path / "image-tag.txt").write_text("t")
    monkeypatch.setattr(apps, "deploy_ecs", lambda *a, **k: "arn:td:9")
    assert apps.main(["--out", str(tmp_path), "--stack", str(stack), "deploy", "ecs"], aws=lambda s: None) == 0
    assert json.loads(stack.read_text())["ecs_baseline_task_definition"] == "arn:td:9"


@pytest.mark.parametrize("write", [lambda p: aurora.merge_stack(p, {"k": "v"}),
                                   lambda p: apps.record_in_stack(p, "k", "v")], ids=["merge_stack", "record_in_stack"])
def test_the_write_itself_refuses_a_stack_outside_the_places_the_tools_work(write):
    """Checked beside the write too, not only in main(): a caller that skips main() still cannot write elsewhere."""
    target = OUTSIDE_DIR / "stack.json"
    with pytest.raises(SystemExit, match="refused: .* is outside the places the tools work"):
        write(target)


@pytest.mark.parametrize("write", [lambda p: aurora.merge_stack(p, {"k": "v"}),
                                   lambda p: apps.record_in_stack(p, "k", "v")], ids=["merge_stack", "record_in_stack"])
def test_a_sibling_whose_name_only_starts_like_a_working_place_is_refused(write, tmp_path, monkeypatch):
    """`<root>-evil/x` is not inside `<root>`: the check compares whole path parts, not the first characters."""
    root, sibling = tmp_path / "work", tmp_path / "work-evil"
    root.mkdir()
    sibling.mkdir()
    (sibling / "stack.json").write_text("{}", encoding="utf-8")
    for mod in (aurora, apps):
        monkeypatch.setattr(mod.paths, "work_roots", lambda: [root])
    with pytest.raises(SystemExit, match="refused: .* is outside the places the tools work"):
        write(sibling / "stack.json")
    assert (sibling / "stack.json").read_text(encoding="utf-8") == "{}"
