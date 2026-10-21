"""SonarQube Cloud's automatic analysis settings (.sonarcloud.properties, owner 2026-10-21) stay true to the code: the
test code is analysed as tests, the Python versions start where pyproject.toml does, and the AWS provider version is
the major every deployed stack locks."""

from __future__ import annotations

import pathlib
import re
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[2]


def _props() -> dict[str, str]:
    lines = (ROOT / ".sonarcloud.properties").read_text(encoding="utf-8").splitlines()
    pairs = [line.split("=", 1) for line in lines if line.strip() and not line.lstrip().startswith("#")]
    return {key.strip(): value.strip() for key, value in pairs}


def _listed(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def test_every_test_file_is_analysed_as_a_test_and_only_as_one():
    props = _props()
    tests = _listed(props["sonar.tests"])
    excluded = _listed(props["sonar.exclusions"])
    assert props["sonar.sources"] == "."
    # Each test path is left out of the sources, or Sonar would index the file twice and stop; beyond them only test
    # DATA is left out: Helios's fixtures (deliberately weak example infrastructure its golden tests are pinned to).
    data = ["helios/fixtures/**"]
    assert sorted(excluded) == sorted([*(t if t.endswith(".py") else f"{t}/**" for t in tests), *data])
    assert all((ROOT / d.removesuffix("/**")).is_dir() for d in data)
    pytest_paths = tomllib.loads((ROOT / "warden" / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["pytest"]["ini_options"]
    assert {f"warden/{p}" for p in pytest_paths["testpaths"]} <= set(tests)  # relative to warden/
    tracked = [p for p in ROOT.rglob("*.py") if ".venv" not in p.parts and "node_modules" not in p.parts]
    test_like = [p.relative_to(ROOT).as_posix() for p in tracked
                 if re.fullmatch(r"test_.*\.py|.*_test\.py|conftest\.py", p.name)]
    outside = [p for p in test_like if not any(p == t or p.startswith(t + "/") for t in tests)]
    assert outside == []


def test_the_python_versions_start_where_pyproject_does():
    requires = tomllib.loads((ROOT / "warden" / "pyproject.toml").read_text(encoding="utf-8"))["project"]["requires-python"]
    floor = re.fullmatch(r">=\s*(3\.\d+)", requires).group(1)
    versions = _listed(_props()["sonar.python.version"])
    assert versions[0] == floor
    assert versions == sorted(versions, key=lambda v: tuple(map(int, v.split("."))))


def test_the_aws_provider_version_is_the_major_the_deployed_stacks_lock():
    stacks = ["fullstack", "modules/warden-runtime", "proving-ground", "runtime", "undo-lab"]
    majors = set()
    for stack in stacks:
        lock = (ROOT / "infra" / "terraform" / stack / ".terraform.lock.hcl").read_text(encoding="utf-8")
        block = lock[lock.index('provider "registry.terraform.io/hashicorp/aws"'):]
        majors.add(re.search(r'version\s*=\s*"(\d+)\.', block).group(1))
    assert majors == {_props()["sonar.terraform.provider.aws.version"]}
