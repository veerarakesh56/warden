"""Terraform and its providers are bounded, and what CI runs satisfies every bound (audit A-I-22: `>= 1.10` and
`>= 5.80` let any future release in)."""
from __future__ import annotations

import pathlib
import re

import pytest
from packaging.specifiers import SpecifierSet
from packaging.version import Version

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULES = [ROOT / "terraform", ROOT / "terraform" / "fullstack", ROOT / "terraform" / "proving-ground",
           ROOT / "terraform" / "modules" / "warden-runtime"]


def _spec(constraint: str) -> SpecifierSet:
    """Terraform's `~> 5.0` is PEP 440's `~= 5.0`; the rest of its syntax is the same."""
    return SpecifierSet(constraint.replace("~>", "~=").replace(" ", ""))


def _bounded(spec: SpecifierSet) -> bool:
    return any(s.operator in ("<", "<=", "~=", "==") for s in spec)


def _ci_terraform() -> set[str]:
    flows = ROOT / ".github" / "workflows"
    return {m for f in flows.glob("*.yml")
            for m in re.findall(r'terraform_version:\s*"([^"]+)"', f.read_text(encoding="utf-8"))}


@pytest.mark.parametrize("module", MODULES, ids=lambda m: m.relative_to(ROOT).as_posix())
def test_terraform_and_every_provider_have_an_upper_bound_ci_satisfies(module):
    text = "\n".join(p.read_text(encoding="utf-8") for p in module.glob("*.tf"))
    required = re.findall(r'required_version\s*=\s*"([^"]+)"', text)
    assert len(required) == 1, required
    spec = _spec(required[0])
    assert _bounded(spec), required[0]
    pinned = _ci_terraform()
    assert pinned and all(Version(v) in spec for v in pinned), (required[0], pinned)

    providers = dict(re.findall(r'source\s*=\s*"([^"]+)"\s*,?\s*\n?\s*version\s*=\s*"([^"]+)"', text))
    assert providers, module
    lock = (module / ".terraform.lock.hcl").read_text(encoding="utf-8")
    locked = dict(re.findall(r'provider "registry\.terraform\.io/([^"]+)" \{\s*version\s*=\s*"([^"]+)"', lock))
    assert set(locked) == set(providers), (locked, providers)  # no stale or missing lock entry
    for source, constraint in providers.items():
        assert _bounded(_spec(constraint)), (source, constraint)
        assert Version(locked[source]) in _spec(constraint), (source, constraint, locked[source])
