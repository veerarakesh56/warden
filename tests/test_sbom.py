"""Registers S9, A-P-7: a software and model bill of materials, and the detector's weights pinned by commit."""

from __future__ import annotations

import json
import pathlib
import sys
import tomllib
import types

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import sbom  # after the sys.path line above

from warden import tripwire


def test_the_committed_bill_is_exactly_a_fresh_render():
    assert json.loads(sbom.OUT.read_text(encoding="utf-8")) == sbom.render(), "run python scripts/sbom.py"


def test_every_locked_package_is_listed_with_its_hash():
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    libs = {c["name"]: c for c in sbom.render()["components"] if c["type"] == "library"}
    locked = {p["name"]: p["version"] for p in lock["package"] if p["name"] != "warden"}
    assert {n: c["version"] for n, c in libs.items()} == locked
    assert all(c["purl"] == f"pkg:pypi/{n}@{c['version']}" and c["hashes"] for n, c in libs.items())


def test_the_model_bill_names_the_pinned_detector_and_every_qualified_model():
    import yaml

    models = {c["name"]: c for c in sbom.render()["components"] if c["type"] == "machine-learning-model"}
    assert models[tripwire.MODEL]["version"] == tripwire.REVISION and len(tripwire.REVISION) == 40
    qualified = yaml.safe_load((ROOT / "src" / "warden" / "data" / "providers.yaml").read_text(encoding="utf-8"))
    assert {q["model"] for q in qualified["qualified"]} <= set(models)


def test_the_detector_loads_its_pinned_revision_from_safetensors_only(monkeypatch):
    seen = {}
    monkeypatch.setitem(sys.modules, "transformers",
                        types.SimpleNamespace(pipeline=lambda task, **kw: seen.update(kw) or object()))
    tripwire._classifier.cache_clear()
    try:
        tripwire._classifier()
    finally:
        tripwire._classifier.cache_clear()
    assert seen["model"] == tripwire.MODEL and seen["revision"] == tripwire.REVISION
    assert seen["model_kwargs"] == {"use_safetensors": True}
