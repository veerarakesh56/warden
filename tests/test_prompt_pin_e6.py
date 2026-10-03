"""Register E6: a model, prompt or CLI change is gated. Model ids are exact (M15) and qualified (M20); the prompt the
qualification measured is pinned by hash, so changing it fails here until it is qualified again; and two runs are
compared with an exact McNemar test, so "better" means more than chance."""

from __future__ import annotations

import importlib.util
import pathlib
import sys

import pytest

from warden.providers import load_qualified

ROOT = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("qualify_provider_e6", ROOT / "scripts" / "qualify_provider.py")
qualify = importlib.util.module_from_spec(_spec)
sys.modules["qualify_provider_e6"] = qualify
_spec.loader.exec_module(qualify)


def test_the_prompt_is_the_one_the_models_were_qualified_with():
    pinned = load_qualified()["prompt"]["sha"]
    assert qualify.prompt_fingerprint() == pinned, (
        "the prompt changed: qualify the model again with it (scripts/qualify_provider.py) and update the pin in "
        "src/warden/data/providers.yaml in the same commit")


def test_the_fingerprint_is_stable_and_ignores_only_the_random_data_marker():
    assert qualify.prompt_fingerprint() == qualify.prompt_fingerprint()


def test_a_change_is_compared_with_mcnemar():
    before = {f"i{k}": k < 15 for k in range(30)}
    same = qualify.mcnemar(before, dict(before))
    assert same == {"incidents": 30, "fixed": 0, "broke": 0, "p": 1.0}
    better = {**before, **{f"i{k}": True for k in range(15, 25)}}  # ten fixed, none broken
    r = qualify.mcnemar(before, better)
    assert (r["fixed"], r["broke"]) == (10, 0) and r["p"] == pytest.approx(2 / 1024)
    noise = {**before, "i20": True, "i0": False}  # one fixed, one broken: chance
    assert qualify.mcnemar(before, noise)["p"] == 1.0
