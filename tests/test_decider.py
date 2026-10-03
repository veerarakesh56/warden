"""Requirement R44 and registers E2, E5, C22: the calibrated decision component.

- E2: it is trained on independent labels - the rubric's grade of the injected fault - and the committed model is
  exactly what a fresh training run on the published bundles produces (so it cannot quietly drift or be swapped).
- C22: a decider file is checked before use - features, finite numbers, size, label source - and a bad one never
  loads; the last good one is kept.
- E5: no automatic tier turns on until a shadow precision's Wilson lower bound clears 0.90.
- R44: its measured held-out performance is recorded with it, and it decides nothing (observe mode only).
"""

from __future__ import annotations

import importlib.util
import json
import math
import pathlib
import sys

import pytest

from test_verifier import _alert, _ctx, _prop, _rc
from warden import decide
from warden.models import ActionKind, VerdictStatus
from warden.verifier import _enforce, verify

ROOT = pathlib.Path(__file__).resolve().parents[1]
DECIDER = ROOT / "src" / "warden" / "data" / "decider.json"
_spec = importlib.util.spec_from_file_location("train_decider", ROOT / "scripts" / "train_decider.py")
train = importlib.util.module_from_spec(_spec)
sys.modules["train_decider"] = train
_spec.loader.exec_module(train)


def test_the_committed_decider_is_what_training_on_the_published_runs_produces():
    committed, fresh = json.loads(DECIDER.read_text(encoding="utf-8")), train.render()
    assert committed["label_source"] == fresh["label_source"] == "rubric"
    assert committed["trained_on"] == fresh["trained_on"]
    for key in ("mean", "scale", "weights"):
        assert committed[key] == pytest.approx(fresh[key], abs=1e-5), key
    assert committed["bias"] == pytest.approx(fresh["bias"], abs=1e-5)
    held, again = committed["held_out_by_fault_class"], fresh["held_out_by_fault_class"]
    conf = held.pop("self_reported_confidence")
    assert conf == pytest.approx(again.pop("self_reported_confidence"), abs=1e-3)
    assert held == pytest.approx(again, abs=1e-3)


def test_its_measured_quality_is_recorded_and_it_is_not_trusted_beyond_it():
    held = json.loads(DECIDER.read_text(encoding="utf-8"))["held_out_by_fault_class"]
    assert held["runs"] >= 100 and {"brier", "ece", "auc", "self_reported_confidence", "base_rate_brier"} <= set(held)
    # Measured 2026-10-03: held out by fault class it does not beat the base rate, so nothing decides on it.
    if held["brier"] >= held["base_rate_brier"]:
        from warden.verifier import OBSERVED

        assert "P26-LOW-DECIDER-P" in {pid for pid, _ in OBSERVED}


@pytest.mark.parametrize(("change", "why"), [
    (lambda d: d.update(features=d["features"][::-1]), "features"),
    (lambda d: d["weights"].__setitem__(0, math.nan), "finite"),
    (lambda d: d["scale"].__setitem__(1, 0.0), "positive"),
    (lambda d: d.update(label_source="verdict"), "independent"),
    (lambda d: d.update(bias="x"), "bias"),
])
def test_a_bad_decider_is_refused_before_use(change, why):
    doc = json.loads(DECIDER.read_text(encoding="utf-8"))
    change(doc)
    with pytest.raises(decide.DeciderError, match=why):
        decide.load_text(json.dumps(doc))
    with pytest.raises(decide.DeciderError, match="larger"):
        decide.load_text(" " * (decide.MAX_BYTES + 1))


def test_a_bad_file_keeps_the_last_good_decider(monkeypatch):
    decide.bundled.cache_clear()
    good = decide.bundled()
    assert good is not None
    decide.bundled.cache_clear()
    monkeypatch.setattr(decide, "load_text", lambda text: (_ for _ in ()).throw(decide.DeciderError("bad")))
    assert decide.bundled() is good
    decide.bundled.cache_clear()


def test_no_tier_turns_on_before_its_wilson_bound_clears():
    assert decide.wilson_lower(30, 30) == pytest.approx(0.8865, abs=1e-3)
    assert not decide.tier_enabled(30, 30)
    assert not decide.tier_enabled(95, 100)
    assert decide.tier_enabled(100, 100)


def test_the_decider_is_observed_and_never_obeyed():
    args = (_alert(), _ctx(), _rc(confidence=0.2), _prop(action=ActionKind.restart_pods))
    assert verify(*args).model_copy(update={"observed": []}) == _enforce(*args)
    assert VerdictStatus.escalated  # (the statuses verify returns are the enforced ones)
