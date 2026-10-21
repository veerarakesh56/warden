"""A paid model's qualification run has a hard total-spend ceiling (scripts/qualify_provider.py --budget-usd)."""

from __future__ import annotations

import importlib.util
import pathlib
import sys

import pytest

from warden.llm import BudgetExceeded

ROOT = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("qualify_provider_b", ROOT / "scripts" / "qualify_provider.py")
qualify = importlib.util.module_from_spec(_spec)
sys.modules["qualify_provider_b"] = qualify
_spec.loader.exec_module(qualify)


class _Client:
    def __init__(self):
        self.max_usd = 0.50
        self.cost = type("Cost", (), {"usd": 0.0})()


def test_each_incident_gets_only_what_is_left_and_none_once_it_is_spent():
    budget = qualify.Budget(1.00, factory=_Client)
    first = budget()
    assert first.max_usd == 0.50  # its own per-incident ceiling is lower than what is left
    first.cost.usd = 0.80
    second = budget()
    assert second.max_usd == pytest.approx(0.20)
    second.cost.usd = 0.20
    with pytest.raises(BudgetExceeded):
        budget()
    assert budget.spent() == pytest.approx(1.00)


def test_a_budget_must_be_positive():
    for bad in (0, -1, float("nan")):
        with pytest.raises(ValueError):
            qualify.Budget(bad, factory=_Client)
