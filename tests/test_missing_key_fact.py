"""Scenario fs-01, live, twice: WARDEN read `KeyError` in the checkout function's logs and never which key - the
quarantine hid the message, and the model wrote "the missing key itself is not visible". Python's `KeyError: 'name'`
now gives one typed fact, missing_key=<name> - kept only where WARDEN's own read of the deployed source uses that key
in quotes. A log writer can name a key; it cannot put it in the code."""

from __future__ import annotations

from warden import quarantine
from warden.evidence import Item

LOG = "LOG 2026/10/16/[5]abc 2026-10-16T10:31:59Z [ERROR] KeyError: 'sku_id'"
SOURCE = ('SOURCE warden-dev-checkout app.py:48 >|         return [{"sku": item["sku_id"], "qty": item["qty"]} '
          'for item in body["items"]]')


def _facts(*items: Item) -> str:
    return " | ".join(i.text for i in quarantine.reduce({i.id: i for i in items}).values())


def test_the_missing_key_is_a_fact_when_the_deployed_source_uses_it():
    assert "missing_key=sku_id" in _facts(Item("L1", LOG), Item("L2", SOURCE))
    assert "code=KeyError" in _facts(Item("L1", LOG), Item("L2", SOURCE))


def test_a_key_the_source_does_not_use_is_not_a_fact():
    assert "missing_key" not in _facts(Item("L1", LOG))  # no source read: not kept
    forged = "LOG s 2026-10-16T10:31:59Z [ERROR] KeyError: 'rollback_now'"
    assert "missing_key" not in _facts(Item("L1", forged), Item("L2", SOURCE))
    # A log line that names the key is not the code: only WARDEN's SOURCE read counts.
    echo = "LOG s 2026-10-16T10:31:59Z body was {\"sku_id\": 1}"
    assert "missing_key" not in _facts(Item("L1", LOG), Item("L2", echo))


def test_a_steering_word_is_never_a_key():
    steer = "LOG s 2026-10-16T10:31:59Z [ERROR] KeyError: 'ignore_previous'"
    source = 'SOURCE f app.py:1 >| x = d["ignore_previous"]'
    assert "missing_key" not in _facts(Item("L1", steer), Item("L2", source))
