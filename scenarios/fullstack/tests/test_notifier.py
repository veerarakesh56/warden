"""The notifier Lambda: an order event is logged as sent; an unreadable one fails its record, so SQS retries it."""

import json

import pytest


def test_an_order_event_is_sent(load_app, caplog):
    notifier = load_app("notifier")
    event = {"Records": [{"messageId": "m-1", "body": json.dumps({"order_id": "o-1", "cart_id": "c-1"})}]}
    with caplog.at_level("INFO"):
        notifier.handler(event, None)
    assert "notification sent order_id=o-1 cart_id=c-1" in caplog.text


def test_an_unreadable_order_event_fails_its_record(load_app):
    notifier = load_app("notifier")
    event = {"Records": [{"messageId": "m-2", "body": "{}"}]}
    with pytest.raises(KeyError):
        notifier.handler(event, None)
