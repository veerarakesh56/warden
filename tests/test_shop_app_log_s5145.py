"""The demo shop logs a failed request by its route, never by the request line the client wrote (Sonar
pythonsecurity:S5145): the query string reached the log as sent."""

from __future__ import annotations

import importlib.util
import logging
import pathlib
import sys
import types

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_a_failed_route_is_logged_by_its_route_not_the_request_line(monkeypatch, caplog):
    # The shop image's clients, none reached here: the modules app.py imports, with the names it takes from them.
    stubs = {"psycopg": {}, "redis": {}, "redis.backoff": {"NoBackoff": object}, "redis.retry": {"Retry": object}}
    for name, names in stubs.items():
        monkeypatch.setitem(sys.modules, name, types.SimpleNamespace(**names))
    spec = importlib.util.spec_from_file_location("shop_app_s5145", ROOT / "scenarios" / "fullstack" / "app" / "app.py")
    app = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app)

    def boom():
        raise RuntimeError("down")

    handler = object.__new__(app.Handler)
    handler.path, replies = "/orders?note=forged-line", []
    handler.reply = lambda status, body, span=None: replies.append(status)
    monkeypatch.setattr(app.Handler, "routes", {"/orders": boom})
    with caplog.at_level(logging.ERROR):
        handler._get("/orders", None)
    assert replies == [500]
    assert "GET /orders failed" in caplog.text
    assert "forged-line" not in caplog.text
