"""Logs hold no raw sensitive value (owner, 2026-10-20): every way a value can reach a log - a message, its arguments,
an exception's text, a chained cause, a traceback, a warning, a thread's error, a Lambda's uncaught error - goes
through the gate. Canaries are built from parts (tests/fakes.py's rule)."""

from __future__ import annotations

import io
import logging
import subprocess
import sys
import textwrap

import pytest

from fakes import AWS_ACCESS_KEY_ID, JWT
from warden import lambdas
from warden.observability import GatedFormatter, GatedWrap, gate_handlers

EMAIL = "canary.person" + "@" + "example.org"
IP = "203.0.113." + "77"
PHONE = "+1 415 555 " + "0142"
ACCOUNT = "1234" + "56789012"
CANARIES = (EMAIL, IP, PHONE, ACCOUNT, AWS_ACCESS_KEY_ID, JWT)


def _lambda_like_logger(name: str) -> tuple[logging.Logger, io.StringIO]:
    """A logger with a handler of its own and a layout of its own, as the Lambda runtime installs on the root."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("[%(levelname)s]\treq-1\t%(message)s"))
    log = logging.getLogger(name)
    log.handlers[:] = [handler]
    log.propagate = False
    return log, stream


@pytest.mark.parametrize("canary", CANARIES)
def test_a_handler_warden_did_not_install_writes_through_the_gate(canary):
    log, stream = _lambda_like_logger(f"canary.wrap.{CANARIES.index(canary)}")
    assert gate_handlers(log) == 1
    log.error("user %s failed", canary)
    try:
        try:
            raise KeyError(canary)
        except KeyError as inner:
            raise RuntimeError(f"while reading {canary}") from inner
    except RuntimeError:
        log.exception("read failed for %s", canary)
    out = stream.getvalue()
    assert canary not in out
    assert out.startswith("[ERROR]\treq-1\tuser <") and "Traceback" in out and "RuntimeError" in out


def test_gating_handlers_is_idempotent_and_keeps_wardens_own_formatter():
    log, _ = _lambda_like_logger("canary.idem")
    own = logging.StreamHandler(io.StringIO())
    own.setFormatter(GatedFormatter())
    log.addHandler(own)
    assert gate_handlers(log) == 1
    assert gate_handlers(log) == 0
    assert isinstance(log.handlers[0].formatter, GatedWrap) and own.formatter.__class__ is GatedFormatter


def test_a_formatter_that_fails_is_withheld_not_printed_raw():
    class Broken(logging.Formatter):
        def format(self, record):
            raise ValueError(EMAIL)

    record = logging.LogRecord("x", logging.ERROR, __file__, 1, "user %s", (EMAIL,), None)
    assert GatedWrap(Broken()).format(record) == "ERROR x: (log text withheld)"


@pytest.mark.parametrize("canary", CANARIES)
def test_a_lambdas_uncaught_error_reaches_neither_the_log_nor_the_runtime_raw(canary, monkeypatch):
    stream = io.StringIO()
    runtime = logging.StreamHandler(stream)  # the Lambda runtime's own root handler
    runtime.setFormatter(logging.Formatter("[%(levelname)s]\treq-1\t%(message)s"))
    root = logging.getLogger()
    monkeypatch.setattr(root, "handlers", [runtime])

    def handler(event, context=None):
        raise ValueError(f"cannot parse {event['detail']}")

    gated = lambdas._gated(handler)
    with pytest.raises(lambdas.HandlerFailed) as caught:
        gated({"detail": f"alarm from {canary}"})
    assert canary not in str(caught.value) and "(ValueError)" in str(caught.value)
    assert caught.value.__cause__ is None and caught.value.__suppress_context__
    out = stream.getvalue()
    assert canary not in out and "handler failed" in out and "ValueError" in out


def test_every_lambda_entry_point_is_gated():
    for name in ("alarm", "alertmanager", "approval", "actor_use", "migrate"):
        fn = getattr(lambdas, name)
        assert fn.__wrapped__.__name__ == name and fn.__code__ is lambdas._gated(fn.__wrapped__).__code__


_PROCESS = textwrap.dedent("""
    import logging, sys, threading, warnings
    sys.path.insert(0, {tests!r})
    from fakes import AWS_ACCESS_KEY_ID, JWT
    from warden.observability import install_log_gate
    install_log_gate(logging.INFO)
    values = ["canary.person" + "@" + "example.org", "203.0.113." + "77", "+1 415 555 " + "0142",
              "1234" + "56789012", AWS_ACCESS_KEY_ID, JWT]
    log = logging.getLogger("warden.anything")
    for v in values:
        log.info("plain %s", v)
        log.warning("in the message " + v)
        try:
            raise OSError("connect to " + v)
        except OSError:
            log.exception("failed")
        warnings.warn("deprecated for " + v)
        t = threading.Thread(target=lambda v=v: (_ for _ in ()).throw(RuntimeError("in a thread " + v)))
        t.start(); t.join()
""")


def test_a_real_process_logs_no_canary_whatever_the_path(tmp_path):
    """The CLI's and the worker's process: log calls, exceptions, warnings, a thread's error. (An exit's text is the
    CLI's to gate: tests/test_log_gate_review5.py.)"""
    code = _PROCESS.format(tests=str(__import__("pathlib").Path(__file__).parent))
    got = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120, check=False)
    out = got.stdout + got.stderr
    assert "in a thread" in out and "deprecated for" in out and "connect to" in out  # each path was taken
    for canary in CANARIES:
        assert canary not in out, canary
