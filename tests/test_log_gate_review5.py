"""Fifth independent review (2026-10-01), area A: every way Python prints raw text goes through the log gate -
warnings, uncaught errors that are not an Exception, errors in threads and in `__del__`, and SystemExit codes
that are not numbers. The secret is AWS's documented example key."""
from __future__ import annotations

import logging
import os
import pathlib
import subprocess
import sys

import pytest

from warden import cli
from warden.observability import GatedFormatter

SECRET = "AKIA" + "IOSFODNN7EXAMPLE"
SRC = str(pathlib.Path(__file__).resolve().parents[1] / "src")


def _child(code: str) -> subprocess.CompletedProcess:
    """`code` in a fresh process that installed the log gate first, as every WARDEN entry point does."""
    env = {**os.environ, "PYTHONPATH": SRC, "PYTHONIOENCODING": "utf-8"}
    script = f"from warden.observability import install_log_gate\ninstall_log_gate()\nSECRET = {SECRET!r}\n{code}"
    return subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, encoding="utf-8",
                          env=env, timeout=120, check=False)


@pytest.mark.parametrize(("code", "marker"), [
    ("import warnings\nwarnings.warn('careful key=' + SECRET)", "py.warnings"),
    ("raise BaseExceptionGroup('g', [KeyboardInterrupt(), RuntimeError('key=' + SECRET)])", "uncaught"),
    ("raise GeneratorExit('key=' + SECRET)", "uncaught GeneratorExit"),
    (("import threading\nt = threading.Thread(target=lambda: (_ for _ in ()).throw(RuntimeError('key=' + SECRET)))\n"
      "t.start()\nt.join()"), "in a thread"),
    ("class D:\n    def __del__(self):\n        raise RuntimeError('key=' + SECRET)\nD()\nimport gc\ngc.collect()",
     "unraisable"),
])
def test_every_raw_print_channel_is_gated(code, marker):
    """Warnings went to stderr raw from the CLI and `warden worker`; a BaseExceptionGroup, a thread's error
    and an error in `__del__` printed a raw traceback with the key."""
    out = _child(code)
    assert SECRET not in out.stdout + out.stderr, out.stderr
    assert marker in out.stderr, out.stderr


@pytest.mark.parametrize("code", [("cfg", SECRET), RuntimeError("key=" + SECRET)])
def test_a_systemexit_that_is_not_a_number_is_gated(monkeypatch, capsys, code):
    """Python prints a SystemExit's tuple or exception raw; only a string was gated."""
    monkeypatch.setattr(cli, "_main", lambda argv: (_ for _ in ()).throw(SystemExit(code)))
    assert cli.main([]) == 2
    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err
    assert captured.err.strip()  # one gated line: here withheld whole, as the outbound gate does with a key


def test_an_error_whose_text_raises_is_one_gated_line(monkeypatch, capsys):
    class Odd(Exception):
        def __str__(self):
            raise ValueError("no text")

    monkeypatch.setattr(cli, "_main", lambda argv: (_ for _ in ()).throw(Odd()))
    assert cli.main([]) == 1
    assert "Odd" in capsys.readouterr().err


@pytest.mark.parametrize("sep", ["\u00a0", "\u2028", "\u3000"])
def test_a_long_record_joined_by_other_whitespace_is_cut_not_withheld(sep):
    """The cut looked for space, newline and tab only: a record joined by NBSP or U+2028 was withheld whole."""
    record = logging.LogRecord("x", logging.INFO, __file__, 1, sep.join(["word"] * 20000), None, None)
    text = GatedFormatter("%(message)s").format(record)
    assert "withheld" not in text and text.startswith("word")
