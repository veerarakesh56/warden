"""The stdin side of the CLI: what Windows actually pipes in, and what a wrong input looks like."""

from __future__ import annotations

import os
import subprocess
import sys

CHAIN = '{"scenario": "s", "failures": [{"id": "aws_subnet.a", "kind": "Subnet", "reason": "r"}]}'


def _run(cmd: str, stdin: bytes) -> subprocess.CompletedProcess[bytes]:
    env = {**os.environ, "HELIOS_AI_MOCK": "1"}
    return subprocess.run([sys.executable, "-m", "helios_ai", cmd], input=stdin,
                          capture_output=True, env=env, timeout=60, check=False)


def test_a_byte_order_mark_from_powershell_is_accepted() -> None:
    # Windows PowerShell 5.1 prefixes one to what it pipes into a native command.
    out = _run("explain", "﻿".encode() + CHAIN.encode())
    assert out.returncode == 0, out.stderr.decode()
    assert out.stdout.strip()


def test_input_that_is_not_a_chain_is_one_line_not_a_traceback() -> None:
    for cmd, stdin in (("explain", b"not json"), ("propose-fix", b'{"no_chain": 1}')):
        out = _run(cmd, stdin)
        err = out.stderr.decode()
        assert out.returncode == 2, err
        assert err.startswith(f"helios-ai: stdin is not valid {cmd} input:"), err
        assert "Traceback" not in err
        assert out.stdout == b""
