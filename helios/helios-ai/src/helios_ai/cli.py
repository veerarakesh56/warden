"""Thin argparse shell. Two subcommands share the same stdin/stdout pipe shape.

- `explain` — reads FailureChain JSON on stdin, writes markdown narrative.
- `propose-fix` — reads {chain, attrs_snapshot} JSON on stdin, writes a
  FixProposal JSON object on stdout.

If HELIOS_AI_MOCK=1 is set, a canned fake client is used instead of the
real Anthropic SDK — used by the Rust end-to-end smoke test and anyone
running the CLI without an API key. Otherwise HELIOS_AI_PROVIDER picks
`anthropic` (default, needs ANTHROPIC_API_KEY) or `claude_cli` (the local
`claude` CLI on a Claude subscription, no key).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from .explain import explain
from .fix_generator import propose_fix
from .models import FailureChain

_PROVIDERS = ("anthropic", "claude_cli", "claude-cli")


def _build_client() -> Any:
    if os.environ.get("HELIOS_AI_MOCK") == "1":
        from ._mock import MockAnthropic

        return MockAnthropic()

    provider = os.environ.get("HELIOS_AI_PROVIDER", "anthropic")
    if provider not in _PROVIDERS:
        raise SystemExit(
            f"unknown HELIOS_AI_PROVIDER={provider!r}; known: {', '.join(_PROVIDERS)}"
        )
    if provider != "anthropic":
        from ._claude_cli import ClaudeCliClient

        return ClaudeCliClient()

    import anthropic  # lazy — tests that mock _build_client don't need SDK

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise SystemExit("ANTHROPIC_API_KEY not set")
    return anthropic.Anthropic(api_key=api_key)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="helios-ai")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("explain", help="Read FailureChain JSON on stdin, write narrative on stdout.")
    sub.add_parser(
        "propose-fix",
        help="Read {chain, attrs_snapshot} JSON on stdin, write FixProposal JSON on stdout.",
    )
    args = parser.parse_args(argv)
    # UTF-8 both ways, not the Windows code page: the engine writes UTF-8 JSON and the model's
    # `—`/`→` must reach the Rust wrapper intact (cp1252 wrote them as mojibake).
    # stdin as utf-8-sig: Windows PowerShell 5.1 prefixes a byte-order mark to what it pipes in.
    for stream, encoding in ((sys.stdin, "utf-8-sig"), (sys.stdout, "utf-8")):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding=encoding)
    try:
        return _run(args.cmd)
    except _BadInput as exc:
        print(f"helios-ai: stdin is not valid {args.cmd} input: {exc}", file=sys.stderr)
        return 2
    except RuntimeError as exc:
        # Provider failure or a reply that is not a valid FixProposal: nothing on stdout, so a
        # pipeline into `helios verify --fix` sees an empty file, never a half-trusted one.
        print(f"helios-ai: {exc}", file=sys.stderr)
        return 1


class _BadInput(Exception):
    """stdin is not the JSON the subcommand reads: one line on stderr, not a traceback."""


def _run(cmd: str) -> int:
    if cmd == "explain":
        try:
            chain = FailureChain.model_validate_json(sys.stdin.read())
        except ValueError as exc:  # pydantic's ValidationError is a ValueError
            raise _BadInput(exc) from exc
        client = _build_client()
        sys.stdout.write(explain(chain, client=client))
        sys.stdout.write("\n")
        return 0

    if cmd == "propose-fix":
        try:
            payload = json.loads(sys.stdin.read())
            chain = FailureChain.model_validate(payload["chain"])
            attrs_snapshot = payload.get("attrs_snapshot", {})
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise _BadInput(exc) from exc
        client = _build_client()
        fix = propose_fix(chain, attrs_snapshot=attrs_snapshot, client=client)
        sys.stdout.write(fix.model_dump_json(indent=2))
        sys.stdout.write("\n")
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
