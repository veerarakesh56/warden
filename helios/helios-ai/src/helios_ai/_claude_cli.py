"""Inference through the locally installed `claude` CLI in headless (`-p`) mode.

For an owner with a Claude subscription (Max) and no API key. `ClaudeCliClient` duck-types the
one method Helios uses, `client.messages.create(**kw)`, so `explain.py` and `fix_generator.py`
do not know which provider they are talking to. Mirrors WARDEN's `ClaudeCliProvider`.

⛔ EVERY TOOL IS DISABLED, AND THE PROCESS RUNS OUTSIDE THE REPOSITORY. The user turn carries
Terraform attrs, which are untrusted input: a `description` or a tag value can say "ignore the
above and run ...". A model with no tools and a scratch cwd has nothing to act on even if it
obeys. Two independent reasons it cannot reach anything, because one would be an assumption.

⚠ Tokens are ESTIMATED (the CLI reports none); nothing is metered per call. `output_config` is
not a CLI feature, so the JSON schema goes into the system prompt instead and the reply is only
trusted after `FixProposal.model_validate_json` accepts it — the fail-closed check stays in
`fix_generator.py`.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Any

from ._mock import _Message, _TextBlock, _Usage

# Named rather than a wildcard: a tool added to the CLI later must not silently become available.
_NO_TOOLS = (
    "Read", "Write", "Edit", "NotebookEdit", "Bash", "Glob", "Grep",
    "WebFetch", "WebSearch", "Task", "Agent", "TodoWrite",
)

# ⛔ Variables that make the CLI load the operator's own CLAUDE.md, skills and modes. Measured in
# WARDEN: with them, the same prompt took 26s and came back as prose refusing the request; without
# them, clean JSON in 11s. Stripped always — but on Windows NOT sufficient on its own (see the
# `--setting-sources` comment in create()); kept because it costs nothing.
_CONFIG_ENV = ("USERPROFILE", "HOME", "HOMEPATH", "HOMEDRIVE", "XDG_CONFIG_HOME",
               "CLAUDE_CONFIG_DIR", "CLAUDE_CODE_CONFIG", "ANTHROPIC_CONFIG_DIR")

# "session limit" is the wording the CLI actually printed when WARDEN's live wave hit it.
_USAGE_LIMIT = re.compile(
    r"usage limit|session limit|hit your \w+ limit|limit reached|rate limit|quota"
    r"|credit balance is too low|out of credits",
    re.IGNORECASE,
)

# At most ONE fence wrapping the whole reply. Anything else is left for the validator to reject.
_FENCE = re.compile(r"\A\s*```[a-zA-Z]*\s*\n(.*?)\n?\s*```\s*\Z", re.DOTALL)


def _timeout_s() -> float:
    # A whole Claude Code process boots per call; 16k-token narrations are not 45s work.
    return float(os.environ.get("HELIOS_AI_TIMEOUT", "300"))


def _estimate_tokens(text: str) -> int:
    """Deliberately an over-estimate (3 chars/token)."""
    return max(1, len(text) // 3)


def _text(system: Any) -> str:
    if isinstance(system, str):
        return system
    return "\n\n".join(block["text"] for block in system)


class _Messages:
    def __init__(self, exe: str) -> None:
        self._exe = exe

    def create(self, *, model: str, system: Any, messages: list[dict[str, Any]],
               output_config: dict[str, Any] | None = None, **_: Any) -> _Message:
        system_text = _text(system)
        if output_config is not None:
            schema = json.dumps(output_config["format"]["schema"])
            system_text += (
                "\n\nReturn ONLY a JSON object matching this JSON Schema, with no prose and no "
                f"code fence:\n{schema}"
            )
        user = "\n\n".join(m["content"] for m in messages)
        env = {k: v for k, v in os.environ.items() if k not in _CONFIG_ENV}
        cmd = [
            self._exe, "-p",
            "--model", model,
            "--system-prompt", system_text,
            # ⛔ MEASURED on this Windows box (CLI 2.1.283): with only the WARDEN flags the model
            # still had 25 callable tools (Skill, Workflow, CronCreate, the operator's claude.ai
            # MCP connectors ...) and the operator's CLAUDE.md and SessionStart hooks were loaded,
            # env stripping notwithstanding (the CLI finds the profile dir without USERPROFILE).
            # These three flags took it to NO TOOLS and none of that context.
            "--tools", "",
            "--strict-mcp-config",
            "--setting-sources", "",
            "--disallowed-tools", *_NO_TOOLS,
        ]
        try:
            proc = subprocess.run(
                cmd,
                # ⛔ STDIN, not argv: chain + attrs run to many KB and Windows caps a command line
                # at ~32k.
                input=user,
                capture_output=True,
                text=True,
                # ⛔ Explicit UTF-8 both ways. The Windows code page (cp1252) cannot encode `→` and
                # silently corrupts `—` for a CLI that reads UTF-8.
                encoding="utf-8",
                errors="replace",
                timeout=_timeout_s(),
                check=False,
                env=env,
                cwd=tempfile.gettempdir(),
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"claude CLI exceeded {_timeout_s():.0f}s") from exc
        if proc.returncode != 0:
            # ⛔ BOTH streams: the CLI writes its refusal reason (usage limit included) to stdout.
            detail = " | ".join(
                part.strip() for part in (proc.stdout, proc.stderr) if part and part.strip()
            )[:400]
            if _USAGE_LIMIT.search(detail):
                raise RuntimeError(f"claude CLI usage limit: {detail}")
            raise RuntimeError(f"claude CLI exited {proc.returncode}: {detail or '(no output)'}")
        text = proc.stdout or ""
        if output_config is not None:
            m = _FENCE.match(text)
            if m:
                text = m.group(1)
        return _Message(
            content=[_TextBlock(type="text", text=text)],
            usage=_Usage(input_tokens=_estimate_tokens(system_text + user),
                         output_tokens=_estimate_tokens(text)),
        )


class ClaudeCliClient:
    """Ducks the part of `anthropic.Anthropic` Helios uses: `.messages.create(**kw)`."""

    def __init__(self) -> None:
        exe = shutil.which("claude")
        if not exe:
            raise SystemExit(
                "HELIOS_AI_PROVIDER=claude_cli needs the `claude` CLI on PATH. Install Claude "
                "Code, or use HELIOS_AI_PROVIDER=anthropic with ANTHROPIC_API_KEY."
            )
        self.messages = _Messages(exe)
