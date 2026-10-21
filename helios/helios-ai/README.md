# helios-ai

Python AI shell for [Helios](../README.md). Reads `FailureChain` JSON from the Rust engine on stdin and writes a human-readable markdown narrative on stdout via Claude.

## Dev

    uv sync
    uv run pytest
    uv run ruff check

## Use

    helios simulate ./infra --scenario scenarios/az-outage.yaml --json \
      | ANTHROPIC_API_KEY=... uv run python -m helios_ai explain

Or go through the Rust wrapper, which finds `helios-ai/.venv` from the repo root (or set
`HELIOS_AI_PYTHON`):

    helios simulate ./infra --scenario scenarios/az-outage.yaml --json | helios explain

## Providers

`HELIOS_AI_MOCK=1` wins (canned replies, no model). Otherwise `HELIOS_AI_PROVIDER` picks:

| Value | Needs | Notes |
|---|---|---|
| `anthropic` (default) | `ANTHROPIC_API_KEY` | Anthropic SDK; `propose-fix` uses structured output |
| `claude_cli` / `claude-cli` | the `claude` CLI on PATH, logged in (e.g. a Claude Max plan) | no API key; one `claude -p` process per call |

    helios simulate ./infra --scenario scenarios/az-outage.yaml --json \
      | HELIOS_AI_PROVIDER=claude_cli uv run python -m helios_ai explain

`HELIOS_AI_MODEL` (default `claude-opus-5-5`; `opus` also works) and
`HELIOS_AI_TIMEOUT` (seconds per CLI call, default 300) apply.

What `claude_cli` does differently, all in `src/helios_ai/_claude_cli.py`:

- **No tools, no operator context.** Terraform attrs are untrusted input (a tag value can carry an
  injected instruction), so the model gets nothing to act with: `--tools ""`,
  `--strict-mcp-config`, `--setting-sources ""`, a named `--disallowed-tools` list, a temp-dir
  cwd, and the config env vars stripped. Measured on Windows: without the first three flags the
  model still had 25 callable tools (the operator's MCP connectors among them) and the operator's
  CLAUDE.md and hooks loaded.
- **No structured output.** The FixProposal JSON Schema goes into the system prompt, one
  surrounding code fence is stripped, and `FixProposal.model_validate_json` stays the fail-closed
  check: anything else exits 1 with empty stdout.
- **Tokens are estimated** (3 chars/token); nothing is metered per call, and the plan's own limit
  is the real ceiling. A usage-limit refusal is reported as `claude CLI usage limit: ...`.
- Results depend on the CLI version as well as the model; label runs made this way.
