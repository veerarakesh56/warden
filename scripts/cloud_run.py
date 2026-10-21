"""Paid measurement runs with the cloud runtime's own model key - one command each (owner, 2026-10-17).

    python scripts/cloud_run.py qualify --model claude-sonnet-5-5 --budget-usd 2
    python scripts/cloud_run.py qualify --model claude-opus-5-5 --budget-usd 3

The key is the runtime's: ANTHROPIC_API_KEY when the process already holds it (the llm zone's task, where ECS injects
it from Secrets Manager), else read from Secrets Manager (`warden/<runtime env>/anthropic-api-key`, the runtime
environment from environments.yaml) with the caller's own AWS identity. It stays in this process's environment and is
never printed or written anywhere. Nothing here names a path on anyone's machine: results go to --out (a new
directory under the system's temporary directory by default), and `--record` writes the measured row into
src/warden/data/providers.yaml of the checkout this script is in, regenerating docs/safety-pins.sha256 with it.

A row is a measurement, never a claim: a passing run is added under `qualified:`; a run below the bar is recorded as a
comment saying NOT QUALIFIED, with its numbers. Either way the change is reviewed in a pull request like any other.

JOBS is the registry: a later run (a head-to-head of two models, a larger bench) adds its own entry with the same key
handling and the same recording.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
import pathlib
import sys
import tempfile
from collections.abc import Callable

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROVIDERS_YAML = ROOT / "src" / "warden" / "data" / "providers.yaml"
KEY_SLOT = "anthropic-api-key"  # the slot's name in Secrets Manager, never its value


def runtime_environment() -> str:
    from warden.environments import default_environment_policies

    env = default_environment_policies().runtime_environment
    if not env:
        raise SystemExit("environments.yaml names no runtime environment")
    return env


def key_source(env: str) -> str:
    """Where the key comes from, in words: computed without reading it, so nothing said can carry it."""
    if os.environ.get("ANTHROPIC_API_KEY", "").strip():
        return "ANTHROPIC_API_KEY, already in this process (the llm zone's task)"
    return f"Secrets Manager warden/{env}/{KEY_SLOT}"


def model_key(env: str, client: object = None) -> None:
    """Put the runtime's Anthropic key in this process's environment, from Secrets Manager unless already there."""
    if os.environ.get("ANTHROPIC_API_KEY", "").strip():
        return
    if client is None:
        import boto3

        from warden.environments import region

        client = boto3.client("secretsmanager", region_name=region())
    name = f"warden/{env}/{KEY_SLOT}"
    value = client.get_secret_value(SecretId=name)["SecretString"].strip()
    if not value:
        raise SystemExit(f"{name} is empty")
    os.environ["ANTHROPIC_API_KEY"] = value


def recorded(result: dict, text: str) -> tuple[str, str]:
    """providers.yaml's text with the measured row in it - under `qualified:` when it passed, else as a NOT QUALIFIED
    comment - and the line written. Pure: main() writes the one file it may, PROVIDERS_YAML."""
    row = {k: v for k, v in result.items() if k not in ("passed", "slo_breaches")}
    when = dt.datetime.now(dt.UTC).strftime("%Y-%m-%d %H:%MZ")
    if result.get("passed"):
        lines = [f"  # Measured {when} by scripts/cloud_run.py qualify with the cloud runtime's key.",
                 f"  - {json.dumps(row)}"]
    else:
        breaches = "; ".join(result.get("slo_breaches") or [])
        said = (f"  # NOT QUALIFIED - measured {when} by scripts/cloud_run.py qualify with the cloud runtime's key "
                f"(below the bar{': ' + breaches if breaches else ''}):")
        lines = [said, f"  #  {json.dumps(row)}"]
    out = text.splitlines(keepends=True)
    at = next((i for i, line in enumerate(out) if line.rstrip() == "qualified:"), None)
    if at is None:
        raise SystemExit("providers.yaml has no `qualified:` list")
    out[at + 1:at + 1] = [line + "\n" for line in lines]
    return "".join(out), lines[-1].strip()


def qualify(a: argparse.Namespace) -> int:
    """scripts/qualify_provider.py for one Anthropic model, under a hard USD ceiling."""
    sys.path.insert(0, str(ROOT / "scripts"))
    import qualify_provider

    os.environ["WARDEN_PROVIDER"] = "anthropic"
    os.environ["WARDEN_MODEL"] = a.model
    for price in ("WARDEN_PRICE_IN", "WARDEN_PRICE_OUT"):
        os.environ.pop(price, None)  # each model at its own price (providers.yaml `prices`)
    code = qualify_provider.main(["--out", str(a.out), "--budget-usd", str(a.budget_usd)])
    # 0 passed, 1 measured below the bar: a result to record. Anything else stopped before one was written.
    if a.record and code in (0, 1):
        _record(json.loads((a.out / "qualification.json").read_text(encoding="utf-8")))
    return code


def _record(result: dict) -> None:
    """The measured row into providers.yaml, and the safety pins rendered again with it."""
    text, line = recorded(result, PROVIDERS_YAML.read_text(encoding="utf-8"))
    PROVIDERS_YAML.write_text(text, encoding="utf-8", newline="\n")
    print("recorded in providers.yaml:", line)
    sys.path.insert(0, str(ROOT / "scripts"))
    import safety_pins

    safety_pins.main()


JOBS: dict[str, Callable[[argparse.Namespace], int]] = {"qualify": qualify}


def _budget(text: str) -> float:
    """A finite, positive number of USD: nan, infinity, zero or less would switch the ceiling off."""
    value = float(text)
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError(f"the budget must be a finite, positive number of USD, not {text!r}")
    return value


def main(argv: list[str] | None = None, *, secrets_client: object = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("job", choices=sorted(JOBS))
    p.add_argument("--model", required=True, help="an exact model id (register M15)")
    p.add_argument("--budget-usd", type=_budget, default=3.0, help="a hard ceiling on what the run may spend")
    p.add_argument("--env", default=None, help="whose key: the runtime environment by default")
    p.add_argument("--out", type=pathlib.Path, default=None, help="a NEW directory outside the repository")
    p.add_argument("--record", action="store_true", help="write the measured row into providers.yaml")
    a = p.parse_args(argv)
    a.out = (a.out or pathlib.Path(tempfile.mkdtemp(prefix=f"warden-{a.job}-"))).expanduser().resolve()
    env = a.env or runtime_environment()
    print(f"{a.job} {a.model}: key from {key_source(env)}; out {a.out}")
    model_key(env, secrets_client)
    return JOBS[a.job](a)


if __name__ == "__main__":
    sys.exit(main())
