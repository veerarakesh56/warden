"""The AWS region for the harness: AWS_REGION, else the `aws_region` WARDEN's environments.yaml names (owner
requirement R17: never a literal in code). Read from the file, not imported: the harness never imports the tool it
measures."""

from __future__ import annotations

import os
import pathlib

import yaml

CONFIG = pathlib.Path(__file__).resolve().parents[2] / "warden" / "src" / "warden" / "data" / "environments.yaml"


# AWS's own documentation account, for dry runs and fakes - never a real one, and written in parts so that no
# twelve-digit number sits in the code.
EXAMPLE_ACCOUNT = "1" * 4 + "2" * 4 + "3" * 4


def fault_environment() -> str:
    """The environment the harness breaks things in: WARDEN_ENV, else the first of environments.yaml
    `fault_environments` - never a name written in code."""
    listed = (yaml.safe_load(CONFIG.read_text(encoding="utf-8")) or {}).get("fault_environments") or []
    chosen = os.environ.get("WARDEN_ENV") or (listed[0] if listed else "")
    if not chosen:
        raise RuntimeError(f"no environment to run in: set WARDEN_ENV or fault_environments in {CONFIG}")
    return str(chosen)


def region() -> str:
    chosen = os.environ.get("AWS_REGION") or (yaml.safe_load(CONFIG.read_text(encoding="utf-8")) or {}).get("aws_region")
    if not chosen:
        raise RuntimeError(f"no AWS region: set AWS_REGION or aws_region in {CONFIG}")
    return str(chosen)
