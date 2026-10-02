"""The AWS region for the harness: AWS_REGION, else the `aws_region` WARDEN's environments.yaml names (owner
requirement R17: never a literal in code). Read from the file, not imported: the harness never imports the tool it
measures."""

from __future__ import annotations

import os
import pathlib

import yaml

CONFIG = pathlib.Path(__file__).resolve().parents[1] / "src" / "warden" / "data" / "environments.yaml"


def region() -> str:
    chosen = os.environ.get("AWS_REGION") or (yaml.safe_load(CONFIG.read_text(encoding="utf-8")) or {}).get("aws_region")
    if not chosen:
        raise RuntimeError(f"no AWS region: set AWS_REGION or aws_region in {CONFIG}")
    return str(chosen)
