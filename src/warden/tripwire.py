"""Injection tripwire: a trained detector over every untrusted evidence line (v2, 2026-09-27).

The quarantine (quarantine.py) already keeps untrusted text away from the model structurally. This
adds a SECOND, independent signal: Meta's Llama Prompt Guard 2 (86M), a classifier trained on a
large corpus of prompt-injection and jailbreak attempts, runs locally on each log line and event.
A line it flags does not change what the model sees; it changes what the gate allows: policy P16
escalates the incident to a person, so a flagged line can never lead to an automatic or pre-approved
fix. It is a tripwire, never a gate that clears text as safe - published work bypasses such
classifiers - so the deterministic layers stay the authority.

Modes (WARDEN_TRIPWIRE):
  off       (default) not run. Tests and CI; the report says the detector was off.
  on        run when available; if the model or its libraries are missing, the report says so.
  required  production: if the detector cannot run, P16 escalates every incident (fail closed).

The model is never bundled with WARDEN. Each deployment downloads it under its own Hugging Face
account and accepts Meta's Llama 4 Community License itself (README, "Injection detector").
"""

from __future__ import annotations

import functools
import os
from typing import Any

from .evidence import Item

MODEL = os.environ.get("WARDEN_TRIPWIRE_MODEL", "meta-llama/Llama-Prompt-Guard-2-86M")
THRESHOLD = float(os.environ.get("WARDEN_TRIPWIRE_THRESHOLD", "0.9"))
# Prompt Guard reads 512 tokens. A long line is scanned in overlapping windows and scores its worst
# window, so an instruction cannot hide behind padding at the start of a line.
WINDOW, STEP = 1200, 1000  # characters (~300 tokens each, well inside 512)


def mode() -> str:
    m = os.environ.get("WARDEN_TRIPWIRE", "off").strip().lower()
    return m if m in ("off", "on", "required") else "required"  # a typo fails closed


@functools.cache
def _classifier() -> Any:
    from transformers import pipeline  # optional: pip install -e ".[guard]"

    return pipeline("text-classification", model=MODEL, top_k=None, truncation=True, max_length=512)


def _malicious(result: list[dict]) -> float:
    return max((r["score"] for r in result if r["label"].upper() in ("MALICIOUS", "LABEL_1")), default=0.0)


def scan(items: dict[str, Item], classify: Any = None) -> tuple[str, dict[str, float]]:
    """(status, {evidence id: score}) for every untrusted item at or above THRESHOLD.

    status: "off", "ran", or "unavailable: <why>" (never the text of an error that could carry data).
    """
    if mode() == "off" and classify is None:
        return "off", {}
    untrusted = [i for i in items.values() if not i.trusted]
    if not untrusted:
        return "ran", {}
    try:
        classify = classify or _classifier()
    except Exception as exc:  # noqa: BLE001 - missing library, no model access, no network
        return f"unavailable: {type(exc).__name__}", {}
    windows, owner = [], []
    for item in untrusted:
        text = item.text
        last = max(len(text) - WINDOW, 0)
        # Every STEP, plus one window ending exactly at the end: the tail is where padding hides it.
        for start in sorted({*range(0, last, STEP), last}):
            windows.append(text[start:start + WINDOW])
            owner.append(item.id)
    worst: dict[str, float] = {}
    for item_id, result in zip(owner, classify(windows, batch_size=16), strict=True):
        worst[item_id] = max(worst.get(item_id, 0.0), _malicious(result))
    return "ran", {i: round(s, 3) for i, s in worst.items() if s >= THRESHOLD}
